//! Windows图标设置功能模块
//! 提供在文件加密后修改文件图标的方法

#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::Foundation::CloseHandle;
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegSetValueExW, HKEY_CLASSES_ROOT, KEY_WRITE, REG_SZ,
};
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken,
};
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION,
};
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG,
};
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::System::Com::CoTaskMemFree;
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::UI::Shell::SHChangeNotify;
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::UI::Shell::SHCNE_ASSOCCHANGED;
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::UI::Shell::SHCNF_IDLIST;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::thread;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::time::Duration;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::sync::mpsc;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::ffi::OsStr;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::os::windows::ffi::OsStrExt;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::ptr;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::io;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::env;

/// 检查当前进程是否以管理员权限运行
#[cfg(all(target_os = "windows", feature = "icons"))]
pub fn is_admin() -> bool {
    unsafe {
        let mut h_token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), windows::Win32::Security::TOKEN_QUERY, &mut h_token).is_err() {
            return false;
        }
        
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;
        let success = GetTokenInformation(
            h_token,
            windows::Win32::Security::TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ).is_ok();
        
        let _ = windows::Win32::Foundation::CloseHandle(h_token);
        
        success && elevation.TokenIsElevated != 0
    }
}

/// 在Windows上设置文件类型关联的图标
/// 需要管理员权限才能修改HKEY_CLASSES_ROOT注册表项
#[cfg(all(target_os = "windows", feature = "icons"))]
pub fn set_file_extension_icon(file_type: &str, icon_path: &str) -> Result<(), io::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    
    println!("Setting icon for file type '{}' with icon path '{}'", file_type, icon_path);

    if file_type.is_empty() {
        println!("Error: File type cannot be empty");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "File type cannot be empty"));
    }
    
    if icon_path.is_empty() {
        println!("Error: Icon path cannot be empty");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Icon path cannot be empty"));
    }
    
    let icon_path_obj = std::path::Path::new(icon_path);
    if !icon_path_obj.exists() {
        println!("Error: Icon file does not exist at path: {}", icon_path);
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Icon file not found: {}", icon_path)));
    }
    
    let admin_status = is_admin();
    println!("Administrator privileges status: {}", if admin_status { "Yes" } else { "No" });
    if !admin_status {
        eprintln!("Warning: Setting file icons requires administrator privileges. Please run as administrator.");
    }

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let subkey_str = format!("{}\\DefaultIcon", file_type);
        let subkey: Vec<u16> = OsStr::new(&subkey_str)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let result = RegCreateKeyExW(
            HKEY_CLASSES_ROOT,
            windows::core::PCWSTR(subkey.as_ptr()),
            0,
            None,
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );

        if result.is_err() {
            println!("Failed to create registry key");
            let error = io::Error::last_os_error();
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, 
                format!("Failed to create registry key '{}' for extension: {}", subkey_str, error)));
        } else {
            println!("Successfully created or opened registry key: {}", subkey_str);
        }

        let icon_value_str = format!("\"{}\",0", icon_path);
        let icon_value: Vec<u16> = OsStr::new(&icon_value_str)
            .encode_wide()
            .chain(Some(0))
            .collect();
            
        let set_result = RegSetValueExW(
            hkey,
            windows::core::PCWSTR::null(),
            0,
            REG_SZ,
            Some(unsafe { std::slice::from_raw_parts(
                icon_value.as_ptr() as *const u8,
                icon_value.len() * 2
            ) }),
        );

        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);

        if set_result.is_err() {
            println!("Failed to set registry value");
            let error = io::Error::last_os_error();
            return Err(io::Error::new(io::ErrorKind::Other, 
                format!("Failed to set icon value for '{}': {}", file_type, error)));
        } else {
            println!("Successfully set icon value in registry");
        }
        
        println!("Successfully set registry key for extension {} with icon {}", file_type, icon_path);
    }
    
    Ok(())
}

/// 跨平台兼容的空实现
#[cfg(not(all(target_os = "windows", feature = "icons")))]
pub fn set_file_extension_icon(_extension: &str, _icon_path: &str) -> Result<(), &'static str> {
    println!("Setting file icons is only supported on Windows with icons feature enabled");
    Ok(())
}

/// 通知系统图标已更改 - 优化版本，移除延迟
#[cfg(all(target_os = "windows", feature = "icons"))]
pub fn notify_icon_change() {
    println!("Sending system notification to refresh icon cache");
    
    unsafe {
        SHChangeNotify(
            SHCNE_ASSOCCHANGED,
            SHCNF_IDLIST,
            None,
            None,
        );
    }
    
    let env_str: Vec<u16> = OsStr::new("Environment")
        .encode_wide()
        .chain(Some(0))
        .collect();
        
    println!("Broadcasting WM_SETTINGCHANGE message for 'Environment'");
        
    unsafe {
        let mut result: usize = 0;
        let res = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            windows::Win32::Foundation::WPARAM(0),
            windows::Win32::Foundation::LPARAM(env_str.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            5000,
            Some(&mut result),
        );
        
        if res == windows::Win32::Foundation::LRESULT(0) {
            println!("Failed to send WM_SETTINGCHANGE message");
        } else {
            println!("Successfully sent WM_SETTINGCHANGE message");
        }
    }
    
    println!("Sent system notification to refresh icon cache");
}

#[cfg(not(all(target_os = "windows", feature = "icons")))]
pub fn notify_icon_change() {
    println!("Icon change notification is only supported on Windows with icons feature enabled");
}

/// 获取嵌入资源中的图标路径
#[cfg(feature = "icons")]
pub fn get_embedded_icon_path() -> &'static str {
    // 确保使用正确的图标文件名
    "resources/encrypt.ico"
}

/// 获取嵌入资源中的图标路径
#[cfg(not(feature = "icons"))]
pub fn get_embedded_icon_path() -> &'static str {
    ""
}

/// 获取当前可执行文件所在目录
#[cfg(all(target_os = "windows", feature = "icons"))]
pub fn get_current_directory() -> std::path::PathBuf {
    use std::env;
    env::current_exe()
        .map(|path| path.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf())
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// 获取绝对图标路径
#[cfg(all(target_os = "windows", feature = "icons"))]
pub fn get_absolute_icon_path() -> std::path::PathBuf {
    // 获取可执行文件路径
    let exe_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let exe_dir = exe_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    
    // 检查图标文件是否在当前执行目录中存在
    let local_icon_path = exe_dir.join("resources").join("encrypt.ico");
    if local_icon_path.exists() {
        return local_icon_path;
    }
    
    // 如果执行目录中没有图标，则尝试使用项目根目录
    // 通过向上查找目录结构寻找resources目录
    let mut current_dir = exe_dir;
    loop {
        let project_icon_path = current_dir.join("resources").join("encrypt.ico");
        if project_icon_path.exists() {
            return project_icon_path;
        }
        
        // 向上移动一级目录
        match current_dir.parent() {
            Some(parent) => current_dir = parent,
            None => break, // 已经到达根目录
        }
    }
    
    // 如果在项目目录结构中找不到，则回退到执行目录
    local_icon_path
}

/// 在程序启动时释放图标资源
#[cfg(all(target_os = "windows", feature = "icons"))]
pub fn extract_icon_resource() -> Result<(), io::Error> {
    println!("Starting icon resource extraction process");
    use std::fs;
    
    // 确保resources目录存在
    if !std::path::Path::new("resources").exists() {
        println!("Creating resources directory");
        fs::create_dir("resources")?;
        println!("Created resources directory");
    } else {
        println!("Resources directory already exists");
    }
    
    // 获取目标图标路径
    let icon_path = get_absolute_icon_path();
    println!("Target icon path: {:?}", icon_path);
    
    // 检查图标文件是否已经存在
    if !icon_path.exists() {
        println!("Icon file does not exist, copying from source directory");
        
        // 查找源图标文件（在项目根目录的resources中）
        let source_icon_path = find_source_icon_path();
        if source_icon_path.exists() {
            // 确保目标目录存在
            if let Some(parent) = icon_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            // 复制图标文件
            fs::copy(&source_icon_path, &icon_path)?;
            println!("Successfully copied icon file from source directory");
        } else {
            // 如果源目录中也没有图标文件，则使用内嵌资源
            println!("Source icon file not found, extracting embedded resource");
            let icon_data = include_bytes!("../../resources/encrypt.ico");
            // 确保目标目录存在
            if let Some(parent) = icon_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&icon_path, icon_data)?;
            println!("Successfully extracted embedded icon file");
        }
    } else {
        println!("Icon file already exists, skipping creation");
    }
    
    println!("Icon file successfully exists at: {:?}", icon_path);
    Ok(())
}

/// 查找源代码目录中的图标文件
#[cfg(all(target_os = "windows", feature = "icons"))]
fn find_source_icon_path() -> std::path::PathBuf {
    // 获取可执行文件路径
    let exe_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let exe_dir = exe_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    
    // 向上搜索目录结构，寻找包含resources目录的项目根目录
    let mut current_dir = exe_dir;
    loop {
        let source_icon_path = current_dir.join("resources").join("encrypt.ico");
        if source_icon_path.exists() {
            return source_icon_path;
        }
        
        // 向上移动一级目录
        match current_dir.parent() {
            Some(parent) => current_dir = parent,
            None => break, // 已经到达根目录
        }
    }
    
    // 如果找不到，则返回默认路径
    std::path::PathBuf::from("resources").join("encrypt.ico")
}

#[cfg(not(all(target_os = "windows", feature = "icons")))]
pub fn extract_icon_resource() -> Result<(), &'static str> {
    println!("Icon extraction is only supported on Windows with icons feature enabled");
    Ok(())
}