use std::sync::OnceLock;

struct Paths {
    nft: String,
    ip: String,
    wg: String,
    tc: String,
    modprobe: String,
    conntrack: String,
    data_dir: String,
    run_dir: String,
    install_dir: String,
}

static PATHS: OnceLock<Paths> = OnceLock::new();

/// Initialize all configurable paths from environment variables.
/// Must be called once at startup before any path accessors are used.
pub fn init() {
    PATHS.get_or_init(|| Paths {
        nft: env_or("HERMITSHELL_NFT_PATH", "/usr/sbin/nft"),
        ip: env_or("HERMITSHELL_IP_PATH", "/usr/sbin/ip"),
        wg: env_or("HERMITSHELL_WG_PATH", "/usr/bin/wg"),
        tc: env_or("HERMITSHELL_TC_PATH", "/usr/sbin/tc"),
        modprobe: env_or("HERMITSHELL_MODPROBE_PATH", "/usr/sbin/modprobe"),
        conntrack: env_or("HERMITSHELL_CONNTRACK_PATH", "/usr/sbin/conntrack"),
        data_dir: env_or("HERMITSHELL_DATA_DIR", "/var/lib/hermitshell"),
        run_dir: env_or("HERMITSHELL_RUN_DIR", "/run/hermitshell"),
        install_dir: env_or("HERMITSHELL_INSTALL_DIR", "/opt/hermitshell"),
    });
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

fn paths() -> &'static Paths {
    PATHS.get().expect("paths::init not called")
}

// Binary path accessors
pub fn nft() -> &'static str { &paths().nft }
pub fn ip() -> &'static str { &paths().ip }
pub fn wg() -> &'static str { &paths().wg }
pub fn tc() -> &'static str { &paths().tc }
pub fn modprobe() -> &'static str { &paths().modprobe }
pub fn conntrack() -> &'static str { &paths().conntrack }

// Directory accessors
pub fn data_dir() -> &'static str { &paths().data_dir }
pub fn run_dir() -> &'static str { &paths().run_dir }
pub fn install_dir() -> &'static str { &paths().install_dir }

// Derived paths
pub fn db_path() -> String { format!("{}/hermitshell.db", data_dir()) }
pub fn backup_path() -> String { format!("{}/hermitshell-backup.db", data_dir()) }
pub fn socket_path() -> String { format!("{}/agent.sock", run_dir()) }
pub fn dhcp_socket_path() -> String { format!("{}/dhcp.sock", run_dir()) }
pub fn unbound_dir() -> String { format!("{}/unbound", data_dir()) }
pub fn unbound_config() -> String { format!("{}/unbound/unbound.conf", data_dir()) }
pub fn blocklist_dir() -> String { format!("{}/unbound/blocklists", data_dir()) }
pub fn update_marker() -> String { format!("{}/update-pending", run_dir()) }
pub fn rollback_dir() -> String { format!("{}/rollback", install_dir()) }
pub fn staging_dir() -> String { format!("{}/staging", install_dir()) }
