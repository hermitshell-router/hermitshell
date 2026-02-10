mod db;
mod dhcp;
mod nftables;

use anyhow::Result;

fn main() -> Result<()> {
    println!("hermitshell-agent starting...");

    // For now, hardcode interfaces (will come from config later)
    let wan_iface = "eth1";
    let lan_iface = "eth2";

    nftables::apply_base_rules(wan_iface, lan_iface)?;

    println!("Agent initialized successfully");
    Ok(())
}
