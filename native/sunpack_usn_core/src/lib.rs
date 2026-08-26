#![cfg(windows)]

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "journal")]
mod journal;
pub mod protocol;
mod types;

#[cfg(feature = "client")]
pub use client::{
    broker_acquire, broker_is_connected, broker_ping, broker_probe_volume,
    broker_read_change_reasons, broker_release,
};
#[cfg(feature = "journal")]
pub use journal::{validate_volume_guid, JournalReader};
pub use types::ChangeReasons;

pub const SERVICE_NAME: &str = "SunPackWatchBroker";
pub const PIPE_NAME: &str = r"\\.\pipe\SunPack.WatchBroker.v1";
