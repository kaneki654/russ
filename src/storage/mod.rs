//! Small local JSON stores.  RUSS keeps configuration and history on the
//! user's machine; no cloud service or telemetry is involved.

pub mod database;
pub mod friends;
pub mod history;

pub use friends::SavedFriend;
pub use history::TransferHistoryEntry;
