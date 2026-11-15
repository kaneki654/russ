pub mod active_transfers;
pub mod dashboard;
pub mod friends;
pub mod history;
pub mod receiver;
pub mod sender;
pub mod settings;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Dashboard,
    SendFiles,
    ReceiveFiles,
    SavedFriends,
    ActiveTransfers,
    History,
    Security,
}

impl Screen {
    pub const ALL: [Screen; 7] = [
        Screen::Dashboard,
        Screen::SendFiles,
        Screen::ReceiveFiles,
        Screen::SavedFriends,
        Screen::ActiveTransfers,
        Screen::History,
        Screen::Security,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::SendFiles => "Send Files",
            Self::ReceiveFiles => "Receive Files",
            Self::SavedFriends => "Saved Friends",
            Self::ActiveTransfers => "Active Transfers",
            Self::History => "Transfer History",
            Self::Security => "Security Settings",
        }
    }
}
