use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

impl PlmnId {
    pub fn new(mcc: String, mnc: String) -> Self {
        Self { mcc, mnc }
    }

    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            Some(Self {
                mcc: parts[0].to_string(),
                mnc: parts[1].to_string(),
            })
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}-{}", self.mcc, self.mnc)
    }
}

impl std::fmt::Display for PlmnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.mcc, self.mnc)
    }
}
