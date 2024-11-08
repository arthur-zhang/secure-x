use serde::{Deserialize, Serialize};
use crate::error::ApiError;

#[derive(Deserialize, Serialize, Debug)]
pub struct Conf {
    pub basic: BasicConf,
    pub firewall: FirewallConf,
}
#[derive(Deserialize, Serialize, Debug)]
pub struct BasicConf {
    pub anti_debugging: Status,
}

#[derive(Deserialize, Serialize, Eq, PartialEq, Debug)]
pub struct FirewallConf {
    pub status: Status,
    pub incoming_policy: IncomingPolicy,
    pub rules: Vec<Rule>,
}
#[derive(Deserialize, Serialize, Eq, PartialEq, Debug, Copy, Clone)]
pub enum Action {
    Allow,
    Deny,
}

impl Into<u8> for Action {
    fn into(self) -> u8 {
        match self {
            Action::Allow => 1,
            Action::Deny => 0,
        }
    }
}
#[derive(Deserialize, Serialize, Eq, PartialEq, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Deserialize, Serialize, Eq, PartialEq, Debug)]
pub struct Rule {
    pub id: Option<String>,
    pub name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub action: Action,
}
#[derive(Deserialize, Serialize, Eq, PartialEq, Debug, Copy, Clone)]
pub enum Status {
    On,
    Off,
}
impl Into<u8> for Status {
    fn into(self) -> u8 {
        match self {
            Status::On => 1,
            Status::Off => 0,
        }
    }
}
#[derive(Deserialize, Serialize, Eq, PartialEq, Debug, Copy, Clone)]
pub enum IncomingPolicy {
    Accept,
    Deny,
}
impl Into<u8> for IncomingPolicy {
    fn into(self) -> u8 {
        match self {
            IncomingPolicy::Accept => 1,
            IncomingPolicy::Deny => 0,
        }
    }
}

async fn get_firewall_conf_inner() -> Result<FirewallConf, ApiError> {
    let conf = get_conf().await.map_err(|_| ApiError::FileError)?;
    Ok(conf.firewall)
}
pub async fn get_conf() -> anyhow::Result<Conf> {
    const FILE_PATH: &str = "/home/arthur/secure-x/conf.toml";
    let file = tokio::fs::read_to_string(FILE_PATH).await?;
    let conf: Conf = toml::from_str(&file)?;
    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_conf_parse() {
        let conf = get_conf().await.unwrap();
        println!("conf: {:?}", conf)
    }
}