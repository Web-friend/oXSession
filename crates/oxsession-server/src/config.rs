use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, bail};

pub struct Config {
    pub bind_address: SocketAddr,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = env::var("AUTH_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
        let ip: IpAddr = host
            .parse()
            .with_context(|| format!("AUTH_BIND_ADDR must be a valid IP address, got {host:?}"))?;

        let port = match env::var("AUTH_PORT") {
            Ok(value) => value.parse::<u16>().with_context(|| {
                format!("AUTH_PORT must be an integer from 0 to 65535, got {value:?}")
            })?,
            Err(env::VarError::NotPresent) => 3000,
            Err(error) => return Err(error).context("AUTH_PORT is not valid Unicode"),
        };

        if port == 0 {
            bail!("AUTH_PORT must be between 1 and 65535");
        }

        Ok(Self {
            bind_address: SocketAddr::new(ip, port),
        })
    }
}
