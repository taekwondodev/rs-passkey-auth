use std::env;

use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;

use crate::app::AppError;

#[derive(Debug, Clone)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub max_size: usize,
}

impl DbConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let host = env::var("DB_HOST")?;
        let port = env::var("DB_PORT")?.parse()?;
        let user = env::var("POSTGRES_USER")?;
        let password = env::var("POSTGRES_PASSWORD")?;
        let dbname = env::var("POSTGRES_DB")?;
        let max_size = env::var("DB_MAX_SIZE")?.parse()?;

        Ok(Self {
            host,
            port,
            user,
            password,
            dbname,
            max_size,
        })
    }

    pub fn to_deadpool_config(&self) -> Config {
        let mut cfg = Config::new();
        cfg.host = Some(self.host.clone());
        cfg.port = Some(self.port);
        cfg.user = Some(self.user.clone());
        cfg.password = Some(self.password.clone());
        cfg.dbname = Some(self.dbname.clone());
        cfg.pool = Some(deadpool_postgres::PoolConfig::new(self.max_size));
        cfg
    }

    pub fn create_pool(&self) -> Result<Pool, AppError> {
        let config = self.to_deadpool_config();
        config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(AppError::from)
    }
}
