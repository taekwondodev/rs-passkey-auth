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
        let host =
            env::var("DB_HOST").map_err(|_| AppError::ConfigMissing("DB_HOST".to_string()))?;

        let port = env::var("DB_PORT")
            .map_err(|_| AppError::ConfigMissing("DB_PORT".to_string()))?
            .parse()
            .map_err(|_| AppError::ConfigInvalid("DB_PORT must be a valid number".to_string()))?;

        let user = env::var("POSTGRES_USER")
            .map_err(|_| AppError::ConfigMissing("POSTGRES_USER".to_string()))?;

        let password = env::var("POSTGRES_PASSWORD")
            .map_err(|_| AppError::ConfigMissing("POSTGRES_PASSWORD".to_string()))?;

        let dbname = env::var("POSTGRES_DB")
            .map_err(|_| AppError::ConfigMissing("POSTGRES_DB".to_string()))?;

        let max_size = env::var("DB_MAX_SIZE")
            .map_err(|_| AppError::ConfigMissing("DB_MAX_SIZE".to_string()))?
            .parse()
            .map_err(|_| {
                AppError::ConfigInvalid("DB_MAX_SIZE must be a valid number".to_string())
            })?;

        Ok(Self {
            host: host,
            port: port,
            user: user,
            password: password,
            dbname: dbname,
            max_size: max_size,
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
