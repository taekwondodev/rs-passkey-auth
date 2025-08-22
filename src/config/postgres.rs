use std::env;

use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;

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
    pub fn from_env() -> Self {
        Self {
            host: env::var("DB_HOST").expect("DB_HOST is not defined"),
            port: env::var("DB_PORT")
                .expect("DB_PORT is not defined")
                .parse()
                .expect("DB_PORT must be a number"),
            user: env::var("POSTGRES_USER").expect("POSTGRES_USER is not defined"),
            password: env::var("POSTGRES_PASSWORD").expect("POSTGRES_PASSWORD is not defined"),
            dbname: env::var("POSTGRES_DB").expect("POSTGRES_DB is not defined"),
            max_size: env::var("DB_MAX_SIZE")
                .expect("DB_MAX_SIZE is not defined")
                .parse()
                .expect("DB_MAX_SIZE must be a number"),
        }
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

    pub fn create_pool(&self) -> Result<Pool, deadpool_postgres::CreatePoolError> {
        let config = self.to_deadpool_config();
        config.create_pool(Some(Runtime::Tokio1), NoTls)
    }
}
