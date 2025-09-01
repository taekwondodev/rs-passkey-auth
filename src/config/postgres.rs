use std::env;

use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;

const DB_MAX_SIZE: usize = 16;

#[derive(Debug)]
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
        let host = env::var("DB_HOST").unwrap();
        let port = env::var("DB_PORT").unwrap().parse().unwrap();
        let user = env::var("POSTGRES_USER").unwrap();
        let password = env::var("POSTGRES_PASSWORD").unwrap();
        let dbname = env::var("POSTGRES_DB").unwrap();

        Self {
            host,
            port,
            user,
            password,
            dbname,
            max_size: DB_MAX_SIZE,
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

    pub fn create_pool(&self) -> Pool {
        let config = self.to_deadpool_config();
        config.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }
}
