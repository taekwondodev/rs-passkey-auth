use std::env;

use redis::{Client, aio::ConnectionManager};

const REDIS_MAX_CONNECTIONS: u32 = 16;
const CONNECTION_TIMEOUT: u64 = 5000;
const RESPONSE_TIMEOUT: u64 = 3000;

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub response_timeout: u64,
}

impl RedisConfig {
    pub fn from_env() -> Self {
        let url = env::var("REDIS_URL").unwrap();
        Self {
            url,
            max_connections: REDIS_MAX_CONNECTIONS,
            connection_timeout: CONNECTION_TIMEOUT,
            response_timeout: RESPONSE_TIMEOUT,
        }
    }

    pub async fn create_conn_manager(&self) -> ConnectionManager {
        let client = Client::open(self.url.as_str()).unwrap();
        ConnectionManager::new(client).await.unwrap()
    }
}
