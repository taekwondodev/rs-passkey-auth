use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct BeginResponse {
    #[schema(example = json!({"challenge": "Y2hhbGxlbmdl", "rp": {"name": "Example", "id": "example.com"}}))]
    pub options: serde_json::Value,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub session_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Operation completed successfully")]
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    #[schema(example = "Login completed successfully")]
    pub message: String,
    #[schema(
        example = "v4.public.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    )]
    pub access_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublickKeyResponse {
    #[schema(example = "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")]
    pub public_key: String,
    #[schema(example = "Ed25519")]
    pub algorithm: String,
    #[schema(example = "PASETO_v4_public")]
    pub key_type: String,
}
