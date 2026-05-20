// Mock Rust gRPC scripture engine error structure
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct GrpcErrorPayload {
    pub status: String, // e.g., "INVALID_ARGUMENT"
    pub msg: String,
    pub meta: Option<serde_json::Value>,
}

fn simulate_grpc_validation_error() -> GrpcErrorPayload {
    GrpcErrorPayload {
        status: "INVALID_ARGUMENT".to_string(),
        msg: "Invalid scripture coordinate format".to_string(),
        meta: Some(serde_json::json!({
            "expected_format": "Book Chapter:Verse (e.g., 'John 3:16')",
            "received": "Jn3.16"
        })),
    }
}

fn main() {
    let err = simulate_grpc_validation_error();
    println!("{}", serde_json::to_string_pretty(&err).unwrap());
}
