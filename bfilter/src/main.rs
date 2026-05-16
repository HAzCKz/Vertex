use bfilter::api::build_router;
use bfilter::{BloomService, ServiceConfig};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr =
        std::env::var("BFILTER_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let admin_token =
        std::env::var("BFILTER_ADMIN_TOKEN").unwrap_or_else(|_| "dev-admin-token".to_string());
    let test_api_enabled = std::env::var("BFILTER_ENABLE_TEST_API")
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    let config = ServiceConfig::from_env();
    let service = BloomService::load_or_initialize(config)?;
    let app = build_router(service, admin_token);

    let addr: SocketAddr = bind_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("============================================================");
    println!("bfilter service listening on http://{}", addr);
    if test_api_enabled {
        println!("mode: TEST");
        println!("warning: test-only endpoints are ENABLED");
    } else {
        println!("mode: PRODUCTION");
        println!("warning: test-only endpoints are DISABLED");
    }
    println!(
        "public endpoints: GET /health, GET /manifest, GET /filters/:filter_id, GET /filters/for-window/:window_start, POST /check"
    );
    println!(
        "admin endpoints: POST /admin/revocations, POST /admin/revocations/v2, POST /admin/filters/close, POST /admin/filters/create, POST /admin/filters/rotate"
    );
    if test_api_enabled {
        println!("test-only endpoints: POST /test/reset");
        println!("test hint: use this mode only in controlled validation environments");
    } else {
        println!("test-only endpoints: not exposed");
    }
    println!("============================================================");

    axum::serve(listener, app).await?;
    Ok(())
}
