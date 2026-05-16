use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose};
use bfilter::api::{build_router, build_router_with_test_mode};
use bfilter::{BloomService, ServiceConfig};
use serde_json::{Value, json};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs;
use tempfile::{TempDir, tempdir};
use tower::util::ServiceExt;

const ADMIN_TOKEN: &str = "integration-admin-token";

struct TestApp {
    _temp_dir: TempDir,
    app: axum::Router,
}

fn test_config(data_dir: &std::path::Path) -> ServiceConfig {
    ServiceConfig {
        data_dir: data_dir.to_path_buf(),
        filter_bytes: 256,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    }
}

fn test_app() -> TestApp {
    let temp_dir = tempdir().expect("tempdir");
    let service = BloomService::load_or_initialize(test_config(temp_dir.path()))
        .expect("service should initialize");
    TestApp {
        _temp_dir: temp_dir,
        app: build_router(service, ADMIN_TOKEN.to_string()),
    }
}

fn test_app_with_config(config: ServiceConfig) -> TestApp {
    let temp_dir = tempdir().expect("tempdir");
    let service = BloomService::load_or_initialize(ServiceConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..config
    })
    .expect("service should initialize");
    TestApp {
        _temp_dir: temp_dir,
        app: build_router(service, ADMIN_TOKEN.to_string()),
    }
}

fn test_app_with_config_and_test_api(config: ServiceConfig, enable_test_api: bool) -> TestApp {
    let temp_dir = tempdir().expect("tempdir");
    let service = BloomService::load_or_initialize(ServiceConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..config
    })
    .expect("service should initialize");
    TestApp {
        _temp_dir: temp_dir,
        app: build_router_with_test_mode(service, ADMIN_TOKEN.to_string(), enable_test_api),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

async fn send_json(
    app: &axum::Router,
    method: Method,
    uri: &str,
    payload: Option<Value>,
    auth_token: Option<&str>,
) -> (StatusCode, Value) {
    let has_payload = payload.is_some();
    let body = payload
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);

    let mut request = Request::builder().method(method).uri(uri);
    if has_payload {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(token) = auth_token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    let response = app
        .clone()
        .oneshot(request.body(body).expect("request should build"))
        .await
        .expect("router should respond");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    let json = serde_json::from_slice(&bytes).expect("body should be valid json");
    (status, json)
}

#[tokio::test]
async fn health_manifest_and_filter_endpoints_return_expected_structure() {
    let test_app = test_app();
    let app = &test_app.app;

    let (health_status, health_body) = send_json(&app, Method::GET, "/health", None, None).await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health_body["ok"], json!(true));
    assert_eq!(health_body["total_filters"], json!(1));

    let active_filter_id = health_body["active_filter_id"]
        .as_str()
        .expect("active_filter_id should be a string")
        .to_string();

    let (manifest_status, manifest_body) =
        send_json(&app, Method::GET, "/manifest", None, None).await;
    assert_eq!(manifest_status, StatusCode::OK);
    assert_eq!(manifest_body["ok"], json!(true));
    assert_eq!(
        manifest_body["manifest"]["active_filter_id"],
        json!(active_filter_id.clone())
    );

    let (filter_status, filter_body) = send_json(
        &app,
        Method::GET,
        &format!("/filters/{}", active_filter_id),
        None,
        None,
    )
    .await;
    assert_eq!(filter_status, StatusCode::OK);
    assert_eq!(filter_body["ok"], json!(true));
    assert_eq!(filter_body["filter_id"], json!(active_filter_id));
    assert!(
        filter_body["bloom_base64"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[tokio::test]
async fn admin_endpoints_require_valid_bearer_token() {
    let test_app = test_app();
    let app = &test_app.app;

    let (missing_status, missing_body) = send_json(
        &app,
        Method::POST,
        "/admin/revocations",
        Some(json!({
            "revocation_keys": ["token-test-key"],
            "encoding": "utf8"
        })),
        None,
    )
    .await;
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_body["ok"], json!(false));
    assert_eq!(missing_body["error"], json!("Authorization ausente"));

    let (invalid_status, invalid_body) = send_json(
        &app,
        Method::POST,
        "/admin/revocations",
        Some(json!({
            "revocation_keys": ["token-test-key"],
            "encoding": "utf8"
        })),
        Some("wrong-token"),
    )
    .await;
    assert_eq!(invalid_status, StatusCode::UNAUTHORIZED);
    assert_eq!(invalid_body["ok"], json!(false));
    assert_eq!(
        invalid_body["error"],
        json!("token administrativo inválido")
    );
}

#[tokio::test]
async fn revocation_insert_then_check_returns_maybe_present_true() {
    let test_app = test_app();
    let app = &test_app.app;
    let key = "integration-key-001";

    let (insert_status, insert_body) = send_json(
        &app,
        Method::POST,
        "/admin/revocations",
        Some(json!({
            "revocation_keys": [key],
            "encoding": "utf8",
            "reason": "integration-test",
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status, StatusCode::OK);
    assert_eq!(insert_body["ok"], json!(true));
    assert_eq!(insert_body["inserted"], json!(1));

    let (check_status, check_body) = send_json(
        &app,
        Method::POST,
        "/check",
        Some(json!({
            "keys": [key],
            "encoding": "utf8"
        })),
        None,
    )
    .await;
    assert_eq!(check_status, StatusCode::OK);
    assert_eq!(check_body["ok"], json!(true));
    assert_eq!(check_body["results"][0]["key"], json!(key));
    assert_eq!(check_body["results"][0]["maybe_present"], json!(true));
}

#[tokio::test]
async fn revocations_v2_updates_window_lookup() {
    let test_app = test_app();
    let app = &test_app.app;
    let target_window = 1_777_000_000i64;

    let (insert_status, insert_body) = send_json(
        &app,
        Method::POST,
        "/admin/revocations/v2",
        Some(json!({
            "revocation_keys": ["window-key-001"],
            "window_starts": [target_window],
            "reason": "window-coverage",
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status, StatusCode::OK);
    assert_eq!(insert_body["ok"], json!(true));
    assert_eq!(insert_body["inserted"], json!(1));

    let (window_status, window_body) = send_json(
        &app,
        Method::GET,
        &format!("/filters/for-window/{}", target_window),
        None,
        None,
    )
    .await;
    assert_eq!(window_status, StatusCode::OK);
    assert_eq!(window_body["ok"], json!(true));
    assert_eq!(window_body["window_start"], json!(target_window));
    assert_eq!(window_body["filters"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        window_body["filters"][0]["window_start_min"],
        json!(target_window)
    );
    assert_eq!(
        window_body["filters"][0]["window_start_max"],
        json!(target_window)
    );
}

#[tokio::test]
async fn revocations_v2_accepts_multi_window_batches() {
    let test_app = test_app();
    let app = &test_app.app;
    let batch = vec![
        ("window-batch-key-001", 1_777_100_000i64),
        ("window-batch-key-002", 1_777_186_400i64),
        ("window-batch-key-003", 1_777_272_800i64),
    ];

    let (insert_status, insert_body) = send_json(
        &app,
        Method::POST,
        "/admin/revocations/v2",
        Some(json!({
            "revocation_keys": batch.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            "window_starts": batch.iter().map(|(_, window)| *window).collect::<Vec<_>>(),
            "reason": "window-batch",
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status, StatusCode::OK);
    assert_eq!(insert_body["ok"], json!(true));
    assert_eq!(insert_body["inserted"], json!(batch.len()));
    assert_eq!(insert_body["filter_ids"].as_array().map(Vec::len), Some(1));

    for (key, window_start) in batch {
        let (window_status, window_body) = send_json(
            &app,
            Method::GET,
            &format!("/filters/for-window/{}", window_start),
            None,
            None,
        )
        .await;
        assert_eq!(window_status, StatusCode::OK);
        assert_eq!(window_body["ok"], json!(true));
        assert_eq!(
            window_body["filters"]
                .as_array()
                .map(|filters| !filters.is_empty()),
            Some(true)
        );

        let (check_status, check_body) = send_json(
            &app,
            Method::POST,
            "/check",
            Some(json!({
                "revocation_keys": [key],
                "window_start": window_start,
                "encoding": "utf8"
            })),
            None,
        )
        .await;
        assert_eq!(check_status, StatusCode::OK);
        assert_eq!(check_body["ok"], json!(true));
        assert_eq!(check_body["results"][0]["maybe_present"], json!(true));
    }
}

#[tokio::test]
async fn filter_admin_lifecycle_close_create_and_rotate_works() {
    let test_app = test_app();
    let app = &test_app.app;

    let (close_status, close_body) = send_json(
        &app,
        Method::POST,
        "/admin/filters/close",
        Some(json!({})),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(close_status, StatusCode::OK);
    assert_eq!(close_body["ok"], json!(true));
    assert_eq!(close_body["manifest"]["active_filter_id"], json!(""));
    assert_eq!(close_body["closed_filter"]["status"], json!("closed"));

    let (create_status, create_body) = send_json(
        &app,
        Method::POST,
        "/admin/filters/create",
        Some(json!({
            "filter_id": "integration-filter-create",
            "m_bits": 512,
            "k": 3
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK);
    assert_eq!(create_body["ok"], json!(true));
    assert_eq!(
        create_body["active_filter"]["filter_id"],
        json!("integration-filter-create")
    );
    assert_eq!(
        create_body["manifest"]["active_filter_id"],
        json!("integration-filter-create")
    );

    let (rotate_status, rotate_body) = send_json(
        &app,
        Method::POST,
        "/admin/filters/rotate",
        Some(json!({
            "filter_id": "integration-filter-rotated",
            "m_bits": 256,
            "k": 2
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(rotate_status, StatusCode::OK);
    assert_eq!(rotate_body["ok"], json!(true));
    assert_eq!(
        rotate_body["active_filter"]["filter_id"],
        json!("integration-filter-rotated")
    );
    assert_eq!(
        rotate_body["manifest"]["active_filter_id"],
        json!("integration-filter-rotated")
    );
}

#[tokio::test]
async fn active_filter_auto_rotates_at_95_percent_capacity() {
    let test_app = test_app_with_config(ServiceConfig {
        data_dir: std::path::PathBuf::new(),
        filter_bytes: 32,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    });
    let app = &test_app.app;

    let (manifest_status, manifest_body) =
        send_json(&app, Method::GET, "/manifest", None, None).await;
    assert_eq!(manifest_status, StatusCode::OK);
    let active_filter_id = manifest_body["manifest"]["active_filter_id"]
        .as_str()
        .expect("active filter id should exist")
        .to_string();
    let capacity_limit = manifest_body["manifest"]["filters"][0]["capacity_limit"]
        .as_u64()
        .expect("capacity_limit should be present") as usize;
    let rotate_threshold = (capacity_limit * 95).div_ceil(100);
    assert!(rotate_threshold >= 1);

    let almost_full_keys = (0..(rotate_threshold - 1))
        .map(|idx| format!("rotate-pre-{}", idx))
        .collect::<Vec<_>>();
    let (insert_status_1, insert_body_1) = send_json(
        &app,
        Method::POST,
        "/admin/revocations/v2",
        Some(json!({
            "revocation_keys": almost_full_keys,
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status_1, StatusCode::OK);
    assert_eq!(insert_body_1["ok"], json!(true));

    let (_, manifest_after_first_insert) =
        send_json(&app, Method::GET, "/manifest", None, None).await;
    let first_filters = manifest_after_first_insert["manifest"]["filters"]
        .as_array()
        .expect("filters should be array");
    let first_active_filter = first_filters
        .iter()
        .find(|item| item["filter_id"] == json!(active_filter_id.clone()))
        .expect("active filter should exist in manifest");
    assert_eq!(
        manifest_after_first_insert["manifest"]["active_filter_id"],
        json!(active_filter_id.clone())
    );
    assert_eq!(first_active_filter["status"], json!("active"));
    assert_eq!(
        first_active_filter["inserted_count"],
        json!(rotate_threshold - 1)
    );

    let (insert_status_2, insert_body_2) = send_json(
        &app,
        Method::POST,
        "/admin/revocations/v2",
        Some(json!({
            "revocation_keys": ["rotate-trigger-key"],
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status_2, StatusCode::OK);
    assert_eq!(insert_body_2["ok"], json!(true));
    assert_eq!(insert_body_2["filter_id"], json!(active_filter_id.clone()));

    let (_, manifest_after_rotation) = send_json(&app, Method::GET, "/manifest", None, None).await;
    let filters = manifest_after_rotation["manifest"]["filters"]
        .as_array()
        .expect("filters should be array");
    assert_eq!(filters.len(), 2);
    let old_filter = filters
        .iter()
        .find(|item| item["filter_id"] == json!(active_filter_id.clone()))
        .expect("old filter should exist");
    let new_active_id = manifest_after_rotation["manifest"]["active_filter_id"]
        .as_str()
        .expect("new active should exist");
    assert_ne!(new_active_id, active_filter_id);
    let new_filter = filters
        .iter()
        .find(|item| item["filter_id"] == json!(new_active_id))
        .expect("new filter should exist");

    assert_eq!(old_filter["status"], json!("closed"));
    assert_eq!(old_filter["inserted_count"], json!(rotate_threshold));
    assert!(old_filter["closed_at"].as_u64().is_some());
    assert_eq!(new_filter["status"], json!("active"));
    assert_eq!(new_filter["inserted_count"], json!(0));
}

#[tokio::test]
async fn rotation_updates_manifest_file_ready_for_ledger_anchor() {
    let temp_dir = tempdir().expect("tempdir");
    let config = ServiceConfig {
        data_dir: temp_dir.path().to_path_buf(),
        filter_bytes: 32,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    };
    let service =
        BloomService::load_or_initialize(config.clone()).expect("service should initialize");
    let app = build_router(service, ADMIN_TOKEN.to_string());

    let manifest_file = temp_dir.path().join("manifest.json");
    let manifest_before_bytes =
        std::fs::read(&manifest_file).expect("manifest before should exist");
    let manifest_before_hash = sha256_hex(&manifest_before_bytes);
    let manifest_before_json: Value = serde_json::from_slice(&manifest_before_bytes)
        .expect("manifest before should be valid json");
    let old_active_id = manifest_before_json["active_filter_id"]
        .as_str()
        .expect("old active filter id should exist")
        .to_string();
    let old_capacity_limit = manifest_before_json["filters"][0]["capacity_limit"]
        .as_u64()
        .expect("capacity_limit should exist") as usize;
    let rotate_threshold = (old_capacity_limit * 95).div_ceil(100);

    let keys = (0..rotate_threshold)
        .map(|idx| format!("manifest-ledger-key-{}", idx))
        .collect::<Vec<_>>();
    let (insert_status, insert_body) = send_json(
        &app,
        Method::POST,
        "/admin/revocations/v2",
        Some(json!({
            "revocation_keys": keys,
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status, StatusCode::OK);
    assert_eq!(insert_body["ok"], json!(true));
    assert_eq!(insert_body["filter_id"], json!(old_active_id.clone()));

    let manifest_after_bytes = std::fs::read(&manifest_file).expect("manifest after should exist");
    let manifest_after_hash = sha256_hex(&manifest_after_bytes);
    let manifest_after_json: Value =
        serde_json::from_slice(&manifest_after_bytes).expect("manifest after should be valid json");
    let new_active_id = manifest_after_json["active_filter_id"]
        .as_str()
        .expect("new active filter id should exist")
        .to_string();

    assert_ne!(manifest_before_hash, manifest_after_hash);
    assert_ne!(old_active_id, new_active_id);
    assert_eq!(
        manifest_after_json["filters"].as_array().map(Vec::len),
        Some(2)
    );

    let old_filter = manifest_after_json["filters"]
        .as_array()
        .expect("filters should be array")
        .iter()
        .find(|item| item["filter_id"] == json!(old_active_id.clone()))
        .expect("old filter should exist");
    let new_filter = manifest_after_json["filters"]
        .as_array()
        .expect("filters should be array")
        .iter()
        .find(|item| item["filter_id"] == json!(new_active_id.clone()))
        .expect("new filter should exist");

    assert_eq!(old_filter["status"], json!("closed"));
    assert_eq!(old_filter["inserted_count"], json!(rotate_threshold));
    assert!(old_filter["closed_at"].as_u64().is_some());
    assert_eq!(new_filter["status"], json!("active"));
    assert_eq!(new_filter["inserted_count"], json!(0));
}

#[tokio::test]
async fn test_only_reset_endpoint_is_gated_and_resets_filters() {
    let config = ServiceConfig {
        data_dir: std::path::PathBuf::new(),
        filter_bytes: 32,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    };

    let disabled_app = test_app_with_config_and_test_api(config.clone(), false);
    let disabled_response = disabled_app
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/test/reset")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", ADMIN_TOKEN))
                .body(Body::from("{}"))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    let disabled_status = disabled_response.status();
    let disabled_bytes = to_bytes(disabled_response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    assert_eq!(disabled_status, StatusCode::NOT_FOUND);
    assert!(disabled_bytes.is_empty());

    let enabled_app = test_app_with_config_and_test_api(config, true);
    let (_, manifest_before) =
        send_json(&enabled_app.app, Method::GET, "/manifest", None, None).await;
    let old_active_id = manifest_before["manifest"]["active_filter_id"]
        .as_str()
        .expect("old active filter should exist")
        .to_string();

    let (insert_status, insert_body) = send_json(
        &enabled_app.app,
        Method::POST,
        "/admin/revocations/v2",
        Some(json!({
            "revocation_keys": ["reset-key-1", "reset-key-2"],
            "requested_by": "cargo-test"
        })),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(insert_status, StatusCode::OK);
    assert_eq!(insert_body["ok"], json!(true));

    let (reset_status, reset_body) = send_json(
        &enabled_app.app,
        Method::POST,
        "/test/reset",
        Some(json!({})),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(reset_status, StatusCode::OK);
    assert_eq!(reset_body["ok"], json!(true));
    let new_active_id = reset_body["manifest"]["active_filter_id"]
        .as_str()
        .expect("new active filter should exist")
        .to_string();
    assert_ne!(new_active_id, old_active_id);
    assert_eq!(
        reset_body["manifest"]["filters"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(reset_body["active_filter"]["status"], json!("active"));
    assert_eq!(reset_body["active_filter"]["inserted_count"], json!(0));
}

#[test]
fn rotated_filters_persist_and_reload_with_new_active_filter() {
    let temp_dir = tempdir().expect("tempdir");
    let config = ServiceConfig {
        data_dir: temp_dir.path().to_path_buf(),
        filter_bytes: 32,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    };

    let mut service =
        BloomService::load_or_initialize(config.clone()).expect("service should initialize");
    let active_before = service.active_filter_id().to_string();
    let first_entry = service
        .get_filter_entry(&active_before)
        .expect("active filter entry should exist")
        .clone();
    let rotate_threshold = (first_entry.capacity_limit * 95).div_ceil(100);

    let keys = (0..rotate_threshold)
        .map(|idx| format!("persist-key-{}", idx).into_bytes())
        .collect::<Vec<_>>();
    let inserted_entry = service
        .insert_keys(None, &keys, None)
        .expect("insert should succeed");
    assert_eq!(inserted_entry.filter_id, active_before);
    assert_eq!(inserted_entry.status, "closed");

    let active_after = service.active_filter_id().to_string();
    assert_ne!(active_after, active_before);
    drop(service);

    let reloaded = BloomService::load_or_initialize(config).expect("service should reload");
    let manifest = reloaded.manifest();
    assert_eq!(manifest.filters.len(), 2);
    assert_eq!(manifest.active_filter_id, active_after);
    let old_filter = manifest
        .filters
        .iter()
        .find(|item| item.filter_id == active_before)
        .expect("old filter should persist");
    let new_filter = manifest
        .filters
        .iter()
        .find(|item| item.filter_id == active_after)
        .expect("new filter should persist");
    assert_eq!(old_filter.status, "closed");
    assert_eq!(old_filter.inserted_count, rotate_threshold);
    assert!(old_filter.closed_at.is_some());
    assert_eq!(new_filter.status, "active");
    assert_eq!(new_filter.inserted_count, 0);
}

#[test]
fn filters_are_persisted_as_raw_binary_while_api_stays_base64() {
    let temp_dir = tempdir().expect("tempdir");
    let config = ServiceConfig {
        data_dir: temp_dir.path().to_path_buf(),
        filter_bytes: 32,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    };

    let service = BloomService::load_or_initialize(config).expect("service should initialize");
    let active_id = service.active_filter_id().to_string();
    let entry = service
        .get_filter_entry(&active_id)
        .expect("active filter entry should exist");
    let file_path = temp_dir.path().join("filters").join(&entry.file_name);

    let raw_on_disk = fs::read(&file_path).expect("filter file should exist");
    let from_api = service
        .get_filter_base64(&active_id)
        .expect("filter base64 should be available");
    let decoded = general_purpose::STANDARD
        .decode(from_api)
        .expect("api payload should be valid base64");

    assert_eq!(raw_on_disk, decoded);
    assert_eq!(raw_on_disk.len(), 16 + entry.m_bits.div_ceil(8));
}

#[test]
fn service_reloads_legacy_base64_filter_files() {
    let temp_dir = tempdir().expect("tempdir");
    let config = ServiceConfig {
        data_dir: temp_dir.path().to_path_buf(),
        filter_bytes: 32,
        false_positive_power: 8,
        public_base_url: None,
        rotate_at_percent: 95,
    };

    let service =
        BloomService::load_or_initialize(config.clone()).expect("service should initialize");
    let active_id = service.active_filter_id().to_string();
    let entry = service
        .get_filter_entry(&active_id)
        .expect("active filter entry should exist")
        .clone();
    let file_path = temp_dir.path().join("filters").join(&entry.file_name);
    let legacy_base64 = service
        .get_filter_base64(&active_id)
        .expect("filter base64 should be available");
    drop(service);

    fs::write(&file_path, legacy_base64.as_bytes())
        .expect("should rewrite filter as legacy base64");

    let reloaded =
        BloomService::load_or_initialize(config).expect("service should reload legacy file");
    let reloaded_base64 = reloaded
        .get_filter_base64(&active_id)
        .expect("reloaded filter should be available");
    let raw_on_disk = fs::read(&file_path).expect("rewritten filter should exist on disk");
    let decoded = general_purpose::STANDARD
        .decode(&legacy_base64)
        .expect("legacy base64 should decode");

    assert_eq!(reloaded_base64, legacy_base64);
    assert_eq!(raw_on_disk, decoded);
    assert_ne!(raw_on_disk, legacy_base64.as_bytes());
}
