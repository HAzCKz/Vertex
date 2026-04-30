use crate::{BloomService, RevocationWriteRequest, ServiceError};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    service: Arc<RwLock<BloomService>>,
    admin_token: String,
    enable_test_api: bool,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    ok: bool,
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl From<ServiceError> for ApiError {
    fn from(value: ServiceError) -> Self {
        match value {
            ServiceError::NotFound(msg) => Self::new(StatusCode::NOT_FOUND, msg),
            ServiceError::Invalid(msg) => Self::new(StatusCode::BAD_REQUEST, msg),
            ServiceError::AlreadyExists(msg) => Self::new(StatusCode::CONFLICT, msg),
            ServiceError::Io(msg) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                ok: false,
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
struct CheckRequest {
    filter_id: Option<String>,
    keys: Option<Vec<String>>,
    revocation_keys: Option<Vec<String>>,
    encoding: Option<String>,
    window_start: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CheckResultItem {
    key: String,
    maybe_present: bool,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    ok: bool,
    filter_id: String,
    results: Vec<CheckResultItem>,
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    issuer_did: Option<String>,
    credential_record_id: Option<String>,
    filter_id: Option<String>,
    keys: Option<Vec<String>>,
    revocation_keys: Option<Vec<String>>,
    encoding: Option<String>,
    reason: Option<String>,
    requested_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct RevokeResponse {
    ok: bool,
    filter_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filter_ids: Vec<String>,
    inserted: usize,
    issuer_did: Option<String>,
    credential_record_id: Option<String>,
    reason: Option<String>,
    requested_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RotateRequest {
    filter_id: Option<String>,
    m_bits: Option<usize>,
    k: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct CreateFilterRequest {
    filter_id: Option<String>,
    m_bits: Option<usize>,
    k: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct CloseFilterRequest {
    filter_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetFiltersRequest {
    filter_id: Option<String>,
    m_bits: Option<usize>,
    k: Option<usize>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    active_filter_id: String,
    total_filters: usize,
}

#[derive(Debug, Serialize)]
struct FilterResponse {
    ok: bool,
    filter_id: String,
    bloom_base64: String,
    meta: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct CandidateFiltersResponse {
    ok: bool,
    window_start: i64,
    filters: Vec<serde_json::Value>,
}

fn decode_key(raw: &str, encoding: Option<&str>) -> Result<Vec<u8>, ApiError> {
    match encoding.unwrap_or("utf8") {
        "utf8" => Ok(raw.as_bytes().to_vec()),
        "base64" => {
            use base64::{Engine as _, engine::general_purpose};
            general_purpose::STANDARD.decode(raw).map_err(|e| {
                ApiError::new(StatusCode::BAD_REQUEST, format!("base64 inválido: {}", e))
            })
        }
        other => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("encoding não suportado: {}", other),
        )),
    }
}

fn resolve_keys(
    keys: Option<Vec<String>>,
    revocation_keys: Option<Vec<String>>,
) -> Result<Vec<String>, ApiError> {
    let resolved = revocation_keys.or(keys).unwrap_or_default();
    if resolved.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "keys/revocation_keys não pode ser vazio",
        ));
    }
    Ok(resolved)
}

fn require_admin(headers: &HeaderMap, expected_token: &str) -> Result<(), ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Authorization ausente"))?;

    let provided = value.strip_prefix("Bearer ").unwrap_or(value).trim();
    if provided != expected_token {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "token administrativo inválido",
        ));
    }
    Ok(())
}

fn require_test_api(enabled: bool) -> Result<(), ApiError> {
    if !enabled {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "endpoint disponível somente no modo de testes",
        ));
    }
    Ok(())
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let service = state.service.read().await;
    let manifest = service.manifest();
    Ok(Json(HealthResponse {
        ok: true,
        active_filter_id: manifest.active_filter_id,
        total_filters: manifest.filters.len(),
    }))
}

async fn get_manifest(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let service = state.service.read().await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "manifest": service.manifest(),
    })))
}

async fn get_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
) -> Result<Json<FilterResponse>, ApiError> {
    let service = state.service.read().await;
    let meta = service
        .get_filter_entry(&filter_id)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "filtro não encontrado"))?;
    let bloom_base64 = service.get_filter_base64(&filter_id)?;
    Ok(Json(FilterResponse {
        ok: true,
        filter_id,
        bloom_base64,
        meta: serde_json::to_value(meta)
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    }))
}

async fn get_candidate_filters_for_window(
    State(state): State<AppState>,
    Path(window_start): Path<i64>,
) -> Result<Json<CandidateFiltersResponse>, ApiError> {
    let service = state.service.read().await;
    let filters = service
        .candidate_filters_for_window(window_start)
        .into_iter()
        .map(|entry| {
            serde_json::to_value(entry)
                .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(CandidateFiltersResponse {
        ok: true,
        window_start,
        filters,
    }))
}

async fn check_filter(
    State(state): State<AppState>,
    Json(payload): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, ApiError> {
    let keys = resolve_keys(payload.keys, payload.revocation_keys)?;

    let service = state.service.read().await;
    let candidate_filter_ids = if let Some(filter_id) = payload.filter_id.as_deref() {
        vec![filter_id.to_string()]
    } else if let Some(window_start) = payload.window_start {
        let candidates = service
            .candidate_filters_for_window(window_start)
            .into_iter()
            .map(|entry| entry.filter_id)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            vec![service.active_filter_id().to_string()]
        } else {
            candidates
        }
    } else {
        vec![service.active_filter_id().to_string()]
    };

    let mut results = Vec::with_capacity(keys.len());
    for key in &keys {
        let bytes = decode_key(key, payload.encoding.as_deref())?;
        let mut maybe_present = false;
        for filter_id in &candidate_filter_ids {
            let (_, candidate_present) = service.check_key(Some(filter_id.as_str()), &bytes)?;
            if candidate_present {
                maybe_present = true;
                break;
            }
        }
        results.push(CheckResultItem {
            key: key.clone(),
            maybe_present,
        });
    }

    Ok(Json(CheckResponse {
        ok: true,
        filter_id: if candidate_filter_ids.len() == 1 {
            candidate_filter_ids[0].clone()
        } else {
            candidate_filter_ids.join(",")
        },
        results,
    }))
}

async fn revoke_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let keys = resolve_keys(payload.keys.clone(), payload.revocation_keys.clone())?;
    let mut decoded = Vec::with_capacity(keys.len());
    for key in &keys {
        decoded.push(decode_key(key, payload.encoding.as_deref())?);
    }

    let mut service = state.service.write().await;
    let entry = service.insert_keys(payload.filter_id.as_deref(), &decoded, None)?;
    let filter_id = entry.filter_id.clone();

    Ok(Json(RevokeResponse {
        ok: true,
        filter_id,
        filter_ids: vec![entry.filter_id],
        inserted: decoded.len(),
        issuer_did: payload.issuer_did,
        credential_record_id: payload.credential_record_id,
        reason: payload.reason,
        requested_by: payload.requested_by,
    }))
}

async fn revoke_keys_v2(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RevocationWriteRequest>,
) -> Result<Json<RevokeResponse>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let mut service = state.service.write().await;
    let normalized = service.normalize_revocation_write_request(payload)?;
    let batch = service.insert_keys_v2(
        normalized.filter_id.as_deref(),
        &normalized.decoded_keys,
        normalized.window_starts.as_deref(),
    )?;
    let filter_id = if batch.filter_ids.len() == 1 {
        batch.filter_ids[0].clone()
    } else {
        batch.filter_ids.join(",")
    };

    Ok(Json(RevokeResponse {
        ok: true,
        filter_id,
        filter_ids: batch.filter_ids,
        inserted: batch.inserted,
        issuer_did: normalized.payload.issuer_did,
        credential_record_id: normalized.payload.credential_record_id,
        reason: normalized.payload.reason,
        requested_by: normalized.payload.requested_by,
    }))
}

async fn rotate_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RotateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let mut service = state.service.write().await;
    let entry = service.rotate_filter(payload.filter_id, payload.m_bits, payload.k)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "active_filter": entry,
        "manifest": service.manifest(),
    })))
}

async fn close_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CloseFilterRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let mut service = state.service.write().await;
    let entry = service.close_filter(payload.filter_id.as_deref())?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "closed_filter": entry,
        "manifest": service.manifest(),
    })))
}

async fn create_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateFilterRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let mut service = state.service.write().await;
    let entry = service.create_filter(payload.filter_id, payload.m_bits, payload.k)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "active_filter": entry,
        "manifest": service.manifest(),
    })))
}

async fn reset_filters_for_tests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResetFiltersRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_test_api(state.enable_test_api)?;
    require_admin(&headers, &state.admin_token)?;
    let mut service = state.service.write().await;
    let entry = service.reset_all_filters(payload.filter_id, payload.m_bits, payload.k)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "active_filter": entry,
        "manifest": service.manifest(),
    })))
}

pub fn build_router_with_test_mode(
    service: BloomService,
    admin_token: String,
    enable_test_api: bool,
) -> Router {
    let state = AppState {
        service: Arc::new(RwLock::new(service)),
        admin_token,
        enable_test_api,
    };

    let router = Router::new()
        .route("/health", get(health))
        .route("/manifest", get(get_manifest))
        .route("/filters/:filter_id", get(get_filter))
        .route(
            "/filters/for-window/:window_start",
            get(get_candidate_filters_for_window),
        )
        .route("/check", post(check_filter))
        .route("/admin/revocations", post(revoke_keys))
        .route("/admin/revocations/v2", post(revoke_keys_v2))
        .route("/admin/filters/close", post(close_filter))
        .route("/admin/filters/create", post(create_filter))
        .route("/admin/filters/rotate", post(rotate_filter));

    let router = if enable_test_api {
        router.route("/test/reset", post(reset_filters_for_tests))
    } else {
        router
    };

    router.with_state(state)
}

pub fn build_router(service: BloomService, admin_token: String) -> Router {
    let enable_test_api = std::env::var("BFILTER_ENABLE_TEST_API")
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    build_router_with_test_mode(service, admin_token, enable_test_api)
}
