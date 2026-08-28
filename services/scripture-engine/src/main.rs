use pgvector::Vector;
use scriptureforge::engine::scripture_engine_server::{ScriptureEngine, ScriptureEngineServer};
use scriptureforge::engine::{
    EmbedTextRequest, EmbedTextResponse, SearchResult, VectorSearchRequest, VectorSearchResponse,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Postgres, Row, Transaction};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tonic::server::NamedService;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

const EMBEDDING_DIMENSION: usize = 1536;
const MAX_VECTOR_SEARCH_RESULTS: i32 = 100;
const MAX_GRPC_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_ORGANIZATION_ID_BYTES: usize = 128;
const MAX_BOOK_BYTES: usize = 128;
const MAX_TEXT_CONTENT_BYTES: usize = 128 * 1024;
const GRPC_AUTHORIZATION_HEADER: &str = "authorization";
const GRPC_TENANT_HEADER: &str = "x-scriptureforge-organization-id";
const DEFAULT_METRICS_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_METRICS_READ_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_METRICS_READ_TIMEOUT: Duration = Duration::from_secs(30);

pub mod scriptureforge {
    pub mod engine {
        tonic::include_proto!("scriptureforge.engine");
    }
}

#[derive(Debug)]
pub struct MyScriptureEngine {
    db_pool: sqlx::PgPool,
    metrics: Arc<RustEngineMetrics>,
}

#[derive(Debug, Default)]
pub struct RustEngineMetrics {
    embedding_requests_total: AtomicU64,
    embedding_failures_total: AtomicU64,
    vector_search_requests_total: AtomicU64,
    vector_search_failures_total: AtomicU64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedTenant {
    organization_id: String,
}

#[derive(Debug, PartialEq, Eq)]
struct MetricsHttpResponse {
    status: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}

#[tonic::async_trait]
impl ScriptureEngine for MyScriptureEngine {
    async fn process_text_embedding(
        &self,
        request: Request<EmbedTextRequest>,
    ) -> Result<Response<EmbedTextResponse>, Status> {
        self.metrics
            .embedding_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let trace_id = traceparent_from_request(&request);
        let organization_id =
            resolve_organization_id(&request, &request.get_ref().organization_id)?;
        let req = request.into_inner();
        validate_embed_text_request(&req)?;
        emit_log(
            "info",
            "process_text_embedding_requested",
            &[
                ("trace_id", trace_id),
                ("organization_id", organization_id.clone()),
                ("book", req.book.clone()),
                ("chapter", req.chapter.to_string()),
                ("verse", req.verse.to_string()),
            ],
        );

        let pool = &self.db_pool;
        if pool.is_closed() {
            self.metrics
                .embedding_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "process_text_embedding_failed",
                &[
                    ("organization_id", req.organization_id.clone()),
                    ("error", "database_pool_closed".to_string()),
                ],
            );
            return Err(Status::internal("Database pool is closed"));
        }

        let embedding = Vector::from(req.embedding.clone());
        let mut transaction = pool.begin().await.map_err(|error| {
            self.metrics
                .embedding_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "process_text_embedding_failed",
                &[
                    ("organization_id", organization_id.clone()),
                    ("error", format!("database_transaction_begin: {error}")),
                ],
            );
            Status::internal("Database write failed")
        })?;

        set_tenant_context(&mut transaction, &organization_id)
            .await
            .map_err(|error| {
                self.metrics
                    .embedding_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                emit_log(
                    "error",
                    "process_text_embedding_failed",
                    &[
                        ("organization_id", organization_id.clone()),
                        ("error", format!("tenant_context: {error}")),
                    ],
                );
                Status::internal("Database write failed")
            })?;

        let row = sqlx::query(
            "INSERT INTO scripture_texts
                (organization_id, book, chapter, verse, content, embedding)
             VALUES ($1::uuid, $2, $3, $4, $5, $6)
             ON CONFLICT (organization_id, book, chapter, verse)
             DO UPDATE SET
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding,
                updated_at = CURRENT_TIMESTAMP
             RETURNING id::text AS id",
        )
        .bind(&organization_id)
        .bind(&req.book)
        .bind(req.chapter)
        .bind(req.verse)
        .bind(&req.text_content)
        .bind(embedding)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            self.metrics
                .embedding_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "process_text_embedding_failed",
                &[
                    ("organization_id", organization_id.clone()),
                    ("error", format!("database_insert: {error}")),
                ],
            );
            Status::internal("Database write failed")
        })?;

        let reference_id: String = row.try_get("id").map_err(|error| {
            self.metrics
                .embedding_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "process_text_embedding_failed",
                &[
                    ("organization_id", organization_id.clone()),
                    ("error", format!("database_reference: {error}")),
                ],
            );
            Status::internal("Database write failed")
        })?;

        transaction.commit().await.map_err(|error| {
            self.metrics
                .embedding_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "process_text_embedding_failed",
                &[
                    ("organization_id", organization_id.clone()),
                    ("error", format!("database_transaction_commit: {error}")),
                ],
            );
            Status::internal("Database write failed")
        })?;

        let reply = EmbedTextResponse {
            reference_id,
            success: true,
            error_message: "".into(),
        };

        Ok(Response::new(reply))
    }

    async fn search_by_vector(
        &self,
        request: Request<VectorSearchRequest>,
    ) -> Result<Response<VectorSearchResponse>, Status> {
        self.metrics
            .vector_search_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let trace_id = traceparent_from_request(&request);
        let organization_id =
            resolve_organization_id(&request, &request.get_ref().organization_id)?;
        let req = request.into_inner();
        emit_log(
            "info",
            "search_by_vector_requested",
            &[
                ("trace_id", trace_id.clone()),
                ("organization_id", organization_id.clone()),
                ("top_k_results", req.top_k_results.to_string()),
                (
                    "minimum_similarity_threshold",
                    req.minimum_similarity_threshold.to_string(),
                ),
            ],
        );

        if let Err(status) = validate_vector_search_request(&req) {
            self.metrics
                .vector_search_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "warn",
                "search_by_vector_rejected",
                &[
                    ("trace_id", trace_id.clone()),
                    ("organization_id", organization_id.clone()),
                    ("error", status.message().to_string()),
                ],
            );
            return Err(status);
        }

        // Execute tenant-scoped vector search via pgvector using the HNSW index.
        let pool = &self.db_pool;
        if pool.is_closed() {
            self.metrics
                .vector_search_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(Status::internal("Database pool is closed"));
        }
        let query_vector = Vector::from(req.query_vector.clone());
        let mut transaction = pool.begin().await.map_err(|error| {
            self.metrics
                .vector_search_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "search_by_vector_failed",
                &[
                    ("trace_id", trace_id.clone()),
                    ("organization_id", organization_id.clone()),
                    ("error", format!("database_transaction_begin: {error}")),
                ],
            );
            Status::internal("Database query failed")
        })?;
        set_tenant_context(&mut transaction, &organization_id)
            .await
            .map_err(|error| {
                self.metrics
                    .vector_search_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                emit_log(
                    "error",
                    "search_by_vector_failed",
                    &[
                        ("trace_id", trace_id.clone()),
                        ("organization_id", organization_id.clone()),
                        ("error", format!("tenant_context: {error}")),
                    ],
                );
                Status::internal("Database query failed")
            })?;
        let rows = sqlx::query(
            "SELECT book, chapter, verse, content, 1 - (embedding <=> $1::vector) as similarity
             FROM scripture_texts
             WHERE organization_id = $2::uuid AND 1 - (embedding <=> $1::vector) >= $4
             ORDER BY embedding <=> $1::vector
             LIMIT $3",
        )
        .bind(query_vector)
        .bind(organization_id.clone())
        .bind(req.top_k_results)
        .bind(req.minimum_similarity_threshold)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|e| {
            self.metrics
                .vector_search_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "search_by_vector_failed",
                &[
                    ("trace_id", trace_id.clone()),
                    ("organization_id", organization_id.clone()),
                    ("error", e.to_string()),
                ],
            );
            Status::internal("Database query failed")
        })?;

        transaction.commit().await.map_err(|error| {
            self.metrics
                .vector_search_failures_total
                .fetch_add(1, Ordering::Relaxed);
            emit_log(
                "error",
                "search_by_vector_failed",
                &[
                    ("trace_id", trace_id.clone()),
                    ("organization_id", organization_id.clone()),
                    ("error", format!("database_transaction_commit: {error}")),
                ],
            );
            Status::internal("Database query failed")
        })?;

        let mut results = Vec::new();

        for row in rows {
            use sqlx::Row;
            results.push(SearchResult {
                book: row.get("book"),
                chapter: row.get("chapter"),
                verse: row.get("verse"),
                text_content: row.get("content"),
                similarity_score: row.get::<f64, _>("similarity") as f32,
            });
        }

        let reply = VectorSearchResponse { results };
        Ok(Response::new(reply))
    }
}

fn requires_grpc_security() -> bool {
    requires_grpc_security_for_environment(
        &std::env::var("DEPLOYMENT_ENVIRONMENT").unwrap_or_default(),
    )
}

fn requires_grpc_security_for_environment(environment: &str) -> bool {
    match environment.trim().to_ascii_lowercase().as_str() {
        "development" | "dev" | "test" | "local" => false,
        _ => true,
    }
}

fn grpc_shared_secret() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let secret = std::env::var("GRPC_ENGINE_SHARED_SECRET")
        .unwrap_or_default()
        .trim()
        .to_string();
    if secret.is_empty() {
        if requires_grpc_security() {
            return Err("GRPC_ENGINE_SHARED_SECRET is required in staging/production".into());
        }
        return Ok(None);
    }
    if secret.len() < 32 {
        return Err("GRPC_ENGINE_SHARED_SECRET must be at least 32 bytes".into());
    }
    Ok(Some(secret))
}

fn grpc_tls_config() -> Result<Option<ServerTlsConfig>, Box<dyn std::error::Error>> {
    let certificate = std::env::var("GRPC_ENGINE_TLS_CERT_PEM").unwrap_or_default();
    let private_key = std::env::var("GRPC_ENGINE_TLS_KEY_PEM").unwrap_or_default();
    let client_ca = std::env::var("GRPC_ENGINE_TLS_CA_PEM").unwrap_or_default();
    let configured = [
        certificate.as_str(),
        private_key.as_str(),
        client_ca.as_str(),
    ]
    .iter()
    .any(|value| !value.trim().is_empty());

    if !configured {
        if requires_grpc_security() {
            return Err(
                "GRPC_ENGINE_TLS_CERT_PEM, GRPC_ENGINE_TLS_KEY_PEM, and GRPC_ENGINE_TLS_CA_PEM are required in staging/production".into(),
            );
        }
        return Ok(None);
    }

    if certificate.trim().is_empty() || private_key.trim().is_empty() || client_ca.trim().is_empty()
    {
        return Err(
            "GRPC_ENGINE_TLS_CERT_PEM, GRPC_ENGINE_TLS_KEY_PEM, and GRPC_ENGINE_TLS_CA_PEM must be configured together".into(),
        );
    }

    Ok(Some(
        ServerTlsConfig::new()
            .identity(Identity::from_pem(certificate, private_key))
            .client_ca_root(Certificate::from_pem(client_ca)),
    ))
}

fn validate_database_url_transport(
    database_url: &str,
    require_tls: bool,
) -> Result<(), &'static str> {
    if !require_tls {
        return Ok(());
    }

    let options = PgConnectOptions::from_str(database_url).map_err(|_| {
        "DATABASE_URL must be a valid PostgreSQL URL with TLS in staging/production"
    })?;
    match options.get_ssl_mode() {
        PgSslMode::Require | PgSslMode::VerifyCa | PgSslMode::VerifyFull => Ok(()),
        _ => Err("DATABASE_URL must set sslmode=require, verify-ca, or verify-full in staging/production"),
    }
}

fn authorize_grpc_request(
    mut request: Request<()>,
    shared_secret: Option<&str>,
) -> Result<Request<()>, Status> {
    let Some(expected_secret) = shared_secret else {
        return Ok(request);
    };

    let expected_header = format!("Bearer {expected_secret}");
    let provided_header = request
        .metadata()
        .get(GRPC_AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok());
    if provided_header != Some(expected_header.as_str()) {
        return Err(Status::unauthenticated("invalid gRPC service credentials"));
    }

    let organization_id = request
        .metadata()
        .get(GRPC_TENANT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Status::permission_denied("authenticated tenant metadata is required"))?
        .to_string();
    validate_organization_id(&organization_id)?;
    request
        .extensions_mut()
        .insert(AuthenticatedTenant { organization_id });
    Ok(request)
}

fn validate_organization_id(value: &str) -> Result<(), Status> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_ORGANIZATION_ID_BYTES
        || trimmed.chars().any(|character| character.is_control())
    {
        return Err(Status::invalid_argument("organization_id is invalid"));
    }
    Ok(())
}

fn resolve_organization_id<T>(request: &Request<T>, payload_value: &str) -> Result<String, Status> {
    validate_organization_id(payload_value)?;
    let payload_value = payload_value.trim();
    if let Some(authenticated) = request.extensions().get::<AuthenticatedTenant>() {
        if authenticated.organization_id != payload_value {
            return Err(Status::permission_denied(
                "organization_id does not match authenticated tenant",
            ));
        }
        return Ok(authenticated.organization_id.clone());
    }
    Ok(payload_value.to_string())
}

fn validate_embed_text_request(request: &EmbedTextRequest) -> Result<(), Status> {
    validate_organization_id(&request.organization_id)?;
    if request.book.trim().is_empty() || request.book.len() > MAX_BOOK_BYTES {
        return Err(Status::invalid_argument("book is invalid"));
    }
    if request.text_content.trim().is_empty() {
        return Err(Status::invalid_argument("text_content is required"));
    }
    if request.text_content.len() > MAX_TEXT_CONTENT_BYTES {
        return Err(Status::resource_exhausted(
            "text_content exceeds the configured limit",
        ));
    }
    if request.chapter < 1 || request.verse < 1 {
        return Err(Status::invalid_argument(
            "chapter and verse must be positive",
        ));
    }
    if request.embedding.len() != EMBEDDING_DIMENSION {
        return Err(Status::invalid_argument(format!(
            "embedding must contain exactly {} dimensions",
            EMBEDDING_DIMENSION
        )));
    }
    if request.embedding.iter().any(|value| !value.is_finite()) {
        return Err(Status::invalid_argument(
            "embedding must contain only finite values",
        ));
    }
    Ok(())
}

async fn set_tenant_context(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(organization_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = bind_address()?;
    let metrics_addr = metrics_address()?;
    let observability = observability_config();
    let grpc_shared_secret = grpc_shared_secret()?;
    let grpc_tls_config = grpc_tls_config()?;

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required for the scripture engine")?;
    if database_url.trim().is_empty() {
        return Err("DATABASE_URL must not be empty".into());
    }
    validate_database_url_transport(&database_url, requires_grpc_security())?;

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let metrics = Arc::new(RustEngineMetrics::default());
    let metrics_task_metrics = Arc::clone(&metrics);
    tokio::spawn(async move {
        if let Err(error) = run_metrics_server(metrics_addr, metrics_task_metrics).await {
            emit_log(
                "error",
                "rust_metrics_server_failed",
                &[
                    ("bind_address", metrics_addr.to_string()),
                    ("error", error.to_string()),
                ],
            );
        }
    });

    let engine = MyScriptureEngine { db_pool, metrics };
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ScriptureEngineServer<MyScriptureEngine>>()
        .await;

    emit_log(
        "info",
        "scripture_engine_starting",
        &[
            ("bind_address", addr.to_string()),
            ("metrics_address", metrics_addr.to_string()),
            ("service_name", observability.service_name),
            ("service_version", observability.service_version),
            (
                "deployment_environment",
                observability.deployment_environment,
            ),
            (
                "otel_exporter_otlp_endpoint",
                observability.otel_exporter_otlp_endpoint,
            ),
        ],
    );

    let protected_service = ScriptureEngineServer::with_interceptor(engine, move |request| {
        authorize_grpc_request(request, grpc_shared_secret.as_deref())
    });
    let mut server = Server::builder()
        .max_frame_size(MAX_GRPC_MESSAGE_BYTES as u32)
        .max_concurrent_streams(128);
    if let Some(tls_config) = grpc_tls_config {
        server = server.tls_config(tls_config)?;
    }
    server
        .add_service(health_service)
        .add_service(protected_service)
        .serve(addr)
        .await?;

    Ok(())
}

fn bind_address() -> Result<SocketAddr, std::net::AddrParseError> {
    std::env::var("RUST_ENGINE_BIND_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
}

fn metrics_address() -> Result<SocketAddr, std::net::AddrParseError> {
    std::env::var("RUST_ENGINE_METRICS_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:9102".to_string())
        .parse()
}

fn metrics_read_timeout() -> Duration {
    let configured = std::env::var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_METRICS_READ_TIMEOUT);
    if configured < MIN_METRICS_READ_TIMEOUT {
        return MIN_METRICS_READ_TIMEOUT;
    }
    if configured > MAX_METRICS_READ_TIMEOUT {
        return MAX_METRICS_READ_TIMEOUT;
    }
    configured
}

fn scripture_engine_service_name() -> &'static str {
    <ScriptureEngineServer<MyScriptureEngine> as NamedService>::NAME
}

fn validate_vector_search_request(req: &VectorSearchRequest) -> Result<(), Status> {
    if req.organization_id.trim().is_empty() {
        return Err(Status::invalid_argument("organization_id is required"));
    }
    if req.query_vector.len() != EMBEDDING_DIMENSION {
        return Err(Status::invalid_argument(format!(
            "query_vector must contain exactly {} dimensions",
            EMBEDDING_DIMENSION
        )));
    }
    if req.query_vector.iter().any(|value| !value.is_finite()) {
        return Err(Status::invalid_argument(
            "query_vector must contain only finite values",
        ));
    }
    if req.top_k_results < 1 || req.top_k_results > MAX_VECTOR_SEARCH_RESULTS {
        return Err(Status::invalid_argument(format!(
            "top_k_results must be between 1 and {}",
            MAX_VECTOR_SEARCH_RESULTS
        )));
    }
    if !req.minimum_similarity_threshold.is_finite()
        || !(0.0..=1.0).contains(&req.minimum_similarity_threshold)
    {
        return Err(Status::invalid_argument(
            "minimum_similarity_threshold must be between 0 and 1",
        ));
    }
    Ok(())
}

impl RustEngineMetrics {
    fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# HELP scriptureforge_rust_engine_embedding_requests_total Total embedding requests handled by the Rust scripture engine.\n",
                "# TYPE scriptureforge_rust_engine_embedding_requests_total counter\n",
                "scriptureforge_rust_engine_embedding_requests_total {}\n",
                "# HELP scriptureforge_rust_engine_embedding_failures_total Total embedding request failures in the Rust scripture engine.\n",
                "# TYPE scriptureforge_rust_engine_embedding_failures_total counter\n",
                "scriptureforge_rust_engine_embedding_failures_total {}\n",
                "# HELP scriptureforge_rust_engine_vector_search_requests_total Total vector search requests handled by the Rust scripture engine.\n",
                "# TYPE scriptureforge_rust_engine_vector_search_requests_total counter\n",
                "scriptureforge_rust_engine_vector_search_requests_total {}\n",
                "# HELP scriptureforge_rust_engine_vector_search_failures_total Total vector search request failures in the Rust scripture engine.\n",
                "# TYPE scriptureforge_rust_engine_vector_search_failures_total counter\n",
                "scriptureforge_rust_engine_vector_search_failures_total {}\n"
            ),
            self.embedding_requests_total.load(Ordering::Relaxed),
            self.embedding_failures_total.load(Ordering::Relaxed),
            self.vector_search_requests_total.load(Ordering::Relaxed),
            self.vector_search_failures_total.load(Ordering::Relaxed)
        )
    }
}

fn metrics_response_for_request(request: &str, metrics: &RustEngineMetrics) -> MetricsHttpResponse {
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    if path == "/healthz" {
        return match method {
            "GET" => MetricsHttpResponse {
                status: "200 OK",
                headers: vec![],
                body: "ok\n".to_string(),
            },
            "HEAD" => MetricsHttpResponse {
                status: "200 OK",
                headers: vec![],
                body: String::new(),
            },
            _ => MetricsHttpResponse {
                status: "405 Method Not Allowed",
                headers: vec![("Allow", "GET, HEAD")],
                body: "method not allowed\n".to_string(),
            },
        };
    }

    if path != "/metrics" {
        return MetricsHttpResponse {
            status: "404 Not Found",
            headers: vec![],
            body: "not found\n".to_string(),
        };
    }

    match method {
        "GET" => MetricsHttpResponse {
            status: "200 OK",
            headers: vec![],
            body: metrics.render_prometheus(),
        },
        "HEAD" => MetricsHttpResponse {
            status: "200 OK",
            headers: vec![],
            body: String::new(),
        },
        _ => MetricsHttpResponse {
            status: "405 Method Not Allowed",
            headers: vec![("Allow", "GET, HEAD")],
            body: "method not allowed\n".to_string(),
        },
    }
}

async fn run_metrics_server(
    addr: SocketAddr,
    metrics: Arc<RustEngineMetrics>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    emit_log(
        "info",
        "rust_metrics_server_listening",
        &[("bind_address", addr.to_string())],
    );
    let read_timeout = metrics_read_timeout();

    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            let request = match timeout(read_timeout, stream.read(&mut buffer)).await {
                Ok(Ok(size)) => String::from_utf8_lossy(&buffer[..size]).to_string(),
                Ok(Err(error)) if error.kind() == ErrorKind::UnexpectedEof => String::new(),
                Ok(Err(_)) | Err(_) => return,
            };
            let response = metrics_response_for_request(&request, metrics.as_ref());
            let extra_headers = response
                .headers
                .iter()
                .map(|(name, value)| format!("{}: {}\r\n", name, value))
                .collect::<String>();
            let response = format!(
				"HTTP/1.1 {}\r\nContent-Type: text/plain; version=0.0.4\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
				response.status,
				extra_headers,
				response.body.as_bytes().len(),
				response.body
			);
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ObservabilityConfig {
    service_name: String,
    service_version: String,
    deployment_environment: String,
    otel_exporter_otlp_endpoint: String,
}

fn observability_config() -> ObservabilityConfig {
    ObservabilityConfig {
        service_name: std::env::var("OTEL_SERVICE_NAME")
            .unwrap_or_else(|_| "scriptureforge-rust-engine".to_string()),
        service_version: std::env::var("SERVICE_VERSION")
            .unwrap_or_else(|_| "unversioned".to_string()),
        deployment_environment: std::env::var("DEPLOYMENT_ENVIRONMENT")
            .unwrap_or_else(|_| "local".to_string()),
        otel_exporter_otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_default(),
    }
}

fn traceparent_from_request<T>(request: &Request<T>) -> String {
    request
        .metadata()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .map(extract_trace_id)
        .unwrap_or_default()
}

fn extract_trace_id(traceparent: &str) -> String {
    traceparent
        .split('-')
        .nth(1)
        .filter(|trace_id| trace_id.len() == 32)
        .unwrap_or("")
        .to_string()
}

fn emit_log(level: &str, event: &str, fields: &[(&str, String)]) {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();

    let mut log = format!(
        "{{\"timestamp_ms\":{},\"level\":\"{}\",\"event\":\"{}\"",
        timestamp_ms,
        json_escape(level),
        json_escape(event)
    );
    for (key, value) in fields {
        log.push_str(&format!(
            ",\"{}\":\"{}\"",
            json_escape(key),
            json_escape(value)
        ));
    }
    log.push('}');
    println!("{}", log);
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::scriptureforge::engine::scripture_engine_client::ScriptureEngineClient;
    use super::scriptureforge::engine::scripture_engine_server::ScriptureEngineServer;
    use super::scriptureforge::engine::{
        EmbedTextRequest, EmbedTextResponse, SearchResult, VectorSearchRequest,
        VectorSearchResponse,
    };
    use super::{
        authorize_grpc_request, bind_address, extract_trace_id, grpc_shared_secret,
        grpc_tls_config, json_escape, metrics_address, metrics_read_timeout,
        metrics_response_for_request, observability_config, requires_grpc_security_for_environment,
        resolve_organization_id, scripture_engine_service_name, traceparent_from_request,
        validate_database_url_transport, validate_embed_text_request,
        validate_vector_search_request, AuthenticatedTenant, RustEngineMetrics,
        DEFAULT_METRICS_READ_TIMEOUT, EMBEDDING_DIMENSION, MAX_METRICS_READ_TIMEOUT,
        MAX_VECTOR_SEARCH_RESULTS, MIN_METRICS_READ_TIMEOUT,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tonic::Request;

    #[test]
    fn database_url_transport_requires_tls_only_in_strict_environments() {
        for database_url in [
            "postgres://user:password@db.example/scriptureforge?sslmode=require",
            "postgresql://user:password@db.example/scriptureforge?sslmode=verify-ca",
            "postgres://user:password@db.example/scriptureforge?sslmode=verify-full",
        ] {
            assert!(validate_database_url_transport(database_url, true).is_ok());
        }

        for database_url in [
            "postgres://user:password@db.example/scriptureforge",
            "postgres://user:password@db.example/scriptureforge?sslmode=disable",
            "postgres://user:password@db.example/scriptureforge?sslmode=prefer",
            "not-a-url",
        ] {
            assert!(validate_database_url_transport(database_url, true).is_err());
        }
        assert!(
            validate_database_url_transport("postgres://local.example/scriptureforge", false)
                .is_ok()
        );
    }

    #[test]
    fn generated_protobuf_types_compile_and_round_trip() {
        let request = EmbedTextRequest {
            organization_id: "00000000-0000-0000-0000-000000000001".into(),
            book: "John".into(),
            chapter: 1,
            verse: 1,
            text_content: "In the beginning was the Word".into(),
            embedding: vec![0.0; EMBEDDING_DIMENSION],
        };

        let response = EmbedTextResponse {
            reference_id: format!("{}-{}-{}", request.book, request.chapter, request.verse),
            success: true,
            error_message: String::new(),
        };

        assert_eq!(response.reference_id, "John-1-1");
        assert!(response.success);
    }

    #[test]
    fn generated_vector_search_response_holds_results() {
        let response = VectorSearchResponse {
            results: vec![SearchResult {
                book: "Romans".into(),
                chapter: 8,
                verse: 1,
                text_content: "There is therefore now no condemnation".into(),
                similarity_score: 0.97,
            }],
        };

        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].book, "Romans");
    }

    #[test]
    fn generated_grpc_client_and_server_types_compile() {
        let client_type = std::any::type_name::<ScriptureEngineClient<tonic::transport::Channel>>();
        let server_type = std::any::type_name::<ScriptureEngineServer<super::MyScriptureEngine>>();

        assert!(client_type.contains("ScriptureEngineClient"));
        assert!(server_type.contains("ScriptureEngineServer"));
        assert_eq!(
            scripture_engine_service_name(),
            "scriptureforge.engine.ScriptureEngine"
        );
    }

    #[test]
    fn vector_search_request_rejects_unbounded_or_invalid_inputs() {
        let valid = VectorSearchRequest {
            organization_id: "00000000-0000-0000-0000-000000000001".into(),
            query_vector: vec![0.0; EMBEDDING_DIMENSION],
            top_k_results: 10,
            minimum_similarity_threshold: 0.5,
        };

        assert!(validate_vector_search_request(&valid).is_ok());

        let mut missing_org = valid.clone();
        missing_org.organization_id = " ".into();
        assert!(validate_vector_search_request(&missing_org).is_err());

        let mut wrong_dimension = valid.clone();
        wrong_dimension.query_vector.pop();
        assert!(validate_vector_search_request(&wrong_dimension).is_err());

        let mut non_finite_vector = valid.clone();
        non_finite_vector.query_vector[0] = f32::NAN;
        assert!(validate_vector_search_request(&non_finite_vector).is_err());

        let mut zero_top_k = valid.clone();
        zero_top_k.top_k_results = 0;
        assert!(validate_vector_search_request(&zero_top_k).is_err());

        let mut excessive_top_k = valid.clone();
        excessive_top_k.top_k_results = MAX_VECTOR_SEARCH_RESULTS + 1;
        assert!(validate_vector_search_request(&excessive_top_k).is_err());

        let mut bad_threshold = valid;
        bad_threshold.minimum_similarity_threshold = 1.1;
        assert!(validate_vector_search_request(&bad_threshold).is_err());
    }

    #[test]
    fn grpc_authentication_requires_service_secret_and_binds_tenant() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            "Bearer 01234567890123456789012345678901"
                .parse()
                .expect("authorization metadata should parse"),
        );
        request.metadata_mut().insert(
            "x-scriptureforge-organization-id",
            "org-a".parse().expect("tenant metadata should parse"),
        );

        let authorized = authorize_grpc_request(request, Some("01234567890123456789012345678901"))
            .expect("valid service credentials should authorize");
        assert_eq!(
            authorized
                .extensions()
                .get::<AuthenticatedTenant>()
                .expect("tenant context should be attached")
                .organization_id,
            "org-a"
        );

        let mismatch = Request::new(EmbedTextRequest {
            organization_id: "org-b".into(),
            book: "John".into(),
            chapter: 1,
            verse: 1,
            text_content: "text".into(),
            embedding: vec![0.0; EMBEDDING_DIMENSION],
        });
        let mut mismatch = mismatch;
        mismatch.extensions_mut().insert(AuthenticatedTenant {
            organization_id: "org-a".into(),
        });
        assert!(resolve_organization_id(&mismatch, &mismatch.get_ref().organization_id).is_err());
    }

    #[test]
    fn grpc_authentication_rejects_invalid_credentials() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            "Bearer wrong-secret"
                .parse()
                .expect("authorization metadata should parse"),
        );
        assert!(
            authorize_grpc_request(request, Some("expected-secret".repeat(4).as_str())).is_err()
        );
    }

    #[test]
    fn embed_request_validation_bounds_text_and_coordinates() {
        let valid = EmbedTextRequest {
            organization_id: "org-a".into(),
            book: "John".into(),
            chapter: 1,
            verse: 1,
            text_content: "text".into(),
            embedding: vec![0.0; EMBEDDING_DIMENSION],
        };
        assert!(validate_embed_text_request(&valid).is_ok());

        let mut oversized = valid.clone();
        oversized.text_content = "x".repeat(super::MAX_TEXT_CONTENT_BYTES + 1);
        assert!(validate_embed_text_request(&oversized).is_err());

        let mut invalid_coordinates = valid;
        invalid_coordinates.chapter = 0;
        assert!(validate_embed_text_request(&invalid_coordinates).is_err());

        let mut wrong_dimension = EmbedTextRequest {
            organization_id: "org-a".into(),
            book: "John".into(),
            chapter: 1,
            verse: 1,
            text_content: "text".into(),
            embedding: vec![0.0; EMBEDDING_DIMENSION - 1],
        };
        assert!(validate_embed_text_request(&wrong_dimension).is_err());
        wrong_dimension.embedding = vec![0.0; EMBEDDING_DIMENSION];
        wrong_dimension.embedding[0] = f32::NAN;
        assert!(validate_embed_text_request(&wrong_dimension).is_err());

        let mut empty_text = wrong_dimension;
        empty_text.embedding[0] = 0.0;
        empty_text.text_content = " ".into();
        assert!(validate_embed_text_request(&empty_text).is_err());
    }

    #[test]
    fn grpc_security_config_is_optional_only_for_local_development() {
        std::env::remove_var("GRPC_ENGINE_SHARED_SECRET");
        std::env::remove_var("GRPC_ENGINE_TLS_CERT_PEM");
        std::env::remove_var("GRPC_ENGINE_TLS_KEY_PEM");
        std::env::remove_var("GRPC_ENGINE_TLS_CA_PEM");
        std::env::set_var("DEPLOYMENT_ENVIRONMENT", "local");

        assert!(grpc_shared_secret()
            .expect("local security config should load")
            .is_none());
        assert!(grpc_tls_config()
            .expect("local TLS config should load")
            .is_none());

        assert!(requires_grpc_security_for_environment("prod-eu"));
        assert!(requires_grpc_security_for_environment("custom-staging"));
        assert!(!requires_grpc_security_for_environment("development"));
    }

    #[test]
    fn empty_environment_requires_grpc_security() {
        assert!(requires_grpc_security_for_environment(""));
    }

    #[test]
    fn default_bind_address_is_reachable_outside_localhost() {
        std::env::remove_var("RUST_ENGINE_BIND_ADDRESS");
        let addr = bind_address().expect("default bind address should parse");

        assert_eq!(addr.to_string(), "0.0.0.0:50051");
    }

    #[test]
    fn default_metrics_address_is_reachable_outside_localhost() {
        std::env::remove_var("RUST_ENGINE_METRICS_ADDRESS");
        let addr = metrics_address().expect("default metrics address should parse");

        assert_eq!(addr.to_string(), "0.0.0.0:9102");
    }

    #[test]
    fn metrics_read_timeout_is_bounded_and_configurable() {
        std::env::remove_var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS");
        assert_eq!(metrics_read_timeout(), DEFAULT_METRICS_READ_TIMEOUT);

        std::env::set_var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS", "25");
        assert_eq!(metrics_read_timeout(), MIN_METRICS_READ_TIMEOUT);

        std::env::set_var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS", "9000");
        assert_eq!(metrics_read_timeout(), Duration::from_secs(9));

        std::env::set_var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS", "60000");
        assert_eq!(metrics_read_timeout(), MAX_METRICS_READ_TIMEOUT);

        std::env::set_var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS", "invalid");
        assert_eq!(metrics_read_timeout(), DEFAULT_METRICS_READ_TIMEOUT);
        std::env::remove_var("RUST_ENGINE_METRICS_READ_TIMEOUT_MS");
    }

    #[test]
    fn scripture_engine_health_service_name_matches_grpc_service() {
        assert_eq!(
            scripture_engine_service_name(),
            "scriptureforge.engine.ScriptureEngine"
        );
    }

    #[test]
    fn default_observability_config_is_staging_safe() {
        std::env::remove_var("OTEL_SERVICE_NAME");
        std::env::remove_var("SERVICE_VERSION");
        std::env::remove_var("DEPLOYMENT_ENVIRONMENT");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");

        let config = observability_config();

        assert_eq!(config.service_name, "scriptureforge-rust-engine");
        assert_eq!(config.service_version, "unversioned");
        assert_eq!(config.deployment_environment, "local");
        assert_eq!(config.otel_exporter_otlp_endpoint, "");
    }

    #[test]
    fn traceparent_metadata_extracts_trace_id() {
        let mut request = Request::new(EmbedTextRequest {
            organization_id: "00000000-0000-0000-0000-000000000001".into(),
            book: "John".into(),
            chapter: 1,
            verse: 1,
            text_content: "In the beginning was the Word".into(),
            embedding: vec![0.0; EMBEDDING_DIMENSION],
        });
        request.metadata_mut().insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .expect("traceparent metadata should parse"),
        );

        assert_eq!(
            traceparent_from_request(&request),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
    }

    #[test]
    fn malformed_traceparent_does_not_emit_trace_id() {
        assert_eq!(extract_trace_id("not-a-traceparent"), "");
    }

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(
            json_escape("quote\" slash\\ newline\n"),
            "quote\\\" slash\\\\ newline\\n"
        );
    }

    #[test]
    fn rust_engine_metrics_render_prometheus_counters() {
        let metrics = RustEngineMetrics::default();
        metrics.embedding_requests_total.store(2, Ordering::Relaxed);
        metrics.embedding_failures_total.store(1, Ordering::Relaxed);
        metrics
            .vector_search_requests_total
            .store(3, Ordering::Relaxed);
        metrics
            .vector_search_failures_total
            .store(1, Ordering::Relaxed);

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains("scriptureforge_rust_engine_embedding_requests_total 2"));
        assert!(rendered.contains("scriptureforge_rust_engine_embedding_failures_total 1"));
        assert!(rendered.contains("scriptureforge_rust_engine_vector_search_requests_total 3"));
        assert!(rendered.contains("scriptureforge_rust_engine_vector_search_failures_total 1"));
    }

    #[test]
    fn metrics_http_response_allows_get_and_head_only() {
        let metrics = RustEngineMetrics::default();
        metrics.embedding_requests_total.store(2, Ordering::Relaxed);

        let get = metrics_response_for_request("GET /metrics HTTP/1.1\r\n\r\n", &metrics);
        assert_eq!(get.status, "200 OK");
        assert!(get
            .body
            .contains("scriptureforge_rust_engine_embedding_requests_total 2"));

        let head = metrics_response_for_request("HEAD /metrics HTTP/1.1\r\n\r\n", &metrics);
        assert_eq!(head.status, "200 OK");
        assert_eq!(head.body, "");

        let post = metrics_response_for_request("POST /metrics HTTP/1.1\r\n\r\n", &metrics);
        assert_eq!(post.status, "405 Method Not Allowed");
        assert_eq!(post.headers, vec![("Allow", "GET, HEAD")]);
        assert!(!post
            .body
            .contains("scriptureforge_rust_engine_embedding_requests_total"));

        let health = metrics_response_for_request("GET /healthz HTTP/1.1\r\n\r\n", &metrics);
        assert_eq!(health.status, "200 OK");
        assert_eq!(health.body, "ok\n");

        let wrong_path = metrics_response_for_request("GET /health HTTP/1.1\r\n\r\n", &metrics);
        assert_eq!(wrong_path.status, "404 Not Found");
    }
}
