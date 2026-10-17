//! Pando server library: feature slices plus the composition root that wires ports
//! to adapters. The binary (`main.rs`) is a thin CLI over [`serve`].

pub mod auth;
pub mod backup;
pub mod config;
pub mod directory;
pub mod features;
pub mod hosting;
pub mod land_hook;
pub mod login;
pub mod oidc;
pub mod permissions;
mod status;
pub mod telemetry;
pub mod webhooks;

use std::future::Future;
use std::sync::Arc;

use pando_core::Repo;
use pando_core::acl::AccessPolicy;
use pando_core::flags::FeatureFlags;
use pando_core::ports::{LandCheck, ObjectStore};
use tokio::net::TcpListener;
use tonic::codegen::http::{HeaderName, HeaderValue, Method};
use tonic::service::{InterceptorLayer, Routes};
use tonic::transport::{Server, ServerTlsConfig};
use tower_http::cors::CorsLayer;

use crate::auth::{AuthInterceptor, Authenticator};
use crate::features::*;

/// All slices, served by the authoritative server.
pub fn authority_routes(
    repo: Repo,
    flags: Arc<dyn FeatureFlags>,
    policy: Arc<dyn AccessPolicy>,
    checks: Arc<dyn LandCheck>,
) -> Routes {
    let f = || flags.clone();
    Routes::new(objects::service(objects::Objects::new(repo.objects.clone(), f(), policy.clone())))
        .add_service(access::service(access::Access::new(f(), policy.clone())))
        .add_service(changesets::service(changesets::Changesets::new(repo.clone(), f(), policy.clone())))
        .add_service(refs::service(refs::Refs::new(repo.clone(), f(), policy.clone())))
        .add_service(land::service(land::Land::new(repo.clone(), f(), policy.clone(), checks)))
        .add_service(locks::service(locks::Locks::new(repo.clone(), f(), policy.clone())))
        .add_service(history::service(history::History::new(repo.clone(), f(), policy.clone())))
        .add_service(diff::service(diff::Diff::new(repo.clone(), f(), policy.clone())))
        .add_service(merge_base::service(merge_base::MergeBase::new(repo.clone(), f())))
        .add_service(browse::service(browse::Browse::new(repo, f(), policy)))
}

/// Objects slice only, served by caches and daemons over a tiered store. Tiers serve
/// objects by id and know no access policy: expose them only to principals with full read
/// access (e.g. build machines), never to path-restricted users.
pub fn tier_routes(store: Arc<dyn ObjectStore>, flags: Arc<dyn FeatureFlags>) -> Routes {
    Routes::new(objects::service(objects::Objects::new(store, flags, Arc::new(pando_core::acl::AllowAllPolicy))))
}

/// Browser access: gRPC-Web (for the web console and other browser clients) and the
/// origins allowed to call the server from another site.
#[derive(Debug, Clone, Default)]
pub struct WebAccess {
    /// Accept gRPC-Web requests (the `web` feature flag).
    pub enabled: bool,
    /// Origins allowed cross-origin, e.g. `https://console.example.com`; `*` allows any (only
    /// for development). Empty: same-origin only.
    pub origins: Vec<String>,
}

impl WebAccess {
    fn cors(&self) -> anyhow::Result<CorsLayer> {
        use tower_http::cors::{AllowOrigin, ExposeHeaders};
        let origin = if self.origins.iter().any(|o| o == "*") {
            AllowOrigin::any()
        } else {
            let list = self.origins.iter().map(|o| o.parse()).collect::<Result<Vec<HeaderValue>, _>>()?;
            AllowOrigin::list(list)
        };
        Ok(CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([Method::POST, Method::OPTIONS])
            .allow_headers([
                HeaderName::from_static("authorization"),
                HeaderName::from_static("content-type"),
                HeaderName::from_static("x-grpc-web"),
                HeaderName::from_static("x-user-agent"),
                HeaderName::from_static("grpc-timeout"),
                HeaderName::from_static("connect-protocol-version"),
                // Names the repository a call is about (multi-repository servers).
                HeaderName::from_static("x-pando-repo"),
            ])
            .expose_headers(ExposeHeaders::list([
                HeaderName::from_static("grpc-status"),
                HeaderName::from_static("grpc-message"),
                HeaderName::from_static("grpc-status-details-bin"),
            ]))
            .max_age(std::time::Duration::from_secs(600)))
    }
}

/// Protection against slow or flooding clients.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest any one call may run (large checkouts stream for a while; the default is generous).
    pub request_timeout: std::time::Duration,
    /// Calls in progress across all connections; beyond this the server answers Unavailable at
    /// once instead of queueing, so clients back off and retry.
    pub max_in_flight: usize,
    /// Concurrent calls on one connection.
    pub per_connection: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { request_timeout: std::time::Duration::from_secs(600), max_in_flight: 4096, per_connection: 256 }
    }
}

/// How a server is exposed: TLS, browser access, limits, and the repositories it hosts.
#[derive(Default)]
pub struct ServeOptions {
    pub tls: Option<ServerTlsConfig>,
    pub web: WebAccess,
    pub limits: Limits,
    /// Many repositories (`--platform`); `None` serves the default repository only.
    pub hosting: Option<Arc<hosting::Hosting>>,
}

/// Serve `routes` with auth, health checks, reflection, metrics and graceful shutdown.
pub async fn serve(
    listener: TcpListener,
    routes: Routes,
    auth: Arc<dyn Authenticator>,
    options: ServeOptions,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let ServeOptions { tls, web, limits, hosting } = options;
    let (health_reporter, health) = tonic_health::server::health_reporter();
    health_reporter.set_service_status("", tonic_health::ServingStatus::Serving).await;
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(pando_proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;
    let mut routes = routes.add_service(health).add_service(reflection);
    // Platform tokens first, then the server's own authentication; everyone gets an account.
    let auth: Arc<dyn Authenticator> = match &hosting {
        Some(h) => Arc::new(permissions::PlatformAuth::new(h.registry.clone(), auth)),
        None => auth,
    };
    if let Some(h) = &hosting {
        tokio::spawn(webhooks::run(h.registry.clone()));
        routes = routes
            .add_service(features::platform::service(features::platform::Platform::new(h.clone())))
            .add_service(features::reviews::service(features::reviews::Reviews::new(h.clone())))
            .add_service(features::issues::service(features::issues::Issues::new(h.clone())));
    }

    let mut builder = Server::builder()
        .timeout(limits.request_timeout)
        .concurrency_limit_per_connection(limits.per_connection)
        .load_shed(true)
        .accept_http1(web.enabled)
        .tcp_nodelay(true)
        .http2_adaptive_window(Some(true))
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)));
    if let Some(tls) = tls {
        builder = builder.tls_config(tls)?;
    }
    // CORS sits outside authentication: browsers send preflight requests without a token.
    builder
        .layer(tower::util::option_layer(web.enabled.then(|| web.cors()).transpose()?))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(limits.max_in_flight))
        // Translates only gRPC-Web requests; plain gRPC passes through untouched. Browsers
        // reach it over HTTP/1.1, which is accepted only when the `web` flag is on.
        .layer(tonic_web::GrpcWebLayer::new())
        .layer(telemetry::MeteredLayer)
        .layer(InterceptorLayer::new(AuthInterceptor(auth)))
        .layer(telemetry::AuditLayer)
        // Innermost: after authentication, so the principal is known before any repository opens.
        .layer(hosting::HostingLayer(hosting))
        .add_routes(routes)
        .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), shutdown)
        .await?;
    Ok(())
}
