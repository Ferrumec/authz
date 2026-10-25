use crate::admin::{AbsoluteRepo, AbsoluteViewSet, create_absolute_viewset};
use crate::{handlers::*, models::AppState, services::Service};
use actix_web::web::{self, ServiceConfig};
use ferrumec::{Infra, Module};
use std::sync::Arc;
use viewset::{ViewSet, web::SessionMiddleware};

#[derive(Clone)]
pub struct AuthorizModule {
    state: web::Data<AppState>,
    absolute_viewset: Arc<AbsoluteViewSet>,
    middleware: Arc<SessionMiddleware>,
}

impl Module for AuthorizModule {
    /// Builds the module, constructing a single [`AbsoluteRepo`] (via `cf`)
    /// that is shared between the grant/deny business logic ([`Service`])
    /// and the `/admin/grants` viewset, so both see the same cache.
    async fn new(infra: impl Infra) -> Result<Self, Box<dyn std::error::Error>> {
        let db = infra.clone().database();
        let cf = infra.cache_factory();
        let absolute_repo = Arc::new(AbsoluteRepo::new(db.clone(), cf.clone()));
        let middleware = Arc::new(SessionMiddleware::new(cf.clone()));
        Ok(Self {
            middleware,
            state: web::Data::new(AppState {
                service: Service::new(db, cf.clone()),
            }),
            absolute_viewset: create_absolute_viewset(absolute_repo),
        })
    }

    /// `claim_admin` stays outside the Permissions gate so any logged-in user
    /// can attempt it (and receive 404 / 406 when they are not the configured
    /// ADMIN). Grant / deny / grants viewset remain permission-checked.
    fn configure(self: Arc<Self>, cfg: &mut ServiceConfig, namespace: &str) {
        cfg.service(
            web::scope(namespace)
                .wrap(self.middleware.clone())
                .app_data(self.state.clone())
                .service(claim_permission)
                .service(
                    web::scope("")
                        .service(grant_permission)
                        .service(deny_permission)
                        .service(web::scope("admin").configure(|cfg| {
                            self.absolute_viewset.clone().configure(cfg, "grants")
                        })),
                ),
        );
    }
}
