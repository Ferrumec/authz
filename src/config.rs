use crate::admin::{AbsoluteRepo, AbsoluteViewSet, create_absolute_viewset};
use crate::{handlers::*, models::AppState, services::Service};
use actix_web::web::{self, ServiceConfig};
use ferrumec::cache::CacheFactory;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use viewset::ViewSet;

#[derive(Clone)]
pub struct AuthorizModule {
    state: web::Data<AppState>,
    absolute_viewset: Arc<AbsoluteViewSet>,
}

impl AuthorizModule {
    /// Builds the module, constructing a single [`AbsoluteRepo`] (via `cf`)
    /// that is shared between the grant/deny business logic ([`Service`])
    /// and the `/admin/grants` viewset, so both see the same cache.
    pub fn new<Cf: CacheFactory + 'static>(
        db: Pool<Postgres>,
        cf: Cf,
    ) -> Self {
        let absolute_repo = Arc::new(AbsoluteRepo::new(db.clone(), cf.clone()));
        Self {
            state: web::Data::new(AppState {
                service: Service::new(db, cf.clone()),
            }),
            absolute_viewset: create_absolute_viewset(absolute_repo),
        }
    }

    /// `claim_admin` stays outside the Permissions gate so any logged-in user
    /// can attempt it (and receive 404 / 406 when they are not the configured
    /// ADMIN). Grant / deny / grants viewset remain permission-checked.
    pub fn config(&self, cfg: &mut ServiceConfig, namespace: &str) {
        cfg.service(
            web::scope(namespace)
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
