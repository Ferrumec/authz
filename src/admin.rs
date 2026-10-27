use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use std::sync::Arc;
use uuid::Uuid;
use viewset::{DefaultRepo, DefaultViewSet, Entity, Service};

pub use ferrumec_perms::Absolute;

#[derive(FromRow, Deserialize, Serialize, Clone, Entity)]
#[entity(create = "CreateNamespace")]
pub struct Namespace {
    #[entity(skip_create)]
    pub(crate) id: Uuid,
    pub(crate) owner: Uuid,
    pub(crate) name: String,
}

#[derive(Deserialize, Serialize)]
pub struct CreateNamespace {
    pub(crate) owner: Uuid,
    pub(crate) name: String,
}

pub type NamespaceRepo = DefaultRepo<Namespace>;

/// Data access for [`Absolute`] grants, plus its item/list caches.
///
/// Mirrors the pattern used by the groups service's repositories (e.g.
/// `groups::community::CommunityRepository`): caches are built from a
/// [`CacheFactory`] instead of relying on `viewset::DefaultRepo`'s built-in
/// (uncached) behavior. Shared by [`crate::services::Service`] (the
/// grant/deny business logic) and [`AbsoluteViewSet`] (`/admin/grants`) so
/// both see a consistent, cached view of the table.
pub type AbsoluteRepo = DefaultRepo<Absolute>;

/// Adapts [`AbsoluteRepo`] for [`viewset::DefaultViewSet`], exposing plain
/// CRUD over `grants` at `/admin/grants`.
pub struct AbsoluteService {
    repo: Arc<AbsoluteRepo>,
}

impl AbsoluteService {
    pub fn new(repo: Arc<AbsoluteRepo>) -> Self {
        Self { repo }
    }
}

impl Service for AbsoluteService {
    type Repository = AbsoluteRepo;
    fn repository(&self) -> &AbsoluteRepo {
        &self.repo
    }
}

pub type AbsoluteViewSet = DefaultViewSet<AbsoluteService>;

/// Builds the generic admin CRUD viewset over grants, mounted at
/// `/admin/grants` by [`crate::config::AuthorizModule`].
pub fn create_absolute_viewset(repo: Arc<AbsoluteRepo>) -> Arc<AbsoluteViewSet> {
    Arc::new(AbsoluteService::new(repo).into())
}
