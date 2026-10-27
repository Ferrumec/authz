use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use std::sync::Arc;
use uuid::Uuid;
use viewset::{DefaultRepo, DefaultViewSet, Entity, Service};

#[derive(FromRow, Deserialize, Serialize, Clone, Entity)]
#[entity(table = "grants", create = "NewAbsolute", update = "UpdateAbsolute")]
pub struct Absolute {
    #[entity(skip_update, skip_create)]
    pub id: Uuid,
    #[entity(skip_update, filterable)]
    pub to_id: Uuid,
    /// Represent u128 permission bit map, represented as str since some db do not support u128
    pub role: Uuid,
    #[entity(skip_update, filterable)]
    pub namespace: Uuid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NewAbsolute {
    pub to_id: Uuid,
    /// Represent u128 permission bit map, represented as str since some db do not support u128
    pub role: Uuid,
    pub namespace: Uuid,
}

impl Absolute {
    pub(crate) fn grant(&self, perm_value: Uuid) -> UpdateAbsolute {
        let current = self.role.as_u128();
        let new = current | perm_value.as_u128();
        UpdateAbsolute {
            role: Some(Uuid::from_u128(new)),
        }
    }

    pub(crate) fn deny(&self, perm_value: Uuid) -> UpdateAbsolute {
        let current = self.role.as_u128();
        let new = current & !perm_value.as_u128();
        UpdateAbsolute {
            role: Some(Uuid::from_u128(new)),
        }
    }

    pub(crate) fn has(&self, value: Uuid) -> bool {
        let value = value.as_u128();
        self.role.as_u128() & value == value
    }
}

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

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateAbsolute {
    pub role: Option<Uuid>,
}

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
