use crate::admin::AbsoluteRepo;
use crate::admin::NamespaceRepo;
use crate::admin::NewAbsolute;
use crate::models::PermissionReq;
use ferrumec::Authority;
use ferrumec::cache::{CacheFactory, Store};
use sqlx::{Error as SqlxError, Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;
use viewset::Repository;
use viewset::filters;

#[derive(Clone)]
pub struct Service {
    pub db: Pool<Postgres>,
    pub absolute_repo: Arc<AbsoluteRepo>,
    pub namespace_repo: Arc<NamespaceRepo>,
    pub(crate) session_store: Arc<dyn Store<Uuid, Authority>>,
}

impl Service {
    /// Builds a `Service` with its own freshly-constructed [`AbsoluteRepo`],
    /// caching via `cf`.
    pub fn new(db: Pool<Postgres>, cf: impl CacheFactory) -> Self {
        Self {
            db: db.clone(),
            absolute_repo: Arc::new(AbsoluteRepo::new(db.clone(), cf.clone())),
            namespace_repo: Arc::new(NamespaceRepo::new(db, cf.clone())),
            session_store: cf.new_cache("permission_sessions", std::time::Duration::from_mins(30)),
        }
    }

    pub async fn get_role(&self, to_id: &Uuid, namespace: &Uuid) -> Result<u128, SqlxError> {
        let grant = match self
            .absolute_repo
            .list_one(filters!(namespace, to_id))
            .await
        {
            Ok(r) => r,

            Err(e) => match e {
                SqlxError::RowNotFound => return Ok(0),
                _ => return Err(e),
            },
        };
        Ok(grant.role.as_u128())
    }

    /// Grants `request.target` the permission in `request`, unconditionally.
    /// Callers MUST verify the caller is actually authorized (e.g. via
    /// `is_admin_for`) before calling this — it performs no auth check itself.
    pub async fn admin_grant_permission(
        &self,
        namespace: &Uuid,
        request: PermissionReq,
    ) -> Result<Option<Uuid>, Box<dyn std::error::Error>> {
        let to_id = &request.target;
        let (grants, count) = self.absolute_repo.list(filters!(to_id, namespace)).await?;
        if count > 0 {
            let grant = grants[0].clone();
            let update = grant.grant(request.permission);
            self.absolute_repo.update(&grant.id, update.clone()).await?;
            Ok(update.role)
        } else {
            let grant = NewAbsolute {
                to_id: to_id.clone(),
                namespace: namespace.clone(),
                role: request.permission,
            };
            self.absolute_repo.create(grant.clone()).await?;
            Ok(Some(grant.role))
        }
    }

    /// Revokes the permission in `request` from `request.target`'s absolute role.
    /// Same caveat as `admin_grant_unchecked`: no auth check performed here.
    pub async fn admin_deny_permission(
        &self,
        namespace: &Uuid,
        request: PermissionReq,
    ) -> Result<Option<Uuid>, Box<dyn std::error::Error>> {
        let grant = self
            .absolute_repo
            .list_one(filters!("to_id"=>&request.target,"namespace"=>namespace))
            .await?;
        let update = grant.deny(request.permission);
        self.absolute_repo.update(&grant.id, update.clone()).await?;
        Ok(update.role)
    }

    pub async fn claim(
        &self,
        namespace: Uuid,
        user: Uuid,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let role = match self
            .absolute_repo
            .list_one(filters!("namespace"=>namespace,"to_id"=>user.clone()))
            .await
        {
            Ok(r) => r.role.as_u128(),
            Err(e) => match e {
                SqlxError::RowNotFound => 0,
                _ => return Err(Box::new(e)),
            },
        };

        let authority = Authority {
            namespace,
            role,
            user,
        };
        let id = Uuid::new_v4();
        self.session_store.set(&id, authority).await?;
        Ok(id)
    }

    pub async fn can_grant(
        &self,
        authority: Authority,
        perm_value: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let namespace = self.namespace_repo.retrieve(&authority.namespace).await?;
        if namespace.owner != authority.user {
            return Ok(false);
        }

        let grant = self
            .absolute_repo
            .list_one(filters!("to_id"=>authority.user,"namespace"=>authority.namespace))
            .await?;

        Ok(grant.has(perm_value))
    }
}
