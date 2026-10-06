use crate::admin::AbsoluteRepo;
use crate::models::PermissionReq;
use actixutils::filters;
use actixutils::middleware::Authority;
use ferrumec::cache::{CacheFactory, Store};
use sqlx::{Error as SqlxError, Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;
use viewset::{ApiError, Repository};

#[derive(Clone)]
pub struct Service {
    pub db: Pool<Postgres>,
    pub absolute_repo: Arc<AbsoluteRepo>,
    pub(crate) session_store: Arc<dyn Store<Uuid, Authority>>,
}

impl Service {
    /// Builds a `Service` with its own freshly-constructed [`AbsoluteRepo`],
    /// caching via `cf`.
    pub fn new<Cf: CacheFactory + 'static>(db: Pool<Postgres>, cf: Cf) -> Self {
        Self {
            db: db.clone(),
            absolute_repo: Arc::new(AbsoluteRepo::new(db, cf.clone())),
            session_store: cf.new_cache("permission_sessions", std::time::Duration::from_mins(30)),
        }
    }

    pub async fn get_role(&self, to_id: &Uuid, namespace: &Uuid) -> Result<u128, SqlxError> {
        let grant = match self
            .absolute_repo
            .list_one(filters!("namespace"=>namespace,"to_id"=>to_id))
            .await
        {
            Ok(r) => r,
            Err(ApiError::Database(e)) => return Err(e),
            _ => return Ok(0),
        };
        Ok(grant.role.as_u128())
    }

    async fn insert_role(&self, to_id: &Uuid, role: u128) -> Result<(), SqlxError> {
        let role = Uuid::from_u128(role);
        sqlx::query(
            r#"
        INSERT INTO grants (to_id, role)
        VALUES ($1, $2)
        ON CONFLICT(to_id) DO UPDATE SET role = excluded.role
        "#,
        )
        .bind(to_id)
        .bind(role)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn update_role(&self, to_id: &Uuid, role: u128) -> Result<(), SqlxError> {
        let role = Uuid::from_u128(role);
        sqlx::query(r#"UPDATE grants SET role = $1 WHERE to_id = $2"#)
            .bind(role)
            .bind(to_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// Grants `request.target` the permission in `request`, unconditionally.
    /// Callers MUST verify the caller is actually authorized (e.g. via
    /// `is_admin_for`) before calling this — it performs no auth check itself.
    async fn admin_grant_unchecked(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        // Validate permission
        if request.permission > 127 {
            return Ok(None);
        }
        let perm_value = 1 << request.permission;
        let current_role = self.get_role(&request.target, &request.namespace).await?;

        let new_role = current_role | perm_value;
        // Grant the permission
        self.insert_role(&request.target, new_role).await?;

        Ok(Some(new_role))
    }

    /// Revokes the permission in `request` from `request.target`'s absolute role.
    /// Same caveat as `admin_grant_unchecked`: no auth check performed here.
    async fn admin_deny_unchecked(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        if request.permission > 127 {
            return Ok(None);
        }
        let perm_value = 1 << request.permission;

        let role = self.get_role(&request.target, &request.namespace).await?;

        let role = role & !perm_value;
        self.update_role(&request.target, role).await?;

        Ok(Some(role))
    }

    /// Grant a permission as admin. Requires a super-admin token scoped to
    /// `request.namespace` (checked via `is_admin_for`).
    pub async fn admin_grant_permission(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        Ok(self.admin_grant_unchecked(request).await?)
    }

    /// Deny (revoke) a permission as admin. Requires a super-admin token scoped
    /// to `request.namespace`.
    pub async fn admin_deny_permission(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        Ok(self.admin_deny_unchecked(request).await?)
    }

    pub async fn claim(
        &self,
        namespace: Uuid,
        user: Uuid,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let role = match self
            .absolute_repo
            .list_one(filters!("namespace"=>namespace,"to_id"=>user))
            .await
        {
            Ok(r) => r.role.as_u128(),
            Err(ApiError::Database(e)) => return Err(Box::new(e)),
            _ => 0,
        };

        let authority = Authority { namespace, role };
        let id = Uuid::new_v4();
        self.session_store.set(&id, authority).await?;
        Ok(id)
    }
}
