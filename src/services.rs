use crate::admin::AbsoluteRepo;
use crate::admin::Namespace;
use crate::admin::NamespaceRepo;
use crate::models::PermissionReq;
use ferrumec::cache::CacheFactory;
use ferrumec_perms::{Authority, AuthzControls};
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
}

impl Service {
    /// Builds a `Service` with its own freshly-constructed [`AbsoluteRepo`],
    /// caching via `cf`.
    pub fn new(db: Pool<Postgres>, cf: impl CacheFactory) -> Self {
        let absolute_repo = Arc::new(AbsoluteRepo::new(db.clone(), cf.clone()));
        Self {
            db: db.clone(),
            absolute_repo: absolute_repo.clone(),
            namespace_repo: Arc::new(NamespaceRepo::new(db, cf.clone())),
        }
    }

    pub async fn get_role(&self, user: &Uuid, namespace: &Uuid) -> Result<u128, SqlxError> {
        let grant = match self.absolute_repo.list_one(filters!(namespace, user)).await {
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
        let user = &request.target;
        let (grants, count) = self.absolute_repo.list(filters!(user, namespace)).await?;
        if count > 0 {
            let grant = grants[0].clone();
            let update = grant.grant(request.permission);
            self.absolute_repo.update(&grant.id, update.clone()).await?;
            Ok(update.role)
        } else {
            let grant = Authority {
                sub: user.clone(),
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
            .list_one(filters!("user"=>&request.target,"namespace"=>namespace))
            .await?;
        let update = grant.deny(request.permission);
        self.absolute_repo.update(&grant.id, update.clone()).await?;
        Ok(update.role)
    }

    pub async fn claim(
        &self,
        namespace: Uuid,
        sub: Uuid,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let role = match self.absolute_repo.list_one(filters!(namespace, sub)).await {
            Ok(r) => r,
            Err(e) => return Err(Box::new(e)),
        };

        Ok(role.id)
    }

    pub async fn can_grant(
        &self,
        authority: Authority,
        perm_value: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let namespace = self.namespace_repo.retrieve(&authority.namespace).await?;
        if namespace.owner != authority.sub {
            return Ok(false);
        }

        let grant = self
            .absolute_repo
            .list_one(filters!("user"=>authority.sub,"namespace"=>authority.namespace))
            .await?;

        Ok(grant.has(perm_value))
    }

    pub async fn create_namespace(
        &self,
        owner: Authority,
        name: String,
    ) -> Result<Namespace, Box<dyn std::error::Error>> {
        let mut authority = owner.clone();
        let namespace = self
            .namespace_repo
            .create(crate::admin::CreateNamespace {
                owner: owner.sub,
                name,
            })
            .await?;
        authority.namespace = namespace.id;
        self.absolute_repo.create(authority).await?;
        Ok(namespace)
    }

    pub async fn bootstrap_namespace(
        &self,
        owner: Uuid,
        name: String,
    ) -> Result<Namespace, Box<dyn std::error::Error>> {
        let has_rows: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM namespaces)")
            .fetch_one(self.absolute_repo.database())
            .await?;

        if has_rows {
            return Err("Namespaces is already bootstrapped".into());
        }
        let namespace = self
            .namespace_repo
            .create(crate::admin::CreateNamespace { owner, name })
            .await?;

        let authority = Authority {
            sub: owner,
            namespace: namespace.id,
            role: Uuid::from_u128(u128::MAX),
        };

        self.absolute_repo.create(authority).await?;
        Ok(namespace)
    }

    pub async fn get_namespaces(
        &self,
        owner: &viewset::Filters,
    ) -> Result<(Vec<Namespace>, i64), Box<dyn std::error::Error>> {
        Ok(self.namespace_repo.list(owner).await?)
    }
}
