use crate::services::Service;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PermissionReq {
    pub permission: Uuid,
    pub target: Uuid,
}

#[derive(Clone)]
pub struct AppState {
    pub service: Service,
}
