use crate::services::Service;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Clone)]
pub struct PermissionReq {
    pub permission: u8,
    pub namespace: Uuid,
    pub target: Uuid,
}

#[derive(Clone)]
pub struct AppState {
    pub service: Service,
}
