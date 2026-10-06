use crate::Service;
use crate::models::{AppState, PermissionReq};
use actix_web::{HttpResponse, Responder, cookie::Cookie, post, web};
use actixutils::extractors::ReadSession;
use serde_json::json;
use uuid::Uuid;

#[post("/admin/grant")]
pub async fn admin_grant_permission(
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
) -> HttpResponse {
    match state
        .service
        .admin_grant_permission(body.into_inner())
        .await
    {
        Ok(Some(r)) => HttpResponse::Ok().json(json!({
            "success": true,
            "new_role": r
        })),
        Ok(None) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "invalid operation"
        })),
        Err(_e) => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/admin/deny")]
pub async fn admin_deny_permission(
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
) -> HttpResponse {
    let req = body.into_inner();
    match state.service.admin_deny_permission(req.clone()).await {
        Ok(Some(r)) => HttpResponse::Ok().json(json!({
            "success": true,
            "new_role": r
        })),
        Ok(None) => HttpResponse::NotAcceptable()
            .body("Error in denying permission, please confirm that the permission was granted"),
        Err(_e) => HttpResponse::InternalServerError().finish(),
    }
}

struct User {
    id: Uuid,
}

#[post("/admin/claim/{namespace}")]
pub async fn claim_admin(
    service: web::Data<Service>,
    sess: ReadSession<User>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let namespace = path.into_inner();
    let id = sess.id;

    let token = match service.claim(namespace, id).await {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let cookie = Cookie::build("permission", token.to_string())
        .http_only(true)
        .secure(true)
        .path("/")
        .finish();

    HttpResponse::Ok().cookie(cookie).finish()
}
