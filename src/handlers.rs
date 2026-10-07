use crate::models::{AppState, PermissionReq};
use actix_web::{HttpResponse, Responder, cookie::Cookie, post, web};
use actixutils::extractors::ReadSession;
use ferrumec::Authority;
use serde_json::json;
use uuid::Uuid;

#[post("/grant")]
pub async fn grant_permission(
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
    authority: web::ReqData<Authority>,
) -> HttpResponse {
    match state
        .service
        .can_grant(authority.clone().into_inner(), body.permission)
        .await
    {
        Ok(true) => match state
            .service
            .admin_grant_permission(&authority.namespace, body.into_inner())
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
        },
        Ok(false) => HttpResponse::Forbidden().finish(),
        Err(e) => {
            tracing::error!("could not confirm permission: {e}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/deny")]
pub async fn deny_permission(
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
    authority: web::ReqData<Authority>,
) -> HttpResponse {
    match state
        .service
        .can_grant(authority.clone().into_inner(), body.permission)
        .await
    {
        Ok(true) => match state
            .service
            .admin_deny_permission(&authority.namespace, body.clone())
            .await
        {
            Ok(Some(r)) => HttpResponse::Ok().json(json!({
                "success": true,
                "new_role": r
            })),
            Ok(None) => HttpResponse::NotAcceptable().body(
                "Error in denying permission, please confirm that the permission was granted",
            ),
            Err(_e) => HttpResponse::InternalServerError().finish(),
        },
        Ok(false) => HttpResponse::Forbidden().finish(),
        Err(e) => {
            tracing::error!("could not confirm permission: {e}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

struct User {
    id: Uuid,
}

#[post("/claim/{namespace}")]
pub async fn claim_permission(
    service: web::Data<AppState>,
    sess: ReadSession<User>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let namespace = path.into_inner();
    let id = sess.id;

    let token = match service.service.claim(namespace, id).await {
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
