use crate::models::{AppState, PermissionReq};
use actix_web::{HttpResponse, Responder, cookie::Cookie, get, post, web};
use ferrumec_perms::Authority;
use serde_json::json;
use uuid::Uuid;

#[post("/grant")]
pub async fn grant_permission(
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
    authority: Authority,
) -> HttpResponse {
    match state
        .service
        .can_grant(authority.clone(), body.permission)
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
            Err(e) => {
                tracing::error!("failed to grant permission: {e}");
                HttpResponse::InternalServerError().finish()
            }
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
    authority: Authority,
) -> HttpResponse {
    match state
        .service
        .can_grant(authority.clone(), body.permission)
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
            Err(e) => {
                tracing::error!("failed to deny permission: {e}");
                HttpResponse::InternalServerError().finish()
            }
        },
        Ok(false) => HttpResponse::Forbidden().finish(),
        Err(e) => {
            tracing::error!("could not confirm permission: {e}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[derive(serde::Deserialize)]
struct CreateNamespace {
    name: String,
}

#[post("/claim/{namespace}")]
pub async fn claim_permission(
    service: web::Data<AppState>,
    sess: viewset::web::Identity,
    path: web::Path<Uuid>,
) -> impl Responder {
    let namespace = path.into_inner();
    let id = sess.sub;

    let token = match service.service.claim(namespace, id).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("failed to claim permission: {e}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    let cookie = Cookie::build("permission", token.to_string())
        .http_only(true)
        .secure(true)
        .path("/")
        .finish();

    HttpResponse::Ok().cookie(cookie).finish()
}

#[post("/namespaces")]
pub async fn create_namespace(
    service: web::Data<AppState>,
    sess: viewset::web::Identity,
    path: web::Json<CreateNamespace>,
) -> impl Responder {
    match service
        .service
        .create_namespace(sess.sub, path.name.clone())
        .await
    {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => {
            tracing::error!("failed to create namespace: {e}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/namespaces")]
pub async fn list_namespaces(
    service: web::Data<AppState>,
    sess: viewset::web::Identity,
    filters: web::Query<viewset::Filters>,
) -> impl Responder {
    let mut filters = filters.into_inner();
    filters.insert("owner".to_string(), sess.sub.to_string());
    match service.service.get_namespaces(&filters).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => {
            tracing::error!("failed to create namespace: {e}");
            HttpResponse::InternalServerError().finish()
        }
    }
}
