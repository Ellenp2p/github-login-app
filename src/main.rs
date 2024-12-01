use axum::{
    async_trait, extract::{Extension, FromRequestParts, Query}, http::{request::Parts, HeaderValue, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}, Json, Router
};
use axum::RequestPartsExt;
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use hyper::header::SET_COOKIE;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::{CookieManagerLayer, Cookies};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::{env, fmt::Display, fs::OpenOptions, sync::{Arc, LazyLock}};
use tokio::{  io::AsyncReadExt, sync::Mutex};
use uuid::Uuid;
use cookie::{Cookie, CookieJar};
use cookie::time::Duration;
use chrono::prelude::Utc;
use lazy_static::lazy_static;

lazy_static! {
    static ref GITHUB_CLIENT_ID: String = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");
    static ref GITHUB_CLIENT_SECRET: String = env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET not set");
    static ref GITHUB_REDIRECT_URI: String = env::var("GITHUB_REDIRECT_URI").expect("GITHUB_REDIRECT_URI not set");
}

static SECRET_KEY: LazyLock<String> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    secret
});

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    access_token: String, // 用户的唯一标识
    exp: usize,  // 过期时间
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sub: {}\nexp: {}", self.access_token, self.exp)
    }
}

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

// GitHub 授权 token 和用户信息
#[derive(Deserialize)]
struct GithubAccessToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUser {
    login: String,
    id: u64,
    name: Option<String>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let log_file = OpenOptions::new()
    .create(true)  
    .append(true)  
    .open("app.log")
    .unwrap();  

    tracing_subscriber::registry()
        
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .with(tracing_subscriber::fmt::layer()
            .with_writer( move ||  
                log_file.try_clone().unwrap()
            )
            .with_ansi(false))
        .init();
    
    // 设置基础路由
    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(github_login))
        .route("/callback", get(github_callback))
        .route("/get_state", get(get_state))
        .route("/logout", post(revoke_github_oauth))
        // .route("/profile", get(profile))
        .layer(CookieManagerLayer::new());

    tracing::debug!("This is a debug message");
    tracing::info!("This is an info message");
    tracing::warn!("This is a warning message");
    tracing::error!("This is an error message");
    // 启动服务器
    let listener  = tokio::net::TcpListener::bind(&"0.0.0.0:8080").await.unwrap();
    axum::serve(listener,app.into_make_service())
        .await
        .unwrap();
}

// 首页路由，欢迎页面
async fn home() -> &'static str {
    "Welcome to the GitHub OAuth login example! Visit /login to log in with GitHub."
}

// GitHub OAuth 登录，生成授权 URL
async fn github_login() -> String {
    let client_id = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");
    let redirect_uri = env::var("GITHUB_REDIRECT_URI").expect("GITHUB_REDIRECT_URI not set");

    // GitHub OAuth 授权 URL
    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}",
        client_id, redirect_uri
    );

    // 返回授权 URL，用户点击后会去 GitHub 登录
    auth_url
}

// 处理 GitHub 回调，交换 code 为 access token
async fn github_callback(
    query: Query<std::collections::HashMap<String, String>>,
    cookies: Cookies
) -> impl IntoResponse  {
    let code = query.get("code").ok_or("Code parameter missing").unwrap();

    let client = Client::new();

    // 请求 token
    let token_url = "https://github.com/login/oauth/access_token";
    let res = client
        .post(token_url)
        .form(&[
            ("client_id", &GITHUB_CLIENT_ID.to_string()),
            ("client_secret", &GITHUB_CLIENT_SECRET.to_string()),
            ("code", code),
            ("redirect_uri", &GITHUB_REDIRECT_URI.to_string()),
        ])
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string()).unwrap();

    let token: GithubAccessToken = res.json().await.map_err(|e| e.to_string()).unwrap();

    // 使用 access_token 获取用户信息
    let user_url = "https://api.github.com/user";
    let user_res = client
        .get(user_url)
        .header("Authorization", format!("token {}", token.access_token))
        .header("User-Agent", "Rust OAuth Example")
        .send()
        .await
        .map_err(|e| e.to_string()).unwrap();

    let user: GithubUser = user_res.json().await.map_err(|e| e.to_string()).unwrap();
    
    // 生成 JWT
    let claims = Claims {
        access_token: token.access_token.clone(),
        exp:  Utc::now().timestamp() as usize + 3600 ,
    };

    let jwt =jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY.as_ref()))
        .map_err(|e| e.to_string()).unwrap();

    // 将会话 ID 存储在 Cookie 中
    let cookie = Cookie::build(("jwt", jwt.clone()))
        .http_only(true)  // 安全标志，防止 JavaScript 访问 Cookie
        .max_age(Duration::hours(1)) // 设置有效期为 1 小时
        .build();
    

    let mut response = Response::new(format!(
        "Successfully logged in as {} (GitHub ID: {}). jwt: {}",
        user.login, user.id, jwt
    ));
    // response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie.to_string()).unwrap());
    cookies.add(cookie);

    response
}

async fn get_state(
    cookies: Cookies
) -> Result<String, String>
{
    let claims = cookies.get("jwt").and_then(|c| 
       Some(jsonwebtoken::decode::<Claims>(c.value(), &DecodingKey::from_secret(SECRET_KEY.as_ref()) , &Validation::default())
        .map_err(|_| AuthError::InvalidToken).unwrap().claims)
    ).unwrap();

    // 使用 access_token 获取用户信息
    let user_url = "https://api.github.com/user";
    let client = Client::new();
    let user_res = client
        .get(user_url)
        .header("Authorization", format!("token {}", claims.access_token))
        .header("User-Agent", "Rust OAuth Example")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let user: GithubUser = user_res.json().await.map_err(|e| e.to_string())?;
    Ok(format!(
        "Successfully logged in as {} (GitHub ID: {}).",
        user.login, user.id
    ))
}

async fn revoke_github_oauth(
    cookies: Cookies
) -> Result<String, String>
{

    let claims = if let Some(cookie) = cookies.get("jwt") {
        let token_data = jsonwebtoken::decode::<Claims>(cookie.to_string().as_str(), &DecodingKey::from_secret(SECRET_KEY.as_ref()) , &Validation::default())
            .map_err(|_| AuthError::InvalidToken).unwrap();
        token_data.claims
    } else {
        return Err( "No cookie found".to_string() );
    };
    // 创建 reqwest 客户端
    let client = Client::new();

    // 构造请求 URL
    let url = format!(
        "https://api.github.com/applications/{}/tokens/{}",
        GITHUB_CLIENT_ID.to_string(), claims.access_token.to_string()
    );
    
    // 发送撤销授权请求
    let res = client
        .delete(&url)
        .basic_auth(&GITHUB_CLIENT_ID.to_string(), Some(& claims.access_token.to_string()))
        .send()
        .await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                Ok("OAuth token revoked successfully.".into())
            } else {
                Err(format!("Failed to revoke token: {}", response.status()))
            }
        },
        Err(err) => Err(format!("Error sending request: {}", err)),
    }
}

// 获取用户信息（需要验证会话）
// async fn profile(
//     state: Extension<AppState>,
//     headers: TypedHeader<Cookie>,
// ) -> Result<Json<GithubUser>, StatusCode> {
//     let cookie_jar = state.cookie_jar.lock().await;

//     // 检查是否存在 session_id cookie
//     if let Some(session_cookie) = headers.get("session_id") {
//         // 这里可以根据 session_id 查找用户的会话信息
//         Ok(Json(GithubUser {
//             login: "github_user".to_string(),
//             id: 12345,
//             name: Some("GitHub User".to_string()),
//         }))
//     } else {
//         Err(StatusCode::UNAUTHORIZED)
//     }
// }
