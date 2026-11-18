//! Wallet and model reads for the application's own frontend, which holds no token.
//!
//! The backend calls auth-service and the gateway on the user's behalf.

use crate::ai::AiClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::messages::{WebRequest, WebResponse, json_response};
use crate::web::handlers::query_of;
use crate::web::sessions::Session;

const MAX_STATS_DAYS: u32 = 90;

pub(super) async fn wallet(ai: &AiClient, session: &Session) -> Result<WebResponse> {
    let user = ai.for_user(&session.user_id)?;
    let account = user.wallet.get_account().await?;
    let mut body = serde_json::to_value(&account).map_err(|err| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("The wallet cannot be serialised")
            .with_source(err)
    })?;
    if let Some(members) = body.as_object_mut() {
        members.insert(
            "topupUrl".to_owned(),
            serde_json::json!(user.wallet.topup_url()),
        );
    }
    Ok(json_response(&body, 200, Vec::new()))
}

pub(super) async fn wallet_stats(
    ai: &AiClient,
    session: &Session,
    request: &WebRequest,
) -> Result<WebResponse> {
    let days = match query_of(request)?.get("days") {
        None => None,
        Some(text) => Some(
            text.parse::<u32>()
                .ok()
                .filter(|days| (1..=MAX_STATS_DAYS).contains(days))
                .ok_or_else(|| {
                    AuthAiError::new(ErrorCode::Req001).with_message("days must be 1 to 90")
                })?,
        ),
    };
    let stats = ai
        .for_user(&session.user_id)?
        .wallet
        .get_stats(days)
        .await?;
    let body = serde_json::to_value(&stats).map_err(|err| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("The statistics cannot be serialised")
            .with_source(err)
    })?;
    Ok(json_response(&body, 200, Vec::new()))
}

pub(super) async fn models(ai: &AiClient, session: &Session) -> Result<WebResponse> {
    let user = ai.for_user(&session.user_id)?;
    let listed = user.gateway()?.list_models().await?;
    let body = serde_json::to_value(&listed).map_err(|err| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("The models cannot be serialised")
            .with_source(err)
    })?;
    Ok(json_response(
        &serde_json::json!({ "models": body }),
        200,
        Vec::new(),
    ))
}
