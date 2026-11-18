//! Bearer verification, back-channel logout, protected-resource metadata and the machine API.

mod backchannel_logout;
mod bearer;
mod billing;
mod consumption;
mod machine_api;
mod machine_tokens;
mod protected_resource;
mod resources;
mod usage;

pub use backchannel_logout::{
    BackchannelLogoutEvent, BackchannelLogoutHandler, LOGOUT_EVENT, LOGOUT_TOKEN_TYP,
    LogoutCallback, LogoutTokenClaims, MAX_BODY_BYTES, MAX_LOGOUT_TOKEN_LIFETIME_SECONDS,
    MemoryReplayStore, ReplayStore, verify_logout_token,
};
pub use bearer::{BearerVerifier, VerifiedAccessToken, extract_bearer_token, require_scopes};
pub use billing::{
    BillingApi, FeatureUsage, InvoicePage, InvoiceView, PlanRef, SubscriptionView, UsageView,
};
pub use consumption::{
    ConsumptionAggregate, ConsumptionApi, ConsumptionResult, ConsumptionTotal, ConsumptionValue,
};
pub use machine_api::MachineApi;
pub use protected_resource::{
    BearerError, bearer_challenge, protected_resource_metadata, protected_resource_metadata_path,
};
pub use resources::{
    AUTHORIZE_SCOPE, AccessKind, AccessibleResource, Allowed, AuthorizeDecision, AuthorizeRequest,
    EventSource, GrantSubjectType, OwnerType, ResourceState, ResourceStatus, ResourcesApi,
    VALIDATE_SCOPE, ValidationResult,
};
pub use usage::{RecordedUsage, USAGE_SCOPE, UsageReceipt, UsageRecord, UsageSource};
