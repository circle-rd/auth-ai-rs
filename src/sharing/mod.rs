//! The signed-in user's own resources and shares.

mod client;
mod grants;
mod models;

pub use client::ResourceSharingClient;
pub use models::{
    BulkShareResult, Catalogue, CatalogueApplication, CreateGrant, CreateResource, Grant,
    MemberApplication, Organization, Resource, ResourceAudience, ShareWithApplication,
    UpdateResource, ValidationRequest,
};

pub use crate::server::{
    AccessibleResource, GrantSubjectType, OwnerType, ResourcePermission, ResourceStatus,
};
