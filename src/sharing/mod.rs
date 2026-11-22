//! The signed-in user's own resources and shares.

mod client;
mod models;

pub use client::ResourceSharingClient;
pub use models::{
    Catalogue, CatalogueApplication, CreateGrant, CreateResource, DeletedResource, Grant,
    MemberApplication, Organization, Resource, ResourceAudience, UpdateResource, ValidationRequest,
};

pub use crate::server::{AccessibleResource, GrantSubjectType, OwnerType, ResourceStatus};
