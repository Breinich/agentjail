//! Core of agentjail: the profile format, its validation, the network posture
//! invariant, and host diagnostics.
//!
//! Nothing in this crate launches containers. It is deliberately a library so
//! the CLI, the launcher, the gateway, and the tests all share one definition of
//! what a valid profile is.

pub mod class;
pub mod doctor;
pub mod lifecycle;
pub mod network;
pub mod paths;
pub mod podman;
pub mod profile;
pub mod run;
pub mod schema;

pub use profile::{
    parse_and_validate, Agent, DnsStrategy, Egress, EnvValue, Image, Mount, Network, NetworkMode,
    Profile, Protocol, Resources, Secret, SecretDelivery, SecretSource, SUPPORTED_PROFILE_VERSION,
};
