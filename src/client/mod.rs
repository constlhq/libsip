//! The client module contains all of the code for
//! processing and generating SIP requests. Encapsulating
//! all this functionality is the SoftPhone struct.

mod registration;
pub use self::registration::RegistrationManager;

mod messaging;
pub use self::messaging::{MessageHelper, MessageWriter};

mod invite;
pub use self::invite::{InviteHelper, InviteWriter};

use crate::{Header, Headers, Method, SipMessage, Uri};

use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
};

/// This struct is used in the client module when creating sip messages
/// it is used to specify some common values for the generated sip
/// headers.
pub struct HeaderWriteConfig {
    /// The Value to set for the User Agent header.
    /// By default this is set to libsip {version},
    /// Set to None to disable adding a User Agent header.
    pub user_agent: Option<String>,
    /// The value for the Allowed Methods Header.
    /// By default set to Invite, Cancel, Bye, Message.
    /// Set to None to disable adding header.
    pub allowed_methods: Option<Vec<Method>>,
}

impl HeaderWriteConfig {
    /// Write configured headers into the provided Vec.
    pub fn write_headers_vec(&self, m: &mut Vec<Header>) {
        if let Some(agent) = &self.user_agent {
            m.push(Header::UserAgent(agent.into()));
        }
        if let Some(allowed) = &self.allowed_methods {
            m.push(Header::Allow(allowed.clone()));
        }
    }

    /// Write configured headers into the provided Headers Map.
    pub fn write_headers(&self, m: &mut Headers) {
        if let Some(agent) = &self.user_agent {
            m.push(Header::UserAgent(agent.into()));
        }
        if let Some(allowed) = &self.allowed_methods {
            m.push(Header::Allow(allowed.clone()));
        }
    }
}

impl Default for HeaderWriteConfig {
    fn default() -> HeaderWriteConfig {
        HeaderWriteConfig {
            user_agent: Some(format!("libsip {}", env!("CARGO_PKG_VERSION"))),
            allowed_methods: Some(vec![
                Method::Invite,
                Method::Cancel,
                Method::Bye,
                Method::Message,
            ]),
        }
    }
}
