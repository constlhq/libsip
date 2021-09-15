use crate::*;

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use nom::Slice;
use std::ops::Range;

/// Handle's the SIP registration process.
/// This structure is designed to handle the authentication
/// process from a SoftPhone's point of view.
///
/// Currently only Digest auth authentication is implemented.
#[derive(Debug, PartialEq, Clone)]
pub struct RegistrationManager {
    /// Uri representing the account to attempt to register.
    remote_uri: Uri,
    /// Uri representing the local machine used to register.
    local_uri: Uri,
    /// Current REGISTER cseq count number.
    cseq_counter: u32,
    /// The computed hash nonce count.
    nonce_c: u32,
    /// The CNonce value of the computer hash.
    c_nonce: Option<String>,
    /// The Finished computed auth header.
    auth_header: Option<AuthHeader>,
    /// The branch to use for registration.
    branch: String,
    /// The Call Id to use for register requests.
    call_id: String,
    // the value of the expires header.
    expires_header: Option<u32>,
    /// The username used for login
    user: String,
    /// The password to use for login.
    pass: String,
    /// Authentication realm
    realm: Option<String>,
    /// Authentication nonce
    nonce: Option<String>,
}

impl RegistrationManager {
    /// Create a new Registration Manager typically this will happen once in a program's
    /// lifecycle. `remote_uri` is the sip uri used to authenticate with and `local_uri`
    /// is the sip uri of the listening socket.
    pub fn new(remote_uri: Uri, local_uri: Uri, user: &str) -> RegistrationManager {
        RegistrationManager {
            remote_uri,
            local_uri,
            cseq_counter: 444,
            auth_header: None,
            nonce_c: 1,
            c_nonce: None,
            branch: format!("z9hG4bK{}", random_alphanumeric(12)),
            call_id: format!("{:x}", md5::compute(rand::random::<[u8; 16]>())),
            expires_header: None,
            user: user.to_owned(),
            pass: "12345678".to_owned(),
            realm: None,
            nonce: None,
        }
    }

    /// Set the username used in the authentication process.
    pub fn username<S: Into<String>>(&mut self, s: S) {
        self.user = s.into();
    }

    /// Set the password used in the authentication process.
    pub fn password<S: Into<String>>(&mut self, p: S) {
        self.pass = p.into();
    }

    pub fn set_realm<S: Into<String>>(&mut self, r: S) {
        self.realm = Some(r.into());
    }

    /// Get the register request. if this method is called before `set_challenge`
    /// then no authentication header will be set, if called after `set_challenge`
    /// then the Authorization header will be set.
    pub fn get_request(&mut self, cfg: &HeaderWriteConfig) -> IoResult<SipMessage> {
        self.cseq_counter += 1;
        self.nonce_c += 1;

        let mut from_uri = self.user.to_owned();

        from_uri.push_str("@");

        from_uri.push_str(self.realm.as_ref().unwrap().as_str());

        let to_header = Uri::sip(Domain::Domain(from_uri, None));

        let from_header = to_header.clone().parameter(UriParam::Tag("asdfss".to_string()));

        // let to_header = self.local_uri.clone();
        // let from_header = self.local_uri.clone();

        let mut contact_header = self.local_uri.clone();
        let mut headers = vec![];

        if !self.user.is_empty() {
            contact_header = contact_header.auth(UriAuth::new(&self.user));
            if let Some(auth_header) = &self.auth_header {
                if self.pass.is_empty() {
                    let ctx = AuthContext {
                        user: &self.user,
                        pass: &self.pass,
                        nc: self.nonce_c,
                        uri: &self.remote_uri,
                    };
                    headers.push(Header::Authorization(auth_header.authenticate(ctx)?));
                }
            }
        }
        headers.push(Header::ContentLength(0));
        headers.push(Header::To(NamedHeader::new(to_header)));
        headers.push(Header::From(NamedHeader::new(from_header)));
        headers.push(Header::Contact(ContactHeader::new(contact_header)));
        headers.push(Header::CSeq(self.cseq_counter, Method::Register));
        headers.push(Header::CallId(format!(
            "{}@{}",
            self.call_id,
            self.local_uri.host()
        )));
        headers.push(self.via_header());
        cfg.write_headers_vec(&mut headers);

        if let Some(exp) = self.expires_header {
            headers.push(Header::Expires(exp));
        }
        Ok(RequestGenerator::new()
            .method(Method::Register)
            .uri(self.remote_uri.clone())
            .headers(headers)
            .build()?)
    }

    /// After the first register request is sent. pass the received sip response
    /// to this function to perform compute the hashed password.
    pub fn set_challenge(&mut self, msg: SipMessage) -> IoResult<()> {
        if let SipMessage::Response { headers, .. } = msg {
            for item in headers.into_iter() {
                match item {
                    Header::WwwAuthenticate(auth) => {
                        self.auth_header = Some(auth);
                    }
                    Header::Expires(expire) => {
                        self.expires_header = Some(expire);
                    }
                    _ => {}
                }
            }
            Ok(())
        } else {
            Err(IoError::new(
                IoErrorKind::InvalidInput,
                "Challenge Response was not a SIP response",
            ))
        }
    }

    /// Retreive the expires header value.
    pub fn expires(&self) -> u32 {
        self.expires_header.unwrap_or(60)
    }

    /// Retreive the current cseq counter.
    pub fn cseq(&self) -> u32 {
        self.cseq_counter
    }

    /// Retreive the via header being used to represent the local
    /// listening socket.
    pub fn via_header(&self) -> Header {
        let via_uri = self
            .local_uri
            .clone()
            .parameter(UriParam::Branch(self.branch.clone()))
            .authless()
            .schemaless();
        Header::Via(ViaHeader {
            uri: via_uri,
            version: Default::default(),
            transport: Transport::Udp,
        })
    }
}
