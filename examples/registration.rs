//! This example was created using a virtualbox vm
//! running ubuntu 19.04 and a SIP server running at
//! 192.168.1.123:5060
//!
//! This will attempt to register a sip account and print
//! the returned OK response.
//!
//! This expects and extension with the numeric id `20`
//! and a password of `program`

extern crate libsip;

use libsip::*;

use std::{io::Result as IoResult, net::UdpSocket};

use nom::error::VerboseError;

use std::future::Future;

use std::thread;
use std::sync::mpsc;
use std::time::Duration;
use std::sync::mpsc::RecvTimeoutError;



fn get_our_uri() -> Uri {
    Uri::sip(domain!("192.168.1.129:5060")).parameter(UriParam::Transport(Transport::Udp))
}


fn send_request_get_response(req: SipMessage) -> Result<SipMessage, RecvTimeoutError> {
    let (sender, receiver) = mpsc::channel();

    let t = thread::spawn(move || {
        let addr = "0.0.0.0:5060";
        let sock = UdpSocket::bind(addr).unwrap();
        sock.send_to(&format!("{}", req).as_ref(), "192.168.1.133:5060").unwrap();
        let mut buf = vec![0; 65535];
        let (amt, _src) = sock.recv_from(&mut buf).unwrap();
        if let Err(nom::Err::Error((data, _))) = parse_response(&buf[..amt]) {
            panic!("{}", String::from_utf8_lossy(data));
        }
        let (_, msg) = parse_response::<VerboseError<&[u8]>>(&buf[..amt]).unwrap();


        match sender.send(msg) {
            Ok(..) => {} // everything good
            Err(_) => {} // we have been released, don't panic
        }
    });
    return receiver.recv_timeout(Duration::from_millis(5000));
}

fn main()  {

    println!("{}",random_alphanumeric(10));

    let remote_url = parse_uri::<VerboseError<&[u8]>>(b"sip:11010203002000000001@192.168.1.133:5060")
        .unwrap()
        .1
        .parameter(UriParam::Transport(Transport::Udp));
    let mut builder = RegistrationManager::new(remote_url, get_our_uri(), "11010203001320000001");

    builder.password("program");
    builder.set_realm("1101020300");

    let req = builder.get_request(&Default::default()).unwrap();

    println!("{}", req);

    let res = send_request_get_response(req);

    if  res.is_err(){
        println!("timeout")
    }

}
