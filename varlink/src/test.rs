use crate::*;
use serde_json::{from_slice, from_value};
use std::{convert::TryInto, os::fd::AsRawFd, thread, time};

#[test]
fn test_listen() -> Result<()> {
    fn run_app<S: ?Sized + AsRef<str>>(address: &S, timeout: u64) -> Result<()> {
        let service = VarlinkService::new(
            "org.varlink",
            "test service",
            "0.1",
            "http://varlink.org",
            vec![], // Your varlink interfaces go here
        );

        if let Err(e) = listen(
            service,
            &address,
            &ListenConfig {
                idle_timeout: timeout,
                ..Default::default()
            },
        ) {
            if *e.kind() != ErrorKind::Timeout {
                panic!("Error listen: {:#?}", e);
            }
        }
        Ok(())
    }

    fn run_client_app<S: ?Sized + AsRef<str>>(address: &S) -> Result<()> {
        let conn = Connection::new(address)?;
        let mut call = OrgVarlinkServiceClient::new(conn.clone());
        {
            let info = call.get_info()?;
            assert_eq!(&info.vendor, "org.varlink");
            assert_eq!(&info.product, "test service");
            assert_eq!(&info.version, "0.1");
            assert_eq!(&info.url, "http://varlink.org");
            assert_eq!(
                info.interfaces.first().unwrap().as_ref(),
                "org.varlink.service"
            );
        }
        let e = call.get_interface_description("org.varlink.unknown");
        assert!(e.is_err());

        match e.err().unwrap().kind() {
            ErrorKind::InvalidParameter(i) => assert_eq!(*i, "interface".to_string()),
            kind => {
                panic!("Unknown error {:?}", kind);
            }
        }

        let e = MethodCall::<GetInfoArgs, ServiceInfo, Error>::new(
            conn.clone(),
            "org.varlink.service.GetInfos",
            GetInfoArgs {},
        )
        .call();

        match e.err().unwrap().kind() {
            ErrorKind::MethodNotFound(i) => {
                assert_eq!(*i, "org.varlink.service.GetInfos".to_string())
            }
            kind => {
                panic!("Unknown error {:?}", kind);
            }
        }

        let e = MethodCall::<GetInfoArgs, ServiceInfo, Error>::new(
            conn.clone(),
            "org.varlink.unknowninterface.Foo",
            GetInfoArgs {},
        )
        .call();

        match e.err().unwrap().kind() {
            ErrorKind::InterfaceNotFound(i) => {
                assert_eq!(*i, "org.varlink.unknowninterface".to_string())
            }
            kind => {
                panic!("Unknown error {:?}", kind);
            }
        }

        let description = call.get_interface_description("org.varlink.service")?;

        assert_eq!(
            &description.description.unwrap(),
            r#"# The Varlink Service Interface is provided by every varlink service. It
# describes the service and the interfaces it implements.
interface org.varlink.service

# Get a list of all the interfaces a service provides and information
# about the implementation.
method GetInfo() -> (
  vendor: string,
  product: string,
  version: string,
  url: string,
  interfaces: []string
)

# Get the description of an interface that is implemented by this service.
method GetInterfaceDescription(interface: string) -> (description: string)

# The requested interface was not found.
error InterfaceNotFound (interface: string)

# The requested method was not found
error MethodNotFound (method: string)

# The interface defines the requested method, but the service does not
# implement it.
error MethodNotImplemented (method: string)

# One of the passed parameters is invalid.
error InvalidParameter (parameter: string)
"#
        );

        Ok(())
    }

    let address = "unix:test_listen_timeout";

    let child = thread::spawn(move || {
        if let Err(e) = run_app(address, 3) {
            panic!("error: {}", e);
        }
    });

    // give server time to start
    thread::sleep(time::Duration::from_secs(1));

    run_client_app(address)?;

    assert!(child.join().is_ok());

    Ok(())
}

#[test]
fn test_handle() -> Result<()> {
    let service = VarlinkService::new(
        "org.varlink",
        "test service",
        "0.1",
        "http://varlink.org",
        vec![],
    );

    let br = concat!(r#"{"method" : "org.varlink.service.GetInfo"}"#, "\0").as_bytes();

    let a = br[0..10].to_vec();
    let b = br[10..20].to_vec();
    let c = br[20..].to_vec();

    let mut w = vec![];

    let mut buf = Vec::<u8>::new();

    for mut i in [a, b, c] {
        buf.append(&mut i);

        let res = {
            let mut br = buf.as_slice();
            service.handle(&mut br, &mut w, None)?
        };
        match res {
            (_, Some(iface)) => {
                panic!("Unexpected handle return value {}", iface);
            }
            (v, None) => {
                if v.is_empty() {
                    break;
                }
                //eprintln!("unhandled: {}", String::from_utf8_lossy(&v));
                buf.clone_from(&v);
            }
        }
    }

    w.pop();

    assert_eq!(
        w,
        concat!(
            r#"{"parameters":{"interfaces":["org.varlink.service"],"product":"test service","#,
            r#""url":"http://varlink.org","vendor":"org.varlink","version":"0.1"}}"#
        )
        .as_bytes()
    );

    let reply = from_slice::<Reply>(&w).unwrap();

    let si = from_value::<ServiceInfo>(reply.parameters.unwrap()).map_err(map_context!())?;

    assert_eq!(
        si,
        ServiceInfo {
            vendor: "org.varlink".into(),
            product: "test service".into(),
            version: "0.1".into(),
            url: "http://varlink.org".into(),
            interfaces: vec!["org.varlink.service".into()],
        }
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn test_listener_unix_abstract_socket_type() {
    const SOCK: &str = "unix:@org.varlink.abstract_socket";

    let listener = Listener::new(SOCK).unwrap();
    let Listener::UNIX(ref inner, _) = listener else {
        unreachable!();
    };
    let Some(unix_listener) = inner.as_ref() else {
        unreachable!();
    };
    let mut sockaddr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut socklen: libc::socklen_t = std::mem::size_of::<libc::sockaddr_un>()
        .try_into()
        .unwrap_or(libc::socklen_t::MAX);
    if unsafe {
        libc::getsockname(
            unix_listener.as_raw_fd(),
            (&mut sockaddr as *mut libc::sockaddr_un).cast(),
            &mut socklen,
        )
    } < 0
    {
        let errno = std::io::Error::last_os_error();
        panic!("getsockname: {:?}", errno);
    }

    if sockaddr.sun_family != (libc::AF_UNIX as libc::sa_family_t) {
        panic!(
            "Expected sockaddr.sun_family == AF_UNIX, got: {}",
            sockaddr.sun_family
        );
    }
    assert_eq!(
        sockaddr.sun_path[0], 0,
        "Expected first byte of sockaddr.sun_path to be a nul byte. sockaddr.sun_path was: {:?}",
        sockaddr.sun_path
    );
    let sun_name_len = socklen as usize - std::mem::size_of::<libc::sa_family_t>();
    assert!(
        sun_name_len == SOCK["unix:@".len()..].len() + 1,
        "sun_name_len = {} but expected {}",
        sun_name_len,
        SOCK["unix:@".len()..].len() + 1
    );
    let sun_path = unsafe { std::ffi::CStr::from_ptr(sockaddr.sun_path[1..].as_ptr()) };
    assert_eq!(
        sun_path,
        std::ffi::CString::new(&SOCK["unix:@".len()..])
            .unwrap()
            .as_c_str(),
        "expected sockaddr.sun_path == {}, got: {:?}",
        &SOCK["unix:@".len()..],
        sun_path
    );
}

#[cfg(unix)]
#[test]
fn test_listener_unix_socket_type() {
    const SOCK: &str = "unix:org.varlink.u\u{04}";

    let listener = Listener::new(SOCK).unwrap();
    let Listener::UNIX(ref inner, _) = listener else {
        unreachable!();
    };
    let Some(unix_listener) = inner.as_ref() else {
        unreachable!();
    };
    let mut sockaddr: libc::sockaddr = unsafe { std::mem::zeroed() };
    let mut socklen: libc::socklen_t = std::mem::size_of::<libc::sockaddr>()
        .try_into()
        .unwrap_or(libc::socklen_t::MAX);
    if unsafe { libc::getsockname(unix_listener.as_raw_fd(), &mut sockaddr, &mut socklen) } < 0 {
        let errno = std::io::Error::last_os_error();
        panic!("getsockname: {:?}", errno);
    }
    if sockaddr.sa_family != (libc::AF_UNIX as libc::sa_family_t) {
        panic!(
            "Expected sockaddr.sa_family == AF_UNIX, got: {}",
            sockaddr.sa_family
        );
    }
    let sa_data = unsafe {
        std::ffi::CString::new::<&[u8]>(
            std::mem::transmute::<&[libc::c_char; 14], &[u8; 14]>(&sockaddr.sa_data).as_slice(),
        )
        .unwrap()
    };
    assert_eq!(
        sa_data.as_c_str(),
        std::ffi::CString::new(&SOCK["unix:".len()..])
            .unwrap()
            .as_c_str(),
        "expected sockaddr.sa_data == {:?}, got: {:?}",
        &SOCK["unix:".len()..],
        sa_data
    );
}

#[test]
fn test_listener_tcp_socket_type() {
    let listener = Listener::new("tcp:127.0.0.1:0").unwrap();
    let Listener::TCP(ref inner, _) = listener else {
        unreachable!();
    };
    let Some(tcp_listener) = inner.as_ref() else {
        unreachable!();
    };
    let mut sockaddr: libc::sockaddr = unsafe { std::mem::zeroed() };
    let mut socklen: libc::socklen_t = std::mem::size_of::<libc::sockaddr>()
        .try_into()
        .unwrap_or(libc::socklen_t::MAX);
    if unsafe { libc::getsockname(tcp_listener.as_raw_fd(), &mut sockaddr, &mut socklen) } < 0 {
        let errno = std::io::Error::last_os_error();
        panic!("getsockname: {:?}", errno);
    }
    if sockaddr.sa_family != (libc::AF_INET as libc::sa_family_t) {
        panic!(
            "Expected sockaddr.sa_family == AF_INET, got: {}",
            sockaddr.sa_family
        );
    }
}
