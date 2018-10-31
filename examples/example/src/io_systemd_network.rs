#![doc = "This file was automatically generated by the varlink rust generator"]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use failure::{Backtrace, Context, Fail};
use serde_derive::{Deserialize, Serialize};
use serde_json;
use std::io::BufRead;
use std::sync::{Arc, RwLock};
use varlink::{self, CallTrait};
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#Netdev {
    pub r#ifindex: i64,
    pub r#ifname: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#NetdevInfo {
    pub r#ifindex: i64,
    pub r#ifname: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UnknownError_Args {
    pub r#text: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UnknownNetworkIfIndex_Args {
    pub r#ifindex: i64,
}
pub trait VarlinkCallError: varlink::CallTrait {
    fn reply_unknown_error(&mut self, r#text: String) -> varlink::Result<()> {
        self.reply_struct(varlink::Reply::error(
            "io.systemd.network.UnknownError",
            Some(serde_json::to_value(UnknownError_Args { r#text })?),
        ))
    }
    fn reply_unknown_network_if_index(&mut self, r#ifindex: i64) -> varlink::Result<()> {
        self.reply_struct(varlink::Reply::error(
            "io.systemd.network.UnknownNetworkIfIndex",
            Some(serde_json::to_value(UnknownNetworkIfIndex_Args {
                r#ifindex,
            })?),
        ))
    }
}
impl<'a> VarlinkCallError for varlink::Call<'a> {}
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "IO error")]
    Io_Error(::std::io::ErrorKind),
    #[fail(display = "(De)Serialization Error")]
    SerdeJson_Error(serde_json::error::Category),
    #[fail(display = "Varlink Error")]
    Varlink_Error(varlink::ErrorKind),
    #[fail(display = "Unknown error reply: '{:#?}'", _0)]
    VarlinkReply_Error(varlink::Reply),
    #[fail(display = "io.systemd.network.UnknownError: {:#?}", _0)]
    UnknownError(Option<UnknownError_Args>),
    #[fail(display = "io.systemd.network.UnknownNetworkIfIndex: {:#?}", _0)]
    UnknownNetworkIfIndex(Option<UnknownNetworkIfIndex_Args>),
}
impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }
    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}
impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self.inner, f)
    }
}
impl Error {
    #[allow(dead_code)]
    pub fn kind(&self) -> ErrorKind {
        self.inner.get_context().clone()
    }
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}
impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}
impl From<::std::io::Error> for Error {
    fn from(e: ::std::io::Error) -> Error {
        let kind = e.kind();
        e.context(ErrorKind::Io_Error(kind)).into()
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        let cat = e.classify();
        e.context(ErrorKind::SerdeJson_Error(cat)).into()
    }
}
#[allow(dead_code)]
pub type Result<T> = ::std::result::Result<T, Error>;
impl From<varlink::Error> for Error {
    fn from(e: varlink::Error) -> Self {
        let kind = e.kind();
        match kind {
            varlink::ErrorKind::Io(kind) => e.context(ErrorKind::Io_Error(kind)).into(),
            varlink::ErrorKind::SerdeJsonSer(cat) => {
                e.context(ErrorKind::SerdeJson_Error(cat)).into()
            }
            kind => e.context(ErrorKind::Varlink_Error(kind)).into(),
        }
    }
}
impl From<varlink::Reply> for Error {
    fn from(e: varlink::Reply) -> Self {
        if varlink::Error::is_error(&e) {
            return varlink::Error::from(e).into();
        }
        match e {
            varlink::Reply {
                error: Some(ref t), ..
            } if t == "io.systemd.network.UnknownError" => match e {
                varlink::Reply {
                    parameters: Some(p),
                    ..
                } => match serde_json::from_value(p) {
                    Ok(v) => ErrorKind::UnknownError(v).into(),
                    Err(_) => ErrorKind::UnknownError(None).into(),
                },
                _ => ErrorKind::UnknownError(None).into(),
            },
            varlink::Reply {
                error: Some(ref t), ..
            } if t == "io.systemd.network.UnknownNetworkIfIndex" => match e {
                varlink::Reply {
                    parameters: Some(p),
                    ..
                } => match serde_json::from_value(p) {
                    Ok(v) => ErrorKind::UnknownNetworkIfIndex(v).into(),
                    Err(_) => ErrorKind::UnknownNetworkIfIndex(None).into(),
                },
                _ => ErrorKind::UnknownNetworkIfIndex(None).into(),
            },
            _ => ErrorKind::VarlinkReply_Error(e).into(),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Info_Reply {
    pub r#info: NetdevInfo,
}
impl varlink::VarlinkReply for Info_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Info_Args {
    pub r#ifindex: i64,
}
pub trait Call_Info: VarlinkCallError {
    fn reply(&mut self, r#info: NetdevInfo) -> varlink::Result<()> {
        self.reply_struct(Info_Reply { r#info }.into())
    }
}
impl<'a> Call_Info for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct List_Reply {
    pub r#netdevs: Vec<Netdev>,
}
impl varlink::VarlinkReply for List_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct List_Args {}
pub trait Call_List: VarlinkCallError {
    fn reply(&mut self, r#netdevs: Vec<Netdev>) -> varlink::Result<()> {
        self.reply_struct(List_Reply { r#netdevs }.into())
    }
}
impl<'a> Call_List for varlink::Call<'a> {}
pub trait VarlinkInterface {
    fn info(&self, call: &mut Call_Info, r#ifindex: i64) -> varlink::Result<()>;
    fn list(&self, call: &mut Call_List) -> varlink::Result<()>;
    fn call_upgraded(
        &self,
        _call: &mut varlink::Call,
        _bufreader: &mut BufRead,
    ) -> varlink::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
pub trait VarlinkClientInterface {
    fn info(&mut self, r#ifindex: i64) -> varlink::MethodCall<Info_Args, Info_Reply, Error>;
    fn list(&mut self) -> varlink::MethodCall<List_Args, List_Reply, Error>;
}
#[allow(dead_code)]
pub struct VarlinkClient {
    connection: Arc<RwLock<varlink::Connection>>,
}
impl VarlinkClient {
    #[allow(dead_code)]
    pub fn new(connection: Arc<RwLock<varlink::Connection>>) -> Self {
        VarlinkClient { connection }
    }
}
impl VarlinkClientInterface for VarlinkClient {
    fn info(&mut self, r#ifindex: i64) -> varlink::MethodCall<Info_Args, Info_Reply, Error> {
        varlink::MethodCall::<Info_Args, Info_Reply, Error>::new(
            self.connection.clone(),
            "io.systemd.network.Info",
            Info_Args { r#ifindex },
        )
    }
    fn list(&mut self) -> varlink::MethodCall<List_Args, List_Reply, Error> {
        varlink::MethodCall::<List_Args, List_Reply, Error>::new(
            self.connection.clone(),
            "io.systemd.network.List",
            List_Args {},
        )
    }
}
#[allow(dead_code)]
pub struct VarlinkInterfaceProxy {
    inner: Box<VarlinkInterface + Send + Sync>,
}
#[allow(dead_code)]
pub fn new(inner: Box<VarlinkInterface + Send + Sync>) -> VarlinkInterfaceProxy {
    VarlinkInterfaceProxy { inner }
}
impl varlink::Interface for VarlinkInterfaceProxy {
    fn get_description(&self) -> &'static str {
        "# Provides information about network state\n#\ninterface io.systemd.network\n\ntype NetdevInfo (\n  ifindex: int,\n  ifname: string\n)\n\ntype Netdev (\n  ifindex: int,\n  ifname: string\n)\n\n# Returns information about a network device\nmethod Info(ifindex: int) -> (info: NetdevInfo)\n\n# Lists all network devices\nmethod List() -> (netdevs: []Netdev)\n\nerror UnknownNetworkIfIndex (ifindex: int)\nerror UnknownError (text: string)\n"
    }
    fn get_name(&self) -> &'static str {
        "io.systemd.network"
    }
    fn call_upgraded(
        &self,
        call: &mut varlink::Call,
        bufreader: &mut BufRead,
    ) -> varlink::Result<Vec<u8>> {
        self.inner.call_upgraded(call, bufreader)
    }
    fn call(&self, call: &mut varlink::Call) -> varlink::Result<()> {
        let req = call.request.unwrap();
        match req.method.as_ref() {
            "io.systemd.network.Info" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Info_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner.info(call as &mut Call_Info, args.r#ifindex)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "io.systemd.network.List" => self.inner.list(call as &mut Call_List),
            m => call.reply_method_not_found(String::from(m)),
        }
    }
}
