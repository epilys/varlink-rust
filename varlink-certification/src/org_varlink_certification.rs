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
pub enum r#Interface_foo {
    r#foo,
    r#bar,
    r#baz,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#Interface_anon {
    pub r#foo: bool,
    pub r#bar: bool,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#Interface {
    pub r#foo: Option<Vec<Option<varlink::StringHashMap<Interface_foo>>>>,
    pub r#anon: Interface_anon,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum r#MyType_enum {
    r#one,
    r#two,
    r#three,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#MyType_struct {
    pub r#first: i64,
    pub r#second: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#MyType_nullable_array_struct {
    pub r#first: i64,
    pub r#second: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#MyType {
    pub r#object: serde_json::Value,
    pub r#enum: MyType_enum,
    pub r#struct: MyType_struct,
    pub r#array: Vec<String>,
    pub r#dictionary: varlink::StringHashMap<String>,
    pub r#stringset: varlink::StringHashSet,
    pub r#nullable: Option<String>,
    pub r#nullable_array_struct: Option<Vec<MyType_nullable_array_struct>>,
    pub r#interface: Interface,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CertificationError_Args {
    pub r#wants: serde_json::Value,
    pub r#got: serde_json::Value,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ClientIdError_Args {}
pub trait VarlinkCallError: varlink::CallTrait {
    fn reply_certification_error(
        &mut self,
        r#wants: serde_json::Value,
        r#got: serde_json::Value,
    ) -> varlink::Result<()> {
        self.reply_struct(varlink::Reply::error(
            "org.varlink.certification.CertificationError",
            Some(serde_json::to_value(CertificationError_Args {
                r#wants,
                r#got,
            })?),
        ))
    }
    fn reply_client_id_error(&mut self) -> varlink::Result<()> {
        self.reply_struct(varlink::Reply::error(
            "org.varlink.certification.ClientIdError",
            None,
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
    #[fail(display = "org.varlink.certification.CertificationError: {:#?}", _0)]
    CertificationError(Option<CertificationError_Args>),
    #[fail(display = "org.varlink.certification.ClientIdError: {:#?}", _0)]
    ClientIdError(Option<ClientIdError_Args>),
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
            } if t == "org.varlink.certification.CertificationError" => match e {
                varlink::Reply {
                    parameters: Some(p),
                    ..
                } => match serde_json::from_value(p) {
                    Ok(v) => ErrorKind::CertificationError(v).into(),
                    Err(_) => ErrorKind::CertificationError(None).into(),
                },
                _ => ErrorKind::CertificationError(None).into(),
            },
            varlink::Reply {
                error: Some(ref t), ..
            } if t == "org.varlink.certification.ClientIdError" => match e {
                varlink::Reply {
                    parameters: Some(p),
                    ..
                } => match serde_json::from_value(p) {
                    Ok(v) => ErrorKind::ClientIdError(v).into(),
                    Err(_) => ErrorKind::ClientIdError(None).into(),
                },
                _ => ErrorKind::ClientIdError(None).into(),
            },
            _ => ErrorKind::VarlinkReply_Error(e).into(),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct End_Reply {
    pub r#all_ok: bool,
}
impl varlink::VarlinkReply for End_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct End_Args {
    pub r#client_id: String,
}
pub trait Call_End: VarlinkCallError {
    fn reply(&mut self, r#all_ok: bool) -> varlink::Result<()> {
        self.reply_struct(End_Reply { r#all_ok }.into())
    }
}
impl<'a> Call_End for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Start_Reply {
    pub r#client_id: String,
}
impl varlink::VarlinkReply for Start_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Start_Args {}
pub trait Call_Start: VarlinkCallError {
    fn reply(&mut self, r#client_id: String) -> varlink::Result<()> {
        self.reply_struct(Start_Reply { r#client_id }.into())
    }
}
impl<'a> Call_Start for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test01_Reply {
    pub r#bool: bool,
}
impl varlink::VarlinkReply for Test01_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test01_Args {
    pub r#client_id: String,
}
pub trait Call_Test01: VarlinkCallError {
    fn reply(&mut self, r#bool: bool) -> varlink::Result<()> {
        self.reply_struct(Test01_Reply { r#bool }.into())
    }
}
impl<'a> Call_Test01 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test02_Reply {
    pub r#int: i64,
}
impl varlink::VarlinkReply for Test02_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test02_Args {
    pub r#client_id: String,
    pub r#bool: bool,
}
pub trait Call_Test02: VarlinkCallError {
    fn reply(&mut self, r#int: i64) -> varlink::Result<()> {
        self.reply_struct(Test02_Reply { r#int }.into())
    }
}
impl<'a> Call_Test02 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test03_Reply {
    pub r#float: f64,
}
impl varlink::VarlinkReply for Test03_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test03_Args {
    pub r#client_id: String,
    pub r#int: i64,
}
pub trait Call_Test03: VarlinkCallError {
    fn reply(&mut self, r#float: f64) -> varlink::Result<()> {
        self.reply_struct(Test03_Reply { r#float }.into())
    }
}
impl<'a> Call_Test03 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test04_Reply {
    pub r#string: String,
}
impl varlink::VarlinkReply for Test04_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test04_Args {
    pub r#client_id: String,
    pub r#float: f64,
}
pub trait Call_Test04: VarlinkCallError {
    fn reply(&mut self, r#string: String) -> varlink::Result<()> {
        self.reply_struct(Test04_Reply { r#string }.into())
    }
}
impl<'a> Call_Test04 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test05_Reply {
    pub r#bool: bool,
    pub r#int: i64,
    pub r#float: f64,
    pub r#string: String,
}
impl varlink::VarlinkReply for Test05_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test05_Args {
    pub r#client_id: String,
    pub r#string: String,
}
pub trait Call_Test05: VarlinkCallError {
    fn reply(
        &mut self,
        r#bool: bool,
        r#int: i64,
        r#float: f64,
        r#string: String,
    ) -> varlink::Result<()> {
        self.reply_struct(
            Test05_Reply {
                r#bool,
                r#int,
                r#float,
                r#string,
            }
            .into(),
        )
    }
}
impl<'a> Call_Test05 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#Test06_Reply_struct {
    pub r#bool: bool,
    pub r#int: i64,
    pub r#float: f64,
    pub r#string: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test06_Reply {
    pub r#struct: Test06_Reply_struct,
}
impl varlink::VarlinkReply for Test06_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test06_Args {
    pub r#client_id: String,
    pub r#bool: bool,
    pub r#int: i64,
    pub r#float: f64,
    pub r#string: String,
}
pub trait Call_Test06: VarlinkCallError {
    fn reply(&mut self, r#struct: Test06_Reply_struct) -> varlink::Result<()> {
        self.reply_struct(Test06_Reply { r#struct }.into())
    }
}
impl<'a> Call_Test06 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct r#Test07_Args_struct {
    pub r#bool: bool,
    pub r#int: i64,
    pub r#float: f64,
    pub r#string: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test07_Reply {
    pub r#map: varlink::StringHashMap<String>,
}
impl varlink::VarlinkReply for Test07_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test07_Args {
    pub r#client_id: String,
    pub r#struct: Test07_Args_struct,
}
pub trait Call_Test07: VarlinkCallError {
    fn reply(&mut self, r#map: varlink::StringHashMap<String>) -> varlink::Result<()> {
        self.reply_struct(Test07_Reply { r#map }.into())
    }
}
impl<'a> Call_Test07 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test08_Reply {
    pub r#set: varlink::StringHashSet,
}
impl varlink::VarlinkReply for Test08_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test08_Args {
    pub r#client_id: String,
    pub r#map: varlink::StringHashMap<String>,
}
pub trait Call_Test08: VarlinkCallError {
    fn reply(&mut self, r#set: varlink::StringHashSet) -> varlink::Result<()> {
        self.reply_struct(Test08_Reply { r#set }.into())
    }
}
impl<'a> Call_Test08 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test09_Reply {
    pub r#mytype: MyType,
}
impl varlink::VarlinkReply for Test09_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test09_Args {
    pub r#client_id: String,
    pub r#set: varlink::StringHashSet,
}
pub trait Call_Test09: VarlinkCallError {
    fn reply(&mut self, r#mytype: MyType) -> varlink::Result<()> {
        self.reply_struct(Test09_Reply { r#mytype }.into())
    }
}
impl<'a> Call_Test09 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test10_Reply {
    pub r#string: String,
}
impl varlink::VarlinkReply for Test10_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test10_Args {
    pub r#client_id: String,
    pub r#mytype: MyType,
}
pub trait Call_Test10: VarlinkCallError {
    fn reply(&mut self, r#string: String) -> varlink::Result<()> {
        self.reply_struct(Test10_Reply { r#string }.into())
    }
}
impl<'a> Call_Test10 for varlink::Call<'a> {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test11_Reply {}
impl varlink::VarlinkReply for Test11_Reply {}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Test11_Args {
    pub r#client_id: String,
    pub r#last_more_replies: Vec<String>,
}
pub trait Call_Test11: VarlinkCallError {
    fn reply(&mut self) -> varlink::Result<()> {
        self.reply_struct(varlink::Reply::parameters(None))
    }
}
impl<'a> Call_Test11 for varlink::Call<'a> {}
pub trait VarlinkInterface {
    fn end(&self, call: &mut Call_End, r#client_id: String) -> varlink::Result<()>;
    fn start(&self, call: &mut Call_Start) -> varlink::Result<()>;
    fn test01(&self, call: &mut Call_Test01, r#client_id: String) -> varlink::Result<()>;
    fn test02(
        &self,
        call: &mut Call_Test02,
        r#client_id: String,
        r#bool: bool,
    ) -> varlink::Result<()>;
    fn test03(
        &self,
        call: &mut Call_Test03,
        r#client_id: String,
        r#int: i64,
    ) -> varlink::Result<()>;
    fn test04(
        &self,
        call: &mut Call_Test04,
        r#client_id: String,
        r#float: f64,
    ) -> varlink::Result<()>;
    fn test05(
        &self,
        call: &mut Call_Test05,
        r#client_id: String,
        r#string: String,
    ) -> varlink::Result<()>;
    fn test06(
        &self,
        call: &mut Call_Test06,
        r#client_id: String,
        r#bool: bool,
        r#int: i64,
        r#float: f64,
        r#string: String,
    ) -> varlink::Result<()>;
    fn test07(
        &self,
        call: &mut Call_Test07,
        r#client_id: String,
        r#struct: Test07_Args_struct,
    ) -> varlink::Result<()>;
    fn test08(
        &self,
        call: &mut Call_Test08,
        r#client_id: String,
        r#map: varlink::StringHashMap<String>,
    ) -> varlink::Result<()>;
    fn test09(
        &self,
        call: &mut Call_Test09,
        r#client_id: String,
        r#set: varlink::StringHashSet,
    ) -> varlink::Result<()>;
    fn test10(
        &self,
        call: &mut Call_Test10,
        r#client_id: String,
        r#mytype: MyType,
    ) -> varlink::Result<()>;
    fn test11(
        &self,
        call: &mut Call_Test11,
        r#client_id: String,
        r#last_more_replies: Vec<String>,
    ) -> varlink::Result<()>;
    fn call_upgraded(
        &self,
        _call: &mut varlink::Call,
        _bufreader: &mut BufRead,
    ) -> varlink::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
pub trait VarlinkClientInterface {
    fn end(&mut self, r#client_id: String) -> varlink::MethodCall<End_Args, End_Reply, Error>;
    fn start(&mut self) -> varlink::MethodCall<Start_Args, Start_Reply, Error>;
    fn test01(
        &mut self,
        r#client_id: String,
    ) -> varlink::MethodCall<Test01_Args, Test01_Reply, Error>;
    fn test02(
        &mut self,
        r#client_id: String,
        r#bool: bool,
    ) -> varlink::MethodCall<Test02_Args, Test02_Reply, Error>;
    fn test03(
        &mut self,
        r#client_id: String,
        r#int: i64,
    ) -> varlink::MethodCall<Test03_Args, Test03_Reply, Error>;
    fn test04(
        &mut self,
        r#client_id: String,
        r#float: f64,
    ) -> varlink::MethodCall<Test04_Args, Test04_Reply, Error>;
    fn test05(
        &mut self,
        r#client_id: String,
        r#string: String,
    ) -> varlink::MethodCall<Test05_Args, Test05_Reply, Error>;
    fn test06(
        &mut self,
        r#client_id: String,
        r#bool: bool,
        r#int: i64,
        r#float: f64,
        r#string: String,
    ) -> varlink::MethodCall<Test06_Args, Test06_Reply, Error>;
    fn test07(
        &mut self,
        r#client_id: String,
        r#struct: Test07_Args_struct,
    ) -> varlink::MethodCall<Test07_Args, Test07_Reply, Error>;
    fn test08(
        &mut self,
        r#client_id: String,
        r#map: varlink::StringHashMap<String>,
    ) -> varlink::MethodCall<Test08_Args, Test08_Reply, Error>;
    fn test09(
        &mut self,
        r#client_id: String,
        r#set: varlink::StringHashSet,
    ) -> varlink::MethodCall<Test09_Args, Test09_Reply, Error>;
    fn test10(
        &mut self,
        r#client_id: String,
        r#mytype: MyType,
    ) -> varlink::MethodCall<Test10_Args, Test10_Reply, Error>;
    fn test11(
        &mut self,
        r#client_id: String,
        r#last_more_replies: Vec<String>,
    ) -> varlink::MethodCall<Test11_Args, Test11_Reply, Error>;
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
    fn end(&mut self, r#client_id: String) -> varlink::MethodCall<End_Args, End_Reply, Error> {
        varlink::MethodCall::<End_Args, End_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.End",
            End_Args { r#client_id },
        )
    }
    fn start(&mut self) -> varlink::MethodCall<Start_Args, Start_Reply, Error> {
        varlink::MethodCall::<Start_Args, Start_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Start",
            Start_Args {},
        )
    }
    fn test01(
        &mut self,
        r#client_id: String,
    ) -> varlink::MethodCall<Test01_Args, Test01_Reply, Error> {
        varlink::MethodCall::<Test01_Args, Test01_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test01",
            Test01_Args { r#client_id },
        )
    }
    fn test02(
        &mut self,
        r#client_id: String,
        r#bool: bool,
    ) -> varlink::MethodCall<Test02_Args, Test02_Reply, Error> {
        varlink::MethodCall::<Test02_Args, Test02_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test02",
            Test02_Args {
                r#client_id,
                r#bool,
            },
        )
    }
    fn test03(
        &mut self,
        r#client_id: String,
        r#int: i64,
    ) -> varlink::MethodCall<Test03_Args, Test03_Reply, Error> {
        varlink::MethodCall::<Test03_Args, Test03_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test03",
            Test03_Args { r#client_id, r#int },
        )
    }
    fn test04(
        &mut self,
        r#client_id: String,
        r#float: f64,
    ) -> varlink::MethodCall<Test04_Args, Test04_Reply, Error> {
        varlink::MethodCall::<Test04_Args, Test04_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test04",
            Test04_Args {
                r#client_id,
                r#float,
            },
        )
    }
    fn test05(
        &mut self,
        r#client_id: String,
        r#string: String,
    ) -> varlink::MethodCall<Test05_Args, Test05_Reply, Error> {
        varlink::MethodCall::<Test05_Args, Test05_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test05",
            Test05_Args {
                r#client_id,
                r#string,
            },
        )
    }
    fn test06(
        &mut self,
        r#client_id: String,
        r#bool: bool,
        r#int: i64,
        r#float: f64,
        r#string: String,
    ) -> varlink::MethodCall<Test06_Args, Test06_Reply, Error> {
        varlink::MethodCall::<Test06_Args, Test06_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test06",
            Test06_Args {
                r#client_id,
                r#bool,
                r#int,
                r#float,
                r#string,
            },
        )
    }
    fn test07(
        &mut self,
        r#client_id: String,
        r#struct: Test07_Args_struct,
    ) -> varlink::MethodCall<Test07_Args, Test07_Reply, Error> {
        varlink::MethodCall::<Test07_Args, Test07_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test07",
            Test07_Args {
                r#client_id,
                r#struct,
            },
        )
    }
    fn test08(
        &mut self,
        r#client_id: String,
        r#map: varlink::StringHashMap<String>,
    ) -> varlink::MethodCall<Test08_Args, Test08_Reply, Error> {
        varlink::MethodCall::<Test08_Args, Test08_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test08",
            Test08_Args { r#client_id, r#map },
        )
    }
    fn test09(
        &mut self,
        r#client_id: String,
        r#set: varlink::StringHashSet,
    ) -> varlink::MethodCall<Test09_Args, Test09_Reply, Error> {
        varlink::MethodCall::<Test09_Args, Test09_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test09",
            Test09_Args { r#client_id, r#set },
        )
    }
    fn test10(
        &mut self,
        r#client_id: String,
        r#mytype: MyType,
    ) -> varlink::MethodCall<Test10_Args, Test10_Reply, Error> {
        varlink::MethodCall::<Test10_Args, Test10_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test10",
            Test10_Args {
                r#client_id,
                r#mytype,
            },
        )
    }
    fn test11(
        &mut self,
        r#client_id: String,
        r#last_more_replies: Vec<String>,
    ) -> varlink::MethodCall<Test11_Args, Test11_Reply, Error> {
        varlink::MethodCall::<Test11_Args, Test11_Reply, Error>::new(
            self.connection.clone(),
            "org.varlink.certification.Test11",
            Test11_Args {
                r#client_id,
                r#last_more_replies,
            },
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
        "# Interface to test varlink implementations against.\n# First you write a varlink client calling:\n# Start, Test01, Test02, \u{2026}, Test09, End\n# The return value of the previous call should be the argument of the next call.\n# Then you test this client against well known servers like python or rust from\n# https://github.com/varlink/\n#\n# Next you write a varlink server providing the same service as the well known ones.\n# Now run your client against it and run well known clients like python or rust\n# from https://github.com/varlink/ against your server. If all works out, then\n# your new language bindings should be varlink certified.\ninterface org.varlink.certification\n\ntype Interface (\n  foo: ?[]?[string](foo, bar, baz),\n  anon: (foo: bool, bar: bool)\n)\n\ntype MyType (\n  object: object,\n  enum: (one, two, three),\n  struct: (first: int, second: string),\n  array: []string,\n  dictionary: [string]string,\n  stringset: [string](),\n  nullable: ?string,\n  nullable_array_struct: ?[](first: int, second: string),\n  interface: Interface\n)\n\nmethod Start() -> (client_id: string)\n\nmethod Test01(client_id: string) -> (bool: bool)\n\nmethod Test02(client_id: string, bool: bool) -> (int: int)\n\nmethod Test03(client_id: string, int: int) -> (float: float)\n\nmethod Test04(client_id: string, float: float) -> (string: string)\n\nmethod Test05(client_id: string, string: string) -> (\n  bool: bool,\n  int: int,\n  float: float,\n  string: string\n)\n\nmethod Test06(\n  client_id: string,\n  bool: bool,\n  int: int,\n  float: float,\n  string: string\n) -> (\n  struct: (\n    bool: bool,\n    int: int,\n    float: float,\n    string: string\n  )\n)\n\nmethod Test07(\n  client_id: string,\n  struct: (\n    bool: bool,\n    int: int,\n    float: float,\n    string: string\n  )\n) -> (map: [string]string)\n\nmethod Test08(client_id: string, map: [string]string) -> (set: [string]())\n\nmethod Test09(client_id: string, set: [string]()) -> (mytype: MyType)\n\n# returns more than one reply with \"continues\"\nmethod Test10(client_id: string, mytype: MyType) -> (string: string)\n\n# must be called as \"oneway\"\nmethod Test11(client_id: string, last_more_replies: []string) -> ()\n\nmethod End(client_id: string) -> (all_ok: bool)\n\nerror ClientIdError ()\nerror CertificationError (wants: object, got: object)\n"
    }
    fn get_name(&self) -> &'static str {
        "org.varlink.certification"
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
            "org.varlink.certification.End" => {
                if let Some(args) = req.parameters.clone() {
                    let args: End_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner.end(call as &mut Call_End, args.r#client_id)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Start" => self.inner.start(call as &mut Call_Start),
            "org.varlink.certification.Test01" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test01_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test01(call as &mut Call_Test01, args.r#client_id)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test02" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test02_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test02(call as &mut Call_Test02, args.r#client_id, args.r#bool)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test03" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test03_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test03(call as &mut Call_Test03, args.r#client_id, args.r#int)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test04" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test04_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test04(call as &mut Call_Test04, args.r#client_id, args.r#float)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test05" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test05_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test05(call as &mut Call_Test05, args.r#client_id, args.r#string)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test06" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test06_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner.test06(
                        call as &mut Call_Test06,
                        args.r#client_id,
                        args.r#bool,
                        args.r#int,
                        args.r#float,
                        args.r#string,
                    )
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test07" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test07_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test07(call as &mut Call_Test07, args.r#client_id, args.r#struct)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test08" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test08_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test08(call as &mut Call_Test08, args.r#client_id, args.r#map)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test09" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test09_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test09(call as &mut Call_Test09, args.r#client_id, args.r#set)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test10" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test10_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner
                        .test10(call as &mut Call_Test10, args.r#client_id, args.r#mytype)
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            "org.varlink.certification.Test11" => {
                if let Some(args) = req.parameters.clone() {
                    let args: Test11_Args = match serde_json::from_value(args) {
                        Ok(v) => v,
                        Err(e) => {
                            let es = format!("{}", e);
                            let _ = call.reply_invalid_parameter(es.clone());
                            return Err(varlink::ErrorKind::SerdeJsonDe(es).into());
                        }
                    };
                    self.inner.test11(
                        call as &mut Call_Test11,
                        args.r#client_id,
                        args.r#last_more_replies,
                    )
                } else {
                    call.reply_invalid_parameter("parameters".into())
                }
            }
            m => call.reply_method_not_found(String::from(m)),
        }
    }
}
