//! The MCP server of one request: the library's, its tool calls made
//! through the caller's client.

use std::sync::{Arc, Mutex};

use origincloud_mcp::{ClientSource, Options, Server, UnknownToolset};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ListToolsResult, PaginatedRequestParams, ServerConfig,
    Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer};

use crate::auth::Caller;
use crate::clients::Registry;
use crate::metrics;

/// The library's server, with what it doesn't know: who calls.
pub struct Session {
    inner: Server,
    caller: Arc<Mutex<Option<Caller>>>,
}

impl Session {
    /// A session exposing what `options` select, whose tool calls go
    /// through the clients of `registry`.
    pub fn new(registry: Arc<Registry>, options: Options) -> Result<Self, UnknownToolset> {
        let caller = Arc::new(Mutex::new(None));
        let source = CallerClients {
            caller: Arc::clone(&caller),
            registry,
        };
        Ok(Self {
            inner: Server::new(source, options)?,
            caller,
        })
    }
}

/// The client of the caller of the tool call being made.
struct CallerClients {
    caller: Arc<Mutex<Option<Caller>>>,
    registry: Arc<Registry>,
}

impl ClientSource for CallerClients {
    fn client(&self, _service: &str) -> Result<origincloud_core::Client, origincloud_core::Error> {
        let caller = self
            .caller
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match caller {
            Some(caller) => self.registry.client(&caller),
            None => Err(origincloud_core::Error::NoCredentials),
        }
    }
}

/// The caller the authentication put on the request's HTTP parts.
fn caller(context: &RequestContext<RoleServer>) -> Option<Caller> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Caller>())
        .cloned()
}

impl ServerHandler for Session {
    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.inner.list_tools(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(caller) = caller(&context) else {
            // The authentication runs before every request reaches here.
            return Err(McpError::internal_error("the request has no caller", None));
        };
        *self.caller.lock().unwrap_or_else(|e| e.into_inner()) = Some(caller);
        let tool = if self.inner.get_tool(&request.name).is_some() {
            request.name.to_string()
        } else {
            "other".to_owned()
        };
        let response = self.inner.call_tool(request, context).await;
        let outcome = match &response {
            Ok(r) if failed(r) => "error",
            Ok(_) => "ok",
            Err(_) => "protocol_error",
        };
        metrics::tool_call(&tool, outcome);
        response
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }
}

/// Whether a tool call's response is the tool's error.
fn failed(response: &CallToolResponse) -> bool {
    matches!(response, CallToolResponse::Complete(result) if result.is_error == Some(true))
}
