//! The plugin trait and the registration API plugins (and the app) use in `init`.

use std::any::{Any, TypeId, type_name};
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use http::Method;

use crate::adapter::Adapter;
use crate::endpoint::{
    After, Before, Ctx, Endpoint, EndpointHooks, Erased, ErasedAfter, ErasedBefore, ErasedEndpoint,
    ErasedEventHandler, ErasedResolver, ErasedResponseHook, Gate, HookCtx, OwnedGate, Response,
    SessionResolver, SignInAttempt,
};
use crate::error::{AuthError, ErrorCodes};
use crate::events::Event;
use crate::model::Fields;
use crate::rate_limit::{Limit, Rule};
use crate::schema::SchemaBuilder;

/// A fastauth plugin. See `docs/05-plugins.md`.
pub trait Plugin: Send + Sync + Sized + 'static {
    /// Unique id, used in error messages, schema ownership and derived keys.
    const ID: &'static str;
    /// Plugins that must be registered before this one, as a tuple: `()`, `(Organization,)`.
    type Requires;
    /// Columns this plugin adds to `user`; `()` for none.
    type UserFields: Fields;
    /// Columns this plugin adds to `session`; `()` for none.
    type SessionFields: Fields;

    /// Adds tables (`schema.model::<M>()`) or columns. `UserFields` and `SessionFields` are
    /// added automatically.
    fn schema(&self, schema: &mut SchemaBuilder) {
        let _ = schema;
    }

    /// Registers endpoints, hooks, gates, resolvers, events, rate limits and error codes.
    /// Runs once, inside `.build()`.
    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        let _ = app;
    }
}

pub(crate) struct RouteDef<D> {
    pub method: Method,
    pub path: &'static str,
    pub owner: &'static str,
    pub type_id: TypeId,
    pub endpoint: Arc<dyn ErasedEndpoint<D>>,
}

/// Everything registered during `.build()`, before it is frozen into `Shared`.
pub struct Registry<D> {
    pub(crate) schema: SchemaBuilder,
    pub(crate) plugins: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    pub(crate) routes: Vec<RouteDef<D>>,
    pub(crate) hooks: HashMap<TypeId, EndpointHooks<D>>,
    pub(crate) hook_targets: Vec<(TypeId, &'static str, &'static str)>,
    pub(crate) server_endpoints: Vec<TypeId>,
    pub(crate) gates: Vec<OwnedGate<D>>,
    pub(crate) resolvers: Vec<Arc<dyn ErasedResolver<D>>>,
    pub(crate) response_hooks: Vec<ErasedResponseHook<D>>,
    pub(crate) events: HashMap<TypeId, Vec<ErasedEventHandler<D>>>,
    pub(crate) rate_rules: Vec<Rule>,
    pub(crate) error_codes: Vec<(&'static str, &'static str)>,
    pub(crate) errors: Vec<String>,
    pub(crate) owner: &'static str,
}

impl<D: Adapter> Registry<D> {
    pub(crate) fn new() -> Self {
        Self {
            schema: SchemaBuilder::new(),
            plugins: HashMap::new(),
            routes: Vec::new(),
            hooks: HashMap::new(),
            hook_targets: Vec::new(),
            server_endpoints: Vec::new(),
            gates: Vec::new(),
            resolvers: Vec::new(),
            response_hooks: Vec::new(),
            events: HashMap::new(),
            rate_rules: Vec::new(),
            error_codes: Vec::new(),
            errors: Vec::new(),
            owner: "core",
        }
    }

    pub(crate) fn set_owner(&mut self, owner: &'static str) {
        self.owner = owner;
        self.schema.owner = owner;
    }

    pub(crate) fn register_plugin<P: Plugin>(&mut self, plugin: &Arc<P>) {
        if self
            .plugins
            .insert(TypeId::of::<P>(), plugin.clone())
            .is_some()
        {
            self.errors
                .push(format!("plugin `{}` is registered twice", P::ID));
            return;
        }
        let previous = self.owner;
        self.set_owner(P::ID);
        self.schema.extend("user", P::UserFields::columns());
        self.schema.extend("session", P::SessionFields::columns());
        plugin.schema(&mut self.schema);
        plugin.init(&mut PluginBuilder { registry: self });
        self.set_owner(previous);
    }
}

/// What `Plugin::init` (and `Builder::configure`) registers things with.
pub struct PluginBuilder<'r, D> {
    pub(crate) registry: &'r mut Registry<D>,
}

impl<D: Adapter> PluginBuilder<'_, D> {
    /// Id of the plugin being initialised (`"app"` for `Builder::configure`).
    pub fn owner(&self) -> &'static str {
        self.registry.owner
    }

    /// Adds tables or columns (normally done in `Plugin::schema`).
    pub fn schema(&mut self) -> &mut SchemaBuilder {
        &mut self.registry.schema
    }

    pub fn endpoint<E: Endpoint<D>>(&mut self, endpoint: E) -> &mut Self {
        let registry = &mut *self.registry;
        if let Some(clash) = registry
            .routes
            .iter()
            .find(|r| r.method == E::METHOD && r.path == E::PATH)
        {
            registry.errors.push(format!(
                "route {} {} is registered by both `{}` and `{}`",
                E::METHOD,
                E::PATH,
                clash.owner,
                registry.owner
            ));
            return self;
        }
        registry.routes.push(RouteDef {
            method: E::METHOD,
            path: E::PATH,
            owner: registry.owner,
            type_id: TypeId::of::<E>(),
            endpoint: Arc::new(Erased(endpoint)),
        });
        self
    }

    /// Declares an endpoint with no HTTP route, one only the server API calls through
    /// `auth.api().call(..)`, so hooks may target it like a routed one.
    pub fn server_endpoint<E: Endpoint<D>>(&mut self) -> &mut Self {
        self.registry.server_endpoints.push(TypeId::of::<E>());
        self
    }

    /// Hooks around endpoint `E`, for every caller: `app.hook::<SignUpEmail>().before(..)`.
    pub fn hook<E: Endpoint<D>>(&mut self) -> HookBuilder<'_, D, E> {
        self.registry
            .hook_targets
            .push((TypeId::of::<E>(), type_name::<E>(), self.registry.owner));
        HookBuilder {
            registry: self.registry,
            _endpoint: PhantomData,
        }
    }

    /// Runs after credentials check out and before a session exists, for every sign-in method.
    /// Gates run in registration order. The gate belongs to [`owner`](Self::owner): when it
    /// answers [`Gate::Challenge`], this plugin finishes the sign-in with
    /// [`Internal::complete_sign_in`](crate::internal::Internal::complete_sign_in) and its own id.
    pub fn sign_in_gate<F, Fut>(&mut self, gate: F) -> &mut Self
    where
        F: Fn(HookCtx<D>, SignInAttempt) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Gate, AuthError>> + Send + 'static,
    {
        let owner = self.registry.owner;
        self.registry.gates.push(OwnedGate {
            owner,
            gate: Arc::new(move |ctx, attempt| Box::pin(gate(ctx, attempt))),
        });
        self
    }

    /// Turns non-cookie credentials (bearer tokens, API keys) into a session.
    pub fn session_resolver(&mut self, resolver: impl SessionResolver<D>) -> &mut Self {
        self.registry.resolvers.push(Arc::new(resolver));
        self
    }

    /// Runs on the HTTP response of every routed endpoint, after its cookies and headers are
    /// set, in registration order. For headers derived from the response itself, like a
    /// bearer plugin copying the session cookie into `set-auth-token`. Server API calls
    /// don't run it.
    pub fn on_response(
        &mut self,
        hook: impl Fn(&Ctx<D>, &mut Response) + Send + Sync + 'static,
    ) -> &mut Self {
        self.registry.response_hooks.push(Arc::new(hook));
        self
    }

    /// Runs after any endpoint that emitted `Ev` succeeds. Errors are logged, not returned.
    pub fn on<Ev, F, Fut>(&mut self, handler: F) -> &mut Self
    where
        Ev: Event,
        F: Fn(Ev, Ctx<D>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), AuthError>> + Send + 'static,
    {
        let erased: ErasedEventHandler<D> = Arc::new(move |event, ctx| {
            let event = event
                .downcast_ref::<Ev>()
                .expect("event routed by TypeId")
                .clone();
            Box::pin(handler(event, ctx))
        });
        self.registry
            .events
            .entry(TypeId::of::<Ev>())
            .or_default()
            .push(erased);
        self
    }

    /// A rate-limit rule for a path pattern (`/two-factor/*`). App rules win over plugin rules.
    pub fn rate_limit(&mut self, pattern: impl Into<String>, limit: Limit) -> &mut Self {
        self.registry.rate_rules.push(Rule {
            pattern: pattern.into(),
            limit,
        });
        self
    }

    /// Registers error codes so two plugins can't claim the same one.
    pub fn errors<E: ErrorCodes>(&mut self) -> &mut Self {
        let owner = self.registry.owner;
        for code in E::CODES {
            if let Some((_, first)) = self.registry.error_codes.iter().find(|(c, _)| c == code) {
                self.registry.errors.push(format!(
                    "error code `{code}` is registered by both `{first}` and `{owner}`"
                ));
                continue;
            }
            self.registry.error_codes.push((code, owner));
        }
        self
    }
}

pub struct HookBuilder<'r, D, E> {
    registry: &'r mut Registry<D>,
    _endpoint: PhantomData<fn() -> E>,
}

impl<D: Adapter, E: Endpoint<D>> HookBuilder<'_, D, E> {
    /// Runs before `E` with its typed input. Return `Before::Continue(input)` to proceed.
    pub fn before<F, Fut>(self, hook: F) -> Self
    where
        F: Fn(HookCtx<D>, E::Input) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Before<E::Input>, AuthError>> + Send + 'static,
    {
        let hook = Arc::new(hook);
        let erased: ErasedBefore<D> = Arc::new(move |ctx, input| {
            let hook = hook.clone();
            Box::pin(async move {
                let input = *input.downcast::<E::Input>().expect("hook input type");
                Ok(match hook(ctx, input).await? {
                    Before::Continue(input) => {
                        Before::Continue(Box::new(input) as Box<dyn Any + Send>)
                    }
                    Before::Respond(response) => Before::Respond(response),
                })
            })
        });
        self.registry
            .hooks
            .entry(TypeId::of::<E>())
            .or_default()
            .before
            .push(erased);
        self
    }

    /// Runs after `E` succeeds with its typed output.
    pub fn after<F, Fut>(self, hook: F) -> Self
    where
        F: Fn(HookCtx<D>, E::Output) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<After<E::Output>, AuthError>> + Send + 'static,
    {
        let hook = Arc::new(hook);
        let erased: ErasedAfter<D> = Arc::new(move |ctx, output| {
            let hook = hook.clone();
            Box::pin(async move {
                let output = *output.downcast::<E::Output>().expect("hook output type");
                Ok(match hook(ctx, output).await? {
                    After::Continue(output) => {
                        After::Continue(Box::new(output) as Box<dyn Any + Send>)
                    }
                    After::Respond(response) => After::Respond(response),
                })
            })
        });
        self.registry
            .hooks
            .entry(TypeId::of::<E>())
            .or_default()
            .after
            .push(erased);
        self
    }
}
