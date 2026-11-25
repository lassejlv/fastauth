use heck::ToShoutySnakeCase;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::ext::IdentExt;
use syn::{Data, DeriveInput, Error, Fields, LitInt, LitStr, Result, Variant};

pub(crate) fn derive(input: &DeriveInput, core: &TokenStream) -> Result<TokenStream> {
    let Data::Enum(data) = &input.data else {
        return Err(Error::new(
            input.ident.span(),
            "`AuthError` can only be derived for enums",
        ));
    };
    let mut prefix = None;
    for attr in input
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("auth_error"))
    {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("prefix") {
                return Err(meta.error("unknown `auth_error` attribute; expected `prefix`"));
            }
            prefix = Some(meta.value()?.parse::<LitStr>()?.value());
            Ok(())
        })?;
    }
    let ident = &input.ident;
    let mut arms = Vec::new();
    let mut codes = Vec::new();
    for variant in &data.variants {
        let (status, message) = attributes(variant)?;
        let name = variant.ident.unraw().to_string().to_shouty_snake_case();
        let code = match &prefix {
            Some(prefix) => format!("{prefix}_{name}"),
            None => name,
        };
        let fields = placeholders(variant, &message)?;
        let variant = &variant.ident;
        arms.push(if fields.is_empty() {
            quote! {
                #ident::#variant { .. } => #core::AuthError::new(status(#status), #code, #message)
            }
        } else {
            quote! {
                #ident::#variant { #(#fields,)* .. } => #core::AuthError::with_message(
                    status(#status),
                    #code,
                    ::std::format!(#message, #(#fields = #fields),*),
                )
            }
        });
        codes.push(code);
    }
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::core::convert::From<#ident #ty_generics> for #core::AuthError
        #where_clause
        {
            fn from(error: #ident #ty_generics) -> Self {
                const fn status(code: u16) -> #core::plugin_prelude::StatusCode {
                    match #core::plugin_prelude::StatusCode::from_u16(code) {
                        ::core::result::Result::Ok(status) => status,
                        ::core::result::Result::Err(_) => ::core::panic!("invalid HTTP status"),
                    }
                }
                match error {
                    #(#arms,)*
                }
            }
        }

        impl #impl_generics #core::error::ErrorCodes for #ident #ty_generics #where_clause {
            const CODES: &'static [&'static str] = &[#(#codes),*];
        }
    })
}

fn attributes(variant: &Variant) -> Result<(u16, LitStr)> {
    let mut status = None;
    let mut message = None;
    for attr in variant
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("auth_error"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("status") {
                let lit: LitInt = meta.value()?.parse()?;
                let code: u16 = lit.base10_parse()?;
                if !(100..=999).contains(&code) {
                    return Err(Error::new(lit.span(), "a status is between 100 and 999"));
                }
                status = Some(code);
            } else if meta.path.is_ident("message") {
                message = Some(meta.value()?.parse()?);
            } else {
                return Err(
                    meta.error("unknown `auth_error` attribute; expected `status` or `message`")
                );
            }
            Ok(())
        })?;
    }
    let (Some(status), Some(message)) = (status, message) else {
        return Err(Error::new(
            variant.ident.span(),
            "missing `#[auth_error(status = .., message = \"..\")]`",
        ));
    };
    Ok((status, message))
}

/// The fields named by `{field}` placeholders in `message`, each once.
fn placeholders(variant: &Variant, message: &LitStr) -> Result<Vec<syn::Ident>> {
    let text = message.value();
    let mut names: Vec<&str> = Vec::new();
    let mut rest = text.as_str();
    while let Some(open) = rest.find('{') {
        rest = &rest[open + 1..];
        if let Some(escaped) = rest.strip_prefix('{') {
            rest = escaped;
            continue;
        }
        let close = rest
            .find('}')
            .ok_or_else(|| Error::new(message.span(), "unclosed `{` in message"))?;
        let name = rest[..close].split(':').next().unwrap_or_default().trim();
        rest = &rest[close + 1..];
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
        .into_iter()
        .map(|name| {
            let Fields::Named(fields) = &variant.fields else {
                return Err(Error::new(
                    message.span(),
                    "`{..}` placeholders need a variant with named fields",
                ));
            };
            if !fields
                .named
                .iter()
                .any(|f| f.ident.as_ref().is_some_and(|i| i == name))
            {
                return Err(Error::new(
                    message.span(),
                    format!("`{name}` is not a field of `{}`", variant.ident),
                ));
            }
            Ok(format_ident!("{name}"))
        })
        .collect()
}
