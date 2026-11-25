use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::ext::IdentExt;
use syn::meta::ParseNestedMeta;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{
    Data, DataStruct, DeriveInput, Error, Expr, ExprLit, ExprUnary, Field, Ident, Lit, LitBool,
    LitStr, Path, Result, UnOp,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Derive {
    Fields,
    Model,
}

impl Derive {
    fn attribute(self) -> &'static str {
        match self {
            Derive::Fields => "field",
            Derive::Model => "model",
        }
    }

    fn keys(self) -> &'static str {
        match self {
            Derive::Fields => "`default`, `input`, `returned`, `unique`, `index` or `rename`",
            Derive::Model => {
                "`id`, `references`, `on_delete`, `unique`, `index`, `default` or `hidden`"
            }
        }
    }
}

enum DefaultLit {
    Bool(bool),
    Int(i64),
    Text(String),
    Now,
}

struct Column<'a> {
    field: &'a Field,
    ident: &'a Ident,
    name: String,
    default: Option<(DefaultLit, Span)>,
    primary_key: bool,
    unique: bool,
    index: bool,
    input: bool,
    hidden: bool,
    references: Option<Path>,
    on_delete: Option<Ident>,
}

pub(crate) fn derive_fields(input: &DeriveInput, core: &TokenStream) -> Result<TokenStream> {
    let fields = named_fields(input, "Fields")?;
    let mut table = None;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("fields")) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("table") {
                return Err(meta.error("unknown `fields` attribute; expected `table`"));
            }
            table = Some(meta.value()?.parse::<Path>()?);
            Ok(())
        })?;
    }
    let table = table.map_or_else(|| quote!(#core::models::User), |table| quote!(#table));
    let columns = columns(fields, Derive::Fields)?;
    let ident = &input.ident;
    let shared = Shared::new(input, &columns, core);
    let Shared {
        defs,
        decode,
        consts,
        checks,
    } = &shared;
    Ok(quote! {
        impl #core::model::Fields for #ident {
            fn columns() -> &'static [#core::schema::ColumnDef] {
                const COLUMNS: &[#core::schema::ColumnDef] = &[#(#defs),*];
                COLUMNS
            }

            #decode
        }

        impl #core::model::OnTable for #ident {
            type Table = #table;
        }

        impl #ident {
            #(#consts)*
        }

        #(#checks)*
    })
}

pub(crate) fn derive_model(input: &DeriveInput, core: &TokenStream) -> Result<TokenStream> {
    let fields = named_fields(input, "Model")?;
    let mut table = None;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("model")) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("table") {
                return Err(meta.error("unknown `model` attribute; expected `table`"));
            }
            let name: LitStr = meta.value()?.parse()?;
            if name.value().is_empty() {
                return Err(Error::new(name.span(), "the table name can't be empty"));
            }
            table = Some(name);
            Ok(())
        })?;
    }
    let Some(table) = table else {
        return Err(Error::new(
            input.ident.span(),
            "missing `#[model(table = \"...\")]`",
        ));
    };
    let columns = columns(fields, Derive::Model)?;
    let ident = &input.ident;
    let encode = columns.iter().map(|column| {
        let (name, field) = (&column.name, column.ident);
        quote! {
            (#name, #core::value::ColumnValue::into_value(::core::clone::Clone::clone(&self.#field)))
        }
    });
    let shared = Shared::new(input, &columns, core);
    let Shared {
        defs,
        decode,
        consts,
        checks,
    } = &shared;
    Ok(quote! {
        impl #core::model::Model for #ident {
            const TABLE: &'static str = #table;

            fn columns() -> &'static [#core::schema::ColumnDef] {
                const COLUMNS: &[#core::schema::ColumnDef] = &[#(#defs),*];
                COLUMNS
            }

            #decode

            fn encode(&self) -> ::std::vec::Vec<(&'static str, #core::value::Value)> {
                ::std::vec![#(#encode),*]
            }
        }

        impl #core::model::OnTable for #ident {
            type Table = Self;
        }

        impl #ident {
            #(#consts)*
        }

        #(#checks)*
    })
}

/// The parts `Fields` and `Model` generate the same way.
struct Shared {
    defs: Vec<TokenStream>,
    decode: TokenStream,
    consts: Vec<TokenStream>,
    checks: Vec<TokenStream>,
}

impl Shared {
    fn new(input: &DeriveInput, columns: &[Column<'_>], core: &TokenStream) -> Self {
        let fields = columns.iter().map(|c| c.ident);
        let names = columns.iter().map(|c| &c.name);
        Self {
            defs: columns.iter().map(|c| c.def(core)).collect(),
            decode: quote! {
                fn decode(
                    row: &#core::value::Row,
                ) -> ::core::result::Result<Self, #core::value::DecodeError> {
                    ::core::result::Result::Ok(Self { #(#fields: row.get(#names)?,)* })
                }
            },
            consts: columns.iter().map(|c| c.col(input, core)).collect(),
            checks: columns.iter().filter_map(|c| c.check(core)).collect(),
        }
    }
}

fn named_fields<'a>(input: &'a DeriveInput, derive: &str) -> Result<&'a Punctuated<Field, Comma>> {
    if !input.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &input.generics,
            format!("`{derive}` can't be derived for generic types"),
        ));
    }
    match &input.data {
        Data::Struct(DataStruct {
            fields: syn::Fields::Named(fields),
            ..
        }) => Ok(&fields.named),
        _ => Err(Error::new(
            input.ident.span(),
            format!("`{derive}` can only be derived for structs with named fields"),
        )),
    }
}

fn columns(fields: &Punctuated<Field, Comma>, derive: Derive) -> Result<Vec<Column<'_>>> {
    fields
        .iter()
        .map(|field| Column::parse(field, derive))
        .collect()
}

impl<'a> Column<'a> {
    fn parse(field: &'a Field, derive: Derive) -> Result<Self> {
        let ident = field.ident.as_ref().expect("named fields have idents");
        let mut column = Column {
            field,
            ident,
            name: ident.unraw().to_string(),
            default: None,
            primary_key: false,
            unique: false,
            index: false,
            input: derive == Derive::Fields,
            hidden: false,
            references: None,
            on_delete: None,
        };
        for attr in field
            .attrs
            .iter()
            .filter(|a| a.path().is_ident(derive.attribute()))
        {
            attr.parse_nested_meta(|meta| column.apply(&meta, derive))?;
        }
        if let (None, Some(on_delete)) = (&column.references, &column.on_delete) {
            return Err(Error::new(
                on_delete.span(),
                "`on_delete` needs `references = ..`",
            ));
        }
        Ok(column)
    }

    fn apply(&mut self, meta: &ParseNestedMeta<'_>, derive: Derive) -> Result<()> {
        let key = meta
            .path
            .get_ident()
            .map(Ident::to_string)
            .unwrap_or_default();
        match (derive, key.as_str()) {
            (_, "default") => self.default = Some(default(meta)?),
            (_, "unique") => self.unique = true,
            (_, "index") => self.index = true,
            (Derive::Fields, "input") => self.input = flag(meta)?,
            (Derive::Fields, "returned") => self.hidden = !flag(meta)?,
            (Derive::Fields, "rename") => self.name = meta.value()?.parse::<LitStr>()?.value(),
            (Derive::Model, "id") => self.primary_key = true,
            (Derive::Model, "hidden") => self.hidden = true,
            (Derive::Model, "references") => self.references = Some(meta.value()?.parse()?),
            (Derive::Model, "on_delete") => {
                let action: Ident = meta.value()?.parse()?;
                if !matches!(
                    action.to_string().as_str(),
                    "Cascade" | "SetNull" | "Restrict"
                ) {
                    return Err(Error::new(
                        action.span(),
                        "expected `Cascade`, `SetNull` or `Restrict`",
                    ));
                }
                self.on_delete = Some(action);
            }
            _ => {
                return Err(meta.error(format!(
                    "unknown `{}` attribute; expected {}",
                    derive.attribute(),
                    derive.keys()
                )));
            }
        }
        Ok(())
    }

    fn def(&self, core: &TokenStream) -> TokenStream {
        let (name, ty) = (&self.name, &self.field.ty);
        let new = quote! {
            #core::schema::ColumnDef::new(#name, <#ty as #core::value::ColumnValue>::TYPE)
        };
        let mut def = quote! {
            (if <#ty as #core::value::ColumnValue>::NULLABLE { #new.nullable() } else { #new })
        };
        if self.primary_key {
            def.extend(quote!(.primary_key()));
        }
        if self.unique {
            def.extend(quote!(.unique()));
        }
        if self.index {
            def.extend(quote!(.index()));
        }
        if let Some((value, _)) = &self.default {
            let value = match value {
                DefaultLit::Bool(b) => quote!(Bool(#b)),
                DefaultLit::Int(i) => quote!(Int(#i)),
                DefaultLit::Text(s) => quote!(Text(#s)),
                DefaultLit::Now => quote!(Now),
            };
            def.extend(quote!(.default(#core::schema::DefaultValue::#value)));
        }
        if let Some(target) = &self.references {
            let on_delete = self
                .on_delete
                .clone()
                .unwrap_or_else(|| Ident::new("Restrict", Span::call_site()));
            def.extend(quote! {
                .references(
                    <#target as #core::model::Model>::TABLE,
                    "id",
                    #core::schema::OnDelete::#on_delete,
                )
            });
        }
        if self.input {
            def.extend(quote!(.input()));
        }
        if self.hidden {
            def.extend(quote!(.hidden()));
        }
        def
    }

    fn col(&self, input: &DeriveInput, core: &TokenStream) -> TokenStream {
        let (owner, vis, ty, name) = (&input.ident, &input.vis, &self.field.ty, &self.name);
        let constant = Ident::new(
            &self.ident.unraw().to_string().to_uppercase(),
            self.ident.span(),
        );
        let mut docs: Vec<_> = self
            .field
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("doc"))
            .map(|a| quote!(#a))
            .collect();
        if docs.is_empty() {
            let doc = format!("The `{name}` column.");
            docs.push(quote!(#[doc = #doc]));
        }
        quote! {
            #(#docs)*
            #vis const #constant: #core::model::Col<#owner, #ty> = #core::model::Col::new(#name);
        }
    }

    /// A const assertion that the default literal fits the column type, so
    /// `#[field(default = "free")]` on a `bool` fails to compile.
    fn check(&self, core: &TokenStream) -> Option<TokenStream> {
        let (value, span) = self.default.as_ref()?;
        let (kind, ty) = match value {
            DefaultLit::Bool(_) => ("a bool", "Bool"),
            DefaultLit::Int(_) => ("an integer", "Int"),
            DefaultLit::Text(_) => ("a string", "Text"),
            DefaultLit::Now => ("`now`", "Timestamp"),
        };
        let message = format!(
            "`{}` defaults to {kind}, so its column type must be {ty}",
            self.name
        );
        let (field_ty, variant) = (&self.field.ty, Ident::new(ty, *span));
        Some(quote_spanned! {*span=>
            const _: () = ::core::assert!(
                ::core::matches!(
                    <#field_ty as #core::value::ColumnValue>::TYPE,
                    #core::schema::ColumnType::#variant
                ),
                #message
            );
        })
    }
}

fn flag(meta: &ParseNestedMeta<'_>) -> Result<bool> {
    if !meta.input.peek(syn::Token![=]) {
        return Ok(true);
    }
    Ok(meta.value()?.parse::<LitBool>()?.value)
}

fn default(meta: &ParseNestedMeta<'_>) -> Result<(DefaultLit, Span)> {
    let expr: Expr = meta.value()?.parse()?;
    let invalid = || {
        Error::new_spanned(
            &expr,
            "expected a bool, integer or string literal, or `now`",
        )
    };
    let value = match &expr {
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::Bool(b) => DefaultLit::Bool(b.value),
            Lit::Int(i) => DefaultLit::Int(i.base10_parse()?),
            Lit::Str(s) => DefaultLit::Text(s.value()),
            _ => return Err(invalid()),
        },
        Expr::Unary(ExprUnary {
            op: UnOp::Neg(_),
            expr: inner,
            ..
        }) => match &**inner {
            Expr::Lit(ExprLit {
                lit: Lit::Int(i), ..
            }) => DefaultLit::Int(-i.base10_parse::<i64>()?),
            _ => return Err(invalid()),
        },
        Expr::Path(path) if path.path.is_ident("now") => DefaultLit::Now,
        _ => return Err(invalid()),
    };
    Ok((value, expr.span()))
}
