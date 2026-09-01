use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Lit, LitStr};

/// 解析变体上的 `#[error_id(...)]`：
/// - 裸字符串 `#[error_id("a.b.c")]`
/// - 键值 `#[error_id(id = "a.b.c")]`
/// - 标志 `#[error_id(transparent)]`
fn parse_error_id_attr(
    attr: &syn::Attribute,
    variant_ident: &syn::Ident,
) -> (Option<LitStr>, bool) {
    let content = &attr.meta.require_list().unwrap().tokens;
    if let Ok(lit) = syn::parse2::<LitStr>(content.clone()) {
        return (Some(lit), false);
    }
    let mut error_id: Option<LitStr> = None;
    let mut transparent = false;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("transparent") {
            transparent = true;
        } else if meta.path.is_ident("id") {
            let value = meta.value()?;
            let lit: Lit = value.parse()?;
            if let Lit::Str(s) = lit {
                error_id = Some(s);
            }
        }
        Ok(())
    })
    .unwrap_or_else(|e| {
        panic!(
            "Failed to parse #[error_id] on variant `{}`: {}",
            variant_ident, e
        )
    });
    (error_id, transparent)
}

/// `#[derive(ErrorId)]` — auto-generate the `ErrorId` trait implementation
/// (stable error ids for i18n serialization, ERROR_ID §2).
///
/// Each non-transparent variant requires `#[error_id("...")]` with a stable
/// dotted id. Optional variant flag `transparent`: for single-field `#[from]`
/// variants wrapping an error that itself implements `ErrorId`, all metadata
/// (id / args / public message) is delegated to the wrapped error.
///
/// Optional enum-level `#[error_id(crate_path = "...")]` overrides the default
/// `landscape_rill_core` path to the crate hosting the `ErrorId` trait.
///
/// Example:
/// ```ignore
/// #[derive(Debug, thiserror::Error, ErrorId)]
/// pub enum SendError {
///     #[error("no session")]
///     #[error_id("mesh.send.no_session")]
///     NoSession,
///     #[error(transparent)]
///     #[error_id(transparent)]
///     Handshake(#[from] HandshakeError),
/// }
/// ```
#[proc_macro_derive(ErrorId, attributes(error_id))]
pub fn derive_error_id(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let mut crate_path_str = "landscape_rill_core".to_string();
    for attr in &input.attrs {
        if attr.path().is_ident("error_id") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate_path") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        crate_path_str = s.value();
                    }
                }
                Ok(())
            });
        }
    }
    let crate_path: syn::Path = syn::parse_str(&crate_path_str).unwrap();

    let variants = match &input.data {
        syn::Data::Enum(data) => &data.variants,
        _ => panic!("ErrorId only supports enums"),
    };

    let mut id_arms = vec![];
    let mut args_arms = vec![];
    let mut public_arms = vec![];

    for variant in variants {
        let variant_ident = &variant.ident;
        let attr = variant
            .attrs
            .iter()
            .find(|a| a.path().is_ident("error_id"))
            .unwrap_or_else(|| {
                panic!(
                    "Variant `{}` is missing #[error_id(\"...\")] attribute",
                    variant_ident
                )
            });

        let (error_id, transparent) = parse_error_id_attr(attr, variant_ident);

        let delegate_pat = if transparent {
            let field = match &variant.fields {
                syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0],
                _ => panic!(
                    "`transparent` variant `{}` must have exactly one unnamed field",
                    variant_ident
                ),
            };
            if !field.attrs.iter().any(|a| a.path().is_ident("from")) {
                panic!(
                    "`transparent` variant `{}` field must be marked #[from]",
                    variant_ident
                );
            }
            Some(quote! { Self::#variant_ident(v0) })
        } else {
            let error_id = error_id
                .unwrap_or_else(|| panic!("Missing `id` in #[error_id] on `{}`", variant_ident));
            let pattern = match &variant.fields {
                syn::Fields::Unit => quote! { Self::#variant_ident },
                syn::Fields::Unnamed(_) => quote! { Self::#variant_ident(..) },
                syn::Fields::Named(_) => quote! { Self::#variant_ident { .. } },
            };
            id_arms.push(quote! { #pattern => #error_id });

            let args_arm = match &variant.fields {
                syn::Fields::Unit => {
                    quote! { Self::#variant_ident => #crate_path::error::args(&[]) }
                }
                syn::Fields::Unnamed(fields) => {
                    let bindings: Vec<_> = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, _)| syn::Ident::new(&format!("v{}", i), variant_ident.span()))
                        .collect();
                    let entries: Vec<_> = bindings
                        .iter()
                        .enumerate()
                        .map(|(i, ident)| {
                            let key = syn::LitStr::new(&format!("{}", i), variant_ident.span());
                            quote! { (#key, #ident.to_string()) }
                        })
                        .collect();
                    quote! {
                        Self::#variant_ident(#(#bindings),*) =>
                            #crate_path::error::args(&[#(#entries),*])
                    }
                }
                syn::Fields::Named(fields) => {
                    let field_names: Vec<_> = fields
                        .named
                        .iter()
                        .map(|f| f.ident.as_ref().unwrap())
                        .collect();
                    let entries: Vec<_> = field_names
                        .iter()
                        .map(|ident| {
                            quote! { (stringify!(#ident).to_string(), #ident.to_string()) }
                        })
                        .collect();
                    quote! {
                        Self::#variant_ident { #(#field_names),* } =>
                            #crate_path::error::args(&[#(#entries),*])
                    }
                }
            };
            args_arms.push(args_arm);
            None
        };

        if let Some(pat) = &delegate_pat {
            id_arms.push(quote! { #pat => v0.error_id() });
            args_arms.push(quote! { #pat => v0.error_args() });
            public_arms.push(quote! { #pat => v0.to_public_message() });
        }
    }

    // transparent 委托需要把 trait 带入方法作用域
    let use_trait = if public_arms.is_empty() {
        quote! {}
    } else {
        quote! { use #crate_path::error::ErrorId as _; }
    };

    let to_public_impl = if public_arms.is_empty() {
        quote! {}
    } else {
        quote! {
            fn to_public_message(&self) -> String {
                #use_trait
                match self {
                    #( #public_arms, )*
                    _ => self.to_string(),
                }
            }
        }
    };

    let expanded = quote! {
        impl #crate_path::error::ErrorId for #name {
            fn error_id(&self) -> &'static str {
                #use_trait
                match self {
                    #( #id_arms, )*
                }
            }

            fn error_args(&self) -> #crate_path::error::ErrorArgs {
                #use_trait
                match self {
                    #( #args_arms, )*
                }
            }

            #to_public_impl
        }
    };

    expanded.into()
}
