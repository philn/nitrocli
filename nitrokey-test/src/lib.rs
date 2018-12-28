// lib.rs

// *************************************************************************
// * Copyright (C) 2018 Daniel Mueller (deso@posteo.net)                   *
// *                                                                       *
// * This program is free software: you can redistribute it and/or modify  *
// * it under the terms of the GNU General Public License as published by  *
// * the Free Software Foundation, either version 3 of the License, or     *
// * (at your option) any later version.                                   *
// *                                                                       *
// * This program is distributed in the hope that it will be useful,       *
// * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
// * GNU General Public License for more details.                          *
// *                                                                       *
// * You should have received a copy of the GNU General Public License     *
// * along with this program.  If not, see <http://www.gnu.org/licenses/>. *
// *************************************************************************

#![deny(
  dead_code,
  duplicate_associated_type_bindings,
  illegal_floating_point_literal_pattern,
  improper_ctypes,
  intra_doc_link_resolution_failure,
  late_bound_lifetime_arguments,
  missing_copy_implementations,
  missing_debug_implementations,
  no_mangle_generic_items,
  non_shorthand_field_patterns,
  overflowing_literals,
  path_statements,
  patterns_in_fns_without_body,
  plugin_as_library,
  private_in_public,
  proc_macro_derive_resolution_fallback,
  safe_packed_borrows,
  stable_features,
  trivial_bounds,
  trivial_numeric_casts,
  type_alias_bounds,
  tyvar_behind_raw_pointer,
  unconditional_recursion,
  unions_with_drop_fields,
  unreachable_code,
  unreachable_patterns,
  unstable_features,
  unstable_name_collisions,
  unused,
  unused_comparisons,
  unused_import_braces,
  unused_lifetimes,
  unused_qualifications,
  unused_results,
  where_clauses_object_safety,
  while_true
)]
#![warn(
  bad_style,
  future_incompatible,
  nonstandard_style,
  renamed_and_removed_lints,
  rust_2018_compatibility,
  rust_2018_idioms
)]

//! A crate providing supporting testing infrastructure for the
//! `nitrokey` crate and its users.
//!
//! Right now we make a few simplifying assumptions that, although not
//! changing what can be expressed and tested, can lead to unexpected
//! error messages when not known:
//! - the parameter naming the device to test on has to be `device`
//! - the parameter has to be an owned object, not a reference
//! - parameter types are pattern matched against "Storage", "Pro", and
//!   "DeviceWrapper"; that means `use ... as` declarations will not work
//!   properly

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Ident;
use proc_macro2::Span;
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::punctuated;


/// A type used to determine what Nitrokey device to test on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupportedDevice {
  /// Both the Nitrokey Pro and Storage are supported.
  Any,
  /// Only the Nitrokey Pro is supported.
  Pro,
  /// Only the Nitrokey Storage is supported.
  Storage,
}


/// A type defining what kind of Nitrokey device to connect to and
/// whether to wrap it.
#[derive(Clone, Copy, Debug)]
enum EmittedDevice {
  /// Connect to and pass in a `nitrokey::Pro`.
  Pro,
  /// Connect to and pass in a `nitrokey::Storage`.
  Storage,
  /// Connect to a `nitrokey::Pro` but pass it in as a `nitrokey::DeviceWrapper`.
  WrappedPro,
  /// Connect to a `nitrokey::Storage` but pass it in as a `nitrokey::DeviceWrapper`.
  WrappedStorage,
}


/// A procedural macro for the `test_device` attribute.
///
/// The attribute can be used to define a test that accepts a Nitrokey
/// device object (which can be any of `nitrokey::Pro`,
/// `nitrokey::Storage`, or `nitrokey::DeviceWrapper`), and runs a test
/// against that device. If the device type was specified as
/// `nitrokey::DeviceWrapper`, the test will actually be invoked for a
/// Nitrokey Pro as well as a Nitrokey Storage. Irrespective, the test
/// is skipped if the device cannot be found.
///
/// # Example
///
/// ```rust,no_run
/// # use nitrokey_test::test_device;
/// #[test_device]
/// fn some_nitrokey_test(device: nitrokey::DeviceWrapper) {
///   assert_eq!(device.get_serial_number().unwrap().len(), 8);
/// }
/// ```
#[proc_macro_attribute]
pub fn test_device(attr: TokenStream, item: TokenStream) -> TokenStream {
  // Bail out if user tried to pass additional arguments. E.g.,
  // #[test_device(foo = "bar")
  if !attr.is_empty() {
    panic!("unsupported attributes supplied: {}", attr);
  }

  let input = syn::parse_macro_input!(item as syn::ItemFn);
  let dev_type = determine_device(&input.decl.inputs);

  match dev_type {
    SupportedDevice::Pro => {
      let name = format!("{}", &input.ident);
      expand_wrapper(name, EmittedDevice::Pro, &input)
    },
    SupportedDevice::Storage => {
      let name = format!("{}", &input.ident);
      expand_wrapper(name, EmittedDevice::Storage, &input)
    },
    SupportedDevice::Any => {
      let name = format!("{}_pro", &input.ident);
      let pro = expand_wrapper(name, EmittedDevice::WrappedPro, &input);

      let name = format!("{}_storage", &input.ident);
      let storage = expand_wrapper(name, EmittedDevice::WrappedStorage, &input);

      // Emit a test for both the Pro and the Storage device.
      quote! {
        #pro
        #storage
      }
    }
  }
  .into()
}

/// Emit code for a wrapper function around a Nitrokey test function.
fn expand_wrapper<S>(fn_name: S, device: EmittedDevice, wrappee: &syn::ItemFn) -> Tokens
where
  S: AsRef<str>,
{
  // Note that we need to rely on proc_macro2 here, because while the
  // compiler provided proc_macro has `Ident` and `Span` types, they
  // cannot be interpolated with quote!{} for lack of quote::ToTokens
  // implementations.
  let name = Ident::new(fn_name.as_ref(), Span::call_site());
  let decl = &wrappee.decl;
  let body = &wrappee.block;
  let (ret_type, check) = match &decl.output {
    syn::ReturnType::Default => (quote! {()}, quote! {.unwrap()}),
    syn::ReturnType::Type(_, type_) => (quote! {#type_}, quote! {?}),
  };

  let connect_pro = quote! {::nitrokey::Pro::connect()#check};
  let connect_storage = quote! {::nitrokey::Storage::connect()#check};

  let connect = match device {
    EmittedDevice::Pro => connect_pro,
    EmittedDevice::Storage => connect_storage,
    EmittedDevice::WrappedPro => quote! {::nitrokey::DeviceWrapper::Pro(#connect_pro)},
    EmittedDevice::WrappedStorage => quote! {::nitrokey::DeviceWrapper::Storage(#connect_storage)},
  };

  quote! {
    #[test]
    fn #name() -> #ret_type {
      let device = #connect;
      #body
    }
  }
}

/// Determine the kind of Nitrokey device a test function support, based
/// on the type of its only parameter.
fn determine_device<P>(args: &punctuated::Punctuated<syn::FnArg, P>) -> SupportedDevice
where
  P: quote::ToTokens,
{
  if args.len() != 1 {
    panic!("functions used as Nitrokey tests can only have a single argument");
  }

  match args.first().unwrap().value() {
    syn::FnArg::Captured(arg) => {
      let type_ = &arg.ty;
      match type_ {
        syn::Type::Path(path) => {
          if path.path.segments.is_empty() {
            panic!("invalid function argument type: {}", quote! {#path});
          }

          let type_ = format!("{}", path.path.segments.last().unwrap().value().ident);
          match type_.as_ref() {
            "Storage" => SupportedDevice::Storage,
            "Pro" => SupportedDevice::Pro,
            "DeviceWrapper" => SupportedDevice::Any,
            _ => panic!("unsupported function argument type: {}", type_),
          }
        },
        _ => panic!("unexpected function argument type: {} (expected owned object)",
                    quote!{#type_}),
      }
    }
    _ => panic!("unexpected function argument signature: {}", quote! {#args}),
  }
}


#[cfg(test)]
mod tests {
  use super::*;


  #[test]
  fn determine_nitrokey_pro() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_pro(device: nitrokey::Pro) {}
    };
    let dev_type = determine_device(&input.decl.inputs);

    assert_eq!(dev_type, SupportedDevice::Pro)
  }

  #[test]
  fn determine_nitrokey_storage() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_storage(device: nitrokey::Storage) {}
    };
    let dev_type = determine_device(&input.decl.inputs);

    assert_eq!(dev_type, SupportedDevice::Storage)
  }

  #[test]
  fn determine_any_nitrokey() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_any(device: nitrokey::DeviceWrapper) {}
    };
    let dev_type = determine_device(&input.decl.inputs);

    assert_eq!(dev_type, SupportedDevice::Any)
  }

  #[test]
  #[should_panic(expected = "functions used as Nitrokey tests can only have a single argument")]
  fn determine_wrong_arg_count() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_pro(device: nitrokey::Pro, _: i32) {}
    };
    let _ = determine_device(&input.decl.inputs);
  }

  #[test]
  #[should_panic(expected = "unexpected function argument signature: & self")]
  fn determine_wrong_function_type() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_self(&self) {}
    };
    let _ = determine_device(&input.decl.inputs);
  }

  #[test]
  #[should_panic(expected = "unexpected function argument type: & nitrokey \
                             :: DeviceWrapper (expected owned object)")]
  fn determine_wrong_argument_type() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_any(device: &nitrokey::DeviceWrapper) {}
    };
    let _ = determine_device(&input.decl.inputs);
  }

  #[test]
  #[should_panic(expected = "unsupported function argument type: FooBarBaz")]
  fn determine_invalid_argument_type() {
    let input: syn::ItemFn = syn::parse_quote! {
      #[test_device]
      fn test_foobarbaz(device: nitrokey::FooBarBaz) {}
    };
    let _ = determine_device(&input.decl.inputs);
  }
}
