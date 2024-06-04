#![allow(non_upper_case_globals)]

use crate::Certificate;
use dlopen2::symbor::{Container, Ref, SymBorApi, Symbol};
use dlopen2::Error as DlopenError;
use once_cell::unsync::OnceCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Error, ErrorKind};
use std::ptr;

#[repr(C)]
pub struct __CFArray(c_void);

pub type CFArrayRef = *const __CFArray;

struct Array<'a, T> {
  array: CFArrayRef,
  cf: &'a CoreFoundation<'a>,
  _marker: std::marker::PhantomData<T>,
}

impl<'a, T> Array<'a, T> {
  fn new(array: CFArrayRef, cf: &'a CoreFoundation<'a>) -> Self {
    Self {
      array,
      cf,
      _marker: std::marker::PhantomData,
    }
  }

  fn len(&self) -> usize {
    unsafe { (self.cf.CFArrayGetCount)(self.array) as usize }
  }

  fn get(&self, index: usize) -> *mut T {
    unsafe {
      (self.cf.CFArrayGetValueAtIndex)(self.array, index as CFIndex) as *mut T
    }
  }

  fn iter(&'a self) -> ArrayIter<'a, T> {
    ArrayIter {
      array: self,
      index: 0,
    }
  }
}

struct ArrayIter<'a, T> {
  array: &'a Array<'a, T>,
  index: usize,
}

impl<'a, T> Iterator for ArrayIter<'a, T> {
  type Item = *mut T;

  fn next(&mut self) -> Option<Self::Item> {
    if self.index < self.array.len() {
      let value = self.array.get(self.index);
      self.index += 1;
      Some(value)
    } else {
      None
    }
  }
}

#[repr(C)]
pub struct __CFData(c_void);

pub type CFDataRef = *const __CFData;

#[repr(C)]
pub struct __CFDictionary(c_void);

pub type CFDictionaryRef = *const __CFDictionary;

#[repr(C)]
pub struct __CFString(c_void);

pub type CFStringRef = *const __CFString;

struct CFString<'a> {
  string: CFStringRef,
  cf: &'a CoreFoundation<'a>,
}

impl<'a> CFString<'a> {
  fn from_raw(string: CFStringRef, cf: &'a CoreFoundation<'a>) -> Self {
    Self { string, cf }
  }

  fn from_static_str(s: &'static str, cf: &'a CoreFoundation<'a>) -> Self {
    Self {
      string: unsafe {
        (cf.CFStringCreateWithBytesNoCopy)(
          *cf.kCFAllocatorDefault,
          s.as_ptr() as _,
          s.len() as _,
          kCFStringEncodingUTF8,
          0,
          *cf.kCFAllocatorNull,
        )
      },
      cf,
    }
  }
}

impl PartialEq for CFString<'_> {
  fn eq(&self, other: &Self) -> bool {
    unsafe { (self.cf.CFEqual)(self.string as _, other.string as _) != 0 }
  }
}

type CFAllocatorRef = *const c_void;
type CFTypeRef = *const c_void;
type OSStatus = i32;
type CFIndex = isize;

type SecTrustSettingsDomain = u32;

const kSecTrustSettingsDomainUser: SecTrustSettingsDomain = 0;
const kSecTrustSettingsDomainAdmin: SecTrustSettingsDomain = 1;
const kSecTrustSettingsDomainSystem: SecTrustSettingsDomain = 2;

type SecTrustSettingsResult = u32;

const kSecTrustSettingsResultTrustRoot: SecTrustSettingsResult = 1;
const kSecTrustSettingsResultTrustAsRoot: SecTrustSettingsResult = 2;
const kSecTrustSettingsResultDeny: SecTrustSettingsResult = 3;

const errSecNoTrustSettings: OSStatus = -25263;
const errSecSuccess: OSStatus = 0;

enum OpaqueSecCertificateRef {}
type SecCertificateRef = *mut OpaqueSecCertificateRef;

#[allow(non_snake_case)]
#[derive(dlopen2_derive::SymBorApi)]
struct TrustSettings<'a> {
  // TrustSettings
  SecTrustSettingsCopyCertificates: Symbol<
    'a,
    unsafe extern "C" fn(SecTrustSettingsDomain, *mut CFArrayRef) -> OSStatus,
  >,
  SecTrustSettingsCopyTrustSettings: Symbol<
    'a,
    unsafe extern "C" fn(
      SecCertificateRef,
      SecTrustSettingsDomain,
      *mut CFArrayRef,
    ) -> OSStatus,
  >,
  // Certificate
  SecCertificateCopyData:
    Symbol<'a, unsafe extern "C" fn(SecCertificateRef) -> CFDataRef>,
}

type CFStringEncoding = u32;
static kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;

#[allow(non_snake_case)]
#[derive(dlopen2_derive::SymBorApi)]
struct CoreFoundation<'a> {
  // CFArray
  CFArrayGetValueAtIndex:
    Symbol<'a, unsafe extern "C" fn(CFArrayRef, CFIndex) -> *const c_void>,
  CFArrayGetCount: Symbol<'a, unsafe extern "C" fn(CFArrayRef) -> CFIndex>,
  CFDictionaryGetValueIfPresent: Symbol<
    'a,
    unsafe extern "C" fn(
      CFDictionaryRef,
      *const c_void,
      *mut *const c_void,
    ) -> u8,
  >,
  CFStringCreateWithBytesNoCopy: Symbol<
    'a,
    unsafe extern "C" fn(
      CFAllocatorRef,
      *const u8,
      CFIndex,
      CFStringEncoding,
      u8,
      CFAllocatorRef,
    ) -> CFStringRef,
  >,
  CFDataGetBytePtr:
    Symbol<'a, unsafe extern "C" fn(theData: CFDataRef) -> *const u8>,
  CFDataGetLength:
    Symbol<'a, unsafe extern "C" fn(theData: CFDataRef) -> CFIndex>,
  CFEqual: Symbol<'a, unsafe extern "C" fn(CFTypeRef, CFTypeRef) -> u8>,
  kCFAllocatorDefault: Ref<'a, CFAllocatorRef>,
  kCFAllocatorNull: Ref<'a, CFAllocatorRef>,
}

type Frameworks = (
  Container<TrustSettings<'static>>,
  Container<CoreFoundation<'static>>,
);

fn find_frameworks() -> Result<Frameworks, DlopenError> {
  unsafe {
    Ok((
      Container::load(
        "/System/Library/Frameworks/Security.framework/Versions/Current/Security",
      )?,
      Container::load(
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
      )?,
    ))
  }
}

pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
  let cell = OnceCell::new();
  let (framework, cf) = cell.get_or_try_init(find_frameworks).map_err(|e| {
    Error::new(
      ErrorKind::Other,
      format!("Failed to load frameworks: {}", e),
    )
  })?;

  let mut all_certs = HashMap::new();

  for domain in [
    kSecTrustSettingsDomainUser,
    kSecTrustSettingsDomainAdmin,
    kSecTrustSettingsDomainSystem,
  ] {
    let mut array_ptr: CFArrayRef = ptr::null_mut();
    match unsafe {
      (framework.SecTrustSettingsCopyCertificates)(domain, &mut array_ptr)
    } {
      errSecNoTrustSettings => continue,
      errSecSuccess => {}
      _ => {
        return Err(Error::new(
          ErrorKind::Other,
          "SecTrustSettingsCopyCertificates",
        ))
      }
    };

    let certs: Array<OpaqueSecCertificateRef> = Array::new(array_ptr, &cf);
    for cert in certs.iter() {
      let der = unsafe { (framework.SecCertificateCopyData)(cert) };

      let trusted = unsafe {
        let mut array_ptr: CFArrayRef = ptr::null_mut();
        (framework.SecTrustSettingsCopyTrustSettings)(
          cert,
          domain,
          &mut array_ptr,
        );

        let settings: Array<__CFDictionary> = Array::new(array_ptr, &cf);
        tls_trust_settings_for_certificates(&cf, settings)
          .unwrap_or(kSecTrustSettingsResultTrustRoot)
      };

      all_certs.entry(der).or_insert(trusted);
    }
  }

  let mut certs = Vec::new();

  for (der, trusted) in all_certs.drain() {
    if let kSecTrustSettingsResultTrustRoot
    | kSecTrustSettingsResultTrustAsRoot = trusted
    {
      certs.push(Certificate(
        unsafe {
          std::slice::from_raw_parts(
            (cf.CFDataGetBytePtr)(der),
            (cf.CFDataGetLength)(der) as usize,
          )
        }
        .to_vec(),
      ));
    }
  }

  Ok(certs)
}

unsafe fn tls_trust_settings_for_certificates<'a>(
  cf: &'a CoreFoundation<'a>,
  settings: Array<'a, __CFDictionary>,
) -> Option<SecTrustSettingsResult> {
  for dict in settings.iter() {
    let policy_name_key =
      CFString::from_static_str("kSecTrustSettingsPolicyName", &cf);
    let ssl_policy_name = CFString::from_static_str("sslServer", &cf);

    let maybe_name = {
      let mut value: *const c_void = ptr::null();
      if (cf.CFDictionaryGetValueIfPresent)(
        dict,
        policy_name_key.string as _,
        &mut value,
      ) != 0
      {
        Some(CFString::from_raw(value as _, &cf))
      } else {
        None
      }
    };

    if matches!(maybe_name, Some(ref name) if name != &ssl_policy_name) {
      continue;
    }

    let settings_result_key =
      CFString::from_static_str("kSecTrustSettingsResult", &cf);
    let mut value: *const c_void = ptr::null();
    let trust_result = if (cf.CFDictionaryGetValueIfPresent)(
      dict,
      settings_result_key.string as _,
      &mut value,
    ) != 0
    {
      value as SecTrustSettingsResult
    } else {
      kSecTrustSettingsResultTrustRoot
    };

    match trust_result {
      kSecTrustSettingsResultDeny
      | kSecTrustSettingsResultTrustRoot
      | kSecTrustSettingsResultTrustAsRoot => {
        return Some(trust_result);
      }
      _ => continue,
    }
  }

  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn load() {
    let mut actual = load_native_certs()
      .unwrap()
      .into_iter()
      .map(|cert| cert.0)
      .collect::<Vec<_>>();
    let mut expected = rustls_native_certs::load_native_certs()
      .unwrap()
      .into_iter()
      .map(|cert| cert.to_vec())
      .collect::<Vec<_>>();

    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
  }
}
