use crate::Certificate;
use dlopen::symbor::{Container, SymBorApi, Symbol};
use dlopen::Error as DlopenError;
use std::collections::HashMap;
use std::ffi::c_char;
use std::ffi::c_void;
use std::io::Error;
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
        unsafe { (self.cf.CFArrayGetValueAtIndex)(self.array, index as CFIndex) as *mut T }
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

type OSStatus = i32;
type CFIndex = isize;

type SecTrustSettingsDomain = u32;

const kSecTrustSettingsDomainUser: SecTrustSettingsDomain = 0;
const kSecTrustSettingsDomainAdmin: SecTrustSettingsDomain = 1;
const kSecTrustSettingsDomainSystem: SecTrustSettingsDomain = 2;

type SecTrustSettingsResult = u32;

const kSecTrustSettingsResultInvalid: SecTrustSettingsResult = 0;
const kSecTrustSettingsResultTrustRoot: SecTrustSettingsResult = 1;
const kSecTrustSettingsResultTrustAsRoot: SecTrustSettingsResult = 2;
const kSecTrustSettingsResultDeny: SecTrustSettingsResult = 3;
const kSecTrustSettingsResultUnspecified: SecTrustSettingsResult = 4;

const errSecNoTrustSettings: OSStatus = -25263;
const errSecSuccess: OSStatus = 0;

enum OpaqueSecCertificateRef {}
type SecCertificateRef = *mut OpaqueSecCertificateRef;

#[allow(non_snake_case)]
#[derive(dlopen_derive::SymBorApi)]
struct TrustSettings<'a> {
    // TrustSettings
    SecTrustSettingsCopyCertificates:
        Symbol<'a, unsafe extern "C" fn(SecTrustSettingsDomain, *mut CFArrayRef) -> OSStatus>,
    SecTrustSettingsCopyTrustSettings: Symbol<
        'a,
        unsafe extern "C" fn(
            SecCertificateRef,
            SecTrustSettingsDomain,
            *mut CFArrayRef,
        ) -> OSStatus,
    >,
    // Certificate
    SecCertificateCopyData: Symbol<'a, unsafe extern "C" fn(SecCertificateRef) -> CFDataRef>,
}

type CFStringEncoding = u32;
static kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;

#[allow(non_snake_case)]
#[derive(dlopen_derive::SymBorApi)]
struct CoreFoundation<'a> {
    // CFArray
    CFArrayGetValueAtIndex: Symbol<'a, unsafe extern "C" fn(CFArrayRef, CFIndex) -> *const c_void>,
    CFArrayGetCount: Symbol<'a, unsafe extern "C" fn(CFArrayRef) -> CFIndex>,
    CFDictionaryGetValueIfPresent:
        Symbol<'a, unsafe extern "C" fn(CFDictionaryRef, *const c_void, *mut *const c_void) -> u8>,
    // CFStringCreateWithCString: Symbol<
    //     'a,
    //     unsafe extern "C" fn(CFAllocatorRef, *const c_char, CFStringEncoding) -> CFStringRef,
    // >,
}

fn find_frameworks() -> Result<
    (
        Container<TrustSettings<'static>>,
        Container<CoreFoundation<'static>>,
    ),
    DlopenError,
> {
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
    let (framework, cf) = find_frameworks().unwrap();

    // let mut all_certs = HashMap::new();

    for domain in [
        kSecTrustSettingsDomainUser,
        kSecTrustSettingsDomainAdmin,
        kSecTrustSettingsDomainSystem,
    ] {
        let mut array_ptr: CFArrayRef = ptr::null_mut();
        match unsafe { (framework.SecTrustSettingsCopyCertificates)(domain, &mut array_ptr) } {
            errSecNoTrustSettings => continue,
            errSecSuccess => {}
            _ => panic!("HUH"),
        };

        let certs: Array<OpaqueSecCertificateRef> = Array::new(array_ptr, &cf);
        for cert in certs.iter() {
            let der = unsafe { (framework.SecCertificateCopyData)(cert) };

            unsafe {
                let mut array_ptr: CFArrayRef = ptr::null_mut();
                (framework.SecTrustSettingsCopyTrustSettings)(cert, domain, &mut array_ptr);

                let settings: Array<__CFDictionary> = Array::new(array_ptr, &cf);
                for dict in settings.iter() {
                    //     let value =
                    //         unsafe { (cf.CFArrayGetValueAtIndex)(array_ptr, index) as CFDictionaryRef };

                    //     let s = unsafe {
                    //         (cf.CFStringCreateWithBytesNoCopy)(
                    //             kCFAllocatorDefault,
                    //             "a",
                    //             1,
                    //             kCFStringEncodingUTF8,
                    //             0,
                    //             kCFAllocatorNull,
                    //         )
                    //     };
                }
            }

            // all_certs.entry(der).or_insert(trusted);
        }
    }

    let mut certs = Vec::new();

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load() {
        load_native_certs().unwrap();
    }
}
