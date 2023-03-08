use std::io::Error;

#[cfg(target_os = "macos")]
mod macos;

/// A newtype representing a single DER-encoded X.509 certificate encoded as a `Vec<u8>`.
pub struct Certificate(pub Vec<u8>);

#[cfg(not(target_os = "macos"))]
pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
  Ok(rustls_native_certs::load_native_certs()?.map(|c| Certificate(c.0)))
}

#[cfg(target_os = "macos")]
pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
  use std::env;
  use std::fs::File;
  use std::io::BufReader;
  use std::io::ErrorKind;
  use std::path::{Path, PathBuf};

  const ENV_CERT_FILE: &str = "SSL_CERT_FILE";

  /// Returns None if SSL_CERT_FILE is not defined in the current environment.
  ///
  /// If it is defined, it is always used, so it must be a path to a real
  /// file from which certificates can be loaded successfully.
  fn load_certs_from_env() -> Option<Result<Vec<Certificate>, Error>> {
    let cert_var_path = PathBuf::from(env::var_os(ENV_CERT_FILE)?);

    Some(load_pem_certs(&cert_var_path))
  }

  fn load_pem_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    let f = File::open(&path)?;
    let mut f = BufReader::new(f);

    match rustls_pemfile::certs(&mut f) {
      Ok(contents) => Ok(contents.into_iter().map(Certificate).collect()),
      Err(_) => Err(Error::new(
        ErrorKind::InvalidData,
        format!("Could not load PEM file {:?}", path),
      )),
    }
  }

  load_certs_from_env().unwrap_or_else(macos::load_native_certs)
}
