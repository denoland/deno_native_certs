use deno_native_certs::load_native_certs;

fn main() {
  let certs = load_native_certs().unwrap();
  for cert in certs {
    println!("{:?}", cert.0);
  }
}
