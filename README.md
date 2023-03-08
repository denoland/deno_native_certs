**deno-native-certs** loads native certificate store into rustls.

On macOS, certificates are loaded from the system keychain. The user, admin and
system trust settings are merged together as documented by Apple. The Security
framework is dynamically loaded using `dlopen` to avoid initial `dyld` overhead.

On Linux and Windows, the
[rustls-native-certs](https://github.com/rustls/rustls-native-certs) is used.
