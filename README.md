# Indy TLS for OpenSSL

**THIS IS NOT AN OFFICIAL RELEASE YET!**

This project implements TLS and Hash functionalities for Indy 10.7 (WIP) using OpenSSL as the backend library.

This project was split off from the main Indy library so it could be updated independantly to the latest version of OpenSSL.

It should be usable as an additional package/dropin to Indy, as long as it remains compatible with Indy's SSLIOHandler and IdFIPS interfaces.

Once this project is stable, the corresponding files will be removed from Indy's main Protocols package, the USE_OPENSSL conditional will be removed from Indy's source files, etc. **This requires Indy 10.7 or later**, otherwise it will conflict with the OpenSSL code that is present in older Indy versions.

Not sure at this time whether this project will stay as an independant repo, or if it will eventually be merged back into the main Indy repo as a sub-folder.  But either way, this project will stay as a separate package moving forward.

**NOT FOR OPENSSL 3.0+ AT THIS TIME!**

However, due to time constraints and lack of resources, updating this project to the latest OpenSSL has not happened yet. So, for the forseeable future, this project is just to provide *backwards compatibility* with existing code that needs to continue using Indy's default SSLIOHandler for OpenSSL 1.0.2.  To use Indy with OpenSSL 3.0 and later, you can use [TaurusTLS](https://github.com/TaurusTLS-Developers/TaurusTLS) or [IndySecOpenSSL](https://github.com/MWASoftware/IndySecOpenSSL) instead, which are both compatible with the current Indy release.

Maybe someday, this project will be able to support modern OpenSSL versions.

## License

This project is dual-licensed under the terms of the Indy Modified BSD License and Indy MPL License.
You can choose between one of them if you use this work.

SPDX-License-Identifier: LicenseRef-IndyBSD OR MPL-1.1
