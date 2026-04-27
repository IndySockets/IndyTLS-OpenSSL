# Indy TLS for OpenSSL

**THIS IS NOT AN OFFICIAL RELEASE YET!**

This project implements TLS and Hash functionalities for (WIP) Indy 10.7 using OpenSSL as the backend library.

This has been split off from the main Indy library so it can be updated independantly to the latest version of OpenSSL.

It should be usable as an additional package/dropin to Indy, as long as it remains compatible with Indy's SSLIOHandler and IdFIPS interfaces.

Once this project is stable, the corresponding files will be removed from Indy's main Protocols package, the USE_OPENSSL conditional will be removed from Indy's source files, etc. **This requires Indy 10.7 or later**, otherwise it will conflict with the OpenSSL files thaat are present in older Indy versions.

Not sure at this time whether this project will stay as an independant repo, or if it will eventually be merged back into the main Indy repo as a sub-folder.  But either way, this project will stay as a separate package moving forward.

## License

This project is dual-licensed under the terms of the Indy Modified BSD License and Indy MPL License.
You can choose between one of them if you use this work.

SPDX-License-Identifier: LicenseRef-IndyBSD OR MPL-1.1
