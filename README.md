# Indy TLS for OpenSSL

THIS REPO IS NO LONGER MAINTAINED. This repo has been replaced by https://github.com/MWASoftware/IndySecOpenSSL.

This project implemented TLS and Hash functionalities for Indy using OpenSSL as the backend library.

This fork is the basis of a change request to the original repo and should be ignored by most users.

It is split off from the main Indy library so it can be updated independantly to the latest version of OpenSSL.

It should be usable as an additional package/dropin to Indy (branch 10.7), as long as it remains compatible with Indy's SSLIOHandler and IdFIPS interfaces.

About this Pull Request
-----------------------

This proposed update adds support for OpenSSL 3.0 and later to Indy. Both Delphi and Lazarus/fpc are fully supported by this source code tree. 

This update includes a new (optional) OpenSSL package separate from Indy's "protocols" package.

Three link models are supported.
   * Dynamic Library Load (the default and the approach used in previous versions)
   * compile time linkage to a shared (.so or .dll) library (OpenSSL 3.x only)
   * compile time linkage to a static library (FPC only with gcc compiled OpenSSL).

For dynamic library load, a "Just in Time" approach is used where each API call is initialised to a local proc "loader" function.
The intent is that on the first call a given API function, the actual entry point in the OpenSSL function
is loaded and the API call is set to the loaded entry point. The API function is now called on the user's
behalf. If the call fails to load then it is replaced by a compatibility function (if one exists). If none exists 
then an exception is raised. If an API function is allowed to be nil (as set in the template), then the function
is loaded at library load time.


The updated package has been tested under the following scenarios:

1. Static Linking to Static Library (Lazarus/Linux only with gcc generated libssl.a and libcrypto.a).

2. Static Linking to Shared Library (DLL/so). Delphi and Lazarus (Windows and Linux).

3. Dynamic Load and Link. Delphi and Lazarus (Windows and Linux). OpenSSL 1.0.2, 1.1.1. and 3.x

For (2) and (3) above, the different link strategies are selected at compile time by a "defined symbol" set in the OpenSSL
package options (not the using program), as follows:

- OPENSSL_USE_STATIC_LIBRARY (Static Linking to Static Library)
- OPENSSL_USE_SHARED_LIBRARY (Static Linking to Shared Library)
- Neither of the above (Dynamic Load and Link).

Note that (2) and (3) behave identically for Static and Shared library linking).

The defined synbol OPENSSL_NO_LEGACY_SUPPORT may also be set at compile time and applies to Dynamic
loading. If set, no compatibility functions are compile in to the executeable. Only 3.0 or later
API calls may be used.


Delphi Builds
=============

All delphi/IndyTLSOpenSSLnnn.dpk  files have been edited to remove references to the moved and updated files.
However only delphi/IndyTLSOpenSSL290 has been tested (with Delphi Berlin edition).

New Packages:

IndyTLSOpenSSL290 and
dclIndyTLSOpenSSL290 (design time only)

may be found in the delphi\ subdirectory.

These are dependent on IndyProtocols290 and dclIndyProtocols290 respectively from the main Indy project tree.

To use OpenSSL in a given project, the IndyTLSOpenSSL290 package must now be included.


Lazarus/FPC Builds
==================

All lazarus packages may be found in the "lazarus-fpc/" top level folder. These are:

indyopenssl.lpk

and the design time only packages

indylaz_indyopenssl

In order to install this proposed update for Lazarus (Windows and Linux), n Open the package indylaz_openssl.lpk and 
click on install. The Indy Library should now be available for use. This assumes that the indyprotocols package 
from the main Indy Project Tree has already been installed.

You can also use fpcmake to create a makefile for building the full package. Run

fpcmake -r

in the package's root directiory.

Test Programs
=============

Two test programs are available with variants for Delphi and Lazarus. These may be found in:

1. Test/openssl-client and
2. Test/openssl-server.

openssl-client uses an HTTP Client to issue an http Get on an https target and returns 
the result. The server certificate is also verified.

openssl-server provides both and a server and uses a local PKI to retrieve a web page 
from the server, with both client and server certificate verification and to return the result.

Note: in all cases the compiled programs are placed in the openssl-client or openssl-server
directories.

These build both test programs and their supporting packages as a single project group. You do
not have to install the design time packages in order to use the test programs.

When testing under Lazarus, similarly you do not need to have installed the design time packages.
However, you need to at least "open" the dependent packages so that the IDE knows where to find
them.

Test program command line arguments:

Usage: fpc_openssl_client [-h] [-n] [-l <cacerts dir>] [-L] [OpenSSL lib dir]

Usage: fpc_openssl_client [-h] [-n] [-l <cacerts dir>] [-L] [OpenSSL lib dir]

-L is useful under Linux when the OpenSSL Library used has not been installed and 
   hence does not know where to find its X.509 certificate store. When -L is
   given, the program searches a list of possible locations.




Upstream README.MD
=================

Once this project is stable, the corresponding files will be removed from Indy's main Protocols package, the USE_OPENSSL conditional will be removed from Indy's source files, etc.  This requires Indy 10.7 or later, otherwise it will conflict with the OpenSSL files thaat are present in older Indy versions.

Not sure at this time whether this project will stay as an independant repo, or if it will eventually be merged back into the main Indy repo as a sub-folder.  But either way, this project will stay as a separate package moving forward.

## License

This project is dual-licensed under the terms of the Indy Modified BSD License and Indy MPL License.
You can choose between one of them if you use this work.

SPDX-License-Identifier: LicenseRef-IndyBSD OR MPL-1.1

