{$i IdSSLOpenSSLDefines.inc}

{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.

    This file includes software copied from the Indy (Internet Direct) project, and which is offered
    under the dual-licensing agreement described on the Indy website. (https://www.indyproject.org/license/)
    }

unit IdSSLOpenSSLResourceStrings;

interface

resourcestring
  RSOSSUnsupportedVersion = 'Unsupported SSL Library version: %.8x.';
  ROSSLCantGetSSLVersionNo = 'Unable to determine SSL Library Version number';
  ROSSLAPIFunctionNotPresent = 'OpenSSL API Function/Procedure %s not found in SSL Library';
  ROSUnsupported = 'Not Supported';
  ROSSLEOFViolation = 'EOF was observed that violates the protocol';
  RSOUnknown        = 'Unknown SSL Error - probably socket error';
  RSONoVersionInfo  = 'Both OpenSSL_version and SSLeay_version missing from OpenSSL Library';


implementation

end.

