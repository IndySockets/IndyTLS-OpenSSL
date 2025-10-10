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


{ Three ways to link to the OpenSSL library are supported:

  1. Dynamic linking at run time using calls to LoadLibrary and GetProcAddress.
     This is the default and allows Indy to find the OpenSSL libraries and adjust
     itself to suit the version found. Versions 1.0.2 to 3.x are currently supported.

  2. Static loading of a shared library (.dll or .so). When your program is loaded
     the loader searches for the shared library and links it to your program. Indy
     can only support the 3.x OpenSSL libraries in this mode.

  3. Statically linked to a static library at link time. Your program executable
     includes the OpenSSL libraries which then do not have to be separately
     installed on the target system. Supported only for the 3.x OpenSSL Libraries
     and for the Free Pascal Compiler (FPC). Delphi does not support this link option.

  Link Option 2 is selected if your program or the IndyOpenSSL package is compiled with
  the OPENSSL_USE_SHARED_LIBRARY defined symbol. It is also selected if
  IdCompilierDefines.inc sets the STATICLOAD_OPENSSL defined symbol (e.g. for IOS).

  Link Option 3 is selected if your program or the IndyOpenSSL package is compiled with
  the OPENSSL_USE_STATIC_LIBRARY defined symbol.

 }
{$IFDEF FPC}
{$mode delphi}
{$ELSE}
  {$IFDEF MSWINDOWS}
    {$DEFINE WINDOWS}
  {$ELSE}
    {$IFDEF POSIX}
      {$DEFINE UNIX}
    {$ELSE}
      {$DEFINE WINDOWS}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}


{$IFDEF STATICLOAD_OPENSSL}
{$DEFINE OPENSSL_STATIC_LINK_MODEL}
{$UNDEF OPENSSL_USE_STATIC_LIBRARY}
{$ENDIF}
{$IFDEF OPENSSL_USE_SHARED_LIBRARY}
{$DEFINE OPENSSL_STATIC_LINK_MODEL}
{$ENDIF}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$IFNDEF FPC}
{$warn Warning:OPENSSL_USE_STATIC_LIBRARY is supported only when compiling with the Free Pascal Compiler}
{$ELSE}
{$DEFINE OPENSSL_STATIC_LINK_MODEL}
{$ENDIF}
{$ENDIF}

{$IFNDEF FPC}
{$if defined(CPU64BITS) or defined(CPUX86_64) or defined(CPUAMD64)}
  {$DEFINE CPU64}
{$else}
  {$DEFINE CPU32}
{$ifend}
{$ENDIF} //FPC

