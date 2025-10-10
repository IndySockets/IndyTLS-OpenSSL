(* This unit was generated from the source file ebcdic.h2pas 
It should not be modified directly. All changes should be made to ebcdic.h2pas
and this file regenerated *)

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


unit IdOpenSSLHeaders_ebcdic;


interface

// Headers for OpenSSL 1.1.1
// ebcdic.h


uses
  IdSSLOpenSSLAPI;


  //extern const unsigned char os_toascii[256];
  //extern const unsigned char os_toebcdic[256];

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ebcdic2ascii}
{$EXTERNALSYM ascii2ebcdic}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ebcdic2ascii(dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl; external CLibCrypto;
function ascii2ebcdic(dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ebcdic2ascii(dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl;
function Load_ascii2ebcdic(dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl;

var
  ebcdic2ascii: function (dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl = Load_ebcdic2ascii;
  ascii2ebcdic: function (dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl = Load_ascii2ebcdic;
{$ENDIF}

implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_ebcdic2ascii(dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  ebcdic2ascii := LoadLibCryptoFunction('ebcdic2ascii');
  if not assigned(ebcdic2ascii) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ebcdic2ascii');
  Result := ebcdic2ascii(dest,srce,count);
end;

function Load_ascii2ebcdic(dest: Pointer; const srce: Pointer; count: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  ascii2ebcdic := LoadLibCryptoFunction('ascii2ebcdic');
  if not assigned(ascii2ebcdic) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ascii2ebcdic');
  Result := ascii2ebcdic(dest,srce,count);
end;


procedure UnLoad;
begin
  ebcdic2ascii := Load_ebcdic2ascii;
  ascii2ebcdic := Load_ascii2ebcdic;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
