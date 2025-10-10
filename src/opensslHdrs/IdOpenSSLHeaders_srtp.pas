(* This unit was generated from the source file srtp.h2pas 
It should not be modified directly. All changes should be made to srtp.h2pas
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


unit IdOpenSSLHeaders_srtp;


interface

// Headers for OpenSSL 1.1.1
// srtp.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_ssl;

const
  SRTP_AES128_CM_SHA1_80 = $0001;
  SRTP_AES128_CM_SHA1_32 = $0002;
  SRTP_AES128_F8_SHA1_80 = $0003;
  SRTP_AES128_F8_SHA1_32 = $0004;
  SRTP_NULL_SHA1_80      = $0005;
  SRTP_NULL_SHA1_32      = $0006;

  (* AEAD SRTP protection profiles from RFC 7714 *)
  SRTP_AEAD_AES_128_GCM = $0007;
  SRTP_AEAD_AES_256_GCM = $0008;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM SSL_CTX_set_tlsext_use_srtp}
{$EXTERNALSYM SSL_set_tlsext_use_srtp}
{$EXTERNALSYM SSL_get_selected_srtp_profile}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl;

var
  SSL_CTX_set_tlsext_use_srtp: function (ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_tlsext_use_srtp;
  SSL_set_tlsext_use_srtp: function (ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set_tlsext_use_srtp;
  SSL_get_selected_srtp_profile: function (s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl = Load_SSL_get_selected_srtp_profile;
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
function Load_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_tlsext_use_srtp := LoadLibCryptoFunction('SSL_CTX_set_tlsext_use_srtp');
  if not assigned(SSL_CTX_set_tlsext_use_srtp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tlsext_use_srtp');
  Result := SSL_CTX_set_tlsext_use_srtp(ctx,profiles);
end;

function Load_SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_tlsext_use_srtp := LoadLibCryptoFunction('SSL_set_tlsext_use_srtp');
  if not assigned(SSL_set_tlsext_use_srtp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tlsext_use_srtp');
  Result := SSL_set_tlsext_use_srtp(ctx,profiles);
end;

function Load_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl;
begin
  SSL_get_selected_srtp_profile := LoadLibCryptoFunction('SSL_get_selected_srtp_profile');
  if not assigned(SSL_get_selected_srtp_profile) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_selected_srtp_profile');
  Result := SSL_get_selected_srtp_profile(s);
end;


procedure UnLoad;
begin
  SSL_CTX_set_tlsext_use_srtp := Load_SSL_CTX_set_tlsext_use_srtp;
  SSL_set_tlsext_use_srtp := Load_SSL_set_tlsext_use_srtp;
  SSL_get_selected_srtp_profile := Load_SSL_get_selected_srtp_profile;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
