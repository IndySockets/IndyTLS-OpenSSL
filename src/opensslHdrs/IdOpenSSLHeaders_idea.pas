(* This unit was generated from the source file idea.h2pas 
It should not be modified directly. All changes should be made to idea.h2pas
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


unit IdOpenSSLHeaders_idea;


interface

// Headers for OpenSSL 1.1.1
// idea.h


uses
  IdSSLOpenSSLAPI;

const
  // Added '_CONST' to avoid name clashes
  IDEA_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  IDEA_DECRYPT_CONST = 0;

  IDEA_BLOCK      = 8;
  IDEA_KEY_LENGTH = 16;

type
  IDEA_INT = type TOpenSSL_C_INT;

  idea_key_st = record
    data: array[0..8, 0..5] of IDEA_INT;
  end;
  IDEA_KEY_SCHEDULE = idea_key_st;
  PIDEA_KEY_SCHEDULE = ^IDEA_KEY_SCHEDULE;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM IDEA_options}
{$EXTERNALSYM IDEA_ecb_encrypt}
{$EXTERNALSYM IDEA_set_encrypt_key}
{$EXTERNALSYM IDEA_set_decrypt_key}
{$EXTERNALSYM IDEA_cbc_encrypt}
{$EXTERNALSYM IDEA_cfb64_encrypt}
{$EXTERNALSYM IDEA_ofb64_encrypt}
{$EXTERNALSYM IDEA_encrypt}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function IDEA_options: PAnsiChar; cdecl; external CLibCrypto;
procedure IDEA_ecb_encrypt(const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;
procedure IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;
procedure IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;
procedure IDEA_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure IDEA_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure IDEA_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;
procedure IDEA_encrypt(in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_IDEA_options: PAnsiChar; cdecl;
procedure Load_IDEA_ecb_encrypt(const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
procedure Load_IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
procedure Load_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
procedure Load_IDEA_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl;
procedure Load_IDEA_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
procedure Load_IDEA_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl;
procedure Load_IDEA_encrypt(in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl;

var
  IDEA_options: function : PAnsiChar; cdecl = Load_IDEA_options;
  IDEA_ecb_encrypt: procedure (const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_ecb_encrypt;
  IDEA_set_encrypt_key: procedure (const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_set_encrypt_key;
  IDEA_set_decrypt_key: procedure (ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_set_decrypt_key;
  IDEA_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl = Load_IDEA_cbc_encrypt;
  IDEA_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_IDEA_cfb64_encrypt;
  IDEA_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl = Load_IDEA_ofb64_encrypt;
  IDEA_encrypt: procedure (in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_encrypt;
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
function Load_IDEA_options: PAnsiChar; cdecl;
begin
  IDEA_options := LoadLibCryptoFunction('IDEA_options');
  if not assigned(IDEA_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_options');
  Result := IDEA_options();
end;

procedure Load_IDEA_ecb_encrypt(const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_ecb_encrypt := LoadLibCryptoFunction('IDEA_ecb_encrypt');
  if not assigned(IDEA_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ecb_encrypt');
  IDEA_ecb_encrypt(in_,out_,ks);
end;

procedure Load_IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_set_encrypt_key := LoadLibCryptoFunction('IDEA_set_encrypt_key');
  if not assigned(IDEA_set_encrypt_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_encrypt_key');
  IDEA_set_encrypt_key(key,ks);
end;

procedure Load_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_set_decrypt_key := LoadLibCryptoFunction('IDEA_set_decrypt_key');
  if not assigned(IDEA_set_decrypt_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_decrypt_key');
  IDEA_set_decrypt_key(ek,dk);
end;

procedure Load_IDEA_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl;
begin
  IDEA_cbc_encrypt := LoadLibCryptoFunction('IDEA_cbc_encrypt');
  if not assigned(IDEA_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cbc_encrypt');
  IDEA_cbc_encrypt(in_,out_,length,ks,iv,enc);
end;

procedure Load_IDEA_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  IDEA_cfb64_encrypt := LoadLibCryptoFunction('IDEA_cfb64_encrypt');
  if not assigned(IDEA_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cfb64_encrypt');
  IDEA_cfb64_encrypt(in_,out_,length,ks,iv,num,enc);
end;

procedure Load_IDEA_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl;
begin
  IDEA_ofb64_encrypt := LoadLibCryptoFunction('IDEA_ofb64_encrypt');
  if not assigned(IDEA_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ofb64_encrypt');
  IDEA_ofb64_encrypt(in_,out_,length,ks,iv,num);
end;

procedure Load_IDEA_encrypt(in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_encrypt := LoadLibCryptoFunction('IDEA_encrypt');
  if not assigned(IDEA_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_encrypt');
  IDEA_encrypt(in_,ks);
end;


procedure UnLoad;
begin
  IDEA_options := Load_IDEA_options;
  IDEA_ecb_encrypt := Load_IDEA_ecb_encrypt;
  IDEA_set_encrypt_key := Load_IDEA_set_encrypt_key;
  IDEA_set_decrypt_key := Load_IDEA_set_decrypt_key;
  IDEA_cbc_encrypt := Load_IDEA_cbc_encrypt;
  IDEA_cfb64_encrypt := Load_IDEA_cfb64_encrypt;
  IDEA_ofb64_encrypt := Load_IDEA_ofb64_encrypt;
  IDEA_encrypt := Load_IDEA_encrypt;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
