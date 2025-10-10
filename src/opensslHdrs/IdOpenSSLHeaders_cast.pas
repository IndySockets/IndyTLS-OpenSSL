(* This unit was generated from the source file cast.h2pas 
It should not be modified directly. All changes should be made to cast.h2pas
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


unit IdOpenSSLHeaders_cast;


interface

// Headers for OpenSSL 1.1.1
// cast.h


uses
  IdSSLOpenSSLAPI;

const
  CAST_ENCRYPT_CONST =  1;
  CAST_DECRYPT_CONST =  0;
  CAST_BLOCK =  8;
  CAST_KEY_LENGTH = 16;

type
  CAST_LONG = type TOpenSSL_C_UINT;
  PCAST_LONG = ^CAST_LONG;

  cast_key_st = record
    data: array of CAST_LONG;
    short_key: TOpenSSL_C_INT;              //* Use reduced rounds for short key */
  end;

  CAST_KEY = cast_key_st;
  PCAST_KEY = ^CAST_KEY;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CAST_set_key}
{$EXTERNALSYM CAST_ecb_encrypt}
{$EXTERNALSYM CAST_encrypt}
{$EXTERNALSYM CAST_decrypt}
{$EXTERNALSYM CAST_cbc_encrypt}
{$EXTERNALSYM CAST_cfb64_encrypt}
{$EXTERNALSYM CAST_ofb64_encrypt}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure CAST_set_key(key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl; external CLibCrypto;
procedure CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CAST_encrypt(data: PCAST_LONG; const key: PCast_Key); cdecl; external CLibCrypto;
procedure CAST_decrypt(data: PCAST_LONG; const key: PCast_Key); cdecl; external CLibCrypto;
procedure CAST_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CAST_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CAST_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

procedure Load_CAST_set_key(key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl;
procedure Load_CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl;
procedure Load_CAST_encrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
procedure Load_CAST_decrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
procedure Load_CAST_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl;
procedure Load_CAST_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
procedure Load_CAST_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl;

var
  CAST_set_key: procedure (key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl = Load_CAST_set_key;
  CAST_ecb_encrypt: procedure (const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl = Load_CAST_ecb_encrypt;
  CAST_encrypt: procedure (data: PCAST_LONG; const key: PCast_Key); cdecl = Load_CAST_encrypt;
  CAST_decrypt: procedure (data: PCAST_LONG; const key: PCast_Key); cdecl = Load_CAST_decrypt;
  CAST_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl = Load_CAST_cbc_encrypt;
  CAST_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_CAST_cfb64_encrypt;
  CAST_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl = Load_CAST_ofb64_encrypt;
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
procedure Load_CAST_set_key(key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl;
begin
  CAST_set_key := LoadLibCryptoFunction('CAST_set_key');
  if not assigned(CAST_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_set_key');
  CAST_set_key(key,len,data);
end;

procedure Load_CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl;
begin
  CAST_ecb_encrypt := LoadLibCryptoFunction('CAST_ecb_encrypt');
  if not assigned(CAST_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_ecb_encrypt');
  CAST_ecb_encrypt(in_,out_,key,enc);
end;

procedure Load_CAST_encrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
begin
  CAST_encrypt := LoadLibCryptoFunction('CAST_encrypt');
  if not assigned(CAST_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_encrypt');
  CAST_encrypt(data,key);
end;

procedure Load_CAST_decrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
begin
  CAST_decrypt := LoadLibCryptoFunction('CAST_decrypt');
  if not assigned(CAST_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_decrypt');
  CAST_decrypt(data,key);
end;

procedure Load_CAST_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl;
begin
  CAST_cbc_encrypt := LoadLibCryptoFunction('CAST_cbc_encrypt');
  if not assigned(CAST_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_cbc_encrypt');
  CAST_cbc_encrypt(in_,out_,length,ks,iv,enc);
end;

procedure Load_CAST_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  CAST_cfb64_encrypt := LoadLibCryptoFunction('CAST_cfb64_encrypt');
  if not assigned(CAST_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_cfb64_encrypt');
  CAST_cfb64_encrypt(in_,out_,length,schedule,ivec,num,enc);
end;

procedure Load_CAST_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl;
begin
  CAST_ofb64_encrypt := LoadLibCryptoFunction('CAST_ofb64_encrypt');
  if not assigned(CAST_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_ofb64_encrypt');
  CAST_ofb64_encrypt(in_,out_,length,schedule,ivec,num);
end;


procedure UnLoad;
begin
  CAST_set_key := Load_CAST_set_key;
  CAST_ecb_encrypt := Load_CAST_ecb_encrypt;
  CAST_encrypt := Load_CAST_encrypt;
  CAST_decrypt := Load_CAST_decrypt;
  CAST_cbc_encrypt := Load_CAST_cbc_encrypt;
  CAST_cfb64_encrypt := Load_CAST_cfb64_encrypt;
  CAST_ofb64_encrypt := Load_CAST_ofb64_encrypt;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
