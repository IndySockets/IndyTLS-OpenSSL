(* This unit was generated from the source file camellia.h2pas 
It should not be modified directly. All changes should be made to camellia.h2pas
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


unit IdOpenSSLHeaders_camellia;


interface

// Headers for OpenSSL 1.1.1
// camellia.h


uses
  IdSSLOpenSSLAPI;

const
  // Added '_CONST' to avoid name clashes
  CAMELLIA_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  CAMELLIA_DECRYPT_CONST = 0;

  CAMELLIA_BLOCK_SIZE = 16;
  CAMELLIA_TABLE_BYTE_LEN = 272;
  CAMELLIA_TABLE_WORD_LEN = CAMELLIA_TABLE_BYTE_LEN div 4;

type
  KEY_TABLE_TYPE = array[0 .. CAMELLIA_TABLE_WORD_LEN - 1] of TOpenSSL_C_UINT;

  camellia_key_st_u = record
    case Integer of
    0: (d: TOpenSSL_C_DOUBLE);
    1: (rd_key: KEY_TABLE_TYPE);
  end;

  camellia_key_st = record
    u: camellia_key_st_u;
    grand_rounds: TOpenSSL_C_INT;
  end;

  CAMELLIA_KEY = camellia_key_st;
  PCAMELLIA_KEY = ^CAMELLIA_KEY;

  TCamellia_ctr128_encrypt_ivec = array[0 .. CAMELLIA_TABLE_WORD_LEN - 1] of Byte;
  TCamellia_ctr128_encrypt_ecount_buf = array[0 .. CAMELLIA_TABLE_WORD_LEN - 1] of Byte;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM Camellia_set_key}
{$EXTERNALSYM Camellia_encrypt}
{$EXTERNALSYM Camellia_decrypt}
{$EXTERNALSYM Camellia_ecb_encrypt}
{$EXTERNALSYM Camellia_cbc_encrypt}
{$EXTERNALSYM Camellia_cfb128_encrypt}
{$EXTERNALSYM Camellia_cfb1_encrypt}
{$EXTERNALSYM Camellia_cfb8_encrypt}
{$EXTERNALSYM Camellia_ofb128_encrypt}
{$EXTERNALSYM Camellia_ctr128_encrypt}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function Camellia_set_key(const userKey: PByte; const bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure Camellia_encrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl; external CLibCrypto;
procedure Camellia_decrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl; external CLibCrypto;
procedure Camellia_ecb_encrypt( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure Camellia_cbc_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure Camellia_cfb128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure Camellia_cfb1_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure Camellia_cfb8_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure Camellia_ofb128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;
procedure Camellia_ctr128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: POpenSSL_C_INT); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_Camellia_set_key(const userKey: PByte; const bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl;
procedure Load_Camellia_encrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl;
procedure Load_Camellia_decrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl;
procedure Load_Camellia_ecb_encrypt( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TOpenSSL_C_INT); cdecl;
procedure Load_Camellia_cbc_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl;
procedure Load_Camellia_cfb128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
procedure Load_Camellia_cfb1_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
procedure Load_Camellia_cfb8_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
procedure Load_Camellia_ofb128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl;
procedure Load_Camellia_ctr128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: POpenSSL_C_INT); cdecl;

var
  Camellia_set_key: function (const userKey: PByte; const bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl = Load_Camellia_set_key;
  Camellia_encrypt: procedure (const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl = Load_Camellia_encrypt;
  Camellia_decrypt: procedure (const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl = Load_Camellia_decrypt;
  Camellia_ecb_encrypt: procedure ( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TOpenSSL_C_INT); cdecl = Load_Camellia_ecb_encrypt;
  Camellia_cbc_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cbc_encrypt;
  Camellia_cfb128_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cfb128_encrypt;
  Camellia_cfb1_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cfb1_encrypt;
  Camellia_cfb8_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cfb8_encrypt;
  Camellia_ofb128_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl = Load_Camellia_ofb128_encrypt;
  Camellia_ctr128_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: POpenSSL_C_INT); cdecl = Load_Camellia_ctr128_encrypt;
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
function Load_Camellia_set_key(const userKey: PByte; const bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl;
begin
  Camellia_set_key := LoadLibCryptoFunction('Camellia_set_key');
  if not assigned(Camellia_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_set_key');
  Result := Camellia_set_key(userKey,bits,key);
end;

procedure Load_Camellia_encrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl;
begin
  Camellia_encrypt := LoadLibCryptoFunction('Camellia_encrypt');
  if not assigned(Camellia_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_encrypt');
  Camellia_encrypt(in_,out_,key);
end;

procedure Load_Camellia_decrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl;
begin
  Camellia_decrypt := LoadLibCryptoFunction('Camellia_decrypt');
  if not assigned(Camellia_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_decrypt');
  Camellia_decrypt(in_,out_,key);
end;

procedure Load_Camellia_ecb_encrypt( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_ecb_encrypt := LoadLibCryptoFunction('Camellia_ecb_encrypt');
  if not assigned(Camellia_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_ecb_encrypt');
  Camellia_ecb_encrypt(in_,out_,key,enc);
end;

procedure Load_Camellia_cbc_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cbc_encrypt := LoadLibCryptoFunction('Camellia_cbc_encrypt');
  if not assigned(Camellia_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cbc_encrypt');
  Camellia_cbc_encrypt(in_,out_,length,key,ivec,enc);
end;

procedure Load_Camellia_cfb128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cfb128_encrypt := LoadLibCryptoFunction('Camellia_cfb128_encrypt');
  if not assigned(Camellia_cfb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cfb128_encrypt');
  Camellia_cfb128_encrypt(in_,out_,length,key,ivec,num,enc);
end;

procedure Load_Camellia_cfb1_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cfb1_encrypt := LoadLibCryptoFunction('Camellia_cfb1_encrypt');
  if not assigned(Camellia_cfb1_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cfb1_encrypt');
  Camellia_cfb1_encrypt(in_,out_,length,key,ivec,num,enc);
end;

procedure Load_Camellia_cfb8_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cfb8_encrypt := LoadLibCryptoFunction('Camellia_cfb8_encrypt');
  if not assigned(Camellia_cfb8_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cfb8_encrypt');
  Camellia_cfb8_encrypt(in_,out_,length,key,ivec,num,enc);
end;

procedure Load_Camellia_ofb128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl;
begin
  Camellia_ofb128_encrypt := LoadLibCryptoFunction('Camellia_ofb128_encrypt');
  if not assigned(Camellia_ofb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_ofb128_encrypt');
  Camellia_ofb128_encrypt(in_,out_,length,key,ivec,num);
end;

procedure Load_Camellia_ctr128_encrypt( const in_: PByte; const out_: PByte; length: TOpenSSL_C_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: POpenSSL_C_INT); cdecl;
begin
  Camellia_ctr128_encrypt := LoadLibCryptoFunction('Camellia_ctr128_encrypt');
  if not assigned(Camellia_ctr128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_ctr128_encrypt');
  Camellia_ctr128_encrypt(in_,out_,length,key,ivec,ecount_buf,num);
end;


procedure UnLoad;
begin
  Camellia_set_key := Load_Camellia_set_key;
  Camellia_encrypt := Load_Camellia_encrypt;
  Camellia_decrypt := Load_Camellia_decrypt;
  Camellia_ecb_encrypt := Load_Camellia_ecb_encrypt;
  Camellia_cbc_encrypt := Load_Camellia_cbc_encrypt;
  Camellia_cfb128_encrypt := Load_Camellia_cfb128_encrypt;
  Camellia_cfb1_encrypt := Load_Camellia_cfb1_encrypt;
  Camellia_cfb8_encrypt := Load_Camellia_cfb8_encrypt;
  Camellia_ofb128_encrypt := Load_Camellia_ofb128_encrypt;
  Camellia_ctr128_encrypt := Load_Camellia_ctr128_encrypt;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
