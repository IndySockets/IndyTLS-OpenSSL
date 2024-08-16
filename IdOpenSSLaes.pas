unit IdOpenSSLaes;

interface

uses
  IdOpenSSLopensslconf,
  IdCTypes;

{
  Automatically converted by H2Pas 1.0.0 from openssl-1.1.0l/include/openssl/aes.h
  The following command line parameters were used:
  -p
  -P
  -t
  -T
  -C
  openssl-1.1.0l/include/openssl/aes.h
}
{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}

const
  AES_DECRYPT = 0;
  {
    * Because array size can't be a const in C, the following two are macros.
    * Both sizes are in bytes.
  }
  AES_MAXNR = 14;
  AES_BLOCK_SIZE = 16;

  { This should be a hidden type, but EVP requires that the size be known }
type
  Paes_key_st = ^Taes_key_st;

  Taes_key_st = record
{$IFDEF AES_LONG}
    rd_key: array [0 .. (4 * (AES_MAXNR + 1)) - 1] of TIdC_ULONG;
{$ELSE}
    rd_key: array [0 .. (4 * (AES_MAXNR + 1)) - 1] of TIdC_UINT;
{$ENDIF}
    rounds: TIdC_Int;
  end;

  PAES_KEY = Pointer;

  {
    * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
    *
    * Licensed under the OpenSSL license (the "License").  You may not use
    * this file except in compliance with the License.  You can obtain a copy
    * in the file LICENSE in the source distribution or at
    * https://www.openssl.org/source/license.html
  }

type
  LPN_AES_options = function: PChar cdecl;
  LPN_AES_set_encrypt_key = function(userKey: PChar; bits: PIdC_INT;
    key: PAES_KEY): PIdC_INT cdecl;
  LPN_AES_set_decrypt_key = function(userKey: PChar; bits: PIdC_INT;
    key: PAES_KEY): PIdC_INT cdecl;
  LPN_AES_encrypt = procedure(_in: PChar; _out: PChar; key: PAES_KEY)cdecl;
  LPN_AES_DECRYPT = procedure(_in: PChar; _out: PChar; key: PAES_KEY)cdecl;
  LPN_AES_ecb_encrypt = procedure(_in: PChar; _out: PChar; key: PAES_KEY;
    enc: PIdC_INT)cdecl;
  LPN_AES_cbc_encrypt = procedure(_in: PChar; _out: PChar; length: TIdC_SSIZET;
    key: PAES_KEY; ivec: PChar; enc: PIdC_INT)cdecl;
  LPN_AES_cfb128_encrypt = procedure(_in: PChar; _out: PChar;
    length: TIdC_SSIZET; key: PAES_KEY; ivec: PChar; num: PIdC_INT;
    enc: PIdC_INT)cdecl;
  LPN_AES_cfb1_encrypt = procedure(_in: PChar; _out: PChar; length: TIdC_SSIZET;
    key: PAES_KEY; ivec: PChar; num: PIdC_INT; enc: PIdC_INT)cdecl;
  LPN_AES_cfb8_encrypt = procedure(_in: PChar; _out: PChar; length: TIdC_SSIZET;
    key: PAES_KEY; ivec: PChar; num: PIdC_INT; enc: PIdC_INT)cdecl;
  LPN_AES_ofb128_encrypt = procedure(_in: PChar; _out: PChar;
    length: TIdC_SSIZET; key: PAES_KEY; ivec: PChar; num: PIdC_INT)cdecl;
  { NB: the IV is _two_ blocks long }
  LPN_AES_ige_encrypt = procedure(_in: PChar; _out: PChar; length: TIdC_SSIZET;
    key: PAES_KEY; ivec: PChar; enc: PIdC_INT)cdecl;
  { NB: the IV is _four_ blocks long }
  LPN_AES_bi_ige_encrypt = procedure(_in: PChar; _out: PChar;
    length: TIdC_SSIZET; key: PAES_KEY; key2: PAES_KEY; ivec: PChar;
    enc: PIdC_INT)cdecl;
  LPN_AES_wrap_key = function(key: PAES_KEY; iv: PChar; _out: PChar; _in: PChar;
    inlen: TIdC_UINT): PIdC_INT cdecl;
  LPN_AES_unwrap_key = function(key: PAES_KEY; iv: PChar; _out: PChar;
    _in: PChar; inlen: TIdC_UINT): PIdC_INT cdecl;

var
  AES_options: LPN_AES_options;
  AES_set_encrypt_key: LPN_AES_set_encrypt_key;
  AES_set_decrypt_key: LPN_AES_set_decrypt_key;
  AES_encrypt: LPN_AES_encrypt;
  _AES_DECRYPT: LPN_AES_DECRYPT;
  AES_ecb_encrypt: LPN_AES_ecb_encrypt;
  AES_cbc_encrypt: LPN_AES_cbc_encrypt;
  AES_cfb128_encrypt: LPN_AES_cfb128_encrypt;
  AES_cfb1_encrypt: LPN_AES_cfb1_encrypt;
  AES_cfb8_encrypt: LPN_AES_cfb8_encrypt;
  AES_ofb128_encrypt: LPN_AES_ofb128_encrypt;
  AES_ige_encrypt: LPN_AES_ige_encrypt;
  AES_bi_ige_encrypt: LPN_AES_bi_ige_encrypt;
  AES_wrap_key: LPN_AES_wrap_key;
  AES_unwrap_key: LPN_AES_unwrap_key;

implementation

uses
  SysUtils;

function stub_AES_options: PChar cdecl;
begin
  AES_options := CryptoFixupStub('AES_options'); { Do not Localize }
  Result := AES_options;
end;

function stub_AES_set_encrypt_key(userKey: PChar; bits: PIdC_INT; key: PAES_KEY)
  : PIdC_INT cdecl;
begin
  AES_set_encrypt_key := CryptoFixupStub('AES_set_encrypt_key');   {Do not Localize}
  Result := AES_set_encrypt_key(userKey, bits, key);
end;

function stub_AES_set_decrypt_key(userKey: PChar; bits: PIdC_INT; key: PAES_KEY)
  : PIdC_INT cdecl;
begin
  AES_set_decrypt_key := CryptoFixupStub('AES_set_decrypt_key');  {Do not Localize}
  Result := AES_set_decrypt_key(userKey, bits, key);
end;

procedure stub_AES_encrypt(_in: PChar; _out: PChar; key: PAES_KEY)cdecl;
begin
  AES_encrypt := CryptoFixupStub('AES_encrypt');   {Do not Localize}
  AES_encrypt(_in, _out, key);
end;

procedure stub_AES_decrypt(_in: PChar; _out: PChar; key: PAES_KEY)cdecl;
begin
  _AES_DECRYPT := CryptoFixupStub('AES_decrypt');   {Do not Localize}
  _AES_DECRYPT(_in, _out, key);
end;

procedure stub_AES_ecb_encrypt(_in: PChar; _out: PChar; key: PAES_KEY;
  enc: PIdC_INT)cdecl;
begin
  AES_ecb_encrypt := CryptoFixupStub('AES_ecb_encrypt');   {Do not Localize}
  AES_ecb_encrypt(_in, _out, key, enc);
end;

procedure stub_AES_cbc_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; ivec: PChar; enc: PIdC_INT)cdecl;
begin
  AES_cbc_encrypt := CryptoFixupStub('LPN_AES_cbc_encrypt');   {Do not Localize}
  AES_cbc_encrypt(_in, _out, length, key, ivec, enc);
end;

procedure stub_AES_cfb128_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; ivec: PChar; num: PIdC_INT; enc: PIdC_INT)cdecl;
begin
  AES_cfb128_encrypt := CryptoFixupStub('AES_cfb128_encrypt');  {Do not Localize}
  AES_cfb128_encrypt(_in, _out, length, key, ivec, num, enc);
end;

procedure stub_AES_cfb1_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; ivec: PChar; num: PIdC_INT; enc: PIdC_INT)cdecl;
begin
  AES_cfb1_encrypt := CryptoFixupStub('AES_cfb1_encrypt');   {Do not Localize}
  AES_cfb1_encrypt(_in, _out, length, key, ivec, num, enc);
end;

procedure stub_AES_cfb8_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; ivec: PChar; num: PIdC_INT; enc: PIdC_INT)cdecl;
begin
  AES_cfb8_encrypt := CryptoFixupStub('AES_cfb8_encrypt');   {Do not Localize}
  AES_cfb8_encrypt(_in, _out, length, key, ivec, num, enc);
end;

procedure stub_AES_ofb128_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; ivec: PChar; num: PIdC_INT)cdecl;
begin
  AES_ofb128_encrypt := CryptoFixupStub('AES_ofb128_encrypt');   {Do not Localize}
  AES_ofb128_encrypt(_in, _out, length, key, ivec, num);
end;

{ NB: the IV is _two_ blocks long }
procedure stub_AES_ige_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; ivec: PChar; enc: PIdC_INT)cdecl;
begin
  AES_ige_encrypt := CryptoFixupStub('AES_ige_encrypt');   {Do not Localize}
  AES_ige_encrypt(_in, _out, length, key, ivec, enc);
end;

{ NB: the IV is _four_ blocks long }
procedure stub_AES_bi_ige_encrypt(_in: PChar; _out: PChar; length: TIdC_SSIZET;
  key: PAES_KEY; key2: PAES_KEY; ivec: PChar; enc: PIdC_INT)cdecl;
begin
  AES_bi_ige_encrypt := CryptoFixupStub('AES_bi_ige_encrypt');   {Do not Localize}
  AES_bi_ige_encrypt(_in, _out, length, key, key2, ivec, enc);
end;

function stub_AES_wrap_key(key: PAES_KEY; iv: PChar; _out: PChar; _in: PChar;
  inlen: TIdC_UINT): PIdC_INT cdecl;
begin
  AES_wrap_key := CryptoFixupStub('AES_wrap_key');   {Do not Localize}
  Result := stub_AES_wrap_key(key, iv, _in, _out, inlen);
end;

function stub_AES_unwrap_key(key: PAES_KEY; iv: PChar; _out: PChar; _in: PChar;
  inlen: TIdC_UINT): PIdC_INT cdecl;
begin
  AES_unwrap_key := CryptoFixupStub('AES_unwrap_key');   {Do not Localize}
  Result := AES_unwrap_key(key, iv, _out, _in, inlen);
end;

procedure InitStubs;
begin
  AES_options := @stub_AES_options;
  AES_set_encrypt_key := @stub_AES_set_encrypt_key;
  AES_set_decrypt_key := @stub_AES_set_decrypt_key;
  AES_encrypt := @stub_AES_encrypt;
  _AES_decrypt := @stub_AES_decrypt;
  AES_ecb_encrypt := @stub_AES_ecb_encrypt;
  AES_cbc_encrypt := @stub_AES_cbc_encrypt;
  AES_cfb1_encrypt := @stub_AES_cfb1_encrypt;
  AES_cfb8_encrypt := @stub_AES_cfb8_encrypt;
  AES_ofb128_encrypt := @stub_AES_ofb128_encrypt;
  AES_ige_encrypt := @stub_AES_ige_encrypt;
  AES_bi_ige_encrypt := @stub_AES_bi_ige_encrypt;
  AES_wrap_key := @stub_AES_wrap_key;
  AES_unwrap_key := @stub_AES_unwrap_key;
end;

initialization

InitStubs;

end.
