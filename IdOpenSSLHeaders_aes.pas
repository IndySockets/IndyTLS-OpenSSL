﻿  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_aes.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_aes.h2pas
     and this file regenerated. IdOpenSSLHeaders_aes.h2pas is distributed with the full Indy
     Distribution.
   *)
   
{$i IdCompilerDefines.inc} 
{$i IdSSLOpenSSLDefines.inc} 

{******************************************************************************}
{                                                                              }
{            Indy (Internet Direct) - Internet Protocols Simplified            }
{                                                                              }
{            https://www.indyproject.org/                                      }
{            https://gitter.im/IndySockets/Indy                                }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  This file is part of the Indy (Internet Direct) project, and is offered     }
{  under the dual-licensing agreement described on the Indy website.           }
{  (https://www.indyproject.org/license/)                                      }
{                                                                              }
{  Copyright:                                                                  }
{   (c) 1993-2020, Chad Z. Hower and the Indy Pit Crew. All rights reserved.   }
{                                                                              }
{******************************************************************************}
{                                                                              }
{                                                                              }
{******************************************************************************}

unit IdOpenSSLHeaders_aes;

interface

// Headers for OpenSSL 1.1.1
// aes.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
// Added '_CONST' to avoid name clashes
  AES_ENCRYPT_CONST = 1;
// Added '_CONST' to avoid name clashes
  AES_DECRYPT_CONST = 0;
  AES_MAXNR = 14;
  AES_BLOCK_SIZE = 16;

type
  aes_key_st = record
  // in old IdSSLOpenSSLHeaders.pas it was also TIdC_UINT ¯\_(ツ)_/¯
//    {$IFDEF AES_LONG}
//    rd_key: array[0..(4 * (AES_MAXNR + 1))] of TIdC_ULONG;
//    {$ELSE}
    rd_key: array[0..(4 * (AES_MAXNR + 1))] of TIdC_UINT;
//    {$ENDIF}
    rounds: TIdC_INT;
  end;
  AES_KEY = aes_key_st;
  PAES_KEY = ^AES_KEY;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM AES_options}
  {$EXTERNALSYM AES_set_encrypt_key}
  {$EXTERNALSYM AES_set_decrypt_key}
  {$EXTERNALSYM AES_encrypt}
  {$EXTERNALSYM AES_decrypt}
  {$EXTERNALSYM AES_ecb_encrypt}
  {$EXTERNALSYM AES_cbc_encrypt}
  {$EXTERNALSYM AES_cfb128_encrypt}
  {$EXTERNALSYM AES_cfb1_encrypt}
  {$EXTERNALSYM AES_cfb8_encrypt}
  {$EXTERNALSYM AES_ofb128_encrypt}
  {$EXTERNALSYM AES_ige_encrypt}
  {$EXTERNALSYM AES_bi_ige_encrypt}
  {$EXTERNALSYM AES_wrap_key}
  {$EXTERNALSYM AES_unwrap_key}

{$IFNDEF USE_EXTERNAL_LIBRARY}
var
  AES_options: function : PIdAnsiChar; cdecl = nil;

  AES_set_encrypt_key: function (const userKey: PByte; const bits: TIdC_INT; const key: PAES_KEY): TIdC_INT; cdecl = nil;
  AES_set_decrypt_key: function (const userKey: PByte; const bits: TIdC_INT; const key: PAES_KEY): TIdC_INT; cdecl = nil;

  AES_encrypt: procedure (const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl = nil;
  AES_decrypt: procedure (const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl = nil;

  AES_ecb_encrypt: procedure (const in_: PByte; out_: PByte; const key: PAES_KEY; const enc: TIdC_INT); cdecl = nil;
  AES_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TIdC_INT); cdecl = nil;
  AES_cfb128_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); cdecl = nil;
  AES_cfb1_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); cdecl = nil;
  AES_cfb8_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); cdecl = nil;
  AES_ofb128_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT); cdecl = nil;
  (* NB: the IV is _two_ blocks long *)
  AES_ige_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TIdC_INT); cdecl = nil;
  (* NB: the IV is _four_ blocks long *)
  AES_bi_ige_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; const key2: PAES_KEY; ivec: PByte; const enc: TIdC_INT); cdecl = nil;

  AES_wrap_key: function (key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TIdC_UINT): TIdC_INT; cdecl = nil;
  AES_unwrap_key: function (key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TIdC_UINT): TIdC_INT; cdecl = nil;

{$ELSE}
  function AES_options: PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function AES_set_encrypt_key(const userKey: PByte; const bits: TIdC_INT; const key: PAES_KEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function AES_set_decrypt_key(const userKey: PByte; const bits: TIdC_INT; const key: PAES_KEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure AES_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure AES_decrypt(const in_: PByte; out_: PByte; const key: PAES_KEY) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure AES_ecb_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure AES_cbc_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure AES_cfb128_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure AES_cfb1_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure AES_cfb8_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure AES_ofb128_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* NB: the IV is _two_ blocks long *)
  procedure AES_ige_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* NB: the IV is _four_ blocks long *)
  procedure AES_bi_ige_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; const key2: PAES_KEY; ivec: PByte; const enc: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function AES_wrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TIdC_UINT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function AES_unwrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TIdC_UINT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF USE_EXTERNAL_LIBRARY}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  

{$IFNDEF USE_EXTERNAL_LIBRARY}
const
  AES_options_procname = 'AES_options';

  AES_set_encrypt_key_procname = 'AES_set_encrypt_key';
  AES_set_decrypt_key_procname = 'AES_set_decrypt_key';

  AES_encrypt_procname = 'AES_encrypt';
  AES_decrypt_procname = 'AES_decrypt';

  AES_ecb_encrypt_procname = 'AES_ecb_encrypt';
  AES_cbc_encrypt_procname = 'AES_cbc_encrypt';
  AES_cfb128_encrypt_procname = 'AES_cfb128_encrypt';
  AES_cfb1_encrypt_procname = 'AES_cfb1_encrypt';
  AES_cfb8_encrypt_procname = 'AES_cfb8_encrypt';
  AES_ofb128_encrypt_procname = 'AES_ofb128_encrypt';
  (* NB: the IV is _two_ blocks long *)
  AES_ige_encrypt_procname = 'AES_ige_encrypt';
  (* NB: the IV is _four_ blocks long *)
  AES_bi_ige_encrypt_procname = 'AES_bi_ige_encrypt';

  AES_wrap_key_procname = 'AES_wrap_key';
  AES_unwrap_key_procname = 'AES_unwrap_key';


{$WARN  NO_RETVAL OFF}
function  ERR_AES_options: PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_options_procname);
end;



function  ERR_AES_set_encrypt_key(const userKey: PByte; const bits: TIdC_INT; const key: PAES_KEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_set_encrypt_key_procname);
end;


function  ERR_AES_set_decrypt_key(const userKey: PByte; const bits: TIdC_INT; const key: PAES_KEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_set_decrypt_key_procname);
end;



procedure  ERR_AES_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_encrypt_procname);
end;


procedure  ERR_AES_decrypt(const in_: PByte; out_: PByte; const key: PAES_KEY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_decrypt_procname);
end;



procedure  ERR_AES_ecb_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_ecb_encrypt_procname);
end;


procedure  ERR_AES_cbc_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_cbc_encrypt_procname);
end;


procedure  ERR_AES_cfb128_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_cfb128_encrypt_procname);
end;


procedure  ERR_AES_cfb1_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_cfb1_encrypt_procname);
end;


procedure  ERR_AES_cfb8_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_cfb8_encrypt_procname);
end;


procedure  ERR_AES_ofb128_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; num: PIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_ofb128_encrypt_procname);
end;


  (* NB: the IV is _two_ blocks long *)
procedure  ERR_AES_ige_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_ige_encrypt_procname);
end;


  (* NB: the IV is _four_ blocks long *)
procedure  ERR_AES_bi_ige_encrypt(const in_: PByte; out_: PByte; length: TIdC_SIZET; const key: PAES_KEY; const key2: PAES_KEY; ivec: PByte; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_bi_ige_encrypt_procname);
end;



function  ERR_AES_wrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_wrap_key_procname);
end;


function  ERR_AES_unwrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(AES_unwrap_key_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  AES_options := LoadLibFunction(ADllHandle, AES_options_procname);
  FuncLoadError := not assigned(AES_options);
  if FuncLoadError then
  begin
    {$if not defined(AES_options_allownil)}
    AES_options := @ERR_AES_options;
    {$ifend}
    {$if declared(AES_options_introduced)}
    if LibVersion < AES_options_introduced then
    begin
      {$if declared(FC_AES_options)}
      AES_options := @FC_AES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_options_removed)}
    if AES_options_removed <= LibVersion then
    begin
      {$if declared(_AES_options)}
      AES_options := @_AES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_options_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_options');
    {$ifend}
  end;


  AES_set_encrypt_key := LoadLibFunction(ADllHandle, AES_set_encrypt_key_procname);
  FuncLoadError := not assigned(AES_set_encrypt_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_set_encrypt_key_allownil)}
    AES_set_encrypt_key := @ERR_AES_set_encrypt_key;
    {$ifend}
    {$if declared(AES_set_encrypt_key_introduced)}
    if LibVersion < AES_set_encrypt_key_introduced then
    begin
      {$if declared(FC_AES_set_encrypt_key)}
      AES_set_encrypt_key := @FC_AES_set_encrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_set_encrypt_key_removed)}
    if AES_set_encrypt_key_removed <= LibVersion then
    begin
      {$if declared(_AES_set_encrypt_key)}
      AES_set_encrypt_key := @_AES_set_encrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_set_encrypt_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_set_encrypt_key');
    {$ifend}
  end;


  AES_set_decrypt_key := LoadLibFunction(ADllHandle, AES_set_decrypt_key_procname);
  FuncLoadError := not assigned(AES_set_decrypt_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_set_decrypt_key_allownil)}
    AES_set_decrypt_key := @ERR_AES_set_decrypt_key;
    {$ifend}
    {$if declared(AES_set_decrypt_key_introduced)}
    if LibVersion < AES_set_decrypt_key_introduced then
    begin
      {$if declared(FC_AES_set_decrypt_key)}
      AES_set_decrypt_key := @FC_AES_set_decrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_set_decrypt_key_removed)}
    if AES_set_decrypt_key_removed <= LibVersion then
    begin
      {$if declared(_AES_set_decrypt_key)}
      AES_set_decrypt_key := @_AES_set_decrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_set_decrypt_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_set_decrypt_key');
    {$ifend}
  end;


  AES_encrypt := LoadLibFunction(ADllHandle, AES_encrypt_procname);
  FuncLoadError := not assigned(AES_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_encrypt_allownil)}
    AES_encrypt := @ERR_AES_encrypt;
    {$ifend}
    {$if declared(AES_encrypt_introduced)}
    if LibVersion < AES_encrypt_introduced then
    begin
      {$if declared(FC_AES_encrypt)}
      AES_encrypt := @FC_AES_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_encrypt_removed)}
    if AES_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_encrypt)}
      AES_encrypt := @_AES_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_encrypt');
    {$ifend}
  end;


  AES_decrypt := LoadLibFunction(ADllHandle, AES_decrypt_procname);
  FuncLoadError := not assigned(AES_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_decrypt_allownil)}
    AES_decrypt := @ERR_AES_decrypt;
    {$ifend}
    {$if declared(AES_decrypt_introduced)}
    if LibVersion < AES_decrypt_introduced then
    begin
      {$if declared(FC_AES_decrypt)}
      AES_decrypt := @FC_AES_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_decrypt_removed)}
    if AES_decrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_decrypt)}
      AES_decrypt := @_AES_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_decrypt');
    {$ifend}
  end;


  AES_ecb_encrypt := LoadLibFunction(ADllHandle, AES_ecb_encrypt_procname);
  FuncLoadError := not assigned(AES_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_ecb_encrypt_allownil)}
    AES_ecb_encrypt := @ERR_AES_ecb_encrypt;
    {$ifend}
    {$if declared(AES_ecb_encrypt_introduced)}
    if LibVersion < AES_ecb_encrypt_introduced then
    begin
      {$if declared(FC_AES_ecb_encrypt)}
      AES_ecb_encrypt := @FC_AES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_ecb_encrypt_removed)}
    if AES_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_ecb_encrypt)}
      AES_ecb_encrypt := @_AES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_ecb_encrypt');
    {$ifend}
  end;


  AES_cbc_encrypt := LoadLibFunction(ADllHandle, AES_cbc_encrypt_procname);
  FuncLoadError := not assigned(AES_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cbc_encrypt_allownil)}
    AES_cbc_encrypt := @ERR_AES_cbc_encrypt;
    {$ifend}
    {$if declared(AES_cbc_encrypt_introduced)}
    if LibVersion < AES_cbc_encrypt_introduced then
    begin
      {$if declared(FC_AES_cbc_encrypt)}
      AES_cbc_encrypt := @FC_AES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cbc_encrypt_removed)}
    if AES_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cbc_encrypt)}
      AES_cbc_encrypt := @_AES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cbc_encrypt');
    {$ifend}
  end;


  AES_cfb128_encrypt := LoadLibFunction(ADllHandle, AES_cfb128_encrypt_procname);
  FuncLoadError := not assigned(AES_cfb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cfb128_encrypt_allownil)}
    AES_cfb128_encrypt := @ERR_AES_cfb128_encrypt;
    {$ifend}
    {$if declared(AES_cfb128_encrypt_introduced)}
    if LibVersion < AES_cfb128_encrypt_introduced then
    begin
      {$if declared(FC_AES_cfb128_encrypt)}
      AES_cfb128_encrypt := @FC_AES_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cfb128_encrypt_removed)}
    if AES_cfb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cfb128_encrypt)}
      AES_cfb128_encrypt := @_AES_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cfb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cfb128_encrypt');
    {$ifend}
  end;


  AES_cfb1_encrypt := LoadLibFunction(ADllHandle, AES_cfb1_encrypt_procname);
  FuncLoadError := not assigned(AES_cfb1_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cfb1_encrypt_allownil)}
    AES_cfb1_encrypt := @ERR_AES_cfb1_encrypt;
    {$ifend}
    {$if declared(AES_cfb1_encrypt_introduced)}
    if LibVersion < AES_cfb1_encrypt_introduced then
    begin
      {$if declared(FC_AES_cfb1_encrypt)}
      AES_cfb1_encrypt := @FC_AES_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cfb1_encrypt_removed)}
    if AES_cfb1_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cfb1_encrypt)}
      AES_cfb1_encrypt := @_AES_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cfb1_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cfb1_encrypt');
    {$ifend}
  end;


  AES_cfb8_encrypt := LoadLibFunction(ADllHandle, AES_cfb8_encrypt_procname);
  FuncLoadError := not assigned(AES_cfb8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cfb8_encrypt_allownil)}
    AES_cfb8_encrypt := @ERR_AES_cfb8_encrypt;
    {$ifend}
    {$if declared(AES_cfb8_encrypt_introduced)}
    if LibVersion < AES_cfb8_encrypt_introduced then
    begin
      {$if declared(FC_AES_cfb8_encrypt)}
      AES_cfb8_encrypt := @FC_AES_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cfb8_encrypt_removed)}
    if AES_cfb8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cfb8_encrypt)}
      AES_cfb8_encrypt := @_AES_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cfb8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cfb8_encrypt');
    {$ifend}
  end;


  AES_ofb128_encrypt := LoadLibFunction(ADllHandle, AES_ofb128_encrypt_procname);
  FuncLoadError := not assigned(AES_ofb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_ofb128_encrypt_allownil)}
    AES_ofb128_encrypt := @ERR_AES_ofb128_encrypt;
    {$ifend}
    {$if declared(AES_ofb128_encrypt_introduced)}
    if LibVersion < AES_ofb128_encrypt_introduced then
    begin
      {$if declared(FC_AES_ofb128_encrypt)}
      AES_ofb128_encrypt := @FC_AES_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_ofb128_encrypt_removed)}
    if AES_ofb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_ofb128_encrypt)}
      AES_ofb128_encrypt := @_AES_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_ofb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_ofb128_encrypt');
    {$ifend}
  end;


  AES_ige_encrypt := LoadLibFunction(ADllHandle, AES_ige_encrypt_procname);
  FuncLoadError := not assigned(AES_ige_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_ige_encrypt_allownil)}
    AES_ige_encrypt := @ERR_AES_ige_encrypt;
    {$ifend}
    {$if declared(AES_ige_encrypt_introduced)}
    if LibVersion < AES_ige_encrypt_introduced then
    begin
      {$if declared(FC_AES_ige_encrypt)}
      AES_ige_encrypt := @FC_AES_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_ige_encrypt_removed)}
    if AES_ige_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_ige_encrypt)}
      AES_ige_encrypt := @_AES_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_ige_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_ige_encrypt');
    {$ifend}
  end;


  AES_bi_ige_encrypt := LoadLibFunction(ADllHandle, AES_bi_ige_encrypt_procname);
  FuncLoadError := not assigned(AES_bi_ige_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_bi_ige_encrypt_allownil)}
    AES_bi_ige_encrypt := @ERR_AES_bi_ige_encrypt;
    {$ifend}
    {$if declared(AES_bi_ige_encrypt_introduced)}
    if LibVersion < AES_bi_ige_encrypt_introduced then
    begin
      {$if declared(FC_AES_bi_ige_encrypt)}
      AES_bi_ige_encrypt := @FC_AES_bi_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_bi_ige_encrypt_removed)}
    if AES_bi_ige_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_bi_ige_encrypt)}
      AES_bi_ige_encrypt := @_AES_bi_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_bi_ige_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_bi_ige_encrypt');
    {$ifend}
  end;


  AES_wrap_key := LoadLibFunction(ADllHandle, AES_wrap_key_procname);
  FuncLoadError := not assigned(AES_wrap_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_wrap_key_allownil)}
    AES_wrap_key := @ERR_AES_wrap_key;
    {$ifend}
    {$if declared(AES_wrap_key_introduced)}
    if LibVersion < AES_wrap_key_introduced then
    begin
      {$if declared(FC_AES_wrap_key)}
      AES_wrap_key := @FC_AES_wrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_wrap_key_removed)}
    if AES_wrap_key_removed <= LibVersion then
    begin
      {$if declared(_AES_wrap_key)}
      AES_wrap_key := @_AES_wrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_wrap_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_wrap_key');
    {$ifend}
  end;


  AES_unwrap_key := LoadLibFunction(ADllHandle, AES_unwrap_key_procname);
  FuncLoadError := not assigned(AES_unwrap_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_unwrap_key_allownil)}
    AES_unwrap_key := @ERR_AES_unwrap_key;
    {$ifend}
    {$if declared(AES_unwrap_key_introduced)}
    if LibVersion < AES_unwrap_key_introduced then
    begin
      {$if declared(FC_AES_unwrap_key)}
      AES_unwrap_key := @FC_AES_unwrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_unwrap_key_removed)}
    if AES_unwrap_key_removed <= LibVersion then
    begin
      {$if declared(_AES_unwrap_key)}
      AES_unwrap_key := @_AES_unwrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_unwrap_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_unwrap_key');
    {$ifend}
  end;


end;

procedure Unload;
begin
  AES_options := nil;
  AES_set_encrypt_key := nil;
  AES_set_decrypt_key := nil;
  AES_encrypt := nil;
  AES_decrypt := nil;
  AES_ecb_encrypt := nil;
  AES_cbc_encrypt := nil;
  AES_cfb128_encrypt := nil;
  AES_cfb1_encrypt := nil;
  AES_cfb8_encrypt := nil;
  AES_ofb128_encrypt := nil;
  AES_ige_encrypt := nil;
  AES_bi_ige_encrypt := nil;
  AES_wrap_key := nil;
  AES_unwrap_key := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF USE_EXTERNAL_LIBRARY}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
