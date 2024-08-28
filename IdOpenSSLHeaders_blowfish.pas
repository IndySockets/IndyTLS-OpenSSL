  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_blowfish.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_blowfish.h2pas
     and this file regenerated. IdOpenSSLHeaders_blowfish.h2pas is distributed with the full Indy
     Distribution.
   *)
   
{$i IdCompilerDefines.inc} 
{$i IdSSLOpenSSLDefines.inc} 
{$IFNDEF USE_OPENSSL}
  { error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}
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

unit IdOpenSSLHeaders_blowfish;

interface

// Headers for OpenSSL 1.1.1
// blowfish.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
  // Added '_CONST' to avoid name clashes
  BF_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  BF_DECRYPT_CONST = 0;

  BF_ROUNDS = 16;
  BF_BLOCK  = 8;

type
  BF_LONG = TIdC_UINT;
  PBF_LONG = ^BF_LONG;

  bf_key_st = record
    p: array[0 .. BF_ROUNDS + 2 - 1] of BF_LONG;
    s: array[0 .. 4 * 256 - 1] of BF_LONG;
  end;
  BF_KEY = bf_key_st;
  PBF_KEY = ^BF_KEY;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM BF_set_key}
  {$EXTERNALSYM BF_encrypt}
  {$EXTERNALSYM BF_decrypt}
  {$EXTERNALSYM BF_ecb_encrypt}
  {$EXTERNALSYM BF_cbc_encrypt}
  {$EXTERNALSYM BF_cfb64_encrypt}
  {$EXTERNALSYM BF_ofb64_encrypt}
  {$EXTERNALSYM BF_options}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  BF_set_key: procedure (key: PBF_KEY; len: TIdC_INT; const data: PByte); cdecl = nil;

  BF_encrypt: procedure (data: PBF_LONG; const key: PBF_KEY); cdecl = nil;
  BF_decrypt: procedure (data: PBF_LONG; const key: PBF_KEY); cdecl = nil;

  BF_ecb_encrypt: procedure (const in_: PByte; out_: PByte; key: PBF_KEY; enc: TIdC_INT); cdecl = nil;
  BF_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; enc: TIdC_INT); cdecl = nil;
  BF_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; num: PIdC_INT; enc: TIdC_INT); cdecl = nil;
  BF_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; num: PIdC_INT); cdecl = nil;

  BF_options: function : PIdAnsiChar; cdecl = nil;

{$ELSE}
  procedure BF_set_key(key: PBF_KEY; len: TIdC_INT; const data: PByte) cdecl; external CLibCrypto;

  procedure BF_encrypt(data: PBF_LONG; const key: PBF_KEY) cdecl; external CLibCrypto;
  procedure BF_decrypt(data: PBF_LONG; const key: PBF_KEY) cdecl; external CLibCrypto;

  procedure BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; num: PIdC_INT; enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; num: PIdC_INT) cdecl; external CLibCrypto;

  function BF_options: PIdAnsiChar cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  BF_set_key_procname = 'BF_set_key';

  BF_encrypt_procname = 'BF_encrypt';
  BF_decrypt_procname = 'BF_decrypt';

  BF_ecb_encrypt_procname = 'BF_ecb_encrypt';
  BF_cbc_encrypt_procname = 'BF_cbc_encrypt';
  BF_cfb64_encrypt_procname = 'BF_cfb64_encrypt';
  BF_ofb64_encrypt_procname = 'BF_ofb64_encrypt';

  BF_options_procname = 'BF_options';


{$WARN  NO_RETVAL OFF}
procedure  ERR_BF_set_key(key: PBF_KEY; len: TIdC_INT; const data: PByte); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_set_key_procname);
end;



procedure  ERR_BF_encrypt(data: PBF_LONG; const key: PBF_KEY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_encrypt_procname);
end;


procedure  ERR_BF_decrypt(data: PBF_LONG; const key: PBF_KEY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_decrypt_procname);
end;



procedure  ERR_BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_ecb_encrypt_procname);
end;


procedure  ERR_BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_cbc_encrypt_procname);
end;


procedure  ERR_BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; num: PIdC_INT; enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_cfb64_encrypt_procname);
end;


procedure  ERR_BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TIdC_LONG; schedule: PBF_KEY; ivec: PByte; num: PIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_ofb64_encrypt_procname);
end;



function  ERR_BF_options: PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BF_options_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  BF_set_key := LoadLibFunction(ADllHandle, BF_set_key_procname);
  FuncLoadError := not assigned(BF_set_key);
  if FuncLoadError then
  begin
    {$if not defined(BF_set_key_allownil)}
    BF_set_key := @ERR_BF_set_key;
    {$ifend}
    {$if declared(BF_set_key_introduced)}
    if LibVersion < BF_set_key_introduced then
    begin
      {$if declared(FC_BF_set_key)}
      BF_set_key := @FC_BF_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_set_key_removed)}
    if BF_set_key_removed <= LibVersion then
    begin
      {$if declared(_BF_set_key)}
      BF_set_key := @_BF_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_set_key');
    {$ifend}
  end;


  BF_encrypt := LoadLibFunction(ADllHandle, BF_encrypt_procname);
  FuncLoadError := not assigned(BF_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_encrypt_allownil)}
    BF_encrypt := @ERR_BF_encrypt;
    {$ifend}
    {$if declared(BF_encrypt_introduced)}
    if LibVersion < BF_encrypt_introduced then
    begin
      {$if declared(FC_BF_encrypt)}
      BF_encrypt := @FC_BF_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_encrypt_removed)}
    if BF_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_encrypt)}
      BF_encrypt := @_BF_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_encrypt');
    {$ifend}
  end;


  BF_decrypt := LoadLibFunction(ADllHandle, BF_decrypt_procname);
  FuncLoadError := not assigned(BF_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_decrypt_allownil)}
    BF_decrypt := @ERR_BF_decrypt;
    {$ifend}
    {$if declared(BF_decrypt_introduced)}
    if LibVersion < BF_decrypt_introduced then
    begin
      {$if declared(FC_BF_decrypt)}
      BF_decrypt := @FC_BF_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_decrypt_removed)}
    if BF_decrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_decrypt)}
      BF_decrypt := @_BF_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_decrypt');
    {$ifend}
  end;


  BF_ecb_encrypt := LoadLibFunction(ADllHandle, BF_ecb_encrypt_procname);
  FuncLoadError := not assigned(BF_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_ecb_encrypt_allownil)}
    BF_ecb_encrypt := @ERR_BF_ecb_encrypt;
    {$ifend}
    {$if declared(BF_ecb_encrypt_introduced)}
    if LibVersion < BF_ecb_encrypt_introduced then
    begin
      {$if declared(FC_BF_ecb_encrypt)}
      BF_ecb_encrypt := @FC_BF_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_ecb_encrypt_removed)}
    if BF_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_ecb_encrypt)}
      BF_ecb_encrypt := @_BF_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_ecb_encrypt');
    {$ifend}
  end;


  BF_cbc_encrypt := LoadLibFunction(ADllHandle, BF_cbc_encrypt_procname);
  FuncLoadError := not assigned(BF_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_cbc_encrypt_allownil)}
    BF_cbc_encrypt := @ERR_BF_cbc_encrypt;
    {$ifend}
    {$if declared(BF_cbc_encrypt_introduced)}
    if LibVersion < BF_cbc_encrypt_introduced then
    begin
      {$if declared(FC_BF_cbc_encrypt)}
      BF_cbc_encrypt := @FC_BF_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_cbc_encrypt_removed)}
    if BF_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_cbc_encrypt)}
      BF_cbc_encrypt := @_BF_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_cbc_encrypt');
    {$ifend}
  end;


  BF_cfb64_encrypt := LoadLibFunction(ADllHandle, BF_cfb64_encrypt_procname);
  FuncLoadError := not assigned(BF_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_cfb64_encrypt_allownil)}
    BF_cfb64_encrypt := @ERR_BF_cfb64_encrypt;
    {$ifend}
    {$if declared(BF_cfb64_encrypt_introduced)}
    if LibVersion < BF_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_BF_cfb64_encrypt)}
      BF_cfb64_encrypt := @FC_BF_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_cfb64_encrypt_removed)}
    if BF_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_cfb64_encrypt)}
      BF_cfb64_encrypt := @_BF_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_cfb64_encrypt');
    {$ifend}
  end;


  BF_ofb64_encrypt := LoadLibFunction(ADllHandle, BF_ofb64_encrypt_procname);
  FuncLoadError := not assigned(BF_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_ofb64_encrypt_allownil)}
    BF_ofb64_encrypt := @ERR_BF_ofb64_encrypt;
    {$ifend}
    {$if declared(BF_ofb64_encrypt_introduced)}
    if LibVersion < BF_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_BF_ofb64_encrypt)}
      BF_ofb64_encrypt := @FC_BF_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_ofb64_encrypt_removed)}
    if BF_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_ofb64_encrypt)}
      BF_ofb64_encrypt := @_BF_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_ofb64_encrypt');
    {$ifend}
  end;


  BF_options := LoadLibFunction(ADllHandle, BF_options_procname);
  FuncLoadError := not assigned(BF_options);
  if FuncLoadError then
  begin
    {$if not defined(BF_options_allownil)}
    BF_options := @ERR_BF_options;
    {$ifend}
    {$if declared(BF_options_introduced)}
    if LibVersion < BF_options_introduced then
    begin
      {$if declared(FC_BF_options)}
      BF_options := @FC_BF_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_options_removed)}
    if BF_options_removed <= LibVersion then
    begin
      {$if declared(_BF_options)}
      BF_options := @_BF_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_options_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_options');
    {$ifend}
  end;


end;

procedure Unload;
begin
  BF_set_key := nil;
  BF_encrypt := nil;
  BF_decrypt := nil;
  BF_ecb_encrypt := nil;
  BF_cbc_encrypt := nil;
  BF_cfb64_encrypt := nil;
  BF_ofb64_encrypt := nil;
  BF_options := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
