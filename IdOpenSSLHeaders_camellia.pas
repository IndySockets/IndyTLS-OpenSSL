  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_camellia.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_camellia.h2pas
     and this file regenerated. IdOpenSSLHeaders_camellia.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_camellia;

interface

// Headers for OpenSSL 1.1.1
// camellia.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
  // Added '_CONST' to avoid name clashes
  CAMELLIA_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  CAMELLIA_DECRYPT_CONST = 0;

  CAMELLIA_BLOCK_SIZE = 16;
  CAMELLIA_TABLE_BYTE_LEN = 272;
  CAMELLIA_TABLE_WORD_LEN = CAMELLIA_TABLE_BYTE_LEN div 4;

type
  KEY_TABLE_TYPE = array[0 .. CAMELLIA_TABLE_WORD_LEN - 1] of TIdC_UINT;

  camellia_key_st_u = record
    case Integer of
    0: (d: TIdC_DOUBLE);
    1: (rd_key: KEY_TABLE_TYPE);
  end;

  camellia_key_st = record
    u: camellia_key_st_u;
    grand_rounds: TIdC_INT;
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  Camellia_set_key: function (const userKey: PByte; const bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT; cdecl = nil;

  Camellia_encrypt: procedure (const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl = nil;
  Camellia_decrypt: procedure (const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); cdecl = nil;

  Camellia_ecb_encrypt: procedure ( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TIdC_INT); cdecl = nil;
  Camellia_cbc_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TIdC_INT); cdecl = nil;
  Camellia_cfb128_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); cdecl = nil;
  Camellia_cfb1_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); cdecl = nil;
  Camellia_cfb8_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); cdecl = nil;
  Camellia_ofb128_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT); cdecl = nil;
  Camellia_ctr128_encrypt: procedure ( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: PIdC_INT); cdecl = nil;

{$ELSE}
  function Camellia_set_key(const userKey: PByte; const bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT cdecl; external CLibCrypto;

  procedure Camellia_encrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY) cdecl; external CLibCrypto;
  procedure Camellia_decrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY) cdecl; external CLibCrypto;

  procedure Camellia_ecb_encrypt( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure Camellia_cbc_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure Camellia_cfb128_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure Camellia_cfb1_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure Camellia_cfb8_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT) cdecl; external CLibCrypto;
  procedure Camellia_ofb128_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT) cdecl; external CLibCrypto;
  procedure Camellia_ctr128_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: PIdC_INT) cdecl; external CLibCrypto;

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
  Camellia_set_key_procname = 'Camellia_set_key';

  Camellia_encrypt_procname = 'Camellia_encrypt';
  Camellia_decrypt_procname = 'Camellia_decrypt';

  Camellia_ecb_encrypt_procname = 'Camellia_ecb_encrypt';
  Camellia_cbc_encrypt_procname = 'Camellia_cbc_encrypt';
  Camellia_cfb128_encrypt_procname = 'Camellia_cfb128_encrypt';
  Camellia_cfb1_encrypt_procname = 'Camellia_cfb1_encrypt';
  Camellia_cfb8_encrypt_procname = 'Camellia_cfb8_encrypt';
  Camellia_ofb128_encrypt_procname = 'Camellia_ofb128_encrypt';
  Camellia_ctr128_encrypt_procname = 'Camellia_ctr128_encrypt';


{$WARN  NO_RETVAL OFF}
function  ERR_Camellia_set_key(const userKey: PByte; const bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_set_key_procname);
end;



procedure  ERR_Camellia_encrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_encrypt_procname);
end;


procedure  ERR_Camellia_decrypt(const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_decrypt_procname);
end;



procedure  ERR_Camellia_ecb_encrypt( const in_: PByte; const out_: PByte; const key: PCAMELLIA_KEY; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_ecb_encrypt_procname);
end;


procedure  ERR_Camellia_cbc_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_cbc_encrypt_procname);
end;


procedure  ERR_Camellia_cfb128_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_cfb128_encrypt_procname);
end;


procedure  ERR_Camellia_cfb1_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_cfb1_encrypt_procname);
end;


procedure  ERR_Camellia_cfb8_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT; const enc: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_cfb8_encrypt_procname);
end;


procedure  ERR_Camellia_ofb128_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: PByte; num: PIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_ofb128_encrypt_procname);
end;


procedure  ERR_Camellia_ctr128_encrypt( const in_: PByte; const out_: PByte; length: TIdC_SIZET; const key: PCAMELLIA_KEY; ivec: TCamellia_ctr128_encrypt_ivec; ecount_buf: TCamellia_ctr128_encrypt_ecount_buf; num: PIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(Camellia_ctr128_encrypt_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  Camellia_set_key := LoadLibFunction(ADllHandle, Camellia_set_key_procname);
  FuncLoadError := not assigned(Camellia_set_key);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_set_key_allownil)}
    Camellia_set_key := @ERR_Camellia_set_key;
    {$ifend}
    {$if declared(Camellia_set_key_introduced)}
    if LibVersion < Camellia_set_key_introduced then
    begin
      {$if declared(FC_Camellia_set_key)}
      Camellia_set_key := @FC_Camellia_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_set_key_removed)}
    if Camellia_set_key_removed <= LibVersion then
    begin
      {$if declared(_Camellia_set_key)}
      Camellia_set_key := @_Camellia_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_set_key');
    {$ifend}
  end;


  Camellia_encrypt := LoadLibFunction(ADllHandle, Camellia_encrypt_procname);
  FuncLoadError := not assigned(Camellia_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_encrypt_allownil)}
    Camellia_encrypt := @ERR_Camellia_encrypt;
    {$ifend}
    {$if declared(Camellia_encrypt_introduced)}
    if LibVersion < Camellia_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_encrypt)}
      Camellia_encrypt := @FC_Camellia_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_encrypt_removed)}
    if Camellia_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_encrypt)}
      Camellia_encrypt := @_Camellia_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_encrypt');
    {$ifend}
  end;


  Camellia_decrypt := LoadLibFunction(ADllHandle, Camellia_decrypt_procname);
  FuncLoadError := not assigned(Camellia_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_decrypt_allownil)}
    Camellia_decrypt := @ERR_Camellia_decrypt;
    {$ifend}
    {$if declared(Camellia_decrypt_introduced)}
    if LibVersion < Camellia_decrypt_introduced then
    begin
      {$if declared(FC_Camellia_decrypt)}
      Camellia_decrypt := @FC_Camellia_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_decrypt_removed)}
    if Camellia_decrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_decrypt)}
      Camellia_decrypt := @_Camellia_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_decrypt');
    {$ifend}
  end;


  Camellia_ecb_encrypt := LoadLibFunction(ADllHandle, Camellia_ecb_encrypt_procname);
  FuncLoadError := not assigned(Camellia_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_ecb_encrypt_allownil)}
    Camellia_ecb_encrypt := @ERR_Camellia_ecb_encrypt;
    {$ifend}
    {$if declared(Camellia_ecb_encrypt_introduced)}
    if LibVersion < Camellia_ecb_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_ecb_encrypt)}
      Camellia_ecb_encrypt := @FC_Camellia_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_ecb_encrypt_removed)}
    if Camellia_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_ecb_encrypt)}
      Camellia_ecb_encrypt := @_Camellia_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_ecb_encrypt');
    {$ifend}
  end;


  Camellia_cbc_encrypt := LoadLibFunction(ADllHandle, Camellia_cbc_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cbc_encrypt_allownil)}
    Camellia_cbc_encrypt := @ERR_Camellia_cbc_encrypt;
    {$ifend}
    {$if declared(Camellia_cbc_encrypt_introduced)}
    if LibVersion < Camellia_cbc_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cbc_encrypt)}
      Camellia_cbc_encrypt := @FC_Camellia_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cbc_encrypt_removed)}
    if Camellia_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cbc_encrypt)}
      Camellia_cbc_encrypt := @_Camellia_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cbc_encrypt');
    {$ifend}
  end;


  Camellia_cfb128_encrypt := LoadLibFunction(ADllHandle, Camellia_cfb128_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cfb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cfb128_encrypt_allownil)}
    Camellia_cfb128_encrypt := @ERR_Camellia_cfb128_encrypt;
    {$ifend}
    {$if declared(Camellia_cfb128_encrypt_introduced)}
    if LibVersion < Camellia_cfb128_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cfb128_encrypt)}
      Camellia_cfb128_encrypt := @FC_Camellia_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cfb128_encrypt_removed)}
    if Camellia_cfb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cfb128_encrypt)}
      Camellia_cfb128_encrypt := @_Camellia_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cfb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cfb128_encrypt');
    {$ifend}
  end;


  Camellia_cfb1_encrypt := LoadLibFunction(ADllHandle, Camellia_cfb1_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cfb1_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cfb1_encrypt_allownil)}
    Camellia_cfb1_encrypt := @ERR_Camellia_cfb1_encrypt;
    {$ifend}
    {$if declared(Camellia_cfb1_encrypt_introduced)}
    if LibVersion < Camellia_cfb1_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cfb1_encrypt)}
      Camellia_cfb1_encrypt := @FC_Camellia_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cfb1_encrypt_removed)}
    if Camellia_cfb1_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cfb1_encrypt)}
      Camellia_cfb1_encrypt := @_Camellia_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cfb1_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cfb1_encrypt');
    {$ifend}
  end;


  Camellia_cfb8_encrypt := LoadLibFunction(ADllHandle, Camellia_cfb8_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cfb8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cfb8_encrypt_allownil)}
    Camellia_cfb8_encrypt := @ERR_Camellia_cfb8_encrypt;
    {$ifend}
    {$if declared(Camellia_cfb8_encrypt_introduced)}
    if LibVersion < Camellia_cfb8_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cfb8_encrypt)}
      Camellia_cfb8_encrypt := @FC_Camellia_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cfb8_encrypt_removed)}
    if Camellia_cfb8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cfb8_encrypt)}
      Camellia_cfb8_encrypt := @_Camellia_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cfb8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cfb8_encrypt');
    {$ifend}
  end;


  Camellia_ofb128_encrypt := LoadLibFunction(ADllHandle, Camellia_ofb128_encrypt_procname);
  FuncLoadError := not assigned(Camellia_ofb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_ofb128_encrypt_allownil)}
    Camellia_ofb128_encrypt := @ERR_Camellia_ofb128_encrypt;
    {$ifend}
    {$if declared(Camellia_ofb128_encrypt_introduced)}
    if LibVersion < Camellia_ofb128_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_ofb128_encrypt)}
      Camellia_ofb128_encrypt := @FC_Camellia_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_ofb128_encrypt_removed)}
    if Camellia_ofb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_ofb128_encrypt)}
      Camellia_ofb128_encrypt := @_Camellia_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_ofb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_ofb128_encrypt');
    {$ifend}
  end;


  Camellia_ctr128_encrypt := LoadLibFunction(ADllHandle, Camellia_ctr128_encrypt_procname);
  FuncLoadError := not assigned(Camellia_ctr128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_ctr128_encrypt_allownil)}
    Camellia_ctr128_encrypt := @ERR_Camellia_ctr128_encrypt;
    {$ifend}
    {$if declared(Camellia_ctr128_encrypt_introduced)}
    if LibVersion < Camellia_ctr128_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_ctr128_encrypt)}
      Camellia_ctr128_encrypt := @FC_Camellia_ctr128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_ctr128_encrypt_removed)}
    if Camellia_ctr128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_ctr128_encrypt)}
      Camellia_ctr128_encrypt := @_Camellia_ctr128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_ctr128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_ctr128_encrypt');
    {$ifend}
  end;


end;

procedure Unload;
begin
  Camellia_set_key := nil;
  Camellia_encrypt := nil;
  Camellia_decrypt := nil;
  Camellia_ecb_encrypt := nil;
  Camellia_cbc_encrypt := nil;
  Camellia_cfb128_encrypt := nil;
  Camellia_cfb1_encrypt := nil;
  Camellia_cfb8_encrypt := nil;
  Camellia_ofb128_encrypt := nil;
  Camellia_ctr128_encrypt := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
