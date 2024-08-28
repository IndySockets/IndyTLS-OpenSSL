  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_sha.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_sha.h2pas
     and this file regenerated. IdOpenSSLHeaders_sha.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_sha;

interface

// Headers for OpenSSL 1.1.1
// sha.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
  SHA_LBLOCK = 16;
  SHA_CBLOCK = SHA_LBLOCK * 4;

  SHA_LAST_BLOCK = SHA_CBLOCK - 8;
  SHA_DIGEST_LENGTH = 20;

  SHA256_CBLOCK = SHA_LBLOCK * 4;

  SHA224_DIGEST_LENGTH = 28;
  SHA256_DIGEST_LENGTH = 32;
  SHA384_DIGEST_LENGTH = 48;
  SHA512_DIGEST_LENGTH = 64;

  SHA512_CBLOCK = SHA_LBLOCK * 8;

type
  SHA_LONG = TIdC_UINT;

  SHAstate_sf = record
    h0, h1, h2, h3, h4: SHA_LONG;
    Nl, Nh: SHA_LONG;
    data: array[0 .. SHA_LAST_BLOCK - 1] of SHA_LONG;
    num: TIdC_UINT;
  end;
  SHA_CTX = SHAstate_sf;
  PSHA_CTX = ^SHA_CTX;

  SHAstate256_sf = record
    h: array[0..7] of SHA_LONG;
    Nl, Nh: SHA_LONG;
    data: array[0 .. SHA_LAST_BLOCK - 1] of SHA_LONG;
    num, md_len: TIdC_UINT;
  end;
  SHA256_CTX = SHAstate256_sf;
  PSHA256_CTX = ^SHA256_CTX;

  SHA_LONG64 = TIdC_UINT64;

  SHA512state_st_u = record
    case Integer of
    0: (d: array[0 .. SHA_LBLOCK - 1] of SHA_LONG64);
    1: (p: array[0 .. SHA512_CBLOCK - 1] of Byte);
  end;

  SHA512state_st = record
    h: array[0..7] of SHA_LONG64;
    Nl, Nh: SHA_LONG64;
    u: SHA512state_st_u;
    num, md_len: TIdC_UINT;
  end;
  SHA512_CTX = SHA512state_st;
  PSHA512_CTX = ^SHA512_CTX;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM SHA1_Init}
  {$EXTERNALSYM SHA1_Update}
  {$EXTERNALSYM SHA1_Final}
  {$EXTERNALSYM SHA1}
  {$EXTERNALSYM SHA1_Transform}
  {$EXTERNALSYM SHA224_Init}
  {$EXTERNALSYM SHA224_Update}
  {$EXTERNALSYM SHA224_Final}
  {$EXTERNALSYM SHA224}
  {$EXTERNALSYM SHA256_Init}
  {$EXTERNALSYM SHA256_Update}
  {$EXTERNALSYM SHA256_Final}
  {$EXTERNALSYM SHA256}
  {$EXTERNALSYM SHA256_Transform}
  {$EXTERNALSYM SHA384_Init}
  {$EXTERNALSYM SHA384_Update}
  {$EXTERNALSYM SHA384_Final}
  {$EXTERNALSYM SHA384}
  {$EXTERNALSYM SHA512_Init}
  {$EXTERNALSYM SHA512_Update}
  {$EXTERNALSYM SHA512_Final}
  {$EXTERNALSYM SHA512}
  {$EXTERNALSYM SHA512_Transform}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  SHA1_Init: function (c: PSHA_CTX): TIdC_INT; cdecl = nil;
  SHA1_Update: function (c: PSHA_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  SHA1_Final: function (md: PByte; c: PSHA_CTX): TIdC_INT; cdecl = nil;
  SHA1: function (const d: PByte; n: TIdC_SIZET; md: PByte): PByte; cdecl = nil;
  SHA1_Transform: procedure (c: PSHA_CTX; const data: PByte); cdecl = nil;

  SHA224_Init: function (c: PSHA256_CTX): TIdC_INT; cdecl = nil;
  SHA224_Update: function (c: PSHA256_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  SHA224_Final: function (md: PByte; c: PSHA256_CTX): TIdC_INT; cdecl = nil;
  SHA224: function (const d: PByte; n: TIdC_SIZET; md: PByte): PByte; cdecl = nil;

  SHA256_Init: function (c: PSHA256_CTX): TIdC_INT; cdecl = nil;
  SHA256_Update: function (c: PSHA256_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  SHA256_Final: function (md: PByte; c: PSHA256_CTX): TIdC_INT; cdecl = nil;
  SHA256: function (const d: PByte; n: TIdC_SIZET; md: PByte): PByte; cdecl = nil;
  SHA256_Transform: procedure (c: PSHA256_CTX; const data: PByte); cdecl = nil;

  SHA384_Init: function (c: PSHA512_CTX): TIdC_INT; cdecl = nil;
  SHA384_Update: function (c: PSHA512_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  SHA384_Final: function (md: PByte; c: PSHA512_CTX): TIdC_INT; cdecl = nil;
  SHA384: function (const d: PByte; n: TIdC_SIZET; md: PByte): PByte; cdecl = nil;

  SHA512_Init: function (c: PSHA512_CTX): TIdC_INT; cdecl = nil;
  SHA512_Update: function (c: PSHA512_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  SHA512_Final: function (md: PByte; c: PSHA512_CTX): TIdC_INT; cdecl = nil;
  SHA512: function (const d: PByte; n: TIdC_SIZET; md: PByte): PByte; cdecl = nil;
  SHA512_Transform: procedure (c: PSHA512_CTX; const data: PByte); cdecl = nil;

{$ELSE}
  function SHA1_Init(c: PSHA_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function SHA1_Final(md: PByte; c: PSHA_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA1(const d: PByte; n: TIdC_SIZET; md: PByte): PByte cdecl; external CLibCrypto;
  procedure SHA1_Transform(c: PSHA_CTX; const data: PByte) cdecl; external CLibCrypto;

  function SHA224_Init(c: PSHA256_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function SHA224_Final(md: PByte; c: PSHA256_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA224(const d: PByte; n: TIdC_SIZET; md: PByte): PByte cdecl; external CLibCrypto;

  function SHA256_Init(c: PSHA256_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function SHA256_Final(md: PByte; c: PSHA256_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA256(const d: PByte; n: TIdC_SIZET; md: PByte): PByte cdecl; external CLibCrypto;
  procedure SHA256_Transform(c: PSHA256_CTX; const data: PByte) cdecl; external CLibCrypto;

  function SHA384_Init(c: PSHA512_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function SHA384_Final(md: PByte; c: PSHA512_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA384(const d: PByte; n: TIdC_SIZET; md: PByte): PByte cdecl; external CLibCrypto;

  function SHA512_Init(c: PSHA512_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function SHA512_Final(md: PByte; c: PSHA512_CTX): TIdC_INT cdecl; external CLibCrypto;
  function SHA512(const d: PByte; n: TIdC_SIZET; md: PByte): PByte cdecl; external CLibCrypto;
  procedure SHA512_Transform(c: PSHA512_CTX; const data: PByte) cdecl; external CLibCrypto;

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
  SHA1_Init_procname = 'SHA1_Init';
  SHA1_Update_procname = 'SHA1_Update';
  SHA1_Final_procname = 'SHA1_Final';
  SHA1_procname = 'SHA1';
  SHA1_Transform_procname = 'SHA1_Transform';

  SHA224_Init_procname = 'SHA224_Init';
  SHA224_Update_procname = 'SHA224_Update';
  SHA224_Final_procname = 'SHA224_Final';
  SHA224_procname = 'SHA224';

  SHA256_Init_procname = 'SHA256_Init';
  SHA256_Update_procname = 'SHA256_Update';
  SHA256_Final_procname = 'SHA256_Final';
  SHA256_procname = 'SHA256';
  SHA256_Transform_procname = 'SHA256_Transform';

  SHA384_Init_procname = 'SHA384_Init';
  SHA384_Update_procname = 'SHA384_Update';
  SHA384_Final_procname = 'SHA384_Final';
  SHA384_procname = 'SHA384';

  SHA512_Init_procname = 'SHA512_Init';
  SHA512_Update_procname = 'SHA512_Update';
  SHA512_Final_procname = 'SHA512_Final';
  SHA512_procname = 'SHA512';
  SHA512_Transform_procname = 'SHA512_Transform';


{$WARN  NO_RETVAL OFF}
function  ERR_SHA1_Init(c: PSHA_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA1_Init_procname);
end;


function  ERR_SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA1_Update_procname);
end;


function  ERR_SHA1_Final(md: PByte; c: PSHA_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA1_Final_procname);
end;


function  ERR_SHA1(const d: PByte; n: TIdC_SIZET; md: PByte): PByte; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA1_procname);
end;


procedure  ERR_SHA1_Transform(c: PSHA_CTX; const data: PByte); 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA1_Transform_procname);
end;



function  ERR_SHA224_Init(c: PSHA256_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA224_Init_procname);
end;


function  ERR_SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA224_Update_procname);
end;


function  ERR_SHA224_Final(md: PByte; c: PSHA256_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA224_Final_procname);
end;


function  ERR_SHA224(const d: PByte; n: TIdC_SIZET; md: PByte): PByte; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA224_procname);
end;



function  ERR_SHA256_Init(c: PSHA256_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA256_Init_procname);
end;


function  ERR_SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA256_Update_procname);
end;


function  ERR_SHA256_Final(md: PByte; c: PSHA256_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA256_Final_procname);
end;


function  ERR_SHA256(const d: PByte; n: TIdC_SIZET; md: PByte): PByte; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA256_procname);
end;


procedure  ERR_SHA256_Transform(c: PSHA256_CTX; const data: PByte); 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA256_Transform_procname);
end;



function  ERR_SHA384_Init(c: PSHA512_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA384_Init_procname);
end;


function  ERR_SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA384_Update_procname);
end;


function  ERR_SHA384_Final(md: PByte; c: PSHA512_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA384_Final_procname);
end;


function  ERR_SHA384(const d: PByte; n: TIdC_SIZET; md: PByte): PByte; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA384_procname);
end;



function  ERR_SHA512_Init(c: PSHA512_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA512_Init_procname);
end;


function  ERR_SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA512_Update_procname);
end;


function  ERR_SHA512_Final(md: PByte; c: PSHA512_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA512_Final_procname);
end;


function  ERR_SHA512(const d: PByte; n: TIdC_SIZET; md: PByte): PByte; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA512_procname);
end;


procedure  ERR_SHA512_Transform(c: PSHA512_CTX; const data: PByte); 
begin
  EIdAPIFunctionNotPresent.RaiseException(SHA512_Transform_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  SHA1_Init := LoadLibFunction(ADllHandle, SHA1_Init_procname);
  FuncLoadError := not assigned(SHA1_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Init_allownil)}
    SHA1_Init := @ERR_SHA1_Init;
    {$ifend}
    {$if declared(SHA1_Init_introduced)}
    if LibVersion < SHA1_Init_introduced then
    begin
      {$if declared(FC_SHA1_Init)}
      SHA1_Init := @FC_SHA1_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Init_removed)}
    if SHA1_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Init)}
      SHA1_Init := @_SHA1_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Init');
    {$ifend}
  end;


  SHA1_Update := LoadLibFunction(ADllHandle, SHA1_Update_procname);
  FuncLoadError := not assigned(SHA1_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Update_allownil)}
    SHA1_Update := @ERR_SHA1_Update;
    {$ifend}
    {$if declared(SHA1_Update_introduced)}
    if LibVersion < SHA1_Update_introduced then
    begin
      {$if declared(FC_SHA1_Update)}
      SHA1_Update := @FC_SHA1_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Update_removed)}
    if SHA1_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Update)}
      SHA1_Update := @_SHA1_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Update');
    {$ifend}
  end;


  SHA1_Final := LoadLibFunction(ADllHandle, SHA1_Final_procname);
  FuncLoadError := not assigned(SHA1_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Final_allownil)}
    SHA1_Final := @ERR_SHA1_Final;
    {$ifend}
    {$if declared(SHA1_Final_introduced)}
    if LibVersion < SHA1_Final_introduced then
    begin
      {$if declared(FC_SHA1_Final)}
      SHA1_Final := @FC_SHA1_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Final_removed)}
    if SHA1_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Final)}
      SHA1_Final := @_SHA1_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Final');
    {$ifend}
  end;


  SHA1 := LoadLibFunction(ADllHandle, SHA1_procname);
  FuncLoadError := not assigned(SHA1);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_allownil)}
    SHA1 := @ERR_SHA1;
    {$ifend}
    {$if declared(SHA1_introduced)}
    if LibVersion < SHA1_introduced then
    begin
      {$if declared(FC_SHA1)}
      SHA1 := @FC_SHA1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_removed)}
    if SHA1_removed <= LibVersion then
    begin
      {$if declared(_SHA1)}
      SHA1 := @_SHA1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1');
    {$ifend}
  end;


  SHA1_Transform := LoadLibFunction(ADllHandle, SHA1_Transform_procname);
  FuncLoadError := not assigned(SHA1_Transform);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Transform_allownil)}
    SHA1_Transform := @ERR_SHA1_Transform;
    {$ifend}
    {$if declared(SHA1_Transform_introduced)}
    if LibVersion < SHA1_Transform_introduced then
    begin
      {$if declared(FC_SHA1_Transform)}
      SHA1_Transform := @FC_SHA1_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Transform_removed)}
    if SHA1_Transform_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Transform)}
      SHA1_Transform := @_SHA1_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Transform');
    {$ifend}
  end;


  SHA224_Init := LoadLibFunction(ADllHandle, SHA224_Init_procname);
  FuncLoadError := not assigned(SHA224_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_Init_allownil)}
    SHA224_Init := @ERR_SHA224_Init;
    {$ifend}
    {$if declared(SHA224_Init_introduced)}
    if LibVersion < SHA224_Init_introduced then
    begin
      {$if declared(FC_SHA224_Init)}
      SHA224_Init := @FC_SHA224_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_Init_removed)}
    if SHA224_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA224_Init)}
      SHA224_Init := @_SHA224_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224_Init');
    {$ifend}
  end;


  SHA224_Update := LoadLibFunction(ADllHandle, SHA224_Update_procname);
  FuncLoadError := not assigned(SHA224_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_Update_allownil)}
    SHA224_Update := @ERR_SHA224_Update;
    {$ifend}
    {$if declared(SHA224_Update_introduced)}
    if LibVersion < SHA224_Update_introduced then
    begin
      {$if declared(FC_SHA224_Update)}
      SHA224_Update := @FC_SHA224_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_Update_removed)}
    if SHA224_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA224_Update)}
      SHA224_Update := @_SHA224_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224_Update');
    {$ifend}
  end;


  SHA224_Final := LoadLibFunction(ADllHandle, SHA224_Final_procname);
  FuncLoadError := not assigned(SHA224_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_Final_allownil)}
    SHA224_Final := @ERR_SHA224_Final;
    {$ifend}
    {$if declared(SHA224_Final_introduced)}
    if LibVersion < SHA224_Final_introduced then
    begin
      {$if declared(FC_SHA224_Final)}
      SHA224_Final := @FC_SHA224_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_Final_removed)}
    if SHA224_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA224_Final)}
      SHA224_Final := @_SHA224_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224_Final');
    {$ifend}
  end;


  SHA224 := LoadLibFunction(ADllHandle, SHA224_procname);
  FuncLoadError := not assigned(SHA224);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_allownil)}
    SHA224 := @ERR_SHA224;
    {$ifend}
    {$if declared(SHA224_introduced)}
    if LibVersion < SHA224_introduced then
    begin
      {$if declared(FC_SHA224)}
      SHA224 := @FC_SHA224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_removed)}
    if SHA224_removed <= LibVersion then
    begin
      {$if declared(_SHA224)}
      SHA224 := @_SHA224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224');
    {$ifend}
  end;


  SHA256_Init := LoadLibFunction(ADllHandle, SHA256_Init_procname);
  FuncLoadError := not assigned(SHA256_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Init_allownil)}
    SHA256_Init := @ERR_SHA256_Init;
    {$ifend}
    {$if declared(SHA256_Init_introduced)}
    if LibVersion < SHA256_Init_introduced then
    begin
      {$if declared(FC_SHA256_Init)}
      SHA256_Init := @FC_SHA256_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Init_removed)}
    if SHA256_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Init)}
      SHA256_Init := @_SHA256_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Init');
    {$ifend}
  end;


  SHA256_Update := LoadLibFunction(ADllHandle, SHA256_Update_procname);
  FuncLoadError := not assigned(SHA256_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Update_allownil)}
    SHA256_Update := @ERR_SHA256_Update;
    {$ifend}
    {$if declared(SHA256_Update_introduced)}
    if LibVersion < SHA256_Update_introduced then
    begin
      {$if declared(FC_SHA256_Update)}
      SHA256_Update := @FC_SHA256_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Update_removed)}
    if SHA256_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Update)}
      SHA256_Update := @_SHA256_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Update');
    {$ifend}
  end;


  SHA256_Final := LoadLibFunction(ADllHandle, SHA256_Final_procname);
  FuncLoadError := not assigned(SHA256_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Final_allownil)}
    SHA256_Final := @ERR_SHA256_Final;
    {$ifend}
    {$if declared(SHA256_Final_introduced)}
    if LibVersion < SHA256_Final_introduced then
    begin
      {$if declared(FC_SHA256_Final)}
      SHA256_Final := @FC_SHA256_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Final_removed)}
    if SHA256_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Final)}
      SHA256_Final := @_SHA256_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Final');
    {$ifend}
  end;


  SHA256 := LoadLibFunction(ADllHandle, SHA256_procname);
  FuncLoadError := not assigned(SHA256);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_allownil)}
    SHA256 := @ERR_SHA256;
    {$ifend}
    {$if declared(SHA256_introduced)}
    if LibVersion < SHA256_introduced then
    begin
      {$if declared(FC_SHA256)}
      SHA256 := @FC_SHA256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_removed)}
    if SHA256_removed <= LibVersion then
    begin
      {$if declared(_SHA256)}
      SHA256 := @_SHA256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256');
    {$ifend}
  end;


  SHA256_Transform := LoadLibFunction(ADllHandle, SHA256_Transform_procname);
  FuncLoadError := not assigned(SHA256_Transform);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Transform_allownil)}
    SHA256_Transform := @ERR_SHA256_Transform;
    {$ifend}
    {$if declared(SHA256_Transform_introduced)}
    if LibVersion < SHA256_Transform_introduced then
    begin
      {$if declared(FC_SHA256_Transform)}
      SHA256_Transform := @FC_SHA256_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Transform_removed)}
    if SHA256_Transform_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Transform)}
      SHA256_Transform := @_SHA256_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Transform');
    {$ifend}
  end;


  SHA384_Init := LoadLibFunction(ADllHandle, SHA384_Init_procname);
  FuncLoadError := not assigned(SHA384_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_Init_allownil)}
    SHA384_Init := @ERR_SHA384_Init;
    {$ifend}
    {$if declared(SHA384_Init_introduced)}
    if LibVersion < SHA384_Init_introduced then
    begin
      {$if declared(FC_SHA384_Init)}
      SHA384_Init := @FC_SHA384_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_Init_removed)}
    if SHA384_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA384_Init)}
      SHA384_Init := @_SHA384_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384_Init');
    {$ifend}
  end;


  SHA384_Update := LoadLibFunction(ADllHandle, SHA384_Update_procname);
  FuncLoadError := not assigned(SHA384_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_Update_allownil)}
    SHA384_Update := @ERR_SHA384_Update;
    {$ifend}
    {$if declared(SHA384_Update_introduced)}
    if LibVersion < SHA384_Update_introduced then
    begin
      {$if declared(FC_SHA384_Update)}
      SHA384_Update := @FC_SHA384_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_Update_removed)}
    if SHA384_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA384_Update)}
      SHA384_Update := @_SHA384_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384_Update');
    {$ifend}
  end;


  SHA384_Final := LoadLibFunction(ADllHandle, SHA384_Final_procname);
  FuncLoadError := not assigned(SHA384_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_Final_allownil)}
    SHA384_Final := @ERR_SHA384_Final;
    {$ifend}
    {$if declared(SHA384_Final_introduced)}
    if LibVersion < SHA384_Final_introduced then
    begin
      {$if declared(FC_SHA384_Final)}
      SHA384_Final := @FC_SHA384_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_Final_removed)}
    if SHA384_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA384_Final)}
      SHA384_Final := @_SHA384_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384_Final');
    {$ifend}
  end;


  SHA384 := LoadLibFunction(ADllHandle, SHA384_procname);
  FuncLoadError := not assigned(SHA384);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_allownil)}
    SHA384 := @ERR_SHA384;
    {$ifend}
    {$if declared(SHA384_introduced)}
    if LibVersion < SHA384_introduced then
    begin
      {$if declared(FC_SHA384)}
      SHA384 := @FC_SHA384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_removed)}
    if SHA384_removed <= LibVersion then
    begin
      {$if declared(_SHA384)}
      SHA384 := @_SHA384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384');
    {$ifend}
  end;


  SHA512_Init := LoadLibFunction(ADllHandle, SHA512_Init_procname);
  FuncLoadError := not assigned(SHA512_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Init_allownil)}
    SHA512_Init := @ERR_SHA512_Init;
    {$ifend}
    {$if declared(SHA512_Init_introduced)}
    if LibVersion < SHA512_Init_introduced then
    begin
      {$if declared(FC_SHA512_Init)}
      SHA512_Init := @FC_SHA512_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Init_removed)}
    if SHA512_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Init)}
      SHA512_Init := @_SHA512_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Init');
    {$ifend}
  end;


  SHA512_Update := LoadLibFunction(ADllHandle, SHA512_Update_procname);
  FuncLoadError := not assigned(SHA512_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Update_allownil)}
    SHA512_Update := @ERR_SHA512_Update;
    {$ifend}
    {$if declared(SHA512_Update_introduced)}
    if LibVersion < SHA512_Update_introduced then
    begin
      {$if declared(FC_SHA512_Update)}
      SHA512_Update := @FC_SHA512_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Update_removed)}
    if SHA512_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Update)}
      SHA512_Update := @_SHA512_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Update');
    {$ifend}
  end;


  SHA512_Final := LoadLibFunction(ADllHandle, SHA512_Final_procname);
  FuncLoadError := not assigned(SHA512_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Final_allownil)}
    SHA512_Final := @ERR_SHA512_Final;
    {$ifend}
    {$if declared(SHA512_Final_introduced)}
    if LibVersion < SHA512_Final_introduced then
    begin
      {$if declared(FC_SHA512_Final)}
      SHA512_Final := @FC_SHA512_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Final_removed)}
    if SHA512_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Final)}
      SHA512_Final := @_SHA512_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Final');
    {$ifend}
  end;


  SHA512 := LoadLibFunction(ADllHandle, SHA512_procname);
  FuncLoadError := not assigned(SHA512);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_allownil)}
    SHA512 := @ERR_SHA512;
    {$ifend}
    {$if declared(SHA512_introduced)}
    if LibVersion < SHA512_introduced then
    begin
      {$if declared(FC_SHA512)}
      SHA512 := @FC_SHA512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_removed)}
    if SHA512_removed <= LibVersion then
    begin
      {$if declared(_SHA512)}
      SHA512 := @_SHA512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512');
    {$ifend}
  end;


  SHA512_Transform := LoadLibFunction(ADllHandle, SHA512_Transform_procname);
  FuncLoadError := not assigned(SHA512_Transform);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Transform_allownil)}
    SHA512_Transform := @ERR_SHA512_Transform;
    {$ifend}
    {$if declared(SHA512_Transform_introduced)}
    if LibVersion < SHA512_Transform_introduced then
    begin
      {$if declared(FC_SHA512_Transform)}
      SHA512_Transform := @FC_SHA512_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Transform_removed)}
    if SHA512_Transform_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Transform)}
      SHA512_Transform := @_SHA512_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Transform');
    {$ifend}
  end;


end;

procedure Unload;
begin
  SHA1_Init := nil;
  SHA1_Update := nil;
  SHA1_Final := nil;
  SHA1 := nil;
  SHA1_Transform := nil;
  SHA224_Init := nil;
  SHA224_Update := nil;
  SHA224_Final := nil;
  SHA224 := nil;
  SHA256_Init := nil;
  SHA256_Update := nil;
  SHA256_Final := nil;
  SHA256 := nil;
  SHA256_Transform := nil;
  SHA384_Init := nil;
  SHA384_Update := nil;
  SHA384_Final := nil;
  SHA384 := nil;
  SHA512_Init := nil;
  SHA512_Update := nil;
  SHA512_Final := nil;
  SHA512 := nil;
  SHA512_Transform := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
