  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_cmac.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_cmac.h2pas
     and this file regenerated. IdOpenSSLHeaders_cmac.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_cmac;

interface

// Headers for OpenSSL 1.1.1
// cmac.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_ossl_typ;

//* Opaque */
type
  CMAC_CTX_st = type Pointer;
  CMAC_CTX = CMAC_CTX_st;
  PCMAC_CTX = ^CMAC_CTX;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM CMAC_CTX_new}
  {$EXTERNALSYM CMAC_CTX_cleanup}
  {$EXTERNALSYM CMAC_CTX_free}
  {$EXTERNALSYM CMAC_CTX_get0_cipher_ctx}
  {$EXTERNALSYM CMAC_CTX_copy}
  {$EXTERNALSYM CMAC_Init}
  {$EXTERNALSYM CMAC_Update}
  {$EXTERNALSYM CMAC_Final}
  {$EXTERNALSYM CMAC_resume}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  CMAC_CTX_new: function : PCMAC_CTX; cdecl = nil;
  CMAC_CTX_cleanup: procedure (ctx: PCMAC_CTX); cdecl = nil;
  CMAC_CTX_free: procedure (ctx: PCMAC_CTX); cdecl = nil;
  CMAC_CTX_get0_cipher_ctx: function (ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl = nil;
  CMAC_CTX_copy: function (out_: PCMAC_CTX; const in_: PCMAC_CTX): TIdC_INT; cdecl = nil;
  CMAC_Init: function (ctx: PCMAC_CTX; const key: Pointer; keylen: TIdC_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TIdC_INT; cdecl = nil;
  CMAC_Update: function (ctx: PCMAC_CTX; const data: Pointer; dlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  CMAC_Final: function (ctx: PCMAC_CTX; out_: PByte; poutlen: PIdC_SIZET): TIdC_INT; cdecl = nil;
  CMAC_resume: function (ctx: PCMAC_CTX): TIdC_INT; cdecl = nil;

{$ELSE}
  function CMAC_CTX_new: PCMAC_CTX cdecl; external CLibCrypto;
  procedure CMAC_CTX_cleanup(ctx: PCMAC_CTX) cdecl; external CLibCrypto;
  procedure CMAC_CTX_free(ctx: PCMAC_CTX) cdecl; external CLibCrypto;
  function CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX cdecl; external CLibCrypto;
  function CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TIdC_INT cdecl; external CLibCrypto;
  function CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TIdC_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TIdC_INT cdecl; external CLibCrypto;
  function CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function CMAC_resume(ctx: PCMAC_CTX): TIdC_INT cdecl; external CLibCrypto;

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
  CMAC_CTX_new_procname = 'CMAC_CTX_new';
  CMAC_CTX_cleanup_procname = 'CMAC_CTX_cleanup';
  CMAC_CTX_free_procname = 'CMAC_CTX_free';
  CMAC_CTX_get0_cipher_ctx_procname = 'CMAC_CTX_get0_cipher_ctx';
  CMAC_CTX_copy_procname = 'CMAC_CTX_copy';
  CMAC_Init_procname = 'CMAC_Init';
  CMAC_Update_procname = 'CMAC_Update';
  CMAC_Final_procname = 'CMAC_Final';
  CMAC_resume_procname = 'CMAC_resume';


{$WARN  NO_RETVAL OFF}
function  ERR_CMAC_CTX_new: PCMAC_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_CTX_new_procname);
end;


procedure  ERR_CMAC_CTX_cleanup(ctx: PCMAC_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_CTX_cleanup_procname);
end;


procedure  ERR_CMAC_CTX_free(ctx: PCMAC_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_CTX_free_procname);
end;


function  ERR_CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_CTX_get0_cipher_ctx_procname);
end;


function  ERR_CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_CTX_copy_procname);
end;


function  ERR_CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TIdC_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_Init_procname);
end;


function  ERR_CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_Update_procname);
end;


function  ERR_CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: PIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_Final_procname);
end;


function  ERR_CMAC_resume(ctx: PCMAC_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMAC_resume_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  CMAC_CTX_new := LoadLibFunction(ADllHandle, CMAC_CTX_new_procname);
  FuncLoadError := not assigned(CMAC_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_CTX_new_allownil)}
    CMAC_CTX_new := @ERR_CMAC_CTX_new;
    {$ifend}
    {$if declared(CMAC_CTX_new_introduced)}
    if LibVersion < CMAC_CTX_new_introduced then
    begin
      {$if declared(FC_CMAC_CTX_new)}
      CMAC_CTX_new := @FC_CMAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_CTX_new_removed)}
    if CMAC_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_CMAC_CTX_new)}
      CMAC_CTX_new := @_CMAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_CTX_new');
    {$ifend}
  end;


  CMAC_CTX_cleanup := LoadLibFunction(ADllHandle, CMAC_CTX_cleanup_procname);
  FuncLoadError := not assigned(CMAC_CTX_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_CTX_cleanup_allownil)}
    CMAC_CTX_cleanup := @ERR_CMAC_CTX_cleanup;
    {$ifend}
    {$if declared(CMAC_CTX_cleanup_introduced)}
    if LibVersion < CMAC_CTX_cleanup_introduced then
    begin
      {$if declared(FC_CMAC_CTX_cleanup)}
      CMAC_CTX_cleanup := @FC_CMAC_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_CTX_cleanup_removed)}
    if CMAC_CTX_cleanup_removed <= LibVersion then
    begin
      {$if declared(_CMAC_CTX_cleanup)}
      CMAC_CTX_cleanup := @_CMAC_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_CTX_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_CTX_cleanup');
    {$ifend}
  end;


  CMAC_CTX_free := LoadLibFunction(ADllHandle, CMAC_CTX_free_procname);
  FuncLoadError := not assigned(CMAC_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_CTX_free_allownil)}
    CMAC_CTX_free := @ERR_CMAC_CTX_free;
    {$ifend}
    {$if declared(CMAC_CTX_free_introduced)}
    if LibVersion < CMAC_CTX_free_introduced then
    begin
      {$if declared(FC_CMAC_CTX_free)}
      CMAC_CTX_free := @FC_CMAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_CTX_free_removed)}
    if CMAC_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_CMAC_CTX_free)}
      CMAC_CTX_free := @_CMAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_CTX_free');
    {$ifend}
  end;


  CMAC_CTX_get0_cipher_ctx := LoadLibFunction(ADllHandle, CMAC_CTX_get0_cipher_ctx_procname);
  FuncLoadError := not assigned(CMAC_CTX_get0_cipher_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_CTX_get0_cipher_ctx_allownil)}
    CMAC_CTX_get0_cipher_ctx := @ERR_CMAC_CTX_get0_cipher_ctx;
    {$ifend}
    {$if declared(CMAC_CTX_get0_cipher_ctx_introduced)}
    if LibVersion < CMAC_CTX_get0_cipher_ctx_introduced then
    begin
      {$if declared(FC_CMAC_CTX_get0_cipher_ctx)}
      CMAC_CTX_get0_cipher_ctx := @FC_CMAC_CTX_get0_cipher_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_CTX_get0_cipher_ctx_removed)}
    if CMAC_CTX_get0_cipher_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMAC_CTX_get0_cipher_ctx)}
      CMAC_CTX_get0_cipher_ctx := @_CMAC_CTX_get0_cipher_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_CTX_get0_cipher_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_CTX_get0_cipher_ctx');
    {$ifend}
  end;


  CMAC_CTX_copy := LoadLibFunction(ADllHandle, CMAC_CTX_copy_procname);
  FuncLoadError := not assigned(CMAC_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_CTX_copy_allownil)}
    CMAC_CTX_copy := @ERR_CMAC_CTX_copy;
    {$ifend}
    {$if declared(CMAC_CTX_copy_introduced)}
    if LibVersion < CMAC_CTX_copy_introduced then
    begin
      {$if declared(FC_CMAC_CTX_copy)}
      CMAC_CTX_copy := @FC_CMAC_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_CTX_copy_removed)}
    if CMAC_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_CMAC_CTX_copy)}
      CMAC_CTX_copy := @_CMAC_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_CTX_copy');
    {$ifend}
  end;


  CMAC_Init := LoadLibFunction(ADllHandle, CMAC_Init_procname);
  FuncLoadError := not assigned(CMAC_Init);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_Init_allownil)}
    CMAC_Init := @ERR_CMAC_Init;
    {$ifend}
    {$if declared(CMAC_Init_introduced)}
    if LibVersion < CMAC_Init_introduced then
    begin
      {$if declared(FC_CMAC_Init)}
      CMAC_Init := @FC_CMAC_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_Init_removed)}
    if CMAC_Init_removed <= LibVersion then
    begin
      {$if declared(_CMAC_Init)}
      CMAC_Init := @_CMAC_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_Init');
    {$ifend}
  end;


  CMAC_Update := LoadLibFunction(ADllHandle, CMAC_Update_procname);
  FuncLoadError := not assigned(CMAC_Update);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_Update_allownil)}
    CMAC_Update := @ERR_CMAC_Update;
    {$ifend}
    {$if declared(CMAC_Update_introduced)}
    if LibVersion < CMAC_Update_introduced then
    begin
      {$if declared(FC_CMAC_Update)}
      CMAC_Update := @FC_CMAC_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_Update_removed)}
    if CMAC_Update_removed <= LibVersion then
    begin
      {$if declared(_CMAC_Update)}
      CMAC_Update := @_CMAC_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_Update');
    {$ifend}
  end;


  CMAC_Final := LoadLibFunction(ADllHandle, CMAC_Final_procname);
  FuncLoadError := not assigned(CMAC_Final);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_Final_allownil)}
    CMAC_Final := @ERR_CMAC_Final;
    {$ifend}
    {$if declared(CMAC_Final_introduced)}
    if LibVersion < CMAC_Final_introduced then
    begin
      {$if declared(FC_CMAC_Final)}
      CMAC_Final := @FC_CMAC_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_Final_removed)}
    if CMAC_Final_removed <= LibVersion then
    begin
      {$if declared(_CMAC_Final)}
      CMAC_Final := @_CMAC_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_Final');
    {$ifend}
  end;


  CMAC_resume := LoadLibFunction(ADllHandle, CMAC_resume_procname);
  FuncLoadError := not assigned(CMAC_resume);
  if FuncLoadError then
  begin
    {$if not defined(CMAC_resume_allownil)}
    CMAC_resume := @ERR_CMAC_resume;
    {$ifend}
    {$if declared(CMAC_resume_introduced)}
    if LibVersion < CMAC_resume_introduced then
    begin
      {$if declared(FC_CMAC_resume)}
      CMAC_resume := @FC_CMAC_resume;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMAC_resume_removed)}
    if CMAC_resume_removed <= LibVersion then
    begin
      {$if declared(_CMAC_resume)}
      CMAC_resume := @_CMAC_resume;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMAC_resume_allownil)}
    if FuncLoadError then
      AFailed.Add('CMAC_resume');
    {$ifend}
  end;


end;

procedure Unload;
begin
  CMAC_CTX_new := nil;
  CMAC_CTX_cleanup := nil;
  CMAC_CTX_free := nil;
  CMAC_CTX_get0_cipher_ctx := nil;
  CMAC_CTX_copy := nil;
  CMAC_Init := nil;
  CMAC_Update := nil;
  CMAC_Final := nil;
  CMAC_resume := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
