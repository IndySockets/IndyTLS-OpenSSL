  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_buffer.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_buffer.h2pas
     and this file regenerated. IdOpenSSLHeaders_buffer.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_buffer;

interface

// Headers for OpenSSL 1.1.1
// buffer.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_ossl_typ;

const
  BUF_MEM_FLAG_SECURE = $01;

type
  buf_mem_st = record
    length: TIdC_SIZET;
    data: PIdAnsiChar;
    max: TIdC_SIZET;
    flags: TIdC_ULONG;
  end;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM BUF_MEM_new}
  {$EXTERNALSYM BUF_MEM_new_ex}
  {$EXTERNALSYM BUF_MEM_free}
  {$EXTERNALSYM BUF_MEM_grow}
  {$EXTERNALSYM BUF_MEM_grow_clean}
  {$EXTERNALSYM BUF_reverse}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  BUF_MEM_new: function : PBUF_MEM; cdecl = nil;
  BUF_MEM_new_ex: function (flags: TIdC_ULONG): PBUF_MEM; cdecl = nil;
  BUF_MEM_free: procedure (a: PBUF_MEM); cdecl = nil;
  BUF_MEM_grow: function (str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  BUF_MEM_grow_clean: function (str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  BUF_reverse: procedure (out_: PByte; const in_: PByte; siz: TIdC_SIZET); cdecl = nil;

{$ELSE}
  function BUF_MEM_new: PBUF_MEM cdecl; external CLibCrypto;
  function BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM cdecl; external CLibCrypto;
  procedure BUF_MEM_free(a: PBUF_MEM) cdecl; external CLibCrypto;
  function BUF_MEM_grow(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto;
  function BUF_MEM_grow_clean(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto;
  procedure BUF_reverse(out_: PByte; const in_: PByte; siz: TIdC_SIZET) cdecl; external CLibCrypto;

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
  BUF_MEM_new_procname = 'BUF_MEM_new';
  BUF_MEM_new_ex_procname = 'BUF_MEM_new_ex';
  BUF_MEM_free_procname = 'BUF_MEM_free';
  BUF_MEM_grow_procname = 'BUF_MEM_grow';
  BUF_MEM_grow_clean_procname = 'BUF_MEM_grow_clean';
  BUF_reverse_procname = 'BUF_reverse';


{$WARN  NO_RETVAL OFF}
function  ERR_BUF_MEM_new: PBUF_MEM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BUF_MEM_new_procname);
end;


function  ERR_BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BUF_MEM_new_ex_procname);
end;


procedure  ERR_BUF_MEM_free(a: PBUF_MEM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BUF_MEM_free_procname);
end;


function  ERR_BUF_MEM_grow(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BUF_MEM_grow_procname);
end;


function  ERR_BUF_MEM_grow_clean(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BUF_MEM_grow_clean_procname);
end;


procedure  ERR_BUF_reverse(out_: PByte; const in_: PByte; siz: TIdC_SIZET); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BUF_reverse_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  BUF_MEM_new := LoadLibFunction(ADllHandle, BUF_MEM_new_procname);
  FuncLoadError := not assigned(BUF_MEM_new);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_new_allownil)}
    BUF_MEM_new := @ERR_BUF_MEM_new;
    {$ifend}
    {$if declared(BUF_MEM_new_introduced)}
    if LibVersion < BUF_MEM_new_introduced then
    begin
      {$if declared(FC_BUF_MEM_new)}
      BUF_MEM_new := @FC_BUF_MEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_new_removed)}
    if BUF_MEM_new_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_new)}
      BUF_MEM_new := @_BUF_MEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_new');
    {$ifend}
  end;


  BUF_MEM_new_ex := LoadLibFunction(ADllHandle, BUF_MEM_new_ex_procname);
  FuncLoadError := not assigned(BUF_MEM_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_new_ex_allownil)}
    BUF_MEM_new_ex := @ERR_BUF_MEM_new_ex;
    {$ifend}
    {$if declared(BUF_MEM_new_ex_introduced)}
    if LibVersion < BUF_MEM_new_ex_introduced then
    begin
      {$if declared(FC_BUF_MEM_new_ex)}
      BUF_MEM_new_ex := @FC_BUF_MEM_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_new_ex_removed)}
    if BUF_MEM_new_ex_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_new_ex)}
      BUF_MEM_new_ex := @_BUF_MEM_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_new_ex');
    {$ifend}
  end;


  BUF_MEM_free := LoadLibFunction(ADllHandle, BUF_MEM_free_procname);
  FuncLoadError := not assigned(BUF_MEM_free);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_free_allownil)}
    BUF_MEM_free := @ERR_BUF_MEM_free;
    {$ifend}
    {$if declared(BUF_MEM_free_introduced)}
    if LibVersion < BUF_MEM_free_introduced then
    begin
      {$if declared(FC_BUF_MEM_free)}
      BUF_MEM_free := @FC_BUF_MEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_free_removed)}
    if BUF_MEM_free_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_free)}
      BUF_MEM_free := @_BUF_MEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_free');
    {$ifend}
  end;


  BUF_MEM_grow := LoadLibFunction(ADllHandle, BUF_MEM_grow_procname);
  FuncLoadError := not assigned(BUF_MEM_grow);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_grow_allownil)}
    BUF_MEM_grow := @ERR_BUF_MEM_grow;
    {$ifend}
    {$if declared(BUF_MEM_grow_introduced)}
    if LibVersion < BUF_MEM_grow_introduced then
    begin
      {$if declared(FC_BUF_MEM_grow)}
      BUF_MEM_grow := @FC_BUF_MEM_grow;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_grow_removed)}
    if BUF_MEM_grow_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_grow)}
      BUF_MEM_grow := @_BUF_MEM_grow;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_grow_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_grow');
    {$ifend}
  end;


  BUF_MEM_grow_clean := LoadLibFunction(ADllHandle, BUF_MEM_grow_clean_procname);
  FuncLoadError := not assigned(BUF_MEM_grow_clean);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_grow_clean_allownil)}
    BUF_MEM_grow_clean := @ERR_BUF_MEM_grow_clean;
    {$ifend}
    {$if declared(BUF_MEM_grow_clean_introduced)}
    if LibVersion < BUF_MEM_grow_clean_introduced then
    begin
      {$if declared(FC_BUF_MEM_grow_clean)}
      BUF_MEM_grow_clean := @FC_BUF_MEM_grow_clean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_grow_clean_removed)}
    if BUF_MEM_grow_clean_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_grow_clean)}
      BUF_MEM_grow_clean := @_BUF_MEM_grow_clean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_grow_clean_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_grow_clean');
    {$ifend}
  end;


  BUF_reverse := LoadLibFunction(ADllHandle, BUF_reverse_procname);
  FuncLoadError := not assigned(BUF_reverse);
  if FuncLoadError then
  begin
    {$if not defined(BUF_reverse_allownil)}
    BUF_reverse := @ERR_BUF_reverse;
    {$ifend}
    {$if declared(BUF_reverse_introduced)}
    if LibVersion < BUF_reverse_introduced then
    begin
      {$if declared(FC_BUF_reverse)}
      BUF_reverse := @FC_BUF_reverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_reverse_removed)}
    if BUF_reverse_removed <= LibVersion then
    begin
      {$if declared(_BUF_reverse)}
      BUF_reverse := @_BUF_reverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_reverse_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_reverse');
    {$ifend}
  end;


end;

procedure Unload;
begin
  BUF_MEM_new := nil;
  BUF_MEM_new_ex := nil;
  BUF_MEM_free := nil;
  BUF_MEM_grow := nil;
  BUF_MEM_grow_clean := nil;
  BUF_reverse := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
