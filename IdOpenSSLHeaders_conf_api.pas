  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_conf_api.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_conf_api.h2pas
     and this file regenerated. IdOpenSSLHeaders_conf_api.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_conf_api;

interface

// Headers for OpenSSL 1.1.1
// conf_api.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_conf;

  //* Up until OpenSSL 0.9.5a, this was new_section */
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM _CONF_new_section}
  {$EXTERNALSYM _CONF_get_section}
  {$EXTERNALSYM _CONF_add_string}
  {$EXTERNALSYM _CONF_get_string}
  {$EXTERNALSYM _CONF_get_number}
  {$EXTERNALSYM _CONF_new_data}
  {$EXTERNALSYM _CONF_free_data}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  _CONF_new_section: function (conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl = nil;
  //* Up until OpenSSL 0.9.5a, this was get_section */
  _CONF_get_section: function (const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl = nil;
  //* Up until OpenSSL 0.9.5a, this was CONF_get_section */
  //STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
  //                                               const char *section);

  _CONF_add_string: function (conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TIdC_INT; cdecl = nil;
  _CONF_get_string: function (const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl = nil;
  _CONF_get_number: function (const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TIdC_LONG; cdecl = nil;

  _CONF_new_data: function (conf: PCONF): TIdC_INT; cdecl = nil;
  _CONF_free_data: procedure (conf: PCONF); cdecl = nil;


{$ELSE}
  function _CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE cdecl; external CLibCrypto;
  //* Up until OpenSSL 0.9.5a, this was get_section */
  function _CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE cdecl; external CLibCrypto;
  //* Up until OpenSSL 0.9.5a, this was CONF_get_section */
  //STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
  //                                               const char *section);

  function _CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TIdC_INT cdecl; external CLibCrypto;
  function _CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar cdecl; external CLibCrypto;
  function _CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TIdC_LONG cdecl; external CLibCrypto;

  function _CONF_new_data(conf: PCONF): TIdC_INT cdecl; external CLibCrypto;
  procedure _CONF_free_data(conf: PCONF) cdecl; external CLibCrypto;


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
  _CONF_new_section_procname = '_CONF_new_section';
  //* Up until OpenSSL 0.9.5a, this was get_section */
  _CONF_get_section_procname = '_CONF_get_section';
  //* Up until OpenSSL 0.9.5a, this was CONF_get_section */
  //STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
  //                                               const char *section);

  _CONF_add_string_procname = '_CONF_add_string';
  _CONF_get_string_procname = '_CONF_get_string';
  _CONF_get_number_procname = '_CONF_get_number';

  _CONF_new_data_procname = '_CONF_new_data';
  _CONF_free_data_procname = '_CONF_free_data';



{$WARN  NO_RETVAL OFF}
function  ERR__CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_new_section_procname);
end;


  //* Up until OpenSSL 0.9.5a, this was get_section */
function  ERR__CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_get_section_procname);
end;


  //* Up until OpenSSL 0.9.5a, this was CONF_get_section */
  //STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
  //                                               const char *section);

function  ERR__CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_add_string_procname);
end;


function  ERR__CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_get_string_procname);
end;


function  ERR__CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TIdC_LONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_get_number_procname);
end;



function  ERR__CONF_new_data(conf: PCONF): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_new_data_procname);
end;


procedure  ERR__CONF_free_data(conf: PCONF); 
begin
  EIdAPIFunctionNotPresent.RaiseException(_CONF_free_data_procname);
end;




{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  _CONF_new_section := LoadLibFunction(ADllHandle, _CONF_new_section_procname);
  FuncLoadError := not assigned(_CONF_new_section);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_new_section_allownil)}
    _CONF_new_section := @ERR__CONF_new_section;
    {$ifend}
    {$if declared(_CONF_new_section_introduced)}
    if LibVersion < _CONF_new_section_introduced then
    begin
      {$if declared(FC__CONF_new_section)}
      _CONF_new_section := @FC__CONF_new_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_new_section_removed)}
    if _CONF_new_section_removed <= LibVersion then
    begin
      {$if declared(__CONF_new_section)}
      _CONF_new_section := @__CONF_new_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_new_section_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_new_section');
    {$ifend}
  end;


  _CONF_get_section := LoadLibFunction(ADllHandle, _CONF_get_section_procname);
  FuncLoadError := not assigned(_CONF_get_section);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_get_section_allownil)}
    _CONF_get_section := @ERR__CONF_get_section;
    {$ifend}
    {$if declared(_CONF_get_section_introduced)}
    if LibVersion < _CONF_get_section_introduced then
    begin
      {$if declared(FC__CONF_get_section)}
      _CONF_get_section := @FC__CONF_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_get_section_removed)}
    if _CONF_get_section_removed <= LibVersion then
    begin
      {$if declared(__CONF_get_section)}
      _CONF_get_section := @__CONF_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_get_section_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_get_section');
    {$ifend}
  end;


  _CONF_add_string := LoadLibFunction(ADllHandle, _CONF_add_string_procname);
  FuncLoadError := not assigned(_CONF_add_string);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_add_string_allownil)}
    _CONF_add_string := @ERR__CONF_add_string;
    {$ifend}
    {$if declared(_CONF_add_string_introduced)}
    if LibVersion < _CONF_add_string_introduced then
    begin
      {$if declared(FC__CONF_add_string)}
      _CONF_add_string := @FC__CONF_add_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_add_string_removed)}
    if _CONF_add_string_removed <= LibVersion then
    begin
      {$if declared(__CONF_add_string)}
      _CONF_add_string := @__CONF_add_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_add_string_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_add_string');
    {$ifend}
  end;


  _CONF_get_string := LoadLibFunction(ADllHandle, _CONF_get_string_procname);
  FuncLoadError := not assigned(_CONF_get_string);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_get_string_allownil)}
    _CONF_get_string := @ERR__CONF_get_string;
    {$ifend}
    {$if declared(_CONF_get_string_introduced)}
    if LibVersion < _CONF_get_string_introduced then
    begin
      {$if declared(FC__CONF_get_string)}
      _CONF_get_string := @FC__CONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_get_string_removed)}
    if _CONF_get_string_removed <= LibVersion then
    begin
      {$if declared(__CONF_get_string)}
      _CONF_get_string := @__CONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_get_string');
    {$ifend}
  end;


  _CONF_get_number := LoadLibFunction(ADllHandle, _CONF_get_number_procname);
  FuncLoadError := not assigned(_CONF_get_number);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_get_number_allownil)}
    _CONF_get_number := @ERR__CONF_get_number;
    {$ifend}
    {$if declared(_CONF_get_number_introduced)}
    if LibVersion < _CONF_get_number_introduced then
    begin
      {$if declared(FC__CONF_get_number)}
      _CONF_get_number := @FC__CONF_get_number;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_get_number_removed)}
    if _CONF_get_number_removed <= LibVersion then
    begin
      {$if declared(__CONF_get_number)}
      _CONF_get_number := @__CONF_get_number;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_get_number_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_get_number');
    {$ifend}
  end;


  _CONF_new_data := LoadLibFunction(ADllHandle, _CONF_new_data_procname);
  FuncLoadError := not assigned(_CONF_new_data);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_new_data_allownil)}
    _CONF_new_data := @ERR__CONF_new_data;
    {$ifend}
    {$if declared(_CONF_new_data_introduced)}
    if LibVersion < _CONF_new_data_introduced then
    begin
      {$if declared(FC__CONF_new_data)}
      _CONF_new_data := @FC__CONF_new_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_new_data_removed)}
    if _CONF_new_data_removed <= LibVersion then
    begin
      {$if declared(__CONF_new_data)}
      _CONF_new_data := @__CONF_new_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_new_data_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_new_data');
    {$ifend}
  end;


  _CONF_free_data := LoadLibFunction(ADllHandle, _CONF_free_data_procname);
  FuncLoadError := not assigned(_CONF_free_data);
  if FuncLoadError then
  begin
    {$if not defined(_CONF_free_data_allownil)}
    _CONF_free_data := @ERR__CONF_free_data;
    {$ifend}
    {$if declared(_CONF_free_data_introduced)}
    if LibVersion < _CONF_free_data_introduced then
    begin
      {$if declared(FC__CONF_free_data)}
      _CONF_free_data := @FC__CONF_free_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(_CONF_free_data_removed)}
    if _CONF_free_data_removed <= LibVersion then
    begin
      {$if declared(__CONF_free_data)}
      _CONF_free_data := @__CONF_free_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(_CONF_free_data_allownil)}
    if FuncLoadError then
      AFailed.Add('_CONF_free_data');
    {$ifend}
  end;


end;

procedure Unload;
begin
  _CONF_new_section := nil;
  _CONF_get_section := nil;
  _CONF_add_string := nil;
  _CONF_get_string := nil;
  _CONF_get_number := nil;
  _CONF_new_data := nil;
  _CONF_free_data := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
