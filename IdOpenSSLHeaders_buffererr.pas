  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_buffererr.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_buffererr.h2pas
     and this file regenerated. IdOpenSSLHeaders_buffererr.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_buffererr;

interface

// Headers for OpenSSL 1.1.1
// buffererr.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
// BUF function codes.
  BUF_F_BUF_MEM_GROW = 100;
  BUF_F_BUF_MEM_GROW_CLEAN = 105;
  BUF_F_BUF_MEM_NEW = 101;

// BUF reason codes.

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM ERR_load_BUF_strings}

{$IFNDEF USE_EXTERNAL_LIBRARY}
var
  ERR_load_BUF_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  function ERR_load_BUF_strings: TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

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
  ERR_load_BUF_strings_procname = 'ERR_load_BUF_strings';


{$WARN  NO_RETVAL OFF}
function  ERR_ERR_load_BUF_strings: TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(ERR_load_BUF_strings_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_BUF_strings := LoadLibFunction(ADllHandle, ERR_load_BUF_strings_procname);
  FuncLoadError := not assigned(ERR_load_BUF_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_BUF_strings_allownil)}
    ERR_load_BUF_strings := @ERR_ERR_load_BUF_strings;
    {$ifend}
    {$if declared(ERR_load_BUF_strings_introduced)}
    if LibVersion < ERR_load_BUF_strings_introduced then
    begin
      {$if declared(FC_ERR_load_BUF_strings)}
      ERR_load_BUF_strings := @FC_ERR_load_BUF_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_BUF_strings_removed)}
    if ERR_load_BUF_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_BUF_strings)}
      ERR_load_BUF_strings := @_ERR_load_BUF_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_BUF_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_BUF_strings');
    {$ifend}
  end;


end;

procedure Unload;
begin
  ERR_load_BUF_strings := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF USE_EXTERNAL_LIBRARY}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
