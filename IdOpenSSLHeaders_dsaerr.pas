  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_dsaerr.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_dsaerr.h2pas
     and this file regenerated. IdOpenSSLHeaders_dsaerr.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_dsaerr;

interface

// Headers for OpenSSL 1.1.1
// dsaerr.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
  ///*
  // * DSA function codes.
  // */
  DSA_F_DSAPARAMS_PRINT = 100;
  DSA_F_DSAPARAMS_PRINT_FP = 101;
  DSA_F_DSA_BUILTIN_PARAMGEN = 125;
  DSA_F_DSA_BUILTIN_PARAMGEN2 = 126;
  DSA_F_DSA_DO_SIGN = 112;
  DSA_F_DSA_DO_VERIFY = 113;
  DSA_F_DSA_METH_DUP = 127;
  DSA_F_DSA_METH_NEW = 128;
  DSA_F_DSA_METH_SET1_NAME = 129;
  DSA_F_DSA_NEW_METHOD = 103;
  DSA_F_DSA_PARAM_DECODE = 119;
  DSA_F_DSA_PRINT_FP = 105;
  DSA_F_DSA_PRIV_DECODE = 115;
  DSA_F_DSA_PRIV_ENCODE = 116;
  DSA_F_DSA_PUB_DECODE = 117;
  DSA_F_DSA_PUB_ENCODE = 118;
  DSA_F_DSA_SIGN = 106;
  DSA_F_DSA_SIGN_SETUP = 107;
  DSA_F_DSA_SIG_NEW = 102;
  DSA_F_OLD_DSA_PRIV_DECODE = 122;
  DSA_F_PKEY_DSA_CTRL = 120;
  DSA_F_PKEY_DSA_CTRL_STR = 104;
  DSA_F_PKEY_DSA_KEYGEN = 121;

  ///*
  // * DSA reason codes.
  // */
  DSA_R_BAD_Q_VALUE = 102;
  DSA_R_BN_DECODE_ERROR = 108;
  DSA_R_BN_ERROR = 109;
  DSA_R_DECODE_ERROR = 104;
  DSA_R_INVALID_DIGEST_TYPE = 106;
  DSA_R_INVALID_PARAMETERS = 112;
  DSA_R_MISSING_PARAMETERS = 101;
  DSA_R_MISSING_PRIVATE_KEY = 111;
  DSA_R_MODULUS_TOO_LARGE = 103;
  DSA_R_NO_PARAMETERS_SET = 107;
  DSA_R_PARAMETER_ENCODING_ERROR = 105;
  DSA_R_Q_NOT_PRIME = 113;
  DSA_R_SEED_LEN_SMALL = 110;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM ERR_load_DSA_strings}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  ERR_load_DSA_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  function ERR_load_DSA_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_DSA_strings_procname = 'ERR_load_DSA_strings';


{$WARN  NO_RETVAL OFF}
function  ERR_ERR_load_DSA_strings: TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(ERR_load_DSA_strings_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_DSA_strings := LoadLibFunction(ADllHandle, ERR_load_DSA_strings_procname);
  FuncLoadError := not assigned(ERR_load_DSA_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_DSA_strings_allownil)}
    ERR_load_DSA_strings := @ERR_ERR_load_DSA_strings;
    {$ifend}
    {$if declared(ERR_load_DSA_strings_introduced)}
    if LibVersion < ERR_load_DSA_strings_introduced then
    begin
      {$if declared(FC_ERR_load_DSA_strings)}
      ERR_load_DSA_strings := @FC_ERR_load_DSA_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_DSA_strings_removed)}
    if ERR_load_DSA_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_DSA_strings)}
      ERR_load_DSA_strings := @_ERR_load_DSA_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_DSA_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_DSA_strings');
    {$ifend}
  end;


end;

procedure Unload;
begin
  ERR_load_DSA_strings := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
