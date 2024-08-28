  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_cryptoerr.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_cryptoerr.h2pas
     and this file regenerated. IdOpenSSLHeaders_cryptoerr.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_cryptoerr;

interface

// Headers for OpenSSL 1.1.1
// cryptoerr.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

const
  (*
   * CRYPTO function codes.
   *)
  CRYPTO_F_CMAC_CTX_NEW = 120;
  CRYPTO_F_CRYPTO_DUP_EX_DATA = 110;
  CRYPTO_F_CRYPTO_FREE_EX_DATA = 111;
  CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;
  CRYPTO_F_CRYPTO_MEMDUP = 115;
  CRYPTO_F_CRYPTO_NEW_EX_DATA = 112;
  CRYPTO_F_CRYPTO_OCB128_COPY_CTX = 121;
  CRYPTO_F_CRYPTO_OCB128_INIT = 122;
  CRYPTO_F_CRYPTO_SET_EX_DATA = 102;
  CRYPTO_F_FIPS_MODE_SET = 109;
  CRYPTO_F_GET_AND_LOCK = 113;
  CRYPTO_F_OPENSSL_ATEXIT = 114;
  CRYPTO_F_OPENSSL_BUF2HEXSTR = 117;
  CRYPTO_F_OPENSSL_FOPEN = 119;
  CRYPTO_F_OPENSSL_HEXSTR2BUF = 118;
  CRYPTO_F_OPENSSL_INIT_CRYPTO = 116;
  CRYPTO_F_OPENSSL_LH_NEW = 126;
  CRYPTO_F_OPENSSL_SK_DEEP_COPY = 127;
  CRYPTO_F_OPENSSL_SK_DUP = 128;
  CRYPTO_F_PKEY_HMAC_INIT = 123;
  CRYPTO_F_PKEY_POLY1305_INIT = 124;
  CRYPTO_F_PKEY_SIPHASH_INIT = 125;
  CRYPTO_F_SK_RESERVE = 129;

  (*
   * CRYPTO reason codes.
   *)
  CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;
  CRYPTO_R_ILLEGAL_HEX_DIGIT = 102;
  CRYPTO_R_ODD_NUMBER_OF_DIGITS = 103;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM ERR_load_CRYPTO_strings}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  ERR_load_CRYPTO_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  function ERR_load_CRYPTO_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_CRYPTO_strings_procname = 'ERR_load_CRYPTO_strings';


{$WARN  NO_RETVAL OFF}
function  ERR_ERR_load_CRYPTO_strings: TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(ERR_load_CRYPTO_strings_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_CRYPTO_strings := LoadLibFunction(ADllHandle, ERR_load_CRYPTO_strings_procname);
  FuncLoadError := not assigned(ERR_load_CRYPTO_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_CRYPTO_strings_allownil)}
    ERR_load_CRYPTO_strings := @ERR_ERR_load_CRYPTO_strings;
    {$ifend}
    {$if declared(ERR_load_CRYPTO_strings_introduced)}
    if LibVersion < ERR_load_CRYPTO_strings_introduced then
    begin
      {$if declared(FC_ERR_load_CRYPTO_strings)}
      ERR_load_CRYPTO_strings := @FC_ERR_load_CRYPTO_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_CRYPTO_strings_removed)}
    if ERR_load_CRYPTO_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_CRYPTO_strings)}
      ERR_load_CRYPTO_strings := @_ERR_load_CRYPTO_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_CRYPTO_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_CRYPTO_strings');
    {$ifend}
  end;


end;

procedure Unload;
begin
  ERR_load_CRYPTO_strings := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
