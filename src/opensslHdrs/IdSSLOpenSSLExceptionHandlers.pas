{$i IdSSLOpenSSLDefines.inc}

{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.

    This file includes software copied from the Indy (Internet Direct) project, and which is offered
    under the dual-licensing agreement described on the Indy website. (https://www.indyproject.org/license/)
    }

unit IdSSLOpenSSLExceptionHandlers;

interface

uses
  Classes, SysUtils, IdSSLOpenSSLAPI;

type
  EOpenSSLError       = class(Exception);
  TOpenSSLAPISSLError = class of EOpenSSLAPISSLError;

  EOpenSSLAPISSLError = class(EOpenSSLError)
  protected
    FErrorCode : TOpenSSL_C_INT;
    FRetCode : TOpenSSL_C_INT;
  public
    class procedure RaiseException(ASSL: Pointer; const ARetCode : TOpenSSL_C_INT; const AMsg : String = '');
    class procedure RaiseExceptionCode(const AErrCode, ARetCode : TOpenSSL_C_INT; const AMsg : String = '');
    property ErrorCode : TOpenSSL_C_INT read FErrorCode;
    property RetCode : TOpenSSL_C_INT read FRetCode;
  end;

  TSSLOpenSSLAPICryptoError = class of EOpenSSLAPICryptoError;
  EOpenSSLAPICryptoError = class(EOpenSSLError)
  protected
    FErrorCode : TOpenSSL_C_ULONG;
  public
    class procedure RaiseExceptionCode(const AErrCode : TOpenSSL_C_ULONG; const AMsg : String = '');
    class procedure RaiseException(const AMsg : String = '');
    property ErrorCode : TOpenSSL_C_ULONG read FErrorCode;
  end;
  EOpenSSLUnderlyingCryptoError = class(EOpenSSLAPICryptoError);
  EOpenSSLUnknownError = class(EOpenSSLAPICryptoError);

  { EOpenSSLAPIFunctionNotPresent }

  EOpenSSLAPIFunctionNotPresent = class(EOpenSSLError)
  public
    class procedure RaiseException(functionName: string);
  end;

implementation

uses IdOpenSSLHeaders_err,
     IdOpenSSLHeaders_ssl,
     IdOpenSSLHeaders_ossl_typ,
     IdSSLOpenSSLResourceStrings;

function GetErrorMessage(const AErr : TOpenSSL_C_ULONG) : String;
const
  sMaxErrMsg = 160;
var
  ErrMsg: array [0..sMaxErrMsg] of AnsiChar;
begin
  ERR_error_string_n(AErr, ErrMsg, sMaxErrMsg);
  ErrMsg[sMaxErrMsg] := #0;
  Result := strpas(PAnsiChar(@ErrMsg));;
end;

{ EAPIFunctionNotPresent }

class procedure EOpenSSLAPIFunctionNotPresent.RaiseException(functionName: string);
begin
  raise EOpenSSLAPIFunctionNotPresent.CreateFmt(ROSSLAPIFunctionNotPresent,[functionName]);
end;

{ EOpenSSLAPICryptoError }
class procedure EOpenSSLAPICryptoError.RaiseException(const AMsg : String = '');
begin
  RaiseExceptionCode(ERR_get_error(), AMsg);
end;

class procedure EOpenSSLAPICryptoError.RaiseExceptionCode(
  const AErrCode: TOpenSSL_C_ULONG; const AMsg: String);
var
  LMsg: String;
  LException : EOpenSSLAPICryptoError;
begin
  if AMsg <> '' then begin
    LMsg := AMsg + LineEnding + GetErrorMessage(AErrCode);
  end else begin
    LMsg := GetErrorMessage(AErrCode);
  end;
  LException := Create(LMsg);
  LException.FErrorCode := AErrCode;
  raise LException;
end;

{ EOpenSSLAPISSLError }

class procedure EOpenSSLAPISSLError.RaiseException(ASSL: Pointer; const ARetCode: TOpenSSL_C_INT;
  const AMsg: String);
begin
  RaiseExceptionCode(SSL_get_error(PSSL(ASSL), ARetCode), ARetCode, AMsg);
end;

class procedure EOpenSSLAPISSLError.RaiseExceptionCode(const AErrCode, ARetCode: TOpenSSL_C_INT;
  const AMsg: String);
var
  LErrQueue : TOpenSSL_C_ULONG;
  LException : EOpenSSLAPISSLError;
  LErrStr : String;
begin
  if AMsg <> '' then begin
    LErrStr := AMsg + LineEnding;
  end else begin
    LErrStr := '';
  end;
  case AErrCode of
    SSL_ERROR_SYSCALL :
    begin
      LErrQueue := ERR_get_error;
      if LErrQueue <> 0 then begin
        EOpenSSLUnderlyingCryptoError.RaiseExceptionCode(LErrQueue, AMsg);
      end;
      if ARetCode = 0 then begin
        LException := Create(LErrStr + ROSSLEOFViolation);
        LException.FErrorCode := AErrCode;
        LException.FRetCode := ARetCode;
        raise LException;
      end;
      raise EOpenSSLUnknownError.Create(RSOUnknown);
    end;

    SSL_ERROR_SSL :
      EOpenSSLUnderlyingCryptoError.RaiseException(AMsg);

  end;
  // everything else...
  LException := Create(LErrStr + GetErrorMessage(AErrCode));
  LException.FErrorCode := AErrCode;
  LException.FRetCode := ARetCode;
  raise LException;
end;

end.


