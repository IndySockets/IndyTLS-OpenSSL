unit IdSSLOpenSSLUtils;

{
  $Project$
  $Workfile$
  $Revision$
  $DateUTC$
  $Id$
  }
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
  {   (c) 1993-2024, the Indy Pit Crew. All rights reserved.   }
  {                                                                              }
  {******************************************************************************}
  {                                                                              }
  {        Contributers:                                                         }
  {         Source code extracted from IdSSLOpenSSL by Tony Whyman (MWA Software)}
  {         tony@mwasoftware.co.uk                                               }
  {                                                                              }
  {******************************************************************************}

{
  $Log$
}

interface

{$I IdCompilerDefines.inc}

{$IFNDEF USE_OPENSSL}
  {$message error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}

uses
  Classes,
  SysUtils,
  IdCTypes,
  IdGlobal,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_ossl_typ
;

type
  TIdSSLEVP_MD = record
    Length: TIdC_UINT;
    MD: Array [0 .. EVP_MAX_MD_SIZE - 1] of TIdAnsiChar;
  end;

function MDAsString(const AMD: TIdSSLEVP_MD): String;
function BytesToHexString(APtr: Pointer; ALen: Integer): String;
function UTCTime2DateTime(UTCtime: PASN1_UTCTIME): TDateTime;

procedure InitializeRandom;
procedure CleanupRandom;

implementation

function AddMins(const DT: TDateTime; const Mins: Extended): TDateTime;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := DT + Mins / (60 * 24)
end;

function AddHrs(const DT: TDateTime; const Hrs: Extended): TDateTime;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := DT + Hrs / 24.0;
end;

function UTC_Time_Decode(UTCtime : PASN1_UTCTIME; var year, month, day, hour, min, sec: Word;
  var tz_hour, tz_min: Integer): Integer;
var
  i, tz_dir: Integer;
  time_str: string;
  {$IFNDEF USE_MARSHALLED_PTRS}
    {$IFNDEF STRING_IS_ANSI}
  LTemp: AnsiString;
    {$ENDIF}
  {$ENDIF}
begin
  Result := 0; {default is to return with an error indication}
  if UTCtime^.length < 12 then begin
    Exit;
  end;
  {$IFDEF USE_MARSHALLED_PTRS}
  time_str := TMarshal.ReadStringAsAnsi(TPtrWrapper.Create(UTCtime^.data), UTCtime^.length);
  {$ELSE}
    {$IFDEF STRING_IS_ANSI}
  SetString(time_str, PAnsiChar(UTCtime^.data), UTCtime^.length);
    {$ELSE}
  SetString(LTemp, PAnsiChar(UTCtime^.data), UTCtime^.length);   {Note: UTCtime is a type defined by OpenSSL and hence is ansistring and not UCS-2}
  // TODO: do we need to use SetCodePage() here?
  time_str := String(LTemp); // explicit convert to Unicode
    {$ENDIF}
  {$ENDIF}
  // Check if first 12 chars are numbers
  if not IsNumeric(time_str, 12) then begin
    Exit;
  end;
  // Convert time from string to number
  year := IndyStrToInt(Copy(time_str, 1, 2)) + 1900;
  month := IndyStrToInt(Copy(time_str, 3, 2));
  day := IndyStrToInt(Copy(time_str, 5, 2));
  hour := IndyStrToInt(Copy(time_str, 7, 2));
  min := IndyStrToInt(Copy(time_str, 9, 2));
  sec := IndyStrToInt(Copy(time_str, 11, 2));
  // Fix year. This function is Y2k but isn't compatible with Y2k5 :-(    {Do not Localize}
  if year < 1950 then begin
    Inc(year, 100);
  end;
  // Check TZ
  tz_hour := 0;
  tz_min := 0;
  if CharIsInSet(time_str, 13, '-+') then begin    {Do not Localize}
    tz_dir := iif(CharEquals(time_str, 13, '-'), -1, 1);    {Do not Localize}
    for i := 14 to 18 do begin  // Check if numbers are numbers
      if i = 16 then begin
        Continue;
      end;
      if not IsNumeric(time_str[i]) then begin
        Exit;
      end;
    end;
    tz_hour := IndyStrToInt(Copy(time_str, 14, 15)) * tz_dir;
    tz_min  := IndyStrToInt(Copy(time_str, 17, 18)) * tz_dir;
  end;
  Result := 1; {everthing OK}
end;

// Note that I define UTCtime as  PASN1_STRING
function UTCTime2DateTime(UTCtime: PASN1_UTCTIME): TDateTime;
var
  year: Word;
  month: Word;
  day: Word;
  hour: Word;
  min: Word;
  sec: Word;
  tz_h: Integer;
  tz_m: Integer;
begin
  Result := 0;
  if UTC_Time_Decode(UTCtime, year, month, day, hour, min, sec, tz_h, tz_m) > 0 then begin
    Result := EncodeDate(year, month, day) + EncodeTime(hour, min, sec, 0);
    AddMins(Result, tz_m);
    AddHrs(Result, tz_h);
    Result := UTCTimeToLocalTime(Result);
  end;
end;

function BytesToHexString(APtr: Pointer; ALen: Integer): String;
{$IFDEF USE_INLINE} inline; {$ENDIF}
var
  i: Integer;
  LPtr: PByte;
begin
  Result := '';
  LPtr := PByte(APtr);
  for i := 0 to (ALen - 1) do begin
    if i <> 0 then begin
      Result := Result + ':'; { Do not Localize }
    end;
    Result := Result + IndyFormat('%.2x', [LPtr^]);
    Inc(LPtr);
  end;
end;

function MDAsString(const AMD: TIdSSLEVP_MD): String;
{$IFDEF USE_INLINE} inline; {$ENDIF}
var
  i: Integer;
begin
  Result := '';
  for i := 0 to AMD.Length - 1 do begin
    if i <> 0 then begin
      Result := Result + ':'; { Do not Localize }
    end;
    Result := Result + IndyFormat('%.2x', [Byte(AMD.MD[i])]);
    { do not localize }
  end;
end;

{
Not sure why these (unused) functions exist. Candiates for code deletion.
}

type
  TRAND_bytes = function(buf : PIdAnsiChar; num : integer) : integer; cdecl;
  TRAND_pseudo_bytes = function(buf : PIdAnsiChar; num : integer) : integer; cdecl;
  TRAND_seed = procedure(buf : PIdAnsiChar; num : integer); cdecl;
  TRAND_add = procedure(buf : PIdAnsiChar; num : integer; entropy : integer); cdecl;
  TRAND_status = function() : integer; cdecl;
  {$IFDEF SYS_WIN}
  TRAND_event = function(iMsg : UINT; wp : wparam; lp : lparam) : integer; cdecl;
  {$ENDIF}
  TRAND_cleanup = procedure; cdecl;

var
  _RAND_cleanup : TRAND_cleanup = nil;
  _RAND_bytes : TRAND_bytes = nil;
  _RAND_pseudo_bytes : TRAND_pseudo_bytes = nil;
  _RAND_seed : TRAND_seed = nil;
  _RAND_add : TRAND_add = nil;
  _RAND_status : TRAND_status = nil;
  {$IFDEF SYS_WIN}
  // LIBEAY functions - open SSL 0.9.6a
  _RAND_screen : procedure cdecl = nil;
  _RAND_event : TRAND_event = nil;
  {$ENDIF}

  procedure InitializeRandom;
  begin
    {$IFDEF SYS_WIN}
    if Assigned(_RAND_screen) then begin
      _RAND_screen;
    end;
    {$ENDIF}
  end;

  procedure CleanupRandom;
  begin
    if Assigned(_RAND_cleanup) then begin
      _RAND_cleanup;
    end;
  end;


end.

