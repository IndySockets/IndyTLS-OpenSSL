unit IdSSLOpenSSL_Utils;

interface
{$I IdCompilerDefines.inc}
{$i IdSSLOpenSSLDefines.inc}

uses
  IdCTypes,
  IdGlobal,
  IdGlobalProtocols,
  IdOpenSSLHeaders_asn1,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_ossl_typ,
  System.Classes;

type
  TIdSSLEVP_MD = record
    Length: TIdC_UINT;
    MD: Array [0 .. EVP_MAX_MD_SIZE - 1] of TIdAnsiChar;
  end;

function ASN1_OBJECT_ToStr(a: PASN1_OBJECT): String;
function LogicalAnd(a, B: Integer): Boolean;
function BytesToHexString(APtr: Pointer; ALen: Integer): String;
function MDAsString(const AMD: TIdSSLEVP_MD): String;
procedure DumpCert(AOut: TStrings; AX509: PX509);
function UTCTime2DateTime(UTCtime: PASN1_UTCTIME): TDateTime;
function UTC_Time_Decode(UTCtime: PASN1_UTCTIME;
  var year, month, day, hour, min, sec: Word;
  var tz_hour, tz_min: Integer): Integer;
function AddMins(const DT: TDateTime; const Mins: Extended): TDateTime;
function AddHrs(const DT: TDateTime; const Hrs: Extended): TDateTime;


implementation

uses IdOpenSSLHeaders_bio, IdOpenSSLHeaders_objects, IdOpenSSLHeaders_x509,
  System.SysUtils;

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

function UTC_Time_Decode(UTCtime: PASN1_UTCTIME;
  var year, month, day, hour, min, sec: Word;
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
  Result := 0; { default is to return with an error indication }
  if UTCtime^.Length < 12 then
  begin
    Exit;
  end;
{$IFDEF USE_MARSHALLED_PTRS}
  time_str := TMarshal.ReadStringAsAnsi(TPtrWrapper.Create(UTCtime^.data),
    UTCtime^.Length);
{$ELSE}
{$IFDEF STRING_IS_ANSI}
  SetString(time_str, PAnsiChar(UTCtime^.data), UTCtime^.Length);
{$ELSE}
  SetString(LTemp, PAnsiChar(UTCtime^.data), UTCtime^.Length);
  { Note: UTCtime is a type defined by OpenSSL and hence is ansistring and not UCS-2 }
  // TODO: do we need to use SetCodePage() here?
  time_str := String(LTemp); // explicit convert to Unicode
{$ENDIF}
{$ENDIF}
  // Check if first 12 chars are numbers
  if not IsNumeric(time_str, 12) then
  begin
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
  if year < 1950 then
  begin
    Inc(year, 100);
  end;
  // Check TZ
  tz_hour := 0;
  tz_min := 0;
  if CharIsInSet(time_str, 13, '-+') then
  begin { Do not Localize }
    tz_dir := iif(CharEquals(time_str, 13, '-'), -1, 1); { Do not Localize }
    for i := 14 to 18 do
    begin // Check if numbers are numbers
      if i = 16 then
      begin
        Continue;
      end;
      if not IsNumeric(time_str[i]) then
      begin
        Exit;
      end;
    end;
    tz_hour := IndyStrToInt(Copy(time_str, 14, 15)) * tz_dir;
    tz_min := IndyStrToInt(Copy(time_str, 17, 18)) * tz_dir;
  end;
  Result := 1; { everthing OK }
end;

function LogicalAnd(a, B: Integer): Boolean;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := (a and B) = B;
end;

function BytesToHexString(APtr: Pointer; ALen: Integer): String;
{$IFDEF USE_INLINE} inline; {$ENDIF}
var
  i: Integer;
  LPtr: PByte;
begin
  Result := '';
  LPtr := PByte(APtr);
  for i := 0 to (ALen - 1) do
  begin
    if i <> 0 then
    begin
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
  for i := 0 to AMD.Length - 1 do
  begin
    if i <> 0 then
    begin
      Result := Result + ':'; { Do not Localize }
    end;
    Result := Result + IndyFormat('%.2x', [Byte(AMD.MD[i])]);
    { do not localize }
  end;
end;

function ASN1_OBJECT_ToStr(a: PASN1_OBJECT): String;
var
  LBuf: array [0 .. 1024] of TIdAnsiChar;
  LNoName: TIdC_INT;
begin
  LNoName := 0;
  OBJ_obj2txt(@LBuf[0], 1024, a, LNoName);
  Result := String(LBuf);
end;

// Note that I define UTCtime as  PASN1_STRING
function UTCTime2DateTime(UTCtime: PASN1_UTCTIME): TDateTime;
{$IFDEF USE_INLINE} inline; {$ENDIF}
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
  if UTC_Time_Decode(UTCtime, year, month, day, hour, min, sec, tz_h, tz_m) > 0
  then
  begin
    Result := EncodeDate(year, month, day) + EncodeTime(hour, min, sec, 0);
    AddMins(Result, tz_m);
    AddHrs(Result, tz_h);
    Result := UTCTimeToLocalTime(Result);
  end;
end;

{$IFNDEF OPENSSL_NO_BIO}

procedure DumpCert(AOut: TStrings; AX509: PX509);
var
  LMem: PBIO;
  LLen: TIdC_INT;
  LBufPtr: PIdAnsiChar;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(X509_print) then
{$ENDIF}
  begin
    LMem := BIO_new(BIO_s_mem);
    if LMem <> nil then
    begin
      try
        X509_print(LMem, AX509);
        LLen := BIO_get_mem_data(LMem, LBufPtr);
        if (LLen > 0) and (LBufPtr <> nil) then
        begin
          AOut.Text := IndyTextEncoding_UTF8.GetString(
{$IFNDEF VCL_6_OR_ABOVE}
            // RLebeau: for some reason, Delphi 5 causes a "There is no overloaded
            // version of 'GetString' that can be called with these arguments" compiler
            // error if the PByte type-cast is used, even though GetString() actually
            // expects a PByte as input.  Must be a compiler bug, as it compiles fine
            // in Delphi 6.  So, converting to TIdBytes until I find a better solution...
            RawToBytes(LBufPtr^, LLen)
{$ELSE}
            PByte(LBufPtr), LLen
{$ENDIF}
            );
        end;
      finally
        BIO_free(LMem);
      end;
    end;
  end;
end;

{$ELSE}

procedure DumpCert(AOut: TStrings; AX509: PX509);
begin
end;

{$ENDIF}

end.
