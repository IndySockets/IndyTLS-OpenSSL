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

unit IdSSLOpenSSLAPI;

{$IFDEF FPC}
{$INTERFACES COM}
{$ENDIF}
{$J+}

interface

uses
  Classes
  {$IFDEF WINDOWS} ,windows {$ENDIF}
  {$IFDEF FPC}
  ,ctypes
  {$IFDEF UNIX}
  , UnixType, BaseUnix
  {$ENDIF}
  {$ENDIF}
  , SysUtils;

const
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  OpenSSL_Using_Dynamic_Library_Load = true;
  {$ENDIF}

  {The default SSLLibraryPath is empty. You can override this by setting the
   OPENSSL_LIBRARY_PATH environment variable to the absolute path of the location
   of your openssl library.}

  OpenSSLLibraryPath = 'OPENSSL_LIBRARY_PATH'; {environment variable name}
  {$IFNDEF OPENSSL_NO_MIN_VERSION}
  min_supported_ssl_version =  ((((((byte(1) shl 8) + byte(0)) shl 8) + byte (0)) shl 8) + byte(0)) shl 4; {1.0.0}
  {$ELSE}
  min_supported_ssl_version = 0;
  {$ENDIF}
  CLibCryptoBase = 'libcrypto';
  CLibSSLBase = 'libssl';

  {The following lists are used when trying to locate the libcrypto and libssl libraries.
   Default sufficies can be replaced by setting the IOpenSSLLoader.GetSSLLibVersions property}
  {$IFDEF OPENSSL_USE_STATIC_LIBRARY}
  CLibCrypto = '';
  CLibSSL = '';
  {$IFDEF FPC}
  {$LINKLIB ssl.a}
  {$LINKLIB crypto.a}
  {$ENDIF}
  {$ENDIF}

  {$IFDEF OPENSSL_USE_SHARED_LIBRARY}
    {$IFDEF UNIX}
    CLibCrypto = 'crypto';
    CLibSSL = 'ssl';
    {$ENDIF}
    {$IFDEF WINDOWS}
      {$IFDEF CPU64}
        CLibCrypto = 'libcrypto-3-x64.dll';
        CLibSSL = 'libssl-3-x64.dll';
      {$ENDIF}
      {$IFDEF CPU32}
        CLibCrypto = 'libcrypto-3.dll';
        CLibSSL = 'libssl-3.dll';
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}

    {$IFDEF UNIX}
  DirListDelimiter = ':';
  LibSuffix = '.so';
  DefaultLibVersions = ':.3:.1.1:.1.0.2:.1.0.0:.0.9.9:.0.9.8:.0.9.7:.0.9.6';
  {$ENDIF}
  {$IFDEF WINDOWS}
  DirListDelimiter = ';';
  LibSuffix = '';
  LegacyLibCrypto = 'libeay32';
  LegacyLibssl = 'ssleay32';

    {$IFDEF CPU64}
    DefaultLibVersions = '-3-x64;-1-x64';
    {$ENDIF}
    {$IFDEF CPU32}
    DefaultLibVersions = '-3;-1';
    {$ENDIF}
  {$ENDIF}

{$if not declared(TLibHandle)}
type
  TLibHandle = THandle;
{$ifend}
{$if not declared(NilHandle)}
const
  NilHandle = TLibHandle(0);
{$ifend}

{$if not declared(LineEnding)}
  {$IFDEF WINDOWS}
  const LineEnding = #$0D#$0A;
  {$ELSE}
  const LineEnding = #$0A;
  {$ENDIF}
{$ifend}

type
  {$IFDEF FPC}
  TOpenSSL_C_LONG  = cLong;
  TOpenSSL_C_ULONG = cuLong;
  TOpenSSL_C_INT   = cInt;
  TOpenSSL_C_UINT  = cuInt;
  TOpenSSL_C_INT64 = cint64;
  TOpenSSL_C_SHORT = cshort;
  TOpenSSL_C_UINT8 = cuint8;
  TOpenSSL_C_UINT16 = cuint16;
  TOpenSSL_C_UINT32 = cuint32;
  TOpenSSL_C_UINT64 = cuint64;
  TOpenSSL_C_USHORT = cushort;
  TOpenSSL_C_DOUBLE = cdouble;
  {$if declared(size_t)}
  TOpenSSL_C_SIZET = size_t;
  {$else}
  {$if declared(PtrUInt)}
  TOpenSSL_C_SIZET = PtrUInt;
  {$ELSE}
    {$IFDEF CPU32}
    TOpenSSL_C_SIZET = TOpenSSL_C_UINT32;
    {$ENDIF}
    {$IFDEF CPU64}
    TOpenSSL_C_SIZET = TOpenSSL_C_UINT64;
    {$ENDIF}
  {$ifend}
  {$ifend}
  {$if declared(ssize_t)}
  TOpenSSL_C_SSIZET = ssize_t;
  {$ELSE}
  {$if declared(PtrInt)}
  TOpenSSL_C_SSIZET = PtrInt;
    {$ELSE}
      {$IFDEF CPU32}
  TOpenSSL_C_SSIZET = TOpenSSL_C_INT32;
      {$ENDIF}
      {$IFDEF CPU64}
  TOpenSSL_C_SSIZET = TOpenSSL_C_INT64;
      {$ENDIF}
    {$ifend}
  {$ifend}
  {$if declared(time_t))}
  TOpenSSL_C_TIMET = time_t;
  {$ELSE}
    {$if declared(PtrInt)}
  TOpenSSL_C_TIMET = PtrInt;
    {$ELSE}
      {$IFDEF CPU32}
  TOpenSSL_C_TIMET = TOpenSSL_C_INT32;
      {$ENDIF}
      {$IFDEF CPU64}
  TOpenSSL_C_TIMET = TOpenSSL_C_INT64;
      {$ENDIF}
    {$ifend}
  {$ifend}

{$ELSE}
  PPByte           = ^PByte;
  PPPAnsiChar      = ^PAnsiChar;
  TOpenSSL_C_LONG  = LongInt;
  TOpenSSL_C_ULONG = LongWord;
  TOpenSSL_C_INT   = Integer;
  TOpenSSL_C_UINT  = Cardinal;
  TOpenSSL_C_INT64 = Int64;
  TOpenSSL_C_UINT8 = Byte;
  TOpenSSL_C_UINT16 = SmallInt;
  TOpenSSL_C_UINT32 = Cardinal;
  TOpenSSL_C_UINT64 = UINT64;
  TOpenSSL_C_SHORT = Smallint;
  TOpenSSL_C_USHORT = Word;
  TOpenSSL_C_DOUBLE = Double;
  {$if declared(size_t)}
  TOpenSSL_C_SIZET = size_t;
  {$else}
    {$if declared(NativeUInt)}
  TOpenSSL_C_SIZET = NativeUInt;
  {$else}
      {$IFDEF CPU32}
  TOpenSSL_C_SIZET = TOp/OpenSSLPackageSplitTake3enSSL_C_UINT32;
      {$ENDIF}
      {$IFDEF CPU64}
  TOpenSSL_C_SIZET = TOpenSSL_C_UINT64;
      {$ENDIF}
    {$ifend}
  {$ifend}

  {$if declared(NativeInt)}
TOpenSSL_C_SSIZET = NativeInt;
  {$ELSE}
    {$IFDEF CPU32}
TOpenSSL_C_SSIZET = TOpenSSL_C_INT32;
    {$ENDIF}
    {$IFDEF CPU64}
TOpenSSL_C_SSIZET = TOpenSSL_C_INT64;
    {$ENDIF}
  {$ifend}

  {$if declared(time_t))}
    TOpenSSL_C_TIMET = time_t;
    {$ELSE}
      {$if declared(NativeInt)}
    TOpenSSL_C_TIMET = NativeInt;
      {$ELSE}
        {$IFDEF CPU32}
    TOpenSSL_C_TIMET = TOpenSSL_C_INT32;
        {$ENDIF}
        {$IFDEF CPU64}
    TOpenSSL_C_TIMET = TOpenSSL_C_INT64;
        {$ENDIF}
      {$ifend}
    {$ifend}
{$ENDIF}
  POpenSSL_C_LONG   = ^TOpenSSL_C_LONG;
  POpenSSL_C_ULONG  = ^TOpenSSL_C_ULONG;
  POpenSSL_C_INT    = ^TOpenSSL_C_INT;
  POpenSSL_C_INT64  = ^TOpenSSL_C_INT64;
  POpenSSL_C_SIZET  = ^TOpenSSL_C_SIZET;
  POpenSSL_C_SSIZET = ^TOpenSSL_C_SSIZET;
  POpenSSL_C_UINT   = ^TOpenSSL_C_UINT;
  POpenSSL_C_UINT8  = ^TOpenSSL_C_UINT8;
  POpenSSL_C_UINT16 = ^TOpenSSL_C_UINT16;
  POpenSSL_C_UINT32 = ^TOpenSSL_C_UINT32;
  POpenSSL_C_UINT64 = ^TOpenSSL_C_UINT64;
  POpenSSL_C_SHORT  = ^TOpenSSL_C_SHORT;
  POpenSSL_C_USHORT = ^TOpenSSL_C_USHORT;
  POpenSSL_C_TIMET  = ^TOpenSSL_C_TIMET ;
  PPPByte           = ^PPByte;
  PPOpenSSL_C_INT   = ^POpenSSL_C_INT;
  POpenSSL_C_DOUBLE = ^TOpenSSL_C_DOUBLE;

  TOpenSSL_C_TM = record
    tm_sec: TOpenSSL_C_INT;         (* seconds,  range 0 to 59          *)
    tm_min: TOpenSSL_C_INT;         (* minutes, range 0 to 59           *)
    tm_hour: TOpenSSL_C_INT;        (* hours, range 0 to 23             *)
    tm_mday: TOpenSSL_C_INT;        (* day of the month, range 1 to 31  *)
    tm_mon: TOpenSSL_C_INT;         (* month, range 0 to 11             *)
    tm_year: TOpenSSL_C_INT;        (* The number of years since 1900   *)
    tm_wday: TOpenSSL_C_INT;        (* day of the week, range 0 to 6    *)
    tm_yday: TOpenSSL_C_INT;        (* day in the year, range 0 to 365  *)
    tm_isdst: TOpenSSL_C_INT;       (* daylight saving time             *)
  end;
  POpenSSL_C_TM = ^TOpenSSL_C_TM;
  PPOpenSSL_C_TM = ^POpenSSL_C_TM;

  IOpenSSL = interface
  ['{aed66223-1700-4199-b1c5-8222648e8cd5}']
    function GetOpenSSLPath: string;
    function GetOpenSSLVersionStr: string;
    function GetOpenSSLVersion: TOpenSSL_C_ULONG;
    function Init: boolean;
  end;

  function GetIOpenSSL: IOpenSSL;

type
  IOpenSSLDLL = interface(IOpenSSL)
  ['{1d6cd9e7-e656-4981-80d2-288b12a69306}']
    procedure SetOpenSSLPath(const Value: string);
    function GetSSLLibVersions: string;
    procedure SetSSLLibVersions(AValue: string);
    function GetSSLBaseLibName: string;
    procedure SetSSLBaseLibName(AValue: string);
    function GetCryptoBaseLibName: string;
    procedure SetCryptoBaseLibName(AValue: string);
    function GetAllowLegacyLibsFallback: boolean;
    procedure SetAllowLegacyLibsFallback(AValue: boolean);
    function GetLibCryptoHandle: TLibHandle;
    function GetLibSSLHandle: TLibHandle;
    function GetLibCryptoFilePath: string;
    function GetLibSSLFilePath: string;
    function GetFailedToLoadList: TStrings;
    function Load: Boolean;
    procedure Unload;
    function IsLoaded: boolean;
    property SSLLibVersions: string read GetSSLLibVersions write SetSSLLibVersions;
    property SSLBaseLibame: string read GetSSLBaseLibName write SetSSLBaseLibName;
    property CryptoBaseLibName: string read GetCryptoBaseLibName write SetCryptoBaseLibName;
    property AllowLegacyLibsFallback: boolean read GetAllowLegacyLibsFallback write SetAllowLegacyLibsFallback;
end;

function GetIOpenSSLDDL: IOpenSSLDLL;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
function LoadLibCryptoFunction(const AProcName: string): Pointer;
function LoadLibSSLFunction(const AProcName:  string): Pointer;

type
  TOpenSSLLoadProc = procedure(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
  TOpenSSLUnloadProc = procedure;

procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc);
procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);
{$ENDIF}

implementation

uses SyncObjs,
     IdOpenSSLHeaders_ssl,
     IdOpenSSLHeaders_crypto,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

type

  { TOpenSSLProvider }

  TOpenSSLStaticLibProvider = class(TInterfacedObject, IOpenSSL)
  private
    class var FOpenSSL: IOpenSSL;
  private
    FThreadLock: TCriticalSection;
    FOpenSSLPath: string;
  public
    constructor Create;
    destructor Destroy; override;
    property OpenSSLPath: string read FOpenSSLPath;
  public
    {IOpenSSL}
    function GetOpenSSLPath: string; virtual;
    function GetOpenSSLVersionStr: string; virtual;
    function GetOpenSSLVersion: TOpenSSL_C_ULONG; virtual;
    function Init: boolean; virtual;
  end;

  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}

  { TOpenSSLDynamicLibProvider }

  TOpenSSLDynamicLibProvider = class(TOpenSSLStaticLibProvider,IOpenSSLDLL)
  private
    class var FOpenSSLDDL: IOpenSSLDLL;
    class var FLibLoadList: TList;
    class var FUnLoadList: TList;
  private
    FLibCrypto: TLibHandle;
    FLibSSL: TLibHandle;
    FLibCryptoFilePath: string;
    FLibSSLFilePath: string;
    FFailed: TStringList;
    FSSLLibVersions: string;
    FFailedToLoad: boolean;
    FSSLBaseLibName: string;
    FCryptoBaseLibName: string;
    FAllowLegacyLibsFallback: boolean;
    function FindLibrary(LibName, LibVersions: string; var FilePath: string): TLibHandle;
  public
    constructor Create;
    destructor Destroy; override;
    {IOpenSSL}
    function GetOpenSSLPath: string; override;
    function GetOpenSSLVersionStr: string; override;
    function GetOpenSSLVersion: TOpenSSL_C_ULONG; override;
    function Init: boolean; override;
  public
    {IOpenSSLDLL}
    procedure SetOpenSSLPath(const Value: string);
    function GetSSLLibVersions: string;
    procedure SetSSLLibVersions(AValue: string);
    function GetSSLBaseLibName: string;
    procedure SetSSLBaseLibName(AValue: string);
    function GetCryptoBaseLibName: string;
    procedure SetCryptoBaseLibName(AValue: string);
    function GetAllowLegacyLibsFallback: boolean;
    procedure SetAllowLegacyLibsFallback(AValue: boolean);
    function GetLibCryptoHandle: TLibHandle;
    function GetLibSSLHandle: TLibHandle;
    function GetLibCryptoFilePath: string;
    function GetLibSSLFilePath: string;
    function GetFailedToLoadList: TStrings;
    function Load: Boolean;
    procedure Unload;
    function IsLoaded: boolean;
  end;
  {$ENDIF}

{ TOpenSSLProvider }

constructor TOpenSSLStaticLibProvider.Create;
begin
  inherited Create;
  FThreadLock := TCriticalSection.Create;
  FOpenSSLPath := GetEnvironmentVariable(OpenSSLLibraryPath)
end;

destructor TOpenSSLStaticLibProvider.Destroy;
begin
  if FThreadLock <> nil then FThreadLock.Free;
  inherited Destroy;
end;

function TOpenSSLStaticLibProvider.GetOpenSSLPath : string;
begin
  Result := OpenSSL_version(OPENSSL_DIR);
end;

function TOpenSSLStaticLibProvider.GetOpenSSLVersionStr : string;
begin
  Result := OpenSSL_Version(OPENSSL_VERSION_CONST);
end;

function TOpenSSLStaticLibProvider.GetOpenSSLVersion : TOpenSSL_C_ULONG;
begin
  Result := OpenSSL_version_num;
end;

{$IFDEF OPENSSL_SET_MEMORY_FUNCS}

function OpenSSLMalloc(num: UInt32): Pointer cdecl;
begin
  Result := AllocMem(num);
end;

function OpenSSLRealloc(addr: Pointer; num: UInt32): Pointer cdecl;
begin
  Result := addr;
  ReallocMem(Result, num);
end;

procedure OpenSSLFree(addr: Pointer)cdecl;
begin
  FreeMem(addr);
end;

procedure OpenSSLCryptoMallocInit;
// replaces the actual alloc routines
// this is useful if you are using a memory manager that can report on leaks
// at shutdown time.
var
  r: Integer;
begin
  r := CRYPTO_set_mem_functions(@OpenSSLMalloc, @OpenSSLRealloc, @OpenSSLFree);
  Assert(r <> 0);
end;
{$ENDIF}

function TOpenSSLStaticLibProvider.Init: boolean;
begin
  Result := true;
  FThreadLock.Acquire;
  try
    {$IFDEF OPENSSL_SET_MEMORY_FUNCS}
        // has to be done before anything that uses memory
        OpenSSLCryptoMallocInit;
    {$ENDIF}
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_ADD_ALL_CIPHERS or
                     OPENSSL_INIT_ADD_ALL_DIGESTS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS or
                     OPENSSL_INIT_LOAD_CONFIG or OPENSSL_INIT_ASYNC or
                     OPENSSL_INIT_ENGINE_ALL_BUILTIN ,nil);

    if GetOpenSSLVersion < CRYPTO_set_locking_callback_removed then
      SetLegacyCallbacks;
  finally
    FThreadLock.Release;
  end;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
function TOpenSSLDynamicLibProvider.FindLibrary(LibName , LibVersions : string;
  var FilePath : string) : TLibHandle;

  function DoLoadLibrary(FullLibName: string): TLibHandle;
  begin
    Result := SafeLoadLibrary(FullLibName, {$IFDEF WINDOWS}SEM_FAILCRITICALERRORS {$ELSE} 0 {$ENDIF});
    if Result <> NilHandle then
    {$if defined(FPC) and defined(UNIX)}
      FilePath := fpReadLink(FullLibName);
    {$else}
      FilePath := FullLibName;
    {$ifend}
  end;

var LibVersionsList: TStringList;
    i: integer;
begin
  Result := NilHandle;
  if LibVersions <> '' then
  begin
    LibVersionsList := TStringList.Create;
    try
      LibVersionsList.Delimiter := DirListDelimiter;
      LibVersionsList.StrictDelimiter := true;
      LibVersionsList.DelimitedText := LibVersions; {Split list on delimiter}
      for i := 0 to LibVersionsList.Count - 1 do
      begin
        Result := DoLoadLibrary(OpenSSLPath + LibName + LibVersionsList[i]);
        if Result <> NilHandle then
          break;
      end;
    finally
       LibVersionsList.Free;
    end;
  end;
end;

constructor TOpenSSLDynamicLibProvider.Create;
begin
  inherited Create;
  FFailed := TStringList.Create();
  FSSLLibVersions := DefaultLibVersions;
  FSSLBaseLibName := CLibSSLBase;
  FCryptoBaseLibName := CLibCryptoBase;
  FAllowLegacyLibsFallback := false;
end;

destructor TOpenSSLDynamicLibProvider.Destroy;
begin
  Unload;
  if FFailed <> nil then  FFailed.Free;
  inherited Destroy;
end;

function TOpenSSLDynamicLibProvider.GetOpenSSLPath : string;
begin
  if not IsLoaded then
    Result := FOpenSSLPath
  else
    Result := inherited GetOpenSSLPath;
end;

function TOpenSSLDynamicLibProvider.GetOpenSSLVersionStr : string;
begin
  if not IsLoaded then
    Load;
  Result := inherited GetOpenSSLVersionStr;
end;

function TOpenSSLDynamicLibProvider.GetOpenSSLVersion : TOpenSSL_C_ULONG;
begin
  if not IsLoaded then
    Load;
  Result := inherited GetOpenSSLVersion;
end;

function TOpenSSLDynamicLibProvider.Init : boolean;
begin
  Result := Load;
end;

function LoadLibCryptoFunction(const AProcName: string): Pointer;
begin
  Result := GetProcAddress(TOpenSSLDynamicLibProvider.FOpenSSLDDL.GetLibCryptoHandle,PChar(AProcName));
end;

function LoadLibSSLFunction(const AProcName:  string): Pointer;
begin
  Result := GetProcAddress(TOpenSSLDynamicLibProvider.FOpenSSLDDL.GetLibSSLHandle,PChar(AProcName));
end;

procedure TOpenSSLDynamicLibProvider.SetOpenSSLPath(const Value : string);
begin
  if Value = '' then
    FOpenSSLPath := ''
  else
    FOpenSSLPath := IncludeTrailingPathDelimiter(Value);
end;

function TOpenSSLDynamicLibProvider.GetSSLLibVersions : string;
begin
  Result := FSSLLibVersions;
end;

procedure TOpenSSLDynamicLibProvider.SetSSLLibVersions(AValue : string);
begin
  if FSSLLibVersions <> AValue then
    UnLoad;
  FSSLLibVersions := AValue;
end;

function TOpenSSLDynamicLibProvider.GetSSLBaseLibName: string;
begin
  Result := FSSLBaseLibName;
end;

procedure TOpenSSLDynamicLibProvider.SetSSLBaseLibName(AValue: string);
begin
  if FSSLBaseLibName <> AValue then
    UnLoad;
  FSSLBaseLibName := AValue;
end;

function TOpenSSLDynamicLibProvider.GetCryptoBaseLibName: string;
begin
  Result := FCryptoBaseLibName;
end;

procedure TOpenSSLDynamicLibProvider.SetCryptoBaseLibName(AValue: string);
begin
  if FCryptoBaseLibName <> AValue then
    UnLoad;
  FCryptoBaseLibName := AValue;
end;

function TOpenSSLDynamicLibProvider.GetAllowLegacyLibsFallback: boolean;
begin
  Result := FAllowLegacyLibsFallback;
end;

procedure TOpenSSLDynamicLibProvider.SetAllowLegacyLibsFallback(AValue: boolean
  );
begin
  if FAllowLegacyLibsFallback <> AValue then
    Unload;
  FAllowLegacyLibsFallback := AValue;
end;

function TOpenSSLDynamicLibProvider.GetLibCryptoHandle : TLibHandle;
begin
  if (FLibCrypto = NilHandle) and not FFailedToLoad then Load;
  Result := FLibCrypto;
end;

function TOpenSSLDynamicLibProvider.GetLibSSLHandle : TLibHandle;
begin
  if (FLibSSL = NilHandle) and not FFailedToLoad then Load;
  Result := FLibSSL;
end;

function TOpenSSLDynamicLibProvider.GetLibCryptoFilePath : string;
begin
  if (FLibCrypto = NilHandle) and not FFailedToLoad then Load;
  Result := FLibCryptoFilePath;
end;

function TOpenSSLDynamicLibProvider.GetLibSSLFilePath : string;
begin
  if (FLibSSL = NilHandle) and not FFailedToLoad then Load;
  Result := FLibSSLFilePath;
end;

function TOpenSSLDynamicLibProvider.GetFailedToLoadList : TStrings;
begin
  Result := FFailed;
end;

function TOpenSSLDynamicLibProvider.Load : Boolean;
type
  TOpenSSL_version_num = function: TOpenSSL_C_ULONG; cdecl;
var i: integer;
    OpenSSL_version_num: TOpenSSL_version_num;
    SSLVersionNo: TOpenSSL_C_ULONG;
begin
  Result := not FFailedToLoad;
  if not Result  then
    Exit;

  FThreadLock.Acquire;
  try
    if not IsLoaded then
    begin
      FLibCrypto := FindLibrary(FCryptoBaseLibName + LibSuffix,FSSLLibVersions,FLibCryptoFilePath);
      FLibSSL := FindLibrary(FSSLBaseLibName + LibSuffix,FSSLLibVersions,FLibSSLFilePath);
      Result := not (FLibCrypto = NilHandle) and not (FLibSSL = NilHandle);
      {$IFDEF WINDOWS}
      if not Result and FAllowLegacyLibsFallback then
      begin
        {try the legacy dll names}
        FLibCrypto := FindLibrary(LegacyLibCrypto,'',FLibCryptoFilePath);
        FLibSSL := FindLibrary(LegacyLibssl,'',FLibSSLFilePath);
        Result := not (FLibCrypto = NilHandle) and not (FLibSSL = NilHandle);
      end;
      {$ENDIF}
      if not Result then
        Exit;

      {Load Version number}
      OpenSSL_version_num := LoadLibCryptoFunction('OpenSSL_version_num');
      if not assigned(OpenSSL_version_num) then
          OpenSSL_version_num := LoadLibCryptoFunction('SSLeay');
      if not assigned(OpenSSL_version_num) then
        raise EOpenSSLError.Create(ROSSLCantGetSSLVersionNo);

      SSLVersionNo := OpenSSL_version_num();

      if SSLVersionNo < min_supported_ssl_version then  {remove patch and dev flag}
        raise EOpenSSLError.CreateFmt(RSOSSUnsupportedVersion,[SSLVersionNo]);

      for i := 0 to FLibLoadList.Count - 1 do
        TOpenSSLLoadProc(FLibLoadList[i])(SSLVersionNo,FFailed);

    end;

  finally
    FThreadLock.Release;
  end;
  Result := inherited Init;
end;

procedure TOpenSSLDynamicLibProvider.Unload;
var i: integer;
begin
  FThreadLock.Acquire;
  try
    if IsLoaded  then
    begin
      RemoveLegacyCallbacks;
      for i := 0 to FUnLoadList.Count - 1 do
         TOpenSSLUnloadProc(FUnLoadList[i]);

      FFailed.Clear();

      if FLibSSL <> NilHandle then
        FreeLibrary(FLibSSL);
      if FLibCrypto <> NilHandle then
        FreeLibrary(FLibCrypto);
      FLibSSL := NilHandle;
      FLibCrypto := NilHandle;
    end;
    FFailedToLoad := false;
  finally
    FThreadLock.Release;
  end;
end;

function TOpenSSLDynamicLibProvider.IsLoaded : boolean;
begin
  Result := (FLibCrypto <> Nilhandle) and (FLibSSL <> Nilhandle);
end;
{$ENDIF}

const InitUnitDone: boolean = false;

procedure InitUnit;
begin
  if not InitUnitDone then
  begin
    {$IFDEF OPENSSL_STATIC_LINK_MODEL}
    TOpenSSLStaticLibProvider.FOpenSSL := TOpenSSLStaticLibProvider.Create;
    {$ELSE}
    TOpenSSLStaticLibProvider.FOpenSSL := TOpenSSLDynamicLibProvider.Create;
    TOpenSSLDynamicLibProvider.FOpenSSLDDL := TOpenSSLDynamicLibProvider.FOpenSSL as IOpenSSLDLL;
    TOpenSSLDynamicLibProvider.FLibLoadList := TList.Create;
    TOpenSSLDynamicLibProvider.FUnLoadList := TList.Create;
    {$ENDIF};
    InitUnitDone := true;
  end;
end;

function GetIOpenSSL: IOpenSSL;
begin
  InitUnit;
  Result := TOpenSSLStaticLibProvider.FOpenSSL;
end;

function GetIOpenSSLDDL: IOpenSSLDLL;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := nil;
  {$ELSE}
  InitUnit;
  Result := TOpenSSLDynamicLibProvider.FOpenSSLDDL;
  {$ENDIF}
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Register_SSLLoader(LoadProc : TOpenSSLLoadProc);
begin
  InitUnit;
  TOpenSSLDynamicLibProvider.FLibLoadList.Add(@LoadProc);
end;

procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);
begin
  InitUnit;
  TOpenSSLDynamicLibProvider.FUnLoadList.Add(@UnloadProc);
end;
{$ENDIF}

initialization
  InitUnit;

finalization
  TOpenSSLStaticLibProvider.FOpenSSL := nil;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TOpenSSLDynamicLibProvider.FOpenSSLDDL := nil;
  FreeAndNil(TOpenSSLDynamicLibProvider.FLibLoadList);
  FreeAndNil(TOpenSSLDynamicLibProvider.FUnLoadList);
  {$ENDIF}
end.


