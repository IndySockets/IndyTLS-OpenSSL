unit IdSSLOpenSSLSocket;

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
  {   (c) 1993-2025, the Indy Pit Crew. All rights reserved.   }
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

uses
  Classes,
  SysUtils,
  IdCTypes,
  IdGlobal,
  IdStackConsts,
  IdSSLOpenSSLX509,
  IdSSLOpenSSLExceptionHandlers,
  IdOpenSSLHeaders_ssl,
  IdSSLOpenSSLOptions,
  IdOpenSSLHeaders_ossl_typ
  ;

{$I IdCompilerDefines.inc}

{$IFDEF WINDOWS}
{$IFNDEF OPENSSL_DONT_USE_WINDOWS_CERT_STORE}
{$DEFINE USE_WINDOWS_CERT_STORE}
{$ENDIF}
{$ENDIF}

{$IFNDEF USE_OPENSSL}
  {$message error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}

type

  TIdSSLByteArray = record
    Length: TIdC_UINT;
    Data: PByte;
  end;

  TIdSSLReadStatus = (sslDataAvailable, sslNoData, sslEOF, sslUnrecoverableError);

  TIdSSLSocket = class;

  // TIdSSLIOHandlerSocketOpenSSL and TIdServerIOHandlerSSLOpenSSL have some common
  // functions, but they do not have a common ancestor, so this interface helps
  // bridge the gap...
  IIdSSLOpenSSLCallbackHelper = interface(IInterface)
    ['{583F1209-10BA-4E06-8810-155FAEC415FE}']
    function GetPassword(const AIsWrite : Boolean): string;
    function GetSSLSocket:  TIdSSLSocket;
    procedure StatusInfo(const aSSLSocket: TIdSSLSocket; AWhere, ARet: TIdC_INT; const AStatusStr: string); overload;
    procedure StatusInfo(const AStatusStr: string); overload;
    function VerifyPeer(ACertificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;
  end;

  TIdSSLCipher = class(TPersistent)
  protected
    FSSLSocket: TIdSSLSocket;
    function GetDescription: String;
    function GetName: String;
    function GetBits: Integer;
    function GetVersion: String;
  public
    constructor Create(AOwner: TIdSSLSocket);
  published
    property Description: String read GetDescription;
    property Name: String read GetName;
    property Bits: Integer read GetBits;
    property Version: String read GetVersion;
  end;

  { TIdSSLContext }

  TIdSSLContext = class(TPersistent)
  private
    {$IFDEF USE_OBJECT_ARC}[Weak]{$ENDIF} fParent: TObject;
    fUseSystemRootCertificateStore : boolean;
    {$IFDEF USE_WINDOWS_CERT_STORE}
    procedure LoadWindowsCertStore;
    {$ENDIF}
  protected
    fMethod: TIdSSLVersion;
    fSSLVersions : TIdSSLVersions;
    fMode: TIdSSLMode;
    fsRootCertFile, fsCertFile, fsKeyFile, fsDHParamsFile: String;
    fVerifyDepth: Integer;
    fVerifyMode: TIdSSLVerifyModeSet;
//    fVerifyFile: String;
    fVerifyDirs: String;
    fCipherList: String;
    fContext: PSSL_CTX;
    fStatusInfoOn: Boolean;
//    fPasswordRoutineOn: Boolean;
    fVerifyOn: Boolean;
    fSessionId: Integer;
    fCtxMode: TIdSSLCtxMode;
    procedure DestroyContext;
    function SetSSLMethod: PSSL_METHOD;
    procedure SetVerifyMode(Mode: TIdSSLVerifyModeSet; CheckRoutine: Boolean);
    function GetVerifyMode: TIdSSLVerifyModeSet;
    procedure InitContext(CtxMode: TIdSSLCtxMode);
    constructor Create; overload;
  public
    constructor Create(aParent: TObject; SSLOptions: TIdSSLOptions; CtxMode: TIdSSLCtxMode;
      aVerifyOn, aStatusInfoOn: boolean); overload;
    destructor Destroy; override;
    function Clone : TIdSSLContext;
    function LoadRootCert: Boolean;
    function LoadCert: Boolean;
    function LoadKey: Boolean;
    function LoadDHParams: Boolean;
    function IsParent(aObject: TObject): boolean;
    function GetCallbackHelper: IIdSSLOpenSSLCallbackHelper;
    property StatusInfoOn: Boolean read fStatusInfoOn write fStatusInfoOn;
//    property PasswordRoutineOn: Boolean read fPasswordRoutineOn write fPasswordRoutineOn;
    property VerifyOn: Boolean read fVerifyOn write fVerifyOn;
  published
    property SSLVersions : TIdSSLVersions read fSSLVersions write fSSLVersions;
    property Method: TIdSSLVersion read fMethod write fMethod;
    property Mode: TIdSSLMode read fMode write fMode;
    property RootCertFile: String read fsRootCertFile write fsRootCertFile;
    property CertFile: String read fsCertFile write fsCertFile;
    property CipherList: String read fCipherList write fCipherList;
    property KeyFile: String read fsKeyFile write fsKeyFile;
    property DHParamsFile: String read fsDHParamsFile write fsDHParamsFile;
//    property VerifyMode: TIdSSLVerifyModeSet read GetVerifyMode write SetVerifyMode;
//    property VerifyFile: String read fVerifyFile write fVerifyFile;
    property UseSystemRootCertificateStore: boolean read fUseSystemRootCertificateStore write fUseSystemRootCertificateStore;
    property VerifyDirs: String read fVerifyDirs write fVerifyDirs;
    property VerifyMode: TIdSSLVerifyModeSet read fVerifyMode write fVerifyMode;
    property VerifyDepth: Integer read fVerifyDepth write fVerifyDepth;

  end;

  { TIdSSLSocket }

  TIdSSLSocket = class(TObject)
  private
    fSession: PSSL_SESSION;
    function GetProtocolVersion: TIdSSLVersion;
    function GetSSLProtocolVersionStr: string;
    procedure SetSSLContext(AValue: TIdSSLContext);
  protected
    {$IFDEF USE_OBJECT_ARC}[Weak]{$ENDIF} fParent: TObject;
    fPeerCert: TIdX509;
    fSSL: PSSL;
    fSSLCipher: TIdSSLCipher;
    fSSLContext: TIdSSLContext;
    fHostName: String;
    function GetPeerCert: TIdX509;
    function GetSSLCipher: TIdSSLCipher;
    procedure SetSessionID(source: TIdSSLSocket);
  public
    constructor Create(Parent: TObject);
    destructor Destroy; override;
    procedure Accept(const pHandle: TIdStackSocketHandle);
    procedure Connect(const pHandle: TIdStackSocketHandle);
    function Send(const ABuffer : TIdBytes; AOffset, ALength: Integer): Integer;
    function Recv(var ABuffer : TIdBytes): Integer;
    function GetSessionID: TIdSSLByteArray;
    function GetSessionIDAsString:String;
    procedure SetCipherList(CipherList: String);
    function GetCallbackHelper: IIdSSLOpenSSLCallbackHelper;
    function Readable: TIdSSLReadStatus;
    procedure DoShutdown;
    function GetSSL: PSSL;
    function GetSSLError(retCode: Integer): Integer;
    procedure RaiseError(AError: Integer);
    procedure GetStateVars(AWhere, Aret: TIdC_INT; var VTypeStr, VMsg : String);
    //
    property SSLContext: TIdSSLContext read fSSLContext write SetSSLContext;
    property PeerCert: TIdX509 read GetPeerCert;
    property Cipher: TIdSSLCipher read GetSSLCipher;
    property HostName: String read fHostName write fHostName;
    property SSLProtocolVersion: TIdSSLVersion read GetProtocolVersion;
    property SSLProtocolVersionStr: string read GetSSLProtocolVersionStr;
  end;

  function LoadOpenSSLLibrary: Boolean;
  procedure UnLoadOpenSSLLibrary;

implementation

uses
  IdStack,
  {$IFDEF USE_WINDOWS_CERT_STORE}
  IdSSLwincrypt,
  {$ENDIF}
  IdThreadSafe,
  IdSSLOpenSSLUtils,
  IdSSLOpenSSLAPI,
  IdSSLOpenSSL,
  IdResourceStringsProtocols,
  IdResourceStringsOpenSSL,
  IdOpenSSLHeaders_x509,
  IdOpenSSLHeaders_ssl3,
  IdOpenSSLHeaders_tls1,
  IdOpenSSLHeaders_x509_vfy,
  IdOpenSSLHeaders_err
;

var
  SSLIsLoaded: TIdThreadSafeBoolean = nil;
  LockInfoCB: TIdCriticalSection = nil;
  LockPassCB: TIdCriticalSection = nil;
  LockVerifyCB: TIdCriticalSection = nil;

function LoadOpenSSLLibrary: Boolean;
begin
  Assert(SSLIsLoaded <> nil);
  SSLIsLoaded.Lock;
  try
    if SSLIsLoaded.Value then begin
      Result := True;
      Exit;
    end;
    InitializeRandom;
    if GetIOpenSSL <> nil then
      GetIOpenSSL.Init;
    Assert(LockInfoCB = nil);
    // Create locking structures, we need them for callback routines
    LockInfoCB := TIdCriticalSection.Create;
    LockPassCB := TIdCriticalSection.Create;
    LockVerifyCB := TIdCriticalSection.Create;
    // Handle internal OpenSSL locking
    SSLIsLoaded.Value := True;
    Result := True;
  finally
    SSLIsLoaded.Unlock;
  end;

end;

procedure UnLoadOpenSSLLibrary;
begin
  SSLIsLoaded.Lock;
  try
    if not SSLIsLoaded.Value then
      Exit;

    CleanupRandom; // <-- RLebeau: why is this here and not in IdSSLOpenSSLHeaders.Unload()?
    if GetIOpenSSLDDL <> nil then
      GetIOpenSSLDDL.Unload;
    FreeAndNil(LockInfoCB);
    FreeAndNil(LockPassCB);
    FreeAndNil(LockVerifyCB);
    SSLIsLoaded.Value := False;
  finally
    SSLIsLoaded.Unlock;
  end;
end;


procedure InfoCallback(const sslSocket: PSSL; where, ret: TIdC_INT); cdecl;
var
  IdSSLSocket: TIdSSLSocket;
  StatusStr : String;
  LErr : Integer;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
{
You have to save the value of WSGetLastError as some Operating System API
function calls will reset that value and we can't know what a programmer will
do in this event.  We need the value of WSGetLastError so we can report
an underlying socket error when the OpenSSL function returns.

JPM.
}
  LErr := GStack.WSGetLastError;
  try
    LockInfoCB.Enter;
    try
      IdSSLSocket := TIdSSLSocket(SSL_get_app_data(sslSocket));
      LHelper := IdSSLSocket.GetCallbackHelper;
      if LHelper <> nil then
      begin
        StatusStr := IndyFormat(RSOSSLStatusString, [String(SSL_state_string_long(sslSocket))]);
        LHelper.StatusInfo(IdSSLSocket, where, ret, StatusStr);
        LHelper := nil;
      end;
    finally
      LockInfoCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

function VerifyCallback(Ok: TIdC_INT; ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
var
  hcert: PX509;
  Certificate: TIdX509;
  hSSL: PSSL;
  IdSSLSocket: TIdSSLSocket;
  // str: String;
  VerifiedOK: Boolean;
  Depth: Integer;
  Error: Integer;
  LOk: Boolean;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
  LockVerifyCB.Enter;
  try
    VerifiedOK := True;
    try
      hSSL := X509_STORE_CTX_get_app_data(ctx);
      if hSSL = nil then begin
        Result := Ok;
        Exit;
      end;
      hcert := X509_STORE_CTX_get_current_cert(ctx);
      Certificate := TIdX509.Create(hcert, False); // the certificate is owned by the store
      try
        IdSSLSocket := TIdSSLSocket(SSL_get_app_data(hSSL));
        Error := X509_STORE_CTX_get_error(ctx);
        Depth := X509_STORE_CTX_get_error_depth(ctx);
        if not ((Ok > 0) and (IdSSLSocket.SSLContext.VerifyDepth >= Depth)) then begin
          Ok := 0;
          {if Error = X509_V_OK then begin
            Error := X509_V_ERR_CERT_CHAIN_TOO_LONG;
          end;}
        end;
        LOk := False;
        if Ok = 1 then begin
          LOk := True;
        end;
        LHelper := IdSSLSocket.GetCallbackHelper;
        if LHelper <> nil then
        begin
          VerifiedOK := LHelper.VerifyPeer(Certificate, LOk, Depth, Error);
          LHelper := nil;
        end;
      finally
        FreeAndNil(Certificate);
      end;
    except
      VerifiedOK := False;
    end;
    //if VerifiedOK and (Ok > 0) then begin
    if VerifiedOK {and (Ok > 0)} then begin
      Result := 1;
    end
    else begin
      Result := 0;
    end;
  //  Result := Ok; // testing
  finally
    LockVerifyCB.Leave;
  end;
end;

function PasswordCallback(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl;
{$IFDEF USE_MARSHALLED_PTRS}
type
  TBytesPtr = ^TBytes;
{$ENDIF}
var
  Password: String;
  {$IFDEF STRING_IS_UNICODE}
  LPassword: TIdBytes;
  {$ENDIF}
  IdSSLContext: TIdSSLContext;
  LErr : Integer;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
  //Preserve last eror just in case OpenSSL is using it and we do something that
  //clobers it.  CYA.
  LErr := GStack.WSGetLastError;
  try
    LockPassCB.Enter;
    try
      Password := '';    {Do not Localize}
      IdSSLContext := TIdSSLContext(userdata);
      LHelper := IdSSLContext.GetCallbackHelper;
      if LHelper <> nil then
      begin
        Password := LHelper.GetPassword(rwflag > 0);
        LHelper := nil;
      end;
      FillChar(buf^, size, 0);
      {$IFDEF STRING_IS_UNICODE}
      LPassword := IndyTextEncoding_OSDefault.GetBytes(Password);
      if Length(LPassword) > 0 then begin
        {$IFDEF USE_MARSHALLED_PTRS}
        TMarshal.Copy(TBytesPtr(@LPassword)^, 0, TPtrWrapper.Create(buf), IndyMin(Length(LPassword), size));
        {$ELSE}
        Move(LPassword[0], buf^, IndyMin(Length(LPassword), size));
        {$ENDIF}
      end;
      Result := Length(LPassword);
      {$ELSE}
      StrPLCopy(buf, Password, size);
      Result := Length(Password);
      {$ENDIF}
      buf[size-1] := #0; // RLebeau: truncate the password if needed
    finally
      LockPassCB.Leave;
    end;
  finally
     GStack.WSSetLastError(LErr);
  end;
end;

{
function RSACallback(sslSocket: PSSL; e: Integer; KeyLength: Integer):PRSA; cdecl;
const
  RSA: PRSA = nil;
var
  SSLSocket: TSSLWSocket;
  IdSSLSocket: TIdSSLSocket;
begin
  IdSSLSocket := TIdSSLSocket(IdSslGetAppData(sslSocket));

  if Assigned(IdSSLSocket) then begin
    IdSSLSocket.TriggerSSLRSACallback(KeyLength);
  end;

  Result := RSA_generate_key(KeyLength, RSA_F4, @RSAProgressCallback, ssl);
end;
}


function TranslateInternalVerifyToSSL(Mode: TIdSSLVerifyModeSet): Integer;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_VERIFY_NONE;
  if sslvrfPeer in Mode then begin
    Result := Result or SSL_VERIFY_PEER;
  end;
  if sslvrfFailIfNoPeerCert in Mode then begin
    Result := Result or SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  end;
  if sslvrfClientOnce in Mode then begin
    Result := Result or SSL_VERIFY_CLIENT_ONCE;
  end;
end;



///////////////////////////////////////////////////////////////
//  TIdSSLCipher
///////////////////////////////////////////////////////////////
constructor TIdSSLCipher.Create(AOwner: TIdSSLSocket);
begin
  inherited Create;
  FSSLSocket := AOwner;
end;

function TIdSSLCipher.GetDescription: String;
var
  Buf: array[0..1024] of TIdAnsiChar;
begin
  Result := String(SSL_CIPHER_description(SSL_get_current_cipher(FSSLSocket.fSSL), @Buf[0], SizeOf(Buf)-1));
end;

function TIdSSLCipher.GetName:String;
begin
  Result := String(SSL_CIPHER_get_name(SSL_get_current_cipher(FSSLSocket.fSSL)));
end;

function TIdSSLCipher.GetBits:TIdC_INT;
begin
  SSL_CIPHER_get_bits(SSL_get_current_cipher(FSSLSocket.fSSL), Result);
end;

function TIdSSLCipher.GetVersion:String;
begin
  Result := String(SSL_CIPHER_get_version(SSL_get_current_cipher(FSSLSocket.fSSL)));
end;

{ TIdSSLContext }

constructor TIdSSLContext.Create;
begin
  inherited Create;
  //an exception here probably means that you are using the wrong version
  //of the openssl libraries. refer to comments at the top of this file.
  if not LoadOpenSSLLibrary then begin
    raise EIdOSSLCouldNotLoadSSLLibrary.Create(RSOSSLCouldNotLoadSSLLibrary);
  end;
  fVerifyMode := [];
  fMode := sslmUnassigned;
  fSessionId := 1;
  fUseSystemRootCertificateStore := true;
end;

constructor TIdSSLContext.Create(aParent: TObject; SSLOptions: TIdSSLOptions;
  CtxMode: TIdSSLCtxMode; aVerifyOn, aStatusInfoOn: boolean);
begin
  Create;
  fParent := aParent;
  RootCertFile := SSLOptions.RootCertFile;
  CertFile := SSLOptions.CertFile;
  KeyFile := SSLOptions.KeyFile;
  DHParamsFile := SSLOptions.DHParamsFile;
  fVerifyDepth := SSLOptions.VerifyDepth;
  fVerifyMode := SSLOptions.VerifyMode;
  // fVerifyFile := SSLOptions.fVerifyFile;
  fUseSystemRootCertificateStore := SSLOptions.UseSystemRootCertificateStore;
  fVerifyDirs := SSLOptions.VerifyDirs;
  fCipherList := SSLOptions.CipherList;
  VerifyOn := aVerifyOn;
  StatusInfoOn := aStatusInfoOn;
  //PasswordRoutineOn := Assigned(fOnGetPassword);
  fMethod :=  SSLOptions.Method;
  fMode := SSLOptions.Mode;
  fSSLVersions := SSLOptions.SSLVersions;
  InitContext(CtxMode);
end;

destructor TIdSSLContext.Destroy;
begin
  DestroyContext;
  inherited Destroy;
end;

{$IFDEF USE_WINDOWS_CERT_STORE}
{Copy Windows CA Certs to out cert store}
procedure TIdSSLContext.LoadWindowsCertStore;
var WinCertStore: HCERTSTORE;
    X509Cert: PX509;
    cert_context: PCCERT_CONTEXT;
    error: integer;
    SSLCertStore: PX509_STORE;
    CertEncoded: PByte;
begin
  cert_context := nil;
  {$IFDEF STRING_IS_ANSI}
  WinCertStore := CertOpenSystemStoreA(nil,RootStore);
  {$ELSE}
  WinCertStore := CertOpenSystemStoreW(nil,RootStore);
  {$ENDIF}
  if WinCertStore = 0 then
    Exit;

  SSLCertStore := SSL_CTX_get_cert_store(fContext);
  try
    cert_context := CertEnumCertificatesInStore(WinCertStore,cert_context);
    while cert_context <> nil do
    begin
      CertEncoded := cert_context^.pbCertEncoded;
      X509Cert := d2i_X509(nil,@CertEncoded, cert_context^.cbCertEncoded);
      if X509Cert <> nil then
      begin
        error := X509_STORE_add_cert(SSLCertStore, X509Cert);
//Ignore if cert already in store
        if (error = 0) and
           (ERR_GET_REASON(ERR_get_error()) <> X509_R_CERT_ALREADY_IN_HASH_TABLE) then
          EOpenSSLAPICryptoError.RaiseException(ROSCertificateNotAddedToStore);
        X509_free(X509Cert);
      end;
      cert_context := CertEnumCertificatesInStore(WinCertStore,cert_context);
    end;
  finally
     CertCloseStore(WinCertStore, 0);
  end;
end;
{$ENDIF}

procedure TIdSSLContext.DestroyContext;
begin
  if fContext <> nil then begin
    SSL_CTX_free(fContext);
    fContext := nil;
  end;
end;

procedure TIdSSLContext.InitContext(CtxMode: TIdSSLCtxMode);
const
  SSLProtoVersion: array[TIdSSLVersion] of TIdC_LONG = (0,0,0,
                         SSL3_VERSION,    {sslvSSLv3}
                         TLS1_VERSION,    {sslvTLSv1}
                         TLS1_1_VERSION,  {sslvTLSv1_1}
                         TLS1_2_VERSION,  {sslvTLSv1_2}
                         TLS1_3_VERSION); {sslvTLSv1_3}
var
  SSLMethod: PSSL_METHOD;
  error: TIdC_INT;
  v: TIdSSLVersion;
//  pCAname: PSTACK_X509_NAME;
  {$IFDEF USE_MARSHALLED_PTRS}
  M: TMarshaller;
  {$ENDIF}
begin
  // Destroy the context first
  DestroyContext;
  if fMode = sslmUnassigned then begin
    if CtxMode = sslCtxServer then begin
      fMode := sslmServer;
    end else begin
      fMode := sslmClient;
    end
  end;
  // get SSL method function (SSL2, SSL23, SSL3, TLS)
  SSLMethod := SetSSLMethod;
  // create new SSL context
  fContext := SSL_CTX_new(SSLMethod);
  if fContext = nil then begin
    EIdOSSLCreatingContextError.RaiseException(RSSSLCreatingContextError);
  end;

  //set SSL Versions we will use
  if HasTLS_method then
  begin
    if SSLVersions <> [] then
    begin
      for v := sslvSSLv3 to MAX_SSLVERSION do
      begin
        if v in SSLVersions then
        begin
          SSL_CTX_set_min_proto_version(fContext,SSLProtoVersion[v]);
          break;
        end;
     end;
      for v := MAX_SSLVERSION downto sslvSSLv3 do
      begin
        if v in SSLVersions then
        begin
          SSL_CTX_set_max_proto_version(fContext,SSLProtoVersion[v]);
          break;
        end;
     end;
   end
   else
   begin
     SSL_CTX_set_min_proto_version(fContext,SSL3_VERSION);
     SSL_CTX_set_max_proto_version(fContext,SSLProtoVersion[high(TIdSSLVersion)]);
   end;
  end
  else
  begin
  {legacy code 1.0.2 and earlier}

      if IsOpenSSL_SSLv2_Available then begin
        if not (sslvSSLv2 in SSLVersions) then begin
          SSL_CTX_set_options(fContext, SSL_OP_NO_SSLv2);
        end
        else if (fMethod = sslvSSLv23) then begin
          SSL_CTX_clear_options(fContext, SSL_OP_NO_SSLv2);
        end;
      end;
      // SSLv3 might also be disabled as well..
      if IsOpenSSL_SSLv3_Available then begin
        if not (sslvSSLv3 in SSLVersions) then begin
          SSL_CTX_set_options(fContext, SSL_OP_NO_SSLv3);
        end
        else if (fMethod = sslvSSLv23) then begin
          SSL_CTX_clear_options(fContext, SSL_OP_NO_SSLv3);
        end;
      end;
      // may as well do the same for all of them...
      if IsOpenSSL_TLSv1_0_Available then begin
        if not (sslvTLSv1 in SSLVersions) then begin
          SSL_CTX_set_options(fContext, SSL_OP_NO_TLSv1);
        end
        else if (fMethod = sslvSSLv23) then begin
          SSL_CTX_clear_options(fContext, SSL_OP_NO_TLSv1);
        end;
      end;
    {IMPORTANT!!!  Do not set SSL_CTX_set_options SSL_OP_NO_TLSv1_1 and
    SSL_OP_NO_TLSv1_2 if that functionality is not available.  OpenSSL 1.0 and
    earlier do not support those flags.  Those flags would only cause
    an invalid MAC when doing SSL.}
      if IsOpenSSL_TLSv1_1_Available then begin
        if not (sslvTLSv1_1 in SSLVersions) then begin
          SSL_CTX_set_options(fContext, SSL_OP_NO_TLSv1_1);
        end
        else if (fMethod = sslvSSLv23) then begin
          SSL_CTX_clear_options(fContext, SSL_OP_NO_TLSv1_1);
        end;
      end;
      if IsOpenSSL_TLSv1_2_Available then begin
        if not (sslvTLSv1_2 in SSLVersions) then begin
          SSL_CTX_set_options(fContext, SSL_OP_NO_TLSv1_2);
        end
        else if (fMethod = sslvSSLv23) then begin
          SSL_CTX_clear_options(fContext, SSL_OP_NO_TLSv1_2);
        end;
      end;
  end;

//  SSL_CTX_set_mode(fContext, SSL_MODE_AUTO_RETRY);
  SSL_CTX_clear_mode(fContext, SSL_MODE_AUTO_RETRY);
  // assign a password lookup routine
//  if PasswordRoutineOn then begin
    SSL_CTX_set_default_passwd_cb(fContext, @PasswordCallback);
    SSL_CTX_set_default_passwd_cb_userdata(fContext, Self);
//  end;

  {$IFDEF USE_WINDOWS_CERT_STORE}
  if fUseSystemRootCertificateStore then
    LoadWindowsCertStore
  else
  {$ENDIF}
  SSL_CTX_set_default_verify_paths(fContext);
  // load key and certificate files
  if (RootCertFile <> '') or (VerifyDirs <> '') then begin    {Do not Localize}
    if not LoadRootCert then begin
       EIdOSSLLoadingRootCertError.RaiseException(RSSSLLoadingRootCertError);
    end;
  end;
  if CertFile <> '' then begin    {Do not Localize}
    if not LoadCert then begin
      EIdOSSLLoadingCertError.RaiseException(RSSSLLoadingCertError);
    end;
  end;
  if KeyFile <> '' then begin    {Do not Localize}
    if not LoadKey then begin
      EIdOSSLLoadingKeyError.RaiseException(RSSSLLoadingKeyError);
    end;
  end;
  if DHParamsFile <> '' then begin     {Do not Localize}
    if not LoadDHParams then begin
      EIdOSSLLoadingDHParamsError.RaiseException(RSSSLLoadingDHParamsError);
    end;
  end;
  if StatusInfoOn then begin
    SSL_CTX_set_info_callback(fContext, @InfoCallback);
  end;
  //if_SSL_CTX_set_tmp_rsa_callback(hSSLContext, @RSACallback);
  if fCipherList <> '' then begin    {Do not Localize}
    error := SSL_CTX_set_cipher_list(fContext,
      {$IFDEF USE_MARSHALLED_PTRS}
      M.AsAnsi(fCipherList).ToPointer
      {$ELSE}
      PAnsiChar(
        {$IFDEF STRING_IS_ANSI}
        fCipherList
        {$ELSE}
        AnsiString(fCipherList) // explicit cast to Ansi
        {$ENDIF}
      )
      {$ENDIF}
    );
  end else begin
    // RLebeau: don't override OpenSSL's default.  As OpenSSL evolves, the
    // SSL_DEFAULT_CIPHER_LIST constant defined in the C/C++ SDK may change,
    // while Indy's define of it might take some time to catch up.  We don't
    // want users using an older default with newer DLLs...
    (*
    error := SSL_CTX_set_cipher_list(fContext,
      {$IFDEF USE_MARSHALLED_PTRS}
      M.AsAnsi(SSL_DEFAULT_CIPHER_LIST).ToPointer
      {$ELSE}
      SSL_DEFAULT_CIPHER_LIST
      {$ENDIF}
    );
    *)
    error := 1;
  end;
  if error <= 0 then begin
    // TODO: should this be using EIdOSSLSettingCipherError.RaiseException() instead?
    raise EIdOSSLSettingCipherError.Create(RSSSLSettingCipherError);
  end;
  if fVerifyMode <> [] then begin
    SetVerifyMode(fVerifyMode, VerifyOn);
  end;
  if CtxMode = sslCtxServer then begin
    SSL_CTX_set_session_id_context(fContext, PByte(@fSessionId), SizeOf(fSessionId));
  end;
  // CA list
  if RootCertFile <> '' then begin    {Do not Localize}
    SSL_CTX_set_client_CA_list(fContext, IndySSL_load_client_CA_file(RootCertFile));
  end

  // TODO: provide an event so users can apply their own settings as needed...
end;

procedure TIdSSLContext.SetVerifyMode(Mode: TIdSSLVerifyModeSet; CheckRoutine: Boolean);
var
  Func: TSSL_CTX_set_verify_callback;
begin
  if fContext<>nil then begin
//    SSL_CTX_set_default_verify_paths(fContext);
    if CheckRoutine then begin
      Func := @VerifyCallback;
    end else begin
      Func := nil;
    end;
    SSL_CTX_set_verify(fContext, TranslateInternalVerifyToSSL(Mode), Func);
    SSL_CTX_set_verify_depth(fContext, fVerifyDepth);
  end;
end;

function TIdSSLContext.GetVerifyMode: TIdSSLVerifyModeSet;
begin
  Result := fVerifyMode;
end;
{
function TIdSSLContext.LoadVerifyLocations(FileName: String; Dirs: String): Boolean;
begin
  Result := False;

  if (Dirs <> '') or (FileName <> '') then begin
    if IndySSL_CTX_load_verify_locations(fContext, FileName, Dirs) <= 0 then begin
      raise EIdOSSLCouldNotLoadSSLLibrary.Create(RSOSSLCouldNotLoadSSLLibrary);
    end;
  end;

  Result := True;
end;
}

function TIdSSLContext.SetSSLMethod: PSSL_METHOD;
begin
  Result := nil;
  if fMode = sslmUnassigned then begin
    raise EIdOSSLModeNotSet.Create(RSOSSLModeNotSet);
  end;

  OpenSSL_SetMethod(TOpenSSL_Version(fMethod));

    {For OpenSSL 1.1.1 or later. OpenSSL will negotiate the best
     available SSL/TLS version and there is not much that we can do to influence this.
     Hence, OpenSSL_SetMethod is ignored. Only if we are using an earlier version
     of OpenSSL will OpenSSL_SetMethod be used to help select the appropriate SSLMethod.

     Quoting from the OpenSSL man page:

     TLS_method(), TLS_server_method(), TLS_client_method()

    These are the general-purpose version-flexible SSL/TLS methods. The actual
    protocol version used will be negotiated to the highest version mutually s
    upported by the client and the server. The supported protocols are SSLv3,
    TLSv1, TLSv1.1, TLSv1.2 and TLSv1.3. Applications should use these methods,
    and avoid the version-specific methods described below [e.g. SSLv2_method),
    which are deprecated.
}
    case fMode of
      sslmClient:
          Result := TLS_client_method();

      sslmServer:
          Result := TLS_server_method();

      sslmBoth:
        Result := TLS_Method();

    end;

  if Result = nil then
    raise EIdOSSLGetMethodError.Create(RSSSLGetMethodError);
end;

function TIdSSLContext.LoadRootCert: Boolean;
begin
  Result := IndySSL_CTX_load_verify_locations(fContext, RootCertFile, VerifyDirs) > 0;
end;

function TIdSSLContext.LoadCert: Boolean;
begin
  if PosInStrArray(ExtractFileExt(CertFile), ['.p12', '.pfx'], False) <> -1 then begin
    Result := IndySSL_CTX_use_certificate_file_PKCS12(fContext, CertFile) > 0;
  end else begin
    Result := IndySSL_CTX_use_certificate_chain_file(fContext, CertFile) > 0;
  end;
end;

function TIdSSLContext.LoadKey: Boolean;
begin
  if PosInStrArray(ExtractFileExt(KeyFile), ['.p12', '.pfx'], False) <> -1 then begin
    Result := IndySSL_CTX_use_PrivateKey_file_PKCS12(fContext, KeyFile) > 0;
  end else begin
    Result := IndySSL_CTX_use_PrivateKey_file(fContext, KeyFile, SSL_FILETYPE_PEM) > 0;
  end;
  if Result then begin
    Result := SSL_CTX_check_private_key(fContext) > 0;
  end;
end;

function TIdSSLContext.LoadDHParams: Boolean;
begin
  Result := IndySSL_CTX_use_DHparams_file(fContext, fsDHParamsFile, SSL_FILETYPE_PEM) > 0;
end;

function TIdSSLContext.IsParent(aObject: TObject): boolean;
begin
  Result := fParent = aObject;
end;

function TIdSSLContext.GetCallbackHelper: IIdSSLOpenSSLCallbackHelper;
begin
  Result := nil;
  if fParent <> nil then
    fParent.GetInterface(IIdSSLOpenSSLCallbackHelper,Result);
end;

//////////////////////////////////////////////////////////////

function TIdSSLContext.Clone: TIdSSLContext;
begin
  Result := TIdSSLContext.Create;
  Result.StatusInfoOn := StatusInfoOn;
//    property PasswordRoutineOn: Boolean read fPasswordRoutineOn write fPasswordRoutineOn;
  Result.VerifyOn := VerifyOn;
  Result.Method := Method;
  Result.SSLVersions := SSLVersions;
  Result.Mode := Mode;
  Result.RootCertFile := RootCertFile;
  Result.CertFile := CertFile;
  Result.KeyFile := KeyFile;
  Result.VerifyMode := VerifyMode;
  Result.VerifyDepth := VerifyDepth;
end;

{ TIdSSLSocket }

constructor TIdSSLSocket.Create(Parent: TObject);
begin
  inherited Create;
  fParent := Parent;
end;

destructor TIdSSLSocket.Destroy;
begin
  if fSession <> nil then
    SSL_SESSION_free(fSession);
  if fSSL <> nil then begin
    // TODO: should this be moved to TIdSSLContext instead?  Is this here
    // just to make sure the SSL shutdown does not log any messages?
    {
    if (fSSLContext <> nil) and (fSSLContext.StatusInfoOn) and
       (fSSLContext.fContext <> nil) then begin
      SSL_CTX_set_info_callback(fSSLContext.fContext, nil);
    end;
    }
    //SSL_set_shutdown(fSSL, SSL_SENT_SHUTDOWN);
    DoShutDown;
    SSL_free(fSSL);
    fSSL := nil;
  end;
  FreeAndNil(fSSLCipher);
  FreeAndNil(fPeerCert);
  inherited Destroy;
end;

function TIdSSLSocket.GetSSLError(retCode: Integer): Integer;
begin
  // COMMENT!!!
  // I found out that SSL layer should not interpret errors, cause they will pop up
  // on the socket layer. Only thing that the SSL layer should consider is key
  // or protocol renegotiation. This is done by loop in read and write
  Result := SSL_get_error(fSSL, retCode);
  case Result of
    SSL_ERROR_NONE:
      Result := SSL_ERROR_NONE;
    SSL_ERROR_WANT_WRITE:
      Result := SSL_ERROR_WANT_WRITE;
    SSL_ERROR_WANT_READ:
      Result := SSL_ERROR_WANT_READ;
    SSL_ERROR_ZERO_RETURN:
      Result := SSL_ERROR_ZERO_RETURN;
      //Result := SSL_ERROR_NONE;
      {
      // ssl layer has been disconnected, it is not necessary that also
      // socked has been closed
      case Mode of
        sslemClient: begin
          case Action of
            sslWrite: begin
              if retCode = 0 then begin
                Result := 0;
              end
              else begin
                raise EIdException.Create(RSOSSLConnectionDropped); // TODO: create a new Exception class for this
              end;
            end;
        end;
      end;}

        //raise EIdException.Create(RSOSSLConnectionDropped); // TODO: create a new Exception class for this
      // X509_LOOKUP event is not really an error, just an event
    // SSL_ERROR_WANT_X509_LOOKUP:
        // raise EIdException.Create(RSOSSLCertificateLookup); // TODO: create a new Exception class for this
    SSL_ERROR_SYSCALL:
      Result := SSL_ERROR_SYSCALL;
      // Result := SSL_ERROR_NONE;

        {//raise EIdException.Create(RSOSSLInternal); // TODO: create a new Exception class for this
        if (retCode <> 0) or (DataLen <> 0) then begin
          raise EIdException.Create(RSOSSLConnectionDropped); // TODO: create a new Exception class for this
        end
        else begin
          Result := 0;
        end;}

    SSL_ERROR_SSL:
      // raise EIdException.Create(RSOSSLInternal); // TODO: create a new Exception class for this
      Result := SSL_ERROR_SSL;
      // Result := SSL_ERROR_NONE;
  end;
end;

procedure TIdSSLSocket.RaiseError(AError: Integer);
begin
  EOpenSSLAPISSLError.RaiseException(fSSL, AError, '');
end;

procedure TIdSSLSocket.GetStateVars(AWhere, Aret: TIdC_INT; var VTypeStr,
  VMsg: String);
begin
  case AWhere of
    SSL_CB_ALERT :
    begin
      VTypeStr := IndyFormat( RSOSSLAlert,[SSL_alert_type_string_long(Aret)]);
      VMsg := String(SSL_alert_type_string_long(Aret));
    end;
    SSL_CB_READ_ALERT :
    begin
      VTypeStr := IndyFormat(RSOSSLReadAlert,[SSL_alert_type_string_long(Aret)]);
      VMsg := String( SSL_alert_desc_string_long(Aret));
    end;
    SSL_CB_WRITE_ALERT :
    begin
      VTypeStr := IndyFormat(RSOSSLWriteAlert,[SSL_alert_type_string_long(Aret)]);
      VMsg := String( SSL_alert_desc_string_long(Aret));
    end;
    SSL_CB_ACCEPT_LOOP :
    begin
      VTypeStr :=  RSOSSLAcceptLoop;
      VMsg := String( SSL_state_string_long(fSSL));
    end;
    SSL_CB_ACCEPT_EXIT :
    begin
      if ARet < 0  then begin
        VTypeStr := RSOSSLAcceptError;
      end else begin
        if ARet = 0 then begin
          VTypeStr := RSOSSLAcceptFailed;
        end else begin
          VTypeStr := RSOSSLAcceptExit;
        end;
      end;
      VMsg := String( SSL_state_string_long(fSSL) );
    end;
    SSL_CB_CONNECT_LOOP :
    begin
      VTypeStr := RSOSSLConnectLoop;
      VMsg := String( SSL_state_string_long(fSSL) );
    end;
    SSL_CB_CONNECT_EXIT :
    begin
      if ARet < 0  then begin
        VTypeStr := RSOSSLConnectError;
      end else begin
        if ARet = 0 then begin
          VTypeStr := RSOSSLConnectFailed
        end else begin
          VTypeStr := RSOSSLConnectExit;
        end;
      end;
      VMsg := String( SSL_state_string_long(fSSL) );
    end;
    SSL_CB_HANDSHAKE_START :
    begin
      VTypeStr :=  RSOSSLHandshakeStart;
      VMsg := String( SSL_state_string_long(fSSL) );
    end;
    SSL_CB_HANDSHAKE_DONE :
    begin
      VTypeStr := RSOSSLHandshakeDone;
      VMsg := String( SSL_state_string_long(fSSL) );
    end;
  end;
{var LW : TIdC_INT;
begin
  VMsg := '';
  LW := Awhere and (not SSL_ST_MASK);
  if (LW and SSL_ST_CONNECT) > 0 then begin
    VWhereStr :=   'SSL_connect:';
  end else begin
    if (LW and SSL_ST_ACCEPT) > 0 then begin
      VWhereStr := ' SSL_accept:';
    end else begin
      VWhereStr := '  undefined:';
    end;
  end;
//  IdSslStateStringLong
  if (Awhere and SSL_CB_LOOP) > 0 then begin
       VMsg := IdSslStateStringLong(fSSL);
  end else begin
    if (Awhere and SSL_CB_ALERT) > 0 then begin
       if (Awhere and SSL_CB_READ > 0) then begin
         VWhereStr := VWhereStr + ' read:'+ IdSslAlertTypeStringLong(Aret);
       end else begin
         VWhereStr := VWhereStr + 'write:'+ IdSslAlertTypeStringLong(Aret);
       end;;
       VMsg := IdSslAlertDescStringLong(Aret);
    end else begin
       if (Awhere and SSL_CB_EXIT) > 0 then begin
         if ARet = 0 then begin

          VWhereStr := VWhereStr +'failed';
          VMsg := IdSslStateStringLong(fSSL);
         end else begin
           if ARet < 0  then  begin
               VWhereStr := VWhereStr +'error';
               VMsg := IdSslStateStringLong(fSSL);
           end;
         end;
       end;
    end;
  end;          }
end;

procedure TIdSSLSocket.Accept(const pHandle: TIdStackSocketHandle);
//Accept and Connect have a lot of duplicated code
var
  error: Integer;
  StatusStr: String;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
  Assert(fSSL=nil);
  Assert(fSSLContext<>nil);
  fSSL := SSL_new(fSSLContext.fContext);
  if fSSL = nil then begin
    raise EIdOSSLCreatingSessionError.Create(RSSSLCreatingSessionError);
  end;
  error := SSL_set_app_data(fSSL, Self);
  if error <= 0 then begin
    EIdOSSLDataBindingError.RaiseException(fSSL, error, RSSSLDataBindingError);
  end;
  error := SSL_set_fd(fSSL, pHandle);
  if error <= 0 then begin
    EIdOSSLFDSetError.RaiseException(fSSL, error, RSSSLFDSetError);
  end;
  // RLebeau: if this socket's IOHandler was cloned, no need to reuse the
  // original IOHandler's active session ID, since this is a server socket
  // that generates its own sessions...
  //
  // RLebeau: is this actually true?  Should we be reusing the original
  // IOHandler's active session ID regardless of whether this is a client
  // or server socket? What about FTP in non-passive mode, for example?
  {
  if (LParentIO <> nil) and (LParentIO.fSSLSocket <> nil) and
     (LParentIO.fSSLSocket <> Self) then
  begin
    SetSessionID(LParentIO.fSSLSocket);
  end;
  }
  error := SSL_accept(fSSL);
  if error <= 0 then begin
    EIdOSSLAcceptError.RaiseException(fSSL, error, RSSSLAcceptError);
  end;
  fSession := SSL_get1_session(fSSL);
  LHelper := GetCallbackHelper;
  if LHelper <> nil then
  begin
    StatusStr := 'Cipher: name = ' + Cipher.Name + '; ' +    {Do not Localize}
                 'description = ' + Cipher.Description + '; ' +    {Do not Localize}
                 'bits = ' + IntToStr(Cipher.Bits) + '; ' +    {Do not Localize}
                 'version = ' + Cipher.Version + '; ';    {Do not Localize}
    LHelper.StatusInfo(StatusStr);
    LHelper := nil;
  end;
end;

procedure TIdSSLSocket.Connect(const pHandle: TIdStackSocketHandle);
var
  error: Integer;
  StatusStr: String;
  LHelper: IIdSSLOpenSSLCallbackHelper;
  IOHandlerSocket: TIdSSLSocket;
begin
  Assert(fSSL=nil);
  Assert(fSSLContext<>nil);
  fSSL := SSL_new(fSSLContext.fContext);
  if fSSL = nil then begin
    raise EIdOSSLCreatingSessionError.Create(RSSSLCreatingSessionError);
  end;
  error := SSL_set_app_data(fSSL, Self);
  if error <= 0 then begin
    EIdOSSLDataBindingError.RaiseException(fSSL, error, RSSSLDataBindingError);
  end;
  error := SSL_set_fd(fSSL, pHandle);
  if error <= 0 then begin
    EIdOSSLFDSetError.RaiseException(fSSL, error, RSSSLFDSetError);
  end;
  // RLebeau: if this socket's IOHandler was cloned, reuse the
  // original IOHandler's active session ID...
  LHelper := GetCallbackHelper;
  if LHelper <> nil then
  begin
   IOHandlerSocket := LHelper.GetSSLSocket;
    if (IOHandlerSocket <> nil) and (IOHandlerSocket <> self) then
      SetSessionID(IOHandlerSocket);
  end;
  {$IFNDEF OPENSSL_NO_TLSEXT}
  {Delphi appears to need the extra AnsiString coerction. Otherwise, only the
   first character to the hostname is passed}
  error := SSL_set_tlsext_host_name(fSSL, PIdAnsiChar(AnsiString(fHostName)));
  if error <= 0 then begin
    // RLebeau: for the time being, not raising an exception on error, as I don't
    // know which OpenSSL versions support this extension, and which error code(s)
    // are safe to ignore on those versions...
    //EIdOSSLSettingTLSHostNameError.RaiseException(fSSL, error, RSSSLSettingTLSHostNameError);
  end;
  {$ENDIF}
  error := SSL_connect(fSSL);
  if error <= 0 then begin
    // TODO: if sslv23 is being used, but sslv23 is not being used on the
    // remote side, SSL_connect() will fail. In that case, before giving up,
    // try re-connecting using a version-specific method for each enabled
    // version, maybe one will succeed...
    EIdOSSLConnectError.RaiseException(fSSL, error, RSSSLConnectError);
  end;
  fSession := SSL_get1_session(fSSL);
  // TODO: even if SSL_connect() returns success, the connection might
  // still be insecure if SSL_connect() detected that certificate validation
  // actually failed, but ignored it because SSL_VERIFY_PEER was disabled!
  // It would report such a failure via SSL_get_verify_result() instead of
  // returning an error code, so we should call SSL_get_verify_result() here
  // to make sure...
  if LHelper <> nil then begin
    StatusStr := 'Cipher: name = ' + Cipher.Name + '; ' +    {Do not Localize}
                 'description = ' + Cipher.Description + '; ' +    {Do not Localize}
                 'bits = ' + IntToStr(Cipher.Bits) + '; ' +    {Do not Localize}
                 'version = ' + Cipher.Version + '; ';    {Do not Localize}
    LHelper.StatusInfo(StatusStr);
  end;
  // TODO: enable this
  {
  var
    peercert: PX509;
    lHostName: AnsiString;
  peercert := SSL_get_peer_certificate(fSSL);
  try
    lHostName := AnsiString(fHostName);
    if (X509_check_host(peercert, PByte(PAnsiChar(lHostName)), Length(lHostName), 0) != 1) and
       (not certificate_host_name_override(peercert, PAnsiChar(lHostName)) then
    begin
      EIdOSSLCertificateError.RaiseException(fSSL, error, 'SSL certificate does not match host name');
    end;
  finally
    X509_free(peercert);
  end;
}
end;

function TIdSSLSocket.Recv(var ABuffer: TIdBytes): Integer;
var
  ret, err: Integer;
begin
  repeat
    ret := SSL_read(fSSL, PByte(ABuffer), Length(ABuffer));
    if ret > 0 then begin
      Result := ret;
      Exit;
    end;
    err := GetSSLError(ret);
    if (err = SSL_ERROR_WANT_READ) or (err = SSL_ERROR_WANT_WRITE) then begin
      Continue;
    end;
    if err = SSL_ERROR_ZERO_RETURN then begin
      Result := 0;
    end else begin
      Result := ret;
    end;
    Exit;
  until False;
end;

function TIdSSLSocket.Send(const ABuffer: TIdBytes; AOffset, ALength: Integer): Integer;
var
  ret, err: Integer;
begin
  Result := 0;
  repeat
    ret := SSL_write(fSSL, @ABuffer[AOffset], ALength);
    if ret > 0 then begin
      Inc(Result, ret);
      Inc(AOffset, ret);
      Dec(ALength, ret);
      if ALength < 1 then begin
        Exit;
      end;
      Continue;
    end;
    err := GetSSLError(ret);
    if (err = SSL_ERROR_WANT_READ) or (err = SSL_ERROR_WANT_WRITE) then begin
      Continue;
    end;
    if err = SSL_ERROR_ZERO_RETURN then begin
      Result := 0;
    end else begin
      Result := ret;
    end;
    Exit;
  until False;
end;

function TIdSSLSocket.GetProtocolVersion: TIdSSLVersion;
begin
  if fSession = nil then
    Result := sslUnknown
  else
  case SSL_SESSION_get_protocol_version(fSession)  of
  SSL3_VERSION:
    Result :=  sslvSSLv3;
 TLS1_VERSION:
    Result := sslvTLSv1;
 TLS1_1_VERSION:
    Result := sslvTLSv1_1;
 TLS1_2_VERSION:
    Result :=  sslvTLSv1_2;
 TLS1_3_VERSION:
    Result := sslvTLSv1_3;
 else
    Result := sslUnknown;
  end;
end;

function TIdSSLSocket.GetSSLProtocolVersionStr: string;
begin
  case SSLProtocolVersion of
  sslUnknown:
    Result := 'Unknown';
  sslvSSLv2:
    Result := 'SSLv2';
  sslvSSLv3:
    Result := 'SSLv3';
  sslvTLSv1:
    Result := 'TLS';
  sslvTLSv1_1:
    Result := 'TLSv1.1';
  sslvTLSv1_2:
    Result := 'TLSv1.2';
  sslvTLSv1_3:
    Result := 'TLSv1.3';
  end;
end;

procedure TIdSSLSocket.SetSessionID(source: TIdSSLSocket);
begin
  SSL_copy_session_id(fSSL, source.fSSL);
end;

procedure TIdSSLSocket.SetSSLContext(AValue: TIdSSLContext);
begin
  if fSSLContext = AValue then Exit;
  Assert(fSSLContext=nil);
  fSSLContext := AValue;
end;

function TIdSSLSocket.GetPeerCert: TIdX509;
var
  LX509: PX509;
begin
  if fPeerCert = nil then begin
    LX509 := SSL_get_peer_certificate(fSSL);
    if LX509 <> nil then begin
      fPeerCert := TIdX509.Create(LX509, False);
    end;
  end;
  Result := fPeerCert;
end;

function TIdSSLSocket.GetSSLCipher: TIdSSLCipher;
begin
  if (fSSLCipher = nil) and (fSSL<>nil) then begin
    fSSLCipher := TIdSSLCipher.Create(Self);
  end;
  Result := fSSLCipher;
end;

function TIdSSLSocket.GetSessionID: TIdSSLByteArray;
var
  pSession: PSSL_SESSION;
begin
  Result.Length := 0;
  Result.Data := nil;
  if fSSL <> nil then begin
    pSession := SSL_get_session(fSSL);
    if pSession <> nil then begin
      Result.Data := PByte(SSL_SESSION_get_id(pSession, @Result.Length));
    end;
  end;
end;

function  TIdSSLSocket.GetSessionIDAsString:String;
var
  Data: TIdSSLByteArray;
  i: TIdC_UINT;
  LDataPtr: PByte;
begin
  Result := '';    {Do not Localize}
  Data := GetSessionID;
  if Data.Length > 0 then begin
    for i := 0 to Data.Length-1 do begin
      // RLebeau: not all Delphi versions support indexed access using PByte
      LDataPtr := Data.Data;
      Inc(LDataPtr, I);
      Result := Result + IndyFormat('%.2x', [LDataPtr^]);{do not localize}
    end;
  end;
end;

procedure TIdSSLSocket.SetCipherList(CipherList: String);
//var
//  tmpPStr: PAnsiChar;
begin
{
  fCipherList := CipherList;
  fCipherList_Ch := True;
  aCipherList := aCipherList+#0;
  if hSSL <> nil then f_SSL_set_cipher_list(hSSL, @aCipherList[1]);
}
end;

function TIdSSLSocket.GetCallbackHelper: IIdSSLOpenSSLCallbackHelper;
begin
  Result := nil;
  if fParent <> nil then
    fParent.GetInterface(IIdSSLOpenSSLCallbackHelper,Result);
end;

function TIdSSLSocket.Readable: TIdSSLReadStatus;
var buf : byte;
    Lr: integer;
begin
  Result := sslNoData;
  {Confirm that there is application data to be read.}
  Lr := SSL_peek(fSSL, @buf, 1);
  {Return sslDataAvailable if application data pending, or if it looks like we have disconnected,
          sslUnrecoverableError if error state indicates thus,
          sslEOF if the connection has been shutdown, or
          sslNoData otherwise => try again later}
  if Lr > 0 then
    Result := sslDataAvailable
  else
  begin
    case SSL_get_error(fSSL,Lr) of
      SSL_ERROR_SSL, SSL_ERROR_SYSCALL:
          if SSL_get_shutdown(fSSL) = SSL_RECEIVED_SHUTDOWN then
            Result := sslEOF
          else
            Result := sslUnrecoverableError;

      SSL_ERROR_ZERO_RETURN:
          if SSL_get_shutdown(fSSL) = SSL_RECEIVED_SHUTDOWN then
            Result := sslEOF;

      {anything else return the function default - sslNoData (yet)}
    end;
  end;
end;

procedure TIdSSLSocket.DoShutdown;
begin
  if fSSL <> nil then begin
    // if SSL_shutdown() returns 0, a "close notify" was sent to the peer and SSL_shutdown()
    // needs to be called again to receive the peer's "close notify" in response...
    if SSL_shutdown(fSSL) = 0 then
      SSL_shutdown(fSSL);
  end;
end;

function TIdSSLSocket.GetSSL: PSSL;
begin
  Result := fSSL;
end;

initialization
  Assert(SSLIsLoaded=nil);
  SSLIsLoaded := TIdThreadSafeBoolean.Create;

finalization
  UnLoadOpenSSLLibrary;
  //free the lock last as unload makes calls that use it
  FreeAndNil(SSLIsLoaded);

end.

