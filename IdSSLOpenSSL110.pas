{
  This file is part of the Indy (Internet Direct) project, and is offered
  under the dual-licensing agreement described on the Indy website.
  (http://www.indyproject.org/)

  Copyright:
  (c) 1993-2024, Chad Z. Hower and the Indy Pit Crew. All rights reserved.
}
unit IdSSLOpenSSL110;
{
  Author: Gregor Ibic (gregor.ibic@intelicom.si)
  Copyright: (c) Gregor Ibic, Intelicom d.o.o and Indy Working Group.
}

{
  Indy OpenSSL now uses the standard OpenSSL libraries
  for pre-compiled win32 dlls, see:
  http://www.openssl.org/related/binaries.html
  recommended v0.9.8a or later
}

{
  Important information concerning OnVerifyPeer:
  Rev 1.39 of February 2005 deliberately broke the OnVerifyPeer interface,
  which (obviously?) only affects programs that implemented that callback
  as part of the SSL negotiation.  Note that you really should always
  implement OnVerifyPeer, otherwise the certificate of the peer you are
  connecting to is NOT checked to ensure it is valid.

  Prior to this, if the SSL library detected a problem with a certificate
  or the Depth was insufficient (i.e. the "Ok" parameter in VerifyCallback
  is 0 / FALSE), then irrespective of whether your OnVerifyPeer returned True
  or False, the SSL connection would be deliberately failed.

  This created a problem in that even if there was only a very minor
  problem with one of the certificates in the chain (OnVerifyPeer is called
  once for each certificate in the certificate chain), which the user may
  have been happy to accept, the SSL negotiation would be failed.  However,
  changing the code to allow the SSL connection when a user returned True
  for OnVerifyPeer would have meant that existing code which depended on
  automatic rejection of invalid certificates would then be accepting
  invalid certificates, which would have been an unacceptable security
  change.

  Consequently, OnVerifyPeer was changed to deliberately break existing code
  by adding an AOk parameter.  To preserve the previous functionality, your
  OnVerifyPeer event should do "Result := AOk;".  If you wish to consider
  accepting certificates that the SSL library has considered invalid, then
  in your OnVerifyPeer, make sure you satisfy yourself that the certificate
  really is valid and then set Result to True.  In reality, in addition to
  checking AOk, you should always implement code that ensures you are only
  accepting certificates which are valid (at least from your point of view).

  Ciaran Costelloe, ccostelloe@flogas.ie
}
{
  RLebeau 1/12/2011: Breaking OnVerifyPeer event again, this time to add an
  additional AError parameter (patch courtesy of "jvlad", dmda@yandex.ru).
  This helps user code distinquish between Self-signed and invalid certificates.
}

interface

{$I IdCompilerDefines.inc}
{$TYPEDADDRESS OFF}

uses
  // facilitate inlining only.
{$IFDEF WINDOWS}
  Windows,
{$ENDIF}
  Classes,
  IdBuffer,
  IdCTypes,
  IdGlobal,
  IdException,
  IdStackConsts,
  IdSocketHandle,
  IdComponent,
  IdIOHandler,
  IdGlobalProtocols,
  IdTCPServer,
  IdThread,
  IdTCPConnection,
  IdIntercept,
  IdIOHandlerSocket,
  IdSSL,
  IdSSLOpenSSLExceptionHandlers,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_ssl,
  IdSocks,
  IdScheduler,
  IdYarn;

type
  TIdSSLVersion = (sslvSSLv2, sslvSSLv23, sslvSSLv3, sslvTLSv1, sslvTLSv1_1,
    sslvTLSv1_2, sslvTLSv1_3);
  TIdSSLVersions = set of TIdSSLVersion;
  TIdSSLMode = (sslmUnassigned, sslmClient, sslmServer, sslmBoth);
  TIdSSLVerifyMode = (sslvrfPeer, sslvrfFailIfNoPeerCert, sslvrfClientOnce);
  TIdSSLVerifyModeSet = set of TIdSSLVerifyMode;
  TIdSSLCtxMode = (sslCtxClient, sslCtxServer);
  TIdSSLAction = (sslRead, sslWrite);

const
  DEF_SSLVERSION = sslvTLSv1_3;
  DEF_SSLVERSIONS = [sslvTLSv1_3];
  P12_FILETYPE = 3;
  MAX_SSL_PASSWORD_LENGTH = 128;

type
  TIdSSLULong = packed record
    case Byte of
      0:
        (B1, B2, B3, B4: UInt8);
      1:
        (W1, W2: UInt16);
      2:
        (L1: Int32);
      3:
        (C1: UInt32);
  end;

  TIdSSLEVP_MD = record
    Length: TIdC_UINT;
    MD: Array [0 .. EVP_MAX_MD_SIZE - 1] of TIdAnsiChar;
  end;

  TIdSSLByteArray = record
    Length: TIdC_UINT;
    Data: PByte;
  end;

  TIdX509 = class;
  TIdSSLIOHandlerSocketOpenSSL110 = class;
  TIdSSLCipher = class;
  TCallbackEvent = procedure(const AMsg: String) of object;
  TCallbackExEvent = procedure(ASender: TObject; const AsslSocket: PSSL;
    const AWhere, Aret: TIdC_INT; const AType, AMsg: String) of object;
  TPasswordEvent = procedure(var Password: String) of object;
  TPasswordEventEx = procedure(ASender: TObject; var VPassword: String;
    const AIsWrite: Boolean) of object;
  TVerifyPeerEvent = function(Certificate: TIdX509; AOk: Boolean;
    ADepth, AError: Integer): Boolean of object;
  TIOHandlerNotify = procedure(ASender: TIdSSLIOHandlerSocketOpenSSL110) of object;

  TIdSSLOptions = class(TPersistent)
  protected
    fsRootCertFile, fsCertFile, fsKeyFile, fsDHParamsFile: String;
    fMethod: TIdSSLVersion;
    fSSLVersions : TIdSSLVersions;
    fMode: TIdSSLMode;
    fVerifyDepth: Integer;
    fVerifyMode: TIdSSLVerifyModeSet;
    //fVerifyFile,
    fVerifyDirs: String;
    fCipherList: String;
    procedure AssignTo(Destination: TPersistent); override;
    procedure SetSSLVersions(const AValue : TIdSSLVersions);
    procedure SetMethod(const AValue : TIdSSLVersion);
  public
    constructor Create;
    // procedure Assign(ASource: TPersistent); override;
  published
    property RootCertFile: String read fsRootCertFile write fsRootCertFile;
    property CertFile: String read fsCertFile write fsCertFile;
    property KeyFile: String read fsKeyFile write fsKeyFile;
    property DHParamsFile: String read fsDHParamsFile write fsDHParamsFile;
    property Method: TIdSSLVersion read fMethod write SetMethod default DEF_SSLVERSION;
    property SSLVersions : TIdSSLVersions read fSSLVersions write SetSSLVersions default DEF_SSLVERSIONS;
    property Mode: TIdSSLMode read fMode write fMode;
    property VerifyMode: TIdSSLVerifyModeSet read fVerifyMode write fVerifyMode;
    property VerifyDepth: Integer read fVerifyDepth write fVerifyDepth;
    // property VerifyFile: String read fVerifyFile write fVerifyFile;
    property VerifyDirs: String read fVerifyDirs write fVerifyDirs;
    property CipherList: String read fCipherList write fCipherList;
  end;

  TIdSSLContext = class(TObject)
  protected
    fMethod: TIdSSLVersion;
    fSSLVersions: TIdSSLVersions;
    fMode: TIdSSLMode;
    fsRootCertFile, fsCertFile, fsKeyFile, fsDHParamsFile: String;
    fVerifyDepth: Integer;
    fVerifyMode: TIdSSLVerifyModeSet;
    // fVerifyFile: String;
    fVerifyDirs: String;
    fCipherList: String;
    fContext: PSSL_CTX;
    fStatusInfoOn: Boolean;
    // fPasswordRoutineOn: Boolean;
    fVerifyOn: Boolean;
    fSessionId: Integer;
    fCtxMode: TIdSSLCtxMode;
    procedure DestroyContext;
    function SetSSLMethod: PSSL_METHOD;
    procedure SetVerifyMode(Mode: TIdSSLVerifyModeSet; CheckRoutine: Boolean);
    function GetVerifyMode: TIdSSLVerifyModeSet;
    procedure InitContext(CtxMode: TIdSSLCtxMode);
  public
{$IFDEF USE_OBJECT_ARC}[Weak]
{$ENDIF} Parent: TObject;
    constructor Create;
    destructor Destroy; override;
    function Clone: TIdSSLContext;
    function LoadRootCert: Boolean;
    function LoadCert: Boolean;
    function LoadKey: Boolean;
    function LoadDHParams: Boolean;
    property StatusInfoOn: Boolean read fStatusInfoOn write fStatusInfoOn;
    // property PasswordRoutineOn: Boolean read fPasswordRoutineOn write fPasswordRoutineOn;
    property VerifyOn: Boolean read fVerifyOn write fVerifyOn;
    // THese can't be published in a TObject without a compiler warning.
    // published
    property SSLVersions: TIdSSLVersions read fSSLVersions write fSSLVersions;
    property Method: TIdSSLVersion read fMethod write fMethod;
    property Mode: TIdSSLMode read fMode write fMode;
    property RootCertFile: String read fsRootCertFile write fsRootCertFile;
    property CertFile: String read fsCertFile write fsCertFile;
    property CipherList: String read fCipherList write fCipherList;
    property KeyFile: String read fsKeyFile write fsKeyFile;
    property DHParamsFile: String read fsDHParamsFile write fsDHParamsFile;
    // property VerifyMode: TIdSSLVerifyModeSet read GetVerifyMode write SetVerifyMode;
    // property VerifyFile: String read fVerifyFile write fVerifyFile;
    property VerifyDirs: String read fVerifyDirs write fVerifyDirs;
    property VerifyMode: TIdSSLVerifyModeSet read fVerifyMode write fVerifyMode;
    property VerifyDepth: Integer read fVerifyDepth write fVerifyDepth;

  end;

  TIdSSLSocket = class(TObject)
  protected
{$IFDEF USE_OBJECT_ARC}[Weak]
{$ENDIF} fParent: TObject;
    fPeerCert: TIdX509;
    fSSL: PSSL;
    fSSLCipher: TIdSSLCipher;
    fSSLContext: TIdSSLContext;
    fHostName: String;
    function GetPeerCert: TIdX509;
    function GetSSLError(retCode: Integer): Integer;
    function GetSSLCipher: TIdSSLCipher;
  public
    constructor Create(Parent: TObject);
    destructor Destroy; override;
    procedure Accept(const pHandle: TIdStackSocketHandle);
    procedure Connect(const pHandle: TIdStackSocketHandle);
    function Send(const ABuffer: TIdBytes; AOffset, ALength: Integer): Integer;
    function Recv(var ABuffer: TIdBytes): Integer;
    function GetSessionID: TIdSSLByteArray;
    function GetSessionIDAsString: String;
    procedure SetCipherList(CipherList: String);
    //
    property PeerCert: TIdX509 read GetPeerCert;
    property Cipher: TIdSSLCipher read GetSSLCipher;
    property HostName: String read fHostName;
  end;

  // TIdSSLIOHandlerSocketOpenSSL110 and TIdServerIOHandlerSSLOpenSSL110 have some common
  // functions, but they do not have a common ancestor, so this interface helps
  // bridge the gap...
  IIdSSLOpenSSLCallbackHelper = interface(IInterface)
    ['{583F1209-10BA-4E06-8810-155FAEC415FE}']
    function GetPassword(const AIsWrite: Boolean): string;
    procedure StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT;
      const AStatusStr: string);
    function VerifyPeer(ACertificate: TIdX509; AOk: Boolean;
      ADepth, AError: Integer): Boolean;
    function GetIOHandlerSelf: TIdSSLIOHandlerSocketOpenSSL110;
  end;

  TIdSSLIOHandlerSocketOpenSSL110 = class(TIdSSLIOHandlerSocketBase,
    IIdSSLOpenSSLCallbackHelper)
  protected
    fSSLContext: TIdSSLContext;
    fxSSLOptions: TIdSSLOptions;
    fSSLSocket: TIdSSLSocket;
    // fPeerCert: TIdX509;
    fOnStatusInfo: TCallbackEvent;
    FOnStatusInfoEx: TCallbackExEvent;
    fOnGetPassword: TPasswordEvent;
    fOnGetPasswordEx: TPasswordEventEx;
    fOnVerifyPeer: TVerifyPeerEvent;
    fSSLLayerClosed: Boolean;
    fOnBeforeConnect: TIOHandlerNotify;
    // function GetPeerCert: TIdX509;
    // procedure CreateSSLContext(axMode: TIdSSLMode);
    //
    procedure SetPassThrough(const Value: Boolean); override;
    procedure DoBeforeConnect(ASender: TIdSSLIOHandlerSocketOpenSSL110); virtual;
    procedure DoStatusInfo(const AMsg: String); virtual;
    procedure DoStatusInfoEx(const AsslSocket: PSSL;
      const AWhere, Aret: TIdC_INT; const AWhereStr, ARetStr: String);
    procedure DoGetPassword(var Password: String); virtual;
    procedure DoGetPasswordEx(var VPassword: String;
      const AIsWrite: Boolean); virtual;

    function DoVerifyPeer(Certificate: TIdX509; AOk: Boolean;
      ADepth, AError: Integer): Boolean; virtual;
    function RecvEnc(var VBuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer)
      : Integer; override;
    procedure Init;
    procedure OpenEncodedConnection; virtual;
    // some overrides from base classes
    procedure InitComponent; override;
    procedure ConnectClient; override;
    function CheckForError(ALastResult: Integer): Integer; override;
    procedure RaiseError(AError: Integer); override;

    { IIdSSLOpenSSLCallbackHelper }
    function GetPassword(const AIsWrite: Boolean): string;
    procedure StatusInfo(const AsslSocket: PSSL; AWhere, Aret: TIdC_INT;
      const AStatusStr: string);
    function VerifyPeer(ACertificate: TIdX509; AOk: Boolean;
      ADepth, AError: Integer): Boolean;
    function GetIOHandlerSelf: TIdSSLIOHandlerSocketOpenSSL110;

  public
    destructor Destroy; override;
    // TODO: add an AOwner parameter
    function Clone: TIdSSLIOHandlerSocketBase; override;
    procedure StartSSL; override;
    procedure AfterAccept; override;
    procedure Close; override;
    procedure Open; override;
    function Readable(AMSec: Integer = IdTimeoutDefault): Boolean; override;
    property SSLSocket: TIdSSLSocket read fSSLSocket write fSSLSocket;
    property OnBeforeConnect: TIOHandlerNotify read fOnBeforeConnect
      write fOnBeforeConnect;
    property SSLContext: TIdSSLContext read fSSLContext write fSSLContext;
  published
    property SSLOptions: TIdSSLOptions read fxSSLOptions write fxSSLOptions;
    property OnStatusInfo: TCallbackEvent read fOnStatusInfo
      write fOnStatusInfo;
    property OnStatusInfoEx: TCallbackExEvent read FOnStatusInfoEx
      write FOnStatusInfoEx;
    property OnGetPassword: TPasswordEvent read fOnGetPassword
      write fOnGetPassword;
    property OnGetPasswordEx: TPasswordEventEx read fOnGetPasswordEx
      write fOnGetPasswordEx;
    property OnVerifyPeer: TVerifyPeerEvent read fOnVerifyPeer
      write fOnVerifyPeer;
  end;

  TIdServerIOHandlerSSLOpenSSL110 = class(TIdServerIOHandlerSSLBase,
    IIdSSLOpenSSLCallbackHelper)
  protected
    fxSSLOptions: TIdSSLOptions;
    fSSLContext: TIdSSLContext;
    fOnStatusInfo: TCallbackEvent;
    FOnStatusInfoEx: TCallbackExEvent;
    fOnGetPassword: TPasswordEvent;
    fOnGetPasswordEx: TPasswordEventEx;
    fOnVerifyPeer: TVerifyPeerEvent;
    //
    // procedure CreateSSLContext(axMode: TIdSSLMode);
    // procedure CreateSSLContext;
    //
    procedure DoStatusInfo(const AMsg: String); virtual;
    procedure DoStatusInfoEx(const AsslSocket: PSSL;
      const AWhere, Aret: TIdC_INT; const AWhereStr, ARetStr: String);
    procedure DoGetPassword(var Password: String); virtual;
    // TPasswordEventEx
    procedure DoGetPasswordEx(var VPassword: String;
      const AIsWrite: Boolean); virtual;
    function DoVerifyPeer(Certificate: TIdX509; AOk: Boolean;
      ADepth, AError: Integer): Boolean; virtual;
    procedure InitComponent; override;

    { IIdSSLOpenSSLCallbackHelper }
    function GetPassword(const AIsWrite: Boolean): string;
    procedure StatusInfo(const AsslSocket: PSSL; AWhere, Aret: TIdC_INT;
      const AStatusStr: string);
    function VerifyPeer(ACertificate: TIdX509; AOk: Boolean;
      ADepth, AError: Integer): Boolean;
    function GetIOHandlerSelf: TIdSSLIOHandlerSocketOpenSSL110;

  public
    procedure Init; override;
    procedure Shutdown; override;
    // AListenerThread is a thread and not a yarn. Its the listener thread.
    function Accept(ASocket: TIdSocketHandle; AListenerThread: TIdThread;
      AYarn: TIdYarn): TIdIOHandler; override;
    // function Accept(ASocket: TIdSocketHandle; AThread: TIdThread) : TIdIOHandler;  override;
    destructor Destroy; override;
    function MakeClientIOHandler: TIdSSLIOHandlerSocketBase; override;
    //
    function MakeFTPSvrPort: TIdSSLIOHandlerSocketBase; override;
    function MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase; override;
    //
    property SSLContext: TIdSSLContext read fSSLContext;
  published
    property SSLOptions: TIdSSLOptions read fxSSLOptions write fxSSLOptions;
    property OnStatusInfo: TCallbackEvent read fOnStatusInfo
      write fOnStatusInfo;
    property OnStatusInfoEx: TCallbackExEvent read FOnStatusInfoEx
      write FOnStatusInfoEx;
    property OnGetPassword: TPasswordEvent read fOnGetPassword
      write fOnGetPassword;
    property OnGetPasswordEx: TPasswordEventEx read fOnGetPasswordEx
      write fOnGetPasswordEx;
    property OnVerifyPeer: TVerifyPeerEvent read fOnVerifyPeer
      write fOnVerifyPeer;
  end;

  TIdX509Name = class(TObject)
  protected
    fX509Name: PX509_NAME;
    function CertInOneLine: String;
    function GetHash: TIdSSLULong;
    function GetHashAsString: String;
  public
    constructor Create(aX509Name: PX509_NAME);
    //
    property Hash: TIdSSLULong read GetHash;
    property HashAsString: string read GetHashAsString;
    property OneLine: string read CertInOneLine;
    //
    property CertificateName: PX509_NAME read fX509Name;
  end;

  TIdX509Info = class(TObject)
  protected
    // Do not free this here because it belongs
    // to the X509 or something else.
    FX509: PX509;
  public
    constructor Create(aX509: PX509);
    //
    property Certificate: PX509 read FX509;
  end;

  TIdX509Fingerprints = class(TIdX509Info)
  protected
    function GetMD5: TIdSSLEVP_MD;
    function GetMD5AsString: String;
    function GetSHA1: TIdSSLEVP_MD;
    function GetSHA1AsString: String;
    function GetSHA224: TIdSSLEVP_MD;
    function GetSHA224AsString: String;
    function GetSHA256: TIdSSLEVP_MD;
    function GetSHA256AsString: String;
    function GetSHA384: TIdSSLEVP_MD;
    function GetSHA384AsString: String;
    function GetSHA512: TIdSSLEVP_MD;
    function GetSHA512AsString: String;
  public
    property MD5: TIdSSLEVP_MD read GetMD5;
    property MD5AsString: String read GetMD5AsString;
    { IMPORTANT!!!

      FIPS approves only these algorithms for hashing.
      SHA-1
      SHA-224
      SHA-256
      SHA-384
      SHA-512

      http://csrc.nist.gov/CryptoToolkit/tkhash.html
    }
    property SHA1: TIdSSLEVP_MD read GetSHA1;
    property SHA1AsString: String read GetSHA1AsString;
    property SHA224: TIdSSLEVP_MD read GetSHA224;
    property SHA224AsString: String read GetSHA224AsString;
    property SHA256: TIdSSLEVP_MD read GetSHA256;
    property SHA256AsString: String read GetSHA256AsString;
    property SHA384: TIdSSLEVP_MD read GetSHA384;
    property SHA384AsString: String read GetSHA384AsString;
    property SHA512: TIdSSLEVP_MD read GetSHA512;
    property SHA512AsString: String read GetSHA512AsString;
  end;

  TIdX509SigInfo = class(TIdX509Info)
  protected
    function GetSignature: String;
    function GetSigType: TIdC_INT;
    function GetSigTypeAsString: String;
  public
    property Signature: String read GetSignature;
    property SigType: TIdC_INT read GetSigType;
    property SigTypeAsString: String read GetSigTypeAsString;
  end;

  TIdX509 = class(TObject)
  protected
    FFingerprints: TIdX509Fingerprints;
    FSigInfo: TIdX509SigInfo;
    FCanFreeX509: Boolean;
    FX509: PX509;
    FSubject: TIdX509Name;
    FIssuer: TIdX509Name;
    FDisplayInfo: TStrings;
    function RSubject: TIdX509Name;
    function RIssuer: TIdX509Name;
    function RnotBefore: TDateTime;
    function RnotAfter: TDateTime;
    function RFingerprint: TIdSSLEVP_MD;
    function RFingerprintAsString: String;
    function GetSerialNumber: String;
    function GetVersion: TIdC_LONG;
    function GetDisplayInfo: TStrings;
  public
    Constructor Create(aX509: PX509; aCanFreeX509: Boolean = True); virtual;
    Destructor Destroy; override;
    property Version: TIdC_LONG read GetVersion;
    //
    property SigInfo: TIdX509SigInfo read FSigInfo;
    property Fingerprints: TIdX509Fingerprints read FFingerprints;
    //
    property Fingerprint: TIdSSLEVP_MD read RFingerprint;
    property FingerprintAsString: String read RFingerprintAsString;
    property Subject: TIdX509Name read RSubject;
    property Issuer: TIdX509Name read RIssuer;
    property notBefore: TDateTime read RnotBefore;
    property notAfter: TDateTime read RnotAfter;
    property SerialNumber: string read GetSerialNumber;
    property DisplayInfo: TStrings read GetDisplayInfo;
    //
    property Certificate: PX509 read FX509;
  end;

  TIdSSLCipher = class(TObject)
  protected
    fSSLSocket: TIdSSLSocket;
    function GetDescription: String;
    function GetName: String;
    function GetBits: Integer;
    function GetVersion: String;
  public
    constructor Create(AOwner: TIdSSLSocket);
    destructor Destroy; override;
    // These can't be published without a compiler warning.
    // published
    property Description: String read GetDescription;
    property Name: String read GetName;
    property Bits: Integer read GetBits;
    property Version: String read GetVersion;
  end;

  EIdOSSLCouldNotLoadSSLLibrary = class(EIdOpenSSLError);
  EIdOSSLModeNotSet = class(EIdOpenSSLError);
  EIdOSSLCreatingSessionError = class(EIdOpenSSLError);
  EIdOSSLCreatingContextError = class(EIdOpenSSLAPICryptoError);
  EIdOSSLLoadingRootCertError = class(EIdOpenSSLAPICryptoError);
  EIdOSSLLoadingCertError = class(EIdOpenSSLAPICryptoError);
  EIdOSSLLoadingKeyError = class(EIdOpenSSLAPICryptoError);
  EIdOSSLLoadingDHParamsError = class(EIdOpenSSLAPICryptoError);
  EIdOSSLSettingCipherError = class(EIdOpenSSLError);
  EIdOSSLFDSetError = class(EIdOpenSSLAPISSLError);
  EIdOSSLDataBindingError = class(EIdOpenSSLAPISSLError);
  EIdOSSLAcceptError = class(EIdOpenSSLAPISSLError);
  EIdOSSLConnectError = class(EIdOpenSSLAPISSLError);
{$IFNDEF OPENSSL_NO_TLSEXT}
  EIdOSSLSettingTLSHostNameError = class(EIdOpenSSLAPISSLError);
{$ENDIF}
  EIdOSSLCouldNotSetMinProtocolVersion = class(EIdOpenSSLAPISSLError);
  EIdOSSLCouldNotSetMaxProtocolVersion = class(EIdOpenSSLAPISSLError);

function LoadOpenSSLLibrary: Boolean;
procedure UnLoadOpenSSLLibrary;

function OpenSSLVersion: string;

implementation

uses
{$IFDEF HAS_UNIT_Generics_Collections}
  System.Generics.Collections,
{$ENDIF}
{$IFDEF USE_VCL_POSIX}
  Posix.SysTime,
  Posix.Time,
  Posix.Unistd,
{$ENDIF}
  IdOpenSSLHeaders_asn1,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_crypto,
  IdOpenSSLHeaders_dh,
  IdOpenSSLHeaders_ec,
  IdOpenSSLHeaders_err,
  IdOpenSSLHeaders_objects,
  IdOpenSSLHeaders_pem,
  IdOpenSSLHeaders_pkcs7,
  IdOpenSSLHeaders_pkcs12,
  IdOpenSSLHeaders_sslerr,
  IdOpenSSLHeaders_stack,
  IdOpenSSLHeaders_tls1,
  IdOpenSSLHeaders_x509,
  IdOpenSSLHeaders_x509_vfy,
  IdFIPS,
  IdResourceStringsCore,
  IdResourceStringsProtocols,
  IdResourceStringsOpenSSL110,
  IdSSLOpenSSLLoader,
  IdStack,
  IdStackBSDBase,
  IdAntiFreezeBase,
  IdExceptionCore,
  IdResourceStrings,
  IdThreadSafe,
  IdCustomTransparentProxy,
  IdURI,
  SysUtils,
  SyncObjs;

const
  INDY_CALLBACK_USERDATA = 0;
  INDY_PASSWORD_CALLBACK = 1;

type
  // TODO: TIdThreadSafeObjectList instead?
{$IFDEF HAS_GENERICS_TThreadList}
  TIdCriticalSectionThreadList = TThreadList<TIdCriticalSection>;
  TIdCriticalSectionList = TList<TIdCriticalSection>;
{$ELSE}
  // TODO: flesh out to match TThreadList<TIdCriticalSection> and TList<TIdCriticalSection> on non-Generics compilers
  TIdCriticalSectionThreadList = TThreadList;
  TIdCriticalSectionList = TList;
{$ENDIF}

  // RLebeau 1/24/2019: defining this as a private implementation for now to
  // avoid a change in the public interface above.  This should be rolled into
  // the public interface at some point...
  TIdSSLOptions_Internal = class(TIdSSLOptions)
  public
{$IFDEF USE_OBJECT_ARC}[Weak]
{$ENDIF} Parent: TObject;
  end;

var
  SSLIsLoaded: TIdThreadSafeBoolean = nil;
  LockInfoCB: TIdCriticalSection = nil;
  LockPassCB: TIdCriticalSection = nil;
  LockVerifyCB: TIdCriticalSection = nil;
  CallbackLockList: TIdCriticalSectionThreadList = nil;

procedure GetStateVars(const SSLSocket: PSSL; AWhere, Aret: TIdC_INT;
  var VTypeStr, VMsg: String);
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  case AWhere of
    SSL_CB_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLAlert, [SSL_alert_type_string_long(Aret)]);
        VMsg := String(SSL_alert_type_string_long(Aret));
      end;
    SSL_CB_READ_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLReadAlert,
          [SSL_alert_type_string_long(Aret)]);
        VMsg := String(SSL_alert_desc_string_long(Aret));
      end;
    SSL_CB_WRITE_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLWriteAlert,
          [SSL_alert_type_string_long(Aret)]);
        VMsg := String(SSL_alert_desc_string_long(Aret));
      end;
    SSL_CB_ACCEPT_LOOP:
      begin
        VTypeStr := RSOSSLAcceptLoop;
        VMsg := String(SSL_state_string_long(SSLSocket));
      end;
    SSL_CB_ACCEPT_EXIT:
      begin
        if Aret < 0 then
        begin
          VTypeStr := RSOSSLAcceptError;
        end
        else
        begin
          if Aret = 0 then
          begin
            VTypeStr := RSOSSLAcceptFailed;
          end
          else
          begin
            VTypeStr := RSOSSLAcceptExit;
          end;
        end;
        VMsg := String(SSL_state_string_long(SSLSocket));
      end;
    SSL_CB_CONNECT_LOOP:
      begin
        VTypeStr := RSOSSLConnectLoop;
        VMsg := String(SSL_state_string_long(SSLSocket));
      end;
    SSL_CB_CONNECT_EXIT:
      begin
        if Aret < 0 then
        begin
          VTypeStr := RSOSSLConnectError;
        end
        else
        begin
          if Aret = 0 then
          begin
            VTypeStr := RSOSSLConnectFailed
          end
          else
          begin
            VTypeStr := RSOSSLConnectExit;
          end;
        end;
        VMsg := String(SSL_state_string_long(SSLSocket));
      end;
    SSL_CB_HANDSHAKE_START:
      begin
        VTypeStr := RSOSSLHandshakeStart;
        VMsg := String(SSL_state_string_long(SSLSocket));
      end;
    SSL_CB_HANDSHAKE_DONE:
      begin
        VTypeStr := RSOSSLHandshakeDone;
        VMsg := String(SSL_state_string_long(SSLSocket));
      end;
  end;
  { var LW : TIdC_INT;
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
    VMsg := IdSslStateStringLong(sslSocket);
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
    VMsg := IdSslStateStringLong(sslSocket);
    end else begin
    if ARet < 0  then  begin
    VWhereStr := VWhereStr +'error';
    VMsg := IdSslStateStringLong(sslSocket);
    end;
    end;
    end;
    end;
    end; }
end;

function PasswordCallback(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT;
  userdata: Pointer): TIdC_INT; cdecl;
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
  LErr: Integer;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
  // Preserve last eror just in case OpenSSL is using it and we do something that
  // clobers it.  CYA.
  LErr := GStack.WSGetLastError;
  try
    LockPassCB.Enter;
    try
      Password := ''; { Do not Localize }
      IdSSLContext := TIdSSLContext(userdata);
      if Supports(IdSSLContext.Parent, IIdSSLOpenSSLCallbackHelper,
        IInterface(LHelper)) then
      begin
        Password := LHelper.GetPassword(rwflag > 0);
        LHelper := nil;
      end;
      FillChar(buf^, size, 0);
{$IFDEF STRING_IS_UNICODE}
      LPassword := IndyTextEncoding_OSDefault.GetBytes(Password);
      if Length(LPassword) > 0 then
      begin
{$IFDEF USE_MARSHALLED_PTRS}
        TMarshal.Copy(TBytesPtr(@LPassword)^, 0, TPtrWrapper.Create(buf),
          IndyMin(Length(LPassword), size));
{$ELSE}
        Move(LPassword[0], buf^, IndyMin(Length(LPassword), size));
{$ENDIF}
      end;
      Result := Length(LPassword);
{$ELSE}
      StrPLCopy(buf, Password, size);
      Result := Length(Password);
{$ENDIF}
      buf[size - 1] := #0; // RLebeau: truncate the password if needed
    finally
      LockPassCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

procedure InfoCallback(const SSLSocket: PSSL; where, ret: TIdC_INT); cdecl;
var
  IdSSLSocket: TIdSSLSocket;
  StatusStr: String;
  LErr: Integer;
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
      IdSSLSocket := TIdSSLSocket(SSL_get_app_data(SSLSocket));
      if Assigned(IdSSLSocket) then begin
        if Supports(IdSSLSocket.fParent, IIdSSLOpenSSLCallbackHelper,
          IInterface(LHelper)) then begin
            StatusStr := IndyFormat(RSOSSLStatusString,
              [String(SSL_state_string_long(SSLSocket))]);
            LHelper.StatusInfo(SSLSocket, where, ret, StatusStr);
            LHelper := nil;
        end;
      end;
    finally
      LockInfoCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

function TranslateInternalVerifyToSSL(Mode: TIdSSLVerifyModeSet): Integer;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_VERIFY_NONE;
  if sslvrfPeer in Mode then
  begin
    Result := Result or SSL_VERIFY_PEER;
  end;
  if sslvrfFailIfNoPeerCert in Mode then
  begin
    Result := Result or SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  end;
  if sslvrfClientOnce in Mode then
  begin
    Result := Result or SSL_VERIFY_CLIENT_ONCE;
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
      if Assigned(X509_STORE_CTX_get_ex_data) then begin
        hSSL := X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx);
      end else begin
        hSSL := X509_STORE_CTX_get_app_data(ctx);
      end;
      if hSSL = nil then
      begin
        Result := Ok;
        Exit;
      end;
      hcert := X509_STORE_CTX_get_current_cert(ctx);
      Certificate := TIdX509.Create(hcert, False);
      // the certificate is owned by the store
      try
        IdSSLSocket := TIdSSLSocket(SSL_get_app_data(hSSL));
        if Assigned(IdSSLSocket) then begin
          Error := X509_STORE_CTX_get_error(ctx);
          Depth := X509_STORE_CTX_get_error_depth(ctx);
          if not((Ok > 0) and (IdSSLSocket.fSSLContext.VerifyDepth >= Depth)) then
          begin
            Ok := 0;
            { if Error = X509_V_OK then begin
            Error := X509_V_ERR_CERT_CHAIN_TOO_LONG;
            end; }
          end;
          LOk := False;
          if Ok = 1 then
          begin
            LOk := True;
          end;
          if Supports(IdSSLSocket.fParent, IIdSSLOpenSSLCallbackHelper,
            IInterface(LHelper)) then
          begin
            VerifiedOK := LHelper.VerifyPeer(Certificate, LOk, Depth, Error);
            LHelper := nil;
          end;
        end;
      finally
        FreeAndNil(Certificate);
      end;
    except
      VerifiedOK := False;
    end;
    // if VerifiedOK and (Ok > 0) then begin
    if VerifiedOK { and (Ok > 0) } then
    begin
      Result := 1;
    end
    else
    begin
      Result := 0;
    end;
    // Result := Ok; // testing
  finally
    LockVerifyCB.Leave;
  end;
end;

/// ///////////////////////////////////////////////////
// Utilities
/// ///////////////////////////////////////////////////

function IndySSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME; forward;
function IndySSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT; forward;
function IndySSL_CTX_use_certificate_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT; forward;
function IndySSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT; forward;

function IndyX509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT; forward;
function IndySSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT; forward;
function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT; forward;

// TODO
{
  function d2i_DHparams_bio(bp: PBIO; x: PPointer): PDH; inline;
  begin
  Result := PDH(ASN1_d2i_bio(@DH_new, @d2i_DHparams, bp, x));
  end;
}

// SSL_CTX_use_PrivateKey_file() and SSL_CTX_use_certificate_file() do not
// natively support PKCS12 certificates/keys, only PEM/ASN1, so load them
// manually...

function IndySSL_CTX_use_PrivateKey_file_PKCS12(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LKey: PEVP_PKEY;
  LCert: PX509;
  P12: PPKCS12;
  CertChain: PSTACK_OF_X509;
  LPassword: array of TIdAnsiChar;
  LPasswordPtr: PIdAnsiChar;
  LPWCallback : function(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT;
    userdata: Pointer): TIdC_INT; cdecl;
begin
  Result := 0;

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    B := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(B) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      SetLength(LPassword, MAX_SSL_PASSWORD_LENGTH + 1);
      LPassword[MAX_SSL_PASSWORD_LENGTH] := TIdAnsiChar(0);
      LPasswordPtr := PIdAnsiChar(LPassword);
      @LPWCallback := SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK);
      if Assigned(LPWCallback) then
      begin
        LPWCallback(LPasswordPtr, MAX_SSL_PASSWORD_LENGTH, 0,
          SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
        // TODO: check return value for failure
      end
      else
      begin
        // TODO: call PEM_def_callback(), like PEM_read_bio_X509() does
        // when default_passwd_callback is nil
      end;
      P12 := d2i_PKCS12_bio(B, nil);
      if not Assigned(P12) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_PKCS12_LIB);
        Exit;
      end;
      try
        CertChain := nil;
        if PKCS12_parse(P12, LPasswordPtr, LKey, LCert, @CertChain) <> 1 then
        begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
          Exit;
        end;
        try
          Result := SSL_CTX_use_PrivateKey(ctx, LKey);
        finally
          if Assigned(CertChain) then begin
            sk_pop_free(CertChain, @X509_free);
          end;
          X509_free(LCert);
          EVP_PKEY_free(LKey);
        end;
      finally
        PKCS12_free(P12);
      end;
    finally
      BIO_free(B);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function IndySSL_CTX_use_certificate_file_PKCS12(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LCert: PX509;
  P12: PPKCS12;
  PKey: PEVP_PKEY;
  CertChain: PSTACK_OF_X509;
  LPassword: array of TIdAnsiChar;
  LPasswordPtr: PIdAnsiChar;
  LPWCallback : function(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT;
    userdata: Pointer): TIdC_INT; cdecl;
begin
  Result := 0;

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    B := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(B) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      SetLength(LPassword, MAX_SSL_PASSWORD_LENGTH + 1);
      LPassword[MAX_SSL_PASSWORD_LENGTH] := TIdAnsiChar(0);
      LPasswordPtr := PIdAnsiChar(LPassword);
      @LPWCallback := SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK);
      if Assigned(LPWCallback) then
      begin
        LPWCallback(LPasswordPtr, MAX_SSL_PASSWORD_LENGTH, 0,
          SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
        // TODO: check return value for failure
      end
      else
      begin
        // TODO: call PEM_def_callback(), like PEM_read_bio_X509() does
        // when default_passwd_callback is nil
      end;
      P12 := d2i_PKCS12_bio(B, nil);
      if not Assigned(P12) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
        Exit;
      end;
      try
        CertChain := nil;
        if PKCS12_parse(P12, LPasswordPtr, PKey, LCert, @CertChain) <> 1 then
        begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
          Exit;
        end;
        try
          Result := SSL_CTX_use_certificate(ctx, LCert);
        finally
          if Assigned(CertChain) then
          begin
            sk_pop_free(CertChain, @X509_free);
          end;
          X509_free(LCert);
          EVP_PKEY_free(PKey);
        end;
      finally
        PKCS12_free(P12);
      end;
    finally
      BIO_free(B);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

{
  IMPORTANT!!!

  OpenSSL can not handle Unicode file names at all.  On Posix systems, UTF8 File
  names can be used with OpenSSL.  The Windows operating system does not accept
  UTF8 file names at all so we have our own routines that will handle Unicode
  filenames.   Most of this section of code is based on code in the OpenSSL .DLL
  which is copyrighted by the OpenSSL developers.  Some of it is translated into
  Pascal and made some modifications so that it will handle Unicode filenames.
}

{$IFDEF STRING_IS_UNICODE}
{$IFDEF WINDOWS}
function Indy_unicode_X509_load_cert_crl_file(ctx: PX509_LOOKUP;
  const AFileName: String; const _type: TIdC_INT): TIdC_INT; forward;
function Indy_unicode_X509_load_cert_file(ctx: PX509_LOOKUP;
  const AFileName: String; _type: TIdC_INT): TIdC_INT; forward;

{
  This is for some file lookup definitions for a LOOKUP method that
  uses Unicode filenames instead of ASCII or UTF8.  It is not meant
  to be portable at all.
}
function by_Indy_unicode_file_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT;
  const argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl; forward;

function Indy_Unicode_X509_LOOKUP_file(): PX509_LOOKUP_METHOD cdecl;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := X509_LOOKUP_meth_new('Load file into cache');
  X509_LOOKUP_meth_set_ctrl(Result, by_Indy_unicode_file_ctrl);
end;

function by_Indy_unicode_file_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT;
  const argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl;
var
  LOk: TIdC_INT;
  LFileName: String;
begin
  LOk := 0;
  case cmd of
    X509_L_FILE_LOAD:
      begin
        // Note that typecasting an AnsiChar as a WideChar below is normally a crazy
        // thing to do.  The thing is that the OpenSSL API is based on PAnsiChar, and
        // we are writing this function just for Unicode filenames.  argc is actually
        // a PWideChar that has been coerced into a PAnsiChar so it can pass through
        // OpenSSL APIs...
        case argl of
          X509_FILETYPE_DEFAULT:
            begin
              LFileName := GetEnvironmentVariable
                (String(X509_get_default_cert_file_env));
              if LFileName = '' then
              begin
                LFileName := String(X509_get_default_cert_file);
              end;
              LOk := Ord(Indy_unicode_X509_load_cert_crl_file(ctx, LFileName,
                X509_FILETYPE_PEM) <> 0);
              if LOk = 0 then
              begin
                X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
              end;
            end;
          X509_FILETYPE_PEM:
            begin
              LFileName := PWideChar(Pointer(argc));
              LOk := Ord(Indy_unicode_X509_load_cert_crl_file(ctx, LFileName,
                X509_FILETYPE_PEM) <> 0);
            end;
        else
          LFileName := PWideChar(Pointer(argc));
          LOk := Ord(Indy_unicode_X509_load_cert_file(ctx, LFileName,
            TIdC_INT(argl)) <> 0);
        end;
      end;
  end;
  Result := LOk;
end;

function Indy_unicode_X509_load_cert_file(ctx: PX509_LOOKUP;
  const AFileName: String; _type: TIdC_INT): TIdC_INT;
var
  LM: TMemoryStream;
  Lin: PBIO;
  LX: PX509;
  i, count: Integer;
begin
  Result := 0;
  count := 0;

  if AFileName = '' then
  begin
    Result := 1;
    Exit;
  end;

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    Lin := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(Lin) then
    begin
      X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
      Exit;
    end;
    try
      case _type of
        X509_FILETYPE_PEM:
          begin
            repeat
              LX := PEM_read_bio_X509_AUX(Lin, nil, nil, nil);
              if not Assigned(LX) then
              begin
                if ((ERR_GET_REASON(ERR_peek_last_error())
                  = PEM_R_NO_START_LINE) and (count > 0)) then
                begin
                  ERR_clear_error();
                  Break;
                end
                else
                begin
                  X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_PEM_LIB);
                  Exit;
                end;
              end;
              i := X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), LX);
              if i = 0 then
              begin
                Exit;
              end;
              Inc(count);
              X509_free(LX);
            until False;
            Result := count;
          end;
        X509_FILETYPE_ASN1:
          begin
            LX := d2i_X509_bio(Lin, nil);
            if not Assigned(LX) then
            begin
              X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
              Exit;
            end;
            i := X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), LX);
            if i = 0 then
            begin
              Exit;
            end;
            Result := i;
          end;
      else
        X509err(X509_F_X509_LOAD_CERT_FILE, X509_R_BAD_X509_FILETYPE);
        Exit;
      end;
    finally
      BIO_free(Lin);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function Indy_unicode_X509_load_cert_crl_file(ctx: PX509_LOOKUP;
  const AFileName: String; const _type: TIdC_INT): TIdC_INT;
var
  LM: TMemoryStream;
  Linf: PSTACK_OF_X509_INFO;
  Litmp: PX509_INFO;
  Lin: PBIO;
  i, count: Integer;
begin
  Result := 0;
  count := 0;
  LM := nil;

  if _type <> X509_FILETYPE_PEM then
  begin
    Result := Indy_unicode_X509_load_cert_file(ctx, AFileName, _type);
    Exit;
  end;

  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    Lin := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(Lin) then
    begin
      X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
      Exit;
    end;
    try
      Linf := PEM_X509_INFO_read_bio(Lin, nil, nil, nil);
    finally
      BIO_free(Lin);
    end;
  finally
    FreeAndNil(LM);
  end;
  if not Assigned(Linf) then
  begin
    X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
    Exit;
  end;
  try
    for i := 0 to sk_X509_INFO_num(Linf) - 1 do
    begin
      Litmp := sk_X509_INFO_value(Linf, i);
      if Assigned(Litmp^.x509) and Assigned(ctx) then
      begin
        X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), Litmp^.x509);
        Inc(count);
      end;
      if Assigned(Litmp^.crl) and Assigned(ctx) then
      begin
        X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), Litmp^.x509);
        Inc(count);
      end;
    end;
  finally
    sk_X509_INFO_pop_free(Linf, @X509_INFO_free);
  end;
  Result := count;
end;

procedure IndySSL_load_client_CA_file_err(var VRes: PSTACK_OF_X509_NAME);
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  if Assigned(VRes) then
  begin
    sk_X509_NAME_pop_free(VRes, @X509_NAME_free);
    VRes := nil;
  end;
end;

function xname_cmp(const a, B: PPX509_NAME): TIdC_INT; cdecl;
begin
  Result := X509_NAME_cmp(a^, B^);
end;

function IndySSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
var
  LM: TMemoryStream;
  LB: PBIO;
  Lsk: PSTACK_OF_X509_NAME;
  LX: PX509;
  LXN, LXNDup: PX509_NAME;
  Failed: Boolean;
begin
  Result := nil;
  Failed := False;
  LX := nil;
  Lsk := sk_X509_NAME_new(@xname_cmp);
  if Assigned(Lsk) then
  begin
    try
      LM := nil;
      try
        LM := TMemoryStream.Create;
        LM.LoadFromFile(AFileName);
      except
        // Surpress exception here since it's going to be called by the OpenSSL .DLL
        // Follow the OpenSSL .DLL Error conventions.
        SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_SYS_LIB);
        LM.Free;
        Exit;
      end;
      try
        LB := BIO_new_mem_buf(LM.Memory, LM.size);
        if Assigned(LB) then
        begin
          try
            try
              repeat
                LX := PEM_read_bio_X509(LB, nil, nil, nil);
                if LX = nil then
                begin
                  Break;
                end;
                if not Assigned(Result) then
                begin
                  Result := sk_X509_NAME_new_null;
                  if not Assigned(Result) then
                  begin
                    SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                    Failed := True;
                    Exit;
                  end;
                end;
                LXN := X509_get_subject_name(LX);
                if not Assigned(LXN) then
                begin
                  // error
                  IndySSL_load_client_CA_file_err(Result);
                  Failed := True;
                  Exit;
                end;
                // * check for duplicates */
                LXNDup := X509_NAME_dup(LXN);
                if not Assigned(LXNDup) then
                begin
                  // error
                  IndySSL_load_client_CA_file_err(Result);
                  Failed := True;
                  Exit;
                end;
                if (sk_X509_NAME_find(Lsk, LXNDup) >= 0) then
                begin
                  X509_NAME_free(LXNDup);
                end
                else
                begin
                  sk_X509_NAME_push(Lsk, LXNDup);
                  sk_X509_NAME_push(Result, LXNDup);
                end;
                X509_free(LX);
                LX := nil;
              until False;
            finally
              if Assigned(LX) then
              begin
                X509_free(LX);
              end;
              if Failed and Assigned(Result) then
              begin
                sk_X509_NAME_pop_free(Result, @X509_NAME_free);
                Result := nil;
              end;
            end;
          finally
            BIO_free(LB);
          end;
        end
        else
        begin
          SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        end;
      finally
        FreeAndNil(LM);
      end;
    finally
      sk_X509_NAME_free(Lsk);
    end;
  end
  else
  begin
    SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
  end;
  if Assigned(Result) then
  begin
    ERR_clear_error;
  end;
end;

function IndySSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LKey: PEVP_PKEY;
  j: TIdC_INT;
begin
  Result := 0;

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    B := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(B) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      case AType of
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_PEM_LIB;
            LKey := PEM_read_bio_PrivateKey(B, nil,
              SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK),
              SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
          end;
        SSL_FILETYPE_ASN1:
          begin
            j := ERR_R_ASN1_LIB;
            LKey := d2i_PrivateKey_bio(B, nil);
          end;
      else
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        Exit;
      end;
      if not Assigned(LKey) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        Exit;
      end;
      Result := SSL_CTX_use_PrivateKey(ctx, LKey);
      EVP_PKEY_free(LKey);
    finally
      BIO_free(B);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function IndySSL_CTX_use_certificate_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LX: PX509;
  j: TIdC_INT;
begin
  Result := 0;

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    B := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(B) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      case AType of
        SSL_FILETYPE_ASN1:
          begin
            j := ERR_R_ASN1_LIB;
            LX := d2i_X509_bio(B, nil);
          end;
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_PEM_LIB;
            LX := PEM_read_bio_X509(B, nil, SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK),
              SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
          end
      else
        begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LX) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, j);
        Exit;
      end;
      Result := SSL_CTX_use_certificate(ctx, LX);
      X509_free(LX);
    finally
      BIO_free(B);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function IndySSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LX: PX509;
  ca: PX509;
  r: TIdC_INT;
  LErr: TIdC_ULONG;

begin
  Result := 0;

  ERR_clear_error(); // * clear error stack for
  // * SSL_CTX_use_certificate() */

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;
  try
    B := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(B) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      LX := PEM_read_bio_X509_AUX(B, nil, SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK),
        SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
      if (LX = nil) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
      end
      else
      begin
        Result := SSL_CTX_use_certificate(ctx, LX);
        if (ERR_peek_error() <> 0) then
        begin
          Result := 0; // * Key/certificate mismatch doesn't imply
          // * ret==0 ... */
        end;
        if Result <> 0 then
        begin
          SSL_CTX_clear_chain_certs(ctx);
          repeat
            ca := PEM_read_bio_X509(B, nil, SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK),
              SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
            if ca = nil then
            begin
              Break;
            end;
            r := SSL_CTX_add0_chain_cert(ctx, ca);
            if (r = 0) then
            begin
              X509_free(ca);
              Result := 0;
              Break;
              // goto end;
            end;
            // *
            // * Note that we must not free r if it was successfully added to
            // * the chain (while we must free the main certificate, since its
            // * reference count is increased by SSL_CTX_use_certificate).
            // */
          until False;
          if ca <> nil then
          begin
            // * When the while loop ends, it's usually just EOF. */
            LErr := ERR_peek_last_error();
            if (ERR_GET_LIB(LErr) = ERR_LIB_PEM) and
              (ERR_GET_REASON(LErr) = PEM_R_NO_START_LINE) then
            begin
              ERR_clear_error();
            end
            else
            begin
              Result := 0; // * some real error */
            end;
          end;
        end;
        // err:
        if LX <> nil then
        begin
          X509_free(LX);
        end;
      end;
    finally
      BIO_free(B);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function IndyX509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;
var
  lookup: PX509_LOOKUP;
begin
  Result := 0;
  if AFileName <> '' then
  begin
    lookup := X509_STORE_add_lookup(ctx, Indy_Unicode_X509_LOOKUP_file);
    if not Assigned(lookup) then
    begin
      Exit;
    end;
    // RLebeau: the PAnsiChar(Pointer(...)) cast below looks weird, but it is
    // intentional. X509_LOOKUP_load_file() takes a PAnsiChar as input, but
    // we are using Unicode strings here.  So casting the UnicodeString to a
    // raw Pointer and then passing that to X509_LOOKUP_load_file() as PAnsiChar.
    // Indy_Unicode_X509_LOOKUP_file will cast it back to PWideChar for processing...
    if (X509_LOOKUP_load_file(lookup, PAnsiChar(Pointer(AFileName)),
      X509_FILETYPE_PEM) <> 1) then
    begin
      Exit;
    end;
  end;
  if APathName <> '' then
  begin
    { TODO: Figure out how to do the hash dir lookup with a Unicode path. }
    if (X509_STORE_load_locations(ctx, nil, PAnsiChar(AnsiString(APathName)))
      <> 1) then
    begin
      Exit;
    end;
  end;
  if (AFileName = '') and (APathName = '') then
  begin
    Exit;
  end;
  Result := 1;
end;

function IndySSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
   Result := IndyX509_STORE_load_locations(SSL_CTX_get_cert_store(ctx), ACAFile, ACAPath);
end;

function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LDH: PDH;
  j: Integer;
begin
  Result := 0;

  LM := nil;
  try
    LM := TMemoryStream.Create;
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL3_CTRL, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    B := BIO_new_mem_buf(LM.Memory, LM.size);
    if not Assigned(B) then
    begin
      SSLerr(SSL_F_SSL3_CTRL, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      case AType of

          SSL_FILETYPE_ASN1:
          begin
          j := ERR_R_ASN1_LIB;
//          LDH := d2i_DHparams_bio(B, nil);
          end;
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_DH_LIB;
            LDH := PEM_read_bio_DHparams(B, nil, SSL_CTX_get_ex_data(ctx, INDY_PASSWORD_CALLBACK),
              SSL_CTX_get_ex_data(ctx, INDY_CALLBACK_USERDATA));
          end
      else
        begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then
      begin
        SSLerr(SSL_F_SSL3_CTRL, j);
        Exit;
      end;
      Result := SSL_CTX_set_tmp_dh(ctx, LDH);
      DH_free(LDH);
    finally
      BIO_free(B);
    end;
  finally
    FreeAndNil(LM);
  end;
end;

{$ENDIF} // WINDOWS

{$IFDEF UNIX}

function IndySSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_load_client_CA_file(
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))
{$ENDIF}
    );
end;

function IndySSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_CTX_use_PrivateKey_file(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))
{$ENDIF}
    , AType);
end;

function IndySSL_CTX_use_certificate_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_CTX_use_certificate_file(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))
{$ENDIF}
    , AType);
end;

function IndySSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_CTX_use_certificate_chain_file(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))
{$ENDIF});
end;

{$IFDEF USE_MARSHALLED_PTRS}

function AsUtf8OrNil(var M: TMarshaller; const S: String): Pointer;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  if S <> '' then
  begin
    Result := M.AsUtf8(S).ToPointer;
  end
  else
  begin
    Result := nil;
  end;
end;
{$ENDIF}

function IndyX509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  // RLebeau 4/18/2010: X509_STORE_load_locations() expects nil pointers
  // for unused values, but casting a string directly to a PAnsiChar
  // always produces a non-nil pointer, which causes X509_STORE_load_locations()
  // to fail. Need to cast the string to an intermediate Pointer so the
  // PAnsiChar cast is applied to the raw data and thus can be nil...
  //
  // RLebeau 8/18/2017: TMarshaller also produces a non-nil TPtrWrapper for
  // an empty string, so need to handle nil specially with marshalled
  // strings as well...
  //
  Result := X509_STORE_load_locations(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    AsUtf8OrNil(M, AFileName), AsUtf8OrNil(M, APathName)
{$ELSE}
    PAnsiChar(Pointer(UTF8String(AFileName))),
    PAnsiChar(Pointer(UTF8String(APathName)))
{$ENDIF}
    );
end;

function IndySSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  // RLebeau: why are we calling X509_STORE_load_locations() directly
  // instead of just calling SSL_CTX_load_verify_locations() with
  // UTF-8 input?

  // Result := SSL_CTX_load_verify_locations(ctx,
  // {$IFDEF USE_MARSHALLED_PTRS}
  // AsUtf8OrNl(ACAFile),
  // AsUtf8OrNil(ACAPath)
  // {$ELSE}
  // PAnsiChar(Pointer(UTF8String(ACAFile))),
  // PAnsiChar(Pointer(UTF8String(ACAPath)))
  // {$ENDIF}
  // );

  Result := IndyX509_STORE_load_locations(ctx^.cert_store, ACAFile, ACAPath);
end;

function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  B: PBIO;
  LDH: PDH;
  j: Integer;
{$IFDEF USE_MARSHALLED_PTRS}
  M: TMarshaller;
{$ENDIF}
begin
  Result := 0;
  B := BIO_new_file(
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))
{$ENDIF}
    , 'r');
  if Assigned(B) then
  begin
    try
      case AType of
        // TODO
        {
          SSL_FILETYPE_ASN1:
          begin
          j := ERR_R_ASN1_LIB;
          LDH := d2i_DHparams_bio(B, nil);
          end;
        }
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_DH_LIB;
            LDH := PEM_read_bio_DHparams(B, nil, ctx^.default_passwd_callback,
              ctx^.default_passwd_callback_userdata);
          end
      else
        begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then
      begin
        SSLerr(SSL_F_SSL3_CTRL, j);
        Exit;
      end;
      Result := SSL_CTX_set_tmp_dh(ctx, LDH);
      DH_free(LDH);
    finally
      BIO_free(B);
    end;
  end;
end;

{$ENDIF} // UNIX

{$ELSE} // STRING_IS_UNICODE

function IndySSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_load_client_CA_file(PAnsiChar(AFileName));
end;

function IndySSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_CTX_use_PrivateKey_file(ctx, PAnsiChar(AFileName), AType);
end;

function IndySSL_CTX_use_certificate_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_CTX_use_certificate_file(ctx, PAnsiChar(AFileName), AType);
end;

function IndySSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_CTX_use_certificate_chain_file(ctx, PAnsiChar(AFileName));
end;

function IndyX509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  // RLebeau 4/18/2010: X509_STORE_load_locations() expects nil pointers
  // for unused values, but casting a string directly to a PAnsiChar
  // always produces a non-nil pointer, which causes X509_STORE_load_locations()
  // to fail. Need to cast the string to an intermediate Pointer so the
  // PAnsiChar cast is applied to the raw data and thus can be nil...
  //
  Result := X509_STORE_load_locations(ctx, PAnsiChar(Pointer(AFileName)),
    PAnsiChar(Pointer(APathName)));
end;

function IndySSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
begin
  // RLebeau 4/18/2010: X509_STORE_load_locations() expects nil pointers
  // for unused values, but casting a string directly to a PAnsiChar
  // always produces a non-nil pointer, which causes X509_STORE_load_locations()
  // to fail. Need to cast the string to an intermediate Pointer so the
  // PAnsiChar cast is applied to the raw data and thus can be nil...
  //
  Result := SSL_CTX_load_verify_locations(ctx, PAnsiChar(Pointer(ACAFile)),
    PAnsiChar(Pointer(ACAPath)));
end;

function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  B: PBIO;
  LDH: PDH;
  j: Integer;
begin
  Result := 0;
  B := BIO_new_file(PAnsiChar(AFileName), 'r');
  if Assigned(B) then
  begin
    try
      case AType of
        // TODO
        {
          SSL_FILETYPE_ASN1:
          begin
          j := ERR_R_ASN1_LIB;
          LDH := d2i_DHparams_bio(B, nil);
          end;
        }
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_DH_LIB;
            LDH := PEM_read_bio_DHparams(B, nil, ctx^.default_passwd_callback,
              ctx^.default_passwd_callback_userdata);
          end
      else
        begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then
      begin
        SSLerr(SSL_F_SSL3_CTRL, j);
        Exit;
      end;
      Result := SSL_CTX_set_tmp_dh(ctx, LDH);
      DH_free(LDH);
    finally
      BIO_free(B);
    end;
  end;
end;

{$ENDIF}

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

{$IFDEF OPENSSL_SET_MEMORY_FUNCS}

function IdMalloc(num: UInt32): Pointer cdecl;
begin
  Result := AllocMem(num);
end;

function IdRealloc(addr: Pointer; num: UInt32): Pointer cdecl;
begin
  Result := addr;
  ReallocMem(Result, num);
end;

procedure IdFree(addr: Pointer)cdecl;
begin
  FreeMem(addr);
end;

procedure IdSslCryptoMallocInit;
// replaces the actual alloc routines
// this is useful if you are using a memory manager that can report on leaks
// at shutdown time.
var
  r: Integer;
begin
  r := CRYPTO_set_mem_functions(@IdMalloc, @IdRealloc, @IdFree);
  Assert(r <> 0);
end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_BIO}

procedure DumpCert(AOut: TStrings; aX509: PX509);
var
  LMem: PBIO;
  LLen: TIdC_INT;
  LBufPtr: PIdAnsiChar;
begin
  if Assigned(X509_print) then
  begin
    LMem := BIO_new(BIO_s_mem);
    if LMem <> nil then
    begin
      try
        X509_print(LMem, aX509);
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

procedure DumpCert(AOut: TStrings; aX509: PX509);
begin
end;

{$ENDIF}

procedure _threadid_func(id: PCRYPTO_THREADID)cdecl;
begin
  if Assigned(CRYPTO_THREADID_set_numeric) then
  begin
    CRYPTO_THREADID_set_numeric(id, TIdC_ULONG(CurrentThreadId));
  end;
end;

function _GetThreadID: TIdC_ULONG; cdecl;
begin
  // TODO: Verify how well this will work with fibers potentially running from
  // thread to thread or many on the same thread.
  Result := TIdC_ULONG(CurrentThreadId);
end;

procedure SslLockingCallback(Mode, n: TIdC_INT; Afile: PIdAnsiChar;
  line: TIdC_INT)cdecl;
var
  Lock: TIdCriticalSection;
  LList: TIdCriticalSectionList;
begin
  Assert(CallbackLockList <> nil);
  Lock := nil;

  LList := CallbackLockList.LockList;
  try
    if n < LList.count then
    begin
      Lock := {$IFDEF HAS_GENERICS_TList}LList.Items[n]{$ELSE}TIdCriticalSection
        (LList.Items[n]){$ENDIF};
    end;
  finally
    CallbackLockList.UnlockList;
  end;
  Assert(Lock <> nil);
  if (Mode and CRYPTO_LOCK) = CRYPTO_LOCK then
  begin
    Lock.Acquire;
  end
  else
  begin
    Lock.Release;
  end;
end;

procedure PrepareOpenSSLLocking;
var
  i, cnt: Integer;
  Lock: TIdCriticalSection;
  LList: TIdCriticalSectionList;
begin
  LList := CallbackLockList.LockList;
  try
    cnt := CRYPTO_num_locks;
    for i := 0 to cnt - 1 do
    begin
      Lock := TIdCriticalSection.Create;
      try
        LList.Add(Lock);
      except
        Lock.Free;
        raise;
      end;
    end;
  finally
    CallbackLockList.UnlockList;
  end;
end;

// Author : Gregor Ibich (gregor.ibic@intelicom.si)
// Pascal translation: Doychin Bondzhev (doichin@5group.com)

// Converts the following string representations into corresponding parts
// YYYYMMDDHHMMSS(+|-)HH( )MM (GeneralizedTime, for dates 2050 and later)
// YYMMDDHHMMSS(+|-)HH( )MM   (UTCTime, for dates up to 2049)
function UTC_Time_Decode(UCTtime : PASN1_UTCTIME; var year, month, day, hour, min, sec: Word;
  var tz_hour, tz_min: Integer): Integer;
var
  i, tz_dir, index: Integer;
  time_str: string;
  {$IFNDEF USE_MARSHALLED_PTRS}
    {$IFNDEF STRING_IS_ANSI}
  LTemp: AnsiString;
    {$ENDIF}
  {$ENDIF}
begin
  Result := 0;
  if UCTtime^.length < 12 then begin
    Exit;
  end;
  {$IFDEF USE_MARSHALLED_PTRS}
  time_str := TMarshal.ReadStringAsAnsi(TPtrWrapper.Create(UCTtime^.data), UCTtime^.length);
  {$ELSE}
    {$IFDEF STRING_IS_ANSI}
  SetString(time_str, PAnsiChar(UCTtime^.data), UCTtime^.length);
    {$ELSE}
  SetString(LTemp, PAnsiChar(UCTtime^.data), UCTtime^.length);
  // TODO: do we need to use SetCodePage() here?
  time_str := String(LTemp); // explicit convert to Unicode
    {$ENDIF}
  {$ENDIF}
  // Check if first 14 chars (4-digit year) are numbers
  if (Length(time_str) >= 14) and IsNumeric(time_str, 14) then begin
    // Convert time from string to number
    year := IndyStrToInt(Copy(time_str, 1, 4));
    month := IndyStrToInt(Copy(time_str, 5, 2));
    day := IndyStrToInt(Copy(time_str, 7, 2));
    hour := IndyStrToInt(Copy(time_str, 9, 2));
    min := IndyStrToInt(Copy(time_str, 11, 2));
    sec := IndyStrToInt(Copy(time_str, 13, 2));
    index := 15;
  end
  // Check if first 12 chars (2-digit year) are numbers
  else if (Length(time_str) >= 12) and IsNumeric(time_str, 12) then begin
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
    index := 13;
  end else begin
    Exit;
  end;
  // Check TZ
  tz_hour := 0;
  tz_min := 0;
  if CharIsInSet(time_str, index, '-+') then begin    {Do not Localize}
    tz_dir := iif(CharEquals(time_str, index, '-'), -1, 1);    {Do not Localize}
    for i := index+1 to index+5 do begin  // Check if numbers are numbers
      if i = index+3 then begin
        Continue;
      end;
      if not IsNumeric(time_str[i]) then begin
        Exit;
      end;
    end;
    tz_hour := IndyStrToInt(Copy(time_str, index+1, 2)) * tz_dir;
    tz_min  := IndyStrToInt(Copy(time_str, index+4, 2)) * tz_dir;
  end;
  Result := 1;
end;

// Note that I define UCTTime as  PASN1_STRING
function UTCTime2DateTime(UCTTime: PASN1_UTCTIME): TDateTime;
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
  if UTC_Time_Decode(UCTTime, year, month, day, hour, min, sec, tz_h, tz_m) > 0
  then
  begin
    Result := EncodeDate(year, month, day) + EncodeTime(hour, min, sec, 0);
    AddMins(Result, tz_m);
    AddHrs(Result, tz_h);
    Result := UTCTimeToLocalTime(Result);
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

function LoadOpenSSLLibrary: Boolean;
begin
  Assert(SSLIsLoaded <> nil);
  SSLIsLoaded.Lock;
  try
    if SSLIsLoaded.Value then
    begin
      Result := True;
      Exit;
    end;
    Result := GetOpenSSLLoader.Load;
    if not Result then
    begin
      Exit;
    end;
{$IFDEF OPENSSL_SET_MEMORY_FUNCS}
    // has to be done before anything that uses memory
    IdSslCryptoMallocInit;
{$ENDIF}
    // required eg to encrypt a private key when writing
    if Assigned(OpenSSL_add_all_ciphers) then
    begin
      OpenSSL_add_all_ciphers;
    end
    else
    begin
      OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);
    end;
    if Assigned(OpenSSL_add_all_digests) then
    begin
      OpenSSL_add_all_digests;
    end
    else
    begin
      OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, nil);
    end;
    // IdSslRandScreen;
    if Assigned(SSL_load_error_strings) then
    begin
      SSL_load_error_strings;
    end
    else
    begin
      OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or
        OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil);
    end;
    // Successful loading if true
    if Assigned(SSLeay_add_ssl_algorithms) then
    begin
      Result := SSLeay_add_ssl_algorithms > 0;
    end
    else
    begin
      Result := OPENSSL_init_ssl(0, nil) > 0;
    end;
    if not Result then
    begin
      Exit;
    end;
    // Create locking structures, we need them for callback routines
    Assert(LockInfoCB = nil);
    LockInfoCB := TIdCriticalSection.Create;
    LockPassCB := TIdCriticalSection.Create;
    LockVerifyCB := TIdCriticalSection.Create;
    // Handle internal OpenSSL locking
    CallbackLockList := TIdCriticalSectionThreadList.Create;
    PrepareOpenSSLLocking;
    if Assigned(CRYPTO_set_locking_callback) then
    begin
      CRYPTO_set_locking_callback(@SslLockingCallback);
    end;
    if Assigned(CRYPTO_THREADID_set_callback) then
    begin
      CRYPTO_THREADID_set_callback(@_threadid_func);
    end
    else
    begin
      if Assigned(CRYPTO_set_id_callback) then begin
        CRYPTO_set_id_callback(@_GetThreadID);
      end;
    end;
    SSLIsLoaded.Value := True;
    Result := True;
  finally
    SSLIsLoaded.Unlock;
  end;
end;

procedure UnLoadOpenSSLLibrary;
// allow the user to call unload directly?
// will then need to implement reference count
{$IFNDEF USE_OBJECT_ARC}
var
  i: Integer;
  LList: TIdCriticalSectionList;
{$ENDIF}
begin
  // ssl was never loaded
  if Assigned(CRYPTO_set_locking_callback) then
  begin
    CRYPTO_set_locking_callback(nil);
  end;
  FreeAndNil(LockInfoCB);
  FreeAndNil(LockPassCB);
  FreeAndNil(LockVerifyCB);
  if Assigned(CallbackLockList) then
  begin
{$IFDEF USE_OBJECT_ARC}
    CallbackLockList.Clear; // Items are auto-freed
{$ELSE}
    LList := CallbackLockList.LockList;
    begin
      try
        for i := 0 to LList.count - 1 do
        begin
{$IFDEF HAS_GENERICS_TList}LList.Items[i]{$ELSE}TIdCriticalSection(LList.Items[i]){$ENDIF}.Free;
        end;
        LList.Clear;
      finally
        CallbackLockList.UnlockList;
      end;
    end;
{$ENDIF}
    FreeAndNil(CallbackLockList);
  end;
  SSLIsLoaded.Value := False;
end;

function OpenSSLVersion: string;
begin
  Result := '';
  // RLebeau 9/7/2015: even if LoadOpenSSLLibrary() fails, _SSLeay_version()
  // might have been loaded OK before the failure occured. LoadOpenSSLLibrary()
  // does not unload ..
  LoadOpenSSLLibrary;
  Result := String(OpenSSL_version(OPENSSL_VERSION_CONST));
end;

/// ///////////////////////////////////////////////////
// TIdSSLOptions
/// ////////////////////////////////////////////////////

constructor TIdSSLOptions.Create;
begin
  inherited Create;
  fMethod := DEF_SSLVERSION;
  fSSLVersions := DEF_SSLVERSIONS;
end;

procedure TIdSSLOptions.SetMethod(const AValue: TIdSSLVersion);
begin
  fMethod := AValue;
  if AValue = sslvSSLv23 then
  begin
    fSSLVersions := [sslvSSLv2, sslvSSLv3, sslvTLSv1, sslvTLSv1_1, sslvTLSv1_2,
      sslvTLSv1_3];
  end
  else
  begin
    fSSLVersions := [AValue];
  end;
end;

procedure TIdSSLOptions.SetSSLVersions(const AValue: TIdSSLVersions);
begin
  fSSLVersions := AValue;
  if fSSLVersions = [sslvSSLv2] then
  begin
    fMethod := sslvSSLv2;
  end
  else if fSSLVersions = [sslvSSLv3] then
  begin
    fMethod := sslvSSLv3;
  end
  else if fSSLVersions = [sslvTLSv1] then
  begin
    fMethod := sslvTLSv1;
  end
  else if fSSLVersions = [sslvTLSv1_1] then
  begin
    fMethod := sslvTLSv1_1;
  end
  else if fSSLVersions = [sslvTLSv1_2] then
  begin
    fMethod := sslvTLSv1_2;
  end
  else if fSSLVersions = [sslvTLSv1_3] then
  begin
    fMethod := sslvTLSv1_3;
  end
  else
  begin
    fMethod := sslvSSLv23;
    if sslvSSLv23 in fSSLVersions then
    begin
      Exclude(fSSLVersions, sslvSSLv23);
      if fSSLVersions = [] then
      begin
        fSSLVersions := [sslvSSLv2, sslvSSLv3, sslvTLSv1, sslvTLSv1_1,
          sslvTLSv1_2, sslvTLSv1_3];
      end;
    end;
  end;
end;

procedure TIdSSLOptions.AssignTo(Destination: TPersistent);
var
  LDest: TIdSSLOptions;
begin
  if Destination is TIdSSLOptions then
  begin
    LDest := TIdSSLOptions(Destination);
    LDest.RootCertFile := RootCertFile;
    LDest.CertFile := CertFile;
    LDest.KeyFile := KeyFile;
    LDest.DHParamsFile := DHParamsFile;
    LDest.Method := Method;
    LDest.SSLVersions := SSLVersions;
    LDest.Mode := Mode;
    LDest.VerifyMode := VerifyMode;
    LDest.VerifyDepth := VerifyDepth;
    LDest.VerifyDirs := VerifyDirs;
    LDest.CipherList := CipherList;
  end
  else
  begin
    inherited AssignTo(Destination);
  end;
end;

/// ////////////////////////////////////////////////////
// TIdServerIOHandlerSSLOpenSSL110
/// ////////////////////////////////////////////////////

{ TIdServerIOHandlerSSLOpenSSL110 }

procedure TIdServerIOHandlerSSLOpenSSL110.InitComponent;
begin
  inherited InitComponent;
  fxSSLOptions := TIdSSLOptions_Internal.Create;
  TIdSSLOptions_Internal(fxSSLOptions).Parent := Self;
end;

destructor TIdServerIOHandlerSSLOpenSSL110.Destroy;
begin
  FreeAndNil(fxSSLOptions);
  inherited Destroy;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.Init;
// see also TIdSSLIOHandlerSocketOpenSSL110.Init
begin
  // ensure Init isn't called twice
  Assert(fSSLContext = nil);
  fSSLContext := TIdSSLContext.Create;
  fSSLContext.Parent := Self;
  fSSLContext.RootCertFile := SSLOptions.RootCertFile;
  fSSLContext.CertFile := SSLOptions.CertFile;
  fSSLContext.KeyFile := SSLOptions.KeyFile;
  fSSLContext.DHParamsFile := SSLOptions.DHParamsFile;
  fSSLContext.fVerifyDepth := SSLOptions.fVerifyDepth;
  fSSLContext.fVerifyMode := SSLOptions.fVerifyMode;
  // fSSLContext.fVerifyFile := SSLOptions.fVerifyFile;
  fSSLContext.fVerifyDirs := SSLOptions.fVerifyDirs;
  fSSLContext.fCipherList := SSLOptions.fCipherList;
  fSSLContext.VerifyOn := Assigned(fOnVerifyPeer);
  fSSLContext.StatusInfoOn := Assigned(fOnStatusInfo) or
    Assigned(FOnStatusInfoEx);
  // fSSLContext.PasswordRoutineOn := Assigned(fOnGetPassword);
  fSSLContext.fMethod := SSLOptions.Method;
  fSSLContext.fMode := SSLOptions.Mode;
  fSSLContext.fSSLVersions := SSLOptions.SSLVersions;

  fSSLContext.InitContext(sslCtxServer);
end;

function TIdServerIOHandlerSSLOpenSSL110.Accept(ASocket: TIdSocketHandle;
  // This is a thread and not a yarn. Its the listener thread.
  AListenerThread: TIdThread; AYarn: TIdYarn): TIdIOHandler;
var
  LIO: TIdSSLIOHandlerSocketOpenSSL110;
begin
  // using a custom scheduler, AYarn may be nil, so don't assert
  Assert(ASocket <> nil);
  Assert(fSSLContext <> nil);
  Assert(AListenerThread <> nil);

  Result := nil;
  LIO := TIdSSLIOHandlerSocketOpenSSL110.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.Open;
    while not AListenerThread.Stopped do
    begin
      if ASocket.Select(250) then
      begin
        if (not AListenerThread.Stopped) and LIO.Binding.Accept(ASocket.Handle)
        then
        begin
          // we need to pass the SSLOptions for the socket from the server
          // TODO: wouldn't it be easier to just Assign() the server's SSLOptions
          // here? Do we really need to share ownership of it?
          // LIO.fxSSLOptions.Assign(fxSSLOptions);
          FreeAndNil(LIO.fxSSLOptions);
          LIO.IsPeer := True;
          LIO.fxSSLOptions := fxSSLOptions;
          LIO.fSSLSocket := TIdSSLSocket.Create(Self);
          LIO.fSSLContext := fSSLContext;
          // TODO: to enable server-side SNI, we need to:
          // - Set up an additional SSL_CTX for each different certificate;
          // - Add a servername callback to each SSL_CTX using SSL_CTX_set_tlsext_servername_callback();
          // - In the callback, retrieve the client-supplied servername with
          // SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name). Figure out the right
          // SSL_CTX to go with that host name, then switch the SSL object to that
          // SSL_CTX with SSL_set_SSL_CTX().

          // RLebeau 2/1/2022: note, the following call is basically a no-op for OpenSSL,
          // because PassThrough=True and fSSLContext are both assigned above, so there
          // is really nothing for TIdSSLIOHandlerSocketOpenSSL110.Init() or
          // TIdSSLIOHandlerSocketOpenSSL110.StartSSL() to do when called by
          // TIdSSLIOHandlerSocketOpenSSL110.AfterAccept().  If anything, all this will
          // really do is update the Binding's IPVersion.  But, calling this is consistent
          // with other server Accept() implementations, so we should do it here, too...
          LIO.AfterAccept;

          Result := LIO;
          LIO := nil;
          Break;
        end;
      end;
    end;
  finally
    FreeAndNil(LIO);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.DoStatusInfo(const AMsg: String);
begin
  if Assigned(fOnStatusInfo) then
  begin
    fOnStatusInfo(AMsg);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.DoStatusInfoEx(const AsslSocket: PSSL;
  const AWhere, Aret: TIdC_INT; const AWhereStr, ARetStr: String);
begin
  if Assigned(FOnStatusInfoEx) then
  begin
    FOnStatusInfoEx(Self, AsslSocket, AWhere, Aret, AWhereStr, ARetStr);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.DoGetPassword(var Password: String);
begin
  if Assigned(fOnGetPassword) then
  begin
    fOnGetPassword(Password);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.DoGetPasswordEx(var VPassword: String;
  const AIsWrite: Boolean);
begin
  if Assigned(fOnGetPasswordEx) then
  begin
    fOnGetPasswordEx(Self, VPassword, AIsWrite);
  end;
end;

function TIdServerIOHandlerSSLOpenSSL110.DoVerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := True;
  if Assigned(fOnVerifyPeer) then
  begin
    Result := fOnVerifyPeer(Certificate, AOk, ADepth, AError);
  end;
end;

function TIdServerIOHandlerSSLOpenSSL110.MakeFTPSvrPort: TIdSSLIOHandlerSocketBase;
var
  LIO: TIdSSLIOHandlerSocketOpenSSL110;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL110.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
    LIO.IsPeer := True; // RLebeau 1/24/2019: is this still needed now?
    LIO.SSLOptions.Assign(SSLOptions);
    LIO.SSLOptions.Mode := sslmBoth; { or sslmClient }{ doesn't really matter }
    LIO.SSLContext := SSLContext;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.Shutdown;
begin
  FreeAndNil(fSSLContext);
  inherited Shutdown;
end;

function TIdServerIOHandlerSSLOpenSSL110.MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase;
var
  LIO: TIdSSLIOHandlerSocketOpenSSL110;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL110.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
    LIO.IsPeer := True;
    LIO.SSLOptions.Assign(SSLOptions);
    LIO.SSLOptions.Mode := sslmBoth; { or sslmServer }
    LIO.SSLContext := nil;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

{ IIdSSLOpenSSLCallbackHelper }

function TIdServerIOHandlerSSLOpenSSL110.GetPassword(const AIsWrite
  : Boolean): string;
begin
  DoGetPasswordEx(Result, AIsWrite);
  if Result = '' then
  begin
    DoGetPassword(Result);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL110.StatusInfo(const AsslSocket: PSSL;
  AWhere, Aret: TIdC_INT; const AStatusStr: string);
var
  LType, LMsg: string;
begin
  DoStatusInfo(AStatusStr);
  if Assigned(FOnStatusInfoEx) then
  begin
    GetStateVars(AsslSocket, AWhere, Aret, LType, LMsg);
    DoStatusInfoEx(AsslSocket, AWhere, Aret, LType, LMsg);
  end;
end;

function TIdServerIOHandlerSSLOpenSSL110.VerifyPeer(ACertificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := DoVerifyPeer(ACertificate, AOk, ADepth, AError);
end;

function TIdServerIOHandlerSSLOpenSSL110.GetIOHandlerSelf
  : TIdSSLIOHandlerSocketOpenSSL110;
begin
  Result := nil;
end;

/// ////////////////////////////////////////////////////
// TIdSSLIOHandlerSocketOpenSSL110
/// ////////////////////////////////////////////////////

function TIdServerIOHandlerSSLOpenSSL110.MakeClientIOHandler
  : TIdSSLIOHandlerSocketBase;
var
  LIO: TIdSSLIOHandlerSocketOpenSSL110;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL110.Create(nil);
  try
    LIO.PassThrough := True;
    // LIO.SSLOptions.Free;
    // LIO.SSLOptions := SSLOptions;
    // LIO.SSLContext := SSLContext;
    LIO.SSLOptions.Assign(SSLOptions);
    // LIO.SSLContext := SSLContext;
    LIO.SSLContext := nil;
    // SSLContext.Clone; // BGO: clone does not work, it must be either NIL, or SSLContext
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

{ TIdSSLIOHandlerSocketOpenSSL110 }

procedure TIdSSLIOHandlerSocketOpenSSL110.InitComponent;
begin
  inherited InitComponent;
  IsPeer := False;
  fxSSLOptions := TIdSSLOptions_Internal.Create;
  TIdSSLOptions_Internal(fxSSLOptions).Parent := Self;
  fSSLLayerClosed := True;
  fSSLContext := nil;
end;

destructor TIdSSLIOHandlerSocketOpenSSL110.Destroy;
begin
  FreeAndNil(fSSLSocket);
  // we do not destroy these if their Parent is not Self
  // because these do not belong to us when we are in a server.
  if (fSSLContext <> nil) and (fSSLContext.Parent = Self) then
  begin
    FreeAndNil(fSSLContext);
  end;
  if (fxSSLOptions <> nil) and (fxSSLOptions is TIdSSLOptions_Internal) and
    (TIdSSLOptions_Internal(fxSSLOptions).Parent = Self) then
  begin
    FreeAndNil(fxSSLOptions);
  end;
  inherited Destroy;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.ConnectClient;
var
  LPassThrough: Boolean;
begin
  // RLebeau: initialize OpenSSL before connecting the socket...
  try
    Init;
  except
    on EIdOSSLCouldNotLoadSSLLibrary do
    begin
      if not PassThrough then
        raise;
    end;
  end;
  // RLebeau 1/11/07: In case a proxy is being used, pass through
  // any data from the base class unencrypted when setting up that
  // connection.  We should do this anyway since SSL hasn't been
  // negotiated yet!
  LPassThrough := fPassThrough;
  fPassThrough := True;
  try
    inherited ConnectClient;
  finally
    fPassThrough := LPassThrough;
  end;
  DoBeforeConnect(Self);
  // CreateSSLContext(sslmClient);
  // CreateSSLContext(SSLOptions.fMode);
  StartSSL;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.StartSSL;
begin
  if not PassThrough then
  begin
    OpenEncodedConnection;
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.Close;
begin
  FreeAndNil(fSSLSocket);
  if fSSLContext <> nil then
  begin
    if fSSLContext.Parent = Self then
    begin
      FreeAndNil(fSSLContext);
    end
    else
    begin
      fSSLContext := nil;
    end;
  end;
  inherited Close;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.Open;
begin
  FOpened := False;
  inherited Open;
end;

function TIdSSLIOHandlerSocketOpenSSL110.Readable
  (AMSec: Integer = IdTimeoutDefault): Boolean;
begin
  if not fPassThrough then
  begin
    Result := (fSSLSocket <> nil) and (ssl_pending(fSSLSocket.fSSL) > 0);
    if Result then
      Exit;
  end;
  Result := inherited Readable(AMSec);
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.SetPassThrough(const Value: Boolean);
begin
  if fPassThrough <> Value then
  begin
    if not Value then
    begin
      if BindingAllocated then
      begin
        if Assigned(fSSLContext) then
        begin
          OpenEncodedConnection;
        end
        else
        begin
          raise EIdOSSLCouldNotLoadSSLLibrary.Create
            (RSOSSLCouldNotLoadSSLLibrary);
        end;
      end;
    end
    else
    begin
      // RLebeau 8/16/2019: need to call SSL_shutdown() here if the SSL/TLS session is active.
      // This is for FTP when handling CCC and REIN commands. The SSL/TLS session needs to be
      // shutdown cleanly on both ends without closing the underlying socket connection because
      // it is going to be used for continued unsecure communications!
      if (fSSLSocket <> nil) and (fSSLSocket.fSSL <> nil) then
      begin
        // if SSL_shutdown() returns 0, a "close notify" was sent to the peer and SSL_shutdown()
        // needs to be called again to receive the peer's "close notify" in response...
        if SSL_shutdown(fSSLSocket.fSSL) = 0 then
        begin
          SSL_shutdown(fSSLSocket.fSSL);
        end;
      end;
{$IFDEF WIN32_OR_WIN64}
      // begin bug fix
      if BindingAllocated and IndyCheckWindowsVersion(6) then
      begin
        // disables Vista+ SSL_Read and SSL_Write timeout fix
        Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_RCVTIMEO, 0);
        Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_SNDTIMEO, 0);
      end;
      // end bug fix
{$ENDIF}
    end;
    fPassThrough := Value;
  end;
end;

function TIdSSLIOHandlerSocketOpenSSL110.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  Result := fSSLSocket.Recv(VBuffer);
end;

function TIdSSLIOHandlerSocketOpenSSL110.SendEnc(const ABuffer: TIdBytes;
  const AOffset, ALength: Integer): Integer;
begin
  Result := fSSLSocket.Send(ABuffer, AOffset, ALength);
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.AfterAccept;
begin
  try
    inherited AfterAccept;
    // RLebeau: initialize OpenSSL after accepting a client socket...
    try
      Init;
    except
      on EIdOSSLCouldNotLoadSSLLibrary do
      begin
        if not PassThrough then
          raise;
      end;
    end;
    StartSSL;
  except
    Close;
    raise;
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.Init;
// see also TIdServerIOHandlerSSLOpenSSL110.Init
begin
  if not Assigned(fSSLContext) then
  begin
    fSSLContext := TIdSSLContext.Create;
    fSSLContext.Parent := Self;
    fSSLContext.RootCertFile := SSLOptions.RootCertFile;
    fSSLContext.CertFile := SSLOptions.CertFile;
    fSSLContext.KeyFile := SSLOptions.KeyFile;
    fSSLContext.DHParamsFile := SSLOptions.DHParamsFile;
    fSSLContext.fVerifyDepth := SSLOptions.fVerifyDepth;
    fSSLContext.fVerifyMode := SSLOptions.fVerifyMode;
    // fSSLContext.fVerifyFile := SSLOptions.fVerifyFile;
    fSSLContext.fVerifyDirs := SSLOptions.fVerifyDirs;
    fSSLContext.fCipherList := SSLOptions.fCipherList;
    fSSLContext.VerifyOn := Assigned(fOnVerifyPeer);
    fSSLContext.StatusInfoOn := Assigned(fOnStatusInfo) or
      Assigned(FOnStatusInfoEx);
    // fSSLContext.PasswordRoutineOn := Assigned(fOnGetPassword);
    fSSLContext.fMethod := SSLOptions.Method;
    fSSLContext.fSSLVersions := SSLOptions.SSLVersions;
    fSSLContext.fMode := SSLOptions.Mode;
    fSSLContext.InitContext(sslCtxClient);
  end;
end;
// }

procedure TIdSSLIOHandlerSocketOpenSSL110.DoStatusInfo(const AMsg: String);
begin
  if Assigned(fOnStatusInfo) then
  begin
    fOnStatusInfo(AMsg);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.DoStatusInfoEx(const AsslSocket: PSSL;
  const AWhere, Aret: TIdC_INT; const AWhereStr, ARetStr: String);
begin
  if Assigned(FOnStatusInfoEx) then
  begin
    FOnStatusInfoEx(Self, AsslSocket, AWhere, Aret, AWhereStr, ARetStr);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.DoGetPassword(var Password: String);
begin
  if Assigned(fOnGetPassword) then
  begin
    fOnGetPassword(Password);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.DoGetPasswordEx(var VPassword: String;
  const AIsWrite: Boolean);
begin
  if Assigned(fOnGetPasswordEx) then
  begin
    fOnGetPasswordEx(Self, VPassword, AIsWrite);
  end;
end;

function TIdSSLIOHandlerSocketOpenSSL110.DoVerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := True;
  if Assigned(fOnVerifyPeer) then
  begin
    Result := fOnVerifyPeer(Certificate, AOk, ADepth, AError);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.OpenEncodedConnection;
var
{$IFDEF WIN32_OR_WIN64}
  LTimeout: Integer;
{$ENDIF}
  LMode: TIdSSLMode;
  LHost: string;

  // TODO: move the following to TIdSSLIOHandlerSocketBase...

  function GetURIHost: string;
  var
    LURI: TIdURI;
  begin
    Result := '';
    if URIToCheck <> '' then
    begin
      LURI := TIdURI.Create(URIToCheck);
      try
        Result := LURI.Host;
      finally
        LURI.Free;
      end;
    end;
  end;

  function GetProxyTargetHost: string;
  var
    // under ARC, convert a weak reference to a strong reference before working with it
    LTransparentProxy, LNextTransparentProxy: TIdCustomTransparentProxy;
  begin
    Result := '';
    // RLebeau: not reading from the property as it will create a
    // default Proxy object if one is not already assigned...
    LTransparentProxy := FTransparentProxy;
    if Assigned(LTransparentProxy) then
    begin
      if LTransparentProxy.Enabled then
      begin
        repeat
          LNextTransparentProxy := LTransparentProxy.ChainedProxy;
          if not Assigned(LNextTransparentProxy) then
            Break;
          if not LNextTransparentProxy.Enabled then
            Break;
          LTransparentProxy := LNextTransparentProxy;
        until False;
        Result := LTransparentProxy.Host;
      end;
    end;
  end;

begin
  Assert(Binding <> nil);
  if not Assigned(fSSLSocket) then
  begin
    fSSLSocket := TIdSSLSocket.Create(Self);
  end;
  Assert(fSSLSocket.fSSLContext = nil);
  fSSLSocket.fSSLContext := fSSLContext;
{$IFDEF WIN32_OR_WIN64}
  // begin bug fix
  if IndyCheckWindowsVersion(6) then
  begin
    // Note: Fix needed to allow SSL_Read and SSL_Write to timeout under
    // Vista+ when connection is dropped
    LTimeout := FReadTimeOut;
    if LTimeout <= 0 then
    begin
      LTimeout := 30000; // 30 seconds
    end;
    Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_RCVTIMEO, LTimeout);
    Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_SNDTIMEO, LTimeout);
  end;
  // end bug fix
{$ENDIF}
  // RLebeau 7/2/2015: do not rely on IsPeer to decide whether to call Connect()
  // or Accept(). SSLContext.Mode controls whether a client or server method is
  // used to handle the connection, so that same value should be used here as well.
  // A user encountered a scenario where he needed to connect a TIdTCPClient to a
  // TCP server on a hardware device, but run the client's SSLIOHandler as an SSL
  // server because the device was initiating the SSL handshake as an SSL client.
  // IsPeer was not designed to handle that scenario.  Setting IsPeer to True
  // allowed Accept() to be called here, but at the cost of causing memory leaks
  // in TIdSSLIOHandlerSocketOpenSSL110.Destroy() and TIdSSLIOHandlerSocketOpenSSL110.Close()
  // in client components!  IsPeer is intended to be set to True only in server
  // components...
  LMode := fSSLContext.Mode;
  if not(LMode in [sslmClient, sslmServer]) then
  begin
    // Mode must be sslmBoth (or else TIdSSLContext.SetSSLMethod() would have
    // raised an exception), so just fall back to previous behavior for now,
    // until we can figure out a better way to handle this scenario...
    if IsPeer then
    begin
      LMode := sslmServer;
    end
    else
    begin
      LMode := sslmClient;
    end;
  end;
  if LMode = sslmClient then
  begin
    LHost := GetURIHost;
    if LHost = '' then
    begin
      LHost := GetProxyTargetHost;
      if LHost = '' then
      begin
        LHost := Self.Host;
      end;
    end;
    fSSLSocket.fHostName := LHost;
    fSSLSocket.Connect(Binding.Handle);
  end
  else
  begin
    fSSLSocket.fHostName := '';
    fSSLSocket.Accept(Binding.Handle);
  end;
  fPassThrough := False;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.DoBeforeConnect
  (ASender: TIdSSLIOHandlerSocketOpenSSL110);
begin
  if Assigned(OnBeforeConnect) then
  begin
    OnBeforeConnect(Self);
  end;
end;

// TODO: add an AOwner parameter
function TIdSSLIOHandlerSocketOpenSSL110.Clone: TIdSSLIOHandlerSocketBase;
var
  LIO: TIdSSLIOHandlerSocketOpenSSL110;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL110.Create(nil);
  try
    LIO.SSLOptions.Assign(SSLOptions);
    LIO.OnStatusInfo := DoStatusInfo;
    LIO.OnStatusInfoEx := Self.OnStatusInfoEx;
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
    LIO.OnVerifyPeer := DoVerifyPeer;
    LIO.fSSLSocket := TIdSSLSocket.Create(Self);
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

function TIdSSLIOHandlerSocketOpenSSL110.CheckForError
  (ALastResult: Integer): Integer;
// var
// err: Integer;
begin
  if PassThrough then
  begin
    Result := inherited CheckForError(ALastResult);
  end
  else
  begin
    Result := fSSLSocket.GetSSLError(ALastResult);
    if Result = SSL_ERROR_NONE then
    begin
      Result := 0;
      Exit;
    end;
    if Result = SSL_ERROR_SYSCALL then
    begin
      Result := inherited CheckForError(Integer(Id_SOCKET_ERROR));
      Exit;
    end;
    EIdOpenSSLAPISSLError.RaiseExceptionCode(Result, ALastResult, '');
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.RaiseError(AError: Integer);
begin
  if (PassThrough) or (AError = Id_WSAESHUTDOWN) or
    (AError = Id_WSAECONNABORTED) or (AError = Id_WSAECONNRESET) then
  begin
    inherited RaiseError(AError);
  end
  else
  begin
    EIdOpenSSLAPISSLError.RaiseException(fSSLSocket.fSSL, AError, '');
  end;
end;

{ IIdSSLOpenSSLCallbackHelper }

function TIdSSLIOHandlerSocketOpenSSL110.GetPassword(const AIsWrite
  : Boolean): string;
begin
  DoGetPasswordEx(Result, AIsWrite);
  if Result = '' then
  begin
    DoGetPassword(Result);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL110.StatusInfo(const AsslSocket: PSSL;
  AWhere, Aret: TIdC_INT; const AStatusStr: string);
var
  LType, LMsg: string;
begin
  DoStatusInfo(AStatusStr);
  if Assigned(FOnStatusInfoEx) then
  begin
    GetStateVars(AsslSocket, AWhere, Aret, LType, LMsg);
    DoStatusInfoEx(AsslSocket, AWhere, Aret, LType, LMsg);
  end;
end;

function TIdSSLIOHandlerSocketOpenSSL110.VerifyPeer(ACertificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := DoVerifyPeer(ACertificate, AOk, ADepth, AError);
end;

function TIdSSLIOHandlerSocketOpenSSL110.GetIOHandlerSelf
  : TIdSSLIOHandlerSocketOpenSSL110;
begin
  Result := Self;
end;

{ TIdSSLContext }

constructor TIdSSLContext.Create;
begin
  inherited Create;
  // an exception here probably means that you are using the wrong version
  // of the openssl libraries. refer to comments at the top of this file.
  if not LoadOpenSSLLibrary then
  begin
    raise EIdOSSLCouldNotLoadSSLLibrary.Create(RSOSSLCouldNotLoadSSLLibrary);
  end;
  fVerifyMode := [];
  fMode := sslmUnassigned;
  fSessionId := 1;
end;

destructor TIdSSLContext.Destroy;
begin
  DestroyContext;
  inherited Destroy;
end;

procedure TIdSSLContext.DestroyContext;
begin
  if fContext <> nil then
  begin
    SSL_CTX_free(fContext);
    fContext := nil;
  end;
end;

procedure TIdSSLContext.InitContext(CtxMode: TIdSSLCtxMode);
var
  SSLMethod: PSSL_METHOD;
  Error: TIdC_INT;
  // pCAname: PSTACK_X509_NAME;
{$IFDEF USE_MARSHALLED_PTRS}
  M: TMarshaller;
{$ENDIF}
begin
  // Destroy the context first
  DestroyContext;
  if fMode = sslmUnassigned then
  begin
    if CtxMode = sslCtxServer then
    begin
      fMode := sslmServer;
    end
    else
    begin
      fMode := sslmClient;
    end
  end;
  // get SSL method function (SSL2, SSL23, SSL3, TLS)
  SSLMethod := SetSSLMethod;
  // create new SSL context
  fContext := SSL_CTX_new(SSLMethod);
  if fContext = nil then
  begin
    EIdOSSLCreatingContextError.RaiseException(RSSSLCreatingContextError);
  end;
{    if not(sslvTLSv1 in SSLVersions) then
    begin
      SSL_CTX_set_options(fContext, SSL_OP_NO_TLSv1);
    end
    else if (fMethod = sslvSSLv23) then
    begin
      SSL_CTX_clear_options(fContext, SSL_OP_NO_TLSv1);
    end;
{    if not(sslvTLSv1_1 in SSLVersions) then
    begin
      SSL_CTX_set_options(fContext, SSL_OP_NO_TLSv1_1);
    end
    else if (fMethod = sslvSSLv23) then
    begin
      SSL_CTX_clear_options(fContext, SSL_OP_NO_TLSv1_1);
    end;
    if not(sslvTLSv1_2 in SSLVersions) then
    begin
      SSL_CTX_set_options(fContext, SSL_OP_NO_TLSv1_2);
    end
    else if (fMethod = sslvSSLv23) then
    begin
      SSL_CTX_clear_options(fContext, SSL_OP_NO_TLSv1_2);
    end;       }
  if sslvTLSv1 in SSLVersions then begin
    if  SSL_CTX_set_min_proto_version(fContext, TLS1_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end else if sslvTLSv1_1 in SSLVersions then begin
    if SSL_CTX_set_min_proto_version(fContext, TLS1_1_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end else if sslvTLSv1_2 in SSLVersions then begin
    if SSL_CTX_set_min_proto_version(fContext, TLS1_2_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end else if sslvTLSv1_3 in SSLVersions then begin
    if SSL_CTX_set_min_proto_version(fContext, TLS1_3_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end;
  if SSL_CTX_set_max_proto_version(fContext, TLS1_3_VERSION) <> 1 then begin
    raise EIdOSSLCouldNotSetMaxProtocolVersion.Create(RSOSSLCouldNotSetMaxProtocolVersion);
  end;
  SSL_CTX_set_mode(fContext, SSL_MODE_AUTO_RETRY);
  // assign a password lookup routine
  // if PasswordRoutineOn then begin
  SSL_CTX_set_default_passwd_cb(fContext, @PasswordCallback);
  SSL_CTX_set_ex_data(fContext, INDY_PASSWORD_CALLBACK, @PasswordCallback);
  SSL_CTX_set_default_passwd_cb_userdata(fContext, Self);
  SSL_CTX_set_ex_data(fContext, INDY_CALLBACK_USERDATA, Self);
  // end;

  SSL_CTX_set_default_verify_paths(fContext);
  // load key and certificate files
  if (RootCertFile <> '') or (VerifyDirs <> '') then
  begin { Do not Localize }
    if not LoadRootCert then
    begin
      EIdOSSLLoadingRootCertError.RaiseException(RSSSLLoadingRootCertError);
    end;
  end;
  if CertFile <> '' then
  begin { Do not Localize }
    if not LoadCert then
    begin
      EIdOSSLLoadingCertError.RaiseException(RSSSLLoadingCertError);
    end;
  end;
  if KeyFile <> '' then
  begin { Do not Localize }
    if not LoadKey then
    begin
      EIdOSSLLoadingKeyError.RaiseException(RSSSLLoadingKeyError);
    end;
  end;
  if DHParamsFile <> '' then
  begin { Do not Localize }
    if not LoadDHParams then
    begin
      EIdOSSLLoadingDHParamsError.RaiseException(RSSSLLoadingDHParamsError);
    end;
  end;
  if StatusInfoOn then
  begin
    SSL_CTX_set_info_callback(fContext, InfoCallback);
  end;
  // if_SSL_CTX_set_tmp_rsa_callback(hSSLContext, @RSACallback);
  if fCipherList <> '' then
  begin { Do not Localize }
    Error := SSL_CTX_set_cipher_list(fContext,
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
  end
  else
  begin
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
    Error := 1;
  end;
  if Error <= 0 then
  begin
    // TODO: should this be using EIdOSSLSettingCipherError.RaiseException() instead?
    raise EIdOSSLSettingCipherError.Create(RSSSLSettingCipherError);
  end;
  if fVerifyMode <> [] then
  begin
    SetVerifyMode(fVerifyMode, VerifyOn);
  end;
  if CtxMode = sslCtxServer then
  begin
    SSL_CTX_set_session_id_context(fContext, PByte(@fSessionId),
      SizeOf(fSessionId));
  end;
  // CA list
  if RootCertFile <> '' then
  begin { Do not Localize }
    SSL_CTX_set_client_CA_list(fContext,
      IndySSL_load_client_CA_file(RootCertFile));
  end

  // TODO: provide an event so users can apply their own settings as needed...
end;

procedure TIdSSLContext.SetVerifyMode(Mode: TIdSSLVerifyModeSet;
  CheckRoutine: Boolean);
var
  Func: TSSL_CTX_set_verify_callback;
begin
  if fContext <> nil then
  begin
    // SSL_CTX_set_default_verify_paths(fContext);
    if CheckRoutine then
    begin
      Func := VerifyCallback;
    end
    else
    begin
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
function SelectTLS1Method(const AMode: TIdSSLMode): PSSL_METHOD;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  case AMode of
    sslmServer:
      begin
          Result := TLS_server_method();
      end;
    sslmClient:
      begin
          Result := TLS_client_method();
      end;
  else
    Result := TLS_method();
  end;
end;

function TIdSSLContext.SetSSLMethod: PSSL_METHOD;
begin
  if fMode = sslmUnassigned then
  begin
    raise EIdOSSLModeNotSet.Create(RSOSSLModeNotSet);
  end;
  case Mode of
    sslmServer : begin
      Result := TLS_server_method;
    end;
    sslmClient : begin
      Result := TLS_client_method;
    end;
  else
      Result := TLS_client_method;
  end;
end;

function TIdSSLContext.LoadRootCert: Boolean;
begin
  Result := IndySSL_CTX_load_verify_locations(fContext, RootCertFile,
    VerifyDirs) > 0;
end;

function TIdSSLContext.LoadCert: Boolean;
begin
  if PosInStrArray(ExtractFileExt(CertFile), ['.p12', '.pfx'], False) <> -1 then
  begin
    Result := IndySSL_CTX_use_certificate_file_PKCS12(fContext, CertFile) > 0;
  end
  else
  begin
    // OpenSSL 1.0.2 has a new function, SSL_CTX_use_certificate_chain_file
    // that handles a chain of certificates in a PEM file.  That is prefered.
    if Assigned(SSL_CTX_use_certificate_chain_file) then
    begin
      Result := IndySSL_CTX_use_certificate_chain_file(fContext, CertFile) > 0;
    end
    else
    begin
      Result := IndySSL_CTX_use_certificate_file(fContext, CertFile,
        SSL_FILETYPE_PEM) > 0;
    end;
  end;
end;

function TIdSSLContext.LoadKey: Boolean;
begin
  if PosInStrArray(ExtractFileExt(KeyFile), ['.p12', '.pfx'], False) <> -1 then
  begin
    Result := IndySSL_CTX_use_PrivateKey_file_PKCS12(fContext, KeyFile) > 0;
  end
  else
  begin
    Result := IndySSL_CTX_use_PrivateKey_file(fContext, KeyFile,
      SSL_FILETYPE_PEM) > 0;
  end;
  if Result then
  begin
    Result := SSL_CTX_check_private_key(fContext) > 0;
  end;
end;

function TIdSSLContext.LoadDHParams: Boolean;
begin
  Result := IndySSL_CTX_use_DHparams_file(fContext, fsDHParamsFile,
    SSL_FILETYPE_PEM) > 0;
end;

/// ///////////////////////////////////////////////////////////

function TIdSSLContext.Clone: TIdSSLContext;
begin
  Result := TIdSSLContext.Create;
  Result.StatusInfoOn := StatusInfoOn;
  // property PasswordRoutineOn: Boolean read fPasswordRoutineOn write fPasswordRoutineOn;
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
  if fSSL <> nil then
  begin
    // TODO: should this be moved to TIdSSLContext instead?  Is this here
    // just to make sure the SSL shutdown does not log any messages?
    {
      if (fSSLContext <> nil) and (fSSLContext.StatusInfoOn) and
      (fSSLContext.fContext <> nil) then begin
      SSL_CTX_set_info_callback(fSSLContext.fContext, nil);
      end;
    }
    // SSL_set_shutdown(fSSL, SSL_SENT_SHUTDOWN);
    SSL_shutdown(fSSL);
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
    // Result := SSL_ERROR_NONE;
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
      end; }

    // raise EIdException.Create(RSOSSLConnectionDropped); // TODO: create a new Exception class for this
    // X509_LOOKUP event is not really an error, just an event
    // SSL_ERROR_WANT_X509_LOOKUP:
    // raise EIdException.Create(RSOSSLCertificateLookup); // TODO: create a new Exception class for this
    SSL_ERROR_SYSCALL:
      Result := SSL_ERROR_SYSCALL;
    // Result := SSL_ERROR_NONE;

    { //raise EIdException.Create(RSOSSLInternal); // TODO: create a new Exception class for this
      if (retCode <> 0) or (DataLen <> 0) then begin
      raise EIdException.Create(RSOSSLConnectionDropped); // TODO: create a new Exception class for this
      end
      else begin
      Result := 0;
      end; }

    SSL_ERROR_SSL:
      // raise EIdException.Create(RSOSSLInternal); // TODO: create a new Exception class for this
      Result := SSL_ERROR_SSL;
    // Result := SSL_ERROR_NONE;
  end;
end;

procedure TIdSSLSocket.Accept(const pHandle: TIdStackSocketHandle);
// Accept and Connect have a lot of duplicated code
var
  Error: Integer;
  StatusStr: String;
  LParentIO: TIdSSLIOHandlerSocketOpenSSL110;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
  Assert(fSSL = nil);
  Assert(fSSLContext <> nil);
  fSSL := SSL_new(fSSLContext.fContext);
  if sslvTLSv1 in fSSLContext.SSLVersions then begin
     if SSL_set_min_proto_version(fSSL, TLS1_VERSION)  <> 1 then begin
       raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
     end;
  end else if sslvTLSv1_1 in fSSLContext.SSLVersions then begin
    if SSL_set_min_proto_version(fSSL, TLS1_1_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end else  if sslvTLSv1_2 in fSSLContext.SSLVersions then begin
    if SSL_set_min_proto_version(fSSL, TLS1_2_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end else if sslvTLSv1_3 in fSSLContext.SSLVersions then begin
    if SSL_set_min_proto_version(fSSL, TLS1_3_VERSION) <> 1 then begin
      raise EIdOSSLCouldNotSetMinProtocolVersion.Create(RSOSSLCouldNotSetMinProtocolVersion);
    end;
  end;
  if SSL_set_max_proto_version(fSSL, TLS1_3_VERSION) <> 1 then begin
    raise EIdOSSLCouldNotSetMaxProtocolVersion.Create(RSOSSLCouldNotSetMaxProtocolVersion);
  end;
  if fSSL = nil then
  begin
    raise EIdOSSLCreatingSessionError.Create(RSSSLCreatingSessionError);
  end;
  Error := SSL_set_app_data(fSSL, Self);
  if Error <= 0 then
  begin
    EIdOSSLDataBindingError.RaiseException(fSSL, Error, RSSSLDataBindingError);
  end;
  Error := SSL_set_fd(fSSL, pHandle);
  if Error <= 0 then
  begin
    EIdOSSLFDSetError.RaiseException(fSSL, Error, RSSSLFDSetError);
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
    SSL_copy_session_id(fSSL, LParentIO.fSSLSocket.fSSL);
    end;
  }
  Error := SSL_accept(fSSL);
  if Error <= 0 then
  begin
    EIdOSSLAcceptError.RaiseException(fSSL, Error, RSSSLAcceptError);
  end;
  if Supports(fParent, IIdSSLOpenSSLCallbackHelper, IInterface(LHelper)) then
  begin
    LParentIO := LHelper.GetIOHandlerSelf;
    if LParentIO <> nil then
    begin
      StatusStr := 'Cipher: name = ' + Cipher.Name + '; ' + { Do not Localize }
        'description = ' + Cipher.Description + '; ' + { Do not Localize }
        'bits = ' + IntToStr(Cipher.Bits) + '; ' + { Do not Localize }
        'version = ' + Cipher.Version + '; '; { Do not Localize }
      LParentIO.DoStatusInfo(StatusStr);
    end;
    LHelper := nil;
  end;
end;

procedure TIdSSLSocket.Connect(const pHandle: TIdStackSocketHandle);
var
  Error: Integer;
  StatusStr: String;
  LParentIO: TIdSSLIOHandlerSocketOpenSSL110;
  LHelper: IIdSSLOpenSSLCallbackHelper;
begin
  Assert(fSSL = nil);
  Assert(fSSLContext <> nil);
  if Supports(fParent, IIdSSLOpenSSLCallbackHelper, IInterface(LHelper)) then
  begin
    LParentIO := LHelper.GetIOHandlerSelf;
  end
  else
  begin
    LParentIO := nil;
  end;
  fSSL := SSL_new(fSSLContext.fContext);
  if fSSL = nil then
  begin
    raise EIdOSSLCreatingSessionError.Create(RSSSLCreatingSessionError);
  end;
  Error := SSL_set_app_data(fSSL, Self);
  if Error <= 0 then
  begin
    EIdOSSLDataBindingError.RaiseException(fSSL, Error, RSSSLDataBindingError);
  end;
  Error := SSL_set_fd(fSSL, pHandle);
  if Error <= 0 then
  begin
    EIdOSSLFDSetError.RaiseException(fSSL, Error, RSSSLFDSetError);
  end;
  // RLebeau: if this socket's IOHandler was cloned, reuse the
  // original IOHandler's active session ID...
  if (LParentIO <> nil) and (LParentIO.fSSLSocket <> nil) and
    (LParentIO.fSSLSocket <> Self) then
  begin
    SSL_copy_session_id(fSSL, LParentIO.fSSLSocket.fSSL);
  end;
{$IFNDEF OPENSSL_NO_TLSEXT}
  Error := SSL_set_tlsext_host_name(fSSL, PAnsiChar( fHostName ));
  if Error <= 0 then
  begin
    // RLebeau: for the time being, not raising an exception on error, as I don't
    // know which OpenSSL versions support this extension, and which error code(s)
    // are safe to ignore on those versions...
    // EIdOSSLSettingTLSHostNameError.RaiseException(fSSL, error, RSSSLSettingTLSHostNameError);
  end;
{$ENDIF}
  Error := SSL_connect(fSSL);
  if Error <= 0 then
  begin
    // TODO: if sslv23 is being used, but sslv23 is not being used on the
    // remote side, SSL_connect() will fail. In that case, before giving up,
    // try re-connecting using a version-specific method for each enabled
    // version, maybe one will succeed...
    EIdOSSLConnectError.RaiseException(fSSL, Error, RSSSLConnectError);
  end;
  // TODO: even if SSL_connect() returns success, the connection might
  // still be insecure if SSL_connect() detected that certificate validation
  // actually failed, but ignored it because SSL_VERIFY_PEER was disabled!
  // It would report such a failure via SSL_get_verify_result() instead of
  // returning an error code, so we should call SSL_get_verify_result() here
  // to make sure...
  if LParentIO <> nil then
  begin
    StatusStr := 'Cipher: name = ' + Cipher.Name + '; ' + { Do not Localize }
      'description = ' + Cipher.Description + '; ' + { Do not Localize }
      'bits = ' + IntToStr(Cipher.Bits) + '; ' + { Do not Localize }
      'version = ' + Cipher.Version + '; '; { Do not Localize }
    LParentIO.DoStatusInfo(StatusStr);
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
    if ret > 0 then
    begin
      Result := ret;
      Exit;
    end;
    err := GetSSLError(ret);
    if (err = SSL_ERROR_WANT_READ) or (err = SSL_ERROR_WANT_WRITE) then
    begin
      Continue;
    end;
    if err = SSL_ERROR_ZERO_RETURN then
    begin
      Result := 0;
    end
    else
    begin
      Result := ret;
    end;
    Exit;
  until False;
end;

function TIdSSLSocket.Send(const ABuffer: TIdBytes;
  AOffset, ALength: Integer): Integer;
var
  ret, err: Integer;
begin
  Result := 0;
  repeat
    ret := SSL_write(fSSL, @ABuffer[AOffset], ALength);
    if ret > 0 then
    begin
      Inc(Result, ret);
      Inc(AOffset, ret);
      Dec(ALength, ret);
      if ALength < 1 then
      begin
        Exit;
      end;
      Continue;
    end;
    err := GetSSLError(ret);
    if (err = SSL_ERROR_WANT_READ) or (err = SSL_ERROR_WANT_WRITE) then
    begin
      Continue;
    end;
    if err = SSL_ERROR_ZERO_RETURN then
    begin
      Result := 0;
    end
    else
    begin
      Result := ret;
    end;
    Exit;
  until False;
end;

function TIdSSLSocket.GetPeerCert: TIdX509;
var
  LX509: PX509;
begin
  if fPeerCert = nil then
  begin
    LX509 := SSL_get_peer_certificate(fSSL);
    if LX509 <> nil then
    begin
      fPeerCert := TIdX509.Create(LX509, False);
    end;
  end;
  Result := fPeerCert;
end;

function TIdSSLSocket.GetSSLCipher: TIdSSLCipher;
begin
  if (fSSLCipher = nil) and (fSSL <> nil) then
  begin
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
  if Assigned(SSL_get_session) and Assigned(SSL_SESSION_get_id) then
  begin
    if fSSL <> nil then
    begin
      pSession := SSL_get_session(fSSL);
      if pSession <> nil then
      begin
        Result.Data := PByte(SSL_SESSION_get_id(pSession, @Result.Length));
      end;
    end;
  end;
end;

function TIdSSLSocket.GetSessionIDAsString: String;
var
  Data: TIdSSLByteArray;
  i: TIdC_UINT;
  LDataPtr: PByte;
begin
  Result := ''; { Do not Localize }
  Data := GetSessionID;
  if Data.Length > 0 then
  begin
    for i := 0 to Data.Length - 1 do
    begin
      // RLebeau: not all Delphi versions support indexed access using PByte
      LDataPtr := Data.Data;
      Inc(LDataPtr, i);
      Result := Result + IndyFormat('%.2x', [LDataPtr^]); { do not localize }
    end;
  end;
end;

procedure TIdSSLSocket.SetCipherList(CipherList: String);
// var
// tmpPStr: PAnsiChar;
begin
  {
    fCipherList := CipherList;
    fCipherList_Ch := True;
    aCipherList := aCipherList+#0;
    if hSSL <> nil then f_SSL_set_cipher_list(hSSL, @aCipherList[1]);
  }
end;

/// ////////////////////////////////////////////////////////////
// X509 Certificate
/// ////////////////////////////////////////////////////////////

{ TIdX509Name }

function TIdX509Name.CertInOneLine: String;
var
  LOneLine: array [0 .. 2048] of TIdAnsiChar;
begin
  if fX509Name = nil then
  begin
    Result := ''; { Do not Localize }
  end
  else
  begin
    Result := String(X509_NAME_oneline(fX509Name, @LOneLine[0],
      SizeOf(LOneLine)));
  end;
end;

function TIdX509Name.GetHash: TIdSSLULong;
begin
  if fX509Name = nil then
  begin
    FillChar(Result, SizeOf(Result), 0)
  end
  else
  begin
    if Assigned(X509_NAME_hash) then
    begin
      Result.C1 := X509_NAME_hash(fX509Name);
    end
    else
    begin
      Result.C1 := X509_NAME_hash_ex(fX509Name, nil, nil, nil);
    end;
  end;
end;

function TIdX509Name.GetHashAsString: String;
begin
  Result := IndyFormat('%.8x', [Hash.L1]); { do not localize }
end;

constructor TIdX509Name.Create(aX509Name: PX509_NAME);
begin
  Inherited Create;
  fX509Name := aX509Name;
end;

/// ////////////////////////////////////////////////////////////
// X509 Certificate
/// ////////////////////////////////////////////////////////////

{ TIdX509Info }

constructor TIdX509Info.Create(aX509: PX509);
begin
  inherited Create;
  FX509 := aX509;
end;

{ TIdX509Fingerprints }

function TIdX509Fingerprints.GetMD5: TIdSSLEVP_MD;
begin
  CheckMD5Permitted;
  X509_digest(FX509, EVP_md5, PByte(@Result.MD), Result.Length);
end;

function TIdX509Fingerprints.GetMD5AsString: String;
begin
  Result := MDAsString(MD5);
end;

function TIdX509Fingerprints.GetSHA1: TIdSSLEVP_MD;
begin
  X509_digest(FX509, EVP_sha1, PByte(@Result.MD), Result.Length);
end;

function TIdX509Fingerprints.GetSHA1AsString: String;
begin
  Result := MDAsString(SHA1);
end;

function TIdX509Fingerprints.GetSHA224: TIdSSLEVP_MD;
begin
  if Assigned(EVP_sha224) then
  begin
    X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result.Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
end;

function TIdX509Fingerprints.GetSHA224AsString: String;
begin
  if Assigned(EVP_sha224) then
  begin
    Result := MDAsString(SHA224);
  end
  else
  begin
    Result := '';
  end;
end;

function TIdX509Fingerprints.GetSHA256: TIdSSLEVP_MD;
begin
  if Assigned(EVP_sha256) then
  begin
    X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result.Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
end;

function TIdX509Fingerprints.GetSHA256AsString: String;
begin
  if Assigned(EVP_sha256) then
  begin
    Result := MDAsString(SHA256);
  end
  else
  begin
    Result := '';
  end;
end;

function TIdX509Fingerprints.GetSHA384: TIdSSLEVP_MD;
begin
  if Assigned(EVP_SHA384) then
  begin
    X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result.Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
end;

function TIdX509Fingerprints.GetSHA384AsString: String;
begin
  if Assigned(EVP_SHA384) then
  begin
    Result := MDAsString(SHA384);
  end
  else
  begin
    Result := '';
  end;
end;

function TIdX509Fingerprints.GetSHA512: TIdSSLEVP_MD;
begin
  if Assigned(EVP_sha512) then
  begin
    X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result.Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
end;

function TIdX509Fingerprints.GetSHA512AsString: String;
begin
  if Assigned(EVP_sha512) then
  begin
    Result := MDAsString(SHA512);
  end
  else
  begin
    Result := '';
  end;
end;

{ TIdX509SigInfo }

function TIdX509SigInfo.GetSignature: String;
var
  LASN1String: PASN1_BIT_STRING;
  LDummy : PX509_ALGOR;
begin
  X509_get0_signature(LASN1String, LDummy, FX509);
  Result := BytesToHexString(LASN1String.Data, LASN1String.Length);
end;

function TIdX509SigInfo.GetSigType: TIdC_INT;
begin
  Result := X509_get_signature_type(FX509);
end;

function TIdX509SigInfo.GetSigTypeAsString: String;
begin
  Result := String(OBJ_nid2ln(SigType));
end;

{ TIdX509 }

constructor TIdX509.Create(aX509: PX509; aCanFreeX509: Boolean = True);
begin
  inherited Create;
  // don't create FDisplayInfo unless specifically requested.
  FDisplayInfo := nil;
  FX509 := aX509;
  FCanFreeX509 := aCanFreeX509;
  FFingerprints := TIdX509Fingerprints.Create(FX509);
  FSigInfo := TIdX509SigInfo.Create(FX509);
  FSubject := nil;
  FIssuer := nil;
end;

destructor TIdX509.Destroy;
begin
  FreeAndNil(FDisplayInfo);
  FreeAndNil(FSubject);
  FreeAndNil(FIssuer);
  FreeAndNil(FFingerprints);
  FreeAndNil(FSigInfo);
  { If the X.509 certificate handle was obtained from a certificate
    store or from the SSL connection as a peer certificate, then DO NOT
    free it here!  The memory is owned by the OpenSSL library and will
    crash the library if Indy tries to free its private memory here }
  if FCanFreeX509 then
  begin
    X509_free(FX509);
  end;
  inherited Destroy;
end;

function TIdX509.GetDisplayInfo: TStrings;
begin
  if not Assigned(FDisplayInfo) then
  begin
    FDisplayInfo := TStringList.Create;
    DumpCert(FDisplayInfo, FX509);
  end;
  Result := FDisplayInfo;
end;

function TIdX509.GetSerialNumber: String;
var
  LSN: PASN1_INTEGER;
begin
  if FX509 <> nil then
  begin
    LSN := X509_get_serialNumber(FX509);
    Result := BytesToHexString(LSN.Data, LSN.Length);
  end
  else
  begin
    Result := '';
  end;
end;

function TIdX509.GetVersion: TIdC_LONG;
begin
  Result := X509_get_version(FX509);
end;

function TIdX509.RSubject: TIdX509Name;
var
  Lx509_name: PX509_NAME;
Begin
  if not Assigned(FSubject) then
  begin
    if FX509 <> nil then
    begin
      Lx509_name := X509_get_subject_name(FX509);
    end
    else
    begin
      Lx509_name := nil;
    end;
    FSubject := TIdX509Name.Create(Lx509_name);
  end;
  Result := FSubject;
end;

function TIdX509.RIssuer: TIdX509Name;
var
  Lx509_name: PX509_NAME;
begin
  if not Assigned(FIssuer) then
  begin
    if FX509 <> nil then
    begin
      Lx509_name := X509_get_issuer_name(FX509);
    end
    else
    begin
      Lx509_name := nil;
    end;
    FIssuer := TIdX509Name.Create(Lx509_name);
  End;
  Result := FIssuer;
end;

function TIdX509.RFingerprint: TIdSSLEVP_MD;
begin
  X509_digest(FX509, EVP_md5, PByte(@Result.MD), Result.Length);
end;

function TIdX509.RFingerprintAsString: String;
begin
  Result := MDAsString(Fingerprint);
end;

function TIdX509.RnotBefore: TDateTime;
begin
  if FX509 = nil then
  begin
    Result := 0
  end
  else
  begin
    // This is a safe typecast since PASN1_UTCTIME and PASN1_TIME are really
    // pointers to ASN1 strings since ASN1_UTCTIME amd ASM1_TIME are ASN1_STRING.
    Result := UTCTime2DateTime(PASN1_UTCTIME(X509_getm_notBefore(FX509)));
  end;
end;

function TIdX509.RnotAfter: TDateTime;
begin
  if FX509 = nil then
  begin
    Result := 0
  end
  else
  begin
    Result := UTCTime2DateTime(PASN1_UTCTIME(X509_getm_notAfter(FX509)));
  end;
end;

/// ////////////////////////////////////////////////////////////
// TIdSSLCipher
/// ////////////////////////////////////////////////////////////
constructor TIdSSLCipher.Create(AOwner: TIdSSLSocket);
begin
  inherited Create;
  fSSLSocket := AOwner;
end;

destructor TIdSSLCipher.Destroy;
begin
  inherited Destroy;
end;

function TIdSSLCipher.GetDescription;
var
  buf: array [0 .. 1024] of TIdAnsiChar;
begin
  Result := String(SSL_CIPHER_description(SSL_get_current_cipher
    (fSSLSocket.fSSL), @buf[0], SizeOf(buf) - 1));
end;

function TIdSSLCipher.GetName: String;
begin
  Result := String(SSL_CIPHER_get_name(SSL_get_current_cipher
    (fSSLSocket.fSSL)));
end;

function TIdSSLCipher.GetBits: TIdC_INT;
begin
  SSL_CIPHER_get_bits(SSL_get_current_cipher(fSSLSocket.fSSL), Result);
end;

function TIdSSLCipher.GetVersion: String;
begin
  Result := String(SSL_CIPHER_get_version(SSL_get_current_cipher
    (fSSLSocket.fSSL)));
end;

initialization

Assert(SSLIsLoaded = nil);
SSLIsLoaded := TIdThreadSafeBoolean.Create;

RegisterSSL('OpenSSL', 'Indy Pit Crew', { do not localize }
  'Copyright ' + Char(169) + ' 1993 - 2023'#10#13 + { do not localize }
  'Chad Z. Hower (Kudzu) and the Indy Pit Crew. All rights reserved.',
  { do not localize }
  'Open SSL Support DLL Delphi and C++Builder interface', { do not localize }
  'http://www.indyproject.org/'#10#13 + { do not localize }
  'Original Author - Gregor Ibic', { do not localize }
  TIdSSLIOHandlerSocketOpenSSL110, TIdServerIOHandlerSSLOpenSSL110);
TIdSSLIOHandlerSocketOpenSSL110.RegisterIOHandler;

finalization

// TODO: TIdSSLIOHandlerSocketOpenSSL110.UnregisterIOHandler;
UnLoadOpenSSLLibrary;
// free the lock last as unload makes calls that use it
FreeAndNil(SSLIsLoaded);

end.