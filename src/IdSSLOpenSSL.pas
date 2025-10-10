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
  {                               Here could be your name                        }
  {                                                                              }
  {******************************************************************************}

{
  $Log$
}
{
  Rev 1.41    22/02/2024 AWhyman
  a. Property SSLProtocolVersion added to TSocket. This returns the SSL/TLS protocol
     version that was negotiated when the session was created.

  b. SSL Headers now loaded using the IdOpenSSLLoader unit in order to support
     OpenSSL 3 and later.

  c. New property TIdSSLOptions.UseSystemRootCertificateStore. Defaults to true.
     If true then SSL_CTX_set_default_verify_paths is called. This causes the
     certs in OPENSSLDIR/certs to be used for certificate verification

  d. Windows only: if OPENSSL_DONT_USE_WINDOWS_CERT_STORE not defined  and
     TIdSSLOptions.UseSystemRootCertificateStore is true then
         Windows Root Certificate store is also loaded into SSL Context X.509 certificate store.

  e. Direct access to OpenSSL internal data structures (exposed in earlier versions,
     but now opaque (typically 1.1.1 onwards) now uses getter and setter functions
     provided by later versions of OpenSSL libraries with forwards compatibility
     functions (in appropriate SSL Header unit) used to provide getters and setters
     for earlier versions.

  f. New functions: OpenSSLVersion and OpenSSLDir. These are information access
     that return, respectively, the OpenSSL Version string and the OpenSSL Directory.

  Rev 1.40    03/11/2009 09:04:00  AWinkelsdorf
  Implemented fix for Vista+ SSL_Read and SSL_Write to allow connection
  timeout.

  Rev 1.39    16/02/2005 23:26:08  CCostelloe
  Changed OnVerifyPeer.  Breaks existing implementation of OnVerifyPeer.  See
  long comment near top of file.

  Rev 1.38    1/31/05 6:02:28 PM  RLebeau
  Updated _GetThreadId() callback to reflect changes in IdGlobal unit

  Rev 1.37    7/27/2004 1:54:26 AM  JPMugaas
  Now should use the Intercept property for sends.

  Rev 1.36    2004-05-18 21:38:36  Mattias
  Fixed unload bug

  Rev 1.35    2004-05-07 16:34:26  Mattias
  Implemented  OpenSSL locking callbacks

  Rev 1.34    27/04/2004 9:38:48  HHariri
  Added compiler directive so it works in BCB

  Rev 1.33    4/26/2004 12:41:10 AM  BGooijen
  Fixed WriteDirect

  Rev 1.32    2004.04.08 10:55:30 PM  czhower
  IOHandler changes.

  Rev 1.31    3/7/2004 9:02:58 PM  JPMugaas
  Fixed compiler warning about visibility.

  Rev 1.30    2004.03.07 11:46:40 AM  czhower
  Flushbuffer fix + other minor ones found

  Rev 1.29    2/7/2004 5:50:50 AM  JPMugaas
  Fixed Copyright.

  Rev 1.28    2/6/2004 3:45:56 PM  JPMugaas
  Only a start on NET porting.  This is not finished and will not compile on
  DotNET>

  Rev 1.27    2004.02.03 5:44:24 PM  czhower
  Name changes

  Rev 1.26    1/21/2004 4:03:48 PM  JPMugaas
  InitComponent

  Rev 1.25    1/14/2004 11:39:10 AM  JPMugaas
  Server IOHandler now works.  Accept was commented out.

  Rev 1.24    2003.11.29 10:19:28 AM  czhower
  Updated for core change to InputBuffer.

  Rev 1.23    10/21/2003 10:09:14 AM  JPMugaas
  Intercept enabled.

  Rev 1.22    10/21/2003 09:41:38 AM  JPMugaas
  Updated for new API.  Verified with TIdFTP with active and passive transfers
  as well as clear and protected data channels.

  Rev 1.21    10/21/2003 07:32:38 AM  JPMugaas
  Checked in what I have.  Porting still continues.

  Rev 1.20    10/17/2003 1:08:08 AM  DSiders
  Added localization comments.

  Rev 1.19    2003.10.12 6:36:44 PM  czhower
  Now compiles.

  Rev 1.18    9/19/2003 11:24:58 AM  JPMugaas
  Should compile.

  Rev 1.17    9/18/2003 10:20:32 AM  JPMugaas
  Updated for new API.

  Rev 1.16    2003.07.16 3:26:52 PM  czhower
  Fixed for a core change.

  Rev 1.15    6/30/2003 1:52:22 PM  BGooijen
  Changed for new buffer interface

  Rev 1.14    6/29/2003 5:42:02 PM  BGooijen
  fixed problem in TIdSSLIOHandlerSocketOpenSSL.SetPassThrough that Henrick
  Hellstrom reported

  Rev 1.13    5/7/2003 7:13:00 PM  BGooijen
  changed Connected to BindingAllocated in ReadFromSource

  Rev 1.12    3/30/2003 12:16:40 AM  BGooijen
  bugfixed+ added MakeFTPSvrPort/MakeFTPSvrPasv

  Rev 1.11    3/14/2003 06:56:08 PM  JPMugaas
  Added a clone method to the SSLContext.

  Rev 1.10    3/14/2003 05:29:10 PM  JPMugaas
  Change to prevent an AV when shutting down the FTP Server.

  Rev 1.9    3/14/2003 10:00:38 PM  BGooijen
  Removed TIdServerIOHandlerSSLBase.PeerPassthrough, the ssl is now enabled in
  the server-protocol-files

  Rev 1.8    3/13/2003 11:55:38 AM  JPMugaas
  Updated registration framework to give more information.

  Rev 1.7    3/13/2003 11:07:14 AM  JPMugaas
  OpenSSL classes renamed.

  Rev 1.6    3/13/2003 10:28:16 AM  JPMugaas
  Forgot the reegistration - OOPS!!!

  Rev 1.5    3/13/2003 09:49:42 AM  JPMugaas
  Now uses an abstract SSL base class instead of OpenSSL so 3rd-party vendors
  can plug-in their products.

  Rev 1.4    3/13/2003 10:20:08 AM  BGooijen
  Server side fibers

  Rev 1.3    2003.02.25 3:56:22 AM  czhower

  Rev 1.2    2/5/2003 10:27:46 PM  BGooijen
  Fixed bug in OpenEncodedConnection

  Rev 1.1    2/4/2003 6:31:22 PM  BGooijen
  Fixed for Indy 10

  Rev 1.0    11/13/2002 08:01:24 AM  JPMugaas
  * 
  * 1/8/2025 Updated by TWhyman (mwasoftware) to support OpenSSL 3.x and later
  * 8/4/2025 Updated by TWhyman to avoid SSL_read handing due to non-application data
}
unit IdSSLOpenSSL;
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

Tony Whyman 2025/8/26: Unit split to improve maintainability. See
  IdSSLOpenSSLSocket
  IdSSLOpenSSLOptions
  IdSSLOpenSSLX509
  IdSSLOpenSSLutils
}

interface

{$I IdCompilerDefines.inc}

{$IFNDEF USE_OPENSSL}
  {$message error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}

uses
  //facilitate inlining only.
  {$IFDEF WINDOWS}
  Windows,
  {$ENDIF}
  Classes,
  IdCTypes,
  IdGlobal,
  IdStackConsts,
  IdSocketHandle,
  IdComponent,
  IdIOHandler,
  IdGlobalProtocols,
  IdThread,
  IdIOHandlerSocket,
  IdSSL,
  IdYarn,
  IdSSLOpenSSLSocket,
  IdSSLOpenSSLX509,
  IdSSLOpenSSLExceptionHandlers,
  IdOpenSSLHeaders_ssl,
  IdSSLOpenSSLOptions,
  IdSSLOpenSSLFIPS {Ensure FIPS functions initialised};

type
  TIdSSLAction = (sslRead, sslWrite);

const
  P12_FILETYPE = 3;
  MAX_SSL_PASSWORD_LENGTH = 128;

type
  TIdSSLIOHandlerSocketOpenSSL = class;
  TCallbackEvent  = procedure(const AMsg: String) of object;
  TCallbackExEvent = procedure(ASender : TObject; const aSSLSocket: TIdSSLSocket;
    const AWhere, Aret: TIdC_INT; const AType, AMsg : String ) of object;
  TPasswordEvent  = procedure(var Password: String) of object;
  TPasswordEventEx = procedure( ASender : TObject; var VPassword: String; const AIsWrite : Boolean) of object;
  TVerifyPeerEvent  = function(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean of object;
  TIOHandlerNotify = procedure(ASender: TIdSSLIOHandlerSocketOpenSSL) of object;

  { TIdSSLIOHandlerSocketOpenSSL }

  TIdSSLIOHandlerSocketOpenSSL = class(TIdSSLIOHandlerSocketBase, IIdSSLOpenSSLCallbackHelper)
  protected
    fSSLContext: TIdSSLContext;
    fxSSLOptions: TIdSSLOptions;
    fSSLSocket: TIdSSLSocket;
    //fPeerCert: TIdX509;
    fOnStatusInfo: TCallbackEvent;
    FOnStatusInfoEx : TCallbackExEvent;
    fOnGetPassword: TPasswordEvent;
    fOnGetPasswordEx : TPasswordEventEx;
    fOnVerifyPeer: TVerifyPeerEvent;
    fSSLLayerClosed: Boolean;
    fOnBeforeConnect: TIOHandlerNotify;
    // function GetPeerCert: TIdX509;
    //procedure CreateSSLContext(axMode: TIdSSLMode);
    //
    procedure SetPassThrough(const Value: Boolean); override;
    procedure DoBeforeConnect(ASender: TIdSSLIOHandlerSocketOpenSSL); virtual;
    procedure DoGetPassword(var Password: String); virtual;
    procedure DoGetPasswordEx(var VPassword: String; const AIsWrite : Boolean); virtual;

    function DoVerifyPeer(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean; virtual;
    procedure DoStatusInfo(const AMsg: String); virtual;
    procedure DoStatusInfoEx(const aSSLSocket: TIdSSLSocket;
             const AWhere, Aret: TIdC_INT; const AWhereStr, ARetStr : String );
    function RecvEnc(var VBuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;
    procedure Init;
    procedure OpenEncodedConnection; virtual;
    //some overrides from base classes
    procedure InitComponent; override;
    procedure ConnectClient; override;
    function CheckForError(ALastResult: Integer): Integer; override;
    procedure RaiseError(AError: Integer); override;

    { IIdSSLOpenSSLCallbackHelper }
    function GetPassword(const AIsWrite : Boolean): string;
    function GetSSLSocket:  TIdSSLSocket;
    procedure StatusInfo(const aSSLSocket: TIdSSLSocket; AWhere, ARet: TIdC_INT; const AStatusStr: string); overload;
    procedure StatusInfo(const AStatusStr: string); overload;
    function VerifyPeer(ACertificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;

  public
    destructor Destroy; override;
    // TODO: add an AOwner parameter
    function Clone :  TIdSSLIOHandlerSocketBase; override;
    procedure StartSSL; override;
    procedure AfterAccept; override;
    procedure Close; override;
    procedure Open; override;
    function Readable(AMSec: Integer = IdTimeoutDefault): Boolean; override;
    property SSLSocket: TIdSSLSocket read fSSLSocket;
    property SSLContext: TIdSSLContext read fSSLContext;
  published
    property SSLOptions: TIdSSLOptions read fxSSLOptions write fxSSLOptions;
    property OnBeforeConnect: TIOHandlerNotify read fOnBeforeConnect write fOnBeforeConnect;
    property OnStatusInfo: TCallbackEvent read fOnStatusInfo write fOnStatusInfo;
    property OnStatusInfoEx: TCallbackExEvent read fOnStatusInfoEx write fOnStatusInfoEx;
    property OnGetPassword: TPasswordEvent read fOnGetPassword write fOnGetPassword;
    property OnGetPasswordEx : TPasswordEventEx read fOnGetPasswordEx write fOnGetPasswordEx;
    property OnVerifyPeer: TVerifyPeerEvent read fOnVerifyPeer write fOnVerifyPeer;
  end;

  { TIdServerIOHandlerSSLOpenSSL }

  TIdServerIOHandlerSSLOpenSSL = class(TIdServerIOHandlerSSLBase, IIdSSLOpenSSLCallbackHelper)
  protected
    fxSSLOptions: TIdSSLOptions;
    fSSLContext: TIdSSLContext;
    fOnStatusInfo: TCallbackEvent;
    FOnStatusInfoEx : TCallbackExEvent;
    fOnGetPassword: TPasswordEvent;
    fOnGetPasswordEx : TPasswordEventEx;
    fOnVerifyPeer: TVerifyPeerEvent;
    //
    //procedure CreateSSLContext(axMode: TIdSSLMode);
    //procedure CreateSSLContext;
    //
    procedure DoStatusInfo(const AMsg: String); virtual;
    procedure DoStatusInfoEx(const aSSLSocket: TIdSSLSocket;
      const AWhere, Aret: TIdC_INT; const AWhereStr, ARetStr : String );
    procedure DoGetPassword(var Password: String); virtual;
//TPasswordEventEx
    procedure DoGetPasswordEx(var VPassword: String; const AIsWrite : Boolean); virtual;
    function DoVerifyPeer(Certificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean; virtual;
    procedure InitComponent; override;

    { IIdSSLOpenSSLCallbackHelper }
    function GetPassword(const AIsWrite : Boolean): string;
    function GetSSLSocket:  TIdSSLSocket;
    procedure StatusInfo(const aSSLSocket: TIdSSLSocket; AWhere, ARet: TIdC_INT; const AStatusStr: string); overload;
    procedure StatusInfo(const AStatusStr: string); overload;
    function VerifyPeer(ACertificate: TIdX509; AOk: Boolean; ADepth, AError: Integer): Boolean;

  public
    procedure Init; override;
    procedure Shutdown; override;
    // AListenerThread is a thread and not a yarn. Its the listener thread.
    function Accept(ASocket: TIdSocketHandle; AListenerThread: TIdThread;
      AYarn: TIdYarn): TIdIOHandler; override;
//    function Accept(ASocket: TIdSocketHandle; AThread: TIdThread) : TIdIOHandler;  override;
    destructor Destroy; override;
    function MakeClientIOHandler : TIdSSLIOHandlerSocketBase; override;
    //
    function MakeFTPSvrPort : TIdSSLIOHandlerSocketBase; override;
    function MakeFTPSvrPasv : TIdSSLIOHandlerSocketBase; override;
    //
    property SSLContext: TIdSSLContext read fSSLContext;
  published
    property SSLOptions: TIdSSLOptions read fxSSLOptions write fxSSLOptions;
    property OnStatusInfo: TCallbackEvent read fOnStatusInfo write fOnStatusInfo;
    property OnStatusInfoEx: TCallbackExEvent read fOnStatusInfoEx write fOnStatusInfoEx;
    property OnGetPassword: TPasswordEvent read fOnGetPassword write fOnGetPassword;
    property OnGetPasswordEx : TPasswordEventEx read fOnGetPasswordEx write fOnGetPasswordEx;
    property OnVerifyPeer: TVerifyPeerEvent read fOnVerifyPeer write fOnVerifyPeer;
  end;

  EIdOSSLCouldNotLoadSSLLibrary = class(EOpenSSLError);
  EIdOSSLCreatingContextError   = class(EOpenSSLAPICryptoError);
  EIdOSSLDataBindingError = class(EOpenSSLAPISSLError);
  EIdOSSLAcceptError = class(EOpenSSLAPISSLError);
  EIdOSSLConnectError = class(EOpenSSLAPISSLError);
  EIdOSSLLoadingCertError = class(EOpenSSLAPICryptoError);
  EIdOSSLLoadingKeyError = class(EOpenSSLAPICryptoError);
  EIdOSSLLoadingDHParamsError = class(EOpenSSLAPICryptoError);
  EIdOSSLSettingCipherError = class(EOpenSSLError);
  EIdOSSLLoadingRootCertError = class(EOpenSSLAPICryptoError);
  EIdOSSLFDSetError = class(EOpenSSLAPISSLError);
  EIdOSSLModeNotSet             = class(EOpenSSLError);
  EIdOSSLGetMethodError         = class(EOpenSSLError);
  EIdOSSLCreatingSessionError   = class(EOpenSSLError);
  {$IFNDEF OPENSSL_NO_TLSEXT}
  EIdOSSLSettingTLSHostNameError = class(EOpenSSLAPISSLError);
  {$ENDIF}

function OpenSSLVersion: string;
function OpenSSLDir: string;

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
  IdFIPS,
  IdResourceStringsOpenSSL,
  IdStack,
  IdCustomTransparentProxy,
  IdURI,
  SysUtils,
  IdSSLOpenSSLAPI;



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
    {$IFDEF USE_OBJECT_ARC}[Weak]{$ENDIF} Parent: TObject;
  end;


function OpenSSLVersion: string;
begin
  Result := '';
  // RLebeau 9/7/2015: even if LoadOpenSSLLibrary() fails, _SSLeay_version()
  // might have been loaded OK before the failure occured. LoadOpenSSLLibrary()
  // does not unload ..
  LoadOpenSSLLibrary;
  Result := GetIOpenSSL.GetOpenSSLVersionStr;
end;

function OpenSSLDir : string;
var i: integer;
begin
  Result := '';
  LoadOpenSSLLibrary;
  Result := GetIOpenSSL.GetOpenSSLPath;
  {assumed format is 'OPENSSLDIR: "<dir>"'}
  i := Pos('"',Result);
  if i < 0 then
    Result := ''
  else
  begin
    Delete(Result,1,i);
    i := Pos('"',Result);
    if i < 0 then
      Result := ''
    else
      Delete(Result,i,Length(Result)-i+1);
  end;
end;


///////////////////////////////////////////////////////
//   TIdServerIOHandlerSSLOpenSSL
///////////////////////////////////////////////////////

{ TIdServerIOHandlerSSLOpenSSL }

procedure TIdServerIOHandlerSSLOpenSSL.InitComponent;
begin
  inherited InitComponent;
  fxSSLOptions := TIdSSLOptions_Internal.Create;
  TIdSSLOptions_Internal(fxSSLOptions).Parent := Self;
end;

destructor TIdServerIOHandlerSSLOpenSSL.Destroy;
begin
  FreeAndNil(fxSSLOptions);
  inherited Destroy;
end;

procedure TIdServerIOHandlerSSLOpenSSL.Init;
//see also TIdSSLIOHandlerSocketOpenSSL.Init
begin
  //ensure Init isn't called twice
  Assert(fSSLContext = nil);
  fSSLContext := TIdSSLContext.Create(self,SSLOptions,sslCtxServer,Assigned(OnVerifyPeer),
                           Assigned(fOnStatusInfo) or Assigned(FOnStatusInfoEx));
end;

function TIdServerIOHandlerSSLOpenSSL.Accept(ASocket: TIdSocketHandle;
  // This is a thread and not a yarn. Its the listener thread.
  AListenerThread: TIdThread; AYarn: TIdYarn ): TIdIOHandler;
var
  LIO: TIdSSLIOHandlerSocketOpenSSL;
begin
  //using a custom scheduler, AYarn may be nil, so don't assert
  Assert(ASocket<>nil);
  Assert(fSSLContext<>nil);
  Assert(AListenerThread<>nil);

  Result := nil;
  LIO := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.Open;
    while not AListenerThread.Stopped do begin
      if ASocket.Select(250) then begin
        if (not AListenerThread.Stopped) and LIO.Binding.Accept(ASocket.Handle) then begin
          //we need to pass the SSLOptions for the socket from the server
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
          //   SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name). Figure out the right
          //   SSL_CTX to go with that host name, then switch the SSL object to that
          //   SSL_CTX with SSL_set_SSL_CTX().

          // RLebeau 2/1/2022: note, the following call is basically a no-op for OpenSSL,
          // because PassThrough=True and fSSLContext are both assigned above, so there
          // is really nothing for TIdSSLIOHandlerSocketOpenSSL.Init() or
          // TIdSSLIOHandlerSocketOpenSSL.StartSSL() to do when called by
          // TIdSSLIOHandlerSocketOpenSSL.AfterAccept().  If anything, all this will
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

procedure TIdServerIOHandlerSSLOpenSSL.DoStatusInfo(const AMsg: String);
begin
  if Assigned(fOnStatusInfo) then begin
    fOnStatusInfo(AMsg);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL.DoStatusInfoEx(
  const aSSLSocket: TIdSSLSocket; const AWhere, Aret: TIdC_INT;
  const AWhereStr, ARetStr: String);
begin
  if Assigned(FOnStatusInfoEx) then begin
    FOnStatusInfoEx(Self,aSSLSocket,AWhere,Aret,AWHereStr,ARetStr);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL.DoGetPassword(var Password: String);
begin
  if Assigned(fOnGetPassword) then  begin
    fOnGetPassword(Password);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL.DoGetPasswordEx(
  var VPassword: String; const AIsWrite: Boolean);
begin
  if Assigned(fOnGetPasswordEx) then begin
    fOnGetPasswordEx(Self,VPassword,AIsWrite);
  end;
end;

function TIdServerIOHandlerSSLOpenSSL.DoVerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := True;
  if Assigned(fOnVerifyPeer) then begin
    Result := fOnVerifyPeer(Certificate, AOk, ADepth, AError);
  end;
end;

function TIdServerIOHandlerSSLOpenSSL.MakeFTPSvrPort : TIdSSLIOHandlerSocketBase;
var
  LIO : TIdSSLIOHandlerSocketOpenSSL;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
    LIO.IsPeer := True; // RLebeau 1/24/2019: is this still needed now?
    LIO.SSLOptions.Assign(SSLOptions);
    LIO.SSLOptions.Mode := sslmBoth;{or sslmClient}{doesn't really matter}
    LIO.fSSLContext := SSLContext;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

procedure TIdServerIOHandlerSSLOpenSSL.Shutdown;
begin
  FreeAndNil(fSSLContext);
  inherited Shutdown;
end;

function TIdServerIOHandlerSSLOpenSSL.MakeFTPSvrPasv : TIdSSLIOHandlerSocketBase;
var
  LIO : TIdSSLIOHandlerSocketOpenSSL;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
    LIO.IsPeer := True;
    LIO.SSLOptions.Assign(SSLOptions);
    LIO.SSLOptions.Mode := sslmBoth;{or sslmServer}
    LIO.fSSLContext := nil;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

{ IIdSSLOpenSSLCallbackHelper }

function TIdServerIOHandlerSSLOpenSSL.GetPassword(const AIsWrite : Boolean): string;
begin
  DoGetPasswordEx(Result, AIsWrite);
  if Result = '' then begin
    DoGetPassword(Result);
  end;
end;

function TIdServerIOHandlerSSLOpenSSL.GetSSLSocket: TIdSSLSocket;
begin
  Result := nil;
end;

procedure TIdServerIOHandlerSSLOpenSSL.StatusInfo(
  const aSSLSocket: TIdSSLSocket; AWhere, ARet: TIdC_INT;
  const AStatusStr: string);
var
  LType, LMsg: string;
begin
  DoStatusInfo(AStatusStr);
  if Assigned(fOnStatusInfoEx) then begin
    aSSLSocket.GetStateVars(AWhere, ARet, LType, LMsg);
    DoStatusInfoEx(aSSLSocket, AWhere, ARet, LType, LMsg);
  end;
end;

procedure TIdServerIOHandlerSSLOpenSSL.StatusInfo(const AStatusStr: string);
begin
  DoStatusInfo(AStatusStr);
end;

function TIdServerIOHandlerSSLOpenSSL.VerifyPeer(ACertificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := DoVerifyPeer(ACertificate, AOk, ADepth, AError);
end;

///////////////////////////////////////////////////////
//   TIdSSLIOHandlerSocketOpenSSL
///////////////////////////////////////////////////////

function TIdServerIOHandlerSSLOpenSSL.MakeClientIOHandler: TIdSSLIOHandlerSocketBase;
var
  LIO : TIdSSLIOHandlerSocketOpenSSL;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  try
    LIO.PassThrough := True;
  //  LIO.SSLOptions.Free;
  //  LIO.SSLOptions := SSLOptions;
  //  LIO.SSLContext := SSLContext;
    LIO.SSLOptions.Assign(SSLOptions);
  //  LIO.SSLContext := SSLContext;
    LIO.fSSLContext := nil;//SSLContext.Clone; // BGO: clone does not work, it must be either NIL, or SSLContext
    LIO.OnGetPassword := DoGetPassword;
    LIO.OnGetPasswordEx := OnGetPasswordEx;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

{ TIdSSLIOHandlerSocketOpenSSL }

procedure TIdSSLIOHandlerSocketOpenSSL.InitComponent;
begin
  inherited InitComponent;
  IsPeer := False;
  fxSSLOptions := TIdSSLOptions_Internal.Create;
  TIdSSLOptions_Internal(fxSSLOptions).Parent := Self;
  fSSLLayerClosed := True;
  fSSLContext := nil;
end;

destructor TIdSSLIOHandlerSocketOpenSSL.Destroy;
begin
  FreeAndNil(fSSLSocket);
  //we do not destroy these if their Parent is not Self
  //because these do not belong to us when we are in a server.
  if (fSSLContext <> nil) and fSSLContext.IsParent(Self) then begin
    FreeAndNil(fSSLContext);
  end;
  if (fxSSLOptions <> nil) and
     (fxSSLOptions is TIdSSLOptions_Internal) and
     (TIdSSLOptions_Internal(fxSSLOptions).Parent = Self) then
  begin
    FreeAndNil(fxSSLOptions);
  end;
  inherited Destroy;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.ConnectClient;
var
  LPassThrough: Boolean;
begin
  // RLebeau: initialize OpenSSL before connecting the socket...
  try
    Init;
  except
    on EIdOSSLCouldNotLoadSSLLibrary do begin
      if not PassThrough then raise;
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

procedure TIdSSLIOHandlerSocketOpenSSL.StartSSL;
begin
  if not PassThrough then begin
    OpenEncodedConnection;
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.Close;
begin
  FreeAndNil(fSSLSocket);
  if fSSLContext <> nil then begin
    if fSSLContext.IsParent(Self) then begin
      FreeAndNil(fSSLContext);
    end else begin
      fSSLContext := nil;
    end;
  end;
  inherited Close;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.Open;
begin
  FOpened := False;
  inherited Open;
end;

function TIdSSLIOHandlerSocketOpenSSL.Readable(AMSec: Integer = IdTimeoutDefault): Boolean;
 begin
  repeat
    {Wait for data ready - or timer expiry}
    Result := inherited Readable(AMSec);
    {If the inherited Readable returns false then we have a timeout.
     Otherwise data is present but could be application or non-application data}
    if not Result then
      Exit;

    if not fPassThrough and (fSSLSocket <> nil) then
    Result := fSSLSocket.Readable in [sslDataAvailable,sslUnRecoverableError,sslEOF];
  until Result;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.SetPassThrough(const Value: Boolean);
begin
  if fPassThrough <> Value then begin
    if not Value then begin
      if BindingAllocated then begin
        if Assigned(fSSLContext) then begin
          OpenEncodedConnection;
        end else begin
          raise EIdOSSLCouldNotLoadSSLLibrary.Create(RSOSSLCouldNotLoadSSLLibrary);
        end;
      end;
    end
    else begin
      // RLebeau 8/16/2019: need to call SSL_shutdown() here if the SSL/TLS session is active.
      // This is for FTP when handling CCC and REIN commands. The SSL/TLS session needs to be
      // shutdown cleanly on both ends without closing the underlying socket connection because
      // it is going to be used for continued unsecure communications!
      if fSSLSocket <> nil then
        fSSLSocket.DoShutdown;

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

function TIdSSLIOHandlerSocketOpenSSL.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  Result := fSSLSocket.Recv(VBuffer);
end;

function TIdSSLIOHandlerSocketOpenSSL.SendEnc(const ABuffer: TIdBytes;
  const AOffset, ALength: Integer): Integer;
begin
  Result := fSSLSocket.Send(ABuffer, AOffset, ALength);
end;

procedure TIdSSLIOHandlerSocketOpenSSL.AfterAccept;
begin
  try
    inherited AfterAccept;
    // RLebeau: initialize OpenSSL after accepting a client socket...
    try
      Init;
    except
      on EIdOSSLCouldNotLoadSSLLibrary do begin
        if not PassThrough then raise;
      end;
    end;
    StartSSL;
  except
    Close;
    raise;
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.Init;
//see also TIdServerIOHandlerSSLOpenSSL.Init
begin
  if not Assigned(fSSLContext) then
    fSSLContext := TIdSSLContext.Create(self,SSLOptions,sslCtxClient,Assigned(OnVerifyPeer),
                           Assigned(fOnStatusInfo) or Assigned(FOnStatusInfoEx));
end;
//}

procedure TIdSSLIOHandlerSocketOpenSSL.DoStatusInfo(const AMsg: String);
begin
  if Assigned(fOnStatusInfo) then begin
    fOnStatusInfo(AMsg);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.DoStatusInfoEx(
  const aSSLSocket: TIdSSLSocket; const AWhere, Aret: TIdC_INT;
  const AWhereStr, ARetStr: String);
begin
  if Assigned(FOnStatusInfoEx) then begin
    FOnStatusInfoEx(Self,aSSLSocket,AWhere,Aret,AWHereStr,ARetStr);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.DoGetPassword(var Password: String);
begin
  if Assigned(fOnGetPassword) then begin
    fOnGetPassword(Password);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.DoGetPasswordEx(var VPassword: String;
  const AIsWrite: Boolean);
begin
  if Assigned(fOnGetPasswordEx) then begin
    fOnGetPasswordEx(Self,VPassword,AIsWrite);
  end;
end;

function TIdSSLIOHandlerSocketOpenSSL.DoVerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := True;
  if Assigned(fOnVerifyPeer) then begin
    Result := fOnVerifyPeer(Certificate, AOk, ADepth, AError);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.OpenEncodedConnection;
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
          if not Assigned(LNextTransparentProxy) then Break;
          if not LNextTransparentProxy.Enabled then Break;
          LTransparentProxy := LNextTransparentProxy;
        until False;
        Result := LTransparentProxy.Host;
      end;
    end;
  end;

begin
  Assert(Binding<>nil);
  if not Assigned(fSSLSocket) then begin
    fSSLSocket := TIdSSLSocket.Create(Self);
  end;
  fSSLSocket.SSLContext := fSSLContext;
  {$IFDEF WIN32_OR_WIN64}
  // begin bug fix
  if IndyCheckWindowsVersion(6) then
  begin
    // Note: Fix needed to allow SSL_Read and SSL_Write to timeout under
    // Vista+ when connection is dropped
    LTimeout := FReadTimeOut;
    if LTimeout <= 0 then begin
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
  // in TIdSSLIOHandlerSocketOpenSSL.Destroy() and TIdSSLIOHandlerSocketOpenSSL.Close()
  // in client components!  IsPeer is intended to be set to True only in server
  // components...
  LMode := fSSLContext.Mode;
  if not (LMode in [sslmClient, sslmServer]) then begin
    // Mode must be sslmBoth (or else TIdSSLContext.SetSSLMethod() would have
    // raised an exception), so just fall back to previous behavior for now,
    // until we can figure out a better way to handle this scenario...
    if IsPeer then begin
      LMode := sslmServer;
    end else begin
      LMode := sslmClient;
    end;
  end;
  if LMode = sslmClient then begin
    LHost := GetURIHost;
    if LHost = '' then
    begin
      LHost := GetProxyTargetHost;
      if LHost = '' then begin
        LHost := Self.Host;
      end;
    end;
    fSSLSocket.HostName := LHost;
    fSSLSocket.Connect(Binding.Handle);
  end else begin
    fSSLSocket.HostName := '';
    fSSLSocket.Accept(Binding.Handle);
  end;
  fPassThrough := False;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.DoBeforeConnect(ASender: TIdSSLIOHandlerSocketOpenSSL);
begin
  if Assigned(OnBeforeConnect) then begin
    OnBeforeConnect(Self);
  end;
end;


// TODO: add an AOwner parameter
function TIdSSLIOHandlerSocketOpenSSL.Clone: TIdSSLIOHandlerSocketBase;
var
  LIO : TIdSSLIOHandlerSocketOpenSSL;
begin
  LIO := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  try
    LIO.SSLOptions.Assign( SSLOptions );
    LIO.OnStatusInfo := DoStatusInfo;
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

function TIdSSLIOHandlerSocketOpenSSL.CheckForError(ALastResult: Integer): Integer;
//var
//  err: Integer;
begin
  if PassThrough then begin
    Result := inherited CheckForError(ALastResult);
  end else begin
    Result := fSSLSocket.GetSSLError(ALastResult);
    if Result = SSL_ERROR_NONE then begin
      Result := 0;
      Exit;
    end;
    if Result = SSL_ERROR_SYSCALL then begin
      Result := inherited CheckForError(Integer(Id_SOCKET_ERROR));
      Exit;
    end;
    EOpenSSLAPISSLError.RaiseExceptionCode(Result, ALastResult, '');
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.RaiseError(AError: Integer);
begin
  if (PassThrough) or (AError = Id_WSAESHUTDOWN) or (AError = Id_WSAECONNABORTED) or (AError = Id_WSAECONNRESET) then begin
    inherited RaiseError(AError);
  end
  else
    fSSLSocket.RaiseError(AError);
end;

{ IIdSSLOpenSSLCallbackHelper }

function TIdSSLIOHandlerSocketOpenSSL.GetPassword(const AIsWrite : Boolean): string;
begin
  DoGetPasswordEx(Result, AIsWrite);
  if Result = '' then begin
    DoGetPassword(Result);
  end;
end;

function TIdSSLIOHandlerSocketOpenSSL.GetSSLSocket: TIdSSLSocket;
begin
  Result := fSSLSocket;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.StatusInfo(
  const aSSLSocket: TIdSSLSocket; AWhere, ARet: TIdC_INT;
  const AStatusStr: string);
var
  LType, LMsg: string;
begin
  DoStatusInfo(AStatusStr);
  if Assigned(fOnStatusInfoEx) then begin
    aSSLSocket.GetStateVars(AWhere, ARet, LType, LMsg);
    DoStatusInfoEx(aSSLSocket, AWhere, ARet, LType, LMsg);
  end;
end;

procedure TIdSSLIOHandlerSocketOpenSSL.StatusInfo(const AStatusStr: string);
begin
  DoStatusInfo(AStatusStr);
end;

function TIdSSLIOHandlerSocketOpenSSL.VerifyPeer(ACertificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Result := DoVerifyPeer(ACertificate, AOk, ADepth, AError);
end;


{$I IdSymbolDeprecatedOff.inc}

initialization

  {$I IdSymbolDeprecatedOff.inc}
  RegisterSSL('OpenSSL','Indy Pit Crew',                                  {do not localize}
    'Copyright '+Char(169)+' 1993 - 2014'#10#13 +                         {do not localize}
    'Chad Z. Hower (Kudzu) and the Indy Pit Crew. All rights reserved.',  {do not localize}
    'Open SSL Support DLL Delphi and C++Builder interface',               {do not localize}
    'http://www.indyproject.org/'#10#13 +                                 {do not localize}
    'Original Author - Gregor Ibic',                                      {do not localize}
    TIdSSLIOHandlerSocketOpenSSL,
    TIdServerIOHandlerSSLOpenSSL);
  {$I IdSymbolDeprecatedOn.inc}

  TIdSSLIOHandlerSocketOpenSSL.RegisterIOHandler;
finalization
  // TODO: TIdSSLIOHandlerSocketOpenSSL.UnregisterIOHandler;
end.
