unit IdSSLOpenSSLX509;

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
  IdOpenSSLHeaders_ssl,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_x509,
  IdSSLOpenSSLUtils
;

type
  TIdSSLULong = packed record
    case Byte of
      0: (B1, B2, B3, B4: UInt8);
      1: (W1, W2: UInt16);
      2: (L1: Int32);
      3: (C1: UInt32);
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
    //Do not free this here because it belongs
    //to the X509 or something else.
    FX509 : PX509;
  public
    constructor Create( aX509: PX509);
    //
    property Certificate: PX509 read FX509;
  end;

  TIdX509Fingerprints = class(TIdX509Info)
  protected
    function GetMD5: TIdSSLEVP_MD;
    function GetMD5AsString:String;
    function GetSHA1: TIdSSLEVP_MD;
    function GetSHA1AsString:String;
    function GetSHA224 : TIdSSLEVP_MD;
    function GetSHA224AsString : String;
    function GetSHA256 : TIdSSLEVP_MD;
    function GetSHA256AsString : String;
    function GetSHA384 : TIdSSLEVP_MD;
    function GetSHA384AsString : String;
    function GetSHA512 : TIdSSLEVP_MD;
    function GetSHA512AsString : String;
  public
     property MD5 : TIdSSLEVP_MD read GetMD5;
     property MD5AsString : String read  GetMD5AsString;
     property SHA1 : TIdSSLEVP_MD read GetSHA1;
     property SHA1AsString : String read  GetSHA1AsString;
{IMPORTANT!!!

FIPS approves only these algorithms for hashing.
SHA-1
SHA-256
SHA-384
SHA-512

http://csrc.nist.gov/CryptoToolkit/tkhash.html
}
    property SHA224 : TIdSSLEVP_MD read GetSHA224;
    property SHA224AsString : String read GetSHA224AsString;
    property SHA256 : TIdSSLEVP_MD read GetSHA256;
    property SHA256AsString : String read GetSHA256AsString;
    property SHA384 : TIdSSLEVP_MD read GetSHA384;
    property SHA384AsString : String read GetSHA384AsString;
    property SHA512 : TIdSSLEVP_MD read GetSHA512;
    property SHA512AsString : String read GetSHA512AsString;
  end;

  TIdX509SigInfo = class(TIdX509Info)
  protected
    function GetSignature : String;
    function GetSigType : TIdC_INT;
    function GetSigTypeAsString : String;
  public
    property Signature : String read GetSignature;
    property SigType : TIdC_INT read  GetSigType ;
    property SigTypeAsString : String read GetSigTypeAsString;
  end;

  TIdX509 = class(TObject)
  protected
    FFingerprints : TIdX509Fingerprints;
    FSigInfo : TIdX509SigInfo;
    FCanFreeX509 : Boolean;
    FX509    : PX509;
    FSubject : TIdX509Name;
    FIssuer  : TIdX509Name;
    FDisplayInfo : TStrings;
    function RSubject:TIdX509Name;
    function RIssuer:TIdX509Name;
    function RnotBefore:TDateTime;
    function RnotAfter:TDateTime;
    function RFingerprint:TIdSSLEVP_MD;
    function RFingerprintAsString:String;
    function GetSerialNumber: String;
    function GetVersion : TIdC_LONG;
    function GetDisplayInfo : TStrings;
  public
    Constructor Create(aX509: PX509; aCanFreeX509: Boolean = True); virtual;
    Destructor Destroy; override;
    property Version : TIdC_LONG read GetVersion;
    //
    property SigInfo : TIdX509SigInfo read FSigInfo;
    property Fingerprints : TIdX509Fingerprints read FFingerprints;
    //
    property Fingerprint: TIdSSLEVP_MD read RFingerprint;
    property FingerprintAsString: String read RFingerprintAsString;
    property Subject: TIdX509Name read RSubject;
    property Issuer: TIdX509Name read RIssuer;
    property notBefore: TDateTime read RnotBefore;
    property notAfter: TDateTime read RnotAfter;
    property SerialNumber : string read GetSerialNumber;
    property DisplayInfo : TStrings read GetDisplayInfo;
    //
    property Certificate: PX509 read FX509;
  end;

function IndySSL_load_client_CA_file(const AFileName: String) : PSTACK_OF_X509_NAME;
function IndySSL_CTX_load_verify_locations(ctx: PSSL_CTX; const ACAFile, ACAPath: String): TIdC_INT;
function IndySSL_CTX_use_certificate_file(ctx: PSSL_CTX; const AFileName: String; AType: Integer): TIdC_INT;
function IndySSL_CTX_use_certificate_file_PKCS12(ctx: PSSL_CTX; const AFileName: String): TIdC_INT;
function IndySSL_CTX_use_certificate_chain_file(ctx :PSSL_CTX; const AFileName: String) : TIdC_INT;
function IndySSL_CTX_use_PrivateKey_file_PKCS12(ctx: PSSL_CTX; const AFileName: String): TIdC_INT;
function IndySSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String; AType: Integer): TIdC_INT;
function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String; AType: Integer): TIdC_INT;
function IndyX509_STORE_load_locations(ctx: PX509_STORE; const AFileName, APathName: String): TIdC_INT;


implementation

uses
  IdStack,
  IdFIPS,
  IdSSLOpenSSL,
  IdOpenSSLHeaders_x509_vfy,
  IdOpenSSLHeaders_pkcs12,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_objects,
  IdOpenSSLHeaders_err,
  IdOpenSSLHeaders_sslerr,
  IdOpenSSLHeaders_stack,
  IdOpenSSLHeaders_dh,
  IdOpenSSLHeaders_pem,
  IdOpenSSLHeaders_bio
  ;


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



{$IFNDEF OPENSSL_NO_BIO}
procedure DumpCert(AOut: TStrings; AX509: PX509);
var
  LMem: PBIO;
  LLen : TIdC_INT;
  LBufPtr : PIdAnsiChar;
begin
    LMem := BIO_new(BIO_s_mem);
    if LMem <> nil then begin
      try
        X509_print(LMem, AX509);
        LLen := BIO_get_mem_data(LMem, LBufPtr);
        if (LLen > 0) and (LBufPtr <> nil) then begin
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

{$ELSE}

procedure DumpCert(AOut: TStrings; AX509: PX509);
begin
end;

{$ENDIF}


///////////////////////////////////////////////////////////////
//  X509 Certificate
///////////////////////////////////////////////////////////////

{ TIdX509Name }

function TIdX509Name.CertInOneLine: String;
var
  LOneLine: array[0..2048] of TIdAnsiChar;
begin
  if FX509Name = nil then begin
    Result := '';    {Do not Localize}
  end else begin
    Result := String(X509_NAME_oneline(FX509Name, @LOneLine[0], SizeOf(LOneLine)));
  end;
end;

function TIdX509Name.GetHash: TIdSSLULong;
begin
  if FX509Name = nil then begin
    FillChar(Result, SizeOf(Result), 0)
  end else begin
    Result.C1 := X509_NAME_hash(FX509Name);
  end;
end;

function TIdX509Name.GetHashAsString: String;
begin
  Result := IndyFormat('%.8x', [Hash.L1]); {do not localize}
end;

constructor TIdX509Name.Create(aX509Name: PX509_NAME);
begin
  Inherited Create;
  FX509Name := aX509Name;
end;


///////////////////////////////////////////////////////////////
//  X509 Certificate
///////////////////////////////////////////////////////////////

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

function TIdX509Fingerprints.GetSHA224 : TIdSSLEVP_MD;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_sha224) then begin
    X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA224AsString : String;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  Result := MDAsString(SHA224);
  {$ELSE}
  if Assigned(EVP_sha224) then begin
    Result := MDAsString(SHA224);
  end else begin
    Result := '';
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA256 : TIdSSLEVP_MD;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_sha256) then begin
    X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA256AsString : String;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  Result := MDAsString(SHA256);
  {$ELSE}
  if Assigned(EVP_sha256) then begin
    Result := MDAsString(SHA256);
  end else begin
    Result := '';
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA384 : TIdSSLEVP_MD;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_SHA384) then begin
    X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA384AsString : String;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  Result := MDAsString(SHA384);
  {$ELSE}
  if Assigned(EVP_SHA384) then begin
    Result := MDAsString(SHA384);
  end else begin
    Result := '';
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA512 : TIdSSLEVP_MD;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_sha512) then begin
    X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ifend}
end;

function TIdX509Fingerprints.GetSHA512AsString : String;
begin
  {$if not declared(OpenSSL_Using_Dynamic_Library_Load)}
  Result := MDAsString(SHA512);
  {$ELSE}
  if Assigned(EVP_sha512) then begin
    Result := MDAsString(SHA512);
  end else begin
    Result := '';
  end;
  {$ifend}
end;

{ TIdX509SigInfo }

function TIdX509SigInfo.GetSignature: String;
var
  sig_alg : PX509_ALGOR;
  signature : PASN1_BIT_STRING;
begin
  X509_get0_signature(signature,sig_alg, FX509);
  Result := BytesToHexString(signature^.data, signature^.length);
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
  //don't create FDisplayInfo unless specifically requested.
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
  if FCanFreeX509 then begin
    X509_free(FX509);
  end;
  inherited Destroy;
end;


function TIdX509.GetDisplayInfo: TStrings;
begin
  if not Assigned(FDisplayInfo) then begin
    FDisplayInfo := TStringList.Create;
    DumpCert(FDisplayInfo, FX509);
  end;
  Result := FDisplayInfo;
end;

function TIdX509.GetSerialNumber: String;
var
  LSN : PASN1_INTEGER;
begin
  if FX509 <> nil then begin
    LSN := X509_get_serialNumber(FX509);
    Result := BytesToHexString(LSN.data, LSN.length);
  end else begin
    Result := '';
  end;
end;

function TIdX509.GetVersion : TIdC_LONG;
begin
  Result := X509_get_version(FX509);
end;

function TIdX509.RSubject: TIdX509Name;
var
  Lx509_name: PX509_NAME;
Begin
  if not Assigned(FSubject) then begin
    if FX509 <> nil then begin
      Lx509_name := X509_get_subject_name(FX509);
    end else begin
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
  if not Assigned(FIssuer) then begin
    if FX509 <> nil then begin
      Lx509_name := X509_get_issuer_name(FX509);
    end else begin
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
  if FX509 = nil then begin
    Result := 0
  end else begin
    //This is a safe typecast since PASN1_UTCTIME and PASN1_TIME are really
    //pointers to ASN1 strings since ASN1_UTCTIME amd ASM1_TIME are ASN1_STRING.
    Result := UTCTime2DateTime(PASN1_UTCTIME(X509_get0_notBefore(FX509)));
  end;
end;

function TIdX509.RnotAfter:TDateTime;
begin
  if FX509 = nil then begin
    Result := 0
  end else begin
    Result := UTCTime2DateTime(PASN1_UTCTIME(X509_get0_notAfter(FX509)));
  end;
end;

function IndySSL_CTX_use_PrivateKey_file_PKCS12(ctx: PSSL_CTX; const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LKey: PEVP_PKEY;
  LCert: PX509;
  P12: PPKCS12;
  CertChain: PSTACK_OF_X509;
  LPassword: array of TIdAnsiChar;
  LPasswordPtr: PIdAnsiChar;
  default_passwd_cb: pem_password_cb;
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
    B := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(B) then begin
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      SetLength(LPassword, MAX_SSL_PASSWORD_LENGTH+1);
      LPassword[MAX_SSL_PASSWORD_LENGTH] := TIdAnsiChar(0);
      LPasswordPtr := PIdAnsiChar(LPassword);
      default_passwd_cb := SSL_CTX_get_default_passwd_cb(ctx);
      if Assigned(default_passwd_cb) then begin
        default_passwd_cb(LPasswordPtr, MAX_SSL_PASSWORD_LENGTH, 0, SSL_CTX_get_default_passwd_cb_userdata(ctx));
        // TODO: check return value for failure
      end else begin
        // TODO: call PEM_def_callback(), like PEM_read_bio_X509() does
        // when default_passwd_callback is nil
      end;
      P12 := d2i_PKCS12_bio(B, nil);
      if not Assigned(P12) then begin
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_PKCS12_LIB);
        Exit;
      end;
      try
        CertChain := nil;
        if PKCS12_parse(P12, LPasswordPtr, LKey, LCert, @CertChain) <> 1 then begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
          Exit;
        end;
        try
          Result := SSL_CTX_use_PrivateKey(ctx, LKey);
        finally
          OPENSSL_sk_pop_free(CertChain, @X509_free);
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

function IndySSL_CTX_use_certificate_file_PKCS12(ctx: PSSL_CTX; const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LCert: PX509;
  P12: PPKCS12;
  PKey: PEVP_PKEY;
  CertChain: PSTACK_OF_X509;
  LPassword: array of TIdAnsiChar;
  LPasswordPtr: PIdAnsiChar;
  default_passwd_callback: pem_password_cb;
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
    B := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(B) then begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      SetLength(LPassword, MAX_SSL_PASSWORD_LENGTH+1);
      LPassword[MAX_SSL_PASSWORD_LENGTH] := TIdAnsiChar(0);
      LPasswordPtr := PIdAnsiChar(LPassword);
      default_passwd_callback := SSL_CTX_get_default_passwd_cb(ctx);
      if Assigned(default_passwd_callback) then begin
        default_passwd_callback(LPasswordPtr, MAX_SSL_PASSWORD_LENGTH, 0, SSL_CTX_get_default_passwd_cb_userdata(ctx));
        // TODO: check return value for failure
      end else begin
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
        if PKCS12_parse(P12, LPasswordPtr, PKey, LCert, @CertChain) <> 1 then begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
          Exit;
        end;
        try
          Result := SSL_CTX_use_certificate(ctx, LCert);
        finally
          OPENSSL_sk_pop_free(CertChain, @X509_free);
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

{$IFDEF STRING_IS_UNICODE} {UCS-2 implied}

  {$IFDEF WINDOWS}

function Indy_unicode_X509_load_cert_crl_file(ctx: PX509_LOOKUP; const AFileName: String;
  const _type: TIdC_INT): TIdC_INT; forward;
function Indy_unicode_X509_load_cert_file(ctx: PX509_LOOKUP; const AFileName: String;
  _type: TIdC_INT): TIdC_INT; forward;

{
  This is for some file lookup definitions for a LOOKUP method that
  uses Unicode filenames instead of ASCII or UTF8.  It is not meant
  to be portable at all.
}

function by_Indy_unicode_file_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT;
  const argc: PAnsiChar; argl: TIdC_LONG; out ret: PAnsiChar): TIdC_INT; cdecl;
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
              LFileName := GetEnvironmentVariable(String(X509_get_default_cert_file_env));
              if LFileName = '' then begin
                LFileName := String(X509_get_default_cert_file);
              end;
              LOk := Ord(Indy_unicode_X509_load_cert_crl_file(ctx, LFileName, X509_FILETYPE_PEM) <> 0);
              if LOk = 0 then begin
                X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
              end;
            end;
          X509_FILETYPE_PEM:
            begin
              LFileName := PWideChar(Pointer(argc));
              LOk := Ord(Indy_unicode_X509_load_cert_crl_file(ctx, LFileName, X509_FILETYPE_PEM) <> 0);
            end;
        else
          LFileName := PWideChar(Pointer(argc));
          LOk := Ord(Indy_unicode_X509_load_cert_file(ctx, LFileName, TIdC_INT(argl)) <> 0);
        end;
      end;
  end;
  Result := LOk;
end;

function Indy_unicode_X509_load_cert_file(ctx: PX509_LOOKUP; const AFileName: String;
  _type: TIdC_INT): TIdC_INT;
var
  LM: TMemoryStream;
  Lin: PBIO;
  LX: PX509;
  i, count: Integer;
begin
  Result := 0;
  count := 0;

  if AFileName = '' then begin
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
    Lin := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(Lin) then begin
      X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
      Exit;
    end;
    try
      case _type of
        X509_FILETYPE_PEM:
          begin
            repeat
              LX := PEM_read_bio_X509_AUX(Lin, nil, nil, nil);
              if not Assigned(LX) then begin
                if ((ERR_GET_REASON(ERR_peek_last_error())
                      = PEM_R_NO_START_LINE) and (count > 0)) then begin
                  ERR_clear_error();
                  Break;
                end else begin
                  X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_PEM_LIB);
                  Exit;
                end;
              end;
              i := X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), LX);
              if i = 0 then begin
                Exit;
              end;
              Inc(count);
              X509_Free(LX);
            until False;
            Result := count;
          end;
        X509_FILETYPE_ASN1:
          begin
            LX := d2i_X509_bio(Lin, nil);
            if not Assigned(LX) then begin
              X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
              Exit;
            end;
            i := X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), LX);
            if i = 0 then begin
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

function Indy_unicode_X509_load_cert_crl_file(ctx: PX509_LOOKUP; const AFileName: String;
  const _type: TIdC_INT): TIdC_INT;
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

  if _type <> X509_FILETYPE_PEM then begin
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
    Lin := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(Lin) then begin
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
  if not Assigned(Linf) then begin
    X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
    Exit;
  end;
  try
    for i := 0 to OPENSSL_sk_num(Linf) - 1 do begin
      Litmp := PX509_INFO(OPENSSL_sk_value(Linf, i));
      if Assigned(Litmp^.x509) then begin
        X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), Litmp^.x509);
        Inc(count);
      end;
      if Assigned(Litmp^.crl) then begin
        X509_STORE_add_crl(X509_LOOKUP_get_store(ctx), Litmp^.crl);
        Inc(count);
      end;
    end;
  finally
    OPENSSL_sk_pop_free(Linf, @X509_INFO_free);
  end;
  Result := count;
end;

procedure IndySSL_load_client_CA_file_err(var VRes: PSTACK_OF_X509_NAME);
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  if Assigned(VRes) then begin
    OPENSSL_sk_pop_free(VRes, @X509_NAME_free);
    VRes := nil;
  end;
end;

function xname_cmp(const a, b: PPX509_NAME): TIdC_INT; cdecl;
begin
  Result := X509_NAME_cmp(a^, b^);
end;

function IndySSL_load_client_CA_file(const AFileName: String): PSTACK_OF_X509_NAME;
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
  Lsk := OPENSSL_sk_new(@xname_cmp);
  if Assigned(Lsk) then begin
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
        LB := BIO_new_mem_buf(LM.Memory, LM.Size);
        if Assigned(LB) then begin
          try
            try
              repeat
                LX := PEM_read_bio_X509(LB, nil, nil, nil);
                if LX = nil then begin
                  Break;
                end;
                if not Assigned(Result) then begin
                  Result := OPENSSL_sk_new_null;
                  if not Assigned(Result) then begin
                    SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                    Failed := True;
                    Exit;
                  end;
                end;
                LXN := X509_get_subject_name(LX);
                if not Assigned(LXN) then begin
                  // error
                  IndySSL_load_client_CA_file_err(Result);
                  Failed := True;
                  Exit;
                end;
                // * check for duplicates */
                LXNDup := X509_NAME_dup(LXN);
                if not Assigned(LXNDup) then begin
                  // error
                  IndySSL_load_client_CA_file_err(Result);
                  Failed := True;
                  Exit;
                end;
                if (OPENSSL_sk_find(Lsk, LXNDup) >= 0) then begin
                  X509_NAME_free(LXNDup);
                end else begin
                  OPENSSL_sk_push(Lsk, LXNDup);
                  OPENSSL_sk_push(Result, LXNDup);
                end;
                X509_free(LX);
                LX := nil;
              until False;
            finally
              if Assigned(LX) then begin
                X509_free(LX);
              end;
              if Failed and Assigned(Result) then begin
                OPENSSL_sk_pop_free(Result, @X509_NAME_free);
                Result := nil;
              end;
            end;
          finally
            BIO_free(LB);
          end;
        end
        else begin
          SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        end;
      finally
        FreeAndNil(LM);
      end;
    finally
      OPENSSL_sk_free(Lsk);
    end;
  end
  else begin
    SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
  end;
  if Assigned(Result) then begin
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
    B := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(B) then begin
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      case AType of
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_PEM_LIB;
            LKey := PEM_read_bio_PrivateKey(B, nil,
              SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
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
      if not Assigned(LKey) then begin
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
    B := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(B) then begin
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
            LX := PEM_read_bio_X509(B, nil, SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
        else begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LX) then begin
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

function IndySSL_CTX_use_certificate_chain_file(ctx :PSSL_CTX;
  const AFileName: String) : TIdC_INT;
var
  LM: TMemoryStream;
  B: PBIO;
  LX: PX509;
  ca :PX509;
  r: TIdC_INT;
  LErr :TIdC_ULONG;

begin
  Result := 0;

  ERR_clear_error();    //* clear error stack for
                        //* SSL_CTX_use_certificate() */

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
    B := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(B) then begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      LX := PEM_read_bio_X509_AUX(B, nil, SSL_CTX_get_default_passwd_cb(ctx),
                              SSL_CTX_get_default_passwd_cb_userdata(ctx));
      if (Lx = nil) then begin
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
      end else begin
        Result := SSL_CTX_use_certificate(ctx, Lx);
        if (ERR_peek_error() <> 0) then begin
          Result := 0;         //* Key/certificate mismatch doesn't imply
                               //* ret==0 ... */
        end;
        if Result <> 0 then begin
          SSL_CTX_clear_chain_certs(ctx);
          repeat
            ca := PEM_read_bio_X509(B, nil,
              SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
            if ca = nil then begin
              break;
            end;
            r := SSL_CTX_add0_chain_cert(ctx, ca);
            if (r = 0) then begin
                X509_free(ca);
                Result := 0;
                break;
//                goto end;
            end;
            //*
            //* Note that we must not free r if it was successfully added to
            //* the chain (while we must free the main certificate, since its
            //* reference count is increased by SSL_CTX_use_certificate).
            // */
          until False;
          if ca <> nil then begin
            //* When the while loop ends, it's usually just EOF. */
            LErr := ERR_peek_last_error();
            if (ERR_GET_LIB(Lerr) = ERR_LIB_PEM)
              and (ERR_GET_REASON(Lerr) = PEM_R_NO_START_LINE) then begin
              ERR_clear_error();
            end else begin
              Result := 0;            //* some real error */
            end;
          end;
        end;
        //err:
        if LX <> nil then begin
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
  method: PX509_LOOKUP_METHOD;  {reference counted}
begin
  Result := 0;
  if AFileName <> '' then begin
    method := X509_LOOKUP_meth_new('Load file into cache');
    lookup := X509_STORE_add_lookup(ctx, method);
    if not Assigned(lookup) then begin
      Exit;
    end;
    X509_LOOKUP_meth_set_ctrl(method,@by_Indy_unicode_file_ctrl);
    // RLebeau: the PAnsiChar(Pointer(...)) cast below looks weird, but it is
    // intentional. X509_LOOKUP_load_file() takes a PAnsiChar as input, but
    // we are using Unicode strings here.  So casting the UnicodeString to a
    // raw Pointer and then passing that to X509_LOOKUP_load_file() as PAnsiChar.
    // Indy_Unicode_X509_LOOKUP_file will cast it back to PWideChar for processing...
    if (X509_LOOKUP_load_file(lookup, PAnsiChar(pointer(AFileName)), X509_FILETYPE_PEM) <> 1) then begin
      Exit;
    end;
  end;
  if APathName <> '' then begin
    { TODO: Figure out how to do the hash dir lookup with a Unicode path. }
    if (X509_STORE_load_locations(ctx, nil, PAnsiChar(AnsiString(APathName))) <> 1) then begin
      Exit;
    end;
  end;
  if (AFileName = '') and (APathName = '') then begin
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

function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT;
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
    B := BIO_new_mem_buf(LM.Memory, LM.Size);
    if not Assigned(B) then begin
      SSLerr(SSL_F_SSL3_CTRL, ERR_R_BUF_LIB);
      Exit;
    end;
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
            LDH := PEM_read_bio_DHparams(B, nil, SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
        else begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then begin
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

function IndySSL_load_client_CA_file(const AFileName: String) : PSTACK_OF_X509_NAME;
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

function IndySSL_CTX_use_certificate_chain_file(ctx :PSSL_CTX;
  const AFileName: String) : TIdC_INT;
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
  if S <> '' then begin
    Result := M.AsUtf8(S).ToPointer;
  end else begin
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
    AsUtf8OrNil(M, AFileName),
    AsUtf8OrNil(M, APathName)
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

  //Result := SSL_CTX_load_verify_locations(ctx,
  //  {$IFDEF USE_MARSHALLED_PTRS}
  //  AsUtf8OrNl(ACAFile),
  //  AsUtf8OrNil(ACAPath)
  //  {$ELSE}
  //  PAnsiChar(Pointer(UTF8String(ACAFile))),
  //  PAnsiChar(Pointer(UTF8String(ACAPath)))
  //  {$ENDIF}
  //);

  Result := IndyX509_STORE_load_locations(SSL_CTX_get_cert_store(ctx), ACAFile, ACAPath);
end;

function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT;
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
  if Assigned(B) then begin
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
            LDH := PEM_read_bio_DHparams(B, nil, SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
        else begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then begin
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
{this conditional section assumes that strings are UTF8 or perhaps use a codepage
 and the calls typically resolve to direct calls to OpenSSL}

function IndySSL_load_client_CA_file(const AFileName: String) : PSTACK_OF_X509_NAME;
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

function IndySSL_CTX_use_certificate_chain_file(ctx :PSSL_CTX;
  const AFileName: String) : TIdC_INT;
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
  Result := X509_STORE_load_locations(ctx,
    PAnsiChar(Pointer(AFileName)),
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
  Result := SSL_CTX_load_verify_locations(ctx,
    PAnsiChar(Pointer(ACAFile)),
    PAnsiChar(Pointer(ACAPath)));
end;

function IndySSL_CTX_use_DHparams_file(ctx: PSSL_CTX;
  const AFileName: String; AType: Integer): TIdC_INT;
var
  B: PBIO;
  LDH: PDH;
  j: Integer;
begin
  Result := 0;
  B := BIO_new_file(PAnsiChar(AFileName), 'r');
  if Assigned(B) then begin
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
            LDH := PEM_read_bio_DHparams(B, nil, SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
        else begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then begin
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

end.

