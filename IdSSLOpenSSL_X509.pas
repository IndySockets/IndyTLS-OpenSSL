unit IdSSLOpenSSL_X509;
{$I IdCompilerDefines.inc}
{$i IdSSLOpenSSLDefines.inc}
interface
uses
  IdCTypes,
  IdGlobal,
  IdGlobalProtocols,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_x509,
  IdOpenSSLHeaders_x509v3,
  IdSSLOpenSSL_Utils,
  System.Classes;

type
  TIdSSLULong = packed record
    case Byte of
      0: (B1, B2, B3, B4: UInt8);
      1: (W1, W2: UInt16);
      2: (L1: Int32);
      3: (C1: UInt32);
  end;

  TIdSSLByteArray = record
    Length: TIdC_UINT;
    Data: PByte;
  end;

  TIdX509 = class;

  TIdX509Name = class(TObject)
  protected
    fX509Name: PX509_NAME;
    function GetStrByNID(const ANid : TIdC_INT) : String;
    function CertInOneLine: String;
    function GetHash: TIdSSLULong;
    function GetHashAsString: String;
    function GetCommonName: String;
    function GetOrginization: String;
    function GetUnit: String;
    function GetEMail : String;
    function GetCity: String;
    function GetCountry: String;
    function GetProvidence: String;
    function GetStreetAddress: String;
  public
    constructor Create(aX509Name: PX509_NAME);
    //
    property Hash: TIdSSLULong read GetHash;
    property HashAsString: string read GetHashAsString;
    property OneLine: string read CertInOneLine;
    property CommonName : String read GetCommonName;
    property Organization : String read GetOrginization;
    property _Unit : String read GetUnit;
    property EMail : String read GetEMail;
    property StreetAddress : String read GetStreetAddress;
    property City : String read GetCity;
    property Providence : String read GetProvidence;
    property Country : String read GetCountry;
    //
    property CertificateName: PX509_NAME read fX509Name;
  end;

  TIdX509Info = class(TObject)
  protected
    //Do not free this here because it belongs
    //to the X509 or something else.
    FX509 : PX509;
  public
    constructor Create( aX509: PX509); virtual;
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
{IMPORTANT!!!

FIPS approves only these algorithms for hashing.
SHA-1
SHA-224
SHA-256
SHA-384
SHA-512

http://csrc.nist.gov/CryptoToolkit/tkhash.html
}
    property SHA1 : TIdSSLEVP_MD read GetSHA1;
    property SHA1AsString : String read  GetSHA1AsString;
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
    function GetAlgorithm : String;
  public
    property Signature : String read GetSignature;
    property Algorithm : String read GetAlgorithm;
    property SigType : TIdC_INT read  GetSigType ;
    property SigTypeAsString : String read GetSigTypeAsString;
  end;
  TIdX509PublicKey = class(TIdX509Info)
  protected
    function GetModulus : String;
    function GetAlgorithm: String;
    function GetBits : TIdC_INT;
    function GetSize : TIdC_INT;
    function GetSecurityBits : TIdC_INT;
    function GetEncoding : String;
    function GetEncodingSize : TIdC_INT;
  public
    property Algorithm : String read GetAlgorithm;
    property Bits : TIdC_INT read GetBits;
    property SecurityBits : TIdC_INT read GetSecurityBits;
    property Size : TIdC_INT read GetSize;
    property Encoding : String read GetEncoding;
    property EncodingSize : TIdC_INT read GetEncodingSize;
    property Modulus : String read GetModulus;
  end;
  TIdX509Exts = class(TIdX509Info)
  protected
    //X509_get_ext
    function GetExtension(const AIndex : TIdC_INT) :  PX509_EXTENSION;
    function GetExtensionByNid(const ANid : TIdC_INT) :  PX509_EXTENSION;
    function GetCount: TIdC_INT;
  public
    property ExtensionByNid[const ANid : TIdC_INT] : PX509_EXTENSION read GetExtensionByNid;
    property Extensions[const AIndex : TIdC_INT]  : PX509_EXTENSION read  GetExtension; default;
    property Count : TIdC_INT read GetCount;
  end;
  TIdX509AuthorityKeyID = class(TIdX509Info)
  protected
    function GetIssuer(const AIndex: TIdC_INT): String;
    function GetKeyId : String;
    function GetSerial : TIdC_INT64;
    function GetIssuerCount : TIdC_INT;
  public
    property KeyID : String read GetKeyId;
    property Serial : TIdC_INT64 read GetSerial;
    property Issuer[const AIndex : TIdC_INT] : String read GetIssuer;
    property IssuerCount : TIdC_INT read GetIssuerCount;
  end;
  TIdX509Warnings = class(TIdX509Info)
  protected
    function GetIsObsoleteV1: Boolean;
    function GetIsSelfSigned: Boolean;
    function GetSubjectAndIssuerMatch: Boolean;
  public
    property IsObsoleteV1 : Boolean read GetIsObsoleteV1;
    property IsSelfSigned : Boolean read GetIsSelfSigned;
    property SubjectAndIssuerMatch : Boolean read  GetSubjectAndIssuerMatch;
  end;
  TIdX509Errors = class(TIdX509Info)
  protected
    function GetInvalidInconsistantValues: Boolean;
    function GetInvalidPolicy: Boolean;
    function GetUnhandledCriticalExtension: Boolean;
    function GetNoFingerprint: Boolean;
  public
    property NoFingerprint : Boolean read GetNoFingerprint;
    property InvalidInconsistantValues : Boolean read GetInvalidInconsistantValues;
    property InvalidPolicy : Boolean read GetInvalidPolicy;
    property UnhandledCriticalExtention : Boolean read GetUnhandledCriticalExtension;
  end;
  TIdX509AltSubjectAltNames = class(TIdX509Info)
  private
    function GetItems(const AIndex: TIdC_INT): string;
    function GetItemsCount: TIdC_INT;
  protected
    FGeneralNames : PGENERAL_NAMES;
    procedure GetGeneralNames;
  public
    constructor Create( aX509: PX509); override;
    destructor Destroy; override;
    property Items[const AIndex : TIdC_INT] : string read GetItems;
    property ItemsCount : TIdC_INT read GetItemsCount;
  end;
  TIdX509KeyUse = (DigitalSignature, NonRepudiation, KeyEncipherment,
    DataEncipherment, KeyAgreement, CertSign, CRLSign, EncipherOnly, DecipherOnly);
  TIdX509KeyUsage = set of  TIdX509KeyUse;
  TIdX509ExtKeyUse = (Server, Client, SMIME, CodeSign, OCSPSign, TimeStamp, DVCS, AnyEKU);
  TIdX509ExtKeyUsage = set of TIdX509ExtKeyUse;
  TIdX509 = class(TObject)
  protected
    FErrors : TIdX509Errors;
    FWarnings : TIdX509Warnings;
    FExtensions : TIdX509Exts;
    FFingerprints : TIdX509Fingerprints;
    FSigInfo : TIdX509SigInfo;
    FPublicKey : TIdX509PublicKey;
    FCanFreeX509 : Boolean;
    FX509    : PX509;
    FSubject : TIdX509Name;
    FIssuer  : TIdX509Name;
    FDisplayInfo : TStrings;
    FAuthorityKeyID : TIdX509AuthorityKeyID;
    FAltSubjectNames : TIdX509AltSubjectAltNames;
    function GetExtensionCount: TIdC_LONG;
    function RSubject:TIdX509Name;
    function RIssuer:TIdX509Name;
    function RnotBefore:TDateTime;
    function RnotAfter:TDateTime;
    function RFingerprint:TIdSSLEVP_MD;
    function RFingerprintAsString:String;
    function GetSerialNumber: String;

    function GetVersion : TIdC_LONG;
    function GetDisplayInfo : TStrings;
    function GetSubjectKeyIdentifier : String;
    function GetBasicConstraints: String;
    function GetExtentionName(const AIndex: TIdC_INT): string;
    function GetExtentionCritical(const AIndex: TIdC_INT): Boolean;
    function GetExtentionValues(const AIndex: TIdC_INT): string;
    function GetKeyUsage: TIdX509KeyUsage;
    function GetExtKeyUsage: TIdX509ExtKeyUsage;
    function GetProxyPathLen: TIdC_LONG;
  public
    Constructor Create(aX509: PX509; aCanFreeX509: Boolean = True); virtual;
    Destructor Destroy; override;
    //These are temporary
    property ExtensionCount : TIdC_LONG read GetExtensionCount;
    //
    property Version : TIdC_LONG read GetVersion;
    //
    property SigInfo : TIdX509SigInfo read FSigInfo;
    property Fingerprints : TIdX509Fingerprints read FFingerprints;
    //
    property Fingerprint: TIdSSLEVP_MD read RFingerprint;
    property FingerprintAsString: String read RFingerprintAsString;
    property Subject: TIdX509Name read RSubject;
    property AltSubjectNames : TIdX509AltSubjectAltNames read  FAltSubjectNames;
    property Issuer: TIdX509Name read RIssuer;
    property notBefore: TDateTime read RnotBefore;
    property notAfter: TDateTime read RnotAfter;
    property SerialNumber : string read GetSerialNumber;
    property DisplayInfo : TStrings read GetDisplayInfo;

    //
    property Certificate: PX509 read FX509;
    property PublicKey : TIdX509PublicKey read FPublicKey;
    property SubjectKeyIdentifier : String  read GetSubjectKeyIdentifier;
    property BasicConstraints : String read GetBasicConstraints;
    property ExtentionName[const AIndex : TIdC_INT] : string read GetExtentionName;
    property ExtentionCritical[const AIndex : TIdC_INT] : Boolean read GetExtentionCritical;
    property ExtensionValues[const AIndex : TIdC_INT] : string read GetExtentionValues;
    property AuthorityKeyID : TIdX509AuthorityKeyID read  FAuthorityKeyID;
    property KeyUsage : TIdX509KeyUsage read GetKeyUsage;
    property ExtendedKeyUsage : TIdX509ExtKeyUsage read GetExtKeyUsage;
    property ProxyPathLen : TIdC_LONG read GetProxyPathLen;
    property Errors : TIdX509Errors read FErrors;
    property Warnings : TIdX509Warnings read FWarnings;
  end;

implementation
uses
  IdFIPS,
  IdOpenSSLHeaders_obj_mac,
  IdOpenSSLHeaders_asn1,
  IdOpenSSLHeaders_bn,
  IdOpenSSLHeaders_objects,
  IdOpenSSLHeaders_rsa,
  IdOpenSSLHeaders_x509_vfy,
  System.SysUtils;
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

function TIdX509Name.GetCity: String;
begin
  Result := GetStrByNid(NID_localityName);
end;

function TIdX509Name.GetCommonName: String;
begin
  Result := GetStrByNid(NID_commonName);
end;

function TIdX509Name.GetCountry: String;
begin
  Result := GetStrByNid(NID_countryName);
end;

function TIdX509Name.GetEMail: String;
begin
  Result := GetStrByNid(NID_pkcs9_emailAddress);
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

function TIdX509Name.GetOrginization: String;
begin
  Result := GetStrByNid( NID_organizationName );
end;

function TIdX509Name.GetProvidence: String;
begin
  Result := GetStrByNid(NID_stateOrProvinceName);
end;

function TIdX509Name.GetStrByNID(const ANid: TIdC_INT): String;
var
  LBuffer: array[0..2048] of TIdAnsiChar;
  LPtr : PAnsiChar;
begin
  if FX509Name = nil then begin
    Result := '';    {Do not Localize}
  end else begin
    LPtr :=  @LBuffer[0];
     if X509_NAME_get_text_by_NID(FX509Name,ANid,LPtr,256) > -1 then begin
       Result := String(LPtr);
     end else begin
       Result := '';
     end;
  end;
end;

function TIdX509Name.GetStreetAddress: String;
begin
  Result := GetStrByNid(  NID_streetAddress );
end;

function TIdX509Name.GetUnit: String;
begin
  Result := GetStrByNid( NID_organizationalUnitName );
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
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
    X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_sha224) then begin
    X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA224AsString : String;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA224);
  {$ELSE}
  if Assigned(EVP_sha224) then begin
    Result := MDAsString(SHA224);
  end else begin
    Result := '';
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA256 : TIdSSLEVP_MD;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_sha256) then begin
    X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA256AsString : String;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA256);
  {$ELSE}
  if Assigned(EVP_sha256) then begin
    Result := MDAsString(SHA256);
  end else begin
    Result := '';
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA384 : TIdSSLEVP_MD;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_SHA384) then begin
    X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA384AsString : String;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA384);
  {$ELSE}
  if Assigned(EVP_SHA384) then begin
    Result := MDAsString(SHA384);
  end else begin
    Result := '';
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA512 : TIdSSLEVP_MD;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result.Length);
  {$ELSE}
  if Assigned(EVP_sha512) then begin
    X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result.Length);
  end else begin
    FillChar(Result, SizeOf(Result), 0);
  end;
  {$ENDIF}
end;

function TIdX509Fingerprints.GetSHA512AsString : String;
begin
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA512);
  {$ELSE}
  if Assigned(EVP_sha512) then begin
    Result := MDAsString(SHA512);
  end else begin
    Result := '';
  end;
  {$ENDIF}
end;

{ TIdX509SigInfo }

function TIdX509SigInfo.GetAlgorithm: String;
var
  sig_alg : PX509_ALGOR;
  signature : PASN1_BIT_STRING;
  lalgorithm : PASN1_OBJECT;
begin
  X509_get0_signature(signature,sig_alg, FX509);
  X509_ALGOR_get0(@lalgorithm, nil, nil, sig_alg);
  Result :=  ASN1_OBJECT_ToStr(lalgorithm);
end;

function TIdX509SigInfo.GetSignature: String;
var
  sig_alg : PX509_ALGOR;
  signature : PASN1_BIT_STRING;
begin
  X509_get0_signature(signature, sig_alg, FX509);
  Result := BytesToHexString( signature^.data, signature^.length);
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
  FAltSubjectNames := TIdX509AltSubjectAltNames.Create(FX509);
  FErrors := TIdX509Errors.Create(FX509);
  FFingerprints := TIdX509Fingerprints.Create(FX509);
  FSigInfo := TIdX509SigInfo.Create(FX509);
  FPublicKey := TIdX509PublicKey.Create(FX509);
  FExtensions := TIdX509Exts.Create(FX509);
  FSubject := nil;
  FIssuer := nil;
  FAuthorityKeyID := TIdX509AuthorityKeyID.Create(FX509);
  FWarnings := TIdX509Warnings.Create(FX509);
end;

destructor TIdX509.Destroy;
begin
  FreeAndNil(FWarnings);
  FreeAndNil(FAuthorityKeyID);
  FreeAndNil(FExtensions);
  FreeAndNil(FDisplayInfo);
  FreeAndNil(FSubject);
  FreeAndNil(FIssuer);
  FreeAndNil(FFingerprints);
  FreeAndNil(FSigInfo);
  FreeAndNil( FAltSubjectNames );
  { If the X.509 certificate handle was obtained from a certificate
  store or from the SSL connection as a peer certificate, then DO NOT
  free it here!  The memory is owned by the OpenSSL library and will
  crash the library if Indy tries to free its private memory here }
  if FCanFreeX509 then begin
    X509_free(FX509);
  end;
  FreeAndNil(FErrors);
  inherited Destroy;
end;

function TIdX509.GetSubjectKeyIdentifier: String;
var
    LPtr : PAnsiChar;
    LLen : TIdC_INT;
    LASN1 : PASN1_OCTET_STRING;
begin
  Result := '';
  LASN1 := X509_get0_subject_key_id(FX509);
  if Assigned(LASN1) then begin
      LPtr := PAnsiChar(ASN1_STRING_get0_data(PASN1_STRING(LASN1)));
      LLen :=  ASN1_STRING_length(PASN1_STRING(LASN1));
      Result := BytesToHexString(LPtr, LLen);
  end;
end;

function TIdX509.GetBasicConstraints: String;
var
  LFlags : TIdC_UINT32;
  LPathLen : TIdC_LONG;
begin
  Result := '';
  LFlags := X509_get_extension_flags(FX509);
  if LFlags and  EXFLAG_CA = EXFLAG_CA then begin
    Result := 'CA = True';
    LPathLen := X509_get_pathlen(FX509);
    if LPathLen > -1 then begin
      Result := Result + ' (Pathlength: '+IntToStr(LPathLen)+')';
    end;
  end;
end;

function TIdX509.GetDisplayInfo: TStrings;
begin
  if not Assigned(FDisplayInfo) then begin
    FDisplayInfo := TStringList.Create;
    DumpCert(FDisplayInfo, FX509);
  end;
  Result := FDisplayInfo;
end;

function TIdX509.GetExtensionCount: TIdC_LONG;
begin
  Result := Self.FExtensions.Count;
end;

function TIdX509.GetExtentionCritical(const AIndex: TIdC_INT): Boolean;
var LExt : PX509_EXTENSION;

begin
  Result := False;
  if AIndex > -1 then begin
     LExt := X509_get_ext(FX509, AIndex);
     Result := X509_EXTENSION_get_critical(LExt) > 0;
  end;
end;

function TIdX509.GetExtentionName(const AIndex: TIdC_INT): string;
var LExt : PX509_EXTENSION;
    LASN1 : PASN1_OBJECT;
begin
  Result := '';
  if AIndex > -1 then begin
      LExt := X509_get_ext(FX509, AIndex);
     LASN1 := X509_EXTENSION_get_object(LExt);
     Result := ASN1_OBJECT_ToStr(LASN1);
  end;
end;

function TIdX509.GetExtentionValues(const AIndex: TIdC_INT): string;
var LExt : PX509_EXTENSION;
    LASN1 : PASN1_OCTET_STRING;
    LPtr : PAnsiChar;
    LLen : TIdC_INT;
begin
  Result := '';
  if AIndex > -1 then begin
      LExt := X509_get_ext(FX509, AIndex);
      LASN1 := X509_EXTENSION_get_data(LExt);
      if Assigned(LASN1) then begin
        LPtr := PAnsiChar(ASN1_STRING_get0_data(PASN1_STRING(LASN1)));
        LLen :=  ASN1_STRING_length(PASN1_STRING(LASN1));
        Result := BytesToHexString(LPtr, LLen);
     end;
  end;
end;

function TIdX509.GetExtKeyUsage: TIdX509ExtKeyUsage;
var LFlags : TIdC_UINT32;
begin
  Result := [];
  if X509_get_extension_flags(FX509) and EXFLAG_XKUSAGE = EXFLAG_XKUSAGE then begin
    LFlags := X509_get_extended_key_usage(FX509);
    if  (LFlags and XKU_SSL_SERVER = XKU_SSL_SERVER) then begin
      Result := Result + [Server];
    end;
    if (LFlags and XKU_SSL_CLIENT = XKU_SSL_CLIENT) then begin
      Result := Result + [Client];
    end;
    if (LFlags and XKU_SMIME = XKU_SMIME) then begin
      Result := Result + [SMIME];
    end;
    if (LFlags and XKU_CODE_SIGN = XKU_CODE_SIGN) then begin
      Result := Result + [CodeSign];
    end;
    if (LFlags and XKU_OCSP_SIGN = XKU_OCSP_SIGN) then begin
      Result := Result +  [OCSPSign];
    end;
    if (LFlags and XKU_TIMESTAMP = XKU_TIMESTAMP) then begin
      Result := Result + [TimeStamp];
    end;
    if (LFlags and XKU_DVCS  = XKU_DVCS) then begin
      Result := Result + [DVCS];
    end;
    if (LFlags and XKU_ANYEKU = XKU_ANYEKU) then begin
      Result := Result + [AnyEKU];
    end;
  end;
end;

function TIdX509.GetKeyUsage: TIdX509KeyUsage;
var
  LKeyUsage : TIdC_UINT32;
begin
  Result := [];
  if X509_get_extension_flags(FX509) and EXFLAG_KUSAGE = EXFLAG_KUSAGE then begin

    LKeyUsage :=X509_get_key_usage(FX509);
    if LKeyUsage and KU_DIGITAL_SIGNATURE = KU_DIGITAL_SIGNATURE then begin
      Result :=  Result + [DigitalSignature];
    end;
    if LKeyUsage and KU_NON_REPUDIATION = KU_NON_REPUDIATION then begin
      Result := Result + [NonRepudiation];
    end;
    if  LKeyUsage and KU_KEY_ENCIPHERMENT = KU_KEY_ENCIPHERMENT then begin
      Result := Result + [DataEncipherment];
    end;
    if LKeyUsage and KU_KEY_AGREEMENT = KU_KEY_AGREEMENT then begin
      Result := Result + [KeyAgreement];
    end;
    if LKeyUsage and KU_KEY_CERT_SIGN = KU_KEY_CERT_SIGN then begin
      Result := Result + [CertSign];
    end;
    if LKeyUsage and KU_CRL_SIGN = KU_CRL_SIGN then begin
      Result := Result + [CRLSign];
    end;
    if LKeyUsage and KU_ENCIPHER_ONLY = KU_ENCIPHER_ONLY  then begin
      Result := Result + [EncipherOnly];
    end;
    if LKeyUsage and KU_DECIPHER_ONLY = KU_DECIPHER_ONLY  then begin
      Result := Result + [DecipherOnly];
    end;
  end;
end;

function TIdX509.GetProxyPathLen: TIdC_LONG;
begin
  Result := -1;
  if X509_get_extension_flags(FX509) and EXFLAG_PROXY = EXFLAG_PROXY then
  begin
    Result := X509_get_proxy_pathlen(FX509);
  end;
end;

function TIdX509.GetSerialNumber: String;
var
  LSN : PASN1_INTEGER;
  LBN : PBIGNUM;
begin
  if FX509 <> nil then begin
    LSN := X509_get_serialNumber(FX509);
    LBN := ASN1_INTEGER_to_BN(LSN, nil);
    Result := String(BN_bn2hex(LBN));
    bn_free(LBN);
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

{ TIdX509PublicKey }

function TIdX509PublicKey.GetAlgorithm: String;
var LPubKey : PX509_PUBKEY;
  LAlgorithm : PASN1_OBJECT;
begin
  LPubKey := X509_get_X509_PUBKEY(FX509);
  X509_PUBKEY_get0_param(@LAlgorithm, nil, nil, nil,LPubKey);
  Result := ASN1_OBJECT_ToStr(lalgorithm);
end;

function TIdX509PublicKey.GetEncoding: String;
var LPubKey : PX509_PUBKEY;
  LLen : TIdC_INT;
  LKey : array[0..2048] of TIdAnsiChar;
  LPtr : PByte;
begin
  LPubKey := X509_get_X509_PUBKEY(FX509);
  LPtr := @LKey[0];
  X509_PUBKEY_get0_param(nil, @LPtr, @LLen, nil,LPubKey);
  Result := BytesToHexString(LPtr,LLen);
end;

function TIdX509PublicKey.GetEncodingSize: TIdC_INT;
var LPubKey : PX509_PUBKEY;
  LKey : array[0..2048] of TIdAnsiChar;
  LPtr : PByte;
begin
  LPubKey := X509_get_X509_PUBKEY(FX509);
  LPtr := @LKey[0];
  X509_PUBKEY_get0_param(nil, @LPtr, @Result, nil,LPubKey);
end;

function TIdX509PublicKey.GetModulus: String;
var LPubKey : PX509_PUBKEY;
  LKey : PEVP_PKEY;
  LBN : PBIGNUM;
begin
  Result := '';
  LPubKey := X509_get_X509_PUBKEY(FX509);
  LKey := X509_PUBKEY_get0(LPubKey);
  if EVP_PKEY_base_id(LKey) = EVP_PKEY_RSA  then begin
    RSA_get0_key(EVP_PKEY_get0_RSA(LKey), @LBN, nil, nil);
    Result := String(BN_bn2hex(LBN));
  end;
end;

function TIdX509PublicKey.GetBits: TIdC_INT;
var LPubKey : PX509_PUBKEY;
  LKey : PEVP_PKEY;
begin
  LPubKey := X509_get_X509_PUBKEY(FX509);
  LKey := X509_PUBKEY_get0(LPubKey);
  Result := EVP_PKEY_bits(LKey);
end;

function TIdX509PublicKey.GetSecurityBits: TIdC_INT;
var LPubKey : PX509_PUBKEY;
  LKey : PEVP_PKEY;
begin
  LPubKey := X509_get_X509_PUBKEY(FX509);
  LKey := X509_PUBKEY_get0(LPubKey);
  Result := EVP_PKEY_security_bits(LKey);
end;

function TIdX509PublicKey.GetSize: TIdC_INT;
var LPubKey : PX509_PUBKEY;
  LKey : PEVP_PKEY;
begin
  LPubKey := X509_get_X509_PUBKEY(FX509);
  LKey := X509_PUBKEY_get0(LPubKey);
  Result := EVP_PKEY_size(LKey);
end;

{ TIdX509Exts }

function TIdX509Exts.GetCount: TIdC_INT;
begin
  Result := X509_get_ext_count(FX509);
end;

function TIdX509Exts.GetExtension(const AIndex: TIdC_INT): PX509_EXTENSION;
begin
  Result := X509_get_ext(FX509, AIndex);
end;

function TIdX509Exts.GetExtensionByNid(const ANid: TIdC_INT): PX509_EXTENSION;
var LIdx : TIdC_INT;
begin
  LIdx := X509_get_ext_by_NID(FX509, ANid, -1);
  if LIdx > -1 then begin
    Result := X509_get_ext(FX509, LIdx);
  end else begin
    Result := nil;
  end;
end;


{ TIdX509AuthorityKeyID }

function TIdX509AuthorityKeyID.GetIssuerCount : TIdC_INT;
var
    LGNs : PGENERAL_NAMES;
begin
  Result := 0;
  LGNs := X509_get0_authority_issuer( FX509);
  if Assigned(LGNs) then begin
    Result := sk_GENERAL_NAME_num(LGNs);
  end;
end;

function DirName(const ADirName : PX509_NAME) : String;
var i, Le_count : TIdC_INT;
  LE : PX509_NAME_ENTRY;
  LASN1 : PASN1_STRING;
  LOBJ : PASN1_OBJECT;
begin
  Result := '';
  Le_count := X509_NAME_entry_count(ADirName);

  for i := 0 to Le_count - 1 do begin
     LE := X509_NAME_get_entry(  ADirName, i);
     LOBJ := X509_NAME_ENTRY_get_object(LE);
     LASN1 := X509_NAME_ENTRY_get_data(LE);
     Result := Result + ' '+ ASN1_OBJECT_ToStr(LOBJ) + ' = ' + String(PAnsiChar(ASN1_STRING_get0_data(LASN1))) +';';
  end;
  Result := Trim(Result);
end;

function ASN1_ToIPAddress(a : PASN1_OCTET_STRING) : String;
var
  LIPv6 : TIdIPv6Address;
  i : Integer;
begin
  Result := '';
  if a.length = 4 then begin
      Result := IntToStr( a.data[0]) +  '.' + IntToStr(a.data[1]) + '.'+
        IntToStr( a.data[2])+'.'+IntToStr(a.data[3]);
  end else begin
    if a.length = 16 then begin

      for i := 0 to 7 do begin
        LIPv6[i] := (a.data[i*2] shl 8) + (a.data[(i*2)+1]);
      end;
      Result := IdGlobal.IPv6AddressToStr( LIPv6);
    end;
  end;
end;

function GeneralNameToStr(AGN : PGENERAL_NAME) : String;
begin
  Result := '';
  case AGN.type_ of
      GEN_OTHERNAME :
        Result := 'Other Name';
      GEN_EMAIL :
      begin
         Result := 'E-Mail: '+String(PAnsiChar(AGN.d.rfc822Name.data)) ;
      end;
      GEN_DNS :
      begin
         Result := 'DNS: '+String(PAnsiChar(AGN.d.dNSName.data));
      end;
      GEN_X400 :
      begin
         Result := 'X400';
      end;
      GEN_DIRNAME :
      begin
         Result := 'Dir Name: '+DirName(AGN.d.directoryName );
      end;
      GEN_EDIPARTY :
      begin
        Result := 'EDI Party';
      end;
      GEN_URI :
      begin
        Result := 'URI: '+String(PAnsiChar(AGN.d.uniformResourceIdentifier.data));
      end;
      GEN_IPADD : begin
        Result := 'IP Address: '+ ASN1_ToIPAddress(AGN.d.iPAddress);
      end;
      GEN_RID :
        Result := 'Registered ID: '+ ASN1_OBJECT_ToStr(AGN.d.rid);
  end;
end;

function TIdX509AuthorityKeyID.GetIssuer(const AIndex: TIdC_INT): String;
var
    LGNs : PGENERAL_NAMES;
    LG : PGENERAL_NAME;
begin
  Result := '';
  LGNs := X509_get0_authority_issuer( FX509);
  if Assigned(LGNs) then begin
     LG := sk_GENERAL_NAME_value( LGNs, AIndex);
     Result :=  GeneralNameToStr(LG);
  end;

end;

function TIdX509AuthorityKeyID.GetKeyId: String;
var
  LASN1 : PASN1_OCTET_STRING;
    LPtr : PAnsiChar;
    LLen : TIdC_INT;
begin
  Result := '';
  LASN1 := X509_get0_authority_key_id(FX509);
  if Assigned(LASN1) then begin
    LPtr := PAnsiChar(ASN1_STRING_get0_data(PASN1_STRING(LASN1)));
      LLen :=  ASN1_STRING_length(PASN1_STRING(LASN1));
      Result := BytesToHexString(LPtr, LLen);
  end;
end;

function TIdX509AuthorityKeyID.GetSerial: TIdC_INT64;
var
  LASN1 : PASN1_INTEGER;

begin
  Result := -1;
  LASN1 :=X509_get0_authority_serial(FX509);
  if Assigned(LASN1) then begin
    ASN1_INTEGER_get_int64(@Result,LASN1);
  end;
end;

{ TIdX509Warnings }

function TIdX509Warnings.GetIsObsoleteV1: Boolean;
begin
  Result := X509_get_extension_flags(FX509) and  EXFLAG_V1 = EXFLAG_V1;
end;

function TIdX509Warnings.GetIsSelfSigned: Boolean;
begin
  Result :=  X509_get_extension_flags(FX509) and EXFLAG_SI = EXFLAG_SI;
end;

function TIdX509Warnings.GetSubjectAndIssuerMatch: Boolean;
begin
  Result := X509_get_extension_flags(FX509) and EXFLAG_SS = EXFLAG_SS;
end;

{ TIdX509Errors }

function TIdX509Errors.GetInvalidInconsistantValues: Boolean;
begin
  Result := X509_get_extension_flags(FX509) and EXFLAG_INVALID = EXFLAG_INVALID;
end;

function TIdX509Errors.GetInvalidPolicy: Boolean;
begin
  Result := X509_get_extension_flags(FX509) and EXFLAG_INVALID_POLICY = EXFLAG_INVALID_POLICY;
end;

function TIdX509Errors.GetNoFingerprint: Boolean;
begin
  Result := X509_get_extension_flags(FX509) and EXFLAG_NO_FINGERPRINT = EXFLAG_NO_FINGERPRINT;
end;

function TIdX509Errors.GetUnhandledCriticalExtension: Boolean;
begin
  Result := X509_get_extension_flags(FX509) and  EXFLAG_CRITICAL = EXFLAG_CRITICAL;
end;

{ TIdX509AltSubjectAltNames }

constructor TIdX509AltSubjectAltNames.Create(aX509: PX509);
begin
  inherited Create(aX509);
  FGeneralNames := nil;
end;

destructor TIdX509AltSubjectAltNames.Destroy;
begin
  if Assigned(FGeneralNames) then begin
    GENERAL_NAMES_free(FGeneralNames);
  end;
  inherited;
end;

procedure TIdX509AltSubjectAltNames.GetGeneralNames;
begin
  if not Assigned(FGeneralNames) then begin
    FGeneralNames := X509_get_ext_d2i(FX509, NID_subject_alt_name, nil, nil);
  end;
end;

function TIdX509AltSubjectAltNames.GetItems(const AIndex: TIdC_INT): string;
var LGN : PGENERAL_NAME;
begin
  Result := '';
  GetGeneralNames;
  if Assigned(FGeneralNames) then begin
     LGN := sk_GENERAL_NAME_value(FGeneralNames,AIndex);
     Result := GeneralNameToStr(LGN);
  end;
end;

function TIdX509AltSubjectAltNames.GetItemsCount: TIdC_INT;
begin
  Result := -1;
  GetGeneralNames;
  if Assigned(FGeneralNames) then begin
    Result := sk_GENERAL_NAME_num(FGeneralNames);
  end;
end;

end.
