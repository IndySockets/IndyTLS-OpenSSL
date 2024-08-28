  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_x509v3.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_x509v3.h2pas
     and this file regenerated. IdOpenSSLHeaders_x509v3.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_x509v3;

interface

// Headers for OpenSSL 1.1.1
// x509v3.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_asn1,
  IdOpenSSLHeaders_asn1t,
  IdOpenSSLHeaders_x509;

const
  (* ext_flags values *)
  X509V3_EXT_DYNAMIC      = $1;
  X509V3_EXT_CTX_DEP      = $2;
  X509V3_EXT_MULTILINE    = $4;

  // v3_ext_ctx
  CTX_TEST = $1;
  X509V3_CTX_REPLACE = $2;

  // GENERAL_NAME_st
  GEN_OTHERNAME   = 0;
  GEN_EMAIL       = 1;
  GEN_DNS         = 2;
  GEN_X400        = 3;
  GEN_DIRNAME     = 4;
  GEN_EDIPARTY    = 5;
  GEN_URI         = 6;
  GEN_IPADD       = 7;
  GEN_RID         = 8;

  (* All existing reasons *)
  CRLDP_ALL_REASONS       = $807f;

  CRL_REASON_NONE                         = -1;
  CRL_REASON_UNSPECIFIED                  = 0;
  CRL_REASON_KEY_COMPROMISE               = 1;
  CRL_REASON_CA_COMPROMISE                = 2;
  CRL_REASON_AFFILIATION_CHANGED          = 3;
  CRL_REASON_SUPERSEDED                   = 4;
  CRL_REASON_CESSATION_OF_OPERATION       = 5;
  CRL_REASON_CERTIFICATE_HOLD             = 6;
  CRL_REASON_REMOVE_FROM_CRL              = 8;
  CRL_REASON_PRIVILEGE_WITHDRAWN          = 9;
  CRL_REASON_AA_COMPROMISE                = 10;

  (* Values in idp_flags field *)
  (* IDP present *)
  IDP_PRESENT     = $1;
  (* IDP values inconsistent *)
  IDP_INVALID     = $2;
  (* onlyuser true *)
  IDP_ONLYUSER    = $4;
  (* onlyCA true *)
  IDP_ONLYCA      = $8;
  (* onlyattr true *)
  IDP_ONLYATTR    = $10;
  (* indirectCRL true *)
  IDP_INDIRECT    = $20;
  (* onlysomereasons present *)
  IDP_REASONS     = $40;

  EXT_END: array[0..13] of TIdC_INT = (-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  (* X509_PURPOSE stuff *)

  EXFLAG_BCONS            = $1;
  EXFLAG_KUSAGE           = $2;
  EXFLAG_XKUSAGE          = $4;
  EXFLAG_NSCERT           = $8;

  EXFLAG_CA               = $10;
  (* Really self issued not necessarily self signed *)
  EXFLAG_SI               = $20;
  EXFLAG_V1               = $40;
  EXFLAG_INVALID          = $80;
  (* EXFLAG_SET is set to indicate that some values have been precomputed *)
  EXFLAG_SET              = $100;
  EXFLAG_CRITICAL         = $200;
  EXFLAG_PROXY            = $400;

  EXFLAG_INVALID_POLICY   = $800;
  EXFLAG_FRESHEST         = $1000;
  (* Self signed *)
  EXFLAG_SS               = $2000;

  KU_DIGITAL_SIGNATURE    = $0080;
  KU_NON_REPUDIATION      = $0040;
  KU_KEY_ENCIPHERMENT     = $0020;
  KU_DATA_ENCIPHERMENT    = $0010;
  KU_KEY_AGREEMENT        = $0008;
  KU_KEY_CERT_SIGN        = $0004;
  KU_CRL_SIGN             = $0002;
  KU_ENCIPHER_ONLY        = $0001;
  KU_DECIPHER_ONLY        = $8000;

  NS_SSL_CLIENT           = $80;
  NS_SSL_SERVER           = $40;
  NS_SMIME                = $20;
  NS_OBJSIGN              = $10;
  NS_SSL_CA               = $04;
  NS_SMIME_CA             = $02;
  NS_OBJSIGN_CA           = $01;
  NS_ANY_CA               = NS_SSL_CA or NS_SMIME_CA or NS_OBJSIGN_CA;

  XKU_SSL_SERVER          = $1;
  XKU_SSL_CLIENT          = $2;
  XKU_SMIME               = $4;
  XKU_CODE_SIGN           = $8;
  XKU_SGC                 = $10;
  XKU_OCSP_SIGN           = $20;
  XKU_TIMESTAMP           = $40;
  XKU_DVCS                = $80;
  XKU_ANYEKU              = $100;

  X509_PURPOSE_DYNAMIC    = $1;
  X509_PURPOSE_DYNAMIC_NAME       = $2;

  X509_PURPOSE_SSL_CLIENT         = 1;
  X509_PURPOSE_SSL_SERVER         = 2;
  X509_PURPOSE_NS_SSL_SERVER      = 3;
  X509_PURPOSE_SMIME_SIGN         = 4;
  X509_PURPOSE_SMIME_ENCRYPT      = 5;
  X509_PURPOSE_CRL_SIGN           = 6;
  X509_PURPOSE_ANY                = 7;
  X509_PURPOSE_OCSP_HELPER        = 8;
  X509_PURPOSE_TIMESTAMP_SIGN     = 9;

  X509_PURPOSE_MIN                = 1;
  X509_PURPOSE_MAX                = 9;

  (* Flags for X509V3_EXT_print() *)

  X509V3_EXT_UNKNOWN_MASK         = TIdC_LONG($f) shl 16;
  (* Return error for unknown extensions *)
  X509V3_EXT_DEFAULT              = 0;
  (* Print error for unknown extensions *)
  X509V3_EXT_ERROR_UNKNOWN        = TIdC_LONG(1) shl 16;
  (* ASN1 parse unknown extensions *)
  X509V3_EXT_PARSE_UNKNOWN        = TIdC_LONG(2) shl 16;
  (* BIO_dump unknown extensions *)
  X509V3_EXT_DUMP_UNKNOWN         = TIdC_LONG(3) shl 16;

  (* Flags for X509V3_add1_i2d *)

  X509V3_ADD_OP_MASK              = TIdC_LONG($f);
  X509V3_ADD_DEFAULT              = TIdC_LONG(0);
  X509V3_ADD_APPEND               = TIdC_LONG(1);
  X509V3_ADD_REPLACE              = TIdC_LONG(2);
  X509V3_ADD_REPLACE_EXISTING     = TIdC_LONG(3);
  X509V3_ADD_KEEP_EXISTING        = TIdC_LONG(4);
  X509V3_ADD_DELETE               = TIdC_LONG(5);
  X509V3_ADD_SILENT               = $10;

  (* Flags for X509_check_* functions *)

  (*
   * Always check subject name for host match even if subject alt names present
   *)
  X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    = $1;
  (* Disable wildcard matching for dnsName fields and common name. *)
  X509_CHECK_FLAG_NO_WILDCARDS    = $2;
  (* Wildcards must not match a partial label. *)
  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = $4;
  (* Allow (non-partial) wildcards to match multiple labels. *)
  X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = $8;
  (* Constraint verifier subdomain patterns to match a single labels. *)
  X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = $10;
  (* Never check the subject CN *)
  X509_CHECK_FLAG_NEVER_CHECK_SUBJECT    = $20;
  (*
   * Match reference identifiers starting with "." to any sub-domain.
   * This is a non-public flag, turned on implicitly when the subject
   * reference identity is a DNS name.
   *)
  _X509_CHECK_FLAG_DOT_SUBDOMAINS = $8000;

  ASIdOrRange_id          = 0;
  ASIdOrRange_range       = 1;

  ASIdentifierChoice_inherit              = 0;
  ASIdentifierChoice_asIdsOrRanges        = 1;

  IPAddressOrRange_addressPrefix  = 0;
  IPAddressOrRange_addressRange   = 1;

  IPAddressChoice_inherit                 = 0;
  IPAddressChoice_addressesOrRanges       = 1;

  (*
   * API tag for elements of the ASIdentifer SEQUENCE.
   *)
  V3_ASID_ASNUM   = 0;
  V3_ASID_RDI     = 1;

  (*
   * AFI values, assigned by IANA.  It'd be nice to make the AFI
   * handling code totally generic, but there are too many little things
   * that would need to be defined for other address families for it to
   * be worth the trouble.
   *)
  IANA_AFI_IPV4   = 1;
  IANA_AFI_IPV6   = 2;

type
  (* Forward reference *)
  //Pv3_ext_method = ^v3_ext_method;
  //Pv3_ext_ctx = ^v3_ext_ctx;

  (* Useful typedefs *)

  //X509V3_EXT_NEW = function: Pointer; cdecl;
  //X509V3_EXT_FREE = procedure(v1: Pointer); cdecl;
  //X509V3_EXT_D2I = function(v1: Pointer; v2: PPByte; v3: TIdC_Long): Pointer; cdecl;
  //X509V3_EXT_I2D = function(v1: Pointer; v2: PPByte): TIdC_INT; cdecl;
//  typedef STACK_OF(CONF_VALUE) *
//      (*X509V3_EXT_I2V) (const struct v3_ext_method *method, void *ext,
//                         STACK_OF(CONF_VALUE) *extlist);
//  typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
//                                  struct v3_ext_ctx *ctx,
//                                  STACK_OF(CONF_VALUE) *values);
  //X509V3_EXT_I2S = function(method: Pv3_ext_method; ext: Pointer): PIdAnsiChar; cdecl;
  //X509V3_EXT_S2I = function(method: Pv3_ext_method; ctx: Pv3_ext_ctx; const str: PIdAnsiChar): Pointer; cdecl;
  //X509V3_EXT_I2R = function(const method: Pv3_ext_method; ext: Pointer; out_: PBIO; indent: TIdC_INT): TIdC_INT; cdecl;
  //X509V3_EXT_R2I = function(const method: Pv3_ext_method; ctx: Pv3_ext_ctx; const str: PIdAnsiChar): Pointer; cdecl;

//  (* V3 extension structure *)
//  v3_ext_method = record
//    ext_nid: TIdC_INT;
//    ext_flags: TIdC_INT;
//(* If this is set the following four fields are ignored *)
//    it: PASN1_ITEM_EXP;
//(* Old style ASN1 calls *)
//    ext_new: X509V3_EXT_NEW;
//    ext_free: X509V3_EXT_FREE;
//    d2i: X509V3_EXT_D2I;
//    i2d: X509V3_EXT_I2D;
//(* The following pair is used for string extensions *)
//    i2s: X509V3_EXT_I2S;
//    s2i: X509V3_EXT_S2I;
//(* The following pair is used for multi-valued extensions *)
//    i2v: X509V3_EXT_I2V;
//    v2i: X509V3_EXT_V2I;
//(* The following are used for raw extensions *)
//    i2r: X509V3_EXT_I2R;
//    r2i: X509V3_EXT_R2I;
//    usr_data: Pointer;             (* Any extension specific data *)
//  end;
//  X509V3_EXT_METHOD = v3_ext_method;
//  PX509V3_EXT_METHOD = ^X509V3_EXT_METHOD;
//  DEFINE_STACK_OF(X509V3_EXT_METHOD)

//  typedef struct X509V3_CONF_METHOD_st {
//      PIdAnsiChar *(*get_string) (void *db, const section: PIdAnsiChar, const value: PIdAnsiChar);
//      STACK_OF(CONF_VALUE) *(*get_section) (void *db, const section: PIdAnsiChar);
//      void (*free_string) (void *db, PIdAnsiChar *string);
//      void (*free_section) (void *db, STACK_OF(CONF_VALUE) *section);
//  } X509V3_CONF_METHOD;

// Moved to ossl_typ
//  (* Context specific info *)
//  v3_ext_ctx = record
//    flags: TIdC_INT;
//    issuer_cert: PX509;
//    subject_cert: PX509;
//    subject_req: PX509_REQ;
//    crl: PX509_CRL;
//    db_meth: PX509V3_CONF_METHOD;
//    db: Pointer;
//  (* Maybe more here *)
//  end;

  ENUMERATED_NAMES = BIT_STRING_BITNAME;

  BASIC_CONSTRAINTS_st = record
    ca: TIdC_INT;
    pathlen: PASN1_INTEGER;
  end;
  BASIC_CONSTRAINTS = BASIC_CONSTRAINTS_st;
  PBASIC_CONSTRAINTS = ^BASIC_CONSTRAINTS;

  PKEY_USAGE_PERIOD_st = record
    notBefore: PASN1_GENERALIZEDTIME;
    notAfter: PASN1_GENERALIZEDTIME;
  end;
  PKEY_USAGE_PERIOD = PKEY_USAGE_PERIOD_st;
  PPKEY_USAGE_PERIOD = ^PKEY_USAGE_PERIOD;

  otherName_st = record
    type_id: PASN1_OBJECT;
    value: PASN1_TYPE;
  end;
  OTHERNAME = otherName_st;
  POTHERNAME = ^OTHERNAME;

  EDIPartyName_st  = record
    nameAssigner: PASN1_STRING;
    partyName: PASN1_STRING;
  end;
  EDIPARTYNAME = EDIPartyName_st;
  PEDIPARTYNAME = ^EDIPARTYNAME;

  GENERAL_NAME_st_union = record
    case TIdC_INT of
      0: (ptr: PIdAnsiChar);
      1: (otherName: POTHERNAME);   (* otherName *)
      2: (rfc822Name: PASN1_IA5STRING);
      3: (dNSName: PASN1_IA5STRING);
      4: (x400Address: PASN1_TYPE);
      5: (directoryName: PX509_NAME);
      6: (ediPartyName: PEDIPARTYNAME);
      7: (uniformResourceIdentifier: PASN1_IA5STRING);
      8: (iPAddress: PASN1_OCTET_STRING);
      9: (registeredID: PASN1_OBJECT);
      (* Old names *)
      10: (ip: PASN1_OCTET_STRING);  (* iPAddress *)
      11: (dirn: PX509_NAME);        (* dirn *)
      12: (ia5: PASN1_IA5STRING);    (* rfc822Name, dNSName,
                                      * uniformResourceIdentifier *)
      13: (rid: PASN1_OBJECT);       (* registeredID *)
      14: (other: PASN1_TYPE);       (* x400Address *)
  end;
  GENERAL_NAME_st = record
    type_: TIdC_INT;
    d: GENERAL_NAME_st_union;
  end;
  GENERAL_NAME = GENERAL_NAME_st;
  PGENERAL_NAME = ^GENERAL_NAME;

  ACCESS_DESCRIPTION_st = record
    method: PASN1_OBJECT;
    location: PGENERAL_NAME;
  end;
  ACCESS_DESCRIPTION = ACCESS_DESCRIPTION_st;
  PACCESS_DESCRIPTION = ^ACCESS_DESCRIPTION;

//  typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;

//  typedef STACK_OF(ASN1_OBJECT) EXTENDED_KEY_USAGE;

//  typedef STACK_OF(ASN1_INTEGER) TLS_FEATURE;

//  DEFINE_STACK_OF(GENERAL_NAME)
//  typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;
//  DEFINE_STACK_OF(GENERAL_NAMES)

//  DEFINE_STACK_OF(ACCESS_DESCRIPTION)
//  DIST_POINT_NAME_st_union = record
//    case TIdC_INT of
//      0: (GENERAL_NAMES *fullname);
//      1: (STACK_OF(X509_NAME_ENTRY) *relativename);
//  end;
  DIST_POINT_NAME_st = record
    type_: TIdC_INT;
    (* If relativename then this contains the full distribution point name *)
    dpname: PX509_NAME;
  end;
  DIST_POINT_NAME = DIST_POINT_NAME_st;
  PDIST_POINT_NAME = ^DIST_POINT_NAME;


//  struct DIST_POINT_ST {
//      DIST_POINT_NAME *distpoint;
//      ASN1_BIT_STRING *reasons;
//      GENERAL_NAMES *CRLissuer;
//      TIdC_INT dp_reasons;
//  };

//  typedef STACK_OF(DIST_POINT) CRL_DIST_POINTS;

//  DEFINE_STACK_OF(DIST_POINT)

//  AUTHORITY_KEYID_st = record
//    keyid: PASN1_OCTET_STRING;
//    issuer: PGENERAL_NAMES;
//    serial: PASN1_INTEGER;
//  end;

  (* Strong extranet structures *)

  SXNET_ID_st = record
    zone: PASN1_INTEGER;
    user: PASN1_OCTET_STRING;
  end;
  SXNETID = SXNET_ID_st;
  PSXNETID = ^SXNETID;
//  DEFINE_STACK_OF(SXNETID)

//  SXNET_st = record
//    ASN1_INTEGER *version;
//    STACK_OF(SXNETID) *ids;
//  end;
//  SXNET = SXNET_st;
//  PSXNET = ^SXNET;

//  NOTICEREF_st = record
//    ASN1_STRING *organization;
//    STACK_OF(ASN1_INTEGER) *noticenos;
//  end;
//  NOTICEREF = NOTICEREF_st;
//  PNOTICEREF = ^NOTICEREF;

//  USERNOTICE_st = record
//    noticeref: PNOTICEREF;
//    exptext: PASN1_STRING;
//  end;
//  USERNOTICE = USERNOTICE_st;
//  PUSERNOTICE = ^USERNOTICE;

//  POLICYQUALINFO_st_union = record
//    case TIdC_INT of
//      0: (cpsuri: PASN1_IA5STRING);
//      1: (usernotice: PUSERNOTICE);
//      2: (other: PASN1_TYPE);
//  end;
//  POLICYQUALINFO_st = record
//    pqualid: PASN1_OBJECT;
//    d: POLICYQUALINFO_st_union;
//  end;
//  POLICYQUALINFO = POLICYQUALINFO_st;
//  PPOLICYQUALINFO = ^POLICYQUALINFO;
//  DEFINE_STACK_OF(POLICYQUALINFO)

//  POLICYINFO_st = record
//    ASN1_OBJECT *policyid;
//    STACK_OF(POLICYQUALINFO) *qualifiers;
//  end;
//  POLICYINFO = POLICYINFO_st;
//  PPOLICYINFO = ^POLICYINFO;
//  typedef STACK_OF(POLICYINFO) CERTIFICATEPOLICIES;
//  DEFINE_STACK_OF(POLICYINFO)

  POLICY_MAPPING_st = record
    issuerDomainPolicy: PASN1_OBJECT;
    subjectDomainPolicy: PASN1_OBJECT;
  end;
  POLICY_MAPPING = POLICY_MAPPING_st;
  PPOLICY_MAPPING = ^POLICY_MAPPING;
//  DEFINE_STACK_OF(POLICY_MAPPING)
//  typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;

  GENERAL_SUBTREE_st = record
    base: PGENERAL_NAME;
    minimum: PASN1_INTEGER;
    maximum: PASN1_INTEGER;
  end;
  GENERAL_SUBTREE = GENERAL_SUBTREE_st;
  PGENERAL_SUBTREE = ^GENERAL_SUBTREE;
//  DEFINE_STACK_OF(GENERAL_SUBTREE)

//  NAME_CONSTRAINTS_st = record
//    STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
//    STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
//  end;

  POLICY_CONSTRAINTS_st = record
    requireExplicitPolicy: PASN1_INTEGER;
    inhibitPolicyMapping: PASN1_INTEGER;
  end;
  POLICY_CONSTRAINTS = POLICY_CONSTRAINTS_st;
  PPOLICY_CONSTRAINTS = ^POLICY_CONSTRAINTS;

  (* Proxy certificate structures, see RFC 3820 *)
  PROXY_POLICY_st = record
    policyLanguage: PASN1_OBJECT;
    policy: PASN1_OCTET_STRING;
  end;
  PROXY_POLICY = PROXY_POLICY_st;
  PPROXY_POLICY = ^PROXY_POLICY;
//  DECLARE_ASN1_FUNCTIONS(PROXY_POLICY)

  PROXY_CERT_INFO_EXTENSION_st = record
    pcPathLengthConstraint: PASN1_INTEGER;
    proxyPolicy: PPROXY_POLICY;
  end;
  PROXY_CERT_INFO_EXTENSION = PROXY_CERT_INFO_EXTENSION_st;
  PPROXY_CERT_INFO_EXTENSION = ^PROXY_CERT_INFO_EXTENSION;
//  DECLARE_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)

//  ISSUING_DIST_POint_st = record
//    distpoint: PDIST_POINT_NAME;
//    TIdC_INT onlyuser;
//    TIdC_INT onlyCA;
//    onlysomereasons: PASN1_BIT_STRING;
//    TIdC_INT indirectCRL;
//    TIdC_INT onlyattr;
//  end;

//  # define X509V3_conf_err(val) ERR_add_error_data(6, \
//                          "section:", (val)->section, \
//                          ",name:", (val)->name, ",value:", (val)->value)
//
//  # define X509V3_set_ctx_test(ctx) \
//                          X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, CTX_TEST)
//  # define X509V3_set_ctx_nodb(ctx) (ctx)->db = NULL;
//
//  # define EXT_BITSTRING(nid, table) { nid, 0, ASN1_ITEM_ref(ASN1_BIT_STRING), \
//                          0,0,0,0, \
//                          0,0, \
//                          (X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
//                          (X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
//                          NULL, NULL, \
//                          table}
//
//  # define EXT_IA5STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_IA5STRING), \
//                          0,0,0,0, \
//                          (X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
//                          (X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
//                          0,0,0,0, \
//                          NULL}

  PX509_PURPOSE = ^X509_PURPOSE;
  x509_purpose_st = record
    purpose: TIdC_INT;
    trust: TIdC_INT;                  (* Default trust ID *)
    flags: TIdC_INT;
    check_purpose: function(const v1: PX509_PURPOSE; const v2: PX509; v3: TIdC_INT): TIdC_INT; cdecl;
    name: PIdAnsiChar;
    sname: PIdAnsiChar;
    usr_data: Pointer;
  end;
  X509_PURPOSE = x509_purpose_st;
//  DEFINE_STACK_OF(X509_PURPOSE)

//  DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS_st)

//  DECLARE_ASN1_FUNCTIONS(SXNET)
//  DECLARE_ASN1_FUNCTIONS(SXNETID)

  ASRange_st = record
    min, max: PASN1_INTEGER;
  end;
  ASRange = ASRange_st;
  PASRange = ^ASRange;

  ASIdOrRange_st = record
    type_: TIdC_INT;
    case u: TIdC_INT of
      0: (id: PASN1_INTEGER);
      1: (range: PASRange);
  end;
  ASIdOrRange = ASIdOrRange_st;
  PASIdOrRange = ^ASIdOrRange;
//  typedef STACK_OF(ASIdOrRange) ASIdOrRanges;
//  DEFINE_STACK_OF(ASIdOrRange)

//  ASIdentifierChoice_st = record
//    type_: TIdC_INT;
//    case u: TIdC_INT of
//      0: (inherit: PASN1_NULL);
//      1: (asIdsOrRanges: PASIdOrRanges);
//  end;
//  ASIdentifierChoice = ASIdentifierChoice_st;
//  PASIdentifierChoice = ^ASIdentifierChoice;

//  ASIdentifiers_st = record
//    asnum, rdi: PASIdentifierChoice;
//  end;
//  ASIdentifiers = ASIdentifiers_st;
//  PASIdentifiers = ^ASIdentifiers;

//  DECLARE_ASN1_FUNCTIONS(ASRange)
//  DECLARE_ASN1_FUNCTIONS(ASIdOrRange)
//  DECLARE_ASN1_FUNCTIONS(ASIdentifierChoice)
//  DECLARE_ASN1_FUNCTIONS(ASIdentifiers)

  IPAddressRange_st = record
    min, max: PASN1_BIT_STRING;
  end;
  IPAddressRange = IPAddressRange_st;
  PIPAddressRange = ^IPAddressRange;

  IPAddressOrRange_st = record
    type_: TIdC_INT;
    case u: TIdC_INT of
      0: (addressPrefix: PASN1_BIT_STRING);
      1: (addressRange: PIPAddressRange);
  end;
  IPAddressOrRange = IPAddressOrRange_st;
  PIPAddressOrRange = ^IPAddressOrRange;

//  typedef STACK_OF(IPAddressOrRange) IPAddressOrRanges;
//  DEFINE_STACK_OF(IPAddressOrRange)

//  IPAddressChoice_st = record
//    type_: TIdC_INT;
//    case u: TIdC_INT of
//      0: (inherit: PASN1_NULL);
//      1: (addressesOrRanges: PIPAddressOrRanges);
//  end;
//  IPAddressChoice = IPAddressChoice_st;
//  PIPAddressChoice = ^IPAddressChoice;

//  IPAddressFamily_st = record
//    addressFamily: PASN1_OCTET_STRING;
//    ipAddressChoice: PIPAddressChoice;
//  end;
//  IPAddressFamily = IPAddressFamily_st;
//  PIPAddressFamily = ^IPAddressFamily;

//  typedef STACK_OF(IPAddressFamily) IPAddrBlocks;
//  DEFINE_STACK_OF(IPAddressFamily)

//  DECLARE_ASN1_FUNCTIONS(IPAddressRange)
//  DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)
//  DECLARE_ASN1_FUNCTIONS(IPAddressChoice)
//  DECLARE_ASN1_FUNCTIONS(IPAddressFamily)

  NamingAuthority_st = type Pointer;
  NAMING_AUTHORITY = NamingAuthority_st;
  PNAMING_AUTHORITY = ^NAMING_AUTHORITY;

  ProfessionInfo_st = type Pointer;
  PROFESSION_INFO = ProfessionInfo_st;
  PPROFESSION_INFO = ^PROFESSION_INFO;

  Admissions_st = type Pointer;
  ADMISSIONS = Admissions_st;
  PADMISSIONS = ^ADMISSIONS;

  AdmissionSyntax_st = type Pointer;
  ADMISSION_SYNTAX = AdmissionSyntax_st;
  PADMISSION_SYNTAX = ^ADMISSION_SYNTAX;
//  DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)
//  DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)
//  DECLARE_ASN1_FUNCTIONS(ADMISSIONS)
//  DECLARE_ASN1_FUNCTIONS(ADMISSION_SYNTAX)
//  DEFINE_STACK_OF(ADMISSIONS)
//  DEFINE_STACK_OF(PROFESSION_INFO)
//  typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;

//  function SXNET_add_id_asc(psx: PPSXNET; const zone: PIdAnsiChar; const user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT;
//  function SXNET_add_id_ulong(psx: PPSXNET; lzone: TIdC_ULONG; const user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT;
//  function SXNET_add_id_INTEGER(psx: PPSXNET; izone: PASN1_INTEGER; const user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT;

//  function SXNET_get_id_asc(sx: PSXNET; const zone: PIdAnsiChar): PASN1_OCTET_STRING;
//  function SXNET_get_id_ulong(sx: PSXNET; lzone: TIdC_ULONG): PASN1_OCTET_STRING;
//  function SXNET_get_id_INTEGER(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_KEYID)

//  DECLARE_ASN1_FUNCTIONS(PKEY_USAGE_PERIOD)

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAME)
//  GENERAL_NAME *GENERAL_NAME_dup(a: PGENERAL_NAME);
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM GENERAL_NAME_cmp}
  {$EXTERNALSYM GENERAL_NAME_print}
  {$EXTERNALSYM OTHERNAME_cmp}
  {$EXTERNALSYM GENERAL_NAME_set0_value}
  {$EXTERNALSYM GENERAL_NAME_get0_value}
  {$EXTERNALSYM GENERAL_NAME_set0_othername}
  {$EXTERNALSYM GENERAL_NAME_get0_otherName}
  {$EXTERNALSYM i2a_ACCESS_DESCRIPTION}
  {$EXTERNALSYM DIST_POINT_set_dpname}
  {$EXTERNALSYM NAME_CONSTRAINTS_check}
  {$EXTERNALSYM NAME_CONSTRAINTS_check_CN}
  {$EXTERNALSYM X509V3_EXT_nconf_nid}
  {$EXTERNALSYM X509V3_EXT_nconf}
  {$EXTERNALSYM X509V3_EXT_add_nconf}
  {$EXTERNALSYM X509V3_EXT_REQ_add_nconf}
  {$EXTERNALSYM X509V3_EXT_CRL_add_nconf}
  {$EXTERNALSYM X509V3_EXT_conf_nid}
  {$EXTERNALSYM X509V3_EXT_conf}
  {$EXTERNALSYM X509V3_EXT_add_conf}
  {$EXTERNALSYM X509V3_EXT_REQ_add_conf}
  {$EXTERNALSYM X509V3_EXT_CRL_add_conf}
  {$EXTERNALSYM X509V3_set_nconf}
  {$EXTERNALSYM X509V3_get_string}
  {$EXTERNALSYM X509V3_string_free}
  {$EXTERNALSYM X509V3_set_ctx}
  {$EXTERNALSYM X509V3_EXT_add_alias}
  {$EXTERNALSYM X509V3_EXT_cleanup}
  {$EXTERNALSYM X509V3_add_standard_extensions}
  {$EXTERNALSYM X509V3_EXT_d2i}
  {$EXTERNALSYM X509V3_EXT_i2d}
  {$EXTERNALSYM X509V3_EXT_print}
  {$EXTERNALSYM X509_check_ca}
  {$EXTERNALSYM X509_check_purpose}
  {$EXTERNALSYM X509_supported_extension}
  {$EXTERNALSYM X509_PURPOSE_set}
  {$EXTERNALSYM X509_check_issued}
  {$EXTERNALSYM X509_check_akid}
  {$EXTERNALSYM X509_set_proxy_flag}
  {$EXTERNALSYM X509_set_proxy_pathlen}
  {$EXTERNALSYM X509_get_proxy_pathlen}
  {$EXTERNALSYM X509_get_extension_flags}
  {$EXTERNALSYM X509_get_key_usage}
  {$EXTERNALSYM X509_get_extended_key_usage}
  {$EXTERNALSYM X509_get0_subject_key_id}
  {$EXTERNALSYM X509_get0_authority_key_id}
  {$EXTERNALSYM X509_get0_authority_serial}
  {$EXTERNALSYM X509_PURPOSE_get_count}
  {$EXTERNALSYM X509_PURPOSE_get0}
  {$EXTERNALSYM X509_PURPOSE_get_by_sname}
  {$EXTERNALSYM X509_PURPOSE_get_by_id}
  {$EXTERNALSYM X509_PURPOSE_get0_name}
  {$EXTERNALSYM X509_PURPOSE_get0_sname}
  {$EXTERNALSYM X509_PURPOSE_get_trust}
  {$EXTERNALSYM X509_PURPOSE_cleanup}
  {$EXTERNALSYM X509_PURPOSE_get_id}
  {$EXTERNALSYM X509_check_host}
  {$EXTERNALSYM X509_check_email}
  {$EXTERNALSYM X509_check_ip}
  {$EXTERNALSYM X509_check_ip_asc}
  {$EXTERNALSYM a2i_IPADDRESS}
  {$EXTERNALSYM a2i_IPADDRESS_NC}
  {$EXTERNALSYM X509_POLICY_NODE_print}
  {$EXTERNALSYM X509v3_addr_get_range}
  {$EXTERNALSYM X509v3_asid_validate_path}
  {$EXTERNALSYM X509v3_addr_validate_path}
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityId}
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityURL}
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityText}
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityId}
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityURL}
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityText}
  {$EXTERNALSYM ADMISSION_SYNTAX_get0_admissionAuthority}
  {$EXTERNALSYM ADMISSION_SYNTAX_set0_admissionAuthority}
  {$EXTERNALSYM ADMISSIONS_get0_admissionAuthority}
  {$EXTERNALSYM ADMISSIONS_set0_admissionAuthority}
  {$EXTERNALSYM ADMISSIONS_get0_namingAuthority}
  {$EXTERNALSYM ADMISSIONS_set0_namingAuthority}
  {$EXTERNALSYM PROFESSION_INFO_get0_addProfessionInfo}
  {$EXTERNALSYM PROFESSION_INFO_set0_addProfessionInfo}
  {$EXTERNALSYM PROFESSION_INFO_get0_namingAuthority}
  {$EXTERNALSYM PROFESSION_INFO_set0_namingAuthority}
  {$EXTERNALSYM PROFESSION_INFO_get0_registrationNumber}
  {$EXTERNALSYM PROFESSION_INFO_set0_registrationNumber}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  GENERAL_NAME_cmp: function (a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl = nil;

//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
  GENERAL_NAME_print: function (out_: PBIO; gen: PGENERAL_NAME): TIdC_INT; cdecl = nil;

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
  OTHERNAME_cmp: function (a: POTHERNAME; b: POTHERNAME): TIdC_INT; cdecl = nil;
  GENERAL_NAME_set0_value: procedure (a: PGENERAL_NAME; type_: TIdC_INT; value: Pointer); cdecl = nil;
  GENERAL_NAME_get0_value: function (const a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; cdecl = nil;
  GENERAL_NAME_set0_othername: function (gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; cdecl = nil;
  GENERAL_NAME_get0_otherName: function (const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; cdecl = nil;

  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
  i2a_ACCESS_DESCRIPTION: function (bp: PBIO; const a: PACCESS_DESCRIPTION): TIdC_INT; cdecl = nil;

//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

  DIST_POINT_set_dpname: function (dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; cdecl = nil;

  NAME_CONSTRAINTS_check: function (x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl = nil;
  NAME_CONSTRAINTS_check_CN: function (x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl = nil;

//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(val: PCONF_VALUE);

  X509V3_EXT_nconf_nid: function (conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  X509V3_EXT_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
  X509V3_EXT_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl = nil;
  X509V3_EXT_REQ_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl = nil;
  X509V3_EXT_CRL_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl = nil;

  X509V3_EXT_conf_nid: function (conf: Pointer; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
  X509V3_EXT_conf: function (conf: Pointer; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
  X509V3_EXT_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
  X509V3_EXT_REQ_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
  X509V3_EXT_CRL_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
  X509V3_set_nconf: procedure (ctx: PX509V3_CTX; conf: PCONF); cdecl = nil;
//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

  X509V3_get_string: function (ctx: PX509V3_CTX; const name: PIdAnsiChar; const section: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
  X509V3_string_free: procedure (ctx: PX509V3_CTX; str: PIdAnsiChar); cdecl = nil;
//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
  X509V3_set_ctx: procedure (ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); cdecl = nil;

//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
  X509V3_EXT_add_alias: function (nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; cdecl = nil;
  X509V3_EXT_cleanup: procedure ; cdecl = nil;

  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
  X509V3_add_standard_extensions: function : TIdC_INT; cdecl = nil;
//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
  X509V3_EXT_d2i: function (ext: PX509_EXTENSION): Pointer; cdecl = nil;
//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

  X509V3_EXT_i2d: function (ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl = nil;
//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
  X509V3_EXT_print: function (out_: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

  X509_check_ca: function (x: PX509): TIdC_INT; cdecl = nil;
  X509_check_purpose: function (x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_supported_extension: function (ex: PX509_EXTENSION): TIdC_INT; cdecl = nil;
  X509_PURPOSE_set: function (p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_check_issued: function (issuer: PX509; subject: PX509): TIdC_INT; cdecl = nil;
  X509_check_akid: function (issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; cdecl = nil;
  X509_set_proxy_flag: procedure (x: PX509); cdecl = nil;
  X509_set_proxy_pathlen: procedure (x: PX509; l: TIdC_LONG); cdecl = nil;
  X509_get_proxy_pathlen: function (x: PX509): TIdC_LONG; cdecl = nil;

  X509_get_extension_flags: function (x: PX509): TIdC_UINT32; cdecl = nil;
  X509_get_key_usage: function (x: PX509): TIdC_UINT32; cdecl = nil;
  X509_get_extended_key_usage: function (x: PX509): TIdC_UINT32; cdecl = nil;
  X509_get0_subject_key_id: function (x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  X509_get0_authority_key_id: function (x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  //function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES;
  X509_get0_authority_serial: function (x: PX509): PASN1_INTEGER; cdecl = nil;

  X509_PURPOSE_get_count: function : TIdC_INT; cdecl = nil;
  X509_PURPOSE_get0: function (idx: TIdC_INT): PX509_PURPOSE; cdecl = nil;
  X509_PURPOSE_get_by_sname: function (const sname: PIdAnsiChar): TIdC_INT; cdecl = nil;
  X509_PURPOSE_get_by_id: function (id: TIdC_INT): TIdC_INT; cdecl = nil;
//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
  X509_PURPOSE_get0_name: function (const xp: PX509_PURPOSE): PIdAnsiChar; cdecl = nil;
  X509_PURPOSE_get0_sname: function (const xp: PX509_PURPOSE): PIdAnsiChar; cdecl = nil;
  X509_PURPOSE_get_trust: function (const xp: PX509_PURPOSE): TIdC_INT; cdecl = nil;
  X509_PURPOSE_cleanup: procedure ; cdecl = nil;
  X509_PURPOSE_get_id: function (const v1: PX509_PURPOSE): TIdC_INT; cdecl = nil;

//  STACK_OF(OPENSSL_STRING) *X509_get1_email(x: PX509);
//  STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x);
//  void X509_email_free(STACK_OF(OPENSSL_STRING) *sk);
//  STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(x: PX509);

  X509_check_host: function (x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  X509_check_email: function (x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  X509_check_ip: function (x: PX509; const chk: PByte; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  X509_check_ip_asc: function (x: PX509; const ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; cdecl = nil;

  a2i_IPADDRESS: function (const ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  a2i_IPADDRESS_NC: function (const ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

  X509_POLICY_NODE_print: procedure (out_: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); cdecl = nil;
//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
  X509v3_addr_get_range: function (aor: PIPAddressOrRange; const afi: TIdC_UINT; min: PByte; max: Byte; const length: TIdC_INT): TIdC_INT; cdecl = nil;

  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
  X509v3_asid_validate_path: function (v1: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  X509v3_addr_validate_path: function (v1: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
  NAMING_AUTHORITY_get0_authorityId: function (const n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl = nil;
  NAMING_AUTHORITY_get0_authorityURL: function (const n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl = nil;
  NAMING_AUTHORITY_get0_authorityText: function (const n: PNAMING_AUTHORITY): PASN1_STRING; cdecl = nil;
  NAMING_AUTHORITY_set0_authorityId: procedure (n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl = nil;
  NAMING_AUTHORITY_set0_authorityURL: procedure (n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl = nil;
  NAMING_AUTHORITY_set0_authorityText: procedure (n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl = nil;

  ADMISSION_SYNTAX_get0_admissionAuthority: function (const as_: ADMISSION_SYNTAX): PGENERAL_NAME; cdecl = nil;
  ADMISSION_SYNTAX_set0_admissionAuthority: procedure (as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl = nil;
//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
  ADMISSIONS_get0_admissionAuthority: function (const a: PADMISSIONS): PGENERAL_NAME; cdecl = nil;
  ADMISSIONS_set0_admissionAuthority: procedure (a: PADMISSIONS; aa: PGENERAL_NAME); cdecl = nil;
  ADMISSIONS_get0_namingAuthority: function (const a: PADMISSIONS): PNAMING_AUTHORITY; cdecl = nil;
  ADMISSIONS_set0_namingAuthority: procedure (a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl = nil;
  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS);
  PROFESSION_INFO_get0_addProfessionInfo: function (const pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl = nil;
  PROFESSION_INFO_set0_addProfessionInfo: procedure (pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl = nil;
  PROFESSION_INFO_get0_namingAuthority: function (const pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl = nil;
  PROFESSION_INFO_set0_namingAuthority: procedure (pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl = nil;
//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
  PROFESSION_INFO_get0_registrationNumber: function (const pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl = nil;
  PROFESSION_INFO_set0_registrationNumber: procedure (pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl = nil;


{$ELSE}
  function GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT cdecl; external CLibCrypto;

//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
  function GENERAL_NAME_print(out_: PBIO; gen: PGENERAL_NAME): TIdC_INT cdecl; external CLibCrypto;

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
  function OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT cdecl; external CLibCrypto;
  procedure GENERAL_NAME_set0_value(a: PGENERAL_NAME; type_: TIdC_INT; value: Pointer) cdecl; external CLibCrypto;
  function GENERAL_NAME_get0_value(const a: PGENERAL_NAME; ptype: PIdC_INT): Pointer cdecl; external CLibCrypto;
  function GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  function GENERAL_NAME_get0_otherName(const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;

  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
  function i2a_ACCESS_DESCRIPTION(bp: PBIO; const a: PACCESS_DESCRIPTION): TIdC_INT cdecl; external CLibCrypto;

//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

  function DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;

  function NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT cdecl; external CLibCrypto;
  function NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT cdecl; external CLibCrypto;

//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(val: PCONF_VALUE);

  function X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
  function X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
  function X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  function X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;
  function X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;

  function X509V3_EXT_conf_nid(conf: Pointer; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
  function X509V3_EXT_conf(conf: Pointer; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
  function X509V3_EXT_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
  function X509V3_EXT_REQ_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
  function X509V3_EXT_CRL_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
  procedure X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF) cdecl; external CLibCrypto;
//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

  function X509V3_get_string(ctx: PX509V3_CTX; const name: PIdAnsiChar; const section: PIdAnsiChar): PIdAnsiChar cdecl; external CLibCrypto;
//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
  procedure X509V3_string_free(ctx: PX509V3_CTX; str: PIdAnsiChar) cdecl; external CLibCrypto;
//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
  procedure X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT) cdecl; external CLibCrypto;

//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
  function X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  procedure X509V3_EXT_cleanup cdecl; external CLibCrypto;

  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
  function X509V3_add_standard_extensions: TIdC_INT cdecl; external CLibCrypto;
//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
  function X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer cdecl; external CLibCrypto;
//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

  function X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION cdecl; external CLibCrypto;
//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
  function X509V3_EXT_print(out_: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

  function X509_check_ca(x: PX509): TIdC_INT cdecl; external CLibCrypto;
  function X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT cdecl; external CLibCrypto;
  function X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT cdecl; external CLibCrypto;
  function X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_set_proxy_flag(x: PX509) cdecl; external CLibCrypto;
  procedure X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG) cdecl; external CLibCrypto;
  function X509_get_proxy_pathlen(x: PX509): TIdC_LONG cdecl; external CLibCrypto;

  function X509_get_extension_flags(x: PX509): TIdC_UINT32 cdecl; external CLibCrypto;
  function X509_get_key_usage(x: PX509): TIdC_UINT32 cdecl; external CLibCrypto;
  function X509_get_extended_key_usage(x: PX509): TIdC_UINT32 cdecl; external CLibCrypto;
  function X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  function X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  //function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES;
  function X509_get0_authority_serial(x: PX509): PASN1_INTEGER cdecl; external CLibCrypto;

  function X509_PURPOSE_get_count: TIdC_INT cdecl; external CLibCrypto;
  function X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE cdecl; external CLibCrypto;
  function X509_PURPOSE_get_by_sname(const sname: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
  function X509_PURPOSE_get0_name(const xp: PX509_PURPOSE): PIdAnsiChar cdecl; external CLibCrypto;
  function X509_PURPOSE_get0_sname(const xp: PX509_PURPOSE): PIdAnsiChar cdecl; external CLibCrypto;
  function X509_PURPOSE_get_trust(const xp: PX509_PURPOSE): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_PURPOSE_cleanup cdecl; external CLibCrypto;
  function X509_PURPOSE_get_id(const v1: PX509_PURPOSE): TIdC_INT cdecl; external CLibCrypto;

//  STACK_OF(OPENSSL_STRING) *X509_get1_email(x: PX509);
//  STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x);
//  void X509_email_free(STACK_OF(OPENSSL_STRING) *sk);
//  STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(x: PX509);

  function X509_check_host(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function X509_check_email(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  function X509_check_ip(x: PX509; const chk: PByte; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  function X509_check_ip_asc(x: PX509; const ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  function a2i_IPADDRESS(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  function a2i_IPADDRESS_NC(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING cdecl; external CLibCrypto;
//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

  procedure X509_POLICY_NODE_print(out_: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT) cdecl; external CLibCrypto;
//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
  function X509v3_addr_get_range(aor: PIPAddressOrRange; const afi: TIdC_UINT; min: PByte; max: Byte; const length: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
  function X509v3_asid_validate_path(v1: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
  function X509v3_addr_validate_path(v1: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
  function NAMING_AUTHORITY_get0_authorityId(const n: PNAMING_AUTHORITY): PASN1_OBJECT cdecl; external CLibCrypto;
  function NAMING_AUTHORITY_get0_authorityURL(const n: PNAMING_AUTHORITY): PASN1_IA5STRING cdecl; external CLibCrypto;
  function NAMING_AUTHORITY_get0_authorityText(const n: PNAMING_AUTHORITY): PASN1_STRING cdecl; external CLibCrypto;
  procedure NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT) cdecl; external CLibCrypto;
  procedure NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING) cdecl; external CLibCrypto;
  procedure NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING) cdecl; external CLibCrypto;

  function ADMISSION_SYNTAX_get0_admissionAuthority(const as_: ADMISSION_SYNTAX): PGENERAL_NAME cdecl; external CLibCrypto;
  procedure ADMISSION_SYNTAX_set0_admissionAuthority(as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME) cdecl; external CLibCrypto;
//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
  function ADMISSIONS_get0_admissionAuthority(const a: PADMISSIONS): PGENERAL_NAME cdecl; external CLibCrypto;
  procedure ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME) cdecl; external CLibCrypto;
  function ADMISSIONS_get0_namingAuthority(const a: PADMISSIONS): PNAMING_AUTHORITY cdecl; external CLibCrypto;
  procedure ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY) cdecl; external CLibCrypto;
  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS);
  function PROFESSION_INFO_get0_addProfessionInfo(const pi: PPROFESSION_INFO): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  procedure PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING) cdecl; external CLibCrypto;
  function PROFESSION_INFO_get0_namingAuthority(const pi: PPROFESSION_INFO): PNAMING_AUTHORITY cdecl; external CLibCrypto;
  procedure PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY) cdecl; external CLibCrypto;
//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
  function PROFESSION_INFO_get0_registrationNumber(const pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING cdecl; external CLibCrypto;
  procedure PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING) cdecl; external CLibCrypto;


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
  GENERAL_NAME_cmp_procname = 'GENERAL_NAME_cmp';

//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
  GENERAL_NAME_print_procname = 'GENERAL_NAME_print';

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
  OTHERNAME_cmp_procname = 'OTHERNAME_cmp';
  GENERAL_NAME_set0_value_procname = 'GENERAL_NAME_set0_value';
  GENERAL_NAME_get0_value_procname = 'GENERAL_NAME_get0_value';
  GENERAL_NAME_set0_othername_procname = 'GENERAL_NAME_set0_othername';
  GENERAL_NAME_get0_otherName_procname = 'GENERAL_NAME_get0_otherName';

  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
  i2a_ACCESS_DESCRIPTION_procname = 'i2a_ACCESS_DESCRIPTION';

//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

  DIST_POINT_set_dpname_procname = 'DIST_POINT_set_dpname';

  NAME_CONSTRAINTS_check_procname = 'NAME_CONSTRAINTS_check';
  NAME_CONSTRAINTS_check_CN_procname = 'NAME_CONSTRAINTS_check_CN';

//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(val: PCONF_VALUE);

  X509V3_EXT_nconf_nid_procname = 'X509V3_EXT_nconf_nid';
  X509V3_EXT_nconf_procname = 'X509V3_EXT_nconf';
//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
  X509V3_EXT_add_nconf_procname = 'X509V3_EXT_add_nconf';
  X509V3_EXT_REQ_add_nconf_procname = 'X509V3_EXT_REQ_add_nconf';
  X509V3_EXT_CRL_add_nconf_procname = 'X509V3_EXT_CRL_add_nconf';

  X509V3_EXT_conf_nid_procname = 'X509V3_EXT_conf_nid';
//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
  X509V3_EXT_conf_procname = 'X509V3_EXT_conf';
//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
  X509V3_EXT_add_conf_procname = 'X509V3_EXT_add_conf';
//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
  X509V3_EXT_REQ_add_conf_procname = 'X509V3_EXT_REQ_add_conf';
//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
  X509V3_EXT_CRL_add_conf_procname = 'X509V3_EXT_CRL_add_conf';
//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
  X509V3_set_nconf_procname = 'X509V3_set_nconf';
//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

  X509V3_get_string_procname = 'X509V3_get_string';
//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
  X509V3_string_free_procname = 'X509V3_string_free';
//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
  X509V3_set_ctx_procname = 'X509V3_set_ctx';

//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
  X509V3_EXT_add_alias_procname = 'X509V3_EXT_add_alias';
  X509V3_EXT_cleanup_procname = 'X509V3_EXT_cleanup';

  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
  X509V3_add_standard_extensions_procname = 'X509V3_add_standard_extensions';
//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
  X509V3_EXT_d2i_procname = 'X509V3_EXT_d2i';
//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

  X509V3_EXT_i2d_procname = 'X509V3_EXT_i2d';
//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
  X509V3_EXT_print_procname = 'X509V3_EXT_print';
//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

  X509_check_ca_procname = 'X509_check_ca';
  X509_check_purpose_procname = 'X509_check_purpose';
  X509_supported_extension_procname = 'X509_supported_extension';
  X509_PURPOSE_set_procname = 'X509_PURPOSE_set';
  X509_check_issued_procname = 'X509_check_issued';
  X509_check_akid_procname = 'X509_check_akid';
  X509_set_proxy_flag_procname = 'X509_set_proxy_flag';
  X509_set_proxy_pathlen_procname = 'X509_set_proxy_pathlen';
  X509_get_proxy_pathlen_procname = 'X509_get_proxy_pathlen';

  X509_get_extension_flags_procname = 'X509_get_extension_flags';
  X509_get_key_usage_procname = 'X509_get_key_usage';
  X509_get_extended_key_usage_procname = 'X509_get_extended_key_usage';
  X509_get0_subject_key_id_procname = 'X509_get0_subject_key_id';
  X509_get0_authority_key_id_procname = 'X509_get0_authority_key_id';
  //function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES;
  X509_get0_authority_serial_procname = 'X509_get0_authority_serial';

  X509_PURPOSE_get_count_procname = 'X509_PURPOSE_get_count';
  X509_PURPOSE_get0_procname = 'X509_PURPOSE_get0';
  X509_PURPOSE_get_by_sname_procname = 'X509_PURPOSE_get_by_sname';
  X509_PURPOSE_get_by_id_procname = 'X509_PURPOSE_get_by_id';
//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
  X509_PURPOSE_get0_name_procname = 'X509_PURPOSE_get0_name';
  X509_PURPOSE_get0_sname_procname = 'X509_PURPOSE_get0_sname';
  X509_PURPOSE_get_trust_procname = 'X509_PURPOSE_get_trust';
  X509_PURPOSE_cleanup_procname = 'X509_PURPOSE_cleanup';
  X509_PURPOSE_get_id_procname = 'X509_PURPOSE_get_id';

//  STACK_OF(OPENSSL_STRING) *X509_get1_email(x: PX509);
//  STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x);
//  void X509_email_free(STACK_OF(OPENSSL_STRING) *sk);
//  STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(x: PX509);

  X509_check_host_procname = 'X509_check_host';
  X509_check_email_procname = 'X509_check_email';
  X509_check_ip_procname = 'X509_check_ip';
  X509_check_ip_asc_procname = 'X509_check_ip_asc';

  a2i_IPADDRESS_procname = 'a2i_IPADDRESS';
  a2i_IPADDRESS_NC_procname = 'a2i_IPADDRESS_NC';
//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

  X509_POLICY_NODE_print_procname = 'X509_POLICY_NODE_print';
//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
  X509v3_addr_get_range_procname = 'X509v3_addr_get_range';

  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
  X509v3_asid_validate_path_procname = 'X509v3_asid_validate_path';
  X509v3_addr_validate_path_procname = 'X509v3_addr_validate_path';
//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
  NAMING_AUTHORITY_get0_authorityId_procname = 'NAMING_AUTHORITY_get0_authorityId';
  NAMING_AUTHORITY_get0_authorityURL_procname = 'NAMING_AUTHORITY_get0_authorityURL';
  NAMING_AUTHORITY_get0_authorityText_procname = 'NAMING_AUTHORITY_get0_authorityText';
  NAMING_AUTHORITY_set0_authorityId_procname = 'NAMING_AUTHORITY_set0_authorityId';
  NAMING_AUTHORITY_set0_authorityURL_procname = 'NAMING_AUTHORITY_set0_authorityURL';
  NAMING_AUTHORITY_set0_authorityText_procname = 'NAMING_AUTHORITY_set0_authorityText';

  ADMISSION_SYNTAX_get0_admissionAuthority_procname = 'ADMISSION_SYNTAX_get0_admissionAuthority';
  ADMISSION_SYNTAX_set0_admissionAuthority_procname = 'ADMISSION_SYNTAX_set0_admissionAuthority';
//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
  ADMISSIONS_get0_admissionAuthority_procname = 'ADMISSIONS_get0_admissionAuthority';
  ADMISSIONS_set0_admissionAuthority_procname = 'ADMISSIONS_set0_admissionAuthority';
  ADMISSIONS_get0_namingAuthority_procname = 'ADMISSIONS_get0_namingAuthority';
  ADMISSIONS_set0_namingAuthority_procname = 'ADMISSIONS_set0_namingAuthority';
  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS);
  PROFESSION_INFO_get0_addProfessionInfo_procname = 'PROFESSION_INFO_get0_addProfessionInfo';
  PROFESSION_INFO_set0_addProfessionInfo_procname = 'PROFESSION_INFO_set0_addProfessionInfo';
  PROFESSION_INFO_get0_namingAuthority_procname = 'PROFESSION_INFO_get0_namingAuthority';
  PROFESSION_INFO_set0_namingAuthority_procname = 'PROFESSION_INFO_set0_namingAuthority';
//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
  PROFESSION_INFO_get0_registrationNumber_procname = 'PROFESSION_INFO_get0_registrationNumber';
  PROFESSION_INFO_set0_registrationNumber_procname = 'PROFESSION_INFO_set0_registrationNumber';



{$WARN  NO_RETVAL OFF}
function  ERR_GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(GENERAL_NAME_cmp_procname);
end;



//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
function  ERR_GENERAL_NAME_print(out_: PBIO; gen: PGENERAL_NAME): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(GENERAL_NAME_print_procname);
end;



//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
function  ERR_OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OTHERNAME_cmp_procname);
end;


procedure  ERR_GENERAL_NAME_set0_value(a: PGENERAL_NAME; type_: TIdC_INT; value: Pointer); 
begin
  EIdAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set0_value_procname);
end;


function  ERR_GENERAL_NAME_get0_value(const a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(GENERAL_NAME_get0_value_procname);
end;


function  ERR_GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set0_othername_procname);
end;


function  ERR_GENERAL_NAME_get0_otherName(const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(GENERAL_NAME_get0_otherName_procname);
end;



  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
function  ERR_i2a_ACCESS_DESCRIPTION(bp: PBIO; const a: PACCESS_DESCRIPTION): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2a_ACCESS_DESCRIPTION_procname);
end;



//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

function  ERR_DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DIST_POINT_set_dpname_procname);
end;



function  ERR_NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_check_procname);
end;


function  ERR_NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_check_CN_procname);
end;



//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(val: PCONF_VALUE);

function  ERR_X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_nconf_nid_procname);
end;


function  ERR_X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_nconf_procname);
end;


//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
function  ERR_X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_nconf_procname);
end;


function  ERR_X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_REQ_add_nconf_procname);
end;


function  ERR_X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_CRL_add_nconf_procname);
end;



function  ERR_X509V3_EXT_conf_nid(conf: Pointer; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_conf_nid_procname);
end;


//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
function  ERR_X509V3_EXT_conf(conf: Pointer; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_conf_procname);
end;


//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
function  ERR_X509V3_EXT_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_conf_procname);
end;


//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
function  ERR_X509V3_EXT_REQ_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_REQ_add_conf_procname);
end;


//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
function  ERR_X509V3_EXT_CRL_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_CRL_add_conf_procname);
end;


//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
procedure  ERR_X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_set_nconf_procname);
end;


//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

function  ERR_X509V3_get_string(ctx: PX509V3_CTX; const name: PIdAnsiChar; const section: PIdAnsiChar): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_get_string_procname);
end;


//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
procedure  ERR_X509V3_string_free(ctx: PX509V3_CTX; str: PIdAnsiChar); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_string_free_procname);
end;


//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
procedure  ERR_X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_set_ctx_procname);
end;



//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
function  ERR_X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_alias_procname);
end;


procedure  ERR_X509V3_EXT_cleanup; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_cleanup_procname);
end;



  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
function  ERR_X509V3_add_standard_extensions: TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_add_standard_extensions_procname);
end;


//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
function  ERR_X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_d2i_procname);
end;


//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

function  ERR_X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_i2d_procname);
end;


//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
function  ERR_X509V3_EXT_print(out_: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509V3_EXT_print_procname);
end;


//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

function  ERR_X509_check_ca(x: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_ca_procname);
end;


function  ERR_X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_purpose_procname);
end;


function  ERR_X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_supported_extension_procname);
end;


function  ERR_X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_set_procname);
end;


function  ERR_X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_issued_procname);
end;


function  ERR_X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_akid_procname);
end;


procedure  ERR_X509_set_proxy_flag(x: PX509); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_set_proxy_flag_procname);
end;


procedure  ERR_X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_set_proxy_pathlen_procname);
end;


function  ERR_X509_get_proxy_pathlen(x: PX509): TIdC_LONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get_proxy_pathlen_procname);
end;



function  ERR_X509_get_extension_flags(x: PX509): TIdC_UINT32; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get_extension_flags_procname);
end;


function  ERR_X509_get_key_usage(x: PX509): TIdC_UINT32; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get_key_usage_procname);
end;


function  ERR_X509_get_extended_key_usage(x: PX509): TIdC_UINT32; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get_extended_key_usage_procname);
end;


function  ERR_X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get0_subject_key_id_procname);
end;


function  ERR_X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get0_authority_key_id_procname);
end;


  //function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES;
function  ERR_X509_get0_authority_serial(x: PX509): PASN1_INTEGER; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_get0_authority_serial_procname);
end;



function  ERR_X509_PURPOSE_get_count: TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_count_procname);
end;


function  ERR_X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_procname);
end;


function  ERR_X509_PURPOSE_get_by_sname(const sname: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_by_sname_procname);
end;


function  ERR_X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_by_id_procname);
end;


//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
function  ERR_X509_PURPOSE_get0_name(const xp: PX509_PURPOSE): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_name_procname);
end;


function  ERR_X509_PURPOSE_get0_sname(const xp: PX509_PURPOSE): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_sname_procname);
end;


function  ERR_X509_PURPOSE_get_trust(const xp: PX509_PURPOSE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_trust_procname);
end;


procedure  ERR_X509_PURPOSE_cleanup; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_cleanup_procname);
end;


function  ERR_X509_PURPOSE_get_id(const v1: PX509_PURPOSE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_id_procname);
end;



//  STACK_OF(OPENSSL_STRING) *X509_get1_email(x: PX509);
//  STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x);
//  void X509_email_free(STACK_OF(OPENSSL_STRING) *sk);
//  STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(x: PX509);

function  ERR_X509_check_host(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_host_procname);
end;


function  ERR_X509_check_email(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_email_procname);
end;


function  ERR_X509_check_ip(x: PX509; const chk: PByte; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_ip_procname);
end;


function  ERR_X509_check_ip_asc(x: PX509; const ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_check_ip_asc_procname);
end;



function  ERR_a2i_IPADDRESS(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(a2i_IPADDRESS_procname);
end;


function  ERR_a2i_IPADDRESS_NC(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(a2i_IPADDRESS_NC_procname);
end;


//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

procedure  ERR_X509_POLICY_NODE_print(out_: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_POLICY_NODE_print_procname);
end;


//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(addr: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
function  ERR_X509v3_addr_get_range(aor: PIPAddressOrRange; const afi: TIdC_UINT; min: PByte; max: Byte; const length: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509v3_addr_get_range_procname);
end;



  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
function  ERR_X509v3_asid_validate_path(v1: PX509_STORE_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509v3_asid_validate_path_procname);
end;


function  ERR_X509v3_addr_validate_path(v1: PX509_STORE_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509v3_addr_validate_path_procname);
end;


//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
function  ERR_NAMING_AUTHORITY_get0_authorityId(const n: PNAMING_AUTHORITY): PASN1_OBJECT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityId_procname);
end;


function  ERR_NAMING_AUTHORITY_get0_authorityURL(const n: PNAMING_AUTHORITY): PASN1_IA5STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityURL_procname);
end;


function  ERR_NAMING_AUTHORITY_get0_authorityText(const n: PNAMING_AUTHORITY): PASN1_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityText_procname);
end;


procedure  ERR_NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityId_procname);
end;


procedure  ERR_NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityURL_procname);
end;


procedure  ERR_NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); 
begin
  EIdAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityText_procname);
end;



function  ERR_ADMISSION_SYNTAX_get0_admissionAuthority(const as_: ADMISSION_SYNTAX): PGENERAL_NAME; 
begin
  EIdAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_get0_admissionAuthority_procname);
end;


procedure  ERR_ADMISSION_SYNTAX_set0_admissionAuthority(as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME); 
begin
  EIdAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_set0_admissionAuthority_procname);
end;


//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
function  ERR_ADMISSIONS_get0_admissionAuthority(const a: PADMISSIONS): PGENERAL_NAME; 
begin
  EIdAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_admissionAuthority_procname);
end;


procedure  ERR_ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME); 
begin
  EIdAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_admissionAuthority_procname);
end;


function  ERR_ADMISSIONS_get0_namingAuthority(const a: PADMISSIONS): PNAMING_AUTHORITY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_namingAuthority_procname);
end;


procedure  ERR_ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_namingAuthority_procname);
end;


  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS);
function  ERR_PROFESSION_INFO_get0_addProfessionInfo(const pi: PPROFESSION_INFO): PASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_addProfessionInfo_procname);
end;


procedure  ERR_PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_addProfessionInfo_procname);
end;


function  ERR_PROFESSION_INFO_get0_namingAuthority(const pi: PPROFESSION_INFO): PNAMING_AUTHORITY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_namingAuthority_procname);
end;


procedure  ERR_PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_namingAuthority_procname);
end;


//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
function  ERR_PROFESSION_INFO_get0_registrationNumber(const pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_registrationNumber_procname);
end;


procedure  ERR_PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_registrationNumber_procname);
end;




{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  GENERAL_NAME_cmp := LoadLibFunction(ADllHandle, GENERAL_NAME_cmp_procname);
  FuncLoadError := not assigned(GENERAL_NAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_cmp_allownil)}
    GENERAL_NAME_cmp := @ERR_GENERAL_NAME_cmp;
    {$ifend}
    {$if declared(GENERAL_NAME_cmp_introduced)}
    if LibVersion < GENERAL_NAME_cmp_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_cmp)}
      GENERAL_NAME_cmp := @FC_GENERAL_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_cmp_removed)}
    if GENERAL_NAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_cmp)}
      GENERAL_NAME_cmp := @_GENERAL_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_cmp');
    {$ifend}
  end;


  GENERAL_NAME_print := LoadLibFunction(ADllHandle, GENERAL_NAME_print_procname);
  FuncLoadError := not assigned(GENERAL_NAME_print);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_print_allownil)}
    GENERAL_NAME_print := @ERR_GENERAL_NAME_print;
    {$ifend}
    {$if declared(GENERAL_NAME_print_introduced)}
    if LibVersion < GENERAL_NAME_print_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_print)}
      GENERAL_NAME_print := @FC_GENERAL_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_print_removed)}
    if GENERAL_NAME_print_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_print)}
      GENERAL_NAME_print := @_GENERAL_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_print');
    {$ifend}
  end;


  OTHERNAME_cmp := LoadLibFunction(ADllHandle, OTHERNAME_cmp_procname);
  FuncLoadError := not assigned(OTHERNAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(OTHERNAME_cmp_allownil)}
    OTHERNAME_cmp := @ERR_OTHERNAME_cmp;
    {$ifend}
    {$if declared(OTHERNAME_cmp_introduced)}
    if LibVersion < OTHERNAME_cmp_introduced then
    begin
      {$if declared(FC_OTHERNAME_cmp)}
      OTHERNAME_cmp := @FC_OTHERNAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OTHERNAME_cmp_removed)}
    if OTHERNAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_OTHERNAME_cmp)}
      OTHERNAME_cmp := @_OTHERNAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OTHERNAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OTHERNAME_cmp');
    {$ifend}
  end;


  GENERAL_NAME_set0_value := LoadLibFunction(ADllHandle, GENERAL_NAME_set0_value_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set0_value);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set0_value_allownil)}
    GENERAL_NAME_set0_value := @ERR_GENERAL_NAME_set0_value;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_value_introduced)}
    if LibVersion < GENERAL_NAME_set0_value_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set0_value)}
      GENERAL_NAME_set0_value := @FC_GENERAL_NAME_set0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_value_removed)}
    if GENERAL_NAME_set0_value_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set0_value)}
      GENERAL_NAME_set0_value := @_GENERAL_NAME_set0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set0_value');
    {$ifend}
  end;


  GENERAL_NAME_get0_value := LoadLibFunction(ADllHandle, GENERAL_NAME_get0_value_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_value);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_get0_value_allownil)}
    GENERAL_NAME_get0_value := @ERR_GENERAL_NAME_get0_value;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_value_introduced)}
    if LibVersion < GENERAL_NAME_get0_value_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_get0_value)}
      GENERAL_NAME_get0_value := @FC_GENERAL_NAME_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_value_removed)}
    if GENERAL_NAME_get0_value_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_get0_value)}
      GENERAL_NAME_get0_value := @_GENERAL_NAME_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_get0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_get0_value');
    {$ifend}
  end;


  GENERAL_NAME_set0_othername := LoadLibFunction(ADllHandle, GENERAL_NAME_set0_othername_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set0_othername);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set0_othername_allownil)}
    GENERAL_NAME_set0_othername := @ERR_GENERAL_NAME_set0_othername;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_othername_introduced)}
    if LibVersion < GENERAL_NAME_set0_othername_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set0_othername)}
      GENERAL_NAME_set0_othername := @FC_GENERAL_NAME_set0_othername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_othername_removed)}
    if GENERAL_NAME_set0_othername_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set0_othername)}
      GENERAL_NAME_set0_othername := @_GENERAL_NAME_set0_othername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set0_othername_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set0_othername');
    {$ifend}
  end;


  GENERAL_NAME_get0_otherName := LoadLibFunction(ADllHandle, GENERAL_NAME_get0_otherName_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_otherName);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_get0_otherName_allownil)}
    GENERAL_NAME_get0_otherName := @ERR_GENERAL_NAME_get0_otherName;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_otherName_introduced)}
    if LibVersion < GENERAL_NAME_get0_otherName_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_get0_otherName)}
      GENERAL_NAME_get0_otherName := @FC_GENERAL_NAME_get0_otherName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_otherName_removed)}
    if GENERAL_NAME_get0_otherName_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_get0_otherName)}
      GENERAL_NAME_get0_otherName := @_GENERAL_NAME_get0_otherName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_get0_otherName_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_get0_otherName');
    {$ifend}
  end;


  i2a_ACCESS_DESCRIPTION := LoadLibFunction(ADllHandle, i2a_ACCESS_DESCRIPTION_procname);
  FuncLoadError := not assigned(i2a_ACCESS_DESCRIPTION);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ACCESS_DESCRIPTION_allownil)}
    i2a_ACCESS_DESCRIPTION := @ERR_i2a_ACCESS_DESCRIPTION;
    {$ifend}
    {$if declared(i2a_ACCESS_DESCRIPTION_introduced)}
    if LibVersion < i2a_ACCESS_DESCRIPTION_introduced then
    begin
      {$if declared(FC_i2a_ACCESS_DESCRIPTION)}
      i2a_ACCESS_DESCRIPTION := @FC_i2a_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ACCESS_DESCRIPTION_removed)}
    if i2a_ACCESS_DESCRIPTION_removed <= LibVersion then
    begin
      {$if declared(_i2a_ACCESS_DESCRIPTION)}
      i2a_ACCESS_DESCRIPTION := @_i2a_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ACCESS_DESCRIPTION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ACCESS_DESCRIPTION');
    {$ifend}
  end;


  DIST_POINT_set_dpname := LoadLibFunction(ADllHandle, DIST_POINT_set_dpname_procname);
  FuncLoadError := not assigned(DIST_POINT_set_dpname);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_set_dpname_allownil)}
    DIST_POINT_set_dpname := @ERR_DIST_POINT_set_dpname;
    {$ifend}
    {$if declared(DIST_POINT_set_dpname_introduced)}
    if LibVersion < DIST_POINT_set_dpname_introduced then
    begin
      {$if declared(FC_DIST_POINT_set_dpname)}
      DIST_POINT_set_dpname := @FC_DIST_POINT_set_dpname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_set_dpname_removed)}
    if DIST_POINT_set_dpname_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_set_dpname)}
      DIST_POINT_set_dpname := @_DIST_POINT_set_dpname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_set_dpname_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_set_dpname');
    {$ifend}
  end;


  NAME_CONSTRAINTS_check := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_check_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_check_allownil)}
    NAME_CONSTRAINTS_check := @ERR_NAME_CONSTRAINTS_check;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_introduced)}
    if LibVersion < NAME_CONSTRAINTS_check_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_check)}
      NAME_CONSTRAINTS_check := @FC_NAME_CONSTRAINTS_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_removed)}
    if NAME_CONSTRAINTS_check_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_check)}
      NAME_CONSTRAINTS_check := @_NAME_CONSTRAINTS_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_check_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_check');
    {$ifend}
  end;


  NAME_CONSTRAINTS_check_CN := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_check_CN_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check_CN);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_check_CN_allownil)}
    NAME_CONSTRAINTS_check_CN := @ERR_NAME_CONSTRAINTS_check_CN;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_CN_introduced)}
    if LibVersion < NAME_CONSTRAINTS_check_CN_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_check_CN)}
      NAME_CONSTRAINTS_check_CN := @FC_NAME_CONSTRAINTS_check_CN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_CN_removed)}
    if NAME_CONSTRAINTS_check_CN_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_check_CN)}
      NAME_CONSTRAINTS_check_CN := @_NAME_CONSTRAINTS_check_CN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_check_CN_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_check_CN');
    {$ifend}
  end;


  X509V3_EXT_nconf_nid := LoadLibFunction(ADllHandle, X509V3_EXT_nconf_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_nconf_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_nconf_nid_allownil)}
    X509V3_EXT_nconf_nid := @ERR_X509V3_EXT_nconf_nid;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_nid_introduced)}
    if LibVersion < X509V3_EXT_nconf_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_nconf_nid)}
      X509V3_EXT_nconf_nid := @FC_X509V3_EXT_nconf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_nid_removed)}
    if X509V3_EXT_nconf_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_nconf_nid)}
      X509V3_EXT_nconf_nid := @_X509V3_EXT_nconf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_nconf_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_nconf_nid');
    {$ifend}
  end;


  X509V3_EXT_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_nconf_allownil)}
    X509V3_EXT_nconf := @ERR_X509V3_EXT_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_introduced)}
    if LibVersion < X509V3_EXT_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_nconf)}
      X509V3_EXT_nconf := @FC_X509V3_EXT_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_removed)}
    if X509V3_EXT_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_nconf)}
      X509V3_EXT_nconf := @_X509V3_EXT_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_nconf');
    {$ifend}
  end;


  X509V3_EXT_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_nconf_allownil)}
    X509V3_EXT_add_nconf := @ERR_X509V3_EXT_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_nconf)}
      X509V3_EXT_add_nconf := @FC_X509V3_EXT_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_removed)}
    if X509V3_EXT_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_nconf)}
      X509V3_EXT_add_nconf := @_X509V3_EXT_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_nconf');
    {$ifend}
  end;


  X509V3_EXT_REQ_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_REQ_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_REQ_add_nconf_allownil)}
    X509V3_EXT_REQ_add_nconf := @ERR_X509V3_EXT_REQ_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_REQ_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_REQ_add_nconf)}
      X509V3_EXT_REQ_add_nconf := @FC_X509V3_EXT_REQ_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_nconf_removed)}
    if X509V3_EXT_REQ_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_REQ_add_nconf)}
      X509V3_EXT_REQ_add_nconf := @_X509V3_EXT_REQ_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_REQ_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_REQ_add_nconf');
    {$ifend}
  end;


  X509V3_EXT_CRL_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_CRL_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_CRL_add_nconf_allownil)}
    X509V3_EXT_CRL_add_nconf := @ERR_X509V3_EXT_CRL_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_CRL_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_CRL_add_nconf)}
      X509V3_EXT_CRL_add_nconf := @FC_X509V3_EXT_CRL_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_nconf_removed)}
    if X509V3_EXT_CRL_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_CRL_add_nconf)}
      X509V3_EXT_CRL_add_nconf := @_X509V3_EXT_CRL_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_CRL_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_CRL_add_nconf');
    {$ifend}
  end;


  X509V3_EXT_conf_nid := LoadLibFunction(ADllHandle, X509V3_EXT_conf_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_conf_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_conf_nid_allownil)}
    X509V3_EXT_conf_nid := @ERR_X509V3_EXT_conf_nid;
    {$ifend}
    {$if declared(X509V3_EXT_conf_nid_introduced)}
    if LibVersion < X509V3_EXT_conf_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_conf_nid)}
      X509V3_EXT_conf_nid := @FC_X509V3_EXT_conf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_conf_nid_removed)}
    if X509V3_EXT_conf_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_conf_nid)}
      X509V3_EXT_conf_nid := @_X509V3_EXT_conf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_conf_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_conf_nid');
    {$ifend}
  end;


  X509V3_EXT_conf := LoadLibFunction(ADllHandle, X509V3_EXT_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_conf_allownil)}
    X509V3_EXT_conf := @ERR_X509V3_EXT_conf;
    {$ifend}
    {$if declared(X509V3_EXT_conf_introduced)}
    if LibVersion < X509V3_EXT_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_conf)}
      X509V3_EXT_conf := @FC_X509V3_EXT_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_conf_removed)}
    if X509V3_EXT_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_conf)}
      X509V3_EXT_conf := @_X509V3_EXT_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_conf');
    {$ifend}
  end;


  X509V3_EXT_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_conf_allownil)}
    X509V3_EXT_add_conf := @ERR_X509V3_EXT_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_add_conf_introduced)}
    if LibVersion < X509V3_EXT_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_conf)}
      X509V3_EXT_add_conf := @FC_X509V3_EXT_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_conf_removed)}
    if X509V3_EXT_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_conf)}
      X509V3_EXT_add_conf := @_X509V3_EXT_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_conf');
    {$ifend}
  end;


  X509V3_EXT_REQ_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_REQ_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_REQ_add_conf_allownil)}
    X509V3_EXT_REQ_add_conf := @ERR_X509V3_EXT_REQ_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_conf_introduced)}
    if LibVersion < X509V3_EXT_REQ_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_REQ_add_conf)}
      X509V3_EXT_REQ_add_conf := @FC_X509V3_EXT_REQ_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_conf_removed)}
    if X509V3_EXT_REQ_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_REQ_add_conf)}
      X509V3_EXT_REQ_add_conf := @_X509V3_EXT_REQ_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_REQ_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_REQ_add_conf');
    {$ifend}
  end;


  X509V3_EXT_CRL_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_CRL_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_CRL_add_conf_allownil)}
    X509V3_EXT_CRL_add_conf := @ERR_X509V3_EXT_CRL_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_conf_introduced)}
    if LibVersion < X509V3_EXT_CRL_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_CRL_add_conf)}
      X509V3_EXT_CRL_add_conf := @FC_X509V3_EXT_CRL_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_conf_removed)}
    if X509V3_EXT_CRL_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_CRL_add_conf)}
      X509V3_EXT_CRL_add_conf := @_X509V3_EXT_CRL_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_CRL_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_CRL_add_conf');
    {$ifend}
  end;


  X509V3_set_nconf := LoadLibFunction(ADllHandle, X509V3_set_nconf_procname);
  FuncLoadError := not assigned(X509V3_set_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_nconf_allownil)}
    X509V3_set_nconf := @ERR_X509V3_set_nconf;
    {$ifend}
    {$if declared(X509V3_set_nconf_introduced)}
    if LibVersion < X509V3_set_nconf_introduced then
    begin
      {$if declared(FC_X509V3_set_nconf)}
      X509V3_set_nconf := @FC_X509V3_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_nconf_removed)}
    if X509V3_set_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_nconf)}
      X509V3_set_nconf := @_X509V3_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_nconf');
    {$ifend}
  end;


  X509V3_get_string := LoadLibFunction(ADllHandle, X509V3_get_string_procname);
  FuncLoadError := not assigned(X509V3_get_string);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_string_allownil)}
    X509V3_get_string := @ERR_X509V3_get_string;
    {$ifend}
    {$if declared(X509V3_get_string_introduced)}
    if LibVersion < X509V3_get_string_introduced then
    begin
      {$if declared(FC_X509V3_get_string)}
      X509V3_get_string := @FC_X509V3_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_string_removed)}
    if X509V3_get_string_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_string)}
      X509V3_get_string := @_X509V3_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_string');
    {$ifend}
  end;


  X509V3_string_free := LoadLibFunction(ADllHandle, X509V3_string_free_procname);
  FuncLoadError := not assigned(X509V3_string_free);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_string_free_allownil)}
    X509V3_string_free := @ERR_X509V3_string_free;
    {$ifend}
    {$if declared(X509V3_string_free_introduced)}
    if LibVersion < X509V3_string_free_introduced then
    begin
      {$if declared(FC_X509V3_string_free)}
      X509V3_string_free := @FC_X509V3_string_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_string_free_removed)}
    if X509V3_string_free_removed <= LibVersion then
    begin
      {$if declared(_X509V3_string_free)}
      X509V3_string_free := @_X509V3_string_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_string_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_string_free');
    {$ifend}
  end;


  X509V3_set_ctx := LoadLibFunction(ADllHandle, X509V3_set_ctx_procname);
  FuncLoadError := not assigned(X509V3_set_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_ctx_allownil)}
    X509V3_set_ctx := @ERR_X509V3_set_ctx;
    {$ifend}
    {$if declared(X509V3_set_ctx_introduced)}
    if LibVersion < X509V3_set_ctx_introduced then
    begin
      {$if declared(FC_X509V3_set_ctx)}
      X509V3_set_ctx := @FC_X509V3_set_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_ctx_removed)}
    if X509V3_set_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_ctx)}
      X509V3_set_ctx := @_X509V3_set_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_ctx');
    {$ifend}
  end;


  X509V3_EXT_add_alias := LoadLibFunction(ADllHandle, X509V3_EXT_add_alias_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_alias_allownil)}
    X509V3_EXT_add_alias := @ERR_X509V3_EXT_add_alias;
    {$ifend}
    {$if declared(X509V3_EXT_add_alias_introduced)}
    if LibVersion < X509V3_EXT_add_alias_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_alias)}
      X509V3_EXT_add_alias := @FC_X509V3_EXT_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_alias_removed)}
    if X509V3_EXT_add_alias_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_alias)}
      X509V3_EXT_add_alias := @_X509V3_EXT_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_alias');
    {$ifend}
  end;


  X509V3_EXT_cleanup := LoadLibFunction(ADllHandle, X509V3_EXT_cleanup_procname);
  FuncLoadError := not assigned(X509V3_EXT_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_cleanup_allownil)}
    X509V3_EXT_cleanup := @ERR_X509V3_EXT_cleanup;
    {$ifend}
    {$if declared(X509V3_EXT_cleanup_introduced)}
    if LibVersion < X509V3_EXT_cleanup_introduced then
    begin
      {$if declared(FC_X509V3_EXT_cleanup)}
      X509V3_EXT_cleanup := @FC_X509V3_EXT_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_cleanup_removed)}
    if X509V3_EXT_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_cleanup)}
      X509V3_EXT_cleanup := @_X509V3_EXT_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_cleanup');
    {$ifend}
  end;


  X509V3_add_standard_extensions := LoadLibFunction(ADllHandle, X509V3_add_standard_extensions_procname);
  FuncLoadError := not assigned(X509V3_add_standard_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_standard_extensions_allownil)}
    X509V3_add_standard_extensions := @ERR_X509V3_add_standard_extensions;
    {$ifend}
    {$if declared(X509V3_add_standard_extensions_introduced)}
    if LibVersion < X509V3_add_standard_extensions_introduced then
    begin
      {$if declared(FC_X509V3_add_standard_extensions)}
      X509V3_add_standard_extensions := @FC_X509V3_add_standard_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_standard_extensions_removed)}
    if X509V3_add_standard_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_standard_extensions)}
      X509V3_add_standard_extensions := @_X509V3_add_standard_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_standard_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_standard_extensions');
    {$ifend}
  end;


  X509V3_EXT_d2i := LoadLibFunction(ADllHandle, X509V3_EXT_d2i_procname);
  FuncLoadError := not assigned(X509V3_EXT_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_d2i_allownil)}
    X509V3_EXT_d2i := @ERR_X509V3_EXT_d2i;
    {$ifend}
    {$if declared(X509V3_EXT_d2i_introduced)}
    if LibVersion < X509V3_EXT_d2i_introduced then
    begin
      {$if declared(FC_X509V3_EXT_d2i)}
      X509V3_EXT_d2i := @FC_X509V3_EXT_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_d2i_removed)}
    if X509V3_EXT_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_d2i)}
      X509V3_EXT_d2i := @_X509V3_EXT_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_d2i');
    {$ifend}
  end;


  X509V3_EXT_i2d := LoadLibFunction(ADllHandle, X509V3_EXT_i2d_procname);
  FuncLoadError := not assigned(X509V3_EXT_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_i2d_allownil)}
    X509V3_EXT_i2d := @ERR_X509V3_EXT_i2d;
    {$ifend}
    {$if declared(X509V3_EXT_i2d_introduced)}
    if LibVersion < X509V3_EXT_i2d_introduced then
    begin
      {$if declared(FC_X509V3_EXT_i2d)}
      X509V3_EXT_i2d := @FC_X509V3_EXT_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_i2d_removed)}
    if X509V3_EXT_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_i2d)}
      X509V3_EXT_i2d := @_X509V3_EXT_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_i2d');
    {$ifend}
  end;


  X509V3_EXT_print := LoadLibFunction(ADllHandle, X509V3_EXT_print_procname);
  FuncLoadError := not assigned(X509V3_EXT_print);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_print_allownil)}
    X509V3_EXT_print := @ERR_X509V3_EXT_print;
    {$ifend}
    {$if declared(X509V3_EXT_print_introduced)}
    if LibVersion < X509V3_EXT_print_introduced then
    begin
      {$if declared(FC_X509V3_EXT_print)}
      X509V3_EXT_print := @FC_X509V3_EXT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_print_removed)}
    if X509V3_EXT_print_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_print)}
      X509V3_EXT_print := @_X509V3_EXT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_print');
    {$ifend}
  end;


  X509_check_ca := LoadLibFunction(ADllHandle, X509_check_ca_procname);
  FuncLoadError := not assigned(X509_check_ca);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ca_allownil)}
    X509_check_ca := @ERR_X509_check_ca;
    {$ifend}
    {$if declared(X509_check_ca_introduced)}
    if LibVersion < X509_check_ca_introduced then
    begin
      {$if declared(FC_X509_check_ca)}
      X509_check_ca := @FC_X509_check_ca;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ca_removed)}
    if X509_check_ca_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ca)}
      X509_check_ca := @_X509_check_ca;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ca_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ca');
    {$ifend}
  end;


  X509_check_purpose := LoadLibFunction(ADllHandle, X509_check_purpose_procname);
  FuncLoadError := not assigned(X509_check_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_purpose_allownil)}
    X509_check_purpose := @ERR_X509_check_purpose;
    {$ifend}
    {$if declared(X509_check_purpose_introduced)}
    if LibVersion < X509_check_purpose_introduced then
    begin
      {$if declared(FC_X509_check_purpose)}
      X509_check_purpose := @FC_X509_check_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_purpose_removed)}
    if X509_check_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_check_purpose)}
      X509_check_purpose := @_X509_check_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_purpose');
    {$ifend}
  end;


  X509_supported_extension := LoadLibFunction(ADllHandle, X509_supported_extension_procname);
  FuncLoadError := not assigned(X509_supported_extension);
  if FuncLoadError then
  begin
    {$if not defined(X509_supported_extension_allownil)}
    X509_supported_extension := @ERR_X509_supported_extension;
    {$ifend}
    {$if declared(X509_supported_extension_introduced)}
    if LibVersion < X509_supported_extension_introduced then
    begin
      {$if declared(FC_X509_supported_extension)}
      X509_supported_extension := @FC_X509_supported_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_supported_extension_removed)}
    if X509_supported_extension_removed <= LibVersion then
    begin
      {$if declared(_X509_supported_extension)}
      X509_supported_extension := @_X509_supported_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_supported_extension_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_supported_extension');
    {$ifend}
  end;


  X509_PURPOSE_set := LoadLibFunction(ADllHandle, X509_PURPOSE_set_procname);
  FuncLoadError := not assigned(X509_PURPOSE_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_set_allownil)}
    X509_PURPOSE_set := @ERR_X509_PURPOSE_set;
    {$ifend}
    {$if declared(X509_PURPOSE_set_introduced)}
    if LibVersion < X509_PURPOSE_set_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_set)}
      X509_PURPOSE_set := @FC_X509_PURPOSE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_set_removed)}
    if X509_PURPOSE_set_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_set)}
      X509_PURPOSE_set := @_X509_PURPOSE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_set');
    {$ifend}
  end;


  X509_check_issued := LoadLibFunction(ADllHandle, X509_check_issued_procname);
  FuncLoadError := not assigned(X509_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_issued_allownil)}
    X509_check_issued := @ERR_X509_check_issued;
    {$ifend}
    {$if declared(X509_check_issued_introduced)}
    if LibVersion < X509_check_issued_introduced then
    begin
      {$if declared(FC_X509_check_issued)}
      X509_check_issued := @FC_X509_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_issued_removed)}
    if X509_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_check_issued)}
      X509_check_issued := @_X509_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_issued');
    {$ifend}
  end;


  X509_check_akid := LoadLibFunction(ADllHandle, X509_check_akid_procname);
  FuncLoadError := not assigned(X509_check_akid);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_akid_allownil)}
    X509_check_akid := @ERR_X509_check_akid;
    {$ifend}
    {$if declared(X509_check_akid_introduced)}
    if LibVersion < X509_check_akid_introduced then
    begin
      {$if declared(FC_X509_check_akid)}
      X509_check_akid := @FC_X509_check_akid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_akid_removed)}
    if X509_check_akid_removed <= LibVersion then
    begin
      {$if declared(_X509_check_akid)}
      X509_check_akid := @_X509_check_akid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_akid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_akid');
    {$ifend}
  end;


  X509_set_proxy_flag := LoadLibFunction(ADllHandle, X509_set_proxy_flag_procname);
  FuncLoadError := not assigned(X509_set_proxy_flag);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_proxy_flag_allownil)}
    X509_set_proxy_flag := @ERR_X509_set_proxy_flag;
    {$ifend}
    {$if declared(X509_set_proxy_flag_introduced)}
    if LibVersion < X509_set_proxy_flag_introduced then
    begin
      {$if declared(FC_X509_set_proxy_flag)}
      X509_set_proxy_flag := @FC_X509_set_proxy_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_proxy_flag_removed)}
    if X509_set_proxy_flag_removed <= LibVersion then
    begin
      {$if declared(_X509_set_proxy_flag)}
      X509_set_proxy_flag := @_X509_set_proxy_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_proxy_flag_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_proxy_flag');
    {$ifend}
  end;


  X509_set_proxy_pathlen := LoadLibFunction(ADllHandle, X509_set_proxy_pathlen_procname);
  FuncLoadError := not assigned(X509_set_proxy_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_proxy_pathlen_allownil)}
    X509_set_proxy_pathlen := @ERR_X509_set_proxy_pathlen;
    {$ifend}
    {$if declared(X509_set_proxy_pathlen_introduced)}
    if LibVersion < X509_set_proxy_pathlen_introduced then
    begin
      {$if declared(FC_X509_set_proxy_pathlen)}
      X509_set_proxy_pathlen := @FC_X509_set_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_proxy_pathlen_removed)}
    if X509_set_proxy_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_set_proxy_pathlen)}
      X509_set_proxy_pathlen := @_X509_set_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_proxy_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_proxy_pathlen');
    {$ifend}
  end;


  X509_get_proxy_pathlen := LoadLibFunction(ADllHandle, X509_get_proxy_pathlen_procname);
  FuncLoadError := not assigned(X509_get_proxy_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_proxy_pathlen_allownil)}
    X509_get_proxy_pathlen := @ERR_X509_get_proxy_pathlen;
    {$ifend}
    {$if declared(X509_get_proxy_pathlen_introduced)}
    if LibVersion < X509_get_proxy_pathlen_introduced then
    begin
      {$if declared(FC_X509_get_proxy_pathlen)}
      X509_get_proxy_pathlen := @FC_X509_get_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_proxy_pathlen_removed)}
    if X509_get_proxy_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_get_proxy_pathlen)}
      X509_get_proxy_pathlen := @_X509_get_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_proxy_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_proxy_pathlen');
    {$ifend}
  end;


  X509_get_extension_flags := LoadLibFunction(ADllHandle, X509_get_extension_flags_procname);
  FuncLoadError := not assigned(X509_get_extension_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_extension_flags_allownil)}
    X509_get_extension_flags := @ERR_X509_get_extension_flags;
    {$ifend}
    {$if declared(X509_get_extension_flags_introduced)}
    if LibVersion < X509_get_extension_flags_introduced then
    begin
      {$if declared(FC_X509_get_extension_flags)}
      X509_get_extension_flags := @FC_X509_get_extension_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_extension_flags_removed)}
    if X509_get_extension_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_get_extension_flags)}
      X509_get_extension_flags := @_X509_get_extension_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_extension_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_extension_flags');
    {$ifend}
  end;


  X509_get_key_usage := LoadLibFunction(ADllHandle, X509_get_key_usage_procname);
  FuncLoadError := not assigned(X509_get_key_usage);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_key_usage_allownil)}
    X509_get_key_usage := @ERR_X509_get_key_usage;
    {$ifend}
    {$if declared(X509_get_key_usage_introduced)}
    if LibVersion < X509_get_key_usage_introduced then
    begin
      {$if declared(FC_X509_get_key_usage)}
      X509_get_key_usage := @FC_X509_get_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_key_usage_removed)}
    if X509_get_key_usage_removed <= LibVersion then
    begin
      {$if declared(_X509_get_key_usage)}
      X509_get_key_usage := @_X509_get_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_key_usage_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_key_usage');
    {$ifend}
  end;


  X509_get_extended_key_usage := LoadLibFunction(ADllHandle, X509_get_extended_key_usage_procname);
  FuncLoadError := not assigned(X509_get_extended_key_usage);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_extended_key_usage_allownil)}
    X509_get_extended_key_usage := @ERR_X509_get_extended_key_usage;
    {$ifend}
    {$if declared(X509_get_extended_key_usage_introduced)}
    if LibVersion < X509_get_extended_key_usage_introduced then
    begin
      {$if declared(FC_X509_get_extended_key_usage)}
      X509_get_extended_key_usage := @FC_X509_get_extended_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_extended_key_usage_removed)}
    if X509_get_extended_key_usage_removed <= LibVersion then
    begin
      {$if declared(_X509_get_extended_key_usage)}
      X509_get_extended_key_usage := @_X509_get_extended_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_extended_key_usage_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_extended_key_usage');
    {$ifend}
  end;


  X509_get0_subject_key_id := LoadLibFunction(ADllHandle, X509_get0_subject_key_id_procname);
  FuncLoadError := not assigned(X509_get0_subject_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_subject_key_id_allownil)}
    X509_get0_subject_key_id := @ERR_X509_get0_subject_key_id;
    {$ifend}
    {$if declared(X509_get0_subject_key_id_introduced)}
    if LibVersion < X509_get0_subject_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_subject_key_id)}
      X509_get0_subject_key_id := @FC_X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_subject_key_id_removed)}
    if X509_get0_subject_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_subject_key_id)}
      X509_get0_subject_key_id := @_X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_subject_key_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_subject_key_id');
    {$ifend}
  end;


  X509_get0_authority_key_id := LoadLibFunction(ADllHandle, X509_get0_authority_key_id_procname);
  FuncLoadError := not assigned(X509_get0_authority_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_key_id_allownil)}
    X509_get0_authority_key_id := @ERR_X509_get0_authority_key_id;
    {$ifend}
    {$if declared(X509_get0_authority_key_id_introduced)}
    if LibVersion < X509_get0_authority_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_authority_key_id)}
      X509_get0_authority_key_id := @FC_X509_get0_authority_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_key_id_removed)}
    if X509_get0_authority_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_key_id)}
      X509_get0_authority_key_id := @_X509_get0_authority_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_key_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_key_id');
    {$ifend}
  end;


  X509_get0_authority_serial := LoadLibFunction(ADllHandle, X509_get0_authority_serial_procname);
  FuncLoadError := not assigned(X509_get0_authority_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_serial_allownil)}
    X509_get0_authority_serial := @ERR_X509_get0_authority_serial;
    {$ifend}
    {$if declared(X509_get0_authority_serial_introduced)}
    if LibVersion < X509_get0_authority_serial_introduced then
    begin
      {$if declared(FC_X509_get0_authority_serial)}
      X509_get0_authority_serial := @FC_X509_get0_authority_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_serial_removed)}
    if X509_get0_authority_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_serial)}
      X509_get0_authority_serial := @_X509_get0_authority_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_serial');
    {$ifend}
  end;


  X509_PURPOSE_get_count := LoadLibFunction(ADllHandle, X509_PURPOSE_get_count_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_count_allownil)}
    X509_PURPOSE_get_count := @ERR_X509_PURPOSE_get_count;
    {$ifend}
    {$if declared(X509_PURPOSE_get_count_introduced)}
    if LibVersion < X509_PURPOSE_get_count_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_count)}
      X509_PURPOSE_get_count := @FC_X509_PURPOSE_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_count_removed)}
    if X509_PURPOSE_get_count_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_count)}
      X509_PURPOSE_get_count := @_X509_PURPOSE_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_count');
    {$ifend}
  end;


  X509_PURPOSE_get0 := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_allownil)}
    X509_PURPOSE_get0 := @ERR_X509_PURPOSE_get0;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_introduced)}
    if LibVersion < X509_PURPOSE_get0_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0)}
      X509_PURPOSE_get0 := @FC_X509_PURPOSE_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_removed)}
    if X509_PURPOSE_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0)}
      X509_PURPOSE_get0 := @_X509_PURPOSE_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0');
    {$ifend}
  end;


  X509_PURPOSE_get_by_sname := LoadLibFunction(ADllHandle, X509_PURPOSE_get_by_sname_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_by_sname);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_by_sname_allownil)}
    X509_PURPOSE_get_by_sname := @ERR_X509_PURPOSE_get_by_sname;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_sname_introduced)}
    if LibVersion < X509_PURPOSE_get_by_sname_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_by_sname)}
      X509_PURPOSE_get_by_sname := @FC_X509_PURPOSE_get_by_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_sname_removed)}
    if X509_PURPOSE_get_by_sname_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_by_sname)}
      X509_PURPOSE_get_by_sname := @_X509_PURPOSE_get_by_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_by_sname_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_by_sname');
    {$ifend}
  end;


  X509_PURPOSE_get_by_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_by_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_by_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_by_id_allownil)}
    X509_PURPOSE_get_by_id := @ERR_X509_PURPOSE_get_by_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_id_introduced)}
    if LibVersion < X509_PURPOSE_get_by_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_by_id)}
      X509_PURPOSE_get_by_id := @FC_X509_PURPOSE_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_id_removed)}
    if X509_PURPOSE_get_by_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_by_id)}
      X509_PURPOSE_get_by_id := @_X509_PURPOSE_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_by_id');
    {$ifend}
  end;


  X509_PURPOSE_get0_name := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_name_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_name_allownil)}
    X509_PURPOSE_get0_name := @ERR_X509_PURPOSE_get0_name;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_name_introduced)}
    if LibVersion < X509_PURPOSE_get0_name_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0_name)}
      X509_PURPOSE_get0_name := @FC_X509_PURPOSE_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_name_removed)}
    if X509_PURPOSE_get0_name_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0_name)}
      X509_PURPOSE_get0_name := @_X509_PURPOSE_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0_name');
    {$ifend}
  end;


  X509_PURPOSE_get0_sname := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_sname_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0_sname);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_sname_allownil)}
    X509_PURPOSE_get0_sname := @ERR_X509_PURPOSE_get0_sname;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_sname_introduced)}
    if LibVersion < X509_PURPOSE_get0_sname_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0_sname)}
      X509_PURPOSE_get0_sname := @FC_X509_PURPOSE_get0_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_sname_removed)}
    if X509_PURPOSE_get0_sname_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0_sname)}
      X509_PURPOSE_get0_sname := @_X509_PURPOSE_get0_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_sname_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0_sname');
    {$ifend}
  end;


  X509_PURPOSE_get_trust := LoadLibFunction(ADllHandle, X509_PURPOSE_get_trust_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_trust_allownil)}
    X509_PURPOSE_get_trust := @ERR_X509_PURPOSE_get_trust;
    {$ifend}
    {$if declared(X509_PURPOSE_get_trust_introduced)}
    if LibVersion < X509_PURPOSE_get_trust_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_trust)}
      X509_PURPOSE_get_trust := @FC_X509_PURPOSE_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_trust_removed)}
    if X509_PURPOSE_get_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_trust)}
      X509_PURPOSE_get_trust := @_X509_PURPOSE_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_trust');
    {$ifend}
  end;


  X509_PURPOSE_cleanup := LoadLibFunction(ADllHandle, X509_PURPOSE_cleanup_procname);
  FuncLoadError := not assigned(X509_PURPOSE_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_cleanup_allownil)}
    X509_PURPOSE_cleanup := @ERR_X509_PURPOSE_cleanup;
    {$ifend}
    {$if declared(X509_PURPOSE_cleanup_introduced)}
    if LibVersion < X509_PURPOSE_cleanup_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_cleanup)}
      X509_PURPOSE_cleanup := @FC_X509_PURPOSE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_cleanup_removed)}
    if X509_PURPOSE_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_cleanup)}
      X509_PURPOSE_cleanup := @_X509_PURPOSE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_cleanup');
    {$ifend}
  end;


  X509_PURPOSE_get_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    X509_PURPOSE_get_id := @ERR_X509_PURPOSE_get_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_id_introduced)}
    if LibVersion < X509_PURPOSE_get_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_id)}
      X509_PURPOSE_get_id := @FC_X509_PURPOSE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_id_removed)}
    if X509_PURPOSE_get_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_id)}
      X509_PURPOSE_get_id := @_X509_PURPOSE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_id');
    {$ifend}
  end;


  X509_check_host := LoadLibFunction(ADllHandle, X509_check_host_procname);
  FuncLoadError := not assigned(X509_check_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_host_allownil)}
    X509_check_host := @ERR_X509_check_host;
    {$ifend}
    {$if declared(X509_check_host_introduced)}
    if LibVersion < X509_check_host_introduced then
    begin
      {$if declared(FC_X509_check_host)}
      X509_check_host := @FC_X509_check_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_host_removed)}
    if X509_check_host_removed <= LibVersion then
    begin
      {$if declared(_X509_check_host)}
      X509_check_host := @_X509_check_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_host');
    {$ifend}
  end;


  X509_check_email := LoadLibFunction(ADllHandle, X509_check_email_procname);
  FuncLoadError := not assigned(X509_check_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_email_allownil)}
    X509_check_email := @ERR_X509_check_email;
    {$ifend}
    {$if declared(X509_check_email_introduced)}
    if LibVersion < X509_check_email_introduced then
    begin
      {$if declared(FC_X509_check_email)}
      X509_check_email := @FC_X509_check_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_email_removed)}
    if X509_check_email_removed <= LibVersion then
    begin
      {$if declared(_X509_check_email)}
      X509_check_email := @_X509_check_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_email');
    {$ifend}
  end;


  X509_check_ip := LoadLibFunction(ADllHandle, X509_check_ip_procname);
  FuncLoadError := not assigned(X509_check_ip);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ip_allownil)}
    X509_check_ip := @ERR_X509_check_ip;
    {$ifend}
    {$if declared(X509_check_ip_introduced)}
    if LibVersion < X509_check_ip_introduced then
    begin
      {$if declared(FC_X509_check_ip)}
      X509_check_ip := @FC_X509_check_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ip_removed)}
    if X509_check_ip_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ip)}
      X509_check_ip := @_X509_check_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ip_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ip');
    {$ifend}
  end;


  X509_check_ip_asc := LoadLibFunction(ADllHandle, X509_check_ip_asc_procname);
  FuncLoadError := not assigned(X509_check_ip_asc);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ip_asc_allownil)}
    X509_check_ip_asc := @ERR_X509_check_ip_asc;
    {$ifend}
    {$if declared(X509_check_ip_asc_introduced)}
    if LibVersion < X509_check_ip_asc_introduced then
    begin
      {$if declared(FC_X509_check_ip_asc)}
      X509_check_ip_asc := @FC_X509_check_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ip_asc_removed)}
    if X509_check_ip_asc_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ip_asc)}
      X509_check_ip_asc := @_X509_check_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ip_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ip_asc');
    {$ifend}
  end;


  a2i_IPADDRESS := LoadLibFunction(ADllHandle, a2i_IPADDRESS_procname);
  FuncLoadError := not assigned(a2i_IPADDRESS);
  if FuncLoadError then
  begin
    {$if not defined(a2i_IPADDRESS_allownil)}
    a2i_IPADDRESS := @ERR_a2i_IPADDRESS;
    {$ifend}
    {$if declared(a2i_IPADDRESS_introduced)}
    if LibVersion < a2i_IPADDRESS_introduced then
    begin
      {$if declared(FC_a2i_IPADDRESS)}
      a2i_IPADDRESS := @FC_a2i_IPADDRESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_IPADDRESS_removed)}
    if a2i_IPADDRESS_removed <= LibVersion then
    begin
      {$if declared(_a2i_IPADDRESS)}
      a2i_IPADDRESS := @_a2i_IPADDRESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_IPADDRESS_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_IPADDRESS');
    {$ifend}
  end;


  a2i_IPADDRESS_NC := LoadLibFunction(ADllHandle, a2i_IPADDRESS_NC_procname);
  FuncLoadError := not assigned(a2i_IPADDRESS_NC);
  if FuncLoadError then
  begin
    {$if not defined(a2i_IPADDRESS_NC_allownil)}
    a2i_IPADDRESS_NC := @ERR_a2i_IPADDRESS_NC;
    {$ifend}
    {$if declared(a2i_IPADDRESS_NC_introduced)}
    if LibVersion < a2i_IPADDRESS_NC_introduced then
    begin
      {$if declared(FC_a2i_IPADDRESS_NC)}
      a2i_IPADDRESS_NC := @FC_a2i_IPADDRESS_NC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_IPADDRESS_NC_removed)}
    if a2i_IPADDRESS_NC_removed <= LibVersion then
    begin
      {$if declared(_a2i_IPADDRESS_NC)}
      a2i_IPADDRESS_NC := @_a2i_IPADDRESS_NC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_IPADDRESS_NC_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_IPADDRESS_NC');
    {$ifend}
  end;


  X509_POLICY_NODE_print := LoadLibFunction(ADllHandle, X509_POLICY_NODE_print_procname);
  FuncLoadError := not assigned(X509_POLICY_NODE_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_POLICY_NODE_print_allownil)}
    X509_POLICY_NODE_print := @ERR_X509_POLICY_NODE_print;
    {$ifend}
    {$if declared(X509_POLICY_NODE_print_introduced)}
    if LibVersion < X509_POLICY_NODE_print_introduced then
    begin
      {$if declared(FC_X509_POLICY_NODE_print)}
      X509_POLICY_NODE_print := @FC_X509_POLICY_NODE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_POLICY_NODE_print_removed)}
    if X509_POLICY_NODE_print_removed <= LibVersion then
    begin
      {$if declared(_X509_POLICY_NODE_print)}
      X509_POLICY_NODE_print := @_X509_POLICY_NODE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_POLICY_NODE_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_POLICY_NODE_print');
    {$ifend}
  end;


  X509v3_addr_get_range := LoadLibFunction(ADllHandle, X509v3_addr_get_range_procname);
  FuncLoadError := not assigned(X509v3_addr_get_range);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_get_range_allownil)}
    X509v3_addr_get_range := @ERR_X509v3_addr_get_range;
    {$ifend}
    {$if declared(X509v3_addr_get_range_introduced)}
    if LibVersion < X509v3_addr_get_range_introduced then
    begin
      {$if declared(FC_X509v3_addr_get_range)}
      X509v3_addr_get_range := @FC_X509v3_addr_get_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_get_range_removed)}
    if X509v3_addr_get_range_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_get_range)}
      X509v3_addr_get_range := @_X509v3_addr_get_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_get_range_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_get_range');
    {$ifend}
  end;


  X509v3_asid_validate_path := LoadLibFunction(ADllHandle, X509v3_asid_validate_path_procname);
  FuncLoadError := not assigned(X509v3_asid_validate_path);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_validate_path_allownil)}
    X509v3_asid_validate_path := @ERR_X509v3_asid_validate_path;
    {$ifend}
    {$if declared(X509v3_asid_validate_path_introduced)}
    if LibVersion < X509v3_asid_validate_path_introduced then
    begin
      {$if declared(FC_X509v3_asid_validate_path)}
      X509v3_asid_validate_path := @FC_X509v3_asid_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_validate_path_removed)}
    if X509v3_asid_validate_path_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_validate_path)}
      X509v3_asid_validate_path := @_X509v3_asid_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_validate_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_validate_path');
    {$ifend}
  end;


  X509v3_addr_validate_path := LoadLibFunction(ADllHandle, X509v3_addr_validate_path_procname);
  FuncLoadError := not assigned(X509v3_addr_validate_path);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_validate_path_allownil)}
    X509v3_addr_validate_path := @ERR_X509v3_addr_validate_path;
    {$ifend}
    {$if declared(X509v3_addr_validate_path_introduced)}
    if LibVersion < X509v3_addr_validate_path_introduced then
    begin
      {$if declared(FC_X509v3_addr_validate_path)}
      X509v3_addr_validate_path := @FC_X509v3_addr_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_validate_path_removed)}
    if X509v3_addr_validate_path_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_validate_path)}
      X509v3_addr_validate_path := @_X509v3_addr_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_validate_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_validate_path');
    {$ifend}
  end;


  NAMING_AUTHORITY_get0_authorityId := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityId_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityId);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityId_allownil)}
    NAMING_AUTHORITY_get0_authorityId := @ERR_NAMING_AUTHORITY_get0_authorityId;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityId_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityId_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityId)}
      NAMING_AUTHORITY_get0_authorityId := @FC_NAMING_AUTHORITY_get0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityId_removed)}
    if NAMING_AUTHORITY_get0_authorityId_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityId)}
      NAMING_AUTHORITY_get0_authorityId := @_NAMING_AUTHORITY_get0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityId_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityId');
    {$ifend}
  end;


  NAMING_AUTHORITY_get0_authorityURL := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityURL_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityURL);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityURL_allownil)}
    NAMING_AUTHORITY_get0_authorityURL := @ERR_NAMING_AUTHORITY_get0_authorityURL;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityURL_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityURL_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityURL)}
      NAMING_AUTHORITY_get0_authorityURL := @FC_NAMING_AUTHORITY_get0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityURL_removed)}
    if NAMING_AUTHORITY_get0_authorityURL_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityURL)}
      NAMING_AUTHORITY_get0_authorityURL := @_NAMING_AUTHORITY_get0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityURL_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityURL');
    {$ifend}
  end;


  NAMING_AUTHORITY_get0_authorityText := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityText_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityText);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityText_allownil)}
    NAMING_AUTHORITY_get0_authorityText := @ERR_NAMING_AUTHORITY_get0_authorityText;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityText_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityText_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityText)}
      NAMING_AUTHORITY_get0_authorityText := @FC_NAMING_AUTHORITY_get0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityText_removed)}
    if NAMING_AUTHORITY_get0_authorityText_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityText)}
      NAMING_AUTHORITY_get0_authorityText := @_NAMING_AUTHORITY_get0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityText_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityText');
    {$ifend}
  end;


  NAMING_AUTHORITY_set0_authorityId := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityId_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityId);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityId_allownil)}
    NAMING_AUTHORITY_set0_authorityId := @ERR_NAMING_AUTHORITY_set0_authorityId;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityId_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityId_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityId)}
      NAMING_AUTHORITY_set0_authorityId := @FC_NAMING_AUTHORITY_set0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityId_removed)}
    if NAMING_AUTHORITY_set0_authorityId_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityId)}
      NAMING_AUTHORITY_set0_authorityId := @_NAMING_AUTHORITY_set0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityId_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityId');
    {$ifend}
  end;


  NAMING_AUTHORITY_set0_authorityURL := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityURL_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityURL);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityURL_allownil)}
    NAMING_AUTHORITY_set0_authorityURL := @ERR_NAMING_AUTHORITY_set0_authorityURL;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityURL_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityURL_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityURL)}
      NAMING_AUTHORITY_set0_authorityURL := @FC_NAMING_AUTHORITY_set0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityURL_removed)}
    if NAMING_AUTHORITY_set0_authorityURL_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityURL)}
      NAMING_AUTHORITY_set0_authorityURL := @_NAMING_AUTHORITY_set0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityURL_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityURL');
    {$ifend}
  end;


  NAMING_AUTHORITY_set0_authorityText := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityText_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityText);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityText_allownil)}
    NAMING_AUTHORITY_set0_authorityText := @ERR_NAMING_AUTHORITY_set0_authorityText;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityText_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityText_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityText)}
      NAMING_AUTHORITY_set0_authorityText := @FC_NAMING_AUTHORITY_set0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityText_removed)}
    if NAMING_AUTHORITY_set0_authorityText_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityText)}
      NAMING_AUTHORITY_set0_authorityText := @_NAMING_AUTHORITY_set0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityText_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityText');
    {$ifend}
  end;


  ADMISSION_SYNTAX_get0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_get0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_get0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_get0_admissionAuthority_allownil)}
    ADMISSION_SYNTAX_get0_admissionAuthority := @ERR_ADMISSION_SYNTAX_get0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_admissionAuthority_introduced)}
    if LibVersion < ADMISSION_SYNTAX_get0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_get0_admissionAuthority)}
      ADMISSION_SYNTAX_get0_admissionAuthority := @FC_ADMISSION_SYNTAX_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_admissionAuthority_removed)}
    if ADMISSION_SYNTAX_get0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_get0_admissionAuthority)}
      ADMISSION_SYNTAX_get0_admissionAuthority := @_ADMISSION_SYNTAX_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_get0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_get0_admissionAuthority');
    {$ifend}
  end;


  ADMISSION_SYNTAX_set0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_set0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_set0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_set0_admissionAuthority_allownil)}
    ADMISSION_SYNTAX_set0_admissionAuthority := @ERR_ADMISSION_SYNTAX_set0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_admissionAuthority_introduced)}
    if LibVersion < ADMISSION_SYNTAX_set0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_set0_admissionAuthority)}
      ADMISSION_SYNTAX_set0_admissionAuthority := @FC_ADMISSION_SYNTAX_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_admissionAuthority_removed)}
    if ADMISSION_SYNTAX_set0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_set0_admissionAuthority)}
      ADMISSION_SYNTAX_set0_admissionAuthority := @_ADMISSION_SYNTAX_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_set0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_set0_admissionAuthority');
    {$ifend}
  end;


  ADMISSIONS_get0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_get0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_admissionAuthority_allownil)}
    ADMISSIONS_get0_admissionAuthority := @ERR_ADMISSIONS_get0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_get0_admissionAuthority_introduced)}
    if LibVersion < ADMISSIONS_get0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_admissionAuthority)}
      ADMISSIONS_get0_admissionAuthority := @FC_ADMISSIONS_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_admissionAuthority_removed)}
    if ADMISSIONS_get0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_admissionAuthority)}
      ADMISSIONS_get0_admissionAuthority := @_ADMISSIONS_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_admissionAuthority');
    {$ifend}
  end;


  ADMISSIONS_set0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_set0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_admissionAuthority_allownil)}
    ADMISSIONS_set0_admissionAuthority := @ERR_ADMISSIONS_set0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_set0_admissionAuthority_introduced)}
    if LibVersion < ADMISSIONS_set0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_admissionAuthority)}
      ADMISSIONS_set0_admissionAuthority := @FC_ADMISSIONS_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_admissionAuthority_removed)}
    if ADMISSIONS_set0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_admissionAuthority)}
      ADMISSIONS_set0_admissionAuthority := @_ADMISSIONS_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_admissionAuthority');
    {$ifend}
  end;


  ADMISSIONS_get0_namingAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_get0_namingAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_namingAuthority_allownil)}
    ADMISSIONS_get0_namingAuthority := @ERR_ADMISSIONS_get0_namingAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_get0_namingAuthority_introduced)}
    if LibVersion < ADMISSIONS_get0_namingAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_namingAuthority)}
      ADMISSIONS_get0_namingAuthority := @FC_ADMISSIONS_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_namingAuthority_removed)}
    if ADMISSIONS_get0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_namingAuthority)}
      ADMISSIONS_get0_namingAuthority := @_ADMISSIONS_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_namingAuthority');
    {$ifend}
  end;


  ADMISSIONS_set0_namingAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_set0_namingAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_namingAuthority_allownil)}
    ADMISSIONS_set0_namingAuthority := @ERR_ADMISSIONS_set0_namingAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_set0_namingAuthority_introduced)}
    if LibVersion < ADMISSIONS_set0_namingAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_namingAuthority)}
      ADMISSIONS_set0_namingAuthority := @FC_ADMISSIONS_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_namingAuthority_removed)}
    if ADMISSIONS_set0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_namingAuthority)}
      ADMISSIONS_set0_namingAuthority := @_ADMISSIONS_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_namingAuthority');
    {$ifend}
  end;


  PROFESSION_INFO_get0_addProfessionInfo := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_addProfessionInfo_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_addProfessionInfo);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_addProfessionInfo_allownil)}
    PROFESSION_INFO_get0_addProfessionInfo := @ERR_PROFESSION_INFO_get0_addProfessionInfo;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_addProfessionInfo_introduced)}
    if LibVersion < PROFESSION_INFO_get0_addProfessionInfo_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_addProfessionInfo)}
      PROFESSION_INFO_get0_addProfessionInfo := @FC_PROFESSION_INFO_get0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_addProfessionInfo_removed)}
    if PROFESSION_INFO_get0_addProfessionInfo_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_addProfessionInfo)}
      PROFESSION_INFO_get0_addProfessionInfo := @_PROFESSION_INFO_get0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_addProfessionInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_addProfessionInfo');
    {$ifend}
  end;


  PROFESSION_INFO_set0_addProfessionInfo := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_addProfessionInfo_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_addProfessionInfo);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_addProfessionInfo_allownil)}
    PROFESSION_INFO_set0_addProfessionInfo := @ERR_PROFESSION_INFO_set0_addProfessionInfo;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_addProfessionInfo_introduced)}
    if LibVersion < PROFESSION_INFO_set0_addProfessionInfo_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_addProfessionInfo)}
      PROFESSION_INFO_set0_addProfessionInfo := @FC_PROFESSION_INFO_set0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_addProfessionInfo_removed)}
    if PROFESSION_INFO_set0_addProfessionInfo_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_addProfessionInfo)}
      PROFESSION_INFO_set0_addProfessionInfo := @_PROFESSION_INFO_set0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_addProfessionInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_addProfessionInfo');
    {$ifend}
  end;


  PROFESSION_INFO_get0_namingAuthority := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_namingAuthority_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_namingAuthority_allownil)}
    PROFESSION_INFO_get0_namingAuthority := @ERR_PROFESSION_INFO_get0_namingAuthority;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_namingAuthority_introduced)}
    if LibVersion < PROFESSION_INFO_get0_namingAuthority_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_namingAuthority)}
      PROFESSION_INFO_get0_namingAuthority := @FC_PROFESSION_INFO_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_namingAuthority_removed)}
    if PROFESSION_INFO_get0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_namingAuthority)}
      PROFESSION_INFO_get0_namingAuthority := @_PROFESSION_INFO_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_namingAuthority');
    {$ifend}
  end;


  PROFESSION_INFO_set0_namingAuthority := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_namingAuthority_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_namingAuthority_allownil)}
    PROFESSION_INFO_set0_namingAuthority := @ERR_PROFESSION_INFO_set0_namingAuthority;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_namingAuthority_introduced)}
    if LibVersion < PROFESSION_INFO_set0_namingAuthority_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_namingAuthority)}
      PROFESSION_INFO_set0_namingAuthority := @FC_PROFESSION_INFO_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_namingAuthority_removed)}
    if PROFESSION_INFO_set0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_namingAuthority)}
      PROFESSION_INFO_set0_namingAuthority := @_PROFESSION_INFO_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_namingAuthority');
    {$ifend}
  end;


  PROFESSION_INFO_get0_registrationNumber := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_registrationNumber_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_registrationNumber);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_registrationNumber_allownil)}
    PROFESSION_INFO_get0_registrationNumber := @ERR_PROFESSION_INFO_get0_registrationNumber;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_registrationNumber_introduced)}
    if LibVersion < PROFESSION_INFO_get0_registrationNumber_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_registrationNumber)}
      PROFESSION_INFO_get0_registrationNumber := @FC_PROFESSION_INFO_get0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_registrationNumber_removed)}
    if PROFESSION_INFO_get0_registrationNumber_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_registrationNumber)}
      PROFESSION_INFO_get0_registrationNumber := @_PROFESSION_INFO_get0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_registrationNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_registrationNumber');
    {$ifend}
  end;


  PROFESSION_INFO_set0_registrationNumber := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_registrationNumber_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_registrationNumber);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_registrationNumber_allownil)}
    PROFESSION_INFO_set0_registrationNumber := @ERR_PROFESSION_INFO_set0_registrationNumber;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_registrationNumber_introduced)}
    if LibVersion < PROFESSION_INFO_set0_registrationNumber_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_registrationNumber)}
      PROFESSION_INFO_set0_registrationNumber := @FC_PROFESSION_INFO_set0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_registrationNumber_removed)}
    if PROFESSION_INFO_set0_registrationNumber_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_registrationNumber)}
      PROFESSION_INFO_set0_registrationNumber := @_PROFESSION_INFO_set0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_registrationNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_registrationNumber');
    {$ifend}
  end;


end;

procedure Unload;
begin
  GENERAL_NAME_cmp := nil;
  GENERAL_NAME_print := nil;
  OTHERNAME_cmp := nil;
  GENERAL_NAME_set0_value := nil;
  GENERAL_NAME_get0_value := nil;
  GENERAL_NAME_set0_othername := nil;
  GENERAL_NAME_get0_otherName := nil;
  i2a_ACCESS_DESCRIPTION := nil;
  DIST_POINT_set_dpname := nil;
  NAME_CONSTRAINTS_check := nil;
  NAME_CONSTRAINTS_check_CN := nil;
  X509V3_EXT_nconf_nid := nil;
  X509V3_EXT_nconf := nil;
  X509V3_EXT_add_nconf := nil;
  X509V3_EXT_REQ_add_nconf := nil;
  X509V3_EXT_CRL_add_nconf := nil;
  X509V3_EXT_conf_nid := nil;
  X509V3_EXT_conf := nil;
  X509V3_EXT_add_conf := nil;
  X509V3_EXT_REQ_add_conf := nil;
  X509V3_EXT_CRL_add_conf := nil;
  X509V3_set_nconf := nil;
  X509V3_get_string := nil;
  X509V3_string_free := nil;
  X509V3_set_ctx := nil;
  X509V3_EXT_add_alias := nil;
  X509V3_EXT_cleanup := nil;
  X509V3_add_standard_extensions := nil;
  X509V3_EXT_d2i := nil;
  X509V3_EXT_i2d := nil;
  X509V3_EXT_print := nil;
  X509_check_ca := nil;
  X509_check_purpose := nil;
  X509_supported_extension := nil;
  X509_PURPOSE_set := nil;
  X509_check_issued := nil;
  X509_check_akid := nil;
  X509_set_proxy_flag := nil;
  X509_set_proxy_pathlen := nil;
  X509_get_proxy_pathlen := nil;
  X509_get_extension_flags := nil;
  X509_get_key_usage := nil;
  X509_get_extended_key_usage := nil;
  X509_get0_subject_key_id := nil;
  X509_get0_authority_key_id := nil;
  X509_get0_authority_serial := nil;
  X509_PURPOSE_get_count := nil;
  X509_PURPOSE_get0 := nil;
  X509_PURPOSE_get_by_sname := nil;
  X509_PURPOSE_get_by_id := nil;
  X509_PURPOSE_get0_name := nil;
  X509_PURPOSE_get0_sname := nil;
  X509_PURPOSE_get_trust := nil;
  X509_PURPOSE_cleanup := nil;
  X509_PURPOSE_get_id := nil;
  X509_check_host := nil;
  X509_check_email := nil;
  X509_check_ip := nil;
  X509_check_ip_asc := nil;
  a2i_IPADDRESS := nil;
  a2i_IPADDRESS_NC := nil;
  X509_POLICY_NODE_print := nil;
  X509v3_addr_get_range := nil;
  X509v3_asid_validate_path := nil;
  X509v3_addr_validate_path := nil;
  NAMING_AUTHORITY_get0_authorityId := nil;
  NAMING_AUTHORITY_get0_authorityURL := nil;
  NAMING_AUTHORITY_get0_authorityText := nil;
  NAMING_AUTHORITY_set0_authorityId := nil;
  NAMING_AUTHORITY_set0_authorityURL := nil;
  NAMING_AUTHORITY_set0_authorityText := nil;
  ADMISSION_SYNTAX_get0_admissionAuthority := nil;
  ADMISSION_SYNTAX_set0_admissionAuthority := nil;
  ADMISSIONS_get0_admissionAuthority := nil;
  ADMISSIONS_set0_admissionAuthority := nil;
  ADMISSIONS_get0_namingAuthority := nil;
  ADMISSIONS_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_addProfessionInfo := nil;
  PROFESSION_INFO_set0_addProfessionInfo := nil;
  PROFESSION_INFO_get0_namingAuthority := nil;
  PROFESSION_INFO_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_registrationNumber := nil;
  PROFESSION_INFO_set0_registrationNumber := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
