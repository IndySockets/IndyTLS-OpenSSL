  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_pem.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_pem.h2pas
     and this file regenerated. IdOpenSSLHeaders_pem.h2pas is distributed with the full Indy
     Distribution.
   *)
   
{$i IdCompilerDefines.inc} 
{$i IdSSLOpenSSLDefines.inc} 

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

unit IdOpenSSLHeaders_pem;

interface

// Headers for OpenSSL 1.1.1
// pem.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSL110Consts,
  IdOpenSSLHeaders_ec,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_pkcs7,
  IdOpenSSLHeaders_x509;

type
  EVP_CIPHER_INFO = type Pointer;
  PEVP_CIPHER_INFO = ^EVP_CIPHER_INFO;

const
  PEM_BUFSIZE             = 1024;

  PEM_STRING_X509_OLD     = AnsiString('X509 CERTIFICATE');
  PEM_STRING_X509         = AnsiString('CERTIFICATE');
  PEM_STRING_X509_TRUSTED = AnsiString('TRUSTED CERTIFICATE');
  PEM_STRING_X509_REQ_OLD = AnsiString('NEW CERTIFICATE REQUEST');
  PEM_STRING_X509_REQ     = AnsiString('CERTIFICATE REQUEST');
  PEM_STRING_X509_CRL     = AnsiString('X509 CRL');
  PEM_STRING_EVP_PKEY     = AnsiString('ANY PRIVATE KEY');
  PEM_STRING_PUBLIC       = AnsiString('PUBLIC KEY');
  PEM_STRING_RSA          = AnsiString('RSA PRIVATE KEY');
  PEM_STRING_RSA_PUBLIC   = AnsiString('RSA PUBLIC KEY');
  PEM_STRING_DSA          = AnsiString('DSA PRIVATE KEY');
  PEM_STRING_DSA_PUBLIC   = AnsiString('DSA PUBLIC KEY');
  PEM_STRING_PKCS7        = AnsiString('PKCS7');
  PEM_STRING_PKCS7_SIGNED = AnsiString('PKCS #7 SIGNED DATA');
  PEM_STRING_PKCS8        = AnsiString('ENCRYPTED PRIVATE KEY');
  PEM_STRING_PKCS8INF     = AnsiString('PRIVATE KEY');
  PEM_STRING_DHPARAMS     = AnsiString('DH PARAMETERS');
  PEM_STRING_DHXPARAMS    = AnsiString('X9.42 DH PARAMETERS');
  PEM_STRING_SSL_SESSION  = AnsiString('SSL SESSION PARAMETERS');
  PEM_STRING_DSAPARAMS    = AnsiString('DSA PARAMETERS');
  PEM_STRING_ECDSA_PUBLIC = AnsiString('ECDSA PUBLIC KEY');
  PEM_STRING_ECPARAMETERS = AnsiString('EC PARAMETERS');
  PEM_STRING_ECPRIVATEKEY = AnsiString('EC PRIVATE KEY');
  PEM_STRING_PARAMETERS   = AnsiString('PARAMETERS');
  PEM_STRING_CMS          = AnsiString('CMS');

  PEM_TYPE_ENCRYPTED      = 10;
  PEM_TYPE_MIC_ONLY       = 20;
  PEM_TYPE_MIC_CLEAR      = 30;
  PEM_TYPE_CLEAR          = 40;

  PEM_FLAG_SECURE         = $1;
  PEM_FLAG_EAY_COMPATIBLE = $2;
  PEM_FLAG_ONLY_B64       = $4;

  {Reason Codes}
  PEM_R_BAD_BASE64_DECODE			= 100;
  PEM_R_BAD_DECRYPT				= 101;
  PEM_R_BAD_END_LINE				= 102;
  PEM_R_BAD_IV_CHARS				= 103;
  PEM_R_BAD_MAGIC_NUMBER			= 116;
  PEM_R_BAD_PASSWORD_READ			= 104;
  PEM_R_BAD_VERSION_NUMBER			= 117;
  PEM_R_BIO_WRITE_FAILURE			= 118;
  PEM_R_CIPHER_IS_NULL				= 127;
  PEM_R_ERROR_CONVERTING_PRIVATE_KEY		= 115;
  PEM_R_EXPECTING_PRIVATE_KEY_BLOB		= 119;
  PEM_R_EXPECTING_PUBLIC_KEY_BLOB		= 120;
  PEM_R_HEADER_TOO_LONG				= 128;
  PEM_R_INCONSISTENT_HEADER			= 121;
  PEM_R_KEYBLOB_HEADER_PARSE_ERROR		= 122;
  PEM_R_KEYBLOB_TOO_SHORT			= 123;
  PEM_R_NOT_DEK_INFO				= 105;
  PEM_R_NOT_ENCRYPTED				= 106;
  PEM_R_NOT_PROC_TYPE				= 107;
  PEM_R_NO_START_LINE				= 108;
  PEM_R_PROBLEMS_GETTING_PASSWORD	        = 109;
  PEM_R_PUBLIC_KEY_NO_RSA			= 110;
  PEM_R_PVK_DATA_TOO_SHORT		        = 124;
  PEM_R_PVK_TOO_SHORT				= 125;
  PEM_R_READ_KEY				= 111;
  PEM_R_SHORT_HEADER				= 112;
  PEM_R_UNSUPPORTED_CIPHER			= 113;
  PEM_R_UNSUPPORTED_ENCRYPTION			= 114;

type
  PSTACK_OF_X509_INFO = pointer;
  pem_password_cb = function(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM PEM_get_EVP_CIPHER_INFO}
  {$EXTERNALSYM PEM_do_header}
  {$EXTERNALSYM PEM_read_bio}
  {$EXTERNALSYM PEM_read_bio_ex} {introduced 1.1.0}
  {$EXTERNALSYM PEM_bytes_read_bio_secmem} {introduced 1.1.0}
  {$EXTERNALSYM PEM_write_bio}
  {$EXTERNALSYM PEM_bytes_read_bio}
  {$EXTERNALSYM PEM_ASN1_read_bio}
  {$EXTERNALSYM PEM_ASN1_write_bio}
  {$EXTERNALSYM PEM_X509_INFO_read_bio}
  {$EXTERNALSYM PEM_X509_INFO_write_bio}
  {$EXTERNALSYM PEM_SignInit}
  {$EXTERNALSYM PEM_SignUpdate}
  {$EXTERNALSYM PEM_SignFinal}
  {$EXTERNALSYM PEM_def_callback}
  {$EXTERNALSYM PEM_proc_type}
  {$EXTERNALSYM PEM_dek_info}
  {$EXTERNALSYM PEM_read_bio_X509}
  {$EXTERNALSYM PEM_write_bio_X509}
  {$EXTERNALSYM PEM_read_bio_X509_AUX}
  {$EXTERNALSYM PEM_write_bio_X509_AUX}
  {$EXTERNALSYM PEM_read_bio_X509_REQ}
  {$EXTERNALSYM PEM_write_bio_X509_REQ}
  {$EXTERNALSYM PEM_write_bio_X509_REQ_NEW}
  {$EXTERNALSYM PEM_read_bio_X509_CRL}
  {$EXTERNALSYM PEM_write_bio_X509_CRL}
  {$EXTERNALSYM PEM_read_bio_PKCS7}
  {$EXTERNALSYM PEM_write_bio_PKCS7}
  {$EXTERNALSYM PEM_read_bio_PKCS8}
  {$EXTERNALSYM PEM_write_bio_PKCS8}
  {$EXTERNALSYM PEM_read_bio_PKCS8_PRIV_KEY_INFO}
  {$EXTERNALSYM PEM_write_bio_PKCS8_PRIV_KEY_INFO}
  {$EXTERNALSYM PEM_read_bio_RSAPrivateKey}
  {$EXTERNALSYM PEM_write_bio_RSAPrivateKey}
  {$EXTERNALSYM PEM_read_bio_RSAPublicKey}
  {$EXTERNALSYM PEM_write_bio_RSAPublicKey}
  {$EXTERNALSYM PEM_read_bio_RSA_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_RSA_PUBKEY}
  {$EXTERNALSYM PEM_read_bio_DSAPrivateKey}
  {$EXTERNALSYM PEM_write_bio_DSAPrivateKey}
  {$EXTERNALSYM PEM_read_bio_DSA_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_DSA_PUBKEY}
  {$EXTERNALSYM PEM_read_bio_DSAparams}
  {$EXTERNALSYM PEM_write_bio_DSAparams}
  {$EXTERNALSYM PEM_read_bio_ECPKParameters}
  {$EXTERNALSYM PEM_write_bio_ECPKParameters}
  {$EXTERNALSYM PEM_read_bio_ECPrivateKey}
  {$EXTERNALSYM PEM_write_bio_ECPrivateKey}
  {$EXTERNALSYM PEM_read_bio_EC_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_EC_PUBKEY}
  {$EXTERNALSYM PEM_read_bio_DHparams}
  {$EXTERNALSYM PEM_write_bio_DHparams}
  {$EXTERNALSYM PEM_write_bio_DHxparams}
  {$EXTERNALSYM PEM_read_bio_PrivateKey}
  {$EXTERNALSYM PEM_write_bio_PrivateKey}
  {$EXTERNALSYM PEM_read_bio_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_PUBKEY}
  {$EXTERNALSYM PEM_write_bio_PrivateKey_traditional} {introduced 1.1.0}
  {$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey_nid}
  {$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey}
  {$EXTERNALSYM i2d_PKCS8PrivateKey_bio}
  {$EXTERNALSYM i2d_PKCS8PrivateKey_nid_bio}
  {$EXTERNALSYM d2i_PKCS8PrivateKey_bio}
  {$EXTERNALSYM PEM_read_bio_Parameters}
  {$EXTERNALSYM PEM_write_bio_Parameters}
  {$EXTERNALSYM b2i_PrivateKey}
  {$EXTERNALSYM b2i_PublicKey}
  {$EXTERNALSYM b2i_PrivateKey_bio}
  {$EXTERNALSYM b2i_PublicKey_bio}
  {$EXTERNALSYM i2b_PrivateKey_bio}
  {$EXTERNALSYM i2b_PublicKey_bio}
  {$EXTERNALSYM b2i_PVK_bio}
  {$EXTERNALSYM i2b_PVK_bio}

{$IFNDEF USE_EXTERNAL_LIBRARY}
var
  PEM_get_EVP_CIPHER_INFO: function (header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT; cdecl = nil;
  PEM_do_header: function (cipher: PEVP_CIPHER_INFO; data: PByte; len: PIdC_LONG; callback: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_read_bio: function (bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPByte; len: PIdC_LONG): TIdC_INT; cdecl = nil;
  PEM_read_bio_ex: function (bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPByte; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  PEM_bytes_read_bio_secmem: function (pdata: PPByte; plen: PIdC_LONG; pnm: PPIdAnsiChar; const name: PIdAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  PEM_write_bio: function (bp: PBIO; const name: PIdAnsiChar; const hdr: PIdAnsiChar; const data: PByte; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  PEM_bytes_read_bio: function (pdata: PPByte; plen: PIdC_LONG; pnm: PPIdAnsiChar; const name: PIdAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;
  PEM_ASN1_read_bio: function (d2i: d2i_of_void; const name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl = nil;
  PEM_ASN1_write_bio: function (i2d: i2d_of_void; const name: PIdAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_X509_INFO_read_bio: function (bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl = nil;
  PEM_X509_INFO_write_bio: function (bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cd: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_SignInit: function (ctx: PEVP_MD_CTX; type_: PEVP_MD): TIdC_INT; cdecl = nil;
  PEM_SignUpdate: function (ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TIdC_INT; cdecl = nil;
  PEM_SignFinal: function (ctx: PEVP_MD_CTX; sigret: PByte; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  (* The default pem_password_cb that's used internally *)
  PEM_def_callback: function (buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl = nil;
  PEM_proc_type: procedure (buf: PIdAnsiChar; type_: TIdC_INT); cdecl = nil;
  PEM_dek_info: procedure (buf: PIdAnsiChar; const type_: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar); cdecl = nil;

  PEM_read_bio_X509: function (bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl = nil;
  PEM_write_bio_X509: function (bp: PBIO; x: PX509): TIdC_INT; cdecl = nil;

  PEM_read_bio_X509_AUX: function (bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl = nil;
  PEM_write_bio_X509_AUX: function (bp: PBIO; x: PX509): TIdC_INT; cdecl = nil;

  PEM_read_bio_X509_REQ: function (bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl = nil;
  PEM_write_bio_X509_REQ: function (bp: PBIO; x: PX509_REQ): TIdC_INT; cdecl = nil;

  PEM_write_bio_X509_REQ_NEW: function (bp: PBIO; x: PX509_REQ): TIdC_INT; cdecl = nil;

  PEM_read_bio_X509_CRL: function (bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl = nil;
  PEM_write_bio_X509_CRL: function (bp: PBIO; x: PX509_CRL): TIdC_INT; cdecl = nil;

  PEM_read_bio_PKCS7: function (bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl = nil;
  PEM_write_bio_PKCS7: function (bp: PBIO; x: PPKCS7): TIdC_INT; cdecl = nil;

//  function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE;
//  function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT;

  PEM_read_bio_PKCS8: function (bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl = nil;
  PEM_write_bio_PKCS8: function (bp: PBIO; x: PX509_SIG): TIdC_INT; cdecl = nil;

  PEM_read_bio_PKCS8_PRIV_KEY_INFO: function (bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO: function (bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;

  // RSA
  PEM_read_bio_RSAPrivateKey: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSAPrivateKey: function (bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_read_bio_RSAPublicKey: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSAPublicKey: function (bp: PBIO; const x: PRSA): TIdC_INT; cdecl = nil;

  PEM_read_bio_RSA_PUBKEY: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSA_PUBKEY: function (bp: PBIO; x: PRSA): TIdC_INT; cdecl = nil;
  // ~RSA

  // DSA
  PEM_read_bio_DSAPrivateKey: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
  PEM_write_bio_DSAPrivateKey: function (bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_read_bio_DSA_PUBKEY: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
  PEM_write_bio_DSA_PUBKEY: function (bp: PBIO; x: PDSA): TIdC_INT; cdecl = nil;

  PEM_read_bio_DSAparams: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
  PEM_write_bio_DSAparams: function (bp: PBIO; const x: PDSA): TIdC_INT; cdecl = nil;
  // ~DSA

  // EC
  PEM_read_bio_ECPKParameters: function (bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl = nil;
  PEM_write_bio_ECPKParameters: function (bp: PBIO; const x: PEC_GROUP): TIdC_INT; cdecl = nil;

  PEM_read_bio_ECPrivateKey: function (bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl = nil;
  PEM_write_bio_ECPrivateKey: function (bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_read_bio_EC_PUBKEY: function (bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl = nil;
  PEM_write_bio_EC_PUBKEY: function (bp: PBIO; x: PEC_KEY): TIdC_INT; cdecl = nil;
  // ~EC

  // DH
  PEM_read_bio_DHparams: function (bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl = nil;
  PEM_write_bio_DHparams: function (bp: PBIO; const x: PDH): TIdC_INT; cdecl = nil;

  PEM_write_bio_DHxparams: function (bp: PBIO; const x: PDH): TIdC_INT; cdecl = nil;
  // ~DH

  PEM_read_bio_PrivateKey: function (bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_PrivateKey: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

  PEM_read_bio_PUBKEY: function (bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_PUBKEY: function (bp: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl = nil;

  PEM_write_bio_PrivateKey_traditional: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  PEM_write_bio_PKCS8PrivateKey_nid: function (bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;
  PEM_write_bio_PKCS8PrivateKey: function (bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;
  i2d_PKCS8PrivateKey_bio: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;
  i2d_PKCS8PrivateKey_nid_bio: function (bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;
  d2i_PKCS8PrivateKey_bio: function (bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;

  PEM_read_bio_Parameters: function (bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_Parameters: function (bp: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl = nil;

  b2i_PrivateKey: function (const in_: PPByte; length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  b2i_PublicKey: function (const in_: PPByte; length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  b2i_PrivateKey_bio: function (in_: PBIO): PEVP_PKEY; cdecl = nil;
  b2i_PublicKey_bio: function (in_: PBIO): PEVP_PKEY; cdecl = nil;
  i2b_PrivateKey_bio: function (out_: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  i2b_PublicKey_bio: function (out_: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  b2i_PVK_bio: function (in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  i2b_PVK_bio: function (out_: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; cdecl = nil;

{$ELSE}
  function PEM_get_EVP_CIPHER_INFO(header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: PIdC_LONG; callback: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPByte; len: PIdC_LONG): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_read_bio_ex(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPByte; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF}; {introduced 1.1.0}
  function PEM_bytes_read_bio_secmem(pdata: PPByte; plen: PIdC_LONG; pnm: PPIdAnsiChar; const name: PIdAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF}; {introduced 1.1.0}
  function PEM_write_bio(bp: PBIO; const name: PIdAnsiChar; const hdr: PIdAnsiChar; const data: PByte; len: TIdC_LONG): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_bytes_read_bio(pdata: PPByte; plen: PIdC_LONG; pnm: PPIdAnsiChar; const name: PIdAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PIdAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cd: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* The default pem_password_cb that's used internally *)
  function PEM_def_callback(buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure PEM_proc_type(buf: PIdAnsiChar; type_: TIdC_INT) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure PEM_dek_info(buf: PIdAnsiChar; const type_: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509 cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_X509(bp: PBIO; x: PX509): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509 cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7 cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

//  function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE;
//  function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT;

  function PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  // RSA
  function PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  // ~RSA

  // DSA
  function PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  // ~DSA

  // EC
  function PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  // ~EC

  // DH
  function PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  // ~DH

  function PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF}; {introduced 1.1.0}
  function PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function b2i_PrivateKey(const in_: PPByte; length: TIdC_LONG): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function b2i_PublicKey(const in_: PPByte; length: TIdC_LONG): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF USE_EXTERNAL_LIBRARY}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  
const
  PEM_read_bio_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_bytes_read_bio_secmem_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_PrivateKey_traditional_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

{$IFNDEF USE_EXTERNAL_LIBRARY}
const
  PEM_get_EVP_CIPHER_INFO_procname = 'PEM_get_EVP_CIPHER_INFO';
  PEM_do_header_procname = 'PEM_do_header';

  PEM_read_bio_procname = 'PEM_read_bio';
  PEM_read_bio_ex_procname = 'PEM_read_bio_ex'; {introduced 1.1.0}
  PEM_bytes_read_bio_secmem_procname = 'PEM_bytes_read_bio_secmem'; {introduced 1.1.0}
  PEM_write_bio_procname = 'PEM_write_bio';
  PEM_bytes_read_bio_procname = 'PEM_bytes_read_bio';
  PEM_ASN1_read_bio_procname = 'PEM_ASN1_read_bio';
  PEM_ASN1_write_bio_procname = 'PEM_ASN1_write_bio';

  PEM_X509_INFO_read_bio_procname = 'PEM_X509_INFO_read_bio';
  PEM_X509_INFO_write_bio_procname = 'PEM_X509_INFO_write_bio';

  PEM_SignInit_procname = 'PEM_SignInit';
  PEM_SignUpdate_procname = 'PEM_SignUpdate';
  PEM_SignFinal_procname = 'PEM_SignFinal';

  (* The default pem_password_cb that's used internally *)
  PEM_def_callback_procname = 'PEM_def_callback';
  PEM_proc_type_procname = 'PEM_proc_type';
  PEM_dek_info_procname = 'PEM_dek_info';

  PEM_read_bio_X509_procname = 'PEM_read_bio_X509';
  PEM_write_bio_X509_procname = 'PEM_write_bio_X509';

  PEM_read_bio_X509_AUX_procname = 'PEM_read_bio_X509_AUX';
  PEM_write_bio_X509_AUX_procname = 'PEM_write_bio_X509_AUX';

  PEM_read_bio_X509_REQ_procname = 'PEM_read_bio_X509_REQ';
  PEM_write_bio_X509_REQ_procname = 'PEM_write_bio_X509_REQ';

  PEM_write_bio_X509_REQ_NEW_procname = 'PEM_write_bio_X509_REQ_NEW';

  PEM_read_bio_X509_CRL_procname = 'PEM_read_bio_X509_CRL';
  PEM_write_bio_X509_CRL_procname = 'PEM_write_bio_X509_CRL';

  PEM_read_bio_PKCS7_procname = 'PEM_read_bio_PKCS7';
  PEM_write_bio_PKCS7_procname = 'PEM_write_bio_PKCS7';

//  function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE;
//  function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT;

  PEM_read_bio_PKCS8_procname = 'PEM_read_bio_PKCS8';
  PEM_write_bio_PKCS8_procname = 'PEM_write_bio_PKCS8';

  PEM_read_bio_PKCS8_PRIV_KEY_INFO_procname = 'PEM_read_bio_PKCS8_PRIV_KEY_INFO';
  PEM_write_bio_PKCS8_PRIV_KEY_INFO_procname = 'PEM_write_bio_PKCS8_PRIV_KEY_INFO';

  // RSA
  PEM_read_bio_RSAPrivateKey_procname = 'PEM_read_bio_RSAPrivateKey';
  PEM_write_bio_RSAPrivateKey_procname = 'PEM_write_bio_RSAPrivateKey';

  PEM_read_bio_RSAPublicKey_procname = 'PEM_read_bio_RSAPublicKey';
  PEM_write_bio_RSAPublicKey_procname = 'PEM_write_bio_RSAPublicKey';

  PEM_read_bio_RSA_PUBKEY_procname = 'PEM_read_bio_RSA_PUBKEY';
  PEM_write_bio_RSA_PUBKEY_procname = 'PEM_write_bio_RSA_PUBKEY';
  // ~RSA

  // DSA
  PEM_read_bio_DSAPrivateKey_procname = 'PEM_read_bio_DSAPrivateKey';
  PEM_write_bio_DSAPrivateKey_procname = 'PEM_write_bio_DSAPrivateKey';

  PEM_read_bio_DSA_PUBKEY_procname = 'PEM_read_bio_DSA_PUBKEY';
  PEM_write_bio_DSA_PUBKEY_procname = 'PEM_write_bio_DSA_PUBKEY';

  PEM_read_bio_DSAparams_procname = 'PEM_read_bio_DSAparams';
  PEM_write_bio_DSAparams_procname = 'PEM_write_bio_DSAparams';
  // ~DSA

  // EC
  PEM_read_bio_ECPKParameters_procname = 'PEM_read_bio_ECPKParameters';
  PEM_write_bio_ECPKParameters_procname = 'PEM_write_bio_ECPKParameters';

  PEM_read_bio_ECPrivateKey_procname = 'PEM_read_bio_ECPrivateKey';
  PEM_write_bio_ECPrivateKey_procname = 'PEM_write_bio_ECPrivateKey';

  PEM_read_bio_EC_PUBKEY_procname = 'PEM_read_bio_EC_PUBKEY';
  PEM_write_bio_EC_PUBKEY_procname = 'PEM_write_bio_EC_PUBKEY';
  // ~EC

  // DH
  PEM_read_bio_DHparams_procname = 'PEM_read_bio_DHparams';
  PEM_write_bio_DHparams_procname = 'PEM_write_bio_DHparams';

  PEM_write_bio_DHxparams_procname = 'PEM_write_bio_DHxparams';
  // ~DH

  PEM_read_bio_PrivateKey_procname = 'PEM_read_bio_PrivateKey';
  PEM_write_bio_PrivateKey_procname = 'PEM_write_bio_PrivateKey';

  PEM_read_bio_PUBKEY_procname = 'PEM_read_bio_PUBKEY';
  PEM_write_bio_PUBKEY_procname = 'PEM_write_bio_PUBKEY';

  PEM_write_bio_PrivateKey_traditional_procname = 'PEM_write_bio_PrivateKey_traditional'; {introduced 1.1.0}
  PEM_write_bio_PKCS8PrivateKey_nid_procname = 'PEM_write_bio_PKCS8PrivateKey_nid';
  PEM_write_bio_PKCS8PrivateKey_procname = 'PEM_write_bio_PKCS8PrivateKey';
  i2d_PKCS8PrivateKey_bio_procname = 'i2d_PKCS8PrivateKey_bio';
  i2d_PKCS8PrivateKey_nid_bio_procname = 'i2d_PKCS8PrivateKey_nid_bio';
  d2i_PKCS8PrivateKey_bio_procname = 'd2i_PKCS8PrivateKey_bio';

  PEM_read_bio_Parameters_procname = 'PEM_read_bio_Parameters';
  PEM_write_bio_Parameters_procname = 'PEM_write_bio_Parameters';

  b2i_PrivateKey_procname = 'b2i_PrivateKey';
  b2i_PublicKey_procname = 'b2i_PublicKey';
  b2i_PrivateKey_bio_procname = 'b2i_PrivateKey_bio';
  b2i_PublicKey_bio_procname = 'b2i_PublicKey_bio';
  i2b_PrivateKey_bio_procname = 'i2b_PrivateKey_bio';
  i2b_PublicKey_bio_procname = 'i2b_PublicKey_bio';
  b2i_PVK_bio_procname = 'b2i_PVK_bio';
  i2b_PVK_bio_procname = 'i2b_PVK_bio';


{$WARN  NO_RETVAL OFF}
function  ERR_PEM_get_EVP_CIPHER_INFO(header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_get_EVP_CIPHER_INFO_procname);
end;


function  ERR_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: PIdC_LONG; callback: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_do_header_procname);
end;



function  ERR_PEM_read_bio(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPByte; len: PIdC_LONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_procname);
end;


function  ERR_PEM_read_bio_ex(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPByte; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_PEM_bytes_read_bio_secmem(pdata: PPByte; plen: PIdC_LONG; pnm: PPIdAnsiChar; const name: PIdAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_bytes_read_bio_secmem_procname);
end;

 {introduced 1.1.0}
function  ERR_PEM_write_bio(bp: PBIO; const name: PIdAnsiChar; const hdr: PIdAnsiChar; const data: PByte; len: TIdC_LONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_procname);
end;


function  ERR_PEM_bytes_read_bio(pdata: PPByte; plen: PIdC_LONG; pnm: PPIdAnsiChar; const name: PIdAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_bytes_read_bio_procname);
end;


function  ERR_PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_ASN1_read_bio_procname);
end;


function  ERR_PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PIdAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_ASN1_write_bio_procname);
end;



function  ERR_PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_read_bio_procname);
end;


function  ERR_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cd: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_write_bio_procname);
end;



function  ERR_PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_SignInit_procname);
end;


function  ERR_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_SignUpdate_procname);
end;


function  ERR_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_SignFinal_procname);
end;



  (* The default pem_password_cb that's used internally *)
function  ERR_PEM_def_callback(buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_def_callback_procname);
end;


procedure  ERR_PEM_proc_type(buf: PIdAnsiChar; type_: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_proc_type_procname);
end;


procedure  ERR_PEM_dek_info(buf: PIdAnsiChar; const type_: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_dek_info_procname);
end;



function  ERR_PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_procname);
end;


function  ERR_PEM_write_bio_X509(bp: PBIO; x: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_procname);
end;



function  ERR_PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_AUX_procname);
end;


function  ERR_PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_AUX_procname);
end;



function  ERR_PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_REQ_procname);
end;


function  ERR_PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_REQ_procname);
end;



function  ERR_PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_REQ_NEW_procname);
end;



function  ERR_PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_CRL_procname);
end;


function  ERR_PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_CRL_procname);
end;



function  ERR_PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_PKCS7_procname);
end;


function  ERR_PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS7_procname);
end;



//  function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE;
//  function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(bp: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT;

function  ERR_PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_PKCS8_procname);
end;


function  ERR_PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8_procname);
end;



function  ERR_PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_PKCS8_PRIV_KEY_INFO_procname);
end;


function  ERR_PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8_PRIV_KEY_INFO_procname);
end;



  // RSA
function  ERR_PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_RSAPrivateKey_procname);
end;


function  ERR_PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_RSAPrivateKey_procname);
end;



function  ERR_PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_RSAPublicKey_procname);
end;


function  ERR_PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_RSAPublicKey_procname);
end;



function  ERR_PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_RSA_PUBKEY_procname);
end;


function  ERR_PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_RSA_PUBKEY_procname);
end;


  // ~RSA

  // DSA
function  ERR_PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_DSAPrivateKey_procname);
end;


function  ERR_PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_DSAPrivateKey_procname);
end;



function  ERR_PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_DSA_PUBKEY_procname);
end;


function  ERR_PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_DSA_PUBKEY_procname);
end;



function  ERR_PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_DSAparams_procname);
end;


function  ERR_PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_DSAparams_procname);
end;


  // ~DSA

  // EC
function  ERR_PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_ECPKParameters_procname);
end;


function  ERR_PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_ECPKParameters_procname);
end;



function  ERR_PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_ECPrivateKey_procname);
end;


function  ERR_PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_ECPrivateKey_procname);
end;



function  ERR_PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_EC_PUBKEY_procname);
end;


function  ERR_PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_EC_PUBKEY_procname);
end;


  // ~EC

  // DH
function  ERR_PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_DHparams_procname);
end;


function  ERR_PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_DHparams_procname);
end;



function  ERR_PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_DHxparams_procname);
end;


  // ~DH

function  ERR_PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_PrivateKey_procname);
end;


function  ERR_PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PrivateKey_procname);
end;



function  ERR_PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_PUBKEY_procname);
end;


function  ERR_PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PUBKEY_procname);
end;



function  ERR_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PrivateKey_traditional_procname);
end;

 {introduced 1.1.0}
function  ERR_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8PrivateKey_nid_procname);
end;


function  ERR_PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8PrivateKey_procname);
end;


function  ERR_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKey_bio_procname);
end;


function  ERR_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKey_nid_bio_procname);
end;


function  ERR_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(d2i_PKCS8PrivateKey_bio_procname);
end;



function  ERR_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_read_bio_Parameters_procname);
end;


function  ERR_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_Parameters_procname);
end;



function  ERR_b2i_PrivateKey(const in_: PPByte; length: TIdC_LONG): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(b2i_PrivateKey_procname);
end;


function  ERR_b2i_PublicKey(const in_: PPByte; length: TIdC_LONG): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(b2i_PublicKey_procname);
end;


function  ERR_b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(b2i_PrivateKey_bio_procname);
end;


function  ERR_b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(b2i_PublicKey_bio_procname);
end;


function  ERR_i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2b_PrivateKey_bio_procname);
end;


function  ERR_i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2b_PublicKey_bio_procname);
end;


function  ERR_b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; 
begin
  EIdAPIFunctionNotPresent.RaiseException(b2i_PVK_bio_procname);
end;


function  ERR_i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: pem_password_cb; u: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2b_PVK_bio_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  PEM_get_EVP_CIPHER_INFO := LoadLibFunction(ADllHandle, PEM_get_EVP_CIPHER_INFO_procname);
  FuncLoadError := not assigned(PEM_get_EVP_CIPHER_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_get_EVP_CIPHER_INFO_allownil)}
    PEM_get_EVP_CIPHER_INFO := @ERR_PEM_get_EVP_CIPHER_INFO;
    {$ifend}
    {$if declared(PEM_get_EVP_CIPHER_INFO_introduced)}
    if LibVersion < PEM_get_EVP_CIPHER_INFO_introduced then
    begin
      {$if declared(FC_PEM_get_EVP_CIPHER_INFO)}
      PEM_get_EVP_CIPHER_INFO := @FC_PEM_get_EVP_CIPHER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_get_EVP_CIPHER_INFO_removed)}
    if PEM_get_EVP_CIPHER_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_get_EVP_CIPHER_INFO)}
      PEM_get_EVP_CIPHER_INFO := @_PEM_get_EVP_CIPHER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_get_EVP_CIPHER_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_get_EVP_CIPHER_INFO');
    {$ifend}
  end;


  PEM_do_header := LoadLibFunction(ADllHandle, PEM_do_header_procname);
  FuncLoadError := not assigned(PEM_do_header);
  if FuncLoadError then
  begin
    {$if not defined(PEM_do_header_allownil)}
    PEM_do_header := @ERR_PEM_do_header;
    {$ifend}
    {$if declared(PEM_do_header_introduced)}
    if LibVersion < PEM_do_header_introduced then
    begin
      {$if declared(FC_PEM_do_header)}
      PEM_do_header := @FC_PEM_do_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_do_header_removed)}
    if PEM_do_header_removed <= LibVersion then
    begin
      {$if declared(_PEM_do_header)}
      PEM_do_header := @_PEM_do_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_do_header_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_do_header');
    {$ifend}
  end;


  PEM_read_bio := LoadLibFunction(ADllHandle, PEM_read_bio_procname);
  FuncLoadError := not assigned(PEM_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_allownil)}
    PEM_read_bio := @ERR_PEM_read_bio;
    {$ifend}
    {$if declared(PEM_read_bio_introduced)}
    if LibVersion < PEM_read_bio_introduced then
    begin
      {$if declared(FC_PEM_read_bio)}
      PEM_read_bio := @FC_PEM_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_removed)}
    if PEM_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio)}
      PEM_read_bio := @_PEM_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio');
    {$ifend}
  end;


  PEM_read_bio_ex := LoadLibFunction(ADllHandle, PEM_read_bio_ex_procname);
  FuncLoadError := not assigned(PEM_read_bio_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_ex_allownil)}
    PEM_read_bio_ex := @ERR_PEM_read_bio_ex;
    {$ifend}
    {$if declared(PEM_read_bio_ex_introduced)}
    if LibVersion < PEM_read_bio_ex_introduced then
    begin
      {$if declared(FC_PEM_read_bio_ex)}
      PEM_read_bio_ex := @FC_PEM_read_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_ex_removed)}
    if PEM_read_bio_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_ex)}
      PEM_read_bio_ex := @_PEM_read_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_ex');
    {$ifend}
  end;

 {introduced 1.1.0}
  PEM_bytes_read_bio_secmem := LoadLibFunction(ADllHandle, PEM_bytes_read_bio_secmem_procname);
  FuncLoadError := not assigned(PEM_bytes_read_bio_secmem);
  if FuncLoadError then
  begin
    {$if not defined(PEM_bytes_read_bio_secmem_allownil)}
    PEM_bytes_read_bio_secmem := @ERR_PEM_bytes_read_bio_secmem;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_secmem_introduced)}
    if LibVersion < PEM_bytes_read_bio_secmem_introduced then
    begin
      {$if declared(FC_PEM_bytes_read_bio_secmem)}
      PEM_bytes_read_bio_secmem := @FC_PEM_bytes_read_bio_secmem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_secmem_removed)}
    if PEM_bytes_read_bio_secmem_removed <= LibVersion then
    begin
      {$if declared(_PEM_bytes_read_bio_secmem)}
      PEM_bytes_read_bio_secmem := @_PEM_bytes_read_bio_secmem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_bytes_read_bio_secmem_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_bytes_read_bio_secmem');
    {$ifend}
  end;

 {introduced 1.1.0}
  PEM_write_bio := LoadLibFunction(ADllHandle, PEM_write_bio_procname);
  FuncLoadError := not assigned(PEM_write_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_allownil)}
    PEM_write_bio := @ERR_PEM_write_bio;
    {$ifend}
    {$if declared(PEM_write_bio_introduced)}
    if LibVersion < PEM_write_bio_introduced then
    begin
      {$if declared(FC_PEM_write_bio)}
      PEM_write_bio := @FC_PEM_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_removed)}
    if PEM_write_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio)}
      PEM_write_bio := @_PEM_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio');
    {$ifend}
  end;


  PEM_bytes_read_bio := LoadLibFunction(ADllHandle, PEM_bytes_read_bio_procname);
  FuncLoadError := not assigned(PEM_bytes_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_bytes_read_bio_allownil)}
    PEM_bytes_read_bio := @ERR_PEM_bytes_read_bio;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_introduced)}
    if LibVersion < PEM_bytes_read_bio_introduced then
    begin
      {$if declared(FC_PEM_bytes_read_bio)}
      PEM_bytes_read_bio := @FC_PEM_bytes_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_removed)}
    if PEM_bytes_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_bytes_read_bio)}
      PEM_bytes_read_bio := @_PEM_bytes_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_bytes_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_bytes_read_bio');
    {$ifend}
  end;


  PEM_ASN1_read_bio := LoadLibFunction(ADllHandle, PEM_ASN1_read_bio_procname);
  FuncLoadError := not assigned(PEM_ASN1_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_read_bio_allownil)}
    PEM_ASN1_read_bio := @ERR_PEM_ASN1_read_bio;
    {$ifend}
    {$if declared(PEM_ASN1_read_bio_introduced)}
    if LibVersion < PEM_ASN1_read_bio_introduced then
    begin
      {$if declared(FC_PEM_ASN1_read_bio)}
      PEM_ASN1_read_bio := @FC_PEM_ASN1_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_read_bio_removed)}
    if PEM_ASN1_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_read_bio)}
      PEM_ASN1_read_bio := @_PEM_ASN1_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_read_bio');
    {$ifend}
  end;


  PEM_ASN1_write_bio := LoadLibFunction(ADllHandle, PEM_ASN1_write_bio_procname);
  FuncLoadError := not assigned(PEM_ASN1_write_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_write_bio_allownil)}
    PEM_ASN1_write_bio := @ERR_PEM_ASN1_write_bio;
    {$ifend}
    {$if declared(PEM_ASN1_write_bio_introduced)}
    if LibVersion < PEM_ASN1_write_bio_introduced then
    begin
      {$if declared(FC_PEM_ASN1_write_bio)}
      PEM_ASN1_write_bio := @FC_PEM_ASN1_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_write_bio_removed)}
    if PEM_ASN1_write_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_write_bio)}
      PEM_ASN1_write_bio := @_PEM_ASN1_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_write_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_write_bio');
    {$ifend}
  end;


  PEM_X509_INFO_read_bio := LoadLibFunction(ADllHandle, PEM_X509_INFO_read_bio_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_read_bio_allownil)}
    PEM_X509_INFO_read_bio := @ERR_PEM_X509_INFO_read_bio;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_bio_introduced)}
    if LibVersion < PEM_X509_INFO_read_bio_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_read_bio)}
      PEM_X509_INFO_read_bio := @FC_PEM_X509_INFO_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_bio_removed)}
    if PEM_X509_INFO_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_read_bio)}
      PEM_X509_INFO_read_bio := @_PEM_X509_INFO_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_read_bio');
    {$ifend}
  end;


  PEM_X509_INFO_write_bio := LoadLibFunction(ADllHandle, PEM_X509_INFO_write_bio_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_write_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_write_bio_allownil)}
    PEM_X509_INFO_write_bio := @ERR_PEM_X509_INFO_write_bio;
    {$ifend}
    {$if declared(PEM_X509_INFO_write_bio_introduced)}
    if LibVersion < PEM_X509_INFO_write_bio_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_write_bio)}
      PEM_X509_INFO_write_bio := @FC_PEM_X509_INFO_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_write_bio_removed)}
    if PEM_X509_INFO_write_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_write_bio)}
      PEM_X509_INFO_write_bio := @_PEM_X509_INFO_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_write_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_write_bio');
    {$ifend}
  end;


  PEM_SignInit := LoadLibFunction(ADllHandle, PEM_SignInit_procname);
  FuncLoadError := not assigned(PEM_SignInit);
  if FuncLoadError then
  begin
    {$if not defined(PEM_SignInit_allownil)}
    PEM_SignInit := @ERR_PEM_SignInit;
    {$ifend}
    {$if declared(PEM_SignInit_introduced)}
    if LibVersion < PEM_SignInit_introduced then
    begin
      {$if declared(FC_PEM_SignInit)}
      PEM_SignInit := @FC_PEM_SignInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_SignInit_removed)}
    if PEM_SignInit_removed <= LibVersion then
    begin
      {$if declared(_PEM_SignInit)}
      PEM_SignInit := @_PEM_SignInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_SignInit_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_SignInit');
    {$ifend}
  end;


  PEM_SignUpdate := LoadLibFunction(ADllHandle, PEM_SignUpdate_procname);
  FuncLoadError := not assigned(PEM_SignUpdate);
  if FuncLoadError then
  begin
    {$if not defined(PEM_SignUpdate_allownil)}
    PEM_SignUpdate := @ERR_PEM_SignUpdate;
    {$ifend}
    {$if declared(PEM_SignUpdate_introduced)}
    if LibVersion < PEM_SignUpdate_introduced then
    begin
      {$if declared(FC_PEM_SignUpdate)}
      PEM_SignUpdate := @FC_PEM_SignUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_SignUpdate_removed)}
    if PEM_SignUpdate_removed <= LibVersion then
    begin
      {$if declared(_PEM_SignUpdate)}
      PEM_SignUpdate := @_PEM_SignUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_SignUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_SignUpdate');
    {$ifend}
  end;


  PEM_SignFinal := LoadLibFunction(ADllHandle, PEM_SignFinal_procname);
  FuncLoadError := not assigned(PEM_SignFinal);
  if FuncLoadError then
  begin
    {$if not defined(PEM_SignFinal_allownil)}
    PEM_SignFinal := @ERR_PEM_SignFinal;
    {$ifend}
    {$if declared(PEM_SignFinal_introduced)}
    if LibVersion < PEM_SignFinal_introduced then
    begin
      {$if declared(FC_PEM_SignFinal)}
      PEM_SignFinal := @FC_PEM_SignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_SignFinal_removed)}
    if PEM_SignFinal_removed <= LibVersion then
    begin
      {$if declared(_PEM_SignFinal)}
      PEM_SignFinal := @_PEM_SignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_SignFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_SignFinal');
    {$ifend}
  end;


  PEM_def_callback := LoadLibFunction(ADllHandle, PEM_def_callback_procname);
  FuncLoadError := not assigned(PEM_def_callback);
  if FuncLoadError then
  begin
    {$if not defined(PEM_def_callback_allownil)}
    PEM_def_callback := @ERR_PEM_def_callback;
    {$ifend}
    {$if declared(PEM_def_callback_introduced)}
    if LibVersion < PEM_def_callback_introduced then
    begin
      {$if declared(FC_PEM_def_callback)}
      PEM_def_callback := @FC_PEM_def_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_def_callback_removed)}
    if PEM_def_callback_removed <= LibVersion then
    begin
      {$if declared(_PEM_def_callback)}
      PEM_def_callback := @_PEM_def_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_def_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_def_callback');
    {$ifend}
  end;


  PEM_proc_type := LoadLibFunction(ADllHandle, PEM_proc_type_procname);
  FuncLoadError := not assigned(PEM_proc_type);
  if FuncLoadError then
  begin
    {$if not defined(PEM_proc_type_allownil)}
    PEM_proc_type := @ERR_PEM_proc_type;
    {$ifend}
    {$if declared(PEM_proc_type_introduced)}
    if LibVersion < PEM_proc_type_introduced then
    begin
      {$if declared(FC_PEM_proc_type)}
      PEM_proc_type := @FC_PEM_proc_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_proc_type_removed)}
    if PEM_proc_type_removed <= LibVersion then
    begin
      {$if declared(_PEM_proc_type)}
      PEM_proc_type := @_PEM_proc_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_proc_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_proc_type');
    {$ifend}
  end;


  PEM_dek_info := LoadLibFunction(ADllHandle, PEM_dek_info_procname);
  FuncLoadError := not assigned(PEM_dek_info);
  if FuncLoadError then
  begin
    {$if not defined(PEM_dek_info_allownil)}
    PEM_dek_info := @ERR_PEM_dek_info;
    {$ifend}
    {$if declared(PEM_dek_info_introduced)}
    if LibVersion < PEM_dek_info_introduced then
    begin
      {$if declared(FC_PEM_dek_info)}
      PEM_dek_info := @FC_PEM_dek_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_dek_info_removed)}
    if PEM_dek_info_removed <= LibVersion then
    begin
      {$if declared(_PEM_dek_info)}
      PEM_dek_info := @_PEM_dek_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_dek_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_dek_info');
    {$ifend}
  end;


  PEM_read_bio_X509 := LoadLibFunction(ADllHandle, PEM_read_bio_X509_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_allownil)}
    PEM_read_bio_X509 := @ERR_PEM_read_bio_X509;
    {$ifend}
    {$if declared(PEM_read_bio_X509_introduced)}
    if LibVersion < PEM_read_bio_X509_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509)}
      PEM_read_bio_X509 := @FC_PEM_read_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_removed)}
    if PEM_read_bio_X509_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509)}
      PEM_read_bio_X509 := @_PEM_read_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509');
    {$ifend}
  end;


  PEM_write_bio_X509 := LoadLibFunction(ADllHandle, PEM_write_bio_X509_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_allownil)}
    PEM_write_bio_X509 := @ERR_PEM_write_bio_X509;
    {$ifend}
    {$if declared(PEM_write_bio_X509_introduced)}
    if LibVersion < PEM_write_bio_X509_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509)}
      PEM_write_bio_X509 := @FC_PEM_write_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_removed)}
    if PEM_write_bio_X509_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509)}
      PEM_write_bio_X509 := @_PEM_write_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509');
    {$ifend}
  end;


  PEM_read_bio_X509_AUX := LoadLibFunction(ADllHandle, PEM_read_bio_X509_AUX_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_AUX_allownil)}
    PEM_read_bio_X509_AUX := @ERR_PEM_read_bio_X509_AUX;
    {$ifend}
    {$if declared(PEM_read_bio_X509_AUX_introduced)}
    if LibVersion < PEM_read_bio_X509_AUX_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_AUX)}
      PEM_read_bio_X509_AUX := @FC_PEM_read_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_AUX_removed)}
    if PEM_read_bio_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_AUX)}
      PEM_read_bio_X509_AUX := @_PEM_read_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_AUX');
    {$ifend}
  end;


  PEM_write_bio_X509_AUX := LoadLibFunction(ADllHandle, PEM_write_bio_X509_AUX_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_AUX_allownil)}
    PEM_write_bio_X509_AUX := @ERR_PEM_write_bio_X509_AUX;
    {$ifend}
    {$if declared(PEM_write_bio_X509_AUX_introduced)}
    if LibVersion < PEM_write_bio_X509_AUX_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_AUX)}
      PEM_write_bio_X509_AUX := @FC_PEM_write_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_AUX_removed)}
    if PEM_write_bio_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_AUX)}
      PEM_write_bio_X509_AUX := @_PEM_write_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_AUX');
    {$ifend}
  end;


  PEM_read_bio_X509_REQ := LoadLibFunction(ADllHandle, PEM_read_bio_X509_REQ_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_REQ_allownil)}
    PEM_read_bio_X509_REQ := @ERR_PEM_read_bio_X509_REQ;
    {$ifend}
    {$if declared(PEM_read_bio_X509_REQ_introduced)}
    if LibVersion < PEM_read_bio_X509_REQ_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_REQ)}
      PEM_read_bio_X509_REQ := @FC_PEM_read_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_REQ_removed)}
    if PEM_read_bio_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_REQ)}
      PEM_read_bio_X509_REQ := @_PEM_read_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_REQ');
    {$ifend}
  end;


  PEM_write_bio_X509_REQ := LoadLibFunction(ADllHandle, PEM_write_bio_X509_REQ_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_REQ_allownil)}
    PEM_write_bio_X509_REQ := @ERR_PEM_write_bio_X509_REQ;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_introduced)}
    if LibVersion < PEM_write_bio_X509_REQ_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_REQ)}
      PEM_write_bio_X509_REQ := @FC_PEM_write_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_removed)}
    if PEM_write_bio_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_REQ)}
      PEM_write_bio_X509_REQ := @_PEM_write_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_REQ');
    {$ifend}
  end;


  PEM_write_bio_X509_REQ_NEW := LoadLibFunction(ADllHandle, PEM_write_bio_X509_REQ_NEW_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_REQ_NEW);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_REQ_NEW_allownil)}
    PEM_write_bio_X509_REQ_NEW := @ERR_PEM_write_bio_X509_REQ_NEW;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_NEW_introduced)}
    if LibVersion < PEM_write_bio_X509_REQ_NEW_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_REQ_NEW)}
      PEM_write_bio_X509_REQ_NEW := @FC_PEM_write_bio_X509_REQ_NEW;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_NEW_removed)}
    if PEM_write_bio_X509_REQ_NEW_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_REQ_NEW)}
      PEM_write_bio_X509_REQ_NEW := @_PEM_write_bio_X509_REQ_NEW;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_REQ_NEW_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_REQ_NEW');
    {$ifend}
  end;


  PEM_read_bio_X509_CRL := LoadLibFunction(ADllHandle, PEM_read_bio_X509_CRL_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_CRL_allownil)}
    PEM_read_bio_X509_CRL := @ERR_PEM_read_bio_X509_CRL;
    {$ifend}
    {$if declared(PEM_read_bio_X509_CRL_introduced)}
    if LibVersion < PEM_read_bio_X509_CRL_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_CRL)}
      PEM_read_bio_X509_CRL := @FC_PEM_read_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_CRL_removed)}
    if PEM_read_bio_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_CRL)}
      PEM_read_bio_X509_CRL := @_PEM_read_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_CRL');
    {$ifend}
  end;


  PEM_write_bio_X509_CRL := LoadLibFunction(ADllHandle, PEM_write_bio_X509_CRL_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_CRL_allownil)}
    PEM_write_bio_X509_CRL := @ERR_PEM_write_bio_X509_CRL;
    {$ifend}
    {$if declared(PEM_write_bio_X509_CRL_introduced)}
    if LibVersion < PEM_write_bio_X509_CRL_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_CRL)}
      PEM_write_bio_X509_CRL := @FC_PEM_write_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_CRL_removed)}
    if PEM_write_bio_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_CRL)}
      PEM_write_bio_X509_CRL := @_PEM_write_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_CRL');
    {$ifend}
  end;


  PEM_read_bio_PKCS7 := LoadLibFunction(ADllHandle, PEM_read_bio_PKCS7_procname);
  FuncLoadError := not assigned(PEM_read_bio_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PKCS7_allownil)}
    PEM_read_bio_PKCS7 := @ERR_PEM_read_bio_PKCS7;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS7_introduced)}
    if LibVersion < PEM_read_bio_PKCS7_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PKCS7)}
      PEM_read_bio_PKCS7 := @FC_PEM_read_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS7_removed)}
    if PEM_read_bio_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PKCS7)}
      PEM_read_bio_PKCS7 := @_PEM_read_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PKCS7');
    {$ifend}
  end;


  PEM_write_bio_PKCS7 := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS7_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS7_allownil)}
    PEM_write_bio_PKCS7 := @ERR_PEM_write_bio_PKCS7;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_introduced)}
    if LibVersion < PEM_write_bio_PKCS7_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS7)}
      PEM_write_bio_PKCS7 := @FC_PEM_write_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_removed)}
    if PEM_write_bio_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS7)}
      PEM_write_bio_PKCS7 := @_PEM_write_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS7');
    {$ifend}
  end;


  PEM_read_bio_PKCS8 := LoadLibFunction(ADllHandle, PEM_read_bio_PKCS8_procname);
  FuncLoadError := not assigned(PEM_read_bio_PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PKCS8_allownil)}
    PEM_read_bio_PKCS8 := @ERR_PEM_read_bio_PKCS8;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_introduced)}
    if LibVersion < PEM_read_bio_PKCS8_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PKCS8)}
      PEM_read_bio_PKCS8 := @FC_PEM_read_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_removed)}
    if PEM_read_bio_PKCS8_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PKCS8)}
      PEM_read_bio_PKCS8 := @_PEM_read_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PKCS8');
    {$ifend}
  end;


  PEM_write_bio_PKCS8 := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8_allownil)}
    PEM_write_bio_PKCS8 := @ERR_PEM_write_bio_PKCS8;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_introduced)}
    if LibVersion < PEM_write_bio_PKCS8_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8)}
      PEM_write_bio_PKCS8 := @FC_PEM_write_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_removed)}
    if PEM_write_bio_PKCS8_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8)}
      PEM_write_bio_PKCS8 := @_PEM_write_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8');
    {$ifend}
  end;


  PEM_read_bio_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, PEM_read_bio_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(PEM_read_bio_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    PEM_read_bio_PKCS8_PRIV_KEY_INFO := @ERR_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < PEM_read_bio_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_read_bio_PKCS8_PRIV_KEY_INFO := @FC_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_PRIV_KEY_INFO_removed)}
    if PEM_read_bio_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_read_bio_PKCS8_PRIV_KEY_INFO := @_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;


  PEM_write_bio_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    PEM_write_bio_PKCS8_PRIV_KEY_INFO := @ERR_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < PEM_write_bio_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_write_bio_PKCS8_PRIV_KEY_INFO := @FC_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_PRIV_KEY_INFO_removed)}
    if PEM_write_bio_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_write_bio_PKCS8_PRIV_KEY_INFO := @_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;


  PEM_read_bio_RSAPrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_RSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_RSAPrivateKey_allownil)}
    PEM_read_bio_RSAPrivateKey := @ERR_PEM_read_bio_RSAPrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPrivateKey_introduced)}
    if LibVersion < PEM_read_bio_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_RSAPrivateKey)}
      PEM_read_bio_RSAPrivateKey := @FC_PEM_read_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPrivateKey_removed)}
    if PEM_read_bio_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_RSAPrivateKey)}
      PEM_read_bio_RSAPrivateKey := @_PEM_read_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_RSAPrivateKey');
    {$ifend}
  end;


  PEM_write_bio_RSAPrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_RSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_RSAPrivateKey_allownil)}
    PEM_write_bio_RSAPrivateKey := @ERR_PEM_write_bio_RSAPrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPrivateKey_introduced)}
    if LibVersion < PEM_write_bio_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_RSAPrivateKey)}
      PEM_write_bio_RSAPrivateKey := @FC_PEM_write_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPrivateKey_removed)}
    if PEM_write_bio_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_RSAPrivateKey)}
      PEM_write_bio_RSAPrivateKey := @_PEM_write_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_RSAPrivateKey');
    {$ifend}
  end;


  PEM_read_bio_RSAPublicKey := LoadLibFunction(ADllHandle, PEM_read_bio_RSAPublicKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_RSAPublicKey_allownil)}
    PEM_read_bio_RSAPublicKey := @ERR_PEM_read_bio_RSAPublicKey;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPublicKey_introduced)}
    if LibVersion < PEM_read_bio_RSAPublicKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_RSAPublicKey)}
      PEM_read_bio_RSAPublicKey := @FC_PEM_read_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPublicKey_removed)}
    if PEM_read_bio_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_RSAPublicKey)}
      PEM_read_bio_RSAPublicKey := @_PEM_read_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_RSAPublicKey');
    {$ifend}
  end;


  PEM_write_bio_RSAPublicKey := LoadLibFunction(ADllHandle, PEM_write_bio_RSAPublicKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_RSAPublicKey_allownil)}
    PEM_write_bio_RSAPublicKey := @ERR_PEM_write_bio_RSAPublicKey;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPublicKey_introduced)}
    if LibVersion < PEM_write_bio_RSAPublicKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_RSAPublicKey)}
      PEM_write_bio_RSAPublicKey := @FC_PEM_write_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPublicKey_removed)}
    if PEM_write_bio_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_RSAPublicKey)}
      PEM_write_bio_RSAPublicKey := @_PEM_write_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_RSAPublicKey');
    {$ifend}
  end;


  PEM_read_bio_RSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_RSA_PUBKEY_allownil)}
    PEM_read_bio_RSA_PUBKEY := @ERR_PEM_read_bio_RSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_RSA_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_RSA_PUBKEY)}
      PEM_read_bio_RSA_PUBKEY := @FC_PEM_read_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_RSA_PUBKEY_removed)}
    if PEM_read_bio_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_RSA_PUBKEY)}
      PEM_read_bio_RSA_PUBKEY := @_PEM_read_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_RSA_PUBKEY');
    {$ifend}
  end;


  PEM_write_bio_RSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_RSA_PUBKEY_allownil)}
    PEM_write_bio_RSA_PUBKEY := @ERR_PEM_write_bio_RSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_RSA_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_RSA_PUBKEY)}
      PEM_write_bio_RSA_PUBKEY := @FC_PEM_write_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_RSA_PUBKEY_removed)}
    if PEM_write_bio_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_RSA_PUBKEY)}
      PEM_write_bio_RSA_PUBKEY := @_PEM_write_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_RSA_PUBKEY');
    {$ifend}
  end;


  PEM_read_bio_DSAPrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_DSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DSAPrivateKey_allownil)}
    PEM_read_bio_DSAPrivateKey := @ERR_PEM_read_bio_DSAPrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_DSAPrivateKey_introduced)}
    if LibVersion < PEM_read_bio_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DSAPrivateKey)}
      PEM_read_bio_DSAPrivateKey := @FC_PEM_read_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DSAPrivateKey_removed)}
    if PEM_read_bio_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DSAPrivateKey)}
      PEM_read_bio_DSAPrivateKey := @_PEM_read_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DSAPrivateKey');
    {$ifend}
  end;


  PEM_write_bio_DSAPrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_DSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DSAPrivateKey_allownil)}
    PEM_write_bio_DSAPrivateKey := @ERR_PEM_write_bio_DSAPrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_DSAPrivateKey_introduced)}
    if LibVersion < PEM_write_bio_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DSAPrivateKey)}
      PEM_write_bio_DSAPrivateKey := @FC_PEM_write_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DSAPrivateKey_removed)}
    if PEM_write_bio_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DSAPrivateKey)}
      PEM_write_bio_DSAPrivateKey := @_PEM_write_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DSAPrivateKey');
    {$ifend}
  end;


  PEM_read_bio_DSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DSA_PUBKEY_allownil)}
    PEM_read_bio_DSA_PUBKEY := @ERR_PEM_read_bio_DSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_DSA_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DSA_PUBKEY)}
      PEM_read_bio_DSA_PUBKEY := @FC_PEM_read_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DSA_PUBKEY_removed)}
    if PEM_read_bio_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DSA_PUBKEY)}
      PEM_read_bio_DSA_PUBKEY := @_PEM_read_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DSA_PUBKEY');
    {$ifend}
  end;


  PEM_write_bio_DSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DSA_PUBKEY_allownil)}
    PEM_write_bio_DSA_PUBKEY := @ERR_PEM_write_bio_DSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_DSA_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DSA_PUBKEY)}
      PEM_write_bio_DSA_PUBKEY := @FC_PEM_write_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DSA_PUBKEY_removed)}
    if PEM_write_bio_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DSA_PUBKEY)}
      PEM_write_bio_DSA_PUBKEY := @_PEM_write_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DSA_PUBKEY');
    {$ifend}
  end;


  PEM_read_bio_DSAparams := LoadLibFunction(ADllHandle, PEM_read_bio_DSAparams_procname);
  FuncLoadError := not assigned(PEM_read_bio_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DSAparams_allownil)}
    PEM_read_bio_DSAparams := @ERR_PEM_read_bio_DSAparams;
    {$ifend}
    {$if declared(PEM_read_bio_DSAparams_introduced)}
    if LibVersion < PEM_read_bio_DSAparams_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DSAparams)}
      PEM_read_bio_DSAparams := @FC_PEM_read_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DSAparams_removed)}
    if PEM_read_bio_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DSAparams)}
      PEM_read_bio_DSAparams := @_PEM_read_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DSAparams');
    {$ifend}
  end;


  PEM_write_bio_DSAparams := LoadLibFunction(ADllHandle, PEM_write_bio_DSAparams_procname);
  FuncLoadError := not assigned(PEM_write_bio_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DSAparams_allownil)}
    PEM_write_bio_DSAparams := @ERR_PEM_write_bio_DSAparams;
    {$ifend}
    {$if declared(PEM_write_bio_DSAparams_introduced)}
    if LibVersion < PEM_write_bio_DSAparams_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DSAparams)}
      PEM_write_bio_DSAparams := @FC_PEM_write_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DSAparams_removed)}
    if PEM_write_bio_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DSAparams)}
      PEM_write_bio_DSAparams := @_PEM_write_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DSAparams');
    {$ifend}
  end;


  PEM_read_bio_ECPKParameters := LoadLibFunction(ADllHandle, PEM_read_bio_ECPKParameters_procname);
  FuncLoadError := not assigned(PEM_read_bio_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_ECPKParameters_allownil)}
    PEM_read_bio_ECPKParameters := @ERR_PEM_read_bio_ECPKParameters;
    {$ifend}
    {$if declared(PEM_read_bio_ECPKParameters_introduced)}
    if LibVersion < PEM_read_bio_ECPKParameters_introduced then
    begin
      {$if declared(FC_PEM_read_bio_ECPKParameters)}
      PEM_read_bio_ECPKParameters := @FC_PEM_read_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_ECPKParameters_removed)}
    if PEM_read_bio_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_ECPKParameters)}
      PEM_read_bio_ECPKParameters := @_PEM_read_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_ECPKParameters');
    {$ifend}
  end;


  PEM_write_bio_ECPKParameters := LoadLibFunction(ADllHandle, PEM_write_bio_ECPKParameters_procname);
  FuncLoadError := not assigned(PEM_write_bio_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_ECPKParameters_allownil)}
    PEM_write_bio_ECPKParameters := @ERR_PEM_write_bio_ECPKParameters;
    {$ifend}
    {$if declared(PEM_write_bio_ECPKParameters_introduced)}
    if LibVersion < PEM_write_bio_ECPKParameters_introduced then
    begin
      {$if declared(FC_PEM_write_bio_ECPKParameters)}
      PEM_write_bio_ECPKParameters := @FC_PEM_write_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_ECPKParameters_removed)}
    if PEM_write_bio_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_ECPKParameters)}
      PEM_write_bio_ECPKParameters := @_PEM_write_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_ECPKParameters');
    {$ifend}
  end;


  PEM_read_bio_ECPrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_ECPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_ECPrivateKey_allownil)}
    PEM_read_bio_ECPrivateKey := @ERR_PEM_read_bio_ECPrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_ECPrivateKey_introduced)}
    if LibVersion < PEM_read_bio_ECPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_ECPrivateKey)}
      PEM_read_bio_ECPrivateKey := @FC_PEM_read_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_ECPrivateKey_removed)}
    if PEM_read_bio_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_ECPrivateKey)}
      PEM_read_bio_ECPrivateKey := @_PEM_read_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_ECPrivateKey');
    {$ifend}
  end;


  PEM_write_bio_ECPrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_ECPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_ECPrivateKey_allownil)}
    PEM_write_bio_ECPrivateKey := @ERR_PEM_write_bio_ECPrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_ECPrivateKey_introduced)}
    if LibVersion < PEM_write_bio_ECPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_ECPrivateKey)}
      PEM_write_bio_ECPrivateKey := @FC_PEM_write_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_ECPrivateKey_removed)}
    if PEM_write_bio_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_ECPrivateKey)}
      PEM_write_bio_ECPrivateKey := @_PEM_write_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_ECPrivateKey');
    {$ifend}
  end;


  PEM_read_bio_EC_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_EC_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_EC_PUBKEY_allownil)}
    PEM_read_bio_EC_PUBKEY := @ERR_PEM_read_bio_EC_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_EC_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_EC_PUBKEY)}
      PEM_read_bio_EC_PUBKEY := @FC_PEM_read_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_EC_PUBKEY_removed)}
    if PEM_read_bio_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_EC_PUBKEY)}
      PEM_read_bio_EC_PUBKEY := @_PEM_read_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_EC_PUBKEY');
    {$ifend}
  end;


  PEM_write_bio_EC_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_EC_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_EC_PUBKEY_allownil)}
    PEM_write_bio_EC_PUBKEY := @ERR_PEM_write_bio_EC_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_EC_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_EC_PUBKEY)}
      PEM_write_bio_EC_PUBKEY := @FC_PEM_write_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_EC_PUBKEY_removed)}
    if PEM_write_bio_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_EC_PUBKEY)}
      PEM_write_bio_EC_PUBKEY := @_PEM_write_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_EC_PUBKEY');
    {$ifend}
  end;


  PEM_read_bio_DHparams := LoadLibFunction(ADllHandle, PEM_read_bio_DHparams_procname);
  FuncLoadError := not assigned(PEM_read_bio_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DHparams_allownil)}
    PEM_read_bio_DHparams := @ERR_PEM_read_bio_DHparams;
    {$ifend}
    {$if declared(PEM_read_bio_DHparams_introduced)}
    if LibVersion < PEM_read_bio_DHparams_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DHparams)}
      PEM_read_bio_DHparams := @FC_PEM_read_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DHparams_removed)}
    if PEM_read_bio_DHparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DHparams)}
      PEM_read_bio_DHparams := @_PEM_read_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DHparams');
    {$ifend}
  end;


  PEM_write_bio_DHparams := LoadLibFunction(ADllHandle, PEM_write_bio_DHparams_procname);
  FuncLoadError := not assigned(PEM_write_bio_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DHparams_allownil)}
    PEM_write_bio_DHparams := @ERR_PEM_write_bio_DHparams;
    {$ifend}
    {$if declared(PEM_write_bio_DHparams_introduced)}
    if LibVersion < PEM_write_bio_DHparams_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DHparams)}
      PEM_write_bio_DHparams := @FC_PEM_write_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DHparams_removed)}
    if PEM_write_bio_DHparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DHparams)}
      PEM_write_bio_DHparams := @_PEM_write_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DHparams');
    {$ifend}
  end;


  PEM_write_bio_DHxparams := LoadLibFunction(ADllHandle, PEM_write_bio_DHxparams_procname);
  FuncLoadError := not assigned(PEM_write_bio_DHxparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DHxparams_allownil)}
    PEM_write_bio_DHxparams := @ERR_PEM_write_bio_DHxparams;
    {$ifend}
    {$if declared(PEM_write_bio_DHxparams_introduced)}
    if LibVersion < PEM_write_bio_DHxparams_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DHxparams)}
      PEM_write_bio_DHxparams := @FC_PEM_write_bio_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DHxparams_removed)}
    if PEM_write_bio_DHxparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DHxparams)}
      PEM_write_bio_DHxparams := @_PEM_write_bio_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DHxparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DHxparams');
    {$ifend}
  end;


  PEM_read_bio_PrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_PrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PrivateKey_allownil)}
    PEM_read_bio_PrivateKey := @ERR_PEM_read_bio_PrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_PrivateKey_introduced)}
    if LibVersion < PEM_read_bio_PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PrivateKey)}
      PEM_read_bio_PrivateKey := @FC_PEM_read_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PrivateKey_removed)}
    if PEM_read_bio_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PrivateKey)}
      PEM_read_bio_PrivateKey := @_PEM_read_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PrivateKey');
    {$ifend}
  end;


  PEM_write_bio_PrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_PrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PrivateKey_allownil)}
    PEM_write_bio_PrivateKey := @ERR_PEM_write_bio_PrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_introduced)}
    if LibVersion < PEM_write_bio_PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PrivateKey)}
      PEM_write_bio_PrivateKey := @FC_PEM_write_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_removed)}
    if PEM_write_bio_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PrivateKey)}
      PEM_write_bio_PrivateKey := @_PEM_write_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PrivateKey');
    {$ifend}
  end;


  PEM_read_bio_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PUBKEY_allownil)}
    PEM_read_bio_PUBKEY := @ERR_PEM_read_bio_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PUBKEY)}
      PEM_read_bio_PUBKEY := @FC_PEM_read_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PUBKEY_removed)}
    if PEM_read_bio_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PUBKEY)}
      PEM_read_bio_PUBKEY := @_PEM_read_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PUBKEY');
    {$ifend}
  end;


  PEM_write_bio_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PUBKEY_allownil)}
    PEM_write_bio_PUBKEY := @ERR_PEM_write_bio_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PUBKEY)}
      PEM_write_bio_PUBKEY := @FC_PEM_write_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PUBKEY_removed)}
    if PEM_write_bio_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PUBKEY)}
      PEM_write_bio_PUBKEY := @_PEM_write_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PUBKEY');
    {$ifend}
  end;


  PEM_write_bio_PrivateKey_traditional := LoadLibFunction(ADllHandle, PEM_write_bio_PrivateKey_traditional_procname);
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey_traditional);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PrivateKey_traditional_allownil)}
    PEM_write_bio_PrivateKey_traditional := @ERR_PEM_write_bio_PrivateKey_traditional;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_traditional_introduced)}
    if LibVersion < PEM_write_bio_PrivateKey_traditional_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PrivateKey_traditional)}
      PEM_write_bio_PrivateKey_traditional := @FC_PEM_write_bio_PrivateKey_traditional;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_traditional_removed)}
    if PEM_write_bio_PrivateKey_traditional_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PrivateKey_traditional)}
      PEM_write_bio_PrivateKey_traditional := @_PEM_write_bio_PrivateKey_traditional;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PrivateKey_traditional_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PrivateKey_traditional');
    {$ifend}
  end;

 {introduced 1.1.0}
  PEM_write_bio_PKCS8PrivateKey_nid := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8PrivateKey_nid_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8PrivateKey_nid);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_nid_allownil)}
    PEM_write_bio_PKCS8PrivateKey_nid := @ERR_PEM_write_bio_PKCS8PrivateKey_nid;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_nid_introduced)}
    if LibVersion < PEM_write_bio_PKCS8PrivateKey_nid_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8PrivateKey_nid)}
      PEM_write_bio_PKCS8PrivateKey_nid := @FC_PEM_write_bio_PKCS8PrivateKey_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_nid_removed)}
    if PEM_write_bio_PKCS8PrivateKey_nid_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8PrivateKey_nid)}
      PEM_write_bio_PKCS8PrivateKey_nid := @_PEM_write_bio_PKCS8PrivateKey_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8PrivateKey_nid');
    {$ifend}
  end;


  PEM_write_bio_PKCS8PrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8PrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_allownil)}
    PEM_write_bio_PKCS8PrivateKey := @ERR_PEM_write_bio_PKCS8PrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_introduced)}
    if LibVersion < PEM_write_bio_PKCS8PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8PrivateKey)}
      PEM_write_bio_PKCS8PrivateKey := @FC_PEM_write_bio_PKCS8PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_removed)}
    if PEM_write_bio_PKCS8PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8PrivateKey)}
      PEM_write_bio_PKCS8PrivateKey := @_PEM_write_bio_PKCS8PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8PrivateKey');
    {$ifend}
  end;


  i2d_PKCS8PrivateKey_bio := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKey_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKey_bio_allownil)}
    i2d_PKCS8PrivateKey_bio := @ERR_i2d_PKCS8PrivateKey_bio;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_bio_introduced)}
    if LibVersion < i2d_PKCS8PrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKey_bio)}
      i2d_PKCS8PrivateKey_bio := @FC_i2d_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_bio_removed)}
    if i2d_PKCS8PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKey_bio)}
      i2d_PKCS8PrivateKey_bio := @_i2d_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKey_bio');
    {$ifend}
  end;


  i2d_PKCS8PrivateKey_nid_bio := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKey_nid_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_nid_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKey_nid_bio_allownil)}
    i2d_PKCS8PrivateKey_nid_bio := @ERR_i2d_PKCS8PrivateKey_nid_bio;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_nid_bio_introduced)}
    if LibVersion < i2d_PKCS8PrivateKey_nid_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKey_nid_bio)}
      i2d_PKCS8PrivateKey_nid_bio := @FC_i2d_PKCS8PrivateKey_nid_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_nid_bio_removed)}
    if i2d_PKCS8PrivateKey_nid_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKey_nid_bio)}
      i2d_PKCS8PrivateKey_nid_bio := @_i2d_PKCS8PrivateKey_nid_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKey_nid_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKey_nid_bio');
    {$ifend}
  end;


  d2i_PKCS8PrivateKey_bio := LoadLibFunction(ADllHandle, d2i_PKCS8PrivateKey_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS8PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8PrivateKey_bio_allownil)}
    d2i_PKCS8PrivateKey_bio := @ERR_d2i_PKCS8PrivateKey_bio;
    {$ifend}
    {$if declared(d2i_PKCS8PrivateKey_bio_introduced)}
    if LibVersion < d2i_PKCS8PrivateKey_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS8PrivateKey_bio)}
      d2i_PKCS8PrivateKey_bio := @FC_d2i_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8PrivateKey_bio_removed)}
    if d2i_PKCS8PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8PrivateKey_bio)}
      d2i_PKCS8PrivateKey_bio := @_d2i_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8PrivateKey_bio');
    {$ifend}
  end;


  PEM_read_bio_Parameters := LoadLibFunction(ADllHandle, PEM_read_bio_Parameters_procname);
  FuncLoadError := not assigned(PEM_read_bio_Parameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_Parameters_allownil)}
    PEM_read_bio_Parameters := @ERR_PEM_read_bio_Parameters;
    {$ifend}
    {$if declared(PEM_read_bio_Parameters_introduced)}
    if LibVersion < PEM_read_bio_Parameters_introduced then
    begin
      {$if declared(FC_PEM_read_bio_Parameters)}
      PEM_read_bio_Parameters := @FC_PEM_read_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_Parameters_removed)}
    if PEM_read_bio_Parameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_Parameters)}
      PEM_read_bio_Parameters := @_PEM_read_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_Parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_Parameters');
    {$ifend}
  end;


  PEM_write_bio_Parameters := LoadLibFunction(ADllHandle, PEM_write_bio_Parameters_procname);
  FuncLoadError := not assigned(PEM_write_bio_Parameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_Parameters_allownil)}
    PEM_write_bio_Parameters := @ERR_PEM_write_bio_Parameters;
    {$ifend}
    {$if declared(PEM_write_bio_Parameters_introduced)}
    if LibVersion < PEM_write_bio_Parameters_introduced then
    begin
      {$if declared(FC_PEM_write_bio_Parameters)}
      PEM_write_bio_Parameters := @FC_PEM_write_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_Parameters_removed)}
    if PEM_write_bio_Parameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_Parameters)}
      PEM_write_bio_Parameters := @_PEM_write_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_Parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_Parameters');
    {$ifend}
  end;


  b2i_PrivateKey := LoadLibFunction(ADllHandle, b2i_PrivateKey_procname);
  FuncLoadError := not assigned(b2i_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PrivateKey_allownil)}
    b2i_PrivateKey := @ERR_b2i_PrivateKey;
    {$ifend}
    {$if declared(b2i_PrivateKey_introduced)}
    if LibVersion < b2i_PrivateKey_introduced then
    begin
      {$if declared(FC_b2i_PrivateKey)}
      b2i_PrivateKey := @FC_b2i_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PrivateKey_removed)}
    if b2i_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_b2i_PrivateKey)}
      b2i_PrivateKey := @_b2i_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PrivateKey');
    {$ifend}
  end;


  b2i_PublicKey := LoadLibFunction(ADllHandle, b2i_PublicKey_procname);
  FuncLoadError := not assigned(b2i_PublicKey);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PublicKey_allownil)}
    b2i_PublicKey := @ERR_b2i_PublicKey;
    {$ifend}
    {$if declared(b2i_PublicKey_introduced)}
    if LibVersion < b2i_PublicKey_introduced then
    begin
      {$if declared(FC_b2i_PublicKey)}
      b2i_PublicKey := @FC_b2i_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PublicKey_removed)}
    if b2i_PublicKey_removed <= LibVersion then
    begin
      {$if declared(_b2i_PublicKey)}
      b2i_PublicKey := @_b2i_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PublicKey');
    {$ifend}
  end;


  b2i_PrivateKey_bio := LoadLibFunction(ADllHandle, b2i_PrivateKey_bio_procname);
  FuncLoadError := not assigned(b2i_PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PrivateKey_bio_allownil)}
    b2i_PrivateKey_bio := @ERR_b2i_PrivateKey_bio;
    {$ifend}
    {$if declared(b2i_PrivateKey_bio_introduced)}
    if LibVersion < b2i_PrivateKey_bio_introduced then
    begin
      {$if declared(FC_b2i_PrivateKey_bio)}
      b2i_PrivateKey_bio := @FC_b2i_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PrivateKey_bio_removed)}
    if b2i_PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_b2i_PrivateKey_bio)}
      b2i_PrivateKey_bio := @_b2i_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PrivateKey_bio');
    {$ifend}
  end;


  b2i_PublicKey_bio := LoadLibFunction(ADllHandle, b2i_PublicKey_bio_procname);
  FuncLoadError := not assigned(b2i_PublicKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PublicKey_bio_allownil)}
    b2i_PublicKey_bio := @ERR_b2i_PublicKey_bio;
    {$ifend}
    {$if declared(b2i_PublicKey_bio_introduced)}
    if LibVersion < b2i_PublicKey_bio_introduced then
    begin
      {$if declared(FC_b2i_PublicKey_bio)}
      b2i_PublicKey_bio := @FC_b2i_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PublicKey_bio_removed)}
    if b2i_PublicKey_bio_removed <= LibVersion then
    begin
      {$if declared(_b2i_PublicKey_bio)}
      b2i_PublicKey_bio := @_b2i_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PublicKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PublicKey_bio');
    {$ifend}
  end;


  i2b_PrivateKey_bio := LoadLibFunction(ADllHandle, i2b_PrivateKey_bio_procname);
  FuncLoadError := not assigned(i2b_PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PrivateKey_bio_allownil)}
    i2b_PrivateKey_bio := @ERR_i2b_PrivateKey_bio;
    {$ifend}
    {$if declared(i2b_PrivateKey_bio_introduced)}
    if LibVersion < i2b_PrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2b_PrivateKey_bio)}
      i2b_PrivateKey_bio := @FC_i2b_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PrivateKey_bio_removed)}
    if i2b_PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2b_PrivateKey_bio)}
      i2b_PrivateKey_bio := @_i2b_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PrivateKey_bio');
    {$ifend}
  end;


  i2b_PublicKey_bio := LoadLibFunction(ADllHandle, i2b_PublicKey_bio_procname);
  FuncLoadError := not assigned(i2b_PublicKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PublicKey_bio_allownil)}
    i2b_PublicKey_bio := @ERR_i2b_PublicKey_bio;
    {$ifend}
    {$if declared(i2b_PublicKey_bio_introduced)}
    if LibVersion < i2b_PublicKey_bio_introduced then
    begin
      {$if declared(FC_i2b_PublicKey_bio)}
      i2b_PublicKey_bio := @FC_i2b_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PublicKey_bio_removed)}
    if i2b_PublicKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2b_PublicKey_bio)}
      i2b_PublicKey_bio := @_i2b_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PublicKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PublicKey_bio');
    {$ifend}
  end;


  b2i_PVK_bio := LoadLibFunction(ADllHandle, b2i_PVK_bio_procname);
  FuncLoadError := not assigned(b2i_PVK_bio);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PVK_bio_allownil)}
    b2i_PVK_bio := @ERR_b2i_PVK_bio;
    {$ifend}
    {$if declared(b2i_PVK_bio_introduced)}
    if LibVersion < b2i_PVK_bio_introduced then
    begin
      {$if declared(FC_b2i_PVK_bio)}
      b2i_PVK_bio := @FC_b2i_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PVK_bio_removed)}
    if b2i_PVK_bio_removed <= LibVersion then
    begin
      {$if declared(_b2i_PVK_bio)}
      b2i_PVK_bio := @_b2i_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PVK_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PVK_bio');
    {$ifend}
  end;


  i2b_PVK_bio := LoadLibFunction(ADllHandle, i2b_PVK_bio_procname);
  FuncLoadError := not assigned(i2b_PVK_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PVK_bio_allownil)}
    i2b_PVK_bio := @ERR_i2b_PVK_bio;
    {$ifend}
    {$if declared(i2b_PVK_bio_introduced)}
    if LibVersion < i2b_PVK_bio_introduced then
    begin
      {$if declared(FC_i2b_PVK_bio)}
      i2b_PVK_bio := @FC_i2b_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PVK_bio_removed)}
    if i2b_PVK_bio_removed <= LibVersion then
    begin
      {$if declared(_i2b_PVK_bio)}
      i2b_PVK_bio := @_i2b_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PVK_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PVK_bio');
    {$ifend}
  end;


end;

procedure Unload;
begin
  PEM_get_EVP_CIPHER_INFO := nil;
  PEM_do_header := nil;
  PEM_read_bio := nil;
  PEM_read_bio_ex := nil; {introduced 1.1.0}
  PEM_bytes_read_bio_secmem := nil; {introduced 1.1.0}
  PEM_write_bio := nil;
  PEM_bytes_read_bio := nil;
  PEM_ASN1_read_bio := nil;
  PEM_ASN1_write_bio := nil;
  PEM_X509_INFO_read_bio := nil;
  PEM_X509_INFO_write_bio := nil;
  PEM_SignInit := nil;
  PEM_SignUpdate := nil;
  PEM_SignFinal := nil;
  PEM_def_callback := nil;
  PEM_proc_type := nil;
  PEM_dek_info := nil;
  PEM_read_bio_X509 := nil;
  PEM_write_bio_X509 := nil;
  PEM_read_bio_X509_AUX := nil;
  PEM_write_bio_X509_AUX := nil;
  PEM_read_bio_X509_REQ := nil;
  PEM_write_bio_X509_REQ := nil;
  PEM_write_bio_X509_REQ_NEW := nil;
  PEM_read_bio_X509_CRL := nil;
  PEM_write_bio_X509_CRL := nil;
  PEM_read_bio_PKCS7 := nil;
  PEM_write_bio_PKCS7 := nil;
  PEM_read_bio_PKCS8 := nil;
  PEM_write_bio_PKCS8 := nil;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := nil;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := nil;
  PEM_read_bio_RSAPrivateKey := nil;
  PEM_write_bio_RSAPrivateKey := nil;
  PEM_read_bio_RSAPublicKey := nil;
  PEM_write_bio_RSAPublicKey := nil;
  PEM_read_bio_RSA_PUBKEY := nil;
  PEM_write_bio_RSA_PUBKEY := nil;
  PEM_read_bio_DSAPrivateKey := nil;
  PEM_write_bio_DSAPrivateKey := nil;
  PEM_read_bio_DSA_PUBKEY := nil;
  PEM_write_bio_DSA_PUBKEY := nil;
  PEM_read_bio_DSAparams := nil;
  PEM_write_bio_DSAparams := nil;
  PEM_read_bio_ECPKParameters := nil;
  PEM_write_bio_ECPKParameters := nil;
  PEM_read_bio_ECPrivateKey := nil;
  PEM_write_bio_ECPrivateKey := nil;
  PEM_read_bio_EC_PUBKEY := nil;
  PEM_write_bio_EC_PUBKEY := nil;
  PEM_read_bio_DHparams := nil;
  PEM_write_bio_DHparams := nil;
  PEM_write_bio_DHxparams := nil;
  PEM_read_bio_PrivateKey := nil;
  PEM_write_bio_PrivateKey := nil;
  PEM_read_bio_PUBKEY := nil;
  PEM_write_bio_PUBKEY := nil;
  PEM_write_bio_PrivateKey_traditional := nil; {introduced 1.1.0}
  PEM_write_bio_PKCS8PrivateKey_nid := nil;
  PEM_write_bio_PKCS8PrivateKey := nil;
  i2d_PKCS8PrivateKey_bio := nil;
  i2d_PKCS8PrivateKey_nid_bio := nil;
  d2i_PKCS8PrivateKey_bio := nil;
  PEM_read_bio_Parameters := nil;
  PEM_write_bio_Parameters := nil;
  b2i_PrivateKey := nil;
  b2i_PublicKey := nil;
  b2i_PrivateKey_bio := nil;
  b2i_PublicKey_bio := nil;
  i2b_PrivateKey_bio := nil;
  i2b_PublicKey_bio := nil;
  b2i_PVK_bio := nil;
  i2b_PVK_bio := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF USE_EXTERNAL_LIBRARY}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.

