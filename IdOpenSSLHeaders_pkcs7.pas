  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_pkcs7.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_pkcs7.h2pas
     and this file regenerated. IdOpenSSLHeaders_pkcs7.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_pkcs7;

interface

// Headers for OpenSSL 1.1.1
// pkcs7.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_ossl_typ;

const
  PKCS7_S_HEADER = 0;
  PKCS7_S_BODY   = 1;
  PKCS7_S_TAIL   = 2;

  PKCS7_OP_SET_DETACHED_SIGNATURE = 1;
  PKCS7_OP_GET_DETACHED_SIGNATURE = 2;

  (* S/MIME related flags *)
  PKCS7_TEXT            =     $1;
  PKCS7_NOCERTS         =     $2;
  PKCS7_NOSIGS          =     $4;
  PKCS7_NOCHAIN         =     $8;
  PKCS7_NOINTERN        =    $10;
  PKCS7_NOVERIFY        =    $20;
  PKCS7_DETACHED        =    $40;
  PKCS7_BINARY          =    $80;
  PKCS7_NOATTR          =   $100;
  PKCS7_NOSMIMECAP      =   $200;
  PKCS7_NOOLDMIMETYPE   =   $400;
  PKCS7_CRLFEOL         =   $800;
  // Added '_CONST' to avoid name clashes
  PKCS7_STREAM_CONST    =  $1000;
  PKCS7_NOCRL           =  $2000;
  PKCS7_PARTIAL         =  $4000;
  PKCS7_REUSE_DIGEST    =  $8000;
  PKCS7_NO_DUAL_CONTENT = $10000;

  (* Flags: for compatibility with older code *)
  SMIME_TEXT      = PKCS7_TEXT;
  SMIME_NOCERTS   = PKCS7_NOCERTS;
  SMIME_NOSIGS    = PKCS7_NOSIGS;
  SMIME_NOCHAIN   = PKCS7_NOCHAIN;
  SMIME_NOINTERN  = PKCS7_NOINTERN;
  SMIME_NOVERIFY  = PKCS7_NOVERIFY;
  SMIME_DETACHED  = PKCS7_DETACHED;
  SMIME_BINARY    = PKCS7_BINARY;
  SMIME_NOATTR    = PKCS7_NOATTR;

  (* CRLF ASCII canonicalisation *)
  SMIME_ASCIICRLF = $80000;

type
  PPKCS7 = ^PKCS7;
  PPPKCS7 = ^PPKCS7;

  PPKCS7_DIGEST = ^PKCS7_DIGEST;
  PPPKCS7_DIGEST = ^PPKCS7_DIGEST;

  pkcs7_issuer_and_serial_st = record
    issue: PX509_NAME;
    serial: PASN1_INTEGER;
  end;
  PKCS7_ISSUER_AND_SERIAL = pkcs7_issuer_and_serial_st;
  PPKCS7_ISSUER_AND_SERIAL = ^PKCS7_ISSUER_AND_SERIAL;
  PPPKCS7_ISSUER_AND_SERIAL = ^PPKCS7_ISSUER_AND_SERIAL;

  pkcs7_signer_info_st = record
    version: PASN1_INTEGER;
    issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
    digest_alg: PX509_ALGOR;
    auth_attr: Pointer; //PSTACK_OF_X509_ATTRIBUTE;
    digest_enc_alg: PX509_ALGOR;
    enc_digest: PASN1_OCTET_STRING;
    unauth_attr: Pointer; //PSTACK_OF_X509_ATTRIBUTE;
    pkey: PEVP_PKEY;
  end;
  PKCS7_SIGNER_INFO = pkcs7_issuer_and_serial_st;
  PPKCS7_SIGNER_INFO = ^PKCS7_SIGNER_INFO;
  PPPKCS7_SIGNER_INFO = ^PPKCS7_SIGNER_INFO;

  pkcs7_recip_info_st = record
    version: PASN1_INTEGER;
    issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
    key_enc_algor: PX509_ALGOR;
    enc_key: PASN1_OCTET_STRING;
    cert: PX509;
  end;
  PKCS7_RECIP_INFO = pkcs7_recip_info_st;
  PPKCS7_RECIP_INFO = ^PKCS7_RECIP_INFO;
  PPPKCS7_RECIP_INFO = ^PPKCS7_RECIP_INFO;

  pkcs7_signed_st = record
    version: PASN1_INTEGER;
    md_algs: Pointer; //PSTACK_OF_X509_ALGOR;
    cert: Pointer; //PSTACK_OF_X509;
    crl: Pointer; //PSTACK_OF_X509_CRL;
    signer_info: Pointer; //PSTACK_OF_PKCS7_SIGNER_INFO;
    contents: PPKCS7;
  end;
  PKCS7_SIGNED = pkcs7_signed_st;
  PPKCS7_SIGNED = ^PKCS7_SIGNED;
  PPPKCS7_SIGNED = ^PPKCS7_SIGNED;

  pkcs7_enc_content_st = record
    content_type: PASN1_OBJECT;
    algorithm: PX509_ALGOR;
    enc_data: PASN1_OCTET_STRING;
    cipher: PEVP_CIPHER;
  end;
  PKCS7_ENC_CONTENT = pkcs7_enc_content_st;
  PPKCS7_ENC_CONTENT = ^PKCS7_ENC_CONTENT;
  PPPKCS7_ENC_CONTENT = ^PPKCS7_ENC_CONTENT;

  pkcs7_enveloped_st = record
    version: PASN1_INTEGER;
    recipientinfo: Pointer; //PSTACK_OF_PKCS7_RECIP_INFO;
    enc_data: PPKCS7_ENC_CONTENT;
  end;
  PKCS7_ENVELOPE = pkcs7_enveloped_st;
  PPKCS7_ENVELOPE = ^PKCS7_ENVELOPE;
  PPPKCS7_ENVELOPE = ^PPKCS7_ENVELOPE;

  pkcs7_signedandenveloped_st = record
    version: PASN1_INTEGER;
    md_algs: Pointer; //PSTACK_OF_X509_ALGOR;
    cert: Pointer; //PSTACK_OF_X509;
    crl: Pointer; //PSTACK_OF_X509_CRL;
    signer_info: Pointer; //PSTACK_OF_PKCS7_SIGNER_INFO;
    enc_data: PPKCS7_ENC_CONTENT;
    recipientinfo: Pointer; //PSTACK_OF_PKCS7_RECIP_INFO;
  end;
  PKCS7_SIGN_ENVELOPE = pkcs7_signedandenveloped_st;
  PPKCS7_SIGN_ENVELOPE = ^PKCS7_SIGN_ENVELOPE;
  PPPKCS7_SIGN_ENVELOPE = ^PPKCS7_SIGN_ENVELOPE;

  pkcs7_encrypted_st = record
    version: PASN1_INTEGER;
    enc_data: PPKCS7_ENC_CONTENT;
  end;
  // Added '_STRUCT' to avoid name clashes
  PKCS7_ENCRYPT_STRUCT = pkcs7_encrypted_st;
  PPKCS7_ENCRYPT_STRUCT = ^PKCS7_ENCRYPT_STRUCT;
  PPPKCS7_ENCRYPT_STRUCT = ^PPKCS7_ENCRYPT_STRUCT;

  pkcs7_st_d = record
    case Integer of
    0: (ptr: PIdAnsiChar);
    1: (data: PASN1_OCTET_STRING);
    2: (sign: PPKCS7_SIGNED);
    3: (enveloped: PPKCS7_ENVELOPE);
    4: (signed_and_enveloped: PPKCS7_SIGN_ENVELOPE);
    5: (digest: PPKCS7_DIGEST);
    6: (encrypted: PPKCS7_ENCRYPT_STRUCT);
    7: (other: PASN1_TYPE);
  end;
  pkcs7_st = record
    asn1: PByte;
    length: TIdC_LONG;
    state: TIdC_INT;
    detached: TIdC_INT;
    type_: PASN1_OBJECT;
    d: pkcs7_st_d;
  end;
  PKCS7 = pkcs7_st;

  pkcs7_digest_st = record
    version: PASN1_INTEGER;
    md: PX509_ALGOR;
    contents: PPKCS7;
    digest: PASN1_OCTET_STRING;
  end;
  PKCS7_DIGEST = pkcs7_digest_st;

  //function PKCS7_ISSUER_AND_SERIAL_new: PPKCS7_ISSUER_AND_SERIAL;
  //procedure PKCS7_ISSUER_AND_SERIAL_free(a: PPKCS7_ISSUER_AND_SERIAL);
  //function d2i_PKCS7_ISSUER_AND_SERIAL(a: PPPKCS7_ISSUER_AND_SERIAL; const in_: PByte; len: TIdC_LONG): PPKCS7_ISSUER_AND_SERIAL;
  //function i2d_PKCS7_ISSUER_AND_SERIAL(const a: PPKCS7_ISSUER_AND_SERIAL; out_: PByte): TIdC_INT;
  //function PKCS7_ISSUER_AND_SERIAL_it: PASN1_ITEM;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM PKCS7_ISSUER_AND_SERIAL_digest}
  {$EXTERNALSYM PKCS7_dup}
  {$EXTERNALSYM d2i_PKCS7_bio}
  {$EXTERNALSYM i2d_PKCS7_bio}
  {$EXTERNALSYM i2d_PKCS7_bio_stream}
  {$EXTERNALSYM PEM_write_bio_PKCS7_stream}
  {$EXTERNALSYM PKCS7_ctrl}
  {$EXTERNALSYM PKCS7_set_type}
  {$EXTERNALSYM PKCS7_set0_type_other}
  {$EXTERNALSYM PKCS7_set_content}
  {$EXTERNALSYM PKCS7_SIGNER_INFO_set}
  {$EXTERNALSYM PKCS7_SIGNER_INFO_sign}
  {$EXTERNALSYM PKCS7_add_signer}
  {$EXTERNALSYM PKCS7_add_certificate}
  {$EXTERNALSYM PKCS7_add_crl}
  {$EXTERNALSYM PKCS7_content_new}
  {$EXTERNALSYM PKCS7_dataVerify}
  {$EXTERNALSYM PKCS7_signatureVerify}
  {$EXTERNALSYM PKCS7_dataInit}
  {$EXTERNALSYM PKCS7_dataFinal}
  {$EXTERNALSYM PKCS7_dataDecode}
  {$EXTERNALSYM PKCS7_add_signature}
  {$EXTERNALSYM PKCS7_cert_from_signer_info}
  {$EXTERNALSYM PKCS7_set_digest}
  {$EXTERNALSYM PKCS7_add_recipient}
  {$EXTERNALSYM PKCS7_SIGNER_INFO_get0_algs}
  {$EXTERNALSYM PKCS7_RECIP_INFO_get0_alg}
  {$EXTERNALSYM PKCS7_add_recipient_info}
  {$EXTERNALSYM PKCS7_RECIP_INFO_set}
  {$EXTERNALSYM PKCS7_set_cipher}
  {$EXTERNALSYM PKCS7_stream}
  {$EXTERNALSYM PKCS7_get_issuer_and_serial}
  {$EXTERNALSYM PKCS7_add_signed_attribute}
  {$EXTERNALSYM PKCS7_add_attribute}
  {$EXTERNALSYM PKCS7_get_attribute}
  {$EXTERNALSYM PKCS7_get_signed_attribute}
  {$EXTERNALSYM PKCS7_sign_add_signer}
  {$EXTERNALSYM PKCS7_final}
  {$EXTERNALSYM PKCS7_decrypt}
  {$EXTERNALSYM PKCS7_add_attrib_content_type}
  {$EXTERNALSYM PKCS7_add0_attrib_signing_time}
  {$EXTERNALSYM PKCS7_add1_attrib_digest}
  {$EXTERNALSYM SMIME_write_PKCS7}
  {$EXTERNALSYM SMIME_read_PKCS7}
  {$EXTERNALSYM BIO_new_PKCS7}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  PKCS7_ISSUER_AND_SERIAL_digest: function (data: PPKCS7_ISSUER_AND_SERIAL; const type_: PEVP_MD; md: PByte; len: PIdC_UINT): TIdC_INT; cdecl = nil;

  PKCS7_dup: function (p7: PPKCS7): PPKCS7; cdecl = nil;
  d2i_PKCS7_bio: function (bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl = nil;
  i2d_PKCS7_bio: function (bp: PBIO; p7: PPKCS7): TIdC_INT; cdecl = nil;
  i2d_PKCS7_bio_stream: function (out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  PEM_write_bio_PKCS7_stream: function (out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;

//  function PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO;
//  procedure PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO);
//  function d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNER_INFO;
//  function i2d_PKCS7_SIGNER_INFO(const a: PPKCS7_SIGNER_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNER_INFO_it: PASN1_ITEM;
//
//  function PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO;
//  procedure PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO);
//  function d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_RECIP_INFO;
//  function i2d_PKCS7_RECIP_INFO(const a: PPKCS7_RECIP_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_RECIP_INFO_it: PASN1_ITEM;
//
//  function PKCS7_SIGNED_new: PPKCS7_SIGNED;
//  procedure PKCS7_SIGNED_free(a: PPKCS7_SIGNED);
//  function d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNED;
//  function i2d_PKCS7_SIGNED(const a: PPKCS7_SIGNED; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNED_it: PASN1_ITEM;
//
//  function PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT;
//  procedure PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT);
//  function d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENC_CONTENT;
//  function i2d_PKCS7_ENC_CONTENT(const a: PPKCS7_ENC_CONTENT; out_: PByte): TIdC_INT;
//  function PKCS7_ENC_CONTENT_it: PASN1_ITEM;
//
//  function PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE;
//  procedure PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE);
//  function d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_ENVELOPE;
//  function i2d_PKCS7_ENVELOPE(const a: PPKCS7_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE;
//  procedure PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE);
//  function d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE;
//  function i2d_PKCS7_SIGN_ENVELOPE(const a: PPKCS7_SIGN_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_DIGEST_new: PPKCS7_DIGEST;
//  procedure PKCS7_DIGEST_free(a: PPKCS7_DIGEST);
//  function d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; const in_: PByte; len: TIdC_LONG): PPKCS7_DIGEST;
//  function i2d_PKCS7_DIGEST(const a: PPKCS7_DIGEST; out_: PByte): TIdC_INT;
//  function PKCS7_DIGEST_it: PASN1_ITEM;
//
//  function PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT_STRUCT;
//  procedure PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT_STRUCT);
//  function d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT_STRUCT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENCRYPT_STRUCT;
//  function i2d_PKCS7_ENCRYPT(const a: PPKCS7_ENCRYPT_STRUCT; out_: PByte): TIdC_INT;
//  function PKCS7_ENCRYPT_it: PASN1_ITEM;
//
//  function PKCS7_new: PPKCS7;
//  procedure PKCS7_free(a: PPKCS7);
//  function d2i_PKCS7(a: PPPKCS7; const in_: PByte; len: TIdC_LONG): PPKCS7;
//  function i2d_PKCS7(const a: PPKCS7; out_: PByte): TIdC_INT;
//  function PKCS7_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_SIGN_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_VERIFY_it: PASN1_ITEM;
//
//  function i2d_PKCS7_NDEF(const a: PPKCS7; out_: PPByte): TIdC_INT;
//  function PKCS7_print_ctx(out_: PBIO; const x: PPKCS7; indent: TIdC_INT; const pctx: PASN1_PCTX): TIdC_INT;

  PKCS7_ctrl: function (p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG; cdecl = nil;

  PKCS7_set_type: function (p7: PPKCS7; type_: TIdC_INT): TIdC_INT; cdecl = nil;
  PKCS7_set0_type_other: function (p7: PPKCS7; type_: TIdC_INT; other: PASN1_TYPE): TIdC_INT; cdecl = nil;
  PKCS7_set_content: function (p7: PPKCS7; p7_data: PPKCS7): TIdC_INT; cdecl = nil;
  PKCS7_SIGNER_INFO_set: function (p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): TIdC_INT; cdecl = nil;
  PKCS7_SIGNER_INFO_sign: function (si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl = nil;
  PKCS7_add_signer: function (p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl = nil;
  PKCS7_add_certificate: function (p7: PPKCS7; x509: PX509): TIdC_INT; cdecl = nil;
  PKCS7_add_crl: function (p7: PPKCS7; x509: PX509_CRL): TIdC_INT; cdecl = nil;
  PKCS7_content_new: function (p7: PPKCS7; nid: TIdC_INT): TIdC_INT; cdecl = nil;
  PKCS7_dataVerify: function (cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl = nil;
  PKCS7_signatureVerify: function (bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; x509: PX509): TIdC_INT; cdecl = nil;

  PKCS7_dataInit: function (p7: PPKCS7; bio: PBIO): PBIO; cdecl = nil;
  PKCS7_dataFinal: function (p7: PPKCS7; bio: PBIO): TIdC_INT; cdecl = nil;
  PKCS7_dataDecode: function (p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl = nil;

  PKCS7_add_signature: function (p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl = nil;
  PKCS7_cert_from_signer_info: function (p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl = nil;
  PKCS7_set_digest: function (p7: PPKCS7; const md: PEVP_MD): TIdC_INT; cdecl = nil;
//  function PKCS7_get_signer_info(p7: PPKCS7): PSTACK_OF_PKCS7_SIGNER_INFO;

  PKCS7_add_recipient: function (p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl = nil;
  PKCS7_SIGNER_INFO_get0_algs: procedure (si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl = nil;
  PKCS7_RECIP_INFO_get0_alg: procedure (ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl = nil;
  PKCS7_add_recipient_info: function (p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT; cdecl = nil;
  PKCS7_RECIP_INFO_set: function (p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT; cdecl = nil;
  PKCS7_set_cipher: function (p7: PPKCS7; const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil;
  PKCS7_stream: function (boundary: PPPByte; p7: PPKCS7): TIdC_INT; cdecl = nil;

  PKCS7_get_issuer_and_serial: function (p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
  //function PKCS7_digest_from_attributes(sk: Pointer{PSTACK_OF_X509_ATTRIBUTE}): PASN1_OCTET_STRING;
  PKCS7_add_signed_attribute: function (p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; type_: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  PKCS7_add_attribute: function (p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT; cdecl = nil;
  PKCS7_get_attribute: function (si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  PKCS7_get_signed_attribute: function (si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  //function PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509): TIdC_INT;
  //function PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509_ATTRIBUTE): TIdC_INT;

  //function PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: PSTACK_OF_X509; data: PBIO; flags: TIdC_INT): PPKCS7;

  PKCS7_sign_add_signer: function (p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO; cdecl = nil;

  PKCS7_final: function (p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  //function PKCS7_verify(p7: PPKCS7; certs: PSTACK_OF_X509; store: PX509_STORE; indata: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT;
  //function PKCS7_get0_signers(p7: PPKCS7; certs: PSTACK_OF_X509; flags: TIdC_INT): PSTACK_OF_X509;
  //function PKCS7_encrypt(certs: PSTACK_OF_X509; in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7;
  PKCS7_decrypt: function (p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;

  //function PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: PSTACK_OF_X509_ALGOR): TIdC_INT;
  //function PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): PSTACK_OF_X509_ALGOR;
  //function PKCS7_simple_smimecap(sk: PSTACK_OF_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT;

  PKCS7_add_attrib_content_type: function (si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  PKCS7_add0_attrib_signing_time: function (si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT; cdecl = nil;
  PKCS7_add1_attrib_digest: function (si: PPKCS7_SIGNER_INFO; const md: PByte; mdlen: TIdC_INT): TIdC_INT; cdecl = nil;

  SMIME_write_PKCS7: function (bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  SMIME_read_PKCS7: function (bio: PBIO; bcont: PPBIO): PPKCS7; cdecl = nil;

  BIO_new_PKCS7: function (out_: PBIO; p7: PPKCS7): PBIO; cdecl = nil;

{$ELSE}
  function PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; const type_: PEVP_MD; md: PByte; len: PIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  function PKCS7_dup(p7: PPKCS7): PPKCS7 cdecl; external CLibCrypto;
  function d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7 cdecl; external CLibCrypto;
  function i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TIdC_INT cdecl; external CLibCrypto;
  function i2d_PKCS7_bio_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function PEM_write_bio_PKCS7_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

//  function PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO;
//  procedure PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO);
//  function d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNER_INFO;
//  function i2d_PKCS7_SIGNER_INFO(const a: PPKCS7_SIGNER_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNER_INFO_it: PASN1_ITEM;
//
//  function PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO;
//  procedure PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO);
//  function d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_RECIP_INFO;
//  function i2d_PKCS7_RECIP_INFO(const a: PPKCS7_RECIP_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_RECIP_INFO_it: PASN1_ITEM;
//
//  function PKCS7_SIGNED_new: PPKCS7_SIGNED;
//  procedure PKCS7_SIGNED_free(a: PPKCS7_SIGNED);
//  function d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNED;
//  function i2d_PKCS7_SIGNED(const a: PPKCS7_SIGNED; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNED_it: PASN1_ITEM;
//
//  function PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT;
//  procedure PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT);
//  function d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENC_CONTENT;
//  function i2d_PKCS7_ENC_CONTENT(const a: PPKCS7_ENC_CONTENT; out_: PByte): TIdC_INT;
//  function PKCS7_ENC_CONTENT_it: PASN1_ITEM;
//
//  function PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE;
//  procedure PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE);
//  function d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_ENVELOPE;
//  function i2d_PKCS7_ENVELOPE(const a: PPKCS7_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE;
//  procedure PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE);
//  function d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE;
//  function i2d_PKCS7_SIGN_ENVELOPE(const a: PPKCS7_SIGN_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_DIGEST_new: PPKCS7_DIGEST;
//  procedure PKCS7_DIGEST_free(a: PPKCS7_DIGEST);
//  function d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; const in_: PByte; len: TIdC_LONG): PPKCS7_DIGEST;
//  function i2d_PKCS7_DIGEST(const a: PPKCS7_DIGEST; out_: PByte): TIdC_INT;
//  function PKCS7_DIGEST_it: PASN1_ITEM;
//
//  function PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT_STRUCT;
//  procedure PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT_STRUCT);
//  function d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT_STRUCT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENCRYPT_STRUCT;
//  function i2d_PKCS7_ENCRYPT(const a: PPKCS7_ENCRYPT_STRUCT; out_: PByte): TIdC_INT;
//  function PKCS7_ENCRYPT_it: PASN1_ITEM;
//
//  function PKCS7_new: PPKCS7;
//  procedure PKCS7_free(a: PPKCS7);
//  function d2i_PKCS7(a: PPPKCS7; const in_: PByte; len: TIdC_LONG): PPKCS7;
//  function i2d_PKCS7(const a: PPKCS7; out_: PByte): TIdC_INT;
//  function PKCS7_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_SIGN_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_VERIFY_it: PASN1_ITEM;
//
//  function i2d_PKCS7_NDEF(const a: PPKCS7; out_: PPByte): TIdC_INT;
//  function PKCS7_print_ctx(out_: PBIO; const x: PPKCS7; indent: TIdC_INT; const pctx: PASN1_PCTX): TIdC_INT;

  function PKCS7_ctrl(p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG cdecl; external CLibCrypto;

  function PKCS7_set_type(p7: PPKCS7; type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_set0_type_other(p7: PPKCS7; type_: TIdC_INT; other: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_add_certificate(p7: PPKCS7; x509: PX509): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_add_crl(p7: PPKCS7; x509: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_content_new(p7: PPKCS7; nid: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; x509: PX509): TIdC_INT cdecl; external CLibCrypto;

  function PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO cdecl; external CLibCrypto;
  function PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO cdecl; external CLibCrypto;

  function PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): PPKCS7_SIGNER_INFO cdecl; external CLibCrypto;
  function PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509 cdecl; external CLibCrypto;
  function PKCS7_set_digest(p7: PPKCS7; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
//  function PKCS7_get_signer_info(p7: PPKCS7): PSTACK_OF_PKCS7_SIGNER_INFO;

  function PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO cdecl; external CLibCrypto;
  procedure PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR) cdecl; external CLibCrypto;
  procedure PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR) cdecl; external CLibCrypto;
  function PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_set_cipher(p7: PPKCS7; const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_stream(boundary: PPPByte; p7: PPKCS7): TIdC_INT cdecl; external CLibCrypto;

  function PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL cdecl; external CLibCrypto;
  //function PKCS7_digest_from_attributes(sk: Pointer{PSTACK_OF_X509_ATTRIBUTE}): PASN1_OCTET_STRING;
  function PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; type_: TIdC_INT; data: Pointer): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE cdecl; external CLibCrypto;
  function PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE cdecl; external CLibCrypto;
  //function PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509): TIdC_INT;
  //function PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509_ATTRIBUTE): TIdC_INT;

  //function PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: PSTACK_OF_X509; data: PBIO; flags: TIdC_INT): PPKCS7;

  function PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO cdecl; external CLibCrypto;

  function PKCS7_final(p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  //function PKCS7_verify(p7: PPKCS7; certs: PSTACK_OF_X509; store: PX509_STORE; indata: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT;
  //function PKCS7_get0_signers(p7: PPKCS7; certs: PSTACK_OF_X509; flags: TIdC_INT): PSTACK_OF_X509;
  //function PKCS7_encrypt(certs: PSTACK_OF_X509; in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7;
  function PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  //function PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: PSTACK_OF_X509_ALGOR): TIdC_INT;
  //function PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): PSTACK_OF_X509_ALGOR;
  //function PKCS7_simple_smimecap(sk: PSTACK_OF_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT;

  function PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto;
  function PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; const md: PByte; mdlen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7 cdecl; external CLibCrypto;

  function BIO_new_PKCS7(out_: PBIO; p7: PPKCS7): PBIO cdecl; external CLibCrypto;

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
  PKCS7_ISSUER_AND_SERIAL_digest_procname = 'PKCS7_ISSUER_AND_SERIAL_digest';

  PKCS7_dup_procname = 'PKCS7_dup';
  d2i_PKCS7_bio_procname = 'd2i_PKCS7_bio';
  i2d_PKCS7_bio_procname = 'i2d_PKCS7_bio';
  i2d_PKCS7_bio_stream_procname = 'i2d_PKCS7_bio_stream';
  PEM_write_bio_PKCS7_stream_procname = 'PEM_write_bio_PKCS7_stream';

//  function PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO;
//  procedure PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO);
//  function d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNER_INFO;
//  function i2d_PKCS7_SIGNER_INFO(const a: PPKCS7_SIGNER_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNER_INFO_it: PASN1_ITEM;
//
//  function PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO;
//  procedure PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO);
//  function d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_RECIP_INFO;
//  function i2d_PKCS7_RECIP_INFO(const a: PPKCS7_RECIP_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_RECIP_INFO_it: PASN1_ITEM;
//
//  function PKCS7_SIGNED_new: PPKCS7_SIGNED;
//  procedure PKCS7_SIGNED_free(a: PPKCS7_SIGNED);
//  function d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNED;
//  function i2d_PKCS7_SIGNED(const a: PPKCS7_SIGNED; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNED_it: PASN1_ITEM;
//
//  function PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT;
//  procedure PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT);
//  function d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENC_CONTENT;
//  function i2d_PKCS7_ENC_CONTENT(const a: PPKCS7_ENC_CONTENT; out_: PByte): TIdC_INT;
//  function PKCS7_ENC_CONTENT_it: PASN1_ITEM;
//
//  function PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE;
//  procedure PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE);
//  function d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_ENVELOPE;
//  function i2d_PKCS7_ENVELOPE(const a: PPKCS7_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE;
//  procedure PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE);
//  function d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE;
//  function i2d_PKCS7_SIGN_ENVELOPE(const a: PPKCS7_SIGN_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_DIGEST_new: PPKCS7_DIGEST;
//  procedure PKCS7_DIGEST_free(a: PPKCS7_DIGEST);
//  function d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; const in_: PByte; len: TIdC_LONG): PPKCS7_DIGEST;
//  function i2d_PKCS7_DIGEST(const a: PPKCS7_DIGEST; out_: PByte): TIdC_INT;
//  function PKCS7_DIGEST_it: PASN1_ITEM;
//
//  function PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT_STRUCT;
//  procedure PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT_STRUCT);
//  function d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT_STRUCT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENCRYPT_STRUCT;
//  function i2d_PKCS7_ENCRYPT(const a: PPKCS7_ENCRYPT_STRUCT; out_: PByte): TIdC_INT;
//  function PKCS7_ENCRYPT_it: PASN1_ITEM;
//
//  function PKCS7_new: PPKCS7;
//  procedure PKCS7_free(a: PPKCS7);
//  function d2i_PKCS7(a: PPPKCS7; const in_: PByte; len: TIdC_LONG): PPKCS7;
//  function i2d_PKCS7(const a: PPKCS7; out_: PByte): TIdC_INT;
//  function PKCS7_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_SIGN_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_VERIFY_it: PASN1_ITEM;
//
//  function i2d_PKCS7_NDEF(const a: PPKCS7; out_: PPByte): TIdC_INT;
//  function PKCS7_print_ctx(out_: PBIO; const x: PPKCS7; indent: TIdC_INT; const pctx: PASN1_PCTX): TIdC_INT;

  PKCS7_ctrl_procname = 'PKCS7_ctrl';

  PKCS7_set_type_procname = 'PKCS7_set_type';
  PKCS7_set0_type_other_procname = 'PKCS7_set0_type_other';
  PKCS7_set_content_procname = 'PKCS7_set_content';
  PKCS7_SIGNER_INFO_set_procname = 'PKCS7_SIGNER_INFO_set';
  PKCS7_SIGNER_INFO_sign_procname = 'PKCS7_SIGNER_INFO_sign';
  PKCS7_add_signer_procname = 'PKCS7_add_signer';
  PKCS7_add_certificate_procname = 'PKCS7_add_certificate';
  PKCS7_add_crl_procname = 'PKCS7_add_crl';
  PKCS7_content_new_procname = 'PKCS7_content_new';
  PKCS7_dataVerify_procname = 'PKCS7_dataVerify';
  PKCS7_signatureVerify_procname = 'PKCS7_signatureVerify';

  PKCS7_dataInit_procname = 'PKCS7_dataInit';
  PKCS7_dataFinal_procname = 'PKCS7_dataFinal';
  PKCS7_dataDecode_procname = 'PKCS7_dataDecode';

  PKCS7_add_signature_procname = 'PKCS7_add_signature';
  PKCS7_cert_from_signer_info_procname = 'PKCS7_cert_from_signer_info';
  PKCS7_set_digest_procname = 'PKCS7_set_digest';
//  function PKCS7_get_signer_info(p7: PPKCS7): PSTACK_OF_PKCS7_SIGNER_INFO;

  PKCS7_add_recipient_procname = 'PKCS7_add_recipient';
  PKCS7_SIGNER_INFO_get0_algs_procname = 'PKCS7_SIGNER_INFO_get0_algs';
  PKCS7_RECIP_INFO_get0_alg_procname = 'PKCS7_RECIP_INFO_get0_alg';
  PKCS7_add_recipient_info_procname = 'PKCS7_add_recipient_info';
  PKCS7_RECIP_INFO_set_procname = 'PKCS7_RECIP_INFO_set';
  PKCS7_set_cipher_procname = 'PKCS7_set_cipher';
  PKCS7_stream_procname = 'PKCS7_stream';

  PKCS7_get_issuer_and_serial_procname = 'PKCS7_get_issuer_and_serial';
  //function PKCS7_digest_from_attributes(sk: Pointer{PSTACK_OF_X509_ATTRIBUTE}): PASN1_OCTET_STRING;
  PKCS7_add_signed_attribute_procname = 'PKCS7_add_signed_attribute';
  PKCS7_add_attribute_procname = 'PKCS7_add_attribute';
  PKCS7_get_attribute_procname = 'PKCS7_get_attribute';
  PKCS7_get_signed_attribute_procname = 'PKCS7_get_signed_attribute';
  //function PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509): TIdC_INT;
  //function PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509_ATTRIBUTE): TIdC_INT;

  //function PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: PSTACK_OF_X509; data: PBIO; flags: TIdC_INT): PPKCS7;

  PKCS7_sign_add_signer_procname = 'PKCS7_sign_add_signer';

  PKCS7_final_procname = 'PKCS7_final';
  //function PKCS7_verify(p7: PPKCS7; certs: PSTACK_OF_X509; store: PX509_STORE; indata: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT;
  //function PKCS7_get0_signers(p7: PPKCS7; certs: PSTACK_OF_X509; flags: TIdC_INT): PSTACK_OF_X509;
  //function PKCS7_encrypt(certs: PSTACK_OF_X509; in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7;
  PKCS7_decrypt_procname = 'PKCS7_decrypt';

  //function PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: PSTACK_OF_X509_ALGOR): TIdC_INT;
  //function PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): PSTACK_OF_X509_ALGOR;
  //function PKCS7_simple_smimecap(sk: PSTACK_OF_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT;

  PKCS7_add_attrib_content_type_procname = 'PKCS7_add_attrib_content_type';
  PKCS7_add0_attrib_signing_time_procname = 'PKCS7_add0_attrib_signing_time';
  PKCS7_add1_attrib_digest_procname = 'PKCS7_add1_attrib_digest';

  SMIME_write_PKCS7_procname = 'SMIME_write_PKCS7';
  SMIME_read_PKCS7_procname = 'SMIME_read_PKCS7';

  BIO_new_PKCS7_procname = 'BIO_new_PKCS7';


{$WARN  NO_RETVAL OFF}
function  ERR_PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; const type_: PEVP_MD; md: PByte; len: PIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_ISSUER_AND_SERIAL_digest_procname);
end;



function  ERR_PKCS7_dup(p7: PPKCS7): PPKCS7; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_dup_procname);
end;


function  ERR_d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7; 
begin
  EIdAPIFunctionNotPresent.RaiseException(d2i_PKCS7_bio_procname);
end;


function  ERR_i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2d_PKCS7_bio_procname);
end;


function  ERR_i2d_PKCS7_bio_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2d_PKCS7_bio_stream_procname);
end;


function  ERR_PEM_write_bio_PKCS7_stream(out_: PBIO; p7: PPKCS7; in_: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS7_stream_procname);
end;



//  function PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO;
//  procedure PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO);
//  function d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNER_INFO;
//  function i2d_PKCS7_SIGNER_INFO(const a: PPKCS7_SIGNER_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNER_INFO_it: PASN1_ITEM;
//
//  function PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO;
//  procedure PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO);
//  function d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; const in_: PByte; len: TIdC_LONG): PPKCS7_RECIP_INFO;
//  function i2d_PKCS7_RECIP_INFO(const a: PPKCS7_RECIP_INFO; out_: PByte): TIdC_INT;
//  function PKCS7_RECIP_INFO_it: PASN1_ITEM;
//
//  function PKCS7_SIGNED_new: PPKCS7_SIGNED;
//  procedure PKCS7_SIGNED_free(a: PPKCS7_SIGNED);
//  function d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGNED;
//  function i2d_PKCS7_SIGNED(const a: PPKCS7_SIGNED; out_: PByte): TIdC_INT;
//  function PKCS7_SIGNED_it: PASN1_ITEM;
//
//  function PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT;
//  procedure PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT);
//  function d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENC_CONTENT;
//  function i2d_PKCS7_ENC_CONTENT(const a: PPKCS7_ENC_CONTENT; out_: PByte): TIdC_INT;
//  function PKCS7_ENC_CONTENT_it: PASN1_ITEM;
//
//  function PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE;
//  procedure PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE);
//  function d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_ENVELOPE;
//  function i2d_PKCS7_ENVELOPE(const a: PPKCS7_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE;
//  procedure PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE);
//  function d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; const in_: PByte; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE;
//  function i2d_PKCS7_SIGN_ENVELOPE(const a: PPKCS7_SIGN_ENVELOPE; out_: PByte): TIdC_INT;
//  function PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM;
//
//  function PKCS7_DIGEST_new: PPKCS7_DIGEST;
//  procedure PKCS7_DIGEST_free(a: PPKCS7_DIGEST);
//  function d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; const in_: PByte; len: TIdC_LONG): PPKCS7_DIGEST;
//  function i2d_PKCS7_DIGEST(const a: PPKCS7_DIGEST; out_: PByte): TIdC_INT;
//  function PKCS7_DIGEST_it: PASN1_ITEM;
//
//  function PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT_STRUCT;
//  procedure PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT_STRUCT);
//  function d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT_STRUCT; const in_: PByte; len: TIdC_LONG): PPKCS7_ENCRYPT_STRUCT;
//  function i2d_PKCS7_ENCRYPT(const a: PPKCS7_ENCRYPT_STRUCT; out_: PByte): TIdC_INT;
//  function PKCS7_ENCRYPT_it: PASN1_ITEM;
//
//  function PKCS7_new: PPKCS7;
//  procedure PKCS7_free(a: PPKCS7);
//  function d2i_PKCS7(a: PPPKCS7; const in_: PByte; len: TIdC_LONG): PPKCS7;
//  function i2d_PKCS7(const a: PPKCS7; out_: PByte): TIdC_INT;
//  function PKCS7_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_SIGN_it: PASN1_ITEM;
//
//  function PKCS7_ATTR_VERIFY_it: PASN1_ITEM;
//
//  function i2d_PKCS7_NDEF(const a: PPKCS7; out_: PPByte): TIdC_INT;
//  function PKCS7_print_ctx(out_: PBIO; const x: PPKCS7; indent: TIdC_INT; const pctx: PASN1_PCTX): TIdC_INT;

function  ERR_PKCS7_ctrl(p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_ctrl_procname);
end;



function  ERR_PKCS7_set_type(p7: PPKCS7; type_: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_set_type_procname);
end;


function  ERR_PKCS7_set0_type_other(p7: PPKCS7; type_: TIdC_INT; other: PASN1_TYPE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_set0_type_other_procname);
end;


function  ERR_PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_set_content_procname);
end;


function  ERR_PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_set_procname);
end;


function  ERR_PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_sign_procname);
end;


function  ERR_PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_signer_procname);
end;


function  ERR_PKCS7_add_certificate(p7: PPKCS7; x509: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_certificate_procname);
end;


function  ERR_PKCS7_add_crl(p7: PPKCS7; x509: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_crl_procname);
end;


function  ERR_PKCS7_content_new(p7: PPKCS7; nid: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_content_new_procname);
end;


function  ERR_PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_dataVerify_procname);
end;


function  ERR_PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; x509: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_signatureVerify_procname);
end;



function  ERR_PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_dataInit_procname);
end;


function  ERR_PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_dataFinal_procname);
end;


function  ERR_PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_dataDecode_procname);
end;



function  ERR_PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; const dgst: PEVP_MD): PPKCS7_SIGNER_INFO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_signature_procname);
end;


function  ERR_PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_cert_from_signer_info_procname);
end;


function  ERR_PKCS7_set_digest(p7: PPKCS7; const md: PEVP_MD): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_set_digest_procname);
end;


//  function PKCS7_get_signer_info(p7: PPKCS7): PSTACK_OF_PKCS7_SIGNER_INFO;

function  ERR_PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_recipient_procname);
end;


procedure  ERR_PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_get0_algs_procname);
end;


procedure  ERR_PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_get0_alg_procname);
end;


function  ERR_PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_recipient_info_procname);
end;


function  ERR_PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_set_procname);
end;


function  ERR_PKCS7_set_cipher(p7: PPKCS7; const cipher: PEVP_CIPHER): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_set_cipher_procname);
end;


function  ERR_PKCS7_stream(boundary: PPPByte; p7: PPKCS7): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_stream_procname);
end;



function  ERR_PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_get_issuer_and_serial_procname);
end;


  //function PKCS7_digest_from_attributes(sk: Pointer{PSTACK_OF_X509_ATTRIBUTE}): PASN1_OCTET_STRING;
function  ERR_PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; type_: TIdC_INT; data: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_signed_attribute_procname);
end;


function  ERR_PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_attribute_procname);
end;


function  ERR_PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_get_attribute_procname);
end;


function  ERR_PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_get_signed_attribute_procname);
end;


  //function PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509): TIdC_INT;
  //function PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: PSTACK_OF_X509_ATTRIBUTE): TIdC_INT;

  //function PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: PSTACK_OF_X509; data: PBIO; flags: TIdC_INT): PPKCS7;

function  ERR_PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_sign_add_signer_procname);
end;



function  ERR_PKCS7_final(p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_final_procname);
end;


  //function PKCS7_verify(p7: PPKCS7; certs: PSTACK_OF_X509; store: PX509_STORE; indata: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT;
  //function PKCS7_get0_signers(p7: PPKCS7; certs: PSTACK_OF_X509; flags: TIdC_INT): PSTACK_OF_X509;
  //function PKCS7_encrypt(certs: PSTACK_OF_X509; in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7;
function  ERR_PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_decrypt_procname);
end;



  //function PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: PSTACK_OF_X509_ALGOR): TIdC_INT;
  //function PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): PSTACK_OF_X509_ALGOR;
  //function PKCS7_simple_smimecap(sk: PSTACK_OF_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT;

function  ERR_PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add_attrib_content_type_procname);
end;


function  ERR_PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add0_attrib_signing_time_procname);
end;


function  ERR_PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; const md: PByte; mdlen: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PKCS7_add1_attrib_digest_procname);
end;



function  ERR_SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SMIME_write_PKCS7_procname);
end;


function  ERR_SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SMIME_read_PKCS7_procname);
end;



function  ERR_BIO_new_PKCS7(out_: PBIO; p7: PPKCS7): PBIO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BIO_new_PKCS7_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  PKCS7_ISSUER_AND_SERIAL_digest := LoadLibFunction(ADllHandle, PKCS7_ISSUER_AND_SERIAL_digest_procname);
  FuncLoadError := not assigned(PKCS7_ISSUER_AND_SERIAL_digest);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_digest_allownil)}
    PKCS7_ISSUER_AND_SERIAL_digest := @ERR_PKCS7_ISSUER_AND_SERIAL_digest;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_digest_introduced)}
    if LibVersion < PKCS7_ISSUER_AND_SERIAL_digest_introduced then
    begin
      {$if declared(FC_PKCS7_ISSUER_AND_SERIAL_digest)}
      PKCS7_ISSUER_AND_SERIAL_digest := @FC_PKCS7_ISSUER_AND_SERIAL_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_digest_removed)}
    if PKCS7_ISSUER_AND_SERIAL_digest_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ISSUER_AND_SERIAL_digest)}
      PKCS7_ISSUER_AND_SERIAL_digest := @_PKCS7_ISSUER_AND_SERIAL_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ISSUER_AND_SERIAL_digest');
    {$ifend}
  end;


  PKCS7_dup := LoadLibFunction(ADllHandle, PKCS7_dup_procname);
  FuncLoadError := not assigned(PKCS7_dup);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dup_allownil)}
    PKCS7_dup := @ERR_PKCS7_dup;
    {$ifend}
    {$if declared(PKCS7_dup_introduced)}
    if LibVersion < PKCS7_dup_introduced then
    begin
      {$if declared(FC_PKCS7_dup)}
      PKCS7_dup := @FC_PKCS7_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dup_removed)}
    if PKCS7_dup_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dup)}
      PKCS7_dup := @_PKCS7_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dup');
    {$ifend}
  end;


  d2i_PKCS7_bio := LoadLibFunction(ADllHandle, d2i_PKCS7_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS7_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_bio_allownil)}
    d2i_PKCS7_bio := @ERR_d2i_PKCS7_bio;
    {$ifend}
    {$if declared(d2i_PKCS7_bio_introduced)}
    if LibVersion < d2i_PKCS7_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_bio)}
      d2i_PKCS7_bio := @FC_d2i_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_bio_removed)}
    if d2i_PKCS7_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_bio)}
      d2i_PKCS7_bio := @_d2i_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_bio');
    {$ifend}
  end;


  i2d_PKCS7_bio := LoadLibFunction(ADllHandle, i2d_PKCS7_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS7_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_bio_allownil)}
    i2d_PKCS7_bio := @ERR_i2d_PKCS7_bio;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_introduced)}
    if LibVersion < i2d_PKCS7_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_bio)}
      i2d_PKCS7_bio := @FC_i2d_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_removed)}
    if i2d_PKCS7_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_bio)}
      i2d_PKCS7_bio := @_i2d_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_bio');
    {$ifend}
  end;


  i2d_PKCS7_bio_stream := LoadLibFunction(ADllHandle, i2d_PKCS7_bio_stream_procname);
  FuncLoadError := not assigned(i2d_PKCS7_bio_stream);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_bio_stream_allownil)}
    i2d_PKCS7_bio_stream := @ERR_i2d_PKCS7_bio_stream;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_stream_introduced)}
    if LibVersion < i2d_PKCS7_bio_stream_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_bio_stream)}
      i2d_PKCS7_bio_stream := @FC_i2d_PKCS7_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_stream_removed)}
    if i2d_PKCS7_bio_stream_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_bio_stream)}
      i2d_PKCS7_bio_stream := @_i2d_PKCS7_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_bio_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_bio_stream');
    {$ifend}
  end;


  PEM_write_bio_PKCS7_stream := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS7_stream_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS7_stream);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS7_stream_allownil)}
    PEM_write_bio_PKCS7_stream := @ERR_PEM_write_bio_PKCS7_stream;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_stream_introduced)}
    if LibVersion < PEM_write_bio_PKCS7_stream_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS7_stream)}
      PEM_write_bio_PKCS7_stream := @FC_PEM_write_bio_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_stream_removed)}
    if PEM_write_bio_PKCS7_stream_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS7_stream)}
      PEM_write_bio_PKCS7_stream := @_PEM_write_bio_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS7_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS7_stream');
    {$ifend}
  end;


  PKCS7_ctrl := LoadLibFunction(ADllHandle, PKCS7_ctrl_procname);
  FuncLoadError := not assigned(PKCS7_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ctrl_allownil)}
    PKCS7_ctrl := @ERR_PKCS7_ctrl;
    {$ifend}
    {$if declared(PKCS7_ctrl_introduced)}
    if LibVersion < PKCS7_ctrl_introduced then
    begin
      {$if declared(FC_PKCS7_ctrl)}
      PKCS7_ctrl := @FC_PKCS7_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ctrl_removed)}
    if PKCS7_ctrl_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ctrl)}
      PKCS7_ctrl := @_PKCS7_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ctrl');
    {$ifend}
  end;


  PKCS7_set_type := LoadLibFunction(ADllHandle, PKCS7_set_type_procname);
  FuncLoadError := not assigned(PKCS7_set_type);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_type_allownil)}
    PKCS7_set_type := @ERR_PKCS7_set_type;
    {$ifend}
    {$if declared(PKCS7_set_type_introduced)}
    if LibVersion < PKCS7_set_type_introduced then
    begin
      {$if declared(FC_PKCS7_set_type)}
      PKCS7_set_type := @FC_PKCS7_set_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_type_removed)}
    if PKCS7_set_type_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_type)}
      PKCS7_set_type := @_PKCS7_set_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_type');
    {$ifend}
  end;


  PKCS7_set0_type_other := LoadLibFunction(ADllHandle, PKCS7_set0_type_other_procname);
  FuncLoadError := not assigned(PKCS7_set0_type_other);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set0_type_other_allownil)}
    PKCS7_set0_type_other := @ERR_PKCS7_set0_type_other;
    {$ifend}
    {$if declared(PKCS7_set0_type_other_introduced)}
    if LibVersion < PKCS7_set0_type_other_introduced then
    begin
      {$if declared(FC_PKCS7_set0_type_other)}
      PKCS7_set0_type_other := @FC_PKCS7_set0_type_other;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set0_type_other_removed)}
    if PKCS7_set0_type_other_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set0_type_other)}
      PKCS7_set0_type_other := @_PKCS7_set0_type_other;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set0_type_other_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set0_type_other');
    {$ifend}
  end;


  PKCS7_set_content := LoadLibFunction(ADllHandle, PKCS7_set_content_procname);
  FuncLoadError := not assigned(PKCS7_set_content);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_content_allownil)}
    PKCS7_set_content := @ERR_PKCS7_set_content;
    {$ifend}
    {$if declared(PKCS7_set_content_introduced)}
    if LibVersion < PKCS7_set_content_introduced then
    begin
      {$if declared(FC_PKCS7_set_content)}
      PKCS7_set_content := @FC_PKCS7_set_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_content_removed)}
    if PKCS7_set_content_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_content)}
      PKCS7_set_content := @_PKCS7_set_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_content_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_content');
    {$ifend}
  end;


  PKCS7_SIGNER_INFO_set := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_set_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_set_allownil)}
    PKCS7_SIGNER_INFO_set := @ERR_PKCS7_SIGNER_INFO_set;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_set_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_set_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_set)}
      PKCS7_SIGNER_INFO_set := @FC_PKCS7_SIGNER_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_set_removed)}
    if PKCS7_SIGNER_INFO_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_set)}
      PKCS7_SIGNER_INFO_set := @_PKCS7_SIGNER_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_set');
    {$ifend}
  end;


  PKCS7_SIGNER_INFO_sign := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_sign_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_sign);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_sign_allownil)}
    PKCS7_SIGNER_INFO_sign := @ERR_PKCS7_SIGNER_INFO_sign;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_sign_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_sign_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_sign)}
      PKCS7_SIGNER_INFO_sign := @FC_PKCS7_SIGNER_INFO_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_sign_removed)}
    if PKCS7_SIGNER_INFO_sign_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_sign)}
      PKCS7_SIGNER_INFO_sign := @_PKCS7_SIGNER_INFO_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_sign');
    {$ifend}
  end;


  PKCS7_add_signer := LoadLibFunction(ADllHandle, PKCS7_add_signer_procname);
  FuncLoadError := not assigned(PKCS7_add_signer);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_signer_allownil)}
    PKCS7_add_signer := @ERR_PKCS7_add_signer;
    {$ifend}
    {$if declared(PKCS7_add_signer_introduced)}
    if LibVersion < PKCS7_add_signer_introduced then
    begin
      {$if declared(FC_PKCS7_add_signer)}
      PKCS7_add_signer := @FC_PKCS7_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_signer_removed)}
    if PKCS7_add_signer_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_signer)}
      PKCS7_add_signer := @_PKCS7_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_signer');
    {$ifend}
  end;


  PKCS7_add_certificate := LoadLibFunction(ADllHandle, PKCS7_add_certificate_procname);
  FuncLoadError := not assigned(PKCS7_add_certificate);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_certificate_allownil)}
    PKCS7_add_certificate := @ERR_PKCS7_add_certificate;
    {$ifend}
    {$if declared(PKCS7_add_certificate_introduced)}
    if LibVersion < PKCS7_add_certificate_introduced then
    begin
      {$if declared(FC_PKCS7_add_certificate)}
      PKCS7_add_certificate := @FC_PKCS7_add_certificate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_certificate_removed)}
    if PKCS7_add_certificate_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_certificate)}
      PKCS7_add_certificate := @_PKCS7_add_certificate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_certificate_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_certificate');
    {$ifend}
  end;


  PKCS7_add_crl := LoadLibFunction(ADllHandle, PKCS7_add_crl_procname);
  FuncLoadError := not assigned(PKCS7_add_crl);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_crl_allownil)}
    PKCS7_add_crl := @ERR_PKCS7_add_crl;
    {$ifend}
    {$if declared(PKCS7_add_crl_introduced)}
    if LibVersion < PKCS7_add_crl_introduced then
    begin
      {$if declared(FC_PKCS7_add_crl)}
      PKCS7_add_crl := @FC_PKCS7_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_crl_removed)}
    if PKCS7_add_crl_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_crl)}
      PKCS7_add_crl := @_PKCS7_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_crl');
    {$ifend}
  end;


  PKCS7_content_new := LoadLibFunction(ADllHandle, PKCS7_content_new_procname);
  FuncLoadError := not assigned(PKCS7_content_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_content_new_allownil)}
    PKCS7_content_new := @ERR_PKCS7_content_new;
    {$ifend}
    {$if declared(PKCS7_content_new_introduced)}
    if LibVersion < PKCS7_content_new_introduced then
    begin
      {$if declared(FC_PKCS7_content_new)}
      PKCS7_content_new := @FC_PKCS7_content_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_content_new_removed)}
    if PKCS7_content_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_content_new)}
      PKCS7_content_new := @_PKCS7_content_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_content_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_content_new');
    {$ifend}
  end;


  PKCS7_dataVerify := LoadLibFunction(ADllHandle, PKCS7_dataVerify_procname);
  FuncLoadError := not assigned(PKCS7_dataVerify);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataVerify_allownil)}
    PKCS7_dataVerify := @ERR_PKCS7_dataVerify;
    {$ifend}
    {$if declared(PKCS7_dataVerify_introduced)}
    if LibVersion < PKCS7_dataVerify_introduced then
    begin
      {$if declared(FC_PKCS7_dataVerify)}
      PKCS7_dataVerify := @FC_PKCS7_dataVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataVerify_removed)}
    if PKCS7_dataVerify_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataVerify)}
      PKCS7_dataVerify := @_PKCS7_dataVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataVerify_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataVerify');
    {$ifend}
  end;


  PKCS7_signatureVerify := LoadLibFunction(ADllHandle, PKCS7_signatureVerify_procname);
  FuncLoadError := not assigned(PKCS7_signatureVerify);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_signatureVerify_allownil)}
    PKCS7_signatureVerify := @ERR_PKCS7_signatureVerify;
    {$ifend}
    {$if declared(PKCS7_signatureVerify_introduced)}
    if LibVersion < PKCS7_signatureVerify_introduced then
    begin
      {$if declared(FC_PKCS7_signatureVerify)}
      PKCS7_signatureVerify := @FC_PKCS7_signatureVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_signatureVerify_removed)}
    if PKCS7_signatureVerify_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_signatureVerify)}
      PKCS7_signatureVerify := @_PKCS7_signatureVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_signatureVerify_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_signatureVerify');
    {$ifend}
  end;


  PKCS7_dataInit := LoadLibFunction(ADllHandle, PKCS7_dataInit_procname);
  FuncLoadError := not assigned(PKCS7_dataInit);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataInit_allownil)}
    PKCS7_dataInit := @ERR_PKCS7_dataInit;
    {$ifend}
    {$if declared(PKCS7_dataInit_introduced)}
    if LibVersion < PKCS7_dataInit_introduced then
    begin
      {$if declared(FC_PKCS7_dataInit)}
      PKCS7_dataInit := @FC_PKCS7_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataInit_removed)}
    if PKCS7_dataInit_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataInit)}
      PKCS7_dataInit := @_PKCS7_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataInit_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataInit');
    {$ifend}
  end;


  PKCS7_dataFinal := LoadLibFunction(ADllHandle, PKCS7_dataFinal_procname);
  FuncLoadError := not assigned(PKCS7_dataFinal);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataFinal_allownil)}
    PKCS7_dataFinal := @ERR_PKCS7_dataFinal;
    {$ifend}
    {$if declared(PKCS7_dataFinal_introduced)}
    if LibVersion < PKCS7_dataFinal_introduced then
    begin
      {$if declared(FC_PKCS7_dataFinal)}
      PKCS7_dataFinal := @FC_PKCS7_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataFinal_removed)}
    if PKCS7_dataFinal_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataFinal)}
      PKCS7_dataFinal := @_PKCS7_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataFinal');
    {$ifend}
  end;


  PKCS7_dataDecode := LoadLibFunction(ADllHandle, PKCS7_dataDecode_procname);
  FuncLoadError := not assigned(PKCS7_dataDecode);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataDecode_allownil)}
    PKCS7_dataDecode := @ERR_PKCS7_dataDecode;
    {$ifend}
    {$if declared(PKCS7_dataDecode_introduced)}
    if LibVersion < PKCS7_dataDecode_introduced then
    begin
      {$if declared(FC_PKCS7_dataDecode)}
      PKCS7_dataDecode := @FC_PKCS7_dataDecode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataDecode_removed)}
    if PKCS7_dataDecode_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataDecode)}
      PKCS7_dataDecode := @_PKCS7_dataDecode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataDecode_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataDecode');
    {$ifend}
  end;


  PKCS7_add_signature := LoadLibFunction(ADllHandle, PKCS7_add_signature_procname);
  FuncLoadError := not assigned(PKCS7_add_signature);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_signature_allownil)}
    PKCS7_add_signature := @ERR_PKCS7_add_signature;
    {$ifend}
    {$if declared(PKCS7_add_signature_introduced)}
    if LibVersion < PKCS7_add_signature_introduced then
    begin
      {$if declared(FC_PKCS7_add_signature)}
      PKCS7_add_signature := @FC_PKCS7_add_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_signature_removed)}
    if PKCS7_add_signature_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_signature)}
      PKCS7_add_signature := @_PKCS7_add_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_signature');
    {$ifend}
  end;


  PKCS7_cert_from_signer_info := LoadLibFunction(ADllHandle, PKCS7_cert_from_signer_info_procname);
  FuncLoadError := not assigned(PKCS7_cert_from_signer_info);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_cert_from_signer_info_allownil)}
    PKCS7_cert_from_signer_info := @ERR_PKCS7_cert_from_signer_info;
    {$ifend}
    {$if declared(PKCS7_cert_from_signer_info_introduced)}
    if LibVersion < PKCS7_cert_from_signer_info_introduced then
    begin
      {$if declared(FC_PKCS7_cert_from_signer_info)}
      PKCS7_cert_from_signer_info := @FC_PKCS7_cert_from_signer_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_cert_from_signer_info_removed)}
    if PKCS7_cert_from_signer_info_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_cert_from_signer_info)}
      PKCS7_cert_from_signer_info := @_PKCS7_cert_from_signer_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_cert_from_signer_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_cert_from_signer_info');
    {$ifend}
  end;


  PKCS7_set_digest := LoadLibFunction(ADllHandle, PKCS7_set_digest_procname);
  FuncLoadError := not assigned(PKCS7_set_digest);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_digest_allownil)}
    PKCS7_set_digest := @ERR_PKCS7_set_digest;
    {$ifend}
    {$if declared(PKCS7_set_digest_introduced)}
    if LibVersion < PKCS7_set_digest_introduced then
    begin
      {$if declared(FC_PKCS7_set_digest)}
      PKCS7_set_digest := @FC_PKCS7_set_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_digest_removed)}
    if PKCS7_set_digest_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_digest)}
      PKCS7_set_digest := @_PKCS7_set_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_digest');
    {$ifend}
  end;


  PKCS7_add_recipient := LoadLibFunction(ADllHandle, PKCS7_add_recipient_procname);
  FuncLoadError := not assigned(PKCS7_add_recipient);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_recipient_allownil)}
    PKCS7_add_recipient := @ERR_PKCS7_add_recipient;
    {$ifend}
    {$if declared(PKCS7_add_recipient_introduced)}
    if LibVersion < PKCS7_add_recipient_introduced then
    begin
      {$if declared(FC_PKCS7_add_recipient)}
      PKCS7_add_recipient := @FC_PKCS7_add_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_recipient_removed)}
    if PKCS7_add_recipient_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_recipient)}
      PKCS7_add_recipient := @_PKCS7_add_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_recipient_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_recipient');
    {$ifend}
  end;


  PKCS7_SIGNER_INFO_get0_algs := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_get0_algs_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_get0_algs);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_get0_algs_allownil)}
    PKCS7_SIGNER_INFO_get0_algs := @ERR_PKCS7_SIGNER_INFO_get0_algs;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_get0_algs_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_get0_algs_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_get0_algs)}
      PKCS7_SIGNER_INFO_get0_algs := @FC_PKCS7_SIGNER_INFO_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_get0_algs_removed)}
    if PKCS7_SIGNER_INFO_get0_algs_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_get0_algs)}
      PKCS7_SIGNER_INFO_get0_algs := @_PKCS7_SIGNER_INFO_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_get0_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_get0_algs');
    {$ifend}
  end;


  PKCS7_RECIP_INFO_get0_alg := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_get0_alg_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_get0_alg);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_get0_alg_allownil)}
    PKCS7_RECIP_INFO_get0_alg := @ERR_PKCS7_RECIP_INFO_get0_alg;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_get0_alg_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_get0_alg_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_get0_alg)}
      PKCS7_RECIP_INFO_get0_alg := @FC_PKCS7_RECIP_INFO_get0_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_get0_alg_removed)}
    if PKCS7_RECIP_INFO_get0_alg_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_get0_alg)}
      PKCS7_RECIP_INFO_get0_alg := @_PKCS7_RECIP_INFO_get0_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_get0_alg_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_get0_alg');
    {$ifend}
  end;


  PKCS7_add_recipient_info := LoadLibFunction(ADllHandle, PKCS7_add_recipient_info_procname);
  FuncLoadError := not assigned(PKCS7_add_recipient_info);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_recipient_info_allownil)}
    PKCS7_add_recipient_info := @ERR_PKCS7_add_recipient_info;
    {$ifend}
    {$if declared(PKCS7_add_recipient_info_introduced)}
    if LibVersion < PKCS7_add_recipient_info_introduced then
    begin
      {$if declared(FC_PKCS7_add_recipient_info)}
      PKCS7_add_recipient_info := @FC_PKCS7_add_recipient_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_recipient_info_removed)}
    if PKCS7_add_recipient_info_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_recipient_info)}
      PKCS7_add_recipient_info := @_PKCS7_add_recipient_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_recipient_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_recipient_info');
    {$ifend}
  end;


  PKCS7_RECIP_INFO_set := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_set_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_set_allownil)}
    PKCS7_RECIP_INFO_set := @ERR_PKCS7_RECIP_INFO_set;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_set_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_set_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_set)}
      PKCS7_RECIP_INFO_set := @FC_PKCS7_RECIP_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_set_removed)}
    if PKCS7_RECIP_INFO_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_set)}
      PKCS7_RECIP_INFO_set := @_PKCS7_RECIP_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_set');
    {$ifend}
  end;


  PKCS7_set_cipher := LoadLibFunction(ADllHandle, PKCS7_set_cipher_procname);
  FuncLoadError := not assigned(PKCS7_set_cipher);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_cipher_allownil)}
    PKCS7_set_cipher := @ERR_PKCS7_set_cipher;
    {$ifend}
    {$if declared(PKCS7_set_cipher_introduced)}
    if LibVersion < PKCS7_set_cipher_introduced then
    begin
      {$if declared(FC_PKCS7_set_cipher)}
      PKCS7_set_cipher := @FC_PKCS7_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_cipher_removed)}
    if PKCS7_set_cipher_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_cipher)}
      PKCS7_set_cipher := @_PKCS7_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_cipher');
    {$ifend}
  end;


  PKCS7_stream := LoadLibFunction(ADllHandle, PKCS7_stream_procname);
  FuncLoadError := not assigned(PKCS7_stream);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_stream_allownil)}
    PKCS7_stream := @ERR_PKCS7_stream;
    {$ifend}
    {$if declared(PKCS7_stream_introduced)}
    if LibVersion < PKCS7_stream_introduced then
    begin
      {$if declared(FC_PKCS7_stream)}
      PKCS7_stream := @FC_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_stream_removed)}
    if PKCS7_stream_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_stream)}
      PKCS7_stream := @_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_stream');
    {$ifend}
  end;


  PKCS7_get_issuer_and_serial := LoadLibFunction(ADllHandle, PKCS7_get_issuer_and_serial_procname);
  FuncLoadError := not assigned(PKCS7_get_issuer_and_serial);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_issuer_and_serial_allownil)}
    PKCS7_get_issuer_and_serial := @ERR_PKCS7_get_issuer_and_serial;
    {$ifend}
    {$if declared(PKCS7_get_issuer_and_serial_introduced)}
    if LibVersion < PKCS7_get_issuer_and_serial_introduced then
    begin
      {$if declared(FC_PKCS7_get_issuer_and_serial)}
      PKCS7_get_issuer_and_serial := @FC_PKCS7_get_issuer_and_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_issuer_and_serial_removed)}
    if PKCS7_get_issuer_and_serial_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_issuer_and_serial)}
      PKCS7_get_issuer_and_serial := @_PKCS7_get_issuer_and_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_issuer_and_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_issuer_and_serial');
    {$ifend}
  end;


  PKCS7_add_signed_attribute := LoadLibFunction(ADllHandle, PKCS7_add_signed_attribute_procname);
  FuncLoadError := not assigned(PKCS7_add_signed_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_signed_attribute_allownil)}
    PKCS7_add_signed_attribute := @ERR_PKCS7_add_signed_attribute;
    {$ifend}
    {$if declared(PKCS7_add_signed_attribute_introduced)}
    if LibVersion < PKCS7_add_signed_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_add_signed_attribute)}
      PKCS7_add_signed_attribute := @FC_PKCS7_add_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_signed_attribute_removed)}
    if PKCS7_add_signed_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_signed_attribute)}
      PKCS7_add_signed_attribute := @_PKCS7_add_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_signed_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_signed_attribute');
    {$ifend}
  end;


  PKCS7_add_attribute := LoadLibFunction(ADllHandle, PKCS7_add_attribute_procname);
  FuncLoadError := not assigned(PKCS7_add_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_attribute_allownil)}
    PKCS7_add_attribute := @ERR_PKCS7_add_attribute;
    {$ifend}
    {$if declared(PKCS7_add_attribute_introduced)}
    if LibVersion < PKCS7_add_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_add_attribute)}
      PKCS7_add_attribute := @FC_PKCS7_add_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_attribute_removed)}
    if PKCS7_add_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_attribute)}
      PKCS7_add_attribute := @_PKCS7_add_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_attribute');
    {$ifend}
  end;


  PKCS7_get_attribute := LoadLibFunction(ADllHandle, PKCS7_get_attribute_procname);
  FuncLoadError := not assigned(PKCS7_get_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_attribute_allownil)}
    PKCS7_get_attribute := @ERR_PKCS7_get_attribute;
    {$ifend}
    {$if declared(PKCS7_get_attribute_introduced)}
    if LibVersion < PKCS7_get_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_get_attribute)}
      PKCS7_get_attribute := @FC_PKCS7_get_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_attribute_removed)}
    if PKCS7_get_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_attribute)}
      PKCS7_get_attribute := @_PKCS7_get_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_attribute');
    {$ifend}
  end;


  PKCS7_get_signed_attribute := LoadLibFunction(ADllHandle, PKCS7_get_signed_attribute_procname);
  FuncLoadError := not assigned(PKCS7_get_signed_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_signed_attribute_allownil)}
    PKCS7_get_signed_attribute := @ERR_PKCS7_get_signed_attribute;
    {$ifend}
    {$if declared(PKCS7_get_signed_attribute_introduced)}
    if LibVersion < PKCS7_get_signed_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_get_signed_attribute)}
      PKCS7_get_signed_attribute := @FC_PKCS7_get_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_signed_attribute_removed)}
    if PKCS7_get_signed_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_signed_attribute)}
      PKCS7_get_signed_attribute := @_PKCS7_get_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_signed_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_signed_attribute');
    {$ifend}
  end;


  PKCS7_sign_add_signer := LoadLibFunction(ADllHandle, PKCS7_sign_add_signer_procname);
  FuncLoadError := not assigned(PKCS7_sign_add_signer);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_sign_add_signer_allownil)}
    PKCS7_sign_add_signer := @ERR_PKCS7_sign_add_signer;
    {$ifend}
    {$if declared(PKCS7_sign_add_signer_introduced)}
    if LibVersion < PKCS7_sign_add_signer_introduced then
    begin
      {$if declared(FC_PKCS7_sign_add_signer)}
      PKCS7_sign_add_signer := @FC_PKCS7_sign_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_sign_add_signer_removed)}
    if PKCS7_sign_add_signer_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_sign_add_signer)}
      PKCS7_sign_add_signer := @_PKCS7_sign_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_sign_add_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_sign_add_signer');
    {$ifend}
  end;


  PKCS7_final := LoadLibFunction(ADllHandle, PKCS7_final_procname);
  FuncLoadError := not assigned(PKCS7_final);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_final_allownil)}
    PKCS7_final := @ERR_PKCS7_final;
    {$ifend}
    {$if declared(PKCS7_final_introduced)}
    if LibVersion < PKCS7_final_introduced then
    begin
      {$if declared(FC_PKCS7_final)}
      PKCS7_final := @FC_PKCS7_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_final_removed)}
    if PKCS7_final_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_final)}
      PKCS7_final := @_PKCS7_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_final_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_final');
    {$ifend}
  end;


  PKCS7_decrypt := LoadLibFunction(ADllHandle, PKCS7_decrypt_procname);
  FuncLoadError := not assigned(PKCS7_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_decrypt_allownil)}
    PKCS7_decrypt := @ERR_PKCS7_decrypt;
    {$ifend}
    {$if declared(PKCS7_decrypt_introduced)}
    if LibVersion < PKCS7_decrypt_introduced then
    begin
      {$if declared(FC_PKCS7_decrypt)}
      PKCS7_decrypt := @FC_PKCS7_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_decrypt_removed)}
    if PKCS7_decrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_decrypt)}
      PKCS7_decrypt := @_PKCS7_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_decrypt');
    {$ifend}
  end;


  PKCS7_add_attrib_content_type := LoadLibFunction(ADllHandle, PKCS7_add_attrib_content_type_procname);
  FuncLoadError := not assigned(PKCS7_add_attrib_content_type);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_attrib_content_type_allownil)}
    PKCS7_add_attrib_content_type := @ERR_PKCS7_add_attrib_content_type;
    {$ifend}
    {$if declared(PKCS7_add_attrib_content_type_introduced)}
    if LibVersion < PKCS7_add_attrib_content_type_introduced then
    begin
      {$if declared(FC_PKCS7_add_attrib_content_type)}
      PKCS7_add_attrib_content_type := @FC_PKCS7_add_attrib_content_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_attrib_content_type_removed)}
    if PKCS7_add_attrib_content_type_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_attrib_content_type)}
      PKCS7_add_attrib_content_type := @_PKCS7_add_attrib_content_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_attrib_content_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_attrib_content_type');
    {$ifend}
  end;


  PKCS7_add0_attrib_signing_time := LoadLibFunction(ADllHandle, PKCS7_add0_attrib_signing_time_procname);
  FuncLoadError := not assigned(PKCS7_add0_attrib_signing_time);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add0_attrib_signing_time_allownil)}
    PKCS7_add0_attrib_signing_time := @ERR_PKCS7_add0_attrib_signing_time;
    {$ifend}
    {$if declared(PKCS7_add0_attrib_signing_time_introduced)}
    if LibVersion < PKCS7_add0_attrib_signing_time_introduced then
    begin
      {$if declared(FC_PKCS7_add0_attrib_signing_time)}
      PKCS7_add0_attrib_signing_time := @FC_PKCS7_add0_attrib_signing_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add0_attrib_signing_time_removed)}
    if PKCS7_add0_attrib_signing_time_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add0_attrib_signing_time)}
      PKCS7_add0_attrib_signing_time := @_PKCS7_add0_attrib_signing_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add0_attrib_signing_time_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add0_attrib_signing_time');
    {$ifend}
  end;


  PKCS7_add1_attrib_digest := LoadLibFunction(ADllHandle, PKCS7_add1_attrib_digest_procname);
  FuncLoadError := not assigned(PKCS7_add1_attrib_digest);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add1_attrib_digest_allownil)}
    PKCS7_add1_attrib_digest := @ERR_PKCS7_add1_attrib_digest;
    {$ifend}
    {$if declared(PKCS7_add1_attrib_digest_introduced)}
    if LibVersion < PKCS7_add1_attrib_digest_introduced then
    begin
      {$if declared(FC_PKCS7_add1_attrib_digest)}
      PKCS7_add1_attrib_digest := @FC_PKCS7_add1_attrib_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add1_attrib_digest_removed)}
    if PKCS7_add1_attrib_digest_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add1_attrib_digest)}
      PKCS7_add1_attrib_digest := @_PKCS7_add1_attrib_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add1_attrib_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add1_attrib_digest');
    {$ifend}
  end;


  SMIME_write_PKCS7 := LoadLibFunction(ADllHandle, SMIME_write_PKCS7_procname);
  FuncLoadError := not assigned(SMIME_write_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_write_PKCS7_allownil)}
    SMIME_write_PKCS7 := @ERR_SMIME_write_PKCS7;
    {$ifend}
    {$if declared(SMIME_write_PKCS7_introduced)}
    if LibVersion < SMIME_write_PKCS7_introduced then
    begin
      {$if declared(FC_SMIME_write_PKCS7)}
      SMIME_write_PKCS7 := @FC_SMIME_write_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_write_PKCS7_removed)}
    if SMIME_write_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_SMIME_write_PKCS7)}
      SMIME_write_PKCS7 := @_SMIME_write_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_write_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_write_PKCS7');
    {$ifend}
  end;


  SMIME_read_PKCS7 := LoadLibFunction(ADllHandle, SMIME_read_PKCS7_procname);
  FuncLoadError := not assigned(SMIME_read_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_PKCS7_allownil)}
    SMIME_read_PKCS7 := @ERR_SMIME_read_PKCS7;
    {$ifend}
    {$if declared(SMIME_read_PKCS7_introduced)}
    if LibVersion < SMIME_read_PKCS7_introduced then
    begin
      {$if declared(FC_SMIME_read_PKCS7)}
      SMIME_read_PKCS7 := @FC_SMIME_read_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_PKCS7_removed)}
    if SMIME_read_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_PKCS7)}
      SMIME_read_PKCS7 := @_SMIME_read_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_PKCS7');
    {$ifend}
  end;


  BIO_new_PKCS7 := LoadLibFunction(ADllHandle, BIO_new_PKCS7_procname);
  FuncLoadError := not assigned(BIO_new_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_PKCS7_allownil)}
    BIO_new_PKCS7 := @ERR_BIO_new_PKCS7;
    {$ifend}
    {$if declared(BIO_new_PKCS7_introduced)}
    if LibVersion < BIO_new_PKCS7_introduced then
    begin
      {$if declared(FC_BIO_new_PKCS7)}
      BIO_new_PKCS7 := @FC_BIO_new_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_PKCS7_removed)}
    if BIO_new_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_PKCS7)}
      BIO_new_PKCS7 := @_BIO_new_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_PKCS7');
    {$ifend}
  end;


end;

procedure Unload;
begin
  PKCS7_ISSUER_AND_SERIAL_digest := nil;
  PKCS7_dup := nil;
  d2i_PKCS7_bio := nil;
  i2d_PKCS7_bio := nil;
  i2d_PKCS7_bio_stream := nil;
  PEM_write_bio_PKCS7_stream := nil;
  PKCS7_ctrl := nil;
  PKCS7_set_type := nil;
  PKCS7_set0_type_other := nil;
  PKCS7_set_content := nil;
  PKCS7_SIGNER_INFO_set := nil;
  PKCS7_SIGNER_INFO_sign := nil;
  PKCS7_add_signer := nil;
  PKCS7_add_certificate := nil;
  PKCS7_add_crl := nil;
  PKCS7_content_new := nil;
  PKCS7_dataVerify := nil;
  PKCS7_signatureVerify := nil;
  PKCS7_dataInit := nil;
  PKCS7_dataFinal := nil;
  PKCS7_dataDecode := nil;
  PKCS7_add_signature := nil;
  PKCS7_cert_from_signer_info := nil;
  PKCS7_set_digest := nil;
  PKCS7_add_recipient := nil;
  PKCS7_SIGNER_INFO_get0_algs := nil;
  PKCS7_RECIP_INFO_get0_alg := nil;
  PKCS7_add_recipient_info := nil;
  PKCS7_RECIP_INFO_set := nil;
  PKCS7_set_cipher := nil;
  PKCS7_stream := nil;
  PKCS7_get_issuer_and_serial := nil;
  PKCS7_add_signed_attribute := nil;
  PKCS7_add_attribute := nil;
  PKCS7_get_attribute := nil;
  PKCS7_get_signed_attribute := nil;
  PKCS7_sign_add_signer := nil;
  PKCS7_final := nil;
  PKCS7_decrypt := nil;
  PKCS7_add_attrib_content_type := nil;
  PKCS7_add0_attrib_signing_time := nil;
  PKCS7_add1_attrib_digest := nil;
  SMIME_write_PKCS7 := nil;
  SMIME_read_PKCS7 := nil;
  BIO_new_PKCS7 := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
