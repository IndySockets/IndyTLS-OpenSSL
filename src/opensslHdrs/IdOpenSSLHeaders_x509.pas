(* This unit was generated from the source file x509.h2pas 
It should not be modified directly. All changes should be made to x509.h2pas
and this file regenerated *)

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


unit IdOpenSSLHeaders_x509;


interface

// Headers for OpenSSL 1.1.1
// x509.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_asn1,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_stack,
  IdOpenSSLHeaders_objects,
  IdOpenSSLHeaders_ossl_typ;

// the following emits are a workaround to a
// name conflict with Win32 API header files
{$IFDEF WINDOWS}
(*$HPPEMIT '#undef X509_EXTENSIONS'*)
(*$HPPEMIT '#undef X509_CERT_PAIR'*)
{$ENDIF}

type
  X509_ALGORS = type Pointer;

const
  (* Flags for X509_get_signature_info() *)
  (* Signature info is valid *)
  X509_SIG_INFO_VALID = $1;
  (* Signature is suitable for TLS use *)
  X509_SIG_INFO_TLS = $2;

  X509_FILETYPE_PEM     = 1;
  X509_FILETYPE_ASN1    = 2;
  X509_FILETYPE_DEFAULT = 3;

  X509v3_KU_DIGITAL_SIGNATURE = $0080;
  X509v3_KU_NON_REPUDIATION   = $0040;
  X509v3_KU_KEY_ENCIPHERMENT  = $0020;
  X509v3_KU_DATA_ENCIPHERMENT = $0010;
  X509v3_KU_KEY_AGREEMENT     = $0008;
  X509v3_KU_KEY_CERT_SIGN     = $0004;
  X509v3_KU_CRL_SIGN          = $0002;
  X509v3_KU_ENCIPHER_ONLY     = $0001;
  X509v3_KU_DECIPHER_ONLY     = $8000;
  X509v3_KU_UNDEF             = $ffff;

  X509_EX_V_NETSCAPE_HACK = $8000;
  X509_EX_V_INIT          = $0001;


  (* standard trust ids *)

  X509_TRUST_DEFAULT      = 0; (* Only valid in purpose settings *)

  X509_TRUST_COMPAT       = 1;
  X509_TRUST_SSL_CLIENT   = 2;
  X509_TRUST_SSL_SERVER   = 3;
  X509_TRUST_EMAIL        = 4;
  X509_TRUST_OBJECT_SIGN  = 5;
  X509_TRUST_OCSP_SIGN    = 6;
  X509_TRUST_OCSP_REQUEST = 7;
  X509_TRUST_TSA          = 8;

  (* Keep these up to date! *)
  X509_TRUST_MIN          = 1;
  X509_TRUST_MAX          = 8;

  (* trust_flags values *)
  X509_TRUST_DYNAMIC      = TOpenSSL_C_UINT(1) shl 0;
  X509_TRUST_DYNAMIC_NAME = TOpenSSL_C_UINT(1) shl 1;
  (* No compat trust if self-signed, preempts "DO_SS" *)
  X509_TRUST_NO_SS_COMPAT = TOpenSSL_C_UINT(1) shl 2;
  (* Compat trust if no explicit accepted trust EKUs *)
  X509_TRUST_DO_SS_COMPAT = TOpenSSL_C_UINT(1) shl 3;
  (* Accept "anyEKU" as a wildcard trust OID *)
  X509_TRUST_OK_ANY_EKU   = TOpenSSL_C_UINT(1) shl 4;

  (* check_trust return codes *)

  X509_TRUST_TRUSTED   = 1;
  X509_TRUST_REJECTED  = 2;
  X509_TRUST_UNTRUSTED = 3;

  (* Flags for X509_print_ex() *)

  X509_FLAG_COMPAT        = 0;
  X509_FLAG_NO_HEADER     = TOpenSSL_C_LONG(1);
  X509_FLAG_NO_VERSION    = TOpenSSL_C_LONG(1) shl 1;
  X509_FLAG_NO_SERIAL     = TOpenSSL_C_LONG(1) shl 2;
  X509_FLAG_NO_SIGNAME    = TOpenSSL_C_LONG(1) shl 3;
  X509_FLAG_NO_ISSUER     = TOpenSSL_C_LONG(1) shl 4;
  X509_FLAG_NO_VALIDITY   = TOpenSSL_C_LONG(1) shl 5;
  X509_FLAG_NO_SUBJECT    = TOpenSSL_C_LONG(1) shl 6;
  X509_FLAG_NO_PUBKEY     = TOpenSSL_C_LONG(1) shl 7;
  X509_FLAG_NO_EXTENSIONS = TOpenSSL_C_LONG(1) shl 8;
  X509_FLAG_NO_SIGDUMP    = TOpenSSL_C_LONG(1) shl 9;
  X509_FLAG_NO_AUX        = TOpenSSL_C_LONG(1) shl 10;
  X509_FLAG_NO_ATTRIBUTES = TOpenSSL_C_LONG(1) shl 11;
  X509_FLAG_NO_IDS        = TOpenSSL_C_LONG(1) shl 12;

  (* Flags specific to X509_NAME_print_ex() *)

  (* The field separator information *)

  XN_FLAG_SEP_MASK       = $f shl 16;

  XN_FLAG_COMPAT         = 0;(* Traditional; use old X509_NAME_print *)
  XN_FLAG_SEP_COMMA_PLUS = 1 shl 16;(* RFC2253 ,+ *)
  XN_FLAG_SEP_CPLUS_SPC  = 2 shl 16;(* ,+ spaced: more readable *)
  XN_FLAG_SEP_SPLUS_SPC  = 3 shl 16;(* ;+ spaced *)
  XN_FLAG_SEP_MULTILINE  = 4 shl 16;(* One line per field *)

  XN_FLAG_DN_REV         = 1 shl 20;(* Reverse DN order *)

  (* How the field name is shown *)

  XN_FLAG_FN_MASK        = $3 shl 21;

  XN_FLAG_FN_SN          = 0;(* Object short name *)
  XN_FLAG_FN_LN          = 1 shl 21;(* Object long name *)
  XN_FLAG_FN_OID         = 2 shl 21;(* Always use OIDs *)
  XN_FLAG_FN_NONE        = 3 shl 21;(* No field names *)

  XN_FLAG_SPC_EQ         = 1 shl 23;(* Put spaces round '=' *)

  {function codes}
  X509_F_ADD_CERT_DIR	= 100;
  X509_F_BY_FILE_CTRL	= 101;
  X509_F_CHECK_NAME_CONSTRAINTS	= 106;
  X509_F_CHECK_POLICY	= 145;
  X509_F_DIR_CTRL	= 102;
  X509_F_GET_CERT_BY_SUBJECT	= 103;
  X509_F_NETSCAPE_SPKI_B64_DECODE	= 129;
  X509_F_NETSCAPE_SPKI_B64_ENCODE	= 130;
  X509_F_X509AT_ADD1_ATTR	= 135;
  X509_F_X509V3_ADD_EXT	= 104;
  X509_F_X509_ATTRIBUTE_CREATE_BY_NID	= 136;
  X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ	= 137;
  X509_F_X509_ATTRIBUTE_CREATE_BY_TXT	= 140;
  X509_F_X509_ATTRIBUTE_GET0_DATA	= 139;
  X509_F_X509_ATTRIBUTE_SET1_DATA	= 138;
  X509_F_X509_CHECK_PRIVATE_KEY	= 128;
  X509_F_X509_CRL_DIFF	= 105;
  X509_F_X509_CRL_PRINT_FP	= 147;
  X509_F_X509_EXTENSION_CREATE_BY_NID	= 108;
  X509_F_X509_EXTENSION_CREATE_BY_OBJ	= 109;
  X509_F_X509_GET_PUBKEY_PARAMETERS	= 110;
  X509_F_X509_LOAD_CERT_CRL_FILE	= 132;
  X509_F_X509_LOAD_CERT_FILE	= 111;
  X509_F_X509_LOAD_CRL_FILE	= 112;
  X509_F_X509_NAME_ADD_ENTRY	= 113;
  X509_F_X509_NAME_ENTRY_CREATE_BY_NID	= 114;
  X509_F_X509_NAME_ENTRY_CREATE_BY_TXT	= 131;
  X509_F_X509_NAME_ENTRY_SET_OBJECT	= 115;
  X509_F_X509_NAME_ONELINE	= 116;
  X509_F_X509_NAME_PRINT	= 117;
  X509_F_X509_PRINT_EX_FP	= 118;
  X509_F_X509_PUBKEY_GET	= 119;
  X509_F_X509_PUBKEY_SET	= 120;
  X509_F_X509_REQ_CHECK_PRIVATE_KEY	= 144;
  X509_F_X509_REQ_PRINT_EX	= 121;
  X509_F_X509_REQ_PRINT_FP	= 122;
  X509_F_X509_REQ_TO_X509	= 123;
  X509_F_X509_STORE_ADD_CERT	= 124;
  X509_F_X509_STORE_ADD_CRL	= 125;
  X509_F_X509_STORE_CTX_GET1_ISSUER	= 146;
  X509_F_X509_STORE_CTX_INIT	= 143;
  X509_F_X509_STORE_CTX_NEW	= 142;
  X509_F_X509_STORE_CTX_PURPOSE_INHERIT	= 134;
  X509_F_X509_TO_X509_REQ	= 126;
  X509_F_X509_TRUST_ADD	= 133;
  X509_F_X509_TRUST_SET	= 141;
  X509_F_X509_VERIFY_CERT	= 127;

  {Reason Codes}
  X509_R_AKID_MISMATCH 				= 110;
  X509_R_BAD_X509_FILETYPE 		        = 100;
  X509_R_BASE64_DECODE_ERROR 		        = 118;
  X509_R_CANT_CHECK_DH_KEY 		        = 114;
  X509_R_CERT_ALREADY_IN_HASH_TABLE 		= 101;
  X509_R_CRL_ALREADY_DELTA 		        = 127;
  X509_R_CRL_VERIFY_FAILURE 		        = 131;
  X509_R_ERR_ASN1_LIB 		                = 102;
  X509_R_IDP_MISMATCH 		                = 128;
  X509_R_INVALID_DIRECTORY 		        = 113;
  X509_R_INVALID_FIELD_NAME 		        = 119;
  X509_R_INVALID_TRUST 		                = 123;
  X509_R_ISSUER_MISMATCH 		        = 129;
  X509_R_KEY_TYPE_MISMATCH	= 115;
  X509_R_KEY_VALUES_MISMATCH	= 116;
  X509_R_LOADING_CERT_DIR	= 103;
  X509_R_LOADING_DEFAULTS	= 104;
  X509_R_METHOD_NOT_SUPPORTED	= 124;
  X509_R_NAME_TOO_LONG	= 134;
  X509_R_NEWER_CRL_NOT_NEWER	= 132;
  X509_R_NO_CERT_SET_FOR_US_TO_VERIFY	= 105;
  X509_R_NO_CRL_NUMBER	= 130;
  X509_R_PUBLIC_KEY_DECODE_ERROR	= 125;
  X509_R_PUBLIC_KEY_ENCODE_ERROR	= 126;
  X509_R_SHOULD_RETRY	= 106;
  X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN	= 107;
  X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY	= 108;
  X509_R_UNKNOWN_KEY_TYPE	= 117;
  X509_R_UNKNOWN_NID	= 109;
  X509_R_UNKNOWN_PURPOSE_ID	= 121;
  X509_R_UNKNOWN_TRUST_ID	= 120;
  X509_R_UNSUPPORTED_ALGORITHM	= 111;
  X509_R_WRONG_LOOKUP_TYPE	= 112;
  X509_R_WRONG_TYPE	= 122;

  (*
   * This determines if we dump fields we don't recognise: RFC2253 requires
   * this.
   *)

  XN_FLAG_DUMP_UNKNOWN_FIELDS = 1 shl 24;

  XN_FLAG_FN_ALIGN = 1 shl 25;(* Align field names to 20
                                             * characters *)

  (* Complete set of RFC2253 flags *)

  XN_FLAG_RFC2253 = ASN1_STRFLGS_RFC2253 or XN_FLAG_SEP_COMMA_PLUS
    or XN_FLAG_DN_REV or XN_FLAG_FN_SN or XN_FLAG_DUMP_UNKNOWN_FIELDS;

  (* readable oneline form *)

  XN_FLAG_ONELINE = ASN1_STRFLGS_RFC2253 or ASN1_STRFLGS_ESC_QUOTE
    or XN_FLAG_SEP_CPLUS_SPC or XN_FLAG_SPC_EQ or XN_FLAG_FN_SN;

  (* readable multiline form *)

  XN_FLAG_MULTILINE = ASN1_STRFLGS_ESC_CTRL or ASN1_STRFLGS_ESC_MSB
    or XN_FLAG_SEP_MULTILINE or XN_FLAG_SPC_EQ or XN_FLAG_FN_LN or XN_FLAG_FN_ALIGN;

  X509_EXT_PACK_UNKNOWN = 1;
  X509_EXT_PACK_STRING  = 2;

type

  X509_val_st = record
    notBefore: PASN1_TIME;
    notAfter: PASN1_TIME;
  end;
  X509_VAL = X509_val_st;
  PX509_VAL = ^X509_VAL;
  PPX509_VAL = ^PX509_VAL;

  X509_SIG = type Pointer; // X509_sig_st
  PX509_SIG = ^X509_SIG;
  PPX509_SIG = ^PX509_SIG;

  X509_NAME_ENTRY = type Pointer; // X509_name_entry_st
  PX509_NAME_ENTRY = ^X509_NAME_ENTRY;
  PPX509_NAME_ENTRY = ^PX509_NAME_ENTRY;

  //DEFINE_STACK_OF(X509_NAME_ENTRY)
  PSTACK_OF_X509_NAME_ENTRY = type pointer;
  //
  //DEFINE_STACK_OF(X509_NAME)
  PSTACK_OF_X509_NAME = type pointer;

  X509_EXTENSION = type Pointer; // X509_extension_st
  PX509_EXTENSION = ^X509_EXTENSION;
  PPX509_EXTENSION = ^PX509_EXTENSION;

  //typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;
  //
  //DEFINE_STACK_OF(X509_EXTENSION)

  X509_ATTRIBUTE = type Pointer; // x509_attributes_st
  PX509_ATTRIBUTE = ^X509_ATTRIBUTE;
  PPX509_ATTRIBUTE = ^PX509_ATTRIBUTE;

  //DEFINE_STACK_OF(X509_ATTRIBUTE)

  X509_REQ_INFO = type Pointer; // X509_req_info_st
  PX509_REQ_INFO = ^X509_REQ_INFO;
  PPX509_REQ_INFO = ^PX509_REQ_INFO;

  X509_CERT_AUX = type Pointer; // x509_cert_aux_st

  X509_CINF = type Pointer; // x509_cinf_st

  //DEFINE_STACK_OF(X509)

  (* This is used for a table of trust checking functions *)

  Px509_trust_st = ^x509_trust_st;
  x509_trust_st = record
    trust: TOpenSSL_C_INT;
    flags: TOpenSSL_C_INT;
    check_trust: function(v1: Px509_trust_st; v2: PX509; v3: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
    name: PAnsiChar;
    arg1: TOpenSSL_C_INT;
    arg2: Pointer;
  end;
  X509_TRUST = x509_trust_st;
  PX509_TRUST = ^X509_TRUST;

  //DEFINE_STACK_OF(X509_TRUST)

  //DEFINE_STACK_OF(X509_REVOKED)
  X509_CRL_INFO = type Pointer; // X509_crl_info_st
  PX509_CRL_INFO = ^X509_CRL_INFO;
  PPX509_CRL_INFO = ^PX509_CRL_INFO;

  //DEFINE_STACK_OF(X509_CRL)

  private_key_st = record
    version: TOpenSSL_C_INT;
    (* The PKCS#8 data types *)
    enc_algor: PX509_ALGOR;
    enc_pkey: PASN1_OCTET_STRING; (* encrypted pub key *)
    (* When decrypted, the following will not be NULL *)
    dec_pkey: PEVP_PKEY;
    (* used to encrypt and decrypt *)
    key_length: TOpenSSL_C_INT;
    key_data: PAnsiChar;
    key_free: TOpenSSL_C_INT;               (* true if we should auto free key_data *)
    (* expanded version of 'enc_algor' *)
    cipher: EVP_CIPHER_INFO;
  end;
  X509_PKEY = private_key_st;
  PX509_PKEY = ^X509_PKEY;

  X509_info_st = record
    x509: PX509;
    crl: PX509_CRL;
    x_pkey: PX509_PKEY;
    enc_cipher: EVP_CIPHER_INFO;
    enc_len: TOpenSSL_C_INT;
    enc_data: PAnsiChar;
  end;
  X509_INFO = X509_info_st;
  PX509_INFO = ^X509_INFO;

  //DEFINE_STACK_OF(X509_INFO)

  (*
   * The next 2 structures and their 8 routines are used to manipulate Netscape's
   * spki structures - useful if you are writing a CA web page
   *)
  Netscape_spkac_st = record
    pubkey: PX509_PUBKEY;
    challenge: PASN1_IA5STRING;  (* challenge sent in atlas >= PR2 *)
  end;
  NETSCAPE_SPKAC = Netscape_spkac_st;
  PNETSCAPE_SPKAC = ^NETSCAPE_SPKAC;

  Netscape_spki_st = record
    spkac: PNETSCAPE_SPKAC;      (* signed public key and challenge *)
    sig_algor: X509_ALGOR;
    signature: PASN1_BIT_STRING;
  end;
  NETSCAPE_SPKI = Netscape_spki_st;
  PNETSCAPE_SPKI = ^NETSCAPE_SPKI;

  (* Netscape certificate sequence structure *)
//  Netscape_certificate_sequence: record
//    type_: PASN1_OBJECT;
//    certs: P --> STACK_OF(X509) <--;
//  end;
//  NETSCAPE_CERT_SEQUENCE = Netscape_certificate_sequence;

  (*- Unused (and iv length is wrong)
  typedef struct CBCParameter_st
          {
          unsigned char iv[8];
          } CBC_PARAM;
  *)

  (* Password based encryption structure *)
  PBEPARAM_st = record
    salt: PASN1_OCTET_STRING;
    iter: PASN1_INTEGER;
  end;
  PBEPARAM = PBEPARAM_st;

  (* Password based encryption V2 structures *)
  PBE2PARAM_st = record
    keyfunc: PX509_ALGOR;
    encryption: X509_ALGOR;
  end;
  PBE2PARAM = PBE2PARAM_st;

  PBKDF2PARAM_st = record
  (* Usually OCTET STRING but could be anything *)
    salt: PASN1_TYPE;
    iter: PASN1_INTEGER;
    keylength: PASN1_INTEGER;
    prf: X509_ALGOR;
  end;
  PBKDF2PARAM = PBKDF2PARAM_st;

  SCRYPT_PARAMS_st = record
    salt: PASN1_OCTET_STRING;
    costParameter: PASN1_INTEGER;
    blockSize: PASN1_INTEGER;
    parallelizationParameter: PASN1_INTEGER;
    keyLength: ASN1_INTEGER;
  end;
  SCRYPT_PARAMS = SCRYPT_PARAMS_st;

  //# define         X509_extract_key(x)     X509_get_pubkey(x)(*****)
  //# define         X509_REQ_extract_key(a) X509_REQ_get_pubkey(a)
  //# define         X509_name_cmp(a,b)      X509_NAME_cmp((a),(b))
  //

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM X509_CRL_set_default_method}
{$EXTERNALSYM X509_CRL_METHOD_free}
{$EXTERNALSYM X509_CRL_set_meth_data}
{$EXTERNALSYM X509_CRL_get_meth_data}
{$EXTERNALSYM X509_verify_cert_error_string}
{$EXTERNALSYM X509_verify}
{$EXTERNALSYM X509_REQ_verify}
{$EXTERNALSYM X509_CRL_verify}
{$EXTERNALSYM NETSCAPE_SPKI_verify}
{$EXTERNALSYM NETSCAPE_SPKI_b64_decode}
{$EXTERNALSYM NETSCAPE_SPKI_b64_encode}
{$EXTERNALSYM NETSCAPE_SPKI_get_pubkey}
{$EXTERNALSYM NETSCAPE_SPKI_set_pubkey}
{$EXTERNALSYM NETSCAPE_SPKI_print}
{$EXTERNALSYM X509_signature_dump}
{$EXTERNALSYM X509_signature_print}
{$EXTERNALSYM X509_sign}
{$EXTERNALSYM X509_sign_ctx}
{$EXTERNALSYM X509_REQ_sign}
{$EXTERNALSYM X509_REQ_sign_ctx}
{$EXTERNALSYM X509_CRL_sign}
{$EXTERNALSYM X509_CRL_sign_ctx}
{$EXTERNALSYM NETSCAPE_SPKI_sign}
{$EXTERNALSYM X509_pubkey_digest}
{$EXTERNALSYM X509_digest}
{$EXTERNALSYM X509_CRL_digest}
{$EXTERNALSYM X509_REQ_digest}
{$EXTERNALSYM X509_NAME_digest}
{$EXTERNALSYM d2i_X509_bio}
{$EXTERNALSYM i2d_X509_bio}
{$EXTERNALSYM d2i_X509_CRL_bio}
{$EXTERNALSYM i2d_X509_CRL_bio}
{$EXTERNALSYM d2i_X509_REQ_bio}
{$EXTERNALSYM i2d_X509_REQ_bio}
{$EXTERNALSYM d2i_RSAPrivateKey_bio}
{$EXTERNALSYM i2d_RSAPrivateKey_bio}
{$EXTERNALSYM d2i_RSAPublicKey_bio}
{$EXTERNALSYM i2d_RSAPublicKey_bio}
{$EXTERNALSYM d2i_RSA_PUBKEY_bio}
{$EXTERNALSYM i2d_RSA_PUBKEY_bio}
{$EXTERNALSYM d2i_DSA_PUBKEY_bio}
{$EXTERNALSYM i2d_DSA_PUBKEY_bio}
{$EXTERNALSYM d2i_DSAPrivateKey_bio}
{$EXTERNALSYM i2d_DSAPrivateKey_bio}
{$EXTERNALSYM d2i_EC_PUBKEY_bio}
{$EXTERNALSYM i2d_EC_PUBKEY_bio}
{$EXTERNALSYM d2i_ECPrivateKey_bio}
{$EXTERNALSYM i2d_ECPrivateKey_bio}
{$EXTERNALSYM d2i_PKCS8_bio}
{$EXTERNALSYM i2d_PKCS8_bio}
{$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO_bio}
{$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO_bio}
{$EXTERNALSYM i2d_PKCS8PrivateKeyInfo_bio}
{$EXTERNALSYM i2d_PrivateKey_bio}
{$EXTERNALSYM d2i_PrivateKey_bio}
{$EXTERNALSYM i2d_PUBKEY_bio}
{$EXTERNALSYM d2i_PUBKEY_bio}
{$EXTERNALSYM X509_dup}
{$EXTERNALSYM X509_ATTRIBUTE_dup}
{$EXTERNALSYM X509_EXTENSION_dup}
{$EXTERNALSYM X509_CRL_dup}
{$EXTERNALSYM X509_REVOKED_dup}
{$EXTERNALSYM X509_REQ_dup}
{$EXTERNALSYM X509_ALGOR_dup}
{$EXTERNALSYM X509_ALGOR_set0}
{$EXTERNALSYM X509_ALGOR_get0}
{$EXTERNALSYM X509_ALGOR_set_md}
{$EXTERNALSYM X509_ALGOR_cmp}
{$EXTERNALSYM X509_NAME_dup}
{$EXTERNALSYM X509_NAME_ENTRY_dup}
{$EXTERNALSYM X509_cmp_time}
{$EXTERNALSYM X509_cmp_current_time}
{$EXTERNALSYM X509_time_adj}
{$EXTERNALSYM X509_time_adj_ex}
{$EXTERNALSYM X509_gmtime_adj}
{$EXTERNALSYM X509_get_default_cert_area}
{$EXTERNALSYM X509_get_default_cert_dir}
{$EXTERNALSYM X509_get_default_cert_file}
{$EXTERNALSYM X509_get_default_cert_dir_env}
{$EXTERNALSYM X509_get_default_cert_file_env}
{$EXTERNALSYM X509_get_default_private_dir}
{$EXTERNALSYM X509_to_X509_REQ}
{$EXTERNALSYM X509_REQ_to_X509}
{$EXTERNALSYM X509_ALGOR_new}
{$EXTERNALSYM X509_ALGOR_free}
{$EXTERNALSYM d2i_X509_ALGOR}
{$EXTERNALSYM i2d_X509_ALGOR}
{$EXTERNALSYM X509_VAL_new}
{$EXTERNALSYM X509_VAL_free}
{$EXTERNALSYM d2i_X509_VAL}
{$EXTERNALSYM i2d_X509_VAL}
{$EXTERNALSYM X509_PUBKEY_new}
{$EXTERNALSYM X509_PUBKEY_free}
{$EXTERNALSYM d2i_X509_PUBKEY}
{$EXTERNALSYM i2d_X509_PUBKEY}
{$EXTERNALSYM X509_PUBKEY_set}
{$EXTERNALSYM X509_PUBKEY_get0}
{$EXTERNALSYM X509_PUBKEY_get}
{$EXTERNALSYM X509_get_pathlen}
{$EXTERNALSYM i2d_PUBKEY}
{$EXTERNALSYM d2i_PUBKEY}
{$EXTERNALSYM i2d_RSA_PUBKEY}
{$EXTERNALSYM d2i_RSA_PUBKEY}
{$EXTERNALSYM i2d_DSA_PUBKEY}
{$EXTERNALSYM d2i_DSA_PUBKEY}
{$EXTERNALSYM i2d_EC_PUBKEY}
{$EXTERNALSYM d2i_EC_PUBKEY}
{$EXTERNALSYM X509_SIG_new}
{$EXTERNALSYM X509_SIG_free}
{$EXTERNALSYM d2i_X509_SIG}
{$EXTERNALSYM i2d_X509_SIG}
{$EXTERNALSYM X509_SIG_get0}
{$EXTERNALSYM X509_SIG_getm}
{$EXTERNALSYM X509_REQ_INFO_new}
{$EXTERNALSYM X509_REQ_INFO_free}
{$EXTERNALSYM d2i_X509_REQ_INFO}
{$EXTERNALSYM i2d_X509_REQ_INFO}
{$EXTERNALSYM X509_REQ_new}
{$EXTERNALSYM X509_REQ_free}
{$EXTERNALSYM d2i_X509_REQ}
{$EXTERNALSYM i2d_X509_REQ}
{$EXTERNALSYM X509_ATTRIBUTE_new}
{$EXTERNALSYM X509_ATTRIBUTE_free}
{$EXTERNALSYM d2i_X509_ATTRIBUTE}
{$EXTERNALSYM i2d_X509_ATTRIBUTE}
{$EXTERNALSYM X509_ATTRIBUTE_create}
{$EXTERNALSYM X509_EXTENSION_new}
{$EXTERNALSYM X509_EXTENSION_free}
{$EXTERNALSYM d2i_X509_EXTENSION}
{$EXTERNALSYM i2d_X509_EXTENSION}
{$EXTERNALSYM X509_NAME_ENTRY_new}
{$EXTERNALSYM X509_NAME_ENTRY_free}
{$EXTERNALSYM d2i_X509_NAME_ENTRY}
{$EXTERNALSYM i2d_X509_NAME_ENTRY}
{$EXTERNALSYM X509_NAME_new}
{$EXTERNALSYM X509_NAME_free}
{$EXTERNALSYM d2i_X509_NAME}
{$EXTERNALSYM i2d_X509_NAME}
{$EXTERNALSYM X509_NAME_set}
{$EXTERNALSYM X509_new}
{$EXTERNALSYM X509_free}
{$EXTERNALSYM d2i_X509}
{$EXTERNALSYM i2d_X509}
{$EXTERNALSYM X509_set_ex_data}
{$EXTERNALSYM X509_get_ex_data}
{$EXTERNALSYM i2d_X509_AUX}
{$EXTERNALSYM d2i_X509_AUX}
{$EXTERNALSYM i2d_re_X509_tbs}
{$EXTERNALSYM X509_SIG_INFO_get}
{$EXTERNALSYM X509_SIG_INFO_set}
{$EXTERNALSYM X509_get_signature_info}
{$EXTERNALSYM X509_get0_signature}
{$EXTERNALSYM X509_get_signature_nid}
{$EXTERNALSYM X509_trusted}
{$EXTERNALSYM X509_alias_set1}
{$EXTERNALSYM X509_keyid_set1}
{$EXTERNALSYM X509_alias_get0}
{$EXTERNALSYM X509_keyid_get0}
{$EXTERNALSYM X509_TRUST_set}
{$EXTERNALSYM X509_add1_trust_object}
{$EXTERNALSYM X509_add1_reject_object}
{$EXTERNALSYM X509_trust_clear}
{$EXTERNALSYM X509_reject_clear}
{$EXTERNALSYM X509_REVOKED_new}
{$EXTERNALSYM X509_REVOKED_free}
{$EXTERNALSYM d2i_X509_REVOKED}
{$EXTERNALSYM i2d_X509_REVOKED}
{$EXTERNALSYM X509_CRL_INFO_new}
{$EXTERNALSYM X509_CRL_INFO_free}
{$EXTERNALSYM d2i_X509_CRL_INFO}
{$EXTERNALSYM i2d_X509_CRL_INFO}
{$EXTERNALSYM X509_CRL_new}
{$EXTERNALSYM X509_CRL_free}
{$EXTERNALSYM d2i_X509_CRL}
{$EXTERNALSYM i2d_X509_CRL}
{$EXTERNALSYM X509_CRL_add0_revoked}
{$EXTERNALSYM X509_CRL_get0_by_serial}
{$EXTERNALSYM X509_CRL_get0_by_cert}
{$EXTERNALSYM X509_PKEY_new}
{$EXTERNALSYM X509_PKEY_free}
{$EXTERNALSYM X509_INFO_new}
{$EXTERNALSYM X509_INFO_free}
{$EXTERNALSYM X509_NAME_oneline}
{$EXTERNALSYM ASN1_item_digest}
{$EXTERNALSYM ASN1_item_verify}
{$EXTERNALSYM ASN1_item_sign}
{$EXTERNALSYM ASN1_item_sign_ctx}
{$EXTERNALSYM X509_get_version}
{$EXTERNALSYM X509_set_version}
{$EXTERNALSYM X509_set_serialNumber}
{$EXTERNALSYM X509_get_serialNumber}
{$EXTERNALSYM X509_get0_serialNumber}
{$EXTERNALSYM X509_set_issuer_name}
{$EXTERNALSYM X509_get_issuer_name}
{$EXTERNALSYM X509_set_subject_name}
{$EXTERNALSYM X509_get_subject_name}
{$EXTERNALSYM X509_get0_notBefore}
{$EXTERNALSYM X509_getm_notBefore}
{$EXTERNALSYM X509_set1_notBefore}
{$EXTERNALSYM X509_get0_notAfter}
{$EXTERNALSYM X509_getm_notAfter}
{$EXTERNALSYM X509_set1_notAfter}
{$EXTERNALSYM X509_set_pubkey}
{$EXTERNALSYM X509_up_ref}
{$EXTERNALSYM X509_get_signature_type}
{$EXTERNALSYM X509_get_X509_PUBKEY}
{$EXTERNALSYM X509_get0_uids}
{$EXTERNALSYM X509_get0_tbs_sigalg}
{$EXTERNALSYM X509_get0_pubkey}
{$EXTERNALSYM X509_get_pubkey}
{$EXTERNALSYM X509_get0_pubkey_bitstr}
{$EXTERNALSYM X509_certificate_type}
{$EXTERNALSYM X509_REQ_get_version}
{$EXTERNALSYM X509_REQ_set_version}
{$EXTERNALSYM X509_REQ_get_subject_name}
{$EXTERNALSYM X509_REQ_set_subject_name}
{$EXTERNALSYM X509_REQ_get0_signature}
{$EXTERNALSYM X509_REQ_get_signature_nid}
{$EXTERNALSYM i2d_re_X509_REQ_tbs}
{$EXTERNALSYM X509_REQ_set_pubkey}
{$EXTERNALSYM X509_REQ_get_pubkey}
{$EXTERNALSYM X509_REQ_get0_pubkey}
{$EXTERNALSYM X509_REQ_get_X509_PUBKEY}
{$EXTERNALSYM X509_REQ_extension_nid}
{$EXTERNALSYM X509_REQ_get_extension_nids}
{$EXTERNALSYM X509_REQ_set_extension_nids}
{$EXTERNALSYM X509_REQ_get_attr_count}
{$EXTERNALSYM X509_REQ_get_attr_by_NID}
{$EXTERNALSYM X509_REQ_get_attr_by_OBJ}
{$EXTERNALSYM X509_REQ_get_attr}
{$EXTERNALSYM X509_REQ_delete_attr}
{$EXTERNALSYM X509_REQ_add1_attr}
{$EXTERNALSYM X509_REQ_add1_attr_by_OBJ}
{$EXTERNALSYM X509_REQ_add1_attr_by_NID}
{$EXTERNALSYM X509_REQ_add1_attr_by_txt}
{$EXTERNALSYM X509_CRL_set_version}
{$EXTERNALSYM X509_CRL_set_issuer_name}
{$EXTERNALSYM X509_CRL_set1_lastUpdate}
{$EXTERNALSYM X509_CRL_set1_nextUpdate}
{$EXTERNALSYM X509_CRL_sort}
{$EXTERNALSYM X509_CRL_up_ref}
{$EXTERNALSYM X509_CRL_get_version}
{$EXTERNALSYM X509_CRL_get0_lastUpdate}
{$EXTERNALSYM X509_CRL_get0_nextUpdate}
{$EXTERNALSYM X509_CRL_get_issuer}
{$EXTERNALSYM X509_CRL_get0_signature}
{$EXTERNALSYM X509_CRL_get_signature_nid}
{$EXTERNALSYM i2d_re_X509_CRL_tbs}
{$EXTERNALSYM X509_REVOKED_get0_serialNumber}
{$EXTERNALSYM X509_REVOKED_set_serialNumber}
{$EXTERNALSYM X509_REVOKED_get0_revocationDate}
{$EXTERNALSYM X509_REVOKED_set_revocationDate}
{$EXTERNALSYM X509_CRL_diff}
{$EXTERNALSYM X509_REQ_check_private_key}
{$EXTERNALSYM X509_check_private_key}
{$EXTERNALSYM X509_CRL_check_suiteb}
{$EXTERNALSYM X509_issuer_and_serial_cmp}
{$EXTERNALSYM X509_issuer_and_serial_hash}
{$EXTERNALSYM X509_issuer_name_cmp}
{$EXTERNALSYM X509_issuer_name_hash}
{$EXTERNALSYM X509_subject_name_cmp}
{$EXTERNALSYM X509_subject_name_hash}
{$EXTERNALSYM X509_cmp}
{$EXTERNALSYM X509_NAME_cmp}
{$EXTERNALSYM X509_NAME_hash_old}
{$EXTERNALSYM X509_CRL_cmp}
{$EXTERNALSYM X509_CRL_match}
{$EXTERNALSYM X509_aux_print}
{$EXTERNALSYM X509_NAME_print}
{$EXTERNALSYM X509_NAME_print_ex}
{$EXTERNALSYM X509_print_ex}
{$EXTERNALSYM X509_print}
{$EXTERNALSYM X509_ocspid_print}
{$EXTERNALSYM X509_CRL_print_ex}
{$EXTERNALSYM X509_CRL_print}
{$EXTERNALSYM X509_REQ_print_ex}
{$EXTERNALSYM X509_REQ_print}
{$EXTERNALSYM X509_NAME_entry_count}
{$EXTERNALSYM X509_NAME_get_text_by_NID}
{$EXTERNALSYM X509_NAME_get_text_by_OBJ}
{$EXTERNALSYM X509_NAME_get_index_by_NID}
{$EXTERNALSYM X509_NAME_get_index_by_OBJ}
{$EXTERNALSYM X509_NAME_get_entry}
{$EXTERNALSYM X509_NAME_delete_entry}
{$EXTERNALSYM X509_NAME_add_entry}
{$EXTERNALSYM X509_NAME_add_entry_by_OBJ}
{$EXTERNALSYM X509_NAME_add_entry_by_NID}
{$EXTERNALSYM X509_NAME_ENTRY_create_by_txt}
{$EXTERNALSYM X509_NAME_ENTRY_create_by_NID}
{$EXTERNALSYM X509_NAME_add_entry_by_txt}
{$EXTERNALSYM X509_NAME_ENTRY_create_by_OBJ}
{$EXTERNALSYM X509_NAME_ENTRY_set_object}
{$EXTERNALSYM X509_NAME_ENTRY_set_data}
{$EXTERNALSYM X509_NAME_ENTRY_get_object}
{$EXTERNALSYM X509_NAME_ENTRY_get_data}
{$EXTERNALSYM X509_NAME_ENTRY_set}
{$EXTERNALSYM X509_NAME_get0_der}
{$EXTERNALSYM X509_get_ext_count}
{$EXTERNALSYM X509_get_ext_by_NID}
{$EXTERNALSYM X509_get_ext_by_OBJ}
{$EXTERNALSYM X509_get_ext_by_critical}
{$EXTERNALSYM X509_get_ext}
{$EXTERNALSYM X509_delete_ext}
{$EXTERNALSYM X509_add_ext}
{$EXTERNALSYM X509_get_ext_d2i}
{$EXTERNALSYM X509_add1_ext_i2d}
{$EXTERNALSYM X509_CRL_get_ext_count}
{$EXTERNALSYM X509_CRL_get_ext_by_NID}
{$EXTERNALSYM X509_CRL_get_ext_by_OBJ}
{$EXTERNALSYM X509_CRL_get_ext_by_critical}
{$EXTERNALSYM X509_CRL_get_ext}
{$EXTERNALSYM X509_CRL_delete_ext}
{$EXTERNALSYM X509_CRL_add_ext}
{$EXTERNALSYM X509_CRL_get_ext_d2i}
{$EXTERNALSYM X509_CRL_add1_ext_i2d}
{$EXTERNALSYM X509_REVOKED_get_ext_count}
{$EXTERNALSYM X509_REVOKED_get_ext_by_NID}
{$EXTERNALSYM X509_REVOKED_get_ext_by_OBJ}
{$EXTERNALSYM X509_REVOKED_get_ext_by_critical}
{$EXTERNALSYM X509_REVOKED_get_ext}
{$EXTERNALSYM X509_REVOKED_delete_ext}
{$EXTERNALSYM X509_REVOKED_add_ext}
{$EXTERNALSYM X509_REVOKED_get_ext_d2i}
{$EXTERNALSYM X509_REVOKED_add1_ext_i2d}
{$EXTERNALSYM X509_EXTENSION_create_by_NID}
{$EXTERNALSYM X509_EXTENSION_create_by_OBJ}
{$EXTERNALSYM X509_EXTENSION_set_object}
{$EXTERNALSYM X509_EXTENSION_set_critical}
{$EXTERNALSYM X509_EXTENSION_set_data}
{$EXTERNALSYM X509_EXTENSION_get_object}
{$EXTERNALSYM X509_EXTENSION_get_data}
{$EXTERNALSYM X509_EXTENSION_get_critical}
{$EXTERNALSYM X509_ATTRIBUTE_create_by_NID}
{$EXTERNALSYM X509_ATTRIBUTE_create_by_OBJ}
{$EXTERNALSYM X509_ATTRIBUTE_create_by_txt}
{$EXTERNALSYM X509_ATTRIBUTE_set1_object}
{$EXTERNALSYM X509_ATTRIBUTE_set1_data}
{$EXTERNALSYM X509_ATTRIBUTE_get0_data}
{$EXTERNALSYM X509_ATTRIBUTE_count}
{$EXTERNALSYM X509_ATTRIBUTE_get0_object}
{$EXTERNALSYM X509_ATTRIBUTE_get0_type}
{$EXTERNALSYM EVP_PKEY_get_attr_count}
{$EXTERNALSYM EVP_PKEY_get_attr_by_NID}
{$EXTERNALSYM EVP_PKEY_get_attr_by_OBJ}
{$EXTERNALSYM EVP_PKEY_get_attr}
{$EXTERNALSYM EVP_PKEY_delete_attr}
{$EXTERNALSYM EVP_PKEY_add1_attr}
{$EXTERNALSYM EVP_PKEY_add1_attr_by_OBJ}
{$EXTERNALSYM EVP_PKEY_add1_attr_by_NID}
{$EXTERNALSYM EVP_PKEY_add1_attr_by_txt}
{$EXTERNALSYM X509_verify_cert}
{$EXTERNALSYM PKCS5_pbe_set0_algor}
{$EXTERNALSYM PKCS5_pbe_set}
{$EXTERNALSYM PKCS5_pbe2_set}
{$EXTERNALSYM PKCS5_pbe2_set_iv}
{$EXTERNALSYM PKCS5_pbe2_set_scrypt}
{$EXTERNALSYM PKCS5_pbkdf2_set}
{$EXTERNALSYM EVP_PKCS82PKEY}
{$EXTERNALSYM EVP_PKEY2PKCS8}
{$EXTERNALSYM PKCS8_pkey_set0}
{$EXTERNALSYM PKCS8_pkey_get0}
{$EXTERNALSYM PKCS8_pkey_add1_attr_by_NID}
{$EXTERNALSYM X509_PUBKEY_set0_param}
{$EXTERNALSYM X509_PUBKEY_get0_param}
{$EXTERNALSYM X509_check_trust}
{$EXTERNALSYM X509_TRUST_get_count}
{$EXTERNALSYM X509_TRUST_get0}
{$EXTERNALSYM X509_TRUST_get_by_id}
{$EXTERNALSYM X509_TRUST_cleanup}
{$EXTERNALSYM X509_TRUST_get_flags}
{$EXTERNALSYM X509_TRUST_get0_name}
{$EXTERNALSYM X509_TRUST_get_trust}
{$EXTERNALSYM X509_NAME_hash_ex}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure X509_CRL_set_default_method(const meth: PX509_CRL_METHOD); cdecl; external CLibCrypto;
procedure X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl; external CLibCrypto;
procedure X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl; external CLibCrypto;
function X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl; external CLibCrypto;
function X509_verify_cert_error_string(n: TOpenSSL_C_LONG): PAnsiChar; cdecl; external CLibCrypto;
function X509_verify(a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_b64_decode(const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PAnsiChar; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl; external CLibCrypto;
function i2d_X509_bio(bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl; external CLibCrypto;
function i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl; external CLibCrypto;
function i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; external CLibCrypto;
function i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; external CLibCrypto;
function i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; external CLibCrypto;
function i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): DSA; cdecl; external CLibCrypto;
function i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl; external CLibCrypto;
function i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl; external CLibCrypto;
function i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl; external CLibCrypto;
function i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl; external CLibCrypto;
function i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_dup(x509: PX509): PX509; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_CRL_dup(crl: PX509_CRL): PX509_CRL; cdecl; external CLibCrypto;
function X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED; cdecl; external CLibCrypto;
function X509_REQ_dup(req: PX509_REQ): PX509_REQ; cdecl; external CLibCrypto;
function X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR; cdecl; external CLibCrypto;
function X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl; external CLibCrypto;
procedure X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD); cdecl; external CLibCrypto;
function X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_dup(xn: PX509_NAME): PX509_NAME; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_cmp_time(const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_cmp_current_time(const s: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_time_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl; external CLibCrypto;
function X509_time_adj_ex(s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl; external CLibCrypto;
function X509_gmtime_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl; external CLibCrypto;
function X509_get_default_cert_area: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_dir: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_file: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_dir_env: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_cert_file_env: PAnsiChar; cdecl; external CLibCrypto;
function X509_get_default_private_dir: PAnsiChar; cdecl; external CLibCrypto;
function X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl; external CLibCrypto;
function X509_REQ_to_X509(r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl; external CLibCrypto;
function X509_ALGOR_new: PX509_ALGOR; cdecl; external CLibCrypto;
procedure X509_ALGOR_free(v1: PX509_ALGOR); cdecl; external CLibCrypto;
function d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl; external CLibCrypto;
function i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_VAL_new: PX509_VAL; cdecl; external CLibCrypto;
procedure X509_VAL_free(v1: PX509_VAL); cdecl; external CLibCrypto;
function d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl; external CLibCrypto;
function i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_new: PX509_PUBKEY; cdecl; external CLibCrypto;
procedure X509_PUBKEY_free(v1: PX509_PUBKEY); cdecl; external CLibCrypto;
function d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl; external CLibCrypto;
function i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_get_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl; external CLibCrypto;
function i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function i2d_EC_PUBKEY(a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl; external CLibCrypto;
function X509_SIG_new: PX509_SIG; cdecl; external CLibCrypto;
procedure X509_SIG_free(v1: PX509_SIG); cdecl; external CLibCrypto;
function d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl; external CLibCrypto;
function i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl; external CLibCrypto;
procedure X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl; external CLibCrypto;
function X509_REQ_INFO_new: PX509_REQ_INFO; cdecl; external CLibCrypto;
procedure X509_REQ_INFO_free(v1: PX509_REQ_INFO); cdecl; external CLibCrypto;
function d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl; external CLibCrypto;
function i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_new: PX509_REQ; cdecl; external CLibCrypto;
procedure X509_REQ_free(v1: PX509_REQ); cdecl; external CLibCrypto;
function d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl; external CLibCrypto;
function i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl; external CLibCrypto;
procedure X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE); cdecl; external CLibCrypto;
function d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create(nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_EXTENSION_new: PX509_EXTENSION; cdecl; external CLibCrypto;
procedure X509_EXTENSION_free(v1: PX509_EXTENSION); cdecl; external CLibCrypto;
function d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl; external CLibCrypto;
function i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl; external CLibCrypto;
procedure X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY); cdecl; external CLibCrypto;
function d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_new: PX509_NAME; cdecl; external CLibCrypto;
procedure X509_NAME_free(v1: PX509_NAME); cdecl; external CLibCrypto;
function d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl; external CLibCrypto;
function i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_new: PX509; cdecl; external CLibCrypto;
procedure X509_free(v1: PX509); cdecl; external CLibCrypto;
function d2i_X509(a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl; external CLibCrypto;
function i2d_X509(a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_set_ex_data(r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ex_data(r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function i2d_X509_AUX(a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_X509_AUX(a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl; external CLibCrypto;
function i2d_re_X509_tbs(x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl; external CLibCrypto;
function X509_get_signature_info(x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl; external CLibCrypto;
function X509_get_signature_nid(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_trusted(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_alias_set1(x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_keyid_set1(x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_alias_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function X509_keyid_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function X509_TRUST_set(t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_trust_clear(x: PX509); cdecl; external CLibCrypto;
procedure X509_reject_clear(x: PX509); cdecl; external CLibCrypto;
function X509_REVOKED_new: PX509_REVOKED; cdecl; external CLibCrypto;
procedure X509_REVOKED_free(v1: PX509_REVOKED); cdecl; external CLibCrypto;
function d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl; external CLibCrypto;
function i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_INFO_new: PX509_CRL_INFO; cdecl; external CLibCrypto;
procedure X509_CRL_INFO_free(v1: PX509_CRL_INFO); cdecl; external CLibCrypto;
function d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl; external CLibCrypto;
function i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_new: PX509_CRL; cdecl; external CLibCrypto;
procedure X509_CRL_free(v1: PX509_CRL); cdecl; external CLibCrypto;
function d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl; external CLibCrypto;
function i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PKEY_new: PX509_PKEY; cdecl; external CLibCrypto;
procedure X509_PKEY_free(a: PX509_PKEY); cdecl; external CLibCrypto;
function X509_INFO_new: PX509_INFO; cdecl; external CLibCrypto;
procedure X509_INFO_free(a: PX509_INFO); cdecl; external CLibCrypto;
function X509_NAME_oneline(const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_version(const x: PX509): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_set_version(x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_get0_serialNumber(const x: PX509): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_set_issuer_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_issuer_name(const a: PX509): PX509_NAME; cdecl; external CLibCrypto;
function X509_set_subject_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_subject_name(const a: PX509): PX509_NAME; cdecl; external CLibCrypto;
function X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_getm_notBefore(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_getm_notAfter(const x: PX509): PASN1_TIME; cdecl; external CLibCrypto;
function X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_up_ref(x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY; cdecl; external CLibCrypto;
procedure X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl; external CLibCrypto;
function X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR; cdecl; external CLibCrypto;
function X509_get0_pubkey(const x: PX509): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING; cdecl; external CLibCrypto;
function X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_version(const req: PX509_REQ): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_REQ_set_version(x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME; cdecl; external CLibCrypto;
function X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl; external CLibCrypto;
function X509_REQ_get_signature_nid(const req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl; external CLibCrypto;
function X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl; external CLibCrypto;
function X509_REQ_extension_nid(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_extension_nids: POpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_REQ_set_extension_nids(nids: POpenSSL_C_INT); cdecl; external CLibCrypto;
function X509_REQ_get_attr_count(const req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_get_attr(const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_REQ_delete_attr(req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set_version(x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_sort(crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_up_ref(crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_version(const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl; external CLibCrypto;
function X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl; external CLibCrypto;
function X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME; cdecl; external CLibCrypto;
procedure X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl; external CLibCrypto;
function X509_CRL_get_signature_nid(const crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER; cdecl; external CLibCrypto;
function X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME; cdecl; external CLibCrypto;
function X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl; external CLibCrypto;
function X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_issuer_and_serial_hash(a: PX509): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_issuer_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_issuer_name_hash(a: PX509): TOpenSSL_C_uLONG; cdecl; external CLibCrypto;
function X509_subject_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_subject_name_hash(x: PX509): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_hash_old(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_aux_print(out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_print_ex(bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ocspid_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_print(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REQ_print(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_entry_count(const name: PX509_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get_entry(const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_delete_entry(name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl; external CLibCrypto;
function X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_count(const x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_by_NID(const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_by_critical(const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext(const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_delete_ext(x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_get_ext_d2i(const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_add1_ext_i2d(x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_count(const x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_by_OBJ(const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext(const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_CRL_delete_ext(x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl; external CLibCrypto;
function X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl; external CLibCrypto;
function X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_verify_cert(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_pbe_set(alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl; external CLibCrypto;
function PKCS5_pbkdf2_set(iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl; external CLibCrypto;
function EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_check_trust(x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_TRUST_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_TRUST_get0(idx: TOpenSSL_C_INT): PX509_TRUST; cdecl; external CLibCrypto;
function X509_TRUST_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure X509_TRUST_cleanup; cdecl; external CLibCrypto;
function X509_TRUST_get_flags(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_TRUST_get0_name(const xp: PX509_TRUST): PAnsiChar; cdecl; external CLibCrypto;
function X509_TRUST_get_trust(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}

{Declare external function initialisers - should not be called directly}

procedure Load_X509_CRL_set_default_method(const meth: PX509_CRL_METHOD); cdecl;
procedure Load_X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl;
procedure Load_X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl;
function Load_X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl;
function Load_X509_verify_cert_error_string(n: TOpenSSL_C_LONG): PAnsiChar; cdecl;
function Load_X509_verify(a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_NETSCAPE_SPKI_b64_decode(const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl;
function Load_NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PAnsiChar; cdecl;
function Load_NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl;
function Load_NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl;
function Load_X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl;
function Load_X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_X509_http_nbio(rctx: POCSP_REQ_CTX; pcert: PPX509): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_X509_CRL_http_nbio(rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl;
function Load_i2d_X509_bio(bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl;
function Load_d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl;
function Load_i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl;
function Load_i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
function Load_d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
function Load_i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
function Load_i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
function Load_i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): DSA; cdecl;
function Load_i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl;
function Load_d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl;
function Load_i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl;
function Load_d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl;
function Load_i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl;
function Load_i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl;
function Load_i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl;
function Load_d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl;
function Load_i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
function Load_i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
function Load_i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
function Load_X509_dup(x509: PX509): PX509; cdecl;
function Load_X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl;
function Load_X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl;
function Load_X509_CRL_dup(crl: PX509_CRL): PX509_CRL; cdecl;
function Load_X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED; cdecl;
function Load_X509_REQ_dup(req: PX509_REQ): PX509_REQ; cdecl;
function Load_X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR; cdecl;
function Load_X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl;
procedure Load_X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl;
procedure Load_X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD); cdecl;
function Load_X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_dup(xn: PX509_NAME): PX509_NAME; cdecl;
function Load_X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl;
function Load_X509_cmp_time(const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
function Load_X509_cmp_current_time(const s: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_X509_time_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl;
function Load_X509_time_adj_ex(s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl;
function Load_X509_gmtime_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
function Load_X509_get_default_cert_area: PAnsiChar; cdecl;
function Load_X509_get_default_cert_dir: PAnsiChar; cdecl;
function Load_X509_get_default_cert_file: PAnsiChar; cdecl;
function Load_X509_get_default_cert_dir_env: PAnsiChar; cdecl;
function Load_X509_get_default_cert_file_env: PAnsiChar; cdecl;
function Load_X509_get_default_private_dir: PAnsiChar; cdecl;
function Load_X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl;
function Load_X509_REQ_to_X509(r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl;
function Load_X509_ALGOR_new: PX509_ALGOR; cdecl;
procedure Load_X509_ALGOR_free(v1: PX509_ALGOR); cdecl;
function Load_d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl;
function Load_i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_VAL_new: PX509_VAL; cdecl;
procedure Load_X509_VAL_free(v1: PX509_VAL); cdecl;
function Load_d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl;
function Load_i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_PUBKEY_new: PX509_PUBKEY; cdecl;
procedure Load_X509_PUBKEY_free(v1: PX509_PUBKEY); cdecl;
function Load_d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl;
function Load_i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
function Load_X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
function Load_X509_get_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl;
function Load_i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
function Load_i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl;
function Load_i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
function Load_i2d_EC_PUBKEY(a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl;
function Load_X509_SIG_new: PX509_SIG; cdecl;
procedure Load_X509_SIG_free(v1: PX509_SIG); cdecl;
function Load_d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl;
function Load_i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl;
procedure Load_X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl;
procedure Load_X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl;
function Load_X509_REQ_INFO_new: PX509_REQ_INFO; cdecl;
procedure Load_X509_REQ_INFO_free(v1: PX509_REQ_INFO); cdecl;
function Load_d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl;
function Load_i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_new: PX509_REQ; cdecl;
procedure Load_X509_REQ_free(v1: PX509_REQ); cdecl;
function Load_d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl;
function Load_i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl;
procedure Load_X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE); cdecl;
function Load_d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl;
function Load_i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_ATTRIBUTE_create(nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl;
function Load_X509_EXTENSION_new: PX509_EXTENSION; cdecl;
procedure Load_X509_EXTENSION_free(v1: PX509_EXTENSION); cdecl;
function Load_d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl;
function Load_i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl;
procedure Load_X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY); cdecl;
function Load_d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl;
function Load_i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_new: PX509_NAME; cdecl;
procedure Load_X509_NAME_free(v1: PX509_NAME); cdecl;
function Load_d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl;
function Load_i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
function Load_X509_new: PX509; cdecl;
procedure Load_X509_free(v1: PX509); cdecl;
function Load_d2i_X509(a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl;
function Load_i2d_X509(a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_set_ex_data(r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ex_data(r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_i2d_X509_AUX(a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_X509_AUX(a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl;
function Load_i2d_re_X509_tbs(x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
procedure Load_X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl;
function Load_X509_get_signature_info(x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
procedure Load_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl;
function Load_X509_get_signature_nid(const x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_trusted(const x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_alias_set1(x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_keyid_set1(x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_alias_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl;
function Load_X509_keyid_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl;
function Load_X509_TRUST_set(t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
procedure Load_X509_trust_clear(x: PX509); cdecl;
procedure Load_X509_reject_clear(x: PX509); cdecl;
function Load_X509_REVOKED_new: PX509_REVOKED; cdecl;
procedure Load_X509_REVOKED_free(v1: PX509_REVOKED); cdecl;
function Load_d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl;
function Load_i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_INFO_new: PX509_CRL_INFO; cdecl;
procedure Load_X509_CRL_INFO_free(v1: PX509_CRL_INFO); cdecl;
function Load_d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl;
function Load_i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_new: PX509_CRL; cdecl;
procedure Load_X509_CRL_free(v1: PX509_CRL); cdecl;
function Load_d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl;
function Load_i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_PKEY_new: PX509_PKEY; cdecl;
procedure Load_X509_PKEY_free(a: PX509_PKEY); cdecl;
function Load_X509_INFO_new: PX509_INFO; cdecl;
procedure Load_X509_INFO_free(a: PX509_INFO); cdecl;
function Load_X509_NAME_oneline(const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
function Load_X509_get_version(const x: PX509): TOpenSSL_C_LONG; cdecl;
function Load_X509_set_version(x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl;
function Load_X509_get0_serialNumber(const x: PX509): PASN1_INTEGER; cdecl;
function Load_X509_set_issuer_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
function Load_X509_get_issuer_name(const a: PX509): PX509_NAME; cdecl;
function Load_X509_set_subject_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
function Load_X509_get_subject_name(const a: PX509): PX509_NAME; cdecl;
function Load_X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl;
function Load_X509_getm_notBefore(const x: PX509): PASN1_TIME; cdecl;
function Load_X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl;
function Load_X509_getm_notAfter(const x: PX509): PASN1_TIME; cdecl;
function Load_X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_up_ref(x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY; cdecl;
procedure Load_X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl;
function Load_X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR; cdecl;
function Load_X509_get0_pubkey(const x: PX509): PEVP_PKEY; cdecl;
function Load_X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl;
function Load_X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING; cdecl;
function Load_X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_version(const req: PX509_REQ): TOpenSSL_C_LONG; cdecl;
function Load_X509_REQ_set_version(x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME; cdecl;
function Load_X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
procedure Load_X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl;
function Load_X509_REQ_get_signature_nid(const req: PX509_REQ): TOpenSSL_C_INT; cdecl;
function Load_i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
function Load_X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
function Load_X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl;
function Load_X509_REQ_extension_nid(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_extension_nids: POpenSSL_C_INT; cdecl;
procedure Load_X509_REQ_set_extension_nids(nids: POpenSSL_C_INT); cdecl;
function Load_X509_REQ_get_attr_count(const req: PX509_REQ): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_get_attr(const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_X509_REQ_delete_attr(req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_set_version(x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_sort(crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_up_ref(crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_version(const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl;
function Load_X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl;
function Load_X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl;
function Load_X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME; cdecl;
procedure Load_X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl;
function Load_X509_CRL_get_signature_nid(const crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER; cdecl;
function Load_X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME; cdecl;
function Load_X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl;
function Load_X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_issuer_and_serial_hash(a: PX509): TOpenSSL_C_ULONG; cdecl;
function Load_X509_issuer_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_issuer_name_hash(a: PX509): TOpenSSL_C_uLONG; cdecl;
function Load_X509_subject_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_subject_name_hash(x: PX509): TOpenSSL_C_ULONG; cdecl;
function Load_X509_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_X509_NAME_hash_old(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;
function Load_X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_X509_aux_print(out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_print_ex(bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_ocspid_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_print(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_REQ_print(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_entry_count(const name: PX509_NAME): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_get_entry(const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
function Load_X509_NAME_delete_entry(name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl;
function Load_X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
function Load_X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
function Load_X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
function Load_X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl;
function Load_X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl;
function Load_X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ext_count(const x: PX509): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ext_by_NID(const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ext_by_critical(const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ext(const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
function Load_X509_delete_ext(x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
function Load_X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_get_ext_d2i(const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
function Load_X509_add1_ext_i2d(x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_ext_count(const x: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_ext_by_OBJ(const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_ext(const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
function Load_X509_CRL_delete_ext(x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
function Load_X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
function Load_X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
function Load_X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
function Load_X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
function Load_X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
function Load_X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
function Load_X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl;
function Load_X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl;
function Load_X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl;
function Load_X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl;
function Load_X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl;
function Load_X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
function Load_X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl;
function Load_X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
function Load_EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_verify_cert(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_pbe_set(alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
function Load_PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
function Load_PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
function Load_PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl;
function Load_PKCS5_pbkdf2_set(iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
function Load_EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl;
function Load_EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl;
function Load_PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
function Load_PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
function Load_X509_check_trust(x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_X509_TRUST_get_count: TOpenSSL_C_INT; cdecl;
function Load_X509_TRUST_get0(idx: TOpenSSL_C_INT): PX509_TRUST; cdecl;
function Load_X509_TRUST_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_X509_TRUST_cleanup; cdecl;
function Load_X509_TRUST_get_flags(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl;
function Load_X509_TRUST_get0_name(const xp: PX509_TRUST): PAnsiChar; cdecl;
function Load_X509_TRUST_get_trust(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl;
function Load_X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;

var
  X509_CRL_set_default_method: procedure (const meth: PX509_CRL_METHOD); cdecl = Load_X509_CRL_set_default_method;
  X509_CRL_METHOD_free: procedure (m: PX509_CRL_METHOD); cdecl = Load_X509_CRL_METHOD_free;
  X509_CRL_set_meth_data: procedure (crl: PX509_CRL; dat: Pointer); cdecl = Load_X509_CRL_set_meth_data;
  X509_CRL_get_meth_data: function (crl: PX509_CRL): Pointer; cdecl = Load_X509_CRL_get_meth_data;
  X509_verify_cert_error_string: function (n: TOpenSSL_C_LONG): PAnsiChar; cdecl = Load_X509_verify_cert_error_string;
  X509_verify: function (a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_verify;
  X509_REQ_verify: function (a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_REQ_verify;
  X509_CRL_verify: function (a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_CRL_verify;
  NETSCAPE_SPKI_verify: function (a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_NETSCAPE_SPKI_verify;
  NETSCAPE_SPKI_b64_decode: function (const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl = Load_NETSCAPE_SPKI_b64_decode;
  NETSCAPE_SPKI_b64_encode: function (x: PNETSCAPE_SPKI): PAnsiChar; cdecl = Load_NETSCAPE_SPKI_b64_encode;
  NETSCAPE_SPKI_get_pubkey: function (x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl = Load_NETSCAPE_SPKI_get_pubkey;
  NETSCAPE_SPKI_set_pubkey: function (x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_NETSCAPE_SPKI_set_pubkey;
  NETSCAPE_SPKI_print: function (out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl = Load_NETSCAPE_SPKI_print;
  X509_signature_dump: function (bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_signature_dump;
  X509_signature_print: function (bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_X509_signature_print;
  X509_sign: function (x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_X509_sign;
  X509_sign_ctx: function (x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_X509_sign_ctx;
  X509_REQ_sign: function (x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_X509_REQ_sign;
  X509_REQ_sign_ctx: function (x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_X509_REQ_sign_ctx;
  X509_CRL_sign: function (x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_X509_CRL_sign;
  X509_CRL_sign_ctx: function (x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_X509_CRL_sign_ctx;
  NETSCAPE_SPKI_sign: function (x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_NETSCAPE_SPKI_sign;
  X509_pubkey_digest: function (const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_X509_pubkey_digest;
  X509_digest: function (const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_X509_digest;
  X509_CRL_digest: function (const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_X509_CRL_digest;
  X509_REQ_digest: function (const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_digest;
  X509_NAME_digest: function (const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_digest;
  d2i_X509_bio: function (bp: PBIO; x509: PPX509): PX509; cdecl = Load_d2i_X509_bio;
  i2d_X509_bio: function (bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl = Load_i2d_X509_bio;
  d2i_X509_CRL_bio: function (bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl = Load_d2i_X509_CRL_bio;
  i2d_X509_CRL_bio: function (bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_i2d_X509_CRL_bio;
  d2i_X509_REQ_bio: function (bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl = Load_d2i_X509_REQ_bio;
  i2d_X509_REQ_bio: function (bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_i2d_X509_REQ_bio;
  d2i_RSAPrivateKey_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = Load_d2i_RSAPrivateKey_bio;
  i2d_RSAPrivateKey_bio: function (bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_i2d_RSAPrivateKey_bio;
  d2i_RSAPublicKey_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = Load_d2i_RSAPublicKey_bio;
  i2d_RSAPublicKey_bio: function (bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_i2d_RSAPublicKey_bio;
  d2i_RSA_PUBKEY_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = Load_d2i_RSA_PUBKEY_bio;
  i2d_RSA_PUBKEY_bio: function (bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_i2d_RSA_PUBKEY_bio;
  d2i_DSA_PUBKEY_bio: function (bp: PBIO; dsa: PPDSA): DSA; cdecl = Load_d2i_DSA_PUBKEY_bio;
  i2d_DSA_PUBKEY_bio: function (bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_i2d_DSA_PUBKEY_bio;
  d2i_DSAPrivateKey_bio: function (bp: PBIO; dsa: PPDSA): PDSA; cdecl = Load_d2i_DSAPrivateKey_bio;
  i2d_DSAPrivateKey_bio: function (bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_i2d_DSAPrivateKey_bio;
  d2i_EC_PUBKEY_bio: function (bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl = Load_d2i_EC_PUBKEY_bio;
  i2d_EC_PUBKEY_bio: function (bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_i2d_EC_PUBKEY_bio;
  d2i_ECPrivateKey_bio: function (bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl = Load_d2i_ECPrivateKey_bio;
  i2d_ECPrivateKey_bio: function (bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_i2d_ECPrivateKey_bio;
  d2i_PKCS8_bio: function (bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl = Load_d2i_PKCS8_bio;
  i2d_PKCS8_bio: function (bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8_bio;
  d2i_PKCS8_PRIV_KEY_INFO_bio: function (bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl = Load_d2i_PKCS8_PRIV_KEY_INFO_bio;
  i2d_PKCS8_PRIV_KEY_INFO_bio: function (bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8_PRIV_KEY_INFO_bio;
  i2d_PKCS8PrivateKeyInfo_bio: function (bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKeyInfo_bio;
  i2d_PrivateKey_bio: function (bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2d_PrivateKey_bio;
  d2i_PrivateKey_bio: function (bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = Load_d2i_PrivateKey_bio;
  i2d_PUBKEY_bio: function (bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2d_PUBKEY_bio;
  d2i_PUBKEY_bio: function (bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = Load_d2i_PUBKEY_bio;
  X509_dup: function (x509: PX509): PX509; cdecl = Load_X509_dup;
  X509_ATTRIBUTE_dup: function (xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl = Load_X509_ATTRIBUTE_dup;
  X509_EXTENSION_dup: function (ex: PX509_EXTENSION): PX509_EXTENSION; cdecl = Load_X509_EXTENSION_dup;
  X509_CRL_dup: function (crl: PX509_CRL): PX509_CRL; cdecl = Load_X509_CRL_dup;
  X509_REVOKED_dup: function (rev: PX509_REVOKED): PX509_REVOKED; cdecl = Load_X509_REVOKED_dup;
  X509_REQ_dup: function (req: PX509_REQ): PX509_REQ; cdecl = Load_X509_REQ_dup;
  X509_ALGOR_dup: function (xn: PX509_ALGOR): PX509_ALGOR; cdecl = Load_X509_ALGOR_dup;
  X509_ALGOR_set0: function (alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl = Load_X509_ALGOR_set0;
  X509_ALGOR_get0: procedure (const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl = Load_X509_ALGOR_get0;
  X509_ALGOR_set_md: procedure (alg: PX509_ALGOR; const md: PEVP_MD); cdecl = Load_X509_ALGOR_set_md;
  X509_ALGOR_cmp: function (const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_X509_ALGOR_cmp;
  X509_NAME_dup: function (xn: PX509_NAME): PX509_NAME; cdecl = Load_X509_NAME_dup;
  X509_NAME_ENTRY_dup: function (ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl = Load_X509_NAME_ENTRY_dup;
  X509_cmp_time: function (const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_X509_cmp_time;
  X509_cmp_current_time: function (const s: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_X509_cmp_current_time;
  X509_time_adj: function (s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl = Load_X509_time_adj;
  X509_time_adj_ex: function (s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl = Load_X509_time_adj_ex;
  X509_gmtime_adj: function (s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl = Load_X509_gmtime_adj;
  X509_get_default_cert_area: function : PAnsiChar; cdecl = Load_X509_get_default_cert_area;
  X509_get_default_cert_dir: function : PAnsiChar; cdecl = Load_X509_get_default_cert_dir;
  X509_get_default_cert_file: function : PAnsiChar; cdecl = Load_X509_get_default_cert_file;
  X509_get_default_cert_dir_env: function : PAnsiChar; cdecl = Load_X509_get_default_cert_dir_env;
  X509_get_default_cert_file_env: function : PAnsiChar; cdecl = Load_X509_get_default_cert_file_env;
  X509_get_default_private_dir: function : PAnsiChar; cdecl = Load_X509_get_default_private_dir;
  X509_to_X509_REQ: function (x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl = Load_X509_to_X509_REQ;
  X509_REQ_to_X509: function (r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl = Load_X509_REQ_to_X509;
  X509_ALGOR_new: function : PX509_ALGOR; cdecl = Load_X509_ALGOR_new;
  X509_ALGOR_free: procedure (v1: PX509_ALGOR); cdecl = Load_X509_ALGOR_free;
  d2i_X509_ALGOR: function (a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl = Load_d2i_X509_ALGOR;
  i2d_X509_ALGOR: function (a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_ALGOR;
  X509_VAL_new: function : PX509_VAL; cdecl = Load_X509_VAL_new;
  X509_VAL_free: procedure (v1: PX509_VAL); cdecl = Load_X509_VAL_free;
  d2i_X509_VAL: function (a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl = Load_d2i_X509_VAL;
  i2d_X509_VAL: function (a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_VAL;
  X509_PUBKEY_new: function : PX509_PUBKEY; cdecl = Load_X509_PUBKEY_new;
  X509_PUBKEY_free: procedure (v1: PX509_PUBKEY); cdecl = Load_X509_PUBKEY_free;
  d2i_X509_PUBKEY: function (a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl = Load_d2i_X509_PUBKEY;
  i2d_X509_PUBKEY: function (a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_PUBKEY;
  X509_PUBKEY_set: function (x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_PUBKEY_set;
  X509_PUBKEY_get0: function (key: PX509_PUBKEY): PEVP_PKEY; cdecl = Load_X509_PUBKEY_get0;
  X509_PUBKEY_get: function (key: PX509_PUBKEY): PEVP_PKEY; cdecl = Load_X509_PUBKEY_get;
  X509_get_pathlen: function (x: PX509): TOpenSSL_C_LONG; cdecl = Load_X509_get_pathlen;
  i2d_PUBKEY: function (a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PUBKEY;
  d2i_PUBKEY: function (a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = Load_d2i_PUBKEY;
  i2d_RSA_PUBKEY: function (a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_RSA_PUBKEY;
  d2i_RSA_PUBKEY: function (a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl = Load_d2i_RSA_PUBKEY;
  i2d_DSA_PUBKEY: function (a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DSA_PUBKEY;
  d2i_DSA_PUBKEY: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = Load_d2i_DSA_PUBKEY;
  i2d_EC_PUBKEY: function (a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_EC_PUBKEY;
  d2i_EC_PUBKEY: function (a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl = Load_d2i_EC_PUBKEY;
  X509_SIG_new: function : PX509_SIG; cdecl = Load_X509_SIG_new;
  X509_SIG_free: procedure (v1: PX509_SIG); cdecl = Load_X509_SIG_free;
  d2i_X509_SIG: function (a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl = Load_d2i_X509_SIG;
  i2d_X509_SIG: function (a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_SIG;
  X509_SIG_get0: procedure (const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl = Load_X509_SIG_get0;
  X509_SIG_getm: procedure (sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl = Load_X509_SIG_getm;
  X509_REQ_INFO_new: function : PX509_REQ_INFO; cdecl = Load_X509_REQ_INFO_new;
  X509_REQ_INFO_free: procedure (v1: PX509_REQ_INFO); cdecl = Load_X509_REQ_INFO_free;
  d2i_X509_REQ_INFO: function (a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl = Load_d2i_X509_REQ_INFO;
  i2d_X509_REQ_INFO: function (a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_REQ_INFO;
  X509_REQ_new: function : PX509_REQ; cdecl = Load_X509_REQ_new;
  X509_REQ_free: procedure (v1: PX509_REQ); cdecl = Load_X509_REQ_free;
  d2i_X509_REQ: function (a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl = Load_d2i_X509_REQ;
  i2d_X509_REQ: function (a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_REQ;
  X509_ATTRIBUTE_new: function : PX509_ATTRIBUTE; cdecl = Load_X509_ATTRIBUTE_new;
  X509_ATTRIBUTE_free: procedure (v1: PX509_ATTRIBUTE); cdecl = Load_X509_ATTRIBUTE_free;
  d2i_X509_ATTRIBUTE: function (a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl = Load_d2i_X509_ATTRIBUTE;
  i2d_X509_ATTRIBUTE: function (a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_ATTRIBUTE;
  X509_ATTRIBUTE_create: function (nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl = Load_X509_ATTRIBUTE_create;
  X509_EXTENSION_new: function : PX509_EXTENSION; cdecl = Load_X509_EXTENSION_new;
  X509_EXTENSION_free: procedure (v1: PX509_EXTENSION); cdecl = Load_X509_EXTENSION_free;
  d2i_X509_EXTENSION: function (a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl = Load_d2i_X509_EXTENSION;
  i2d_X509_EXTENSION: function (a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_EXTENSION;
  X509_NAME_ENTRY_new: function : PX509_NAME_ENTRY; cdecl = Load_X509_NAME_ENTRY_new;
  X509_NAME_ENTRY_free: procedure (v1: PX509_NAME_ENTRY); cdecl = Load_X509_NAME_ENTRY_free;
  d2i_X509_NAME_ENTRY: function (a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl = Load_d2i_X509_NAME_ENTRY;
  i2d_X509_NAME_ENTRY: function (a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_NAME_ENTRY;
  X509_NAME_new: function : PX509_NAME; cdecl = Load_X509_NAME_new;
  X509_NAME_free: procedure (v1: PX509_NAME); cdecl = Load_X509_NAME_free;
  d2i_X509_NAME: function (a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl = Load_d2i_X509_NAME;
  i2d_X509_NAME: function (a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_NAME;
  X509_NAME_set: function (xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_NAME_set;
  X509_new: function : PX509; cdecl = Load_X509_new;
  X509_free: procedure (v1: PX509); cdecl = Load_X509_free;
  d2i_X509: function (a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl = Load_d2i_X509;
  i2d_X509: function (a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509;
  X509_set_ex_data: function (r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_X509_set_ex_data;
  X509_get_ex_data: function (r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_X509_get_ex_data;
  i2d_X509_AUX: function (a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_AUX;
  d2i_X509_AUX: function (a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl = Load_d2i_X509_AUX;
  i2d_re_X509_tbs: function (x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_re_X509_tbs;
  X509_SIG_INFO_get: function (const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_X509_SIG_INFO_get;
  X509_SIG_INFO_set: procedure (siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl = Load_X509_SIG_INFO_set;
  X509_get_signature_info: function (x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_X509_get_signature_info;
  X509_get0_signature: procedure (var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl = Load_X509_get0_signature;
  X509_get_signature_nid: function (const x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_get_signature_nid;
  X509_trusted: function (const x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_trusted;
  X509_alias_set1: function (x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_alias_set1;
  X509_keyid_set1: function (x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_keyid_set1;
  X509_alias_get0: function (x: PX509; len: POpenSSL_C_INT): PByte; cdecl = Load_X509_alias_get0;
  X509_keyid_get0: function (x: PX509; len: POpenSSL_C_INT): PByte; cdecl = Load_X509_keyid_get0;
  X509_TRUST_set: function (t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_TRUST_set;
  X509_add1_trust_object: function (x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_X509_add1_trust_object;
  X509_add1_reject_object: function (x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_X509_add1_reject_object;
  X509_trust_clear: procedure (x: PX509); cdecl = Load_X509_trust_clear;
  X509_reject_clear: procedure (x: PX509); cdecl = Load_X509_reject_clear;
  X509_REVOKED_new: function : PX509_REVOKED; cdecl = Load_X509_REVOKED_new;
  X509_REVOKED_free: procedure (v1: PX509_REVOKED); cdecl = Load_X509_REVOKED_free;
  d2i_X509_REVOKED: function (a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl = Load_d2i_X509_REVOKED;
  i2d_X509_REVOKED: function (a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_REVOKED;
  X509_CRL_INFO_new: function : PX509_CRL_INFO; cdecl = Load_X509_CRL_INFO_new;
  X509_CRL_INFO_free: procedure (v1: PX509_CRL_INFO); cdecl = Load_X509_CRL_INFO_free;
  d2i_X509_CRL_INFO: function (a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl = Load_d2i_X509_CRL_INFO;
  i2d_X509_CRL_INFO: function (a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_CRL_INFO;
  X509_CRL_new: function : PX509_CRL; cdecl = Load_X509_CRL_new;
  X509_CRL_free: procedure (v1: PX509_CRL); cdecl = Load_X509_CRL_free;
  d2i_X509_CRL: function (a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl = Load_d2i_X509_CRL;
  i2d_X509_CRL: function (a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_X509_CRL;
  X509_CRL_add0_revoked: function (crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl = Load_X509_CRL_add0_revoked;
  X509_CRL_get0_by_serial: function (crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get0_by_serial;
  X509_CRL_get0_by_cert: function (crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get0_by_cert;
  X509_PKEY_new: function : PX509_PKEY; cdecl = Load_X509_PKEY_new;
  X509_PKEY_free: procedure (a: PX509_PKEY); cdecl = Load_X509_PKEY_free;
  X509_INFO_new: function : PX509_INFO; cdecl = Load_X509_INFO_new;
  X509_INFO_free: procedure (a: PX509_INFO); cdecl = Load_X509_INFO_free;
  X509_NAME_oneline: function (const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_X509_NAME_oneline;
  ASN1_item_digest: function (const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_ASN1_item_digest;
  ASN1_item_verify: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_ASN1_item_verify;
  ASN1_item_sign: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_ASN1_item_sign;
  ASN1_item_sign_ctx: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_ASN1_item_sign_ctx;
  X509_get_version: function (const x: PX509): TOpenSSL_C_LONG; cdecl = Load_X509_get_version;
  X509_set_version: function (x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_X509_set_version;
  X509_set_serialNumber: function (x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_X509_set_serialNumber;
  X509_get_serialNumber: function (x: PX509): PASN1_INTEGER; cdecl = Load_X509_get_serialNumber;
  X509_get0_serialNumber: function (const x: PX509): PASN1_INTEGER; cdecl = Load_X509_get0_serialNumber;
  X509_set_issuer_name: function (x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_set_issuer_name;
  X509_get_issuer_name: function (const a: PX509): PX509_NAME; cdecl = Load_X509_get_issuer_name;
  X509_set_subject_name: function (x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_set_subject_name;
  X509_get_subject_name: function (const a: PX509): PX509_NAME; cdecl = Load_X509_get_subject_name;
  X509_get0_notBefore: function (const x: PX509): PASN1_TIME; cdecl = Load_X509_get0_notBefore;
  X509_getm_notBefore: function (const x: PX509): PASN1_TIME; cdecl = Load_X509_getm_notBefore;
  X509_set1_notBefore: function (x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_X509_set1_notBefore;
  X509_get0_notAfter: function (const x: PX509): PASN1_TIME; cdecl = Load_X509_get0_notAfter;
  X509_getm_notAfter: function (const x: PX509): PASN1_TIME; cdecl = Load_X509_getm_notAfter;
  X509_set1_notAfter: function (x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_X509_set1_notAfter;
  X509_set_pubkey: function (x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_set_pubkey;
  X509_up_ref: function (x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_up_ref;
  X509_get_signature_type: function (const x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_get_signature_type;
  X509_get_X509_PUBKEY: function (const x: PX509): PX509_PUBKEY; cdecl = Load_X509_get_X509_PUBKEY;
  X509_get0_uids: procedure (const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl = Load_X509_get0_uids;
  X509_get0_tbs_sigalg: function (const x: PX509): PX509_ALGOR; cdecl = Load_X509_get0_tbs_sigalg;
  X509_get0_pubkey: function (const x: PX509): PEVP_PKEY; cdecl = Load_X509_get0_pubkey;
  X509_get_pubkey: function (x: PX509): PEVP_PKEY; cdecl = Load_X509_get_pubkey;
  X509_get0_pubkey_bitstr: function (const x: PX509): PASN1_BIT_STRING; cdecl = Load_X509_get0_pubkey_bitstr;
  X509_certificate_type: function (const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_certificate_type;
  X509_REQ_get_version: function (const req: PX509_REQ): TOpenSSL_C_LONG; cdecl = Load_X509_REQ_get_version;
  X509_REQ_set_version: function (x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_X509_REQ_set_version;
  X509_REQ_get_subject_name: function (const req: PX509_REQ): PX509_NAME; cdecl = Load_X509_REQ_get_subject_name;
  X509_REQ_set_subject_name: function (req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_REQ_set_subject_name;
  X509_REQ_get0_signature: procedure (const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl = Load_X509_REQ_get0_signature;
  X509_REQ_get_signature_nid: function (const req: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_X509_REQ_get_signature_nid;
  i2d_re_X509_REQ_tbs: function (req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_re_X509_REQ_tbs;
  X509_REQ_set_pubkey: function (x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_REQ_set_pubkey;
  X509_REQ_get_pubkey: function (req: PX509_REQ): PEVP_PKEY; cdecl = Load_X509_REQ_get_pubkey;
  X509_REQ_get0_pubkey: function (req: PX509_REQ): PEVP_PKEY; cdecl = Load_X509_REQ_get0_pubkey;
  X509_REQ_get_X509_PUBKEY: function (req: PX509_REQ): PX509_PUBKEY; cdecl = Load_X509_REQ_get_X509_PUBKEY;
  X509_REQ_extension_nid: function (nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_extension_nid;
  X509_REQ_get_extension_nids: function : POpenSSL_C_INT; cdecl = Load_X509_REQ_get_extension_nids;
  X509_REQ_set_extension_nids: procedure (nids: POpenSSL_C_INT); cdecl = Load_X509_REQ_set_extension_nids;
  X509_REQ_get_attr_count: function (const req: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_X509_REQ_get_attr_count;
  X509_REQ_get_attr_by_NID: function (const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_get_attr_by_NID;
  X509_REQ_get_attr_by_OBJ: function (const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_get_attr_by_OBJ;
  X509_REQ_get_attr: function (const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_X509_REQ_get_attr;
  X509_REQ_delete_attr: function (req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_X509_REQ_delete_attr;
  X509_REQ_add1_attr: function (req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = Load_X509_REQ_add1_attr;
  X509_REQ_add1_attr_by_OBJ: function (req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_add1_attr_by_OBJ;
  X509_REQ_add1_attr_by_NID: function (req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_add1_attr_by_NID;
  X509_REQ_add1_attr_by_txt: function (req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REQ_add1_attr_by_txt;
  X509_CRL_set_version: function (x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_X509_CRL_set_version;
  X509_CRL_set_issuer_name: function (x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_CRL_set_issuer_name;
  X509_CRL_set1_lastUpdate: function (x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_X509_CRL_set1_lastUpdate;
  X509_CRL_set1_nextUpdate: function (x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_X509_CRL_set1_nextUpdate;
  X509_CRL_sort: function (crl: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_sort;
  X509_CRL_up_ref: function (crl: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_up_ref;
  X509_CRL_get_version: function (const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl = Load_X509_CRL_get_version;
  X509_CRL_get0_lastUpdate: function (const crl: PX509_CRL): PASN1_TIME; cdecl = Load_X509_CRL_get0_lastUpdate;
  X509_CRL_get0_nextUpdate: function (const crl: PX509_CRL): PASN1_TIME; cdecl = Load_X509_CRL_get0_nextUpdate;
  X509_CRL_get_issuer: function (const crl: PX509_CRL): PX509_NAME; cdecl = Load_X509_CRL_get_issuer;
  X509_CRL_get0_signature: procedure (const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl = Load_X509_CRL_get0_signature;
  X509_CRL_get_signature_nid: function (const crl: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get_signature_nid;
  i2d_re_X509_CRL_tbs: function (req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_re_X509_CRL_tbs;
  X509_REVOKED_get0_serialNumber: function (const x: PX509_REVOKED): PASN1_INTEGER; cdecl = Load_X509_REVOKED_get0_serialNumber;
  X509_REVOKED_set_serialNumber: function (x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_set_serialNumber;
  X509_REVOKED_get0_revocationDate: function (const x: PX509_REVOKED): PASN1_TIME; cdecl = Load_X509_REVOKED_get0_revocationDate;
  X509_REVOKED_set_revocationDate: function (r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_set_revocationDate;
  X509_CRL_diff: function (base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl = Load_X509_CRL_diff;
  X509_REQ_check_private_key: function (x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_REQ_check_private_key;
  X509_check_private_key: function (const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_X509_check_private_key;
  X509_CRL_check_suiteb: function (crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_CRL_check_suiteb;
  X509_issuer_and_serial_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = Load_X509_issuer_and_serial_cmp;
  X509_issuer_and_serial_hash: function (a: PX509): TOpenSSL_C_ULONG; cdecl = Load_X509_issuer_and_serial_hash;
  X509_issuer_name_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = Load_X509_issuer_name_cmp;
  X509_issuer_name_hash: function (a: PX509): TOpenSSL_C_uLONG; cdecl = Load_X509_issuer_name_hash;
  X509_subject_name_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = Load_X509_subject_name_cmp;
  X509_subject_name_hash: function (x: PX509): TOpenSSL_C_ULONG; cdecl = Load_X509_subject_name_hash;
  X509_cmp: function (const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl = Load_X509_cmp;
  X509_NAME_cmp: function (const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_NAME_cmp;
  X509_NAME_hash_old: function (x: PX509_NAME): TOpenSSL_C_ULONG; cdecl = Load_X509_NAME_hash_old;
  X509_CRL_cmp: function (const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_cmp;
  X509_CRL_match: function (const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_match;
  X509_aux_print: function (out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_aux_print;
  X509_NAME_print: function (bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_print;
  X509_NAME_print_ex: function (out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_NAME_print_ex;
  X509_print_ex: function (bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_print_ex;
  X509_print: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_print;
  X509_ocspid_print: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_ocspid_print;
  X509_CRL_print_ex: function (out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_CRL_print_ex;
  X509_CRL_print: function (bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_print;
  X509_REQ_print_ex: function (bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_REQ_print_ex;
  X509_REQ_print: function (bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_X509_REQ_print;
  X509_NAME_entry_count: function (const name: PX509_NAME): TOpenSSL_C_INT; cdecl = Load_X509_NAME_entry_count;
  X509_NAME_get_text_by_NID: function (name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_get_text_by_NID;
  X509_NAME_get_text_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_get_text_by_OBJ;
  X509_NAME_get_index_by_NID: function (name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_get_index_by_NID;
  X509_NAME_get_index_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_get_index_by_OBJ;
  X509_NAME_get_entry: function (const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = Load_X509_NAME_get_entry;
  X509_NAME_delete_entry: function (name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl = Load_X509_NAME_delete_entry;
  X509_NAME_add_entry: function (name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_add_entry;
  X509_NAME_add_entry_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_add_entry_by_OBJ;
  X509_NAME_add_entry_by_NID: function (name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_add_entry_by_NID;
  X509_NAME_ENTRY_create_by_txt: function (ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = Load_X509_NAME_ENTRY_create_by_txt;
  X509_NAME_ENTRY_create_by_NID: function (ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = Load_X509_NAME_ENTRY_create_by_NID;
  X509_NAME_add_entry_by_txt: function (name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_add_entry_by_txt;
  X509_NAME_ENTRY_create_by_OBJ: function (ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl = Load_X509_NAME_ENTRY_create_by_OBJ;
  X509_NAME_ENTRY_set_object: function (ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_ENTRY_set_object;
  X509_NAME_ENTRY_set_data: function (ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_NAME_ENTRY_set_data;
  X509_NAME_ENTRY_get_object: function (const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl = Load_X509_NAME_ENTRY_get_object;
  X509_NAME_ENTRY_get_data: function (const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl = Load_X509_NAME_ENTRY_get_data;
  X509_NAME_ENTRY_set: function (const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl = Load_X509_NAME_ENTRY_set;
  X509_NAME_get0_der: function (nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_X509_NAME_get0_der;
  X509_get_ext_count: function (const x: PX509): TOpenSSL_C_INT; cdecl = Load_X509_get_ext_count;
  X509_get_ext_by_NID: function (const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_get_ext_by_NID;
  X509_get_ext_by_OBJ: function (const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_get_ext_by_OBJ;
  X509_get_ext_by_critical: function (const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_get_ext_by_critical;
  X509_get_ext: function (const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_X509_get_ext;
  X509_delete_ext: function (x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_X509_delete_ext;
  X509_add_ext: function (x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_add_ext;
  X509_get_ext_d2i: function (const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = Load_X509_get_ext_d2i;
  X509_add1_ext_i2d: function (x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_add1_ext_i2d;
  X509_CRL_get_ext_count: function (const x: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get_ext_count;
  X509_CRL_get_ext_by_NID: function (const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get_ext_by_NID;
  X509_CRL_get_ext_by_OBJ: function (const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get_ext_by_OBJ;
  X509_CRL_get_ext_by_critical: function (const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_CRL_get_ext_by_critical;
  X509_CRL_get_ext: function (const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_X509_CRL_get_ext;
  X509_CRL_delete_ext: function (x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_X509_CRL_delete_ext;
  X509_CRL_add_ext: function (x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_CRL_add_ext;
  X509_CRL_get_ext_d2i: function (const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = Load_X509_CRL_get_ext_d2i;
  X509_CRL_add1_ext_i2d: function (x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_CRL_add1_ext_i2d;
  X509_REVOKED_get_ext_count: function (const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_get_ext_count;
  X509_REVOKED_get_ext_by_NID: function (const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_get_ext_by_NID;
  X509_REVOKED_get_ext_by_OBJ: function (const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_get_ext_by_OBJ;
  X509_REVOKED_get_ext_by_critical: function (const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_get_ext_by_critical;
  X509_REVOKED_get_ext: function (const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_X509_REVOKED_get_ext;
  X509_REVOKED_delete_ext: function (x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_X509_REVOKED_delete_ext;
  X509_REVOKED_add_ext: function (x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_add_ext;
  X509_REVOKED_get_ext_d2i: function (const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = Load_X509_REVOKED_get_ext_d2i;
  X509_REVOKED_add1_ext_i2d: function (x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_X509_REVOKED_add1_ext_i2d;
  X509_EXTENSION_create_by_NID: function (ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = Load_X509_EXTENSION_create_by_NID;
  X509_EXTENSION_create_by_OBJ: function (ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = Load_X509_EXTENSION_create_by_OBJ;
  X509_EXTENSION_set_object: function (ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_X509_EXTENSION_set_object;
  X509_EXTENSION_set_critical: function (ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_EXTENSION_set_critical;
  X509_EXTENSION_set_data: function (ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl = Load_X509_EXTENSION_set_data;
  X509_EXTENSION_get_object: function (ex: PX509_EXTENSION): PASN1_OBJECT; cdecl = Load_X509_EXTENSION_get_object;
  X509_EXTENSION_get_data: function (ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl = Load_X509_EXTENSION_get_data;
  X509_EXTENSION_get_critical: function (const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl = Load_X509_EXTENSION_get_critical;
  X509_ATTRIBUTE_create_by_NID: function (attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_X509_ATTRIBUTE_create_by_NID;
  X509_ATTRIBUTE_create_by_OBJ: function (attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_X509_ATTRIBUTE_create_by_OBJ;
  X509_ATTRIBUTE_create_by_txt: function (attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_X509_ATTRIBUTE_create_by_txt;
  X509_ATTRIBUTE_set1_object: function (attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_X509_ATTRIBUTE_set1_object;
  X509_ATTRIBUTE_set1_data: function (attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_ATTRIBUTE_set1_data;
  X509_ATTRIBUTE_get0_data: function (attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl = Load_X509_ATTRIBUTE_get0_data;
  X509_ATTRIBUTE_count: function (const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = Load_X509_ATTRIBUTE_count;
  X509_ATTRIBUTE_get0_object: function (attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl = Load_X509_ATTRIBUTE_get0_object;
  X509_ATTRIBUTE_get0_type: function (attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl = Load_X509_ATTRIBUTE_get0_type;
  EVP_PKEY_get_attr_count: function (const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_attr_count;
  EVP_PKEY_get_attr_by_NID: function (const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_attr_by_NID;
  EVP_PKEY_get_attr_by_OBJ: function (const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_attr_by_OBJ;
  EVP_PKEY_get_attr: function (const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_EVP_PKEY_get_attr;
  EVP_PKEY_delete_attr: function (key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_EVP_PKEY_delete_attr;
  EVP_PKEY_add1_attr: function (key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_add1_attr;
  EVP_PKEY_add1_attr_by_OBJ: function (key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_add1_attr_by_OBJ;
  EVP_PKEY_add1_attr_by_NID: function (key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_add1_attr_by_NID;
  EVP_PKEY_add1_attr_by_txt: function (key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_add1_attr_by_txt;
  X509_verify_cert: function (ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl = Load_X509_verify_cert;
  PKCS5_pbe_set0_algor: function (algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_pbe_set0_algor;
  PKCS5_pbe_set: function (alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl = Load_PKCS5_pbe_set;
  PKCS5_pbe2_set: function (const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl = Load_PKCS5_pbe2_set;
  PKCS5_pbe2_set_iv: function (const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl = Load_PKCS5_pbe2_set_iv;
  PKCS5_pbe2_set_scrypt: function (const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl = Load_PKCS5_pbe2_set_scrypt;
  PKCS5_pbkdf2_set: function (iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl = Load_PKCS5_pbkdf2_set;
  EVP_PKCS82PKEY: function (const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl = Load_EVP_PKCS82PKEY;
  EVP_PKEY2PKCS8: function (pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl = Load_EVP_PKEY2PKCS8;
  PKCS8_pkey_set0: function (priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS8_pkey_set0;
  PKCS8_pkey_get0: function (const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = Load_PKCS8_pkey_get0;
  PKCS8_pkey_add1_attr_by_NID: function (p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS8_pkey_add1_attr_by_NID;
  X509_PUBKEY_set0_param: function (pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_PUBKEY_set0_param;
  X509_PUBKEY_get0_param: function (ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl = Load_X509_PUBKEY_get0_param;
  X509_check_trust: function (x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_check_trust;
  X509_TRUST_get_count: function : TOpenSSL_C_INT; cdecl = Load_X509_TRUST_get_count;
  X509_TRUST_get0: function (idx: TOpenSSL_C_INT): PX509_TRUST; cdecl = Load_X509_TRUST_get0;
  X509_TRUST_get_by_id: function (id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_X509_TRUST_get_by_id;
  X509_TRUST_cleanup: procedure ; cdecl = Load_X509_TRUST_cleanup;
  X509_TRUST_get_flags: function (const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl = Load_X509_TRUST_get_flags;
  X509_TRUST_get0_name: function (const xp: PX509_TRUST): PAnsiChar; cdecl = Load_X509_TRUST_get0_name;
  X509_TRUST_get_trust: function (const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl = Load_X509_TRUST_get_trust;
  X509_NAME_hash_ex: function (const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = Load_X509_NAME_hash_ex;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  X509_NAME_hash: function (x: PX509_NAME): TOpenSSL_C_ULONG; cdecl = Load_X509_NAME_hash; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  X509_http_nbio_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  X509_CRL_http_nbio_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  X509_PUBKEY_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_pathlen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_getm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_INFO_get_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_SIG_INFO_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_signature_info_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_signature_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_trusted_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_serialNumber_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_notBefore_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_getm_notBefore_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_set1_notBefore_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_notAfter_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_getm_notAfter_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_set1_notAfter_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_signature_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get_X509_PUBKEY_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_uids_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_tbs_sigalg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_get0_pubkey_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_subject_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get0_signature_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_signature_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  i2d_re_X509_REQ_tbs_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get0_pubkey_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REQ_get_X509_PUBKEY_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_set1_lastUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_set1_nextUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get0_lastUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get0_nextUpdate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get_issuer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get0_signature_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_get_signature_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  i2d_re_X509_CRL_tbs_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REVOKED_get0_serialNumber_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_REVOKED_get0_revocationDate_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_hash_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  X509_aux_print_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_CRL_print_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_ENTRY_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_get0_der_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS5_pbe2_set_scrypt_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS8_pkey_add1_attr_by_NID_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  X509_NAME_hash_ex_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}


implementation


//# define X509_NAME_hash(x) X509_NAME_hash_ex(x, NULL, NULL, NULL)

uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  X509_http_nbio: function (rctx: POCSP_REQ_CTX; pcert: PPX509): TOpenSSL_C_INT; cdecl = Load_X509_http_nbio; {removed 3.0.0}
  X509_CRL_http_nbio: function (rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TOpenSSL_C_INT; cdecl = Load_X509_CRL_http_nbio; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  ASIdentifierChoice_inherit = 0;
  ASIdentifierChoice_asIdsOrRanges = 1;
  SHA_DIGEST_LENGTH = 20;

type
  PSTACK= type pointer;
  PSTACK_OF_X509_EXTENSION = PSTACK; 
  PX509_CINF = ^_X509_CINF;
  _X509_CINF = record
    version: PASN1_INTEGER;
    serialNumber: PASN1_INTEGER;
    signature: PX509_ALGOR;
    issuer: PX509_NAME;
    validity: PX509_VAL;
    subject: PX509_NAME;
    key: PX509_PUBKEY;
    issuerUID: PASN1_BIT_STRING; // [ 1 ] optional in v2
    subjectUID: PASN1_BIT_STRING; // [ 2 ] optional in v2
    extensions: PSTACK_OF_X509_EXTENSION;
    enc : ASN1_ENCODING;
  end;

  PSTACK_OF_ASIdOrRange = PSTACK;

  PSTACK_OF_DIST_POINT = PSTACK;
  PSTACK_OF_GENERAL_NAME = PSTACK;
  PSTACK_OF_IPAddressFamily = PSTACK;
  PASIdOrRanges = PSTACK_OF_ASIdOrRange;

  ASIdentifierChoice_union = record
  case byte of
   ASIdentifierChoice_inherit : (inherit : PASN1_NULL);
   ASIdentifierChoice_asIdsOrRanges : (asIdsOrRanges : PASIdOrRanges);
  end;

  PASIdentifierChoice = ^ASIdentifierChoice;
  ASIdentifierChoice = record
    _type : TOpenSSL_C_INT;
    u : ASIdentifierChoice_union;
  end;

  PASIdentifiers = ^ASIdentifiers;
  ASIdentifiers = record
    asnum : PASIdentifierChoice;
    rdi : PASIdentifierChoice;
  end;

  PX509_CERT_AUX = pointer;
  
   _PX509 = ^X509;

X509 = record
    cert_info: PX509_CINF;
    sig_alg : PX509_ALGOR;
    signature : PASN1_BIT_STRING;
    valid : TOpenSSL_C_INT;
    references : TOpenSSL_C_INT;
    name : PAnsiChar;
    ex_data : CRYPTO_EX_DATA;
    // These contain copies of various extension values
    ex_pathlen : TOpenSSL_C_LONG;
    ex_pcpathlen : TOpenSSL_C_LONG;
    ex_flags : TOpenSSL_C_ULONG;
    ex_kusage : TOpenSSL_C_ULONG;
    ex_xkusage : TOpenSSL_C_ULONG;
    ex_nscert : TOpenSSL_C_ULONG;
    skid : PASN1_OCTET_STRING;
    akid : PAUTHORITY_KEYID;
    policy_cache : PX509_POLICY_CACHE;
    crldp : PSTACK_OF_DIST_POINT;
    altname : PSTACK_OF_GENERAL_NAME;
    nc : PNAME_CONSTRAINTS;
    {$IFNDEF OPENSSL_NO_RFC3779}
    rfc3779_addr : PSTACK_OF_IPAddressFamily;
    rfc3779_asid : PASIdentifiers;
    {$ENDIF}
    {$IFNDEF OPENSSL_NO_SHA}
    sha1_hash : array [0..SHA_DIGEST_LENGTH-1] of AnsiChar;
    {$ENDIF}
    aux : PX509_CERT_AUX;
  end;   


{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG;

begin
  Result := X509_NAME_hash_ex(x,nil,nil,nil);
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;

begin
  Result := X509_NAME_hash_ex(x,nil,nil,nil);
end;


procedure COMPAT_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl;

begin
  sig := _PX509(x)^.signature;
  alg := _PX509(x)^.sig_alg;
end;



function COMPAT_X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl;

begin
  Result := _PX509(x)^.cert_info.validity.notBefore;
end;



function COMPAT_X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl;

begin
  Result := _PX509(x)^.cert_info.validity.notAfter;
end;



function COMPAT_X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_type(OBJ_obj2nid(_PX509(x)^.sig_alg^.algorithm));
end;









{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_X509_CRL_set_default_method(const meth: PX509_CRL_METHOD); cdecl;
begin
  X509_CRL_set_default_method := LoadLibCryptoFunction('X509_CRL_set_default_method');
  if not assigned(X509_CRL_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_default_method');
  X509_CRL_set_default_method(meth);
end;

procedure Load_X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl;
begin
  X509_CRL_METHOD_free := LoadLibCryptoFunction('X509_CRL_METHOD_free');
  if not assigned(X509_CRL_METHOD_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_METHOD_free');
  X509_CRL_METHOD_free(m);
end;

procedure Load_X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl;
begin
  X509_CRL_set_meth_data := LoadLibCryptoFunction('X509_CRL_set_meth_data');
  if not assigned(X509_CRL_set_meth_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_meth_data');
  X509_CRL_set_meth_data(crl,dat);
end;

function Load_X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl;
begin
  X509_CRL_get_meth_data := LoadLibCryptoFunction('X509_CRL_get_meth_data');
  if not assigned(X509_CRL_get_meth_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_meth_data');
  Result := X509_CRL_get_meth_data(crl);
end;

function Load_X509_verify_cert_error_string(n: TOpenSSL_C_LONG): PAnsiChar; cdecl;
begin
  X509_verify_cert_error_string := LoadLibCryptoFunction('X509_verify_cert_error_string');
  if not assigned(X509_verify_cert_error_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_verify_cert_error_string');
  Result := X509_verify_cert_error_string(n);
end;

function Load_X509_verify(a: PX509; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_verify := LoadLibCryptoFunction('X509_verify');
  if not assigned(X509_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_verify');
  Result := X509_verify(a,r);
end;

function Load_X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_verify := LoadLibCryptoFunction('X509_REQ_verify');
  if not assigned(X509_REQ_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_verify');
  Result := X509_REQ_verify(a,r);
end;

function Load_X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_verify := LoadLibCryptoFunction('X509_CRL_verify');
  if not assigned(X509_CRL_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_verify');
  Result := X509_CRL_verify(a,r);
end;

function Load_NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  NETSCAPE_SPKI_verify := LoadLibCryptoFunction('NETSCAPE_SPKI_verify');
  if not assigned(NETSCAPE_SPKI_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_verify');
  Result := NETSCAPE_SPKI_verify(a,r);
end;

function Load_NETSCAPE_SPKI_b64_decode(const str: PAnsiChar; len: TOpenSSL_C_INT): PNETSCAPE_SPKI; cdecl;
begin
  NETSCAPE_SPKI_b64_decode := LoadLibCryptoFunction('NETSCAPE_SPKI_b64_decode');
  if not assigned(NETSCAPE_SPKI_b64_decode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_b64_decode');
  Result := NETSCAPE_SPKI_b64_decode(str,len);
end;

function Load_NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PAnsiChar; cdecl;
begin
  NETSCAPE_SPKI_b64_encode := LoadLibCryptoFunction('NETSCAPE_SPKI_b64_encode');
  if not assigned(NETSCAPE_SPKI_b64_encode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_b64_encode');
  Result := NETSCAPE_SPKI_b64_encode(x);
end;

function Load_NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl;
begin
  NETSCAPE_SPKI_get_pubkey := LoadLibCryptoFunction('NETSCAPE_SPKI_get_pubkey');
  if not assigned(NETSCAPE_SPKI_get_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_get_pubkey');
  Result := NETSCAPE_SPKI_get_pubkey(x);
end;

function Load_NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  NETSCAPE_SPKI_set_pubkey := LoadLibCryptoFunction('NETSCAPE_SPKI_set_pubkey');
  if not assigned(NETSCAPE_SPKI_set_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_set_pubkey');
  Result := NETSCAPE_SPKI_set_pubkey(x,pkey);
end;

function Load_NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TOpenSSL_C_INT; cdecl;
begin
  NETSCAPE_SPKI_print := LoadLibCryptoFunction('NETSCAPE_SPKI_print');
  if not assigned(NETSCAPE_SPKI_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_print');
  Result := NETSCAPE_SPKI_print(out_,spki);
end;

function Load_X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_signature_dump := LoadLibCryptoFunction('X509_signature_dump');
  if not assigned(X509_signature_dump) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_signature_dump');
  Result := X509_signature_dump(bp,sig,indent);
end;

function Load_X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  X509_signature_print := LoadLibCryptoFunction('X509_signature_print');
  if not assigned(X509_signature_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_signature_print');
  Result := X509_signature_print(bp,alg,sig);
end;

function Load_X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  X509_sign := LoadLibCryptoFunction('X509_sign');
  if not assigned(X509_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_sign');
  Result := X509_sign(x,pkey,md);
end;

function Load_X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  X509_sign_ctx := LoadLibCryptoFunction('X509_sign_ctx');
  if not assigned(X509_sign_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_sign_ctx');
  Result := X509_sign_ctx(x,ctx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_X509_http_nbio(rctx: POCSP_REQ_CTX; pcert: PPX509): TOpenSSL_C_INT; cdecl;
begin
  X509_http_nbio := LoadLibCryptoFunction('X509_http_nbio');
  if not assigned(X509_http_nbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_http_nbio');
  Result := X509_http_nbio(rctx,pcert);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_sign := LoadLibCryptoFunction('X509_REQ_sign');
  if not assigned(X509_REQ_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_sign');
  Result := X509_REQ_sign(x,pkey,md);
end;

function Load_X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_sign_ctx := LoadLibCryptoFunction('X509_REQ_sign_ctx');
  if not assigned(X509_REQ_sign_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_sign_ctx');
  Result := X509_REQ_sign_ctx(x,ctx);
end;

function Load_X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_sign := LoadLibCryptoFunction('X509_CRL_sign');
  if not assigned(X509_CRL_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_sign');
  Result := X509_CRL_sign(x,pkey,md);
end;

function Load_X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_sign_ctx := LoadLibCryptoFunction('X509_CRL_sign_ctx');
  if not assigned(X509_CRL_sign_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_sign_ctx');
  Result := X509_CRL_sign_ctx(x,ctx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_X509_CRL_http_nbio(rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_http_nbio := LoadLibCryptoFunction('X509_CRL_http_nbio');
  if not assigned(X509_CRL_http_nbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_http_nbio');
  Result := X509_CRL_http_nbio(rctx,pcrl);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  NETSCAPE_SPKI_sign := LoadLibCryptoFunction('NETSCAPE_SPKI_sign');
  if not assigned(NETSCAPE_SPKI_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NETSCAPE_SPKI_sign');
  Result := NETSCAPE_SPKI_sign(x,pkey,md);
end;

function Load_X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  X509_pubkey_digest := LoadLibCryptoFunction('X509_pubkey_digest');
  if not assigned(X509_pubkey_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_pubkey_digest');
  Result := X509_pubkey_digest(data,type_,md,len);
end;

function Load_X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  X509_digest := LoadLibCryptoFunction('X509_digest');
  if not assigned(X509_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_digest');
  Result := X509_digest(data,type_,md,len);
end;

function Load_X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_digest := LoadLibCryptoFunction('X509_CRL_digest');
  if not assigned(X509_CRL_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_digest');
  Result := X509_CRL_digest(data,type_,md,len);
end;

function Load_X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_digest := LoadLibCryptoFunction('X509_REQ_digest');
  if not assigned(X509_REQ_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_digest');
  Result := X509_REQ_digest(data,type_,md,len);
end;

function Load_X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_digest := LoadLibCryptoFunction('X509_NAME_digest');
  if not assigned(X509_NAME_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_digest');
  Result := X509_NAME_digest(data,type_,md,len);
end;

function Load_d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl;
begin
  d2i_X509_bio := LoadLibCryptoFunction('d2i_X509_bio');
  if not assigned(d2i_X509_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_bio');
  Result := d2i_X509_bio(bp,x509);
end;

function Load_i2d_X509_bio(bp: PBIO; x509: PX509): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_bio := LoadLibCryptoFunction('i2d_X509_bio');
  if not assigned(i2d_X509_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_bio');
  Result := i2d_X509_bio(bp,x509);
end;

function Load_d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl;
begin
  d2i_X509_CRL_bio := LoadLibCryptoFunction('d2i_X509_CRL_bio');
  if not assigned(d2i_X509_CRL_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_CRL_bio');
  Result := d2i_X509_CRL_bio(bp,crl);
end;

function Load_i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_CRL_bio := LoadLibCryptoFunction('i2d_X509_CRL_bio');
  if not assigned(i2d_X509_CRL_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_CRL_bio');
  Result := i2d_X509_CRL_bio(bp,crl);
end;

function Load_d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl;
begin
  d2i_X509_REQ_bio := LoadLibCryptoFunction('d2i_X509_REQ_bio');
  if not assigned(d2i_X509_REQ_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REQ_bio');
  Result := d2i_X509_REQ_bio(bp,req);
end;

function Load_i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_REQ_bio := LoadLibCryptoFunction('i2d_X509_REQ_bio');
  if not assigned(i2d_X509_REQ_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REQ_bio');
  Result := i2d_X509_REQ_bio(bp,req);
end;

function Load_d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
begin
  d2i_RSAPrivateKey_bio := LoadLibCryptoFunction('d2i_RSAPrivateKey_bio');
  if not assigned(d2i_RSAPrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSAPrivateKey_bio');
  Result := d2i_RSAPrivateKey_bio(bp,rsa);
end;

function Load_i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSAPrivateKey_bio := LoadLibCryptoFunction('i2d_RSAPrivateKey_bio');
  if not assigned(i2d_RSAPrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSAPrivateKey_bio');
  Result := i2d_RSAPrivateKey_bio(bp,rsa);
end;

function Load_d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
begin
  d2i_RSAPublicKey_bio := LoadLibCryptoFunction('d2i_RSAPublicKey_bio');
  if not assigned(d2i_RSAPublicKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSAPublicKey_bio');
  Result := d2i_RSAPublicKey_bio(bp,rsa);
end;

function Load_i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSAPublicKey_bio := LoadLibCryptoFunction('i2d_RSAPublicKey_bio');
  if not assigned(i2d_RSAPublicKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSAPublicKey_bio');
  Result := i2d_RSAPublicKey_bio(bp,rsa);
end;

function Load_d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl;
begin
  d2i_RSA_PUBKEY_bio := LoadLibCryptoFunction('d2i_RSA_PUBKEY_bio');
  if not assigned(d2i_RSA_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSA_PUBKEY_bio');
  Result := d2i_RSA_PUBKEY_bio(bp,rsa);
end;

function Load_i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSA_PUBKEY_bio := LoadLibCryptoFunction('i2d_RSA_PUBKEY_bio');
  if not assigned(i2d_RSA_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSA_PUBKEY_bio');
  Result := i2d_RSA_PUBKEY_bio(bp,rsa);
end;

function Load_d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): DSA; cdecl;
begin
  d2i_DSA_PUBKEY_bio := LoadLibCryptoFunction('d2i_DSA_PUBKEY_bio');
  if not assigned(d2i_DSA_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_PUBKEY_bio');
  Result := d2i_DSA_PUBKEY_bio(bp,dsa);
end;

function Load_i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSA_PUBKEY_bio := LoadLibCryptoFunction('i2d_DSA_PUBKEY_bio');
  if not assigned(i2d_DSA_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_PUBKEY_bio');
  Result := i2d_DSA_PUBKEY_bio(bp,dsa);
end;

function Load_d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl;
begin
  d2i_DSAPrivateKey_bio := LoadLibCryptoFunction('d2i_DSAPrivateKey_bio');
  if not assigned(d2i_DSAPrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPrivateKey_bio');
  Result := d2i_DSAPrivateKey_bio(bp,dsa);
end;

function Load_i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAPrivateKey_bio := LoadLibCryptoFunction('i2d_DSAPrivateKey_bio');
  if not assigned(i2d_DSAPrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPrivateKey_bio');
  Result := i2d_DSAPrivateKey_bio(bp,dsa);
end;

function Load_d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl;
begin
  d2i_EC_PUBKEY_bio := LoadLibCryptoFunction('d2i_EC_PUBKEY_bio');
  if not assigned(d2i_EC_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_EC_PUBKEY_bio');
  Result := d2i_EC_PUBKEY_bio(bp,eckey);
end;

function Load_i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  i2d_EC_PUBKEY_bio := LoadLibCryptoFunction('i2d_EC_PUBKEY_bio');
  if not assigned(i2d_EC_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_EC_PUBKEY_bio');
  Result := i2d_EC_PUBKEY_bio(bp,eckey);
end;

function Load_d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): EC_KEY; cdecl;
begin
  d2i_ECPrivateKey_bio := LoadLibCryptoFunction('d2i_ECPrivateKey_bio');
  if not assigned(d2i_ECPrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPrivateKey_bio');
  Result := d2i_ECPrivateKey_bio(bp,eckey);
end;

function Load_i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECPrivateKey_bio := LoadLibCryptoFunction('i2d_ECPrivateKey_bio');
  if not assigned(i2d_ECPrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPrivateKey_bio');
  Result := i2d_ECPrivateKey_bio(bp,eckey);
end;

function Load_d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl;
begin
  d2i_PKCS8_bio := LoadLibCryptoFunction('d2i_PKCS8_bio');
  if not assigned(d2i_PKCS8_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8_bio');
  Result := d2i_PKCS8_bio(bp,p8);
end;

function Load_i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8_bio := LoadLibCryptoFunction('i2d_PKCS8_bio');
  if not assigned(i2d_PKCS8_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8_bio');
  Result := i2d_PKCS8_bio(bp,p8);
end;

function Load_d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  d2i_PKCS8_PRIV_KEY_INFO_bio := LoadLibCryptoFunction('d2i_PKCS8_PRIV_KEY_INFO_bio');
  if not assigned(d2i_PKCS8_PRIV_KEY_INFO_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8_PRIV_KEY_INFO_bio');
  Result := d2i_PKCS8_PRIV_KEY_INFO_bio(bp,p8inf);
end;

function Load_i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8_PRIV_KEY_INFO_bio := LoadLibCryptoFunction('i2d_PKCS8_PRIV_KEY_INFO_bio');
  if not assigned(i2d_PKCS8_PRIV_KEY_INFO_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8_PRIV_KEY_INFO_bio');
  Result := i2d_PKCS8_PRIV_KEY_INFO_bio(bp,p8inf);
end;

function Load_i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKeyInfo_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKeyInfo_bio');
  if not assigned(i2d_PKCS8PrivateKeyInfo_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKeyInfo_bio');
  Result := i2d_PKCS8PrivateKeyInfo_bio(bp,key);
end;

function Load_i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2d_PrivateKey_bio := LoadLibCryptoFunction('i2d_PrivateKey_bio');
  if not assigned(i2d_PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PrivateKey_bio');
  Result := i2d_PrivateKey_bio(bp,pkey);
end;

function Load_d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  d2i_PrivateKey_bio := LoadLibCryptoFunction('d2i_PrivateKey_bio');
  if not assigned(d2i_PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PrivateKey_bio');
  Result := d2i_PrivateKey_bio(bp,a);
end;

function Load_i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2d_PUBKEY_bio := LoadLibCryptoFunction('i2d_PUBKEY_bio');
  if not assigned(i2d_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PUBKEY_bio');
  Result := i2d_PUBKEY_bio(bp,pkey);
end;

function Load_d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  d2i_PUBKEY_bio := LoadLibCryptoFunction('d2i_PUBKEY_bio');
  if not assigned(d2i_PUBKEY_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PUBKEY_bio');
  Result := d2i_PUBKEY_bio(bp,a);
end;

function Load_X509_dup(x509: PX509): PX509; cdecl;
begin
  X509_dup := LoadLibCryptoFunction('X509_dup');
  if not assigned(X509_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_dup');
  Result := X509_dup(x509);
end;

function Load_X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl;
begin
  X509_ATTRIBUTE_dup := LoadLibCryptoFunction('X509_ATTRIBUTE_dup');
  if not assigned(X509_ATTRIBUTE_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_dup');
  Result := X509_ATTRIBUTE_dup(xa);
end;

function Load_X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl;
begin
  X509_EXTENSION_dup := LoadLibCryptoFunction('X509_EXTENSION_dup');
  if not assigned(X509_EXTENSION_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_dup');
  Result := X509_EXTENSION_dup(ex);
end;

function Load_X509_CRL_dup(crl: PX509_CRL): PX509_CRL; cdecl;
begin
  X509_CRL_dup := LoadLibCryptoFunction('X509_CRL_dup');
  if not assigned(X509_CRL_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_dup');
  Result := X509_CRL_dup(crl);
end;

function Load_X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED; cdecl;
begin
  X509_REVOKED_dup := LoadLibCryptoFunction('X509_REVOKED_dup');
  if not assigned(X509_REVOKED_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_dup');
  Result := X509_REVOKED_dup(rev);
end;

function Load_X509_REQ_dup(req: PX509_REQ): PX509_REQ; cdecl;
begin
  X509_REQ_dup := LoadLibCryptoFunction('X509_REQ_dup');
  if not assigned(X509_REQ_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_dup');
  Result := X509_REQ_dup(req);
end;

function Load_X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR; cdecl;
begin
  X509_ALGOR_dup := LoadLibCryptoFunction('X509_ALGOR_dup');
  if not assigned(X509_ALGOR_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_dup');
  Result := X509_ALGOR_dup(xn);
end;

function Load_X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer): TOpenSSL_C_INT; cdecl;
begin
  X509_ALGOR_set0 := LoadLibCryptoFunction('X509_ALGOR_set0');
  if not assigned(X509_ALGOR_set0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_set0');
  Result := X509_ALGOR_set0(alg,aobj,ptype,pval);
end;

procedure Load_X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: POpenSSL_C_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl;
begin
  X509_ALGOR_get0 := LoadLibCryptoFunction('X509_ALGOR_get0');
  if not assigned(X509_ALGOR_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_get0');
  X509_ALGOR_get0(paobj,pptype,ppval,algor);
end;

procedure Load_X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD); cdecl;
begin
  X509_ALGOR_set_md := LoadLibCryptoFunction('X509_ALGOR_set_md');
  if not assigned(X509_ALGOR_set_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_set_md');
  X509_ALGOR_set_md(alg,md);
end;

function Load_X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  X509_ALGOR_cmp := LoadLibCryptoFunction('X509_ALGOR_cmp');
  if not assigned(X509_ALGOR_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_cmp');
  Result := X509_ALGOR_cmp(a,b);
end;

function Load_X509_NAME_dup(xn: PX509_NAME): PX509_NAME; cdecl;
begin
  X509_NAME_dup := LoadLibCryptoFunction('X509_NAME_dup');
  if not assigned(X509_NAME_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_dup');
  Result := X509_NAME_dup(xn);
end;

function Load_X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_ENTRY_dup := LoadLibCryptoFunction('X509_NAME_ENTRY_dup');
  if not assigned(X509_NAME_ENTRY_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_dup');
  Result := X509_NAME_ENTRY_dup(ne);
end;

function Load_X509_cmp_time(const s: PASN1_TIME; t: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  X509_cmp_time := LoadLibCryptoFunction('X509_cmp_time');
  if not assigned(X509_cmp_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_cmp_time');
  Result := X509_cmp_time(s,t);
end;

function Load_X509_cmp_current_time(const s: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  X509_cmp_current_time := LoadLibCryptoFunction('X509_cmp_current_time');
  if not assigned(X509_cmp_current_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_cmp_current_time');
  Result := X509_cmp_current_time(s);
end;

function Load_X509_time_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl;
begin
  X509_time_adj := LoadLibCryptoFunction('X509_time_adj');
  if not assigned(X509_time_adj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_time_adj');
  Result := X509_time_adj(s,adj,t);
end;

function Load_X509_time_adj_ex(s: PASN1_TIME; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG; t: POpenSSL_C_TIMET): PASN1_TIME; cdecl;
begin
  X509_time_adj_ex := LoadLibCryptoFunction('X509_time_adj_ex');
  if not assigned(X509_time_adj_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_time_adj_ex');
  Result := X509_time_adj_ex(s,offset_day,offset_sec,t);
end;

function Load_X509_gmtime_adj(s: PASN1_TIME; adj: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
begin
  X509_gmtime_adj := LoadLibCryptoFunction('X509_gmtime_adj');
  if not assigned(X509_gmtime_adj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_gmtime_adj');
  Result := X509_gmtime_adj(s,adj);
end;

function Load_X509_get_default_cert_area: PAnsiChar; cdecl;
begin
  X509_get_default_cert_area := LoadLibCryptoFunction('X509_get_default_cert_area');
  if not assigned(X509_get_default_cert_area) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_area');
  Result := X509_get_default_cert_area();
end;

function Load_X509_get_default_cert_dir: PAnsiChar; cdecl;
begin
  X509_get_default_cert_dir := LoadLibCryptoFunction('X509_get_default_cert_dir');
  if not assigned(X509_get_default_cert_dir) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_dir');
  Result := X509_get_default_cert_dir();
end;

function Load_X509_get_default_cert_file: PAnsiChar; cdecl;
begin
  X509_get_default_cert_file := LoadLibCryptoFunction('X509_get_default_cert_file');
  if not assigned(X509_get_default_cert_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_file');
  Result := X509_get_default_cert_file();
end;

function Load_X509_get_default_cert_dir_env: PAnsiChar; cdecl;
begin
  X509_get_default_cert_dir_env := LoadLibCryptoFunction('X509_get_default_cert_dir_env');
  if not assigned(X509_get_default_cert_dir_env) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_dir_env');
  Result := X509_get_default_cert_dir_env();
end;

function Load_X509_get_default_cert_file_env: PAnsiChar; cdecl;
begin
  X509_get_default_cert_file_env := LoadLibCryptoFunction('X509_get_default_cert_file_env');
  if not assigned(X509_get_default_cert_file_env) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_cert_file_env');
  Result := X509_get_default_cert_file_env();
end;

function Load_X509_get_default_private_dir: PAnsiChar; cdecl;
begin
  X509_get_default_private_dir := LoadLibCryptoFunction('X509_get_default_private_dir');
  if not assigned(X509_get_default_private_dir) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_default_private_dir');
  Result := X509_get_default_private_dir();
end;

function Load_X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl;
begin
  X509_to_X509_REQ := LoadLibCryptoFunction('X509_to_X509_REQ');
  if not assigned(X509_to_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_to_X509_REQ');
  Result := X509_to_X509_REQ(x,pkey,md);
end;

function Load_X509_REQ_to_X509(r: PX509_REQ; days: TOpenSSL_C_INT; pkey: PEVP_PKEY): PX509; cdecl;
begin
  X509_REQ_to_X509 := LoadLibCryptoFunction('X509_REQ_to_X509');
  if not assigned(X509_REQ_to_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_to_X509');
  Result := X509_REQ_to_X509(r,days,pkey);
end;

function Load_X509_ALGOR_new: PX509_ALGOR; cdecl;
begin
  X509_ALGOR_new := LoadLibCryptoFunction('X509_ALGOR_new');
  if not assigned(X509_ALGOR_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_new');
  Result := X509_ALGOR_new();
end;

procedure Load_X509_ALGOR_free(v1: PX509_ALGOR); cdecl;
begin
  X509_ALGOR_free := LoadLibCryptoFunction('X509_ALGOR_free');
  if not assigned(X509_ALGOR_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ALGOR_free');
  X509_ALGOR_free(v1);
end;

function Load_d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ALGOR; cdecl;
begin
  d2i_X509_ALGOR := LoadLibCryptoFunction('d2i_X509_ALGOR');
  if not assigned(d2i_X509_ALGOR) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_ALGOR');
  Result := d2i_X509_ALGOR(a,in_,len);
end;

function Load_i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_ALGOR := LoadLibCryptoFunction('i2d_X509_ALGOR');
  if not assigned(i2d_X509_ALGOR) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_ALGOR');
  Result := i2d_X509_ALGOR(a,out_);
end;

function Load_X509_VAL_new: PX509_VAL; cdecl;
begin
  X509_VAL_new := LoadLibCryptoFunction('X509_VAL_new');
  if not assigned(X509_VAL_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VAL_new');
  Result := X509_VAL_new();
end;

procedure Load_X509_VAL_free(v1: PX509_VAL); cdecl;
begin
  X509_VAL_free := LoadLibCryptoFunction('X509_VAL_free');
  if not assigned(X509_VAL_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_VAL_free');
  X509_VAL_free(v1);
end;

function Load_d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_VAL; cdecl;
begin
  d2i_X509_VAL := LoadLibCryptoFunction('d2i_X509_VAL');
  if not assigned(d2i_X509_VAL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_VAL');
  Result := d2i_X509_VAL(a,in_,len);
end;

function Load_i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_VAL := LoadLibCryptoFunction('i2d_X509_VAL');
  if not assigned(i2d_X509_VAL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_VAL');
  Result := i2d_X509_VAL(a,out_);
end;

function Load_X509_PUBKEY_new: PX509_PUBKEY; cdecl;
begin
  X509_PUBKEY_new := LoadLibCryptoFunction('X509_PUBKEY_new');
  if not assigned(X509_PUBKEY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_new');
  Result := X509_PUBKEY_new();
end;

procedure Load_X509_PUBKEY_free(v1: PX509_PUBKEY); cdecl;
begin
  X509_PUBKEY_free := LoadLibCryptoFunction('X509_PUBKEY_free');
  if not assigned(X509_PUBKEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_free');
  X509_PUBKEY_free(v1);
end;

function Load_d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_PUBKEY; cdecl;
begin
  d2i_X509_PUBKEY := LoadLibCryptoFunction('d2i_X509_PUBKEY');
  if not assigned(d2i_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_PUBKEY');
  Result := d2i_X509_PUBKEY(a,in_,len);
end;

function Load_i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_PUBKEY := LoadLibCryptoFunction('i2d_X509_PUBKEY');
  if not assigned(i2d_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_PUBKEY');
  Result := i2d_X509_PUBKEY(a,out_);
end;

function Load_X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_PUBKEY_set := LoadLibCryptoFunction('X509_PUBKEY_set');
  if not assigned(X509_PUBKEY_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_set');
  Result := X509_PUBKEY_set(x,pkey);
end;

function Load_X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
begin
  X509_PUBKEY_get0 := LoadLibCryptoFunction('X509_PUBKEY_get0');
  if not assigned(X509_PUBKEY_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_get0');
  Result := X509_PUBKEY_get0(key);
end;

function Load_X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
begin
  X509_PUBKEY_get := LoadLibCryptoFunction('X509_PUBKEY_get');
  if not assigned(X509_PUBKEY_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_get');
  Result := X509_PUBKEY_get(key);
end;

function Load_X509_get_pathlen(x: PX509): TOpenSSL_C_LONG; cdecl;
begin
  X509_get_pathlen := LoadLibCryptoFunction('X509_get_pathlen');
  if not assigned(X509_get_pathlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_pathlen');
  Result := X509_get_pathlen(x);
end;

function Load_i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PUBKEY := LoadLibCryptoFunction('i2d_PUBKEY');
  if not assigned(i2d_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PUBKEY');
  Result := i2d_PUBKEY(a,pp);
end;

function Load_d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  d2i_PUBKEY := LoadLibCryptoFunction('d2i_PUBKEY');
  if not assigned(d2i_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PUBKEY');
  Result := d2i_PUBKEY(a,pp,length);
end;

function Load_i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSA_PUBKEY := LoadLibCryptoFunction('i2d_RSA_PUBKEY');
  if not assigned(i2d_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSA_PUBKEY');
  Result := i2d_RSA_PUBKEY(a,pp);
end;

function Load_d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; length: TOpenSSL_C_LONG): PRSA; cdecl;
begin
  d2i_RSA_PUBKEY := LoadLibCryptoFunction('d2i_RSA_PUBKEY');
  if not assigned(d2i_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSA_PUBKEY');
  Result := d2i_RSA_PUBKEY(a,pp,length);
end;

function Load_i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSA_PUBKEY := LoadLibCryptoFunction('i2d_DSA_PUBKEY');
  if not assigned(i2d_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_PUBKEY');
  Result := i2d_DSA_PUBKEY(a,pp);
end;

function Load_d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  d2i_DSA_PUBKEY := LoadLibCryptoFunction('d2i_DSA_PUBKEY');
  if not assigned(d2i_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_PUBKEY');
  Result := d2i_DSA_PUBKEY(a,pp,length);
end;

function Load_i2d_EC_PUBKEY(a: EC_KEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_EC_PUBKEY := LoadLibCryptoFunction('i2d_EC_PUBKEY');
  if not assigned(i2d_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_EC_PUBKEY');
  Result := i2d_EC_PUBKEY(a,pp);
end;

function Load_d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEC_KEY; cdecl;
begin
  d2i_EC_PUBKEY := LoadLibCryptoFunction('d2i_EC_PUBKEY');
  if not assigned(d2i_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_EC_PUBKEY');
  Result := d2i_EC_PUBKEY(a,pp,length);
end;

function Load_X509_SIG_new: PX509_SIG; cdecl;
begin
  X509_SIG_new := LoadLibCryptoFunction('X509_SIG_new');
  if not assigned(X509_SIG_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_new');
  Result := X509_SIG_new();
end;

procedure Load_X509_SIG_free(v1: PX509_SIG); cdecl;
begin
  X509_SIG_free := LoadLibCryptoFunction('X509_SIG_free');
  if not assigned(X509_SIG_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_free');
  X509_SIG_free(v1);
end;

function Load_d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_SIG; cdecl;
begin
  d2i_X509_SIG := LoadLibCryptoFunction('d2i_X509_SIG');
  if not assigned(d2i_X509_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_SIG');
  Result := d2i_X509_SIG(a,in_,len);
end;

function Load_i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_SIG := LoadLibCryptoFunction('i2d_X509_SIG');
  if not assigned(i2d_X509_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_SIG');
  Result := i2d_X509_SIG(a,out_);
end;

procedure Load_X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl;
begin
  X509_SIG_get0 := LoadLibCryptoFunction('X509_SIG_get0');
  if not assigned(X509_SIG_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_get0');
  X509_SIG_get0(sig,palg,pdigest);
end;

procedure Load_X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl;
begin
  X509_SIG_getm := LoadLibCryptoFunction('X509_SIG_getm');
  if not assigned(X509_SIG_getm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_getm');
  X509_SIG_getm(sig,palg,pdigest);
end;

function Load_X509_REQ_INFO_new: PX509_REQ_INFO; cdecl;
begin
  X509_REQ_INFO_new := LoadLibCryptoFunction('X509_REQ_INFO_new');
  if not assigned(X509_REQ_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_INFO_new');
  Result := X509_REQ_INFO_new();
end;

procedure Load_X509_REQ_INFO_free(v1: PX509_REQ_INFO); cdecl;
begin
  X509_REQ_INFO_free := LoadLibCryptoFunction('X509_REQ_INFO_free');
  if not assigned(X509_REQ_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_INFO_free');
  X509_REQ_INFO_free(v1);
end;

function Load_d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ_INFO; cdecl;
begin
  d2i_X509_REQ_INFO := LoadLibCryptoFunction('d2i_X509_REQ_INFO');
  if not assigned(d2i_X509_REQ_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REQ_INFO');
  Result := d2i_X509_REQ_INFO(a,in_,len);
end;

function Load_i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_REQ_INFO := LoadLibCryptoFunction('i2d_X509_REQ_INFO');
  if not assigned(i2d_X509_REQ_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REQ_INFO');
  Result := i2d_X509_REQ_INFO(a,out_);
end;

function Load_X509_REQ_new: PX509_REQ; cdecl;
begin
  X509_REQ_new := LoadLibCryptoFunction('X509_REQ_new');
  if not assigned(X509_REQ_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_new');
  Result := X509_REQ_new();
end;

procedure Load_X509_REQ_free(v1: PX509_REQ); cdecl;
begin
  X509_REQ_free := LoadLibCryptoFunction('X509_REQ_free');
  if not assigned(X509_REQ_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_free');
  X509_REQ_free(v1);
end;

function Load_d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REQ; cdecl;
begin
  d2i_X509_REQ := LoadLibCryptoFunction('d2i_X509_REQ');
  if not assigned(d2i_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REQ');
  Result := d2i_X509_REQ(a,in_,len);
end;

function Load_i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_REQ := LoadLibCryptoFunction('i2d_X509_REQ');
  if not assigned(i2d_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REQ');
  Result := i2d_X509_REQ(a,out_);
end;

function Load_X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl;
begin
  X509_ATTRIBUTE_new := LoadLibCryptoFunction('X509_ATTRIBUTE_new');
  if not assigned(X509_ATTRIBUTE_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_new');
  Result := X509_ATTRIBUTE_new();
end;

procedure Load_X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE); cdecl;
begin
  X509_ATTRIBUTE_free := LoadLibCryptoFunction('X509_ATTRIBUTE_free');
  if not assigned(X509_ATTRIBUTE_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_free');
  X509_ATTRIBUTE_free(v1);
end;

function Load_d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_ATTRIBUTE; cdecl;
begin
  d2i_X509_ATTRIBUTE := LoadLibCryptoFunction('d2i_X509_ATTRIBUTE');
  if not assigned(d2i_X509_ATTRIBUTE) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_ATTRIBUTE');
  Result := d2i_X509_ATTRIBUTE(a,in_,len);
end;

function Load_i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_ATTRIBUTE := LoadLibCryptoFunction('i2d_X509_ATTRIBUTE');
  if not assigned(i2d_X509_ATTRIBUTE) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_ATTRIBUTE');
  Result := i2d_X509_ATTRIBUTE(a,out_);
end;

function Load_X509_ATTRIBUTE_create(nid: TOpenSSL_C_INT; trtype: TOpenSSL_C_INT; value: Pointer): PX509_ATTRIBUTE; cdecl;
begin
  X509_ATTRIBUTE_create := LoadLibCryptoFunction('X509_ATTRIBUTE_create');
  if not assigned(X509_ATTRIBUTE_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create');
  Result := X509_ATTRIBUTE_create(nid,trtype,value);
end;

function Load_X509_EXTENSION_new: PX509_EXTENSION; cdecl;
begin
  X509_EXTENSION_new := LoadLibCryptoFunction('X509_EXTENSION_new');
  if not assigned(X509_EXTENSION_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_new');
  Result := X509_EXTENSION_new();
end;

procedure Load_X509_EXTENSION_free(v1: PX509_EXTENSION); cdecl;
begin
  X509_EXTENSION_free := LoadLibCryptoFunction('X509_EXTENSION_free');
  if not assigned(X509_EXTENSION_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_free');
  X509_EXTENSION_free(v1);
end;

function Load_d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_EXTENSION; cdecl;
begin
  d2i_X509_EXTENSION := LoadLibCryptoFunction('d2i_X509_EXTENSION');
  if not assigned(d2i_X509_EXTENSION) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_EXTENSION');
  Result := d2i_X509_EXTENSION(a,in_,len);
end;

function Load_i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_EXTENSION := LoadLibCryptoFunction('i2d_X509_EXTENSION');
  if not assigned(i2d_X509_EXTENSION) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_EXTENSION');
  Result := i2d_X509_EXTENSION(a,out_);
end;

function Load_X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_ENTRY_new := LoadLibCryptoFunction('X509_NAME_ENTRY_new');
  if not assigned(X509_NAME_ENTRY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_new');
  Result := X509_NAME_ENTRY_new();
end;

procedure Load_X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY); cdecl;
begin
  X509_NAME_ENTRY_free := LoadLibCryptoFunction('X509_NAME_ENTRY_free');
  if not assigned(X509_NAME_ENTRY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_free');
  X509_NAME_ENTRY_free(v1);
end;

function Load_d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME_ENTRY; cdecl;
begin
  d2i_X509_NAME_ENTRY := LoadLibCryptoFunction('d2i_X509_NAME_ENTRY');
  if not assigned(d2i_X509_NAME_ENTRY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_NAME_ENTRY');
  Result := d2i_X509_NAME_ENTRY(a,in_,len);
end;

function Load_i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_NAME_ENTRY := LoadLibCryptoFunction('i2d_X509_NAME_ENTRY');
  if not assigned(i2d_X509_NAME_ENTRY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_NAME_ENTRY');
  Result := i2d_X509_NAME_ENTRY(a,out_);
end;

function Load_X509_NAME_new: PX509_NAME; cdecl;
begin
  X509_NAME_new := LoadLibCryptoFunction('X509_NAME_new');
  if not assigned(X509_NAME_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_new');
  Result := X509_NAME_new();
end;

procedure Load_X509_NAME_free(v1: PX509_NAME); cdecl;
begin
  X509_NAME_free := LoadLibCryptoFunction('X509_NAME_free');
  if not assigned(X509_NAME_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_free');
  X509_NAME_free(v1);
end;

function Load_d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_NAME; cdecl;
begin
  d2i_X509_NAME := LoadLibCryptoFunction('d2i_X509_NAME');
  if not assigned(d2i_X509_NAME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_NAME');
  Result := d2i_X509_NAME(a,in_,len);
end;

function Load_i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_NAME := LoadLibCryptoFunction('i2d_X509_NAME');
  if not assigned(i2d_X509_NAME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_NAME');
  Result := i2d_X509_NAME(a,out_);
end;

function Load_X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_set := LoadLibCryptoFunction('X509_NAME_set');
  if not assigned(X509_NAME_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_set');
  Result := X509_NAME_set(xn,name);
end;

function Load_X509_new: PX509; cdecl;
begin
  X509_new := LoadLibCryptoFunction('X509_new');
  if not assigned(X509_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_new');
  Result := X509_new();
end;

procedure Load_X509_free(v1: PX509); cdecl;
begin
  X509_free := LoadLibCryptoFunction('X509_free');
  if not assigned(X509_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_free');
  X509_free(v1);
end;

function Load_d2i_X509(a: PPX509; const in_: PPByte; len: TOpenSSL_C_LONG): PX509; cdecl;
begin
  d2i_X509 := LoadLibCryptoFunction('d2i_X509');
  if not assigned(d2i_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509');
  Result := d2i_X509(a,in_,len);
end;

function Load_i2d_X509(a: PX509; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509 := LoadLibCryptoFunction('i2d_X509');
  if not assigned(i2d_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509');
  Result := i2d_X509(a,out_);
end;

function Load_X509_set_ex_data(r: PX509; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  X509_set_ex_data := LoadLibCryptoFunction('X509_set_ex_data');
  if not assigned(X509_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_ex_data');
  Result := X509_set_ex_data(r,idx,arg);
end;

function Load_X509_get_ex_data(r: PX509; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  X509_get_ex_data := LoadLibCryptoFunction('X509_get_ex_data');
  if not assigned(X509_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ex_data');
  Result := X509_get_ex_data(r,idx);
end;

function Load_i2d_X509_AUX(a: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_AUX := LoadLibCryptoFunction('i2d_X509_AUX');
  if not assigned(i2d_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_AUX');
  Result := i2d_X509_AUX(a,pp);
end;

function Load_d2i_X509_AUX(a: PPX509; const pp: PPByte; length: TOpenSSL_C_LONG): PX509; cdecl;
begin
  d2i_X509_AUX := LoadLibCryptoFunction('d2i_X509_AUX');
  if not assigned(d2i_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_AUX');
  Result := d2i_X509_AUX(a,pp,length);
end;

function Load_i2d_re_X509_tbs(x: PX509; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_re_X509_tbs := LoadLibCryptoFunction('i2d_re_X509_tbs');
  if not assigned(i2d_re_X509_tbs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_re_X509_tbs');
  Result := i2d_re_X509_tbs(x,pp);
end;

function Load_X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  X509_SIG_INFO_get := LoadLibCryptoFunction('X509_SIG_INFO_get');
  if not assigned(X509_SIG_INFO_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_INFO_get');
  Result := X509_SIG_INFO_get(siginf,mdnid,pknid,secbits,flags);
end;

procedure Load_X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TOpenSSL_C_INT; pknid: TOpenSSL_C_INT; secbits: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT32); cdecl;
begin
  X509_SIG_INFO_set := LoadLibCryptoFunction('X509_SIG_INFO_set');
  if not assigned(X509_SIG_INFO_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_SIG_INFO_set');
  X509_SIG_INFO_set(siginf,mdnid,pknid,secbits,flags);
end;

function Load_X509_get_signature_info(x: PX509; mdnid: POpenSSL_C_INT; pknid: POpenSSL_C_INT; secbits: POpenSSL_C_INT; flags: POpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  X509_get_signature_info := LoadLibCryptoFunction('X509_get_signature_info');
  if not assigned(X509_get_signature_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_signature_info');
  Result := X509_get_signature_info(x,mdnid,pknid,secbits,flags);
end;

procedure Load_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl;
begin
  X509_get0_signature := LoadLibCryptoFunction('X509_get0_signature');
  if not assigned(X509_get0_signature) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get0_signature := @COMPAT_X509_get0_signature;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_signature');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  X509_get0_signature(sig,alg,x);
end;

function Load_X509_get_signature_nid(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_get_signature_nid := LoadLibCryptoFunction('X509_get_signature_nid');
  if not assigned(X509_get_signature_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_signature_nid');
  Result := X509_get_signature_nid(x);
end;

function Load_X509_trusted(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_trusted := LoadLibCryptoFunction('X509_trusted');
  if not assigned(X509_trusted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_trusted');
  Result := X509_trusted(x);
end;

function Load_X509_alias_set1(x: PX509; const name: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_alias_set1 := LoadLibCryptoFunction('X509_alias_set1');
  if not assigned(X509_alias_set1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_alias_set1');
  Result := X509_alias_set1(x,name,len);
end;

function Load_X509_keyid_set1(x: PX509; const id: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_keyid_set1 := LoadLibCryptoFunction('X509_keyid_set1');
  if not assigned(X509_keyid_set1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_keyid_set1');
  Result := X509_keyid_set1(x,id,len);
end;

function Load_X509_alias_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl;
begin
  X509_alias_get0 := LoadLibCryptoFunction('X509_alias_get0');
  if not assigned(X509_alias_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_alias_get0');
  Result := X509_alias_get0(x,len);
end;

function Load_X509_keyid_get0(x: PX509; len: POpenSSL_C_INT): PByte; cdecl;
begin
  X509_keyid_get0 := LoadLibCryptoFunction('X509_keyid_get0');
  if not assigned(X509_keyid_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_keyid_get0');
  Result := X509_keyid_get0(x,len);
end;

function Load_X509_TRUST_set(t: POpenSSL_C_INT; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_TRUST_set := LoadLibCryptoFunction('X509_TRUST_set');
  if not assigned(X509_TRUST_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_set');
  Result := X509_TRUST_set(t,trust);
end;

function Load_X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  X509_add1_trust_object := LoadLibCryptoFunction('X509_add1_trust_object');
  if not assigned(X509_add1_trust_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add1_trust_object');
  Result := X509_add1_trust_object(x,obj);
end;

function Load_X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  X509_add1_reject_object := LoadLibCryptoFunction('X509_add1_reject_object');
  if not assigned(X509_add1_reject_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add1_reject_object');
  Result := X509_add1_reject_object(x,obj);
end;

procedure Load_X509_trust_clear(x: PX509); cdecl;
begin
  X509_trust_clear := LoadLibCryptoFunction('X509_trust_clear');
  if not assigned(X509_trust_clear) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_trust_clear');
  X509_trust_clear(x);
end;

procedure Load_X509_reject_clear(x: PX509); cdecl;
begin
  X509_reject_clear := LoadLibCryptoFunction('X509_reject_clear');
  if not assigned(X509_reject_clear) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_reject_clear');
  X509_reject_clear(x);
end;

function Load_X509_REVOKED_new: PX509_REVOKED; cdecl;
begin
  X509_REVOKED_new := LoadLibCryptoFunction('X509_REVOKED_new');
  if not assigned(X509_REVOKED_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_new');
  Result := X509_REVOKED_new();
end;

procedure Load_X509_REVOKED_free(v1: PX509_REVOKED); cdecl;
begin
  X509_REVOKED_free := LoadLibCryptoFunction('X509_REVOKED_free');
  if not assigned(X509_REVOKED_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_free');
  X509_REVOKED_free(v1);
end;

function Load_d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_REVOKED; cdecl;
begin
  d2i_X509_REVOKED := LoadLibCryptoFunction('d2i_X509_REVOKED');
  if not assigned(d2i_X509_REVOKED) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_REVOKED');
  Result := d2i_X509_REVOKED(a,in_,len);
end;

function Load_i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_REVOKED := LoadLibCryptoFunction('i2d_X509_REVOKED');
  if not assigned(i2d_X509_REVOKED) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_REVOKED');
  Result := i2d_X509_REVOKED(a,out_);
end;

function Load_X509_CRL_INFO_new: PX509_CRL_INFO; cdecl;
begin
  X509_CRL_INFO_new := LoadLibCryptoFunction('X509_CRL_INFO_new');
  if not assigned(X509_CRL_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_INFO_new');
  Result := X509_CRL_INFO_new();
end;

procedure Load_X509_CRL_INFO_free(v1: PX509_CRL_INFO); cdecl;
begin
  X509_CRL_INFO_free := LoadLibCryptoFunction('X509_CRL_INFO_free');
  if not assigned(X509_CRL_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_INFO_free');
  X509_CRL_INFO_free(v1);
end;

function Load_d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL_INFO; cdecl;
begin
  d2i_X509_CRL_INFO := LoadLibCryptoFunction('d2i_X509_CRL_INFO');
  if not assigned(d2i_X509_CRL_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_CRL_INFO');
  Result := d2i_X509_CRL_INFO(a,in_,len);
end;

function Load_i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_CRL_INFO := LoadLibCryptoFunction('i2d_X509_CRL_INFO');
  if not assigned(i2d_X509_CRL_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_CRL_INFO');
  Result := i2d_X509_CRL_INFO(a,out_);
end;

function Load_X509_CRL_new: PX509_CRL; cdecl;
begin
  X509_CRL_new := LoadLibCryptoFunction('X509_CRL_new');
  if not assigned(X509_CRL_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_new');
  Result := X509_CRL_new();
end;

procedure Load_X509_CRL_free(v1: PX509_CRL); cdecl;
begin
  X509_CRL_free := LoadLibCryptoFunction('X509_CRL_free');
  if not assigned(X509_CRL_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_free');
  X509_CRL_free(v1);
end;

function Load_d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TOpenSSL_C_LONG): PX509_CRL; cdecl;
begin
  d2i_X509_CRL := LoadLibCryptoFunction('d2i_X509_CRL');
  if not assigned(d2i_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_X509_CRL');
  Result := d2i_X509_CRL(a,in_,len);
end;

function Load_i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_X509_CRL := LoadLibCryptoFunction('i2d_X509_CRL');
  if not assigned(i2d_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_X509_CRL');
  Result := i2d_X509_CRL(a,out_);
end;

function Load_X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_add0_revoked := LoadLibCryptoFunction('X509_CRL_add0_revoked');
  if not assigned(X509_CRL_add0_revoked) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_add0_revoked');
  Result := X509_CRL_add0_revoked(crl,rev);
end;

function Load_X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get0_by_serial := LoadLibCryptoFunction('X509_CRL_get0_by_serial');
  if not assigned(X509_CRL_get0_by_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_by_serial');
  Result := X509_CRL_get0_by_serial(crl,ret,serial);
end;

function Load_X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get0_by_cert := LoadLibCryptoFunction('X509_CRL_get0_by_cert');
  if not assigned(X509_CRL_get0_by_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_by_cert');
  Result := X509_CRL_get0_by_cert(crl,ret,x);
end;

function Load_X509_PKEY_new: PX509_PKEY; cdecl;
begin
  X509_PKEY_new := LoadLibCryptoFunction('X509_PKEY_new');
  if not assigned(X509_PKEY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PKEY_new');
  Result := X509_PKEY_new();
end;

procedure Load_X509_PKEY_free(a: PX509_PKEY); cdecl;
begin
  X509_PKEY_free := LoadLibCryptoFunction('X509_PKEY_free');
  if not assigned(X509_PKEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PKEY_free');
  X509_PKEY_free(a);
end;

function Load_X509_INFO_new: PX509_INFO; cdecl;
begin
  X509_INFO_new := LoadLibCryptoFunction('X509_INFO_new');
  if not assigned(X509_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_INFO_new');
  Result := X509_INFO_new();
end;

procedure Load_X509_INFO_free(a: PX509_INFO); cdecl;
begin
  X509_INFO_free := LoadLibCryptoFunction('X509_INFO_free');
  if not assigned(X509_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_INFO_free');
  X509_INFO_free(a);
end;

function Load_X509_NAME_oneline(const a: PX509_NAME; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  X509_NAME_oneline := LoadLibCryptoFunction('X509_NAME_oneline');
  if not assigned(X509_NAME_oneline) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_oneline');
  Result := X509_NAME_oneline(a,buf,size);
end;

function Load_ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_digest := LoadLibCryptoFunction('ASN1_item_digest');
  if not assigned(ASN1_item_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_digest');
  Result := ASN1_item_digest(it,type_,data,md,len);
end;

function Load_ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_verify := LoadLibCryptoFunction('ASN1_item_verify');
  if not assigned(ASN1_item_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_verify');
  Result := ASN1_item_verify(it,algor1,signature,data,pkey);
end;

function Load_ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_sign := LoadLibCryptoFunction('ASN1_item_sign');
  if not assigned(ASN1_item_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_sign');
  Result := ASN1_item_sign(it,algor1,algor2,signature,data,pkey,type_);
end;

function Load_ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_sign_ctx := LoadLibCryptoFunction('ASN1_item_sign_ctx');
  if not assigned(ASN1_item_sign_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_sign_ctx');
  Result := ASN1_item_sign_ctx(it,algor1,algor2,signature,asn,ctx);
end;

function Load_X509_get_version(const x: PX509): TOpenSSL_C_LONG; cdecl;
begin
  X509_get_version := LoadLibCryptoFunction('X509_get_version');
  if not assigned(X509_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_version');
  Result := X509_get_version(x);
end;

function Load_X509_set_version(x: PX509; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  X509_set_version := LoadLibCryptoFunction('X509_set_version');
  if not assigned(X509_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_version');
  Result := X509_set_version(x,version);
end;

function Load_X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  X509_set_serialNumber := LoadLibCryptoFunction('X509_set_serialNumber');
  if not assigned(X509_set_serialNumber) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_serialNumber');
  Result := X509_set_serialNumber(x,serial);
end;

function Load_X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl;
begin
  X509_get_serialNumber := LoadLibCryptoFunction('X509_get_serialNumber');
  if not assigned(X509_get_serialNumber) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_serialNumber');
  Result := X509_get_serialNumber(x);
end;

function Load_X509_get0_serialNumber(const x: PX509): PASN1_INTEGER; cdecl;
begin
  X509_get0_serialNumber := LoadLibCryptoFunction('X509_get0_serialNumber');
  if not assigned(X509_get0_serialNumber) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_serialNumber');
  Result := X509_get0_serialNumber(x);
end;

function Load_X509_set_issuer_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_set_issuer_name := LoadLibCryptoFunction('X509_set_issuer_name');
  if not assigned(X509_set_issuer_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_issuer_name');
  Result := X509_set_issuer_name(x,name);
end;

function Load_X509_get_issuer_name(const a: PX509): PX509_NAME; cdecl;
begin
  X509_get_issuer_name := LoadLibCryptoFunction('X509_get_issuer_name');
  if not assigned(X509_get_issuer_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_issuer_name');
  Result := X509_get_issuer_name(a);
end;

function Load_X509_set_subject_name(x: PX509; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_set_subject_name := LoadLibCryptoFunction('X509_set_subject_name');
  if not assigned(X509_set_subject_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_subject_name');
  Result := X509_set_subject_name(x,name);
end;

function Load_X509_get_subject_name(const a: PX509): PX509_NAME; cdecl;
begin
  X509_get_subject_name := LoadLibCryptoFunction('X509_get_subject_name');
  if not assigned(X509_get_subject_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_subject_name');
  Result := X509_get_subject_name(a);
end;

function Load_X509_get0_notBefore(const x: PX509): PASN1_TIME; cdecl;
begin
  X509_get0_notBefore := LoadLibCryptoFunction('X509_get0_notBefore');
  if not assigned(X509_get0_notBefore) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get0_notBefore := @COMPAT_X509_get0_notBefore;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_notBefore');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := X509_get0_notBefore(x);
end;

function Load_X509_getm_notBefore(const x: PX509): PASN1_TIME; cdecl;
begin
  X509_getm_notBefore := LoadLibCryptoFunction('X509_getm_notBefore');
  if not assigned(X509_getm_notBefore) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_getm_notBefore');
  Result := X509_getm_notBefore(x);
end;

function Load_X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  X509_set1_notBefore := LoadLibCryptoFunction('X509_set1_notBefore');
  if not assigned(X509_set1_notBefore) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set1_notBefore');
  Result := X509_set1_notBefore(x,tm);
end;

function Load_X509_get0_notAfter(const x: PX509): PASN1_TIME; cdecl;
begin
  X509_get0_notAfter := LoadLibCryptoFunction('X509_get0_notAfter');
  if not assigned(X509_get0_notAfter) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get0_notAfter := @COMPAT_X509_get0_notAfter;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_notAfter');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := X509_get0_notAfter(x);
end;

function Load_X509_getm_notAfter(const x: PX509): PASN1_TIME; cdecl;
begin
  X509_getm_notAfter := LoadLibCryptoFunction('X509_getm_notAfter');
  if not assigned(X509_getm_notAfter) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_getm_notAfter');
  Result := X509_getm_notAfter(x);
end;

function Load_X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  X509_set1_notAfter := LoadLibCryptoFunction('X509_set1_notAfter');
  if not assigned(X509_set1_notAfter) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set1_notAfter');
  Result := X509_set1_notAfter(x,tm);
end;

function Load_X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_set_pubkey := LoadLibCryptoFunction('X509_set_pubkey');
  if not assigned(X509_set_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_set_pubkey');
  Result := X509_set_pubkey(x,pkey);
end;

function Load_X509_up_ref(x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_up_ref := LoadLibCryptoFunction('X509_up_ref');
  if not assigned(X509_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_up_ref');
  Result := X509_up_ref(x);
end;

function Load_X509_get_signature_type(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_get_signature_type := LoadLibCryptoFunction('X509_get_signature_type');
  if not assigned(X509_get_signature_type) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    X509_get_signature_type := @COMPAT_X509_get_signature_type;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_signature_type');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := X509_get_signature_type(x);
end;

function Load_X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY; cdecl;
begin
  X509_get_X509_PUBKEY := LoadLibCryptoFunction('X509_get_X509_PUBKEY');
  if not assigned(X509_get_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_X509_PUBKEY');
  Result := X509_get_X509_PUBKEY(x);
end;

procedure Load_X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl;
begin
  X509_get0_uids := LoadLibCryptoFunction('X509_get0_uids');
  if not assigned(X509_get0_uids) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_uids');
  X509_get0_uids(x,piuid,psuid);
end;

function Load_X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR; cdecl;
begin
  X509_get0_tbs_sigalg := LoadLibCryptoFunction('X509_get0_tbs_sigalg');
  if not assigned(X509_get0_tbs_sigalg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_tbs_sigalg');
  Result := X509_get0_tbs_sigalg(x);
end;

function Load_X509_get0_pubkey(const x: PX509): PEVP_PKEY; cdecl;
begin
  X509_get0_pubkey := LoadLibCryptoFunction('X509_get0_pubkey');
  if not assigned(X509_get0_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_pubkey');
  Result := X509_get0_pubkey(x);
end;

function Load_X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl;
begin
  X509_get_pubkey := LoadLibCryptoFunction('X509_get_pubkey');
  if not assigned(X509_get_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_pubkey');
  Result := X509_get_pubkey(x);
end;

function Load_X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING; cdecl;
begin
  X509_get0_pubkey_bitstr := LoadLibCryptoFunction('X509_get0_pubkey_bitstr');
  if not assigned(X509_get0_pubkey_bitstr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get0_pubkey_bitstr');
  Result := X509_get0_pubkey_bitstr(x);
end;

function Load_X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_certificate_type := LoadLibCryptoFunction('X509_certificate_type');
  if not assigned(X509_certificate_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_certificate_type');
  Result := X509_certificate_type(x,pubkey);
end;

function Load_X509_REQ_get_version(const req: PX509_REQ): TOpenSSL_C_LONG; cdecl;
begin
  X509_REQ_get_version := LoadLibCryptoFunction('X509_REQ_get_version');
  if not assigned(X509_REQ_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_version');
  Result := X509_REQ_get_version(req);
end;

function Load_X509_REQ_set_version(x: PX509_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_set_version := LoadLibCryptoFunction('X509_REQ_set_version');
  if not assigned(X509_REQ_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_version');
  Result := X509_REQ_set_version(x,version);
end;

function Load_X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME; cdecl;
begin
  X509_REQ_get_subject_name := LoadLibCryptoFunction('X509_REQ_get_subject_name');
  if not assigned(X509_REQ_get_subject_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_subject_name');
  Result := X509_REQ_get_subject_name(req);
end;

function Load_X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_set_subject_name := LoadLibCryptoFunction('X509_REQ_set_subject_name');
  if not assigned(X509_REQ_set_subject_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_subject_name');
  Result := X509_REQ_set_subject_name(req,name);
end;

procedure Load_X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl;
begin
  X509_REQ_get0_signature := LoadLibCryptoFunction('X509_REQ_get0_signature');
  if not assigned(X509_REQ_get0_signature) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get0_signature');
  X509_REQ_get0_signature(req,psig,palg);
end;

function Load_X509_REQ_get_signature_nid(const req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_get_signature_nid := LoadLibCryptoFunction('X509_REQ_get_signature_nid');
  if not assigned(X509_REQ_get_signature_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_signature_nid');
  Result := X509_REQ_get_signature_nid(req);
end;

function Load_i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_re_X509_REQ_tbs := LoadLibCryptoFunction('i2d_re_X509_REQ_tbs');
  if not assigned(i2d_re_X509_REQ_tbs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_re_X509_REQ_tbs');
  Result := i2d_re_X509_REQ_tbs(req,pp);
end;

function Load_X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_set_pubkey := LoadLibCryptoFunction('X509_REQ_set_pubkey');
  if not assigned(X509_REQ_set_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_pubkey');
  Result := X509_REQ_set_pubkey(x,pkey);
end;

function Load_X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
begin
  X509_REQ_get_pubkey := LoadLibCryptoFunction('X509_REQ_get_pubkey');
  if not assigned(X509_REQ_get_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_pubkey');
  Result := X509_REQ_get_pubkey(req);
end;

function Load_X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
begin
  X509_REQ_get0_pubkey := LoadLibCryptoFunction('X509_REQ_get0_pubkey');
  if not assigned(X509_REQ_get0_pubkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get0_pubkey');
  Result := X509_REQ_get0_pubkey(req);
end;

function Load_X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl;
begin
  X509_REQ_get_X509_PUBKEY := LoadLibCryptoFunction('X509_REQ_get_X509_PUBKEY');
  if not assigned(X509_REQ_get_X509_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_X509_PUBKEY');
  Result := X509_REQ_get_X509_PUBKEY(req);
end;

function Load_X509_REQ_extension_nid(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_extension_nid := LoadLibCryptoFunction('X509_REQ_extension_nid');
  if not assigned(X509_REQ_extension_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_extension_nid');
  Result := X509_REQ_extension_nid(nid);
end;

function Load_X509_REQ_get_extension_nids: POpenSSL_C_INT; cdecl;
begin
  X509_REQ_get_extension_nids := LoadLibCryptoFunction('X509_REQ_get_extension_nids');
  if not assigned(X509_REQ_get_extension_nids) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_extension_nids');
  Result := X509_REQ_get_extension_nids();
end;

procedure Load_X509_REQ_set_extension_nids(nids: POpenSSL_C_INT); cdecl;
begin
  X509_REQ_set_extension_nids := LoadLibCryptoFunction('X509_REQ_set_extension_nids');
  if not assigned(X509_REQ_set_extension_nids) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_set_extension_nids');
  X509_REQ_set_extension_nids(nids);
end;

function Load_X509_REQ_get_attr_count(const req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_get_attr_count := LoadLibCryptoFunction('X509_REQ_get_attr_count');
  if not assigned(X509_REQ_get_attr_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr_count');
  Result := X509_REQ_get_attr_count(req);
end;

function Load_X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_get_attr_by_NID := LoadLibCryptoFunction('X509_REQ_get_attr_by_NID');
  if not assigned(X509_REQ_get_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr_by_NID');
  Result := X509_REQ_get_attr_by_NID(req,nid,lastpos);
end;

function Load_X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_get_attr_by_OBJ := LoadLibCryptoFunction('X509_REQ_get_attr_by_OBJ');
  if not assigned(X509_REQ_get_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr_by_OBJ');
  Result := X509_REQ_get_attr_by_OBJ(req,obj,lastpos);
end;

function Load_X509_REQ_get_attr(const req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  X509_REQ_get_attr := LoadLibCryptoFunction('X509_REQ_get_attr');
  if not assigned(X509_REQ_get_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_get_attr');
  Result := X509_REQ_get_attr(req,loc);
end;

function Load_X509_REQ_delete_attr(req: PX509_REQ; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  X509_REQ_delete_attr := LoadLibCryptoFunction('X509_REQ_delete_attr');
  if not assigned(X509_REQ_delete_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_delete_attr');
  Result := X509_REQ_delete_attr(req,loc);
end;

function Load_X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_add1_attr := LoadLibCryptoFunction('X509_REQ_add1_attr');
  if not assigned(X509_REQ_add1_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr');
  Result := X509_REQ_add1_attr(req,attr);
end;

function Load_X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_add1_attr_by_OBJ := LoadLibCryptoFunction('X509_REQ_add1_attr_by_OBJ');
  if not assigned(X509_REQ_add1_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr_by_OBJ');
  Result := X509_REQ_add1_attr_by_OBJ(req,obj,type_,bytes,len);
end;

function Load_X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_add1_attr_by_NID := LoadLibCryptoFunction('X509_REQ_add1_attr_by_NID');
  if not assigned(X509_REQ_add1_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr_by_NID');
  Result := X509_REQ_add1_attr_by_NID(req,nid,type_,bytes,len);
end;

function Load_X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_add1_attr_by_txt := LoadLibCryptoFunction('X509_REQ_add1_attr_by_txt');
  if not assigned(X509_REQ_add1_attr_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_add1_attr_by_txt');
  Result := X509_REQ_add1_attr_by_txt(req,attrname,type_,bytes,len);
end;

function Load_X509_CRL_set_version(x: PX509_CRL; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_set_version := LoadLibCryptoFunction('X509_CRL_set_version');
  if not assigned(X509_CRL_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_version');
  Result := X509_CRL_set_version(x,version);
end;

function Load_X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_set_issuer_name := LoadLibCryptoFunction('X509_CRL_set_issuer_name');
  if not assigned(X509_CRL_set_issuer_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set_issuer_name');
  Result := X509_CRL_set_issuer_name(x,name);
end;

function Load_X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_set1_lastUpdate := LoadLibCryptoFunction('X509_CRL_set1_lastUpdate');
  if not assigned(X509_CRL_set1_lastUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set1_lastUpdate');
  Result := X509_CRL_set1_lastUpdate(x,tm);
end;

function Load_X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_set1_nextUpdate := LoadLibCryptoFunction('X509_CRL_set1_nextUpdate');
  if not assigned(X509_CRL_set1_nextUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_set1_nextUpdate');
  Result := X509_CRL_set1_nextUpdate(x,tm);
end;

function Load_X509_CRL_sort(crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_sort := LoadLibCryptoFunction('X509_CRL_sort');
  if not assigned(X509_CRL_sort) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_sort');
  Result := X509_CRL_sort(crl);
end;

function Load_X509_CRL_up_ref(crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_up_ref := LoadLibCryptoFunction('X509_CRL_up_ref');
  if not assigned(X509_CRL_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_up_ref');
  Result := X509_CRL_up_ref(crl);
end;

function Load_X509_CRL_get_version(const crl: PX509_CRL): TOpenSSL_C_LONG; cdecl;
begin
  X509_CRL_get_version := LoadLibCryptoFunction('X509_CRL_get_version');
  if not assigned(X509_CRL_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_version');
  Result := X509_CRL_get_version(crl);
end;

function Load_X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl;
begin
  X509_CRL_get0_lastUpdate := LoadLibCryptoFunction('X509_CRL_get0_lastUpdate');
  if not assigned(X509_CRL_get0_lastUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_lastUpdate');
  Result := X509_CRL_get0_lastUpdate(crl);
end;

function Load_X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME; cdecl;
begin
  X509_CRL_get0_nextUpdate := LoadLibCryptoFunction('X509_CRL_get0_nextUpdate');
  if not assigned(X509_CRL_get0_nextUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_nextUpdate');
  Result := X509_CRL_get0_nextUpdate(crl);
end;

function Load_X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME; cdecl;
begin
  X509_CRL_get_issuer := LoadLibCryptoFunction('X509_CRL_get_issuer');
  if not assigned(X509_CRL_get_issuer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_issuer');
  Result := X509_CRL_get_issuer(crl);
end;

procedure Load_X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl;
begin
  X509_CRL_get0_signature := LoadLibCryptoFunction('X509_CRL_get0_signature');
  if not assigned(X509_CRL_get0_signature) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get0_signature');
  X509_CRL_get0_signature(crl,psig,palg);
end;

function Load_X509_CRL_get_signature_nid(const crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get_signature_nid := LoadLibCryptoFunction('X509_CRL_get_signature_nid');
  if not assigned(X509_CRL_get_signature_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_signature_nid');
  Result := X509_CRL_get_signature_nid(crl);
end;

function Load_i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_re_X509_CRL_tbs := LoadLibCryptoFunction('i2d_re_X509_CRL_tbs');
  if not assigned(i2d_re_X509_CRL_tbs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_re_X509_CRL_tbs');
  Result := i2d_re_X509_CRL_tbs(req,pp);
end;

function Load_X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER; cdecl;
begin
  X509_REVOKED_get0_serialNumber := LoadLibCryptoFunction('X509_REVOKED_get0_serialNumber');
  if not assigned(X509_REVOKED_get0_serialNumber) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get0_serialNumber');
  Result := X509_REVOKED_get0_serialNumber(x);
end;

function Load_X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_set_serialNumber := LoadLibCryptoFunction('X509_REVOKED_set_serialNumber');
  if not assigned(X509_REVOKED_set_serialNumber) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_set_serialNumber');
  Result := X509_REVOKED_set_serialNumber(x,serial);
end;

function Load_X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME; cdecl;
begin
  X509_REVOKED_get0_revocationDate := LoadLibCryptoFunction('X509_REVOKED_get0_revocationDate');
  if not assigned(X509_REVOKED_get0_revocationDate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get0_revocationDate');
  Result := X509_REVOKED_get0_revocationDate(x);
end;

function Load_X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_set_revocationDate := LoadLibCryptoFunction('X509_REVOKED_set_revocationDate');
  if not assigned(X509_REVOKED_set_revocationDate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_set_revocationDate');
  Result := X509_REVOKED_set_revocationDate(r,tm);
end;

function Load_X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PX509_CRL; cdecl;
begin
  X509_CRL_diff := LoadLibCryptoFunction('X509_CRL_diff');
  if not assigned(X509_CRL_diff) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_diff');
  Result := X509_CRL_diff(base,newer,skey,md,flags);
end;

function Load_X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_check_private_key := LoadLibCryptoFunction('X509_REQ_check_private_key');
  if not assigned(X509_REQ_check_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_check_private_key');
  Result := X509_REQ_check_private_key(x509,pkey);
end;

function Load_X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_check_private_key := LoadLibCryptoFunction('X509_check_private_key');
  if not assigned(X509_check_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_private_key');
  Result := X509_check_private_key(x509,pkey);
end;

function Load_X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_check_suiteb := LoadLibCryptoFunction('X509_CRL_check_suiteb');
  if not assigned(X509_CRL_check_suiteb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_check_suiteb');
  Result := X509_CRL_check_suiteb(crl,pk,flags);
end;

function Load_X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_issuer_and_serial_cmp := LoadLibCryptoFunction('X509_issuer_and_serial_cmp');
  if not assigned(X509_issuer_and_serial_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_and_serial_cmp');
  Result := X509_issuer_and_serial_cmp(a,b);
end;

function Load_X509_issuer_and_serial_hash(a: PX509): TOpenSSL_C_ULONG; cdecl;
begin
  X509_issuer_and_serial_hash := LoadLibCryptoFunction('X509_issuer_and_serial_hash');
  if not assigned(X509_issuer_and_serial_hash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_and_serial_hash');
  Result := X509_issuer_and_serial_hash(a);
end;

function Load_X509_issuer_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_issuer_name_cmp := LoadLibCryptoFunction('X509_issuer_name_cmp');
  if not assigned(X509_issuer_name_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_name_cmp');
  Result := X509_issuer_name_cmp(a,b);
end;

function Load_X509_issuer_name_hash(a: PX509): TOpenSSL_C_uLONG; cdecl;
begin
  X509_issuer_name_hash := LoadLibCryptoFunction('X509_issuer_name_hash');
  if not assigned(X509_issuer_name_hash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_issuer_name_hash');
  Result := X509_issuer_name_hash(a);
end;

function Load_X509_subject_name_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_subject_name_cmp := LoadLibCryptoFunction('X509_subject_name_cmp');
  if not assigned(X509_subject_name_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_subject_name_cmp');
  Result := X509_subject_name_cmp(a,b);
end;

function Load_X509_subject_name_hash(x: PX509): TOpenSSL_C_ULONG; cdecl;
begin
  X509_subject_name_hash := LoadLibCryptoFunction('X509_subject_name_hash');
  if not assigned(X509_subject_name_hash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_subject_name_hash');
  Result := X509_subject_name_hash(x);
end;

function Load_X509_cmp(const a: PX509; const b: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_cmp := LoadLibCryptoFunction('X509_cmp');
  if not assigned(X509_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_cmp');
  Result := X509_cmp(a,b);
end;

function Load_X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_cmp := LoadLibCryptoFunction('X509_NAME_cmp');
  if not assigned(X509_NAME_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_cmp');
  Result := X509_NAME_cmp(a,b);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_X509_NAME_hash(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;
begin
  X509_NAME_hash := LoadLibCryptoFunction('X509_NAME_hash');
  if not assigned(X509_NAME_hash) then
    X509_NAME_hash := @COMPAT_X509_NAME_hash;
  Result := X509_NAME_hash(x);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_X509_NAME_hash_old(x: PX509_NAME): TOpenSSL_C_ULONG; cdecl;
begin
  X509_NAME_hash_old := LoadLibCryptoFunction('X509_NAME_hash_old');
  if not assigned(X509_NAME_hash_old) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_hash_old');
  Result := X509_NAME_hash_old(x);
end;

function Load_X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_cmp := LoadLibCryptoFunction('X509_CRL_cmp');
  if not assigned(X509_CRL_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_cmp');
  Result := X509_CRL_cmp(a,b);
end;

function Load_X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_match := LoadLibCryptoFunction('X509_CRL_match');
  if not assigned(X509_CRL_match) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_match');
  Result := X509_CRL_match(a,b);
end;

function Load_X509_aux_print(out_: PBIO; x: PX509; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_aux_print := LoadLibCryptoFunction('X509_aux_print');
  if not assigned(X509_aux_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_aux_print');
  Result := X509_aux_print(out_,x,indent);
end;

function Load_X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_print := LoadLibCryptoFunction('X509_NAME_print');
  if not assigned(X509_NAME_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_print');
  Result := X509_NAME_print(bp,name,obase);
end;

function Load_X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_print_ex := LoadLibCryptoFunction('X509_NAME_print_ex');
  if not assigned(X509_NAME_print_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_print_ex');
  Result := X509_NAME_print_ex(out_,nm,indent,flags);
end;

function Load_X509_print_ex(bp: PBIO; x: PX509; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_print_ex := LoadLibCryptoFunction('X509_print_ex');
  if not assigned(X509_print_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_print_ex');
  Result := X509_print_ex(bp,x,nmflag,cflag);
end;

function Load_X509_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_print := LoadLibCryptoFunction('X509_print');
  if not assigned(X509_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_print');
  Result := X509_print(bp,x);
end;

function Load_X509_ocspid_print(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_ocspid_print := LoadLibCryptoFunction('X509_ocspid_print');
  if not assigned(X509_ocspid_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ocspid_print');
  Result := X509_ocspid_print(bp,x);
end;

function Load_X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_print_ex := LoadLibCryptoFunction('X509_CRL_print_ex');
  if not assigned(X509_CRL_print_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_print_ex');
  Result := X509_CRL_print_ex(out_,x,nmflag);
end;

function Load_X509_CRL_print(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_print := LoadLibCryptoFunction('X509_CRL_print');
  if not assigned(X509_CRL_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_print');
  Result := X509_CRL_print(bp,x);
end;

function Load_X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TOpenSSL_C_ULONG; cflag: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_print_ex := LoadLibCryptoFunction('X509_REQ_print_ex');
  if not assigned(X509_REQ_print_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_print_ex');
  Result := X509_REQ_print_ex(bp,x,nmflag,cflag);
end;

function Load_X509_REQ_print(bp: PBIO; req: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  X509_REQ_print := LoadLibCryptoFunction('X509_REQ_print');
  if not assigned(X509_REQ_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REQ_print');
  Result := X509_REQ_print(bp,req);
end;

function Load_X509_NAME_entry_count(const name: PX509_NAME): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_entry_count := LoadLibCryptoFunction('X509_NAME_entry_count');
  if not assigned(X509_NAME_entry_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_entry_count');
  Result := X509_NAME_entry_count(name);
end;

function Load_X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_get_text_by_NID := LoadLibCryptoFunction('X509_NAME_get_text_by_NID');
  if not assigned(X509_NAME_get_text_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_text_by_NID');
  Result := X509_NAME_get_text_by_NID(name,nid,buf,len);
end;

function Load_X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_get_text_by_OBJ := LoadLibCryptoFunction('X509_NAME_get_text_by_OBJ');
  if not assigned(X509_NAME_get_text_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_text_by_OBJ');
  Result := X509_NAME_get_text_by_OBJ(name,obj,buf,len);
end;

function Load_X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_get_index_by_NID := LoadLibCryptoFunction('X509_NAME_get_index_by_NID');
  if not assigned(X509_NAME_get_index_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_index_by_NID');
  Result := X509_NAME_get_index_by_NID(name,nid,lastpos);
end;

function Load_X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_get_index_by_OBJ := LoadLibCryptoFunction('X509_NAME_get_index_by_OBJ');
  if not assigned(X509_NAME_get_index_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_index_by_OBJ');
  Result := X509_NAME_get_index_by_OBJ(name,obj,lastpos);
end;

function Load_X509_NAME_get_entry(const name: PX509_NAME; loc: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_get_entry := LoadLibCryptoFunction('X509_NAME_get_entry');
  if not assigned(X509_NAME_get_entry) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get_entry');
  Result := X509_NAME_get_entry(name,loc);
end;

function Load_X509_NAME_delete_entry(name: PX509_NAME; loc: TOpenSSL_C_INT): pX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_delete_entry := LoadLibCryptoFunction('X509_NAME_delete_entry');
  if not assigned(X509_NAME_delete_entry) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_delete_entry');
  Result := X509_NAME_delete_entry(name,loc);
end;

function Load_X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_add_entry := LoadLibCryptoFunction('X509_NAME_add_entry');
  if not assigned(X509_NAME_add_entry) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry');
  Result := X509_NAME_add_entry(name,ne,loc,set_);
end;

function Load_X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_add_entry_by_OBJ := LoadLibCryptoFunction('X509_NAME_add_entry_by_OBJ');
  if not assigned(X509_NAME_add_entry_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry_by_OBJ');
  Result := X509_NAME_add_entry_by_OBJ(name,obj,type_,bytes,len,loc,set_);
end;

function Load_X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_add_entry_by_NID := LoadLibCryptoFunction('X509_NAME_add_entry_by_NID');
  if not assigned(X509_NAME_add_entry_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry_by_NID');
  Result := X509_NAME_add_entry_by_NID(name,nid,type_,bytes,len,loc,set_);
end;

function Load_X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_ENTRY_create_by_txt := LoadLibCryptoFunction('X509_NAME_ENTRY_create_by_txt');
  if not assigned(X509_NAME_ENTRY_create_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_create_by_txt');
  Result := X509_NAME_ENTRY_create_by_txt(ne,field,type_,bytes,len);
end;

function Load_X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_ENTRY_create_by_NID := LoadLibCryptoFunction('X509_NAME_ENTRY_create_by_NID');
  if not assigned(X509_NAME_ENTRY_create_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_create_by_NID');
  Result := X509_NAME_ENTRY_create_by_NID(ne,nid,type_,bytes,len);
end;

function Load_X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT; loc: TOpenSSL_C_INT; set_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_add_entry_by_txt := LoadLibCryptoFunction('X509_NAME_add_entry_by_txt');
  if not assigned(X509_NAME_add_entry_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_add_entry_by_txt');
  Result := X509_NAME_add_entry_by_txt(name,field,type_,bytes,len,loc,set_);
end;

function Load_X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_NAME_ENTRY; cdecl;
begin
  X509_NAME_ENTRY_create_by_OBJ := LoadLibCryptoFunction('X509_NAME_ENTRY_create_by_OBJ');
  if not assigned(X509_NAME_ENTRY_create_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_create_by_OBJ');
  Result := X509_NAME_ENTRY_create_by_OBJ(ne,obj,type_,bytes,len);
end;

function Load_X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_ENTRY_set_object := LoadLibCryptoFunction('X509_NAME_ENTRY_set_object');
  if not assigned(X509_NAME_ENTRY_set_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_set_object');
  Result := X509_NAME_ENTRY_set_object(ne,obj);
end;

function Load_X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_ENTRY_set_data := LoadLibCryptoFunction('X509_NAME_ENTRY_set_data');
  if not assigned(X509_NAME_ENTRY_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_set_data');
  Result := X509_NAME_ENTRY_set_data(ne,type_,bytes,len);
end;

function Load_X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl;
begin
  X509_NAME_ENTRY_get_object := LoadLibCryptoFunction('X509_NAME_ENTRY_get_object');
  if not assigned(X509_NAME_ENTRY_get_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_get_object');
  Result := X509_NAME_ENTRY_get_object(ne);
end;

function Load_X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl;
begin
  X509_NAME_ENTRY_get_data := LoadLibCryptoFunction('X509_NAME_ENTRY_get_data');
  if not assigned(X509_NAME_ENTRY_get_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_get_data');
  Result := X509_NAME_ENTRY_get_data(ne);
end;

function Load_X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_ENTRY_set := LoadLibCryptoFunction('X509_NAME_ENTRY_set');
  if not assigned(X509_NAME_ENTRY_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_ENTRY_set');
  Result := X509_NAME_ENTRY_set(ne);
end;

function Load_X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  X509_NAME_get0_der := LoadLibCryptoFunction('X509_NAME_get0_der');
  if not assigned(X509_NAME_get0_der) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_get0_der');
  Result := X509_NAME_get0_der(nm,pder,pderlen);
end;

function Load_X509_get_ext_count(const x: PX509): TOpenSSL_C_INT; cdecl;
begin
  X509_get_ext_count := LoadLibCryptoFunction('X509_get_ext_count');
  if not assigned(X509_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_count');
  Result := X509_get_ext_count(x);
end;

function Load_X509_get_ext_by_NID(const x: PX509; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_get_ext_by_NID := LoadLibCryptoFunction('X509_get_ext_by_NID');
  if not assigned(X509_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_by_NID');
  Result := X509_get_ext_by_NID(x,nid,lastpos);
end;

function Load_X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_get_ext_by_OBJ := LoadLibCryptoFunction('X509_get_ext_by_OBJ');
  if not assigned(X509_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_by_OBJ');
  Result := X509_get_ext_by_OBJ(x,obj,lastpos);
end;

function Load_X509_get_ext_by_critical(const x: PX509; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_get_ext_by_critical := LoadLibCryptoFunction('X509_get_ext_by_critical');
  if not assigned(X509_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_by_critical');
  Result := X509_get_ext_by_critical(x,crit,lastpos);
end;

function Load_X509_get_ext(const x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  X509_get_ext := LoadLibCryptoFunction('X509_get_ext');
  if not assigned(X509_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext');
  Result := X509_get_ext(x,loc);
end;

function Load_X509_delete_ext(x: PX509; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  X509_delete_ext := LoadLibCryptoFunction('X509_delete_ext');
  if not assigned(X509_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_delete_ext');
  Result := X509_delete_ext(x,loc);
end;

function Load_X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_add_ext := LoadLibCryptoFunction('X509_add_ext');
  if not assigned(X509_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add_ext');
  Result := X509_add_ext(x,ex,loc);
end;

function Load_X509_get_ext_d2i(const x: PX509; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  X509_get_ext_d2i := LoadLibCryptoFunction('X509_get_ext_d2i');
  if not assigned(X509_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_get_ext_d2i');
  Result := X509_get_ext_d2i(x,nid,crit,idx);
end;

function Load_X509_add1_ext_i2d(x: PX509; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_add1_ext_i2d := LoadLibCryptoFunction('X509_add1_ext_i2d');
  if not assigned(X509_add1_ext_i2d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_add1_ext_i2d');
  Result := X509_add1_ext_i2d(x,nid,value,crit,flags);
end;

function Load_X509_CRL_get_ext_count(const x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get_ext_count := LoadLibCryptoFunction('X509_CRL_get_ext_count');
  if not assigned(X509_CRL_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_count');
  Result := X509_CRL_get_ext_count(x);
end;

function Load_X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get_ext_by_NID := LoadLibCryptoFunction('X509_CRL_get_ext_by_NID');
  if not assigned(X509_CRL_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_by_NID');
  Result := X509_CRL_get_ext_by_NID(x,nid,lastpos);
end;

function Load_X509_CRL_get_ext_by_OBJ(const x: X509_CRL; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get_ext_by_OBJ := LoadLibCryptoFunction('X509_CRL_get_ext_by_OBJ');
  if not assigned(X509_CRL_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_by_OBJ');
  Result := X509_CRL_get_ext_by_OBJ(x,obj,lastpos);
end;

function Load_X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_get_ext_by_critical := LoadLibCryptoFunction('X509_CRL_get_ext_by_critical');
  if not assigned(X509_CRL_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_by_critical');
  Result := X509_CRL_get_ext_by_critical(x,crit,lastpos);
end;

function Load_X509_CRL_get_ext(const x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  X509_CRL_get_ext := LoadLibCryptoFunction('X509_CRL_get_ext');
  if not assigned(X509_CRL_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext');
  Result := X509_CRL_get_ext(x,loc);
end;

function Load_X509_CRL_delete_ext(x: PX509_CRL; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  X509_CRL_delete_ext := LoadLibCryptoFunction('X509_CRL_delete_ext');
  if not assigned(X509_CRL_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_delete_ext');
  Result := X509_CRL_delete_ext(x,loc);
end;

function Load_X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_add_ext := LoadLibCryptoFunction('X509_CRL_add_ext');
  if not assigned(X509_CRL_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_add_ext');
  Result := X509_CRL_add_ext(x,ex,loc);
end;

function Load_X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  X509_CRL_get_ext_d2i := LoadLibCryptoFunction('X509_CRL_get_ext_d2i');
  if not assigned(X509_CRL_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_get_ext_d2i');
  Result := X509_CRL_get_ext_d2i(x,nid,crit,idx);
end;

function Load_X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_CRL_add1_ext_i2d := LoadLibCryptoFunction('X509_CRL_add1_ext_i2d');
  if not assigned(X509_CRL_add1_ext_i2d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_CRL_add1_ext_i2d');
  Result := X509_CRL_add1_ext_i2d(x,nid,value,crit,flags);
end;

function Load_X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_get_ext_count := LoadLibCryptoFunction('X509_REVOKED_get_ext_count');
  if not assigned(X509_REVOKED_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_count');
  Result := X509_REVOKED_get_ext_count(x);
end;

function Load_X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_get_ext_by_NID := LoadLibCryptoFunction('X509_REVOKED_get_ext_by_NID');
  if not assigned(X509_REVOKED_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_by_NID');
  Result := X509_REVOKED_get_ext_by_NID(x,nid,lastpos);
end;

function Load_X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_get_ext_by_OBJ := LoadLibCryptoFunction('X509_REVOKED_get_ext_by_OBJ');
  if not assigned(X509_REVOKED_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_by_OBJ');
  Result := X509_REVOKED_get_ext_by_OBJ(x,obj,lastpos);
end;

function Load_X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_get_ext_by_critical := LoadLibCryptoFunction('X509_REVOKED_get_ext_by_critical');
  if not assigned(X509_REVOKED_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_by_critical');
  Result := X509_REVOKED_get_ext_by_critical(x,crit,lastpos);
end;

function Load_X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  X509_REVOKED_get_ext := LoadLibCryptoFunction('X509_REVOKED_get_ext');
  if not assigned(X509_REVOKED_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext');
  Result := X509_REVOKED_get_ext(x,loc);
end;

function Load_X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  X509_REVOKED_delete_ext := LoadLibCryptoFunction('X509_REVOKED_delete_ext');
  if not assigned(X509_REVOKED_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_delete_ext');
  Result := X509_REVOKED_delete_ext(x,loc);
end;

function Load_X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_add_ext := LoadLibCryptoFunction('X509_REVOKED_add_ext');
  if not assigned(X509_REVOKED_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_add_ext');
  Result := X509_REVOKED_add_ext(x,ex,loc);
end;

function Load_X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  X509_REVOKED_get_ext_d2i := LoadLibCryptoFunction('X509_REVOKED_get_ext_d2i');
  if not assigned(X509_REVOKED_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_get_ext_d2i');
  Result := X509_REVOKED_get_ext_d2i(x,nid,crit,idx);
end;

function Load_X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TOpenSSL_C_INT; value: Pointer; crit: TOpenSSL_C_INT; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  X509_REVOKED_add1_ext_i2d := LoadLibCryptoFunction('X509_REVOKED_add1_ext_i2d');
  if not assigned(X509_REVOKED_add1_ext_i2d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_REVOKED_add1_ext_i2d');
  Result := X509_REVOKED_add1_ext_i2d(x,nid,value,crit,flags);
end;

function Load_X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TOpenSSL_C_INT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
begin
  X509_EXTENSION_create_by_NID := LoadLibCryptoFunction('X509_EXTENSION_create_by_NID');
  if not assigned(X509_EXTENSION_create_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_create_by_NID');
  Result := X509_EXTENSION_create_by_NID(ex,nid,crit,data);
end;

function Load_X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TOpenSSL_C_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
begin
  X509_EXTENSION_create_by_OBJ := LoadLibCryptoFunction('X509_EXTENSION_create_by_OBJ');
  if not assigned(X509_EXTENSION_create_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_create_by_OBJ');
  Result := X509_EXTENSION_create_by_OBJ(ex,obj,crit,data);
end;

function Load_X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  X509_EXTENSION_set_object := LoadLibCryptoFunction('X509_EXTENSION_set_object');
  if not assigned(X509_EXTENSION_set_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_set_object');
  Result := X509_EXTENSION_set_object(ex,obj);
end;

function Load_X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_EXTENSION_set_critical := LoadLibCryptoFunction('X509_EXTENSION_set_critical');
  if not assigned(X509_EXTENSION_set_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_set_critical');
  Result := X509_EXTENSION_set_critical(ex,crit);
end;

function Load_X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl;
begin
  X509_EXTENSION_set_data := LoadLibCryptoFunction('X509_EXTENSION_set_data');
  if not assigned(X509_EXTENSION_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_set_data');
  Result := X509_EXTENSION_set_data(ex,data);
end;

function Load_X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl;
begin
  X509_EXTENSION_get_object := LoadLibCryptoFunction('X509_EXTENSION_get_object');
  if not assigned(X509_EXTENSION_get_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_get_object');
  Result := X509_EXTENSION_get_object(ex);
end;

function Load_X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl;
begin
  X509_EXTENSION_get_data := LoadLibCryptoFunction('X509_EXTENSION_get_data');
  if not assigned(X509_EXTENSION_get_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_get_data');
  Result := X509_EXTENSION_get_data(ne);
end;

function Load_X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TOpenSSL_C_INT; cdecl;
begin
  X509_EXTENSION_get_critical := LoadLibCryptoFunction('X509_EXTENSION_get_critical');
  if not assigned(X509_EXTENSION_get_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_EXTENSION_get_critical');
  Result := X509_EXTENSION_get_critical(ex);
end;

function Load_X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  X509_ATTRIBUTE_create_by_NID := LoadLibCryptoFunction('X509_ATTRIBUTE_create_by_NID');
  if not assigned(X509_ATTRIBUTE_create_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create_by_NID');
  Result := X509_ATTRIBUTE_create_by_NID(attr,nid,atrtype,data,len);
end;

function Load_X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  X509_ATTRIBUTE_create_by_OBJ := LoadLibCryptoFunction('X509_ATTRIBUTE_create_by_OBJ');
  if not assigned(X509_ATTRIBUTE_create_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create_by_OBJ');
  Result := X509_ATTRIBUTE_create_by_OBJ(attr,obj,atrtype,data,len);
end;

function Load_X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  X509_ATTRIBUTE_create_by_txt := LoadLibCryptoFunction('X509_ATTRIBUTE_create_by_txt');
  if not assigned(X509_ATTRIBUTE_create_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_create_by_txt');
  Result := X509_ATTRIBUTE_create_by_txt(attr,atrname,type_,bytes,len);
end;

function Load_X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  X509_ATTRIBUTE_set1_object := LoadLibCryptoFunction('X509_ATTRIBUTE_set1_object');
  if not assigned(X509_ATTRIBUTE_set1_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_set1_object');
  Result := X509_ATTRIBUTE_set1_object(attr,obj);
end;

function Load_X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TOpenSSL_C_INT; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_ATTRIBUTE_set1_data := LoadLibCryptoFunction('X509_ATTRIBUTE_set1_data');
  if not assigned(X509_ATTRIBUTE_set1_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_set1_data');
  Result := X509_ATTRIBUTE_set1_data(attr,attrtype,data,len);
end;

function Load_X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT; atrtype: TOpenSSL_C_INT; data: Pointer): Pointer; cdecl;
begin
  X509_ATTRIBUTE_get0_data := LoadLibCryptoFunction('X509_ATTRIBUTE_get0_data');
  if not assigned(X509_ATTRIBUTE_get0_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_get0_data');
  Result := X509_ATTRIBUTE_get0_data(attr,idx,atrtype,data);
end;

function Load_X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  X509_ATTRIBUTE_count := LoadLibCryptoFunction('X509_ATTRIBUTE_count');
  if not assigned(X509_ATTRIBUTE_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_count');
  Result := X509_ATTRIBUTE_count(attr);
end;

function Load_X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl;
begin
  X509_ATTRIBUTE_get0_object := LoadLibCryptoFunction('X509_ATTRIBUTE_get0_object');
  if not assigned(X509_ATTRIBUTE_get0_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_get0_object');
  Result := X509_ATTRIBUTE_get0_object(attr);
end;

function Load_X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
begin
  X509_ATTRIBUTE_get0_type := LoadLibCryptoFunction('X509_ATTRIBUTE_get0_type');
  if not assigned(X509_ATTRIBUTE_get0_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_ATTRIBUTE_get0_type');
  Result := X509_ATTRIBUTE_get0_type(attr,idx);
end;

function Load_EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_attr_count := LoadLibCryptoFunction('EVP_PKEY_get_attr_count');
  if not assigned(EVP_PKEY_get_attr_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr_count');
  Result := EVP_PKEY_get_attr_count(key);
end;

function Load_EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_attr_by_NID := LoadLibCryptoFunction('EVP_PKEY_get_attr_by_NID');
  if not assigned(EVP_PKEY_get_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr_by_NID');
  Result := EVP_PKEY_get_attr_by_NID(key,nid,lastpos);
end;

function Load_EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_attr_by_OBJ := LoadLibCryptoFunction('EVP_PKEY_get_attr_by_OBJ');
  if not assigned(EVP_PKEY_get_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr_by_OBJ');
  Result := EVP_PKEY_get_attr_by_OBJ(key,obj,lastpos);
end;

function Load_EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EVP_PKEY_get_attr := LoadLibCryptoFunction('EVP_PKEY_get_attr');
  if not assigned(EVP_PKEY_get_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_attr');
  Result := EVP_PKEY_get_attr(key,loc);
end;

function Load_EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  EVP_PKEY_delete_attr := LoadLibCryptoFunction('EVP_PKEY_delete_attr');
  if not assigned(EVP_PKEY_delete_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_delete_attr');
  Result := EVP_PKEY_delete_attr(key,loc);
end;

function Load_EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_add1_attr := LoadLibCryptoFunction('EVP_PKEY_add1_attr');
  if not assigned(EVP_PKEY_add1_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr');
  Result := EVP_PKEY_add1_attr(key,attr);
end;

function Load_EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_add1_attr_by_OBJ := LoadLibCryptoFunction('EVP_PKEY_add1_attr_by_OBJ');
  if not assigned(EVP_PKEY_add1_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr_by_OBJ');
  Result := EVP_PKEY_add1_attr_by_OBJ(key,obj,type_,bytes,len);
end;

function Load_EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_add1_attr_by_NID := LoadLibCryptoFunction('EVP_PKEY_add1_attr_by_NID');
  if not assigned(EVP_PKEY_add1_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr_by_NID');
  Result := EVP_PKEY_add1_attr_by_NID(key,nid,type_,bytes,len);
end;

function Load_EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_add1_attr_by_txt := LoadLibCryptoFunction('EVP_PKEY_add1_attr_by_txt');
  if not assigned(EVP_PKEY_add1_attr_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_add1_attr_by_txt');
  Result := EVP_PKEY_add1_attr_by_txt(key,attrname,type_,bytes,len);
end;

function Load_X509_verify_cert(ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  X509_verify_cert := LoadLibCryptoFunction('X509_verify_cert');
  if not assigned(X509_verify_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_verify_cert');
  Result := X509_verify_cert(ctx);
end;

function Load_PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_pbe_set0_algor := LoadLibCryptoFunction('PKCS5_pbe_set0_algor');
  if not assigned(PKCS5_pbe_set0_algor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe_set0_algor');
  Result := PKCS5_pbe_set0_algor(algor,alg,iter,salt,saltlen);
end;

function Load_PKCS5_pbe_set(alg: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  PKCS5_pbe_set := LoadLibCryptoFunction('PKCS5_pbe_set');
  if not assigned(PKCS5_pbe_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe_set');
  Result := PKCS5_pbe_set(alg,iter,salt,saltlen);
end;

function Load_PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  PKCS5_pbe2_set := LoadLibCryptoFunction('PKCS5_pbe2_set');
  if not assigned(PKCS5_pbe2_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe2_set');
  Result := PKCS5_pbe2_set(cipher,iter,salt,saltlen);
end;

function Load_PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; prf_nid: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  PKCS5_pbe2_set_iv := LoadLibCryptoFunction('PKCS5_pbe2_set_iv');
  if not assigned(PKCS5_pbe2_set_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe2_set_iv');
  Result := PKCS5_pbe2_set_iv(cipher,iter,salt,saltlen,aiv,prf_nid);
end;

function Load_PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TOpenSSL_C_INT; aiv: PByte; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64): PX509_ALGOR; cdecl;
begin
  PKCS5_pbe2_set_scrypt := LoadLibCryptoFunction('PKCS5_pbe2_set_scrypt');
  if not assigned(PKCS5_pbe2_set_scrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbe2_set_scrypt');
  Result := PKCS5_pbe2_set_scrypt(cipher,salt,saltlen,aiv,N,r,p);
end;

function Load_PKCS5_pbkdf2_set(iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; prf_nid: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT): PX509_ALGOR; cdecl;
begin
  PKCS5_pbkdf2_set := LoadLibCryptoFunction('PKCS5_pbkdf2_set');
  if not assigned(PKCS5_pbkdf2_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_pbkdf2_set');
  Result := PKCS5_pbkdf2_set(iter,salt,saltlen,prf_nid,keylen);
end;

function Load_EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl;
begin
  EVP_PKCS82PKEY := LoadLibCryptoFunction('EVP_PKCS82PKEY');
  if not assigned(EVP_PKCS82PKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKCS82PKEY');
  Result := EVP_PKCS82PKEY(p8);
end;

function Load_EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl;
begin
  EVP_PKEY2PKCS8 := LoadLibCryptoFunction('EVP_PKEY2PKCS8');
  if not assigned(EVP_PKEY2PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY2PKCS8');
  Result := EVP_PKEY2PKCS8(pkey);
end;

function Load_PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TOpenSSL_C_INT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS8_pkey_set0 := LoadLibCryptoFunction('PKCS8_pkey_set0');
  if not assigned(PKCS8_pkey_set0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_pkey_set0');
  Result := PKCS8_pkey_set0(priv,aobj,version,ptype,pval,penc,penclen);
end;

function Load_PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  PKCS8_pkey_get0 := LoadLibCryptoFunction('PKCS8_pkey_get0');
  if not assigned(PKCS8_pkey_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_pkey_get0');
  Result := PKCS8_pkey_get0(ppkalg,pk,ppklen,pa,p8);
end;

function Load_PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS8_pkey_add1_attr_by_NID := LoadLibCryptoFunction('PKCS8_pkey_add1_attr_by_NID');
  if not assigned(PKCS8_pkey_add1_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_pkey_add1_attr_by_NID');
  Result := PKCS8_pkey_add1_attr_by_NID(p8,nid,type_,bytes,len);
end;

function Load_X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TOpenSSL_C_INT; pval: Pointer; penc: PByte; penclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_PUBKEY_set0_param := LoadLibCryptoFunction('X509_PUBKEY_set0_param');
  if not assigned(X509_PUBKEY_set0_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_set0_param');
  Result := X509_PUBKEY_set0_param(pub,aobj,ptype,pval,penc,penclen);
end;

function Load_X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: POpenSSL_C_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
begin
  X509_PUBKEY_get0_param := LoadLibCryptoFunction('X509_PUBKEY_get0_param');
  if not assigned(X509_PUBKEY_get0_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_PUBKEY_get0_param');
  Result := X509_PUBKEY_get0_param(ppkalg,pk,ppklen,pa,pub);
end;

function Load_X509_check_trust(x: PX509; id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_check_trust := LoadLibCryptoFunction('X509_check_trust');
  if not assigned(X509_check_trust) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_check_trust');
  Result := X509_check_trust(x,id,flags);
end;

function Load_X509_TRUST_get_count: TOpenSSL_C_INT; cdecl;
begin
  X509_TRUST_get_count := LoadLibCryptoFunction('X509_TRUST_get_count');
  if not assigned(X509_TRUST_get_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_count');
  Result := X509_TRUST_get_count();
end;

function Load_X509_TRUST_get0(idx: TOpenSSL_C_INT): PX509_TRUST; cdecl;
begin
  X509_TRUST_get0 := LoadLibCryptoFunction('X509_TRUST_get0');
  if not assigned(X509_TRUST_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get0');
  Result := X509_TRUST_get0(idx);
end;

function Load_X509_TRUST_get_by_id(id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  X509_TRUST_get_by_id := LoadLibCryptoFunction('X509_TRUST_get_by_id');
  if not assigned(X509_TRUST_get_by_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_by_id');
  Result := X509_TRUST_get_by_id(id);
end;

procedure Load_X509_TRUST_cleanup; cdecl;
begin
  X509_TRUST_cleanup := LoadLibCryptoFunction('X509_TRUST_cleanup');
  if not assigned(X509_TRUST_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_cleanup');
  X509_TRUST_cleanup();
end;

function Load_X509_TRUST_get_flags(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl;
begin
  X509_TRUST_get_flags := LoadLibCryptoFunction('X509_TRUST_get_flags');
  if not assigned(X509_TRUST_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_flags');
  Result := X509_TRUST_get_flags(xp);
end;

function Load_X509_TRUST_get0_name(const xp: PX509_TRUST): PAnsiChar; cdecl;
begin
  X509_TRUST_get0_name := LoadLibCryptoFunction('X509_TRUST_get0_name');
  if not assigned(X509_TRUST_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get0_name');
  Result := X509_TRUST_get0_name(xp);
end;

function Load_X509_TRUST_get_trust(const xp: PX509_TRUST): TOpenSSL_C_INT; cdecl;
begin
  X509_TRUST_get_trust := LoadLibCryptoFunction('X509_TRUST_get_trust');
  if not assigned(X509_TRUST_get_trust) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_TRUST_get_trust');
  Result := X509_TRUST_get_trust(xp);
end;

function Load_X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PAnsiChar; ok: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  X509_NAME_hash_ex := LoadLibCryptoFunction('X509_NAME_hash_ex');
  if not assigned(X509_NAME_hash_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('X509_NAME_hash_ex');
  Result := X509_NAME_hash_ex(x,libctx,propq,ok);
end;


procedure UnLoad;
begin
  X509_CRL_set_default_method := Load_X509_CRL_set_default_method;
  X509_CRL_METHOD_free := Load_X509_CRL_METHOD_free;
  X509_CRL_set_meth_data := Load_X509_CRL_set_meth_data;
  X509_CRL_get_meth_data := Load_X509_CRL_get_meth_data;
  X509_verify_cert_error_string := Load_X509_verify_cert_error_string;
  X509_verify := Load_X509_verify;
  X509_REQ_verify := Load_X509_REQ_verify;
  X509_CRL_verify := Load_X509_CRL_verify;
  NETSCAPE_SPKI_verify := Load_NETSCAPE_SPKI_verify;
  NETSCAPE_SPKI_b64_decode := Load_NETSCAPE_SPKI_b64_decode;
  NETSCAPE_SPKI_b64_encode := Load_NETSCAPE_SPKI_b64_encode;
  NETSCAPE_SPKI_get_pubkey := Load_NETSCAPE_SPKI_get_pubkey;
  NETSCAPE_SPKI_set_pubkey := Load_NETSCAPE_SPKI_set_pubkey;
  NETSCAPE_SPKI_print := Load_NETSCAPE_SPKI_print;
  X509_signature_dump := Load_X509_signature_dump;
  X509_signature_print := Load_X509_signature_print;
  X509_sign := Load_X509_sign;
  X509_sign_ctx := Load_X509_sign_ctx;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_http_nbio := Load_X509_http_nbio;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_REQ_sign := Load_X509_REQ_sign;
  X509_REQ_sign_ctx := Load_X509_REQ_sign_ctx;
  X509_CRL_sign := Load_X509_CRL_sign;
  X509_CRL_sign_ctx := Load_X509_CRL_sign_ctx;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_CRL_http_nbio := Load_X509_CRL_http_nbio;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  NETSCAPE_SPKI_sign := Load_NETSCAPE_SPKI_sign;
  X509_pubkey_digest := Load_X509_pubkey_digest;
  X509_digest := Load_X509_digest;
  X509_CRL_digest := Load_X509_CRL_digest;
  X509_REQ_digest := Load_X509_REQ_digest;
  X509_NAME_digest := Load_X509_NAME_digest;
  d2i_X509_bio := Load_d2i_X509_bio;
  i2d_X509_bio := Load_i2d_X509_bio;
  d2i_X509_CRL_bio := Load_d2i_X509_CRL_bio;
  i2d_X509_CRL_bio := Load_i2d_X509_CRL_bio;
  d2i_X509_REQ_bio := Load_d2i_X509_REQ_bio;
  i2d_X509_REQ_bio := Load_i2d_X509_REQ_bio;
  d2i_RSAPrivateKey_bio := Load_d2i_RSAPrivateKey_bio;
  i2d_RSAPrivateKey_bio := Load_i2d_RSAPrivateKey_bio;
  d2i_RSAPublicKey_bio := Load_d2i_RSAPublicKey_bio;
  i2d_RSAPublicKey_bio := Load_i2d_RSAPublicKey_bio;
  d2i_RSA_PUBKEY_bio := Load_d2i_RSA_PUBKEY_bio;
  i2d_RSA_PUBKEY_bio := Load_i2d_RSA_PUBKEY_bio;
  d2i_DSA_PUBKEY_bio := Load_d2i_DSA_PUBKEY_bio;
  i2d_DSA_PUBKEY_bio := Load_i2d_DSA_PUBKEY_bio;
  d2i_DSAPrivateKey_bio := Load_d2i_DSAPrivateKey_bio;
  i2d_DSAPrivateKey_bio := Load_i2d_DSAPrivateKey_bio;
  d2i_EC_PUBKEY_bio := Load_d2i_EC_PUBKEY_bio;
  i2d_EC_PUBKEY_bio := Load_i2d_EC_PUBKEY_bio;
  d2i_ECPrivateKey_bio := Load_d2i_ECPrivateKey_bio;
  i2d_ECPrivateKey_bio := Load_i2d_ECPrivateKey_bio;
  d2i_PKCS8_bio := Load_d2i_PKCS8_bio;
  i2d_PKCS8_bio := Load_i2d_PKCS8_bio;
  d2i_PKCS8_PRIV_KEY_INFO_bio := Load_d2i_PKCS8_PRIV_KEY_INFO_bio;
  i2d_PKCS8_PRIV_KEY_INFO_bio := Load_i2d_PKCS8_PRIV_KEY_INFO_bio;
  i2d_PKCS8PrivateKeyInfo_bio := Load_i2d_PKCS8PrivateKeyInfo_bio;
  i2d_PrivateKey_bio := Load_i2d_PrivateKey_bio;
  d2i_PrivateKey_bio := Load_d2i_PrivateKey_bio;
  i2d_PUBKEY_bio := Load_i2d_PUBKEY_bio;
  d2i_PUBKEY_bio := Load_d2i_PUBKEY_bio;
  X509_dup := Load_X509_dup;
  X509_ATTRIBUTE_dup := Load_X509_ATTRIBUTE_dup;
  X509_EXTENSION_dup := Load_X509_EXTENSION_dup;
  X509_CRL_dup := Load_X509_CRL_dup;
  X509_REVOKED_dup := Load_X509_REVOKED_dup;
  X509_REQ_dup := Load_X509_REQ_dup;
  X509_ALGOR_dup := Load_X509_ALGOR_dup;
  X509_ALGOR_set0 := Load_X509_ALGOR_set0;
  X509_ALGOR_get0 := Load_X509_ALGOR_get0;
  X509_ALGOR_set_md := Load_X509_ALGOR_set_md;
  X509_ALGOR_cmp := Load_X509_ALGOR_cmp;
  X509_NAME_dup := Load_X509_NAME_dup;
  X509_NAME_ENTRY_dup := Load_X509_NAME_ENTRY_dup;
  X509_cmp_time := Load_X509_cmp_time;
  X509_cmp_current_time := Load_X509_cmp_current_time;
  X509_time_adj := Load_X509_time_adj;
  X509_time_adj_ex := Load_X509_time_adj_ex;
  X509_gmtime_adj := Load_X509_gmtime_adj;
  X509_get_default_cert_area := Load_X509_get_default_cert_area;
  X509_get_default_cert_dir := Load_X509_get_default_cert_dir;
  X509_get_default_cert_file := Load_X509_get_default_cert_file;
  X509_get_default_cert_dir_env := Load_X509_get_default_cert_dir_env;
  X509_get_default_cert_file_env := Load_X509_get_default_cert_file_env;
  X509_get_default_private_dir := Load_X509_get_default_private_dir;
  X509_to_X509_REQ := Load_X509_to_X509_REQ;
  X509_REQ_to_X509 := Load_X509_REQ_to_X509;
  X509_ALGOR_new := Load_X509_ALGOR_new;
  X509_ALGOR_free := Load_X509_ALGOR_free;
  d2i_X509_ALGOR := Load_d2i_X509_ALGOR;
  i2d_X509_ALGOR := Load_i2d_X509_ALGOR;
  X509_VAL_new := Load_X509_VAL_new;
  X509_VAL_free := Load_X509_VAL_free;
  d2i_X509_VAL := Load_d2i_X509_VAL;
  i2d_X509_VAL := Load_i2d_X509_VAL;
  X509_PUBKEY_new := Load_X509_PUBKEY_new;
  X509_PUBKEY_free := Load_X509_PUBKEY_free;
  d2i_X509_PUBKEY := Load_d2i_X509_PUBKEY;
  i2d_X509_PUBKEY := Load_i2d_X509_PUBKEY;
  X509_PUBKEY_set := Load_X509_PUBKEY_set;
  X509_PUBKEY_get0 := Load_X509_PUBKEY_get0;
  X509_PUBKEY_get := Load_X509_PUBKEY_get;
  X509_get_pathlen := Load_X509_get_pathlen;
  i2d_PUBKEY := Load_i2d_PUBKEY;
  d2i_PUBKEY := Load_d2i_PUBKEY;
  i2d_RSA_PUBKEY := Load_i2d_RSA_PUBKEY;
  d2i_RSA_PUBKEY := Load_d2i_RSA_PUBKEY;
  i2d_DSA_PUBKEY := Load_i2d_DSA_PUBKEY;
  d2i_DSA_PUBKEY := Load_d2i_DSA_PUBKEY;
  i2d_EC_PUBKEY := Load_i2d_EC_PUBKEY;
  d2i_EC_PUBKEY := Load_d2i_EC_PUBKEY;
  X509_SIG_new := Load_X509_SIG_new;
  X509_SIG_free := Load_X509_SIG_free;
  d2i_X509_SIG := Load_d2i_X509_SIG;
  i2d_X509_SIG := Load_i2d_X509_SIG;
  X509_SIG_get0 := Load_X509_SIG_get0;
  X509_SIG_getm := Load_X509_SIG_getm;
  X509_REQ_INFO_new := Load_X509_REQ_INFO_new;
  X509_REQ_INFO_free := Load_X509_REQ_INFO_free;
  d2i_X509_REQ_INFO := Load_d2i_X509_REQ_INFO;
  i2d_X509_REQ_INFO := Load_i2d_X509_REQ_INFO;
  X509_REQ_new := Load_X509_REQ_new;
  X509_REQ_free := Load_X509_REQ_free;
  d2i_X509_REQ := Load_d2i_X509_REQ;
  i2d_X509_REQ := Load_i2d_X509_REQ;
  X509_ATTRIBUTE_new := Load_X509_ATTRIBUTE_new;
  X509_ATTRIBUTE_free := Load_X509_ATTRIBUTE_free;
  d2i_X509_ATTRIBUTE := Load_d2i_X509_ATTRIBUTE;
  i2d_X509_ATTRIBUTE := Load_i2d_X509_ATTRIBUTE;
  X509_ATTRIBUTE_create := Load_X509_ATTRIBUTE_create;
  X509_EXTENSION_new := Load_X509_EXTENSION_new;
  X509_EXTENSION_free := Load_X509_EXTENSION_free;
  d2i_X509_EXTENSION := Load_d2i_X509_EXTENSION;
  i2d_X509_EXTENSION := Load_i2d_X509_EXTENSION;
  X509_NAME_ENTRY_new := Load_X509_NAME_ENTRY_new;
  X509_NAME_ENTRY_free := Load_X509_NAME_ENTRY_free;
  d2i_X509_NAME_ENTRY := Load_d2i_X509_NAME_ENTRY;
  i2d_X509_NAME_ENTRY := Load_i2d_X509_NAME_ENTRY;
  X509_NAME_new := Load_X509_NAME_new;
  X509_NAME_free := Load_X509_NAME_free;
  d2i_X509_NAME := Load_d2i_X509_NAME;
  i2d_X509_NAME := Load_i2d_X509_NAME;
  X509_NAME_set := Load_X509_NAME_set;
  X509_new := Load_X509_new;
  X509_free := Load_X509_free;
  d2i_X509 := Load_d2i_X509;
  i2d_X509 := Load_i2d_X509;
  X509_set_ex_data := Load_X509_set_ex_data;
  X509_get_ex_data := Load_X509_get_ex_data;
  i2d_X509_AUX := Load_i2d_X509_AUX;
  d2i_X509_AUX := Load_d2i_X509_AUX;
  i2d_re_X509_tbs := Load_i2d_re_X509_tbs;
  X509_SIG_INFO_get := Load_X509_SIG_INFO_get;
  X509_SIG_INFO_set := Load_X509_SIG_INFO_set;
  X509_get_signature_info := Load_X509_get_signature_info;
  X509_get0_signature := Load_X509_get0_signature;
  X509_get_signature_nid := Load_X509_get_signature_nid;
  X509_trusted := Load_X509_trusted;
  X509_alias_set1 := Load_X509_alias_set1;
  X509_keyid_set1 := Load_X509_keyid_set1;
  X509_alias_get0 := Load_X509_alias_get0;
  X509_keyid_get0 := Load_X509_keyid_get0;
  X509_TRUST_set := Load_X509_TRUST_set;
  X509_add1_trust_object := Load_X509_add1_trust_object;
  X509_add1_reject_object := Load_X509_add1_reject_object;
  X509_trust_clear := Load_X509_trust_clear;
  X509_reject_clear := Load_X509_reject_clear;
  X509_REVOKED_new := Load_X509_REVOKED_new;
  X509_REVOKED_free := Load_X509_REVOKED_free;
  d2i_X509_REVOKED := Load_d2i_X509_REVOKED;
  i2d_X509_REVOKED := Load_i2d_X509_REVOKED;
  X509_CRL_INFO_new := Load_X509_CRL_INFO_new;
  X509_CRL_INFO_free := Load_X509_CRL_INFO_free;
  d2i_X509_CRL_INFO := Load_d2i_X509_CRL_INFO;
  i2d_X509_CRL_INFO := Load_i2d_X509_CRL_INFO;
  X509_CRL_new := Load_X509_CRL_new;
  X509_CRL_free := Load_X509_CRL_free;
  d2i_X509_CRL := Load_d2i_X509_CRL;
  i2d_X509_CRL := Load_i2d_X509_CRL;
  X509_CRL_add0_revoked := Load_X509_CRL_add0_revoked;
  X509_CRL_get0_by_serial := Load_X509_CRL_get0_by_serial;
  X509_CRL_get0_by_cert := Load_X509_CRL_get0_by_cert;
  X509_PKEY_new := Load_X509_PKEY_new;
  X509_PKEY_free := Load_X509_PKEY_free;
  X509_INFO_new := Load_X509_INFO_new;
  X509_INFO_free := Load_X509_INFO_free;
  X509_NAME_oneline := Load_X509_NAME_oneline;
  ASN1_item_digest := Load_ASN1_item_digest;
  ASN1_item_verify := Load_ASN1_item_verify;
  ASN1_item_sign := Load_ASN1_item_sign;
  ASN1_item_sign_ctx := Load_ASN1_item_sign_ctx;
  X509_get_version := Load_X509_get_version;
  X509_set_version := Load_X509_set_version;
  X509_set_serialNumber := Load_X509_set_serialNumber;
  X509_get_serialNumber := Load_X509_get_serialNumber;
  X509_get0_serialNumber := Load_X509_get0_serialNumber;
  X509_set_issuer_name := Load_X509_set_issuer_name;
  X509_get_issuer_name := Load_X509_get_issuer_name;
  X509_set_subject_name := Load_X509_set_subject_name;
  X509_get_subject_name := Load_X509_get_subject_name;
  X509_get0_notBefore := Load_X509_get0_notBefore;
  X509_getm_notBefore := Load_X509_getm_notBefore;
  X509_set1_notBefore := Load_X509_set1_notBefore;
  X509_get0_notAfter := Load_X509_get0_notAfter;
  X509_getm_notAfter := Load_X509_getm_notAfter;
  X509_set1_notAfter := Load_X509_set1_notAfter;
  X509_set_pubkey := Load_X509_set_pubkey;
  X509_up_ref := Load_X509_up_ref;
  X509_get_signature_type := Load_X509_get_signature_type;
  X509_get_X509_PUBKEY := Load_X509_get_X509_PUBKEY;
  X509_get0_uids := Load_X509_get0_uids;
  X509_get0_tbs_sigalg := Load_X509_get0_tbs_sigalg;
  X509_get0_pubkey := Load_X509_get0_pubkey;
  X509_get_pubkey := Load_X509_get_pubkey;
  X509_get0_pubkey_bitstr := Load_X509_get0_pubkey_bitstr;
  X509_certificate_type := Load_X509_certificate_type;
  X509_REQ_get_version := Load_X509_REQ_get_version;
  X509_REQ_set_version := Load_X509_REQ_set_version;
  X509_REQ_get_subject_name := Load_X509_REQ_get_subject_name;
  X509_REQ_set_subject_name := Load_X509_REQ_set_subject_name;
  X509_REQ_get0_signature := Load_X509_REQ_get0_signature;
  X509_REQ_get_signature_nid := Load_X509_REQ_get_signature_nid;
  i2d_re_X509_REQ_tbs := Load_i2d_re_X509_REQ_tbs;
  X509_REQ_set_pubkey := Load_X509_REQ_set_pubkey;
  X509_REQ_get_pubkey := Load_X509_REQ_get_pubkey;
  X509_REQ_get0_pubkey := Load_X509_REQ_get0_pubkey;
  X509_REQ_get_X509_PUBKEY := Load_X509_REQ_get_X509_PUBKEY;
  X509_REQ_extension_nid := Load_X509_REQ_extension_nid;
  X509_REQ_get_extension_nids := Load_X509_REQ_get_extension_nids;
  X509_REQ_set_extension_nids := Load_X509_REQ_set_extension_nids;
  X509_REQ_get_attr_count := Load_X509_REQ_get_attr_count;
  X509_REQ_get_attr_by_NID := Load_X509_REQ_get_attr_by_NID;
  X509_REQ_get_attr_by_OBJ := Load_X509_REQ_get_attr_by_OBJ;
  X509_REQ_get_attr := Load_X509_REQ_get_attr;
  X509_REQ_delete_attr := Load_X509_REQ_delete_attr;
  X509_REQ_add1_attr := Load_X509_REQ_add1_attr;
  X509_REQ_add1_attr_by_OBJ := Load_X509_REQ_add1_attr_by_OBJ;
  X509_REQ_add1_attr_by_NID := Load_X509_REQ_add1_attr_by_NID;
  X509_REQ_add1_attr_by_txt := Load_X509_REQ_add1_attr_by_txt;
  X509_CRL_set_version := Load_X509_CRL_set_version;
  X509_CRL_set_issuer_name := Load_X509_CRL_set_issuer_name;
  X509_CRL_set1_lastUpdate := Load_X509_CRL_set1_lastUpdate;
  X509_CRL_set1_nextUpdate := Load_X509_CRL_set1_nextUpdate;
  X509_CRL_sort := Load_X509_CRL_sort;
  X509_CRL_up_ref := Load_X509_CRL_up_ref;
  X509_CRL_get_version := Load_X509_CRL_get_version;
  X509_CRL_get0_lastUpdate := Load_X509_CRL_get0_lastUpdate;
  X509_CRL_get0_nextUpdate := Load_X509_CRL_get0_nextUpdate;
  X509_CRL_get_issuer := Load_X509_CRL_get_issuer;
  X509_CRL_get0_signature := Load_X509_CRL_get0_signature;
  X509_CRL_get_signature_nid := Load_X509_CRL_get_signature_nid;
  i2d_re_X509_CRL_tbs := Load_i2d_re_X509_CRL_tbs;
  X509_REVOKED_get0_serialNumber := Load_X509_REVOKED_get0_serialNumber;
  X509_REVOKED_set_serialNumber := Load_X509_REVOKED_set_serialNumber;
  X509_REVOKED_get0_revocationDate := Load_X509_REVOKED_get0_revocationDate;
  X509_REVOKED_set_revocationDate := Load_X509_REVOKED_set_revocationDate;
  X509_CRL_diff := Load_X509_CRL_diff;
  X509_REQ_check_private_key := Load_X509_REQ_check_private_key;
  X509_check_private_key := Load_X509_check_private_key;
  X509_CRL_check_suiteb := Load_X509_CRL_check_suiteb;
  X509_issuer_and_serial_cmp := Load_X509_issuer_and_serial_cmp;
  X509_issuer_and_serial_hash := Load_X509_issuer_and_serial_hash;
  X509_issuer_name_cmp := Load_X509_issuer_name_cmp;
  X509_issuer_name_hash := Load_X509_issuer_name_hash;
  X509_subject_name_cmp := Load_X509_subject_name_cmp;
  X509_subject_name_hash := Load_X509_subject_name_hash;
  X509_cmp := Load_X509_cmp;
  X509_NAME_cmp := Load_X509_NAME_cmp;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  X509_NAME_hash := Load_X509_NAME_hash;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  X509_NAME_hash_old := Load_X509_NAME_hash_old;
  X509_CRL_cmp := Load_X509_CRL_cmp;
  X509_CRL_match := Load_X509_CRL_match;
  X509_aux_print := Load_X509_aux_print;
  X509_NAME_print := Load_X509_NAME_print;
  X509_NAME_print_ex := Load_X509_NAME_print_ex;
  X509_print_ex := Load_X509_print_ex;
  X509_print := Load_X509_print;
  X509_ocspid_print := Load_X509_ocspid_print;
  X509_CRL_print_ex := Load_X509_CRL_print_ex;
  X509_CRL_print := Load_X509_CRL_print;
  X509_REQ_print_ex := Load_X509_REQ_print_ex;
  X509_REQ_print := Load_X509_REQ_print;
  X509_NAME_entry_count := Load_X509_NAME_entry_count;
  X509_NAME_get_text_by_NID := Load_X509_NAME_get_text_by_NID;
  X509_NAME_get_text_by_OBJ := Load_X509_NAME_get_text_by_OBJ;
  X509_NAME_get_index_by_NID := Load_X509_NAME_get_index_by_NID;
  X509_NAME_get_index_by_OBJ := Load_X509_NAME_get_index_by_OBJ;
  X509_NAME_get_entry := Load_X509_NAME_get_entry;
  X509_NAME_delete_entry := Load_X509_NAME_delete_entry;
  X509_NAME_add_entry := Load_X509_NAME_add_entry;
  X509_NAME_add_entry_by_OBJ := Load_X509_NAME_add_entry_by_OBJ;
  X509_NAME_add_entry_by_NID := Load_X509_NAME_add_entry_by_NID;
  X509_NAME_ENTRY_create_by_txt := Load_X509_NAME_ENTRY_create_by_txt;
  X509_NAME_ENTRY_create_by_NID := Load_X509_NAME_ENTRY_create_by_NID;
  X509_NAME_add_entry_by_txt := Load_X509_NAME_add_entry_by_txt;
  X509_NAME_ENTRY_create_by_OBJ := Load_X509_NAME_ENTRY_create_by_OBJ;
  X509_NAME_ENTRY_set_object := Load_X509_NAME_ENTRY_set_object;
  X509_NAME_ENTRY_set_data := Load_X509_NAME_ENTRY_set_data;
  X509_NAME_ENTRY_get_object := Load_X509_NAME_ENTRY_get_object;
  X509_NAME_ENTRY_get_data := Load_X509_NAME_ENTRY_get_data;
  X509_NAME_ENTRY_set := Load_X509_NAME_ENTRY_set;
  X509_NAME_get0_der := Load_X509_NAME_get0_der;
  X509_get_ext_count := Load_X509_get_ext_count;
  X509_get_ext_by_NID := Load_X509_get_ext_by_NID;
  X509_get_ext_by_OBJ := Load_X509_get_ext_by_OBJ;
  X509_get_ext_by_critical := Load_X509_get_ext_by_critical;
  X509_get_ext := Load_X509_get_ext;
  X509_delete_ext := Load_X509_delete_ext;
  X509_add_ext := Load_X509_add_ext;
  X509_get_ext_d2i := Load_X509_get_ext_d2i;
  X509_add1_ext_i2d := Load_X509_add1_ext_i2d;
  X509_CRL_get_ext_count := Load_X509_CRL_get_ext_count;
  X509_CRL_get_ext_by_NID := Load_X509_CRL_get_ext_by_NID;
  X509_CRL_get_ext_by_OBJ := Load_X509_CRL_get_ext_by_OBJ;
  X509_CRL_get_ext_by_critical := Load_X509_CRL_get_ext_by_critical;
  X509_CRL_get_ext := Load_X509_CRL_get_ext;
  X509_CRL_delete_ext := Load_X509_CRL_delete_ext;
  X509_CRL_add_ext := Load_X509_CRL_add_ext;
  X509_CRL_get_ext_d2i := Load_X509_CRL_get_ext_d2i;
  X509_CRL_add1_ext_i2d := Load_X509_CRL_add1_ext_i2d;
  X509_REVOKED_get_ext_count := Load_X509_REVOKED_get_ext_count;
  X509_REVOKED_get_ext_by_NID := Load_X509_REVOKED_get_ext_by_NID;
  X509_REVOKED_get_ext_by_OBJ := Load_X509_REVOKED_get_ext_by_OBJ;
  X509_REVOKED_get_ext_by_critical := Load_X509_REVOKED_get_ext_by_critical;
  X509_REVOKED_get_ext := Load_X509_REVOKED_get_ext;
  X509_REVOKED_delete_ext := Load_X509_REVOKED_delete_ext;
  X509_REVOKED_add_ext := Load_X509_REVOKED_add_ext;
  X509_REVOKED_get_ext_d2i := Load_X509_REVOKED_get_ext_d2i;
  X509_REVOKED_add1_ext_i2d := Load_X509_REVOKED_add1_ext_i2d;
  X509_EXTENSION_create_by_NID := Load_X509_EXTENSION_create_by_NID;
  X509_EXTENSION_create_by_OBJ := Load_X509_EXTENSION_create_by_OBJ;
  X509_EXTENSION_set_object := Load_X509_EXTENSION_set_object;
  X509_EXTENSION_set_critical := Load_X509_EXTENSION_set_critical;
  X509_EXTENSION_set_data := Load_X509_EXTENSION_set_data;
  X509_EXTENSION_get_object := Load_X509_EXTENSION_get_object;
  X509_EXTENSION_get_data := Load_X509_EXTENSION_get_data;
  X509_EXTENSION_get_critical := Load_X509_EXTENSION_get_critical;
  X509_ATTRIBUTE_create_by_NID := Load_X509_ATTRIBUTE_create_by_NID;
  X509_ATTRIBUTE_create_by_OBJ := Load_X509_ATTRIBUTE_create_by_OBJ;
  X509_ATTRIBUTE_create_by_txt := Load_X509_ATTRIBUTE_create_by_txt;
  X509_ATTRIBUTE_set1_object := Load_X509_ATTRIBUTE_set1_object;
  X509_ATTRIBUTE_set1_data := Load_X509_ATTRIBUTE_set1_data;
  X509_ATTRIBUTE_get0_data := Load_X509_ATTRIBUTE_get0_data;
  X509_ATTRIBUTE_count := Load_X509_ATTRIBUTE_count;
  X509_ATTRIBUTE_get0_object := Load_X509_ATTRIBUTE_get0_object;
  X509_ATTRIBUTE_get0_type := Load_X509_ATTRIBUTE_get0_type;
  EVP_PKEY_get_attr_count := Load_EVP_PKEY_get_attr_count;
  EVP_PKEY_get_attr_by_NID := Load_EVP_PKEY_get_attr_by_NID;
  EVP_PKEY_get_attr_by_OBJ := Load_EVP_PKEY_get_attr_by_OBJ;
  EVP_PKEY_get_attr := Load_EVP_PKEY_get_attr;
  EVP_PKEY_delete_attr := Load_EVP_PKEY_delete_attr;
  EVP_PKEY_add1_attr := Load_EVP_PKEY_add1_attr;
  EVP_PKEY_add1_attr_by_OBJ := Load_EVP_PKEY_add1_attr_by_OBJ;
  EVP_PKEY_add1_attr_by_NID := Load_EVP_PKEY_add1_attr_by_NID;
  EVP_PKEY_add1_attr_by_txt := Load_EVP_PKEY_add1_attr_by_txt;
  X509_verify_cert := Load_X509_verify_cert;
  PKCS5_pbe_set0_algor := Load_PKCS5_pbe_set0_algor;
  PKCS5_pbe_set := Load_PKCS5_pbe_set;
  PKCS5_pbe2_set := Load_PKCS5_pbe2_set;
  PKCS5_pbe2_set_iv := Load_PKCS5_pbe2_set_iv;
  PKCS5_pbe2_set_scrypt := Load_PKCS5_pbe2_set_scrypt;
  PKCS5_pbkdf2_set := Load_PKCS5_pbkdf2_set;
  EVP_PKCS82PKEY := Load_EVP_PKCS82PKEY;
  EVP_PKEY2PKCS8 := Load_EVP_PKEY2PKCS8;
  PKCS8_pkey_set0 := Load_PKCS8_pkey_set0;
  PKCS8_pkey_get0 := Load_PKCS8_pkey_get0;
  PKCS8_pkey_add1_attr_by_NID := Load_PKCS8_pkey_add1_attr_by_NID;
  X509_PUBKEY_set0_param := Load_X509_PUBKEY_set0_param;
  X509_PUBKEY_get0_param := Load_X509_PUBKEY_get0_param;
  X509_check_trust := Load_X509_check_trust;
  X509_TRUST_get_count := Load_X509_TRUST_get_count;
  X509_TRUST_get0 := Load_X509_TRUST_get0;
  X509_TRUST_get_by_id := Load_X509_TRUST_get_by_id;
  X509_TRUST_cleanup := Load_X509_TRUST_cleanup;
  X509_TRUST_get_flags := Load_X509_TRUST_get_flags;
  X509_TRUST_get0_name := Load_X509_TRUST_get0_name;
  X509_TRUST_get_trust := Load_X509_TRUST_get_trust;
  X509_NAME_hash_ex := Load_X509_NAME_hash_ex;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
