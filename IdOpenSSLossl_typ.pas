unit IdOpenSSLossl_typ;

interface

uses
  IdCTypes, IdOpenSSLe_os2;

{
  Automatically converted by H2Pas 1.0.0 from openssl-1.1.0l/include/openssl/ossl_typ.h
  The following command line parameters were used:
  -p
  -P
  -t
  -T
  -C
  openssl-1.1.0l/include/openssl/ossl_typ.h
}

{$IF defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && \}
(* error
  defined(INTMAX_MAX) && defined(UINTMAX_MAX)
  in declarator_list *)

type
  Possl_uintmax_t = ^Tossl_uintmax_t;
  Tossl_uintmax_t = Tuintmax_t;
{$ELSE}
{
  * Not long long, because the C-library can only be expected to provide
  * strtoll(), strtoull() at the same time as intmax_t and strtoimax(),
  * strtoumax().  Since we use these for parsing arguments, we need the
  * conversion functions, not just the sizes.
}

type
  Possl_intmax_t = ^Tossl_intmax_t;
  Tossl_intmax_t = TIdC_LONG;

  Possl_uintmax_t = ^Tossl_uintmax_t;
  Tossl_uintmax_t = TIdC_ULONG;
{$ENDIF}
  { C++ end of extern C conditionnal removed }

  // * This is the base type that holds just about everything :-) */
  asn1_string_st = record
    length: TIdC_INT;
    _type: TIdC_INT;
    data: PAnsiChar;
    { *
      * The value of the following field depends on the type being held.  It
      * is mostly being used for BIT_STRING so if the input data has a
      * non-zero 'unused bits' value, it will be handled correctly
      * }
    flags: TIdC_LONG;
  end;

{$IFDEF NO_ASN1_TYPEDEFS}

type
  ASN1_INTEGER = ASN1_STRING;
  ASN1_ENUMERATED = ASN1_STRING;
  ASN1_BIT_STRING = ASN1_STRING;
  ASN1_OCTET_STRING = ASN1_STRING;
  ASN1_PRINTABLESTRING = ASN1_STRING;
  ASN1_T61STRING = ASN1_STRING;
  ASN1_IA5STRING = ASN1_STRING;
  ASN1_UTCTIME = ASN1_STRING;
  ASN1_GENERALIZEDTIME = ASN1_STRING;
  ASN1_TIME = ASN1_STRING;
  ASN1_GENERALSTRING = ASN1_STRING;
  ASN1_UNIVERSALSTRING = ASN1_STRING;
  ASN1_BMPSTRING = ASN1_STRING;
  ASN1_VISIBLESTRING = ASN1_STRING;
  ASN1_UTF8STRING = ASN1_STRING;
  ASN1_BOOLEAN = TIdC_int;
  ASN1_NULL = TIdC_int;
{$ELSE}

type
  ASN1_INTEGER = asn1_string_st;
  PASN1_INTEGER = ^ASN1_INTEGER;
  PPASN1_INTEGER = ^PASN1_INTEGER;
  ASN1_ENUMERATED = asn1_string_st;
  PASN1_ENUMERATED = ^ASN1_ENUMERATED;
  ASN1_BIT_STRING = asn1_string_st;
  PASN1_BIT_STRING = ^ASN1_BIT_STRING;
  ASN1_OCTET_STRING = asn1_string_st;
  PASN1_OCTET_STRING = ^ASN1_OCTET_STRING;
  PPASN1_OCTET_STRING = ^PASN1_OCTET_STRING;
  ASN1_PRINTABLESTRING = asn1_string_st;
  PASN1_PRINTABLESTRING = ^ASN1_PRINTABLESTRING;
  ASN1_T61STRING = asn1_string_st;
  PASN1_T61STRING = ^ASN1_T61STRING;
  ASN1_IA5STRING = asn1_string_st;
  PASN1_IA5STRING = ^ASN1_IA5STRING;
  ASN1_GENERALSTRING = asn1_string_st;
  PASN1_GENERALSTRING = ^ASN1_GENERALSTRING;
  ASN1_UNIVERSALSTRING = asn1_string_st;
  PASN1_UNIVERSALSTRING = ^ASN1_UNIVERSALSTRING;
  ASN1_BMPSTRING = asn1_string_st;
  PASN1_BMPSTRING = ^ASN1_BMPSTRING;
  ASN1_UTCTIME = asn1_string_st;
  PASN1_UTCTIME = ^ASN1_UTCTIME;
  ASN1_TIME = asn1_string_st;
  PASN1_TIME = ^ASN1_TIME;
  ASN1_GENERALIZEDTIME = asn1_string_st;
  PASN1_GENERALIZEDTIME = ^ASN1_GENERALIZEDTIME;
  PPASN1_GENERALIZEDTIME = ^PASN1_GENERALIZEDTIME;
  ASN1_VISIBLESTRING = asn1_string_st;
  PASN1_VISIBLESTRING = ^ASN1_VISIBLESTRING;
  ASN1_UTF8STRING = asn1_string_st;
  PASN1_UTF8STRING = ^ASN1_UTF8STRING;
  ASN1_STRING = asn1_string_st;
  PASN1_STRING = ^ASN1_STRING;
  PPASN1_STRING = ^PASN1_STRING;
  ASN1_BOOLEAN = TIdC_INT;
  PASN1_BOOLEAN = ^TASN1_BOOLEAN;
  TASN1_BOOLEAN = ASN1_BOOLEAN;

  PASN1_NULL = ^TASN1_NULL;
  TASN1_NULL = TIdC_INT;
{$ENDIF}

Type
  Pdane_st = Pointer;
  PBIO = Pointer;
  PPBIO = ^PBIO;
  PBIO_METHOD = Pointer;
  PBIGNUM = Pointer;
  PBN_CTX = Pointer;
  PBN_BLINDING = Pointer;
  PBN_MONT_CTX = Pointer;
  PBN_RECP_CTX = Pointer;
  PBN_GENCB = Pointer;
  BUF_MEM = Pointer;

  PEVP_CIPHER = Pointer;
  PEVP_CIPHER_CTX = Pointer;

  PEVP_MD = Pointer;
  PEVP_MD_CTX = Pointer;
  PEVP_PKEY = Pointer;

  PEVP_PKEY_ASN1_METHOD = Pointer;

  PEVP_PKEY_METHOD = Pointer;
  PEVP_PKEY_CTX = Pointer;

  PEVP_ENCODE_CTX = Pointer;

  PHMAC_CTX = Pointer;

  PDH = Pointer;
  Pdh_method = Pointer;

  PDSA = Pointer;
  Pdsa_method = Pointer;

  PRSA = Pointer;
  PRSA_METHOD = Pointer;

  PEC_KEY = Pointer;
  EC_KEY_METHOD = Pointer;

  PRAND_METHOD = Pointer;

  PSSL_DANE = Pointer;
  PX509 = Pointer;
  PX509_ALGOR = Pointer;
  PX509_CRL = Pointer;
  PX509_CRL_METHOD = Pointer;
  PX509_REVOKED = Pointer;
  PX509_NAME = Pointer;
  PX509_PUBKEY = Pointer;
  PX509_STORE = Pointer;
  PX509_STORE_CTX = Pointer;

  PX509_OBJECT = Pointer;
  PX509_LOOKUP = Pointer;
  PX509_LOOKUP_METHOD = Pointer;
  PX509_VERIFY_PARAM = Pointer;

  PPKCS8_PRIV_KEY_INFO = Pointer;

  PX509V3_CTX = Pointer;
  PCONF = Pointer;
  POPENSSL_INIT_SETTINGS = Pointer;

  PUI = Pointer;
  PUI_METHOD = Pointer;

  PENGINE = Pointer;
  PSSL = Pointer;
  PSSL_CTX = Pointer;

  PCOMP_CTX = Pointer;
  PCOMP_METHOD = Pointer;

  PX509_POLICY_NODE = Pointer;
  PX509_POLICY_LEVEL = Pointer;
  PX509_POLICY_TREE = Pointer;
  PX509_POLICY_CACHE = Pointer;

  PAUTHORITY_KEYID = Pointer;
  PDIST_POINT = Pointer;
  PISSUING_DIST_POINT = Pointer;
  PNAME_CONSTRAINTS = Pointer;

  PCRYPTO_EX_DATA = Pointer;

  POCSP_REQ_CTX = Pointer;
  POCSP_RESPONSE = Pointer;
  POCSP_RESPID = Pointer;

  PSCT = Pointer;
  PSCT_CTX = Pointer;
  PCTLOG = Pointer;
  PCTLOG_STORE = Pointer;
  PCT_POLICY_EVAL_CTX = Pointer;
{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}
  {
    * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
    *
    * Licensed under the OpenSSL license (the "License").  You may not use
    * this file except in compliance with the License.  You can obtain a copy
    * in the file LICENSE in the source distribution or at
    * https://www.openssl.org/source/license.html
  }
{$IFNDEF HEADER_OPENSSL_TYPES_H}
{$DEFINE HEADER_OPENSSL_TYP}
  { C++ extern C conditionnal removed }

{$IFDEF _WIN32}
{$UNDEF X509_NAME}
{$UNDEF X509_EXTENSIONS}
{$UNDEF PKCS7_ISSUER_AND_SERIAL}
{$UNDEF PKCS7_SIGNER_INFO}
{$UNDEF OCSP_REQUEST}
{$UNDEF OCSP_RESPONSE}
{$ENDIF}
{$IFDEF BIGNUM}
{$UNDEF BIGNUM}
{$ENDIF}
{$ENDIF}
  PASN1_OBJECT = Pointer;
  PPASN1_OBJECT = ^PASN1_OBJECT;
  PASN1_PCTX = Pointer;
  PASN1_SCTX = Pointer;

implementation

uses
  SysUtils;

end.
