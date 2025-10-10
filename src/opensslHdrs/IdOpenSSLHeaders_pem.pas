(* This unit was generated from the source file pem.h2pas 
It should not be modified directly. All changes should be made to pem.h2pas
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


unit IdOpenSSLHeaders_pem;


interface

// Headers for OpenSSL 1.1.1
// pem.h


uses
  IdSSLOpenSSLAPI,
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
  pem_password_cb = function(buf: PAnsiChar; size: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM PEM_get_EVP_CIPHER_INFO}
{$EXTERNALSYM PEM_do_header}
{$EXTERNALSYM PEM_read_bio}
{$EXTERNALSYM PEM_read_bio_ex}
{$EXTERNALSYM PEM_bytes_read_bio_secmem}
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
{$EXTERNALSYM PEM_write_bio_PrivateKey_traditional}
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

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_bytes_read_bio_secmem(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio(bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_bytes_read_bio(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl; external CLibCrypto;
function PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl; external CLibCrypto;
function PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure PEM_dek_info(buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl; external CLibCrypto;
function PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl; external CLibCrypto;
function PEM_write_bio_X509(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl; external CLibCrypto;
function PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl; external CLibCrypto;
function PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl; external CLibCrypto;
function PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl; external CLibCrypto;
function PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl; external CLibCrypto;
function PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl; external CLibCrypto;
function PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl; external CLibCrypto;
function PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl; external CLibCrypto;
function PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl; external CLibCrypto;
function PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl; external CLibCrypto;
function PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl; external CLibCrypto;
function PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl; external CLibCrypto;
function PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl; external CLibCrypto;
function PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto;
function PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function b2i_PrivateKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function b2i_PublicKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto;
function b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto;
function i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl;
function Load_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_PEM_bytes_read_bio_secmem(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio(bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_PEM_bytes_read_bio(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl;
function Load_PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl;
function Load_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl;
function Load_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl;
procedure Load_PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl;
procedure Load_PEM_dek_info(buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl;
function Load_PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl;
function Load_PEM_write_bio_X509(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl;
function Load_PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl;
function Load_PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl;
function Load_PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl;
function Load_PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl;
function Load_PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
function Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
function Load_PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
function Load_PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
function Load_PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
function Load_PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
function Load_PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
function Load_PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl;
function Load_PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl;
function Load_PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl;
function Load_PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl;
function Load_PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
function Load_PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
function Load_PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
function Load_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
function Load_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl;
function Load_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_b2i_PrivateKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
function Load_b2i_PublicKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
function Load_b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
function Load_b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
function Load_i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
function Load_i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;

var
  PEM_get_EVP_CIPHER_INFO: function (header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl = Load_PEM_get_EVP_CIPHER_INFO;
  PEM_do_header: function (cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_do_header;
  PEM_read_bio: function (bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_PEM_read_bio;
  PEM_read_bio_ex: function (bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_PEM_read_bio_ex;
  PEM_bytes_read_bio_secmem: function (pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_bytes_read_bio_secmem;
  PEM_write_bio: function (bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio;
  PEM_bytes_read_bio: function (pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_bytes_read_bio;
  PEM_ASN1_read_bio: function (d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl = Load_PEM_ASN1_read_bio;
  PEM_ASN1_write_bio: function (i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_ASN1_write_bio;
  PEM_X509_INFO_read_bio: function (bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl = Load_PEM_X509_INFO_read_bio;
  PEM_X509_INFO_write_bio: function (bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_X509_INFO_write_bio;
  PEM_SignInit: function (ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PEM_SignInit;
  PEM_SignUpdate: function (ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl = Load_PEM_SignUpdate;
  PEM_SignFinal: function (ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_SignFinal;
  PEM_def_callback: function (buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_def_callback;
  PEM_proc_type: procedure (buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl = Load_PEM_proc_type;
  PEM_dek_info: procedure (buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl = Load_PEM_dek_info;
  PEM_read_bio_X509: function (bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl = Load_PEM_read_bio_X509;
  PEM_write_bio_X509: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509;
  PEM_read_bio_X509_AUX: function (bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl = Load_PEM_read_bio_X509_AUX;
  PEM_write_bio_X509_AUX: function (bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_AUX;
  PEM_read_bio_X509_REQ: function (bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl = Load_PEM_read_bio_X509_REQ;
  PEM_write_bio_X509_REQ: function (bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_REQ;
  PEM_write_bio_X509_REQ_NEW: function (bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_REQ_NEW;
  PEM_read_bio_X509_CRL: function (bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl = Load_PEM_read_bio_X509_CRL;
  PEM_write_bio_X509_CRL: function (bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_X509_CRL;
  PEM_read_bio_PKCS7: function (bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl = Load_PEM_read_bio_PKCS7;
  PEM_write_bio_PKCS7: function (bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS7;
  PEM_read_bio_PKCS8: function (bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl = Load_PEM_read_bio_PKCS8;
  PEM_write_bio_PKCS8: function (bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO: function (bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl = Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO: function (bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
  PEM_read_bio_RSAPrivateKey: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = Load_PEM_read_bio_RSAPrivateKey;
  PEM_write_bio_RSAPrivateKey: function (bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_RSAPrivateKey;
  PEM_read_bio_RSAPublicKey: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = Load_PEM_read_bio_RSAPublicKey;
  PEM_write_bio_RSAPublicKey: function (bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_RSAPublicKey;
  PEM_read_bio_RSA_PUBKEY: function (bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl = Load_PEM_read_bio_RSA_PUBKEY;
  PEM_write_bio_RSA_PUBKEY: function (bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_RSA_PUBKEY;
  PEM_read_bio_DSAPrivateKey: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = Load_PEM_read_bio_DSAPrivateKey;
  PEM_write_bio_DSAPrivateKey: function (bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DSAPrivateKey;
  PEM_read_bio_DSA_PUBKEY: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = Load_PEM_read_bio_DSA_PUBKEY;
  PEM_write_bio_DSA_PUBKEY: function (bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DSA_PUBKEY;
  PEM_read_bio_DSAparams: function (bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = Load_PEM_read_bio_DSAparams;
  PEM_write_bio_DSAparams: function (bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DSAparams;
  PEM_read_bio_ECPKParameters: function (bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl = Load_PEM_read_bio_ECPKParameters;
  PEM_write_bio_ECPKParameters: function (bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_ECPKParameters;
  PEM_read_bio_ECPrivateKey: function (bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl = Load_PEM_read_bio_ECPrivateKey;
  PEM_write_bio_ECPrivateKey: function (bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_ECPrivateKey;
  PEM_read_bio_EC_PUBKEY: function (bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl = Load_PEM_read_bio_EC_PUBKEY;
  PEM_write_bio_EC_PUBKEY: function (bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_EC_PUBKEY;
  PEM_read_bio_DHparams: function (bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl = Load_PEM_read_bio_DHparams;
  PEM_write_bio_DHparams: function (bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DHparams;
  PEM_write_bio_DHxparams: function (bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_DHxparams;
  PEM_read_bio_PrivateKey: function (bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = Load_PEM_read_bio_PrivateKey;
  PEM_write_bio_PrivateKey: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PrivateKey;
  PEM_read_bio_PUBKEY: function (bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = Load_PEM_read_bio_PUBKEY;
  PEM_write_bio_PUBKEY: function (bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PUBKEY;
  PEM_write_bio_PrivateKey_traditional: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PrivateKey_traditional;
  PEM_write_bio_PKCS8PrivateKey_nid: function (bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8PrivateKey_nid;
  PEM_write_bio_PKCS8PrivateKey: function (bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_PKCS8PrivateKey;
  i2d_PKCS8PrivateKey_bio: function (bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey_bio;
  i2d_PKCS8PrivateKey_nid_bio: function (bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey_nid_bio;
  d2i_PKCS8PrivateKey_bio: function (bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = Load_d2i_PKCS8PrivateKey_bio;
  PEM_read_bio_Parameters: function (bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl = Load_PEM_read_bio_Parameters;
  PEM_write_bio_Parameters: function (bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_Parameters;
  b2i_PrivateKey: function (const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = Load_b2i_PrivateKey;
  b2i_PublicKey: function (const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = Load_b2i_PublicKey;
  b2i_PrivateKey_bio: function (in_: PBIO): PEVP_PKEY; cdecl = Load_b2i_PrivateKey_bio;
  b2i_PublicKey_bio: function (in_: PBIO): PEVP_PKEY; cdecl = Load_b2i_PublicKey_bio;
  i2b_PrivateKey_bio: function (out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2b_PrivateKey_bio;
  i2b_PublicKey_bio: function (out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2b_PublicKey_bio;
  b2i_PVK_bio: function (in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl = Load_b2i_PVK_bio;
  i2b_PVK_bio: function (out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl = Load_i2b_PVK_bio;
{$ENDIF}
const
  PEM_read_bio_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PEM_bytes_read_bio_secmem_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PEM_write_bio_PrivateKey_traditional_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_PEM_get_EVP_CIPHER_INFO(header: PAnsiChar; cipher: PEVP_CIPHER_INFO): TOpenSSL_C_INT; cdecl;
begin
  PEM_get_EVP_CIPHER_INFO := LoadLibCryptoFunction('PEM_get_EVP_CIPHER_INFO');
  if not assigned(PEM_get_EVP_CIPHER_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_get_EVP_CIPHER_INFO');
  Result := PEM_get_EVP_CIPHER_INFO(header,cipher);
end;

function Load_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PByte; len: POpenSSL_C_LONG; callback: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_do_header := LoadLibCryptoFunction('PEM_do_header');
  if not assigned(PEM_do_header) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_do_header');
  Result := PEM_do_header(cipher,data,len,callback,u);
end;

function Load_PEM_read_bio(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  PEM_read_bio := LoadLibCryptoFunction('PEM_read_bio');
  if not assigned(PEM_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio');
  Result := PEM_read_bio(bp,name,header,data,len);
end;

function Load_PEM_read_bio_ex(bp: PBIO; name: PPAnsiChar; header: PPAnsiChar; data: PPByte; len: POpenSSL_C_LONG; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  PEM_read_bio_ex := LoadLibCryptoFunction('PEM_read_bio_ex');
  if not assigned(PEM_read_bio_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ex');
  Result := PEM_read_bio_ex(bp,name,header,data,len,flags);
end;

function Load_PEM_bytes_read_bio_secmem(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_bytes_read_bio_secmem := LoadLibCryptoFunction('PEM_bytes_read_bio_secmem');
  if not assigned(PEM_bytes_read_bio_secmem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_bytes_read_bio_secmem');
  Result := PEM_bytes_read_bio_secmem(pdata,plen,pnm,name,bp,cb,u);
end;

function Load_PEM_write_bio(bp: PBIO; const name: PAnsiChar; const hdr: PAnsiChar; const data: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio := LoadLibCryptoFunction('PEM_write_bio');
  if not assigned(PEM_write_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio');
  Result := PEM_write_bio(bp,name,hdr,data,len);
end;

function Load_PEM_bytes_read_bio(pdata: PPByte; plen: POpenSSL_C_LONG; pnm: PPAnsiChar; const name: PAnsiChar; bp: PBIO; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_bytes_read_bio := LoadLibCryptoFunction('PEM_bytes_read_bio');
  if not assigned(PEM_bytes_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_bytes_read_bio');
  Result := PEM_bytes_read_bio(pdata,plen,pnm,name,bp,cb,u);
end;

function Load_PEM_ASN1_read_bio(d2i: d2i_of_void; const name: PAnsiChar; bp: PBIO; x: PPointer; cb: pem_password_cb; u: Pointer): Pointer; cdecl;
begin
  PEM_ASN1_read_bio := LoadLibCryptoFunction('PEM_ASN1_read_bio');
  if not assigned(PEM_ASN1_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_read_bio');
  Result := PEM_ASN1_read_bio(d2i,name,bp,x,cb,u);
end;

function Load_PEM_ASN1_write_bio(i2d: i2d_of_void; const name: PAnsiChar; bp: PBIO; x: Pointer; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_ASN1_write_bio := LoadLibCryptoFunction('PEM_ASN1_write_bio');
  if not assigned(PEM_ASN1_write_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_ASN1_write_bio');
  Result := PEM_ASN1_write_bio(i2d,name,bp,x,enc,kstr,klen,cb,u);
end;

function Load_PEM_X509_INFO_read_bio(bp: PBIO; sk: PSTACK_OF_X509_INFO; cb: pem_password_cb; u: Pointer): PSTACK_OF_X509_INFO; cdecl;
begin
  PEM_X509_INFO_read_bio := LoadLibCryptoFunction('PEM_X509_INFO_read_bio');
  if not assigned(PEM_X509_INFO_read_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_read_bio');
  Result := PEM_X509_INFO_read_bio(bp,sk,cb,u);
end;

function Load_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cd: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_X509_INFO_write_bio := LoadLibCryptoFunction('PEM_X509_INFO_write_bio');
  if not assigned(PEM_X509_INFO_write_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_X509_INFO_write_bio');
  Result := PEM_X509_INFO_write_bio(bp,xi,enc,kstr,klen,cd,u);
end;

function Load_PEM_SignInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PEM_SignInit := LoadLibCryptoFunction('PEM_SignInit');
  if not assigned(PEM_SignInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignInit');
  Result := PEM_SignInit(ctx,type_);
end;

function Load_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PByte; cnt: Byte): TOpenSSL_C_INT; cdecl;
begin
  PEM_SignUpdate := LoadLibCryptoFunction('PEM_SignUpdate');
  if not assigned(PEM_SignUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignUpdate');
  Result := PEM_SignUpdate(ctx,d,cnt);
end;

function Load_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_SignFinal := LoadLibCryptoFunction('PEM_SignFinal');
  if not assigned(PEM_SignFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_SignFinal');
  Result := PEM_SignFinal(ctx,sigret,siglen,pkey);
end;

function Load_PEM_def_callback(buf: PAnsiChar; num: TOpenSSL_C_INT; rwflag: TOpenSSL_C_INT; userdata: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_def_callback := LoadLibCryptoFunction('PEM_def_callback');
  if not assigned(PEM_def_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_def_callback');
  Result := PEM_def_callback(buf,num,rwflag,userdata);
end;

procedure Load_PEM_proc_type(buf: PAnsiChar; type_: TOpenSSL_C_INT); cdecl;
begin
  PEM_proc_type := LoadLibCryptoFunction('PEM_proc_type');
  if not assigned(PEM_proc_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_proc_type');
  PEM_proc_type(buf,type_);
end;

procedure Load_PEM_dek_info(buf: PAnsiChar; const type_: PAnsiChar; len: TOpenSSL_C_INT; str: PAnsiChar); cdecl;
begin
  PEM_dek_info := LoadLibCryptoFunction('PEM_dek_info');
  if not assigned(PEM_dek_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_dek_info');
  PEM_dek_info(buf,type_,len,str);
end;

function Load_PEM_read_bio_X509(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl;
begin
  PEM_read_bio_X509 := LoadLibCryptoFunction('PEM_read_bio_X509');
  if not assigned(PEM_read_bio_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509');
  Result := PEM_read_bio_X509(bp,x,cb,u);
end;

function Load_PEM_write_bio_X509(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509 := LoadLibCryptoFunction('PEM_write_bio_X509');
  if not assigned(PEM_write_bio_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509');
  Result := PEM_write_bio_X509(bp,x);
end;

function Load_PEM_read_bio_X509_AUX(bp: PBIO; x: PPX509; cb: pem_password_cb; u: Pointer): PX509; cdecl;
begin
  PEM_read_bio_X509_AUX := LoadLibCryptoFunction('PEM_read_bio_X509_AUX');
  if not assigned(PEM_read_bio_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_AUX');
  Result := PEM_read_bio_X509_AUX(bp,x,cb,u);
end;

function Load_PEM_write_bio_X509_AUX(bp: PBIO; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_AUX := LoadLibCryptoFunction('PEM_write_bio_X509_AUX');
  if not assigned(PEM_write_bio_X509_AUX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_AUX');
  Result := PEM_write_bio_X509_AUX(bp,x);
end;

function Load_PEM_read_bio_X509_REQ(bp: PBIO; x: PPX509_REQ; cb: pem_password_cb; u: Pointer): PX509_REQ; cdecl;
begin
  PEM_read_bio_X509_REQ := LoadLibCryptoFunction('PEM_read_bio_X509_REQ');
  if not assigned(PEM_read_bio_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_REQ');
  Result := PEM_read_bio_X509_REQ(bp,x,cb,u);
end;

function Load_PEM_write_bio_X509_REQ(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_REQ := LoadLibCryptoFunction('PEM_write_bio_X509_REQ');
  if not assigned(PEM_write_bio_X509_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_REQ');
  Result := PEM_write_bio_X509_REQ(bp,x);
end;

function Load_PEM_write_bio_X509_REQ_NEW(bp: PBIO; x: PX509_REQ): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_REQ_NEW := LoadLibCryptoFunction('PEM_write_bio_X509_REQ_NEW');
  if not assigned(PEM_write_bio_X509_REQ_NEW) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_REQ_NEW');
  Result := PEM_write_bio_X509_REQ_NEW(bp,x);
end;

function Load_PEM_read_bio_X509_CRL(bp: PBIO; x: PPX509_CRL; cb: pem_password_cb; u: Pointer): PX509_CRL; cdecl;
begin
  PEM_read_bio_X509_CRL := LoadLibCryptoFunction('PEM_read_bio_X509_CRL');
  if not assigned(PEM_read_bio_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_X509_CRL');
  Result := PEM_read_bio_X509_CRL(bp,x,cb,u);
end;

function Load_PEM_write_bio_X509_CRL(bp: PBIO; x: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_X509_CRL := LoadLibCryptoFunction('PEM_write_bio_X509_CRL');
  if not assigned(PEM_write_bio_X509_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_X509_CRL');
  Result := PEM_write_bio_X509_CRL(bp,x);
end;

function Load_PEM_read_bio_PKCS7(bp: PBIO; x: PPPKCS7; cb: pem_password_cb; u: Pointer): PPKCS7; cdecl;
begin
  PEM_read_bio_PKCS7 := LoadLibCryptoFunction('PEM_read_bio_PKCS7');
  if not assigned(PEM_read_bio_PKCS7) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS7');
  Result := PEM_read_bio_PKCS7(bp,x,cb,u);
end;

function Load_PEM_write_bio_PKCS7(bp: PBIO; x: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS7 := LoadLibCryptoFunction('PEM_write_bio_PKCS7');
  if not assigned(PEM_write_bio_PKCS7) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS7');
  Result := PEM_write_bio_PKCS7(bp,x);
end;

function Load_PEM_read_bio_PKCS8(bp: PBIO; x: PPX509_SIG; cb: pem_password_cb; u: Pointer): PX509_SIG; cdecl;
begin
  PEM_read_bio_PKCS8 := LoadLibCryptoFunction('PEM_read_bio_PKCS8');
  if not assigned(PEM_read_bio_PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS8');
  Result := PEM_read_bio_PKCS8(bp,x,cb,u);
end;

function Load_PEM_write_bio_PKCS8(bp: PBIO; x: PX509_SIG): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8 := LoadLibCryptoFunction('PEM_write_bio_PKCS8');
  if not assigned(PEM_write_bio_PKCS8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8');
  Result := PEM_write_bio_PKCS8(bp,x);
end;

function Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: pem_password_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
  if not assigned(PEM_read_bio_PKCS8_PRIV_KEY_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
  Result := PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp,x,cb,u);
end;

function Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: PBIO; x: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := LoadLibCryptoFunction('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
  if not assigned(PEM_write_bio_PKCS8_PRIV_KEY_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
  Result := PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp,x);
end;

function Load_PEM_read_bio_RSAPrivateKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
begin
  PEM_read_bio_RSAPrivateKey := LoadLibCryptoFunction('PEM_read_bio_RSAPrivateKey');
  if not assigned(PEM_read_bio_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSAPrivateKey');
  Result := PEM_read_bio_RSAPrivateKey(bp,x,cb,u);
end;

function Load_PEM_write_bio_RSAPrivateKey(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_RSAPrivateKey := LoadLibCryptoFunction('PEM_write_bio_RSAPrivateKey');
  if not assigned(PEM_write_bio_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSAPrivateKey');
  Result := PEM_write_bio_RSAPrivateKey(bp,x,enc,kstr,klen,cb,u);
end;

function Load_PEM_read_bio_RSAPublicKey(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
begin
  PEM_read_bio_RSAPublicKey := LoadLibCryptoFunction('PEM_read_bio_RSAPublicKey');
  if not assigned(PEM_read_bio_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSAPublicKey');
  Result := PEM_read_bio_RSAPublicKey(bp,x,cb,u);
end;

function Load_PEM_write_bio_RSAPublicKey(bp: PBIO; const x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_RSAPublicKey := LoadLibCryptoFunction('PEM_write_bio_RSAPublicKey');
  if not assigned(PEM_write_bio_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSAPublicKey');
  Result := PEM_write_bio_RSAPublicKey(bp,x);
end;

function Load_PEM_read_bio_RSA_PUBKEY(bp: PBIO; x: PPRSA; cb: pem_password_cb; u: Pointer): PRSA; cdecl;
begin
  PEM_read_bio_RSA_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_RSA_PUBKEY');
  if not assigned(PEM_read_bio_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_RSA_PUBKEY');
  Result := PEM_read_bio_RSA_PUBKEY(bp,x,cb,u);
end;

function Load_PEM_write_bio_RSA_PUBKEY(bp: PBIO; x: PRSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_RSA_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_RSA_PUBKEY');
  if not assigned(PEM_write_bio_RSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_RSA_PUBKEY');
  Result := PEM_write_bio_RSA_PUBKEY(bp,x);
end;

function Load_PEM_read_bio_DSAPrivateKey(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
begin
  PEM_read_bio_DSAPrivateKey := LoadLibCryptoFunction('PEM_read_bio_DSAPrivateKey');
  if not assigned(PEM_read_bio_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSAPrivateKey');
  Result := PEM_read_bio_DSAPrivateKey(bp,x,cb,u);
end;

function Load_PEM_write_bio_DSAPrivateKey(bp: PBIO; x: PDSA; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DSAPrivateKey := LoadLibCryptoFunction('PEM_write_bio_DSAPrivateKey');
  if not assigned(PEM_write_bio_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSAPrivateKey');
  Result := PEM_write_bio_DSAPrivateKey(bp,x,enc,kstr,klen,cb,u);
end;

function Load_PEM_read_bio_DSA_PUBKEY(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
begin
  PEM_read_bio_DSA_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_DSA_PUBKEY');
  if not assigned(PEM_read_bio_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSA_PUBKEY');
  Result := PEM_read_bio_DSA_PUBKEY(bp,x,cb,u);
end;

function Load_PEM_write_bio_DSA_PUBKEY(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DSA_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_DSA_PUBKEY');
  if not assigned(PEM_write_bio_DSA_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSA_PUBKEY');
  Result := PEM_write_bio_DSA_PUBKEY(bp,x);
end;

function Load_PEM_read_bio_DSAparams(bp: PBIO; x: PPDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl;
begin
  PEM_read_bio_DSAparams := LoadLibCryptoFunction('PEM_read_bio_DSAparams');
  if not assigned(PEM_read_bio_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DSAparams');
  Result := PEM_read_bio_DSAparams(bp,x,cb,u);
end;

function Load_PEM_write_bio_DSAparams(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DSAparams := LoadLibCryptoFunction('PEM_write_bio_DSAparams');
  if not assigned(PEM_write_bio_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DSAparams');
  Result := PEM_write_bio_DSAparams(bp,x);
end;

function Load_PEM_read_bio_ECPKParameters(bp: PBIO; x: PPEC_GROUP; cb: pem_password_cb; u: Pointer): PEC_GROUP; cdecl;
begin
  PEM_read_bio_ECPKParameters := LoadLibCryptoFunction('PEM_read_bio_ECPKParameters');
  if not assigned(PEM_read_bio_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ECPKParameters');
  Result := PEM_read_bio_ECPKParameters(bp,x,cb,u);
end;

function Load_PEM_write_bio_ECPKParameters(bp: PBIO; const x: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_ECPKParameters := LoadLibCryptoFunction('PEM_write_bio_ECPKParameters');
  if not assigned(PEM_write_bio_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ECPKParameters');
  Result := PEM_write_bio_ECPKParameters(bp,x);
end;

function Load_PEM_read_bio_ECPrivateKey(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl;
begin
  PEM_read_bio_ECPrivateKey := LoadLibCryptoFunction('PEM_read_bio_ECPrivateKey');
  if not assigned(PEM_read_bio_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_ECPrivateKey');
  Result := PEM_read_bio_ECPrivateKey(bp,x,cb,u);
end;

function Load_PEM_write_bio_ECPrivateKey(bp: PBIO; x: PEC_KEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_ECPrivateKey := LoadLibCryptoFunction('PEM_write_bio_ECPrivateKey');
  if not assigned(PEM_write_bio_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ECPrivateKey');
  Result := PEM_write_bio_ECPrivateKey(bp,x,enc,kstr,klen,cb,u);
end;

function Load_PEM_read_bio_EC_PUBKEY(bp: PBIO; x: PPEC_KEY; cb: pem_password_cb; u: Pointer): PEC_KEY; cdecl;
begin
  PEM_read_bio_EC_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_EC_PUBKEY');
  if not assigned(PEM_read_bio_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_EC_PUBKEY');
  Result := PEM_read_bio_EC_PUBKEY(bp,x,cb,u);
end;

function Load_PEM_write_bio_EC_PUBKEY(bp: PBIO; x: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_EC_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_EC_PUBKEY');
  if not assigned(PEM_write_bio_EC_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_EC_PUBKEY');
  Result := PEM_write_bio_EC_PUBKEY(bp,x);
end;

function Load_PEM_read_bio_DHparams(bp: PBIO; x: PPDH; cb: pem_password_cb; u: Pointer): PDH; cdecl;
begin
  PEM_read_bio_DHparams := LoadLibCryptoFunction('PEM_read_bio_DHparams');
  if not assigned(PEM_read_bio_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_DHparams');
  Result := PEM_read_bio_DHparams(bp,x,cb,u);
end;

function Load_PEM_write_bio_DHparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DHparams := LoadLibCryptoFunction('PEM_write_bio_DHparams');
  if not assigned(PEM_write_bio_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DHparams');
  Result := PEM_write_bio_DHparams(bp,x);
end;

function Load_PEM_write_bio_DHxparams(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_DHxparams := LoadLibCryptoFunction('PEM_write_bio_DHxparams');
  if not assigned(PEM_write_bio_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_DHxparams');
  Result := PEM_write_bio_DHxparams(bp,x);
end;

function Load_PEM_read_bio_PrivateKey(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_PrivateKey := LoadLibCryptoFunction('PEM_read_bio_PrivateKey');
  if not assigned(PEM_read_bio_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PrivateKey');
  Result := PEM_read_bio_PrivateKey(bp,x,cb,u);
end;

function Load_PEM_write_bio_PrivateKey(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PrivateKey := LoadLibCryptoFunction('PEM_write_bio_PrivateKey');
  if not assigned(PEM_write_bio_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey');
  Result := PEM_write_bio_PrivateKey(bp,x,enc,kstr,klen,cb,u);
end;

function Load_PEM_read_bio_PUBKEY(bp: PBIO; x: PPEVP_PKEY; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_PUBKEY := LoadLibCryptoFunction('PEM_read_bio_PUBKEY');
  if not assigned(PEM_read_bio_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_PUBKEY');
  Result := PEM_read_bio_PUBKEY(bp,x,cb,u);
end;

function Load_PEM_write_bio_PUBKEY(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PUBKEY := LoadLibCryptoFunction('PEM_write_bio_PUBKEY');
  if not assigned(PEM_write_bio_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PUBKEY');
  Result := PEM_write_bio_PUBKEY(bp,x);
end;

function Load_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PrivateKey_traditional := LoadLibCryptoFunction('PEM_write_bio_PrivateKey_traditional');
  if not assigned(PEM_write_bio_PrivateKey_traditional) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PrivateKey_traditional');
  Result := PEM_write_bio_PrivateKey_traditional(bp,x,enc,kstr,klen,cb,u);
end;

function Load_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8PrivateKey_nid := LoadLibCryptoFunction('PEM_write_bio_PKCS8PrivateKey_nid');
  if not assigned(PEM_write_bio_PKCS8PrivateKey_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8PrivateKey_nid');
  Result := PEM_write_bio_PKCS8PrivateKey_nid(bp,x,nid,kstr,klen,cb,u);
end;

function Load_PEM_write_bio_PKCS8PrivateKey(bp: PBIO; x: PEVP_PKEY_METHOD; const enc: PEVP_CIPHER; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_PKCS8PrivateKey := LoadLibCryptoFunction('PEM_write_bio_PKCS8PrivateKey');
  if not assigned(PEM_write_bio_PKCS8PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_PKCS8PrivateKey');
  Result := PEM_write_bio_PKCS8PrivateKey(bp,x,enc,kstr,klen,cb,u);
end;

function Load_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER_CTX; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_bio');
  if not assigned(i2d_PKCS8PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_bio');
  Result := i2d_PKCS8PrivateKey_bio(bp,x,enc,kstr,klen,cb,u);
end;

function Load_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TOpenSSL_C_INT; kstr: PAnsiChar; klen: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey_nid_bio := LoadLibCryptoFunction('i2d_PKCS8PrivateKey_nid_bio');
  if not assigned(i2d_PKCS8PrivateKey_nid_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey_nid_bio');
  Result := i2d_PKCS8PrivateKey_nid_bio(bp,x,nid,kstr,klen,cb,u);
end;

function Load_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY_CTX; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  d2i_PKCS8PrivateKey_bio := LoadLibCryptoFunction('d2i_PKCS8PrivateKey_bio');
  if not assigned(d2i_PKCS8PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS8PrivateKey_bio');
  Result := d2i_PKCS8PrivateKey_bio(bp,x,cb,u);
end;

function Load_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl;
begin
  PEM_read_bio_Parameters := LoadLibCryptoFunction('PEM_read_bio_Parameters');
  if not assigned(PEM_read_bio_Parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_read_bio_Parameters');
  Result := PEM_read_bio_Parameters(bp,x);
end;

function Load_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_Parameters := LoadLibCryptoFunction('PEM_write_bio_Parameters');
  if not assigned(PEM_write_bio_Parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_Parameters');
  Result := PEM_write_bio_Parameters(bp,x);
end;

function Load_b2i_PrivateKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  b2i_PrivateKey := LoadLibCryptoFunction('b2i_PrivateKey');
  if not assigned(b2i_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PrivateKey');
  Result := b2i_PrivateKey(in_,length);
end;

function Load_b2i_PublicKey(const in_: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  b2i_PublicKey := LoadLibCryptoFunction('b2i_PublicKey');
  if not assigned(b2i_PublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PublicKey');
  Result := b2i_PublicKey(in_,length);
end;

function Load_b2i_PrivateKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
begin
  b2i_PrivateKey_bio := LoadLibCryptoFunction('b2i_PrivateKey_bio');
  if not assigned(b2i_PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PrivateKey_bio');
  Result := b2i_PrivateKey_bio(in_);
end;

function Load_b2i_PublicKey_bio(in_: PBIO): PEVP_PKEY; cdecl;
begin
  b2i_PublicKey_bio := LoadLibCryptoFunction('b2i_PublicKey_bio');
  if not assigned(b2i_PublicKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PublicKey_bio');
  Result := b2i_PublicKey_bio(in_);
end;

function Load_i2b_PrivateKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2b_PrivateKey_bio := LoadLibCryptoFunction('i2b_PrivateKey_bio');
  if not assigned(i2b_PrivateKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PrivateKey_bio');
  Result := i2b_PrivateKey_bio(out_,pk);
end;

function Load_i2b_PublicKey_bio(out_: PBIO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2b_PublicKey_bio := LoadLibCryptoFunction('i2b_PublicKey_bio');
  if not assigned(i2b_PublicKey_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PublicKey_bio');
  Result := i2b_PublicKey_bio(out_,pk);
end;

function Load_b2i_PVK_bio(in_: PBIO; cb: pem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
begin
  b2i_PVK_bio := LoadLibCryptoFunction('b2i_PVK_bio');
  if not assigned(b2i_PVK_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('b2i_PVK_bio');
  Result := b2i_PVK_bio(in_,cb,u);
end;

function Load_i2b_PVK_bio(out_: PBIO; pk: PEVP_PKEY; enclevel: TOpenSSL_C_INT; cb: pem_password_cb; u: Pointer): TOpenSSL_C_INT; cdecl;
begin
  i2b_PVK_bio := LoadLibCryptoFunction('i2b_PVK_bio');
  if not assigned(i2b_PVK_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2b_PVK_bio');
  Result := i2b_PVK_bio(out_,pk,enclevel,cb,u);
end;


procedure UnLoad;
begin
  PEM_get_EVP_CIPHER_INFO := Load_PEM_get_EVP_CIPHER_INFO;
  PEM_do_header := Load_PEM_do_header;
  PEM_read_bio := Load_PEM_read_bio;
  PEM_read_bio_ex := Load_PEM_read_bio_ex;
  PEM_bytes_read_bio_secmem := Load_PEM_bytes_read_bio_secmem;
  PEM_write_bio := Load_PEM_write_bio;
  PEM_bytes_read_bio := Load_PEM_bytes_read_bio;
  PEM_ASN1_read_bio := Load_PEM_ASN1_read_bio;
  PEM_ASN1_write_bio := Load_PEM_ASN1_write_bio;
  PEM_X509_INFO_read_bio := Load_PEM_X509_INFO_read_bio;
  PEM_X509_INFO_write_bio := Load_PEM_X509_INFO_write_bio;
  PEM_SignInit := Load_PEM_SignInit;
  PEM_SignUpdate := Load_PEM_SignUpdate;
  PEM_SignFinal := Load_PEM_SignFinal;
  PEM_def_callback := Load_PEM_def_callback;
  PEM_proc_type := Load_PEM_proc_type;
  PEM_dek_info := Load_PEM_dek_info;
  PEM_read_bio_X509 := Load_PEM_read_bio_X509;
  PEM_write_bio_X509 := Load_PEM_write_bio_X509;
  PEM_read_bio_X509_AUX := Load_PEM_read_bio_X509_AUX;
  PEM_write_bio_X509_AUX := Load_PEM_write_bio_X509_AUX;
  PEM_read_bio_X509_REQ := Load_PEM_read_bio_X509_REQ;
  PEM_write_bio_X509_REQ := Load_PEM_write_bio_X509_REQ;
  PEM_write_bio_X509_REQ_NEW := Load_PEM_write_bio_X509_REQ_NEW;
  PEM_read_bio_X509_CRL := Load_PEM_read_bio_X509_CRL;
  PEM_write_bio_X509_CRL := Load_PEM_write_bio_X509_CRL;
  PEM_read_bio_PKCS7 := Load_PEM_read_bio_PKCS7;
  PEM_write_bio_PKCS7 := Load_PEM_write_bio_PKCS7;
  PEM_read_bio_PKCS8 := Load_PEM_read_bio_PKCS8;
  PEM_write_bio_PKCS8 := Load_PEM_write_bio_PKCS8;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := Load_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := Load_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
  PEM_read_bio_RSAPrivateKey := Load_PEM_read_bio_RSAPrivateKey;
  PEM_write_bio_RSAPrivateKey := Load_PEM_write_bio_RSAPrivateKey;
  PEM_read_bio_RSAPublicKey := Load_PEM_read_bio_RSAPublicKey;
  PEM_write_bio_RSAPublicKey := Load_PEM_write_bio_RSAPublicKey;
  PEM_read_bio_RSA_PUBKEY := Load_PEM_read_bio_RSA_PUBKEY;
  PEM_write_bio_RSA_PUBKEY := Load_PEM_write_bio_RSA_PUBKEY;
  PEM_read_bio_DSAPrivateKey := Load_PEM_read_bio_DSAPrivateKey;
  PEM_write_bio_DSAPrivateKey := Load_PEM_write_bio_DSAPrivateKey;
  PEM_read_bio_DSA_PUBKEY := Load_PEM_read_bio_DSA_PUBKEY;
  PEM_write_bio_DSA_PUBKEY := Load_PEM_write_bio_DSA_PUBKEY;
  PEM_read_bio_DSAparams := Load_PEM_read_bio_DSAparams;
  PEM_write_bio_DSAparams := Load_PEM_write_bio_DSAparams;
  PEM_read_bio_ECPKParameters := Load_PEM_read_bio_ECPKParameters;
  PEM_write_bio_ECPKParameters := Load_PEM_write_bio_ECPKParameters;
  PEM_read_bio_ECPrivateKey := Load_PEM_read_bio_ECPrivateKey;
  PEM_write_bio_ECPrivateKey := Load_PEM_write_bio_ECPrivateKey;
  PEM_read_bio_EC_PUBKEY := Load_PEM_read_bio_EC_PUBKEY;
  PEM_write_bio_EC_PUBKEY := Load_PEM_write_bio_EC_PUBKEY;
  PEM_read_bio_DHparams := Load_PEM_read_bio_DHparams;
  PEM_write_bio_DHparams := Load_PEM_write_bio_DHparams;
  PEM_write_bio_DHxparams := Load_PEM_write_bio_DHxparams;
  PEM_read_bio_PrivateKey := Load_PEM_read_bio_PrivateKey;
  PEM_write_bio_PrivateKey := Load_PEM_write_bio_PrivateKey;
  PEM_read_bio_PUBKEY := Load_PEM_read_bio_PUBKEY;
  PEM_write_bio_PUBKEY := Load_PEM_write_bio_PUBKEY;
  PEM_write_bio_PrivateKey_traditional := Load_PEM_write_bio_PrivateKey_traditional;
  PEM_write_bio_PKCS8PrivateKey_nid := Load_PEM_write_bio_PKCS8PrivateKey_nid;
  PEM_write_bio_PKCS8PrivateKey := Load_PEM_write_bio_PKCS8PrivateKey;
  i2d_PKCS8PrivateKey_bio := Load_i2d_PKCS8PrivateKey_bio;
  i2d_PKCS8PrivateKey_nid_bio := Load_i2d_PKCS8PrivateKey_nid_bio;
  d2i_PKCS8PrivateKey_bio := Load_d2i_PKCS8PrivateKey_bio;
  PEM_read_bio_Parameters := Load_PEM_read_bio_Parameters;
  PEM_write_bio_Parameters := Load_PEM_write_bio_Parameters;
  b2i_PrivateKey := Load_b2i_PrivateKey;
  b2i_PublicKey := Load_b2i_PublicKey;
  b2i_PrivateKey_bio := Load_b2i_PrivateKey_bio;
  b2i_PublicKey_bio := Load_b2i_PublicKey_bio;
  i2b_PrivateKey_bio := Load_i2b_PrivateKey_bio;
  i2b_PublicKey_bio := Load_i2b_PublicKey_bio;
  b2i_PVK_bio := Load_b2i_PVK_bio;
  i2b_PVK_bio := Load_i2b_PVK_bio;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
