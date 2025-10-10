(* This unit was generated from the source file evp.h2pas 
It should not be modified directly. All changes should be made to evp.h2pas
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


unit IdOpenSSLHeaders_evp;


interface

// Headers for OpenSSL 1.1.1
// evp.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_obj_mac,
  IdOpenSSLHeaders_ossl_typ;

const
  EVP_MAX_MD_SIZE = 64; // longest known is SHA512
  EVP_MAX_KEY_LENGTH = 64;
  EVP_MAX_IV_LENGTH = 16;
  EVP_MAX_BLOCK_LENGTH = 32;
  PKCS5_SALT_LEN = 8;
  // Default PKCS#5 iteration count
  PKCS5_DEFAULT_ITER = 2048;
  EVP_PK_RSA = $0001;
  EVP_PK_DSA = $0002;
  EVP_PK_DH  = $0004;
  EVP_PK_EC = $0008;
  EVP_PKT_SIGN = $0010;
  EVP_PKT_ENC = $0020;
  EVP_PKT_EXCH = $0040;
  EVP_PKS_RSA = $0100;
  EVP_PKS_DSA = $0200;
  EVP_PKS_EC = $0400;

  EVP_PKEY_NONE = NID_undef;
  EVP_PKEY_RSA = NID_rsaEncryption;
  EVP_PKEY_RSA2 = NID_rsa;
  EVP_PKEY_RSA_PSS = NID_rsassaPss;
  EVP_PKEY_DSA = NID_dsa;
  EVP_PKEY_DSA1 = NID_dsa_2;
  EVP_PKEY_DSA2 = NID_dsaWithSHA;
  EVP_PKEY_DSA3 = NID_dsaWithSHA1;
  EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;
  EVP_PKEY_DH = NID_dhKeyAgreement;
  EVP_PKEY_DHX = NID_dhpublicnumber;
  EVP_PKEY_EC = NID_X9_62_id_ecPublicKey;
  EVP_PKEY_SM2 = NID_sm2;
  EVP_PKEY_HMAC = NID_hmac;
  EVP_PKEY_CMAC = NID_cmac;
  EVP_PKEY_SCRYPT = NID_id_scrypt;
  EVP_PKEY_TLS1_PRF = NID_tls1_prf;
  EVP_PKEY_HKDF = NID_hkdf;
  EVP_PKEY_POLY1305 = NID_poly1305;
  EVP_PKEY_SIPHASH = NID_siphash;
  EVP_PKEY_X25519 = NID_X25519;
  EVP_PKEY_ED25519 = NID_ED25519;
  EVP_PKEY_X448 = NID_X448;
  EVP_PKEY_ED448 = NID_ED448;

  EVP_PKEY_MO_SIGN = $0001;
  EVP_PKEY_MO_VERIFY = $0002;
  EVP_PKEY_MO_ENCRYPT = $0004;
  EVP_PKEY_MO_DECRYPT = $0008;

// digest can only handle a single block ///
  EVP_MD_FLAG_ONESHOT = $0001;

// digest is extensible-output function; XOF ///

  EVP_MD_FLAG_XOF = $0002;

// DigestAlgorithmIdentifier flags... ///

  EVP_MD_FLAG_DIGALGID_MASK = $0018;

// NULL or absent parameter accepted. Use NULL ///

  EVP_MD_FLAG_DIGALGID_NULL = $0000;

// NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent ///

  EVP_MD_FLAG_DIGALGID_ABSENT = $0008;

// Custom handling via ctrl ///

  EVP_MD_FLAG_DIGALGID_CUSTOM = $0018;

// Note if suitable for use in FIPS mode ///

  EVP_MD_FLAG_FIPS = $0400;

// Digest ctrls ///

  EVP_MD_CTRL_DIGALGID = $1;
  EVP_MD_CTRL_MICALG = $2;
  EVP_MD_CTRL_XOF_LEN = $3;

// Minimum Algorithm specific ctrl value ///

  EVP_MD_CTRL_ALG_CTRL = $1000;
 // not EVP_MD ///

// values for EVP_MD_CTX flags ///
  EVP_MD_CTX_FLAG_ONESHOT = $0001;
  EVP_MD_CTX_FLAG_CLEANED = $0002;
  EVP_MD_CTX_FLAG_REUSE = $0004;
//
 // FIPS and pad options are ignored in 1.0.0; definitions are here so we
 // don't accidentally reuse the values for other purposes.
 ///

  EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = $0008;

//
 // The following PAD options are also currently ignored in 1.0.0; digest
 // parameters are handled through EVP_DigestSign//() and EVP_DigestVerify//()
 // instead.
 ///
  EVP_MD_CTX_FLAG_PAD_MASK = $F0;
  EVP_MD_CTX_FLAG_PAD_PKCS1 = $00;
  EVP_MD_CTX_FLAG_PAD_X931 = $10;
  EVP_MD_CTX_FLAG_PAD_PSS = $20;

  EVP_MD_CTX_FLAG_NO_INIT = $0100;
//
 // Some functions such as EVP_DigestSign only finalise copies of internal
 // contexts so additional data can be included after the finalisation call.
 // This is inefficient if this functionality is not required: it is disabled
 // if the following flag is set.
 ///
  EVP_MD_CTX_FLAG_FINALISE = $0200;


// NOTE: $0400 is reserved for internal usage ///
// Values for cipher flags ///

// Modes for ciphers ///

  EVP_CIPH_STREAM_CIPHER = $0;
  EVP_CIPH_ECB_MODE = $1;
  EVP_CIPHC_MODE = $2;
  EVP_CIPH_CFB_MODE = $3;
  EVP_CIPH_OFB_MODE = $4;
  EVP_CIPH_CTR_MODE = $5;
  EVP_CIPH_GCM_MODE = $6;
  EVP_CIPH_CCM_MODE = $7;
  EVP_CIPH_XTS_MODE = $10001;
  EVP_CIPH_WRAP_MODE = $10002;
  EVP_CIPH_OCB_MODE = $10003;
  EVP_CIPH_MODE = $F0007;
// Set if variable length cipher ///
  EVP_CIPH_VARIABLE_LENGTH = $8;
// Set if the iv handling should be done by the cipher itself ///
  EVP_CIPH_CUSTOM_IV = $10;
// Set if the cipher's init() function should be called if key is NULL ///
  EVP_CIPH_ALWAYS_CALL_INIT = $20;
// Call ctrl() to init cipher parameters ///
  EVP_CIPH_CTRL_INIT = $40;
// Don't use standard key length function ///
  EVP_CIPH_CUSTOM_KEY_LENGTH = $80;
// Don't use standard block padding ///
  EVP_CIPH_NO_PADDING = $100;
// cipher handles random key generation ///
  EVP_CIPH_RAND_KEY = $200;
// cipher has its own additional copying logic ///
  EVP_CIPH_CUSTOM_COPY = $400;
// Don't use standard iv length function ///
  EVP_CIPH_CUSTOM_IV_LENGTH = $800;
// Allow use default ASN1 get/set iv ///
  EVP_CIPH_FLAG_DEFAULT_ASN1 = $1000;
// Buffer length in bits not bytes: CFB1 mode only ///
  EVP_CIPH_FLAG_LENGTH_BITS = $2000;
// Note if suitable for use in FIPS mode ///
  EVP_CIPH_FLAG_FIPS = $4000;
// Allow non FIPS cipher in FIPS mode ///
  EVP_CIPH_FLAG_NON_FIPS_ALLOW = $8000;
//
 // Cipher handles any and all padding logic as well as finalisation.
 ///
  EVP_CIPH_FLAG_CUSTOM_CIPHER = $100000;
  EVP_CIPH_FLAG_AEAD_CIPHER = $200000;
  EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK = $400000;
// Cipher can handle pipeline operations ///
  EVP_CIPH_FLAG_PIPELINE = $800000;

//
 // Cipher context flag to indicate we can handle wrap mode: if allowed in
 // older applications it could overflow buffers.
 ///

  EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = $1;

// ctrl() values ///

  EVP_CTRL_INIT = $0;
  EVP_CTRL_SET_KEY_LENGTH = $1;
  EVP_CTRL_GET_RC2_KEY_BITS = $2;
  EVP_CTRL_SET_RC2_KEY_BITS = $3;
  EVP_CTRL_GET_RC5_ROUNDS = $4;
  EVP_CTRL_SET_RC5_ROUNDS = $5;
  EVP_CTRL_RAND_KEY = $6;
  EVP_CTRL_PBE_PRF_NID = $7;
  EVP_CTRL_COPY = $8;
  EVP_CTRL_AEAD_SET_IVLEN = $9;
  EVP_CTRL_AEAD_GET_TAG = $10;
  EVP_CTRL_AEAD_SET_TAG = $11;
  EVP_CTRL_AEAD_SET_IV_FIXED = $12;
  EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;
  EVP_CTRL_GCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;
  EVP_CTRL_GCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;
  EVP_CTRL_GCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;
  EVP_CTRL_GCM_IV_GEN = $13;
  EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;
  EVP_CTRL_CCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;
  EVP_CTRL_CCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;
  EVP_CTRL_CCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;
  EVP_CTRL_CCM_SET_L = $14;
  EVP_CTRL_CCM_SET_MSGLEN = $15;
//
 // AEAD cipher deduces payload length and returns number of bytes required to
 // store MAC and eventual padding. Subsequent call to EVP_Cipher even
 // appends/verifies MAC.
 ///
  EVP_CTRL_AEAD_TLS1_AAD = $16;
// Used by composite AEAD ciphers; no-op in GCM; CCM... ///
  EVP_CTRL_AEAD_SET_MAC_KEY = $17;
// Set the GCM invocation field; decrypt only ///
  EVP_CTRL_GCM_SET_IV_INV = $18;

  EVP_CTRL_TLS1_1_MULTIBLOCK_AAD = $19;
  EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT = $1a;
  EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT = $1b;
  EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = $1c;

  EVP_CTRL_SSL3_MASTER_SECRET = $1d;

// EVP_CTRL_SET_SBOX takes the PAnsiChar// specifying S-boxes///
  EVP_CTRL_SET_SBOX = $1e;
//
// EVP_CTRL_SBOX_USED takes a 'TOpenSSL_C_SIZET' and 'PAnsiChar//'; pointing at a
// pre-allocated buffer with specified size
///
  EVP_CTRL_SBOX_USED = $1f;
// EVP_CTRL_KEY_MESH takes 'TOpenSSL_C_SIZET' number of bytes to mesh the key after;
// 0 switches meshing off
///
  EVP_CTRL_KEY_MESH = $20;
// EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode///
  EVP_CTRL_BLOCK_PADDING_MODE = $21;

// Set the output buffers to use for a pipelined operation///
  EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS = $22;
// Set the input buffers to use for a pipelined operation///
  EVP_CTRL_SET_PIPELINE_INPUT_BUFS = $23;
// Set the input buffer lengths to use for a pipelined operation///
  EVP_CTRL_SET_PIPELINE_INPUT_LENS = $24;

  EVP_CTRL_GET_IVLEN = $25;

// Padding modes///
  EVP_PADDING_PKCS7 = 1;
  EVP_PADDING_ISO7816_4 = 2;
  EVP_PADDING_ANSI923 = 3;
  EVP_PADDING_ISO10126 = 4;
  EVP_PADDING_ZERO = 5;

// RFC 5246 defines additional data to be 13 bytes in length///
  EVP_AEAD_TLS1_AAD_LEN = 13;

// GCM TLS constants///
// Length of fixed part of IV derived from PRF///
  EVP_GCM_TLS_FIXED_IV_LEN = 4;
// Length of explicit part of IV part of TLS records///
  EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;
// Length of tag for TLS
  EVP_GCM_TLS_TAG_LEN = 16;

/// CCM TLS constants ///
/// Length of fixed part of IV derived from PRF ///
  EVP_CCM_TLS_FIXED_IV_LEN = 4;
/// Length of explicit part of IV part of TLS records ///
  EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;
/// Total length of CCM IV length for TLS ///
  EVP_CCM_TLS_IV_LEN = 12;
/// Length of tag for TLS ///
  EVP_CCM_TLS_TAG_LEN = 16;
/// Length of CCM8 tag for TLS ///
  EVP_CCM8_TLS_TAG_LEN = 8;

/// Length of tag for TLS ///
  EVP_CHACHAPOLY_TLS_TAG_LEN = 16;

(* Can appear as the outermost AlgorithmIdentifier *)
  EVP_PBE_TYPE_OUTER = $0;
(* Is an PRF type OID *)
  EVP_PBE_TYPE_PRF = $1;
(* Is a PKCS#5 v2.0 KDF *)
  EVP_PBE_TYPE_KDF = $2;

  ASN1_PKEY_ALIAS = $1;
  ASN1_PKEY_DYNAMIC = $2;
  ASN1_PKEY_SIGPARAM_NULL = $4;

  ASN1_PKEY_CTRL_PKCS7_SIGN = $1;
  ASN1_PKEY_CTRL_PKCS7_ENCRYPT = $2;
  ASN1_PKEY_CTRL_DEFAULT_MD_NID = $3;
  ASN1_PKEY_CTRL_CMS_SIGN = $5;
  ASN1_PKEY_CTRL_CMS_ENVELOPE = $7;
  ASN1_PKEY_CTRL_CMS_RI_TYPE = $8;

  ASN1_PKEY_CTRL_SET1_TLS_ENCPT = $9;
  ASN1_PKEY_CTRL_GET1_TLS_ENCPT = $a;

  EVP_PKEY_OP_UNDEFINED = 0;
  EVP_PKEY_OP_PARAMGEN = (1 shl 1);
  EVP_PKEY_OP_KEYGEN = (1 shl 2);
  EVP_PKEY_OP_SIGN = (1 shl 3);
  EVP_PKEY_OP_VERIFY = (1 shl 4);
  EVP_PKEY_OP_VERIFYRECOVER = (1 shl 5);
  EVP_PKEY_OP_SIGNCTX = (1 shl 6);
  EVP_PKEY_OP_VERIFYCTX = (1 shl 7);
  EVP_PKEY_OP_ENCRYPT = (1 shl 8);
  EVP_PKEY_OP_DECRYPT = (1 shl 9);
  EVP_PKEY_OP_DERIVE = (1 shl 10);

  EVP_PKEY_OP_TYPE_SIG = EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY
    or EVP_PKEY_OP_VERIFYRECOVER or EVP_PKEY_OP_SIGNCTX or EVP_PKEY_OP_VERIFYCTX;

  EVP_PKEY_OP_TYPE_CRYPT = EVP_PKEY_OP_ENCRYPT or EVP_PKEY_OP_DECRYPT;

  EVP_PKEY_OP_TYPE_NOGEN = EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_DERIVE;

  EVP_PKEY_OP_TYPE_GEN = EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN;

  EVP_PKEY_CTRL_MD = 1;
  EVP_PKEY_CTRL_PEER_KEY = 2;

  EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
  EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;

  EVP_PKEY_CTRL_PKCS7_SIGN = 5;

  EVP_PKEY_CTRL_SET_MAC_KEY = 6;

  EVP_PKEY_CTRL_DIGESTINIT = 7;

(* Used by GOST key encryption in TLS *)
  EVP_PKEY_CTRL_SET_IV = 8;

  EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
  EVP_PKEY_CTRL_CMS_DECRYPT = 10;
  EVP_PKEY_CTRL_CMS_SIGN = 11;

  EVP_PKEY_CTRL_CIPHER = 12;

  EVP_PKEY_CTRL_GET_MD = 13;

  EVP_PKEY_CTRL_SET_DIGEST_SIZE = 14;

  EVP_PKEY_ALG_CTRL = $1000;

  EVP_PKEY_FLAG_AUTOARGLEN = 2;
  //
 // Method handles all operations: don't assume any digest related defaults.
 //
  EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;

type
  EVP_MD_meth_init = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_update = function(ctx: PEVP_MD_CTX; const data: Pointer;
    count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_final = function(ctx: PEVP_MD_CTX; const md: PByte): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_copy = function(to_: PEVP_MD_CTX; const from: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_cleanup = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_ctrl = function(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT;
    p2: Pointer): TOpenSSL_C_INT; cdecl;

  EVP_CIPHER_meth_init = function(ctx: PEVP_CIPHER_CTX; const key: PByte;
    const iv: PByte; enc: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_do_cipher = function(ctx: PEVP_CIPHER_CTX; out_: PByte;
    const in_: PByte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_cleanup = function(v1: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_set_asn1_params = function(v1: PEVP_CIPHER_CTX;
    v2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_get_asn1_params = function(v1: PEVP_CIPHER_CTX;
    v2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_ctrl = function(v1: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT;
    arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl;

  EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = record
    out_: PByte;
    inp: PByte;
    len: TOpenSSL_C_SIZET;
    interleave: TOpenSSL_C_UINT;
  end;

  evp_cipher_info_st = record
    cipher: PEVP_CIPHER;
    iv: array[0 .. EVP_MAX_IV_LENGTH - 1] of PByte;
  end;
  EVP_CIPHER_INFO = evp_cipher_info_st;

  EVP_MD_CTX_update = function(ctx: PEVP_MD_CTX; const data: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

  fn = procedure(const ciph: PEVP_CIPHER; const from: PAnsiChar; const to_: PAnsiChar; x: Pointer); cdecl;

  pub_decode = function(pk: PEVP_PKEY; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
  pub_encode = function(pub: PX509_PUBKEY; const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pub_cmd = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pub_print = function(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  pkey_size = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pkey_bits = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

  priv_decode = function(pk: PEVP_PKEY; const p8inf: PKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
  priv_encode = function(p8: PPKCS8_PRIV_KEY_INFO; const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  priv_print = function(out_: PBIO; const pkea: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;

  param_decode = function(pkey: PEVP_PKEY; const pder: PPByte; derlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  param_encode = function(const pkey: PEVP_PKEY; pder: PPByte): TOpenSSL_C_INT; cdecl;
  param_missing = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  param_copy = function(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  param_cmp = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  param_print = function(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;

  pkey_free = procedure(pkey: PEVP_PKEY); cdecl;
  pkey_ctrl = function(pkey: PEVP_PKEY; op: TOpenSSL_C_INT; arg1: TOpenSSL_C_LONG; arg2: Pointer): TOpenSSL_C_INT; cdecl;
  item_verify = function(ctx: PEVP_MD_CTX; const it: PASN1_ITEM; asn: Pointer;
    a: PX509_ALGOR; sig: PASN1_BIT_STRING; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  item_sign = function(ctx: PEVP_MD_CTX; const it: PASN1_ITEM; asn: Pointer;
    alg1: PX509_ALGOR; alg2: PX509_ALGOR; sig: PASN1_BIT_STRING): TOpenSSL_C_INT; cdecl;
  siginf_set = function(siginf: PX509_SIG_INFO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl;
  pkey_check = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pkey_pub_check = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pkey_param_check = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  set_priv_key = function(pk: PEVP_PKEY; const priv: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  set_pub_key = function(pk: PEVP_PKEY; const pub: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  get_priv_key = function(const pk: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  get_pub_key = function(const pk: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  pkey_security_bits = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

  EVP_PKEY_gen_cb = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
//  PEVP_PKEY_gen_cb = ^EVP_PKEY_gen_cb;

  EVP_PKEY_meth_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_init = ^EVP_PKEY_meth_init;
  EVP_PKEY_meth_copy_cb = function(dst: PEVP_PKEY_CTX; src: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_copy = ^EVP_PKEY_meth_copy_cb;
  EVP_PKEY_meth_cleanup = procedure(ctx: PEVP_PKEY_CTX); cdecl;
  PEVP_PKEY_meth_cleanup = ^EVP_PKEY_meth_cleanup;
  EVP_PKEY_meth_paramgen_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_paramgen_init = ^EVP_PKEY_meth_paramgen_init;
  EVP_PKEY_meth_paramgen = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_paramgen = ^EVP_PKEY_meth_paramgen;
  EVP_PKEY_meth_keygen_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_keygen_init = ^EVP_PKEY_meth_keygen_init;
  EVP_PKEY_meth_keygen = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_keygen = ^EVP_PKEY_meth_keygen;
  EVP_PKEY_meth_sign_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_sign_init = ^EVP_PKEY_meth_sign_init;
  EVP_PKEY_meth_sign = function(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: TOpenSSL_C_SIZET;
    const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_sign = ^EVP_PKEY_meth_sign;
  EVP_PKEY_meth_verify_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify_init = ^EVP_PKEY_meth_verify_init;
  EVP_PKEY_meth_verify = function(ctx: PEVP_PKEY_CTX; const sig: PByte;
    siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify = ^EVP_PKEY_meth_verify;
  EVP_PKEY_meth_verify_recover_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify_recover_init = ^EVP_PKEY_meth_verify_recover_init;
  EVP_PKEY_meth_verify_recover = function(ctx: PEVP_PKEY_CTX; sig: PByte;
    siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify_recover = ^EVP_PKEY_meth_verify_recover;
  EVP_PKEY_meth_signctx_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_signctx_init = ^EVP_PKEY_meth_signctx_init;
  EVP_PKEY_meth_signctx = function(ctx: PEVP_PKEY_CTX; sig: Pbyte;
    siglen: TOpenSSL_C_SIZET; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_signctx = ^EVP_PKEY_meth_signctx;
  EVP_PKEY_meth_verifyctx_init = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verifyctx_init = ^EVP_PKEY_meth_verifyctx_init;
  EVP_PKEY_meth_verifyctx = function(ctx: PEVP_PKEY_CTX; const sig: PByte;
    siglen: TOpenSSL_C_INT; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verifyctx = ^EVP_PKEY_meth_verifyctx;
  EVP_PKEY_meth_encrypt_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_encrypt_init = ^EVP_PKEY_meth_encrypt_init;
  EVP_PKEY_meth_encrypt = function(ctx: PEVP_PKEY_CTX; out_: PByte;
    outlen: TOpenSSL_C_SIZET; const in_: PByte): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_encrypt = ^ EVP_PKEY_meth_encrypt;
  EVP_PKEY_meth_decrypt_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_decrypt_init = ^EVP_PKEY_meth_decrypt_init;
  EVP_PKEY_meth_decrypt = function(ctx: PEVP_PKEY_CTX; out_: PByte;
    outlen: TOpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_decrypt = ^EVP_PKEY_meth_decrypt;
  EVP_PKEY_meth_derive_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_derive_init = ^EVP_PKEY_meth_derive_init;
  EVP_PKEY_meth_derive = function(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_derive = ^EVP_PKEY_meth_derive;
  EVP_PKEY_meth_ctrl = function(ctx: PEVP_PKEY_CTX; type_: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_ctrl = ^EVP_PKEY_meth_ctrl;
  EVP_PKEY_meth_ctrl_str = function(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_ctrl_str = ^EVP_PKEY_meth_ctrl_str;
  EVP_PKEY_meth_digestsign = function(ctx: PEVP_PKEY_CTX; sig: PByte;
    siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_digestsign = ^EVP_PKEY_meth_digestsign;
  EVP_PKEY_meth_digestverify = function(ctx: PEVP_MD_CTX; const sig: PByte;
    siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_digestverify = ^EVP_PKEY_meth_digestverify;
  EVP_PKEY_meth_check = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_check = ^EVP_PKEY_meth_check;
  EVP_PKEY_meth_public_check = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_public_check = ^EVP_PKEY_meth_public_check;
  EVP_PKEY_meth_param_check = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_param_check = ^EVP_PKEY_meth_param_check;
  EVP_PKEY_meth_digest_custom = function(pkey: PEVP_PKEY; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_digest_custom = ^EVP_PKEY_meth_digest_custom;

  // Password based encryption function
  EVP_PBE_KEYGEN = function(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar;
    passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER;
    const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  PEVP_PBE_KEYGEN = ^EVP_PBE_KEYGEN;
  PPEVP_PBE_KEYGEN = ^PEVP_PBE_KEYGEN;


{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM EVP_MD_meth_new}
{$EXTERNALSYM EVP_MD_meth_dup}
{$EXTERNALSYM EVP_MD_meth_free}
{$EXTERNALSYM EVP_MD_meth_set_input_blocksize}
{$EXTERNALSYM EVP_MD_meth_set_result_size}
{$EXTERNALSYM EVP_MD_meth_set_app_datasize}
{$EXTERNALSYM EVP_MD_meth_set_flags}
{$EXTERNALSYM EVP_MD_meth_set_init}
{$EXTERNALSYM EVP_MD_meth_set_update}
{$EXTERNALSYM EVP_MD_meth_set_final}
{$EXTERNALSYM EVP_MD_meth_set_copy}
{$EXTERNALSYM EVP_MD_meth_set_cleanup}
{$EXTERNALSYM EVP_MD_meth_set_ctrl}
{$EXTERNALSYM EVP_MD_meth_get_input_blocksize}
{$EXTERNALSYM EVP_MD_meth_get_result_size}
{$EXTERNALSYM EVP_MD_meth_get_app_datasize}
{$EXTERNALSYM EVP_MD_meth_get_flags}
{$EXTERNALSYM EVP_MD_meth_get_init}
{$EXTERNALSYM EVP_MD_meth_get_update}
{$EXTERNALSYM EVP_MD_meth_get_final}
{$EXTERNALSYM EVP_MD_meth_get_copy}
{$EXTERNALSYM EVP_MD_meth_get_cleanup}
{$EXTERNALSYM EVP_MD_meth_get_ctrl}
{$EXTERNALSYM EVP_CIPHER_meth_new}
{$EXTERNALSYM EVP_CIPHER_meth_dup}
{$EXTERNALSYM EVP_CIPHER_meth_free}
{$EXTERNALSYM EVP_CIPHER_meth_set_iv_length}
{$EXTERNALSYM EVP_CIPHER_meth_set_flags}
{$EXTERNALSYM EVP_CIPHER_meth_set_impl_ctx_size}
{$EXTERNALSYM EVP_CIPHER_meth_set_init}
{$EXTERNALSYM EVP_CIPHER_meth_set_do_cipher}
{$EXTERNALSYM EVP_CIPHER_meth_set_cleanup}
{$EXTERNALSYM EVP_CIPHER_meth_set_set_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_set_get_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_set_ctrl}
{$EXTERNALSYM EVP_CIPHER_meth_get_init}
{$EXTERNALSYM EVP_CIPHER_meth_get_do_cipher}
{$EXTERNALSYM EVP_CIPHER_meth_get_cleanup}
{$EXTERNALSYM EVP_CIPHER_meth_get_set_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_get_get_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_get_ctrl}
{$EXTERNALSYM EVP_MD_CTX_md}
{$EXTERNALSYM EVP_MD_CTX_update_fn}
{$EXTERNALSYM EVP_MD_CTX_set_update_fn}
{$EXTERNALSYM EVP_MD_CTX_set_pkey_ctx}
{$EXTERNALSYM EVP_CIPHER_impl_ctx_size}
{$EXTERNALSYM EVP_CIPHER_CTX_cipher}
{$EXTERNALSYM EVP_CIPHER_CTX_iv}
{$EXTERNALSYM EVP_CIPHER_CTX_original_iv}
{$EXTERNALSYM EVP_CIPHER_CTX_iv_noconst}
{$EXTERNALSYM EVP_CIPHER_CTX_buf_noconst}
{$EXTERNALSYM EVP_CIPHER_CTX_set_num}
{$EXTERNALSYM EVP_CIPHER_CTX_copy}
{$EXTERNALSYM EVP_CIPHER_CTX_get_app_data}
{$EXTERNALSYM EVP_CIPHER_CTX_set_app_data}
{$EXTERNALSYM EVP_CIPHER_CTX_get_cipher_data}
{$EXTERNALSYM EVP_CIPHER_CTX_set_cipher_data}
{$EXTERNALSYM EVP_MD_CTX_ctrl}
{$EXTERNALSYM EVP_MD_CTX_new}
{$EXTERNALSYM EVP_MD_CTX_reset}
{$EXTERNALSYM EVP_MD_CTX_free}
{$EXTERNALSYM EVP_MD_CTX_copy_ex}
{$EXTERNALSYM EVP_MD_CTX_set_flags}
{$EXTERNALSYM EVP_MD_CTX_clear_flags}
{$EXTERNALSYM EVP_MD_CTX_test_flags}
{$EXTERNALSYM EVP_DigestInit_ex}
{$EXTERNALSYM EVP_DigestUpdate}
{$EXTERNALSYM EVP_DigestFinal_ex}
{$EXTERNALSYM EVP_Digest}
{$EXTERNALSYM EVP_MD_CTX_copy}
{$EXTERNALSYM EVP_DigestInit}
{$EXTERNALSYM EVP_DigestFinal}
{$EXTERNALSYM EVP_DigestFinalXOF}
{$EXTERNALSYM EVP_read_pw_string}
{$EXTERNALSYM EVP_read_pw_string_min}
{$EXTERNALSYM EVP_set_pw_prompt}
{$EXTERNALSYM EVP_get_pw_prompt}
{$EXTERNALSYM EVP_BytesToKey}
{$EXTERNALSYM EVP_CIPHER_CTX_set_flags}
{$EXTERNALSYM EVP_CIPHER_CTX_clear_flags}
{$EXTERNALSYM EVP_CIPHER_CTX_test_flags}
{$EXTERNALSYM EVP_EncryptInit}
{$EXTERNALSYM EVP_EncryptInit_ex}
{$EXTERNALSYM EVP_EncryptUpdate}
{$EXTERNALSYM EVP_EncryptFinal_ex}
{$EXTERNALSYM EVP_EncryptFinal}
{$EXTERNALSYM EVP_DecryptInit}
{$EXTERNALSYM EVP_DecryptInit_ex}
{$EXTERNALSYM EVP_DecryptUpdate}
{$EXTERNALSYM EVP_DecryptFinal}
{$EXTERNALSYM EVP_DecryptFinal_ex}
{$EXTERNALSYM EVP_CipherInit}
{$EXTERNALSYM EVP_CipherInit_ex}
{$EXTERNALSYM EVP_CipherUpdate}
{$EXTERNALSYM EVP_CipherFinal}
{$EXTERNALSYM EVP_CipherFinal_ex}
{$EXTERNALSYM EVP_SignFinal}
{$EXTERNALSYM EVP_DigestSign}
{$EXTERNALSYM EVP_VerifyFinal}
{$EXTERNALSYM EVP_DigestVerify}
{$EXTERNALSYM EVP_DigestSignInit}
{$EXTERNALSYM EVP_DigestSignFinal}
{$EXTERNALSYM EVP_DigestVerifyInit}
{$EXTERNALSYM EVP_DigestVerifyFinal}
{$EXTERNALSYM EVP_OpenInit}
{$EXTERNALSYM EVP_OpenFinal}
{$EXTERNALSYM EVP_SealInit}
{$EXTERNALSYM EVP_SealFinal}
{$EXTERNALSYM EVP_ENCODE_CTX_new}
{$EXTERNALSYM EVP_ENCODE_CTX_free}
{$EXTERNALSYM EVP_ENCODE_CTX_copy}
{$EXTERNALSYM EVP_ENCODE_CTX_num}
{$EXTERNALSYM EVP_EncodeInit}
{$EXTERNALSYM EVP_EncodeUpdate}
{$EXTERNALSYM EVP_EncodeFinal}
{$EXTERNALSYM EVP_EncodeBlock}
{$EXTERNALSYM EVP_DecodeInit}
{$EXTERNALSYM EVP_DecodeUpdate}
{$EXTERNALSYM EVP_DecodeFinal}
{$EXTERNALSYM EVP_DecodeBlock}
{$EXTERNALSYM EVP_CIPHER_CTX_new}
{$EXTERNALSYM EVP_CIPHER_CTX_reset}
{$EXTERNALSYM EVP_CIPHER_CTX_free}
{$EXTERNALSYM EVP_CIPHER_CTX_set_key_length}
{$EXTERNALSYM EVP_CIPHER_CTX_set_padding}
{$EXTERNALSYM EVP_CIPHER_CTX_ctrl}
{$EXTERNALSYM EVP_CIPHER_CTX_rand_key}
{$EXTERNALSYM BIO_f_md}
{$EXTERNALSYM BIO_f_base64}
{$EXTERNALSYM BIO_f_cipher}
{$EXTERNALSYM BIO_f_reliable}
{$EXTERNALSYM BIO_set_cipher}
{$EXTERNALSYM EVP_md_null}
{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
{$EXTERNALSYM EVP_md5_sha1}
{$EXTERNALSYM EVP_sha1}
{$EXTERNALSYM EVP_sha224}
{$EXTERNALSYM EVP_sha256}
{$EXTERNALSYM EVP_sha384}
{$EXTERNALSYM EVP_sha512}
{$EXTERNALSYM EVP_sha512_224}
{$EXTERNALSYM EVP_sha512_256}
{$EXTERNALSYM EVP_sha3_224}
{$EXTERNALSYM EVP_sha3_256}
{$EXTERNALSYM EVP_sha3_384}
{$EXTERNALSYM EVP_sha3_512}
{$EXTERNALSYM EVP_shake128}
{$EXTERNALSYM EVP_shake256}
{$EXTERNALSYM EVP_enc_null}
{$EXTERNALSYM EVP_des_ecb}
{$EXTERNALSYM EVP_des_ede}
{$EXTERNALSYM EVP_des_ede3}
{$EXTERNALSYM EVP_des_ede_ecb}
{$EXTERNALSYM EVP_des_ede3_ecb}
{$EXTERNALSYM EVP_des_cfb64}
{$EXTERNALSYM EVP_des_cfb1}
{$EXTERNALSYM EVP_des_cfb8}
{$EXTERNALSYM EVP_des_ede_cfb64}
{$EXTERNALSYM EVP_des_ede3_cfb64}
{$EXTERNALSYM EVP_des_ede3_cfb1}
{$EXTERNALSYM EVP_des_ede3_cfb8}
{$EXTERNALSYM EVP_des_ofb}
{$EXTERNALSYM EVP_des_ede_ofb}
{$EXTERNALSYM EVP_des_ede3_ofb}
{$EXTERNALSYM EVP_des_cbc}
{$EXTERNALSYM EVP_des_ede_cbc}
{$EXTERNALSYM EVP_des_ede3_cbc}
{$EXTERNALSYM EVP_desx_cbc}
{$EXTERNALSYM EVP_des_ede3_wrap}
{$EXTERNALSYM EVP_rc4}
{$EXTERNALSYM EVP_rc4_40}
{$EXTERNALSYM EVP_rc2_ecb}
{$EXTERNALSYM EVP_rc2_cbc}
{$EXTERNALSYM EVP_rc2_40_cbc}
{$EXTERNALSYM EVP_rc2_64_cbc}
{$EXTERNALSYM EVP_rc2_cfb64}
{$EXTERNALSYM EVP_rc2_ofb}
{$EXTERNALSYM EVP_bf_ecb}
{$EXTERNALSYM EVP_bf_cbc}
{$EXTERNALSYM EVP_bf_cfb64}
{$EXTERNALSYM EVP_bf_ofb}
{$EXTERNALSYM EVP_cast5_ecb}
{$EXTERNALSYM EVP_cast5_cbc}
{$EXTERNALSYM EVP_cast5_cfb64}
{$EXTERNALSYM EVP_cast5_ofb}
{$EXTERNALSYM EVP_aes_128_ecb}
{$EXTERNALSYM EVP_aes_128_cbc}
{$EXTERNALSYM EVP_aes_128_cfb1}
{$EXTERNALSYM EVP_aes_128_cfb8}
{$EXTERNALSYM EVP_aes_128_cfb128}
{$EXTERNALSYM EVP_aes_128_ofb}
{$EXTERNALSYM EVP_aes_128_ctr}
{$EXTERNALSYM EVP_aes_128_ccm}
{$EXTERNALSYM EVP_aes_128_gcm}
{$EXTERNALSYM EVP_aes_128_xts}
{$EXTERNALSYM EVP_aes_128_wrap}
{$EXTERNALSYM EVP_aes_128_wrap_pad}
{$EXTERNALSYM EVP_aes_128_ocb}
{$EXTERNALSYM EVP_aes_192_ecb}
{$EXTERNALSYM EVP_aes_192_cbc}
{$EXTERNALSYM EVP_aes_192_cfb1}
{$EXTERNALSYM EVP_aes_192_cfb8}
{$EXTERNALSYM EVP_aes_192_cfb128}
{$EXTERNALSYM EVP_aes_192_ofb}
{$EXTERNALSYM EVP_aes_192_ctr}
{$EXTERNALSYM EVP_aes_192_ccm}
{$EXTERNALSYM EVP_aes_192_gcm}
{$EXTERNALSYM EVP_aes_192_wrap}
{$EXTERNALSYM EVP_aes_192_wrap_pad}
{$EXTERNALSYM EVP_aes_192_ocb}
{$EXTERNALSYM EVP_aes_256_ecb}
{$EXTERNALSYM EVP_aes_256_cbc}
{$EXTERNALSYM EVP_aes_256_cfb1}
{$EXTERNALSYM EVP_aes_256_cfb8}
{$EXTERNALSYM EVP_aes_256_cfb128}
{$EXTERNALSYM EVP_aes_256_ofb}
{$EXTERNALSYM EVP_aes_256_ctr}
{$EXTERNALSYM EVP_aes_256_ccm}
{$EXTERNALSYM EVP_aes_256_gcm}
{$EXTERNALSYM EVP_aes_256_xts}
{$EXTERNALSYM EVP_aes_256_wrap}
{$EXTERNALSYM EVP_aes_256_wrap_pad}
{$EXTERNALSYM EVP_aes_256_ocb}
{$EXTERNALSYM EVP_aes_128_cbc_hmac_sha1}
{$EXTERNALSYM EVP_aes_256_cbc_hmac_sha1}
{$EXTERNALSYM EVP_aes_128_cbc_hmac_sha256}
{$EXTERNALSYM EVP_aes_256_cbc_hmac_sha256}
{$EXTERNALSYM EVP_aria_128_ecb}
{$EXTERNALSYM EVP_aria_128_cbc}
{$EXTERNALSYM EVP_aria_128_cfb1}
{$EXTERNALSYM EVP_aria_128_cfb8}
{$EXTERNALSYM EVP_aria_128_cfb128}
{$EXTERNALSYM EVP_aria_128_ctr}
{$EXTERNALSYM EVP_aria_128_ofb}
{$EXTERNALSYM EVP_aria_128_gcm}
{$EXTERNALSYM EVP_aria_128_ccm}
{$EXTERNALSYM EVP_aria_192_ecb}
{$EXTERNALSYM EVP_aria_192_cbc}
{$EXTERNALSYM EVP_aria_192_cfb1}
{$EXTERNALSYM EVP_aria_192_cfb8}
{$EXTERNALSYM EVP_aria_192_cfb128}
{$EXTERNALSYM EVP_aria_192_ctr}
{$EXTERNALSYM EVP_aria_192_ofb}
{$EXTERNALSYM EVP_aria_192_gcm}
{$EXTERNALSYM EVP_aria_192_ccm}
{$EXTERNALSYM EVP_aria_256_ecb}
{$EXTERNALSYM EVP_aria_256_cbc}
{$EXTERNALSYM EVP_aria_256_cfb1}
{$EXTERNALSYM EVP_aria_256_cfb8}
{$EXTERNALSYM EVP_aria_256_cfb128}
{$EXTERNALSYM EVP_aria_256_ctr}
{$EXTERNALSYM EVP_aria_256_ofb}
{$EXTERNALSYM EVP_aria_256_gcm}
{$EXTERNALSYM EVP_aria_256_ccm}
{$EXTERNALSYM EVP_camellia_128_ecb}
{$EXTERNALSYM EVP_camellia_128_cbc}
{$EXTERNALSYM EVP_camellia_128_cfb1}
{$EXTERNALSYM EVP_camellia_128_cfb8}
{$EXTERNALSYM EVP_camellia_128_cfb128}
{$EXTERNALSYM EVP_camellia_128_ofb}
{$EXTERNALSYM EVP_camellia_128_ctr}
{$EXTERNALSYM EVP_camellia_192_ecb}
{$EXTERNALSYM EVP_camellia_192_cbc}
{$EXTERNALSYM EVP_camellia_192_cfb1}
{$EXTERNALSYM EVP_camellia_192_cfb8}
{$EXTERNALSYM EVP_camellia_192_cfb128}
{$EXTERNALSYM EVP_camellia_192_ofb}
{$EXTERNALSYM EVP_camellia_192_ctr}
{$EXTERNALSYM EVP_camellia_256_ecb}
{$EXTERNALSYM EVP_camellia_256_cbc}
{$EXTERNALSYM EVP_camellia_256_cfb1}
{$EXTERNALSYM EVP_camellia_256_cfb8}
{$EXTERNALSYM EVP_camellia_256_cfb128}
{$EXTERNALSYM EVP_camellia_256_ofb}
{$EXTERNALSYM EVP_camellia_256_ctr}
{$EXTERNALSYM EVP_chacha20}
{$EXTERNALSYM EVP_chacha20_poly1305}
{$EXTERNALSYM EVP_seed_ecb}
{$EXTERNALSYM EVP_seed_cbc}
{$EXTERNALSYM EVP_seed_cfb128}
{$EXTERNALSYM EVP_seed_ofb}
{$EXTERNALSYM EVP_sm4_ecb}
{$EXTERNALSYM EVP_sm4_cbc}
{$EXTERNALSYM EVP_sm4_cfb128}
{$EXTERNALSYM EVP_sm4_ofb}
{$EXTERNALSYM EVP_sm4_ctr}
{$EXTERNALSYM EVP_add_cipher}
{$EXTERNALSYM EVP_add_digest}
{$EXTERNALSYM EVP_get_cipherbyname}
{$EXTERNALSYM EVP_get_digestbyname}
{$EXTERNALSYM EVP_CIPHER_do_all}
{$EXTERNALSYM EVP_CIPHER_do_all_sorted}
{$EXTERNALSYM EVP_MD_do_all}
{$EXTERNALSYM EVP_MD_do_all_sorted}
{$EXTERNALSYM EVP_PKEY_decrypt_old}
{$EXTERNALSYM EVP_PKEY_encrypt_old}
{$EXTERNALSYM EVP_PKEY_type}
{$EXTERNALSYM EVP_PKEY_get_base_id}
{$EXTERNALSYM EVP_PKEY_get_security_bits}
{$EXTERNALSYM EVP_PKEY_get_size}
{$EXTERNALSYM EVP_PKEY_set_type}
{$EXTERNALSYM EVP_PKEY_set_type_str}
{$EXTERNALSYM EVP_PKEY_set1_engine}
{$EXTERNALSYM EVP_PKEY_get0_engine}
{$EXTERNALSYM EVP_PKEY_assign}
{$EXTERNALSYM EVP_PKEY_get0}
{$EXTERNALSYM EVP_PKEY_get0_hmac}
{$EXTERNALSYM EVP_PKEY_get0_poly1305}
{$EXTERNALSYM EVP_PKEY_get0_siphash}
{$EXTERNALSYM EVP_PKEY_set1_RSA}
{$EXTERNALSYM EVP_PKEY_get0_RSA}
{$EXTERNALSYM EVP_PKEY_get1_RSA}
{$EXTERNALSYM EVP_PKEY_set1_DSA}
{$EXTERNALSYM EVP_PKEY_get0_DSA}
{$EXTERNALSYM EVP_PKEY_get1_DSA}
{$EXTERNALSYM EVP_PKEY_set1_DH}
{$EXTERNALSYM EVP_PKEY_get0_DH}
{$EXTERNALSYM EVP_PKEY_get1_DH}
{$EXTERNALSYM EVP_PKEY_set1_EC_KEY}
{$EXTERNALSYM EVP_PKEY_get0_EC_KEY}
{$EXTERNALSYM EVP_PKEY_get1_EC_KEY}
{$EXTERNALSYM EVP_PKEY_new}
{$EXTERNALSYM EVP_PKEY_up_ref}
{$EXTERNALSYM EVP_PKEY_free}
{$EXTERNALSYM d2i_PublicKey}
{$EXTERNALSYM i2d_PublicKey}
{$EXTERNALSYM d2i_PrivateKey}
{$EXTERNALSYM d2i_AutoPrivateKey}
{$EXTERNALSYM i2d_PrivateKey}
{$EXTERNALSYM EVP_PKEY_copy_parameters}
{$EXTERNALSYM EVP_PKEY_missing_parameters}
{$EXTERNALSYM EVP_PKEY_save_parameters}
{$EXTERNALSYM EVP_PKEY_cmp_parameters}
{$EXTERNALSYM EVP_PKEY_cmp}
{$EXTERNALSYM EVP_PKEY_print_public}
{$EXTERNALSYM EVP_PKEY_print_private}
{$EXTERNALSYM EVP_PKEY_print_params}
{$EXTERNALSYM EVP_PKEY_get_default_digest_nid}
{$EXTERNALSYM EVP_CIPHER_param_to_asn1}
{$EXTERNALSYM EVP_CIPHER_asn1_to_param}
{$EXTERNALSYM EVP_CIPHER_set_asn1_iv}
{$EXTERNALSYM EVP_CIPHER_get_asn1_iv}
{$EXTERNALSYM PKCS5_PBE_keyivgen}
{$EXTERNALSYM PKCS5_PBKDF2_HMAC_SHA1}
{$EXTERNALSYM PKCS5_PBKDF2_HMAC}
{$EXTERNALSYM PKCS5_v2_PBE_keyivgen}
{$EXTERNALSYM EVP_PBE_scrypt}
{$EXTERNALSYM PKCS5_v2_scrypt_keyivgen}
{$EXTERNALSYM PKCS5_PBE_add}
{$EXTERNALSYM EVP_PBE_CipherInit}
{$EXTERNALSYM EVP_PBE_alg_add_type}
{$EXTERNALSYM EVP_PBE_alg_add}
{$EXTERNALSYM EVP_PBE_find}
{$EXTERNALSYM EVP_PBE_cleanup}
{$EXTERNALSYM EVP_PBE_get}
{$EXTERNALSYM EVP_PKEY_asn1_get_count}
{$EXTERNALSYM EVP_PKEY_asn1_get0}
{$EXTERNALSYM EVP_PKEY_asn1_find}
{$EXTERNALSYM EVP_PKEY_asn1_find_str}
{$EXTERNALSYM EVP_PKEY_asn1_add0}
{$EXTERNALSYM EVP_PKEY_asn1_add_alias}
{$EXTERNALSYM EVP_PKEY_asn1_get0_info}
{$EXTERNALSYM EVP_PKEY_get0_asn1}
{$EXTERNALSYM EVP_PKEY_asn1_new}
{$EXTERNALSYM EVP_PKEY_asn1_copy}
{$EXTERNALSYM EVP_PKEY_asn1_free}
{$EXTERNALSYM EVP_PKEY_asn1_set_public}
{$EXTERNALSYM EVP_PKEY_asn1_set_private}
{$EXTERNALSYM EVP_PKEY_asn1_set_param}
{$EXTERNALSYM EVP_PKEY_asn1_set_free}
{$EXTERNALSYM EVP_PKEY_asn1_set_ctrl}
{$EXTERNALSYM EVP_PKEY_asn1_set_item}
{$EXTERNALSYM EVP_PKEY_asn1_set_siginf}
{$EXTERNALSYM EVP_PKEY_asn1_set_check}
{$EXTERNALSYM EVP_PKEY_asn1_set_public_check}
{$EXTERNALSYM EVP_PKEY_asn1_set_param_check}
{$EXTERNALSYM EVP_PKEY_asn1_set_set_priv_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_set_pub_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_get_priv_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_get_pub_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_security_bits}
{$EXTERNALSYM EVP_PKEY_meth_find}
{$EXTERNALSYM EVP_PKEY_meth_new}
{$EXTERNALSYM EVP_PKEY_meth_get0_info}
{$EXTERNALSYM EVP_PKEY_meth_copy}
{$EXTERNALSYM EVP_PKEY_meth_free}
{$EXTERNALSYM EVP_PKEY_meth_add0}
{$EXTERNALSYM EVP_PKEY_meth_remove}
{$EXTERNALSYM EVP_PKEY_meth_get_count}
{$EXTERNALSYM EVP_PKEY_meth_get0}
{$EXTERNALSYM EVP_PKEY_CTX_new}
{$EXTERNALSYM EVP_PKEY_CTX_new_id}
{$EXTERNALSYM EVP_PKEY_CTX_dup}
{$EXTERNALSYM EVP_PKEY_CTX_free}
{$EXTERNALSYM EVP_PKEY_CTX_ctrl}
{$EXTERNALSYM EVP_PKEY_CTX_ctrl_str}
{$EXTERNALSYM EVP_PKEY_CTX_ctrl_uint64}
{$EXTERNALSYM EVP_PKEY_CTX_str2ctrl}
{$EXTERNALSYM EVP_PKEY_CTX_hex2ctrl}
{$EXTERNALSYM EVP_PKEY_CTX_md}
{$EXTERNALSYM EVP_PKEY_CTX_get_operation}
{$EXTERNALSYM EVP_PKEY_CTX_set0_keygen_info}
{$EXTERNALSYM EVP_PKEY_new_mac_key}
{$EXTERNALSYM EVP_PKEY_new_raw_private_key}
{$EXTERNALSYM EVP_PKEY_new_raw_public_key}
{$EXTERNALSYM EVP_PKEY_get_raw_private_key}
{$EXTERNALSYM EVP_PKEY_get_raw_public_key}
{$EXTERNALSYM EVP_PKEY_new_CMAC_key}
{$EXTERNALSYM EVP_PKEY_CTX_set_data}
{$EXTERNALSYM EVP_PKEY_CTX_get_data}
{$EXTERNALSYM EVP_PKEY_CTX_get0_pkey}
{$EXTERNALSYM EVP_PKEY_CTX_get0_peerkey}
{$EXTERNALSYM EVP_PKEY_CTX_set_app_data}
{$EXTERNALSYM EVP_PKEY_CTX_get_app_data}
{$EXTERNALSYM EVP_PKEY_sign_init}
{$EXTERNALSYM EVP_PKEY_sign}
{$EXTERNALSYM EVP_PKEY_verify_init}
{$EXTERNALSYM EVP_PKEY_verify}
{$EXTERNALSYM EVP_PKEY_verify_recover_init}
{$EXTERNALSYM EVP_PKEY_verify_recover}
{$EXTERNALSYM EVP_PKEY_encrypt_init}
{$EXTERNALSYM EVP_PKEY_encrypt}
{$EXTERNALSYM EVP_PKEY_decrypt_init}
{$EXTERNALSYM EVP_PKEY_decrypt}
{$EXTERNALSYM EVP_PKEY_derive_init}
{$EXTERNALSYM EVP_PKEY_derive_set_peer}
{$EXTERNALSYM EVP_PKEY_derive}
{$EXTERNALSYM EVP_PKEY_paramgen_init}
{$EXTERNALSYM EVP_PKEY_paramgen}
{$EXTERNALSYM EVP_PKEY_keygen_init}
{$EXTERNALSYM EVP_PKEY_keygen}
{$EXTERNALSYM EVP_PKEY_check}
{$EXTERNALSYM EVP_PKEY_public_check}
{$EXTERNALSYM EVP_PKEY_param_check}
{$EXTERNALSYM EVP_PKEY_CTX_set_cb}
{$EXTERNALSYM EVP_PKEY_CTX_get_cb}
{$EXTERNALSYM EVP_PKEY_CTX_get_keygen_info}
{$EXTERNALSYM EVP_PKEY_meth_set_init}
{$EXTERNALSYM EVP_PKEY_meth_set_copy}
{$EXTERNALSYM EVP_PKEY_meth_set_cleanup}
{$EXTERNALSYM EVP_PKEY_meth_set_paramgen}
{$EXTERNALSYM EVP_PKEY_meth_set_keygen}
{$EXTERNALSYM EVP_PKEY_meth_set_sign}
{$EXTERNALSYM EVP_PKEY_meth_set_verify}
{$EXTERNALSYM EVP_PKEY_meth_set_verify_recover}
{$EXTERNALSYM EVP_PKEY_meth_set_signctx}
{$EXTERNALSYM EVP_PKEY_meth_set_verifyctx}
{$EXTERNALSYM EVP_PKEY_meth_set_encrypt}
{$EXTERNALSYM EVP_PKEY_meth_set_decrypt}
{$EXTERNALSYM EVP_PKEY_meth_set_derive}
{$EXTERNALSYM EVP_PKEY_meth_set_ctrl}
{$EXTERNALSYM EVP_PKEY_meth_set_digestsign}
{$EXTERNALSYM EVP_PKEY_meth_set_digestverify}
{$EXTERNALSYM EVP_PKEY_meth_set_check}
{$EXTERNALSYM EVP_PKEY_meth_set_public_check}
{$EXTERNALSYM EVP_PKEY_meth_set_param_check}
{$EXTERNALSYM EVP_PKEY_meth_set_digest_custom}
{$EXTERNALSYM EVP_PKEY_meth_get_init}
{$EXTERNALSYM EVP_PKEY_meth_get_copy}
{$EXTERNALSYM EVP_PKEY_meth_get_cleanup}
{$EXTERNALSYM EVP_PKEY_meth_get_paramgen}
{$EXTERNALSYM EVP_PKEY_meth_get_keygen}
{$EXTERNALSYM EVP_PKEY_meth_get_sign}
{$EXTERNALSYM EVP_PKEY_meth_get_verify}
{$EXTERNALSYM EVP_PKEY_meth_get_verify_recover}
{$EXTERNALSYM EVP_PKEY_meth_get_signctx}
{$EXTERNALSYM EVP_PKEY_meth_get_verifyctx}
{$EXTERNALSYM EVP_PKEY_meth_get_encrypt}
{$EXTERNALSYM EVP_PKEY_meth_get_decrypt}
{$EXTERNALSYM EVP_PKEY_meth_get_derive}
{$EXTERNALSYM EVP_PKEY_meth_get_ctrl}
{$EXTERNALSYM EVP_PKEY_meth_get_digestsign}
{$EXTERNALSYM EVP_PKEY_meth_get_digestverify}
{$EXTERNALSYM EVP_PKEY_meth_get_check}
{$EXTERNALSYM EVP_PKEY_meth_get_public_check}
{$EXTERNALSYM EVP_PKEY_meth_get_param_check}
{$EXTERNALSYM EVP_PKEY_meth_get_digest_custom}
{$EXTERNALSYM EVP_add_alg_module}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl; external CLibCrypto;
function EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD; cdecl; external CLibCrypto;
procedure EVP_MD_meth_free(md: PEVP_MD); cdecl; external CLibCrypto;
function EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_copy(md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_result_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_flags(const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init; cdecl; external CLibCrypto;
function EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update; cdecl; external CLibCrypto;
function EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final; cdecl; external CLibCrypto;
function EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy; cdecl; external CLibCrypto;
function EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl; external CLibCrypto;
function EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl; external CLibCrypto;
procedure EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl; external CLibCrypto;
function EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl; external CLibCrypto;
function EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl; external CLibCrypto;
procedure EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl; external CLibCrypto;
procedure EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl; external CLibCrypto;
function EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl; external CLibCrypto;
function EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_CTX_new: PEVP_MD_CTX; cdecl; external CLibCrypto;
function EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl; external CLibCrypto;
function EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_Digest(const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_set_pw_prompt(const prompt: PAnsiChar); cdecl; external CLibCrypto;
function EVP_get_pw_prompt: PAnsiChar; cdecl; external CLibCrypto;
function EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl; external CLibCrypto;
procedure EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto;
function EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto;
function EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_EncodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto;
function EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_f_md: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_base64: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_cipher: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_reliable: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_md_null: PEVP_MD; cdecl; external CLibCrypto;
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_MD2}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_MD4}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_MD5}
  
{$ENDIF}
{$ENDIF}
  
function EVP_md5_sha1: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha1: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha224: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha384: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha512: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha512_224: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha512_256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_224: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_384: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_512: PEVP_MD; cdecl; external CLibCrypto;
function EVP_shake128: PEVP_MD; cdecl; external CLibCrypto;
function EVP_shake256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_enc_null: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_desx_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc4: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc4_40: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_40_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_64_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_xts: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ocb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ocb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_xts: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ocb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_chacha20: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_chacha20_poly1305: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_add_cipher(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_add_digest(const digest: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; cdecl; external CLibCrypto;
procedure EVP_CIPHER_do_all(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
procedure EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
procedure EVP_MD_do_all(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
procedure EVP_MD_do_all_sorted(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
function EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_set_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE; cdecl; external CLibCrypto;
function EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer; cdecl; external CLibCrypto;
function EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl; external CLibCrypto;
function EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl; external CLibCrypto;
function EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl; external CLibCrypto;
function EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA; cdecl; external CLibCrypto;
function EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA; cdecl; external CLibCrypto;
function EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA; cdecl; external CLibCrypto;
function EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA; cdecl; external CLibCrypto;
function EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH; cdecl; external CLibCrypto;
function EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH; cdecl; external CLibCrypto;
function EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl; external CLibCrypto;
function EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl; external CLibCrypto;
function EVP_PKEY_new: PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_free(pkey: PEVP_PKEY); cdecl; external CLibCrypto;
function d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_PBKDF2_HMAC_SHA1(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_PBKDF2_HMAC(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_scrypt(const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure PKCS5_PBE_add; cdecl; external CLibCrypto;
function EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_alg_add(nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PBE_cleanup; cdecl; external CLibCrypto;
function EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl; external CLibCrypto;
function EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl; external CLibCrypto;
function EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl; external CLibCrypto;
function EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl; external CLibCrypto;
procedure EVP_add_alg_module; cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
procedure BIO_set_md(v1: PBIO; const md: PEVP_MD); {removed 1.0.0}
{$IFNDEF OPENSSL_NO_MD2}
function EVP_md2: PEVP_MD; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
function EVP_md4: PEVP_MD; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
function EVP_md5: PEVP_MD; {removed 1.1.0 allow_nil}
{$ENDIF}
function EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; {removed 3.0.0}
function EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; {removed 3.0.0}
procedure OpenSSL_add_all_ciphers; {removed 1.1.0}
procedure OpenSSL_add_all_digests; {removed 1.1.0}
procedure EVP_cleanup; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}

{Declare external function initialisers - should not be called directly}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl;
function Load_EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD; cdecl;
procedure Load_EVP_MD_meth_free(md: PEVP_MD); cdecl;
function Load_EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_copy(md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_get_result_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_meth_get_flags(const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl;
function Load_EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init; cdecl;
function Load_EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update; cdecl;
function Load_EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final; cdecl;
function Load_EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy; cdecl;
function Load_EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl;
function Load_EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl;
function Load_EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
function Load_EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl;
procedure Load_EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl;
function Load_EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl;
function Load_EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl;
function Load_EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl;
function Load_EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl;
function Load_EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl;
function Load_EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_MD_type(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_pkey_type(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_block_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_flags(const md: PEVP_MD): POpenSSL_C_ULONG; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
function Load_EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl;
procedure Load_EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_MD_CTX_pkey_ctx(const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_MD_CTX_md_data(const ctx: PEVP_MD_CTX): Pointer; cdecl;
function Load_EVP_CIPHER_nid(const ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_block_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_CIPHER_key_length(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_iv_length(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_flags(const cipher: PEVP_CIPHER): TOpenSSL_C_ULONG; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_CIPHER_CTX_encrypting(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_nid(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_block_size(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_key_length(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_iv_length(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl;
function Load_EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl;
function Load_EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
function Load_EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_CIPHER_CTX_num(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl;
function Load_EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl;
procedure Load_EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl;
function Load_EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl;
function Load_EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_BIO_set_md(v1: PBIO; const md: PEVP_MD); cdecl;
procedure Load_EVP_MD_CTX_init(ctx : PEVP_MD_CTX); cdecl;
function Load_EVP_MD_CTX_cleanup(ctx : PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;
function Load_EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;
function Load_EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
procedure Load_EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
function Load_EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_EVP_Digest(const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
function Load_EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_set_pw_prompt(const prompt: PAnsiChar); cdecl;
function Load_EVP_get_pw_prompt: PAnsiChar; cdecl;
function Load_EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
procedure Load_EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
function Load_EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
function Load_EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
function Load_EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl;
procedure Load_EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl;
function Load_EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
function Load_EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl;
function Load_EVP_EncodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
function Load_EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_DecodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl;
function Load_EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl;
function Load_EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl;
function Load_BIO_f_md: PBIO_METHOD; cdecl;
function Load_BIO_f_base64: PBIO_METHOD; cdecl;
function Load_BIO_f_cipher: PBIO_METHOD; cdecl;
function Load_BIO_f_reliable: PBIO_METHOD; cdecl;
function Load_BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_md_null: PEVP_MD; cdecl;
{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
function Load_EVP_md5_sha1: PEVP_MD; cdecl;
function Load_EVP_sha1: PEVP_MD; cdecl;
function Load_EVP_sha224: PEVP_MD; cdecl;
function Load_EVP_sha256: PEVP_MD; cdecl;
function Load_EVP_sha384: PEVP_MD; cdecl;
function Load_EVP_sha512: PEVP_MD; cdecl;
function Load_EVP_sha512_224: PEVP_MD; cdecl;
function Load_EVP_sha512_256: PEVP_MD; cdecl;
function Load_EVP_sha3_224: PEVP_MD; cdecl;
function Load_EVP_sha3_256: PEVP_MD; cdecl;
function Load_EVP_sha3_384: PEVP_MD; cdecl;
function Load_EVP_sha3_512: PEVP_MD; cdecl;
function Load_EVP_shake128: PEVP_MD; cdecl;
function Load_EVP_shake256: PEVP_MD; cdecl;
function Load_EVP_enc_null: PEVP_CIPHER; cdecl;
function Load_EVP_des_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_des_cfb64: PEVP_CIPHER; cdecl;
function Load_EVP_des_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_des_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede_cfb64: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_des_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_des_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_desx_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_des_ede3_wrap: PEVP_CIPHER; cdecl;
function Load_EVP_rc4: PEVP_CIPHER; cdecl;
function Load_EVP_rc4_40: PEVP_CIPHER; cdecl;
function Load_EVP_rc2_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_rc2_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_rc2_40_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_rc2_64_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_rc2_cfb64: PEVP_CIPHER; cdecl;
function Load_EVP_rc2_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_bf_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_bf_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_bf_cfb64: PEVP_CIPHER; cdecl;
function Load_EVP_bf_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_cast5_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_cast5_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_cast5_cfb64: PEVP_CIPHER; cdecl;
function Load_EVP_cast5_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_ccm: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_gcm: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_xts: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_wrap: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_ocb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_ccm: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_gcm: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_wrap: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl;
function Load_EVP_aes_192_ocb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_ccm: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_gcm: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_xts: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_wrap: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_ocb: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
function Load_EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
function Load_EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_gcm: PEVP_CIPHER; cdecl;
function Load_EVP_aria_128_ccm: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_gcm: PEVP_CIPHER; cdecl;
function Load_EVP_aria_192_ccm: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_gcm: PEVP_CIPHER; cdecl;
function Load_EVP_aria_256_ccm: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_128_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_192_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_camellia_256_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_chacha20: PEVP_CIPHER; cdecl;
function Load_EVP_chacha20_poly1305: PEVP_CIPHER; cdecl;
function Load_EVP_seed_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_seed_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_seed_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_seed_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_sm4_ecb: PEVP_CIPHER; cdecl;
function Load_EVP_sm4_cbc: PEVP_CIPHER; cdecl;
function Load_EVP_sm4_cfb128: PEVP_CIPHER; cdecl;
function Load_EVP_sm4_ofb: PEVP_CIPHER; cdecl;
function Load_EVP_sm4_ctr: PEVP_CIPHER; cdecl;
function Load_EVP_add_cipher(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_EVP_add_digest(const digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; cdecl;
function Load_EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; cdecl;
procedure Load_EVP_CIPHER_do_all(AFn: fn; arg: Pointer); cdecl;
procedure Load_EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer); cdecl;
procedure Load_EVP_MD_do_all(AFn: fn; arg: Pointer); cdecl;
procedure Load_EVP_MD_do_all_sorted(AFn: fn; arg: Pointer); cdecl;
function Load_EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_get_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_get_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_get_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_set_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE; cdecl;
function Load_EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer; cdecl;
function Load_EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
function Load_EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
function Load_EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
function Load_EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA; cdecl;
function Load_EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA; cdecl;
function Load_EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA; cdecl;
function Load_EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA; cdecl;
function Load_EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH; cdecl;
function Load_EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH; cdecl;
function Load_EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl;
function Load_EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl;
function Load_EVP_PKEY_new: PEVP_PKEY; cdecl;
function Load_EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_PKEY_free(pkey: PEVP_PKEY); cdecl;
function Load_d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
function Load_i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
function Load_d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
function Load_i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_set1_tls_encodedpoint(pkey: PEVP_PKEY; const pt: PByte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get1_tls_encodedpoint(pkey: PEVP_PKEY; ppt: PPByte): TOpenSSL_C_SIZET; cdecl;
function Load_EVP_CIPHER_type(const ctx: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
function Load_EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_PBKDF2_HMAC_SHA1(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_PBKDF2_HMAC(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PBE_scrypt(const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_PKCS5_PBE_add; cdecl;
function Load_EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
function Load_EVP_PBE_alg_add(nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
function Load_EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_PBE_cleanup; cdecl;
function Load_EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
function Load_EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
function Load_EVP_PKEY_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
function Load_EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl;
function Load_EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl;
procedure Load_EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl;
procedure Load_EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl;
procedure Load_EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl;
procedure Load_EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl;
procedure Load_EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl;
procedure Load_EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl;
procedure Load_EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl;
procedure Load_EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl;
procedure Load_EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl;
procedure Load_EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl;
procedure Load_EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl;
procedure Load_EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl;
procedure Load_EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl;
procedure Load_EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl;
procedure Load_EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl;
procedure Load_EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl;
procedure Load_EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl;
function Load_EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
function Load_EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
procedure Load_EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl;
procedure Load_EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl;
procedure Load_EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl;
function Load_EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl;
function Load_EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl;
function Load_EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl;
function Load_EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl;
function Load_EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl;
procedure Load_EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl;
function Load_EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl;
function Load_EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
function Load_EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
function Load_EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
function Load_EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl;
procedure Load_EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl;
function Load_EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl;
function Load_EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
function Load_EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
procedure Load_EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl;
function Load_EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl;
function Load_EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
function Load_EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl;
function Load_EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl;
function Load_EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl;
procedure Load_EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl;
procedure Load_EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl;
procedure Load_EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl;
procedure Load_EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl;
procedure Load_EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl;
procedure Load_EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl;
procedure Load_EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl;
procedure Load_EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl;
procedure Load_EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl;
procedure Load_EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl;
procedure Load_EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl;
procedure Load_EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl;
procedure Load_EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl;
procedure Load_EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl;
procedure Load_EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl;
procedure Load_EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl;
procedure Load_EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl;
procedure Load_EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl;
procedure Load_EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl;
procedure Load_EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl;
procedure Load_EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl;
procedure Load_EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl;
procedure Load_EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl;
procedure Load_EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl;
procedure Load_EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl;
procedure Load_EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl;
procedure Load_EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl;
procedure Load_EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl;
procedure Load_EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl;
procedure Load_EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl;
procedure Load_EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl;
procedure Load_EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl;
procedure Load_EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl;
procedure Load_EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl;
procedure Load_EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl;
procedure Load_EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl;
procedure Load_EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl;
procedure Load_EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl;
procedure Load_EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl;
procedure Load_EVP_add_alg_module; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_OpenSSL_add_all_ciphers; cdecl;
procedure Load_OpenSSL_add_all_digests; cdecl;
procedure Load_EVP_cleanup; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

var
  EVP_MD_meth_new: function (md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl = Load_EVP_MD_meth_new;
  EVP_MD_meth_dup: function (const md: PEVP_MD): PEVP_MD; cdecl = Load_EVP_MD_meth_dup;
  EVP_MD_meth_free: procedure (md: PEVP_MD); cdecl = Load_EVP_MD_meth_free;
  EVP_MD_meth_set_input_blocksize: function (md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_input_blocksize;
  EVP_MD_meth_set_result_size: function (md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_result_size;
  EVP_MD_meth_set_app_datasize: function (md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_app_datasize;
  EVP_MD_meth_set_flags: function (md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_flags;
  EVP_MD_meth_set_init: function (md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_init;
  EVP_MD_meth_set_update: function (md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_update;
  EVP_MD_meth_set_final: function (md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_final;
  EVP_MD_meth_set_copy: function (md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_copy;
  EVP_MD_meth_set_cleanup: function (md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_cleanup;
  EVP_MD_meth_set_ctrl: function (md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_ctrl;
  EVP_MD_meth_get_input_blocksize: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_get_input_blocksize;
  EVP_MD_meth_get_result_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_get_result_size;
  EVP_MD_meth_get_app_datasize: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_get_app_datasize;
  EVP_MD_meth_get_flags: function (const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl = Load_EVP_MD_meth_get_flags;
  EVP_MD_meth_get_init: function (const md: PEVP_MD): EVP_MD_meth_init; cdecl = Load_EVP_MD_meth_get_init;
  EVP_MD_meth_get_update: function (const md: PEVP_MD): EVP_MD_meth_update; cdecl = Load_EVP_MD_meth_get_update;
  EVP_MD_meth_get_final: function (const md: PEVP_MD): EVP_MD_meth_final; cdecl = Load_EVP_MD_meth_get_final;
  EVP_MD_meth_get_copy: function (const md: PEVP_MD): EVP_MD_meth_copy; cdecl = Load_EVP_MD_meth_get_copy;
  EVP_MD_meth_get_cleanup: function (const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl = Load_EVP_MD_meth_get_cleanup;
  EVP_MD_meth_get_ctrl: function (const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl = Load_EVP_MD_meth_get_ctrl;
  EVP_CIPHER_meth_new: function (cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_meth_new;
  EVP_CIPHER_meth_dup: function (const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_meth_dup;
  EVP_CIPHER_meth_free: procedure (cipher: PEVP_CIPHER); cdecl = Load_EVP_CIPHER_meth_free;
  EVP_CIPHER_meth_set_iv_length: function (cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_iv_length;
  EVP_CIPHER_meth_set_flags: function (cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_flags;
  EVP_CIPHER_meth_set_impl_ctx_size: function (cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_impl_ctx_size;
  EVP_CIPHER_meth_set_init: function (cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_init;
  EVP_CIPHER_meth_set_do_cipher: function (cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_do_cipher;
  EVP_CIPHER_meth_set_cleanup: function (cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_cleanup;
  EVP_CIPHER_meth_set_set_asn1_params: function (cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_set_asn1_params;
  EVP_CIPHER_meth_set_get_asn1_params: function (cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_get_asn1_params;
  EVP_CIPHER_meth_set_ctrl: function (cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_ctrl;
  EVP_CIPHER_meth_get_init: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl = Load_EVP_CIPHER_meth_get_init;
  EVP_CIPHER_meth_get_do_cipher: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl = Load_EVP_CIPHER_meth_get_do_cipher;
  EVP_CIPHER_meth_get_cleanup: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl = Load_EVP_CIPHER_meth_get_cleanup;
  EVP_CIPHER_meth_get_set_asn1_params: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl = Load_EVP_CIPHER_meth_get_set_asn1_params;
  EVP_CIPHER_meth_get_get_asn1_params: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl = Load_EVP_CIPHER_meth_get_get_asn1_params;
  EVP_CIPHER_meth_get_ctrl: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl = Load_EVP_CIPHER_meth_get_ctrl;
  EVP_MD_CTX_md: function (ctx: PEVP_MD_CTX): PEVP_MD; cdecl = Load_EVP_MD_CTX_md;
  EVP_MD_CTX_update_fn: function (ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl = Load_EVP_MD_CTX_update_fn;
  EVP_MD_CTX_set_update_fn: procedure (ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl = Load_EVP_MD_CTX_set_update_fn;
  EVP_MD_CTX_set_pkey_ctx: procedure (ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl = Load_EVP_MD_CTX_set_pkey_ctx;
  EVP_CIPHER_impl_ctx_size: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_impl_ctx_size;
  EVP_CIPHER_CTX_cipher: function (const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_CTX_cipher;
  EVP_CIPHER_CTX_iv: function (const ctx: PEVP_CIPHER_CTX): PByte; cdecl = Load_EVP_CIPHER_CTX_iv;
  EVP_CIPHER_CTX_original_iv: function (const ctx: PEVP_CIPHER_CTX): PByte; cdecl = Load_EVP_CIPHER_CTX_original_iv;
  EVP_CIPHER_CTX_iv_noconst: function (ctx: PEVP_CIPHER_CTX): PByte; cdecl = Load_EVP_CIPHER_CTX_iv_noconst;
  EVP_CIPHER_CTX_buf_noconst: function (ctx: PEVP_CIPHER_CTX): PByte; cdecl = Load_EVP_CIPHER_CTX_buf_noconst;
  EVP_CIPHER_CTX_set_num: procedure (ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl = Load_EVP_CIPHER_CTX_set_num;
  EVP_CIPHER_CTX_copy: function (out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_copy;
  EVP_CIPHER_CTX_get_app_data: function (const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = Load_EVP_CIPHER_CTX_get_app_data;
  EVP_CIPHER_CTX_set_app_data: procedure (ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl = Load_EVP_CIPHER_CTX_set_app_data;
  EVP_CIPHER_CTX_get_cipher_data: function (const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = Load_EVP_CIPHER_CTX_get_cipher_data;
  EVP_CIPHER_CTX_set_cipher_data: function (ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl = Load_EVP_CIPHER_CTX_set_cipher_data;
  EVP_MD_CTX_ctrl: function (ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_ctrl;
  EVP_MD_CTX_new: function : PEVP_MD_CTX; cdecl = Load_EVP_MD_CTX_new;
  EVP_MD_CTX_reset: function (ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_reset;
  EVP_MD_CTX_free: procedure (ctx: PEVP_MD_CTX); cdecl = Load_EVP_MD_CTX_free;
  EVP_MD_CTX_copy_ex: function (out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_copy_ex;
  EVP_MD_CTX_set_flags: procedure (ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_MD_CTX_set_flags;
  EVP_MD_CTX_clear_flags: procedure (ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_MD_CTX_clear_flags;
  EVP_MD_CTX_test_flags: function (const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_test_flags;
  EVP_DigestInit_ex: function (ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_EVP_DigestInit_ex;
  EVP_DigestUpdate: function (ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestUpdate;
  EVP_DigestFinal_ex: function (ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_DigestFinal_ex;
  EVP_Digest: function (const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_EVP_Digest;
  EVP_MD_CTX_copy: function (out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_copy;
  EVP_DigestInit: function (ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_DigestInit;
  EVP_DigestFinal: function (ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_DigestFinal;
  EVP_DigestFinalXOF: function (ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestFinalXOF;
  EVP_read_pw_string: function (buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_read_pw_string;
  EVP_read_pw_string_min: function (buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_read_pw_string_min;
  EVP_set_pw_prompt: procedure (const prompt: PAnsiChar); cdecl = Load_EVP_set_pw_prompt;
  EVP_get_pw_prompt: function : PAnsiChar; cdecl = Load_EVP_get_pw_prompt;
  EVP_BytesToKey: function (const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl = Load_EVP_BytesToKey;
  EVP_CIPHER_CTX_set_flags: procedure (ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_CIPHER_CTX_set_flags;
  EVP_CIPHER_CTX_clear_flags: procedure (ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_CIPHER_CTX_clear_flags;
  EVP_CIPHER_CTX_test_flags: function (const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_test_flags;
  EVP_EncryptInit: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptInit;
  EVP_EncryptInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptInit_ex;
  EVP_EncryptUpdate: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptUpdate;
  EVP_EncryptFinal_ex: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptFinal_ex;
  EVP_EncryptFinal: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptFinal;
  EVP_DecryptInit: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptInit;
  EVP_DecryptInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptInit_ex;
  EVP_DecryptUpdate: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptUpdate;
  EVP_DecryptFinal: function (ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptFinal;
  EVP_DecryptFinal_ex: function (ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptFinal_ex;
  EVP_CipherInit: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherInit;
  EVP_CipherInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherInit_ex;
  EVP_CipherUpdate: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherUpdate;
  EVP_CipherFinal: function (ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherFinal;
  EVP_CipherFinal_ex: function (ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherFinal_ex;
  EVP_SignFinal: function (ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_SignFinal;
  EVP_DigestSign: function (ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSign;
  EVP_VerifyFinal: function (ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_VerifyFinal;
  EVP_DigestVerify: function (ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerify;
  EVP_DigestSignInit: function (ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSignInit;
  EVP_DigestSignFinal: function (ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSignFinal;
  EVP_DigestVerifyInit: function (ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerifyInit;
  EVP_DigestVerifyFinal: function (ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerifyFinal;
  EVP_OpenInit: function (ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_OpenInit;
  EVP_OpenFinal: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_OpenFinal;
  EVP_SealInit: function (ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_SealInit;
  EVP_SealFinal: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_SealFinal;
  EVP_ENCODE_CTX_new: function : PEVP_ENCODE_CTX; cdecl = Load_EVP_ENCODE_CTX_new;
  EVP_ENCODE_CTX_free: procedure (ctx: PEVP_ENCODE_CTX); cdecl = Load_EVP_ENCODE_CTX_free;
  EVP_ENCODE_CTX_copy: function (dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_ENCODE_CTX_copy;
  EVP_ENCODE_CTX_num: function (ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_ENCODE_CTX_num;
  EVP_EncodeInit: procedure (ctx: PEVP_ENCODE_CTX); cdecl = Load_EVP_EncodeInit;
  EVP_EncodeUpdate: function (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncodeUpdate;
  EVP_EncodeFinal: procedure (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl = Load_EVP_EncodeFinal;
  EVP_EncodeBlock: function (t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncodeBlock;
  EVP_DecodeInit: procedure (ctx: PEVP_ENCODE_CTX); cdecl = Load_EVP_DecodeInit;
  EVP_DecodeUpdate: function (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecodeUpdate;
  EVP_DecodeFinal: function (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecodeFinal;
  EVP_DecodeBlock: function (t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecodeBlock;
  EVP_CIPHER_CTX_new: function : PEVP_CIPHER_CTX; cdecl = Load_EVP_CIPHER_CTX_new;
  EVP_CIPHER_CTX_reset: function (c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_reset;
  EVP_CIPHER_CTX_free: procedure (c: PEVP_CIPHER_CTX); cdecl = Load_EVP_CIPHER_CTX_free;
  EVP_CIPHER_CTX_set_key_length: function (x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_key_length;
  EVP_CIPHER_CTX_set_padding: function (c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_padding;
  EVP_CIPHER_CTX_ctrl: function (ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_ctrl;
  EVP_CIPHER_CTX_rand_key: function (ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_rand_key;
  BIO_f_md: function : PBIO_METHOD; cdecl = Load_BIO_f_md;
  BIO_f_base64: function : PBIO_METHOD; cdecl = Load_BIO_f_base64;
  BIO_f_cipher: function : PBIO_METHOD; cdecl = Load_BIO_f_cipher;
  BIO_f_reliable: function : PBIO_METHOD; cdecl = Load_BIO_f_reliable;
  BIO_set_cipher: function (b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_set_cipher;
  EVP_md_null: function : PEVP_MD; cdecl = Load_EVP_md_null;
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_MD2}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_MD4}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_MD5}
  
{$ENDIF}
{$ENDIF}
  
  EVP_md5_sha1: function : PEVP_MD; cdecl = Load_EVP_md5_sha1;
  EVP_sha1: function : PEVP_MD; cdecl = Load_EVP_sha1;
  EVP_sha224: function : PEVP_MD; cdecl = Load_EVP_sha224;
  EVP_sha256: function : PEVP_MD; cdecl = Load_EVP_sha256;
  EVP_sha384: function : PEVP_MD; cdecl = Load_EVP_sha384;
  EVP_sha512: function : PEVP_MD; cdecl = Load_EVP_sha512;
  EVP_sha512_224: function : PEVP_MD; cdecl = Load_EVP_sha512_224;
  EVP_sha512_256: function : PEVP_MD; cdecl = Load_EVP_sha512_256;
  EVP_sha3_224: function : PEVP_MD; cdecl = Load_EVP_sha3_224;
  EVP_sha3_256: function : PEVP_MD; cdecl = Load_EVP_sha3_256;
  EVP_sha3_384: function : PEVP_MD; cdecl = Load_EVP_sha3_384;
  EVP_sha3_512: function : PEVP_MD; cdecl = Load_EVP_sha3_512;
  EVP_shake128: function : PEVP_MD; cdecl = Load_EVP_shake128;
  EVP_shake256: function : PEVP_MD; cdecl = Load_EVP_shake256;
  EVP_enc_null: function : PEVP_CIPHER; cdecl = Load_EVP_enc_null;
  EVP_des_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_des_ecb;
  EVP_des_ede: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede;
  EVP_des_ede3: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3;
  EVP_des_ede_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede_ecb;
  EVP_des_ede3_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_ecb;
  EVP_des_cfb64: function : PEVP_CIPHER; cdecl = Load_EVP_des_cfb64;
  EVP_des_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_des_cfb1;
  EVP_des_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_des_cfb8;
  EVP_des_ede_cfb64: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede_cfb64;
  EVP_des_ede3_cfb64: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb64;
  EVP_des_ede3_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb1;
  EVP_des_ede3_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb8;
  EVP_des_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_des_ofb;
  EVP_des_ede_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede_ofb;
  EVP_des_ede3_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_ofb;
  EVP_des_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_des_cbc;
  EVP_des_ede_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede_cbc;
  EVP_des_ede3_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cbc;
  EVP_desx_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_desx_cbc;
  EVP_des_ede3_wrap: function : PEVP_CIPHER; cdecl = Load_EVP_des_ede3_wrap;
  EVP_rc4: function : PEVP_CIPHER; cdecl = Load_EVP_rc4;
  EVP_rc4_40: function : PEVP_CIPHER; cdecl = Load_EVP_rc4_40;
  EVP_rc2_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_rc2_ecb;
  EVP_rc2_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_rc2_cbc;
  EVP_rc2_40_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_rc2_40_cbc;
  EVP_rc2_64_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_rc2_64_cbc;
  EVP_rc2_cfb64: function : PEVP_CIPHER; cdecl = Load_EVP_rc2_cfb64;
  EVP_rc2_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_rc2_ofb;
  EVP_bf_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_bf_ecb;
  EVP_bf_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_bf_cbc;
  EVP_bf_cfb64: function : PEVP_CIPHER; cdecl = Load_EVP_bf_cfb64;
  EVP_bf_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_bf_ofb;
  EVP_cast5_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_cast5_ecb;
  EVP_cast5_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_cast5_cbc;
  EVP_cast5_cfb64: function : PEVP_CIPHER; cdecl = Load_EVP_cast5_cfb64;
  EVP_cast5_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_cast5_ofb;
  EVP_aes_128_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_ecb;
  EVP_aes_128_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_cbc;
  EVP_aes_128_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb1;
  EVP_aes_128_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb8;
  EVP_aes_128_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb128;
  EVP_aes_128_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_ofb;
  EVP_aes_128_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_ctr;
  EVP_aes_128_ccm: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_ccm;
  EVP_aes_128_gcm: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_gcm;
  EVP_aes_128_xts: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_xts;
  EVP_aes_128_wrap: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_wrap;
  EVP_aes_128_wrap_pad: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_wrap_pad;
  EVP_aes_128_ocb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_ocb;
  EVP_aes_192_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_ecb;
  EVP_aes_192_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_cbc;
  EVP_aes_192_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb1;
  EVP_aes_192_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb8;
  EVP_aes_192_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb128;
  EVP_aes_192_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_ofb;
  EVP_aes_192_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_ctr;
  EVP_aes_192_ccm: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_ccm;
  EVP_aes_192_gcm: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_gcm;
  EVP_aes_192_wrap: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_wrap;
  EVP_aes_192_wrap_pad: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_wrap_pad;
  EVP_aes_192_ocb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_192_ocb;
  EVP_aes_256_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_ecb;
  EVP_aes_256_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_cbc;
  EVP_aes_256_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb1;
  EVP_aes_256_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb8;
  EVP_aes_256_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb128;
  EVP_aes_256_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_ofb;
  EVP_aes_256_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_ctr;
  EVP_aes_256_ccm: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_ccm;
  EVP_aes_256_gcm: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_gcm;
  EVP_aes_256_xts: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_xts;
  EVP_aes_256_wrap: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_wrap;
  EVP_aes_256_wrap_pad: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_wrap_pad;
  EVP_aes_256_ocb: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_ocb;
  EVP_aes_128_cbc_hmac_sha1: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_cbc_hmac_sha1;
  EVP_aes_256_cbc_hmac_sha1: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_cbc_hmac_sha1;
  EVP_aes_128_cbc_hmac_sha256: function : PEVP_CIPHER; cdecl = Load_EVP_aes_128_cbc_hmac_sha256;
  EVP_aes_256_cbc_hmac_sha256: function : PEVP_CIPHER; cdecl = Load_EVP_aes_256_cbc_hmac_sha256;
  EVP_aria_128_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_ecb;
  EVP_aria_128_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_cbc;
  EVP_aria_128_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb1;
  EVP_aria_128_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb8;
  EVP_aria_128_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb128;
  EVP_aria_128_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_ctr;
  EVP_aria_128_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_ofb;
  EVP_aria_128_gcm: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_gcm;
  EVP_aria_128_ccm: function : PEVP_CIPHER; cdecl = Load_EVP_aria_128_ccm;
  EVP_aria_192_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_ecb;
  EVP_aria_192_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_cbc;
  EVP_aria_192_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb1;
  EVP_aria_192_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb8;
  EVP_aria_192_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb128;
  EVP_aria_192_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_ctr;
  EVP_aria_192_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_ofb;
  EVP_aria_192_gcm: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_gcm;
  EVP_aria_192_ccm: function : PEVP_CIPHER; cdecl = Load_EVP_aria_192_ccm;
  EVP_aria_256_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_ecb;
  EVP_aria_256_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_cbc;
  EVP_aria_256_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb1;
  EVP_aria_256_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb8;
  EVP_aria_256_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb128;
  EVP_aria_256_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_ctr;
  EVP_aria_256_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_ofb;
  EVP_aria_256_gcm: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_gcm;
  EVP_aria_256_ccm: function : PEVP_CIPHER; cdecl = Load_EVP_aria_256_ccm;
  EVP_camellia_128_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_ecb;
  EVP_camellia_128_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cbc;
  EVP_camellia_128_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb1;
  EVP_camellia_128_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb8;
  EVP_camellia_128_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb128;
  EVP_camellia_128_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_ofb;
  EVP_camellia_128_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_128_ctr;
  EVP_camellia_192_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_ecb;
  EVP_camellia_192_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cbc;
  EVP_camellia_192_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb1;
  EVP_camellia_192_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb8;
  EVP_camellia_192_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb128;
  EVP_camellia_192_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_ofb;
  EVP_camellia_192_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_192_ctr;
  EVP_camellia_256_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_ecb;
  EVP_camellia_256_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cbc;
  EVP_camellia_256_cfb1: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb1;
  EVP_camellia_256_cfb8: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb8;
  EVP_camellia_256_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb128;
  EVP_camellia_256_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_ofb;
  EVP_camellia_256_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_camellia_256_ctr;
  EVP_chacha20: function : PEVP_CIPHER; cdecl = Load_EVP_chacha20;
  EVP_chacha20_poly1305: function : PEVP_CIPHER; cdecl = Load_EVP_chacha20_poly1305;
  EVP_seed_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_seed_ecb;
  EVP_seed_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_seed_cbc;
  EVP_seed_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_seed_cfb128;
  EVP_seed_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_seed_ofb;
  EVP_sm4_ecb: function : PEVP_CIPHER; cdecl = Load_EVP_sm4_ecb;
  EVP_sm4_cbc: function : PEVP_CIPHER; cdecl = Load_EVP_sm4_cbc;
  EVP_sm4_cfb128: function : PEVP_CIPHER; cdecl = Load_EVP_sm4_cfb128;
  EVP_sm4_ofb: function : PEVP_CIPHER; cdecl = Load_EVP_sm4_ofb;
  EVP_sm4_ctr: function : PEVP_CIPHER; cdecl = Load_EVP_sm4_ctr;
  EVP_add_cipher: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_add_cipher;
  EVP_add_digest: function (const digest: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_add_digest;
  EVP_get_cipherbyname: function (const name: PAnsiChar): PEVP_CIPHER; cdecl = Load_EVP_get_cipherbyname;
  EVP_get_digestbyname: function (const name: PAnsiChar): PEVP_MD; cdecl = Load_EVP_get_digestbyname;
  EVP_CIPHER_do_all: procedure (AFn: fn; arg: Pointer); cdecl = Load_EVP_CIPHER_do_all;
  EVP_CIPHER_do_all_sorted: procedure (AFn: fn; arg: Pointer); cdecl = Load_EVP_CIPHER_do_all_sorted;
  EVP_MD_do_all: procedure (AFn: fn; arg: Pointer); cdecl = Load_EVP_MD_do_all;
  EVP_MD_do_all_sorted: procedure (AFn: fn; arg: Pointer); cdecl = Load_EVP_MD_do_all_sorted;
  EVP_PKEY_decrypt_old: function (dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt_old;
  EVP_PKEY_encrypt_old: function (dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt_old;
  EVP_PKEY_type: function (type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_type;
  EVP_PKEY_get_base_id: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_base_id;
  EVP_PKEY_get_security_bits: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_security_bits;
  EVP_PKEY_get_size: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_size;
  EVP_PKEY_set_type: function (pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_type;
  EVP_PKEY_set_type_str: function (pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_type_str;
  EVP_PKEY_set1_engine: function (pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_engine;
  EVP_PKEY_get0_engine: function (const pkey: PEVP_PKEY): PENGINE; cdecl = Load_EVP_PKEY_get0_engine;
  EVP_PKEY_assign: function (pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign;
  EVP_PKEY_get0: function (const pkey: PEVP_PKEY): Pointer; cdecl = Load_EVP_PKEY_get0;
  EVP_PKEY_get0_hmac: function (const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl = Load_EVP_PKEY_get0_hmac;
  EVP_PKEY_get0_poly1305: function (const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl = Load_EVP_PKEY_get0_poly1305;
  EVP_PKEY_get0_siphash: function (const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl = Load_EVP_PKEY_get0_siphash;
  EVP_PKEY_set1_RSA: function (pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_RSA;
  EVP_PKEY_get0_RSA: function (pkey: PEVP_PKEY): PRSA; cdecl = Load_EVP_PKEY_get0_RSA;
  EVP_PKEY_get1_RSA: function (pkey: PEVP_PKEY): PRSA; cdecl = Load_EVP_PKEY_get1_RSA;
  EVP_PKEY_set1_DSA: function (pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_DSA;
  EVP_PKEY_get0_DSA: function (pkey: PEVP_PKEY): PDSA; cdecl = Load_EVP_PKEY_get0_DSA;
  EVP_PKEY_get1_DSA: function (pkey: PEVP_PKEY): PDSA; cdecl = Load_EVP_PKEY_get1_DSA;
  EVP_PKEY_set1_DH: function (pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_DH;
  EVP_PKEY_get0_DH: function (pkey: PEVP_PKEY): PDH; cdecl = Load_EVP_PKEY_get0_DH;
  EVP_PKEY_get1_DH: function (pkey: PEVP_PKEY): PDH; cdecl = Load_EVP_PKEY_get1_DH;
  EVP_PKEY_set1_EC_KEY: function (pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_EC_KEY;
  EVP_PKEY_get0_EC_KEY: function (pkey: PEVP_PKEY): PEC_KEY; cdecl = Load_EVP_PKEY_get0_EC_KEY;
  EVP_PKEY_get1_EC_KEY: function (pkey: PEVP_PKEY): PEC_KEY; cdecl = Load_EVP_PKEY_get1_EC_KEY;
  EVP_PKEY_new: function : PEVP_PKEY; cdecl = Load_EVP_PKEY_new;
  EVP_PKEY_up_ref: function (pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_up_ref;
  EVP_PKEY_free: procedure (pkey: PEVP_PKEY); cdecl = Load_EVP_PKEY_free;
  d2i_PublicKey: function (type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = Load_d2i_PublicKey;
  i2d_PublicKey: function (a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PublicKey;
  d2i_PrivateKey: function (type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = Load_d2i_PrivateKey;
  d2i_AutoPrivateKey: function (a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = Load_d2i_AutoPrivateKey;
  i2d_PrivateKey: function (a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PrivateKey;
  EVP_PKEY_copy_parameters: function (to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_copy_parameters;
  EVP_PKEY_missing_parameters: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_missing_parameters;
  EVP_PKEY_save_parameters: function (pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_save_parameters;
  EVP_PKEY_cmp_parameters: function (const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_cmp_parameters;
  EVP_PKEY_cmp: function (const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_cmp;
  EVP_PKEY_print_public: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_public;
  EVP_PKEY_print_private: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_private;
  EVP_PKEY_print_params: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_params;
  EVP_PKEY_get_default_digest_nid: function (pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_default_digest_nid;
  EVP_CIPHER_param_to_asn1: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_param_to_asn1;
  EVP_CIPHER_asn1_to_param: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_asn1_to_param;
  EVP_CIPHER_set_asn1_iv: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_set_asn1_iv;
  EVP_CIPHER_get_asn1_iv: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_asn1_iv;
  PKCS5_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBE_keyivgen;
  PKCS5_PBKDF2_HMAC_SHA1: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBKDF2_HMAC_SHA1;
  PKCS5_PBKDF2_HMAC: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBKDF2_HMAC;
  PKCS5_v2_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_v2_PBE_keyivgen;
  EVP_PBE_scrypt: function (const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_scrypt;
  PKCS5_v2_scrypt_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_v2_scrypt_keyivgen;
  PKCS5_PBE_add: procedure ; cdecl = Load_PKCS5_PBE_add;
  EVP_PBE_CipherInit: function (pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_CipherInit;
  EVP_PBE_alg_add_type: function (pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_alg_add_type;
  EVP_PBE_alg_add: function (nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_alg_add;
  EVP_PBE_find: function (type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_find;
  EVP_PBE_cleanup: procedure ; cdecl = Load_EVP_PBE_cleanup;
  EVP_PBE_get: function (ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_get;
  EVP_PKEY_asn1_get_count: function : TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_get_count;
  EVP_PKEY_asn1_get0: function (idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_get0;
  EVP_PKEY_asn1_find: function (pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_find;
  EVP_PKEY_asn1_find_str: function (pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_find_str;
  EVP_PKEY_asn1_add0: function (const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_add0;
  EVP_PKEY_asn1_add_alias: function (to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_add_alias;
  EVP_PKEY_asn1_get0_info: function (ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_get0_info;
  EVP_PKEY_get0_asn1: function (const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_get0_asn1;
  EVP_PKEY_asn1_new: function (id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_new;
  EVP_PKEY_asn1_copy: procedure (dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl = Load_EVP_PKEY_asn1_copy;
  EVP_PKEY_asn1_free: procedure (ameth: PEVP_PKEY_ASN1_METHOD); cdecl = Load_EVP_PKEY_asn1_free;
  EVP_PKEY_asn1_set_public: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl = Load_EVP_PKEY_asn1_set_public;
  EVP_PKEY_asn1_set_private: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl = Load_EVP_PKEY_asn1_set_private;
  EVP_PKEY_asn1_set_param: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl = Load_EVP_PKEY_asn1_set_param;
  EVP_PKEY_asn1_set_free: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl = Load_EVP_PKEY_asn1_set_free;
  EVP_PKEY_asn1_set_ctrl: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl = Load_EVP_PKEY_asn1_set_ctrl;
  EVP_PKEY_asn1_set_item: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl = Load_EVP_PKEY_asn1_set_item;
  EVP_PKEY_asn1_set_siginf: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl = Load_EVP_PKEY_asn1_set_siginf;
  EVP_PKEY_asn1_set_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl = Load_EVP_PKEY_asn1_set_check;
  EVP_PKEY_asn1_set_public_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl = Load_EVP_PKEY_asn1_set_public_check;
  EVP_PKEY_asn1_set_param_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl = Load_EVP_PKEY_asn1_set_param_check;
  EVP_PKEY_asn1_set_set_priv_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl = Load_EVP_PKEY_asn1_set_set_priv_key;
  EVP_PKEY_asn1_set_set_pub_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl = Load_EVP_PKEY_asn1_set_set_pub_key;
  EVP_PKEY_asn1_set_get_priv_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl = Load_EVP_PKEY_asn1_set_get_priv_key;
  EVP_PKEY_asn1_set_get_pub_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl = Load_EVP_PKEY_asn1_set_get_pub_key;
  EVP_PKEY_asn1_set_security_bits: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl = Load_EVP_PKEY_asn1_set_security_bits;
  EVP_PKEY_meth_find: function (type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = Load_EVP_PKEY_meth_find;
  EVP_PKEY_meth_new: function (id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = Load_EVP_PKEY_meth_new;
  EVP_PKEY_meth_get0_info: procedure (ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl = Load_EVP_PKEY_meth_get0_info;
  EVP_PKEY_meth_copy: procedure (dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl = Load_EVP_PKEY_meth_copy;
  EVP_PKEY_meth_free: procedure (pmeth: PEVP_PKEY_METHOD); cdecl = Load_EVP_PKEY_meth_free;
  EVP_PKEY_meth_add0: function (const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_meth_add0;
  EVP_PKEY_meth_remove: function (const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_meth_remove;
  EVP_PKEY_meth_get_count: function : TOpenSSL_C_SIZET; cdecl = Load_EVP_PKEY_meth_get_count;
  EVP_PKEY_meth_get0: function (idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl = Load_EVP_PKEY_meth_get0;
  EVP_PKEY_CTX_new: function (pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_new;
  EVP_PKEY_CTX_new_id: function (id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_new_id;
  EVP_PKEY_CTX_dup: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_dup;
  EVP_PKEY_CTX_free: procedure (ctx: PEVP_PKEY_CTX); cdecl = Load_EVP_PKEY_CTX_free;
  EVP_PKEY_CTX_ctrl: function (ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_ctrl;
  EVP_PKEY_CTX_ctrl_str: function (ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_ctrl_str;
  EVP_PKEY_CTX_ctrl_uint64: function (ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_ctrl_uint64;
  EVP_PKEY_CTX_str2ctrl: function (ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_str2ctrl;
  EVP_PKEY_CTX_hex2ctrl: function (ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_hex2ctrl;
  EVP_PKEY_CTX_md: function (ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_md;
  EVP_PKEY_CTX_get_operation: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_operation;
  EVP_PKEY_CTX_set0_keygen_info: procedure (ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl = Load_EVP_PKEY_CTX_set0_keygen_info;
  EVP_PKEY_new_mac_key: function (type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_mac_key;
  EVP_PKEY_new_raw_private_key: function (type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_raw_private_key;
  EVP_PKEY_new_raw_public_key: function (type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_raw_public_key;
  EVP_PKEY_get_raw_private_key: function (const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_raw_private_key;
  EVP_PKEY_get_raw_public_key: function (const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_raw_public_key;
  EVP_PKEY_new_CMAC_key: function (e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_CMAC_key;
  EVP_PKEY_CTX_set_data: procedure (ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = Load_EVP_PKEY_CTX_set_data;
  EVP_PKEY_CTX_get_data: function (ctx: PEVP_PKEY_CTX): Pointer; cdecl = Load_EVP_PKEY_CTX_get_data;
  EVP_PKEY_CTX_get0_pkey: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = Load_EVP_PKEY_CTX_get0_pkey;
  EVP_PKEY_CTX_get0_peerkey: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = Load_EVP_PKEY_CTX_get0_peerkey;
  EVP_PKEY_CTX_set_app_data: procedure (ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = Load_EVP_PKEY_CTX_set_app_data;
  EVP_PKEY_CTX_get_app_data: function (ctx: PEVP_PKEY_CTX): Pointer; cdecl = Load_EVP_PKEY_CTX_get_app_data;
  EVP_PKEY_sign_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_init;
  EVP_PKEY_sign: function (ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign;
  EVP_PKEY_verify_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_init;
  EVP_PKEY_verify: function (ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify;
  EVP_PKEY_verify_recover_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_recover_init;
  EVP_PKEY_verify_recover: function (ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_recover;
  EVP_PKEY_encrypt_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt_init;
  EVP_PKEY_encrypt: function (ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt;
  EVP_PKEY_decrypt_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt_init;
  EVP_PKEY_decrypt: function (ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt;
  EVP_PKEY_derive_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive_init;
  EVP_PKEY_derive_set_peer: function (ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive_set_peer;
  EVP_PKEY_derive: function (ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive;
  EVP_PKEY_paramgen_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_paramgen_init;
  EVP_PKEY_paramgen: function (ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_paramgen;
  EVP_PKEY_keygen_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_keygen_init;
  EVP_PKEY_keygen: function (ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_keygen;
  EVP_PKEY_check: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_check;
  EVP_PKEY_public_check: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_public_check;
  EVP_PKEY_param_check: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_param_check;
  EVP_PKEY_CTX_set_cb: procedure (ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl = Load_EVP_PKEY_CTX_set_cb;
  EVP_PKEY_CTX_get_cb: function (ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl = Load_EVP_PKEY_CTX_get_cb;
  EVP_PKEY_CTX_get_keygen_info: function (ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_keygen_info;
  EVP_PKEY_meth_set_init: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl = Load_EVP_PKEY_meth_set_init;
  EVP_PKEY_meth_set_copy: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl = Load_EVP_PKEY_meth_set_copy;
  EVP_PKEY_meth_set_cleanup: procedure (pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl = Load_EVP_PKEY_meth_set_cleanup;
  EVP_PKEY_meth_set_paramgen: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl = Load_EVP_PKEY_meth_set_paramgen;
  EVP_PKEY_meth_set_keygen: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl = Load_EVP_PKEY_meth_set_keygen;
  EVP_PKEY_meth_set_sign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl = Load_EVP_PKEY_meth_set_sign;
  EVP_PKEY_meth_set_verify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl = Load_EVP_PKEY_meth_set_verify;
  EVP_PKEY_meth_set_verify_recover: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl = Load_EVP_PKEY_meth_set_verify_recover;
  EVP_PKEY_meth_set_signctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl = Load_EVP_PKEY_meth_set_signctx;
  EVP_PKEY_meth_set_verifyctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl = Load_EVP_PKEY_meth_set_verifyctx;
  EVP_PKEY_meth_set_encrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl = Load_EVP_PKEY_meth_set_encrypt;
  EVP_PKEY_meth_set_decrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl = Load_EVP_PKEY_meth_set_decrypt;
  EVP_PKEY_meth_set_derive: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl = Load_EVP_PKEY_meth_set_derive;
  EVP_PKEY_meth_set_ctrl: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl = Load_EVP_PKEY_meth_set_ctrl;
  EVP_PKEY_meth_set_digestsign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl = Load_EVP_PKEY_meth_set_digestsign;
  EVP_PKEY_meth_set_digestverify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl = Load_EVP_PKEY_meth_set_digestverify;
  EVP_PKEY_meth_set_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl = Load_EVP_PKEY_meth_set_check;
  EVP_PKEY_meth_set_public_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl = Load_EVP_PKEY_meth_set_public_check;
  EVP_PKEY_meth_set_param_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl = Load_EVP_PKEY_meth_set_param_check;
  EVP_PKEY_meth_set_digest_custom: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl = Load_EVP_PKEY_meth_set_digest_custom;
  EVP_PKEY_meth_get_init: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl = Load_EVP_PKEY_meth_get_init;
  EVP_PKEY_meth_get_copy: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl = Load_EVP_PKEY_meth_get_copy;
  EVP_PKEY_meth_get_cleanup: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl = Load_EVP_PKEY_meth_get_cleanup;
  EVP_PKEY_meth_get_paramgen: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl = Load_EVP_PKEY_meth_get_paramgen;
  EVP_PKEY_meth_get_keygen: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl = Load_EVP_PKEY_meth_get_keygen;
  EVP_PKEY_meth_get_sign: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl = Load_EVP_PKEY_meth_get_sign;
  EVP_PKEY_meth_get_verify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl = Load_EVP_PKEY_meth_get_verify;
  EVP_PKEY_meth_get_verify_recover: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl = Load_EVP_PKEY_meth_get_verify_recover;
  EVP_PKEY_meth_get_signctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl = Load_EVP_PKEY_meth_get_signctx;
  EVP_PKEY_meth_get_verifyctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl = Load_EVP_PKEY_meth_get_verifyctx;
  EVP_PKEY_meth_get_encrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl = Load_EVP_PKEY_meth_get_encrypt;
  EVP_PKEY_meth_get_decrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl = Load_EVP_PKEY_meth_get_decrypt;
  EVP_PKEY_meth_get_derive: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl = Load_EVP_PKEY_meth_get_derive;
  EVP_PKEY_meth_get_ctrl: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl = Load_EVP_PKEY_meth_get_ctrl;
  EVP_PKEY_meth_get_digestsign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl = Load_EVP_PKEY_meth_get_digestsign;
  EVP_PKEY_meth_get_digestverify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl = Load_EVP_PKEY_meth_get_digestverify;
  EVP_PKEY_meth_get_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl = Load_EVP_PKEY_meth_get_check;
  EVP_PKEY_meth_get_public_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl = Load_EVP_PKEY_meth_get_public_check;
  EVP_PKEY_meth_get_param_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl = Load_EVP_PKEY_meth_get_param_check;
  EVP_PKEY_meth_get_digest_custom: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl = Load_EVP_PKEY_meth_get_digest_custom;
  EVP_add_alg_module: procedure ; cdecl = Load_EVP_add_alg_module;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  EVP_PKEY_assign_RSA: function (pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign_RSA; {removed 1.0.0}
  EVP_PKEY_assign_DSA: function (pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign_DSA; {removed 1.0.0}
  EVP_PKEY_assign_DH: function (pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign_DH; {removed 1.0.0}
  EVP_PKEY_assign_EC_KEY: function (pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign_EC_KEY; {removed 1.0.0}
  EVP_PKEY_assign_SIPHASH: function (pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign_SIPHASH; {removed 1.0.0}
  EVP_PKEY_assign_POLY1305: function (pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign_POLY1305; {removed 1.0.0}
  BIO_set_md: procedure (v1: PBIO; const md: PEVP_MD); cdecl = Load_BIO_set_md; {removed 1.0.0}
{$IFNDEF OPENSSL_NO_MD2}
  EVP_md2: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
  EVP_md4: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
  EVP_md5: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF}
  EVP_PKEY_security_bits: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_security_bits; {removed 3.0.0}
  EVP_PKEY_size: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_size; {removed 3.0.0}
  OpenSSL_add_all_ciphers: procedure ; cdecl = Load_OpenSSL_add_all_ciphers; {removed 1.1.0}
  OpenSSL_add_all_digests: procedure ; cdecl = Load_OpenSSL_add_all_digests; {removed 1.1.0}
  EVP_cleanup: procedure ; cdecl = Load_EVP_cleanup; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  EVP_PKEY_assign_RSA_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_DSA_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_DH_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_EC_KEY_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_SIPHASH_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_POLY1305_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_MD_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_input_blocksize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_result_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_app_datasize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_update_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_final_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_input_blocksize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_result_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_app_datasize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_update_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_final_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_iv_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_impl_ctx_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_do_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_set_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_get_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_do_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_set_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_get_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_pkey_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_block_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_flags_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_CTX_update_fn_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_set_update_fn_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_pkey_ctx_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_pkey_ctx_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_CTX_set_pkey_ctx_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_md_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_md_data_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_nid_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_block_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_impl_ctx_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_key_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_iv_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_flags_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_encrypting_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_encrypting_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_nid_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_block_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_key_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_iv_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_iv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_original_iv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_iv_noconst_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_buf_noconst_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_num_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_set_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_get_cipher_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_set_cipher_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_md_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_MD_CTX_init_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_MD_CTX_cleanup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_MD_CTX_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_reset_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_DigestFinalXOF_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_DigestSign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_DigestVerify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_reset_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_md2_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_md4_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_md5_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_md5_sha1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha512_224_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha512_256_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_224_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_256_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_384_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_512_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_shake128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_shake256_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_128_wrap_pad_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_128_ocb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_192_wrap_pad_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_192_ocb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_256_wrap_pad_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_256_ocb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cfb1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cfb8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_gcm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ccm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cfb1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cfb8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_gcm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ccm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cfb1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cfb8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_gcm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ccm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_camellia_128_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_camellia_192_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_camellia_256_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_chacha20_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_chacha20_poly1305_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_id_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_base_id_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get_base_id_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  EVP_PKEY_bits_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_security_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_security_bits_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get_security_bits_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  EVP_PKEY_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get_size_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  EVP_PKEY_set_alias_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_set_alias_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_set1_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_hmac_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_poly1305_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_siphash_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_RSA_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_DSA_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_DH_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_EC_KEY_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_set1_tls_encodedpoint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_set1_tls_encodedpoint_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get1_tls_encodedpoint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get1_tls_encodedpoint_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PBE_scrypt_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS5_v2_scrypt_keyivgen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PBE_get_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_siginf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_priv_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_pub_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_priv_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_pub_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_security_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_remove_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_count_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_ctrl_uint64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_str2ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_hex2ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_md_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_new_raw_private_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_new_raw_public_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get_raw_private_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get_raw_public_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_new_CMAC_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_digestsign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_digestverify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_digest_custom_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_digestsign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_digestverify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_digest_custom_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OpenSSL_add_all_ciphers_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  OpenSSL_add_all_digests_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_cleanup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}


implementation

uses IdOpenSSLHeaders_crypto,
Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

//#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA, (char *)(rsa))

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  EVP_MD_type: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_type; {removed 3.0.0}
  EVP_MD_pkey_type: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_pkey_type; {removed 3.0.0}
  EVP_MD_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_size; {removed 3.0.0}
  EVP_MD_block_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_block_size; {removed 3.0.0}
  EVP_MD_flags: function (const md: PEVP_MD): POpenSSL_C_ULONG; cdecl = Load_EVP_MD_flags; {removed 3.0.0}
  EVP_MD_CTX_pkey_ctx: function (const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl = Load_EVP_MD_CTX_pkey_ctx; {removed 3.0.0}
  EVP_MD_CTX_md_data: function (const ctx: PEVP_MD_CTX): Pointer; cdecl = Load_EVP_MD_CTX_md_data; {removed 3.0.0}
  EVP_CIPHER_nid: function (const ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_nid; {removed 3.0.0}
  EVP_CIPHER_block_size: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_block_size; {removed 3.0.0}
  EVP_CIPHER_key_length: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_key_length; {removed 3.0.0}
  EVP_CIPHER_iv_length: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_iv_length; {removed 3.0.0}
  EVP_CIPHER_flags: function (const cipher: PEVP_CIPHER): TOpenSSL_C_ULONG; cdecl = Load_EVP_CIPHER_flags; {removed 3.0.0}
  EVP_CIPHER_CTX_encrypting: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_encrypting; {removed 3.0.0}
  EVP_CIPHER_CTX_nid: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_nid; {removed 3.0.0}
  EVP_CIPHER_CTX_block_size: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_block_size; {removed 3.0.0}
  EVP_CIPHER_CTX_key_length: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_key_length; {removed 3.0.0}
  EVP_CIPHER_CTX_iv_length: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_iv_length; {removed 3.0.0}
  EVP_CIPHER_CTX_num: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_num; {removed 3.0.0}
  EVP_MD_CTX_init: procedure (ctx : PEVP_MD_CTX); cdecl = Load_EVP_MD_CTX_init; {removed 1.1.0}
  EVP_MD_CTX_cleanup: function (ctx : PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_cleanup; {removed 1.1.0}
{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
  EVP_PKEY_id: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_id; {removed 3.0.0}
  EVP_PKEY_base_id: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_base_id; {removed 3.0.0}
  EVP_PKEY_bits: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_bits; {removed 3.0.0}
  EVP_PKEY_set_alias_type: function (pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_alias_type; {removed 3.0.0}
  EVP_PKEY_set1_tls_encodedpoint: function (pkey: PEVP_PKEY; const pt: PByte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_tls_encodedpoint; {removed 3.0.0}
  EVP_PKEY_get1_tls_encodedpoint: function (pkey: PEVP_PKEY; ppt: PPByte): TOpenSSL_C_SIZET; cdecl = Load_EVP_PKEY_get1_tls_encodedpoint; {removed 3.0.0}
  EVP_CIPHER_type: function (const ctx: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_type; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
end;

//#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA, (char *)(dsa))


function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
end;

//#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH, (char *)(dh))


function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh);
end;

//#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC, (char *)(eckey))


function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey);
end;

//#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH, (char *)(shkey))


function EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_SIPHASH, shkey);
end;

//#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305, (char *)(polykey))


function EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_POLY1305, polykey);
end;



procedure OpenSSL_add_all_ciphers;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);
end;



procedure OpenSSL_add_all_digests;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, Nil);
end;



procedure EVP_cleanup;

begin
end;



procedure BIO_set_md(v1: PBIO; const md: PEVP_MD);

begin
  {define BIO_set_md(b,md)  BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))}
  BIO_ctrl(v1,BIO_C_SET_MD,0,PAnsiChar(md));
end;



{$WARN   NO_RETVAL OFF}
{$IFNDEF  OPENSSL_NO_MD2}
function EVP_md2: PEVP_MD;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF }
{$IFNDEF  OPENSSL_NO_MD4}
function EVP_md4: PEVP_MD;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF }
{$IFNDEF  OPENSSL_NO_MD5}
function EVP_md5: PEVP_MD;

begin
  Result := EVP_md5_sha1;
end;

{$ENDIF }
{$WARN   NO_RETVAL ON}
function EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_get_security_bits(pkey);
end;



function EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_get_size(pkey);
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
end;

//#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA, (char *)(dsa))


function COMPAT_EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
end;

//#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH, (char *)(dh))


function COMPAT_EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh);
end;

//#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC, (char *)(eckey))


function COMPAT_EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey);
end;

//#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH, (char *)(shkey))


function COMPAT_EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_SIPHASH, shkey);
end;

//#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305, (char *)(polykey))


function COMPAT_EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_POLY1305, polykey);
end;



procedure COMPAT_OpenSSL_add_all_ciphers; cdecl;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);
end;



procedure COMPAT_OpenSSL_add_all_digests; cdecl;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, Nil);
end;



procedure COMPAT_EVP_cleanup; cdecl;

begin
end;



procedure COMPAT_BIO_set_md(v1: PBIO; const md: PEVP_MD); cdecl;

begin
  {define BIO_set_md(b,md)  BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))}
  BIO_ctrl(v1,BIO_C_SET_MD,0,PAnsiChar(md));
end;



function COMPAT_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;

begin
  Result := AllocMem(SizeOf(EVP_MD_CTX));
  EVP_MD_CTX_init(Result);
end;



procedure COMPAT_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;

begin
  EVP_MD_CTX_cleanup(ctx);
  FreeMem(ctx,SizeOf(EVP_MD_CTX));
end;


{$WARN  NO_RETVAL OFF}
{$IFNDEF OPENSSL_NO_MD2}
function COMPAT_EVP_md2: PEVP_MD; cdecl;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
function COMPAT_EVP_md4: PEVP_MD; cdecl;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
function COMPAT_EVP_md5: PEVP_MD; cdecl;

begin
  Result := EVP_md5_sha1;
end;

{$ENDIF}
{$WARN  NO_RETVAL ON}
function COMPAT_EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_get_security_bits(pkey);
end;



function COMPAT_EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_get_size(pkey);
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign_RSA := LoadLibCryptoFunction('EVP_PKEY_assign_RSA');
  if not assigned(EVP_PKEY_assign_RSA) then
    EVP_PKEY_assign_RSA := @COMPAT_EVP_PKEY_assign_RSA;
  Result := EVP_PKEY_assign_RSA(pkey,rsa);
end;

function Load_EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign_DSA := LoadLibCryptoFunction('EVP_PKEY_assign_DSA');
  if not assigned(EVP_PKEY_assign_DSA) then
    EVP_PKEY_assign_DSA := @COMPAT_EVP_PKEY_assign_DSA;
  Result := EVP_PKEY_assign_DSA(pkey,dsa);
end;

function Load_EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign_DH := LoadLibCryptoFunction('EVP_PKEY_assign_DH');
  if not assigned(EVP_PKEY_assign_DH) then
    EVP_PKEY_assign_DH := @COMPAT_EVP_PKEY_assign_DH;
  Result := EVP_PKEY_assign_DH(pkey,dh);
end;

function Load_EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_assign_EC_KEY');
  if not assigned(EVP_PKEY_assign_EC_KEY) then
    EVP_PKEY_assign_EC_KEY := @COMPAT_EVP_PKEY_assign_EC_KEY;
  Result := EVP_PKEY_assign_EC_KEY(pkey,eckey);
end;

function Load_EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign_SIPHASH := LoadLibCryptoFunction('EVP_PKEY_assign_SIPHASH');
  if not assigned(EVP_PKEY_assign_SIPHASH) then
    EVP_PKEY_assign_SIPHASH := @COMPAT_EVP_PKEY_assign_SIPHASH;
  Result := EVP_PKEY_assign_SIPHASH(pkey,shkey);
end;

function Load_EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign_POLY1305 := LoadLibCryptoFunction('EVP_PKEY_assign_POLY1305');
  if not assigned(EVP_PKEY_assign_POLY1305) then
    EVP_PKEY_assign_POLY1305 := @COMPAT_EVP_PKEY_assign_POLY1305;
  Result := EVP_PKEY_assign_POLY1305(pkey,polykey);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl;
begin
  EVP_MD_meth_new := LoadLibCryptoFunction('EVP_MD_meth_new');
  if not assigned(EVP_MD_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_new');
  Result := EVP_MD_meth_new(md_type,pkey_type);
end;

function Load_EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD; cdecl;
begin
  EVP_MD_meth_dup := LoadLibCryptoFunction('EVP_MD_meth_dup');
  if not assigned(EVP_MD_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_dup');
  Result := EVP_MD_meth_dup(md);
end;

procedure Load_EVP_MD_meth_free(md: PEVP_MD); cdecl;
begin
  EVP_MD_meth_free := LoadLibCryptoFunction('EVP_MD_meth_free');
  if not assigned(EVP_MD_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_free');
  EVP_MD_meth_free(md);
end;

function Load_EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_input_blocksize := LoadLibCryptoFunction('EVP_MD_meth_set_input_blocksize');
  if not assigned(EVP_MD_meth_set_input_blocksize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_input_blocksize');
  Result := EVP_MD_meth_set_input_blocksize(md,blocksize);
end;

function Load_EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_result_size := LoadLibCryptoFunction('EVP_MD_meth_set_result_size');
  if not assigned(EVP_MD_meth_set_result_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_result_size');
  Result := EVP_MD_meth_set_result_size(md,resultsize);
end;

function Load_EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_app_datasize := LoadLibCryptoFunction('EVP_MD_meth_set_app_datasize');
  if not assigned(EVP_MD_meth_set_app_datasize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_app_datasize');
  Result := EVP_MD_meth_set_app_datasize(md,datasize);
end;

function Load_EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_flags := LoadLibCryptoFunction('EVP_MD_meth_set_flags');
  if not assigned(EVP_MD_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_flags');
  Result := EVP_MD_meth_set_flags(md,flags);
end;

function Load_EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_init := LoadLibCryptoFunction('EVP_MD_meth_set_init');
  if not assigned(EVP_MD_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_init');
  Result := EVP_MD_meth_set_init(md,init);
end;

function Load_EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_update := LoadLibCryptoFunction('EVP_MD_meth_set_update');
  if not assigned(EVP_MD_meth_set_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_update');
  Result := EVP_MD_meth_set_update(md,update);
end;

function Load_EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_final := LoadLibCryptoFunction('EVP_MD_meth_set_final');
  if not assigned(EVP_MD_meth_set_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_final');
  Result := EVP_MD_meth_set_final(md,final_);
end;

function Load_EVP_MD_meth_set_copy(md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_copy := LoadLibCryptoFunction('EVP_MD_meth_set_copy');
  if not assigned(EVP_MD_meth_set_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_copy');
  Result := EVP_MD_meth_set_copy(md,copy);
end;

function Load_EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_cleanup := LoadLibCryptoFunction('EVP_MD_meth_set_cleanup');
  if not assigned(EVP_MD_meth_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_cleanup');
  Result := EVP_MD_meth_set_cleanup(md,cleanup);
end;

function Load_EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_ctrl := LoadLibCryptoFunction('EVP_MD_meth_set_ctrl');
  if not assigned(EVP_MD_meth_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_ctrl');
  Result := EVP_MD_meth_set_ctrl(md,ctrl);
end;

function Load_EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_get_input_blocksize := LoadLibCryptoFunction('EVP_MD_meth_get_input_blocksize');
  if not assigned(EVP_MD_meth_get_input_blocksize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_input_blocksize');
  Result := EVP_MD_meth_get_input_blocksize(md);
end;

function Load_EVP_MD_meth_get_result_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_get_result_size := LoadLibCryptoFunction('EVP_MD_meth_get_result_size');
  if not assigned(EVP_MD_meth_get_result_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_result_size');
  Result := EVP_MD_meth_get_result_size(md);
end;

function Load_EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_get_app_datasize := LoadLibCryptoFunction('EVP_MD_meth_get_app_datasize');
  if not assigned(EVP_MD_meth_get_app_datasize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_app_datasize');
  Result := EVP_MD_meth_get_app_datasize(md);
end;

function Load_EVP_MD_meth_get_flags(const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl;
begin
  EVP_MD_meth_get_flags := LoadLibCryptoFunction('EVP_MD_meth_get_flags');
  if not assigned(EVP_MD_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_flags');
  Result := EVP_MD_meth_get_flags(md);
end;

function Load_EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init; cdecl;
begin
  EVP_MD_meth_get_init := LoadLibCryptoFunction('EVP_MD_meth_get_init');
  if not assigned(EVP_MD_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_init');
  Result := EVP_MD_meth_get_init(md);
end;

function Load_EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update; cdecl;
begin
  EVP_MD_meth_get_update := LoadLibCryptoFunction('EVP_MD_meth_get_update');
  if not assigned(EVP_MD_meth_get_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_update');
  Result := EVP_MD_meth_get_update(md);
end;

function Load_EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final; cdecl;
begin
  EVP_MD_meth_get_final := LoadLibCryptoFunction('EVP_MD_meth_get_final');
  if not assigned(EVP_MD_meth_get_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_final');
  Result := EVP_MD_meth_get_final(md);
end;

function Load_EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy; cdecl;
begin
  EVP_MD_meth_get_copy := LoadLibCryptoFunction('EVP_MD_meth_get_copy');
  if not assigned(EVP_MD_meth_get_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_copy');
  Result := EVP_MD_meth_get_copy(md);
end;

function Load_EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl;
begin
  EVP_MD_meth_get_cleanup := LoadLibCryptoFunction('EVP_MD_meth_get_cleanup');
  if not assigned(EVP_MD_meth_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_cleanup');
  Result := EVP_MD_meth_get_cleanup(md);
end;

function Load_EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl;
begin
  EVP_MD_meth_get_ctrl := LoadLibCryptoFunction('EVP_MD_meth_get_ctrl');
  if not assigned(EVP_MD_meth_get_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_ctrl');
  Result := EVP_MD_meth_get_ctrl(md);
end;

function Load_EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_meth_new := LoadLibCryptoFunction('EVP_CIPHER_meth_new');
  if not assigned(EVP_CIPHER_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_new');
  Result := EVP_CIPHER_meth_new(cipher_type,block_size,key_len);
end;

function Load_EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_meth_dup := LoadLibCryptoFunction('EVP_CIPHER_meth_dup');
  if not assigned(EVP_CIPHER_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_dup');
  Result := EVP_CIPHER_meth_dup(cipher);
end;

procedure Load_EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl;
begin
  EVP_CIPHER_meth_free := LoadLibCryptoFunction('EVP_CIPHER_meth_free');
  if not assigned(EVP_CIPHER_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_free');
  EVP_CIPHER_meth_free(cipher);
end;

function Load_EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_iv_length := LoadLibCryptoFunction('EVP_CIPHER_meth_set_iv_length');
  if not assigned(EVP_CIPHER_meth_set_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_iv_length');
  Result := EVP_CIPHER_meth_set_iv_length(cipher,iv_len);
end;

function Load_EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_flags := LoadLibCryptoFunction('EVP_CIPHER_meth_set_flags');
  if not assigned(EVP_CIPHER_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_flags');
  Result := EVP_CIPHER_meth_set_flags(cipher,flags);
end;

function Load_EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_impl_ctx_size := LoadLibCryptoFunction('EVP_CIPHER_meth_set_impl_ctx_size');
  if not assigned(EVP_CIPHER_meth_set_impl_ctx_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_impl_ctx_size');
  Result := EVP_CIPHER_meth_set_impl_ctx_size(cipher,ctx_size);
end;

function Load_EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_init := LoadLibCryptoFunction('EVP_CIPHER_meth_set_init');
  if not assigned(EVP_CIPHER_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_init');
  Result := EVP_CIPHER_meth_set_init(cipher,init);
end;

function Load_EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_do_cipher := LoadLibCryptoFunction('EVP_CIPHER_meth_set_do_cipher');
  if not assigned(EVP_CIPHER_meth_set_do_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_do_cipher');
  Result := EVP_CIPHER_meth_set_do_cipher(cipher,do_cipher);
end;

function Load_EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_cleanup := LoadLibCryptoFunction('EVP_CIPHER_meth_set_cleanup');
  if not assigned(EVP_CIPHER_meth_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_cleanup');
  Result := EVP_CIPHER_meth_set_cleanup(cipher,cleanup);
end;

function Load_EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_set_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_set_set_asn1_params');
  if not assigned(EVP_CIPHER_meth_set_set_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_set_asn1_params');
  Result := EVP_CIPHER_meth_set_set_asn1_params(cipher,set_asn1_parameters);
end;

function Load_EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_get_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_set_get_asn1_params');
  if not assigned(EVP_CIPHER_meth_set_get_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_get_asn1_params');
  Result := EVP_CIPHER_meth_set_get_asn1_params(cipher,get_asn1_parameters);
end;

function Load_EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_ctrl := LoadLibCryptoFunction('EVP_CIPHER_meth_set_ctrl');
  if not assigned(EVP_CIPHER_meth_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_ctrl');
  Result := EVP_CIPHER_meth_set_ctrl(cipher,ctrl);
end;

function Load_EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl;
begin
  EVP_CIPHER_meth_get_init := LoadLibCryptoFunction('EVP_CIPHER_meth_get_init');
  if not assigned(EVP_CIPHER_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_init');
  Result := EVP_CIPHER_meth_get_init(cipher);
end;

function Load_EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl;
begin
  EVP_CIPHER_meth_get_do_cipher := LoadLibCryptoFunction('EVP_CIPHER_meth_get_do_cipher');
  if not assigned(EVP_CIPHER_meth_get_do_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_do_cipher');
  Result := EVP_CIPHER_meth_get_do_cipher(cipher);
end;

function Load_EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl;
begin
  EVP_CIPHER_meth_get_cleanup := LoadLibCryptoFunction('EVP_CIPHER_meth_get_cleanup');
  if not assigned(EVP_CIPHER_meth_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_cleanup');
  Result := EVP_CIPHER_meth_get_cleanup(cipher);
end;

function Load_EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl;
begin
  EVP_CIPHER_meth_get_set_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_get_set_asn1_params');
  if not assigned(EVP_CIPHER_meth_get_set_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_set_asn1_params');
  Result := EVP_CIPHER_meth_get_set_asn1_params(cipher);
end;

function Load_EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl;
begin
  EVP_CIPHER_meth_get_get_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_get_get_asn1_params');
  if not assigned(EVP_CIPHER_meth_get_get_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_get_asn1_params');
  Result := EVP_CIPHER_meth_get_get_asn1_params(cipher);
end;

function Load_EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl;
begin
  EVP_CIPHER_meth_get_ctrl := LoadLibCryptoFunction('EVP_CIPHER_meth_get_ctrl');
  if not assigned(EVP_CIPHER_meth_get_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_ctrl');
  Result := EVP_CIPHER_meth_get_ctrl(cipher);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_MD_type(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_type := LoadLibCryptoFunction('EVP_MD_type');
  if not assigned(EVP_MD_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_type');
  Result := EVP_MD_type(md);
end;

function Load_EVP_MD_pkey_type(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_pkey_type := LoadLibCryptoFunction('EVP_MD_pkey_type');
  if not assigned(EVP_MD_pkey_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_pkey_type');
  Result := EVP_MD_pkey_type(md);
end;

function Load_EVP_MD_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_size := LoadLibCryptoFunction('EVP_MD_size');
  if not assigned(EVP_MD_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_size');
  Result := EVP_MD_size(md);
end;

function Load_EVP_MD_block_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_block_size := LoadLibCryptoFunction('EVP_MD_block_size');
  if not assigned(EVP_MD_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_block_size');
  Result := EVP_MD_block_size(md);
end;

function Load_EVP_MD_flags(const md: PEVP_MD): POpenSSL_C_ULONG; cdecl;
begin
  EVP_MD_flags := LoadLibCryptoFunction('EVP_MD_flags');
  if not assigned(EVP_MD_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_flags');
  Result := EVP_MD_flags(md);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
begin
  EVP_MD_CTX_md := LoadLibCryptoFunction('EVP_MD_CTX_md');
  if not assigned(EVP_MD_CTX_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_md');
  Result := EVP_MD_CTX_md(ctx);
end;

function Load_EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl;
begin
  EVP_MD_CTX_update_fn := LoadLibCryptoFunction('EVP_MD_CTX_update_fn');
  if not assigned(EVP_MD_CTX_update_fn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_update_fn');
  Result := EVP_MD_CTX_update_fn(ctx);
end;

procedure Load_EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl;
begin
  EVP_MD_CTX_set_update_fn := LoadLibCryptoFunction('EVP_MD_CTX_set_update_fn');
  if not assigned(EVP_MD_CTX_set_update_fn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_update_fn');
  EVP_MD_CTX_set_update_fn(ctx,update);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_MD_CTX_pkey_ctx(const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl;
begin
  EVP_MD_CTX_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_pkey_ctx');
  if not assigned(EVP_MD_CTX_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_pkey_ctx');
  Result := EVP_MD_CTX_pkey_ctx(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl;
begin
  EVP_MD_CTX_set_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_set_pkey_ctx');
  if not assigned(EVP_MD_CTX_set_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_pkey_ctx');
  EVP_MD_CTX_set_pkey_ctx(ctx,pctx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_MD_CTX_md_data(const ctx: PEVP_MD_CTX): Pointer; cdecl;
begin
  EVP_MD_CTX_md_data := LoadLibCryptoFunction('EVP_MD_CTX_md_data');
  if not assigned(EVP_MD_CTX_md_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_md_data');
  Result := EVP_MD_CTX_md_data(ctx);
end;

function Load_EVP_CIPHER_nid(const ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_nid := LoadLibCryptoFunction('EVP_CIPHER_nid');
  if not assigned(EVP_CIPHER_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_nid');
  Result := EVP_CIPHER_nid(ctx);
end;

function Load_EVP_CIPHER_block_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_block_size := LoadLibCryptoFunction('EVP_CIPHER_block_size');
  if not assigned(EVP_CIPHER_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_block_size');
  Result := EVP_CIPHER_block_size(cipher);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_impl_ctx_size := LoadLibCryptoFunction('EVP_CIPHER_impl_ctx_size');
  if not assigned(EVP_CIPHER_impl_ctx_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_impl_ctx_size');
  Result := EVP_CIPHER_impl_ctx_size(cipher);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_CIPHER_key_length(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_key_length := LoadLibCryptoFunction('EVP_CIPHER_key_length');
  if not assigned(EVP_CIPHER_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_key_length');
  Result := EVP_CIPHER_key_length(cipher);
end;

function Load_EVP_CIPHER_iv_length(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_iv_length := LoadLibCryptoFunction('EVP_CIPHER_iv_length');
  if not assigned(EVP_CIPHER_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_iv_length');
  Result := EVP_CIPHER_iv_length(cipher);
end;

function Load_EVP_CIPHER_flags(const cipher: PEVP_CIPHER): TOpenSSL_C_ULONG; cdecl;
begin
  EVP_CIPHER_flags := LoadLibCryptoFunction('EVP_CIPHER_flags');
  if not assigned(EVP_CIPHER_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_flags');
  Result := EVP_CIPHER_flags(cipher);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_CTX_cipher := LoadLibCryptoFunction('EVP_CIPHER_CTX_cipher');
  if not assigned(EVP_CIPHER_CTX_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_cipher');
  Result := EVP_CIPHER_CTX_cipher(ctx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_CIPHER_CTX_encrypting(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_encrypting := LoadLibCryptoFunction('EVP_CIPHER_CTX_encrypting');
  if not assigned(EVP_CIPHER_CTX_encrypting) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_encrypting');
  Result := EVP_CIPHER_CTX_encrypting(ctx);
end;

function Load_EVP_CIPHER_CTX_nid(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_nid := LoadLibCryptoFunction('EVP_CIPHER_CTX_nid');
  if not assigned(EVP_CIPHER_CTX_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_nid');
  Result := EVP_CIPHER_CTX_nid(ctx);
end;

function Load_EVP_CIPHER_CTX_block_size(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_block_size := LoadLibCryptoFunction('EVP_CIPHER_CTX_block_size');
  if not assigned(EVP_CIPHER_CTX_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_block_size');
  Result := EVP_CIPHER_CTX_block_size(ctx);
end;

function Load_EVP_CIPHER_CTX_key_length(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_key_length');
  if not assigned(EVP_CIPHER_CTX_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_key_length');
  Result := EVP_CIPHER_CTX_key_length(ctx);
end;

function Load_EVP_CIPHER_CTX_iv_length(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_iv_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv_length');
  if not assigned(EVP_CIPHER_CTX_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv_length');
  Result := EVP_CIPHER_CTX_iv_length(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EVP_CIPHER_CTX_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv');
  if not assigned(EVP_CIPHER_CTX_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv');
  Result := EVP_CIPHER_CTX_iv(ctx);
end;

function Load_EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EVP_CIPHER_CTX_original_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_original_iv');
  if not assigned(EVP_CIPHER_CTX_original_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_original_iv');
  Result := EVP_CIPHER_CTX_original_iv(ctx);
end;

function Load_EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EVP_CIPHER_CTX_iv_noconst := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv_noconst');
  if not assigned(EVP_CIPHER_CTX_iv_noconst) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv_noconst');
  Result := EVP_CIPHER_CTX_iv_noconst(ctx);
end;

function Load_EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EVP_CIPHER_CTX_buf_noconst := LoadLibCryptoFunction('EVP_CIPHER_CTX_buf_noconst');
  if not assigned(EVP_CIPHER_CTX_buf_noconst) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_buf_noconst');
  Result := EVP_CIPHER_CTX_buf_noconst(ctx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_CIPHER_CTX_num(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_num');
  if not assigned(EVP_CIPHER_CTX_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_num');
  Result := EVP_CIPHER_CTX_num(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl;
begin
  EVP_CIPHER_CTX_set_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_num');
  if not assigned(EVP_CIPHER_CTX_set_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_num');
  EVP_CIPHER_CTX_set_num(ctx,num);
end;

function Load_EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_copy := LoadLibCryptoFunction('EVP_CIPHER_CTX_copy');
  if not assigned(EVP_CIPHER_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_copy');
  Result := EVP_CIPHER_CTX_copy(out_,in_);
end;

function Load_EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl;
begin
  EVP_CIPHER_CTX_get_app_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_app_data');
  if not assigned(EVP_CIPHER_CTX_get_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_app_data');
  Result := EVP_CIPHER_CTX_get_app_data(ctx);
end;

procedure Load_EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl;
begin
  EVP_CIPHER_CTX_set_app_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_app_data');
  if not assigned(EVP_CIPHER_CTX_set_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_app_data');
  EVP_CIPHER_CTX_set_app_data(ctx,data);
end;

function Load_EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl;
begin
  EVP_CIPHER_CTX_get_cipher_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_cipher_data');
  if not assigned(EVP_CIPHER_CTX_get_cipher_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_cipher_data');
  Result := EVP_CIPHER_CTX_get_cipher_data(ctx);
end;

function Load_EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl;
begin
  EVP_CIPHER_CTX_set_cipher_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_cipher_data');
  if not assigned(EVP_CIPHER_CTX_set_cipher_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_cipher_data');
  Result := EVP_CIPHER_CTX_set_cipher_data(ctx,cipher_data);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_BIO_set_md(v1: PBIO; const md: PEVP_MD); cdecl;
begin
  BIO_set_md := LoadLibCryptoFunction('BIO_set_md');
  if not assigned(BIO_set_md) then
    BIO_set_md := @COMPAT_BIO_set_md;
  BIO_set_md(v1,md);
end;

procedure Load_EVP_MD_CTX_init(ctx : PEVP_MD_CTX); cdecl;
begin
  EVP_MD_CTX_init := LoadLibCryptoFunction('EVP_MD_CTX_init');
  if not assigned(EVP_MD_CTX_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_init');
  EVP_MD_CTX_init(ctx);
end;

function Load_EVP_MD_CTX_cleanup(ctx : PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_cleanup := LoadLibCryptoFunction('EVP_MD_CTX_cleanup');
  if not assigned(EVP_MD_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_cleanup');
  Result := EVP_MD_CTX_cleanup(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_ctrl := LoadLibCryptoFunction('EVP_MD_CTX_ctrl');
  if not assigned(EVP_MD_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_ctrl');
  Result := EVP_MD_CTX_ctrl(ctx,cmd,p1,p2);
end;

function Load_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;
begin
  EVP_MD_CTX_new := LoadLibCryptoFunction('EVP_MD_CTX_new');
  if not assigned(EVP_MD_CTX_new) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    EVP_MD_CTX_new := @COMPAT_EVP_MD_CTX_new;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_new');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := EVP_MD_CTX_new();
end;

function Load_EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_reset := LoadLibCryptoFunction('EVP_MD_CTX_reset');
  if not assigned(EVP_MD_CTX_reset) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_reset');
  Result := EVP_MD_CTX_reset(ctx);
end;

procedure Load_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;
begin
  EVP_MD_CTX_free := LoadLibCryptoFunction('EVP_MD_CTX_free');
  if not assigned(EVP_MD_CTX_free) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    EVP_MD_CTX_free := @COMPAT_EVP_MD_CTX_free;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_free');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_free(ctx);
end;

function Load_EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_copy_ex := LoadLibCryptoFunction('EVP_MD_CTX_copy_ex');
  if not assigned(EVP_MD_CTX_copy_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_copy_ex');
  Result := EVP_MD_CTX_copy_ex(out_,in_);
end;

procedure Load_EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_MD_CTX_set_flags := LoadLibCryptoFunction('EVP_MD_CTX_set_flags');
  if not assigned(EVP_MD_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_flags');
  EVP_MD_CTX_set_flags(ctx,flags);
end;

procedure Load_EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_MD_CTX_clear_flags := LoadLibCryptoFunction('EVP_MD_CTX_clear_flags');
  if not assigned(EVP_MD_CTX_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_clear_flags');
  EVP_MD_CTX_clear_flags(ctx,flags);
end;

function Load_EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_test_flags := LoadLibCryptoFunction('EVP_MD_CTX_test_flags');
  if not assigned(EVP_MD_CTX_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_test_flags');
  Result := EVP_MD_CTX_test_flags(ctx,flags);
end;

function Load_EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestInit_ex := LoadLibCryptoFunction('EVP_DigestInit_ex');
  if not assigned(EVP_DigestInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit_ex');
  Result := EVP_DigestInit_ex(ctx,type_,impl);
end;

function Load_EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestUpdate := LoadLibCryptoFunction('EVP_DigestUpdate');
  if not assigned(EVP_DigestUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestUpdate');
  Result := EVP_DigestUpdate(ctx,d,cnt);
end;

function Load_EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestFinal_ex := LoadLibCryptoFunction('EVP_DigestFinal_ex');
  if not assigned(EVP_DigestFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinal_ex');
  Result := EVP_DigestFinal_ex(ctx,md,s);
end;

function Load_EVP_Digest(const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EVP_Digest := LoadLibCryptoFunction('EVP_Digest');
  if not assigned(EVP_Digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_Digest');
  Result := EVP_Digest(data,count,md,size,type_,impl);
end;

function Load_EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_copy := LoadLibCryptoFunction('EVP_MD_CTX_copy');
  if not assigned(EVP_MD_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_copy');
  Result := EVP_MD_CTX_copy(out_,in_);
end;

function Load_EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestInit := LoadLibCryptoFunction('EVP_DigestInit');
  if not assigned(EVP_DigestInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit');
  Result := EVP_DigestInit(ctx,type_);
end;

function Load_EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestFinal := LoadLibCryptoFunction('EVP_DigestFinal');
  if not assigned(EVP_DigestFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinal');
  Result := EVP_DigestFinal(ctx,md,s);
end;

function Load_EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestFinalXOF := LoadLibCryptoFunction('EVP_DigestFinalXOF');
  if not assigned(EVP_DigestFinalXOF) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinalXOF');
  Result := EVP_DigestFinalXOF(ctx,md,len);
end;

function Load_EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_read_pw_string := LoadLibCryptoFunction('EVP_read_pw_string');
  if not assigned(EVP_read_pw_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_read_pw_string');
  Result := EVP_read_pw_string(buf,length,prompt,verify);
end;

function Load_EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_read_pw_string_min := LoadLibCryptoFunction('EVP_read_pw_string_min');
  if not assigned(EVP_read_pw_string_min) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_read_pw_string_min');
  Result := EVP_read_pw_string_min(buf,minlen,maxlen,prompt,verify);
end;

procedure Load_EVP_set_pw_prompt(const prompt: PAnsiChar); cdecl;
begin
  EVP_set_pw_prompt := LoadLibCryptoFunction('EVP_set_pw_prompt');
  if not assigned(EVP_set_pw_prompt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_set_pw_prompt');
  EVP_set_pw_prompt(prompt);
end;

function Load_EVP_get_pw_prompt: PAnsiChar; cdecl;
begin
  EVP_get_pw_prompt := LoadLibCryptoFunction('EVP_get_pw_prompt');
  if not assigned(EVP_get_pw_prompt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_pw_prompt');
  Result := EVP_get_pw_prompt();
end;

function Load_EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EVP_BytesToKey := LoadLibCryptoFunction('EVP_BytesToKey');
  if not assigned(EVP_BytesToKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_BytesToKey');
  Result := EVP_BytesToKey(type_,md,salt,data,data1,count,key,iv);
end;

procedure Load_EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_CIPHER_CTX_set_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_flags');
  if not assigned(EVP_CIPHER_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_flags');
  EVP_CIPHER_CTX_set_flags(ctx,flags);
end;

procedure Load_EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_CIPHER_CTX_clear_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_clear_flags');
  if not assigned(EVP_CIPHER_CTX_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_clear_flags');
  EVP_CIPHER_CTX_clear_flags(ctx,flags);
end;

function Load_EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_test_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_test_flags');
  if not assigned(EVP_CIPHER_CTX_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_test_flags');
  Result := EVP_CIPHER_CTX_test_flags(ctx,flags);
end;

function Load_EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptInit := LoadLibCryptoFunction('EVP_EncryptInit');
  if not assigned(EVP_EncryptInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit');
  Result := EVP_EncryptInit(ctx,cipher,key,iv);
end;

function Load_EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptInit_ex := LoadLibCryptoFunction('EVP_EncryptInit_ex');
  if not assigned(EVP_EncryptInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit_ex');
  Result := EVP_EncryptInit_ex(ctx,cipher,impl,key,iv);
end;

function Load_EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptUpdate := LoadLibCryptoFunction('EVP_EncryptUpdate');
  if not assigned(EVP_EncryptUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptUpdate');
  Result := EVP_EncryptUpdate(ctx,out_,out1,in_,in_1);
end;

function Load_EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptFinal_ex := LoadLibCryptoFunction('EVP_EncryptFinal_ex');
  if not assigned(EVP_EncryptFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptFinal_ex');
  Result := EVP_EncryptFinal_ex(ctx,out_,out1);
end;

function Load_EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptFinal := LoadLibCryptoFunction('EVP_EncryptFinal');
  if not assigned(EVP_EncryptFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptFinal');
  Result := EVP_EncryptFinal(ctx,out_,out1);
end;

function Load_EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptInit := LoadLibCryptoFunction('EVP_DecryptInit');
  if not assigned(EVP_DecryptInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit');
  Result := EVP_DecryptInit(ctx,out_,out1);
end;

function Load_EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptInit_ex := LoadLibCryptoFunction('EVP_DecryptInit_ex');
  if not assigned(EVP_DecryptInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit_ex');
  Result := EVP_DecryptInit_ex(ctx,cipher,impl,key,iv);
end;

function Load_EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptUpdate := LoadLibCryptoFunction('EVP_DecryptUpdate');
  if not assigned(EVP_DecryptUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptUpdate');
  Result := EVP_DecryptUpdate(ctx,out_,out1,in_,in_1);
end;

function Load_EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptFinal := LoadLibCryptoFunction('EVP_DecryptFinal');
  if not assigned(EVP_DecryptFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptFinal');
  Result := EVP_DecryptFinal(ctx,outm,out1);
end;

function Load_EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptFinal_ex := LoadLibCryptoFunction('EVP_DecryptFinal_ex');
  if not assigned(EVP_DecryptFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptFinal_ex');
  Result := EVP_DecryptFinal_ex(ctx,outm,out1);
end;

function Load_EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherInit := LoadLibCryptoFunction('EVP_CipherInit');
  if not assigned(EVP_CipherInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit');
  Result := EVP_CipherInit(ctx,cipher,key,iv,enc);
end;

function Load_EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherInit_ex := LoadLibCryptoFunction('EVP_CipherInit_ex');
  if not assigned(EVP_CipherInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit_ex');
  Result := EVP_CipherInit_ex(ctx,cipher,impl,key,iv,enc);
end;

function Load_EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherUpdate := LoadLibCryptoFunction('EVP_CipherUpdate');
  if not assigned(EVP_CipherUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherUpdate');
  Result := EVP_CipherUpdate(ctx,out_,out1,in_,in1);
end;

function Load_EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherFinal := LoadLibCryptoFunction('EVP_CipherFinal');
  if not assigned(EVP_CipherFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherFinal');
  Result := EVP_CipherFinal(ctx,outm,out1);
end;

function Load_EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherFinal_ex := LoadLibCryptoFunction('EVP_CipherFinal_ex');
  if not assigned(EVP_CipherFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherFinal_ex');
  Result := EVP_CipherFinal_ex(ctx,outm,out1);
end;

function Load_EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_SignFinal := LoadLibCryptoFunction('EVP_SignFinal');
  if not assigned(EVP_SignFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SignFinal');
  Result := EVP_SignFinal(ctx,md,s,pkey);
end;

function Load_EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSign := LoadLibCryptoFunction('EVP_DigestSign');
  if not assigned(EVP_DigestSign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSign');
  Result := EVP_DigestSign(ctx,sigret,siglen,tbs,tbslen);
end;

function Load_EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_VerifyFinal := LoadLibCryptoFunction('EVP_VerifyFinal');
  if not assigned(EVP_VerifyFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_VerifyFinal');
  Result := EVP_VerifyFinal(ctx,sigbuf,siglen,pkey);
end;

function Load_EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerify := LoadLibCryptoFunction('EVP_DigestVerify');
  if not assigned(EVP_DigestVerify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerify');
  Result := EVP_DigestVerify(ctx,sigret,siglen,tbs,tbslen);
end;

function Load_EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSignInit := LoadLibCryptoFunction('EVP_DigestSignInit');
  if not assigned(EVP_DigestSignInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignInit');
  Result := EVP_DigestSignInit(ctx,pctx,type_,e,pkey);
end;

function Load_EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSignFinal := LoadLibCryptoFunction('EVP_DigestSignFinal');
  if not assigned(EVP_DigestSignFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignFinal');
  Result := EVP_DigestSignFinal(ctx,sigret,siglen);
end;

function Load_EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerifyInit := LoadLibCryptoFunction('EVP_DigestVerifyInit');
  if not assigned(EVP_DigestVerifyInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyInit');
  Result := EVP_DigestVerifyInit(ctx,ppctx,type_,e,pkey);
end;

function Load_EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerifyFinal := LoadLibCryptoFunction('EVP_DigestVerifyFinal');
  if not assigned(EVP_DigestVerifyFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyFinal');
  Result := EVP_DigestVerifyFinal(ctx,sig,siglen);
end;

function Load_EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_OpenInit := LoadLibCryptoFunction('EVP_OpenInit');
  if not assigned(EVP_OpenInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_OpenInit');
  Result := EVP_OpenInit(ctx,type_,ek,ek1,iv,priv);
end;

function Load_EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_OpenFinal := LoadLibCryptoFunction('EVP_OpenFinal');
  if not assigned(EVP_OpenFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_OpenFinal');
  Result := EVP_OpenFinal(ctx,out_,out1);
end;

function Load_EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_SealInit := LoadLibCryptoFunction('EVP_SealInit');
  if not assigned(EVP_SealInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SealInit');
  Result := EVP_SealInit(ctx,type_,ek,ek1,iv,pubk,npubk);
end;

function Load_EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_SealFinal := LoadLibCryptoFunction('EVP_SealFinal');
  if not assigned(EVP_SealFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SealFinal');
  Result := EVP_SealFinal(ctx,out_,out1);
end;

function Load_EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl;
begin
  EVP_ENCODE_CTX_new := LoadLibCryptoFunction('EVP_ENCODE_CTX_new');
  if not assigned(EVP_ENCODE_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_new');
  Result := EVP_ENCODE_CTX_new();
end;

procedure Load_EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EVP_ENCODE_CTX_free := LoadLibCryptoFunction('EVP_ENCODE_CTX_free');
  if not assigned(EVP_ENCODE_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_free');
  EVP_ENCODE_CTX_free(ctx);
end;

function Load_EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_ENCODE_CTX_copy := LoadLibCryptoFunction('EVP_ENCODE_CTX_copy');
  if not assigned(EVP_ENCODE_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_copy');
  Result := EVP_ENCODE_CTX_copy(dctx,sctx);
end;

function Load_EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_ENCODE_CTX_num := LoadLibCryptoFunction('EVP_ENCODE_CTX_num');
  if not assigned(EVP_ENCODE_CTX_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_num');
  Result := EVP_ENCODE_CTX_num(ctx);
end;

procedure Load_EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EVP_EncodeInit := LoadLibCryptoFunction('EVP_EncodeInit');
  if not assigned(EVP_EncodeInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeInit');
  EVP_EncodeInit(ctx);
end;

function Load_EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncodeUpdate := LoadLibCryptoFunction('EVP_EncodeUpdate');
  if not assigned(EVP_EncodeUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeUpdate');
  Result := EVP_EncodeUpdate(ctx,out_,out1,in_,in1);
end;

procedure Load_EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl;
begin
  EVP_EncodeFinal := LoadLibCryptoFunction('EVP_EncodeFinal');
  if not assigned(EVP_EncodeFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeFinal');
  EVP_EncodeFinal(ctx,out_,out1);
end;

function Load_EVP_EncodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncodeBlock := LoadLibCryptoFunction('EVP_EncodeBlock');
  if not assigned(EVP_EncodeBlock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeBlock');
  Result := EVP_EncodeBlock(t,f,n);
end;

procedure Load_EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EVP_DecodeInit := LoadLibCryptoFunction('EVP_DecodeInit');
  if not assigned(EVP_DecodeInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeInit');
  EVP_DecodeInit(ctx);
end;

function Load_EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecodeUpdate := LoadLibCryptoFunction('EVP_DecodeUpdate');
  if not assigned(EVP_DecodeUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeUpdate');
  Result := EVP_DecodeUpdate(ctx,out_,out1,in_,in1);
end;

function Load_EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecodeFinal := LoadLibCryptoFunction('EVP_DecodeFinal');
  if not assigned(EVP_DecodeFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeFinal');
  Result := EVP_DecodeFinal(ctx,out_,out1);
end;

function Load_EVP_DecodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecodeBlock := LoadLibCryptoFunction('EVP_DecodeBlock');
  if not assigned(EVP_DecodeBlock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeBlock');
  Result := EVP_DecodeBlock(t,f,n);
end;

function Load_EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl;
begin
  EVP_CIPHER_CTX_new := LoadLibCryptoFunction('EVP_CIPHER_CTX_new');
  if not assigned(EVP_CIPHER_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_new');
  Result := EVP_CIPHER_CTX_new();
end;

function Load_EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_reset := LoadLibCryptoFunction('EVP_CIPHER_CTX_reset');
  if not assigned(EVP_CIPHER_CTX_reset) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_reset');
  Result := EVP_CIPHER_CTX_reset(c);
end;

procedure Load_EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl;
begin
  EVP_CIPHER_CTX_free := LoadLibCryptoFunction('EVP_CIPHER_CTX_free');
  if not assigned(EVP_CIPHER_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_free');
  EVP_CIPHER_CTX_free(c);
end;

function Load_EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_key_length');
  if not assigned(EVP_CIPHER_CTX_set_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_key_length');
  Result := EVP_CIPHER_CTX_set_key_length(x,keylen);
end;

function Load_EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_padding := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_padding');
  if not assigned(EVP_CIPHER_CTX_set_padding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_padding');
  Result := EVP_CIPHER_CTX_set_padding(c,pad);
end;

function Load_EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_ctrl := LoadLibCryptoFunction('EVP_CIPHER_CTX_ctrl');
  if not assigned(EVP_CIPHER_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_ctrl');
  Result := EVP_CIPHER_CTX_ctrl(ctx,type_,arg,ptr);
end;

function Load_EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_rand_key := LoadLibCryptoFunction('EVP_CIPHER_CTX_rand_key');
  if not assigned(EVP_CIPHER_CTX_rand_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_rand_key');
  Result := EVP_CIPHER_CTX_rand_key(ctx,key);
end;

function Load_BIO_f_md: PBIO_METHOD; cdecl;
begin
  BIO_f_md := LoadLibCryptoFunction('BIO_f_md');
  if not assigned(BIO_f_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_md');
  Result := BIO_f_md();
end;

function Load_BIO_f_base64: PBIO_METHOD; cdecl;
begin
  BIO_f_base64 := LoadLibCryptoFunction('BIO_f_base64');
  if not assigned(BIO_f_base64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_base64');
  Result := BIO_f_base64();
end;

function Load_BIO_f_cipher: PBIO_METHOD; cdecl;
begin
  BIO_f_cipher := LoadLibCryptoFunction('BIO_f_cipher');
  if not assigned(BIO_f_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_cipher');
  Result := BIO_f_cipher();
end;

function Load_BIO_f_reliable: PBIO_METHOD; cdecl;
begin
  BIO_f_reliable := LoadLibCryptoFunction('BIO_f_reliable');
  if not assigned(BIO_f_reliable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_reliable');
  Result := BIO_f_reliable();
end;

function Load_BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_set_cipher := LoadLibCryptoFunction('BIO_set_cipher');
  if not assigned(BIO_set_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_cipher');
  Result := BIO_set_cipher(b,c,k,i,enc);
end;

function Load_EVP_md_null: PEVP_MD; cdecl;
begin
  EVP_md_null := LoadLibCryptoFunction('EVP_md_null');
  if not assigned(EVP_md_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md_null');
  Result := EVP_md_null();
end;

{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
function Load_EVP_md5_sha1: PEVP_MD; cdecl;
begin
  EVP_md5_sha1 := LoadLibCryptoFunction('EVP_md5_sha1');
  if not assigned(EVP_md5_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md5_sha1');
  Result := EVP_md5_sha1();
end;

function Load_EVP_sha1: PEVP_MD; cdecl;
begin
  EVP_sha1 := LoadLibCryptoFunction('EVP_sha1');
  if not assigned(EVP_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha1');
  Result := EVP_sha1();
end;

function Load_EVP_sha224: PEVP_MD; cdecl;
begin
  EVP_sha224 := LoadLibCryptoFunction('EVP_sha224');
  if not assigned(EVP_sha224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha224');
  Result := EVP_sha224();
end;

function Load_EVP_sha256: PEVP_MD; cdecl;
begin
  EVP_sha256 := LoadLibCryptoFunction('EVP_sha256');
  if not assigned(EVP_sha256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha256');
  Result := EVP_sha256();
end;

function Load_EVP_sha384: PEVP_MD; cdecl;
begin
  EVP_sha384 := LoadLibCryptoFunction('EVP_sha384');
  if not assigned(EVP_sha384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha384');
  Result := EVP_sha384();
end;

function Load_EVP_sha512: PEVP_MD; cdecl;
begin
  EVP_sha512 := LoadLibCryptoFunction('EVP_sha512');
  if not assigned(EVP_sha512) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512');
  Result := EVP_sha512();
end;

function Load_EVP_sha512_224: PEVP_MD; cdecl;
begin
  EVP_sha512_224 := LoadLibCryptoFunction('EVP_sha512_224');
  if not assigned(EVP_sha512_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512_224');
  Result := EVP_sha512_224();
end;

function Load_EVP_sha512_256: PEVP_MD; cdecl;
begin
  EVP_sha512_256 := LoadLibCryptoFunction('EVP_sha512_256');
  if not assigned(EVP_sha512_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512_256');
  Result := EVP_sha512_256();
end;

function Load_EVP_sha3_224: PEVP_MD; cdecl;
begin
  EVP_sha3_224 := LoadLibCryptoFunction('EVP_sha3_224');
  if not assigned(EVP_sha3_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_224');
  Result := EVP_sha3_224();
end;

function Load_EVP_sha3_256: PEVP_MD; cdecl;
begin
  EVP_sha3_256 := LoadLibCryptoFunction('EVP_sha3_256');
  if not assigned(EVP_sha3_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_256');
  Result := EVP_sha3_256();
end;

function Load_EVP_sha3_384: PEVP_MD; cdecl;
begin
  EVP_sha3_384 := LoadLibCryptoFunction('EVP_sha3_384');
  if not assigned(EVP_sha3_384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_384');
  Result := EVP_sha3_384();
end;

function Load_EVP_sha3_512: PEVP_MD; cdecl;
begin
  EVP_sha3_512 := LoadLibCryptoFunction('EVP_sha3_512');
  if not assigned(EVP_sha3_512) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_512');
  Result := EVP_sha3_512();
end;

function Load_EVP_shake128: PEVP_MD; cdecl;
begin
  EVP_shake128 := LoadLibCryptoFunction('EVP_shake128');
  if not assigned(EVP_shake128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_shake128');
  Result := EVP_shake128();
end;

function Load_EVP_shake256: PEVP_MD; cdecl;
begin
  EVP_shake256 := LoadLibCryptoFunction('EVP_shake256');
  if not assigned(EVP_shake256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_shake256');
  Result := EVP_shake256();
end;

function Load_EVP_enc_null: PEVP_CIPHER; cdecl;
begin
  EVP_enc_null := LoadLibCryptoFunction('EVP_enc_null');
  if not assigned(EVP_enc_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_enc_null');
  Result := EVP_enc_null();
end;

function Load_EVP_des_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ecb := LoadLibCryptoFunction('EVP_des_ecb');
  if not assigned(EVP_des_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ecb');
  Result := EVP_des_ecb();
end;

function Load_EVP_des_ede: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede := LoadLibCryptoFunction('EVP_des_ede');
  if not assigned(EVP_des_ede) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede');
  Result := EVP_des_ede();
end;

function Load_EVP_des_ede3: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3 := LoadLibCryptoFunction('EVP_des_ede3');
  if not assigned(EVP_des_ede3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3');
  Result := EVP_des_ede3();
end;

function Load_EVP_des_ede_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_ecb := LoadLibCryptoFunction('EVP_des_ede_ecb');
  if not assigned(EVP_des_ede_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_ecb');
  Result := EVP_des_ede_ecb();
end;

function Load_EVP_des_ede3_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_ecb := LoadLibCryptoFunction('EVP_des_ede3_ecb');
  if not assigned(EVP_des_ede3_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_ecb');
  Result := EVP_des_ede3_ecb();
end;

function Load_EVP_des_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb64 := LoadLibCryptoFunction('EVP_des_cfb64');
  if not assigned(EVP_des_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb64');
  Result := EVP_des_cfb64();
end;

function Load_EVP_des_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb1 := LoadLibCryptoFunction('EVP_des_cfb1');
  if not assigned(EVP_des_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb1');
  Result := EVP_des_cfb1();
end;

function Load_EVP_des_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb8 := LoadLibCryptoFunction('EVP_des_cfb8');
  if not assigned(EVP_des_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb8');
  Result := EVP_des_cfb8();
end;

function Load_EVP_des_ede_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_cfb64 := LoadLibCryptoFunction('EVP_des_ede_cfb64');
  if not assigned(EVP_des_ede_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cfb64');
  Result := EVP_des_ede_cfb64();
end;

function Load_EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb64 := LoadLibCryptoFunction('EVP_des_ede3_cfb64');
  if not assigned(EVP_des_ede3_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb64');
  Result := EVP_des_ede3_cfb64();
end;

function Load_EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb1 := LoadLibCryptoFunction('EVP_des_ede3_cfb1');
  if not assigned(EVP_des_ede3_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb1');
  Result := EVP_des_ede3_cfb1();
end;

function Load_EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb8 := LoadLibCryptoFunction('EVP_des_ede3_cfb8');
  if not assigned(EVP_des_ede3_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb8');
  Result := EVP_des_ede3_cfb8();
end;

function Load_EVP_des_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ofb := LoadLibCryptoFunction('EVP_des_ofb');
  if not assigned(EVP_des_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ofb');
  Result := EVP_des_ofb();
end;

function Load_EVP_des_ede_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_ofb := LoadLibCryptoFunction('EVP_des_ede_ofb');
  if not assigned(EVP_des_ede_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_ofb');
  Result := EVP_des_ede_ofb();
end;

function Load_EVP_des_ede3_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_ofb := LoadLibCryptoFunction('EVP_des_ede3_ofb');
  if not assigned(EVP_des_ede3_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_ofb');
  Result := EVP_des_ede3_ofb();
end;

function Load_EVP_des_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_des_cbc := LoadLibCryptoFunction('EVP_des_cbc');
  if not assigned(EVP_des_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cbc');
  Result := EVP_des_cbc();
end;

function Load_EVP_des_ede_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_cbc := LoadLibCryptoFunction('EVP_des_ede_cbc');
  if not assigned(EVP_des_ede_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cbc');
  Result := EVP_des_ede_cbc();
end;

function Load_EVP_des_ede3_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cbc := LoadLibCryptoFunction('EVP_des_ede3_cbc');
  if not assigned(EVP_des_ede3_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cbc');
  Result := EVP_des_ede3_cbc();
end;

function Load_EVP_desx_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_desx_cbc := LoadLibCryptoFunction('EVP_desx_cbc');
  if not assigned(EVP_desx_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_desx_cbc');
  Result := EVP_desx_cbc();
end;

function Load_EVP_des_ede3_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_wrap := LoadLibCryptoFunction('EVP_des_ede3_wrap');
  if not assigned(EVP_des_ede3_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_wrap');
  Result := EVP_des_ede3_wrap();
end;

function Load_EVP_rc4: PEVP_CIPHER; cdecl;
begin
  EVP_rc4 := LoadLibCryptoFunction('EVP_rc4');
  if not assigned(EVP_rc4) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4');
  Result := EVP_rc4();
end;

function Load_EVP_rc4_40: PEVP_CIPHER; cdecl;
begin
  EVP_rc4_40 := LoadLibCryptoFunction('EVP_rc4_40');
  if not assigned(EVP_rc4_40) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4_40');
  Result := EVP_rc4_40();
end;

function Load_EVP_rc2_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_ecb := LoadLibCryptoFunction('EVP_rc2_ecb');
  if not assigned(EVP_rc2_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_ecb');
  Result := EVP_rc2_ecb();
end;

function Load_EVP_rc2_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_cbc := LoadLibCryptoFunction('EVP_rc2_cbc');
  if not assigned(EVP_rc2_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cbc');
  Result := EVP_rc2_cbc();
end;

function Load_EVP_rc2_40_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_40_cbc := LoadLibCryptoFunction('EVP_rc2_40_cbc');
  if not assigned(EVP_rc2_40_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_40_cbc');
  Result := EVP_rc2_40_cbc();
end;

function Load_EVP_rc2_64_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_64_cbc := LoadLibCryptoFunction('EVP_rc2_64_cbc');
  if not assigned(EVP_rc2_64_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_64_cbc');
  Result := EVP_rc2_64_cbc();
end;

function Load_EVP_rc2_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_cfb64 := LoadLibCryptoFunction('EVP_rc2_cfb64');
  if not assigned(EVP_rc2_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cfb64');
  Result := EVP_rc2_cfb64();
end;

function Load_EVP_rc2_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_ofb := LoadLibCryptoFunction('EVP_rc2_ofb');
  if not assigned(EVP_rc2_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_ofb');
  Result := EVP_rc2_ofb();
end;

function Load_EVP_bf_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_bf_ecb := LoadLibCryptoFunction('EVP_bf_ecb');
  if not assigned(EVP_bf_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_ecb');
  Result := EVP_bf_ecb();
end;

function Load_EVP_bf_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_bf_cbc := LoadLibCryptoFunction('EVP_bf_cbc');
  if not assigned(EVP_bf_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cbc');
  Result := EVP_bf_cbc();
end;

function Load_EVP_bf_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_bf_cfb64 := LoadLibCryptoFunction('EVP_bf_cfb64');
  if not assigned(EVP_bf_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cfb64');
  Result := EVP_bf_cfb64();
end;

function Load_EVP_bf_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_bf_ofb := LoadLibCryptoFunction('EVP_bf_ofb');
  if not assigned(EVP_bf_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_ofb');
  Result := EVP_bf_ofb();
end;

function Load_EVP_cast5_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_ecb := LoadLibCryptoFunction('EVP_cast5_ecb');
  if not assigned(EVP_cast5_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_ecb');
  Result := EVP_cast5_ecb();
end;

function Load_EVP_cast5_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_cbc := LoadLibCryptoFunction('EVP_cast5_cbc');
  if not assigned(EVP_cast5_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cbc');
  Result := EVP_cast5_cbc();
end;

function Load_EVP_cast5_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_cfb64 := LoadLibCryptoFunction('EVP_cast5_cfb64');
  if not assigned(EVP_cast5_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cfb64');
  Result := EVP_cast5_cfb64();
end;

function Load_EVP_cast5_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_ofb := LoadLibCryptoFunction('EVP_cast5_ofb');
  if not assigned(EVP_cast5_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_ofb');
  Result := EVP_cast5_ofb();
end;

function Load_EVP_aes_128_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ecb := LoadLibCryptoFunction('EVP_aes_128_ecb');
  if not assigned(EVP_aes_128_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ecb');
  Result := EVP_aes_128_ecb();
end;

function Load_EVP_aes_128_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cbc := LoadLibCryptoFunction('EVP_aes_128_cbc');
  if not assigned(EVP_aes_128_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc');
  Result := EVP_aes_128_cbc();
end;

function Load_EVP_aes_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb1 := LoadLibCryptoFunction('EVP_aes_128_cfb1');
  if not assigned(EVP_aes_128_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb1');
  Result := EVP_aes_128_cfb1();
end;

function Load_EVP_aes_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb8 := LoadLibCryptoFunction('EVP_aes_128_cfb8');
  if not assigned(EVP_aes_128_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb8');
  Result := EVP_aes_128_cfb8();
end;

function Load_EVP_aes_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb128 := LoadLibCryptoFunction('EVP_aes_128_cfb128');
  if not assigned(EVP_aes_128_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb128');
  Result := EVP_aes_128_cfb128();
end;

function Load_EVP_aes_128_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ofb := LoadLibCryptoFunction('EVP_aes_128_ofb');
  if not assigned(EVP_aes_128_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ofb');
  Result := EVP_aes_128_ofb();
end;

function Load_EVP_aes_128_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ctr := LoadLibCryptoFunction('EVP_aes_128_ctr');
  if not assigned(EVP_aes_128_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ctr');
  Result := EVP_aes_128_ctr();
end;

function Load_EVP_aes_128_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ccm := LoadLibCryptoFunction('EVP_aes_128_ccm');
  if not assigned(EVP_aes_128_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ccm');
  Result := EVP_aes_128_ccm();
end;

function Load_EVP_aes_128_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_gcm := LoadLibCryptoFunction('EVP_aes_128_gcm');
  if not assigned(EVP_aes_128_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_gcm');
  Result := EVP_aes_128_gcm();
end;

function Load_EVP_aes_128_xts: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_xts := LoadLibCryptoFunction('EVP_aes_128_xts');
  if not assigned(EVP_aes_128_xts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_xts');
  Result := EVP_aes_128_xts();
end;

function Load_EVP_aes_128_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_wrap := LoadLibCryptoFunction('EVP_aes_128_wrap');
  if not assigned(EVP_aes_128_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_wrap');
  Result := EVP_aes_128_wrap();
end;

function Load_EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_wrap_pad := LoadLibCryptoFunction('EVP_aes_128_wrap_pad');
  if not assigned(EVP_aes_128_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_wrap_pad');
  Result := EVP_aes_128_wrap_pad();
end;

function Load_EVP_aes_128_ocb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ocb := LoadLibCryptoFunction('EVP_aes_128_ocb');
  if not assigned(EVP_aes_128_ocb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ocb');
  Result := EVP_aes_128_ocb();
end;

function Load_EVP_aes_192_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ecb := LoadLibCryptoFunction('EVP_aes_192_ecb');
  if not assigned(EVP_aes_192_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ecb');
  Result := EVP_aes_192_ecb();
end;

function Load_EVP_aes_192_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cbc := LoadLibCryptoFunction('EVP_aes_192_cbc');
  if not assigned(EVP_aes_192_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cbc');
  Result := EVP_aes_192_cbc();
end;

function Load_EVP_aes_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb1 := LoadLibCryptoFunction('EVP_aes_192_cfb1');
  if not assigned(EVP_aes_192_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb1');
  Result := EVP_aes_192_cfb1();
end;

function Load_EVP_aes_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb8 := LoadLibCryptoFunction('EVP_aes_192_cfb8');
  if not assigned(EVP_aes_192_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb8');
  Result := EVP_aes_192_cfb8();
end;

function Load_EVP_aes_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb128 := LoadLibCryptoFunction('EVP_aes_192_cfb128');
  if not assigned(EVP_aes_192_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb128');
  Result := EVP_aes_192_cfb128();
end;

function Load_EVP_aes_192_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ofb := LoadLibCryptoFunction('EVP_aes_192_ofb');
  if not assigned(EVP_aes_192_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ofb');
  Result := EVP_aes_192_ofb();
end;

function Load_EVP_aes_192_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ctr := LoadLibCryptoFunction('EVP_aes_192_ctr');
  if not assigned(EVP_aes_192_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ctr');
  Result := EVP_aes_192_ctr();
end;

function Load_EVP_aes_192_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ccm := LoadLibCryptoFunction('EVP_aes_192_ccm');
  if not assigned(EVP_aes_192_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ccm');
  Result := EVP_aes_192_ccm();
end;

function Load_EVP_aes_192_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_gcm := LoadLibCryptoFunction('EVP_aes_192_gcm');
  if not assigned(EVP_aes_192_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_gcm');
  Result := EVP_aes_192_gcm();
end;

function Load_EVP_aes_192_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_wrap := LoadLibCryptoFunction('EVP_aes_192_wrap');
  if not assigned(EVP_aes_192_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_wrap');
  Result := EVP_aes_192_wrap();
end;

function Load_EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_wrap_pad := LoadLibCryptoFunction('EVP_aes_192_wrap_pad');
  if not assigned(EVP_aes_192_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_wrap_pad');
  Result := EVP_aes_192_wrap_pad();
end;

function Load_EVP_aes_192_ocb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ocb := LoadLibCryptoFunction('EVP_aes_192_ocb');
  if not assigned(EVP_aes_192_ocb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ocb');
  Result := EVP_aes_192_ocb();
end;

function Load_EVP_aes_256_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ecb := LoadLibCryptoFunction('EVP_aes_256_ecb');
  if not assigned(EVP_aes_256_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ecb');
  Result := EVP_aes_256_ecb();
end;

function Load_EVP_aes_256_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cbc := LoadLibCryptoFunction('EVP_aes_256_cbc');
  if not assigned(EVP_aes_256_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc');
  Result := EVP_aes_256_cbc();
end;

function Load_EVP_aes_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb1 := LoadLibCryptoFunction('EVP_aes_256_cfb1');
  if not assigned(EVP_aes_256_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb1');
  Result := EVP_aes_256_cfb1();
end;

function Load_EVP_aes_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb8 := LoadLibCryptoFunction('EVP_aes_256_cfb8');
  if not assigned(EVP_aes_256_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb8');
  Result := EVP_aes_256_cfb8();
end;

function Load_EVP_aes_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb128 := LoadLibCryptoFunction('EVP_aes_256_cfb128');
  if not assigned(EVP_aes_256_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb128');
  Result := EVP_aes_256_cfb128();
end;

function Load_EVP_aes_256_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ofb := LoadLibCryptoFunction('EVP_aes_256_ofb');
  if not assigned(EVP_aes_256_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ofb');
  Result := EVP_aes_256_ofb();
end;

function Load_EVP_aes_256_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ctr := LoadLibCryptoFunction('EVP_aes_256_ctr');
  if not assigned(EVP_aes_256_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ctr');
  Result := EVP_aes_256_ctr();
end;

function Load_EVP_aes_256_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ccm := LoadLibCryptoFunction('EVP_aes_256_ccm');
  if not assigned(EVP_aes_256_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ccm');
  Result := EVP_aes_256_ccm();
end;

function Load_EVP_aes_256_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_gcm := LoadLibCryptoFunction('EVP_aes_256_gcm');
  if not assigned(EVP_aes_256_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_gcm');
  Result := EVP_aes_256_gcm();
end;

function Load_EVP_aes_256_xts: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_xts := LoadLibCryptoFunction('EVP_aes_256_xts');
  if not assigned(EVP_aes_256_xts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_xts');
  Result := EVP_aes_256_xts();
end;

function Load_EVP_aes_256_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_wrap := LoadLibCryptoFunction('EVP_aes_256_wrap');
  if not assigned(EVP_aes_256_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_wrap');
  Result := EVP_aes_256_wrap();
end;

function Load_EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_wrap_pad := LoadLibCryptoFunction('EVP_aes_256_wrap_pad');
  if not assigned(EVP_aes_256_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_wrap_pad');
  Result := EVP_aes_256_wrap_pad();
end;

function Load_EVP_aes_256_ocb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ocb := LoadLibCryptoFunction('EVP_aes_256_ocb');
  if not assigned(EVP_aes_256_ocb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ocb');
  Result := EVP_aes_256_ocb();
end;

function Load_EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cbc_hmac_sha1 := LoadLibCryptoFunction('EVP_aes_128_cbc_hmac_sha1');
  if not assigned(EVP_aes_128_cbc_hmac_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc_hmac_sha1');
  Result := EVP_aes_128_cbc_hmac_sha1();
end;

function Load_EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cbc_hmac_sha1 := LoadLibCryptoFunction('EVP_aes_256_cbc_hmac_sha1');
  if not assigned(EVP_aes_256_cbc_hmac_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc_hmac_sha1');
  Result := EVP_aes_256_cbc_hmac_sha1();
end;

function Load_EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cbc_hmac_sha256 := LoadLibCryptoFunction('EVP_aes_128_cbc_hmac_sha256');
  if not assigned(EVP_aes_128_cbc_hmac_sha256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc_hmac_sha256');
  Result := EVP_aes_128_cbc_hmac_sha256();
end;

function Load_EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cbc_hmac_sha256 := LoadLibCryptoFunction('EVP_aes_256_cbc_hmac_sha256');
  if not assigned(EVP_aes_256_cbc_hmac_sha256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc_hmac_sha256');
  Result := EVP_aes_256_cbc_hmac_sha256();
end;

function Load_EVP_aria_128_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ecb := LoadLibCryptoFunction('EVP_aria_128_ecb');
  if not assigned(EVP_aria_128_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ecb');
  Result := EVP_aria_128_ecb();
end;

function Load_EVP_aria_128_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cbc := LoadLibCryptoFunction('EVP_aria_128_cbc');
  if not assigned(EVP_aria_128_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cbc');
  Result := EVP_aria_128_cbc();
end;

function Load_EVP_aria_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb1 := LoadLibCryptoFunction('EVP_aria_128_cfb1');
  if not assigned(EVP_aria_128_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb1');
  Result := EVP_aria_128_cfb1();
end;

function Load_EVP_aria_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb8 := LoadLibCryptoFunction('EVP_aria_128_cfb8');
  if not assigned(EVP_aria_128_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb8');
  Result := EVP_aria_128_cfb8();
end;

function Load_EVP_aria_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb128 := LoadLibCryptoFunction('EVP_aria_128_cfb128');
  if not assigned(EVP_aria_128_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb128');
  Result := EVP_aria_128_cfb128();
end;

function Load_EVP_aria_128_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ctr := LoadLibCryptoFunction('EVP_aria_128_ctr');
  if not assigned(EVP_aria_128_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ctr');
  Result := EVP_aria_128_ctr();
end;

function Load_EVP_aria_128_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ofb := LoadLibCryptoFunction('EVP_aria_128_ofb');
  if not assigned(EVP_aria_128_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ofb');
  Result := EVP_aria_128_ofb();
end;

function Load_EVP_aria_128_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_gcm := LoadLibCryptoFunction('EVP_aria_128_gcm');
  if not assigned(EVP_aria_128_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_gcm');
  Result := EVP_aria_128_gcm();
end;

function Load_EVP_aria_128_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ccm := LoadLibCryptoFunction('EVP_aria_128_ccm');
  if not assigned(EVP_aria_128_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ccm');
  Result := EVP_aria_128_ccm();
end;

function Load_EVP_aria_192_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ecb := LoadLibCryptoFunction('EVP_aria_192_ecb');
  if not assigned(EVP_aria_192_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ecb');
  Result := EVP_aria_192_ecb();
end;

function Load_EVP_aria_192_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cbc := LoadLibCryptoFunction('EVP_aria_192_cbc');
  if not assigned(EVP_aria_192_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cbc');
  Result := EVP_aria_192_cbc();
end;

function Load_EVP_aria_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb1 := LoadLibCryptoFunction('EVP_aria_192_cfb1');
  if not assigned(EVP_aria_192_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb1');
  Result := EVP_aria_192_cfb1();
end;

function Load_EVP_aria_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb8 := LoadLibCryptoFunction('EVP_aria_192_cfb8');
  if not assigned(EVP_aria_192_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb8');
  Result := EVP_aria_192_cfb8();
end;

function Load_EVP_aria_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb128 := LoadLibCryptoFunction('EVP_aria_192_cfb128');
  if not assigned(EVP_aria_192_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb128');
  Result := EVP_aria_192_cfb128();
end;

function Load_EVP_aria_192_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ctr := LoadLibCryptoFunction('EVP_aria_192_ctr');
  if not assigned(EVP_aria_192_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ctr');
  Result := EVP_aria_192_ctr();
end;

function Load_EVP_aria_192_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ofb := LoadLibCryptoFunction('EVP_aria_192_ofb');
  if not assigned(EVP_aria_192_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ofb');
  Result := EVP_aria_192_ofb();
end;

function Load_EVP_aria_192_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_gcm := LoadLibCryptoFunction('EVP_aria_192_gcm');
  if not assigned(EVP_aria_192_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_gcm');
  Result := EVP_aria_192_gcm();
end;

function Load_EVP_aria_192_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ccm := LoadLibCryptoFunction('EVP_aria_192_ccm');
  if not assigned(EVP_aria_192_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ccm');
  Result := EVP_aria_192_ccm();
end;

function Load_EVP_aria_256_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ecb := LoadLibCryptoFunction('EVP_aria_256_ecb');
  if not assigned(EVP_aria_256_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ecb');
  Result := EVP_aria_256_ecb();
end;

function Load_EVP_aria_256_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cbc := LoadLibCryptoFunction('EVP_aria_256_cbc');
  if not assigned(EVP_aria_256_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cbc');
  Result := EVP_aria_256_cbc();
end;

function Load_EVP_aria_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb1 := LoadLibCryptoFunction('EVP_aria_256_cfb1');
  if not assigned(EVP_aria_256_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb1');
  Result := EVP_aria_256_cfb1();
end;

function Load_EVP_aria_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb8 := LoadLibCryptoFunction('EVP_aria_256_cfb8');
  if not assigned(EVP_aria_256_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb8');
  Result := EVP_aria_256_cfb8();
end;

function Load_EVP_aria_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb128 := LoadLibCryptoFunction('EVP_aria_256_cfb128');
  if not assigned(EVP_aria_256_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb128');
  Result := EVP_aria_256_cfb128();
end;

function Load_EVP_aria_256_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ctr := LoadLibCryptoFunction('EVP_aria_256_ctr');
  if not assigned(EVP_aria_256_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ctr');
  Result := EVP_aria_256_ctr();
end;

function Load_EVP_aria_256_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ofb := LoadLibCryptoFunction('EVP_aria_256_ofb');
  if not assigned(EVP_aria_256_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ofb');
  Result := EVP_aria_256_ofb();
end;

function Load_EVP_aria_256_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_gcm := LoadLibCryptoFunction('EVP_aria_256_gcm');
  if not assigned(EVP_aria_256_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_gcm');
  Result := EVP_aria_256_gcm();
end;

function Load_EVP_aria_256_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ccm := LoadLibCryptoFunction('EVP_aria_256_ccm');
  if not assigned(EVP_aria_256_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ccm');
  Result := EVP_aria_256_ccm();
end;

function Load_EVP_camellia_128_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_ecb := LoadLibCryptoFunction('EVP_camellia_128_ecb');
  if not assigned(EVP_camellia_128_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ecb');
  Result := EVP_camellia_128_ecb();
end;

function Load_EVP_camellia_128_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cbc := LoadLibCryptoFunction('EVP_camellia_128_cbc');
  if not assigned(EVP_camellia_128_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cbc');
  Result := EVP_camellia_128_cbc();
end;

function Load_EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb1 := LoadLibCryptoFunction('EVP_camellia_128_cfb1');
  if not assigned(EVP_camellia_128_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb1');
  Result := EVP_camellia_128_cfb1();
end;

function Load_EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb8 := LoadLibCryptoFunction('EVP_camellia_128_cfb8');
  if not assigned(EVP_camellia_128_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb8');
  Result := EVP_camellia_128_cfb8();
end;

function Load_EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb128 := LoadLibCryptoFunction('EVP_camellia_128_cfb128');
  if not assigned(EVP_camellia_128_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb128');
  Result := EVP_camellia_128_cfb128();
end;

function Load_EVP_camellia_128_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_ofb := LoadLibCryptoFunction('EVP_camellia_128_ofb');
  if not assigned(EVP_camellia_128_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ofb');
  Result := EVP_camellia_128_ofb();
end;

function Load_EVP_camellia_128_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_ctr := LoadLibCryptoFunction('EVP_camellia_128_ctr');
  if not assigned(EVP_camellia_128_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ctr');
  Result := EVP_camellia_128_ctr();
end;

function Load_EVP_camellia_192_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_ecb := LoadLibCryptoFunction('EVP_camellia_192_ecb');
  if not assigned(EVP_camellia_192_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ecb');
  Result := EVP_camellia_192_ecb();
end;

function Load_EVP_camellia_192_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cbc := LoadLibCryptoFunction('EVP_camellia_192_cbc');
  if not assigned(EVP_camellia_192_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cbc');
  Result := EVP_camellia_192_cbc();
end;

function Load_EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb1 := LoadLibCryptoFunction('EVP_camellia_192_cfb1');
  if not assigned(EVP_camellia_192_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb1');
  Result := EVP_camellia_192_cfb1();
end;

function Load_EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb8 := LoadLibCryptoFunction('EVP_camellia_192_cfb8');
  if not assigned(EVP_camellia_192_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb8');
  Result := EVP_camellia_192_cfb8();
end;

function Load_EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb128 := LoadLibCryptoFunction('EVP_camellia_192_cfb128');
  if not assigned(EVP_camellia_192_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb128');
  Result := EVP_camellia_192_cfb128();
end;

function Load_EVP_camellia_192_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_ofb := LoadLibCryptoFunction('EVP_camellia_192_ofb');
  if not assigned(EVP_camellia_192_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ofb');
  Result := EVP_camellia_192_ofb();
end;

function Load_EVP_camellia_192_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_ctr := LoadLibCryptoFunction('EVP_camellia_192_ctr');
  if not assigned(EVP_camellia_192_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ctr');
  Result := EVP_camellia_192_ctr();
end;

function Load_EVP_camellia_256_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_ecb := LoadLibCryptoFunction('EVP_camellia_256_ecb');
  if not assigned(EVP_camellia_256_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ecb');
  Result := EVP_camellia_256_ecb();
end;

function Load_EVP_camellia_256_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cbc := LoadLibCryptoFunction('EVP_camellia_256_cbc');
  if not assigned(EVP_camellia_256_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cbc');
  Result := EVP_camellia_256_cbc();
end;

function Load_EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb1 := LoadLibCryptoFunction('EVP_camellia_256_cfb1');
  if not assigned(EVP_camellia_256_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb1');
  Result := EVP_camellia_256_cfb1();
end;

function Load_EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb8 := LoadLibCryptoFunction('EVP_camellia_256_cfb8');
  if not assigned(EVP_camellia_256_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb8');
  Result := EVP_camellia_256_cfb8();
end;

function Load_EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb128 := LoadLibCryptoFunction('EVP_camellia_256_cfb128');
  if not assigned(EVP_camellia_256_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb128');
  Result := EVP_camellia_256_cfb128();
end;

function Load_EVP_camellia_256_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_ofb := LoadLibCryptoFunction('EVP_camellia_256_ofb');
  if not assigned(EVP_camellia_256_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ofb');
  Result := EVP_camellia_256_ofb();
end;

function Load_EVP_camellia_256_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_ctr := LoadLibCryptoFunction('EVP_camellia_256_ctr');
  if not assigned(EVP_camellia_256_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ctr');
  Result := EVP_camellia_256_ctr();
end;

function Load_EVP_chacha20: PEVP_CIPHER; cdecl;
begin
  EVP_chacha20 := LoadLibCryptoFunction('EVP_chacha20');
  if not assigned(EVP_chacha20) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_chacha20');
  Result := EVP_chacha20();
end;

function Load_EVP_chacha20_poly1305: PEVP_CIPHER; cdecl;
begin
  EVP_chacha20_poly1305 := LoadLibCryptoFunction('EVP_chacha20_poly1305');
  if not assigned(EVP_chacha20_poly1305) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_chacha20_poly1305');
  Result := EVP_chacha20_poly1305();
end;

function Load_EVP_seed_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_seed_ecb := LoadLibCryptoFunction('EVP_seed_ecb');
  if not assigned(EVP_seed_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_ecb');
  Result := EVP_seed_ecb();
end;

function Load_EVP_seed_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_seed_cbc := LoadLibCryptoFunction('EVP_seed_cbc');
  if not assigned(EVP_seed_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cbc');
  Result := EVP_seed_cbc();
end;

function Load_EVP_seed_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_seed_cfb128 := LoadLibCryptoFunction('EVP_seed_cfb128');
  if not assigned(EVP_seed_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cfb128');
  Result := EVP_seed_cfb128();
end;

function Load_EVP_seed_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_seed_ofb := LoadLibCryptoFunction('EVP_seed_ofb');
  if not assigned(EVP_seed_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_ofb');
  Result := EVP_seed_ofb();
end;

function Load_EVP_sm4_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_ecb := LoadLibCryptoFunction('EVP_sm4_ecb');
  if not assigned(EVP_sm4_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ecb');
  Result := EVP_sm4_ecb();
end;

function Load_EVP_sm4_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_cbc := LoadLibCryptoFunction('EVP_sm4_cbc');
  if not assigned(EVP_sm4_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cbc');
  Result := EVP_sm4_cbc();
end;

function Load_EVP_sm4_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_cfb128 := LoadLibCryptoFunction('EVP_sm4_cfb128');
  if not assigned(EVP_sm4_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cfb128');
  Result := EVP_sm4_cfb128();
end;

function Load_EVP_sm4_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_ofb := LoadLibCryptoFunction('EVP_sm4_ofb');
  if not assigned(EVP_sm4_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ofb');
  Result := EVP_sm4_ofb();
end;

function Load_EVP_sm4_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_ctr := LoadLibCryptoFunction('EVP_sm4_ctr');
  if not assigned(EVP_sm4_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ctr');
  Result := EVP_sm4_ctr();
end;

function Load_EVP_add_cipher(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_add_cipher := LoadLibCryptoFunction('EVP_add_cipher');
  if not assigned(EVP_add_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_cipher');
  Result := EVP_add_cipher(cipher);
end;

function Load_EVP_add_digest(const digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_add_digest := LoadLibCryptoFunction('EVP_add_digest');
  if not assigned(EVP_add_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_digest');
  Result := EVP_add_digest(digest);
end;

function Load_EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; cdecl;
begin
  EVP_get_cipherbyname := LoadLibCryptoFunction('EVP_get_cipherbyname');
  if not assigned(EVP_get_cipherbyname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_cipherbyname');
  Result := EVP_get_cipherbyname(name);
end;

function Load_EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; cdecl;
begin
  EVP_get_digestbyname := LoadLibCryptoFunction('EVP_get_digestbyname');
  if not assigned(EVP_get_digestbyname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_digestbyname');
  Result := EVP_get_digestbyname(name);
end;

procedure Load_EVP_CIPHER_do_all(AFn: fn; arg: Pointer); cdecl;
begin
  EVP_CIPHER_do_all := LoadLibCryptoFunction('EVP_CIPHER_do_all');
  if not assigned(EVP_CIPHER_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all');
  EVP_CIPHER_do_all(AFn,arg);
end;

procedure Load_EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer); cdecl;
begin
  EVP_CIPHER_do_all_sorted := LoadLibCryptoFunction('EVP_CIPHER_do_all_sorted');
  if not assigned(EVP_CIPHER_do_all_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all_sorted');
  EVP_CIPHER_do_all_sorted(AFn,arg);
end;

procedure Load_EVP_MD_do_all(AFn: fn; arg: Pointer); cdecl;
begin
  EVP_MD_do_all := LoadLibCryptoFunction('EVP_MD_do_all');
  if not assigned(EVP_MD_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all');
  EVP_MD_do_all(AFn,arg);
end;

procedure Load_EVP_MD_do_all_sorted(AFn: fn; arg: Pointer); cdecl;
begin
  EVP_MD_do_all_sorted := LoadLibCryptoFunction('EVP_MD_do_all_sorted');
  if not assigned(EVP_MD_do_all_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all_sorted');
  EVP_MD_do_all_sorted(AFn,arg);
end;

function Load_EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt_old := LoadLibCryptoFunction('EVP_PKEY_decrypt_old');
  if not assigned(EVP_PKEY_decrypt_old) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_old');
  Result := EVP_PKEY_decrypt_old(dec_key,enc_key,enc_key_len,private_key);
end;

function Load_EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt_old := LoadLibCryptoFunction('EVP_PKEY_encrypt_old');
  if not assigned(EVP_PKEY_encrypt_old) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_old');
  Result := EVP_PKEY_encrypt_old(dec_key,enc_key,key_len,pub_key);
end;

function Load_EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_type := LoadLibCryptoFunction('EVP_PKEY_type');
  if not assigned(EVP_PKEY_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_type');
  Result := EVP_PKEY_type(type_);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_id := LoadLibCryptoFunction('EVP_PKEY_id');
  if not assigned(EVP_PKEY_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_id');
  Result := EVP_PKEY_id(pkey);
end;

function Load_EVP_PKEY_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_base_id := LoadLibCryptoFunction('EVP_PKEY_base_id');
  if not assigned(EVP_PKEY_base_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_base_id');
  Result := EVP_PKEY_base_id(pkey);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_get_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_base_id := LoadLibCryptoFunction('EVP_PKEY_get_base_id');
  if not assigned(EVP_PKEY_get_base_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_base_id');
  Result := EVP_PKEY_get_base_id(pkey);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_bits := LoadLibCryptoFunction('EVP_PKEY_bits');
  if not assigned(EVP_PKEY_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_bits');
  Result := EVP_PKEY_bits(pkey);
end;

function Load_EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_security_bits := LoadLibCryptoFunction('EVP_PKEY_security_bits');
  if not assigned(EVP_PKEY_security_bits) then
    EVP_PKEY_security_bits := @COMPAT_EVP_PKEY_security_bits;
  Result := EVP_PKEY_security_bits(pkey);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_get_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_security_bits := LoadLibCryptoFunction('EVP_PKEY_get_security_bits');
  if not assigned(EVP_PKEY_get_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_security_bits');
  Result := EVP_PKEY_get_security_bits(pkey);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_size := LoadLibCryptoFunction('EVP_PKEY_size');
  if not assigned(EVP_PKEY_size) then
    EVP_PKEY_size := @COMPAT_EVP_PKEY_size;
  Result := EVP_PKEY_size(pkey);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_get_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_size := LoadLibCryptoFunction('EVP_PKEY_get_size');
  if not assigned(EVP_PKEY_get_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_size');
  Result := EVP_PKEY_get_size(pkey);
end;

function Load_EVP_PKEY_set_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_type := LoadLibCryptoFunction('EVP_PKEY_set_type');
  if not assigned(EVP_PKEY_set_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type');
  Result := EVP_PKEY_set_type(pkey);
end;

function Load_EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_type_str := LoadLibCryptoFunction('EVP_PKEY_set_type_str');
  if not assigned(EVP_PKEY_set_type_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type_str');
  Result := EVP_PKEY_set_type_str(pkey,str,len);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_alias_type := LoadLibCryptoFunction('EVP_PKEY_set_alias_type');
  if not assigned(EVP_PKEY_set_alias_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_alias_type');
  Result := EVP_PKEY_set_alias_type(pkey,type_);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_engine := LoadLibCryptoFunction('EVP_PKEY_set1_engine');
  if not assigned(EVP_PKEY_set1_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_engine');
  Result := EVP_PKEY_set1_engine(pkey,e);
end;

function Load_EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE; cdecl;
begin
  EVP_PKEY_get0_engine := LoadLibCryptoFunction('EVP_PKEY_get0_engine');
  if not assigned(EVP_PKEY_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_engine');
  Result := EVP_PKEY_get0_engine(pkey);
end;

function Load_EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign := LoadLibCryptoFunction('EVP_PKEY_assign');
  if not assigned(EVP_PKEY_assign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign');
  Result := EVP_PKEY_assign(pkey,type_,key);
end;

function Load_EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer; cdecl;
begin
  EVP_PKEY_get0 := LoadLibCryptoFunction('EVP_PKEY_get0');
  if not assigned(EVP_PKEY_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0');
  Result := EVP_PKEY_get0(pkey);
end;

function Load_EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
begin
  EVP_PKEY_get0_hmac := LoadLibCryptoFunction('EVP_PKEY_get0_hmac');
  if not assigned(EVP_PKEY_get0_hmac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_hmac');
  Result := EVP_PKEY_get0_hmac(pkey,len);
end;

function Load_EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
begin
  EVP_PKEY_get0_poly1305 := LoadLibCryptoFunction('EVP_PKEY_get0_poly1305');
  if not assigned(EVP_PKEY_get0_poly1305) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_poly1305');
  Result := EVP_PKEY_get0_poly1305(pkey,len);
end;

function Load_EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
begin
  EVP_PKEY_get0_siphash := LoadLibCryptoFunction('EVP_PKEY_get0_siphash');
  if not assigned(EVP_PKEY_get0_siphash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_siphash');
  Result := EVP_PKEY_get0_siphash(pkey,len);
end;

function Load_EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_RSA := LoadLibCryptoFunction('EVP_PKEY_set1_RSA');
  if not assigned(EVP_PKEY_set1_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_RSA');
  Result := EVP_PKEY_set1_RSA(pkey,key);
end;

function Load_EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA; cdecl;
begin
  EVP_PKEY_get0_RSA := LoadLibCryptoFunction('EVP_PKEY_get0_RSA');
  if not assigned(EVP_PKEY_get0_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_RSA');
  Result := EVP_PKEY_get0_RSA(pkey);
end;

function Load_EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA; cdecl;
begin
  EVP_PKEY_get1_RSA := LoadLibCryptoFunction('EVP_PKEY_get1_RSA');
  if not assigned(EVP_PKEY_get1_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_RSA');
  Result := EVP_PKEY_get1_RSA(pkey);
end;

function Load_EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_DSA := LoadLibCryptoFunction('EVP_PKEY_set1_DSA');
  if not assigned(EVP_PKEY_set1_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_DSA');
  Result := EVP_PKEY_set1_DSA(pkey,key);
end;

function Load_EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA; cdecl;
begin
  EVP_PKEY_get0_DSA := LoadLibCryptoFunction('EVP_PKEY_get0_DSA');
  if not assigned(EVP_PKEY_get0_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_DSA');
  Result := EVP_PKEY_get0_DSA(pkey);
end;

function Load_EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA; cdecl;
begin
  EVP_PKEY_get1_DSA := LoadLibCryptoFunction('EVP_PKEY_get1_DSA');
  if not assigned(EVP_PKEY_get1_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_DSA');
  Result := EVP_PKEY_get1_DSA(pkey);
end;

function Load_EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_DH := LoadLibCryptoFunction('EVP_PKEY_set1_DH');
  if not assigned(EVP_PKEY_set1_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_DH');
  Result := EVP_PKEY_set1_DH(pkey,key);
end;

function Load_EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH; cdecl;
begin
  EVP_PKEY_get0_DH := LoadLibCryptoFunction('EVP_PKEY_get0_DH');
  if not assigned(EVP_PKEY_get0_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_DH');
  Result := EVP_PKEY_get0_DH(pkey);
end;

function Load_EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH; cdecl;
begin
  EVP_PKEY_get1_DH := LoadLibCryptoFunction('EVP_PKEY_get1_DH');
  if not assigned(EVP_PKEY_get1_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_DH');
  Result := EVP_PKEY_get1_DH(pkey);
end;

function Load_EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_set1_EC_KEY');
  if not assigned(EVP_PKEY_set1_EC_KEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_EC_KEY');
  Result := EVP_PKEY_set1_EC_KEY(pkey,key);
end;

function Load_EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl;
begin
  EVP_PKEY_get0_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_get0_EC_KEY');
  if not assigned(EVP_PKEY_get0_EC_KEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_EC_KEY');
  Result := EVP_PKEY_get0_EC_KEY(pkey);
end;

function Load_EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl;
begin
  EVP_PKEY_get1_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_get1_EC_KEY');
  if not assigned(EVP_PKEY_get1_EC_KEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_EC_KEY');
  Result := EVP_PKEY_get1_EC_KEY(pkey);
end;

function Load_EVP_PKEY_new: PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new := LoadLibCryptoFunction('EVP_PKEY_new');
  if not assigned(EVP_PKEY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new');
  Result := EVP_PKEY_new();
end;

function Load_EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_up_ref := LoadLibCryptoFunction('EVP_PKEY_up_ref');
  if not assigned(EVP_PKEY_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_up_ref');
  Result := EVP_PKEY_up_ref(pkey);
end;

procedure Load_EVP_PKEY_free(pkey: PEVP_PKEY); cdecl;
begin
  EVP_PKEY_free := LoadLibCryptoFunction('EVP_PKEY_free');
  if not assigned(EVP_PKEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_free');
  EVP_PKEY_free(pkey);
end;

function Load_d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  d2i_PublicKey := LoadLibCryptoFunction('d2i_PublicKey');
  if not assigned(d2i_PublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PublicKey');
  Result := d2i_PublicKey(type_,a,pp,length);
end;

function Load_i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PublicKey := LoadLibCryptoFunction('i2d_PublicKey');
  if not assigned(i2d_PublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PublicKey');
  Result := i2d_PublicKey(a,pp);
end;

function Load_d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  d2i_PrivateKey := LoadLibCryptoFunction('d2i_PrivateKey');
  if not assigned(d2i_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PrivateKey');
  Result := d2i_PrivateKey(type_,a,pp,length);
end;

function Load_d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  d2i_AutoPrivateKey := LoadLibCryptoFunction('d2i_AutoPrivateKey');
  if not assigned(d2i_AutoPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_AutoPrivateKey');
  Result := d2i_AutoPrivateKey(a,pp,length);
end;

function Load_i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PrivateKey := LoadLibCryptoFunction('i2d_PrivateKey');
  if not assigned(i2d_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PrivateKey');
  Result := i2d_PrivateKey(a,pp);
end;

function Load_EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_copy_parameters := LoadLibCryptoFunction('EVP_PKEY_copy_parameters');
  if not assigned(EVP_PKEY_copy_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_copy_parameters');
  Result := EVP_PKEY_copy_parameters(to_,from);
end;

function Load_EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_missing_parameters := LoadLibCryptoFunction('EVP_PKEY_missing_parameters');
  if not assigned(EVP_PKEY_missing_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_missing_parameters');
  Result := EVP_PKEY_missing_parameters(pkey);
end;

function Load_EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_save_parameters := LoadLibCryptoFunction('EVP_PKEY_save_parameters');
  if not assigned(EVP_PKEY_save_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_save_parameters');
  Result := EVP_PKEY_save_parameters(pkey,mode);
end;

function Load_EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_cmp_parameters := LoadLibCryptoFunction('EVP_PKEY_cmp_parameters');
  if not assigned(EVP_PKEY_cmp_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_cmp_parameters');
  Result := EVP_PKEY_cmp_parameters(a,b);
end;

function Load_EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_cmp := LoadLibCryptoFunction('EVP_PKEY_cmp');
  if not assigned(EVP_PKEY_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_cmp');
  Result := EVP_PKEY_cmp(a,b);
end;

function Load_EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_public := LoadLibCryptoFunction('EVP_PKEY_print_public');
  if not assigned(EVP_PKEY_print_public) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_public');
  Result := EVP_PKEY_print_public(out_,pkey,indent,pctx);
end;

function Load_EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_private := LoadLibCryptoFunction('EVP_PKEY_print_private');
  if not assigned(EVP_PKEY_print_private) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_private');
  Result := EVP_PKEY_print_private(out_,pkey,indent,pctx);
end;

function Load_EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_params := LoadLibCryptoFunction('EVP_PKEY_print_params');
  if not assigned(EVP_PKEY_print_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_params');
  Result := EVP_PKEY_print_params(out_,pkey,indent,pctx);
end;

function Load_EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_default_digest_nid := LoadLibCryptoFunction('EVP_PKEY_get_default_digest_nid');
  if not assigned(EVP_PKEY_get_default_digest_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_default_digest_nid');
  Result := EVP_PKEY_get_default_digest_nid(pkey,pnid);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EVP_PKEY_set1_tls_encodedpoint(pkey: PEVP_PKEY; const pt: PByte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_tls_encodedpoint := LoadLibCryptoFunction('EVP_PKEY_set1_tls_encodedpoint');
  if not assigned(EVP_PKEY_set1_tls_encodedpoint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_tls_encodedpoint');
  Result := EVP_PKEY_set1_tls_encodedpoint(pkey,pt,ptlen);
end;

function Load_EVP_PKEY_get1_tls_encodedpoint(pkey: PEVP_PKEY; ppt: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EVP_PKEY_get1_tls_encodedpoint := LoadLibCryptoFunction('EVP_PKEY_get1_tls_encodedpoint');
  if not assigned(EVP_PKEY_get1_tls_encodedpoint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_tls_encodedpoint');
  Result := EVP_PKEY_get1_tls_encodedpoint(pkey,ppt);
end;

function Load_EVP_CIPHER_type(const ctx: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_type := LoadLibCryptoFunction('EVP_CIPHER_type');
  if not assigned(EVP_CIPHER_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_type');
  Result := EVP_CIPHER_type(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_param_to_asn1 := LoadLibCryptoFunction('EVP_CIPHER_param_to_asn1');
  if not assigned(EVP_CIPHER_param_to_asn1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_param_to_asn1');
  Result := EVP_CIPHER_param_to_asn1(c,type_);
end;

function Load_EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_asn1_to_param := LoadLibCryptoFunction('EVP_CIPHER_asn1_to_param');
  if not assigned(EVP_CIPHER_asn1_to_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_asn1_to_param');
  Result := EVP_CIPHER_asn1_to_param(c,type_);
end;

function Load_EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_set_asn1_iv := LoadLibCryptoFunction('EVP_CIPHER_set_asn1_iv');
  if not assigned(EVP_CIPHER_set_asn1_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_set_asn1_iv');
  Result := EVP_CIPHER_set_asn1_iv(c,type_);
end;

function Load_EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_asn1_iv := LoadLibCryptoFunction('EVP_CIPHER_get_asn1_iv');
  if not assigned(EVP_CIPHER_get_asn1_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_asn1_iv');
  Result := EVP_CIPHER_get_asn1_iv(c,type_);
end;

function Load_PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBE_keyivgen := LoadLibCryptoFunction('PKCS5_PBE_keyivgen');
  if not assigned(PKCS5_PBE_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_keyivgen');
  Result := PKCS5_PBE_keyivgen(ctx,pass,passlen,param,cipher,md,en_de);
end;

function Load_PKCS5_PBKDF2_HMAC_SHA1(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBKDF2_HMAC_SHA1 := LoadLibCryptoFunction('PKCS5_PBKDF2_HMAC_SHA1');
  if not assigned(PKCS5_PBKDF2_HMAC_SHA1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBKDF2_HMAC_SHA1');
  Result := PKCS5_PBKDF2_HMAC_SHA1(pass,passlen,salt,saltlen,iter,keylen,out_);
end;

function Load_PKCS5_PBKDF2_HMAC(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBKDF2_HMAC := LoadLibCryptoFunction('PKCS5_PBKDF2_HMAC');
  if not assigned(PKCS5_PBKDF2_HMAC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBKDF2_HMAC');
  Result := PKCS5_PBKDF2_HMAC(pass,passlen,salt,saltlen,iter,digest,keylen,out_);
end;

function Load_PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_v2_PBE_keyivgen := LoadLibCryptoFunction('PKCS5_v2_PBE_keyivgen');
  if not assigned(PKCS5_v2_PBE_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_PBE_keyivgen');
  Result := PKCS5_v2_PBE_keyivgen(ctx,pass,passlen,param,cipher,md,en_de);
end;

function Load_EVP_PBE_scrypt(const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_scrypt := LoadLibCryptoFunction('EVP_PBE_scrypt');
  if not assigned(EVP_PBE_scrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_scrypt');
  Result := EVP_PBE_scrypt(pass,passlen,salt,saltlen,N,r,p,maxmem,key,keylen);
end;

function Load_PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_v2_scrypt_keyivgen := LoadLibCryptoFunction('PKCS5_v2_scrypt_keyivgen');
  if not assigned(PKCS5_v2_scrypt_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_scrypt_keyivgen');
  Result := PKCS5_v2_scrypt_keyivgen(ctx,pass,passlen,param,c,md,en_de);
end;

procedure Load_PKCS5_PBE_add; cdecl;
begin
  PKCS5_PBE_add := LoadLibCryptoFunction('PKCS5_PBE_add');
  if not assigned(PKCS5_PBE_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_add');
  PKCS5_PBE_add();
end;

function Load_EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_CipherInit := LoadLibCryptoFunction('EVP_PBE_CipherInit');
  if not assigned(EVP_PBE_CipherInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_CipherInit');
  Result := EVP_PBE_CipherInit(pbe_obj,pass,passlen,param,ctx,en_de);
end;

function Load_EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_alg_add_type := LoadLibCryptoFunction('EVP_PBE_alg_add_type');
  if not assigned(EVP_PBE_alg_add_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_alg_add_type');
  Result := EVP_PBE_alg_add_type(pbe_type,pbe_nid,cipher_nid,md_nid,keygen);
end;

function Load_EVP_PBE_alg_add(nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_alg_add := LoadLibCryptoFunction('EVP_PBE_alg_add');
  if not assigned(EVP_PBE_alg_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_alg_add');
  Result := EVP_PBE_alg_add(nid,cipher,md,keygen);
end;

function Load_EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_find := LoadLibCryptoFunction('EVP_PBE_find');
  if not assigned(EVP_PBE_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_find');
  Result := EVP_PBE_find(type_,pbe_nid,pcnid,pmnid,pkeygen);
end;

procedure Load_EVP_PBE_cleanup; cdecl;
begin
  EVP_PBE_cleanup := LoadLibCryptoFunction('EVP_PBE_cleanup');
  if not assigned(EVP_PBE_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_cleanup');
  EVP_PBE_cleanup();
end;

function Load_EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_get := LoadLibCryptoFunction('EVP_PBE_get');
  if not assigned(EVP_PBE_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_get');
  Result := EVP_PBE_get(ptype,ppbe_nid,num);
end;

function Load_EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_get_count := LoadLibCryptoFunction('EVP_PKEY_asn1_get_count');
  if not assigned(EVP_PKEY_asn1_get_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get_count');
  Result := EVP_PKEY_asn1_get_count();
end;

function Load_EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_get0 := LoadLibCryptoFunction('EVP_PKEY_asn1_get0');
  if not assigned(EVP_PKEY_asn1_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get0');
  Result := EVP_PKEY_asn1_get0(idx);
end;

function Load_EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_find := LoadLibCryptoFunction('EVP_PKEY_asn1_find');
  if not assigned(EVP_PKEY_asn1_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_find');
  Result := EVP_PKEY_asn1_find(pe,type_);
end;

function Load_EVP_PKEY_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_find_str := LoadLibCryptoFunction('EVP_PKEY_asn1_find_str');
  if not assigned(EVP_PKEY_asn1_find_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_find_str');
  Result := EVP_PKEY_asn1_find_str(pe,str,len);
end;

function Load_EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_add0 := LoadLibCryptoFunction('EVP_PKEY_asn1_add0');
  if not assigned(EVP_PKEY_asn1_add0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_add0');
  Result := EVP_PKEY_asn1_add0(ameth);
end;

function Load_EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_add_alias := LoadLibCryptoFunction('EVP_PKEY_asn1_add_alias');
  if not assigned(EVP_PKEY_asn1_add_alias) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_add_alias');
  Result := EVP_PKEY_asn1_add_alias(to_,from);
end;

function Load_EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_get0_info := LoadLibCryptoFunction('EVP_PKEY_asn1_get0_info');
  if not assigned(EVP_PKEY_asn1_get0_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get0_info');
  Result := EVP_PKEY_asn1_get0_info(ppkey_id,pkey_base_id,ppkey_flags,pinfo,ppem_str,ameth);
end;

function Load_EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_get0_asn1 := LoadLibCryptoFunction('EVP_PKEY_get0_asn1');
  if not assigned(EVP_PKEY_get0_asn1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_asn1');
  Result := EVP_PKEY_get0_asn1(pkey);
end;

function Load_EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_new := LoadLibCryptoFunction('EVP_PKEY_asn1_new');
  if not assigned(EVP_PKEY_asn1_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_new');
  Result := EVP_PKEY_asn1_new(id,flags,pem_str,info);
end;

procedure Load_EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl;
begin
  EVP_PKEY_asn1_copy := LoadLibCryptoFunction('EVP_PKEY_asn1_copy');
  if not assigned(EVP_PKEY_asn1_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_copy');
  EVP_PKEY_asn1_copy(dst,src);
end;

procedure Load_EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl;
begin
  EVP_PKEY_asn1_free := LoadLibCryptoFunction('EVP_PKEY_asn1_free');
  if not assigned(EVP_PKEY_asn1_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_free');
  EVP_PKEY_asn1_free(ameth);
end;

procedure Load_EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl;
begin
  EVP_PKEY_asn1_set_public := LoadLibCryptoFunction('EVP_PKEY_asn1_set_public');
  if not assigned(EVP_PKEY_asn1_set_public) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_public');
  EVP_PKEY_asn1_set_public(ameth,APub_decode,APub_encode,APub_cmd,APub_print,APkey_size,APkey_bits);
end;

procedure Load_EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl;
begin
  EVP_PKEY_asn1_set_private := LoadLibCryptoFunction('EVP_PKEY_asn1_set_private');
  if not assigned(EVP_PKEY_asn1_set_private) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_private');
  EVP_PKEY_asn1_set_private(ameth,APriv_decode,APriv_encode,APriv_print);
end;

procedure Load_EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl;
begin
  EVP_PKEY_asn1_set_param := LoadLibCryptoFunction('EVP_PKEY_asn1_set_param');
  if not assigned(EVP_PKEY_asn1_set_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_param');
  EVP_PKEY_asn1_set_param(ameth,AParam_decode,AParam_encode,AParam_missing,AParam_copy,AParam_cmp,AParam_print);
end;

procedure Load_EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl;
begin
  EVP_PKEY_asn1_set_free := LoadLibCryptoFunction('EVP_PKEY_asn1_set_free');
  if not assigned(EVP_PKEY_asn1_set_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_free');
  EVP_PKEY_asn1_set_free(ameth,APkey_free);
end;

procedure Load_EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl;
begin
  EVP_PKEY_asn1_set_ctrl := LoadLibCryptoFunction('EVP_PKEY_asn1_set_ctrl');
  if not assigned(EVP_PKEY_asn1_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_ctrl');
  EVP_PKEY_asn1_set_ctrl(ameth,APkey_ctrl);
end;

procedure Load_EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl;
begin
  EVP_PKEY_asn1_set_item := LoadLibCryptoFunction('EVP_PKEY_asn1_set_item');
  if not assigned(EVP_PKEY_asn1_set_item) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_item');
  EVP_PKEY_asn1_set_item(ameth,AItem_verify,AItem_sign);
end;

procedure Load_EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl;
begin
  EVP_PKEY_asn1_set_siginf := LoadLibCryptoFunction('EVP_PKEY_asn1_set_siginf');
  if not assigned(EVP_PKEY_asn1_set_siginf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_siginf');
  EVP_PKEY_asn1_set_siginf(ameth,ASiginf_set);
end;

procedure Load_EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl;
begin
  EVP_PKEY_asn1_set_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_check');
  if not assigned(EVP_PKEY_asn1_set_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_check');
  EVP_PKEY_asn1_set_check(ameth,APkey_check);
end;

procedure Load_EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl;
begin
  EVP_PKEY_asn1_set_public_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_public_check');
  if not assigned(EVP_PKEY_asn1_set_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_public_check');
  EVP_PKEY_asn1_set_public_check(ameth,APkey_pub_check);
end;

procedure Load_EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl;
begin
  EVP_PKEY_asn1_set_param_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_param_check');
  if not assigned(EVP_PKEY_asn1_set_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_param_check');
  EVP_PKEY_asn1_set_param_check(ameth,APkey_param_check);
end;

procedure Load_EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl;
begin
  EVP_PKEY_asn1_set_set_priv_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_set_priv_key');
  if not assigned(EVP_PKEY_asn1_set_set_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_set_priv_key');
  EVP_PKEY_asn1_set_set_priv_key(ameth,ASet_priv_key);
end;

procedure Load_EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl;
begin
  EVP_PKEY_asn1_set_set_pub_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_set_pub_key');
  if not assigned(EVP_PKEY_asn1_set_set_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_set_pub_key');
  EVP_PKEY_asn1_set_set_pub_key(ameth,ASet_pub_key);
end;

procedure Load_EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl;
begin
  EVP_PKEY_asn1_set_get_priv_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_get_priv_key');
  if not assigned(EVP_PKEY_asn1_set_get_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_get_priv_key');
  EVP_PKEY_asn1_set_get_priv_key(ameth,AGet_priv_key);
end;

procedure Load_EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl;
begin
  EVP_PKEY_asn1_set_get_pub_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_get_pub_key');
  if not assigned(EVP_PKEY_asn1_set_get_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_get_pub_key');
  EVP_PKEY_asn1_set_get_pub_key(ameth,AGet_pub_key);
end;

procedure Load_EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl;
begin
  EVP_PKEY_asn1_set_security_bits := LoadLibCryptoFunction('EVP_PKEY_asn1_set_security_bits');
  if not assigned(EVP_PKEY_asn1_set_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_security_bits');
  EVP_PKEY_asn1_set_security_bits(ameth,APkey_security_bits);
end;

function Load_EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EVP_PKEY_meth_find := LoadLibCryptoFunction('EVP_PKEY_meth_find');
  if not assigned(EVP_PKEY_meth_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_find');
  Result := EVP_PKEY_meth_find(type_);
end;

function Load_EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EVP_PKEY_meth_new := LoadLibCryptoFunction('EVP_PKEY_meth_new');
  if not assigned(EVP_PKEY_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_new');
  Result := EVP_PKEY_meth_new(id,flags);
end;

procedure Load_EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl;
begin
  EVP_PKEY_meth_get0_info := LoadLibCryptoFunction('EVP_PKEY_meth_get0_info');
  if not assigned(EVP_PKEY_meth_get0_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get0_info');
  EVP_PKEY_meth_get0_info(ppkey_id,pflags,meth);
end;

procedure Load_EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl;
begin
  EVP_PKEY_meth_copy := LoadLibCryptoFunction('EVP_PKEY_meth_copy');
  if not assigned(EVP_PKEY_meth_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_copy');
  EVP_PKEY_meth_copy(dst,src);
end;

procedure Load_EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl;
begin
  EVP_PKEY_meth_free := LoadLibCryptoFunction('EVP_PKEY_meth_free');
  if not assigned(EVP_PKEY_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_free');
  EVP_PKEY_meth_free(pmeth);
end;

function Load_EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_meth_add0 := LoadLibCryptoFunction('EVP_PKEY_meth_add0');
  if not assigned(EVP_PKEY_meth_add0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_add0');
  Result := EVP_PKEY_meth_add0(pmeth);
end;

function Load_EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_meth_remove := LoadLibCryptoFunction('EVP_PKEY_meth_remove');
  if not assigned(EVP_PKEY_meth_remove) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_remove');
  Result := EVP_PKEY_meth_remove(pmeth);
end;

function Load_EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl;
begin
  EVP_PKEY_meth_get_count := LoadLibCryptoFunction('EVP_PKEY_meth_get_count');
  if not assigned(EVP_PKEY_meth_get_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_count');
  Result := EVP_PKEY_meth_get_count();
end;

function Load_EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl;
begin
  EVP_PKEY_meth_get0 := LoadLibCryptoFunction('EVP_PKEY_meth_get0');
  if not assigned(EVP_PKEY_meth_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get0');
  Result := EVP_PKEY_meth_get0(idx);
end;

function Load_EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_new := LoadLibCryptoFunction('EVP_PKEY_CTX_new');
  if not assigned(EVP_PKEY_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new');
  Result := EVP_PKEY_CTX_new(pkey,e);
end;

function Load_EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_new_id := LoadLibCryptoFunction('EVP_PKEY_CTX_new_id');
  if not assigned(EVP_PKEY_CTX_new_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new_id');
  Result := EVP_PKEY_CTX_new_id(id,e);
end;

function Load_EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_dup := LoadLibCryptoFunction('EVP_PKEY_CTX_dup');
  if not assigned(EVP_PKEY_CTX_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_dup');
  Result := EVP_PKEY_CTX_dup(ctx);
end;

procedure Load_EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl;
begin
  EVP_PKEY_CTX_free := LoadLibCryptoFunction('EVP_PKEY_CTX_free');
  if not assigned(EVP_PKEY_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_free');
  EVP_PKEY_CTX_free(ctx);
end;

function Load_EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl');
  if not assigned(EVP_PKEY_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl');
  Result := EVP_PKEY_CTX_ctrl(ctx,keytype,optype,cmd,p1,p2);
end;

function Load_EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_ctrl_str := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl_str');
  if not assigned(EVP_PKEY_CTX_ctrl_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl_str');
  Result := EVP_PKEY_CTX_ctrl_str(ctx,type_,value);
end;

function Load_EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_ctrl_uint64 := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl_uint64');
  if not assigned(EVP_PKEY_CTX_ctrl_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl_uint64');
  Result := EVP_PKEY_CTX_ctrl_uint64(ctx,keytype,optype,cmd,value);
end;

function Load_EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_str2ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_str2ctrl');
  if not assigned(EVP_PKEY_CTX_str2ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_str2ctrl');
  Result := EVP_PKEY_CTX_str2ctrl(ctx,cmd,str);
end;

function Load_EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_hex2ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_hex2ctrl');
  if not assigned(EVP_PKEY_CTX_hex2ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_hex2ctrl');
  Result := EVP_PKEY_CTX_hex2ctrl(ctx,cmd,hex);
end;

function Load_EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_md := LoadLibCryptoFunction('EVP_PKEY_CTX_md');
  if not assigned(EVP_PKEY_CTX_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_md');
  Result := EVP_PKEY_CTX_md(ctx,optype,cmd,md);
end;

function Load_EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_operation := LoadLibCryptoFunction('EVP_PKEY_CTX_get_operation');
  if not assigned(EVP_PKEY_CTX_get_operation) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_operation');
  Result := EVP_PKEY_CTX_get_operation(ctx);
end;

procedure Load_EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl;
begin
  EVP_PKEY_CTX_set0_keygen_info := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_keygen_info');
  if not assigned(EVP_PKEY_CTX_set0_keygen_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_keygen_info');
  EVP_PKEY_CTX_set0_keygen_info(ctx,dat,datlen);
end;

function Load_EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_mac_key := LoadLibCryptoFunction('EVP_PKEY_new_mac_key');
  if not assigned(EVP_PKEY_new_mac_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_mac_key');
  Result := EVP_PKEY_new_mac_key(type_,e,key,keylen);
end;

function Load_EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_raw_private_key := LoadLibCryptoFunction('EVP_PKEY_new_raw_private_key');
  if not assigned(EVP_PKEY_new_raw_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_private_key');
  Result := EVP_PKEY_new_raw_private_key(type_,e,priv,len);
end;

function Load_EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_raw_public_key := LoadLibCryptoFunction('EVP_PKEY_new_raw_public_key');
  if not assigned(EVP_PKEY_new_raw_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_public_key');
  Result := EVP_PKEY_new_raw_public_key(type_,e,pub,len);
end;

function Load_EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_raw_private_key := LoadLibCryptoFunction('EVP_PKEY_get_raw_private_key');
  if not assigned(EVP_PKEY_get_raw_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_raw_private_key');
  Result := EVP_PKEY_get_raw_private_key(pkey,priv,len);
end;

function Load_EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_raw_public_key := LoadLibCryptoFunction('EVP_PKEY_get_raw_public_key');
  if not assigned(EVP_PKEY_get_raw_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_raw_public_key');
  Result := EVP_PKEY_get_raw_public_key(pkey,pub,len);
end;

function Load_EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_CMAC_key := LoadLibCryptoFunction('EVP_PKEY_new_CMAC_key');
  if not assigned(EVP_PKEY_new_CMAC_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_CMAC_key');
  Result := EVP_PKEY_new_CMAC_key(e,priv,len,cipher);
end;

procedure Load_EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl;
begin
  EVP_PKEY_CTX_set_data := LoadLibCryptoFunction('EVP_PKEY_CTX_set_data');
  if not assigned(EVP_PKEY_CTX_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_data');
  EVP_PKEY_CTX_set_data(ctx,data);
end;

function Load_EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl;
begin
  EVP_PKEY_CTX_get_data := LoadLibCryptoFunction('EVP_PKEY_CTX_get_data');
  if not assigned(EVP_PKEY_CTX_get_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_data');
  Result := EVP_PKEY_CTX_get_data(ctx);
end;

function Load_EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_CTX_get0_pkey := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_pkey');
  if not assigned(EVP_PKEY_CTX_get0_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_pkey');
  Result := EVP_PKEY_CTX_get0_pkey(ctx);
end;

function Load_EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_CTX_get0_peerkey := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_peerkey');
  if not assigned(EVP_PKEY_CTX_get0_peerkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_peerkey');
  Result := EVP_PKEY_CTX_get0_peerkey(ctx);
end;

procedure Load_EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl;
begin
  EVP_PKEY_CTX_set_app_data := LoadLibCryptoFunction('EVP_PKEY_CTX_set_app_data');
  if not assigned(EVP_PKEY_CTX_set_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_app_data');
  EVP_PKEY_CTX_set_app_data(ctx,data);
end;

function Load_EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl;
begin
  EVP_PKEY_CTX_get_app_data := LoadLibCryptoFunction('EVP_PKEY_CTX_get_app_data');
  if not assigned(EVP_PKEY_CTX_get_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_app_data');
  Result := EVP_PKEY_CTX_get_app_data(ctx);
end;

function Load_EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_init := LoadLibCryptoFunction('EVP_PKEY_sign_init');
  if not assigned(EVP_PKEY_sign_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_init');
  Result := EVP_PKEY_sign_init(ctx);
end;

function Load_EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign := LoadLibCryptoFunction('EVP_PKEY_sign');
  if not assigned(EVP_PKEY_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign');
  Result := EVP_PKEY_sign(ctx,sig,siglen,tbs,tbslen);
end;

function Load_EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_init := LoadLibCryptoFunction('EVP_PKEY_verify_init');
  if not assigned(EVP_PKEY_verify_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_init');
  Result := EVP_PKEY_verify_init(ctx);
end;

function Load_EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify := LoadLibCryptoFunction('EVP_PKEY_verify');
  if not assigned(EVP_PKEY_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify');
  Result := EVP_PKEY_verify(ctx,sig,siglen,tbs,tbslen);
end;

function Load_EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_recover_init := LoadLibCryptoFunction('EVP_PKEY_verify_recover_init');
  if not assigned(EVP_PKEY_verify_recover_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover_init');
  Result := EVP_PKEY_verify_recover_init(ctx);
end;

function Load_EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_recover := LoadLibCryptoFunction('EVP_PKEY_verify_recover');
  if not assigned(EVP_PKEY_verify_recover) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover');
  Result := EVP_PKEY_verify_recover(ctx,rout,routlen,sig,siglen);
end;

function Load_EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt_init := LoadLibCryptoFunction('EVP_PKEY_encrypt_init');
  if not assigned(EVP_PKEY_encrypt_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_init');
  Result := EVP_PKEY_encrypt_init(ctx);
end;

function Load_EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt := LoadLibCryptoFunction('EVP_PKEY_encrypt');
  if not assigned(EVP_PKEY_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt');
  Result := EVP_PKEY_encrypt(ctx,out_,outlen,in_,inlen);
end;

function Load_EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt_init := LoadLibCryptoFunction('EVP_PKEY_decrypt_init');
  if not assigned(EVP_PKEY_decrypt_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_init');
  Result := EVP_PKEY_decrypt_init(ctx);
end;

function Load_EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt := LoadLibCryptoFunction('EVP_PKEY_decrypt');
  if not assigned(EVP_PKEY_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt');
  Result := EVP_PKEY_decrypt(ctx,out_,outlen,in_,inlen);
end;

function Load_EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive_init := LoadLibCryptoFunction('EVP_PKEY_derive_init');
  if not assigned(EVP_PKEY_derive_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_init');
  Result := EVP_PKEY_derive_init(ctx);
end;

function Load_EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive_set_peer := LoadLibCryptoFunction('EVP_PKEY_derive_set_peer');
  if not assigned(EVP_PKEY_derive_set_peer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_set_peer');
  Result := EVP_PKEY_derive_set_peer(ctx,peer);
end;

function Load_EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive := LoadLibCryptoFunction('EVP_PKEY_derive');
  if not assigned(EVP_PKEY_derive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive');
  Result := EVP_PKEY_derive(ctx,key,keylen);
end;

function Load_EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_paramgen_init := LoadLibCryptoFunction('EVP_PKEY_paramgen_init');
  if not assigned(EVP_PKEY_paramgen_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_paramgen_init');
  Result := EVP_PKEY_paramgen_init(ctx);
end;

function Load_EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_paramgen := LoadLibCryptoFunction('EVP_PKEY_paramgen');
  if not assigned(EVP_PKEY_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_paramgen');
  Result := EVP_PKEY_paramgen(ctx,ppkey);
end;

function Load_EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_keygen_init := LoadLibCryptoFunction('EVP_PKEY_keygen_init');
  if not assigned(EVP_PKEY_keygen_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_keygen_init');
  Result := EVP_PKEY_keygen_init(ctx);
end;

function Load_EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_keygen := LoadLibCryptoFunction('EVP_PKEY_keygen');
  if not assigned(EVP_PKEY_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_keygen');
  Result := EVP_PKEY_keygen(ctx,ppkey);
end;

function Load_EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_check := LoadLibCryptoFunction('EVP_PKEY_check');
  if not assigned(EVP_PKEY_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_check');
  Result := EVP_PKEY_check(ctx);
end;

function Load_EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_public_check := LoadLibCryptoFunction('EVP_PKEY_public_check');
  if not assigned(EVP_PKEY_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_public_check');
  Result := EVP_PKEY_public_check(ctx);
end;

function Load_EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_param_check := LoadLibCryptoFunction('EVP_PKEY_param_check');
  if not assigned(EVP_PKEY_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_param_check');
  Result := EVP_PKEY_param_check(ctx);
end;

procedure Load_EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl;
begin
  EVP_PKEY_CTX_set_cb := LoadLibCryptoFunction('EVP_PKEY_CTX_set_cb');
  if not assigned(EVP_PKEY_CTX_set_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_cb');
  EVP_PKEY_CTX_set_cb(ctx,cb);
end;

function Load_EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl;
begin
  EVP_PKEY_CTX_get_cb := LoadLibCryptoFunction('EVP_PKEY_CTX_get_cb');
  if not assigned(EVP_PKEY_CTX_get_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_cb');
  Result := EVP_PKEY_CTX_get_cb(ctx);
end;

function Load_EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_keygen_info := LoadLibCryptoFunction('EVP_PKEY_CTX_get_keygen_info');
  if not assigned(EVP_PKEY_CTX_get_keygen_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_keygen_info');
  Result := EVP_PKEY_CTX_get_keygen_info(ctx,idx);
end;

procedure Load_EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl;
begin
  EVP_PKEY_meth_set_init := LoadLibCryptoFunction('EVP_PKEY_meth_set_init');
  if not assigned(EVP_PKEY_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_init');
  EVP_PKEY_meth_set_init(pmeth,AEVP_PKEY_meth_init);
end;

procedure Load_EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl;
begin
  EVP_PKEY_meth_set_copy := LoadLibCryptoFunction('EVP_PKEY_meth_set_copy');
  if not assigned(EVP_PKEY_meth_set_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_copy');
  EVP_PKEY_meth_set_copy(pmeth,AEVP_PKEY_meth_copy_cb);
end;

procedure Load_EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl;
begin
  EVP_PKEY_meth_set_cleanup := LoadLibCryptoFunction('EVP_PKEY_meth_set_cleanup');
  if not assigned(EVP_PKEY_meth_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_cleanup');
  EVP_PKEY_meth_set_cleanup(pmeth,PEVP_PKEY_meth_cleanup);
end;

procedure Load_EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl;
begin
  EVP_PKEY_meth_set_paramgen := LoadLibCryptoFunction('EVP_PKEY_meth_set_paramgen');
  if not assigned(EVP_PKEY_meth_set_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_paramgen');
  EVP_PKEY_meth_set_paramgen(pmeth,AEVP_PKEY_meth_paramgen_init,AEVP_PKEY_meth_paramgen);
end;

procedure Load_EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl;
begin
  EVP_PKEY_meth_set_keygen := LoadLibCryptoFunction('EVP_PKEY_meth_set_keygen');
  if not assigned(EVP_PKEY_meth_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_keygen');
  EVP_PKEY_meth_set_keygen(pmeth,AEVP_PKEY_meth_keygen_init,AEVP_PKEY_meth_keygen);
end;

procedure Load_EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl;
begin
  EVP_PKEY_meth_set_sign := LoadLibCryptoFunction('EVP_PKEY_meth_set_sign');
  if not assigned(EVP_PKEY_meth_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_sign');
  EVP_PKEY_meth_set_sign(pmeth,AEVP_PKEY_meth_sign_init,AEVP_PKEY_meth_sign);
end;

procedure Load_EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl;
begin
  EVP_PKEY_meth_set_verify := LoadLibCryptoFunction('EVP_PKEY_meth_set_verify');
  if not assigned(EVP_PKEY_meth_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verify');
  EVP_PKEY_meth_set_verify(pmeth,AEVP_PKEY_meth_verify_init,AEVP_PKEY_meth_verify);
end;

procedure Load_EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl;
begin
  EVP_PKEY_meth_set_verify_recover := LoadLibCryptoFunction('EVP_PKEY_meth_set_verify_recover');
  if not assigned(EVP_PKEY_meth_set_verify_recover) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verify_recover');
  EVP_PKEY_meth_set_verify_recover(pmeth,AEVP_PKEY_meth_verify_recover_init,AEVP_PKEY_meth_verify_recover);
end;

procedure Load_EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl;
begin
  EVP_PKEY_meth_set_signctx := LoadLibCryptoFunction('EVP_PKEY_meth_set_signctx');
  if not assigned(EVP_PKEY_meth_set_signctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_signctx');
  EVP_PKEY_meth_set_signctx(pmeth,AEVP_PKEY_meth_signctx_init,AEVP_PKEY_meth_signctx);
end;

procedure Load_EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl;
begin
  EVP_PKEY_meth_set_verifyctx := LoadLibCryptoFunction('EVP_PKEY_meth_set_verifyctx');
  if not assigned(EVP_PKEY_meth_set_verifyctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verifyctx');
  EVP_PKEY_meth_set_verifyctx(pmeth,AEVP_PKEY_meth_verifyctx_init,AEVP_PKEY_meth_verifyctx);
end;

procedure Load_EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl;
begin
  EVP_PKEY_meth_set_encrypt := LoadLibCryptoFunction('EVP_PKEY_meth_set_encrypt');
  if not assigned(EVP_PKEY_meth_set_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_encrypt');
  EVP_PKEY_meth_set_encrypt(pmeth,AEVP_PKEY_meth_encrypt_init,AEVP_PKEY_meth_encrypt);
end;

procedure Load_EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl;
begin
  EVP_PKEY_meth_set_decrypt := LoadLibCryptoFunction('EVP_PKEY_meth_set_decrypt');
  if not assigned(EVP_PKEY_meth_set_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_decrypt');
  EVP_PKEY_meth_set_decrypt(pmeth,AEVP_PKEY_meth_decrypt_init,AEVP_PKEY_meth_decrypt);
end;

procedure Load_EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl;
begin
  EVP_PKEY_meth_set_derive := LoadLibCryptoFunction('EVP_PKEY_meth_set_derive');
  if not assigned(EVP_PKEY_meth_set_derive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_derive');
  EVP_PKEY_meth_set_derive(pmeth,AEVP_PKEY_meth_derive_init,AEVP_PKEY_meth_derive);
end;

procedure Load_EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl;
begin
  EVP_PKEY_meth_set_ctrl := LoadLibCryptoFunction('EVP_PKEY_meth_set_ctrl');
  if not assigned(EVP_PKEY_meth_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_ctrl');
  EVP_PKEY_meth_set_ctrl(pmeth,AEVP_PKEY_meth_ctrl,AEVP_PKEY_meth_ctrl_str);
end;

procedure Load_EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl;
begin
  EVP_PKEY_meth_set_digestsign := LoadLibCryptoFunction('EVP_PKEY_meth_set_digestsign');
  if not assigned(EVP_PKEY_meth_set_digestsign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digestsign');
  EVP_PKEY_meth_set_digestsign(pmeth,AEVP_PKEY_meth_digestsign);
end;

procedure Load_EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl;
begin
  EVP_PKEY_meth_set_digestverify := LoadLibCryptoFunction('EVP_PKEY_meth_set_digestverify');
  if not assigned(EVP_PKEY_meth_set_digestverify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digestverify');
  EVP_PKEY_meth_set_digestverify(pmeth,AEVP_PKEY_meth_digestverify);
end;

procedure Load_EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl;
begin
  EVP_PKEY_meth_set_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_check');
  if not assigned(EVP_PKEY_meth_set_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_check');
  EVP_PKEY_meth_set_check(pmeth,AEVP_PKEY_meth_check);
end;

procedure Load_EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl;
begin
  EVP_PKEY_meth_set_public_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_public_check');
  if not assigned(EVP_PKEY_meth_set_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_public_check');
  EVP_PKEY_meth_set_public_check(pmeth,AEVP_PKEY_meth_public_check);
end;

procedure Load_EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl;
begin
  EVP_PKEY_meth_set_param_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_param_check');
  if not assigned(EVP_PKEY_meth_set_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_param_check');
  EVP_PKEY_meth_set_param_check(pmeth,AEVP_PKEY_meth_param_check);
end;

procedure Load_EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl;
begin
  EVP_PKEY_meth_set_digest_custom := LoadLibCryptoFunction('EVP_PKEY_meth_set_digest_custom');
  if not assigned(EVP_PKEY_meth_set_digest_custom) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digest_custom');
  EVP_PKEY_meth_set_digest_custom(pmeth,AEVP_PKEY_meth_digest_custom);
end;

procedure Load_EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl;
begin
  EVP_PKEY_meth_get_init := LoadLibCryptoFunction('EVP_PKEY_meth_get_init');
  if not assigned(EVP_PKEY_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_init');
  EVP_PKEY_meth_get_init(pmeth,AEVP_PKEY_meth_init);
end;

procedure Load_EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl;
begin
  EVP_PKEY_meth_get_copy := LoadLibCryptoFunction('EVP_PKEY_meth_get_copy');
  if not assigned(EVP_PKEY_meth_get_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_copy');
  EVP_PKEY_meth_get_copy(pmeth,AEVP_PKEY_meth_copy);
end;

procedure Load_EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl;
begin
  EVP_PKEY_meth_get_cleanup := LoadLibCryptoFunction('EVP_PKEY_meth_get_cleanup');
  if not assigned(EVP_PKEY_meth_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_cleanup');
  EVP_PKEY_meth_get_cleanup(pmeth,AEVP_PKEY_meth_cleanup);
end;

procedure Load_EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl;
begin
  EVP_PKEY_meth_get_paramgen := LoadLibCryptoFunction('EVP_PKEY_meth_get_paramgen');
  if not assigned(EVP_PKEY_meth_get_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_paramgen');
  EVP_PKEY_meth_get_paramgen(pmeth,AEVP_PKEY_meth_paramgen_init,AEVP_PKEY_meth_paramgen);
end;

procedure Load_EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl;
begin
  EVP_PKEY_meth_get_keygen := LoadLibCryptoFunction('EVP_PKEY_meth_get_keygen');
  if not assigned(EVP_PKEY_meth_get_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_keygen');
  EVP_PKEY_meth_get_keygen(pmeth,AEVP_PKEY_meth_keygen_init,AEVP_PKEY_meth_keygen);
end;

procedure Load_EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl;
begin
  EVP_PKEY_meth_get_sign := LoadLibCryptoFunction('EVP_PKEY_meth_get_sign');
  if not assigned(EVP_PKEY_meth_get_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_sign');
  EVP_PKEY_meth_get_sign(pmeth,AEVP_PKEY_meth_sign_init,AEVP_PKEY_meth_sign);
end;

procedure Load_EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl;
begin
  EVP_PKEY_meth_get_verify := LoadLibCryptoFunction('EVP_PKEY_meth_get_verify');
  if not assigned(EVP_PKEY_meth_get_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verify');
  EVP_PKEY_meth_get_verify(pmeth,AEVP_PKEY_meth_verify_init,AEVP_PKEY_meth_verify);
end;

procedure Load_EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl;
begin
  EVP_PKEY_meth_get_verify_recover := LoadLibCryptoFunction('EVP_PKEY_meth_get_verify_recover');
  if not assigned(EVP_PKEY_meth_get_verify_recover) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verify_recover');
  EVP_PKEY_meth_get_verify_recover(pmeth,AEVP_PKEY_meth_verify_recover_init,AEVP_PKEY_meth_verify_recover);
end;

procedure Load_EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl;
begin
  EVP_PKEY_meth_get_signctx := LoadLibCryptoFunction('EVP_PKEY_meth_get_signctx');
  if not assigned(EVP_PKEY_meth_get_signctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_signctx');
  EVP_PKEY_meth_get_signctx(pmeth,AEVP_PKEY_meth_signctx_init,AEVP_PKEY_meth_signctx);
end;

procedure Load_EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl;
begin
  EVP_PKEY_meth_get_verifyctx := LoadLibCryptoFunction('EVP_PKEY_meth_get_verifyctx');
  if not assigned(EVP_PKEY_meth_get_verifyctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verifyctx');
  EVP_PKEY_meth_get_verifyctx(pmeth,AEVP_PKEY_meth_verifyctx_init,AEVP_PKEY_meth_verifyctx);
end;

procedure Load_EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl;
begin
  EVP_PKEY_meth_get_encrypt := LoadLibCryptoFunction('EVP_PKEY_meth_get_encrypt');
  if not assigned(EVP_PKEY_meth_get_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_encrypt');
  EVP_PKEY_meth_get_encrypt(pmeth,AEVP_PKEY_meth_encrypt_init,AEVP_PKEY_meth_encrypt);
end;

procedure Load_EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl;
begin
  EVP_PKEY_meth_get_decrypt := LoadLibCryptoFunction('EVP_PKEY_meth_get_decrypt');
  if not assigned(EVP_PKEY_meth_get_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_decrypt');
  EVP_PKEY_meth_get_decrypt(pmeth,AEVP_PKEY_meth_decrypt_init,AEVP_PKEY_meth_decrypt);
end;

procedure Load_EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl;
begin
  EVP_PKEY_meth_get_derive := LoadLibCryptoFunction('EVP_PKEY_meth_get_derive');
  if not assigned(EVP_PKEY_meth_get_derive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_derive');
  EVP_PKEY_meth_get_derive(pmeth,AEVP_PKEY_meth_derive_init,AEVP_PKEY_meth_derive);
end;

procedure Load_EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl;
begin
  EVP_PKEY_meth_get_ctrl := LoadLibCryptoFunction('EVP_PKEY_meth_get_ctrl');
  if not assigned(EVP_PKEY_meth_get_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_ctrl');
  EVP_PKEY_meth_get_ctrl(pmeth,AEVP_PKEY_meth_ctrl,AEVP_PKEY_meth_ctrl_str);
end;

procedure Load_EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl;
begin
  EVP_PKEY_meth_get_digestsign := LoadLibCryptoFunction('EVP_PKEY_meth_get_digestsign');
  if not assigned(EVP_PKEY_meth_get_digestsign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digestsign');
  EVP_PKEY_meth_get_digestsign(pmeth,AEVP_PKEY_meth_digestsign);
end;

procedure Load_EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl;
begin
  EVP_PKEY_meth_get_digestverify := LoadLibCryptoFunction('EVP_PKEY_meth_get_digestverify');
  if not assigned(EVP_PKEY_meth_get_digestverify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digestverify');
  EVP_PKEY_meth_get_digestverify(pmeth,AEVP_PKEY_meth_digestverify);
end;

procedure Load_EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl;
begin
  EVP_PKEY_meth_get_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_check');
  if not assigned(EVP_PKEY_meth_get_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_check');
  EVP_PKEY_meth_get_check(pmeth,AEVP_PKEY_meth_check);
end;

procedure Load_EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl;
begin
  EVP_PKEY_meth_get_public_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_public_check');
  if not assigned(EVP_PKEY_meth_get_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_public_check');
  EVP_PKEY_meth_get_public_check(pmeth,AEVP_PKEY_meth_public_check);
end;

procedure Load_EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl;
begin
  EVP_PKEY_meth_get_param_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_param_check');
  if not assigned(EVP_PKEY_meth_get_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_param_check');
  EVP_PKEY_meth_get_param_check(pmeth,AEVP_PKEY_meth_param_check);
end;

procedure Load_EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl;
begin
  EVP_PKEY_meth_get_digest_custom := LoadLibCryptoFunction('EVP_PKEY_meth_get_digest_custom');
  if not assigned(EVP_PKEY_meth_get_digest_custom) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digest_custom');
  EVP_PKEY_meth_get_digest_custom(pmeth,AEVP_PKEY_meth_digest_custom);
end;

procedure Load_EVP_add_alg_module; cdecl;
begin
  EVP_add_alg_module := LoadLibCryptoFunction('EVP_add_alg_module');
  if not assigned(EVP_add_alg_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_alg_module');
  EVP_add_alg_module();
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_OpenSSL_add_all_ciphers; cdecl;
begin
  OpenSSL_add_all_ciphers := LoadLibCryptoFunction('OpenSSL_add_all_ciphers');
  if not assigned(OpenSSL_add_all_ciphers) then
    OpenSSL_add_all_ciphers := @COMPAT_OpenSSL_add_all_ciphers;
  OpenSSL_add_all_ciphers();
end;

procedure Load_OpenSSL_add_all_digests; cdecl;
begin
  OpenSSL_add_all_digests := LoadLibCryptoFunction('OpenSSL_add_all_digests');
  if not assigned(OpenSSL_add_all_digests) then
    OpenSSL_add_all_digests := @COMPAT_OpenSSL_add_all_digests;
  OpenSSL_add_all_digests();
end;

procedure Load_EVP_cleanup; cdecl;
begin
  EVP_cleanup := LoadLibCryptoFunction('EVP_cleanup');
  if not assigned(EVP_cleanup) then
    EVP_cleanup := @COMPAT_EVP_cleanup;
  EVP_cleanup();
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$WARN  NO_RETVAL OFF}
{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md2 := LoadLibCryptoFunction('EVP_md2');
  FuncLoadError := not assigned(EVP_md2);
  if FuncLoadError then
  begin
    EVP_md2 := @COMPAT_EVP_md2;
    {Don't report allow nil failure}
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md4 := LoadLibCryptoFunction('EVP_md4');
  FuncLoadError := not assigned(EVP_md4);
  if FuncLoadError then
  begin
    EVP_md4 := @COMPAT_EVP_md4;
    {Don't report allow nil failure}
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md5 := LoadLibCryptoFunction('EVP_md5');
  FuncLoadError := not assigned(EVP_md5);
  if FuncLoadError then
  begin
    EVP_md5 := @COMPAT_EVP_md5;
    {Don't report allow nil failure}
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$ENDIF}
end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_assign_RSA := Load_EVP_PKEY_assign_RSA;
  EVP_PKEY_assign_DSA := Load_EVP_PKEY_assign_DSA;
  EVP_PKEY_assign_DH := Load_EVP_PKEY_assign_DH;
  EVP_PKEY_assign_EC_KEY := Load_EVP_PKEY_assign_EC_KEY;
  EVP_PKEY_assign_SIPHASH := Load_EVP_PKEY_assign_SIPHASH;
  EVP_PKEY_assign_POLY1305 := Load_EVP_PKEY_assign_POLY1305;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_meth_new := Load_EVP_MD_meth_new;
  EVP_MD_meth_dup := Load_EVP_MD_meth_dup;
  EVP_MD_meth_free := Load_EVP_MD_meth_free;
  EVP_MD_meth_set_input_blocksize := Load_EVP_MD_meth_set_input_blocksize;
  EVP_MD_meth_set_result_size := Load_EVP_MD_meth_set_result_size;
  EVP_MD_meth_set_app_datasize := Load_EVP_MD_meth_set_app_datasize;
  EVP_MD_meth_set_flags := Load_EVP_MD_meth_set_flags;
  EVP_MD_meth_set_init := Load_EVP_MD_meth_set_init;
  EVP_MD_meth_set_update := Load_EVP_MD_meth_set_update;
  EVP_MD_meth_set_final := Load_EVP_MD_meth_set_final;
  EVP_MD_meth_set_copy := Load_EVP_MD_meth_set_copy;
  EVP_MD_meth_set_cleanup := Load_EVP_MD_meth_set_cleanup;
  EVP_MD_meth_set_ctrl := Load_EVP_MD_meth_set_ctrl;
  EVP_MD_meth_get_input_blocksize := Load_EVP_MD_meth_get_input_blocksize;
  EVP_MD_meth_get_result_size := Load_EVP_MD_meth_get_result_size;
  EVP_MD_meth_get_app_datasize := Load_EVP_MD_meth_get_app_datasize;
  EVP_MD_meth_get_flags := Load_EVP_MD_meth_get_flags;
  EVP_MD_meth_get_init := Load_EVP_MD_meth_get_init;
  EVP_MD_meth_get_update := Load_EVP_MD_meth_get_update;
  EVP_MD_meth_get_final := Load_EVP_MD_meth_get_final;
  EVP_MD_meth_get_copy := Load_EVP_MD_meth_get_copy;
  EVP_MD_meth_get_cleanup := Load_EVP_MD_meth_get_cleanup;
  EVP_MD_meth_get_ctrl := Load_EVP_MD_meth_get_ctrl;
  EVP_CIPHER_meth_new := Load_EVP_CIPHER_meth_new;
  EVP_CIPHER_meth_dup := Load_EVP_CIPHER_meth_dup;
  EVP_CIPHER_meth_free := Load_EVP_CIPHER_meth_free;
  EVP_CIPHER_meth_set_iv_length := Load_EVP_CIPHER_meth_set_iv_length;
  EVP_CIPHER_meth_set_flags := Load_EVP_CIPHER_meth_set_flags;
  EVP_CIPHER_meth_set_impl_ctx_size := Load_EVP_CIPHER_meth_set_impl_ctx_size;
  EVP_CIPHER_meth_set_init := Load_EVP_CIPHER_meth_set_init;
  EVP_CIPHER_meth_set_do_cipher := Load_EVP_CIPHER_meth_set_do_cipher;
  EVP_CIPHER_meth_set_cleanup := Load_EVP_CIPHER_meth_set_cleanup;
  EVP_CIPHER_meth_set_set_asn1_params := Load_EVP_CIPHER_meth_set_set_asn1_params;
  EVP_CIPHER_meth_set_get_asn1_params := Load_EVP_CIPHER_meth_set_get_asn1_params;
  EVP_CIPHER_meth_set_ctrl := Load_EVP_CIPHER_meth_set_ctrl;
  EVP_CIPHER_meth_get_init := Load_EVP_CIPHER_meth_get_init;
  EVP_CIPHER_meth_get_do_cipher := Load_EVP_CIPHER_meth_get_do_cipher;
  EVP_CIPHER_meth_get_cleanup := Load_EVP_CIPHER_meth_get_cleanup;
  EVP_CIPHER_meth_get_set_asn1_params := Load_EVP_CIPHER_meth_get_set_asn1_params;
  EVP_CIPHER_meth_get_get_asn1_params := Load_EVP_CIPHER_meth_get_get_asn1_params;
  EVP_CIPHER_meth_get_ctrl := Load_EVP_CIPHER_meth_get_ctrl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_type := Load_EVP_MD_type;
  EVP_MD_pkey_type := Load_EVP_MD_pkey_type;
  EVP_MD_size := Load_EVP_MD_size;
  EVP_MD_block_size := Load_EVP_MD_block_size;
  EVP_MD_flags := Load_EVP_MD_flags;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_md := Load_EVP_MD_CTX_md;
  EVP_MD_CTX_update_fn := Load_EVP_MD_CTX_update_fn;
  EVP_MD_CTX_set_update_fn := Load_EVP_MD_CTX_set_update_fn;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_pkey_ctx := Load_EVP_MD_CTX_pkey_ctx;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_set_pkey_ctx := Load_EVP_MD_CTX_set_pkey_ctx;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_md_data := Load_EVP_MD_CTX_md_data;
  EVP_CIPHER_nid := Load_EVP_CIPHER_nid;
  EVP_CIPHER_block_size := Load_EVP_CIPHER_block_size;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_impl_ctx_size := Load_EVP_CIPHER_impl_ctx_size;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_key_length := Load_EVP_CIPHER_key_length;
  EVP_CIPHER_iv_length := Load_EVP_CIPHER_iv_length;
  EVP_CIPHER_flags := Load_EVP_CIPHER_flags;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_cipher := Load_EVP_CIPHER_CTX_cipher;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_CTX_encrypting := Load_EVP_CIPHER_CTX_encrypting;
  EVP_CIPHER_CTX_nid := Load_EVP_CIPHER_CTX_nid;
  EVP_CIPHER_CTX_block_size := Load_EVP_CIPHER_CTX_block_size;
  EVP_CIPHER_CTX_key_length := Load_EVP_CIPHER_CTX_key_length;
  EVP_CIPHER_CTX_iv_length := Load_EVP_CIPHER_CTX_iv_length;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_iv := Load_EVP_CIPHER_CTX_iv;
  EVP_CIPHER_CTX_original_iv := Load_EVP_CIPHER_CTX_original_iv;
  EVP_CIPHER_CTX_iv_noconst := Load_EVP_CIPHER_CTX_iv_noconst;
  EVP_CIPHER_CTX_buf_noconst := Load_EVP_CIPHER_CTX_buf_noconst;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_CTX_num := Load_EVP_CIPHER_CTX_num;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_set_num := Load_EVP_CIPHER_CTX_set_num;
  EVP_CIPHER_CTX_copy := Load_EVP_CIPHER_CTX_copy;
  EVP_CIPHER_CTX_get_app_data := Load_EVP_CIPHER_CTX_get_app_data;
  EVP_CIPHER_CTX_set_app_data := Load_EVP_CIPHER_CTX_set_app_data;
  EVP_CIPHER_CTX_get_cipher_data := Load_EVP_CIPHER_CTX_get_cipher_data;
  EVP_CIPHER_CTX_set_cipher_data := Load_EVP_CIPHER_CTX_set_cipher_data;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  BIO_set_md := Load_BIO_set_md;
  EVP_MD_CTX_init := Load_EVP_MD_CTX_init;
  EVP_MD_CTX_cleanup := Load_EVP_MD_CTX_cleanup;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_ctrl := Load_EVP_MD_CTX_ctrl;
  EVP_MD_CTX_new := Load_EVP_MD_CTX_new;
  EVP_MD_CTX_reset := Load_EVP_MD_CTX_reset;
  EVP_MD_CTX_free := Load_EVP_MD_CTX_free;
  EVP_MD_CTX_copy_ex := Load_EVP_MD_CTX_copy_ex;
  EVP_MD_CTX_set_flags := Load_EVP_MD_CTX_set_flags;
  EVP_MD_CTX_clear_flags := Load_EVP_MD_CTX_clear_flags;
  EVP_MD_CTX_test_flags := Load_EVP_MD_CTX_test_flags;
  EVP_DigestInit_ex := Load_EVP_DigestInit_ex;
  EVP_DigestUpdate := Load_EVP_DigestUpdate;
  EVP_DigestFinal_ex := Load_EVP_DigestFinal_ex;
  EVP_Digest := Load_EVP_Digest;
  EVP_MD_CTX_copy := Load_EVP_MD_CTX_copy;
  EVP_DigestInit := Load_EVP_DigestInit;
  EVP_DigestFinal := Load_EVP_DigestFinal;
  EVP_DigestFinalXOF := Load_EVP_DigestFinalXOF;
  EVP_read_pw_string := Load_EVP_read_pw_string;
  EVP_read_pw_string_min := Load_EVP_read_pw_string_min;
  EVP_set_pw_prompt := Load_EVP_set_pw_prompt;
  EVP_get_pw_prompt := Load_EVP_get_pw_prompt;
  EVP_BytesToKey := Load_EVP_BytesToKey;
  EVP_CIPHER_CTX_set_flags := Load_EVP_CIPHER_CTX_set_flags;
  EVP_CIPHER_CTX_clear_flags := Load_EVP_CIPHER_CTX_clear_flags;
  EVP_CIPHER_CTX_test_flags := Load_EVP_CIPHER_CTX_test_flags;
  EVP_EncryptInit := Load_EVP_EncryptInit;
  EVP_EncryptInit_ex := Load_EVP_EncryptInit_ex;
  EVP_EncryptUpdate := Load_EVP_EncryptUpdate;
  EVP_EncryptFinal_ex := Load_EVP_EncryptFinal_ex;
  EVP_EncryptFinal := Load_EVP_EncryptFinal;
  EVP_DecryptInit := Load_EVP_DecryptInit;
  EVP_DecryptInit_ex := Load_EVP_DecryptInit_ex;
  EVP_DecryptUpdate := Load_EVP_DecryptUpdate;
  EVP_DecryptFinal := Load_EVP_DecryptFinal;
  EVP_DecryptFinal_ex := Load_EVP_DecryptFinal_ex;
  EVP_CipherInit := Load_EVP_CipherInit;
  EVP_CipherInit_ex := Load_EVP_CipherInit_ex;
  EVP_CipherUpdate := Load_EVP_CipherUpdate;
  EVP_CipherFinal := Load_EVP_CipherFinal;
  EVP_CipherFinal_ex := Load_EVP_CipherFinal_ex;
  EVP_SignFinal := Load_EVP_SignFinal;
  EVP_DigestSign := Load_EVP_DigestSign;
  EVP_VerifyFinal := Load_EVP_VerifyFinal;
  EVP_DigestVerify := Load_EVP_DigestVerify;
  EVP_DigestSignInit := Load_EVP_DigestSignInit;
  EVP_DigestSignFinal := Load_EVP_DigestSignFinal;
  EVP_DigestVerifyInit := Load_EVP_DigestVerifyInit;
  EVP_DigestVerifyFinal := Load_EVP_DigestVerifyFinal;
  EVP_OpenInit := Load_EVP_OpenInit;
  EVP_OpenFinal := Load_EVP_OpenFinal;
  EVP_SealInit := Load_EVP_SealInit;
  EVP_SealFinal := Load_EVP_SealFinal;
  EVP_ENCODE_CTX_new := Load_EVP_ENCODE_CTX_new;
  EVP_ENCODE_CTX_free := Load_EVP_ENCODE_CTX_free;
  EVP_ENCODE_CTX_copy := Load_EVP_ENCODE_CTX_copy;
  EVP_ENCODE_CTX_num := Load_EVP_ENCODE_CTX_num;
  EVP_EncodeInit := Load_EVP_EncodeInit;
  EVP_EncodeUpdate := Load_EVP_EncodeUpdate;
  EVP_EncodeFinal := Load_EVP_EncodeFinal;
  EVP_EncodeBlock := Load_EVP_EncodeBlock;
  EVP_DecodeInit := Load_EVP_DecodeInit;
  EVP_DecodeUpdate := Load_EVP_DecodeUpdate;
  EVP_DecodeFinal := Load_EVP_DecodeFinal;
  EVP_DecodeBlock := Load_EVP_DecodeBlock;
  EVP_CIPHER_CTX_new := Load_EVP_CIPHER_CTX_new;
  EVP_CIPHER_CTX_reset := Load_EVP_CIPHER_CTX_reset;
  EVP_CIPHER_CTX_free := Load_EVP_CIPHER_CTX_free;
  EVP_CIPHER_CTX_set_key_length := Load_EVP_CIPHER_CTX_set_key_length;
  EVP_CIPHER_CTX_set_padding := Load_EVP_CIPHER_CTX_set_padding;
  EVP_CIPHER_CTX_ctrl := Load_EVP_CIPHER_CTX_ctrl;
  EVP_CIPHER_CTX_rand_key := Load_EVP_CIPHER_CTX_rand_key;
  BIO_f_md := Load_BIO_f_md;
  BIO_f_base64 := Load_BIO_f_base64;
  BIO_f_cipher := Load_BIO_f_cipher;
  BIO_f_reliable := Load_BIO_f_reliable;
  BIO_set_cipher := Load_BIO_set_cipher;
  EVP_md_null := Load_EVP_md_null;
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md2 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md4 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md5 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$ENDIF}
  EVP_md5_sha1 := Load_EVP_md5_sha1;
  EVP_sha1 := Load_EVP_sha1;
  EVP_sha224 := Load_EVP_sha224;
  EVP_sha256 := Load_EVP_sha256;
  EVP_sha384 := Load_EVP_sha384;
  EVP_sha512 := Load_EVP_sha512;
  EVP_sha512_224 := Load_EVP_sha512_224;
  EVP_sha512_256 := Load_EVP_sha512_256;
  EVP_sha3_224 := Load_EVP_sha3_224;
  EVP_sha3_256 := Load_EVP_sha3_256;
  EVP_sha3_384 := Load_EVP_sha3_384;
  EVP_sha3_512 := Load_EVP_sha3_512;
  EVP_shake128 := Load_EVP_shake128;
  EVP_shake256 := Load_EVP_shake256;
  EVP_enc_null := Load_EVP_enc_null;
  EVP_des_ecb := Load_EVP_des_ecb;
  EVP_des_ede := Load_EVP_des_ede;
  EVP_des_ede3 := Load_EVP_des_ede3;
  EVP_des_ede_ecb := Load_EVP_des_ede_ecb;
  EVP_des_ede3_ecb := Load_EVP_des_ede3_ecb;
  EVP_des_cfb64 := Load_EVP_des_cfb64;
  EVP_des_cfb1 := Load_EVP_des_cfb1;
  EVP_des_cfb8 := Load_EVP_des_cfb8;
  EVP_des_ede_cfb64 := Load_EVP_des_ede_cfb64;
  EVP_des_ede3_cfb64 := Load_EVP_des_ede3_cfb64;
  EVP_des_ede3_cfb1 := Load_EVP_des_ede3_cfb1;
  EVP_des_ede3_cfb8 := Load_EVP_des_ede3_cfb8;
  EVP_des_ofb := Load_EVP_des_ofb;
  EVP_des_ede_ofb := Load_EVP_des_ede_ofb;
  EVP_des_ede3_ofb := Load_EVP_des_ede3_ofb;
  EVP_des_cbc := Load_EVP_des_cbc;
  EVP_des_ede_cbc := Load_EVP_des_ede_cbc;
  EVP_des_ede3_cbc := Load_EVP_des_ede3_cbc;
  EVP_desx_cbc := Load_EVP_desx_cbc;
  EVP_des_ede3_wrap := Load_EVP_des_ede3_wrap;
  EVP_rc4 := Load_EVP_rc4;
  EVP_rc4_40 := Load_EVP_rc4_40;
  EVP_rc2_ecb := Load_EVP_rc2_ecb;
  EVP_rc2_cbc := Load_EVP_rc2_cbc;
  EVP_rc2_40_cbc := Load_EVP_rc2_40_cbc;
  EVP_rc2_64_cbc := Load_EVP_rc2_64_cbc;
  EVP_rc2_cfb64 := Load_EVP_rc2_cfb64;
  EVP_rc2_ofb := Load_EVP_rc2_ofb;
  EVP_bf_ecb := Load_EVP_bf_ecb;
  EVP_bf_cbc := Load_EVP_bf_cbc;
  EVP_bf_cfb64 := Load_EVP_bf_cfb64;
  EVP_bf_ofb := Load_EVP_bf_ofb;
  EVP_cast5_ecb := Load_EVP_cast5_ecb;
  EVP_cast5_cbc := Load_EVP_cast5_cbc;
  EVP_cast5_cfb64 := Load_EVP_cast5_cfb64;
  EVP_cast5_ofb := Load_EVP_cast5_ofb;
  EVP_aes_128_ecb := Load_EVP_aes_128_ecb;
  EVP_aes_128_cbc := Load_EVP_aes_128_cbc;
  EVP_aes_128_cfb1 := Load_EVP_aes_128_cfb1;
  EVP_aes_128_cfb8 := Load_EVP_aes_128_cfb8;
  EVP_aes_128_cfb128 := Load_EVP_aes_128_cfb128;
  EVP_aes_128_ofb := Load_EVP_aes_128_ofb;
  EVP_aes_128_ctr := Load_EVP_aes_128_ctr;
  EVP_aes_128_ccm := Load_EVP_aes_128_ccm;
  EVP_aes_128_gcm := Load_EVP_aes_128_gcm;
  EVP_aes_128_xts := Load_EVP_aes_128_xts;
  EVP_aes_128_wrap := Load_EVP_aes_128_wrap;
  EVP_aes_128_wrap_pad := Load_EVP_aes_128_wrap_pad;
  EVP_aes_128_ocb := Load_EVP_aes_128_ocb;
  EVP_aes_192_ecb := Load_EVP_aes_192_ecb;
  EVP_aes_192_cbc := Load_EVP_aes_192_cbc;
  EVP_aes_192_cfb1 := Load_EVP_aes_192_cfb1;
  EVP_aes_192_cfb8 := Load_EVP_aes_192_cfb8;
  EVP_aes_192_cfb128 := Load_EVP_aes_192_cfb128;
  EVP_aes_192_ofb := Load_EVP_aes_192_ofb;
  EVP_aes_192_ctr := Load_EVP_aes_192_ctr;
  EVP_aes_192_ccm := Load_EVP_aes_192_ccm;
  EVP_aes_192_gcm := Load_EVP_aes_192_gcm;
  EVP_aes_192_wrap := Load_EVP_aes_192_wrap;
  EVP_aes_192_wrap_pad := Load_EVP_aes_192_wrap_pad;
  EVP_aes_192_ocb := Load_EVP_aes_192_ocb;
  EVP_aes_256_ecb := Load_EVP_aes_256_ecb;
  EVP_aes_256_cbc := Load_EVP_aes_256_cbc;
  EVP_aes_256_cfb1 := Load_EVP_aes_256_cfb1;
  EVP_aes_256_cfb8 := Load_EVP_aes_256_cfb8;
  EVP_aes_256_cfb128 := Load_EVP_aes_256_cfb128;
  EVP_aes_256_ofb := Load_EVP_aes_256_ofb;
  EVP_aes_256_ctr := Load_EVP_aes_256_ctr;
  EVP_aes_256_ccm := Load_EVP_aes_256_ccm;
  EVP_aes_256_gcm := Load_EVP_aes_256_gcm;
  EVP_aes_256_xts := Load_EVP_aes_256_xts;
  EVP_aes_256_wrap := Load_EVP_aes_256_wrap;
  EVP_aes_256_wrap_pad := Load_EVP_aes_256_wrap_pad;
  EVP_aes_256_ocb := Load_EVP_aes_256_ocb;
  EVP_aes_128_cbc_hmac_sha1 := Load_EVP_aes_128_cbc_hmac_sha1;
  EVP_aes_256_cbc_hmac_sha1 := Load_EVP_aes_256_cbc_hmac_sha1;
  EVP_aes_128_cbc_hmac_sha256 := Load_EVP_aes_128_cbc_hmac_sha256;
  EVP_aes_256_cbc_hmac_sha256 := Load_EVP_aes_256_cbc_hmac_sha256;
  EVP_aria_128_ecb := Load_EVP_aria_128_ecb;
  EVP_aria_128_cbc := Load_EVP_aria_128_cbc;
  EVP_aria_128_cfb1 := Load_EVP_aria_128_cfb1;
  EVP_aria_128_cfb8 := Load_EVP_aria_128_cfb8;
  EVP_aria_128_cfb128 := Load_EVP_aria_128_cfb128;
  EVP_aria_128_ctr := Load_EVP_aria_128_ctr;
  EVP_aria_128_ofb := Load_EVP_aria_128_ofb;
  EVP_aria_128_gcm := Load_EVP_aria_128_gcm;
  EVP_aria_128_ccm := Load_EVP_aria_128_ccm;
  EVP_aria_192_ecb := Load_EVP_aria_192_ecb;
  EVP_aria_192_cbc := Load_EVP_aria_192_cbc;
  EVP_aria_192_cfb1 := Load_EVP_aria_192_cfb1;
  EVP_aria_192_cfb8 := Load_EVP_aria_192_cfb8;
  EVP_aria_192_cfb128 := Load_EVP_aria_192_cfb128;
  EVP_aria_192_ctr := Load_EVP_aria_192_ctr;
  EVP_aria_192_ofb := Load_EVP_aria_192_ofb;
  EVP_aria_192_gcm := Load_EVP_aria_192_gcm;
  EVP_aria_192_ccm := Load_EVP_aria_192_ccm;
  EVP_aria_256_ecb := Load_EVP_aria_256_ecb;
  EVP_aria_256_cbc := Load_EVP_aria_256_cbc;
  EVP_aria_256_cfb1 := Load_EVP_aria_256_cfb1;
  EVP_aria_256_cfb8 := Load_EVP_aria_256_cfb8;
  EVP_aria_256_cfb128 := Load_EVP_aria_256_cfb128;
  EVP_aria_256_ctr := Load_EVP_aria_256_ctr;
  EVP_aria_256_ofb := Load_EVP_aria_256_ofb;
  EVP_aria_256_gcm := Load_EVP_aria_256_gcm;
  EVP_aria_256_ccm := Load_EVP_aria_256_ccm;
  EVP_camellia_128_ecb := Load_EVP_camellia_128_ecb;
  EVP_camellia_128_cbc := Load_EVP_camellia_128_cbc;
  EVP_camellia_128_cfb1 := Load_EVP_camellia_128_cfb1;
  EVP_camellia_128_cfb8 := Load_EVP_camellia_128_cfb8;
  EVP_camellia_128_cfb128 := Load_EVP_camellia_128_cfb128;
  EVP_camellia_128_ofb := Load_EVP_camellia_128_ofb;
  EVP_camellia_128_ctr := Load_EVP_camellia_128_ctr;
  EVP_camellia_192_ecb := Load_EVP_camellia_192_ecb;
  EVP_camellia_192_cbc := Load_EVP_camellia_192_cbc;
  EVP_camellia_192_cfb1 := Load_EVP_camellia_192_cfb1;
  EVP_camellia_192_cfb8 := Load_EVP_camellia_192_cfb8;
  EVP_camellia_192_cfb128 := Load_EVP_camellia_192_cfb128;
  EVP_camellia_192_ofb := Load_EVP_camellia_192_ofb;
  EVP_camellia_192_ctr := Load_EVP_camellia_192_ctr;
  EVP_camellia_256_ecb := Load_EVP_camellia_256_ecb;
  EVP_camellia_256_cbc := Load_EVP_camellia_256_cbc;
  EVP_camellia_256_cfb1 := Load_EVP_camellia_256_cfb1;
  EVP_camellia_256_cfb8 := Load_EVP_camellia_256_cfb8;
  EVP_camellia_256_cfb128 := Load_EVP_camellia_256_cfb128;
  EVP_camellia_256_ofb := Load_EVP_camellia_256_ofb;
  EVP_camellia_256_ctr := Load_EVP_camellia_256_ctr;
  EVP_chacha20 := Load_EVP_chacha20;
  EVP_chacha20_poly1305 := Load_EVP_chacha20_poly1305;
  EVP_seed_ecb := Load_EVP_seed_ecb;
  EVP_seed_cbc := Load_EVP_seed_cbc;
  EVP_seed_cfb128 := Load_EVP_seed_cfb128;
  EVP_seed_ofb := Load_EVP_seed_ofb;
  EVP_sm4_ecb := Load_EVP_sm4_ecb;
  EVP_sm4_cbc := Load_EVP_sm4_cbc;
  EVP_sm4_cfb128 := Load_EVP_sm4_cfb128;
  EVP_sm4_ofb := Load_EVP_sm4_ofb;
  EVP_sm4_ctr := Load_EVP_sm4_ctr;
  EVP_add_cipher := Load_EVP_add_cipher;
  EVP_add_digest := Load_EVP_add_digest;
  EVP_get_cipherbyname := Load_EVP_get_cipherbyname;
  EVP_get_digestbyname := Load_EVP_get_digestbyname;
  EVP_CIPHER_do_all := Load_EVP_CIPHER_do_all;
  EVP_CIPHER_do_all_sorted := Load_EVP_CIPHER_do_all_sorted;
  EVP_MD_do_all := Load_EVP_MD_do_all;
  EVP_MD_do_all_sorted := Load_EVP_MD_do_all_sorted;
  EVP_PKEY_decrypt_old := Load_EVP_PKEY_decrypt_old;
  EVP_PKEY_encrypt_old := Load_EVP_PKEY_encrypt_old;
  EVP_PKEY_type := Load_EVP_PKEY_type;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_id := Load_EVP_PKEY_id;
  EVP_PKEY_base_id := Load_EVP_PKEY_base_id;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_base_id := Load_EVP_PKEY_get_base_id;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_bits := Load_EVP_PKEY_bits;
  EVP_PKEY_security_bits := Load_EVP_PKEY_security_bits;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_security_bits := Load_EVP_PKEY_get_security_bits;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_size := Load_EVP_PKEY_size;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_size := Load_EVP_PKEY_get_size;
  EVP_PKEY_set_type := Load_EVP_PKEY_set_type;
  EVP_PKEY_set_type_str := Load_EVP_PKEY_set_type_str;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_set_alias_type := Load_EVP_PKEY_set_alias_type;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_set1_engine := Load_EVP_PKEY_set1_engine;
  EVP_PKEY_get0_engine := Load_EVP_PKEY_get0_engine;
  EVP_PKEY_assign := Load_EVP_PKEY_assign;
  EVP_PKEY_get0 := Load_EVP_PKEY_get0;
  EVP_PKEY_get0_hmac := Load_EVP_PKEY_get0_hmac;
  EVP_PKEY_get0_poly1305 := Load_EVP_PKEY_get0_poly1305;
  EVP_PKEY_get0_siphash := Load_EVP_PKEY_get0_siphash;
  EVP_PKEY_set1_RSA := Load_EVP_PKEY_set1_RSA;
  EVP_PKEY_get0_RSA := Load_EVP_PKEY_get0_RSA;
  EVP_PKEY_get1_RSA := Load_EVP_PKEY_get1_RSA;
  EVP_PKEY_set1_DSA := Load_EVP_PKEY_set1_DSA;
  EVP_PKEY_get0_DSA := Load_EVP_PKEY_get0_DSA;
  EVP_PKEY_get1_DSA := Load_EVP_PKEY_get1_DSA;
  EVP_PKEY_set1_DH := Load_EVP_PKEY_set1_DH;
  EVP_PKEY_get0_DH := Load_EVP_PKEY_get0_DH;
  EVP_PKEY_get1_DH := Load_EVP_PKEY_get1_DH;
  EVP_PKEY_set1_EC_KEY := Load_EVP_PKEY_set1_EC_KEY;
  EVP_PKEY_get0_EC_KEY := Load_EVP_PKEY_get0_EC_KEY;
  EVP_PKEY_get1_EC_KEY := Load_EVP_PKEY_get1_EC_KEY;
  EVP_PKEY_new := Load_EVP_PKEY_new;
  EVP_PKEY_up_ref := Load_EVP_PKEY_up_ref;
  EVP_PKEY_free := Load_EVP_PKEY_free;
  d2i_PublicKey := Load_d2i_PublicKey;
  i2d_PublicKey := Load_i2d_PublicKey;
  d2i_PrivateKey := Load_d2i_PrivateKey;
  d2i_AutoPrivateKey := Load_d2i_AutoPrivateKey;
  i2d_PrivateKey := Load_i2d_PrivateKey;
  EVP_PKEY_copy_parameters := Load_EVP_PKEY_copy_parameters;
  EVP_PKEY_missing_parameters := Load_EVP_PKEY_missing_parameters;
  EVP_PKEY_save_parameters := Load_EVP_PKEY_save_parameters;
  EVP_PKEY_cmp_parameters := Load_EVP_PKEY_cmp_parameters;
  EVP_PKEY_cmp := Load_EVP_PKEY_cmp;
  EVP_PKEY_print_public := Load_EVP_PKEY_print_public;
  EVP_PKEY_print_private := Load_EVP_PKEY_print_private;
  EVP_PKEY_print_params := Load_EVP_PKEY_print_params;
  EVP_PKEY_get_default_digest_nid := Load_EVP_PKEY_get_default_digest_nid;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_set1_tls_encodedpoint := Load_EVP_PKEY_set1_tls_encodedpoint;
  EVP_PKEY_get1_tls_encodedpoint := Load_EVP_PKEY_get1_tls_encodedpoint;
  EVP_CIPHER_type := Load_EVP_CIPHER_type;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_param_to_asn1 := Load_EVP_CIPHER_param_to_asn1;
  EVP_CIPHER_asn1_to_param := Load_EVP_CIPHER_asn1_to_param;
  EVP_CIPHER_set_asn1_iv := Load_EVP_CIPHER_set_asn1_iv;
  EVP_CIPHER_get_asn1_iv := Load_EVP_CIPHER_get_asn1_iv;
  PKCS5_PBE_keyivgen := Load_PKCS5_PBE_keyivgen;
  PKCS5_PBKDF2_HMAC_SHA1 := Load_PKCS5_PBKDF2_HMAC_SHA1;
  PKCS5_PBKDF2_HMAC := Load_PKCS5_PBKDF2_HMAC;
  PKCS5_v2_PBE_keyivgen := Load_PKCS5_v2_PBE_keyivgen;
  EVP_PBE_scrypt := Load_EVP_PBE_scrypt;
  PKCS5_v2_scrypt_keyivgen := Load_PKCS5_v2_scrypt_keyivgen;
  PKCS5_PBE_add := Load_PKCS5_PBE_add;
  EVP_PBE_CipherInit := Load_EVP_PBE_CipherInit;
  EVP_PBE_alg_add_type := Load_EVP_PBE_alg_add_type;
  EVP_PBE_alg_add := Load_EVP_PBE_alg_add;
  EVP_PBE_find := Load_EVP_PBE_find;
  EVP_PBE_cleanup := Load_EVP_PBE_cleanup;
  EVP_PBE_get := Load_EVP_PBE_get;
  EVP_PKEY_asn1_get_count := Load_EVP_PKEY_asn1_get_count;
  EVP_PKEY_asn1_get0 := Load_EVP_PKEY_asn1_get0;
  EVP_PKEY_asn1_find := Load_EVP_PKEY_asn1_find;
  EVP_PKEY_asn1_find_str := Load_EVP_PKEY_asn1_find_str;
  EVP_PKEY_asn1_add0 := Load_EVP_PKEY_asn1_add0;
  EVP_PKEY_asn1_add_alias := Load_EVP_PKEY_asn1_add_alias;
  EVP_PKEY_asn1_get0_info := Load_EVP_PKEY_asn1_get0_info;
  EVP_PKEY_get0_asn1 := Load_EVP_PKEY_get0_asn1;
  EVP_PKEY_asn1_new := Load_EVP_PKEY_asn1_new;
  EVP_PKEY_asn1_copy := Load_EVP_PKEY_asn1_copy;
  EVP_PKEY_asn1_free := Load_EVP_PKEY_asn1_free;
  EVP_PKEY_asn1_set_public := Load_EVP_PKEY_asn1_set_public;
  EVP_PKEY_asn1_set_private := Load_EVP_PKEY_asn1_set_private;
  EVP_PKEY_asn1_set_param := Load_EVP_PKEY_asn1_set_param;
  EVP_PKEY_asn1_set_free := Load_EVP_PKEY_asn1_set_free;
  EVP_PKEY_asn1_set_ctrl := Load_EVP_PKEY_asn1_set_ctrl;
  EVP_PKEY_asn1_set_item := Load_EVP_PKEY_asn1_set_item;
  EVP_PKEY_asn1_set_siginf := Load_EVP_PKEY_asn1_set_siginf;
  EVP_PKEY_asn1_set_check := Load_EVP_PKEY_asn1_set_check;
  EVP_PKEY_asn1_set_public_check := Load_EVP_PKEY_asn1_set_public_check;
  EVP_PKEY_asn1_set_param_check := Load_EVP_PKEY_asn1_set_param_check;
  EVP_PKEY_asn1_set_set_priv_key := Load_EVP_PKEY_asn1_set_set_priv_key;
  EVP_PKEY_asn1_set_set_pub_key := Load_EVP_PKEY_asn1_set_set_pub_key;
  EVP_PKEY_asn1_set_get_priv_key := Load_EVP_PKEY_asn1_set_get_priv_key;
  EVP_PKEY_asn1_set_get_pub_key := Load_EVP_PKEY_asn1_set_get_pub_key;
  EVP_PKEY_asn1_set_security_bits := Load_EVP_PKEY_asn1_set_security_bits;
  EVP_PKEY_meth_find := Load_EVP_PKEY_meth_find;
  EVP_PKEY_meth_new := Load_EVP_PKEY_meth_new;
  EVP_PKEY_meth_get0_info := Load_EVP_PKEY_meth_get0_info;
  EVP_PKEY_meth_copy := Load_EVP_PKEY_meth_copy;
  EVP_PKEY_meth_free := Load_EVP_PKEY_meth_free;
  EVP_PKEY_meth_add0 := Load_EVP_PKEY_meth_add0;
  EVP_PKEY_meth_remove := Load_EVP_PKEY_meth_remove;
  EVP_PKEY_meth_get_count := Load_EVP_PKEY_meth_get_count;
  EVP_PKEY_meth_get0 := Load_EVP_PKEY_meth_get0;
  EVP_PKEY_CTX_new := Load_EVP_PKEY_CTX_new;
  EVP_PKEY_CTX_new_id := Load_EVP_PKEY_CTX_new_id;
  EVP_PKEY_CTX_dup := Load_EVP_PKEY_CTX_dup;
  EVP_PKEY_CTX_free := Load_EVP_PKEY_CTX_free;
  EVP_PKEY_CTX_ctrl := Load_EVP_PKEY_CTX_ctrl;
  EVP_PKEY_CTX_ctrl_str := Load_EVP_PKEY_CTX_ctrl_str;
  EVP_PKEY_CTX_ctrl_uint64 := Load_EVP_PKEY_CTX_ctrl_uint64;
  EVP_PKEY_CTX_str2ctrl := Load_EVP_PKEY_CTX_str2ctrl;
  EVP_PKEY_CTX_hex2ctrl := Load_EVP_PKEY_CTX_hex2ctrl;
  EVP_PKEY_CTX_md := Load_EVP_PKEY_CTX_md;
  EVP_PKEY_CTX_get_operation := Load_EVP_PKEY_CTX_get_operation;
  EVP_PKEY_CTX_set0_keygen_info := Load_EVP_PKEY_CTX_set0_keygen_info;
  EVP_PKEY_new_mac_key := Load_EVP_PKEY_new_mac_key;
  EVP_PKEY_new_raw_private_key := Load_EVP_PKEY_new_raw_private_key;
  EVP_PKEY_new_raw_public_key := Load_EVP_PKEY_new_raw_public_key;
  EVP_PKEY_get_raw_private_key := Load_EVP_PKEY_get_raw_private_key;
  EVP_PKEY_get_raw_public_key := Load_EVP_PKEY_get_raw_public_key;
  EVP_PKEY_new_CMAC_key := Load_EVP_PKEY_new_CMAC_key;
  EVP_PKEY_CTX_set_data := Load_EVP_PKEY_CTX_set_data;
  EVP_PKEY_CTX_get_data := Load_EVP_PKEY_CTX_get_data;
  EVP_PKEY_CTX_get0_pkey := Load_EVP_PKEY_CTX_get0_pkey;
  EVP_PKEY_CTX_get0_peerkey := Load_EVP_PKEY_CTX_get0_peerkey;
  EVP_PKEY_CTX_set_app_data := Load_EVP_PKEY_CTX_set_app_data;
  EVP_PKEY_CTX_get_app_data := Load_EVP_PKEY_CTX_get_app_data;
  EVP_PKEY_sign_init := Load_EVP_PKEY_sign_init;
  EVP_PKEY_sign := Load_EVP_PKEY_sign;
  EVP_PKEY_verify_init := Load_EVP_PKEY_verify_init;
  EVP_PKEY_verify := Load_EVP_PKEY_verify;
  EVP_PKEY_verify_recover_init := Load_EVP_PKEY_verify_recover_init;
  EVP_PKEY_verify_recover := Load_EVP_PKEY_verify_recover;
  EVP_PKEY_encrypt_init := Load_EVP_PKEY_encrypt_init;
  EVP_PKEY_encrypt := Load_EVP_PKEY_encrypt;
  EVP_PKEY_decrypt_init := Load_EVP_PKEY_decrypt_init;
  EVP_PKEY_decrypt := Load_EVP_PKEY_decrypt;
  EVP_PKEY_derive_init := Load_EVP_PKEY_derive_init;
  EVP_PKEY_derive_set_peer := Load_EVP_PKEY_derive_set_peer;
  EVP_PKEY_derive := Load_EVP_PKEY_derive;
  EVP_PKEY_paramgen_init := Load_EVP_PKEY_paramgen_init;
  EVP_PKEY_paramgen := Load_EVP_PKEY_paramgen;
  EVP_PKEY_keygen_init := Load_EVP_PKEY_keygen_init;
  EVP_PKEY_keygen := Load_EVP_PKEY_keygen;
  EVP_PKEY_check := Load_EVP_PKEY_check;
  EVP_PKEY_public_check := Load_EVP_PKEY_public_check;
  EVP_PKEY_param_check := Load_EVP_PKEY_param_check;
  EVP_PKEY_CTX_set_cb := Load_EVP_PKEY_CTX_set_cb;
  EVP_PKEY_CTX_get_cb := Load_EVP_PKEY_CTX_get_cb;
  EVP_PKEY_CTX_get_keygen_info := Load_EVP_PKEY_CTX_get_keygen_info;
  EVP_PKEY_meth_set_init := Load_EVP_PKEY_meth_set_init;
  EVP_PKEY_meth_set_copy := Load_EVP_PKEY_meth_set_copy;
  EVP_PKEY_meth_set_cleanup := Load_EVP_PKEY_meth_set_cleanup;
  EVP_PKEY_meth_set_paramgen := Load_EVP_PKEY_meth_set_paramgen;
  EVP_PKEY_meth_set_keygen := Load_EVP_PKEY_meth_set_keygen;
  EVP_PKEY_meth_set_sign := Load_EVP_PKEY_meth_set_sign;
  EVP_PKEY_meth_set_verify := Load_EVP_PKEY_meth_set_verify;
  EVP_PKEY_meth_set_verify_recover := Load_EVP_PKEY_meth_set_verify_recover;
  EVP_PKEY_meth_set_signctx := Load_EVP_PKEY_meth_set_signctx;
  EVP_PKEY_meth_set_verifyctx := Load_EVP_PKEY_meth_set_verifyctx;
  EVP_PKEY_meth_set_encrypt := Load_EVP_PKEY_meth_set_encrypt;
  EVP_PKEY_meth_set_decrypt := Load_EVP_PKEY_meth_set_decrypt;
  EVP_PKEY_meth_set_derive := Load_EVP_PKEY_meth_set_derive;
  EVP_PKEY_meth_set_ctrl := Load_EVP_PKEY_meth_set_ctrl;
  EVP_PKEY_meth_set_digestsign := Load_EVP_PKEY_meth_set_digestsign;
  EVP_PKEY_meth_set_digestverify := Load_EVP_PKEY_meth_set_digestverify;
  EVP_PKEY_meth_set_check := Load_EVP_PKEY_meth_set_check;
  EVP_PKEY_meth_set_public_check := Load_EVP_PKEY_meth_set_public_check;
  EVP_PKEY_meth_set_param_check := Load_EVP_PKEY_meth_set_param_check;
  EVP_PKEY_meth_set_digest_custom := Load_EVP_PKEY_meth_set_digest_custom;
  EVP_PKEY_meth_get_init := Load_EVP_PKEY_meth_get_init;
  EVP_PKEY_meth_get_copy := Load_EVP_PKEY_meth_get_copy;
  EVP_PKEY_meth_get_cleanup := Load_EVP_PKEY_meth_get_cleanup;
  EVP_PKEY_meth_get_paramgen := Load_EVP_PKEY_meth_get_paramgen;
  EVP_PKEY_meth_get_keygen := Load_EVP_PKEY_meth_get_keygen;
  EVP_PKEY_meth_get_sign := Load_EVP_PKEY_meth_get_sign;
  EVP_PKEY_meth_get_verify := Load_EVP_PKEY_meth_get_verify;
  EVP_PKEY_meth_get_verify_recover := Load_EVP_PKEY_meth_get_verify_recover;
  EVP_PKEY_meth_get_signctx := Load_EVP_PKEY_meth_get_signctx;
  EVP_PKEY_meth_get_verifyctx := Load_EVP_PKEY_meth_get_verifyctx;
  EVP_PKEY_meth_get_encrypt := Load_EVP_PKEY_meth_get_encrypt;
  EVP_PKEY_meth_get_decrypt := Load_EVP_PKEY_meth_get_decrypt;
  EVP_PKEY_meth_get_derive := Load_EVP_PKEY_meth_get_derive;
  EVP_PKEY_meth_get_ctrl := Load_EVP_PKEY_meth_get_ctrl;
  EVP_PKEY_meth_get_digestsign := Load_EVP_PKEY_meth_get_digestsign;
  EVP_PKEY_meth_get_digestverify := Load_EVP_PKEY_meth_get_digestverify;
  EVP_PKEY_meth_get_check := Load_EVP_PKEY_meth_get_check;
  EVP_PKEY_meth_get_public_check := Load_EVP_PKEY_meth_get_public_check;
  EVP_PKEY_meth_get_param_check := Load_EVP_PKEY_meth_get_param_check;
  EVP_PKEY_meth_get_digest_custom := Load_EVP_PKEY_meth_get_digest_custom;
  EVP_add_alg_module := Load_EVP_add_alg_module;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OpenSSL_add_all_ciphers := Load_OpenSSL_add_all_ciphers;
  OpenSSL_add_all_digests := Load_OpenSSL_add_all_digests;
  EVP_cleanup := Load_EVP_cleanup;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
