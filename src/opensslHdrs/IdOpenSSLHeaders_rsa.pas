(* This unit was generated from the source file rsa.h2pas 
It should not be modified directly. All changes should be made to rsa.h2pas
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


unit IdOpenSSLHeaders_rsa;


interface

// Headers for OpenSSL 1.1.1
// rsa.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_evp;

(* The types RSA and RSA_METHOD are defined in ossl_typ.h *)

const
  OPENSSL_RSA_MAX_MODULUS_BITS =  16384;
  OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 1024;
  OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
  (* exponent limit enforced for "large" modulus only *)
  OPENSSL_RSA_MAX_PUBEXP_BITS =  64;

  RSA_3 =  TOpenSSL_C_Long($3);
  RSA_F4 = TOpenSSL_C_Long($10001);

  (* based on RFC 8017 appendix A.1.2 *)
  RSA_ASN1_VERSION_DEFAULT = 0;
  RSA_ASN1_VERSION_MULTI =   1;
  RSA_DEFAULT_PRIME_NUM =    2;

  RSA_METHOD_FLAG_NO_CHECK = $0001; (* don't check pub/private match *)
  RSA_FLAG_CACHE_PUBLIC =    $0002;
  RSA_FLAG_CACHE_PRIVATE =   $0004;
  RSA_FLAG_BLINDING =        $0008;
  RSA_FLAG_THREAD_SAFE =     $0010;
  (*
   * This flag means the private key operations will be handled by rsa_mod_exp
   * and that they do not depend on the private key components being present:
   * for example a key stored in external hardware. Without this flag
   * bn_mod_exp gets called when private key components are absent.
   *)
  RSA_FLAG_EXT_PKEY =        $0020;
  (*
   * new with 0.9.6j and 0.9.7b; the built-in
   * RSA implementation now uses blinding by
   * default (ignoring RSA_FLAG_BLINDING),
   * but other engines might not need it
   *)
  RSA_FLAG_NO_BLINDING =     $0080;
  (*
   * Does nothing. Previously this switched off constant time behaviour.
   *)
  RSA_FLAG_NO_CONSTTIME =    $0000;

  (* Salt length matches digest *)
  RSA_PSS_SALTLEN_DIGEST = -1;
  (* Verify only: auto detect salt length *)
  RSA_PSS_SALTLEN_AUTO = -2;
  (* Set salt length to maximum possible *)
  RSA_PSS_SALTLEN_MAX = -3;
  (* Old compatible max salt length for sign only *)
  RSA_PSS_SALTLEN_MAX_SIGN = -2;

  EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1;
  EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 2;

  EVP_PKEY_CTRL_RSA_KEYGEN_BITS = EVP_PKEY_ALG_CTRL + 3;
  EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = EVP_PKEY_ALG_CTRL + 4;
  EVP_PKEY_CTRL_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL + 5;

  EVP_PKEY_CTRL_GET_RSA_PADDING =  EVP_PKEY_ALG_CTRL + 6;
  EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 7;
  EVP_PKEY_CTRL_GET_RSA_MGF1_MD =  EVP_PKEY_ALG_CTRL + 8;

  EVP_PKEY_CTRL_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL + 9;
  EVP_PKEY_CTRL_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL + 10;

  EVP_PKEY_CTRL_GET_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL + 11;
  EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL + 12;

  EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES = EVP_PKEY_ALG_CTRL + 13;

  RSA_PKCS1_PADDING =   1;
  RSA_SSLV23_PADDING =  2;
  RSA_NO_PADDING =   3;
  RSA_PKCS1_OAEP_PADDING = 4;
  RSA_X931_PADDING =   5;
  RSA_PKCS1_PSS_PADDING =  6; (* EVP_PKEY_ only *)
  RSA_PKCS1_PADDING_SIZE = 11;

  (*
   * If this flag is set the RSA method is FIPS compliant and can be used in
   * FIPS mode. This is set in the validated module method. If an application
   * sets this flag in its own methods it is its responsibility to ensure the
   * result is compliant.
   *)
  RSA_FLAG_FIPS_METHOD = $0400;
  (*
   * If this flag is set the operations normally disabled in FIPS mode are
   * permitted it is then the applications responsibility to ensure that the
   * usage is compliant.
   *)
  RSA_FLAG_NON_FIPS_ALLOW = $0400;
  (*
   * Application has decided PRNG is good enough to generate a key: don't
   * check.
   *)
  RSA_FLAG_CHECKED = $0800;

type
  rsa_pss_params_st = record
    hashAlgorithm: PX509_ALGOR;
    maskGenAlgorithm: PX509_ALGOR;
    saltLength: PASN1_INTEGER;
    trailerField: PASN1_INTEGER;
    (* Decoded hash algorithm from maskGenAlgorithm *)
    maskHash: PX509_ALGOR;
  end;
  RSA_PSS_PARAMS = rsa_pss_params_st;
  // DECLARE_ASN1_FUNCTIONS(RSA_PSS_PARAMS)

  rsa_oaep_params_st = record
    hashFunc: PX509_ALGOR;
    maskGenFunc: PX509_ALGOR;
    pSourceFunc: PX509_ALGOR;
    (* Decoded hash algorithm from maskGenFunc *)
    maskHash: PX509_ALGOR;
  end;
  RSA_OAEP_PARAMS = rsa_oaep_params_st;
  //DECLARE_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

  //DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
  //DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

  RSA_meth_set_priv_dec_priv_dec = function(flen: TOpenSSL_C_INT; const from: PByte;
    to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_mod_exp_mod_exp = function(r0: PBIGNUM; const i: PBIGNUM;
    rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_bn_mod_exp_bn_mod_exp = function(r: PBIGNUM; const a: PBIGNUM;
    const p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTx; m_ctx: PBN_MONT_CTx): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_init_init = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_finish_finish = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_sign_sign = function(type_: TOpenSSL_C_INT; const m: PByte;
    m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; const rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_verify_verify = function(dtype: TOpenSSL_C_INT; const m: PByte;
    m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; const rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_keygen_keygen = function(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCb): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_multi_prime_keygen_keygen = function(rsa: PRSA; bits: TOpenSSL_C_INT;
    primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCb): TOpenSSL_C_INT; cdecl;

//# define EVP_PKEY_CTX_set_rsa_padding(ctx, pad) \
//        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL)
//
//# define EVP_PKEY_CTX_get_rsa_padding(ctx, ppad) \
//        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, ppad)
//
//# define EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, len) \
//        RSA_pkey_ctx_ctrl(ctx, (EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), \
//                          EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)

//# define EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, len) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)
//
//# define EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, plen) \
//        RSA_pkey_ctx_ctrl(ctx, (EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), \
//                          EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, plen)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, primes, NULL)
//
//# define  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, \
//                          EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, \
//                          EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)(pmd))
//
//# define  EVP_PKEY_CTX_get_rsa_oaep_md(ctx, pmd) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)(pmd))
//
//# define  EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)(l))
//
//# define  EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, l) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, (void *)(l))
//
//# define  EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS,  \
//                          EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD,  \
//                          0, (void *)(md))

//# define RSA_set_app_data(s,arg)         RSA_set_ex_data(s,0,arg)
//# define RSA_get_app_data(s)             RSA_get_ex_data(s,0)

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM RSA_new}
{$EXTERNALSYM RSA_new_method}
{$EXTERNALSYM RSA_bits}
{$EXTERNALSYM RSA_size}
{$EXTERNALSYM RSA_security_bits}
{$EXTERNALSYM RSA_set0_key}
{$EXTERNALSYM RSA_set0_factors}
{$EXTERNALSYM RSA_set0_crt_params}
{$EXTERNALSYM RSA_get0_key}
{$EXTERNALSYM RSA_get0_factors}
{$EXTERNALSYM RSA_get_multi_prime_extra_count}
{$EXTERNALSYM RSA_get0_crt_params}
{$EXTERNALSYM RSA_get0_n}
{$EXTERNALSYM RSA_get0_e}
{$EXTERNALSYM RSA_get0_d}
{$EXTERNALSYM RSA_get0_p}
{$EXTERNALSYM RSA_get0_q}
{$EXTERNALSYM RSA_get0_dmp1}
{$EXTERNALSYM RSA_get0_dmq1}
{$EXTERNALSYM RSA_get0_iqmp}
{$EXTERNALSYM RSA_clear_flags}
{$EXTERNALSYM RSA_test_flags}
{$EXTERNALSYM RSA_set_flags}
{$EXTERNALSYM RSA_get_version}
{$EXTERNALSYM RSA_get0_engine}
{$EXTERNALSYM RSA_generate_key_ex}
{$EXTERNALSYM RSA_generate_multi_prime_key}
{$EXTERNALSYM RSA_X931_derive_ex}
{$EXTERNALSYM RSA_X931_generate_key_ex}
{$EXTERNALSYM RSA_check_key}
{$EXTERNALSYM RSA_check_key_ex}
{$EXTERNALSYM RSA_public_encrypt}
{$EXTERNALSYM RSA_private_encrypt}
{$EXTERNALSYM RSA_public_decrypt}
{$EXTERNALSYM RSA_private_decrypt}
{$EXTERNALSYM RSA_free}
{$EXTERNALSYM RSA_up_ref}
{$EXTERNALSYM RSA_flags}
{$EXTERNALSYM RSA_set_default_method}
{$EXTERNALSYM RSA_get_default_method}
{$EXTERNALSYM RSA_null_method}
{$EXTERNALSYM RSA_get_method}
{$EXTERNALSYM RSA_set_method}
{$EXTERNALSYM RSA_PKCS1_OpenSSL}
{$EXTERNALSYM RSA_pkey_ctx_ctrl}
{$EXTERNALSYM RSA_print}
{$EXTERNALSYM RSA_sign}
{$EXTERNALSYM RSA_verify}
{$EXTERNALSYM RSA_sign_ASN1_OCTET_STRING}
{$EXTERNALSYM RSA_verify_ASN1_OCTET_STRING}
{$EXTERNALSYM RSA_blinding_on}
{$EXTERNALSYM RSA_blinding_off}
{$EXTERNALSYM RSA_setup_blinding}
{$EXTERNALSYM RSA_padding_add_PKCS1_type_1}
{$EXTERNALSYM RSA_padding_check_PKCS1_type_1}
{$EXTERNALSYM RSA_padding_add_PKCS1_type_2}
{$EXTERNALSYM RSA_padding_check_PKCS1_type_2}
{$EXTERNALSYM PKCS1_MGF1}
{$EXTERNALSYM RSA_padding_add_PKCS1_OAEP}
{$EXTERNALSYM RSA_padding_check_PKCS1_OAEP}
{$EXTERNALSYM RSA_padding_add_PKCS1_OAEP_mgf1}
{$EXTERNALSYM RSA_padding_check_PKCS1_OAEP_mgf1}
{$EXTERNALSYM RSA_padding_add_none}
{$EXTERNALSYM RSA_padding_check_none}
{$EXTERNALSYM RSA_padding_add_X931}
{$EXTERNALSYM RSA_padding_check_X931}
{$EXTERNALSYM RSA_X931_hash_id}
{$EXTERNALSYM RSA_verify_PKCS1_PSS}
{$EXTERNALSYM RSA_padding_add_PKCS1_PSS}
{$EXTERNALSYM RSA_verify_PKCS1_PSS_mgf1}
{$EXTERNALSYM RSA_padding_add_PKCS1_PSS_mgf1}
{$EXTERNALSYM RSA_set_ex_data}
{$EXTERNALSYM RSA_get_ex_data}
{$EXTERNALSYM RSAPublicKey_dup}
{$EXTERNALSYM RSAPrivateKey_dup}
{$EXTERNALSYM RSA_meth_new}
{$EXTERNALSYM RSA_meth_free}
{$EXTERNALSYM RSA_meth_dup}
{$EXTERNALSYM RSA_meth_get0_name}
{$EXTERNALSYM RSA_meth_set1_name}
{$EXTERNALSYM RSA_meth_get_flags}
{$EXTERNALSYM RSA_meth_set_flags}
{$EXTERNALSYM RSA_meth_get0_app_data}
{$EXTERNALSYM RSA_meth_set0_app_data}
{$EXTERNALSYM RSA_meth_set_priv_dec}
{$EXTERNALSYM RSA_meth_set_mod_exp}
{$EXTERNALSYM RSA_meth_set_bn_mod_exp}
{$EXTERNALSYM RSA_meth_set_init}
{$EXTERNALSYM RSA_meth_set_finish}
{$EXTERNALSYM RSA_meth_set_sign}
{$EXTERNALSYM RSA_meth_set_verify}
{$EXTERNALSYM RSA_meth_set_keygen}
{$EXTERNALSYM RSA_meth_set_multi_prime_keygen}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function RSA_new: PRSA; cdecl; external CLibCrypto;
function RSA_new_method(engine: PENGINE): PRSA; cdecl; external CLibCrypto;
function RSA_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_size(const rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_security_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl; external CLibCrypto;
procedure RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl; external CLibCrypto;
function RSA_get_multi_prime_extra_count(const r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl; external CLibCrypto;
function RSA_get0_n(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_e(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_d(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_p(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_q(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_dmp1(const r: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_dmq1(const r: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_iqmp(const r: PRSA): PBIGNUM; cdecl; external CLibCrypto;
procedure RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function RSA_test_flags(const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_get0_engine(const r: PRSA): PENGINE; cdecl; external CLibCrypto;
function RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_check_key(const v1: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_check_key_ex(const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_public_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_private_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_public_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_private_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_free(r: PRSA); cdecl; external CLibCrypto;
function RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_flags(const r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_set_default_method(const meth: PRSA_METHOD); cdecl; external CLibCrypto;
function RSA_get_default_method: PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_null_method: PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_get_method(const rsa: PRSA): PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_print(bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_sign(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_blinding_off(rsa: PRSA); cdecl; external CLibCrypto;
function RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS1_MGF1(mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_get_ex_data(const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function RSAPublicKey_dup(rsa: PRSA): PRSA; cdecl; external CLibCrypto;
function RSAPrivateKey_dup(rsa: PRSA): PRSA; cdecl; external CLibCrypto;
function RSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl; external CLibCrypto;
procedure RSA_meth_free(meth: PRSA_METHOD); cdecl; external CLibCrypto;
function RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_meth_get0_name(const meth: PRSA_METHOD): PAnsiChar; cdecl; external CLibCrypto;
function RSA_meth_set1_name(meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_get_flags(const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer; cdecl; external CLibCrypto;
function RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_RSA_new: PRSA; cdecl;
function Load_RSA_new_method(engine: PENGINE): PRSA; cdecl;
function Load_RSA_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_size(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_security_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl;
procedure Load_RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl;
procedure Load_RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl;
function Load_RSA_get_multi_prime_extra_count(const r: PRSA): TOpenSSL_C_INT; cdecl;
procedure Load_RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl;
function Load_RSA_get0_n(const d: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_e(const d: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_d(const d: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_p(const d: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_q(const d: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_dmp1(const r: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_dmq1(const r: PRSA): PBIGNUM; cdecl;
function Load_RSA_get0_iqmp(const r: PRSA): PBIGNUM; cdecl;
procedure Load_RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
function Load_RSA_test_flags(const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
function Load_RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_get0_engine(const r: PRSA): PENGINE; cdecl;
function Load_RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_RSA_check_key(const v1: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_check_key_ex(const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_RSA_public_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_private_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_public_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_private_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_RSA_free(r: PRSA); cdecl;
function Load_RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_flags(const r: PRSA): TOpenSSL_C_INT; cdecl;
procedure Load_RSA_set_default_method(const meth: PRSA_METHOD); cdecl;
function Load_RSA_get_default_method: PRSA_METHOD; cdecl;
function Load_RSA_null_method: PRSA_METHOD; cdecl;
function Load_RSA_get_method(const rsa: PRSA): PRSA_METHOD; cdecl;
function Load_RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
function Load_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl;
function Load_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
function Load_RSA_print(bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_sign(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_verify(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_RSA_blinding_off(rsa: PRSA); cdecl;
function Load_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl;
function Load_RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS1_MGF1(mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_RSA_padding_add_SSLv23(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_SSLv23(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_RSA_padding_add_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_add_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_check_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_RSA_get_ex_data(const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_RSAPublicKey_dup(rsa: PRSA): PRSA; cdecl;
function Load_RSAPrivateKey_dup(rsa: PRSA): PRSA; cdecl;
function Load_RSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl;
procedure Load_RSA_meth_free(meth: PRSA_METHOD); cdecl;
function Load_RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD; cdecl;
function Load_RSA_meth_get0_name(const meth: PRSA_METHOD): PAnsiChar; cdecl;
function Load_RSA_meth_set1_name(meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_get_flags(const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer; cdecl;
function Load_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl;
function Load_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl;

var
  RSA_new: function : PRSA; cdecl = Load_RSA_new;
  RSA_new_method: function (engine: PENGINE): PRSA; cdecl = Load_RSA_new_method;
  RSA_bits: function (const rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_bits;
  RSA_size: function (const rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_size;
  RSA_security_bits: function (const rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_security_bits;
  RSA_set0_key: function (r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_set0_key;
  RSA_set0_factors: function (r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_set0_factors;
  RSA_set0_crt_params: function (r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_set0_crt_params;
  RSA_get0_key: procedure (const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl = Load_RSA_get0_key;
  RSA_get0_factors: procedure (const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl = Load_RSA_get0_factors;
  RSA_get_multi_prime_extra_count: function (const r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_get_multi_prime_extra_count;
  RSA_get0_crt_params: procedure (const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl = Load_RSA_get0_crt_params;
  RSA_get0_n: function (const d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_n;
  RSA_get0_e: function (const d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_e;
  RSA_get0_d: function (const d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_d;
  RSA_get0_p: function (const d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_p;
  RSA_get0_q: function (const d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_q;
  RSA_get0_dmp1: function (const r: PRSA): PBIGNUM; cdecl = Load_RSA_get0_dmp1;
  RSA_get0_dmq1: function (const r: PRSA): PBIGNUM; cdecl = Load_RSA_get0_dmq1;
  RSA_get0_iqmp: function (const r: PRSA): PBIGNUM; cdecl = Load_RSA_get0_iqmp;
  RSA_clear_flags: procedure (r: PRSA; flags: TOpenSSL_C_INT); cdecl = Load_RSA_clear_flags;
  RSA_test_flags: function (const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_test_flags;
  RSA_set_flags: procedure (r: PRSA; flags: TOpenSSL_C_INT); cdecl = Load_RSA_set_flags;
  RSA_get_version: function (r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_get_version;
  RSA_get0_engine: function (const r: PRSA): PENGINE; cdecl = Load_RSA_get0_engine;
  RSA_generate_key_ex: function (rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_generate_key_ex;
  RSA_generate_multi_prime_key: function (rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_generate_multi_prime_key;
  RSA_X931_derive_ex: function (rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_X931_derive_ex;
  RSA_X931_generate_key_ex: function (rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_X931_generate_key_ex;
  RSA_check_key: function (const v1: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_check_key;
  RSA_check_key_ex: function (const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_check_key_ex;
  RSA_public_encrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_public_encrypt;
  RSA_private_encrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_private_encrypt;
  RSA_public_decrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_public_decrypt;
  RSA_private_decrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_private_decrypt;
  RSA_free: procedure (r: PRSA); cdecl = Load_RSA_free;
  RSA_up_ref: function (r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_up_ref;
  RSA_flags: function (const r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_flags;
  RSA_set_default_method: procedure (const meth: PRSA_METHOD); cdecl = Load_RSA_set_default_method;
  RSA_get_default_method: function : PRSA_METHOD; cdecl = Load_RSA_get_default_method;
  RSA_null_method: function : PRSA_METHOD; cdecl = Load_RSA_null_method;
  RSA_get_method: function (const rsa: PRSA): PRSA_METHOD; cdecl = Load_RSA_get_method;
  RSA_set_method: function (rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = Load_RSA_set_method;
  RSA_PKCS1_OpenSSL: function : PRSA_METHOD; cdecl = Load_RSA_PKCS1_OpenSSL;
  RSA_pkey_ctx_ctrl: function (ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl = Load_RSA_pkey_ctx_ctrl;
  RSA_print: function (bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_print;
  RSA_sign: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_sign;
  RSA_verify: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_verify;
  RSA_sign_ASN1_OCTET_STRING: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_sign_ASN1_OCTET_STRING;
  RSA_verify_ASN1_OCTET_STRING: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_verify_ASN1_OCTET_STRING;
  RSA_blinding_on: function (rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_RSA_blinding_on;
  RSA_blinding_off: procedure (rsa: PRSA); cdecl = Load_RSA_blinding_off;
  RSA_setup_blinding: function (rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl = Load_RSA_setup_blinding;
  RSA_padding_add_PKCS1_type_1: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_type_1;
  RSA_padding_check_PKCS1_type_1: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_type_1;
  RSA_padding_add_PKCS1_type_2: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_type_2;
  RSA_padding_check_PKCS1_type_2: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_type_2;
  PKCS1_MGF1: function (mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS1_MGF1;
  RSA_padding_add_PKCS1_OAEP: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_OAEP;
  RSA_padding_check_PKCS1_OAEP: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_OAEP;
  RSA_padding_add_PKCS1_OAEP_mgf1: function (to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_OAEP_mgf1;
  RSA_padding_check_PKCS1_OAEP_mgf1: function (to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_OAEP_mgf1;
  RSA_padding_add_none: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_none;
  RSA_padding_check_none: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_none;
  RSA_padding_add_X931: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_X931;
  RSA_padding_check_X931: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_X931;
  RSA_X931_hash_id: function (nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_X931_hash_id;
  RSA_verify_PKCS1_PSS: function (rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_verify_PKCS1_PSS;
  RSA_padding_add_PKCS1_PSS: function (rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_PSS;
  RSA_verify_PKCS1_PSS_mgf1: function (rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_verify_PKCS1_PSS_mgf1;
  RSA_padding_add_PKCS1_PSS_mgf1: function (rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_PSS_mgf1;
  RSA_set_ex_data: function (r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_RSA_set_ex_data;
  RSA_get_ex_data: function (const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_RSA_get_ex_data;
  RSAPublicKey_dup: function (rsa: PRSA): PRSA; cdecl = Load_RSAPublicKey_dup;
  RSAPrivateKey_dup: function (rsa: PRSA): PRSA; cdecl = Load_RSAPrivateKey_dup;
  RSA_meth_new: function (const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl = Load_RSA_meth_new;
  RSA_meth_free: procedure (meth: PRSA_METHOD); cdecl = Load_RSA_meth_free;
  RSA_meth_dup: function (const meth: PRSA_METHOD): PRSA_METHOD; cdecl = Load_RSA_meth_dup;
  RSA_meth_get0_name: function (const meth: PRSA_METHOD): PAnsiChar; cdecl = Load_RSA_meth_get0_name;
  RSA_meth_set1_name: function (meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set1_name;
  RSA_meth_get_flags: function (const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = Load_RSA_meth_get_flags;
  RSA_meth_set_flags: function (meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_flags;
  RSA_meth_get0_app_data: function (const meth: PRSA_METHOD): Pointer; cdecl = Load_RSA_meth_get0_app_data;
  RSA_meth_set0_app_data: function (meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set0_app_data;
  RSA_meth_set_priv_dec: function (rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_priv_dec;
  RSA_meth_set_mod_exp: function (rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_mod_exp;
  RSA_meth_set_bn_mod_exp: function (rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_bn_mod_exp;
  RSA_meth_set_init: function (rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_init;
  RSA_meth_set_finish: function (rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_finish;
  RSA_meth_set_sign: function (rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_sign;
  RSA_meth_set_verify: function (rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_verify;
  RSA_meth_set_keygen: function (rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_keygen;
  RSA_meth_set_multi_prime_keygen: function (meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_multi_prime_keygen;
{$ENDIF}
const
  RSA_padding_add_SSLv23_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  RSA_padding_check_SSLv23_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}


implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  RSA_padding_add_SSLv23: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_SSLv23; {removed 3.0.0}
  RSA_padding_check_SSLv23: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_SSLv23; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_RSA_new: PRSA; cdecl;
begin
  RSA_new := LoadLibCryptoFunction('RSA_new');
  if not assigned(RSA_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_new');
  Result := RSA_new();
end;

function Load_RSA_new_method(engine: PENGINE): PRSA; cdecl;
begin
  RSA_new_method := LoadLibCryptoFunction('RSA_new_method');
  if not assigned(RSA_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_new_method');
  Result := RSA_new_method(engine);
end;

function Load_RSA_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_bits := LoadLibCryptoFunction('RSA_bits');
  if not assigned(RSA_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_bits');
  Result := RSA_bits(rsa);
end;

function Load_RSA_size(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_size := LoadLibCryptoFunction('RSA_size');
  if not assigned(RSA_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_size');
  Result := RSA_size(rsa);
end;

function Load_RSA_security_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_security_bits := LoadLibCryptoFunction('RSA_security_bits');
  if not assigned(RSA_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_security_bits');
  Result := RSA_security_bits(rsa);
end;

function Load_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_key := LoadLibCryptoFunction('RSA_set0_key');
  if not assigned(RSA_set0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_key');
  Result := RSA_set0_key(r,n,e,d);
end;

function Load_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_factors := LoadLibCryptoFunction('RSA_set0_factors');
  if not assigned(RSA_set0_factors) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_factors');
  Result := RSA_set0_factors(r,p,q);
end;

function Load_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_crt_params := LoadLibCryptoFunction('RSA_set0_crt_params');
  if not assigned(RSA_set0_crt_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_crt_params');
  Result := RSA_set0_crt_params(r,dmp1,dmq1,iqmp);
end;

procedure Load_RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl;
begin
  RSA_get0_key := LoadLibCryptoFunction('RSA_get0_key');
  if not assigned(RSA_get0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_key');
  RSA_get0_key(r,n,e,d);
end;

procedure Load_RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl;
begin
  RSA_get0_factors := LoadLibCryptoFunction('RSA_get0_factors');
  if not assigned(RSA_get0_factors) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_factors');
  RSA_get0_factors(r,p,q);
end;

function Load_RSA_get_multi_prime_extra_count(const r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_get_multi_prime_extra_count := LoadLibCryptoFunction('RSA_get_multi_prime_extra_count');
  if not assigned(RSA_get_multi_prime_extra_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_multi_prime_extra_count');
  Result := RSA_get_multi_prime_extra_count(r);
end;

procedure Load_RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl;
begin
  RSA_get0_crt_params := LoadLibCryptoFunction('RSA_get0_crt_params');
  if not assigned(RSA_get0_crt_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_crt_params');
  RSA_get0_crt_params(r,dmp1,dmq1,iqmp);
end;

function Load_RSA_get0_n(const d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_n := LoadLibCryptoFunction('RSA_get0_n');
  if not assigned(RSA_get0_n) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_n');
  Result := RSA_get0_n(d);
end;

function Load_RSA_get0_e(const d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_e := LoadLibCryptoFunction('RSA_get0_e');
  if not assigned(RSA_get0_e) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_e');
  Result := RSA_get0_e(d);
end;

function Load_RSA_get0_d(const d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_d := LoadLibCryptoFunction('RSA_get0_d');
  if not assigned(RSA_get0_d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_d');
  Result := RSA_get0_d(d);
end;

function Load_RSA_get0_p(const d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_p := LoadLibCryptoFunction('RSA_get0_p');
  if not assigned(RSA_get0_p) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_p');
  Result := RSA_get0_p(d);
end;

function Load_RSA_get0_q(const d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_q := LoadLibCryptoFunction('RSA_get0_q');
  if not assigned(RSA_get0_q) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_q');
  Result := RSA_get0_q(d);
end;

function Load_RSA_get0_dmp1(const r: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_dmp1 := LoadLibCryptoFunction('RSA_get0_dmp1');
  if not assigned(RSA_get0_dmp1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_dmp1');
  Result := RSA_get0_dmp1(r);
end;

function Load_RSA_get0_dmq1(const r: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_dmq1 := LoadLibCryptoFunction('RSA_get0_dmq1');
  if not assigned(RSA_get0_dmq1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_dmq1');
  Result := RSA_get0_dmq1(r);
end;

function Load_RSA_get0_iqmp(const r: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_iqmp := LoadLibCryptoFunction('RSA_get0_iqmp');
  if not assigned(RSA_get0_iqmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_iqmp');
  Result := RSA_get0_iqmp(r);
end;

procedure Load_RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
begin
  RSA_clear_flags := LoadLibCryptoFunction('RSA_clear_flags');
  if not assigned(RSA_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_clear_flags');
  RSA_clear_flags(r,flags);
end;

function Load_RSA_test_flags(const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_test_flags := LoadLibCryptoFunction('RSA_test_flags');
  if not assigned(RSA_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_test_flags');
  Result := RSA_test_flags(r,flags);
end;

procedure Load_RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
begin
  RSA_set_flags := LoadLibCryptoFunction('RSA_set_flags');
  if not assigned(RSA_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_flags');
  RSA_set_flags(r,flags);
end;

function Load_RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_get_version := LoadLibCryptoFunction('RSA_get_version');
  if not assigned(RSA_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_version');
  Result := RSA_get_version(r);
end;

function Load_RSA_get0_engine(const r: PRSA): PENGINE; cdecl;
begin
  RSA_get0_engine := LoadLibCryptoFunction('RSA_get0_engine');
  if not assigned(RSA_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_engine');
  Result := RSA_get0_engine(r);
end;

function Load_RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_generate_key_ex := LoadLibCryptoFunction('RSA_generate_key_ex');
  if not assigned(RSA_generate_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_key_ex');
  Result := RSA_generate_key_ex(rsa,bits,e,cb);
end;

function Load_RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_generate_multi_prime_key := LoadLibCryptoFunction('RSA_generate_multi_prime_key');
  if not assigned(RSA_generate_multi_prime_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_multi_prime_key');
  Result := RSA_generate_multi_prime_key(rsa,bits,primes,e,cb);
end;

function Load_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_X931_derive_ex := LoadLibCryptoFunction('RSA_X931_derive_ex');
  if not assigned(RSA_X931_derive_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_derive_ex');
  Result := RSA_X931_derive_ex(rsa,p1,p2,q1,q2,Xp1,Xp2,Xp,Xq1,Xq2,Xq,e,cb);
end;

function Load_RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_X931_generate_key_ex := LoadLibCryptoFunction('RSA_X931_generate_key_ex');
  if not assigned(RSA_X931_generate_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_generate_key_ex');
  Result := RSA_X931_generate_key_ex(rsa,bits,e,cb);
end;

function Load_RSA_check_key(const v1: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_check_key := LoadLibCryptoFunction('RSA_check_key');
  if not assigned(RSA_check_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_check_key');
  Result := RSA_check_key(v1);
end;

function Load_RSA_check_key_ex(const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_check_key_ex := LoadLibCryptoFunction('RSA_check_key_ex');
  if not assigned(RSA_check_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_check_key_ex');
  Result := RSA_check_key_ex(v1,cb);
end;

function Load_RSA_public_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_public_encrypt := LoadLibCryptoFunction('RSA_public_encrypt');
  if not assigned(RSA_public_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_public_encrypt');
  Result := RSA_public_encrypt(flen,from,to_,rsa,padding);
end;

function Load_RSA_private_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_private_encrypt := LoadLibCryptoFunction('RSA_private_encrypt');
  if not assigned(RSA_private_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_private_encrypt');
  Result := RSA_private_encrypt(flen,from,to_,rsa,padding);
end;

function Load_RSA_public_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_public_decrypt := LoadLibCryptoFunction('RSA_public_decrypt');
  if not assigned(RSA_public_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_public_decrypt');
  Result := RSA_public_decrypt(flen,from,to_,rsa,padding);
end;

function Load_RSA_private_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_private_decrypt := LoadLibCryptoFunction('RSA_private_decrypt');
  if not assigned(RSA_private_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_private_decrypt');
  Result := RSA_private_decrypt(flen,from,to_,rsa,padding);
end;

procedure Load_RSA_free(r: PRSA); cdecl;
begin
  RSA_free := LoadLibCryptoFunction('RSA_free');
  if not assigned(RSA_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_free');
  RSA_free(r);
end;

function Load_RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_up_ref := LoadLibCryptoFunction('RSA_up_ref');
  if not assigned(RSA_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_up_ref');
  Result := RSA_up_ref(r);
end;

function Load_RSA_flags(const r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_flags := LoadLibCryptoFunction('RSA_flags');
  if not assigned(RSA_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_flags');
  Result := RSA_flags(r);
end;

procedure Load_RSA_set_default_method(const meth: PRSA_METHOD); cdecl;
begin
  RSA_set_default_method := LoadLibCryptoFunction('RSA_set_default_method');
  if not assigned(RSA_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_default_method');
  RSA_set_default_method(meth);
end;

function Load_RSA_get_default_method: PRSA_METHOD; cdecl;
begin
  RSA_get_default_method := LoadLibCryptoFunction('RSA_get_default_method');
  if not assigned(RSA_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_default_method');
  Result := RSA_get_default_method();
end;

function Load_RSA_null_method: PRSA_METHOD; cdecl;
begin
  RSA_null_method := LoadLibCryptoFunction('RSA_null_method');
  if not assigned(RSA_null_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_null_method');
  Result := RSA_null_method();
end;

function Load_RSA_get_method(const rsa: PRSA): PRSA_METHOD; cdecl;
begin
  RSA_get_method := LoadLibCryptoFunction('RSA_get_method');
  if not assigned(RSA_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_method');
  Result := RSA_get_method(rsa);
end;

function Load_RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  RSA_set_method := LoadLibCryptoFunction('RSA_set_method');
  if not assigned(RSA_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_method');
  Result := RSA_set_method(rsa,meth);
end;

function Load_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl;
begin
  RSA_PKCS1_OpenSSL := LoadLibCryptoFunction('RSA_PKCS1_OpenSSL');
  if not assigned(RSA_PKCS1_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PKCS1_OpenSSL');
  Result := RSA_PKCS1_OpenSSL();
end;

function Load_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
begin
  RSA_pkey_ctx_ctrl := LoadLibCryptoFunction('RSA_pkey_ctx_ctrl');
  if not assigned(RSA_pkey_ctx_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_pkey_ctx_ctrl');
  Result := RSA_pkey_ctx_ctrl(ctx,optype,cmd,p1,p2);
end;

function Load_RSA_print(bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_print := LoadLibCryptoFunction('RSA_print');
  if not assigned(RSA_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_print');
  Result := RSA_print(bp,r,offset);
end;

function Load_RSA_sign(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_sign := LoadLibCryptoFunction('RSA_sign');
  if not assigned(RSA_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_sign');
  Result := RSA_sign(type_,m,m_length,sigret,siglen,rsa);
end;

function Load_RSA_verify(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify := LoadLibCryptoFunction('RSA_verify');
  if not assigned(RSA_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify');
  Result := RSA_verify(type_,m,m_length,sigbuf,siglen,rsa);
end;

function Load_RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_sign_ASN1_OCTET_STRING := LoadLibCryptoFunction('RSA_sign_ASN1_OCTET_STRING');
  if not assigned(RSA_sign_ASN1_OCTET_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_sign_ASN1_OCTET_STRING');
  Result := RSA_sign_ASN1_OCTET_STRING(type_,m,m_length,sigret,siglen,rsa);
end;

function Load_RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify_ASN1_OCTET_STRING := LoadLibCryptoFunction('RSA_verify_ASN1_OCTET_STRING');
  if not assigned(RSA_verify_ASN1_OCTET_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_ASN1_OCTET_STRING');
  Result := RSA_verify_ASN1_OCTET_STRING(type_,m,m_length,sigbuf,siglen,rsa);
end;

function Load_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  RSA_blinding_on := LoadLibCryptoFunction('RSA_blinding_on');
  if not assigned(RSA_blinding_on) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_blinding_on');
  Result := RSA_blinding_on(rsa,ctx);
end;

procedure Load_RSA_blinding_off(rsa: PRSA); cdecl;
begin
  RSA_blinding_off := LoadLibCryptoFunction('RSA_blinding_off');
  if not assigned(RSA_blinding_off) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_blinding_off');
  RSA_blinding_off(rsa);
end;

function Load_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl;
begin
  RSA_setup_blinding := LoadLibCryptoFunction('RSA_setup_blinding');
  if not assigned(RSA_setup_blinding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_setup_blinding');
  Result := RSA_setup_blinding(rsa,ctx);
end;

function Load_RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_type_1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_type_1');
  if not assigned(RSA_padding_add_PKCS1_type_1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_type_1');
  Result := RSA_padding_add_PKCS1_type_1(to_,tlen,f,fl);
end;

function Load_RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_type_1 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_type_1');
  if not assigned(RSA_padding_check_PKCS1_type_1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_type_1');
  Result := RSA_padding_check_PKCS1_type_1(to_,tlen,f,fl,rsa_len);
end;

function Load_RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_type_2 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_type_2');
  if not assigned(RSA_padding_add_PKCS1_type_2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_type_2');
  Result := RSA_padding_add_PKCS1_type_2(to_,tlen,f,fl);
end;

function Load_RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_type_2 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_type_2');
  if not assigned(RSA_padding_check_PKCS1_type_2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_type_2');
  Result := RSA_padding_check_PKCS1_type_2(to_,tlen,f,fl,rsa_len);
end;

function Load_PKCS1_MGF1(mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS1_MGF1 := LoadLibCryptoFunction('PKCS1_MGF1');
  if not assigned(PKCS1_MGF1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS1_MGF1');
  Result := PKCS1_MGF1(mask,len,seed,seedlen,dgst);
end;

function Load_RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_OAEP := LoadLibCryptoFunction('RSA_padding_add_PKCS1_OAEP');
  if not assigned(RSA_padding_add_PKCS1_OAEP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_OAEP');
  Result := RSA_padding_add_PKCS1_OAEP(to_,tlen,f,fl,p,pl);
end;

function Load_RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_OAEP := LoadLibCryptoFunction('RSA_padding_check_PKCS1_OAEP');
  if not assigned(RSA_padding_check_PKCS1_OAEP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_OAEP');
  Result := RSA_padding_check_PKCS1_OAEP(to_,tlen,f,fl,rsa_len,p,pl);
end;

function Load_RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_OAEP_mgf1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_OAEP_mgf1');
  if not assigned(RSA_padding_add_PKCS1_OAEP_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_OAEP_mgf1');
  Result := RSA_padding_add_PKCS1_OAEP_mgf1(to_,tlen,from,flen,param,plen,md,mgf1md);
end;

function Load_RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_OAEP_mgf1 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_OAEP_mgf1');
  if not assigned(RSA_padding_check_PKCS1_OAEP_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_OAEP_mgf1');
  Result := RSA_padding_check_PKCS1_OAEP_mgf1(to_,tlen,from,flen,num,param,plen,md,mgf1md);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_RSA_padding_add_SSLv23(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_SSLv23 := LoadLibCryptoFunction('RSA_padding_add_SSLv23');
  if not assigned(RSA_padding_add_SSLv23) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_SSLv23');
  Result := RSA_padding_add_SSLv23(to_,tlen,f,fl);
end;

function Load_RSA_padding_check_SSLv23(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_SSLv23 := LoadLibCryptoFunction('RSA_padding_check_SSLv23');
  if not assigned(RSA_padding_check_SSLv23) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_SSLv23');
  Result := RSA_padding_check_SSLv23(to_,tlen,f,fl,rsa_len);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_RSA_padding_add_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_none := LoadLibCryptoFunction('RSA_padding_add_none');
  if not assigned(RSA_padding_add_none) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_none');
  Result := RSA_padding_add_none(to_,tlen,f,fl);
end;

function Load_RSA_padding_check_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_none := LoadLibCryptoFunction('RSA_padding_check_none');
  if not assigned(RSA_padding_check_none) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_none');
  Result := RSA_padding_check_none(to_,tlen,f,fl,rsa_len);
end;

function Load_RSA_padding_add_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_X931 := LoadLibCryptoFunction('RSA_padding_add_X931');
  if not assigned(RSA_padding_add_X931) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_X931');
  Result := RSA_padding_add_X931(to_,tlen,f,fl);
end;

function Load_RSA_padding_check_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_X931 := LoadLibCryptoFunction('RSA_padding_check_X931');
  if not assigned(RSA_padding_check_X931) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_X931');
  Result := RSA_padding_check_X931(to_,tlen,f,fl,rsa_len);
end;

function Load_RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_X931_hash_id := LoadLibCryptoFunction('RSA_X931_hash_id');
  if not assigned(RSA_X931_hash_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_hash_id');
  Result := RSA_X931_hash_id(nid);
end;

function Load_RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify_PKCS1_PSS := LoadLibCryptoFunction('RSA_verify_PKCS1_PSS');
  if not assigned(RSA_verify_PKCS1_PSS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_PKCS1_PSS');
  Result := RSA_verify_PKCS1_PSS(rsa,mHash,Hash,EM,sLen);
end;

function Load_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_PSS := LoadLibCryptoFunction('RSA_padding_add_PKCS1_PSS');
  if not assigned(RSA_padding_add_PKCS1_PSS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_PSS');
  Result := RSA_padding_add_PKCS1_PSS(rsa,EM,mHash,Hash,sLen);
end;

function Load_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify_PKCS1_PSS_mgf1 := LoadLibCryptoFunction('RSA_verify_PKCS1_PSS_mgf1');
  if not assigned(RSA_verify_PKCS1_PSS_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_PKCS1_PSS_mgf1');
  Result := RSA_verify_PKCS1_PSS_mgf1(rsa,mHash,Hash,mgf1Hash,EM,sLen);
end;

function Load_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_PSS_mgf1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_PSS_mgf1');
  if not assigned(RSA_padding_add_PKCS1_PSS_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_PSS_mgf1');
  Result := RSA_padding_add_PKCS1_PSS_mgf1(rsa,EM,mHash,Hash,mgf1Hash,sLen);
end;

function Load_RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  RSA_set_ex_data := LoadLibCryptoFunction('RSA_set_ex_data');
  if not assigned(RSA_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_ex_data');
  Result := RSA_set_ex_data(r,idx,arg);
end;

function Load_RSA_get_ex_data(const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  RSA_get_ex_data := LoadLibCryptoFunction('RSA_get_ex_data');
  if not assigned(RSA_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_ex_data');
  Result := RSA_get_ex_data(r,idx);
end;

function Load_RSAPublicKey_dup(rsa: PRSA): PRSA; cdecl;
begin
  RSAPublicKey_dup := LoadLibCryptoFunction('RSAPublicKey_dup');
  if not assigned(RSAPublicKey_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPublicKey_dup');
  Result := RSAPublicKey_dup(rsa);
end;

function Load_RSAPrivateKey_dup(rsa: PRSA): PRSA; cdecl;
begin
  RSAPrivateKey_dup := LoadLibCryptoFunction('RSAPrivateKey_dup');
  if not assigned(RSAPrivateKey_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPrivateKey_dup');
  Result := RSAPrivateKey_dup(rsa);
end;

function Load_RSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl;
begin
  RSA_meth_new := LoadLibCryptoFunction('RSA_meth_new');
  if not assigned(RSA_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_new');
  Result := RSA_meth_new(name,flags);
end;

procedure Load_RSA_meth_free(meth: PRSA_METHOD); cdecl;
begin
  RSA_meth_free := LoadLibCryptoFunction('RSA_meth_free');
  if not assigned(RSA_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_free');
  RSA_meth_free(meth);
end;

function Load_RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD; cdecl;
begin
  RSA_meth_dup := LoadLibCryptoFunction('RSA_meth_dup');
  if not assigned(RSA_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_dup');
  Result := RSA_meth_dup(meth);
end;

function Load_RSA_meth_get0_name(const meth: PRSA_METHOD): PAnsiChar; cdecl;
begin
  RSA_meth_get0_name := LoadLibCryptoFunction('RSA_meth_get0_name');
  if not assigned(RSA_meth_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get0_name');
  Result := RSA_meth_get0_name(meth);
end;

function Load_RSA_meth_set1_name(meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set1_name := LoadLibCryptoFunction('RSA_meth_set1_name');
  if not assigned(RSA_meth_set1_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set1_name');
  Result := RSA_meth_set1_name(meth,name);
end;

function Load_RSA_meth_get_flags(const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_get_flags := LoadLibCryptoFunction('RSA_meth_get_flags');
  if not assigned(RSA_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_flags');
  Result := RSA_meth_get_flags(meth);
end;

function Load_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_flags := LoadLibCryptoFunction('RSA_meth_set_flags');
  if not assigned(RSA_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_flags');
  Result := RSA_meth_set_flags(meth,flags);
end;

function Load_RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer; cdecl;
begin
  RSA_meth_get0_app_data := LoadLibCryptoFunction('RSA_meth_get0_app_data');
  if not assigned(RSA_meth_get0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get0_app_data');
  Result := RSA_meth_get0_app_data(meth);
end;

function Load_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set0_app_data := LoadLibCryptoFunction('RSA_meth_set0_app_data');
  if not assigned(RSA_meth_set0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set0_app_data');
  Result := RSA_meth_set0_app_data(meth,app_data);
end;

function Load_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_priv_dec := LoadLibCryptoFunction('RSA_meth_set_priv_dec');
  if not assigned(RSA_meth_set_priv_dec) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_priv_dec');
  Result := RSA_meth_set_priv_dec(rsa,priv_dec);
end;

function Load_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_mod_exp := LoadLibCryptoFunction('RSA_meth_set_mod_exp');
  if not assigned(RSA_meth_set_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_mod_exp');
  Result := RSA_meth_set_mod_exp(rsa,mod_exp);
end;

function Load_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_bn_mod_exp := LoadLibCryptoFunction('RSA_meth_set_bn_mod_exp');
  if not assigned(RSA_meth_set_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_bn_mod_exp');
  Result := RSA_meth_set_bn_mod_exp(rsa,bn_mod_exp);
end;

function Load_RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_init := LoadLibCryptoFunction('RSA_meth_set_init');
  if not assigned(RSA_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_init');
  Result := RSA_meth_set_init(rsa,init);
end;

function Load_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_finish := LoadLibCryptoFunction('RSA_meth_set_finish');
  if not assigned(RSA_meth_set_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_finish');
  Result := RSA_meth_set_finish(rsa,finish);
end;

function Load_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_sign := LoadLibCryptoFunction('RSA_meth_set_sign');
  if not assigned(RSA_meth_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_sign');
  Result := RSA_meth_set_sign(rsa,sign);
end;

function Load_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_verify := LoadLibCryptoFunction('RSA_meth_set_verify');
  if not assigned(RSA_meth_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_verify');
  Result := RSA_meth_set_verify(rsa,verify);
end;

function Load_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_keygen := LoadLibCryptoFunction('RSA_meth_set_keygen');
  if not assigned(RSA_meth_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_keygen');
  Result := RSA_meth_set_keygen(rsa,keygen);
end;

function Load_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_multi_prime_keygen := LoadLibCryptoFunction('RSA_meth_set_multi_prime_keygen');
  if not assigned(RSA_meth_set_multi_prime_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_multi_prime_keygen');
  Result := RSA_meth_set_multi_prime_keygen(meth,keygen);
end;


procedure UnLoad;
begin
  RSA_new := Load_RSA_new;
  RSA_new_method := Load_RSA_new_method;
  RSA_bits := Load_RSA_bits;
  RSA_size := Load_RSA_size;
  RSA_security_bits := Load_RSA_security_bits;
  RSA_set0_key := Load_RSA_set0_key;
  RSA_set0_factors := Load_RSA_set0_factors;
  RSA_set0_crt_params := Load_RSA_set0_crt_params;
  RSA_get0_key := Load_RSA_get0_key;
  RSA_get0_factors := Load_RSA_get0_factors;
  RSA_get_multi_prime_extra_count := Load_RSA_get_multi_prime_extra_count;
  RSA_get0_crt_params := Load_RSA_get0_crt_params;
  RSA_get0_n := Load_RSA_get0_n;
  RSA_get0_e := Load_RSA_get0_e;
  RSA_get0_d := Load_RSA_get0_d;
  RSA_get0_p := Load_RSA_get0_p;
  RSA_get0_q := Load_RSA_get0_q;
  RSA_get0_dmp1 := Load_RSA_get0_dmp1;
  RSA_get0_dmq1 := Load_RSA_get0_dmq1;
  RSA_get0_iqmp := Load_RSA_get0_iqmp;
  RSA_clear_flags := Load_RSA_clear_flags;
  RSA_test_flags := Load_RSA_test_flags;
  RSA_set_flags := Load_RSA_set_flags;
  RSA_get_version := Load_RSA_get_version;
  RSA_get0_engine := Load_RSA_get0_engine;
  RSA_generate_key_ex := Load_RSA_generate_key_ex;
  RSA_generate_multi_prime_key := Load_RSA_generate_multi_prime_key;
  RSA_X931_derive_ex := Load_RSA_X931_derive_ex;
  RSA_X931_generate_key_ex := Load_RSA_X931_generate_key_ex;
  RSA_check_key := Load_RSA_check_key;
  RSA_check_key_ex := Load_RSA_check_key_ex;
  RSA_public_encrypt := Load_RSA_public_encrypt;
  RSA_private_encrypt := Load_RSA_private_encrypt;
  RSA_public_decrypt := Load_RSA_public_decrypt;
  RSA_private_decrypt := Load_RSA_private_decrypt;
  RSA_free := Load_RSA_free;
  RSA_up_ref := Load_RSA_up_ref;
  RSA_flags := Load_RSA_flags;
  RSA_set_default_method := Load_RSA_set_default_method;
  RSA_get_default_method := Load_RSA_get_default_method;
  RSA_null_method := Load_RSA_null_method;
  RSA_get_method := Load_RSA_get_method;
  RSA_set_method := Load_RSA_set_method;
  RSA_PKCS1_OpenSSL := Load_RSA_PKCS1_OpenSSL;
  RSA_pkey_ctx_ctrl := Load_RSA_pkey_ctx_ctrl;
  RSA_print := Load_RSA_print;
  RSA_sign := Load_RSA_sign;
  RSA_verify := Load_RSA_verify;
  RSA_sign_ASN1_OCTET_STRING := Load_RSA_sign_ASN1_OCTET_STRING;
  RSA_verify_ASN1_OCTET_STRING := Load_RSA_verify_ASN1_OCTET_STRING;
  RSA_blinding_on := Load_RSA_blinding_on;
  RSA_blinding_off := Load_RSA_blinding_off;
  RSA_setup_blinding := Load_RSA_setup_blinding;
  RSA_padding_add_PKCS1_type_1 := Load_RSA_padding_add_PKCS1_type_1;
  RSA_padding_check_PKCS1_type_1 := Load_RSA_padding_check_PKCS1_type_1;
  RSA_padding_add_PKCS1_type_2 := Load_RSA_padding_add_PKCS1_type_2;
  RSA_padding_check_PKCS1_type_2 := Load_RSA_padding_check_PKCS1_type_2;
  PKCS1_MGF1 := Load_PKCS1_MGF1;
  RSA_padding_add_PKCS1_OAEP := Load_RSA_padding_add_PKCS1_OAEP;
  RSA_padding_check_PKCS1_OAEP := Load_RSA_padding_check_PKCS1_OAEP;
  RSA_padding_add_PKCS1_OAEP_mgf1 := Load_RSA_padding_add_PKCS1_OAEP_mgf1;
  RSA_padding_check_PKCS1_OAEP_mgf1 := Load_RSA_padding_check_PKCS1_OAEP_mgf1;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  RSA_padding_add_SSLv23 := Load_RSA_padding_add_SSLv23;
  RSA_padding_check_SSLv23 := Load_RSA_padding_check_SSLv23;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  RSA_padding_add_none := Load_RSA_padding_add_none;
  RSA_padding_check_none := Load_RSA_padding_check_none;
  RSA_padding_add_X931 := Load_RSA_padding_add_X931;
  RSA_padding_check_X931 := Load_RSA_padding_check_X931;
  RSA_X931_hash_id := Load_RSA_X931_hash_id;
  RSA_verify_PKCS1_PSS := Load_RSA_verify_PKCS1_PSS;
  RSA_padding_add_PKCS1_PSS := Load_RSA_padding_add_PKCS1_PSS;
  RSA_verify_PKCS1_PSS_mgf1 := Load_RSA_verify_PKCS1_PSS_mgf1;
  RSA_padding_add_PKCS1_PSS_mgf1 := Load_RSA_padding_add_PKCS1_PSS_mgf1;
  RSA_set_ex_data := Load_RSA_set_ex_data;
  RSA_get_ex_data := Load_RSA_get_ex_data;
  RSAPublicKey_dup := Load_RSAPublicKey_dup;
  RSAPrivateKey_dup := Load_RSAPrivateKey_dup;
  RSA_meth_new := Load_RSA_meth_new;
  RSA_meth_free := Load_RSA_meth_free;
  RSA_meth_dup := Load_RSA_meth_dup;
  RSA_meth_get0_name := Load_RSA_meth_get0_name;
  RSA_meth_set1_name := Load_RSA_meth_set1_name;
  RSA_meth_get_flags := Load_RSA_meth_get_flags;
  RSA_meth_set_flags := Load_RSA_meth_set_flags;
  RSA_meth_get0_app_data := Load_RSA_meth_get0_app_data;
  RSA_meth_set0_app_data := Load_RSA_meth_set0_app_data;
  RSA_meth_set_priv_dec := Load_RSA_meth_set_priv_dec;
  RSA_meth_set_mod_exp := Load_RSA_meth_set_mod_exp;
  RSA_meth_set_bn_mod_exp := Load_RSA_meth_set_bn_mod_exp;
  RSA_meth_set_init := Load_RSA_meth_set_init;
  RSA_meth_set_finish := Load_RSA_meth_set_finish;
  RSA_meth_set_sign := Load_RSA_meth_set_sign;
  RSA_meth_set_verify := Load_RSA_meth_set_verify;
  RSA_meth_set_keygen := Load_RSA_meth_set_keygen;
  RSA_meth_set_multi_prime_keygen := Load_RSA_meth_set_multi_prime_keygen;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
