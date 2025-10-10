(* This unit was generated from the source file dh.h2pas 
It should not be modified directly. All changes should be made to dh.h2pas
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


unit IdOpenSSLHeaders_dh;


interface

// Headers for OpenSSL 1.1.1
// dh.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_asn1;

const
  OPENSSL_DH_MAX_MODULUS_BITS      = 10000;
  OPENSSL_DH_FIPS_MIN_MODULUS_BITS =  1024;

  DH_FLAG_CACHE_MONT_P   =   $01;
  DH_FLAG_FIPS_METHOD    = $0400;
  DH_FLAG_NON_FIPS_ALLOW = $0400;

  DH_GENERATOR_2 = 2;
  DH_GENERATOR_5 = 5;

  DH_CHECK_P_NOT_PRIME         = $01;
  DH_CHECK_P_NOT_SAFE_PRIME    = $02;
  DH_UNABLE_TO_CHECK_GENERATOR = $04;
  DH_NOT_SUITABLE_GENERATOR    = $08;
  DH_CHECK_Q_NOT_PRIME         = $10;
  DH_CHECK_INVALID_Q_VALUE     = $20;
  DH_CHECK_INVALID_J_VALUE     = $40;
  DH_CHECK_PUBKEY_TOO_SMALL    = $01;
  DH_CHECK_PUBKEY_TOO_LARGE    = $02;
  DH_CHECK_PUBKEY_INVALID      = $04;
  DH_CHECK_P_NOT_STRONG_PRIME  = DH_CHECK_P_NOT_SAFE_PRIME;

  EVP_PKEY_DH_KDF_NONE  = 1;
  EVP_PKEY_DH_KDF_X9_42 = 2;

  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN    = (EVP_PKEY_ALG_CTRL + 1);
  EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR    = (EVP_PKEY_ALG_CTRL + 2);
  EVP_PKEY_CTRL_DH_RFC5114               = (EVP_PKEY_ALG_CTRL + 3);
  EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN = (EVP_PKEY_ALG_CTRL + 4);
  EVP_PKEY_CTRL_DH_PARAMGEN_TYPE         = (EVP_PKEY_ALG_CTRL + 5);
  EVP_PKEY_CTRL_DH_KDF_TYPE              = (EVP_PKEY_ALG_CTRL + 6);
  EVP_PKEY_CTRL_DH_KDF_MD                = (EVP_PKEY_ALG_CTRL + 7);
  EVP_PKEY_CTRL_GET_DH_KDF_MD            = (EVP_PKEY_ALG_CTRL + 8);
  EVP_PKEY_CTRL_DH_KDF_OUTLEN            = (EVP_PKEY_ALG_CTRL + 9);
  EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN        = (EVP_PKEY_ALG_CTRL + 10);
  EVP_PKEY_CTRL_DH_KDF_UKM               = (EVP_PKEY_ALG_CTRL + 11);
  EVP_PKEY_CTRL_GET_DH_KDF_UKM           = (EVP_PKEY_ALG_CTRL + 12);
  EVP_PKEY_CTRL_DH_KDF_OID               = (EVP_PKEY_ALG_CTRL + 13);
  EVP_PKEY_CTRL_GET_DH_KDF_OID           = (EVP_PKEY_ALG_CTRL + 14);
  EVP_PKEY_CTRL_DH_NID                   = (EVP_PKEY_ALG_CTRL + 15);
  EVP_PKEY_CTRL_DH_PAD                   = (EVP_PKEY_ALG_CTRL + 16);

type
  DH_meth_generate_key_cb = function(dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_compute_key_cb = function(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_bn_mod_exp_cb = function(
    const dh: PDH; r: PBIGNUM; const a: PBIGNUM;
    const p: PBIGNUM; const m: PBIGNUM;
    ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT cdecl;
  DH_meth_init_cb = function(dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_finish_cb = function(dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_generate_params_cb = function(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT cdecl;

{
  # define DH_CHECK_P_NOT_STRONG_PRIME     DH_CHECK_P_NOT_SAFE_PRIME

  # define d2i_DHparams_fp(fp,x) \
      (DH *)ASN1_d2i_fp((char *(*)())DH_new, \
                        (char *(*)())d2i_DHparams, \
                        (fp), \
                        (unsigned char **)(x))
  # define i2d_DHparams_fp(fp,x) \
      ASN1_i2d_fp(i2d_DHparams,(fp), (unsigned char *)(x))
  # define d2i_DHparams_bio(bp,x) \
      ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)
  # define i2d_DHparams_bio(bp,x) \
      ASN1_i2d_bio_of_const(DH,i2d_DHparams,bp,x)

  # define d2i_DHxparams_fp(fp,x) \
      (DH *)ASN1_d2i_fp((char *(*)())DH_new, \
                        (char *(*)())d2i_DHxparams, \
                        (fp), \
                        (unsigned char **)(x))
  # define i2d_DHxparams_fp(fp,x) \
      ASN1_i2d_fp(i2d_DHxparams,(fp), (unsigned char *)(x))
  # define d2i_DHxparams_bio(bp,x) \
      ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x)
  # define i2d_DHxparams_bio(bp,x) \
      ASN1_i2d_bio_of_const(DH, i2d_DHxparams, bp, x)
}

  

function d2i_DHparams_bio(bp: PBIO; x: PPDH): PDH;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM DHparams_dup}
{$EXTERNALSYM DH_OpenSSL}
{$EXTERNALSYM DH_set_default_method}
{$EXTERNALSYM DH_get_default_method}
{$EXTERNALSYM DH_set_method}
{$EXTERNALSYM DH_new_method}
{$EXTERNALSYM DH_new}
{$EXTERNALSYM DH_free}
{$EXTERNALSYM DH_up_ref}
{$EXTERNALSYM DH_bits}
{$EXTERNALSYM DH_size}
{$EXTERNALSYM DH_security_bits}
{$EXTERNALSYM DH_set_ex_data}
{$EXTERNALSYM DH_get_ex_data}
{$EXTERNALSYM DH_generate_parameters_ex}
{$EXTERNALSYM DH_check_params_ex}
{$EXTERNALSYM DH_check_ex}
{$EXTERNALSYM DH_check_pub_key_ex}
{$EXTERNALSYM DH_check_params}
{$EXTERNALSYM DH_check}
{$EXTERNALSYM DH_check_pub_key}
{$EXTERNALSYM DH_generate_key}
{$EXTERNALSYM DH_compute_key}
{$EXTERNALSYM DH_compute_key_padded}
{$EXTERNALSYM d2i_DHparams}
{$EXTERNALSYM i2d_DHparams}
{$EXTERNALSYM d2i_DHxparams}
{$EXTERNALSYM i2d_DHxparams}
{$EXTERNALSYM DHparams_print}
{$EXTERNALSYM DH_get_1024_160}
{$EXTERNALSYM DH_get_2048_224}
{$EXTERNALSYM DH_get_2048_256}
{$EXTERNALSYM DH_new_by_nid}
{$EXTERNALSYM DH_get_nid}
{$EXTERNALSYM DH_KDF_X9_42}
{$EXTERNALSYM DH_get0_pqg}
{$EXTERNALSYM DH_set0_pqg}
{$EXTERNALSYM DH_get0_key}
{$EXTERNALSYM DH_set0_key}
{$EXTERNALSYM DH_get0_p}
{$EXTERNALSYM DH_get0_q}
{$EXTERNALSYM DH_get0_g}
{$EXTERNALSYM DH_get0_priv_key}
{$EXTERNALSYM DH_get0_pub_key}
{$EXTERNALSYM DH_clear_flags}
{$EXTERNALSYM DH_test_flags}
{$EXTERNALSYM DH_set_flags}
{$EXTERNALSYM DH_get0_engine}
{$EXTERNALSYM DH_get_length}
{$EXTERNALSYM DH_set_length}
{$EXTERNALSYM DH_meth_new}
{$EXTERNALSYM DH_meth_free}
{$EXTERNALSYM DH_meth_dup}
{$EXTERNALSYM DH_meth_get0_name}
{$EXTERNALSYM DH_meth_set1_name}
{$EXTERNALSYM DH_meth_get_flags}
{$EXTERNALSYM DH_meth_set_flags}
{$EXTERNALSYM DH_meth_get0_app_data}
{$EXTERNALSYM DH_meth_set0_app_data}
{$EXTERNALSYM DH_meth_get_generate_key}
{$EXTERNALSYM DH_meth_set_generate_key}
{$EXTERNALSYM DH_meth_get_compute_key}
{$EXTERNALSYM DH_meth_set_compute_key}
{$EXTERNALSYM DH_meth_get_bn_mod_exp}
{$EXTERNALSYM DH_meth_set_bn_mod_exp}
{$EXTERNALSYM DH_meth_get_init}
{$EXTERNALSYM DH_meth_set_init}
{$EXTERNALSYM DH_meth_get_finish}
{$EXTERNALSYM DH_meth_set_finish}
{$EXTERNALSYM DH_meth_get_generate_params}
{$EXTERNALSYM DH_meth_set_generate_params}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function DHparams_dup(dh: PDH): PDH; cdecl; external CLibCrypto;
function DH_OpenSSL: PDH_Method; cdecl; external CLibCrypto;
procedure DH_set_default_method(const meth: PDH_Method); cdecl; external CLibCrypto;
function DH_get_default_method: PDH_Method; cdecl; external CLibCrypto;
function DH_set_method(dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_new_method(engine: PENGINE): PDH; cdecl; external CLibCrypto;
function DH_new: PDH; cdecl; external CLibCrypto;
procedure DH_free(dh: PDH); cdecl; external CLibCrypto;
function DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_bits(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_size(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_security_bits(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_params_ex(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_ex(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_params(const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check(const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DHparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl; external CLibCrypto;
function i2d_DHparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DHxparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl; external CLibCrypto;
function i2d_DHxparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DHparams_print(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_get_1024_160: PDH; cdecl; external CLibCrypto;
function DH_get_2048_224: PDH; cdecl; external CLibCrypto;
function DH_get_2048_256: PDH; cdecl; external CLibCrypto;
function DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl; external CLibCrypto;
function DH_get_nid(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_KDF_X9_42( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl; external CLibCrypto;
function DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl; external CLibCrypto;
function DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_get0_p(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_q(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_g(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_priv_key(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_pub_key(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
procedure DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DH_test_flags(const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DH_get0_engine(d: PDH): PENGINE; cdecl; external CLibCrypto;
function DH_get_length(const dh: PDH): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function DH_set_length(dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl; external CLibCrypto;
procedure DH_meth_free(dhm: PDH_Method); cdecl; external CLibCrypto;
function DH_meth_dup(const dhm: PDH_Method): PDH_Method; cdecl; external CLibCrypto;
function DH_meth_get0_name(const dhm: PDH_Method): PAnsiChar; cdecl; external CLibCrypto;
function DH_meth_set1_name(dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_flags(const dhm: PDH_Method): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_set_flags(const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get0_app_data(const dhm: PDH_Method): Pointer; cdecl; external CLibCrypto;
function DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl; external CLibCrypto;
function DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl; external CLibCrypto;
function DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl; external CLibCrypto;
function DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb; cdecl; external CLibCrypto;
function DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb; cdecl; external CLibCrypto;
function DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl; external CLibCrypto;
function DH_meth_set_generate_params(const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;




{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_DHparams_dup(dh: PDH): PDH; cdecl;
function Load_DH_OpenSSL: PDH_Method; cdecl;
procedure Load_DH_set_default_method(const meth: PDH_Method); cdecl;
function Load_DH_get_default_method: PDH_Method; cdecl;
function Load_DH_set_method(dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl;
function Load_DH_new_method(engine: PENGINE): PDH; cdecl;
function Load_DH_new: PDH; cdecl;
procedure Load_DH_free(dh: PDH); cdecl;
function Load_DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_bits(const dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_size(const dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_security_bits(const dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_DH_check_params_ex(const dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_check_ex(const dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_DH_check_params(const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_DH_check(const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_d2i_DHparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl;
function Load_i2d_DHparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_DHxparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl;
function Load_i2d_DHxparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_DHparams_print(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_get_1024_160: PDH; cdecl;
function Load_DH_get_2048_224: PDH; cdecl;
function Load_DH_get_2048_256: PDH; cdecl;
function Load_DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl;
function Load_DH_get_nid(const dh: PDH): TOpenSSL_C_INT; cdecl;
function Load_DH_KDF_X9_42( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
procedure Load_DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
function Load_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
procedure Load_DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
function Load_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_DH_get0_p(const dh: PDH): PBIGNUM; cdecl;
function Load_DH_get0_q(const dh: PDH): PBIGNUM; cdecl;
function Load_DH_get0_g(const dh: PDH): PBIGNUM; cdecl;
function Load_DH_get0_priv_key(const dh: PDH): PBIGNUM; cdecl;
function Load_DH_get0_pub_key(const dh: PDH): PBIGNUM; cdecl;
procedure Load_DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
function Load_DH_test_flags(const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
function Load_DH_get0_engine(d: PDH): PENGINE; cdecl;
function Load_DH_get_length(const dh: PDH): TOpenSSL_C_LONG; cdecl;
function Load_DH_set_length(dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl;
procedure Load_DH_meth_free(dhm: PDH_Method); cdecl;
function Load_DH_meth_dup(const dhm: PDH_Method): PDH_Method; cdecl;
function Load_DH_meth_get0_name(const dhm: PDH_Method): PAnsiChar; cdecl;
function Load_DH_meth_set1_name(dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_flags(const dhm: PDH_Method): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_set_flags(const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get0_app_data(const dhm: PDH_Method): Pointer; cdecl;
function Load_DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl;
function Load_DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl;
function Load_DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl;
function Load_DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb; cdecl;
function Load_DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb; cdecl;
function Load_DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl;
function Load_DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl;
function Load_DH_meth_set_generate_params(const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl;

var
  DHparams_dup: function (dh: PDH): PDH; cdecl = Load_DHparams_dup;
  DH_OpenSSL: function : PDH_Method; cdecl = Load_DH_OpenSSL;
  DH_set_default_method: procedure (const meth: PDH_Method); cdecl = Load_DH_set_default_method;
  DH_get_default_method: function : PDH_Method; cdecl = Load_DH_get_default_method;
  DH_set_method: function (dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl = Load_DH_set_method;
  DH_new_method: function (engine: PENGINE): PDH; cdecl = Load_DH_new_method;
  DH_new: function : PDH; cdecl = Load_DH_new;
  DH_free: procedure (dh: PDH); cdecl = Load_DH_free;
  DH_up_ref: function (dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_up_ref;
  DH_bits: function (const dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_bits;
  DH_size: function (const dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_size;
  DH_security_bits: function (const dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_security_bits;
  DH_set_ex_data: function (d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_DH_set_ex_data;
  DH_get_ex_data: function (d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_DH_get_ex_data;
  DH_generate_parameters_ex: function (dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_DH_generate_parameters_ex;
  DH_check_params_ex: function (const dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_check_params_ex;
  DH_check_ex: function (const dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_check_ex;
  DH_check_pub_key_ex: function (const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DH_check_pub_key_ex;
  DH_check_params: function (const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_check_params;
  DH_check: function (const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_check;
  DH_check_pub_key: function (const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_check_pub_key;
  DH_generate_key: function (dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_generate_key;
  DH_compute_key: function (key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_compute_key;
  DH_compute_key_padded: function (key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_compute_key_padded;
  d2i_DHparams: function (a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl = Load_d2i_DHparams;
  i2d_DHparams: function (const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DHparams;
  d2i_DHxparams: function (a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl = Load_d2i_DHxparams;
  i2d_DHxparams: function (const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DHxparams;
  DHparams_print: function (bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl = Load_DHparams_print;
  DH_get_1024_160: function : PDH; cdecl = Load_DH_get_1024_160;
  DH_get_2048_224: function : PDH; cdecl = Load_DH_get_2048_224;
  DH_get_2048_256: function : PDH; cdecl = Load_DH_get_2048_256;
  DH_new_by_nid: function (nid: TOpenSSL_C_INT): PDH; cdecl = Load_DH_new_by_nid;
  DH_get_nid: function (const dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_get_nid;
  DH_KDF_X9_42: function ( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_DH_KDF_X9_42;
  DH_get0_pqg: procedure (const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl = Load_DH_get0_pqg;
  DH_set0_pqg: function (dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DH_set0_pqg;
  DH_get0_key: procedure (const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl = Load_DH_get0_key;
  DH_set0_key: function (dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DH_set0_key;
  DH_get0_p: function (const dh: PDH): PBIGNUM; cdecl = Load_DH_get0_p;
  DH_get0_q: function (const dh: PDH): PBIGNUM; cdecl = Load_DH_get0_q;
  DH_get0_g: function (const dh: PDH): PBIGNUM; cdecl = Load_DH_get0_g;
  DH_get0_priv_key: function (const dh: PDH): PBIGNUM; cdecl = Load_DH_get0_priv_key;
  DH_get0_pub_key: function (const dh: PDH): PBIGNUM; cdecl = Load_DH_get0_pub_key;
  DH_clear_flags: procedure (dh: PDH; flags: TOpenSSL_C_INT); cdecl = Load_DH_clear_flags;
  DH_test_flags: function (const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_test_flags;
  DH_set_flags: procedure (dh: PDH; flags: TOpenSSL_C_INT); cdecl = Load_DH_set_flags;
  DH_get0_engine: function (d: PDH): PENGINE; cdecl = Load_DH_get0_engine;
  DH_get_length: function (const dh: PDH): TOpenSSL_C_LONG; cdecl = Load_DH_get_length;
  DH_set_length: function (dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_DH_set_length;
  DH_meth_new: function (const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl = Load_DH_meth_new;
  DH_meth_free: procedure (dhm: PDH_Method); cdecl = Load_DH_meth_free;
  DH_meth_dup: function (const dhm: PDH_Method): PDH_Method; cdecl = Load_DH_meth_dup;
  DH_meth_get0_name: function (const dhm: PDH_Method): PAnsiChar; cdecl = Load_DH_meth_get0_name;
  DH_meth_set1_name: function (dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_DH_meth_set1_name;
  DH_meth_get_flags: function (const dhm: PDH_Method): TOpenSSL_C_INT; cdecl = Load_DH_meth_get_flags;
  DH_meth_set_flags: function (const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_flags;
  DH_meth_get0_app_data: function (const dhm: PDH_Method): Pointer; cdecl = Load_DH_meth_get0_app_data;
  DH_meth_set0_app_data: function (const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl = Load_DH_meth_set0_app_data;
  DH_meth_get_generate_key: function (const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl = Load_DH_meth_get_generate_key;
  DH_meth_set_generate_key: function (const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_generate_key;
  DH_meth_get_compute_key: function (const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl = Load_DH_meth_get_compute_key;
  DH_meth_set_compute_key: function (const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_compute_key;
  DH_meth_get_bn_mod_exp: function (const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl = Load_DH_meth_get_bn_mod_exp;
  DH_meth_set_bn_mod_exp: function (const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_bn_mod_exp;
  DH_meth_get_init: function (const dhm: PDH_Method): DH_meth_init_cb; cdecl = Load_DH_meth_get_init;
  DH_meth_set_init: function (const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_init;
  DH_meth_get_finish: function (const dhm: PDH_Method): DH_meth_finish_cb; cdecl = Load_DH_meth_get_finish;
  DH_meth_set_finish: function (const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_finish;
  DH_meth_get_generate_params: function (const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl = Load_DH_meth_get_generate_params;
  DH_meth_set_generate_params: function (const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_generate_params;



{$ENDIF}
const
  DH_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_security_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_params_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_pub_key_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_new_by_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_pqg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set0_pqg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set0_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_p_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_q_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_g_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_priv_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_pub_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_clear_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_test_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get0_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set1_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get0_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set0_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_generate_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_generate_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_bn_mod_exp_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_bn_mod_exp_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_finish_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_finish_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_generate_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_generate_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation

uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;


function d2i_DHparams_bio(bp: PBIO; x: PPDH): PDH;
begin
  Result := PDH(ASN1_d2i_bio(pxnew(@DH_new), pd2i_of_void(@d2i_DHparams), bp, PPointer(x)));
end;




{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_DHparams_dup(dh: PDH): PDH; cdecl;
begin
  DHparams_dup := LoadLibCryptoFunction('DHparams_dup');
  if not assigned(DHparams_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_dup');
  Result := DHparams_dup(dh);
end;

function Load_DH_OpenSSL: PDH_Method; cdecl;
begin
  DH_OpenSSL := LoadLibCryptoFunction('DH_OpenSSL');
  if not assigned(DH_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_OpenSSL');
  Result := DH_OpenSSL();
end;

procedure Load_DH_set_default_method(const meth: PDH_Method); cdecl;
begin
  DH_set_default_method := LoadLibCryptoFunction('DH_set_default_method');
  if not assigned(DH_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_default_method');
  DH_set_default_method(meth);
end;

function Load_DH_get_default_method: PDH_Method; cdecl;
begin
  DH_get_default_method := LoadLibCryptoFunction('DH_get_default_method');
  if not assigned(DH_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_default_method');
  Result := DH_get_default_method();
end;

function Load_DH_set_method(dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl;
begin
  DH_set_method := LoadLibCryptoFunction('DH_set_method');
  if not assigned(DH_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_method');
  Result := DH_set_method(dh,meth);
end;

function Load_DH_new_method(engine: PENGINE): PDH; cdecl;
begin
  DH_new_method := LoadLibCryptoFunction('DH_new_method');
  if not assigned(DH_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new_method');
  Result := DH_new_method(engine);
end;

function Load_DH_new: PDH; cdecl;
begin
  DH_new := LoadLibCryptoFunction('DH_new');
  if not assigned(DH_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new');
  Result := DH_new();
end;

procedure Load_DH_free(dh: PDH); cdecl;
begin
  DH_free := LoadLibCryptoFunction('DH_free');
  if not assigned(DH_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_free');
  DH_free(dh);
end;

function Load_DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_up_ref := LoadLibCryptoFunction('DH_up_ref');
  if not assigned(DH_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_up_ref');
  Result := DH_up_ref(dh);
end;

function Load_DH_bits(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_bits := LoadLibCryptoFunction('DH_bits');
  if not assigned(DH_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_bits');
  Result := DH_bits(dh);
end;

function Load_DH_size(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_size := LoadLibCryptoFunction('DH_size');
  if not assigned(DH_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_size');
  Result := DH_size(dh);
end;

function Load_DH_security_bits(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_security_bits := LoadLibCryptoFunction('DH_security_bits');
  if not assigned(DH_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_security_bits');
  Result := DH_security_bits(dh);
end;

function Load_DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  DH_set_ex_data := LoadLibCryptoFunction('DH_set_ex_data');
  if not assigned(DH_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_ex_data');
  Result := DH_set_ex_data(d,idx,arg);
end;

function Load_DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  DH_get_ex_data := LoadLibCryptoFunction('DH_get_ex_data');
  if not assigned(DH_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_ex_data');
  Result := DH_get_ex_data(d,idx);
end;

function Load_DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  DH_generate_parameters_ex := LoadLibCryptoFunction('DH_generate_parameters_ex');
  if not assigned(DH_generate_parameters_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_parameters_ex');
  Result := DH_generate_parameters_ex(dh,prime_len,generator,cb);
end;

function Load_DH_check_params_ex(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_check_params_ex := LoadLibCryptoFunction('DH_check_params_ex');
  if not assigned(DH_check_params_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_params_ex');
  Result := DH_check_params_ex(dh);
end;

function Load_DH_check_ex(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_check_ex := LoadLibCryptoFunction('DH_check_ex');
  if not assigned(DH_check_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_ex');
  Result := DH_check_ex(dh);
end;

function Load_DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DH_check_pub_key_ex := LoadLibCryptoFunction('DH_check_pub_key_ex');
  if not assigned(DH_check_pub_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_pub_key_ex');
  Result := DH_check_pub_key_ex(dh,pub_key);
end;

function Load_DH_check_params(const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_check_params := LoadLibCryptoFunction('DH_check_params');
  if not assigned(DH_check_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_params');
  Result := DH_check_params(dh,ret);
end;

function Load_DH_check(const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_check := LoadLibCryptoFunction('DH_check');
  if not assigned(DH_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check');
  Result := DH_check(dh,codes);
end;

function Load_DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_check_pub_key := LoadLibCryptoFunction('DH_check_pub_key');
  if not assigned(DH_check_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_pub_key');
  Result := DH_check_pub_key(dh,pub_key,codes);
end;

function Load_DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_generate_key := LoadLibCryptoFunction('DH_generate_key');
  if not assigned(DH_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_key');
  Result := DH_generate_key(dh);
end;

function Load_DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_compute_key := LoadLibCryptoFunction('DH_compute_key');
  if not assigned(DH_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_compute_key');
  Result := DH_compute_key(key,pub_key,dh);
end;

function Load_DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_compute_key_padded := LoadLibCryptoFunction('DH_compute_key_padded');
  if not assigned(DH_compute_key_padded) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_compute_key_padded');
  Result := DH_compute_key_padded(key,pub_key,dh);
end;

function Load_d2i_DHparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl;
begin
  d2i_DHparams := LoadLibCryptoFunction('d2i_DHparams');
  if not assigned(d2i_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DHparams');
  Result := d2i_DHparams(a,pp,length);
end;

function Load_i2d_DHparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DHparams := LoadLibCryptoFunction('i2d_DHparams');
  if not assigned(i2d_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DHparams');
  Result := i2d_DHparams(a,pp);
end;

function Load_d2i_DHxparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl;
begin
  d2i_DHxparams := LoadLibCryptoFunction('d2i_DHxparams');
  if not assigned(d2i_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DHxparams');
  Result := d2i_DHxparams(a,pp,length);
end;

function Load_i2d_DHxparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DHxparams := LoadLibCryptoFunction('i2d_DHxparams');
  if not assigned(i2d_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DHxparams');
  Result := i2d_DHxparams(a,pp);
end;

function Load_DHparams_print(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
begin
  DHparams_print := LoadLibCryptoFunction('DHparams_print');
  if not assigned(DHparams_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_print');
  Result := DHparams_print(bp,x);
end;

function Load_DH_get_1024_160: PDH; cdecl;
begin
  DH_get_1024_160 := LoadLibCryptoFunction('DH_get_1024_160');
  if not assigned(DH_get_1024_160) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_1024_160');
  Result := DH_get_1024_160();
end;

function Load_DH_get_2048_224: PDH; cdecl;
begin
  DH_get_2048_224 := LoadLibCryptoFunction('DH_get_2048_224');
  if not assigned(DH_get_2048_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_2048_224');
  Result := DH_get_2048_224();
end;

function Load_DH_get_2048_256: PDH; cdecl;
begin
  DH_get_2048_256 := LoadLibCryptoFunction('DH_get_2048_256');
  if not assigned(DH_get_2048_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_2048_256');
  Result := DH_get_2048_256();
end;

function Load_DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl;
begin
  DH_new_by_nid := LoadLibCryptoFunction('DH_new_by_nid');
  if not assigned(DH_new_by_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new_by_nid');
  Result := DH_new_by_nid(nid);
end;

function Load_DH_get_nid(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_get_nid := LoadLibCryptoFunction('DH_get_nid');
  if not assigned(DH_get_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_nid');
  Result := DH_get_nid(dh);
end;

function Load_DH_KDF_X9_42( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  DH_KDF_X9_42 := LoadLibCryptoFunction('DH_KDF_X9_42');
  if not assigned(DH_KDF_X9_42) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_KDF_X9_42');
  Result := DH_KDF_X9_42(out_,outlen,Z,Zlen,key_oid,ukm,ukmlen,md);
end;

procedure Load_DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
begin
  DH_get0_pqg := LoadLibCryptoFunction('DH_get0_pqg');
  if not assigned(DH_get0_pqg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_pqg');
  DH_get0_pqg(dh,p,q,g);
end;

function Load_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DH_set0_pqg := LoadLibCryptoFunction('DH_set0_pqg');
  if not assigned(DH_set0_pqg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set0_pqg');
  Result := DH_set0_pqg(dh,p,q,g);
end;

procedure Load_DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
begin
  DH_get0_key := LoadLibCryptoFunction('DH_get0_key');
  if not assigned(DH_get0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_key');
  DH_get0_key(dh,pub_key,priv_key);
end;

function Load_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DH_set0_key := LoadLibCryptoFunction('DH_set0_key');
  if not assigned(DH_set0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set0_key');
  Result := DH_set0_key(dh,pub_key,priv_key);
end;

function Load_DH_get0_p(const dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_p := LoadLibCryptoFunction('DH_get0_p');
  if not assigned(DH_get0_p) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_p');
  Result := DH_get0_p(dh);
end;

function Load_DH_get0_q(const dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_q := LoadLibCryptoFunction('DH_get0_q');
  if not assigned(DH_get0_q) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_q');
  Result := DH_get0_q(dh);
end;

function Load_DH_get0_g(const dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_g := LoadLibCryptoFunction('DH_get0_g');
  if not assigned(DH_get0_g) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_g');
  Result := DH_get0_g(dh);
end;

function Load_DH_get0_priv_key(const dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_priv_key := LoadLibCryptoFunction('DH_get0_priv_key');
  if not assigned(DH_get0_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_priv_key');
  Result := DH_get0_priv_key(dh);
end;

function Load_DH_get0_pub_key(const dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_pub_key := LoadLibCryptoFunction('DH_get0_pub_key');
  if not assigned(DH_get0_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_pub_key');
  Result := DH_get0_pub_key(dh);
end;

procedure Load_DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
begin
  DH_clear_flags := LoadLibCryptoFunction('DH_clear_flags');
  if not assigned(DH_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_clear_flags');
  DH_clear_flags(dh,flags);
end;

function Load_DH_test_flags(const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_test_flags := LoadLibCryptoFunction('DH_test_flags');
  if not assigned(DH_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_test_flags');
  Result := DH_test_flags(dh,flags);
end;

procedure Load_DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
begin
  DH_set_flags := LoadLibCryptoFunction('DH_set_flags');
  if not assigned(DH_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_flags');
  DH_set_flags(dh,flags);
end;

function Load_DH_get0_engine(d: PDH): PENGINE; cdecl;
begin
  DH_get0_engine := LoadLibCryptoFunction('DH_get0_engine');
  if not assigned(DH_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_engine');
  Result := DH_get0_engine(d);
end;

function Load_DH_get_length(const dh: PDH): TOpenSSL_C_LONG; cdecl;
begin
  DH_get_length := LoadLibCryptoFunction('DH_get_length');
  if not assigned(DH_get_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_length');
  Result := DH_get_length(dh);
end;

function Load_DH_set_length(dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  DH_set_length := LoadLibCryptoFunction('DH_set_length');
  if not assigned(DH_set_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_length');
  Result := DH_set_length(dh,length);
end;

function Load_DH_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl;
begin
  DH_meth_new := LoadLibCryptoFunction('DH_meth_new');
  if not assigned(DH_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_new');
  Result := DH_meth_new(name,flags);
end;

procedure Load_DH_meth_free(dhm: PDH_Method); cdecl;
begin
  DH_meth_free := LoadLibCryptoFunction('DH_meth_free');
  if not assigned(DH_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_free');
  DH_meth_free(dhm);
end;

function Load_DH_meth_dup(const dhm: PDH_Method): PDH_Method; cdecl;
begin
  DH_meth_dup := LoadLibCryptoFunction('DH_meth_dup');
  if not assigned(DH_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_dup');
  Result := DH_meth_dup(dhm);
end;

function Load_DH_meth_get0_name(const dhm: PDH_Method): PAnsiChar; cdecl;
begin
  DH_meth_get0_name := LoadLibCryptoFunction('DH_meth_get0_name');
  if not assigned(DH_meth_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get0_name');
  Result := DH_meth_get0_name(dhm);
end;

function Load_DH_meth_set1_name(dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set1_name := LoadLibCryptoFunction('DH_meth_set1_name');
  if not assigned(DH_meth_set1_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set1_name');
  Result := DH_meth_set1_name(dhm,name);
end;

function Load_DH_meth_get_flags(const dhm: PDH_Method): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_get_flags := LoadLibCryptoFunction('DH_meth_get_flags');
  if not assigned(DH_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_flags');
  Result := DH_meth_get_flags(dhm);
end;

function Load_DH_meth_set_flags(const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_flags := LoadLibCryptoFunction('DH_meth_set_flags');
  if not assigned(DH_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_flags');
  Result := DH_meth_set_flags(dhm,flags);
end;

function Load_DH_meth_get0_app_data(const dhm: PDH_Method): Pointer; cdecl;
begin
  DH_meth_get0_app_data := LoadLibCryptoFunction('DH_meth_get0_app_data');
  if not assigned(DH_meth_get0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get0_app_data');
  Result := DH_meth_get0_app_data(dhm);
end;

function Load_DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set0_app_data := LoadLibCryptoFunction('DH_meth_set0_app_data');
  if not assigned(DH_meth_set0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set0_app_data');
  Result := DH_meth_set0_app_data(dhm,app_data);
end;

function Load_DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl;
begin
  DH_meth_get_generate_key := LoadLibCryptoFunction('DH_meth_get_generate_key');
  if not assigned(DH_meth_get_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_generate_key');
  Result := DH_meth_get_generate_key(dhm);
end;

function Load_DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_generate_key := LoadLibCryptoFunction('DH_meth_set_generate_key');
  if not assigned(DH_meth_set_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_generate_key');
  Result := DH_meth_set_generate_key(dhm,generate_key);
end;

function Load_DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl;
begin
  DH_meth_get_compute_key := LoadLibCryptoFunction('DH_meth_get_compute_key');
  if not assigned(DH_meth_get_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_compute_key');
  Result := DH_meth_get_compute_key(dhm);
end;

function Load_DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_compute_key := LoadLibCryptoFunction('DH_meth_set_compute_key');
  if not assigned(DH_meth_set_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_compute_key');
  Result := DH_meth_set_compute_key(dhm,compute_key);
end;

function Load_DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl;
begin
  DH_meth_get_bn_mod_exp := LoadLibCryptoFunction('DH_meth_get_bn_mod_exp');
  if not assigned(DH_meth_get_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_bn_mod_exp');
  Result := DH_meth_get_bn_mod_exp(dhm);
end;

function Load_DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_bn_mod_exp := LoadLibCryptoFunction('DH_meth_set_bn_mod_exp');
  if not assigned(DH_meth_set_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_bn_mod_exp');
  Result := DH_meth_set_bn_mod_exp(dhm,bn_mod_expr);
end;

function Load_DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb; cdecl;
begin
  DH_meth_get_init := LoadLibCryptoFunction('DH_meth_get_init');
  if not assigned(DH_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_init');
  Result := DH_meth_get_init(dhm);
end;

function Load_DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_init := LoadLibCryptoFunction('DH_meth_set_init');
  if not assigned(DH_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_init');
  Result := DH_meth_set_init(dhm,init);
end;

function Load_DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb; cdecl;
begin
  DH_meth_get_finish := LoadLibCryptoFunction('DH_meth_get_finish');
  if not assigned(DH_meth_get_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_finish');
  Result := DH_meth_get_finish(dhm);
end;

function Load_DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_finish := LoadLibCryptoFunction('DH_meth_set_finish');
  if not assigned(DH_meth_set_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_finish');
  Result := DH_meth_set_finish(dhm,finish);
end;

function Load_DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl;
begin
  DH_meth_get_generate_params := LoadLibCryptoFunction('DH_meth_get_generate_params');
  if not assigned(DH_meth_get_generate_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_generate_params');
  Result := DH_meth_get_generate_params(dhm);
end;

function Load_DH_meth_set_generate_params(const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_generate_params := LoadLibCryptoFunction('DH_meth_set_generate_params');
  if not assigned(DH_meth_set_generate_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_generate_params');
  Result := DH_meth_set_generate_params(dhm,generate_params);
end;


procedure UnLoad;
begin
  DHparams_dup := Load_DHparams_dup;
  DH_OpenSSL := Load_DH_OpenSSL;
  DH_set_default_method := Load_DH_set_default_method;
  DH_get_default_method := Load_DH_get_default_method;
  DH_set_method := Load_DH_set_method;
  DH_new_method := Load_DH_new_method;
  DH_new := Load_DH_new;
  DH_free := Load_DH_free;
  DH_up_ref := Load_DH_up_ref;
  DH_bits := Load_DH_bits;
  DH_size := Load_DH_size;
  DH_security_bits := Load_DH_security_bits;
  DH_set_ex_data := Load_DH_set_ex_data;
  DH_get_ex_data := Load_DH_get_ex_data;
  DH_generate_parameters_ex := Load_DH_generate_parameters_ex;
  DH_check_params_ex := Load_DH_check_params_ex;
  DH_check_ex := Load_DH_check_ex;
  DH_check_pub_key_ex := Load_DH_check_pub_key_ex;
  DH_check_params := Load_DH_check_params;
  DH_check := Load_DH_check;
  DH_check_pub_key := Load_DH_check_pub_key;
  DH_generate_key := Load_DH_generate_key;
  DH_compute_key := Load_DH_compute_key;
  DH_compute_key_padded := Load_DH_compute_key_padded;
  d2i_DHparams := Load_d2i_DHparams;
  i2d_DHparams := Load_i2d_DHparams;
  d2i_DHxparams := Load_d2i_DHxparams;
  i2d_DHxparams := Load_i2d_DHxparams;
  DHparams_print := Load_DHparams_print;
  DH_get_1024_160 := Load_DH_get_1024_160;
  DH_get_2048_224 := Load_DH_get_2048_224;
  DH_get_2048_256 := Load_DH_get_2048_256;
  DH_new_by_nid := Load_DH_new_by_nid;
  DH_get_nid := Load_DH_get_nid;
  DH_KDF_X9_42 := Load_DH_KDF_X9_42;
  DH_get0_pqg := Load_DH_get0_pqg;
  DH_set0_pqg := Load_DH_set0_pqg;
  DH_get0_key := Load_DH_get0_key;
  DH_set0_key := Load_DH_set0_key;
  DH_get0_p := Load_DH_get0_p;
  DH_get0_q := Load_DH_get0_q;
  DH_get0_g := Load_DH_get0_g;
  DH_get0_priv_key := Load_DH_get0_priv_key;
  DH_get0_pub_key := Load_DH_get0_pub_key;
  DH_clear_flags := Load_DH_clear_flags;
  DH_test_flags := Load_DH_test_flags;
  DH_set_flags := Load_DH_set_flags;
  DH_get0_engine := Load_DH_get0_engine;
  DH_get_length := Load_DH_get_length;
  DH_set_length := Load_DH_set_length;
  DH_meth_new := Load_DH_meth_new;
  DH_meth_free := Load_DH_meth_free;
  DH_meth_dup := Load_DH_meth_dup;
  DH_meth_get0_name := Load_DH_meth_get0_name;
  DH_meth_set1_name := Load_DH_meth_set1_name;
  DH_meth_get_flags := Load_DH_meth_get_flags;
  DH_meth_set_flags := Load_DH_meth_set_flags;
  DH_meth_get0_app_data := Load_DH_meth_get0_app_data;
  DH_meth_set0_app_data := Load_DH_meth_set0_app_data;
  DH_meth_get_generate_key := Load_DH_meth_get_generate_key;
  DH_meth_set_generate_key := Load_DH_meth_set_generate_key;
  DH_meth_get_compute_key := Load_DH_meth_get_compute_key;
  DH_meth_set_compute_key := Load_DH_meth_set_compute_key;
  DH_meth_get_bn_mod_exp := Load_DH_meth_get_bn_mod_exp;
  DH_meth_set_bn_mod_exp := Load_DH_meth_set_bn_mod_exp;
  DH_meth_get_init := Load_DH_meth_get_init;
  DH_meth_set_init := Load_DH_meth_set_init;
  DH_meth_get_finish := Load_DH_meth_get_finish;
  DH_meth_set_finish := Load_DH_meth_set_finish;
  DH_meth_get_generate_params := Load_DH_meth_get_generate_params;
  DH_meth_set_generate_params := Load_DH_meth_set_generate_params;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
