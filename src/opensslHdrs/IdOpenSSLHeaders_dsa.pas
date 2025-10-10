(* This unit was generated from the source file dsa.h2pas 
It should not be modified directly. All changes should be made to dsa.h2pas
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


unit IdOpenSSLHeaders_dsa;


interface

// Headers for OpenSSL 1.1.1
// dsa.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_evp;

const
  OPENSSL_DSA_MAX_MODULUS_BITS = 10000;
  OPENSSL_DSA_FIPS_MIN_MODULUS_BITS = 1024;
  DSA_FLAG_CACHE_MONT_P = $01;
  DSA_FLAG_NO_EXP_CONSTTIME = $00;
  DSA_FLAG_FIPS_METHOD = $0400;
  DSA_FLAG_NON_FIPS_ALLOW = $0400;
  DSA_FLAG_FIPS_CHECKED = $0800;

  DSS_prime_checks = 64;

  EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = EVP_PKEY_ALG_CTRL + 1;
  EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = EVP_PKEY_ALG_CTRL + 2;
  EVP_PKEY_CTRL_DSA_PARAMGEN_MD = EVP_PKEY_ALG_CTRL + 3;

type
  DSA_SIG = type Pointer; // DSA_SIG_st
  PDSA_SIG = ^DSA_SIG;
  PPDSA_SIG = ^PDSA_SIG;

  DSA_meth_sign_cb = function (const v1: PByte; v2: TOpenSSL_C_INT; v3: PDSA): PDSA_SIG cdecl;
  DSA_meth_sign_setup_cb = function (v1: PDSA; v2: PBN_CTX;
    v3: PPBIGNUM; v4: PPBIGNUM): TOpenSSL_C_INT cdecl;
  DSA_meth_verify_cb = function (const v1: PByte; v2: TOpenSSL_C_INT;
    v3: PDSA_SIG; v4: PDSA): TOpenSSL_C_INT cdecl;
  DSA_meth_mod_exp_cb = function (v1: PDSA; v2: PBIGNUM;
    const v3: PBIGNUM; const v4: PBIGNUM; const v5: PBIGNUM; const v6: PBIGNUM;
    const v7: PBIGNUM; v8: PBN_CTX; v9: PBN_MONT_CTX): TOpenSSL_C_INT cdecl;
  DSA_meth_bn_mod_exp_cb = function (v1: PDSA; v2: PBIGNUM;
    const v3: PBIGNUM; const v4: PBIGNUM; const v5: PBIGNUM; v6: PBN_CTX; v7: PBN_MONT_CTX): TOpenSSL_C_INT cdecl;
  DSA_meth_init_cb = function(v1: PDSA): TOpenSSL_C_INT cdecl;
  DSA_meth_finish_cb = function (v1: PDSA): TOpenSSL_C_INT cdecl;
  DSA_meth_paramgen_cb = function (v1: PDSA; v2: TOpenSSL_C_INT;
    const v3: PByte; v4: TOpenSSL_C_INT; v5: POpenSSL_C_INT; v6: POpenSSL_C_ULONG; v7: PBN_GENCB): TOpenSSL_C_INT cdecl;
  DSA_meth_keygen_cb = function (v1: PDSA): TOpenSSL_C_INT cdecl;

//# define d2i_DSAparams_fp(fp,x) (DSA *)ASN1_d2i_fp((char *(*)())DSA_new, \
//                (char *(*)())d2i_DSAparams,(fp),(unsigned char **)(x))
//# define i2d_DSAparams_fp(fp,x) ASN1_i2d_fp(i2d_DSAparams,(fp), \
//                (unsigned char *)(x))
//# define d2i_DSAparams_bio(bp,x) ASN1_d2i_bio_of(DSA,DSA_new,d2i_DSAparams,bp,x)
//# define i2d_DSAparams_bio(bp,x) ASN1_i2d_bio_of_const(DSA,i2d_DSAparams,bp,x)

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM DSAparams_dup}
{$EXTERNALSYM DSA_SIG_new}
{$EXTERNALSYM DSA_SIG_free}
{$EXTERNALSYM i2d_DSA_SIG}
{$EXTERNALSYM d2i_DSA_SIG}
{$EXTERNALSYM DSA_SIG_get0}
{$EXTERNALSYM DSA_SIG_set0}
{$EXTERNALSYM DSA_do_sign}
{$EXTERNALSYM DSA_do_verify}
{$EXTERNALSYM DSA_OpenSSL}
{$EXTERNALSYM DSA_set_default_method}
{$EXTERNALSYM DSA_get_default_method}
{$EXTERNALSYM DSA_set_method}
{$EXTERNALSYM DSA_get_method}
{$EXTERNALSYM DSA_new}
{$EXTERNALSYM DSA_new_method}
{$EXTERNALSYM DSA_free}
{$EXTERNALSYM DSA_up_ref}
{$EXTERNALSYM DSA_size}
{$EXTERNALSYM DSA_bits}
{$EXTERNALSYM DSA_security_bits}
{$EXTERNALSYM DSA_sign}
{$EXTERNALSYM DSA_verify}
{$EXTERNALSYM DSA_set_ex_data}
{$EXTERNALSYM DSA_get_ex_data}
{$EXTERNALSYM d2i_DSAPublicKey}
{$EXTERNALSYM d2i_DSAPrivateKey}
{$EXTERNALSYM d2i_DSAparams}
{$EXTERNALSYM DSA_generate_parameters_ex}
{$EXTERNALSYM DSA_generate_key}
{$EXTERNALSYM i2d_DSAPublicKey}
{$EXTERNALSYM i2d_DSAPrivateKey}
{$EXTERNALSYM i2d_DSAparams}
{$EXTERNALSYM DSAparams_print}
{$EXTERNALSYM DSA_print}
{$EXTERNALSYM DSA_dup_DH}
{$EXTERNALSYM DSA_get0_pqg}
{$EXTERNALSYM DSA_set0_pqg}
{$EXTERNALSYM DSA_get0_key}
{$EXTERNALSYM DSA_set0_key}
{$EXTERNALSYM DSA_get0_p}
{$EXTERNALSYM DSA_get0_q}
{$EXTERNALSYM DSA_get0_g}
{$EXTERNALSYM DSA_get0_pub_key}
{$EXTERNALSYM DSA_get0_priv_key}
{$EXTERNALSYM DSA_clear_flags}
{$EXTERNALSYM DSA_test_flags}
{$EXTERNALSYM DSA_set_flags}
{$EXTERNALSYM DSA_get0_engine}
{$EXTERNALSYM DSA_meth_new}
{$EXTERNALSYM DSA_meth_free}
{$EXTERNALSYM DSA_meth_dup}
{$EXTERNALSYM DSA_meth_get0_name}
{$EXTERNALSYM DSA_meth_set1_name}
{$EXTERNALSYM DSA_meth_get_flags}
{$EXTERNALSYM DSA_meth_set_flags}
{$EXTERNALSYM DSA_meth_get0_app_data}
{$EXTERNALSYM DSA_meth_set0_app_data}
{$EXTERNALSYM DSA_meth_get_sign}
{$EXTERNALSYM DSA_meth_set_sign}
{$EXTERNALSYM DSA_meth_get_sign_setup}
{$EXTERNALSYM DSA_meth_set_sign_setup}
{$EXTERNALSYM DSA_meth_get_verify}
{$EXTERNALSYM DSA_meth_set_verify}
{$EXTERNALSYM DSA_meth_get_mod_exp}
{$EXTERNALSYM DSA_meth_set_mod_exp}
{$EXTERNALSYM DSA_meth_get_bn_mod_exp}
{$EXTERNALSYM DSA_meth_set_bn_mod_exp}
{$EXTERNALSYM DSA_meth_get_init}
{$EXTERNALSYM DSA_meth_set_init}
{$EXTERNALSYM DSA_meth_get_finish}
{$EXTERNALSYM DSA_meth_set_finish}
{$EXTERNALSYM DSA_meth_get_paramgen}
{$EXTERNALSYM DSA_meth_set_paramgen}
{$EXTERNALSYM DSA_meth_get_keygen}
{$EXTERNALSYM DSA_meth_set_keygen}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function DSAparams_dup(x: PDSA): PDSA; cdecl; external CLibCrypto;
function DSA_SIG_new: PDSA_SIG; cdecl; external CLibCrypto;
procedure DSA_SIG_free(a: PDSA_SIG); cdecl; external CLibCrypto;
function i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl; external CLibCrypto;
procedure DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl; external CLibCrypto;
function DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_do_sign(const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl; external CLibCrypto;
function DSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_OpenSSL: PDSA_METHOD; cdecl; external CLibCrypto;
procedure DSA_set_default_method(const v1: PDSA_METHOD); cdecl; external CLibCrypto;
function DSA_get_default_method: PDSA_METHOD; cdecl; external CLibCrypto;
function DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_get_method(d: PDSA): PDSA_METHOD; cdecl; external CLibCrypto;
function DSA_new: PDSA; cdecl; external CLibCrypto;
function DSA_new_method(engine: PENGINE): PDSA; cdecl; external CLibCrypto;
procedure DSA_free(r: PDSA); cdecl; external CLibCrypto;
function DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_size(const v1: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_bits(const d: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_security_bits(const d: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function d2i_DSAparams(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_DSAparams(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSAparams_print(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_print(bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_dup_DH(const r: PDSA): PDH; cdecl; external CLibCrypto;
procedure DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl; external CLibCrypto;
function DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl; external CLibCrypto;
function DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_get0_p(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_q(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_g(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_pub_key(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_priv_key(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
procedure DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DSA_test_flags(const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DSA_get0_engine(d: PDSA): PENGINE; cdecl; external CLibCrypto;
function DSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl; external CLibCrypto;
procedure DSA_meth_free(dsam: PDSA_METHOD); cdecl; external CLibCrypto;
function DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD; cdecl; external CLibCrypto;
function DSA_meth_get0_name(const dsam: PDSA_METHOD): PAnsiChar; cdecl; external CLibCrypto;
function DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_flags(const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer; cdecl; external CLibCrypto;
function DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl; external CLibCrypto;
function DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl; external CLibCrypto;
function DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl; external CLibCrypto;
function DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl; external CLibCrypto;
function DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl; external CLibCrypto;
function DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl; external CLibCrypto;
function DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl; external CLibCrypto;
function DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl; external CLibCrypto;
function DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl; external CLibCrypto;
function DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_DSAparams_dup(x: PDSA): PDSA; cdecl;
function Load_DSA_SIG_new: PDSA_SIG; cdecl;
procedure Load_DSA_SIG_free(a: PDSA_SIG); cdecl;
function Load_i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl;
procedure Load_DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
function Load_DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_DSA_do_sign(const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl;
function Load_DSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_OpenSSL: PDSA_METHOD; cdecl;
procedure Load_DSA_set_default_method(const v1: PDSA_METHOD); cdecl;
function Load_DSA_get_default_method: PDSA_METHOD; cdecl;
function Load_DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
function Load_DSA_get_method(d: PDSA): PDSA_METHOD; cdecl;
function Load_DSA_new: PDSA; cdecl;
function Load_DSA_new_method(engine: PENGINE): PDSA; cdecl;
procedure Load_DSA_free(r: PDSA); cdecl;
function Load_DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_size(const v1: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_bits(const d: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_security_bits(const d: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
function Load_d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
function Load_d2i_DSAparams(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
function Load_DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl;
function Load_i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_i2d_DSAparams(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_DSAparams_print(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl;
function Load_DSA_print(bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_DSA_dup_DH(const r: PDSA): PDH; cdecl;
procedure Load_DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
function Load_DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
procedure Load_DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
function Load_DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_DSA_get0_p(const d: PDSA): PBIGNUM; cdecl;
function Load_DSA_get0_q(const d: PDSA): PBIGNUM; cdecl;
function Load_DSA_get0_g(const d: PDSA): PBIGNUM; cdecl;
function Load_DSA_get0_pub_key(const d: PDSA): PBIGNUM; cdecl;
function Load_DSA_get0_priv_key(const d: PDSA): PBIGNUM; cdecl;
procedure Load_DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
function Load_DSA_test_flags(const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
function Load_DSA_get0_engine(d: PDSA): PENGINE; cdecl;
function Load_DSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl;
procedure Load_DSA_meth_free(dsam: PDSA_METHOD); cdecl;
function Load_DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD; cdecl;
function Load_DSA_meth_get0_name(const dsam: PDSA_METHOD): PAnsiChar; cdecl;
function Load_DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_flags(const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer; cdecl;
function Load_DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl;
function Load_DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl;
function Load_DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl;
function Load_DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl;
function Load_DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl;
function Load_DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl;
function Load_DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl;
function Load_DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl;
function Load_DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl;
function Load_DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl;
function Load_DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl;

var
  DSAparams_dup: function (x: PDSA): PDSA; cdecl = Load_DSAparams_dup;
  DSA_SIG_new: function : PDSA_SIG; cdecl = Load_DSA_SIG_new;
  DSA_SIG_free: procedure (a: PDSA_SIG); cdecl = Load_DSA_SIG_free;
  i2d_DSA_SIG: function (const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DSA_SIG;
  d2i_DSA_SIG: function (v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl = Load_d2i_DSA_SIG;
  DSA_SIG_get0: procedure (const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl = Load_DSA_SIG_get0;
  DSA_SIG_set0: function (sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_SIG_set0;
  DSA_do_sign: function (const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl = Load_DSA_do_sign;
  DSA_do_verify: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_do_verify;
  DSA_OpenSSL: function : PDSA_METHOD; cdecl = Load_DSA_OpenSSL;
  DSA_set_default_method: procedure (const v1: PDSA_METHOD); cdecl = Load_DSA_set_default_method;
  DSA_get_default_method: function : PDSA_METHOD; cdecl = Load_DSA_get_default_method;
  DSA_set_method: function (dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl = Load_DSA_set_method;
  DSA_get_method: function (d: PDSA): PDSA_METHOD; cdecl = Load_DSA_get_method;
  DSA_new: function : PDSA; cdecl = Load_DSA_new;
  DSA_new_method: function (engine: PENGINE): PDSA; cdecl = Load_DSA_new_method;
  DSA_free: procedure (r: PDSA); cdecl = Load_DSA_free;
  DSA_up_ref: function (r: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_up_ref;
  DSA_size: function (const v1: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_size;
  DSA_bits: function (const d: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_bits;
  DSA_security_bits: function (const d: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_security_bits;
  DSA_sign: function (type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_sign;
  DSA_verify: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_verify;
  DSA_set_ex_data: function (d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_DSA_set_ex_data;
  DSA_get_ex_data: function (d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_DSA_get_ex_data;
  d2i_DSAPublicKey: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = Load_d2i_DSAPublicKey;
  d2i_DSAPrivateKey: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = Load_d2i_DSAPrivateKey;
  d2i_DSAparams: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = Load_d2i_DSAparams;
  DSA_generate_parameters_ex: function (dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_DSA_generate_parameters_ex;
  DSA_generate_key: function (a: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_generate_key;
  i2d_DSAPublicKey: function (const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DSAPublicKey;
  i2d_DSAPrivateKey: function (const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DSAPrivateKey;
  i2d_DSAparams: function (const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_DSAparams;
  DSAparams_print: function (bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl = Load_DSAparams_print;
  DSA_print: function (bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_print;
  DSA_dup_DH: function (const r: PDSA): PDH; cdecl = Load_DSA_dup_DH;
  DSA_get0_pqg: procedure (const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl = Load_DSA_get0_pqg;
  DSA_set0_pqg: function (d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_set0_pqg;
  DSA_get0_key: procedure (const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl = Load_DSA_get0_key;
  DSA_set0_key: function (d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_set0_key;
  DSA_get0_p: function (const d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_p;
  DSA_get0_q: function (const d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_q;
  DSA_get0_g: function (const d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_g;
  DSA_get0_pub_key: function (const d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_pub_key;
  DSA_get0_priv_key: function (const d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_priv_key;
  DSA_clear_flags: procedure (d: PDSA; flags: TOpenSSL_C_INT); cdecl = Load_DSA_clear_flags;
  DSA_test_flags: function (const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_test_flags;
  DSA_set_flags: procedure (d: PDSA; flags: TOpenSSL_C_INT); cdecl = Load_DSA_set_flags;
  DSA_get0_engine: function (d: PDSA): PENGINE; cdecl = Load_DSA_get0_engine;
  DSA_meth_new: function (const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl = Load_DSA_meth_new;
  DSA_meth_free: procedure (dsam: PDSA_METHOD); cdecl = Load_DSA_meth_free;
  DSA_meth_dup: function (const dsam: PDSA_METHOD): PDSA_METHOD; cdecl = Load_DSA_meth_dup;
  DSA_meth_get0_name: function (const dsam: PDSA_METHOD): PAnsiChar; cdecl = Load_DSA_meth_get0_name;
  DSA_meth_set1_name: function (dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set1_name;
  DSA_meth_get_flags: function (const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl = Load_DSA_meth_get_flags;
  DSA_meth_set_flags: function (dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_flags;
  DSA_meth_get0_app_data: function (const dsam: PDSA_METHOD): Pointer; cdecl = Load_DSA_meth_get0_app_data;
  DSA_meth_set0_app_data: function (dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set0_app_data;
  DSA_meth_get_sign: function (const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl = Load_DSA_meth_get_sign;
  DSA_meth_set_sign: function (dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_sign;
  DSA_meth_get_sign_setup: function (const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl = Load_DSA_meth_get_sign_setup;
  DSA_meth_set_sign_setup: function (dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_sign_setup;
  DSA_meth_get_verify: function (const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl = Load_DSA_meth_get_verify;
  DSA_meth_set_verify: function (dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_verify;
  DSA_meth_get_mod_exp: function (const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl = Load_DSA_meth_get_mod_exp;
  DSA_meth_set_mod_exp: function (dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_mod_exp;
  DSA_meth_get_bn_mod_exp: function (const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl = Load_DSA_meth_get_bn_mod_exp;
  DSA_meth_set_bn_mod_exp: function (dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_bn_mod_exp;
  DSA_meth_get_init: function (const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl = Load_DSA_meth_get_init;
  DSA_meth_set_init: function (dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_init;
  DSA_meth_get_finish: function (const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl = Load_DSA_meth_get_finish;
  DSA_meth_set_finish: function (dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_finish;
  DSA_meth_get_paramgen: function (const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl = Load_DSA_meth_get_paramgen;
  DSA_meth_set_paramgen: function (dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_paramgen;
  DSA_meth_get_keygen: function (const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl = Load_DSA_meth_get_keygen;
  DSA_meth_set_keygen: function (dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_keygen;
{$ENDIF}

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
function Load_DSAparams_dup(x: PDSA): PDSA; cdecl;
begin
  DSAparams_dup := LoadLibCryptoFunction('DSAparams_dup');
  if not assigned(DSAparams_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_dup');
  Result := DSAparams_dup(x);
end;

function Load_DSA_SIG_new: PDSA_SIG; cdecl;
begin
  DSA_SIG_new := LoadLibCryptoFunction('DSA_SIG_new');
  if not assigned(DSA_SIG_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_new');
  Result := DSA_SIG_new();
end;

procedure Load_DSA_SIG_free(a: PDSA_SIG); cdecl;
begin
  DSA_SIG_free := LoadLibCryptoFunction('DSA_SIG_free');
  if not assigned(DSA_SIG_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_free');
  DSA_SIG_free(a);
end;

function Load_i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSA_SIG := LoadLibCryptoFunction('i2d_DSA_SIG');
  if not assigned(i2d_DSA_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_SIG');
  Result := i2d_DSA_SIG(a,pp);
end;

function Load_d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl;
begin
  d2i_DSA_SIG := LoadLibCryptoFunction('d2i_DSA_SIG');
  if not assigned(d2i_DSA_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_SIG');
  Result := d2i_DSA_SIG(v,pp,length);
end;

procedure Load_DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
begin
  DSA_SIG_get0 := LoadLibCryptoFunction('DSA_SIG_get0');
  if not assigned(DSA_SIG_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_get0');
  DSA_SIG_get0(sig,pr,ps);
end;

function Load_DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_SIG_set0 := LoadLibCryptoFunction('DSA_SIG_set0');
  if not assigned(DSA_SIG_set0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_set0');
  Result := DSA_SIG_set0(sig,r,s);
end;

function Load_DSA_do_sign(const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl;
begin
  DSA_do_sign := LoadLibCryptoFunction('DSA_do_sign');
  if not assigned(DSA_do_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_do_sign');
  Result := DSA_do_sign(dgst,dlen,dsa);
end;

function Load_DSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_do_verify := LoadLibCryptoFunction('DSA_do_verify');
  if not assigned(DSA_do_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_do_verify');
  Result := DSA_do_verify(dgst,dgst_len,sig,dsa);
end;

function Load_DSA_OpenSSL: PDSA_METHOD; cdecl;
begin
  DSA_OpenSSL := LoadLibCryptoFunction('DSA_OpenSSL');
  if not assigned(DSA_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_OpenSSL');
  Result := DSA_OpenSSL();
end;

procedure Load_DSA_set_default_method(const v1: PDSA_METHOD); cdecl;
begin
  DSA_set_default_method := LoadLibCryptoFunction('DSA_set_default_method');
  if not assigned(DSA_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_default_method');
  DSA_set_default_method(v1);
end;

function Load_DSA_get_default_method: PDSA_METHOD; cdecl;
begin
  DSA_get_default_method := LoadLibCryptoFunction('DSA_get_default_method');
  if not assigned(DSA_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_default_method');
  Result := DSA_get_default_method();
end;

function Load_DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  DSA_set_method := LoadLibCryptoFunction('DSA_set_method');
  if not assigned(DSA_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_method');
  Result := DSA_set_method(dsa,v1);
end;

function Load_DSA_get_method(d: PDSA): PDSA_METHOD; cdecl;
begin
  DSA_get_method := LoadLibCryptoFunction('DSA_get_method');
  if not assigned(DSA_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_method');
  Result := DSA_get_method(d);
end;

function Load_DSA_new: PDSA; cdecl;
begin
  DSA_new := LoadLibCryptoFunction('DSA_new');
  if not assigned(DSA_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_new');
  Result := DSA_new();
end;

function Load_DSA_new_method(engine: PENGINE): PDSA; cdecl;
begin
  DSA_new_method := LoadLibCryptoFunction('DSA_new_method');
  if not assigned(DSA_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_new_method');
  Result := DSA_new_method(engine);
end;

procedure Load_DSA_free(r: PDSA); cdecl;
begin
  DSA_free := LoadLibCryptoFunction('DSA_free');
  if not assigned(DSA_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_free');
  DSA_free(r);
end;

function Load_DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_up_ref := LoadLibCryptoFunction('DSA_up_ref');
  if not assigned(DSA_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_up_ref');
  Result := DSA_up_ref(r);
end;

function Load_DSA_size(const v1: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_size := LoadLibCryptoFunction('DSA_size');
  if not assigned(DSA_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_size');
  Result := DSA_size(v1);
end;

function Load_DSA_bits(const d: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_bits := LoadLibCryptoFunction('DSA_bits');
  if not assigned(DSA_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_bits');
  Result := DSA_bits(d);
end;

function Load_DSA_security_bits(const d: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_security_bits := LoadLibCryptoFunction('DSA_security_bits');
  if not assigned(DSA_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_security_bits');
  Result := DSA_security_bits(d);
end;

function Load_DSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_sign := LoadLibCryptoFunction('DSA_sign');
  if not assigned(DSA_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_sign');
  Result := DSA_sign(type_,dgst,dlen,sig,siglen,dsa);
end;

function Load_DSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_verify := LoadLibCryptoFunction('DSA_verify');
  if not assigned(DSA_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_verify');
  Result := DSA_verify(type_,dgst,dgst_len,sigbuf,siglen,dsa);
end;

function Load_DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  DSA_set_ex_data := LoadLibCryptoFunction('DSA_set_ex_data');
  if not assigned(DSA_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_ex_data');
  Result := DSA_set_ex_data(d,idx,arg);
end;

function Load_DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  DSA_get_ex_data := LoadLibCryptoFunction('DSA_get_ex_data');
  if not assigned(DSA_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_ex_data');
  Result := DSA_get_ex_data(d,idx);
end;

function Load_d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  d2i_DSAPublicKey := LoadLibCryptoFunction('d2i_DSAPublicKey');
  if not assigned(d2i_DSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPublicKey');
  Result := d2i_DSAPublicKey(a,pp,length);
end;

function Load_d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  d2i_DSAPrivateKey := LoadLibCryptoFunction('d2i_DSAPrivateKey');
  if not assigned(d2i_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPrivateKey');
  Result := d2i_DSAPrivateKey(a,pp,length);
end;

function Load_d2i_DSAparams(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  d2i_DSAparams := LoadLibCryptoFunction('d2i_DSAparams');
  if not assigned(d2i_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAparams');
  Result := d2i_DSAparams(a,pp,length);
end;

function Load_DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  DSA_generate_parameters_ex := LoadLibCryptoFunction('DSA_generate_parameters_ex');
  if not assigned(DSA_generate_parameters_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_parameters_ex');
  Result := DSA_generate_parameters_ex(dsa,bits,seed,seed_len,counter_ret,h_ret,cb);
end;

function Load_DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_generate_key := LoadLibCryptoFunction('DSA_generate_key');
  if not assigned(DSA_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_key');
  Result := DSA_generate_key(a);
end;

function Load_i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAPublicKey := LoadLibCryptoFunction('i2d_DSAPublicKey');
  if not assigned(i2d_DSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPublicKey');
  Result := i2d_DSAPublicKey(a,pp);
end;

function Load_i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAPrivateKey := LoadLibCryptoFunction('i2d_DSAPrivateKey');
  if not assigned(i2d_DSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPrivateKey');
  Result := i2d_DSAPrivateKey(a,pp);
end;

function Load_i2d_DSAparams(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAparams := LoadLibCryptoFunction('i2d_DSAparams');
  if not assigned(i2d_DSAparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAparams');
  Result := i2d_DSAparams(a,pp);
end;

function Load_DSAparams_print(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSAparams_print := LoadLibCryptoFunction('DSAparams_print');
  if not assigned(DSAparams_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_print');
  Result := DSAparams_print(bp,x);
end;

function Load_DSA_print(bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_print := LoadLibCryptoFunction('DSA_print');
  if not assigned(DSA_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_print');
  Result := DSA_print(bp,x,off);
end;

function Load_DSA_dup_DH(const r: PDSA): PDH; cdecl;
begin
  DSA_dup_DH := LoadLibCryptoFunction('DSA_dup_DH');
  if not assigned(DSA_dup_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_dup_DH');
  Result := DSA_dup_DH(r);
end;

procedure Load_DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
begin
  DSA_get0_pqg := LoadLibCryptoFunction('DSA_get0_pqg');
  if not assigned(DSA_get0_pqg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_pqg');
  DSA_get0_pqg(d,p,q,g);
end;

function Load_DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_set0_pqg := LoadLibCryptoFunction('DSA_set0_pqg');
  if not assigned(DSA_set0_pqg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set0_pqg');
  Result := DSA_set0_pqg(d,p,q,g);
end;

procedure Load_DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
begin
  DSA_get0_key := LoadLibCryptoFunction('DSA_get0_key');
  if not assigned(DSA_get0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_key');
  DSA_get0_key(d,pub_key,priv_key);
end;

function Load_DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_set0_key := LoadLibCryptoFunction('DSA_set0_key');
  if not assigned(DSA_set0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set0_key');
  Result := DSA_set0_key(d,pub_key,priv_key);
end;

function Load_DSA_get0_p(const d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_p := LoadLibCryptoFunction('DSA_get0_p');
  if not assigned(DSA_get0_p) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_p');
  Result := DSA_get0_p(d);
end;

function Load_DSA_get0_q(const d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_q := LoadLibCryptoFunction('DSA_get0_q');
  if not assigned(DSA_get0_q) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_q');
  Result := DSA_get0_q(d);
end;

function Load_DSA_get0_g(const d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_g := LoadLibCryptoFunction('DSA_get0_g');
  if not assigned(DSA_get0_g) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_g');
  Result := DSA_get0_g(d);
end;

function Load_DSA_get0_pub_key(const d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_pub_key := LoadLibCryptoFunction('DSA_get0_pub_key');
  if not assigned(DSA_get0_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_pub_key');
  Result := DSA_get0_pub_key(d);
end;

function Load_DSA_get0_priv_key(const d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_priv_key := LoadLibCryptoFunction('DSA_get0_priv_key');
  if not assigned(DSA_get0_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_priv_key');
  Result := DSA_get0_priv_key(d);
end;

procedure Load_DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
begin
  DSA_clear_flags := LoadLibCryptoFunction('DSA_clear_flags');
  if not assigned(DSA_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_clear_flags');
  DSA_clear_flags(d,flags);
end;

function Load_DSA_test_flags(const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_test_flags := LoadLibCryptoFunction('DSA_test_flags');
  if not assigned(DSA_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_test_flags');
  Result := DSA_test_flags(d,flags);
end;

procedure Load_DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
begin
  DSA_set_flags := LoadLibCryptoFunction('DSA_set_flags');
  if not assigned(DSA_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_flags');
  DSA_set_flags(d,flags);
end;

function Load_DSA_get0_engine(d: PDSA): PENGINE; cdecl;
begin
  DSA_get0_engine := LoadLibCryptoFunction('DSA_get0_engine');
  if not assigned(DSA_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_engine');
  Result := DSA_get0_engine(d);
end;

function Load_DSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl;
begin
  DSA_meth_new := LoadLibCryptoFunction('DSA_meth_new');
  if not assigned(DSA_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_new');
  Result := DSA_meth_new(name,flags);
end;

procedure Load_DSA_meth_free(dsam: PDSA_METHOD); cdecl;
begin
  DSA_meth_free := LoadLibCryptoFunction('DSA_meth_free');
  if not assigned(DSA_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_free');
  DSA_meth_free(dsam);
end;

function Load_DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD; cdecl;
begin
  DSA_meth_dup := LoadLibCryptoFunction('DSA_meth_dup');
  if not assigned(DSA_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_dup');
  Result := DSA_meth_dup(dsam);
end;

function Load_DSA_meth_get0_name(const dsam: PDSA_METHOD): PAnsiChar; cdecl;
begin
  DSA_meth_get0_name := LoadLibCryptoFunction('DSA_meth_get0_name');
  if not assigned(DSA_meth_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get0_name');
  Result := DSA_meth_get0_name(dsam);
end;

function Load_DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set1_name := LoadLibCryptoFunction('DSA_meth_set1_name');
  if not assigned(DSA_meth_set1_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set1_name');
  Result := DSA_meth_set1_name(dsam,name);
end;

function Load_DSA_meth_get_flags(const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_get_flags := LoadLibCryptoFunction('DSA_meth_get_flags');
  if not assigned(DSA_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_flags');
  Result := DSA_meth_get_flags(dsam);
end;

function Load_DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_flags := LoadLibCryptoFunction('DSA_meth_set_flags');
  if not assigned(DSA_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_flags');
  Result := DSA_meth_set_flags(dsam,flags);
end;

function Load_DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer; cdecl;
begin
  DSA_meth_get0_app_data := LoadLibCryptoFunction('DSA_meth_get0_app_data');
  if not assigned(DSA_meth_get0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get0_app_data');
  Result := DSA_meth_get0_app_data(dsam);
end;

function Load_DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set0_app_data := LoadLibCryptoFunction('DSA_meth_set0_app_data');
  if not assigned(DSA_meth_set0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set0_app_data');
  Result := DSA_meth_set0_app_data(dsam,app_data);
end;

function Load_DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl;
begin
  DSA_meth_get_sign := LoadLibCryptoFunction('DSA_meth_get_sign');
  if not assigned(DSA_meth_get_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_sign');
  Result := DSA_meth_get_sign(dsam);
end;

function Load_DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_sign := LoadLibCryptoFunction('DSA_meth_set_sign');
  if not assigned(DSA_meth_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_sign');
  Result := DSA_meth_set_sign(dsam,sign);
end;

function Load_DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl;
begin
  DSA_meth_get_sign_setup := LoadLibCryptoFunction('DSA_meth_get_sign_setup');
  if not assigned(DSA_meth_get_sign_setup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_sign_setup');
  Result := DSA_meth_get_sign_setup(dsam);
end;

function Load_DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_sign_setup := LoadLibCryptoFunction('DSA_meth_set_sign_setup');
  if not assigned(DSA_meth_set_sign_setup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_sign_setup');
  Result := DSA_meth_set_sign_setup(dsam,sign_setup);
end;

function Load_DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl;
begin
  DSA_meth_get_verify := LoadLibCryptoFunction('DSA_meth_get_verify');
  if not assigned(DSA_meth_get_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_verify');
  Result := DSA_meth_get_verify(dsam);
end;

function Load_DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_verify := LoadLibCryptoFunction('DSA_meth_set_verify');
  if not assigned(DSA_meth_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_verify');
  Result := DSA_meth_set_verify(dsam,verify);
end;

function Load_DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl;
begin
  DSA_meth_get_mod_exp := LoadLibCryptoFunction('DSA_meth_get_mod_exp');
  if not assigned(DSA_meth_get_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_mod_exp');
  Result := DSA_meth_get_mod_exp(dsam);
end;

function Load_DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_mod_exp := LoadLibCryptoFunction('DSA_meth_set_mod_exp');
  if not assigned(DSA_meth_set_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_mod_exp');
  Result := DSA_meth_set_mod_exp(dsam,mod_exp);
end;

function Load_DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl;
begin
  DSA_meth_get_bn_mod_exp := LoadLibCryptoFunction('DSA_meth_get_bn_mod_exp');
  if not assigned(DSA_meth_get_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_bn_mod_exp');
  Result := DSA_meth_get_bn_mod_exp(dsam);
end;

function Load_DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_bn_mod_exp := LoadLibCryptoFunction('DSA_meth_set_bn_mod_exp');
  if not assigned(DSA_meth_set_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_bn_mod_exp');
  Result := DSA_meth_set_bn_mod_exp(dsam,bn_mod_exp);
end;

function Load_DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl;
begin
  DSA_meth_get_init := LoadLibCryptoFunction('DSA_meth_get_init');
  if not assigned(DSA_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_init');
  Result := DSA_meth_get_init(dsam);
end;

function Load_DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_init := LoadLibCryptoFunction('DSA_meth_set_init');
  if not assigned(DSA_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_init');
  Result := DSA_meth_set_init(dsam,init);
end;

function Load_DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl;
begin
  DSA_meth_get_finish := LoadLibCryptoFunction('DSA_meth_get_finish');
  if not assigned(DSA_meth_get_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_finish');
  Result := DSA_meth_get_finish(dsam);
end;

function Load_DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_finish := LoadLibCryptoFunction('DSA_meth_set_finish');
  if not assigned(DSA_meth_set_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_finish');
  Result := DSA_meth_set_finish(dsam,finish);
end;

function Load_DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl;
begin
  DSA_meth_get_paramgen := LoadLibCryptoFunction('DSA_meth_get_paramgen');
  if not assigned(DSA_meth_get_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_paramgen');
  Result := DSA_meth_get_paramgen(dsam);
end;

function Load_DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_paramgen := LoadLibCryptoFunction('DSA_meth_set_paramgen');
  if not assigned(DSA_meth_set_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_paramgen');
  Result := DSA_meth_set_paramgen(dsam,paramgen);
end;

function Load_DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl;
begin
  DSA_meth_get_keygen := LoadLibCryptoFunction('DSA_meth_get_keygen');
  if not assigned(DSA_meth_get_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_keygen');
  Result := DSA_meth_get_keygen(dsam);
end;

function Load_DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_keygen := LoadLibCryptoFunction('DSA_meth_set_keygen');
  if not assigned(DSA_meth_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_keygen');
  Result := DSA_meth_set_keygen(dsam,keygen);
end;


procedure UnLoad;
begin
  DSAparams_dup := Load_DSAparams_dup;
  DSA_SIG_new := Load_DSA_SIG_new;
  DSA_SIG_free := Load_DSA_SIG_free;
  i2d_DSA_SIG := Load_i2d_DSA_SIG;
  d2i_DSA_SIG := Load_d2i_DSA_SIG;
  DSA_SIG_get0 := Load_DSA_SIG_get0;
  DSA_SIG_set0 := Load_DSA_SIG_set0;
  DSA_do_sign := Load_DSA_do_sign;
  DSA_do_verify := Load_DSA_do_verify;
  DSA_OpenSSL := Load_DSA_OpenSSL;
  DSA_set_default_method := Load_DSA_set_default_method;
  DSA_get_default_method := Load_DSA_get_default_method;
  DSA_set_method := Load_DSA_set_method;
  DSA_get_method := Load_DSA_get_method;
  DSA_new := Load_DSA_new;
  DSA_new_method := Load_DSA_new_method;
  DSA_free := Load_DSA_free;
  DSA_up_ref := Load_DSA_up_ref;
  DSA_size := Load_DSA_size;
  DSA_bits := Load_DSA_bits;
  DSA_security_bits := Load_DSA_security_bits;
  DSA_sign := Load_DSA_sign;
  DSA_verify := Load_DSA_verify;
  DSA_set_ex_data := Load_DSA_set_ex_data;
  DSA_get_ex_data := Load_DSA_get_ex_data;
  d2i_DSAPublicKey := Load_d2i_DSAPublicKey;
  d2i_DSAPrivateKey := Load_d2i_DSAPrivateKey;
  d2i_DSAparams := Load_d2i_DSAparams;
  DSA_generate_parameters_ex := Load_DSA_generate_parameters_ex;
  DSA_generate_key := Load_DSA_generate_key;
  i2d_DSAPublicKey := Load_i2d_DSAPublicKey;
  i2d_DSAPrivateKey := Load_i2d_DSAPrivateKey;
  i2d_DSAparams := Load_i2d_DSAparams;
  DSAparams_print := Load_DSAparams_print;
  DSA_print := Load_DSA_print;
  DSA_dup_DH := Load_DSA_dup_DH;
  DSA_get0_pqg := Load_DSA_get0_pqg;
  DSA_set0_pqg := Load_DSA_set0_pqg;
  DSA_get0_key := Load_DSA_get0_key;
  DSA_set0_key := Load_DSA_set0_key;
  DSA_get0_p := Load_DSA_get0_p;
  DSA_get0_q := Load_DSA_get0_q;
  DSA_get0_g := Load_DSA_get0_g;
  DSA_get0_pub_key := Load_DSA_get0_pub_key;
  DSA_get0_priv_key := Load_DSA_get0_priv_key;
  DSA_clear_flags := Load_DSA_clear_flags;
  DSA_test_flags := Load_DSA_test_flags;
  DSA_set_flags := Load_DSA_set_flags;
  DSA_get0_engine := Load_DSA_get0_engine;
  DSA_meth_new := Load_DSA_meth_new;
  DSA_meth_free := Load_DSA_meth_free;
  DSA_meth_dup := Load_DSA_meth_dup;
  DSA_meth_get0_name := Load_DSA_meth_get0_name;
  DSA_meth_set1_name := Load_DSA_meth_set1_name;
  DSA_meth_get_flags := Load_DSA_meth_get_flags;
  DSA_meth_set_flags := Load_DSA_meth_set_flags;
  DSA_meth_get0_app_data := Load_DSA_meth_get0_app_data;
  DSA_meth_set0_app_data := Load_DSA_meth_set0_app_data;
  DSA_meth_get_sign := Load_DSA_meth_get_sign;
  DSA_meth_set_sign := Load_DSA_meth_set_sign;
  DSA_meth_get_sign_setup := Load_DSA_meth_get_sign_setup;
  DSA_meth_set_sign_setup := Load_DSA_meth_set_sign_setup;
  DSA_meth_get_verify := Load_DSA_meth_get_verify;
  DSA_meth_set_verify := Load_DSA_meth_set_verify;
  DSA_meth_get_mod_exp := Load_DSA_meth_get_mod_exp;
  DSA_meth_set_mod_exp := Load_DSA_meth_set_mod_exp;
  DSA_meth_get_bn_mod_exp := Load_DSA_meth_get_bn_mod_exp;
  DSA_meth_set_bn_mod_exp := Load_DSA_meth_set_bn_mod_exp;
  DSA_meth_get_init := Load_DSA_meth_get_init;
  DSA_meth_set_init := Load_DSA_meth_set_init;
  DSA_meth_get_finish := Load_DSA_meth_get_finish;
  DSA_meth_set_finish := Load_DSA_meth_set_finish;
  DSA_meth_get_paramgen := Load_DSA_meth_get_paramgen;
  DSA_meth_set_paramgen := Load_DSA_meth_set_paramgen;
  DSA_meth_get_keygen := Load_DSA_meth_get_keygen;
  DSA_meth_set_keygen := Load_DSA_meth_set_keygen;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
