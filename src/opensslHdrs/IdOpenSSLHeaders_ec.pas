(* This unit was generated from the source file ec.h2pas 
It should not be modified directly. All changes should be made to ec.h2pas
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


unit IdOpenSSLHeaders_ec;


interface

// Headers for OpenSSL 1.1.1
// ec.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_evp;

const
  OPENSSL_EC_EXPLICIT_CURVE = $000;
  OPENSSL_EC_NAMED_CURVE    = $001;
  EC_PKEY_NO_PARAMETERS = $001;
  EC_PKEY_NO_PUBKEY     = $002;
  EC_FLAG_NON_FIPS_ALLOW = $1;
  EC_FLAG_FIPS_CHECKED   = $2;
  EC_FLAG_COFACTOR_ECDH  = $1000;
  EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1);
  EVP_PKEY_CTRL_EC_PARAM_ENC          = (EVP_PKEY_ALG_CTRL + 2);
  EVP_PKEY_CTRL_EC_ECDH_COFACTOR      = (EVP_PKEY_ALG_CTRL + 3);
  EVP_PKEY_CTRL_EC_KDF_TYPE           = (EVP_PKEY_ALG_CTRL + 4);
  EVP_PKEY_CTRL_EC_KDF_MD             = (EVP_PKEY_ALG_CTRL + 5);
  EVP_PKEY_CTRL_GET_EC_KDF_MD         = (EVP_PKEY_ALG_CTRL + 6);
  EVP_PKEY_CTRL_EC_KDF_OUTLEN         = (EVP_PKEY_ALG_CTRL + 7);
  EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN     = (EVP_PKEY_ALG_CTRL + 8);
  EVP_PKEY_CTRL_EC_KDF_UKM            = (EVP_PKEY_ALG_CTRL + 9);
  EVP_PKEY_CTRL_GET_EC_KDF_UKM        = (EVP_PKEY_ALG_CTRL + 10);
  EVP_PKEY_CTRL_SET1_ID               = (EVP_PKEY_ALG_CTRL + 11);
  EVP_PKEY_CTRL_GET1_ID               = (EVP_PKEY_ALG_CTRL + 12);
  EVP_PKEY_CTRL_GET1_ID_LEN           = (EVP_PKEY_ALG_CTRL + 13);
  EVP_PKEY_ECDH_KDF_NONE              = 1;
  EVP_PKEY_ECDH_KDF_X9_63             = 2;
  EVP_PKEY_ECDH_KDF_X9_62             = EVP_PKEY_ECDH_KDF_X9_63;

type
  {$MINENUMSIZE 4}
  point_conversion_form_t = (
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
  );

  EC_METHOD = type Pointer; // ec_method_st
  PEC_METHOD = ^EC_METHOD;
  
  EC_GROUP = type Pointer; // ec_group_st
  PEC_GROUP = ^EC_GROUP;
  PPEC_GROUP = ^PEC_GROUP;
  
  EC_POINT = type Pointer; // ec_point_st
  PEC_POINT = ^EC_POINT;
  PPEC_POINT = ^PEC_POINT;
  
  ECPKPARAMETERS = type Pointer; // ecpk_parameters_st
  PECPKPARAMETERS = ^ECPKPARAMETERS;
  
  ECPARAMETERS = type Pointer; // ec_parameters_st
  PECPARAMETERS = ^ECPARAMETERS;

  EC_builtin_curve = record
    nid: TOpenSSL_C_INT;
    comment: PAnsiChar;
  end;
  PEC_builtin_curve = ^EC_builtin_curve;

  ECDSA_SIG = type Pointer; // ECDSA_SIG_st
  PECDSA_SIG = ^ECDSA_SIG;
  PPECDSA_SIG = ^PECDSA_SIG;

  ECDH_compute_key_KDF = function(const in_: Pointer; inlen: TOpenSSL_C_SIZET; out_: Pointer; outlen: POpenSSL_C_SIZET): Pointer; cdecl;

  EC_KEY_METHOD_init_init = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_finish = procedure(key: PEC_KEY); cdecl;
  EC_KEY_METHOD_init_copy = function(dest: PEC_KEY; const src: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_set_group = function(key: PEC_KEY; const grp: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_set_private = function(key: PEC_KEY; const priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_set_public = function(key: PEC_KEY; const pub_key: PEC_POINT): TOpenSSL_C_INT; cdecl;

  EC_KEY_METHOD_keygen_keygen = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;

  EC_KEY_METHOD_compute_key_ckey = function(psec: PPByte; pseclen: POpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY): TOpenSSL_C_INT; cdecl;

  EC_KEY_METHOD_sign_sign = function(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const r: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_sign_sign_setup = function(eckey: PEC_KEY; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_sign_sign_sig = function(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const in_kinv: PBIGNUM; const in_r: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;

  EC_KEY_METHOD_verify_verify = function(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; sig_len: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_verify_verify_sig = function(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;

  PEC_KEY_METHOD_init_init = ^EC_KEY_METHOD_init_init;
  PEC_KEY_METHOD_init_finish = ^EC_KEY_METHOD_init_finish;
  PEC_KEY_METHOD_init_copy = ^EC_KEY_METHOD_init_copy;
  PEC_KEY_METHOD_init_set_group = ^EC_KEY_METHOD_init_set_group;
  PEC_KEY_METHOD_init_set_private = ^EC_KEY_METHOD_init_set_private;
  PEC_KEY_METHOD_init_set_public = ^EC_KEY_METHOD_init_set_public;

  PEC_KEY_METHOD_keygen_keygen = ^EC_KEY_METHOD_keygen_keygen;

  PEC_KEY_METHOD_compute_key_ckey = ^EC_KEY_METHOD_compute_key_ckey;

  PEC_KEY_METHOD_sign_sign = ^EC_KEY_METHOD_sign_sign;
  PEC_KEY_METHOD_sign_sign_setup = ^EC_KEY_METHOD_sign_sign_setup;
  PEC_KEY_METHOD_sign_sign_sig = ^EC_KEY_METHOD_sign_sign_sig;

  PEC_KEY_METHOD_verify_verify = ^EC_KEY_METHOD_verify_verify;
  PEC_KEY_METHOD_verify_verify_sig = ^EC_KEY_METHOD_verify_verify_sig;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM EC_GFp_simple_method}
{$EXTERNALSYM EC_GFp_mont_method}
{$EXTERNALSYM EC_GFp_nist_method}
{$EXTERNALSYM EC_GF2m_simple_method}
{$EXTERNALSYM EC_GROUP_new}
{$EXTERNALSYM EC_GROUP_free}
{$EXTERNALSYM EC_GROUP_clear_free}
{$EXTERNALSYM EC_GROUP_copy}
{$EXTERNALSYM EC_GROUP_dup}
{$EXTERNALSYM EC_GROUP_method_of}
{$EXTERNALSYM EC_METHOD_get_field_type}
{$EXTERNALSYM EC_GROUP_set_generator}
{$EXTERNALSYM EC_GROUP_get0_generator}
{$EXTERNALSYM EC_GROUP_get_mont_data}
{$EXTERNALSYM EC_GROUP_get_order}
{$EXTERNALSYM EC_GROUP_get0_order}
{$EXTERNALSYM EC_GROUP_order_bits}
{$EXTERNALSYM EC_GROUP_get_cofactor}
{$EXTERNALSYM EC_GROUP_get0_cofactor}
{$EXTERNALSYM EC_GROUP_set_curve_name}
{$EXTERNALSYM EC_GROUP_get_curve_name}
{$EXTERNALSYM EC_GROUP_set_asn1_flag}
{$EXTERNALSYM EC_GROUP_get_asn1_flag}
{$EXTERNALSYM EC_GROUP_set_point_conversion_form}
{$EXTERNALSYM EC_GROUP_get_point_conversion_form}
{$EXTERNALSYM EC_GROUP_get0_seed}
{$EXTERNALSYM EC_GROUP_get_seed_len}
{$EXTERNALSYM EC_GROUP_set_seed}
{$EXTERNALSYM EC_GROUP_set_curve}
{$EXTERNALSYM EC_GROUP_get_curve}
{$EXTERNALSYM EC_GROUP_set_curve_GFp}
{$EXTERNALSYM EC_GROUP_get_curve_GFp}
{$EXTERNALSYM EC_GROUP_set_curve_GF2m}
{$EXTERNALSYM EC_GROUP_get_curve_GF2m}
{$EXTERNALSYM EC_GROUP_get_degree}
{$EXTERNALSYM EC_GROUP_check}
{$EXTERNALSYM EC_GROUP_check_discriminant}
{$EXTERNALSYM EC_GROUP_cmp}
{$EXTERNALSYM EC_GROUP_new_curve_GFp}
{$EXTERNALSYM EC_GROUP_new_curve_GF2m}
{$EXTERNALSYM EC_GROUP_new_by_curve_name}
{$EXTERNALSYM EC_GROUP_new_from_ecparameters}
{$EXTERNALSYM EC_GROUP_get_ecparameters}
{$EXTERNALSYM EC_GROUP_new_from_ecpkparameters}
{$EXTERNALSYM EC_GROUP_get_ecpkparameters}
{$EXTERNALSYM EC_get_builtin_curves}
{$EXTERNALSYM EC_curve_nid2nist}
{$EXTERNALSYM EC_curve_nist2nid}
{$EXTERNALSYM EC_POINT_new}
{$EXTERNALSYM EC_POINT_free}
{$EXTERNALSYM EC_POINT_clear_free}
{$EXTERNALSYM EC_POINT_copy}
{$EXTERNALSYM EC_POINT_dup}
{$EXTERNALSYM EC_POINT_method_of}
{$EXTERNALSYM EC_POINT_set_to_infinity}
{$EXTERNALSYM EC_POINT_set_Jprojective_coordinates_GFp}
{$EXTERNALSYM EC_POINT_get_Jprojective_coordinates_GFp}
{$EXTERNALSYM EC_POINT_set_affine_coordinates}
{$EXTERNALSYM EC_POINT_get_affine_coordinates}
{$EXTERNALSYM EC_POINT_set_affine_coordinates_GFp}
{$EXTERNALSYM EC_POINT_get_affine_coordinates_GFp}
{$EXTERNALSYM EC_POINT_set_compressed_coordinates}
{$EXTERNALSYM EC_POINT_set_compressed_coordinates_GFp}
{$EXTERNALSYM EC_POINT_set_affine_coordinates_GF2m}
{$EXTERNALSYM EC_POINT_get_affine_coordinates_GF2m}
{$EXTERNALSYM EC_POINT_set_compressed_coordinates_GF2m}
{$EXTERNALSYM EC_POINT_point2oct}
{$EXTERNALSYM EC_POINT_oct2point}
{$EXTERNALSYM EC_POINT_point2buf}
{$EXTERNALSYM EC_POINT_point2bn}
{$EXTERNALSYM EC_POINT_bn2point}
{$EXTERNALSYM EC_POINT_point2hex}
{$EXTERNALSYM EC_POINT_hex2point}
{$EXTERNALSYM EC_POINT_add}
{$EXTERNALSYM EC_POINT_dbl}
{$EXTERNALSYM EC_POINT_invert}
{$EXTERNALSYM EC_POINT_is_at_infinity}
{$EXTERNALSYM EC_POINT_is_on_curve}
{$EXTERNALSYM EC_POINT_cmp}
{$EXTERNALSYM EC_POINT_make_affine}
{$EXTERNALSYM EC_POINTs_make_affine}
{$EXTERNALSYM EC_POINTs_mul}
{$EXTERNALSYM EC_POINT_mul}
{$EXTERNALSYM EC_GROUP_precompute_mult}
{$EXTERNALSYM EC_GROUP_have_precompute_mult}
{$EXTERNALSYM ECPKPARAMETERS_it}
{$EXTERNALSYM ECPKPARAMETERS_new}
{$EXTERNALSYM ECPKPARAMETERS_free}
{$EXTERNALSYM ECPARAMETERS_it}
{$EXTERNALSYM ECPARAMETERS_new}
{$EXTERNALSYM ECPARAMETERS_free}
{$EXTERNALSYM EC_GROUP_get_basis_type}
{$EXTERNALSYM EC_GROUP_get_trinomial_basis}
{$EXTERNALSYM EC_GROUP_get_pentanomial_basis}
{$EXTERNALSYM d2i_ECPKParameters}
{$EXTERNALSYM i2d_ECPKParameters}
{$EXTERNALSYM ECPKParameters_print}
{$EXTERNALSYM EC_KEY_new}
{$EXTERNALSYM EC_KEY_get_flags}
{$EXTERNALSYM EC_KEY_set_flags}
{$EXTERNALSYM EC_KEY_clear_flags}
{$EXTERNALSYM EC_KEY_new_by_curve_name}
{$EXTERNALSYM EC_KEY_free}
{$EXTERNALSYM EC_KEY_copy}
{$EXTERNALSYM EC_KEY_dup}
{$EXTERNALSYM EC_KEY_up_ref}
{$EXTERNALSYM EC_KEY_get0_engine}
{$EXTERNALSYM EC_KEY_get0_group}
{$EXTERNALSYM EC_KEY_set_group}
{$EXTERNALSYM EC_KEY_get0_private_key}
{$EXTERNALSYM EC_KEY_set_private_key}
{$EXTERNALSYM EC_KEY_get0_public_key}
{$EXTERNALSYM EC_KEY_set_public_key}
{$EXTERNALSYM EC_KEY_get_enc_flags}
{$EXTERNALSYM EC_KEY_set_enc_flags}
{$EXTERNALSYM EC_KEY_get_conv_form}
{$EXTERNALSYM EC_KEY_set_conv_form}
{$EXTERNALSYM EC_KEY_set_ex_data}
{$EXTERNALSYM EC_KEY_get_ex_data}
{$EXTERNALSYM EC_KEY_set_asn1_flag}
{$EXTERNALSYM EC_KEY_precompute_mult}
{$EXTERNALSYM EC_KEY_generate_key}
{$EXTERNALSYM EC_KEY_check_key}
{$EXTERNALSYM EC_KEY_can_sign}
{$EXTERNALSYM EC_KEY_set_public_key_affine_coordinates}
{$EXTERNALSYM EC_KEY_key2buf}
{$EXTERNALSYM EC_KEY_oct2key}
{$EXTERNALSYM EC_KEY_oct2priv}
{$EXTERNALSYM EC_KEY_priv2oct}
{$EXTERNALSYM EC_KEY_priv2buf}
{$EXTERNALSYM d2i_ECPrivateKey}
{$EXTERNALSYM i2d_ECPrivateKey}
{$EXTERNALSYM o2i_ECPublicKey}
{$EXTERNALSYM i2o_ECPublicKey}
{$EXTERNALSYM ECParameters_print}
{$EXTERNALSYM EC_KEY_print}
{$EXTERNALSYM EC_KEY_OpenSSL}
{$EXTERNALSYM EC_KEY_get_default_method}
{$EXTERNALSYM EC_KEY_set_default_method}
{$EXTERNALSYM EC_KEY_get_method}
{$EXTERNALSYM EC_KEY_set_method}
{$EXTERNALSYM EC_KEY_new_method}
{$EXTERNALSYM ECDH_KDF_X9_62}
{$EXTERNALSYM ECDH_compute_key}
{$EXTERNALSYM ECDSA_SIG_new}
{$EXTERNALSYM ECDSA_SIG_free}
{$EXTERNALSYM i2d_ECDSA_SIG}
{$EXTERNALSYM d2i_ECDSA_SIG}
{$EXTERNALSYM ECDSA_SIG_get0}
{$EXTERNALSYM ECDSA_SIG_get0_r}
{$EXTERNALSYM ECDSA_SIG_get0_s}
{$EXTERNALSYM ECDSA_SIG_set0}
{$EXTERNALSYM ECDSA_do_sign}
{$EXTERNALSYM ECDSA_do_sign_ex}
{$EXTERNALSYM ECDSA_do_verify}
{$EXTERNALSYM ECDSA_sign_setup}
{$EXTERNALSYM ECDSA_sign}
{$EXTERNALSYM ECDSA_sign_ex}
{$EXTERNALSYM ECDSA_verify}
{$EXTERNALSYM ECDSA_size}
{$EXTERNALSYM EC_KEY_METHOD_new}
{$EXTERNALSYM EC_KEY_METHOD_free}
{$EXTERNALSYM EC_KEY_METHOD_set_init}
{$EXTERNALSYM EC_KEY_METHOD_set_keygen}
{$EXTERNALSYM EC_KEY_METHOD_set_compute_key}
{$EXTERNALSYM EC_KEY_METHOD_set_sign}
{$EXTERNALSYM EC_KEY_METHOD_set_verify}
{$EXTERNALSYM EC_KEY_METHOD_get_init}
{$EXTERNALSYM EC_KEY_METHOD_get_keygen}
{$EXTERNALSYM EC_KEY_METHOD_get_compute_key}
{$EXTERNALSYM EC_KEY_METHOD_get_sign}
{$EXTERNALSYM EC_KEY_METHOD_get_verify}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function EC_GFp_simple_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GFp_mont_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GFp_nist_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GF2m_simple_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; cdecl; external CLibCrypto;
procedure EC_GROUP_free(group: PEC_GROUP); cdecl; external CLibCrypto;
procedure EC_GROUP_clear_free(group: PEC_GROUP); cdecl; external CLibCrypto;
function EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP; cdecl; external CLibCrypto;
function EC_METHOD_get_field_type(const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto;
function EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; cdecl; external CLibCrypto;
function EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto;
function EC_GROUP_order_bits(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto;
procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_GROUP_get_curve_name(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t); cdecl; external CLibCrypto;
function EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t; cdecl; external CLibCrypto;
function EC_GROUP_get0_seed(const x: PEC_GROUP): PByte; cdecl; external CLibCrypto;
function EC_GROUP_get_seed_len(const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_degree(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl; external CLibCrypto;
function EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl; external CLibCrypto;
function EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function EC_curve_nist2nid(const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_new(const group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto;
procedure EC_POINT_free(point: PEC_POINT); cdecl; external CLibCrypto;
procedure EC_POINT_clear_free(point: PEC_POINT); cdecl; external CLibCrypto;
function EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto;
function EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD; cdecl; external CLibCrypto;
function EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
function EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl; external CLibCrypto;
function EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl; external CLibCrypto;
function EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl; external CLibCrypto;
function EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINTs_make_affine(const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECPKPARAMETERS_it: PASN1_ITEM; cdecl; external CLibCrypto;
function ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl; external CLibCrypto;
procedure ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl; external CLibCrypto;
function ECPARAMETERS_it: PASN1_ITEM; cdecl; external CLibCrypto;
function ECPARAMETERS_new: PECPARAMETERS; cdecl; external CLibCrypto;
procedure ECPARAMETERS_free(a: PECPARAMETERS); cdecl; external CLibCrypto;
function EC_GROUP_get_basis_type(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl; external CLibCrypto;
function i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_new: PEC_KEY; cdecl; external CLibCrypto;
function EC_KEY_get_flags(const key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto;
procedure EC_KEY_free(key: PEC_KEY); cdecl; external CLibCrypto;
function EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl; external CLibCrypto;
function EC_KEY_dup(const src: PEC_KEY): PEC_KEY; cdecl; external CLibCrypto;
function EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; cdecl; external CLibCrypto;
function EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; cdecl; external CLibCrypto;
function EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; cdecl; external CLibCrypto;
function EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; cdecl; external CLibCrypto;
function EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get_enc_flags(const key: PEC_KEY): TOpenSSL_C_UINT; cdecl; external CLibCrypto;
procedure EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto;
function EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t; cdecl; external CLibCrypto;
procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl; external CLibCrypto;
function EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get_ex_data(const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
procedure EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_check_key(const key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_can_sign(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl; external CLibCrypto;
function i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl; external CLibCrypto;
function i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECParameters_print(bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl; external CLibCrypto;
function EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl; external CLibCrypto;
procedure EC_KEY_set_default_method(const meth: PEC_KEY_METHOD); cdecl; external CLibCrypto;
function EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD; cdecl; external CLibCrypto;
function EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl; external CLibCrypto;
function ECDH_KDF_X9_62(out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDH_compute_key(out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_SIG_new: PECDSA_SIG; cdecl; external CLibCrypto;
procedure ECDSA_SIG_free(sig: PECDSA_SIG); cdecl; external CLibCrypto;
function i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl; external CLibCrypto;
procedure ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl; external CLibCrypto;
function ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; cdecl; external CLibCrypto;
function ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; cdecl; external CLibCrypto;
function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_do_sign(const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl; external CLibCrypto;
function ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl; external CLibCrypto;
function ECDSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_sign_ex(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_size(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_EC_GFp_simple_method: PEC_METHOD; cdecl;
function Load_EC_GFp_mont_method: PEC_METHOD; cdecl;
function Load_EC_GFp_nist_method: PEC_METHOD; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EC_GFp_nistp224_method: PEC_METHOD; cdecl;
function Load_EC_GFp_nistp256_method: PEC_METHOD; cdecl;
function Load_EC_GFp_nistp521_method: PEC_METHOD; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EC_GF2m_simple_method: PEC_METHOD; cdecl;
function Load_EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; cdecl;
procedure Load_EC_GROUP_free(group: PEC_GROUP); cdecl;
procedure Load_EC_GROUP_clear_free(group: PEC_GROUP); cdecl;
function Load_EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP; cdecl;
function Load_EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP; cdecl;
function Load_EC_METHOD_get_field_type(const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; cdecl;
function Load_EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; cdecl;
function Load_EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; cdecl;
function Load_EC_GROUP_order_bits(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; cdecl;
procedure Load_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl;
function Load_EC_GROUP_get_curve_name(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
procedure Load_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl;
function Load_EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
procedure Load_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t); cdecl;
function Load_EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t; cdecl;
function Load_EC_GROUP_get0_seed(const x: PEC_GROUP): PByte; cdecl;
function Load_EC_GROUP_get_seed_len(const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl;
function Load_EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_degree(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
function Load_EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
function Load_EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
function Load_EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP; cdecl;
function Load_EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
function Load_EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP; cdecl;
function Load_EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;
function Load_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_EC_curve_nist2nid(const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_new(const group: PEC_GROUP): PEC_POINT; cdecl;
procedure Load_EC_POINT_free(point: PEC_POINT); cdecl;
procedure Load_EC_POINT_clear_free(point: PEC_POINT); cdecl;
function Load_EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl;
function Load_EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD; cdecl;
function Load_EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
function Load_EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
function Load_EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
function Load_EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl;
function Load_EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl;
function Load_EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl;
function Load_EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINTs_make_affine(const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
function Load_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
procedure Load_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
function Load_ECPARAMETERS_it: PASN1_ITEM; cdecl;
function Load_ECPARAMETERS_new: PECPARAMETERS; cdecl;
procedure Load_ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
function Load_EC_GROUP_get_basis_type(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl;
function Load_i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_new: PEC_KEY; cdecl;
function Load_EC_KEY_get_flags(const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
procedure Load_EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
procedure Load_EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
function Load_EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
procedure Load_EC_KEY_free(key: PEC_KEY); cdecl;
function Load_EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl;
function Load_EC_KEY_dup(const src: PEC_KEY): PEC_KEY; cdecl;
function Load_EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; cdecl;
function Load_EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; cdecl;
function Load_EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; cdecl;
function Load_EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; cdecl;
function Load_EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_get_enc_flags(const key: PEC_KEY): TOpenSSL_C_UINT; cdecl;
procedure Load_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl;
function Load_EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t; cdecl;
procedure Load_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl;
function Load_EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_get_ex_data(const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl;
procedure Load_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl;
function Load_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_check_key(const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_can_sign(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
function Load_EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl;
function Load_d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl;
function Load_i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl;
function Load_i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_ECParameters_print(bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl;
function Load_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl;
procedure Load_EC_KEY_set_default_method(const meth: PEC_KEY_METHOD); cdecl;
function Load_EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD; cdecl;
function Load_EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl;
function Load_ECDH_KDF_X9_62(out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_ECDH_compute_key(out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_SIG_new: PECDSA_SIG; cdecl;
procedure Load_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
function Load_i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl;
procedure Load_ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
function Load_ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; cdecl;
function Load_ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; cdecl;
function Load_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_do_sign(const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl;
function Load_ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
function Load_ECDSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_sign_ex(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_ECDSA_size(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
function Load_EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl;
procedure Load_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl;
procedure Load_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl;
procedure Load_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl;
procedure Load_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl;
procedure Load_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl;
procedure Load_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl;
procedure Load_EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl;
procedure Load_EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl;
procedure Load_EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl;
procedure Load_EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl;
procedure Load_EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl;

var
  EC_GFp_simple_method: function : PEC_METHOD; cdecl = Load_EC_GFp_simple_method;
  EC_GFp_mont_method: function : PEC_METHOD; cdecl = Load_EC_GFp_mont_method;
  EC_GFp_nist_method: function : PEC_METHOD; cdecl = Load_EC_GFp_nist_method;
  EC_GF2m_simple_method: function : PEC_METHOD; cdecl = Load_EC_GF2m_simple_method;
  EC_GROUP_new: function (const meth: PEC_METHOD): PEC_GROUP; cdecl = Load_EC_GROUP_new;
  EC_GROUP_free: procedure (group: PEC_GROUP); cdecl = Load_EC_GROUP_free;
  EC_GROUP_clear_free: procedure (group: PEC_GROUP); cdecl = Load_EC_GROUP_clear_free;
  EC_GROUP_copy: function (dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_copy;
  EC_GROUP_dup: function (const src: PEC_GROUP): PEC_GROUP; cdecl = Load_EC_GROUP_dup;
  EC_GROUP_method_of: function (const group: PEC_GROUP): PEC_GROUP; cdecl = Load_EC_GROUP_method_of;
  EC_METHOD_get_field_type: function (const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl = Load_EC_METHOD_get_field_type;
  EC_GROUP_set_generator: function (group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_generator;
  EC_GROUP_get0_generator: function (const group: PEC_GROUP): PEC_POINT; cdecl = Load_EC_GROUP_get0_generator;
  EC_GROUP_get_mont_data: function (const group: PEC_GROUP): PBN_MONT_CTX; cdecl = Load_EC_GROUP_get_mont_data;
  EC_GROUP_get_order: function (const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_order;
  EC_GROUP_get0_order: function (const group: PEC_GROUP): PBIGNUM; cdecl = Load_EC_GROUP_get0_order;
  EC_GROUP_order_bits: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_order_bits;
  EC_GROUP_get_cofactor: function (const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_cofactor;
  EC_GROUP_get0_cofactor: function (const group: PEC_GROUP): PBIGNUM; cdecl = Load_EC_GROUP_get0_cofactor;
  EC_GROUP_set_curve_name: procedure (group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl = Load_EC_GROUP_set_curve_name;
  EC_GROUP_get_curve_name: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve_name;
  EC_GROUP_set_asn1_flag: procedure (group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl = Load_EC_GROUP_set_asn1_flag;
  EC_GROUP_get_asn1_flag: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_asn1_flag;
  EC_GROUP_set_point_conversion_form: procedure (group: PEC_GROUP; form: point_conversion_form_t); cdecl = Load_EC_GROUP_set_point_conversion_form;
  EC_GROUP_get_point_conversion_form: function (const group: PEC_GROUP): point_conversion_form_t; cdecl = Load_EC_GROUP_get_point_conversion_form;
  EC_GROUP_get0_seed: function (const x: PEC_GROUP): PByte; cdecl = Load_EC_GROUP_get0_seed;
  EC_GROUP_get_seed_len: function (const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl = Load_EC_GROUP_get_seed_len;
  EC_GROUP_set_seed: function (x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_EC_GROUP_set_seed;
  EC_GROUP_set_curve: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_curve;
  EC_GROUP_get_curve: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve;
  EC_GROUP_set_curve_GFp: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_curve_GFp;
  EC_GROUP_get_curve_GFp: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve_GFp;
  EC_GROUP_set_curve_GF2m: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_set_curve_GF2m;
  EC_GROUP_get_curve_GF2m: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_curve_GF2m;
  EC_GROUP_get_degree: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_degree;
  EC_GROUP_check: function (const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_check;
  EC_GROUP_check_discriminant: function (const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_check_discriminant;
  EC_GROUP_cmp: function (const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_cmp;
  EC_GROUP_new_curve_GFp: function (const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = Load_EC_GROUP_new_curve_GFp;
  EC_GROUP_new_curve_GF2m: function (const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = Load_EC_GROUP_new_curve_GF2m;
  EC_GROUP_new_by_curve_name: function (nid: TOpenSSL_C_INT): PEC_GROUP; cdecl = Load_EC_GROUP_new_by_curve_name;
  EC_GROUP_new_from_ecparameters: function (const params: PECPARAMETERS): PEC_GROUP; cdecl = Load_EC_GROUP_new_from_ecparameters;
  EC_GROUP_get_ecparameters: function (const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl = Load_EC_GROUP_get_ecparameters;
  EC_GROUP_new_from_ecpkparameters: function (const params: PECPKPARAMETERS): PEC_GROUP; cdecl = Load_EC_GROUP_new_from_ecpkparameters;
  EC_GROUP_get_ecpkparameters: function (const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl = Load_EC_GROUP_get_ecpkparameters;
  EC_get_builtin_curves: function (r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_EC_get_builtin_curves;
  EC_curve_nid2nist: function (nid: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_EC_curve_nid2nist;
  EC_curve_nist2nid: function (const name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EC_curve_nist2nid;
  EC_POINT_new: function (const group: PEC_GROUP): PEC_POINT; cdecl = Load_EC_POINT_new;
  EC_POINT_free: procedure (point: PEC_POINT); cdecl = Load_EC_POINT_free;
  EC_POINT_clear_free: procedure (point: PEC_POINT); cdecl = Load_EC_POINT_clear_free;
  EC_POINT_copy: function (dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_POINT_copy;
  EC_POINT_dup: function (const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl = Load_EC_POINT_dup;
  EC_POINT_method_of: function (const point: PEC_POINT): PEC_METHOD; cdecl = Load_EC_POINT_method_of;
  EC_POINT_set_to_infinity: function (const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_to_infinity;
  EC_POINT_set_Jprojective_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_Jprojective_coordinates_GFp;
  EC_POINT_get_Jprojective_coordinates_GFp: function (const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_Jprojective_coordinates_GFp;
  EC_POINT_set_affine_coordinates: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_affine_coordinates;
  EC_POINT_get_affine_coordinates: function (const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_affine_coordinates;
  EC_POINT_set_affine_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_affine_coordinates_GFp;
  EC_POINT_get_affine_coordinates_GFp: function (const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_affine_coordinates_GFp;
  EC_POINT_set_compressed_coordinates: function (const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_compressed_coordinates;
  EC_POINT_set_compressed_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_compressed_coordinates_GFp;
  EC_POINT_set_affine_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_affine_coordinates_GF2m;
  EC_POINT_get_affine_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_get_affine_coordinates_GF2m;
  EC_POINT_set_compressed_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_set_compressed_coordinates_GF2m;
  EC_POINT_point2oct: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = Load_EC_POINT_point2oct;
  EC_POINT_oct2point: function (const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_oct2point;
  EC_POINT_point2buf: function (const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = Load_EC_POINT_point2buf;
  EC_POINT_point2bn: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = Load_EC_POINT_point2bn;
  EC_POINT_bn2point: function (const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl = Load_EC_POINT_bn2point;
  EC_POINT_point2hex: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl = Load_EC_POINT_point2hex;
  EC_POINT_hex2point: function (const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl = Load_EC_POINT_hex2point;
  EC_POINT_add: function (const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_add;
  EC_POINT_dbl: function (const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_dbl;
  EC_POINT_invert: function (const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_invert;
  EC_POINT_is_at_infinity: function (const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_POINT_is_at_infinity;
  EC_POINT_is_on_curve: function (const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_is_on_curve;
  EC_POINT_cmp: function (const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_cmp;
  EC_POINT_make_affine: function (const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_make_affine;
  EC_POINTs_make_affine: function (const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINTs_make_affine;
  EC_POINTs_mul: function (const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINTs_mul;
  EC_POINT_mul: function (const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_POINT_mul;
  EC_GROUP_precompute_mult: function (group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_precompute_mult;
  EC_GROUP_have_precompute_mult: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_have_precompute_mult;
  ECPKPARAMETERS_it: function : PASN1_ITEM; cdecl = Load_ECPKPARAMETERS_it;
  ECPKPARAMETERS_new: function : PECPKPARAMETERS; cdecl = Load_ECPKPARAMETERS_new;
  ECPKPARAMETERS_free: procedure (a: PECPKPARAMETERS); cdecl = Load_ECPKPARAMETERS_free;
  ECPARAMETERS_it: function : PASN1_ITEM; cdecl = Load_ECPARAMETERS_it;
  ECPARAMETERS_new: function : PECPARAMETERS; cdecl = Load_ECPARAMETERS_new;
  ECPARAMETERS_free: procedure (a: PECPARAMETERS); cdecl = Load_ECPARAMETERS_free;
  EC_GROUP_get_basis_type: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_basis_type;
  EC_GROUP_get_trinomial_basis: function (const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_trinomial_basis;
  EC_GROUP_get_pentanomial_basis: function (const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EC_GROUP_get_pentanomial_basis;
  d2i_ECPKParameters: function (group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl = Load_d2i_ECPKParameters;
  i2d_ECPKParameters: function (const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ECPKParameters;
  ECPKParameters_print: function (bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ECPKParameters_print;
  EC_KEY_new: function : PEC_KEY; cdecl = Load_EC_KEY_new;
  EC_KEY_get_flags: function (const key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_get_flags;
  EC_KEY_set_flags: procedure (key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl = Load_EC_KEY_set_flags;
  EC_KEY_clear_flags: procedure (key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl = Load_EC_KEY_clear_flags;
  EC_KEY_new_by_curve_name: function (nid: TOpenSSL_C_INT): PEC_KEY; cdecl = Load_EC_KEY_new_by_curve_name;
  EC_KEY_free: procedure (key: PEC_KEY); cdecl = Load_EC_KEY_free;
  EC_KEY_copy: function (dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl = Load_EC_KEY_copy;
  EC_KEY_dup: function (const src: PEC_KEY): PEC_KEY; cdecl = Load_EC_KEY_dup;
  EC_KEY_up_ref: function (key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_up_ref;
  EC_KEY_get0_engine: function (const eckey: PEC_KEY): PENGINE; cdecl = Load_EC_KEY_get0_engine;
  EC_KEY_get0_group: function (const key: PEC_KEY): PEC_GROUP; cdecl = Load_EC_KEY_get0_group;
  EC_KEY_set_group: function (key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_group;
  EC_KEY_get0_private_key: function (const key: PEC_KEY): PBIGNUM; cdecl = Load_EC_KEY_get0_private_key;
  EC_KEY_set_private_key: function (const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_private_key;
  EC_KEY_get0_public_key: function (const key: PEC_KEY): PEC_POINT; cdecl = Load_EC_KEY_get0_public_key;
  EC_KEY_set_public_key: function (key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_public_key;
  EC_KEY_get_enc_flags: function (const key: PEC_KEY): TOpenSSL_C_UINT; cdecl = Load_EC_KEY_get_enc_flags;
  EC_KEY_set_enc_flags: procedure (eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl = Load_EC_KEY_set_enc_flags;
  EC_KEY_get_conv_form: function (const key: PEC_KEY): point_conversion_form_t; cdecl = Load_EC_KEY_get_conv_form;
  EC_KEY_set_conv_form: procedure (eckey: PEC_KEY; cform: point_conversion_form_t); cdecl = Load_EC_KEY_set_conv_form;
  EC_KEY_set_ex_data: function (key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_ex_data;
  EC_KEY_get_ex_data: function (const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_EC_KEY_get_ex_data;
  EC_KEY_set_asn1_flag: procedure (eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl = Load_EC_KEY_set_asn1_flag;
  EC_KEY_precompute_mult: function (key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_KEY_precompute_mult;
  EC_KEY_generate_key: function (key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_generate_key;
  EC_KEY_check_key: function (const key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_check_key;
  EC_KEY_can_sign: function (const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_EC_KEY_can_sign;
  EC_KEY_set_public_key_affine_coordinates: function (key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_public_key_affine_coordinates;
  EC_KEY_key2buf: function (const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = Load_EC_KEY_key2buf;
  EC_KEY_oct2key: function (key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_EC_KEY_oct2key;
  EC_KEY_oct2priv: function (key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EC_KEY_oct2priv;
  EC_KEY_priv2oct: function (const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_EC_KEY_priv2oct;
  EC_KEY_priv2buf: function (const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl = Load_EC_KEY_priv2buf;
  d2i_ECPrivateKey: function (key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl = Load_d2i_ECPrivateKey;
  i2d_ECPrivateKey: function (key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ECPrivateKey;
  o2i_ECPublicKey: function (key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl = Load_o2i_ECPublicKey;
  i2o_ECPublicKey: function (const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2o_ECPublicKey;
  ECParameters_print: function (bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECParameters_print;
  EC_KEY_print: function (bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EC_KEY_print;
  EC_KEY_OpenSSL: function : PEC_KEY_METHOD; cdecl = Load_EC_KEY_OpenSSL;
  EC_KEY_get_default_method: function : PEC_KEY_METHOD; cdecl = Load_EC_KEY_get_default_method;
  EC_KEY_set_default_method: procedure (const meth: PEC_KEY_METHOD); cdecl = Load_EC_KEY_set_default_method;
  EC_KEY_get_method: function (const key: PEC_KEY): PEC_KEY_METHOD; cdecl = Load_EC_KEY_get_method;
  EC_KEY_set_method: function (key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl = Load_EC_KEY_set_method;
  EC_KEY_new_method: function (engine: PENGINE): PEC_KEY; cdecl = Load_EC_KEY_new_method;
  ECDH_KDF_X9_62: function (out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_ECDH_KDF_X9_62;
  ECDH_compute_key: function (out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl = Load_ECDH_compute_key;
  ECDSA_SIG_new: function : PECDSA_SIG; cdecl = Load_ECDSA_SIG_new;
  ECDSA_SIG_free: procedure (sig: PECDSA_SIG); cdecl = Load_ECDSA_SIG_free;
  i2d_ECDSA_SIG: function (const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ECDSA_SIG;
  d2i_ECDSA_SIG: function (sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl = Load_d2i_ECDSA_SIG;
  ECDSA_SIG_get0: procedure (const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl = Load_ECDSA_SIG_get0;
  ECDSA_SIG_get0_r: function (const sig: PECDSA_SIG): PBIGNUM; cdecl = Load_ECDSA_SIG_get0_r;
  ECDSA_SIG_get0_s: function (const sig: PECDSA_SIG): PBIGNUM; cdecl = Load_ECDSA_SIG_get0_s;
  ECDSA_SIG_set0: function (sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_ECDSA_SIG_set0;
  ECDSA_do_sign: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl = Load_ECDSA_do_sign;
  ECDSA_do_sign_ex: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl = Load_ECDSA_do_sign_ex;
  ECDSA_do_verify: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_do_verify;
  ECDSA_sign_setup: function (eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_ECDSA_sign_setup;
  ECDSA_sign: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_sign;
  ECDSA_sign_ex: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_sign_ex;
  ECDSA_verify: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_verify;
  ECDSA_size: function (const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = Load_ECDSA_size;
  EC_KEY_METHOD_new: function (const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl = Load_EC_KEY_METHOD_new;
  EC_KEY_METHOD_free: procedure (meth: PEC_KEY_METHOD); cdecl = Load_EC_KEY_METHOD_free;
  EC_KEY_METHOD_set_init: procedure (meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl = Load_EC_KEY_METHOD_set_init;
  EC_KEY_METHOD_set_keygen: procedure (meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl = Load_EC_KEY_METHOD_set_keygen;
  EC_KEY_METHOD_set_compute_key: procedure (meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl = Load_EC_KEY_METHOD_set_compute_key;
  EC_KEY_METHOD_set_sign: procedure (meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl = Load_EC_KEY_METHOD_set_sign;
  EC_KEY_METHOD_set_verify: procedure (meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl = Load_EC_KEY_METHOD_set_verify;
  EC_KEY_METHOD_get_init: procedure (const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl = Load_EC_KEY_METHOD_get_init;
  EC_KEY_METHOD_get_keygen: procedure (const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl = Load_EC_KEY_METHOD_get_keygen;
  EC_KEY_METHOD_get_compute_key: procedure (const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl = Load_EC_KEY_METHOD_get_compute_key;
  EC_KEY_METHOD_get_sign: procedure (const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl = Load_EC_KEY_METHOD_get_sign;
  EC_KEY_METHOD_get_verify: procedure (const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl = Load_EC_KEY_METHOD_get_verify;
{$ENDIF}
const
  EC_GFp_nistp224_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GFp_nistp224_method_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EC_GFp_nistp256_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GFp_nistp256_method_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EC_GFp_nistp521_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GFp_nistp521_method_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EC_GROUP_get0_order_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_order_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get0_cofactor_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_set_curve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get_curve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_new_from_ecparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get_ecparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_new_from_ecpkparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get_ecpkparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_set_affine_coordinates_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_get_affine_coordinates_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_set_compressed_coordinates_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_point2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get0_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_set_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_can_sign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_key2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_oct2key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_oct2priv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_priv2oct_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_priv2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_OpenSSL_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get_default_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_set_default_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_set_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_new_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_get0_r_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_get0_s_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_set0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_keygen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_sign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_keygen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_sign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  EC_GFp_nistp224_method: function : PEC_METHOD; cdecl = Load_EC_GFp_nistp224_method; {removed 3.0.0}
  EC_GFp_nistp256_method: function : PEC_METHOD; cdecl = Load_EC_GFp_nistp256_method; {removed 3.0.0}
  EC_GFp_nistp521_method: function : PEC_METHOD; cdecl = Load_EC_GFp_nistp521_method; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_EC_GFp_simple_method: PEC_METHOD; cdecl;
begin
  EC_GFp_simple_method := LoadLibCryptoFunction('EC_GFp_simple_method');
  if not assigned(EC_GFp_simple_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_simple_method');
  Result := EC_GFp_simple_method();
end;

function Load_EC_GFp_mont_method: PEC_METHOD; cdecl;
begin
  EC_GFp_mont_method := LoadLibCryptoFunction('EC_GFp_mont_method');
  if not assigned(EC_GFp_mont_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_mont_method');
  Result := EC_GFp_mont_method();
end;

function Load_EC_GFp_nist_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nist_method := LoadLibCryptoFunction('EC_GFp_nist_method');
  if not assigned(EC_GFp_nist_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nist_method');
  Result := EC_GFp_nist_method();
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_EC_GFp_nistp224_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nistp224_method := LoadLibCryptoFunction('EC_GFp_nistp224_method');
  if not assigned(EC_GFp_nistp224_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp224_method');
  Result := EC_GFp_nistp224_method();
end;

function Load_EC_GFp_nistp256_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nistp256_method := LoadLibCryptoFunction('EC_GFp_nistp256_method');
  if not assigned(EC_GFp_nistp256_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp256_method');
  Result := EC_GFp_nistp256_method();
end;

function Load_EC_GFp_nistp521_method: PEC_METHOD; cdecl;
begin
  EC_GFp_nistp521_method := LoadLibCryptoFunction('EC_GFp_nistp521_method');
  if not assigned(EC_GFp_nistp521_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp521_method');
  Result := EC_GFp_nistp521_method();
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_EC_GF2m_simple_method: PEC_METHOD; cdecl;
begin
  EC_GF2m_simple_method := LoadLibCryptoFunction('EC_GF2m_simple_method');
  if not assigned(EC_GF2m_simple_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GF2m_simple_method');
  Result := EC_GF2m_simple_method();
end;

function Load_EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; cdecl;
begin
  EC_GROUP_new := LoadLibCryptoFunction('EC_GROUP_new');
  if not assigned(EC_GROUP_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new');
  Result := EC_GROUP_new(meth);
end;

procedure Load_EC_GROUP_free(group: PEC_GROUP); cdecl;
begin
  EC_GROUP_free := LoadLibCryptoFunction('EC_GROUP_free');
  if not assigned(EC_GROUP_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_free');
  EC_GROUP_free(group);
end;

procedure Load_EC_GROUP_clear_free(group: PEC_GROUP); cdecl;
begin
  EC_GROUP_clear_free := LoadLibCryptoFunction('EC_GROUP_clear_free');
  if not assigned(EC_GROUP_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_clear_free');
  EC_GROUP_clear_free(group);
end;

function Load_EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_copy := LoadLibCryptoFunction('EC_GROUP_copy');
  if not assigned(EC_GROUP_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_copy');
  Result := EC_GROUP_copy(dst,src);
end;

function Load_EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP; cdecl;
begin
  EC_GROUP_dup := LoadLibCryptoFunction('EC_GROUP_dup');
  if not assigned(EC_GROUP_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_dup');
  Result := EC_GROUP_dup(src);
end;

function Load_EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP; cdecl;
begin
  EC_GROUP_method_of := LoadLibCryptoFunction('EC_GROUP_method_of');
  if not assigned(EC_GROUP_method_of) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_method_of');
  Result := EC_GROUP_method_of(group);
end;

function Load_EC_METHOD_get_field_type(const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EC_METHOD_get_field_type := LoadLibCryptoFunction('EC_METHOD_get_field_type');
  if not assigned(EC_METHOD_get_field_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_METHOD_get_field_type');
  Result := EC_METHOD_get_field_type(meth);
end;

function Load_EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_generator := LoadLibCryptoFunction('EC_GROUP_set_generator');
  if not assigned(EC_GROUP_set_generator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_generator');
  Result := EC_GROUP_set_generator(group,generator,order,cofactor);
end;

function Load_EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EC_GROUP_get0_generator := LoadLibCryptoFunction('EC_GROUP_get0_generator');
  if not assigned(EC_GROUP_get0_generator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_generator');
  Result := EC_GROUP_get0_generator(group);
end;

function Load_EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; cdecl;
begin
  EC_GROUP_get_mont_data := LoadLibCryptoFunction('EC_GROUP_get_mont_data');
  if not assigned(EC_GROUP_get_mont_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_mont_data');
  Result := EC_GROUP_get_mont_data(group);
end;

function Load_EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_order := LoadLibCryptoFunction('EC_GROUP_get_order');
  if not assigned(EC_GROUP_get_order) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_order');
  Result := EC_GROUP_get_order(group,order,ctx);
end;

function Load_EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EC_GROUP_get0_order := LoadLibCryptoFunction('EC_GROUP_get0_order');
  if not assigned(EC_GROUP_get0_order) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_order');
  Result := EC_GROUP_get0_order(group);
end;

function Load_EC_GROUP_order_bits(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_order_bits := LoadLibCryptoFunction('EC_GROUP_order_bits');
  if not assigned(EC_GROUP_order_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_order_bits');
  Result := EC_GROUP_order_bits(group);
end;

function Load_EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_cofactor := LoadLibCryptoFunction('EC_GROUP_get_cofactor');
  if not assigned(EC_GROUP_get_cofactor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_cofactor');
  Result := EC_GROUP_get_cofactor(group,cofactor,ctx);
end;

function Load_EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EC_GROUP_get0_cofactor := LoadLibCryptoFunction('EC_GROUP_get0_cofactor');
  if not assigned(EC_GROUP_get0_cofactor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_cofactor');
  Result := EC_GROUP_get0_cofactor(group);
end;

procedure Load_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl;
begin
  EC_GROUP_set_curve_name := LoadLibCryptoFunction('EC_GROUP_set_curve_name');
  if not assigned(EC_GROUP_set_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_name');
  EC_GROUP_set_curve_name(group,nid);
end;

function Load_EC_GROUP_get_curve_name(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve_name := LoadLibCryptoFunction('EC_GROUP_get_curve_name');
  if not assigned(EC_GROUP_get_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_name');
  Result := EC_GROUP_get_curve_name(group);
end;

procedure Load_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl;
begin
  EC_GROUP_set_asn1_flag := LoadLibCryptoFunction('EC_GROUP_set_asn1_flag');
  if not assigned(EC_GROUP_set_asn1_flag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_asn1_flag');
  EC_GROUP_set_asn1_flag(group,flag);
end;

function Load_EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_asn1_flag := LoadLibCryptoFunction('EC_GROUP_get_asn1_flag');
  if not assigned(EC_GROUP_get_asn1_flag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_asn1_flag');
  Result := EC_GROUP_get_asn1_flag(group);
end;

procedure Load_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t); cdecl;
begin
  EC_GROUP_set_point_conversion_form := LoadLibCryptoFunction('EC_GROUP_set_point_conversion_form');
  if not assigned(EC_GROUP_set_point_conversion_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_point_conversion_form');
  EC_GROUP_set_point_conversion_form(group,form);
end;

function Load_EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t; cdecl;
begin
  EC_GROUP_get_point_conversion_form := LoadLibCryptoFunction('EC_GROUP_get_point_conversion_form');
  if not assigned(EC_GROUP_get_point_conversion_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_point_conversion_form');
  Result := EC_GROUP_get_point_conversion_form(group);
end;

function Load_EC_GROUP_get0_seed(const x: PEC_GROUP): PByte; cdecl;
begin
  EC_GROUP_get0_seed := LoadLibCryptoFunction('EC_GROUP_get0_seed');
  if not assigned(EC_GROUP_get0_seed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_seed');
  Result := EC_GROUP_get0_seed(x);
end;

function Load_EC_GROUP_get_seed_len(const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl;
begin
  EC_GROUP_get_seed_len := LoadLibCryptoFunction('EC_GROUP_get_seed_len');
  if not assigned(EC_GROUP_get_seed_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_seed_len');
  Result := EC_GROUP_get_seed_len(x);
end;

function Load_EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EC_GROUP_set_seed := LoadLibCryptoFunction('EC_GROUP_set_seed');
  if not assigned(EC_GROUP_set_seed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_seed');
  Result := EC_GROUP_set_seed(x,p,len);
end;

function Load_EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_curve := LoadLibCryptoFunction('EC_GROUP_set_curve');
  if not assigned(EC_GROUP_set_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve');
  Result := EC_GROUP_set_curve(group,p,a,b,ctx);
end;

function Load_EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve := LoadLibCryptoFunction('EC_GROUP_get_curve');
  if not assigned(EC_GROUP_get_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve');
  Result := EC_GROUP_get_curve(group,p,a,b,ctx);
end;

function Load_EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_curve_GFp := LoadLibCryptoFunction('EC_GROUP_set_curve_GFp');
  if not assigned(EC_GROUP_set_curve_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_GFp');
  Result := EC_GROUP_set_curve_GFp(group,p,a,b,ctx);
end;

function Load_EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve_GFp := LoadLibCryptoFunction('EC_GROUP_get_curve_GFp');
  if not assigned(EC_GROUP_get_curve_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_GFp');
  Result := EC_GROUP_get_curve_GFp(group,p,a,b,ctx);
end;

function Load_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_set_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_set_curve_GF2m');
  if not assigned(EC_GROUP_set_curve_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_GF2m');
  Result := EC_GROUP_set_curve_GF2m(group,p,a,b,ctx);
end;

function Load_EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_get_curve_GF2m');
  if not assigned(EC_GROUP_get_curve_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_GF2m');
  Result := EC_GROUP_get_curve_GF2m(group,p,a,ctx);
end;

function Load_EC_GROUP_get_degree(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_degree := LoadLibCryptoFunction('EC_GROUP_get_degree');
  if not assigned(EC_GROUP_get_degree) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_degree');
  Result := EC_GROUP_get_degree(group);
end;

function Load_EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_check := LoadLibCryptoFunction('EC_GROUP_check');
  if not assigned(EC_GROUP_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check');
  Result := EC_GROUP_check(group,ctx);
end;

function Load_EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_check_discriminant := LoadLibCryptoFunction('EC_GROUP_check_discriminant');
  if not assigned(EC_GROUP_check_discriminant) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check_discriminant');
  Result := EC_GROUP_check_discriminant(group,ctx);
end;

function Load_EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_cmp := LoadLibCryptoFunction('EC_GROUP_cmp');
  if not assigned(EC_GROUP_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_cmp');
  Result := EC_GROUP_cmp(a,b,ctx);
end;

function Load_EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_curve_GFp := LoadLibCryptoFunction('EC_GROUP_new_curve_GFp');
  if not assigned(EC_GROUP_new_curve_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_curve_GFp');
  Result := EC_GROUP_new_curve_GFp(p,a,b,ctx);
end;

function Load_EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_new_curve_GF2m');
  if not assigned(EC_GROUP_new_curve_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_curve_GF2m');
  Result := EC_GROUP_new_curve_GF2m(p,a,b,ctx);
end;

function Load_EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_by_curve_name := LoadLibCryptoFunction('EC_GROUP_new_by_curve_name');
  if not assigned(EC_GROUP_new_by_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_by_curve_name');
  Result := EC_GROUP_new_by_curve_name(nid);
end;

function Load_EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_from_ecparameters := LoadLibCryptoFunction('EC_GROUP_new_from_ecparameters');
  if not assigned(EC_GROUP_new_from_ecparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_ecparameters');
  Result := EC_GROUP_new_from_ecparameters(params);
end;

function Load_EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
begin
  EC_GROUP_get_ecparameters := LoadLibCryptoFunction('EC_GROUP_get_ecparameters');
  if not assigned(EC_GROUP_get_ecparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_ecparameters');
  Result := EC_GROUP_get_ecparameters(group,params);
end;

function Load_EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP; cdecl;
begin
  EC_GROUP_new_from_ecpkparameters := LoadLibCryptoFunction('EC_GROUP_new_from_ecpkparameters');
  if not assigned(EC_GROUP_new_from_ecpkparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_ecpkparameters');
  Result := EC_GROUP_new_from_ecpkparameters(params);
end;

function Load_EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;
begin
  EC_GROUP_get_ecpkparameters := LoadLibCryptoFunction('EC_GROUP_get_ecpkparameters');
  if not assigned(EC_GROUP_get_ecpkparameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_ecpkparameters');
  Result := EC_GROUP_get_ecpkparameters(group,params);
end;

function Load_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EC_get_builtin_curves := LoadLibCryptoFunction('EC_get_builtin_curves');
  if not assigned(EC_get_builtin_curves) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_get_builtin_curves');
  Result := EC_get_builtin_curves(r,nitems);
end;

function Load_EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EC_curve_nid2nist := LoadLibCryptoFunction('EC_curve_nid2nist');
  if not assigned(EC_curve_nid2nist) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_curve_nid2nist');
  Result := EC_curve_nid2nist(nid);
end;

function Load_EC_curve_nist2nid(const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EC_curve_nist2nid := LoadLibCryptoFunction('EC_curve_nist2nid');
  if not assigned(EC_curve_nist2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_curve_nist2nid');
  Result := EC_curve_nist2nid(name);
end;

function Load_EC_POINT_new(const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EC_POINT_new := LoadLibCryptoFunction('EC_POINT_new');
  if not assigned(EC_POINT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_new');
  Result := EC_POINT_new(group);
end;

procedure Load_EC_POINT_free(point: PEC_POINT); cdecl;
begin
  EC_POINT_free := LoadLibCryptoFunction('EC_POINT_free');
  if not assigned(EC_POINT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_free');
  EC_POINT_free(point);
end;

procedure Load_EC_POINT_clear_free(point: PEC_POINT); cdecl;
begin
  EC_POINT_clear_free := LoadLibCryptoFunction('EC_POINT_clear_free');
  if not assigned(EC_POINT_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_clear_free');
  EC_POINT_clear_free(point);
end;

function Load_EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_copy := LoadLibCryptoFunction('EC_POINT_copy');
  if not assigned(EC_POINT_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_copy');
  Result := EC_POINT_copy(dst,src);
end;

function Load_EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EC_POINT_dup := LoadLibCryptoFunction('EC_POINT_dup');
  if not assigned(EC_POINT_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_dup');
  Result := EC_POINT_dup(src,group);
end;

function Load_EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD; cdecl;
begin
  EC_POINT_method_of := LoadLibCryptoFunction('EC_POINT_method_of');
  if not assigned(EC_POINT_method_of) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_method_of');
  Result := EC_POINT_method_of(point);
end;

function Load_EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_to_infinity := LoadLibCryptoFunction('EC_POINT_set_to_infinity');
  if not assigned(EC_POINT_set_to_infinity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_to_infinity');
  Result := EC_POINT_set_to_infinity(group,point);
end;

function Load_EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_Jprojective_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_Jprojective_coordinates_GFp');
  if not assigned(EC_POINT_set_Jprojective_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_Jprojective_coordinates_GFp');
  Result := EC_POINT_set_Jprojective_coordinates_GFp(group,p,x,y,z,ctx);
end;

function Load_EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_Jprojective_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_get_Jprojective_coordinates_GFp');
  if not assigned(EC_POINT_get_Jprojective_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_Jprojective_coordinates_GFp');
  Result := EC_POINT_get_Jprojective_coordinates_GFp(group,p,x,y,z,ctx);
end;

function Load_EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_affine_coordinates := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates');
  if not assigned(EC_POINT_set_affine_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates');
  Result := EC_POINT_set_affine_coordinates(group,p,x,y,ctx);
end;

function Load_EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_affine_coordinates := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates');
  if not assigned(EC_POINT_get_affine_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates');
  Result := EC_POINT_get_affine_coordinates(group,p,x,y,ctx);
end;

function Load_EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_affine_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates_GFp');
  if not assigned(EC_POINT_set_affine_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates_GFp');
  Result := EC_POINT_set_affine_coordinates_GFp(group,p,x,y,ctx);
end;

function Load_EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_affine_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates_GFp');
  if not assigned(EC_POINT_get_affine_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates_GFp');
  Result := EC_POINT_get_affine_coordinates_GFp(group,p,x,y,ctx);
end;

function Load_EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_compressed_coordinates := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates');
  if not assigned(EC_POINT_set_compressed_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates');
  Result := EC_POINT_set_compressed_coordinates(group,p,x,y_bit,ctx);
end;

function Load_EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_compressed_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates_GFp');
  if not assigned(EC_POINT_set_compressed_coordinates_GFp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates_GFp');
  Result := EC_POINT_set_compressed_coordinates_GFp(group,p,x,y_bit,ctx);
end;

function Load_EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_affine_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates_GF2m');
  if not assigned(EC_POINT_set_affine_coordinates_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates_GF2m');
  Result := EC_POINT_set_affine_coordinates_GF2m(group,p,x,y,ctx);
end;

function Load_EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_get_affine_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates_GF2m');
  if not assigned(EC_POINT_get_affine_coordinates_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates_GF2m');
  Result := EC_POINT_get_affine_coordinates_GF2m(group,p,x,y,ctx);
end;

function Load_EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_set_compressed_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates_GF2m');
  if not assigned(EC_POINT_set_compressed_coordinates_GF2m) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates_GF2m');
  Result := EC_POINT_set_compressed_coordinates_GF2m(group,p,x,y_bit,ctx);
end;

function Load_EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EC_POINT_point2oct := LoadLibCryptoFunction('EC_POINT_point2oct');
  if not assigned(EC_POINT_point2oct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2oct');
  Result := EC_POINT_point2oct(group,p,form,buf,len,ctx);
end;

function Load_EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_oct2point := LoadLibCryptoFunction('EC_POINT_oct2point');
  if not assigned(EC_POINT_oct2point) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_oct2point');
  Result := EC_POINT_oct2point(group,p,buf,len,ctx);
end;

function Load_EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EC_POINT_point2buf := LoadLibCryptoFunction('EC_POINT_point2buf');
  if not assigned(EC_POINT_point2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2buf');
  Result := EC_POINT_point2buf(group,point,form,pbuf,ctx);
end;

function Load_EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  EC_POINT_point2bn := LoadLibCryptoFunction('EC_POINT_point2bn');
  if not assigned(EC_POINT_point2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2bn');
  Result := EC_POINT_point2bn(group,p,form,bn,ctx);
end;

function Load_EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl;
begin
  EC_POINT_bn2point := LoadLibCryptoFunction('EC_POINT_bn2point');
  if not assigned(EC_POINT_bn2point) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_bn2point');
  Result := EC_POINT_bn2point(group,bn,p,ctx);
end;

function Load_EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl;
begin
  EC_POINT_point2hex := LoadLibCryptoFunction('EC_POINT_point2hex');
  if not assigned(EC_POINT_point2hex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2hex');
  Result := EC_POINT_point2hex(group,p,form,ctx);
end;

function Load_EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl;
begin
  EC_POINT_hex2point := LoadLibCryptoFunction('EC_POINT_hex2point');
  if not assigned(EC_POINT_hex2point) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_hex2point');
  Result := EC_POINT_hex2point(group,buf,p,ctx);
end;

function Load_EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_add := LoadLibCryptoFunction('EC_POINT_add');
  if not assigned(EC_POINT_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_add');
  Result := EC_POINT_add(group,r,a,b,ctx);
end;

function Load_EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_dbl := LoadLibCryptoFunction('EC_POINT_dbl');
  if not assigned(EC_POINT_dbl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_dbl');
  Result := EC_POINT_dbl(group,r,a,ctx);
end;

function Load_EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_invert := LoadLibCryptoFunction('EC_POINT_invert');
  if not assigned(EC_POINT_invert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_invert');
  Result := EC_POINT_invert(group,a,ctx);
end;

function Load_EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_is_at_infinity := LoadLibCryptoFunction('EC_POINT_is_at_infinity');
  if not assigned(EC_POINT_is_at_infinity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_is_at_infinity');
  Result := EC_POINT_is_at_infinity(group,p);
end;

function Load_EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_is_on_curve := LoadLibCryptoFunction('EC_POINT_is_on_curve');
  if not assigned(EC_POINT_is_on_curve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_is_on_curve');
  Result := EC_POINT_is_on_curve(group,point,ctx);
end;

function Load_EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_cmp := LoadLibCryptoFunction('EC_POINT_cmp');
  if not assigned(EC_POINT_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_cmp');
  Result := EC_POINT_cmp(group,a,b,ctx);
end;

function Load_EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_make_affine := LoadLibCryptoFunction('EC_POINT_make_affine');
  if not assigned(EC_POINT_make_affine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_make_affine');
  Result := EC_POINT_make_affine(group,point,ctx);
end;

function Load_EC_POINTs_make_affine(const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINTs_make_affine := LoadLibCryptoFunction('EC_POINTs_make_affine');
  if not assigned(EC_POINTs_make_affine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINTs_make_affine');
  Result := EC_POINTs_make_affine(group,num,points,ctx);
end;

function Load_EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINTs_mul := LoadLibCryptoFunction('EC_POINTs_mul');
  if not assigned(EC_POINTs_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINTs_mul');
  Result := EC_POINTs_mul(group,r,n,num,p,m,ctx);
end;

function Load_EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_POINT_mul := LoadLibCryptoFunction('EC_POINT_mul');
  if not assigned(EC_POINT_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_mul');
  Result := EC_POINT_mul(group,r,n,q,m,ctx);
end;

function Load_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_precompute_mult := LoadLibCryptoFunction('EC_GROUP_precompute_mult');
  if not assigned(EC_GROUP_precompute_mult) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_precompute_mult');
  Result := EC_GROUP_precompute_mult(group,ctx);
end;

function Load_EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_have_precompute_mult := LoadLibCryptoFunction('EC_GROUP_have_precompute_mult');
  if not assigned(EC_GROUP_have_precompute_mult) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_have_precompute_mult');
  Result := EC_GROUP_have_precompute_mult(group);
end;

function Load_ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  ECPKPARAMETERS_it := LoadLibCryptoFunction('ECPKPARAMETERS_it');
  if not assigned(ECPKPARAMETERS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_it');
  Result := ECPKPARAMETERS_it();
end;

function Load_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
begin
  ECPKPARAMETERS_new := LoadLibCryptoFunction('ECPKPARAMETERS_new');
  if not assigned(ECPKPARAMETERS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_new');
  Result := ECPKPARAMETERS_new();
end;

procedure Load_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
begin
  ECPKPARAMETERS_free := LoadLibCryptoFunction('ECPKPARAMETERS_free');
  if not assigned(ECPKPARAMETERS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_free');
  ECPKPARAMETERS_free(a);
end;

function Load_ECPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  ECPARAMETERS_it := LoadLibCryptoFunction('ECPARAMETERS_it');
  if not assigned(ECPARAMETERS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_it');
  Result := ECPARAMETERS_it();
end;

function Load_ECPARAMETERS_new: PECPARAMETERS; cdecl;
begin
  ECPARAMETERS_new := LoadLibCryptoFunction('ECPARAMETERS_new');
  if not assigned(ECPARAMETERS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_new');
  Result := ECPARAMETERS_new();
end;

procedure Load_ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
begin
  ECPARAMETERS_free := LoadLibCryptoFunction('ECPARAMETERS_free');
  if not assigned(ECPARAMETERS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_free');
  ECPARAMETERS_free(a);
end;

function Load_EC_GROUP_get_basis_type(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_basis_type := LoadLibCryptoFunction('EC_GROUP_get_basis_type');
  if not assigned(EC_GROUP_get_basis_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_basis_type');
  Result := EC_GROUP_get_basis_type(group);
end;

function Load_EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_trinomial_basis := LoadLibCryptoFunction('EC_GROUP_get_trinomial_basis');
  if not assigned(EC_GROUP_get_trinomial_basis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_trinomial_basis');
  Result := EC_GROUP_get_trinomial_basis(group,k);
end;

function Load_EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EC_GROUP_get_pentanomial_basis := LoadLibCryptoFunction('EC_GROUP_get_pentanomial_basis');
  if not assigned(EC_GROUP_get_pentanomial_basis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_pentanomial_basis');
  Result := EC_GROUP_get_pentanomial_basis(group,k1,k2,k3);
end;

function Load_d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl;
begin
  d2i_ECPKParameters := LoadLibCryptoFunction('d2i_ECPKParameters');
  if not assigned(d2i_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPKParameters');
  Result := d2i_ECPKParameters(group,in_,len);
end;

function Load_i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECPKParameters := LoadLibCryptoFunction('i2d_ECPKParameters');
  if not assigned(i2d_ECPKParameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPKParameters');
  Result := i2d_ECPKParameters(group,out_);
end;

function Load_ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ECPKParameters_print := LoadLibCryptoFunction('ECPKParameters_print');
  if not assigned(ECPKParameters_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKParameters_print');
  Result := ECPKParameters_print(bp,x,off);
end;

function Load_EC_KEY_new: PEC_KEY; cdecl;
begin
  EC_KEY_new := LoadLibCryptoFunction('EC_KEY_new');
  if not assigned(EC_KEY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new');
  Result := EC_KEY_new();
end;

function Load_EC_KEY_get_flags(const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_get_flags := LoadLibCryptoFunction('EC_KEY_get_flags');
  if not assigned(EC_KEY_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_flags');
  Result := EC_KEY_get_flags(key);
end;

procedure Load_EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
begin
  EC_KEY_set_flags := LoadLibCryptoFunction('EC_KEY_set_flags');
  if not assigned(EC_KEY_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_flags');
  EC_KEY_set_flags(key,flags);
end;

procedure Load_EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
begin
  EC_KEY_clear_flags := LoadLibCryptoFunction('EC_KEY_clear_flags');
  if not assigned(EC_KEY_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_clear_flags');
  EC_KEY_clear_flags(key,flags);
end;

function Load_EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  EC_KEY_new_by_curve_name := LoadLibCryptoFunction('EC_KEY_new_by_curve_name');
  if not assigned(EC_KEY_new_by_curve_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_by_curve_name');
  Result := EC_KEY_new_by_curve_name(nid);
end;

procedure Load_EC_KEY_free(key: PEC_KEY); cdecl;
begin
  EC_KEY_free := LoadLibCryptoFunction('EC_KEY_free');
  if not assigned(EC_KEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_free');
  EC_KEY_free(key);
end;

function Load_EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl;
begin
  EC_KEY_copy := LoadLibCryptoFunction('EC_KEY_copy');
  if not assigned(EC_KEY_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_copy');
  Result := EC_KEY_copy(dst,src);
end;

function Load_EC_KEY_dup(const src: PEC_KEY): PEC_KEY; cdecl;
begin
  EC_KEY_dup := LoadLibCryptoFunction('EC_KEY_dup');
  if not assigned(EC_KEY_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_dup');
  Result := EC_KEY_dup(src);
end;

function Load_EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_up_ref := LoadLibCryptoFunction('EC_KEY_up_ref');
  if not assigned(EC_KEY_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_up_ref');
  Result := EC_KEY_up_ref(key);
end;

function Load_EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; cdecl;
begin
  EC_KEY_get0_engine := LoadLibCryptoFunction('EC_KEY_get0_engine');
  if not assigned(EC_KEY_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_engine');
  Result := EC_KEY_get0_engine(eckey);
end;

function Load_EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; cdecl;
begin
  EC_KEY_get0_group := LoadLibCryptoFunction('EC_KEY_get0_group');
  if not assigned(EC_KEY_get0_group) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_group');
  Result := EC_KEY_get0_group(key);
end;

function Load_EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_group := LoadLibCryptoFunction('EC_KEY_set_group');
  if not assigned(EC_KEY_set_group) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_group');
  Result := EC_KEY_set_group(key,group);
end;

function Load_EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; cdecl;
begin
  EC_KEY_get0_private_key := LoadLibCryptoFunction('EC_KEY_get0_private_key');
  if not assigned(EC_KEY_get0_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_private_key');
  Result := EC_KEY_get0_private_key(key);
end;

function Load_EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_private_key := LoadLibCryptoFunction('EC_KEY_set_private_key');
  if not assigned(EC_KEY_set_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_private_key');
  Result := EC_KEY_set_private_key(key,prv);
end;

function Load_EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; cdecl;
begin
  EC_KEY_get0_public_key := LoadLibCryptoFunction('EC_KEY_get0_public_key');
  if not assigned(EC_KEY_get0_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_public_key');
  Result := EC_KEY_get0_public_key(key);
end;

function Load_EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_public_key := LoadLibCryptoFunction('EC_KEY_set_public_key');
  if not assigned(EC_KEY_set_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_public_key');
  Result := EC_KEY_set_public_key(key,pub);
end;

function Load_EC_KEY_get_enc_flags(const key: PEC_KEY): TOpenSSL_C_UINT; cdecl;
begin
  EC_KEY_get_enc_flags := LoadLibCryptoFunction('EC_KEY_get_enc_flags');
  if not assigned(EC_KEY_get_enc_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_enc_flags');
  Result := EC_KEY_get_enc_flags(key);
end;

procedure Load_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl;
begin
  EC_KEY_set_enc_flags := LoadLibCryptoFunction('EC_KEY_set_enc_flags');
  if not assigned(EC_KEY_set_enc_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_enc_flags');
  EC_KEY_set_enc_flags(eckey,flags);
end;

function Load_EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t; cdecl;
begin
  EC_KEY_get_conv_form := LoadLibCryptoFunction('EC_KEY_get_conv_form');
  if not assigned(EC_KEY_get_conv_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_conv_form');
  Result := EC_KEY_get_conv_form(key);
end;

procedure Load_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl;
begin
  EC_KEY_set_conv_form := LoadLibCryptoFunction('EC_KEY_set_conv_form');
  if not assigned(EC_KEY_set_conv_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_conv_form');
  EC_KEY_set_conv_form(eckey,cform);
end;

function Load_EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_ex_data := LoadLibCryptoFunction('EC_KEY_set_ex_data');
  if not assigned(EC_KEY_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_ex_data');
  Result := EC_KEY_set_ex_data(key,idx,arg);
end;

function Load_EC_KEY_get_ex_data(const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EC_KEY_get_ex_data := LoadLibCryptoFunction('EC_KEY_get_ex_data');
  if not assigned(EC_KEY_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_ex_data');
  Result := EC_KEY_get_ex_data(key,idx);
end;

procedure Load_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl;
begin
  EC_KEY_set_asn1_flag := LoadLibCryptoFunction('EC_KEY_set_asn1_flag');
  if not assigned(EC_KEY_set_asn1_flag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_asn1_flag');
  EC_KEY_set_asn1_flag(eckey,asn1_flag);
end;

function Load_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_precompute_mult := LoadLibCryptoFunction('EC_KEY_precompute_mult');
  if not assigned(EC_KEY_precompute_mult) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_precompute_mult');
  Result := EC_KEY_precompute_mult(key,ctx);
end;

function Load_EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_generate_key := LoadLibCryptoFunction('EC_KEY_generate_key');
  if not assigned(EC_KEY_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_generate_key');
  Result := EC_KEY_generate_key(key);
end;

function Load_EC_KEY_check_key(const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_check_key := LoadLibCryptoFunction('EC_KEY_check_key');
  if not assigned(EC_KEY_check_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_check_key');
  Result := EC_KEY_check_key(key);
end;

function Load_EC_KEY_can_sign(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_can_sign := LoadLibCryptoFunction('EC_KEY_can_sign');
  if not assigned(EC_KEY_can_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_can_sign');
  Result := EC_KEY_can_sign(eckey);
end;

function Load_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_public_key_affine_coordinates := LoadLibCryptoFunction('EC_KEY_set_public_key_affine_coordinates');
  if not assigned(EC_KEY_set_public_key_affine_coordinates) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_public_key_affine_coordinates');
  Result := EC_KEY_set_public_key_affine_coordinates(key,x,y);
end;

function Load_EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EC_KEY_key2buf := LoadLibCryptoFunction('EC_KEY_key2buf');
  if not assigned(EC_KEY_key2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_key2buf');
  Result := EC_KEY_key2buf(key,form,pbuf,ctx);
end;

function Load_EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_oct2key := LoadLibCryptoFunction('EC_KEY_oct2key');
  if not assigned(EC_KEY_oct2key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_oct2key');
  Result := EC_KEY_oct2key(key,buf,len,ctx);
end;

function Load_EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_oct2priv := LoadLibCryptoFunction('EC_KEY_oct2priv');
  if not assigned(EC_KEY_oct2priv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_oct2priv');
  Result := EC_KEY_oct2priv(key,buf,len);
end;

function Load_EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EC_KEY_priv2oct := LoadLibCryptoFunction('EC_KEY_priv2oct');
  if not assigned(EC_KEY_priv2oct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_priv2oct');
  Result := EC_KEY_priv2oct(key,buf,len);
end;

function Load_EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EC_KEY_priv2buf := LoadLibCryptoFunction('EC_KEY_priv2buf');
  if not assigned(EC_KEY_priv2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_priv2buf');
  Result := EC_KEY_priv2buf(eckey,buf);
end;

function Load_d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl;
begin
  d2i_ECPrivateKey := LoadLibCryptoFunction('d2i_ECPrivateKey');
  if not assigned(d2i_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPrivateKey');
  Result := d2i_ECPrivateKey(key,in_,len);
end;

function Load_i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECPrivateKey := LoadLibCryptoFunction('i2d_ECPrivateKey');
  if not assigned(i2d_ECPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPrivateKey');
  Result := i2d_ECPrivateKey(key,out_);
end;

function Load_o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl;
begin
  o2i_ECPublicKey := LoadLibCryptoFunction('o2i_ECPublicKey');
  if not assigned(o2i_ECPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('o2i_ECPublicKey');
  Result := o2i_ECPublicKey(key,in_,len);
end;

function Load_i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2o_ECPublicKey := LoadLibCryptoFunction('i2o_ECPublicKey');
  if not assigned(i2o_ECPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2o_ECPublicKey');
  Result := i2o_ECPublicKey(key,out_);
end;

function Load_ECParameters_print(bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECParameters_print := LoadLibCryptoFunction('ECParameters_print');
  if not assigned(ECParameters_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECParameters_print');
  Result := ECParameters_print(bp,key);
end;

function Load_EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_print := LoadLibCryptoFunction('EC_KEY_print');
  if not assigned(EC_KEY_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_print');
  Result := EC_KEY_print(bp,key,off);
end;

function Load_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_OpenSSL := LoadLibCryptoFunction('EC_KEY_OpenSSL');
  if not assigned(EC_KEY_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_OpenSSL');
  Result := EC_KEY_OpenSSL();
end;

function Load_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_get_default_method := LoadLibCryptoFunction('EC_KEY_get_default_method');
  if not assigned(EC_KEY_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_default_method');
  Result := EC_KEY_get_default_method();
end;

procedure Load_EC_KEY_set_default_method(const meth: PEC_KEY_METHOD); cdecl;
begin
  EC_KEY_set_default_method := LoadLibCryptoFunction('EC_KEY_set_default_method');
  if not assigned(EC_KEY_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_default_method');
  EC_KEY_set_default_method(meth);
end;

function Load_EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_get_method := LoadLibCryptoFunction('EC_KEY_get_method');
  if not assigned(EC_KEY_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_method');
  Result := EC_KEY_get_method(key);
end;

function Load_EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EC_KEY_set_method := LoadLibCryptoFunction('EC_KEY_set_method');
  if not assigned(EC_KEY_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_method');
  Result := EC_KEY_set_method(key,meth);
end;

function Load_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl;
begin
  EC_KEY_new_method := LoadLibCryptoFunction('EC_KEY_new_method');
  if not assigned(EC_KEY_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_method');
  Result := EC_KEY_new_method(engine);
end;

function Load_ECDH_KDF_X9_62(out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  ECDH_KDF_X9_62 := LoadLibCryptoFunction('ECDH_KDF_X9_62');
  if not assigned(ECDH_KDF_X9_62) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDH_KDF_X9_62');
  Result := ECDH_KDF_X9_62(out_,outlen,Z,Zlen,sinfo,sinfolen,md);
end;

function Load_ECDH_compute_key(out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl;
begin
  ECDH_compute_key := LoadLibCryptoFunction('ECDH_compute_key');
  if not assigned(ECDH_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDH_compute_key');
  Result := ECDH_compute_key(out_,oulen,pub_key,ecdh,kdf);
end;

function Load_ECDSA_SIG_new: PECDSA_SIG; cdecl;
begin
  ECDSA_SIG_new := LoadLibCryptoFunction('ECDSA_SIG_new');
  if not assigned(ECDSA_SIG_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_new');
  Result := ECDSA_SIG_new();
end;

procedure Load_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
begin
  ECDSA_SIG_free := LoadLibCryptoFunction('ECDSA_SIG_free');
  if not assigned(ECDSA_SIG_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_free');
  ECDSA_SIG_free(sig);
end;

function Load_i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ECDSA_SIG := LoadLibCryptoFunction('i2d_ECDSA_SIG');
  if not assigned(i2d_ECDSA_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECDSA_SIG');
  Result := i2d_ECDSA_SIG(sig,pp);
end;

function Load_d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl;
begin
  d2i_ECDSA_SIG := LoadLibCryptoFunction('d2i_ECDSA_SIG');
  if not assigned(d2i_ECDSA_SIG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECDSA_SIG');
  Result := d2i_ECDSA_SIG(sig,pp,len);
end;

procedure Load_ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
begin
  ECDSA_SIG_get0 := LoadLibCryptoFunction('ECDSA_SIG_get0');
  if not assigned(ECDSA_SIG_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0');
  ECDSA_SIG_get0(sig,pr,ps);
end;

function Load_ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  ECDSA_SIG_get0_r := LoadLibCryptoFunction('ECDSA_SIG_get0_r');
  if not assigned(ECDSA_SIG_get0_r) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0_r');
  Result := ECDSA_SIG_get0_r(sig);
end;

function Load_ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  ECDSA_SIG_get0_s := LoadLibCryptoFunction('ECDSA_SIG_get0_s');
  if not assigned(ECDSA_SIG_get0_s) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0_s');
  Result := ECDSA_SIG_get0_s(sig);
end;

function Load_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_SIG_set0 := LoadLibCryptoFunction('ECDSA_SIG_set0');
  if not assigned(ECDSA_SIG_set0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_set0');
  Result := ECDSA_SIG_set0(sig,r,s);
end;

function Load_ECDSA_do_sign(const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  ECDSA_do_sign := LoadLibCryptoFunction('ECDSA_do_sign');
  if not assigned(ECDSA_do_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_sign');
  Result := ECDSA_do_sign(dgst,dgst_len,eckey);
end;

function Load_ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  ECDSA_do_sign_ex := LoadLibCryptoFunction('ECDSA_do_sign_ex');
  if not assigned(ECDSA_do_sign_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_sign_ex');
  Result := ECDSA_do_sign_ex(dgst,dgst_len,kinv,rp,eckey);
end;

function Load_ECDSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_do_verify := LoadLibCryptoFunction('ECDSA_do_verify');
  if not assigned(ECDSA_do_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_verify');
  Result := ECDSA_do_verify(dgst,dgst_len,sig,eckey);
end;

function Load_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_sign_setup := LoadLibCryptoFunction('ECDSA_sign_setup');
  if not assigned(ECDSA_sign_setup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign_setup');
  Result := ECDSA_sign_setup(eckey,ctx,kiv,rp);
end;

function Load_ECDSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_sign := LoadLibCryptoFunction('ECDSA_sign');
  if not assigned(ECDSA_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign');
  Result := ECDSA_sign(type_,dgst,dgstlen,sig,siglen,eckey);
end;

function Load_ECDSA_sign_ex(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_sign_ex := LoadLibCryptoFunction('ECDSA_sign_ex');
  if not assigned(ECDSA_sign_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign_ex');
  Result := ECDSA_sign_ex(type_,dgst,dgstlen,sig,siglen,kinv,rp,eckey);
end;

function Load_ECDSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_verify := LoadLibCryptoFunction('ECDSA_verify');
  if not assigned(ECDSA_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_verify');
  Result := ECDSA_verify(type_,dgst,dgstlen,sig,siglen,eckey);
end;

function Load_ECDSA_size(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  ECDSA_size := LoadLibCryptoFunction('ECDSA_size');
  if not assigned(ECDSA_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_size');
  Result := ECDSA_size(eckey);
end;

function Load_EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl;
begin
  EC_KEY_METHOD_new := LoadLibCryptoFunction('EC_KEY_METHOD_new');
  if not assigned(EC_KEY_METHOD_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_new');
  Result := EC_KEY_METHOD_new(meth);
end;

procedure Load_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl;
begin
  EC_KEY_METHOD_free := LoadLibCryptoFunction('EC_KEY_METHOD_free');
  if not assigned(EC_KEY_METHOD_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_free');
  EC_KEY_METHOD_free(meth);
end;

procedure Load_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl;
begin
  EC_KEY_METHOD_set_init := LoadLibCryptoFunction('EC_KEY_METHOD_set_init');
  if not assigned(EC_KEY_METHOD_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_init');
  EC_KEY_METHOD_set_init(meth,init,finish,copy,set_group,set_private,set_public);
end;

procedure Load_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl;
begin
  EC_KEY_METHOD_set_keygen := LoadLibCryptoFunction('EC_KEY_METHOD_set_keygen');
  if not assigned(EC_KEY_METHOD_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_keygen');
  EC_KEY_METHOD_set_keygen(meth,keygen);
end;

procedure Load_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl;
begin
  EC_KEY_METHOD_set_compute_key := LoadLibCryptoFunction('EC_KEY_METHOD_set_compute_key');
  if not assigned(EC_KEY_METHOD_set_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_compute_key');
  EC_KEY_METHOD_set_compute_key(meth,ckey);
end;

procedure Load_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl;
begin
  EC_KEY_METHOD_set_sign := LoadLibCryptoFunction('EC_KEY_METHOD_set_sign');
  if not assigned(EC_KEY_METHOD_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_sign');
  EC_KEY_METHOD_set_sign(meth,sign,sign_setup,sign_sig);
end;

procedure Load_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl;
begin
  EC_KEY_METHOD_set_verify := LoadLibCryptoFunction('EC_KEY_METHOD_set_verify');
  if not assigned(EC_KEY_METHOD_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_verify');
  EC_KEY_METHOD_set_verify(meth,verify,verify_sig);
end;

procedure Load_EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl;
begin
  EC_KEY_METHOD_get_init := LoadLibCryptoFunction('EC_KEY_METHOD_get_init');
  if not assigned(EC_KEY_METHOD_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_init');
  EC_KEY_METHOD_get_init(meth,pinit,pfinish,pcopy,pset_group,pset_private,pset_public);
end;

procedure Load_EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl;
begin
  EC_KEY_METHOD_get_keygen := LoadLibCryptoFunction('EC_KEY_METHOD_get_keygen');
  if not assigned(EC_KEY_METHOD_get_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_keygen');
  EC_KEY_METHOD_get_keygen(meth,pkeygen);
end;

procedure Load_EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl;
begin
  EC_KEY_METHOD_get_compute_key := LoadLibCryptoFunction('EC_KEY_METHOD_get_compute_key');
  if not assigned(EC_KEY_METHOD_get_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_compute_key');
  EC_KEY_METHOD_get_compute_key(meth,pck);
end;

procedure Load_EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl;
begin
  EC_KEY_METHOD_get_sign := LoadLibCryptoFunction('EC_KEY_METHOD_get_sign');
  if not assigned(EC_KEY_METHOD_get_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_sign');
  EC_KEY_METHOD_get_sign(meth,psign,psign_setup,psign_sig);
end;

procedure Load_EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl;
begin
  EC_KEY_METHOD_get_verify := LoadLibCryptoFunction('EC_KEY_METHOD_get_verify');
  if not assigned(EC_KEY_METHOD_get_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_verify');
  EC_KEY_METHOD_get_verify(meth,pverify,pverify_sig);
end;


procedure UnLoad;
begin
  EC_GFp_simple_method := Load_EC_GFp_simple_method;
  EC_GFp_mont_method := Load_EC_GFp_mont_method;
  EC_GFp_nist_method := Load_EC_GFp_nist_method;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EC_GFp_nistp224_method := Load_EC_GFp_nistp224_method;
  EC_GFp_nistp256_method := Load_EC_GFp_nistp256_method;
  EC_GFp_nistp521_method := Load_EC_GFp_nistp521_method;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EC_GF2m_simple_method := Load_EC_GF2m_simple_method;
  EC_GROUP_new := Load_EC_GROUP_new;
  EC_GROUP_free := Load_EC_GROUP_free;
  EC_GROUP_clear_free := Load_EC_GROUP_clear_free;
  EC_GROUP_copy := Load_EC_GROUP_copy;
  EC_GROUP_dup := Load_EC_GROUP_dup;
  EC_GROUP_method_of := Load_EC_GROUP_method_of;
  EC_METHOD_get_field_type := Load_EC_METHOD_get_field_type;
  EC_GROUP_set_generator := Load_EC_GROUP_set_generator;
  EC_GROUP_get0_generator := Load_EC_GROUP_get0_generator;
  EC_GROUP_get_mont_data := Load_EC_GROUP_get_mont_data;
  EC_GROUP_get_order := Load_EC_GROUP_get_order;
  EC_GROUP_get0_order := Load_EC_GROUP_get0_order;
  EC_GROUP_order_bits := Load_EC_GROUP_order_bits;
  EC_GROUP_get_cofactor := Load_EC_GROUP_get_cofactor;
  EC_GROUP_get0_cofactor := Load_EC_GROUP_get0_cofactor;
  EC_GROUP_set_curve_name := Load_EC_GROUP_set_curve_name;
  EC_GROUP_get_curve_name := Load_EC_GROUP_get_curve_name;
  EC_GROUP_set_asn1_flag := Load_EC_GROUP_set_asn1_flag;
  EC_GROUP_get_asn1_flag := Load_EC_GROUP_get_asn1_flag;
  EC_GROUP_set_point_conversion_form := Load_EC_GROUP_set_point_conversion_form;
  EC_GROUP_get_point_conversion_form := Load_EC_GROUP_get_point_conversion_form;
  EC_GROUP_get0_seed := Load_EC_GROUP_get0_seed;
  EC_GROUP_get_seed_len := Load_EC_GROUP_get_seed_len;
  EC_GROUP_set_seed := Load_EC_GROUP_set_seed;
  EC_GROUP_set_curve := Load_EC_GROUP_set_curve;
  EC_GROUP_get_curve := Load_EC_GROUP_get_curve;
  EC_GROUP_set_curve_GFp := Load_EC_GROUP_set_curve_GFp;
  EC_GROUP_get_curve_GFp := Load_EC_GROUP_get_curve_GFp;
  EC_GROUP_set_curve_GF2m := Load_EC_GROUP_set_curve_GF2m;
  EC_GROUP_get_curve_GF2m := Load_EC_GROUP_get_curve_GF2m;
  EC_GROUP_get_degree := Load_EC_GROUP_get_degree;
  EC_GROUP_check := Load_EC_GROUP_check;
  EC_GROUP_check_discriminant := Load_EC_GROUP_check_discriminant;
  EC_GROUP_cmp := Load_EC_GROUP_cmp;
  EC_GROUP_new_curve_GFp := Load_EC_GROUP_new_curve_GFp;
  EC_GROUP_new_curve_GF2m := Load_EC_GROUP_new_curve_GF2m;
  EC_GROUP_new_by_curve_name := Load_EC_GROUP_new_by_curve_name;
  EC_GROUP_new_from_ecparameters := Load_EC_GROUP_new_from_ecparameters;
  EC_GROUP_get_ecparameters := Load_EC_GROUP_get_ecparameters;
  EC_GROUP_new_from_ecpkparameters := Load_EC_GROUP_new_from_ecpkparameters;
  EC_GROUP_get_ecpkparameters := Load_EC_GROUP_get_ecpkparameters;
  EC_get_builtin_curves := Load_EC_get_builtin_curves;
  EC_curve_nid2nist := Load_EC_curve_nid2nist;
  EC_curve_nist2nid := Load_EC_curve_nist2nid;
  EC_POINT_new := Load_EC_POINT_new;
  EC_POINT_free := Load_EC_POINT_free;
  EC_POINT_clear_free := Load_EC_POINT_clear_free;
  EC_POINT_copy := Load_EC_POINT_copy;
  EC_POINT_dup := Load_EC_POINT_dup;
  EC_POINT_method_of := Load_EC_POINT_method_of;
  EC_POINT_set_to_infinity := Load_EC_POINT_set_to_infinity;
  EC_POINT_set_Jprojective_coordinates_GFp := Load_EC_POINT_set_Jprojective_coordinates_GFp;
  EC_POINT_get_Jprojective_coordinates_GFp := Load_EC_POINT_get_Jprojective_coordinates_GFp;
  EC_POINT_set_affine_coordinates := Load_EC_POINT_set_affine_coordinates;
  EC_POINT_get_affine_coordinates := Load_EC_POINT_get_affine_coordinates;
  EC_POINT_set_affine_coordinates_GFp := Load_EC_POINT_set_affine_coordinates_GFp;
  EC_POINT_get_affine_coordinates_GFp := Load_EC_POINT_get_affine_coordinates_GFp;
  EC_POINT_set_compressed_coordinates := Load_EC_POINT_set_compressed_coordinates;
  EC_POINT_set_compressed_coordinates_GFp := Load_EC_POINT_set_compressed_coordinates_GFp;
  EC_POINT_set_affine_coordinates_GF2m := Load_EC_POINT_set_affine_coordinates_GF2m;
  EC_POINT_get_affine_coordinates_GF2m := Load_EC_POINT_get_affine_coordinates_GF2m;
  EC_POINT_set_compressed_coordinates_GF2m := Load_EC_POINT_set_compressed_coordinates_GF2m;
  EC_POINT_point2oct := Load_EC_POINT_point2oct;
  EC_POINT_oct2point := Load_EC_POINT_oct2point;
  EC_POINT_point2buf := Load_EC_POINT_point2buf;
  EC_POINT_point2bn := Load_EC_POINT_point2bn;
  EC_POINT_bn2point := Load_EC_POINT_bn2point;
  EC_POINT_point2hex := Load_EC_POINT_point2hex;
  EC_POINT_hex2point := Load_EC_POINT_hex2point;
  EC_POINT_add := Load_EC_POINT_add;
  EC_POINT_dbl := Load_EC_POINT_dbl;
  EC_POINT_invert := Load_EC_POINT_invert;
  EC_POINT_is_at_infinity := Load_EC_POINT_is_at_infinity;
  EC_POINT_is_on_curve := Load_EC_POINT_is_on_curve;
  EC_POINT_cmp := Load_EC_POINT_cmp;
  EC_POINT_make_affine := Load_EC_POINT_make_affine;
  EC_POINTs_make_affine := Load_EC_POINTs_make_affine;
  EC_POINTs_mul := Load_EC_POINTs_mul;
  EC_POINT_mul := Load_EC_POINT_mul;
  EC_GROUP_precompute_mult := Load_EC_GROUP_precompute_mult;
  EC_GROUP_have_precompute_mult := Load_EC_GROUP_have_precompute_mult;
  ECPKPARAMETERS_it := Load_ECPKPARAMETERS_it;
  ECPKPARAMETERS_new := Load_ECPKPARAMETERS_new;
  ECPKPARAMETERS_free := Load_ECPKPARAMETERS_free;
  ECPARAMETERS_it := Load_ECPARAMETERS_it;
  ECPARAMETERS_new := Load_ECPARAMETERS_new;
  ECPARAMETERS_free := Load_ECPARAMETERS_free;
  EC_GROUP_get_basis_type := Load_EC_GROUP_get_basis_type;
  EC_GROUP_get_trinomial_basis := Load_EC_GROUP_get_trinomial_basis;
  EC_GROUP_get_pentanomial_basis := Load_EC_GROUP_get_pentanomial_basis;
  d2i_ECPKParameters := Load_d2i_ECPKParameters;
  i2d_ECPKParameters := Load_i2d_ECPKParameters;
  ECPKParameters_print := Load_ECPKParameters_print;
  EC_KEY_new := Load_EC_KEY_new;
  EC_KEY_get_flags := Load_EC_KEY_get_flags;
  EC_KEY_set_flags := Load_EC_KEY_set_flags;
  EC_KEY_clear_flags := Load_EC_KEY_clear_flags;
  EC_KEY_new_by_curve_name := Load_EC_KEY_new_by_curve_name;
  EC_KEY_free := Load_EC_KEY_free;
  EC_KEY_copy := Load_EC_KEY_copy;
  EC_KEY_dup := Load_EC_KEY_dup;
  EC_KEY_up_ref := Load_EC_KEY_up_ref;
  EC_KEY_get0_engine := Load_EC_KEY_get0_engine;
  EC_KEY_get0_group := Load_EC_KEY_get0_group;
  EC_KEY_set_group := Load_EC_KEY_set_group;
  EC_KEY_get0_private_key := Load_EC_KEY_get0_private_key;
  EC_KEY_set_private_key := Load_EC_KEY_set_private_key;
  EC_KEY_get0_public_key := Load_EC_KEY_get0_public_key;
  EC_KEY_set_public_key := Load_EC_KEY_set_public_key;
  EC_KEY_get_enc_flags := Load_EC_KEY_get_enc_flags;
  EC_KEY_set_enc_flags := Load_EC_KEY_set_enc_flags;
  EC_KEY_get_conv_form := Load_EC_KEY_get_conv_form;
  EC_KEY_set_conv_form := Load_EC_KEY_set_conv_form;
  EC_KEY_set_ex_data := Load_EC_KEY_set_ex_data;
  EC_KEY_get_ex_data := Load_EC_KEY_get_ex_data;
  EC_KEY_set_asn1_flag := Load_EC_KEY_set_asn1_flag;
  EC_KEY_precompute_mult := Load_EC_KEY_precompute_mult;
  EC_KEY_generate_key := Load_EC_KEY_generate_key;
  EC_KEY_check_key := Load_EC_KEY_check_key;
  EC_KEY_can_sign := Load_EC_KEY_can_sign;
  EC_KEY_set_public_key_affine_coordinates := Load_EC_KEY_set_public_key_affine_coordinates;
  EC_KEY_key2buf := Load_EC_KEY_key2buf;
  EC_KEY_oct2key := Load_EC_KEY_oct2key;
  EC_KEY_oct2priv := Load_EC_KEY_oct2priv;
  EC_KEY_priv2oct := Load_EC_KEY_priv2oct;
  EC_KEY_priv2buf := Load_EC_KEY_priv2buf;
  d2i_ECPrivateKey := Load_d2i_ECPrivateKey;
  i2d_ECPrivateKey := Load_i2d_ECPrivateKey;
  o2i_ECPublicKey := Load_o2i_ECPublicKey;
  i2o_ECPublicKey := Load_i2o_ECPublicKey;
  ECParameters_print := Load_ECParameters_print;
  EC_KEY_print := Load_EC_KEY_print;
  EC_KEY_OpenSSL := Load_EC_KEY_OpenSSL;
  EC_KEY_get_default_method := Load_EC_KEY_get_default_method;
  EC_KEY_set_default_method := Load_EC_KEY_set_default_method;
  EC_KEY_get_method := Load_EC_KEY_get_method;
  EC_KEY_set_method := Load_EC_KEY_set_method;
  EC_KEY_new_method := Load_EC_KEY_new_method;
  ECDH_KDF_X9_62 := Load_ECDH_KDF_X9_62;
  ECDH_compute_key := Load_ECDH_compute_key;
  ECDSA_SIG_new := Load_ECDSA_SIG_new;
  ECDSA_SIG_free := Load_ECDSA_SIG_free;
  i2d_ECDSA_SIG := Load_i2d_ECDSA_SIG;
  d2i_ECDSA_SIG := Load_d2i_ECDSA_SIG;
  ECDSA_SIG_get0 := Load_ECDSA_SIG_get0;
  ECDSA_SIG_get0_r := Load_ECDSA_SIG_get0_r;
  ECDSA_SIG_get0_s := Load_ECDSA_SIG_get0_s;
  ECDSA_SIG_set0 := Load_ECDSA_SIG_set0;
  ECDSA_do_sign := Load_ECDSA_do_sign;
  ECDSA_do_sign_ex := Load_ECDSA_do_sign_ex;
  ECDSA_do_verify := Load_ECDSA_do_verify;
  ECDSA_sign_setup := Load_ECDSA_sign_setup;
  ECDSA_sign := Load_ECDSA_sign;
  ECDSA_sign_ex := Load_ECDSA_sign_ex;
  ECDSA_verify := Load_ECDSA_verify;
  ECDSA_size := Load_ECDSA_size;
  EC_KEY_METHOD_new := Load_EC_KEY_METHOD_new;
  EC_KEY_METHOD_free := Load_EC_KEY_METHOD_free;
  EC_KEY_METHOD_set_init := Load_EC_KEY_METHOD_set_init;
  EC_KEY_METHOD_set_keygen := Load_EC_KEY_METHOD_set_keygen;
  EC_KEY_METHOD_set_compute_key := Load_EC_KEY_METHOD_set_compute_key;
  EC_KEY_METHOD_set_sign := Load_EC_KEY_METHOD_set_sign;
  EC_KEY_METHOD_set_verify := Load_EC_KEY_METHOD_set_verify;
  EC_KEY_METHOD_get_init := Load_EC_KEY_METHOD_get_init;
  EC_KEY_METHOD_get_keygen := Load_EC_KEY_METHOD_get_keygen;
  EC_KEY_METHOD_get_compute_key := Load_EC_KEY_METHOD_get_compute_key;
  EC_KEY_METHOD_get_sign := Load_EC_KEY_METHOD_get_sign;
  EC_KEY_METHOD_get_verify := Load_EC_KEY_METHOD_get_verify;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
