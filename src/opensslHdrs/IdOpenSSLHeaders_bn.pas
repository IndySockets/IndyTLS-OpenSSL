(* This unit was generated from the source file bn.h2pas 
It should not be modified directly. All changes should be made to bn.h2pas
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


unit IdOpenSSLHeaders_bn;


interface

// Headers for OpenSSL 1.1.1
// bn.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ;

const
  BN_FLG_MALLOCED = $01;
  BN_FLG_STATIC_DATA = $02;

  (*
   * avoid leaking exponent information through timing,
   * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
   * BN_div() will call BN_div_no_branch,
   * BN_mod_inverse() will call BN_mod_inverse_no_branch.
   *)
  BN_FLG_CONSTTIME = $04;
  BN_FLG_SECURE = $08;

  (* Values for |top| in BN_rand() *)
  BN_RAND_TOP_ANY = -1;
  BN_RAND_TOP_ONE = 0;
  BN_RAND_TOP_TWO = 1;

  (* Values for |bottom| in BN_rand() *)
  BN_RAND_BOTTOM_ANY = 0;
  BN_RAND_BOTTOM_ODD = 1;
  
  (* BN_BLINDING flags *)
  BN_BLINDING_NO_UPDATE = $00000001;
  BN_BLINDING_NO_RECREATE = $00000002;

type
  BN_ULONG = TOpenSSL_C_ULONG;

  BN_GENCB_set_old_cb = procedure (a: TOpenSSL_C_INT; b: TOpenSSL_C_INT; c: Pointer); cdecl;
  BN_GENCB_set_cb = function (a: TOpenSSL_C_INT; b: TOpenSSL_C_INT; c: PBN_GENCB): TOpenSSL_C_INT; cdecl;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BN_set_flags}
{$EXTERNALSYM BN_get_flags}
{$EXTERNALSYM BN_with_flags}
{$EXTERNALSYM BN_GENCB_call}
{$EXTERNALSYM BN_GENCB_new}
{$EXTERNALSYM BN_GENCB_free}
{$EXTERNALSYM BN_GENCB_set_old}
{$EXTERNALSYM BN_GENCB_set}
{$EXTERNALSYM BN_GENCB_get_arg}
{$EXTERNALSYM BN_abs_is_word}
{$EXTERNALSYM BN_is_zero}
{$EXTERNALSYM BN_is_one}
{$EXTERNALSYM BN_is_word}
{$EXTERNALSYM BN_is_odd}
{$EXTERNALSYM BN_zero_ex}
{$EXTERNALSYM BN_value_one}
{$EXTERNALSYM BN_options}
{$EXTERNALSYM BN_CTX_new}
{$EXTERNALSYM BN_CTX_secure_new}
{$EXTERNALSYM BN_CTX_free}
{$EXTERNALSYM BN_CTX_start}
{$EXTERNALSYM BN_CTX_get}
{$EXTERNALSYM BN_CTX_end}
{$EXTERNALSYM BN_rand}
{$EXTERNALSYM BN_priv_rand}
{$EXTERNALSYM BN_rand_range}
{$EXTERNALSYM BN_priv_rand_range}
{$EXTERNALSYM BN_pseudo_rand}
{$EXTERNALSYM BN_pseudo_rand_range}
{$EXTERNALSYM BN_num_bits}
{$EXTERNALSYM BN_num_bits_word}
{$EXTERNALSYM BN_security_bits}
{$EXTERNALSYM BN_new}
{$EXTERNALSYM BN_secure_new}
{$EXTERNALSYM BN_clear_free}
{$EXTERNALSYM BN_copy}
{$EXTERNALSYM BN_swap}
{$EXTERNALSYM BN_bin2bn}
{$EXTERNALSYM BN_bn2bin}
{$EXTERNALSYM BN_bn2binpad}
{$EXTERNALSYM BN_lebin2bn}
{$EXTERNALSYM BN_bn2lebinpad}
{$EXTERNALSYM BN_mpi2bn}
{$EXTERNALSYM BN_bn2mpi}
{$EXTERNALSYM BN_sub}
{$EXTERNALSYM BN_usub}
{$EXTERNALSYM BN_uadd}
{$EXTERNALSYM BN_add}
{$EXTERNALSYM BN_mul}
{$EXTERNALSYM BN_sqr}
{$EXTERNALSYM BN_set_negative}
{$EXTERNALSYM BN_is_negative}
{$EXTERNALSYM BN_div}
{$EXTERNALSYM BN_nnmod}
{$EXTERNALSYM BN_mod_add}
{$EXTERNALSYM BN_mod_add_quick}
{$EXTERNALSYM BN_mod_sub}
{$EXTERNALSYM BN_mod_sub_quick}
{$EXTERNALSYM BN_mod_mul}
{$EXTERNALSYM BN_mod_sqr}
{$EXTERNALSYM BN_mod_lshift1}
{$EXTERNALSYM BN_mod_lshift1_quick}
{$EXTERNALSYM BN_mod_lshift}
{$EXTERNALSYM BN_mod_lshift_quick}
{$EXTERNALSYM BN_mod_word}
{$EXTERNALSYM BN_div_word}
{$EXTERNALSYM BN_mul_word}
{$EXTERNALSYM BN_add_word}
{$EXTERNALSYM BN_sub_word}
{$EXTERNALSYM BN_set_word}
{$EXTERNALSYM BN_get_word}
{$EXTERNALSYM BN_cmp}
{$EXTERNALSYM BN_free}
{$EXTERNALSYM BN_is_bit_set}
{$EXTERNALSYM BN_lshift}
{$EXTERNALSYM BN_lshift1}
{$EXTERNALSYM BN_exp}
{$EXTERNALSYM BN_mod_exp}
{$EXTERNALSYM BN_mod_exp_mont}
{$EXTERNALSYM BN_mod_exp_mont_consttime}
{$EXTERNALSYM BN_mod_exp_mont_word}
{$EXTERNALSYM BN_mod_exp2_mont}
{$EXTERNALSYM BN_mod_exp_simple}
{$EXTERNALSYM BN_mask_bits}
{$EXTERNALSYM BN_print}
{$EXTERNALSYM BN_reciprocal}
{$EXTERNALSYM BN_rshift}
{$EXTERNALSYM BN_rshift1}
{$EXTERNALSYM BN_clear}
{$EXTERNALSYM BN_dup}
{$EXTERNALSYM BN_ucmp}
{$EXTERNALSYM BN_set_bit}
{$EXTERNALSYM BN_clear_bit}
{$EXTERNALSYM BN_bn2hex}
{$EXTERNALSYM BN_bn2dec}
{$EXTERNALSYM BN_hex2bn}
{$EXTERNALSYM BN_dec2bn}
{$EXTERNALSYM BN_asc2bn}
{$EXTERNALSYM BN_gcd}
{$EXTERNALSYM BN_kronecker}
{$EXTERNALSYM BN_mod_inverse}
{$EXTERNALSYM BN_mod_sqrt}
{$EXTERNALSYM BN_consttime_swap}
{$EXTERNALSYM BN_generate_prime_ex}
{$EXTERNALSYM BN_is_prime_ex}
{$EXTERNALSYM BN_is_prime_fasttest_ex}
{$EXTERNALSYM BN_X931_generate_Xpq}
{$EXTERNALSYM BN_X931_derive_prime_ex}
{$EXTERNALSYM BN_X931_generate_prime_ex}
{$EXTERNALSYM BN_MONT_CTX_new}
{$EXTERNALSYM BN_mod_mul_montgomery}
{$EXTERNALSYM BN_to_montgomery}
{$EXTERNALSYM BN_from_montgomery}
{$EXTERNALSYM BN_MONT_CTX_free}
{$EXTERNALSYM BN_MONT_CTX_set}
{$EXTERNALSYM BN_MONT_CTX_copy}
{$EXTERNALSYM BN_BLINDING_new}
{$EXTERNALSYM BN_BLINDING_free}
{$EXTERNALSYM BN_BLINDING_update}
{$EXTERNALSYM BN_BLINDING_convert}
{$EXTERNALSYM BN_BLINDING_invert}
{$EXTERNALSYM BN_BLINDING_convert_ex}
{$EXTERNALSYM BN_BLINDING_invert_ex}
{$EXTERNALSYM BN_BLINDING_is_current_thread}
{$EXTERNALSYM BN_BLINDING_set_current_thread}
{$EXTERNALSYM BN_BLINDING_lock}
{$EXTERNALSYM BN_BLINDING_unlock}
{$EXTERNALSYM BN_BLINDING_get_flags}
{$EXTERNALSYM BN_BLINDING_set_flags}
{$EXTERNALSYM BN_RECP_CTX_free}
{$EXTERNALSYM BN_RECP_CTX_set}
{$EXTERNALSYM BN_mod_mul_reciprocal}
{$EXTERNALSYM BN_mod_exp_recp}
{$EXTERNALSYM BN_div_recp}
{$EXTERNALSYM BN_GF2m_add}
{$EXTERNALSYM BN_GF2m_mod}
{$EXTERNALSYM BN_GF2m_mod_mul}
{$EXTERNALSYM BN_GF2m_mod_sqr}
{$EXTERNALSYM BN_GF2m_mod_inv}
{$EXTERNALSYM BN_GF2m_mod_div}
{$EXTERNALSYM BN_GF2m_mod_exp}
{$EXTERNALSYM BN_GF2m_mod_sqrt}
{$EXTERNALSYM BN_GF2m_mod_solve_quad}
{$EXTERNALSYM BN_nist_mod_192}
{$EXTERNALSYM BN_nist_mod_224}
{$EXTERNALSYM BN_nist_mod_256}
{$EXTERNALSYM BN_nist_mod_384}
{$EXTERNALSYM BN_nist_mod_521}
{$EXTERNALSYM BN_get0_nist_prime_192}
{$EXTERNALSYM BN_get0_nist_prime_224}
{$EXTERNALSYM BN_get0_nist_prime_256}
{$EXTERNALSYM BN_get0_nist_prime_384}
{$EXTERNALSYM BN_get0_nist_prime_521}
{$EXTERNALSYM BN_generate_dsa_nonce}
{$EXTERNALSYM BN_get_rfc2409_prime_768}
{$EXTERNALSYM BN_get_rfc2409_prime_1024}
{$EXTERNALSYM BN_get_rfc3526_prime_1536}
{$EXTERNALSYM BN_get_rfc3526_prime_2048}
{$EXTERNALSYM BN_get_rfc3526_prime_3072}
{$EXTERNALSYM BN_get_rfc3526_prime_4096}
{$EXTERNALSYM BN_get_rfc3526_prime_6144}
{$EXTERNALSYM BN_get_rfc3526_prime_8192}
{$EXTERNALSYM BN_bntest_rand}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure BN_set_flags(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_get_flags(b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_GENCB_call(cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GENCB_new: PBN_GENCB; cdecl; external CLibCrypto;
procedure BN_GENCB_free(cb: PBN_GENCB); cdecl; external CLibCrypto;
procedure BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl; external CLibCrypto;
procedure BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl; external CLibCrypto;
function BN_GENCB_get_arg(cb: PBN_GENCB): Pointer; cdecl; external CLibCrypto;
function BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_zero(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_one(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_odd(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_zero_ex(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_value_one: PBIGNUM; cdecl; external CLibCrypto;
function BN_options: PAnsiChar; cdecl; external CLibCrypto;
function BN_CTX_new: PBN_CTX; cdecl; external CLibCrypto;
function BN_CTX_secure_new: PBN_CTX; cdecl; external CLibCrypto;
procedure BN_CTX_free(c: PBN_CTX); cdecl; external CLibCrypto;
procedure BN_CTX_start(ctx: PBN_CTX); cdecl; external CLibCrypto;
function BN_CTX_get(ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
procedure BN_CTX_end(ctx: PBN_CTX); cdecl; external CLibCrypto;
function BN_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_priv_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_pseudo_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_num_bits(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_num_bits_word(l: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_security_bits(L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_new: PBIGNUM; cdecl; external CLibCrypto;
function BN_secure_new: PBIGNUM; cdecl; external CLibCrypto;
procedure BN_clear_free(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
procedure BN_swap(a: PBIGNUM; b: PBIGNUM); cdecl; external CLibCrypto;
function BN_bin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bn2bin(const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_lebin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mpi2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bn2mpi(a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_set_negative(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_is_negative(b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl; external CLibCrypto;
function BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl; external CLibCrypto;
function BN_mul_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_add_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_sub_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_set_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_get_word(const a: PBIGNUM): BN_ULONG; cdecl; external CLibCrypto;
function BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_free(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_is_bit_set(const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mask_bits(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_print(bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_rshift1(r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_clear(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_dup(const a: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_ucmp(a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_set_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_clear_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_bn2hex(a: PBIGNUM): PAnsiChar; cdecl; external CLibCrypto;
function BN_bn2dec(a: PBIGNUM): PAnsiChar; cdecl; external CLibCrypto;
function BN_hex2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_dec2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_asc2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
function BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
procedure BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_generate_prime_ex(ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_prime_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_MONT_CTX_new: PBN_MONT_CTX; cdecl; external CLibCrypto;
function BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_MONT_CTX_free(mont: PBN_MONT_CTX); cdecl; external CLibCrypto;
function BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl; external CLibCrypto;
function BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl; external CLibCrypto;
procedure BN_BLINDING_free(b: PBN_BLINDING); cdecl; external CLibCrypto;
function BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_is_current_thread(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_BLINDING_set_current_thread(b: PBN_BLINDING); cdecl; external CLibCrypto;
function BN_BLINDING_lock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_unlock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_get_flags(v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
procedure BN_RECP_CTX_free(recp: PBN_RECP_CTX); cdecl; external CLibCrypto;
function BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_get0_nist_prime_192: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_224: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_256: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_384: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_521: PBIGNUM; cdecl; external CLibCrypto;
function BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bntest_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

procedure Load_BN_set_flags(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl;
function Load_BN_get_flags(b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl;
function Load_BN_GENCB_call(cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_GENCB_new: PBN_GENCB; cdecl;
procedure Load_BN_GENCB_free(cb: PBN_GENCB); cdecl;
procedure Load_BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl;
procedure Load_BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl;
function Load_BN_GENCB_get_arg(cb: PBN_GENCB): Pointer; cdecl;
function Load_BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_is_zero(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_is_one(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_is_odd(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
procedure Load_BN_zero_ex(a: PBIGNUM); cdecl;
function Load_BN_value_one: PBIGNUM; cdecl;
function Load_BN_options: PAnsiChar; cdecl;
function Load_BN_CTX_new: PBN_CTX; cdecl;
function Load_BN_CTX_secure_new: PBN_CTX; cdecl;
procedure Load_BN_CTX_free(c: PBN_CTX); cdecl;
procedure Load_BN_CTX_start(ctx: PBN_CTX); cdecl;
function Load_BN_CTX_get(ctx: PBN_CTX): PBIGNUM; cdecl;
procedure Load_BN_CTX_end(ctx: PBN_CTX); cdecl;
function Load_BN_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_priv_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_pseudo_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_num_bits(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_num_bits_word(l: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_security_bits(L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_new: PBIGNUM; cdecl;
function Load_BN_secure_new: PBIGNUM; cdecl;
procedure Load_BN_clear_free(a: PBIGNUM); cdecl;
function Load_BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl;
procedure Load_BN_swap(a: PBIGNUM; b: PBIGNUM); cdecl;
function Load_BN_bin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_bn2bin(const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl;
function Load_BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_lebin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_mpi2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_bn2mpi(a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl;
function Load_BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_BN_set_negative(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl;
function Load_BN_is_negative(b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl;
function Load_BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl;
function Load_BN_mul_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_add_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_sub_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_set_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
function Load_BN_get_word(const a: PBIGNUM): BN_ULONG; cdecl;
function Load_BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
procedure Load_BN_free(a: PBIGNUM); cdecl;
function Load_BN_is_bit_set(const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mask_bits(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_print(bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_rshift1(r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl;
procedure Load_BN_clear(a: PBIGNUM); cdecl;
function Load_BN_dup(const a: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_ucmp(a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_set_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_clear_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BN_bn2hex(a: PBIGNUM): PAnsiChar; cdecl;
function Load_BN_bn2dec(a: PBIGNUM): PAnsiChar; cdecl;
function Load_BN_hex2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BN_dec2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BN_asc2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
function Load_BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
procedure Load_BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl;
function Load_BN_generate_prime_ex(ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_BN_is_prime_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
function Load_BN_MONT_CTX_new: PBN_MONT_CTX; cdecl;
function Load_BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_BN_MONT_CTX_free(mont: PBN_MONT_CTX); cdecl;
function Load_BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl;
function Load_BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl;
procedure Load_BN_BLINDING_free(b: PBN_BLINDING); cdecl;
function Load_BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_is_current_thread(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
procedure Load_BN_BLINDING_set_current_thread(b: PBN_BLINDING); cdecl;
function Load_BN_BLINDING_lock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_unlock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
function Load_BN_BLINDING_get_flags(v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl;
procedure Load_BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl;
procedure Load_BN_RECP_CTX_free(recp: PBN_RECP_CTX); cdecl;
function Load_BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_get0_nist_prime_192: PBIGNUM; cdecl;
function Load_BN_get0_nist_prime_224: PBIGNUM; cdecl;
function Load_BN_get0_nist_prime_256: PBIGNUM; cdecl;
function Load_BN_get0_nist_prime_384: PBIGNUM; cdecl;
function Load_BN_get0_nist_prime_521: PBIGNUM; cdecl;
function Load_BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
function Load_BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM; cdecl;
function Load_BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM; cdecl;
function Load_BN_bntest_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  BN_set_flags: procedure (b: PBIGNUM; n: TOpenSSL_C_INT); cdecl = Load_BN_set_flags;
  BN_get_flags: function (b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_get_flags;
  BN_with_flags: procedure (dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl = Load_BN_with_flags;
  BN_GENCB_call: function (cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_GENCB_call;
  BN_GENCB_new: function : PBN_GENCB; cdecl = Load_BN_GENCB_new;
  BN_GENCB_free: procedure (cb: PBN_GENCB); cdecl = Load_BN_GENCB_free;
  BN_GENCB_set_old: procedure (gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl = Load_BN_GENCB_set_old;
  BN_GENCB_set: procedure (gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl = Load_BN_GENCB_set;
  BN_GENCB_get_arg: function (cb: PBN_GENCB): Pointer; cdecl = Load_BN_GENCB_get_arg;
  BN_abs_is_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_abs_is_word;
  BN_is_zero: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_is_zero;
  BN_is_one: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_is_one;
  BN_is_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_is_word;
  BN_is_odd: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_is_odd;
  BN_zero_ex: procedure (a: PBIGNUM); cdecl = Load_BN_zero_ex;
  BN_value_one: function : PBIGNUM; cdecl = Load_BN_value_one;
  BN_options: function : PAnsiChar; cdecl = Load_BN_options;
  BN_CTX_new: function : PBN_CTX; cdecl = Load_BN_CTX_new;
  BN_CTX_secure_new: function : PBN_CTX; cdecl = Load_BN_CTX_secure_new;
  BN_CTX_free: procedure (c: PBN_CTX); cdecl = Load_BN_CTX_free;
  BN_CTX_start: procedure (ctx: PBN_CTX); cdecl = Load_BN_CTX_start;
  BN_CTX_get: function (ctx: PBN_CTX): PBIGNUM; cdecl = Load_BN_CTX_get;
  BN_CTX_end: procedure (ctx: PBN_CTX); cdecl = Load_BN_CTX_end;
  BN_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_rand;
  BN_priv_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_priv_rand;
  BN_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_rand_range;
  BN_priv_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_priv_rand_range;
  BN_pseudo_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_pseudo_rand;
  BN_pseudo_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_pseudo_rand_range;
  BN_num_bits: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_num_bits;
  BN_num_bits_word: function (l: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_num_bits_word;
  BN_security_bits: function (L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_security_bits;
  BN_new: function : PBIGNUM; cdecl = Load_BN_new;
  BN_secure_new: function : PBIGNUM; cdecl = Load_BN_secure_new;
  BN_clear_free: procedure (a: PBIGNUM); cdecl = Load_BN_clear_free;
  BN_copy: function (a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl = Load_BN_copy;
  BN_swap: procedure (a: PBIGNUM; b: PBIGNUM); cdecl = Load_BN_swap;
  BN_bin2bn: function (const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl = Load_BN_bin2bn;
  BN_bn2bin: function (const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl = Load_BN_bn2bin;
  BN_bn2binpad: function (const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_bn2binpad;
  BN_lebin2bn: function (const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl = Load_BN_lebin2bn;
  BN_bn2lebinpad: function (a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_bn2lebinpad;
  BN_mpi2bn: function (const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl = Load_BN_mpi2bn;
  BN_bn2mpi: function (a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl = Load_BN_bn2mpi;
  BN_sub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_sub;
  BN_usub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_usub;
  BN_uadd: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_uadd;
  BN_add: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_add;
  BN_mul: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mul;
  BN_sqr: function (r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_sqr;
  BN_set_negative: procedure (b: PBIGNUM; n: TOpenSSL_C_INT); cdecl = Load_BN_set_negative;
  BN_is_negative: function (b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_is_negative;
  BN_div: function (dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_div;
  BN_nnmod: function (r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_nnmod;
  BN_mod_add: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_add;
  BN_mod_add_quick: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_mod_add_quick;
  BN_mod_sub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_sub;
  BN_mod_sub_quick: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_mod_sub_quick;
  BN_mod_mul: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_mul;
  BN_mod_sqr: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_sqr;
  BN_mod_lshift1: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_lshift1;
  BN_mod_lshift1_quick: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_mod_lshift1_quick;
  BN_mod_lshift: function (r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_lshift;
  BN_mod_lshift_quick: function (r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_mod_lshift_quick;
  BN_mod_word: function (const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl = Load_BN_mod_word;
  BN_div_word: function (a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl = Load_BN_div_word;
  BN_mul_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_mul_word;
  BN_add_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_add_word;
  BN_sub_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_sub_word;
  BN_set_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = Load_BN_set_word;
  BN_get_word: function (const a: PBIGNUM): BN_ULONG; cdecl = Load_BN_get_word;
  BN_cmp: function (const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_cmp;
  BN_free: procedure (a: PBIGNUM); cdecl = Load_BN_free;
  BN_is_bit_set: function (const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_is_bit_set;
  BN_lshift: function (r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_lshift;
  BN_lshift1: function (r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_lshift1;
  BN_exp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_exp;
  BN_mod_exp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp;
  BN_mod_exp_mont: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp_mont;
  BN_mod_exp_mont_consttime: function (rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp_mont_consttime;
  BN_mod_exp_mont_word: function (r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp_mont_word;
  BN_mod_exp2_mont: function (r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp2_mont;
  BN_mod_exp_simple: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp_simple;
  BN_mask_bits: function (a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_mask_bits;
  BN_print: function (bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_print;
  BN_reciprocal: function (r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_reciprocal;
  BN_rshift: function (r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_rshift;
  BN_rshift1: function (r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_rshift1;
  BN_clear: procedure (a: PBIGNUM); cdecl = Load_BN_clear;
  BN_dup: function (const a: PBIGNUM): PBIGNUM; cdecl = Load_BN_dup;
  BN_ucmp: function (a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_ucmp;
  BN_set_bit: function (a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_set_bit;
  BN_clear_bit: function (a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_clear_bit;
  BN_bn2hex: function (a: PBIGNUM): PAnsiChar; cdecl = Load_BN_bn2hex;
  BN_bn2dec: function (a: PBIGNUM): PAnsiChar; cdecl = Load_BN_bn2dec;
  BN_hex2bn: function (a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_BN_hex2bn;
  BN_dec2bn: function (a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_BN_dec2bn;
  BN_asc2bn: function (a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_BN_asc2bn;
  BN_gcd: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_gcd;
  BN_kronecker: function (a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_kronecker;
  BN_mod_inverse: function (ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = Load_BN_mod_inverse;
  BN_mod_sqrt: function (ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = Load_BN_mod_sqrt;
  BN_consttime_swap: procedure (swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl = Load_BN_consttime_swap;
  BN_generate_prime_ex: function (ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_BN_generate_prime_ex;
  BN_is_prime_ex: function (const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_BN_is_prime_ex;
  BN_is_prime_fasttest_ex: function (const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_BN_is_prime_fasttest_ex;
  BN_X931_generate_Xpq: function (Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_X931_generate_Xpq;
  BN_X931_derive_prime_ex: function (p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_BN_X931_derive_prime_ex;
  BN_X931_generate_prime_ex: function (p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_BN_X931_generate_prime_ex;
  BN_MONT_CTX_new: function : PBN_MONT_CTX; cdecl = Load_BN_MONT_CTX_new;
  BN_mod_mul_montgomery: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_mul_montgomery;
  BN_to_montgomery: function (r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_to_montgomery;
  BN_from_montgomery: function (r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_from_montgomery;
  BN_MONT_CTX_free: procedure (mont: PBN_MONT_CTX); cdecl = Load_BN_MONT_CTX_free;
  BN_MONT_CTX_set: function (mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_MONT_CTX_set;
  BN_MONT_CTX_copy: function (to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl = Load_BN_MONT_CTX_copy;
  BN_BLINDING_new: function (const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl = Load_BN_BLINDING_new;
  BN_BLINDING_free: procedure (b: PBN_BLINDING); cdecl = Load_BN_BLINDING_free;
  BN_BLINDING_update: function (b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_update;
  BN_BLINDING_convert: function (n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_convert;
  BN_BLINDING_invert: function (n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_invert;
  BN_BLINDING_convert_ex: function (n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_convert_ex;
  BN_BLINDING_invert_ex: function (n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_invert_ex;
  BN_BLINDING_is_current_thread: function (b: PBN_BLINDING): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_is_current_thread;
  BN_BLINDING_set_current_thread: procedure (b: PBN_BLINDING); cdecl = Load_BN_BLINDING_set_current_thread;
  BN_BLINDING_lock: function (b: PBN_BLINDING): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_lock;
  BN_BLINDING_unlock: function (b: PBN_BLINDING): TOpenSSL_C_INT; cdecl = Load_BN_BLINDING_unlock;
  BN_BLINDING_get_flags: function (v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl = Load_BN_BLINDING_get_flags;
  BN_BLINDING_set_flags: procedure (v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl = Load_BN_BLINDING_set_flags;
  BN_RECP_CTX_free: procedure (recp: PBN_RECP_CTX); cdecl = Load_BN_RECP_CTX_free;
  BN_RECP_CTX_set: function (recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_RECP_CTX_set;
  BN_mod_mul_reciprocal: function (r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_mul_reciprocal;
  BN_mod_exp_recp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_mod_exp_recp;
  BN_div_recp: function (dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_div_recp;
  BN_GF2m_add: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_add;
  BN_GF2m_mod: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod;
  BN_GF2m_mod_mul: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_mul;
  BN_GF2m_mod_sqr: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_sqr;
  BN_GF2m_mod_inv: function (r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_inv;
  BN_GF2m_mod_div: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_div;
  BN_GF2m_mod_exp: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_exp;
  BN_GF2m_mod_sqrt: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_sqrt;
  BN_GF2m_mod_solve_quad: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_GF2m_mod_solve_quad;
  BN_nist_mod_192: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_nist_mod_192;
  BN_nist_mod_224: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_nist_mod_224;
  BN_nist_mod_256: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_nist_mod_256;
  BN_nist_mod_384: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_nist_mod_384;
  BN_nist_mod_521: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_nist_mod_521;
  BN_get0_nist_prime_192: function : PBIGNUM; cdecl = Load_BN_get0_nist_prime_192;
  BN_get0_nist_prime_224: function : PBIGNUM; cdecl = Load_BN_get0_nist_prime_224;
  BN_get0_nist_prime_256: function : PBIGNUM; cdecl = Load_BN_get0_nist_prime_256;
  BN_get0_nist_prime_384: function : PBIGNUM; cdecl = Load_BN_get0_nist_prime_384;
  BN_get0_nist_prime_521: function : PBIGNUM; cdecl = Load_BN_get0_nist_prime_521;
  BN_generate_dsa_nonce: function (out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_BN_generate_dsa_nonce;
  BN_get_rfc2409_prime_768: function (bn: PBIGNUM ): PBIGNUM; cdecl = Load_BN_get_rfc2409_prime_768;
  BN_get_rfc2409_prime_1024: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc2409_prime_1024;
  BN_get_rfc3526_prime_1536: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc3526_prime_1536;
  BN_get_rfc3526_prime_2048: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc3526_prime_2048;
  BN_get_rfc3526_prime_3072: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc3526_prime_3072;
  BN_get_rfc3526_prime_4096: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc3526_prime_4096;
  BN_get_rfc3526_prime_6144: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc3526_prime_6144;
  BN_get_rfc3526_prime_8192: function (bn: PBIGNUM): PBIGNUM; cdecl = Load_BN_get_rfc3526_prime_8192;
  BN_bntest_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BN_bntest_rand;
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
procedure Load_BN_set_flags(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl;
begin
  BN_set_flags := LoadLibCryptoFunction('BN_set_flags');
  if not assigned(BN_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_flags');
  BN_set_flags(b,n);
end;

function Load_BN_get_flags(b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_get_flags := LoadLibCryptoFunction('BN_get_flags');
  if not assigned(BN_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_flags');
  Result := BN_get_flags(b,n);
end;

procedure Load_BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl;
begin
  BN_with_flags := LoadLibCryptoFunction('BN_with_flags');
  if not assigned(BN_with_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_with_flags');
  BN_with_flags(dest,b,flags);
end;

function Load_BN_GENCB_call(cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_GENCB_call := LoadLibCryptoFunction('BN_GENCB_call');
  if not assigned(BN_GENCB_call) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_call');
  Result := BN_GENCB_call(cb,a,b);
end;

function Load_BN_GENCB_new: PBN_GENCB; cdecl;
begin
  BN_GENCB_new := LoadLibCryptoFunction('BN_GENCB_new');
  if not assigned(BN_GENCB_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_new');
  Result := BN_GENCB_new();
end;

procedure Load_BN_GENCB_free(cb: PBN_GENCB); cdecl;
begin
  BN_GENCB_free := LoadLibCryptoFunction('BN_GENCB_free');
  if not assigned(BN_GENCB_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_free');
  BN_GENCB_free(cb);
end;

procedure Load_BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl;
begin
  BN_GENCB_set_old := LoadLibCryptoFunction('BN_GENCB_set_old');
  if not assigned(BN_GENCB_set_old) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_set_old');
  BN_GENCB_set_old(gencb,callback,cb_arg);
end;

procedure Load_BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl;
begin
  BN_GENCB_set := LoadLibCryptoFunction('BN_GENCB_set');
  if not assigned(BN_GENCB_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_set');
  BN_GENCB_set(gencb,callback,cb_arg);
end;

function Load_BN_GENCB_get_arg(cb: PBN_GENCB): Pointer; cdecl;
begin
  BN_GENCB_get_arg := LoadLibCryptoFunction('BN_GENCB_get_arg');
  if not assigned(BN_GENCB_get_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_get_arg');
  Result := BN_GENCB_get_arg(cb);
end;

function Load_BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_abs_is_word := LoadLibCryptoFunction('BN_abs_is_word');
  if not assigned(BN_abs_is_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_abs_is_word');
  Result := BN_abs_is_word(a,w);
end;

function Load_BN_is_zero(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_is_zero := LoadLibCryptoFunction('BN_is_zero');
  if not assigned(BN_is_zero) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_zero');
  Result := BN_is_zero(a);
end;

function Load_BN_is_one(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_is_one := LoadLibCryptoFunction('BN_is_one');
  if not assigned(BN_is_one) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_one');
  Result := BN_is_one(a);
end;

function Load_BN_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_is_word := LoadLibCryptoFunction('BN_is_word');
  if not assigned(BN_is_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_word');
  Result := BN_is_word(a,w);
end;

function Load_BN_is_odd(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_is_odd := LoadLibCryptoFunction('BN_is_odd');
  if not assigned(BN_is_odd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_odd');
  Result := BN_is_odd(a);
end;

procedure Load_BN_zero_ex(a: PBIGNUM); cdecl;
begin
  BN_zero_ex := LoadLibCryptoFunction('BN_zero_ex');
  if not assigned(BN_zero_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_zero_ex');
  BN_zero_ex(a);
end;

function Load_BN_value_one: PBIGNUM; cdecl;
begin
  BN_value_one := LoadLibCryptoFunction('BN_value_one');
  if not assigned(BN_value_one) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_value_one');
  Result := BN_value_one();
end;

function Load_BN_options: PAnsiChar; cdecl;
begin
  BN_options := LoadLibCryptoFunction('BN_options');
  if not assigned(BN_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_options');
  Result := BN_options();
end;

function Load_BN_CTX_new: PBN_CTX; cdecl;
begin
  BN_CTX_new := LoadLibCryptoFunction('BN_CTX_new');
  if not assigned(BN_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_new');
  Result := BN_CTX_new();
end;

function Load_BN_CTX_secure_new: PBN_CTX; cdecl;
begin
  BN_CTX_secure_new := LoadLibCryptoFunction('BN_CTX_secure_new');
  if not assigned(BN_CTX_secure_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_secure_new');
  Result := BN_CTX_secure_new();
end;

procedure Load_BN_CTX_free(c: PBN_CTX); cdecl;
begin
  BN_CTX_free := LoadLibCryptoFunction('BN_CTX_free');
  if not assigned(BN_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_free');
  BN_CTX_free(c);
end;

procedure Load_BN_CTX_start(ctx: PBN_CTX); cdecl;
begin
  BN_CTX_start := LoadLibCryptoFunction('BN_CTX_start');
  if not assigned(BN_CTX_start) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_start');
  BN_CTX_start(ctx);
end;

function Load_BN_CTX_get(ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  BN_CTX_get := LoadLibCryptoFunction('BN_CTX_get');
  if not assigned(BN_CTX_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_get');
  Result := BN_CTX_get(ctx);
end;

procedure Load_BN_CTX_end(ctx: PBN_CTX); cdecl;
begin
  BN_CTX_end := LoadLibCryptoFunction('BN_CTX_end');
  if not assigned(BN_CTX_end) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_end');
  BN_CTX_end(ctx);
end;

function Load_BN_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_rand := LoadLibCryptoFunction('BN_rand');
  if not assigned(BN_rand) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rand');
  Result := BN_rand(rnd,bits,top,bottom);
end;

function Load_BN_priv_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_priv_rand := LoadLibCryptoFunction('BN_priv_rand');
  if not assigned(BN_priv_rand) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_priv_rand');
  Result := BN_priv_rand(rnd,bits,top,bottom);
end;

function Load_BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_rand_range := LoadLibCryptoFunction('BN_rand_range');
  if not assigned(BN_rand_range) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rand_range');
  Result := BN_rand_range(rnd,range);
end;

function Load_BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_priv_rand_range := LoadLibCryptoFunction('BN_priv_rand_range');
  if not assigned(BN_priv_rand_range) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_priv_rand_range');
  Result := BN_priv_rand_range(rnd,range);
end;

function Load_BN_pseudo_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_pseudo_rand := LoadLibCryptoFunction('BN_pseudo_rand');
  if not assigned(BN_pseudo_rand) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_pseudo_rand');
  Result := BN_pseudo_rand(rnd,bits,top,bottom);
end;

function Load_BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_pseudo_rand_range := LoadLibCryptoFunction('BN_pseudo_rand_range');
  if not assigned(BN_pseudo_rand_range) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_pseudo_rand_range');
  Result := BN_pseudo_rand_range(rnd,range);
end;

function Load_BN_num_bits(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_num_bits := LoadLibCryptoFunction('BN_num_bits');
  if not assigned(BN_num_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_num_bits');
  Result := BN_num_bits(a);
end;

function Load_BN_num_bits_word(l: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_num_bits_word := LoadLibCryptoFunction('BN_num_bits_word');
  if not assigned(BN_num_bits_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_num_bits_word');
  Result := BN_num_bits_word(l);
end;

function Load_BN_security_bits(L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_security_bits := LoadLibCryptoFunction('BN_security_bits');
  if not assigned(BN_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_security_bits');
  Result := BN_security_bits(L,N);
end;

function Load_BN_new: PBIGNUM; cdecl;
begin
  BN_new := LoadLibCryptoFunction('BN_new');
  if not assigned(BN_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_new');
  Result := BN_new();
end;

function Load_BN_secure_new: PBIGNUM; cdecl;
begin
  BN_secure_new := LoadLibCryptoFunction('BN_secure_new');
  if not assigned(BN_secure_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_secure_new');
  Result := BN_secure_new();
end;

procedure Load_BN_clear_free(a: PBIGNUM); cdecl;
begin
  BN_clear_free := LoadLibCryptoFunction('BN_clear_free');
  if not assigned(BN_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_clear_free');
  BN_clear_free(a);
end;

function Load_BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_copy := LoadLibCryptoFunction('BN_copy');
  if not assigned(BN_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_copy');
  Result := BN_copy(a,b);
end;

procedure Load_BN_swap(a: PBIGNUM; b: PBIGNUM); cdecl;
begin
  BN_swap := LoadLibCryptoFunction('BN_swap');
  if not assigned(BN_swap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_swap');
  BN_swap(a,b);
end;

function Load_BN_bin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_bin2bn := LoadLibCryptoFunction('BN_bin2bn');
  if not assigned(BN_bin2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bin2bn');
  Result := BN_bin2bn(s,len,ret);
end;

function Load_BN_bn2bin(const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl;
begin
  BN_bn2bin := LoadLibCryptoFunction('BN_bn2bin');
  if not assigned(BN_bn2bin) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2bin');
  Result := BN_bn2bin(a,to_);
end;

function Load_BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_bn2binpad := LoadLibCryptoFunction('BN_bn2binpad');
  if not assigned(BN_bn2binpad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2binpad');
  Result := BN_bn2binpad(a,to_,tolen);
end;

function Load_BN_lebin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_lebin2bn := LoadLibCryptoFunction('BN_lebin2bn');
  if not assigned(BN_lebin2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_lebin2bn');
  Result := BN_lebin2bn(s,len,ret);
end;

function Load_BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_bn2lebinpad := LoadLibCryptoFunction('BN_bn2lebinpad');
  if not assigned(BN_bn2lebinpad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2lebinpad');
  Result := BN_bn2lebinpad(a,to_,tolen);
end;

function Load_BN_mpi2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_mpi2bn := LoadLibCryptoFunction('BN_mpi2bn');
  if not assigned(BN_mpi2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mpi2bn');
  Result := BN_mpi2bn(s,len,ret);
end;

function Load_BN_bn2mpi(a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl;
begin
  BN_bn2mpi := LoadLibCryptoFunction('BN_bn2mpi');
  if not assigned(BN_bn2mpi) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2mpi');
  Result := BN_bn2mpi(a,to_);
end;

function Load_BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_sub := LoadLibCryptoFunction('BN_sub');
  if not assigned(BN_sub) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_sub');
  Result := BN_sub(r,a,b);
end;

function Load_BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_usub := LoadLibCryptoFunction('BN_usub');
  if not assigned(BN_usub) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_usub');
  Result := BN_usub(r,a,b);
end;

function Load_BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_uadd := LoadLibCryptoFunction('BN_uadd');
  if not assigned(BN_uadd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_uadd');
  Result := BN_uadd(r,a,b);
end;

function Load_BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_add := LoadLibCryptoFunction('BN_add');
  if not assigned(BN_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_add');
  Result := BN_add(r,a,b);
end;

function Load_BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mul := LoadLibCryptoFunction('BN_mul');
  if not assigned(BN_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mul');
  Result := BN_mul(r,a,b,ctx);
end;

function Load_BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_sqr := LoadLibCryptoFunction('BN_sqr');
  if not assigned(BN_sqr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_sqr');
  Result := BN_sqr(r,a,ctx);
end;

procedure Load_BN_set_negative(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl;
begin
  BN_set_negative := LoadLibCryptoFunction('BN_set_negative');
  if not assigned(BN_set_negative) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_negative');
  BN_set_negative(b,n);
end;

function Load_BN_is_negative(b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_is_negative := LoadLibCryptoFunction('BN_is_negative');
  if not assigned(BN_is_negative) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_negative');
  Result := BN_is_negative(b);
end;

function Load_BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_div := LoadLibCryptoFunction('BN_div');
  if not assigned(BN_div) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_div');
  Result := BN_div(dv,rem,m,d,ctx);
end;

function Load_BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_nnmod := LoadLibCryptoFunction('BN_nnmod');
  if not assigned(BN_nnmod) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nnmod');
  Result := BN_nnmod(r,m,d,ctx);
end;

function Load_BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_add := LoadLibCryptoFunction('BN_mod_add');
  if not assigned(BN_mod_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_add');
  Result := BN_mod_add(r,a,b,m,ctx);
end;

function Load_BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_add_quick := LoadLibCryptoFunction('BN_mod_add_quick');
  if not assigned(BN_mod_add_quick) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_add_quick');
  Result := BN_mod_add_quick(r,a,b,m);
end;

function Load_BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_sub := LoadLibCryptoFunction('BN_mod_sub');
  if not assigned(BN_mod_sub) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sub');
  Result := BN_mod_sub(r,a,b,m,ctx);
end;

function Load_BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_sub_quick := LoadLibCryptoFunction('BN_mod_sub_quick');
  if not assigned(BN_mod_sub_quick) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sub_quick');
  Result := BN_mod_sub_quick(r,a,b,m);
end;

function Load_BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_mul := LoadLibCryptoFunction('BN_mod_mul');
  if not assigned(BN_mod_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_mul');
  Result := BN_mod_mul(r,a,b,m,ctx);
end;

function Load_BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_sqr := LoadLibCryptoFunction('BN_mod_sqr');
  if not assigned(BN_mod_sqr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sqr');
  Result := BN_mod_sqr(r,a,m,ctx);
end;

function Load_BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_lshift1 := LoadLibCryptoFunction('BN_mod_lshift1');
  if not assigned(BN_mod_lshift1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift1');
  Result := BN_mod_lshift1(r,a,m,ctx);
end;

function Load_BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_lshift1_quick := LoadLibCryptoFunction('BN_mod_lshift1_quick');
  if not assigned(BN_mod_lshift1_quick) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift1_quick');
  Result := BN_mod_lshift1_quick(r,a,m);
end;

function Load_BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_lshift := LoadLibCryptoFunction('BN_mod_lshift');
  if not assigned(BN_mod_lshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift');
  Result := BN_mod_lshift(r,a,n,m,ctx);
end;

function Load_BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_lshift_quick := LoadLibCryptoFunction('BN_mod_lshift_quick');
  if not assigned(BN_mod_lshift_quick) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift_quick');
  Result := BN_mod_lshift_quick(r,a,n,m);
end;

function Load_BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl;
begin
  BN_mod_word := LoadLibCryptoFunction('BN_mod_word');
  if not assigned(BN_mod_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_word');
  Result := BN_mod_word(a,w);
end;

function Load_BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl;
begin
  BN_div_word := LoadLibCryptoFunction('BN_div_word');
  if not assigned(BN_div_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_div_word');
  Result := BN_div_word(a,w);
end;

function Load_BN_mul_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_mul_word := LoadLibCryptoFunction('BN_mul_word');
  if not assigned(BN_mul_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mul_word');
  Result := BN_mul_word(a,w);
end;

function Load_BN_add_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_add_word := LoadLibCryptoFunction('BN_add_word');
  if not assigned(BN_add_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_add_word');
  Result := BN_add_word(a,w);
end;

function Load_BN_sub_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_sub_word := LoadLibCryptoFunction('BN_sub_word');
  if not assigned(BN_sub_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_sub_word');
  Result := BN_sub_word(a,w);
end;

function Load_BN_set_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  BN_set_word := LoadLibCryptoFunction('BN_set_word');
  if not assigned(BN_set_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_word');
  Result := BN_set_word(a,w);
end;

function Load_BN_get_word(const a: PBIGNUM): BN_ULONG; cdecl;
begin
  BN_get_word := LoadLibCryptoFunction('BN_get_word');
  if not assigned(BN_get_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_word');
  Result := BN_get_word(a);
end;

function Load_BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_cmp := LoadLibCryptoFunction('BN_cmp');
  if not assigned(BN_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_cmp');
  Result := BN_cmp(a,b);
end;

procedure Load_BN_free(a: PBIGNUM); cdecl;
begin
  BN_free := LoadLibCryptoFunction('BN_free');
  if not assigned(BN_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_free');
  BN_free(a);
end;

function Load_BN_is_bit_set(const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_is_bit_set := LoadLibCryptoFunction('BN_is_bit_set');
  if not assigned(BN_is_bit_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_bit_set');
  Result := BN_is_bit_set(a,n);
end;

function Load_BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_lshift := LoadLibCryptoFunction('BN_lshift');
  if not assigned(BN_lshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_lshift');
  Result := BN_lshift(r,a,n);
end;

function Load_BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_lshift1 := LoadLibCryptoFunction('BN_lshift1');
  if not assigned(BN_lshift1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_lshift1');
  Result := BN_lshift1(r,a);
end;

function Load_BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_exp := LoadLibCryptoFunction('BN_exp');
  if not assigned(BN_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_exp');
  Result := BN_exp(r,a,p,ctx);
end;

function Load_BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp := LoadLibCryptoFunction('BN_mod_exp');
  if not assigned(BN_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp');
  Result := BN_mod_exp(r,a,p,m,ctx);
end;

function Load_BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp_mont := LoadLibCryptoFunction('BN_mod_exp_mont');
  if not assigned(BN_mod_exp_mont) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_mont');
  Result := BN_mod_exp_mont(r,a,p,m,ctx,m_ctx);
end;

function Load_BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp_mont_consttime := LoadLibCryptoFunction('BN_mod_exp_mont_consttime');
  if not assigned(BN_mod_exp_mont_consttime) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_mont_consttime');
  Result := BN_mod_exp_mont_consttime(rr,a,p,m,ctx,in_mont);
end;

function Load_BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp_mont_word := LoadLibCryptoFunction('BN_mod_exp_mont_word');
  if not assigned(BN_mod_exp_mont_word) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_mont_word');
  Result := BN_mod_exp_mont_word(r,a,p,m,ctx,m_ctx);
end;

function Load_BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp2_mont := LoadLibCryptoFunction('BN_mod_exp2_mont');
  if not assigned(BN_mod_exp2_mont) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp2_mont');
  Result := BN_mod_exp2_mont(r,a1,p1,a2,p2,m,ctx,m_ctx);
end;

function Load_BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp_simple := LoadLibCryptoFunction('BN_mod_exp_simple');
  if not assigned(BN_mod_exp_simple) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_simple');
  Result := BN_mod_exp_simple(r,a,p,m,ctx);
end;

function Load_BN_mask_bits(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_mask_bits := LoadLibCryptoFunction('BN_mask_bits');
  if not assigned(BN_mask_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mask_bits');
  Result := BN_mask_bits(a,n);
end;

function Load_BN_print(bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_print := LoadLibCryptoFunction('BN_print');
  if not assigned(BN_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_print');
  Result := BN_print(bio,a);
end;

function Load_BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_reciprocal := LoadLibCryptoFunction('BN_reciprocal');
  if not assigned(BN_reciprocal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_reciprocal');
  Result := BN_reciprocal(r,m,len,ctx);
end;

function Load_BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_rshift := LoadLibCryptoFunction('BN_rshift');
  if not assigned(BN_rshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rshift');
  Result := BN_rshift(r,a,n);
end;

function Load_BN_rshift1(r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_rshift1 := LoadLibCryptoFunction('BN_rshift1');
  if not assigned(BN_rshift1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rshift1');
  Result := BN_rshift1(r,a);
end;

procedure Load_BN_clear(a: PBIGNUM); cdecl;
begin
  BN_clear := LoadLibCryptoFunction('BN_clear');
  if not assigned(BN_clear) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_clear');
  BN_clear(a);
end;

function Load_BN_dup(const a: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_dup := LoadLibCryptoFunction('BN_dup');
  if not assigned(BN_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_dup');
  Result := BN_dup(a);
end;

function Load_BN_ucmp(a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_ucmp := LoadLibCryptoFunction('BN_ucmp');
  if not assigned(BN_ucmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_ucmp');
  Result := BN_ucmp(a,b);
end;

function Load_BN_set_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_set_bit := LoadLibCryptoFunction('BN_set_bit');
  if not assigned(BN_set_bit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_bit');
  Result := BN_set_bit(a,n);
end;

function Load_BN_clear_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_clear_bit := LoadLibCryptoFunction('BN_clear_bit');
  if not assigned(BN_clear_bit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_clear_bit');
  Result := BN_clear_bit(a,n);
end;

function Load_BN_bn2hex(a: PBIGNUM): PAnsiChar; cdecl;
begin
  BN_bn2hex := LoadLibCryptoFunction('BN_bn2hex');
  if not assigned(BN_bn2hex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2hex');
  Result := BN_bn2hex(a);
end;

function Load_BN_bn2dec(a: PBIGNUM): PAnsiChar; cdecl;
begin
  BN_bn2dec := LoadLibCryptoFunction('BN_bn2dec');
  if not assigned(BN_bn2dec) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2dec');
  Result := BN_bn2dec(a);
end;

function Load_BN_hex2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BN_hex2bn := LoadLibCryptoFunction('BN_hex2bn');
  if not assigned(BN_hex2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_hex2bn');
  Result := BN_hex2bn(a,str);
end;

function Load_BN_dec2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BN_dec2bn := LoadLibCryptoFunction('BN_dec2bn');
  if not assigned(BN_dec2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_dec2bn');
  Result := BN_dec2bn(a,str);
end;

function Load_BN_asc2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BN_asc2bn := LoadLibCryptoFunction('BN_asc2bn');
  if not assigned(BN_asc2bn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_asc2bn');
  Result := BN_asc2bn(a,str);
end;

function Load_BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_gcd := LoadLibCryptoFunction('BN_gcd');
  if not assigned(BN_gcd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_gcd');
  Result := BN_gcd(r,a,b,ctx);
end;

function Load_BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_kronecker := LoadLibCryptoFunction('BN_kronecker');
  if not assigned(BN_kronecker) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_kronecker');
  Result := BN_kronecker(a,b,ctx);
end;

function Load_BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  BN_mod_inverse := LoadLibCryptoFunction('BN_mod_inverse');
  if not assigned(BN_mod_inverse) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_inverse');
  Result := BN_mod_inverse(ret,a,n,ctx);
end;

function Load_BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  BN_mod_sqrt := LoadLibCryptoFunction('BN_mod_sqrt');
  if not assigned(BN_mod_sqrt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sqrt');
  Result := BN_mod_sqrt(ret,a,n,ctx);
end;

procedure Load_BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl;
begin
  BN_consttime_swap := LoadLibCryptoFunction('BN_consttime_swap');
  if not assigned(BN_consttime_swap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_consttime_swap');
  BN_consttime_swap(swap,a,b,nwords);
end;

function Load_BN_generate_prime_ex(ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  BN_generate_prime_ex := LoadLibCryptoFunction('BN_generate_prime_ex');
  if not assigned(BN_generate_prime_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_generate_prime_ex');
  Result := BN_generate_prime_ex(ret,bits,safe,add,rem,cb);
end;

function Load_BN_is_prime_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  BN_is_prime_ex := LoadLibCryptoFunction('BN_is_prime_ex');
  if not assigned(BN_is_prime_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_prime_ex');
  Result := BN_is_prime_ex(p,nchecks,ctx,cb);
end;

function Load_BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  BN_is_prime_fasttest_ex := LoadLibCryptoFunction('BN_is_prime_fasttest_ex');
  if not assigned(BN_is_prime_fasttest_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_prime_fasttest_ex');
  Result := BN_is_prime_fasttest_ex(p,nchecks,ctx,do_trial_division,cb);
end;

function Load_BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_X931_generate_Xpq := LoadLibCryptoFunction('BN_X931_generate_Xpq');
  if not assigned(BN_X931_generate_Xpq) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_X931_generate_Xpq');
  Result := BN_X931_generate_Xpq(Xp,Xq,nbits,ctx);
end;

function Load_BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  BN_X931_derive_prime_ex := LoadLibCryptoFunction('BN_X931_derive_prime_ex');
  if not assigned(BN_X931_derive_prime_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_X931_derive_prime_ex');
  Result := BN_X931_derive_prime_ex(p,p1,p2,Xp,Xp1,Xp2,e,ctx,cb);
end;

function Load_BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  BN_X931_generate_prime_ex := LoadLibCryptoFunction('BN_X931_generate_prime_ex');
  if not assigned(BN_X931_generate_prime_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_X931_generate_prime_ex');
  Result := BN_X931_generate_prime_ex(p,p1,p2,Xp1,Xp2,Xp,e,ctx,cb);
end;

function Load_BN_MONT_CTX_new: PBN_MONT_CTX; cdecl;
begin
  BN_MONT_CTX_new := LoadLibCryptoFunction('BN_MONT_CTX_new');
  if not assigned(BN_MONT_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_new');
  Result := BN_MONT_CTX_new();
end;

function Load_BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_mul_montgomery := LoadLibCryptoFunction('BN_mod_mul_montgomery');
  if not assigned(BN_mod_mul_montgomery) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_mul_montgomery');
  Result := BN_mod_mul_montgomery(r,a,b,mont,ctx);
end;

function Load_BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_to_montgomery := LoadLibCryptoFunction('BN_to_montgomery');
  if not assigned(BN_to_montgomery) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_to_montgomery');
  Result := BN_to_montgomery(r,a,mont,ctx);
end;

function Load_BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_from_montgomery := LoadLibCryptoFunction('BN_from_montgomery');
  if not assigned(BN_from_montgomery) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_from_montgomery');
  Result := BN_from_montgomery(r,a,mont,ctx);
end;

procedure Load_BN_MONT_CTX_free(mont: PBN_MONT_CTX); cdecl;
begin
  BN_MONT_CTX_free := LoadLibCryptoFunction('BN_MONT_CTX_free');
  if not assigned(BN_MONT_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_free');
  BN_MONT_CTX_free(mont);
end;

function Load_BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_MONT_CTX_set := LoadLibCryptoFunction('BN_MONT_CTX_set');
  if not assigned(BN_MONT_CTX_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_set');
  Result := BN_MONT_CTX_set(mont,mod_,ctx);
end;

function Load_BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl;
begin
  BN_MONT_CTX_copy := LoadLibCryptoFunction('BN_MONT_CTX_copy');
  if not assigned(BN_MONT_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_copy');
  Result := BN_MONT_CTX_copy(to_,from);
end;

function Load_BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl;
begin
  BN_BLINDING_new := LoadLibCryptoFunction('BN_BLINDING_new');
  if not assigned(BN_BLINDING_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_new');
  Result := BN_BLINDING_new(A,Ai,mod_);
end;

procedure Load_BN_BLINDING_free(b: PBN_BLINDING); cdecl;
begin
  BN_BLINDING_free := LoadLibCryptoFunction('BN_BLINDING_free');
  if not assigned(BN_BLINDING_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_free');
  BN_BLINDING_free(b);
end;

function Load_BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_update := LoadLibCryptoFunction('BN_BLINDING_update');
  if not assigned(BN_BLINDING_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_update');
  Result := BN_BLINDING_update(b,ctx);
end;

function Load_BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_convert := LoadLibCryptoFunction('BN_BLINDING_convert');
  if not assigned(BN_BLINDING_convert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_convert');
  Result := BN_BLINDING_convert(n,b,ctx);
end;

function Load_BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_invert := LoadLibCryptoFunction('BN_BLINDING_invert');
  if not assigned(BN_BLINDING_invert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_invert');
  Result := BN_BLINDING_invert(n,b,ctx);
end;

function Load_BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_convert_ex := LoadLibCryptoFunction('BN_BLINDING_convert_ex');
  if not assigned(BN_BLINDING_convert_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_convert_ex');
  Result := BN_BLINDING_convert_ex(n,r,b,v4);
end;

function Load_BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_invert_ex := LoadLibCryptoFunction('BN_BLINDING_invert_ex');
  if not assigned(BN_BLINDING_invert_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_invert_ex');
  Result := BN_BLINDING_invert_ex(n,r,b,v2);
end;

function Load_BN_BLINDING_is_current_thread(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_is_current_thread := LoadLibCryptoFunction('BN_BLINDING_is_current_thread');
  if not assigned(BN_BLINDING_is_current_thread) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_is_current_thread');
  Result := BN_BLINDING_is_current_thread(b);
end;

procedure Load_BN_BLINDING_set_current_thread(b: PBN_BLINDING); cdecl;
begin
  BN_BLINDING_set_current_thread := LoadLibCryptoFunction('BN_BLINDING_set_current_thread');
  if not assigned(BN_BLINDING_set_current_thread) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_set_current_thread');
  BN_BLINDING_set_current_thread(b);
end;

function Load_BN_BLINDING_lock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_lock := LoadLibCryptoFunction('BN_BLINDING_lock');
  if not assigned(BN_BLINDING_lock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_lock');
  Result := BN_BLINDING_lock(b);
end;

function Load_BN_BLINDING_unlock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
begin
  BN_BLINDING_unlock := LoadLibCryptoFunction('BN_BLINDING_unlock');
  if not assigned(BN_BLINDING_unlock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_unlock');
  Result := BN_BLINDING_unlock(b);
end;

function Load_BN_BLINDING_get_flags(v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl;
begin
  BN_BLINDING_get_flags := LoadLibCryptoFunction('BN_BLINDING_get_flags');
  if not assigned(BN_BLINDING_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_get_flags');
  Result := BN_BLINDING_get_flags(v1);
end;

procedure Load_BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl;
begin
  BN_BLINDING_set_flags := LoadLibCryptoFunction('BN_BLINDING_set_flags');
  if not assigned(BN_BLINDING_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_set_flags');
  BN_BLINDING_set_flags(v1,v2);
end;

procedure Load_BN_RECP_CTX_free(recp: PBN_RECP_CTX); cdecl;
begin
  BN_RECP_CTX_free := LoadLibCryptoFunction('BN_RECP_CTX_free');
  if not assigned(BN_RECP_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_RECP_CTX_free');
  BN_RECP_CTX_free(recp);
end;

function Load_BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_RECP_CTX_set := LoadLibCryptoFunction('BN_RECP_CTX_set');
  if not assigned(BN_RECP_CTX_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_RECP_CTX_set');
  Result := BN_RECP_CTX_set(recp,rdiv,ctx);
end;

function Load_BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_mul_reciprocal := LoadLibCryptoFunction('BN_mod_mul_reciprocal');
  if not assigned(BN_mod_mul_reciprocal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_mul_reciprocal');
  Result := BN_mod_mul_reciprocal(r,x,y,recp,ctx);
end;

function Load_BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_mod_exp_recp := LoadLibCryptoFunction('BN_mod_exp_recp');
  if not assigned(BN_mod_exp_recp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_recp');
  Result := BN_mod_exp_recp(r,a,p,m,ctx);
end;

function Load_BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_div_recp := LoadLibCryptoFunction('BN_div_recp');
  if not assigned(BN_div_recp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_div_recp');
  Result := BN_div_recp(dv,rem,m,recp,ctx);
end;

function Load_BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_add := LoadLibCryptoFunction('BN_GF2m_add');
  if not assigned(BN_GF2m_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_add');
  Result := BN_GF2m_add(r,a,b);
end;

function Load_BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod := LoadLibCryptoFunction('BN_GF2m_mod');
  if not assigned(BN_GF2m_mod) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod');
  Result := BN_GF2m_mod(r,a,p);
end;

function Load_BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_mul := LoadLibCryptoFunction('BN_GF2m_mod_mul');
  if not assigned(BN_GF2m_mod_mul) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_mul');
  Result := BN_GF2m_mod_mul(r,a,b,p,ctx);
end;

function Load_BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_sqr := LoadLibCryptoFunction('BN_GF2m_mod_sqr');
  if not assigned(BN_GF2m_mod_sqr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_sqr');
  Result := BN_GF2m_mod_sqr(r,a,p,ctx);
end;

function Load_BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_inv := LoadLibCryptoFunction('BN_GF2m_mod_inv');
  if not assigned(BN_GF2m_mod_inv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_inv');
  Result := BN_GF2m_mod_inv(r,b,p,ctx);
end;

function Load_BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_div := LoadLibCryptoFunction('BN_GF2m_mod_div');
  if not assigned(BN_GF2m_mod_div) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_div');
  Result := BN_GF2m_mod_div(r,a,b,p,ctx);
end;

function Load_BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_exp := LoadLibCryptoFunction('BN_GF2m_mod_exp');
  if not assigned(BN_GF2m_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_exp');
  Result := BN_GF2m_mod_exp(r,a,b,p,ctx);
end;

function Load_BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_sqrt := LoadLibCryptoFunction('BN_GF2m_mod_sqrt');
  if not assigned(BN_GF2m_mod_sqrt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_sqrt');
  Result := BN_GF2m_mod_sqrt(r,a,p,ctx);
end;

function Load_BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_GF2m_mod_solve_quad := LoadLibCryptoFunction('BN_GF2m_mod_solve_quad');
  if not assigned(BN_GF2m_mod_solve_quad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_solve_quad');
  Result := BN_GF2m_mod_solve_quad(r,a,p,ctx);
end;

function Load_BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_nist_mod_192 := LoadLibCryptoFunction('BN_nist_mod_192');
  if not assigned(BN_nist_mod_192) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_192');
  Result := BN_nist_mod_192(r,a,p,ctx);
end;

function Load_BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_nist_mod_224 := LoadLibCryptoFunction('BN_nist_mod_224');
  if not assigned(BN_nist_mod_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_224');
  Result := BN_nist_mod_224(r,a,p,ctx);
end;

function Load_BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_nist_mod_256 := LoadLibCryptoFunction('BN_nist_mod_256');
  if not assigned(BN_nist_mod_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_256');
  Result := BN_nist_mod_256(r,a,p,ctx);
end;

function Load_BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_nist_mod_384 := LoadLibCryptoFunction('BN_nist_mod_384');
  if not assigned(BN_nist_mod_384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_384');
  Result := BN_nist_mod_384(r,a,p,ctx);
end;

function Load_BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_nist_mod_521 := LoadLibCryptoFunction('BN_nist_mod_521');
  if not assigned(BN_nist_mod_521) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_521');
  Result := BN_nist_mod_521(r,a,p,ctx);
end;

function Load_BN_get0_nist_prime_192: PBIGNUM; cdecl;
begin
  BN_get0_nist_prime_192 := LoadLibCryptoFunction('BN_get0_nist_prime_192');
  if not assigned(BN_get0_nist_prime_192) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_192');
  Result := BN_get0_nist_prime_192();
end;

function Load_BN_get0_nist_prime_224: PBIGNUM; cdecl;
begin
  BN_get0_nist_prime_224 := LoadLibCryptoFunction('BN_get0_nist_prime_224');
  if not assigned(BN_get0_nist_prime_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_224');
  Result := BN_get0_nist_prime_224();
end;

function Load_BN_get0_nist_prime_256: PBIGNUM; cdecl;
begin
  BN_get0_nist_prime_256 := LoadLibCryptoFunction('BN_get0_nist_prime_256');
  if not assigned(BN_get0_nist_prime_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_256');
  Result := BN_get0_nist_prime_256();
end;

function Load_BN_get0_nist_prime_384: PBIGNUM; cdecl;
begin
  BN_get0_nist_prime_384 := LoadLibCryptoFunction('BN_get0_nist_prime_384');
  if not assigned(BN_get0_nist_prime_384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_384');
  Result := BN_get0_nist_prime_384();
end;

function Load_BN_get0_nist_prime_521: PBIGNUM; cdecl;
begin
  BN_get0_nist_prime_521 := LoadLibCryptoFunction('BN_get0_nist_prime_521');
  if not assigned(BN_get0_nist_prime_521) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_521');
  Result := BN_get0_nist_prime_521();
end;

function Load_BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  BN_generate_dsa_nonce := LoadLibCryptoFunction('BN_generate_dsa_nonce');
  if not assigned(BN_generate_dsa_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_generate_dsa_nonce');
  Result := BN_generate_dsa_nonce(out_,range,priv,message_,message_len,ctx);
end;

function Load_BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM; cdecl;
begin
  BN_get_rfc2409_prime_768 := LoadLibCryptoFunction('BN_get_rfc2409_prime_768');
  if not assigned(BN_get_rfc2409_prime_768) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc2409_prime_768');
  Result := BN_get_rfc2409_prime_768(bn);
end;

function Load_BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc2409_prime_1024 := LoadLibCryptoFunction('BN_get_rfc2409_prime_1024');
  if not assigned(BN_get_rfc2409_prime_1024) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc2409_prime_1024');
  Result := BN_get_rfc2409_prime_1024(bn);
end;

function Load_BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc3526_prime_1536 := LoadLibCryptoFunction('BN_get_rfc3526_prime_1536');
  if not assigned(BN_get_rfc3526_prime_1536) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_1536');
  Result := BN_get_rfc3526_prime_1536(bn);
end;

function Load_BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc3526_prime_2048 := LoadLibCryptoFunction('BN_get_rfc3526_prime_2048');
  if not assigned(BN_get_rfc3526_prime_2048) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_2048');
  Result := BN_get_rfc3526_prime_2048(bn);
end;

function Load_BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc3526_prime_3072 := LoadLibCryptoFunction('BN_get_rfc3526_prime_3072');
  if not assigned(BN_get_rfc3526_prime_3072) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_3072');
  Result := BN_get_rfc3526_prime_3072(bn);
end;

function Load_BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc3526_prime_4096 := LoadLibCryptoFunction('BN_get_rfc3526_prime_4096');
  if not assigned(BN_get_rfc3526_prime_4096) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_4096');
  Result := BN_get_rfc3526_prime_4096(bn);
end;

function Load_BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc3526_prime_6144 := LoadLibCryptoFunction('BN_get_rfc3526_prime_6144');
  if not assigned(BN_get_rfc3526_prime_6144) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_6144');
  Result := BN_get_rfc3526_prime_6144(bn);
end;

function Load_BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  BN_get_rfc3526_prime_8192 := LoadLibCryptoFunction('BN_get_rfc3526_prime_8192');
  if not assigned(BN_get_rfc3526_prime_8192) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_8192');
  Result := BN_get_rfc3526_prime_8192(bn);
end;

function Load_BN_bntest_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BN_bntest_rand := LoadLibCryptoFunction('BN_bntest_rand');
  if not assigned(BN_bntest_rand) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bntest_rand');
  Result := BN_bntest_rand(rnd,bits,top,bottom);
end;


procedure UnLoad;
begin
  BN_set_flags := Load_BN_set_flags;
  BN_get_flags := Load_BN_get_flags;
  BN_with_flags := Load_BN_with_flags;
  BN_GENCB_call := Load_BN_GENCB_call;
  BN_GENCB_new := Load_BN_GENCB_new;
  BN_GENCB_free := Load_BN_GENCB_free;
  BN_GENCB_set_old := Load_BN_GENCB_set_old;
  BN_GENCB_set := Load_BN_GENCB_set;
  BN_GENCB_get_arg := Load_BN_GENCB_get_arg;
  BN_abs_is_word := Load_BN_abs_is_word;
  BN_is_zero := Load_BN_is_zero;
  BN_is_one := Load_BN_is_one;
  BN_is_word := Load_BN_is_word;
  BN_is_odd := Load_BN_is_odd;
  BN_zero_ex := Load_BN_zero_ex;
  BN_value_one := Load_BN_value_one;
  BN_options := Load_BN_options;
  BN_CTX_new := Load_BN_CTX_new;
  BN_CTX_secure_new := Load_BN_CTX_secure_new;
  BN_CTX_free := Load_BN_CTX_free;
  BN_CTX_start := Load_BN_CTX_start;
  BN_CTX_get := Load_BN_CTX_get;
  BN_CTX_end := Load_BN_CTX_end;
  BN_rand := Load_BN_rand;
  BN_priv_rand := Load_BN_priv_rand;
  BN_rand_range := Load_BN_rand_range;
  BN_priv_rand_range := Load_BN_priv_rand_range;
  BN_pseudo_rand := Load_BN_pseudo_rand;
  BN_pseudo_rand_range := Load_BN_pseudo_rand_range;
  BN_num_bits := Load_BN_num_bits;
  BN_num_bits_word := Load_BN_num_bits_word;
  BN_security_bits := Load_BN_security_bits;
  BN_new := Load_BN_new;
  BN_secure_new := Load_BN_secure_new;
  BN_clear_free := Load_BN_clear_free;
  BN_copy := Load_BN_copy;
  BN_swap := Load_BN_swap;
  BN_bin2bn := Load_BN_bin2bn;
  BN_bn2bin := Load_BN_bn2bin;
  BN_bn2binpad := Load_BN_bn2binpad;
  BN_lebin2bn := Load_BN_lebin2bn;
  BN_bn2lebinpad := Load_BN_bn2lebinpad;
  BN_mpi2bn := Load_BN_mpi2bn;
  BN_bn2mpi := Load_BN_bn2mpi;
  BN_sub := Load_BN_sub;
  BN_usub := Load_BN_usub;
  BN_uadd := Load_BN_uadd;
  BN_add := Load_BN_add;
  BN_mul := Load_BN_mul;
  BN_sqr := Load_BN_sqr;
  BN_set_negative := Load_BN_set_negative;
  BN_is_negative := Load_BN_is_negative;
  BN_div := Load_BN_div;
  BN_nnmod := Load_BN_nnmod;
  BN_mod_add := Load_BN_mod_add;
  BN_mod_add_quick := Load_BN_mod_add_quick;
  BN_mod_sub := Load_BN_mod_sub;
  BN_mod_sub_quick := Load_BN_mod_sub_quick;
  BN_mod_mul := Load_BN_mod_mul;
  BN_mod_sqr := Load_BN_mod_sqr;
  BN_mod_lshift1 := Load_BN_mod_lshift1;
  BN_mod_lshift1_quick := Load_BN_mod_lshift1_quick;
  BN_mod_lshift := Load_BN_mod_lshift;
  BN_mod_lshift_quick := Load_BN_mod_lshift_quick;
  BN_mod_word := Load_BN_mod_word;
  BN_div_word := Load_BN_div_word;
  BN_mul_word := Load_BN_mul_word;
  BN_add_word := Load_BN_add_word;
  BN_sub_word := Load_BN_sub_word;
  BN_set_word := Load_BN_set_word;
  BN_get_word := Load_BN_get_word;
  BN_cmp := Load_BN_cmp;
  BN_free := Load_BN_free;
  BN_is_bit_set := Load_BN_is_bit_set;
  BN_lshift := Load_BN_lshift;
  BN_lshift1 := Load_BN_lshift1;
  BN_exp := Load_BN_exp;
  BN_mod_exp := Load_BN_mod_exp;
  BN_mod_exp_mont := Load_BN_mod_exp_mont;
  BN_mod_exp_mont_consttime := Load_BN_mod_exp_mont_consttime;
  BN_mod_exp_mont_word := Load_BN_mod_exp_mont_word;
  BN_mod_exp2_mont := Load_BN_mod_exp2_mont;
  BN_mod_exp_simple := Load_BN_mod_exp_simple;
  BN_mask_bits := Load_BN_mask_bits;
  BN_print := Load_BN_print;
  BN_reciprocal := Load_BN_reciprocal;
  BN_rshift := Load_BN_rshift;
  BN_rshift1 := Load_BN_rshift1;
  BN_clear := Load_BN_clear;
  BN_dup := Load_BN_dup;
  BN_ucmp := Load_BN_ucmp;
  BN_set_bit := Load_BN_set_bit;
  BN_clear_bit := Load_BN_clear_bit;
  BN_bn2hex := Load_BN_bn2hex;
  BN_bn2dec := Load_BN_bn2dec;
  BN_hex2bn := Load_BN_hex2bn;
  BN_dec2bn := Load_BN_dec2bn;
  BN_asc2bn := Load_BN_asc2bn;
  BN_gcd := Load_BN_gcd;
  BN_kronecker := Load_BN_kronecker;
  BN_mod_inverse := Load_BN_mod_inverse;
  BN_mod_sqrt := Load_BN_mod_sqrt;
  BN_consttime_swap := Load_BN_consttime_swap;
  BN_generate_prime_ex := Load_BN_generate_prime_ex;
  BN_is_prime_ex := Load_BN_is_prime_ex;
  BN_is_prime_fasttest_ex := Load_BN_is_prime_fasttest_ex;
  BN_X931_generate_Xpq := Load_BN_X931_generate_Xpq;
  BN_X931_derive_prime_ex := Load_BN_X931_derive_prime_ex;
  BN_X931_generate_prime_ex := Load_BN_X931_generate_prime_ex;
  BN_MONT_CTX_new := Load_BN_MONT_CTX_new;
  BN_mod_mul_montgomery := Load_BN_mod_mul_montgomery;
  BN_to_montgomery := Load_BN_to_montgomery;
  BN_from_montgomery := Load_BN_from_montgomery;
  BN_MONT_CTX_free := Load_BN_MONT_CTX_free;
  BN_MONT_CTX_set := Load_BN_MONT_CTX_set;
  BN_MONT_CTX_copy := Load_BN_MONT_CTX_copy;
  BN_BLINDING_new := Load_BN_BLINDING_new;
  BN_BLINDING_free := Load_BN_BLINDING_free;
  BN_BLINDING_update := Load_BN_BLINDING_update;
  BN_BLINDING_convert := Load_BN_BLINDING_convert;
  BN_BLINDING_invert := Load_BN_BLINDING_invert;
  BN_BLINDING_convert_ex := Load_BN_BLINDING_convert_ex;
  BN_BLINDING_invert_ex := Load_BN_BLINDING_invert_ex;
  BN_BLINDING_is_current_thread := Load_BN_BLINDING_is_current_thread;
  BN_BLINDING_set_current_thread := Load_BN_BLINDING_set_current_thread;
  BN_BLINDING_lock := Load_BN_BLINDING_lock;
  BN_BLINDING_unlock := Load_BN_BLINDING_unlock;
  BN_BLINDING_get_flags := Load_BN_BLINDING_get_flags;
  BN_BLINDING_set_flags := Load_BN_BLINDING_set_flags;
  BN_RECP_CTX_free := Load_BN_RECP_CTX_free;
  BN_RECP_CTX_set := Load_BN_RECP_CTX_set;
  BN_mod_mul_reciprocal := Load_BN_mod_mul_reciprocal;
  BN_mod_exp_recp := Load_BN_mod_exp_recp;
  BN_div_recp := Load_BN_div_recp;
  BN_GF2m_add := Load_BN_GF2m_add;
  BN_GF2m_mod := Load_BN_GF2m_mod;
  BN_GF2m_mod_mul := Load_BN_GF2m_mod_mul;
  BN_GF2m_mod_sqr := Load_BN_GF2m_mod_sqr;
  BN_GF2m_mod_inv := Load_BN_GF2m_mod_inv;
  BN_GF2m_mod_div := Load_BN_GF2m_mod_div;
  BN_GF2m_mod_exp := Load_BN_GF2m_mod_exp;
  BN_GF2m_mod_sqrt := Load_BN_GF2m_mod_sqrt;
  BN_GF2m_mod_solve_quad := Load_BN_GF2m_mod_solve_quad;
  BN_nist_mod_192 := Load_BN_nist_mod_192;
  BN_nist_mod_224 := Load_BN_nist_mod_224;
  BN_nist_mod_256 := Load_BN_nist_mod_256;
  BN_nist_mod_384 := Load_BN_nist_mod_384;
  BN_nist_mod_521 := Load_BN_nist_mod_521;
  BN_get0_nist_prime_192 := Load_BN_get0_nist_prime_192;
  BN_get0_nist_prime_224 := Load_BN_get0_nist_prime_224;
  BN_get0_nist_prime_256 := Load_BN_get0_nist_prime_256;
  BN_get0_nist_prime_384 := Load_BN_get0_nist_prime_384;
  BN_get0_nist_prime_521 := Load_BN_get0_nist_prime_521;
  BN_generate_dsa_nonce := Load_BN_generate_dsa_nonce;
  BN_get_rfc2409_prime_768 := Load_BN_get_rfc2409_prime_768;
  BN_get_rfc2409_prime_1024 := Load_BN_get_rfc2409_prime_1024;
  BN_get_rfc3526_prime_1536 := Load_BN_get_rfc3526_prime_1536;
  BN_get_rfc3526_prime_2048 := Load_BN_get_rfc3526_prime_2048;
  BN_get_rfc3526_prime_3072 := Load_BN_get_rfc3526_prime_3072;
  BN_get_rfc3526_prime_4096 := Load_BN_get_rfc3526_prime_4096;
  BN_get_rfc3526_prime_6144 := Load_BN_get_rfc3526_prime_6144;
  BN_get_rfc3526_prime_8192 := Load_BN_get_rfc3526_prime_8192;
  BN_bntest_rand := Load_BN_bntest_rand;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
