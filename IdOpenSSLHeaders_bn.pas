  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_bn.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_bn.h2pas
     and this file regenerated. IdOpenSSLHeaders_bn.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_bn;

interface

// Headers for OpenSSL 1.1.1
// bn.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
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
  BN_ULONG = TIdC_ULONG;

  BN_GENCB_set_old_cb = procedure (a: TIdC_INT; b: TIdC_INT; c: Pointer); cdecl;
  BN_GENCB_set_cb = function (a: TIdC_INT; b: TIdC_INT; c: PBN_GENCB): TIdC_INT; cdecl;

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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  BN_set_flags: procedure (b: PBIGNUM; n: TIdC_INT); cdecl = nil;
  BN_get_flags: function (b: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;

  (*
   * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
   * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
   * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
   * has not been otherwise initialised or used.
   *)
  BN_with_flags: procedure (dest: PBIGNUM; b: PBIGNUM; flags: TIdC_INT); cdecl = nil;
  (* Wrapper function to make using BN_GENCB easier *)
  BN_GENCB_call: function (cb: PBN_GENCB; a: TIdC_INT; b: TIdC_INT): TIdC_INT; cdecl = nil;

  BN_GENCB_new: function : PBN_GENCB; cdecl = nil;
  BN_GENCB_free: procedure (cb: PBN_GENCB); cdecl = nil;

  (* Populate a PBN_GENCB structure with an "old"-style callback *)
  BN_GENCB_set_old: procedure (gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl = nil;

  (* Populate a PBN_GENCB structure with a "new"-style callback *)
  BN_GENCB_set: procedure (gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl = nil;

  BN_GENCB_get_arg: function (cb: PBN_GENCB): Pointer; cdecl = nil;
  
  (*
   * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
   * that will be done for checking that a random number is probably prime. The
   * error rate for accepting a composite number as prime depends on the size of
   * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
   * and so the level is what you would expect for a key of double the size of the
   * prime.
   *
   * This table is generated using the algorithm of FIPS PUB 186-4
   * Digital Signature Standard (DSS), section F.1, page 117.
   * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
   *
   * The following magma script was used to generate the output:
   * securitybits:=125;
   * k:=1024;
   * for t:=1 to 65 do
   *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
   *     S:=0;
   *     // Sum over m
   *     for m:=3 to M do
   *       s:=0;
   *       // Sum over j
   *       for j:=2 to m do
   *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
   *       end for;
   *       S+:=2^(m-(m-1)*t)*s;
   *     end for;
   *     A:=2^(k-2-M*t);
   *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
   *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
   *     seclevel:=Floor(-Log(2,pkt));
   *     if seclevel ge securitybits then
   *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
   *       break;
   *     end if;
   *   end for;
   *   if seclevel ge securitybits then break; end if;
   * end for;
   *
   * It can be run online at:
   * http://magma.maths.usyd.edu.au/calc
   *
   * And will output:
   * k:  1024, security: 129 bits  (t: 6, M: 23)
   *
   * k is the number of bits of the prime, securitybits is the level we want to
   * reach.
   *
   * prime length | RSA key size | # MR tests | security level
   * -------------+--------------|------------+---------------
   *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
   *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
   *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
   *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
   *  (b) >=  852 |     >=  1704 |          5 |        112 bit
   *  (b) >=  476 |     >=   952 |          5 |         80 bit
   *  (b) >=  400 |     >=   800 |          6 |         80 bit
   *  (b) >=  347 |     >=   694 |          7 |         80 bit
   *  (b) >=  308 |     >=   616 |          8 |         80 bit
   *  (b) >=   55 |     >=   110 |         27 |         64 bit
   *  (b) >=    6 |     >=    12 |         34 |         64 bit
   *)

//  # define BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
//                                  (b) >=  1345 ?  4 : \
//                                  (b) >=  476 ?  5 : \
//                                  (b) >=  400 ?  6 : \
//                                  (b) >=  347 ?  7 : \
//                                  (b) >=  308 ?  8 : \
//                                  (b) >=  55  ? 27 : \
//                                  (* b >= 6 *) 34)
//
//  # define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

  BN_abs_is_word: function (a: PBIGNUM; w: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_is_zero: function (a: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_is_one: function (a: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_is_word: function (a: PBIGNUM; w: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_is_odd: function (a: PBIGNUM): TIdC_INT; cdecl = nil;

//  # define BN_one(a)       (BN_set_word((a),1))

  BN_zero_ex: procedure (a: PBIGNUM); cdecl = nil;

  BN_value_one: function : PBIGNUM; cdecl = nil;
  BN_options: function : PIdAnsiChar; cdecl = nil;
  BN_CTX_new: function : PBN_CTX; cdecl = nil;
  BN_CTX_secure_new: function : PBN_CTX; cdecl = nil;
  BN_CTX_free: procedure (c: PBN_CTX); cdecl = nil;
  BN_CTX_start: procedure (ctx: PBN_CTX); cdecl = nil;
  BN_CTX_get: function (ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  BN_CTX_end: procedure (ctx: PBN_CTX); cdecl = nil;
  BN_rand: function (rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_priv_rand: function (rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_priv_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_pseudo_rand: function (rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_pseudo_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_num_bits: function (a: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_num_bits_word: function (l: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_security_bits: function (L: TIdC_INT; N: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_new: function : PBIGNUM; cdecl = nil;
  BN_secure_new: function : PBIGNUM; cdecl = nil;
  BN_clear_free: procedure (a: PBIGNUM); cdecl = nil;
  BN_copy: function (a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_swap: procedure (a: PBIGNUM; b: PBIGNUM); cdecl = nil;
  BN_bin2bn: function (const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bn2bin: function (const a: PBIGNUM; to_: PByte): TIdC_INT; cdecl = nil;
  BN_bn2binpad: function (const a: PBIGNUM; to_: PByte; tolen: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_lebin2bn: function (const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bn2lebinpad: function (a: PBIGNUM; to_: PByte; tolen: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_mpi2bn: function (const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bn2mpi: function (a: PBIGNUM; to_: PByte): TIdC_INT; cdecl = nil;
  BN_sub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_usub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_uadd: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_add: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_mul: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_sqr: function (r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  (** BN_set_negative sets sign of a BIGNUM
   * \param  b  pointer to the BIGNUM object
   * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
   *)
  BN_set_negative: procedure (b: PBIGNUM; n: TIdC_INT); cdecl = nil;
  (** BN_is_negative returns 1 if the BIGNUM is negative
   * \param  b  pointer to the BIGNUM object
   * \return 1 if a < 0 and 0 otherwise
   *)
  BN_is_negative: function (b: PBIGNUM): TIdC_INT; cdecl = nil;

  BN_div: function (dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
//  # define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
  BN_nnmod: function (r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_add: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_add_quick: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_mod_sub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_sub_quick: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_mod_mul: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_sqr: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_lshift1: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_lshift1_quick: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_mod_lshift: function (r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_lshift_quick: function (r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT; const m: PBIGNUM): TIdC_INT; cdecl = nil;

  BN_mod_word: function (const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl = nil;
  BN_div_word: function (a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl = nil;
  BN_mul_word: function (a: PBIGNUM; w: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_add_word: function (a: PBIGNUM; w: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_sub_word: function (a: PBIGNUM; w: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_set_word: function (a: PBIGNUM; w: BN_ULONG): TIdC_INT; cdecl = nil;
  BN_get_word: function (const a: PBIGNUM): BN_ULONG; cdecl = nil;

  BN_cmp: function (const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_free: procedure (a: PBIGNUM); cdecl = nil;
  BN_is_bit_set: function (const a: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_lshift: function (r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_lshift1: function (r: PBIGNUM; const a: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_exp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  BN_mod_exp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_exp_mont: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT; cdecl = nil;
  BN_mod_exp_mont_consttime: function (rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TIdC_INT; cdecl = nil;
  BN_mod_exp_mont_word: function (r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT; cdecl = nil;
  BN_mod_exp2_mont: function (r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT; cdecl = nil;
  BN_mod_exp_simple: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  BN_mask_bits: function (a: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_print: function (bio: PBIO; a: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_reciprocal: function (r: PBIGNUM; m: PBIGNUM; len: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_rshift: function (r: PBIGNUM; a: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_rshift1: function (r: PBIGNUM; a: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_clear: procedure (a: PBIGNUM); cdecl = nil;
  BN_dup: function (const a: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_ucmp: function (a: PBIGNUM; b: PBIGNUM): TIdC_INT; cdecl = nil;
  BN_set_bit: function (a: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_clear_bit: function (a: PBIGNUM; n: TIdC_INT): TIdC_INT; cdecl = nil;
  BN_bn2hex: function (a: PBIGNUM): PIdAnsiChar; cdecl = nil;
  BN_bn2dec: function (a: PBIGNUM): PIdAnsiChar; cdecl = nil;
  BN_hex2bn: function (a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  BN_dec2bn: function (a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  BN_asc2bn: function (a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  BN_gcd: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_kronecker: function (a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  BN_mod_inverse: function (ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  BN_mod_sqrt: function (ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = nil;

  BN_consttime_swap: procedure (swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TIdC_INT); cdecl = nil;

  BN_generate_prime_ex: function (ret: PBIGNUM; bits: TIdC_INT; safe: TIdC_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  BN_is_prime_ex: function (const p: PBIGNUM; nchecks: TIdC_INT; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  BN_is_prime_fasttest_ex: function (const p: PBIGNUM; nchecks: TIdC_INT; ctx: PBN_CTX; do_trial_division: TIdC_INT; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  BN_X931_generate_Xpq: function (Xp: PBIGNUM; Xq: PBIGNUM; nbits: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_X931_derive_prime_ex: function (p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  BN_X931_generate_prime_ex: function (p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  BN_MONT_CTX_new: function : PBN_MONT_CTX; cdecl = nil;
  BN_mod_mul_montgomery: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_to_montgomery: function (r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_from_montgomery: function (r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_MONT_CTX_free: procedure (mont: PBN_MONT_CTX); cdecl = nil;
  BN_MONT_CTX_set: function (mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_MONT_CTX_copy: function (to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl = nil;
//  function BN_MONT_CTX_set_locked(pmont: ^PBN_MONT_CTX; lock: CRYPTO_RWLOCK; mod_: PBIGNUM; ctx: PBN_CTX): PBN_MONT_CTX;

  BN_BLINDING_new: function (const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl = nil;
  BN_BLINDING_free: procedure (b: PBN_BLINDING); cdecl = nil;
  BN_BLINDING_update: function (b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_BLINDING_convert: function (n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_BLINDING_invert: function (n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_BLINDING_convert_ex: function (n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_BLINDING_invert_ex: function (n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TIdC_INT; cdecl = nil;

  BN_BLINDING_is_current_thread: function (b: PBN_BLINDING): TIdC_INT; cdecl = nil;
  BN_BLINDING_set_current_thread: procedure (b: PBN_BLINDING); cdecl = nil;
  BN_BLINDING_lock: function (b: PBN_BLINDING): TIdC_INT; cdecl = nil;
  BN_BLINDING_unlock: function (b: PBN_BLINDING): TIdC_INT; cdecl = nil;

  BN_BLINDING_get_flags: function (v1: PBN_BLINDING): TIdC_ULONG; cdecl = nil;
  BN_BLINDING_set_flags: procedure (v1: PBN_BLINDING; v2: TIdC_ULONG); cdecl = nil;
//  function BN_BLINDING_create_param(PBN_BLINDING *b,
//                                         PBIGNUM *e, PBIGNUM *m, PBN_CTX *ctx,
//                                        function (
//    r: PBIGNUM;
//    a: PBIGNUM;
//    p: PBIGNUM;
//    m: PBIGNUM;
//    ctx: PBN_CTX;
//    m_ctx: PBN_MONT_CTX): TIdC_INT,
//                                        PBN_MONT_CTX *m_ctx): PBN_BLINDING;

  BN_RECP_CTX_free: procedure (recp: PBN_RECP_CTX); cdecl = nil;
  BN_RECP_CTX_set: function (recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_mul_reciprocal: function (r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_mod_exp_recp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_div_recp: function (dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  (*
   * Functions for arithmetic over binary polynomials represented by BIGNUMs.
   * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
   * ignored. Note that input arguments are not const so that their bit arrays
   * can be expanded to the appropriate size if needed.
   *)

  (*
   * r = a + b
   *)
  BN_GF2m_add: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TIdC_INT; cdecl = nil;
//  #  define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
  (*
   * r=a mod p
   *)
  BN_GF2m_mod: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TIdC_INT; cdecl = nil;
  (* r = (a * b) mod p *)
  BN_GF2m_mod_mul: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  (* r = (a * a) mod p *)
  BN_GF2m_mod_sqr: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  (* r = (1 / b) mod p *)
  BN_GF2m_mod_inv: function (r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  (* r = (a / b) mod p *)
  BN_GF2m_mod_div: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  (* r = (a ^ b) mod p *)
  BN_GF2m_mod_exp: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  (* r = sqrt(a) mod p *)
  BN_GF2m_mod_sqrt: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  (* r^2 + r = a mod p *)
  BN_GF2m_mod_solve_quad: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
//  #  define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
  (*-
   * Some functions allow for representation of the irreducible polynomials
   * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
   *     t^p[0] + t^p[1] + ... + t^p[k]
   * where m = p[0] > p[1] > ... > p[k] = 0.
   *)
  (* r = a mod p *)
//  function BN_GF2m_mod_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT): TIdC_INT;
  (* r = (a * b) mod p *)
//  function BN_GF2m_mod_mul_arr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a * a) mod p *)
//  function BN_GF2m_mod_sqr_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (1 / b) mod p *)
//  function BN_GF2m_mod_inv_arr(r: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a / b) mod p *)
//  function BN_GF2m_mod_div_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a ^ b) mod p *)
//  function BN_GF2m_mod_exp_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = sqrt(a) mod p *)
//  function BN_GF2m_mod_sqrt_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r^2 + r = a mod p *)
//  function BN_GF2m_mod_solve_quad_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
//  function BN_GF2m_poly2arr(a: PBIGNUM; p: array of TIdC_INT; max: TIdC_INT): TIdC_INT;
//  function BN_GF2m_arr2poly(p: array of TIdC_INT; a: PBIGNUM): TIdC_INT;

  (*
   * faster mod functions for the 'NIST primes' 0 <= a < p^2
   *)
  BN_nist_mod_192: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_nist_mod_224: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_nist_mod_256: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_nist_mod_384: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  BN_nist_mod_521: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  BN_get0_nist_prime_192: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_224: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_256: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_384: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_521: function : PBIGNUM; cdecl = nil;

//int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
//                                          const BIGNUM *field, BN_CTX *ctx);

  BN_generate_dsa_nonce: function (out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  (* Primes from RFC 2409 *)
  BN_get_rfc2409_prime_768: function (bn: PBIGNUM ): PBIGNUM; cdecl = nil;
  BN_get_rfc2409_prime_1024: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;

  (* Primes from RFC 3526 *)
  BN_get_rfc3526_prime_1536: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_2048: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_3072: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_4096: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_6144: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_8192: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;

  BN_bntest_rand: function (rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; cdecl = nil;

{$ELSE}
  procedure BN_set_flags(b: PBIGNUM; n: TIdC_INT) cdecl; external CLibCrypto;
  function BN_get_flags(b: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
   * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
   * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
   * has not been otherwise initialised or used.
   *)
  procedure BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TIdC_INT) cdecl; external CLibCrypto;
  (* Wrapper function to make using BN_GENCB easier *)
  function BN_GENCB_call(cb: PBN_GENCB; a: TIdC_INT; b: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function BN_GENCB_new: PBN_GENCB cdecl; external CLibCrypto;
  procedure BN_GENCB_free(cb: PBN_GENCB) cdecl; external CLibCrypto;

  (* Populate a PBN_GENCB structure with an "old"-style callback *)
  procedure BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer) cdecl; external CLibCrypto;

  (* Populate a PBN_GENCB structure with a "new"-style callback *)
  procedure BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer) cdecl; external CLibCrypto;

  function BN_GENCB_get_arg(cb: PBN_GENCB): Pointer cdecl; external CLibCrypto;
  
  (*
   * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
   * that will be done for checking that a random number is probably prime. The
   * error rate for accepting a composite number as prime depends on the size of
   * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
   * and so the level is what you would expect for a key of double the size of the
   * prime.
   *
   * This table is generated using the algorithm of FIPS PUB 186-4
   * Digital Signature Standard (DSS), section F.1, page 117.
   * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
   *
   * The following magma script was used to generate the output:
   * securitybits:=125;
   * k:=1024;
   * for t:=1 to 65 do
   *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
   *     S:=0;
   *     // Sum over m
   *     for m:=3 to M do
   *       s:=0;
   *       // Sum over j
   *       for j:=2 to m do
   *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
   *       end for;
   *       S+:=2^(m-(m-1)*t)*s;
   *     end for;
   *     A:=2^(k-2-M*t);
   *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
   *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
   *     seclevel:=Floor(-Log(2,pkt));
   *     if seclevel ge securitybits then
   *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
   *       break;
   *     end if;
   *   end for;
   *   if seclevel ge securitybits then break; end if;
   * end for;
   *
   * It can be run online at:
   * http://magma.maths.usyd.edu.au/calc
   *
   * And will output:
   * k:  1024, security: 129 bits  (t: 6, M: 23)
   *
   * k is the number of bits of the prime, securitybits is the level we want to
   * reach.
   *
   * prime length | RSA key size | # MR tests | security level
   * -------------+--------------|------------+---------------
   *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
   *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
   *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
   *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
   *  (b) >=  852 |     >=  1704 |          5 |        112 bit
   *  (b) >=  476 |     >=   952 |          5 |         80 bit
   *  (b) >=  400 |     >=   800 |          6 |         80 bit
   *  (b) >=  347 |     >=   694 |          7 |         80 bit
   *  (b) >=  308 |     >=   616 |          8 |         80 bit
   *  (b) >=   55 |     >=   110 |         27 |         64 bit
   *  (b) >=    6 |     >=    12 |         34 |         64 bit
   *)

//  # define BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
//                                  (b) >=  1345 ?  4 : \
//                                  (b) >=  476 ?  5 : \
//                                  (b) >=  400 ?  6 : \
//                                  (b) >=  347 ?  7 : \
//                                  (b) >=  308 ?  8 : \
//                                  (b) >=  55  ? 27 : \
//                                  (* b >= 6 *) 34)
//
//  # define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

  function BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_is_zero(a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_is_one(a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_is_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_is_odd(a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;

//  # define BN_one(a)       (BN_set_word((a),1))

  procedure BN_zero_ex(a: PBIGNUM) cdecl; external CLibCrypto;

  function BN_value_one: PBIGNUM cdecl; external CLibCrypto;
  function BN_options: PIdAnsiChar cdecl; external CLibCrypto;
  function BN_CTX_new: PBN_CTX cdecl; external CLibCrypto;
  function BN_CTX_secure_new: PBN_CTX cdecl; external CLibCrypto;
  procedure BN_CTX_free(c: PBN_CTX) cdecl; external CLibCrypto;
  procedure BN_CTX_start(ctx: PBN_CTX) cdecl; external CLibCrypto;
  function BN_CTX_get(ctx: PBN_CTX): PBIGNUM cdecl; external CLibCrypto;
  procedure BN_CTX_end(ctx: PBN_CTX) cdecl; external CLibCrypto;
  function BN_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_priv_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_pseudo_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_num_bits(a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_num_bits_word(l: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_security_bits(L: TIdC_INT; N: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_new: PBIGNUM cdecl; external CLibCrypto;
  function BN_secure_new: PBIGNUM cdecl; external CLibCrypto;
  procedure BN_clear_free(a: PBIGNUM) cdecl; external CLibCrypto;
  function BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  procedure BN_swap(a: PBIGNUM; b: PBIGNUM) cdecl; external CLibCrypto;
  function BN_bin2bn(const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_bn2bin(const a: PBIGNUM; to_: PByte): TIdC_INT cdecl; external CLibCrypto;
  function BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_lebin2bn(const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_mpi2bn(const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_bn2mpi(a: PBIGNUM; to_: PByte): TIdC_INT cdecl; external CLibCrypto;
  function BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  (** BN_set_negative sets sign of a BIGNUM
   * \param  b  pointer to the BIGNUM object
   * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
   *)
  procedure BN_set_negative(b: PBIGNUM; n: TIdC_INT) cdecl; external CLibCrypto;
  (** BN_is_negative returns 1 if the BIGNUM is negative
   * \param  b  pointer to the BIGNUM object
   * \return 1 if a < 0 and 0 otherwise
   *)
  function BN_is_negative(b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;

  function BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
//  # define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
  function BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT; const m: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;

  function BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG cdecl; external CLibCrypto;
  function BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG cdecl; external CLibCrypto;
  function BN_mul_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_add_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_sub_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_set_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function BN_get_word(const a: PBIGNUM): BN_ULONG cdecl; external CLibCrypto;

  function BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  procedure BN_free(a: PBIGNUM) cdecl; external CLibCrypto;
  function BN_is_bit_set(const a: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  function BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  function BN_mask_bits(a: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_print(bio: PBIO; a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TIdC_INT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_rshift1(r: PBIGNUM; a: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  procedure BN_clear(a: PBIGNUM) cdecl; external CLibCrypto;
  function BN_dup(const a: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_ucmp(a: PBIGNUM; b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  function BN_set_bit(a: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_clear_bit(a: PBIGNUM; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BN_bn2hex(a: PBIGNUM): PIdAnsiChar cdecl; external CLibCrypto;
  function BN_bn2dec(a: PBIGNUM): PIdAnsiChar cdecl; external CLibCrypto;
  function BN_hex2bn(a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function BN_dec2bn(a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function BN_asc2bn(a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  function BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM cdecl; external CLibCrypto;
  function BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM cdecl; external CLibCrypto;

  procedure BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TIdC_INT) cdecl; external CLibCrypto;

  function BN_generate_prime_ex(ret: PBIGNUM; bits: TIdC_INT; safe: TIdC_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  function BN_is_prime_ex(const p: PBIGNUM; nchecks: TIdC_INT; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  function BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TIdC_INT; ctx: PBN_CTX; do_trial_division: TIdC_INT; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  function BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TIdC_INT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  function BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  function BN_MONT_CTX_new: PBN_MONT_CTX cdecl; external CLibCrypto;
  function BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  procedure BN_MONT_CTX_free(mont: PBN_MONT_CTX) cdecl; external CLibCrypto;
  function BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX cdecl; external CLibCrypto;
//  function BN_MONT_CTX_set_locked(pmont: ^PBN_MONT_CTX; lock: CRYPTO_RWLOCK; mod_: PBIGNUM; ctx: PBN_CTX): PBN_MONT_CTX;

  function BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING cdecl; external CLibCrypto;
  procedure BN_BLINDING_free(b: PBN_BLINDING) cdecl; external CLibCrypto;
  function BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  function BN_BLINDING_is_current_thread(b: PBN_BLINDING): TIdC_INT cdecl; external CLibCrypto;
  procedure BN_BLINDING_set_current_thread(b: PBN_BLINDING) cdecl; external CLibCrypto;
  function BN_BLINDING_lock(b: PBN_BLINDING): TIdC_INT cdecl; external CLibCrypto;
  function BN_BLINDING_unlock(b: PBN_BLINDING): TIdC_INT cdecl; external CLibCrypto;

  function BN_BLINDING_get_flags(v1: PBN_BLINDING): TIdC_ULONG cdecl; external CLibCrypto;
  procedure BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TIdC_ULONG) cdecl; external CLibCrypto;
//  function BN_BLINDING_create_param(PBN_BLINDING *b,
//                                         PBIGNUM *e, PBIGNUM *m, PBN_CTX *ctx,
//                                        function (
//    r: PBIGNUM;
//    a: PBIGNUM;
//    p: PBIGNUM;
//    m: PBIGNUM;
//    ctx: PBN_CTX;
//    m_ctx: PBN_MONT_CTX): TIdC_INT,
//                                        PBN_MONT_CTX *m_ctx): PBN_BLINDING;

  procedure BN_RECP_CTX_free(recp: PBN_RECP_CTX) cdecl; external CLibCrypto;
  function BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Functions for arithmetic over binary polynomials represented by BIGNUMs.
   * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
   * ignored. Note that input arguments are not const so that their bit arrays
   * can be expanded to the appropriate size if needed.
   *)

  (*
   * r = a + b
   *)
  function BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
//  #  define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
  (*
   * r=a mod p
   *)
  function BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  (* r = (a * b) mod p *)
  function BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  (* r = (a * a) mod p *)
  function BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  (* r = (1 / b) mod p *)
  function BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  (* r = (a / b) mod p *)
  function BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  (* r = (a ^ b) mod p *)
  function BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  (* r = sqrt(a) mod p *)
  function BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  (* r^2 + r = a mod p *)
  function BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
//  #  define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
  (*-
   * Some functions allow for representation of the irreducible polynomials
   * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
   *     t^p[0] + t^p[1] + ... + t^p[k]
   * where m = p[0] > p[1] > ... > p[k] = 0.
   *)
  (* r = a mod p *)
//  function BN_GF2m_mod_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT): TIdC_INT;
  (* r = (a * b) mod p *)
//  function BN_GF2m_mod_mul_arr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a * a) mod p *)
//  function BN_GF2m_mod_sqr_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (1 / b) mod p *)
//  function BN_GF2m_mod_inv_arr(r: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a / b) mod p *)
//  function BN_GF2m_mod_div_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a ^ b) mod p *)
//  function BN_GF2m_mod_exp_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = sqrt(a) mod p *)
//  function BN_GF2m_mod_sqrt_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r^2 + r = a mod p *)
//  function BN_GF2m_mod_solve_quad_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
//  function BN_GF2m_poly2arr(a: PBIGNUM; p: array of TIdC_INT; max: TIdC_INT): TIdC_INT;
//  function BN_GF2m_arr2poly(p: array of TIdC_INT; a: PBIGNUM): TIdC_INT;

  (*
   * faster mod functions for the 'NIST primes' 0 <= a < p^2
   *)
  function BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  function BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  function BN_get0_nist_prime_192: PBIGNUM cdecl; external CLibCrypto;
  function BN_get0_nist_prime_224: PBIGNUM cdecl; external CLibCrypto;
  function BN_get0_nist_prime_256: PBIGNUM cdecl; external CLibCrypto;
  function BN_get0_nist_prime_384: PBIGNUM cdecl; external CLibCrypto;
  function BN_get0_nist_prime_521: PBIGNUM cdecl; external CLibCrypto;

//int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
//                                          const BIGNUM *field, BN_CTX *ctx);

  function BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  (* Primes from RFC 2409 *)
  function BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM cdecl; external CLibCrypto;
  function BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;

  (* Primes from RFC 3526 *)
  function BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;
  function BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;

  function BN_bntest_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

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
  BN_set_flags_procname = 'BN_set_flags';
  BN_get_flags_procname = 'BN_get_flags';

  (*
   * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
   * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
   * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
   * has not been otherwise initialised or used.
   *)
  BN_with_flags_procname = 'BN_with_flags';
  (* Wrapper function to make using BN_GENCB easier *)
  BN_GENCB_call_procname = 'BN_GENCB_call';

  BN_GENCB_new_procname = 'BN_GENCB_new';
  BN_GENCB_free_procname = 'BN_GENCB_free';

  (* Populate a PBN_GENCB structure with an "old"-style callback *)
  BN_GENCB_set_old_procname = 'BN_GENCB_set_old';

  (* Populate a PBN_GENCB structure with a "new"-style callback *)
  BN_GENCB_set_procname = 'BN_GENCB_set';

  BN_GENCB_get_arg_procname = 'BN_GENCB_get_arg';
  
  (*
   * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
   * that will be done for checking that a random number is probably prime. The
   * error rate for accepting a composite number as prime depends on the size of
   * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
   * and so the level is what you would expect for a key of double the size of the
   * prime.
   *
   * This table is generated using the algorithm of FIPS PUB 186-4
   * Digital Signature Standard (DSS), section F.1, page 117.
   * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
   *
   * The following magma script was used to generate the output:
   * securitybits:=125;
   * k:=1024;
   * for t:=1 to 65 do
   *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
   *     S:=0;
   *     // Sum over m
   *     for m:=3 to M do
   *       s:=0;
   *       // Sum over j
   *       for j:=2 to m do
   *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
   *       end for;
   *       S+:=2^(m-(m-1)*t)*s;
   *     end for;
   *     A:=2^(k-2-M*t);
   *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
   *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
   *     seclevel:=Floor(-Log(2,pkt));
   *     if seclevel ge securitybits then
   *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
   *       break;
   *     end if;
   *   end for;
   *   if seclevel ge securitybits then break; end if;
   * end for;
   *
   * It can be run online at:
   * http://magma.maths.usyd.edu.au/calc
   *
   * And will output:
   * k:  1024, security: 129 bits  (t: 6, M: 23)
   *
   * k is the number of bits of the prime, securitybits is the level we want to
   * reach.
   *
   * prime length | RSA key size | # MR tests | security level
   * -------------+--------------|------------+---------------
   *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
   *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
   *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
   *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
   *  (b) >=  852 |     >=  1704 |          5 |        112 bit
   *  (b) >=  476 |     >=   952 |          5 |         80 bit
   *  (b) >=  400 |     >=   800 |          6 |         80 bit
   *  (b) >=  347 |     >=   694 |          7 |         80 bit
   *  (b) >=  308 |     >=   616 |          8 |         80 bit
   *  (b) >=   55 |     >=   110 |         27 |         64 bit
   *  (b) >=    6 |     >=    12 |         34 |         64 bit
   *)

//  # define BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
//                                  (b) >=  1345 ?  4 : \
//                                  (b) >=  476 ?  5 : \
//                                  (b) >=  400 ?  6 : \
//                                  (b) >=  347 ?  7 : \
//                                  (b) >=  308 ?  8 : \
//                                  (b) >=  55  ? 27 : \
//                                  (* b >= 6 *) 34)
//
//  # define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

  BN_abs_is_word_procname = 'BN_abs_is_word';
  BN_is_zero_procname = 'BN_is_zero';
  BN_is_one_procname = 'BN_is_one';
  BN_is_word_procname = 'BN_is_word';
  BN_is_odd_procname = 'BN_is_odd';

//  # define BN_one(a)       (BN_set_word((a),1))

  BN_zero_ex_procname = 'BN_zero_ex';

  BN_value_one_procname = 'BN_value_one';
  BN_options_procname = 'BN_options';
  BN_CTX_new_procname = 'BN_CTX_new';
  BN_CTX_secure_new_procname = 'BN_CTX_secure_new';
  BN_CTX_free_procname = 'BN_CTX_free';
  BN_CTX_start_procname = 'BN_CTX_start';
  BN_CTX_get_procname = 'BN_CTX_get';
  BN_CTX_end_procname = 'BN_CTX_end';
  BN_rand_procname = 'BN_rand';
  BN_priv_rand_procname = 'BN_priv_rand';
  BN_rand_range_procname = 'BN_rand_range';
  BN_priv_rand_range_procname = 'BN_priv_rand_range';
  BN_pseudo_rand_procname = 'BN_pseudo_rand';
  BN_pseudo_rand_range_procname = 'BN_pseudo_rand_range';
  BN_num_bits_procname = 'BN_num_bits';
  BN_num_bits_word_procname = 'BN_num_bits_word';
  BN_security_bits_procname = 'BN_security_bits';
  BN_new_procname = 'BN_new';
  BN_secure_new_procname = 'BN_secure_new';
  BN_clear_free_procname = 'BN_clear_free';
  BN_copy_procname = 'BN_copy';
  BN_swap_procname = 'BN_swap';
  BN_bin2bn_procname = 'BN_bin2bn';
  BN_bn2bin_procname = 'BN_bn2bin';
  BN_bn2binpad_procname = 'BN_bn2binpad';
  BN_lebin2bn_procname = 'BN_lebin2bn';
  BN_bn2lebinpad_procname = 'BN_bn2lebinpad';
  BN_mpi2bn_procname = 'BN_mpi2bn';
  BN_bn2mpi_procname = 'BN_bn2mpi';
  BN_sub_procname = 'BN_sub';
  BN_usub_procname = 'BN_usub';
  BN_uadd_procname = 'BN_uadd';
  BN_add_procname = 'BN_add';
  BN_mul_procname = 'BN_mul';
  BN_sqr_procname = 'BN_sqr';

  (** BN_set_negative sets sign of a BIGNUM
   * \param  b  pointer to the BIGNUM object
   * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
   *)
  BN_set_negative_procname = 'BN_set_negative';
  (** BN_is_negative returns 1 if the BIGNUM is negative
   * \param  b  pointer to the BIGNUM object
   * \return 1 if a < 0 and 0 otherwise
   *)
  BN_is_negative_procname = 'BN_is_negative';

  BN_div_procname = 'BN_div';
//  # define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
  BN_nnmod_procname = 'BN_nnmod';
  BN_mod_add_procname = 'BN_mod_add';
  BN_mod_add_quick_procname = 'BN_mod_add_quick';
  BN_mod_sub_procname = 'BN_mod_sub';
  BN_mod_sub_quick_procname = 'BN_mod_sub_quick';
  BN_mod_mul_procname = 'BN_mod_mul';
  BN_mod_sqr_procname = 'BN_mod_sqr';
  BN_mod_lshift1_procname = 'BN_mod_lshift1';
  BN_mod_lshift1_quick_procname = 'BN_mod_lshift1_quick';
  BN_mod_lshift_procname = 'BN_mod_lshift';
  BN_mod_lshift_quick_procname = 'BN_mod_lshift_quick';

  BN_mod_word_procname = 'BN_mod_word';
  BN_div_word_procname = 'BN_div_word';
  BN_mul_word_procname = 'BN_mul_word';
  BN_add_word_procname = 'BN_add_word';
  BN_sub_word_procname = 'BN_sub_word';
  BN_set_word_procname = 'BN_set_word';
  BN_get_word_procname = 'BN_get_word';

  BN_cmp_procname = 'BN_cmp';
  BN_free_procname = 'BN_free';
  BN_is_bit_set_procname = 'BN_is_bit_set';
  BN_lshift_procname = 'BN_lshift';
  BN_lshift1_procname = 'BN_lshift1';
  BN_exp_procname = 'BN_exp';

  BN_mod_exp_procname = 'BN_mod_exp';
  BN_mod_exp_mont_procname = 'BN_mod_exp_mont';
  BN_mod_exp_mont_consttime_procname = 'BN_mod_exp_mont_consttime';
  BN_mod_exp_mont_word_procname = 'BN_mod_exp_mont_word';
  BN_mod_exp2_mont_procname = 'BN_mod_exp2_mont';
  BN_mod_exp_simple_procname = 'BN_mod_exp_simple';

  BN_mask_bits_procname = 'BN_mask_bits';
  BN_print_procname = 'BN_print';
  BN_reciprocal_procname = 'BN_reciprocal';
  BN_rshift_procname = 'BN_rshift';
  BN_rshift1_procname = 'BN_rshift1';
  BN_clear_procname = 'BN_clear';
  BN_dup_procname = 'BN_dup';
  BN_ucmp_procname = 'BN_ucmp';
  BN_set_bit_procname = 'BN_set_bit';
  BN_clear_bit_procname = 'BN_clear_bit';
  BN_bn2hex_procname = 'BN_bn2hex';
  BN_bn2dec_procname = 'BN_bn2dec';
  BN_hex2bn_procname = 'BN_hex2bn';
  BN_dec2bn_procname = 'BN_dec2bn';
  BN_asc2bn_procname = 'BN_asc2bn';
  BN_gcd_procname = 'BN_gcd';
  BN_kronecker_procname = 'BN_kronecker';

  BN_mod_inverse_procname = 'BN_mod_inverse';
  BN_mod_sqrt_procname = 'BN_mod_sqrt';

  BN_consttime_swap_procname = 'BN_consttime_swap';

  BN_generate_prime_ex_procname = 'BN_generate_prime_ex';
  BN_is_prime_ex_procname = 'BN_is_prime_ex';
  BN_is_prime_fasttest_ex_procname = 'BN_is_prime_fasttest_ex';
  BN_X931_generate_Xpq_procname = 'BN_X931_generate_Xpq';
  BN_X931_derive_prime_ex_procname = 'BN_X931_derive_prime_ex';
  BN_X931_generate_prime_ex_procname = 'BN_X931_generate_prime_ex';
  BN_MONT_CTX_new_procname = 'BN_MONT_CTX_new';
  BN_mod_mul_montgomery_procname = 'BN_mod_mul_montgomery';
  BN_to_montgomery_procname = 'BN_to_montgomery';
  BN_from_montgomery_procname = 'BN_from_montgomery';
  BN_MONT_CTX_free_procname = 'BN_MONT_CTX_free';
  BN_MONT_CTX_set_procname = 'BN_MONT_CTX_set';
  BN_MONT_CTX_copy_procname = 'BN_MONT_CTX_copy';
//  function BN_MONT_CTX_set_locked(pmont: ^PBN_MONT_CTX; lock: CRYPTO_RWLOCK; mod_: PBIGNUM; ctx: PBN_CTX): PBN_MONT_CTX;

  BN_BLINDING_new_procname = 'BN_BLINDING_new';
  BN_BLINDING_free_procname = 'BN_BLINDING_free';
  BN_BLINDING_update_procname = 'BN_BLINDING_update';
  BN_BLINDING_convert_procname = 'BN_BLINDING_convert';
  BN_BLINDING_invert_procname = 'BN_BLINDING_invert';
  BN_BLINDING_convert_ex_procname = 'BN_BLINDING_convert_ex';
  BN_BLINDING_invert_ex_procname = 'BN_BLINDING_invert_ex';

  BN_BLINDING_is_current_thread_procname = 'BN_BLINDING_is_current_thread';
  BN_BLINDING_set_current_thread_procname = 'BN_BLINDING_set_current_thread';
  BN_BLINDING_lock_procname = 'BN_BLINDING_lock';
  BN_BLINDING_unlock_procname = 'BN_BLINDING_unlock';

  BN_BLINDING_get_flags_procname = 'BN_BLINDING_get_flags';
  BN_BLINDING_set_flags_procname = 'BN_BLINDING_set_flags';
//  function BN_BLINDING_create_param(PBN_BLINDING *b,
//                                         PBIGNUM *e, PBIGNUM *m, PBN_CTX *ctx,
//                                        function (
//    r: PBIGNUM;
//    a: PBIGNUM;
//    p: PBIGNUM;
//    m: PBIGNUM;
//    ctx: PBN_CTX;
//    m_ctx: PBN_MONT_CTX): TIdC_INT,
//                                        PBN_MONT_CTX *m_ctx): PBN_BLINDING;

  BN_RECP_CTX_free_procname = 'BN_RECP_CTX_free';
  BN_RECP_CTX_set_procname = 'BN_RECP_CTX_set';
  BN_mod_mul_reciprocal_procname = 'BN_mod_mul_reciprocal';
  BN_mod_exp_recp_procname = 'BN_mod_exp_recp';
  BN_div_recp_procname = 'BN_div_recp';

  (*
   * Functions for arithmetic over binary polynomials represented by BIGNUMs.
   * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
   * ignored. Note that input arguments are not const so that their bit arrays
   * can be expanded to the appropriate size if needed.
   *)

  (*
   * r = a + b
   *)
  BN_GF2m_add_procname = 'BN_GF2m_add';
//  #  define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
  (*
   * r=a mod p
   *)
  BN_GF2m_mod_procname = 'BN_GF2m_mod';
  (* r = (a * b) mod p *)
  BN_GF2m_mod_mul_procname = 'BN_GF2m_mod_mul';
  (* r = (a * a) mod p *)
  BN_GF2m_mod_sqr_procname = 'BN_GF2m_mod_sqr';
  (* r = (1 / b) mod p *)
  BN_GF2m_mod_inv_procname = 'BN_GF2m_mod_inv';
  (* r = (a / b) mod p *)
  BN_GF2m_mod_div_procname = 'BN_GF2m_mod_div';
  (* r = (a ^ b) mod p *)
  BN_GF2m_mod_exp_procname = 'BN_GF2m_mod_exp';
  (* r = sqrt(a) mod p *)
  BN_GF2m_mod_sqrt_procname = 'BN_GF2m_mod_sqrt';
  (* r^2 + r = a mod p *)
  BN_GF2m_mod_solve_quad_procname = 'BN_GF2m_mod_solve_quad';
//  #  define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
  (*-
   * Some functions allow for representation of the irreducible polynomials
   * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
   *     t^p[0] + t^p[1] + ... + t^p[k]
   * where m = p[0] > p[1] > ... > p[k] = 0.
   *)
  (* r = a mod p *)
//  function BN_GF2m_mod_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT): TIdC_INT;
  (* r = (a * b) mod p *)
//  function BN_GF2m_mod_mul_arr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a * a) mod p *)
//  function BN_GF2m_mod_sqr_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (1 / b) mod p *)
//  function BN_GF2m_mod_inv_arr(r: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a / b) mod p *)
//  function BN_GF2m_mod_div_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a ^ b) mod p *)
//  function BN_GF2m_mod_exp_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = sqrt(a) mod p *)
//  function BN_GF2m_mod_sqrt_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r^2 + r = a mod p *)
//  function BN_GF2m_mod_solve_quad_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
//  function BN_GF2m_poly2arr(a: PBIGNUM; p: array of TIdC_INT; max: TIdC_INT): TIdC_INT;
//  function BN_GF2m_arr2poly(p: array of TIdC_INT; a: PBIGNUM): TIdC_INT;

  (*
   * faster mod functions for the 'NIST primes' 0 <= a < p^2
   *)
  BN_nist_mod_192_procname = 'BN_nist_mod_192';
  BN_nist_mod_224_procname = 'BN_nist_mod_224';
  BN_nist_mod_256_procname = 'BN_nist_mod_256';
  BN_nist_mod_384_procname = 'BN_nist_mod_384';
  BN_nist_mod_521_procname = 'BN_nist_mod_521';

  BN_get0_nist_prime_192_procname = 'BN_get0_nist_prime_192';
  BN_get0_nist_prime_224_procname = 'BN_get0_nist_prime_224';
  BN_get0_nist_prime_256_procname = 'BN_get0_nist_prime_256';
  BN_get0_nist_prime_384_procname = 'BN_get0_nist_prime_384';
  BN_get0_nist_prime_521_procname = 'BN_get0_nist_prime_521';

//int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
//                                          const BIGNUM *field, BN_CTX *ctx);

  BN_generate_dsa_nonce_procname = 'BN_generate_dsa_nonce';

  (* Primes from RFC 2409 *)
  BN_get_rfc2409_prime_768_procname = 'BN_get_rfc2409_prime_768';
  BN_get_rfc2409_prime_1024_procname = 'BN_get_rfc2409_prime_1024';

  (* Primes from RFC 3526 *)
  BN_get_rfc3526_prime_1536_procname = 'BN_get_rfc3526_prime_1536';
  BN_get_rfc3526_prime_2048_procname = 'BN_get_rfc3526_prime_2048';
  BN_get_rfc3526_prime_3072_procname = 'BN_get_rfc3526_prime_3072';
  BN_get_rfc3526_prime_4096_procname = 'BN_get_rfc3526_prime_4096';
  BN_get_rfc3526_prime_6144_procname = 'BN_get_rfc3526_prime_6144';
  BN_get_rfc3526_prime_8192_procname = 'BN_get_rfc3526_prime_8192';

  BN_bntest_rand_procname = 'BN_bntest_rand';


{$WARN  NO_RETVAL OFF}
procedure  ERR_BN_set_flags(b: PBIGNUM; n: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_set_flags_procname);
end;


function  ERR_BN_get_flags(b: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_flags_procname);
end;



  (*
   * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
   * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
   * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
   * has not been otherwise initialised or used.
   *)
procedure  ERR_BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_with_flags_procname);
end;


  (* Wrapper function to make using BN_GENCB easier *)
function  ERR_BN_GENCB_call(cb: PBN_GENCB; a: TIdC_INT; b: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GENCB_call_procname);
end;



function  ERR_BN_GENCB_new: PBN_GENCB; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GENCB_new_procname);
end;


procedure  ERR_BN_GENCB_free(cb: PBN_GENCB); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GENCB_free_procname);
end;



  (* Populate a PBN_GENCB structure with an "old"-style callback *)
procedure  ERR_BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GENCB_set_old_procname);
end;



  (* Populate a PBN_GENCB structure with a "new"-style callback *)
procedure  ERR_BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GENCB_set_procname);
end;



function  ERR_BN_GENCB_get_arg(cb: PBN_GENCB): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GENCB_get_arg_procname);
end;


  
  (*
   * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
   * that will be done for checking that a random number is probably prime. The
   * error rate for accepting a composite number as prime depends on the size of
   * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
   * and so the level is what you would expect for a key of double the size of the
   * prime.
   *
   * This table is generated using the algorithm of FIPS PUB 186-4
   * Digital Signature Standard (DSS), section F.1, page 117.
   * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
   *
   * The following magma script was used to generate the output:
   * securitybits:=125;
   * k:=1024;
   * for t:=1 to 65 do
   *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
   *     S:=0;
   *     // Sum over m
   *     for m:=3 to M do
   *       s:=0;
   *       // Sum over j
   *       for j:=2 to m do
   *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
   *       end for;
   *       S+:=2^(m-(m-1)*t)*s;
   *     end for;
   *     A:=2^(k-2-M*t);
   *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
   *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
   *     seclevel:=Floor(-Log(2,pkt));
   *     if seclevel ge securitybits then
   *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
   *       break;
   *     end if;
   *   end for;
   *   if seclevel ge securitybits then break; end if;
   * end for;
   *
   * It can be run online at:
   * http://magma.maths.usyd.edu.au/calc
   *
   * And will output:
   * k:  1024, security: 129 bits  (t: 6, M: 23)
   *
   * k is the number of bits of the prime, securitybits is the level we want to
   * reach.
   *
   * prime length | RSA key size | # MR tests | security level
   * -------------+--------------|------------+---------------
   *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
   *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
   *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
   *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
   *  (b) >=  852 |     >=  1704 |          5 |        112 bit
   *  (b) >=  476 |     >=   952 |          5 |         80 bit
   *  (b) >=  400 |     >=   800 |          6 |         80 bit
   *  (b) >=  347 |     >=   694 |          7 |         80 bit
   *  (b) >=  308 |     >=   616 |          8 |         80 bit
   *  (b) >=   55 |     >=   110 |         27 |         64 bit
   *  (b) >=    6 |     >=    12 |         34 |         64 bit
   *)

//  # define BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
//                                  (b) >=  1345 ?  4 : \
//                                  (b) >=  476 ?  5 : \
//                                  (b) >=  400 ?  6 : \
//                                  (b) >=  347 ?  7 : \
//                                  (b) >=  308 ?  8 : \
//                                  (b) >=  55  ? 27 : \
//                                  (* b >= 6 *) 34)
//
//  # define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

function  ERR_BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_abs_is_word_procname);
end;


function  ERR_BN_is_zero(a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_zero_procname);
end;


function  ERR_BN_is_one(a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_one_procname);
end;


function  ERR_BN_is_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_word_procname);
end;


function  ERR_BN_is_odd(a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_odd_procname);
end;



//  # define BN_one(a)       (BN_set_word((a),1))

procedure  ERR_BN_zero_ex(a: PBIGNUM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_zero_ex_procname);
end;



function  ERR_BN_value_one: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_value_one_procname);
end;


function  ERR_BN_options: PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_options_procname);
end;


function  ERR_BN_CTX_new: PBN_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_CTX_new_procname);
end;


function  ERR_BN_CTX_secure_new: PBN_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_CTX_secure_new_procname);
end;


procedure  ERR_BN_CTX_free(c: PBN_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_CTX_free_procname);
end;


procedure  ERR_BN_CTX_start(ctx: PBN_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_CTX_start_procname);
end;


function  ERR_BN_CTX_get(ctx: PBN_CTX): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_CTX_get_procname);
end;


procedure  ERR_BN_CTX_end(ctx: PBN_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_CTX_end_procname);
end;


function  ERR_BN_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_rand_procname);
end;


function  ERR_BN_priv_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_priv_rand_procname);
end;


function  ERR_BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_rand_range_procname);
end;


function  ERR_BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_priv_rand_range_procname);
end;


function  ERR_BN_pseudo_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_pseudo_rand_procname);
end;


function  ERR_BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_pseudo_rand_range_procname);
end;


function  ERR_BN_num_bits(a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_num_bits_procname);
end;


function  ERR_BN_num_bits_word(l: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_num_bits_word_procname);
end;


function  ERR_BN_security_bits(L: TIdC_INT; N: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_security_bits_procname);
end;


function  ERR_BN_new: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_new_procname);
end;


function  ERR_BN_secure_new: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_secure_new_procname);
end;


procedure  ERR_BN_clear_free(a: PBIGNUM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_clear_free_procname);
end;


function  ERR_BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_copy_procname);
end;


procedure  ERR_BN_swap(a: PBIGNUM; b: PBIGNUM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_swap_procname);
end;


function  ERR_BN_bin2bn(const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bin2bn_procname);
end;


function  ERR_BN_bn2bin(const a: PBIGNUM; to_: PByte): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bn2bin_procname);
end;


function  ERR_BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bn2binpad_procname);
end;


function  ERR_BN_lebin2bn(const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_lebin2bn_procname);
end;


function  ERR_BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bn2lebinpad_procname);
end;


function  ERR_BN_mpi2bn(const s: PByte; len: TIdC_INT; ret: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mpi2bn_procname);
end;


function  ERR_BN_bn2mpi(a: PBIGNUM; to_: PByte): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bn2mpi_procname);
end;


function  ERR_BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_sub_procname);
end;


function  ERR_BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_usub_procname);
end;


function  ERR_BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_uadd_procname);
end;


function  ERR_BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_add_procname);
end;


function  ERR_BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mul_procname);
end;


function  ERR_BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_sqr_procname);
end;



  (** BN_set_negative sets sign of a BIGNUM
   * \param  b  pointer to the BIGNUM object
   * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
   *)
procedure  ERR_BN_set_negative(b: PBIGNUM; n: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_set_negative_procname);
end;


  (** BN_is_negative returns 1 if the BIGNUM is negative
   * \param  b  pointer to the BIGNUM object
   * \return 1 if a < 0 and 0 otherwise
   *)
function  ERR_BN_is_negative(b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_negative_procname);
end;



function  ERR_BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_div_procname);
end;


//  # define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
function  ERR_BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_nnmod_procname);
end;


function  ERR_BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_add_procname);
end;


function  ERR_BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_add_quick_procname);
end;


function  ERR_BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_sub_procname);
end;


function  ERR_BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_sub_quick_procname);
end;


function  ERR_BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_mul_procname);
end;


function  ERR_BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_sqr_procname);
end;


function  ERR_BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_lshift1_procname);
end;


function  ERR_BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_lshift1_quick_procname);
end;


function  ERR_BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_lshift_procname);
end;


function  ERR_BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT; const m: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_lshift_quick_procname);
end;



function  ERR_BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_word_procname);
end;


function  ERR_BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_div_word_procname);
end;


function  ERR_BN_mul_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mul_word_procname);
end;


function  ERR_BN_add_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_add_word_procname);
end;


function  ERR_BN_sub_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_sub_word_procname);
end;


function  ERR_BN_set_word(a: PBIGNUM; w: BN_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_set_word_procname);
end;


function  ERR_BN_get_word(const a: PBIGNUM): BN_ULONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_word_procname);
end;



function  ERR_BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_cmp_procname);
end;


procedure  ERR_BN_free(a: PBIGNUM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_free_procname);
end;


function  ERR_BN_is_bit_set(const a: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_bit_set_procname);
end;


function  ERR_BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_lshift_procname);
end;


function  ERR_BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_lshift1_procname);
end;


function  ERR_BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_exp_procname);
end;



function  ERR_BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp_procname);
end;


function  ERR_BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp_mont_procname);
end;


function  ERR_BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp_mont_consttime_procname);
end;


function  ERR_BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp_mont_word_procname);
end;


function  ERR_BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp2_mont_procname);
end;


function  ERR_BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp_simple_procname);
end;



function  ERR_BN_mask_bits(a: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mask_bits_procname);
end;


function  ERR_BN_print(bio: PBIO; a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_print_procname);
end;


function  ERR_BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TIdC_INT; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_reciprocal_procname);
end;


function  ERR_BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_rshift_procname);
end;


function  ERR_BN_rshift1(r: PBIGNUM; a: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_rshift1_procname);
end;


procedure  ERR_BN_clear(a: PBIGNUM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_clear_procname);
end;


function  ERR_BN_dup(const a: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_dup_procname);
end;


function  ERR_BN_ucmp(a: PBIGNUM; b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_ucmp_procname);
end;


function  ERR_BN_set_bit(a: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_set_bit_procname);
end;


function  ERR_BN_clear_bit(a: PBIGNUM; n: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_clear_bit_procname);
end;


function  ERR_BN_bn2hex(a: PBIGNUM): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bn2hex_procname);
end;


function  ERR_BN_bn2dec(a: PBIGNUM): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bn2dec_procname);
end;


function  ERR_BN_hex2bn(a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_hex2bn_procname);
end;


function  ERR_BN_dec2bn(a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_dec2bn_procname);
end;


function  ERR_BN_asc2bn(a: PPBIGNUM; str: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_asc2bn_procname);
end;


function  ERR_BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_gcd_procname);
end;


function  ERR_BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_kronecker_procname);
end;



function  ERR_BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_inverse_procname);
end;


function  ERR_BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_sqrt_procname);
end;



procedure  ERR_BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_consttime_swap_procname);
end;



function  ERR_BN_generate_prime_ex(ret: PBIGNUM; bits: TIdC_INT; safe: TIdC_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_generate_prime_ex_procname);
end;


function  ERR_BN_is_prime_ex(const p: PBIGNUM; nchecks: TIdC_INT; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_prime_ex_procname);
end;


function  ERR_BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TIdC_INT; ctx: PBN_CTX; do_trial_division: TIdC_INT; cb: PBN_GENCB): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_is_prime_fasttest_ex_procname);
end;


function  ERR_BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TIdC_INT; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_X931_generate_Xpq_procname);
end;


function  ERR_BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_X931_derive_prime_ex_procname);
end;


function  ERR_BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_X931_generate_prime_ex_procname);
end;


function  ERR_BN_MONT_CTX_new: PBN_MONT_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_MONT_CTX_new_procname);
end;


function  ERR_BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_mul_montgomery_procname);
end;


function  ERR_BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_to_montgomery_procname);
end;


function  ERR_BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_from_montgomery_procname);
end;


procedure  ERR_BN_MONT_CTX_free(mont: PBN_MONT_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_MONT_CTX_free_procname);
end;


function  ERR_BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_MONT_CTX_set_procname);
end;


function  ERR_BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_MONT_CTX_copy_procname);
end;


//  function BN_MONT_CTX_set_locked(pmont: ^PBN_MONT_CTX; lock: CRYPTO_RWLOCK; mod_: PBIGNUM; ctx: PBN_CTX): PBN_MONT_CTX;

function  ERR_BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_new_procname);
end;


procedure  ERR_BN_BLINDING_free(b: PBN_BLINDING); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_free_procname);
end;


function  ERR_BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_update_procname);
end;


function  ERR_BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_convert_procname);
end;


function  ERR_BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_invert_procname);
end;


function  ERR_BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_convert_ex_procname);
end;


function  ERR_BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_invert_ex_procname);
end;



function  ERR_BN_BLINDING_is_current_thread(b: PBN_BLINDING): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_is_current_thread_procname);
end;


procedure  ERR_BN_BLINDING_set_current_thread(b: PBN_BLINDING); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_set_current_thread_procname);
end;


function  ERR_BN_BLINDING_lock(b: PBN_BLINDING): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_lock_procname);
end;


function  ERR_BN_BLINDING_unlock(b: PBN_BLINDING): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_unlock_procname);
end;



function  ERR_BN_BLINDING_get_flags(v1: PBN_BLINDING): TIdC_ULONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_get_flags_procname);
end;


procedure  ERR_BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TIdC_ULONG); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_BLINDING_set_flags_procname);
end;


//  function BN_BLINDING_create_param(PBN_BLINDING *b,
//                                         PBIGNUM *e, PBIGNUM *m, PBN_CTX *ctx,
//                                        function (
//    r: PBIGNUM;
//    a: PBIGNUM;
//    p: PBIGNUM;
//    m: PBIGNUM;
//    ctx: PBN_CTX;
//    m_ctx: PBN_MONT_CTX): TIdC_INT,
//                                        PBN_MONT_CTX *m_ctx): PBN_BLINDING;

procedure  ERR_BN_RECP_CTX_free(recp: PBN_RECP_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_RECP_CTX_free_procname);
end;


function  ERR_BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_RECP_CTX_set_procname);
end;


function  ERR_BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_mul_reciprocal_procname);
end;


function  ERR_BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_mod_exp_recp_procname);
end;


function  ERR_BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_div_recp_procname);
end;



  (*
   * Functions for arithmetic over binary polynomials represented by BIGNUMs.
   * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
   * ignored. Note that input arguments are not const so that their bit arrays
   * can be expanded to the appropriate size if needed.
   *)

  (*
   * r = a + b
   *)
function  ERR_BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_add_procname);
end;


//  #  define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
  (*
   * r=a mod p
   *)
function  ERR_BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_procname);
end;


  (* r = (a * b) mod p *)
function  ERR_BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_mul_procname);
end;


  (* r = (a * a) mod p *)
function  ERR_BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_sqr_procname);
end;


  (* r = (1 / b) mod p *)
function  ERR_BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_inv_procname);
end;


  (* r = (a / b) mod p *)
function  ERR_BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_div_procname);
end;


  (* r = (a ^ b) mod p *)
function  ERR_BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_exp_procname);
end;


  (* r = sqrt(a) mod p *)
function  ERR_BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_sqrt_procname);
end;


  (* r^2 + r = a mod p *)
function  ERR_BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_GF2m_mod_solve_quad_procname);
end;


//  #  define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
  (*-
   * Some functions allow for representation of the irreducible polynomials
   * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
   *     t^p[0] + t^p[1] + ... + t^p[k]
   * where m = p[0] > p[1] > ... > p[k] = 0.
   *)
  (* r = a mod p *)
//  function BN_GF2m_mod_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT): TIdC_INT;
  (* r = (a * b) mod p *)
//  function BN_GF2m_mod_mul_arr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a * a) mod p *)
//  function BN_GF2m_mod_sqr_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (1 / b) mod p *)
//  function BN_GF2m_mod_inv_arr(r: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a / b) mod p *)
//  function BN_GF2m_mod_div_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = (a ^ b) mod p *)
//  function BN_GF2m_mod_exp_arr(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r = sqrt(a) mod p *)
//  function BN_GF2m_mod_sqrt_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
  (* r^2 + r = a mod p *)
//  function BN_GF2m_mod_solve_quad_arr(r: PBIGNUM; a: PBIGNUM; p: array of TIdC_INT; ctx: PBN_CTX): TIdC_INT;
//  function BN_GF2m_poly2arr(a: PBIGNUM; p: array of TIdC_INT; max: TIdC_INT): TIdC_INT;
//  function BN_GF2m_arr2poly(p: array of TIdC_INT; a: PBIGNUM): TIdC_INT;

  (*
   * faster mod functions for the 'NIST primes' 0 <= a < p^2
   *)
function  ERR_BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_nist_mod_192_procname);
end;


function  ERR_BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_nist_mod_224_procname);
end;


function  ERR_BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_nist_mod_256_procname);
end;


function  ERR_BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_nist_mod_384_procname);
end;


function  ERR_BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_nist_mod_521_procname);
end;



function  ERR_BN_get0_nist_prime_192: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get0_nist_prime_192_procname);
end;


function  ERR_BN_get0_nist_prime_224: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get0_nist_prime_224_procname);
end;


function  ERR_BN_get0_nist_prime_256: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get0_nist_prime_256_procname);
end;


function  ERR_BN_get0_nist_prime_384: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get0_nist_prime_384_procname);
end;


function  ERR_BN_get0_nist_prime_521: PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get0_nist_prime_521_procname);
end;



//int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
//                                          const BIGNUM *field, BN_CTX *ctx);

function  ERR_BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_generate_dsa_nonce_procname);
end;



  (* Primes from RFC 2409 *)
function  ERR_BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc2409_prime_768_procname);
end;


function  ERR_BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc2409_prime_1024_procname);
end;



  (* Primes from RFC 3526 *)
function  ERR_BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc3526_prime_1536_procname);
end;


function  ERR_BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc3526_prime_2048_procname);
end;


function  ERR_BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc3526_prime_3072_procname);
end;


function  ERR_BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc3526_prime_4096_procname);
end;


function  ERR_BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc3526_prime_6144_procname);
end;


function  ERR_BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_get_rfc3526_prime_8192_procname);
end;



function  ERR_BN_bntest_rand(rnd: PBIGNUM; bits: TIdC_INT; top: TIdC_INT; bottom: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BN_bntest_rand_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  BN_set_flags := LoadLibFunction(ADllHandle, BN_set_flags_procname);
  FuncLoadError := not assigned(BN_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(BN_set_flags_allownil)}
    BN_set_flags := @ERR_BN_set_flags;
    {$ifend}
    {$if declared(BN_set_flags_introduced)}
    if LibVersion < BN_set_flags_introduced then
    begin
      {$if declared(FC_BN_set_flags)}
      BN_set_flags := @FC_BN_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_set_flags_removed)}
    if BN_set_flags_removed <= LibVersion then
    begin
      {$if declared(_BN_set_flags)}
      BN_set_flags := @_BN_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_set_flags');
    {$ifend}
  end;


  BN_get_flags := LoadLibFunction(ADllHandle, BN_get_flags_procname);
  FuncLoadError := not assigned(BN_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_flags_allownil)}
    BN_get_flags := @ERR_BN_get_flags;
    {$ifend}
    {$if declared(BN_get_flags_introduced)}
    if LibVersion < BN_get_flags_introduced then
    begin
      {$if declared(FC_BN_get_flags)}
      BN_get_flags := @FC_BN_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_flags_removed)}
    if BN_get_flags_removed <= LibVersion then
    begin
      {$if declared(_BN_get_flags)}
      BN_get_flags := @_BN_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_flags');
    {$ifend}
  end;


  BN_with_flags := LoadLibFunction(ADllHandle, BN_with_flags_procname);
  FuncLoadError := not assigned(BN_with_flags);
  if FuncLoadError then
  begin
    {$if not defined(BN_with_flags_allownil)}
    BN_with_flags := @ERR_BN_with_flags;
    {$ifend}
    {$if declared(BN_with_flags_introduced)}
    if LibVersion < BN_with_flags_introduced then
    begin
      {$if declared(FC_BN_with_flags)}
      BN_with_flags := @FC_BN_with_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_with_flags_removed)}
    if BN_with_flags_removed <= LibVersion then
    begin
      {$if declared(_BN_with_flags)}
      BN_with_flags := @_BN_with_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_with_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_with_flags');
    {$ifend}
  end;


  BN_GENCB_call := LoadLibFunction(ADllHandle, BN_GENCB_call_procname);
  FuncLoadError := not assigned(BN_GENCB_call);
  if FuncLoadError then
  begin
    {$if not defined(BN_GENCB_call_allownil)}
    BN_GENCB_call := @ERR_BN_GENCB_call;
    {$ifend}
    {$if declared(BN_GENCB_call_introduced)}
    if LibVersion < BN_GENCB_call_introduced then
    begin
      {$if declared(FC_BN_GENCB_call)}
      BN_GENCB_call := @FC_BN_GENCB_call;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GENCB_call_removed)}
    if BN_GENCB_call_removed <= LibVersion then
    begin
      {$if declared(_BN_GENCB_call)}
      BN_GENCB_call := @_BN_GENCB_call;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GENCB_call_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GENCB_call');
    {$ifend}
  end;


  BN_GENCB_new := LoadLibFunction(ADllHandle, BN_GENCB_new_procname);
  FuncLoadError := not assigned(BN_GENCB_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_GENCB_new_allownil)}
    BN_GENCB_new := @ERR_BN_GENCB_new;
    {$ifend}
    {$if declared(BN_GENCB_new_introduced)}
    if LibVersion < BN_GENCB_new_introduced then
    begin
      {$if declared(FC_BN_GENCB_new)}
      BN_GENCB_new := @FC_BN_GENCB_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GENCB_new_removed)}
    if BN_GENCB_new_removed <= LibVersion then
    begin
      {$if declared(_BN_GENCB_new)}
      BN_GENCB_new := @_BN_GENCB_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GENCB_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GENCB_new');
    {$ifend}
  end;


  BN_GENCB_free := LoadLibFunction(ADllHandle, BN_GENCB_free_procname);
  FuncLoadError := not assigned(BN_GENCB_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_GENCB_free_allownil)}
    BN_GENCB_free := @ERR_BN_GENCB_free;
    {$ifend}
    {$if declared(BN_GENCB_free_introduced)}
    if LibVersion < BN_GENCB_free_introduced then
    begin
      {$if declared(FC_BN_GENCB_free)}
      BN_GENCB_free := @FC_BN_GENCB_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GENCB_free_removed)}
    if BN_GENCB_free_removed <= LibVersion then
    begin
      {$if declared(_BN_GENCB_free)}
      BN_GENCB_free := @_BN_GENCB_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GENCB_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GENCB_free');
    {$ifend}
  end;


  BN_GENCB_set_old := LoadLibFunction(ADllHandle, BN_GENCB_set_old_procname);
  FuncLoadError := not assigned(BN_GENCB_set_old);
  if FuncLoadError then
  begin
    {$if not defined(BN_GENCB_set_old_allownil)}
    BN_GENCB_set_old := @ERR_BN_GENCB_set_old;
    {$ifend}
    {$if declared(BN_GENCB_set_old_introduced)}
    if LibVersion < BN_GENCB_set_old_introduced then
    begin
      {$if declared(FC_BN_GENCB_set_old)}
      BN_GENCB_set_old := @FC_BN_GENCB_set_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GENCB_set_old_removed)}
    if BN_GENCB_set_old_removed <= LibVersion then
    begin
      {$if declared(_BN_GENCB_set_old)}
      BN_GENCB_set_old := @_BN_GENCB_set_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GENCB_set_old_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GENCB_set_old');
    {$ifend}
  end;


  BN_GENCB_set := LoadLibFunction(ADllHandle, BN_GENCB_set_procname);
  FuncLoadError := not assigned(BN_GENCB_set);
  if FuncLoadError then
  begin
    {$if not defined(BN_GENCB_set_allownil)}
    BN_GENCB_set := @ERR_BN_GENCB_set;
    {$ifend}
    {$if declared(BN_GENCB_set_introduced)}
    if LibVersion < BN_GENCB_set_introduced then
    begin
      {$if declared(FC_BN_GENCB_set)}
      BN_GENCB_set := @FC_BN_GENCB_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GENCB_set_removed)}
    if BN_GENCB_set_removed <= LibVersion then
    begin
      {$if declared(_BN_GENCB_set)}
      BN_GENCB_set := @_BN_GENCB_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GENCB_set_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GENCB_set');
    {$ifend}
  end;


  BN_GENCB_get_arg := LoadLibFunction(ADllHandle, BN_GENCB_get_arg_procname);
  FuncLoadError := not assigned(BN_GENCB_get_arg);
  if FuncLoadError then
  begin
    {$if not defined(BN_GENCB_get_arg_allownil)}
    BN_GENCB_get_arg := @ERR_BN_GENCB_get_arg;
    {$ifend}
    {$if declared(BN_GENCB_get_arg_introduced)}
    if LibVersion < BN_GENCB_get_arg_introduced then
    begin
      {$if declared(FC_BN_GENCB_get_arg)}
      BN_GENCB_get_arg := @FC_BN_GENCB_get_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GENCB_get_arg_removed)}
    if BN_GENCB_get_arg_removed <= LibVersion then
    begin
      {$if declared(_BN_GENCB_get_arg)}
      BN_GENCB_get_arg := @_BN_GENCB_get_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GENCB_get_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GENCB_get_arg');
    {$ifend}
  end;


  BN_abs_is_word := LoadLibFunction(ADllHandle, BN_abs_is_word_procname);
  FuncLoadError := not assigned(BN_abs_is_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_abs_is_word_allownil)}
    BN_abs_is_word := @ERR_BN_abs_is_word;
    {$ifend}
    {$if declared(BN_abs_is_word_introduced)}
    if LibVersion < BN_abs_is_word_introduced then
    begin
      {$if declared(FC_BN_abs_is_word)}
      BN_abs_is_word := @FC_BN_abs_is_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_abs_is_word_removed)}
    if BN_abs_is_word_removed <= LibVersion then
    begin
      {$if declared(_BN_abs_is_word)}
      BN_abs_is_word := @_BN_abs_is_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_abs_is_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_abs_is_word');
    {$ifend}
  end;


  BN_is_zero := LoadLibFunction(ADllHandle, BN_is_zero_procname);
  FuncLoadError := not assigned(BN_is_zero);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_zero_allownil)}
    BN_is_zero := @ERR_BN_is_zero;
    {$ifend}
    {$if declared(BN_is_zero_introduced)}
    if LibVersion < BN_is_zero_introduced then
    begin
      {$if declared(FC_BN_is_zero)}
      BN_is_zero := @FC_BN_is_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_zero_removed)}
    if BN_is_zero_removed <= LibVersion then
    begin
      {$if declared(_BN_is_zero)}
      BN_is_zero := @_BN_is_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_zero_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_zero');
    {$ifend}
  end;


  BN_is_one := LoadLibFunction(ADllHandle, BN_is_one_procname);
  FuncLoadError := not assigned(BN_is_one);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_one_allownil)}
    BN_is_one := @ERR_BN_is_one;
    {$ifend}
    {$if declared(BN_is_one_introduced)}
    if LibVersion < BN_is_one_introduced then
    begin
      {$if declared(FC_BN_is_one)}
      BN_is_one := @FC_BN_is_one;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_one_removed)}
    if BN_is_one_removed <= LibVersion then
    begin
      {$if declared(_BN_is_one)}
      BN_is_one := @_BN_is_one;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_one_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_one');
    {$ifend}
  end;


  BN_is_word := LoadLibFunction(ADllHandle, BN_is_word_procname);
  FuncLoadError := not assigned(BN_is_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_word_allownil)}
    BN_is_word := @ERR_BN_is_word;
    {$ifend}
    {$if declared(BN_is_word_introduced)}
    if LibVersion < BN_is_word_introduced then
    begin
      {$if declared(FC_BN_is_word)}
      BN_is_word := @FC_BN_is_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_word_removed)}
    if BN_is_word_removed <= LibVersion then
    begin
      {$if declared(_BN_is_word)}
      BN_is_word := @_BN_is_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_word');
    {$ifend}
  end;


  BN_is_odd := LoadLibFunction(ADllHandle, BN_is_odd_procname);
  FuncLoadError := not assigned(BN_is_odd);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_odd_allownil)}
    BN_is_odd := @ERR_BN_is_odd;
    {$ifend}
    {$if declared(BN_is_odd_introduced)}
    if LibVersion < BN_is_odd_introduced then
    begin
      {$if declared(FC_BN_is_odd)}
      BN_is_odd := @FC_BN_is_odd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_odd_removed)}
    if BN_is_odd_removed <= LibVersion then
    begin
      {$if declared(_BN_is_odd)}
      BN_is_odd := @_BN_is_odd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_odd_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_odd');
    {$ifend}
  end;


  BN_zero_ex := LoadLibFunction(ADllHandle, BN_zero_ex_procname);
  FuncLoadError := not assigned(BN_zero_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_zero_ex_allownil)}
    BN_zero_ex := @ERR_BN_zero_ex;
    {$ifend}
    {$if declared(BN_zero_ex_introduced)}
    if LibVersion < BN_zero_ex_introduced then
    begin
      {$if declared(FC_BN_zero_ex)}
      BN_zero_ex := @FC_BN_zero_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_zero_ex_removed)}
    if BN_zero_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_zero_ex)}
      BN_zero_ex := @_BN_zero_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_zero_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_zero_ex');
    {$ifend}
  end;


  BN_value_one := LoadLibFunction(ADllHandle, BN_value_one_procname);
  FuncLoadError := not assigned(BN_value_one);
  if FuncLoadError then
  begin
    {$if not defined(BN_value_one_allownil)}
    BN_value_one := @ERR_BN_value_one;
    {$ifend}
    {$if declared(BN_value_one_introduced)}
    if LibVersion < BN_value_one_introduced then
    begin
      {$if declared(FC_BN_value_one)}
      BN_value_one := @FC_BN_value_one;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_value_one_removed)}
    if BN_value_one_removed <= LibVersion then
    begin
      {$if declared(_BN_value_one)}
      BN_value_one := @_BN_value_one;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_value_one_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_value_one');
    {$ifend}
  end;


  BN_options := LoadLibFunction(ADllHandle, BN_options_procname);
  FuncLoadError := not assigned(BN_options);
  if FuncLoadError then
  begin
    {$if not defined(BN_options_allownil)}
    BN_options := @ERR_BN_options;
    {$ifend}
    {$if declared(BN_options_introduced)}
    if LibVersion < BN_options_introduced then
    begin
      {$if declared(FC_BN_options)}
      BN_options := @FC_BN_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_options_removed)}
    if BN_options_removed <= LibVersion then
    begin
      {$if declared(_BN_options)}
      BN_options := @_BN_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_options_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_options');
    {$ifend}
  end;


  BN_CTX_new := LoadLibFunction(ADllHandle, BN_CTX_new_procname);
  FuncLoadError := not assigned(BN_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_CTX_new_allownil)}
    BN_CTX_new := @ERR_BN_CTX_new;
    {$ifend}
    {$if declared(BN_CTX_new_introduced)}
    if LibVersion < BN_CTX_new_introduced then
    begin
      {$if declared(FC_BN_CTX_new)}
      BN_CTX_new := @FC_BN_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_CTX_new_removed)}
    if BN_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_BN_CTX_new)}
      BN_CTX_new := @_BN_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_CTX_new');
    {$ifend}
  end;


  BN_CTX_secure_new := LoadLibFunction(ADllHandle, BN_CTX_secure_new_procname);
  FuncLoadError := not assigned(BN_CTX_secure_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_CTX_secure_new_allownil)}
    BN_CTX_secure_new := @ERR_BN_CTX_secure_new;
    {$ifend}
    {$if declared(BN_CTX_secure_new_introduced)}
    if LibVersion < BN_CTX_secure_new_introduced then
    begin
      {$if declared(FC_BN_CTX_secure_new)}
      BN_CTX_secure_new := @FC_BN_CTX_secure_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_CTX_secure_new_removed)}
    if BN_CTX_secure_new_removed <= LibVersion then
    begin
      {$if declared(_BN_CTX_secure_new)}
      BN_CTX_secure_new := @_BN_CTX_secure_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_CTX_secure_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_CTX_secure_new');
    {$ifend}
  end;


  BN_CTX_free := LoadLibFunction(ADllHandle, BN_CTX_free_procname);
  FuncLoadError := not assigned(BN_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_CTX_free_allownil)}
    BN_CTX_free := @ERR_BN_CTX_free;
    {$ifend}
    {$if declared(BN_CTX_free_introduced)}
    if LibVersion < BN_CTX_free_introduced then
    begin
      {$if declared(FC_BN_CTX_free)}
      BN_CTX_free := @FC_BN_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_CTX_free_removed)}
    if BN_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_BN_CTX_free)}
      BN_CTX_free := @_BN_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_CTX_free');
    {$ifend}
  end;


  BN_CTX_start := LoadLibFunction(ADllHandle, BN_CTX_start_procname);
  FuncLoadError := not assigned(BN_CTX_start);
  if FuncLoadError then
  begin
    {$if not defined(BN_CTX_start_allownil)}
    BN_CTX_start := @ERR_BN_CTX_start;
    {$ifend}
    {$if declared(BN_CTX_start_introduced)}
    if LibVersion < BN_CTX_start_introduced then
    begin
      {$if declared(FC_BN_CTX_start)}
      BN_CTX_start := @FC_BN_CTX_start;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_CTX_start_removed)}
    if BN_CTX_start_removed <= LibVersion then
    begin
      {$if declared(_BN_CTX_start)}
      BN_CTX_start := @_BN_CTX_start;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_CTX_start_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_CTX_start');
    {$ifend}
  end;


  BN_CTX_get := LoadLibFunction(ADllHandle, BN_CTX_get_procname);
  FuncLoadError := not assigned(BN_CTX_get);
  if FuncLoadError then
  begin
    {$if not defined(BN_CTX_get_allownil)}
    BN_CTX_get := @ERR_BN_CTX_get;
    {$ifend}
    {$if declared(BN_CTX_get_introduced)}
    if LibVersion < BN_CTX_get_introduced then
    begin
      {$if declared(FC_BN_CTX_get)}
      BN_CTX_get := @FC_BN_CTX_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_CTX_get_removed)}
    if BN_CTX_get_removed <= LibVersion then
    begin
      {$if declared(_BN_CTX_get)}
      BN_CTX_get := @_BN_CTX_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_CTX_get_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_CTX_get');
    {$ifend}
  end;


  BN_CTX_end := LoadLibFunction(ADllHandle, BN_CTX_end_procname);
  FuncLoadError := not assigned(BN_CTX_end);
  if FuncLoadError then
  begin
    {$if not defined(BN_CTX_end_allownil)}
    BN_CTX_end := @ERR_BN_CTX_end;
    {$ifend}
    {$if declared(BN_CTX_end_introduced)}
    if LibVersion < BN_CTX_end_introduced then
    begin
      {$if declared(FC_BN_CTX_end)}
      BN_CTX_end := @FC_BN_CTX_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_CTX_end_removed)}
    if BN_CTX_end_removed <= LibVersion then
    begin
      {$if declared(_BN_CTX_end)}
      BN_CTX_end := @_BN_CTX_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_CTX_end_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_CTX_end');
    {$ifend}
  end;


  BN_rand := LoadLibFunction(ADllHandle, BN_rand_procname);
  FuncLoadError := not assigned(BN_rand);
  if FuncLoadError then
  begin
    {$if not defined(BN_rand_allownil)}
    BN_rand := @ERR_BN_rand;
    {$ifend}
    {$if declared(BN_rand_introduced)}
    if LibVersion < BN_rand_introduced then
    begin
      {$if declared(FC_BN_rand)}
      BN_rand := @FC_BN_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_rand_removed)}
    if BN_rand_removed <= LibVersion then
    begin
      {$if declared(_BN_rand)}
      BN_rand := @_BN_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_rand_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_rand');
    {$ifend}
  end;


  BN_priv_rand := LoadLibFunction(ADllHandle, BN_priv_rand_procname);
  FuncLoadError := not assigned(BN_priv_rand);
  if FuncLoadError then
  begin
    {$if not defined(BN_priv_rand_allownil)}
    BN_priv_rand := @ERR_BN_priv_rand;
    {$ifend}
    {$if declared(BN_priv_rand_introduced)}
    if LibVersion < BN_priv_rand_introduced then
    begin
      {$if declared(FC_BN_priv_rand)}
      BN_priv_rand := @FC_BN_priv_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_priv_rand_removed)}
    if BN_priv_rand_removed <= LibVersion then
    begin
      {$if declared(_BN_priv_rand)}
      BN_priv_rand := @_BN_priv_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_priv_rand_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_priv_rand');
    {$ifend}
  end;


  BN_rand_range := LoadLibFunction(ADllHandle, BN_rand_range_procname);
  FuncLoadError := not assigned(BN_rand_range);
  if FuncLoadError then
  begin
    {$if not defined(BN_rand_range_allownil)}
    BN_rand_range := @ERR_BN_rand_range;
    {$ifend}
    {$if declared(BN_rand_range_introduced)}
    if LibVersion < BN_rand_range_introduced then
    begin
      {$if declared(FC_BN_rand_range)}
      BN_rand_range := @FC_BN_rand_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_rand_range_removed)}
    if BN_rand_range_removed <= LibVersion then
    begin
      {$if declared(_BN_rand_range)}
      BN_rand_range := @_BN_rand_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_rand_range_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_rand_range');
    {$ifend}
  end;


  BN_priv_rand_range := LoadLibFunction(ADllHandle, BN_priv_rand_range_procname);
  FuncLoadError := not assigned(BN_priv_rand_range);
  if FuncLoadError then
  begin
    {$if not defined(BN_priv_rand_range_allownil)}
    BN_priv_rand_range := @ERR_BN_priv_rand_range;
    {$ifend}
    {$if declared(BN_priv_rand_range_introduced)}
    if LibVersion < BN_priv_rand_range_introduced then
    begin
      {$if declared(FC_BN_priv_rand_range)}
      BN_priv_rand_range := @FC_BN_priv_rand_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_priv_rand_range_removed)}
    if BN_priv_rand_range_removed <= LibVersion then
    begin
      {$if declared(_BN_priv_rand_range)}
      BN_priv_rand_range := @_BN_priv_rand_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_priv_rand_range_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_priv_rand_range');
    {$ifend}
  end;


  BN_pseudo_rand := LoadLibFunction(ADllHandle, BN_pseudo_rand_procname);
  FuncLoadError := not assigned(BN_pseudo_rand);
  if FuncLoadError then
  begin
    {$if not defined(BN_pseudo_rand_allownil)}
    BN_pseudo_rand := @ERR_BN_pseudo_rand;
    {$ifend}
    {$if declared(BN_pseudo_rand_introduced)}
    if LibVersion < BN_pseudo_rand_introduced then
    begin
      {$if declared(FC_BN_pseudo_rand)}
      BN_pseudo_rand := @FC_BN_pseudo_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_pseudo_rand_removed)}
    if BN_pseudo_rand_removed <= LibVersion then
    begin
      {$if declared(_BN_pseudo_rand)}
      BN_pseudo_rand := @_BN_pseudo_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_pseudo_rand_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_pseudo_rand');
    {$ifend}
  end;


  BN_pseudo_rand_range := LoadLibFunction(ADllHandle, BN_pseudo_rand_range_procname);
  FuncLoadError := not assigned(BN_pseudo_rand_range);
  if FuncLoadError then
  begin
    {$if not defined(BN_pseudo_rand_range_allownil)}
    BN_pseudo_rand_range := @ERR_BN_pseudo_rand_range;
    {$ifend}
    {$if declared(BN_pseudo_rand_range_introduced)}
    if LibVersion < BN_pseudo_rand_range_introduced then
    begin
      {$if declared(FC_BN_pseudo_rand_range)}
      BN_pseudo_rand_range := @FC_BN_pseudo_rand_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_pseudo_rand_range_removed)}
    if BN_pseudo_rand_range_removed <= LibVersion then
    begin
      {$if declared(_BN_pseudo_rand_range)}
      BN_pseudo_rand_range := @_BN_pseudo_rand_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_pseudo_rand_range_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_pseudo_rand_range');
    {$ifend}
  end;


  BN_num_bits := LoadLibFunction(ADllHandle, BN_num_bits_procname);
  FuncLoadError := not assigned(BN_num_bits);
  if FuncLoadError then
  begin
    {$if not defined(BN_num_bits_allownil)}
    BN_num_bits := @ERR_BN_num_bits;
    {$ifend}
    {$if declared(BN_num_bits_introduced)}
    if LibVersion < BN_num_bits_introduced then
    begin
      {$if declared(FC_BN_num_bits)}
      BN_num_bits := @FC_BN_num_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_num_bits_removed)}
    if BN_num_bits_removed <= LibVersion then
    begin
      {$if declared(_BN_num_bits)}
      BN_num_bits := @_BN_num_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_num_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_num_bits');
    {$ifend}
  end;


  BN_num_bits_word := LoadLibFunction(ADllHandle, BN_num_bits_word_procname);
  FuncLoadError := not assigned(BN_num_bits_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_num_bits_word_allownil)}
    BN_num_bits_word := @ERR_BN_num_bits_word;
    {$ifend}
    {$if declared(BN_num_bits_word_introduced)}
    if LibVersion < BN_num_bits_word_introduced then
    begin
      {$if declared(FC_BN_num_bits_word)}
      BN_num_bits_word := @FC_BN_num_bits_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_num_bits_word_removed)}
    if BN_num_bits_word_removed <= LibVersion then
    begin
      {$if declared(_BN_num_bits_word)}
      BN_num_bits_word := @_BN_num_bits_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_num_bits_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_num_bits_word');
    {$ifend}
  end;


  BN_security_bits := LoadLibFunction(ADllHandle, BN_security_bits_procname);
  FuncLoadError := not assigned(BN_security_bits);
  if FuncLoadError then
  begin
    {$if not defined(BN_security_bits_allownil)}
    BN_security_bits := @ERR_BN_security_bits;
    {$ifend}
    {$if declared(BN_security_bits_introduced)}
    if LibVersion < BN_security_bits_introduced then
    begin
      {$if declared(FC_BN_security_bits)}
      BN_security_bits := @FC_BN_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_security_bits_removed)}
    if BN_security_bits_removed <= LibVersion then
    begin
      {$if declared(_BN_security_bits)}
      BN_security_bits := @_BN_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_security_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_security_bits');
    {$ifend}
  end;


  BN_new := LoadLibFunction(ADllHandle, BN_new_procname);
  FuncLoadError := not assigned(BN_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_new_allownil)}
    BN_new := @ERR_BN_new;
    {$ifend}
    {$if declared(BN_new_introduced)}
    if LibVersion < BN_new_introduced then
    begin
      {$if declared(FC_BN_new)}
      BN_new := @FC_BN_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_new_removed)}
    if BN_new_removed <= LibVersion then
    begin
      {$if declared(_BN_new)}
      BN_new := @_BN_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_new');
    {$ifend}
  end;


  BN_secure_new := LoadLibFunction(ADllHandle, BN_secure_new_procname);
  FuncLoadError := not assigned(BN_secure_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_secure_new_allownil)}
    BN_secure_new := @ERR_BN_secure_new;
    {$ifend}
    {$if declared(BN_secure_new_introduced)}
    if LibVersion < BN_secure_new_introduced then
    begin
      {$if declared(FC_BN_secure_new)}
      BN_secure_new := @FC_BN_secure_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_secure_new_removed)}
    if BN_secure_new_removed <= LibVersion then
    begin
      {$if declared(_BN_secure_new)}
      BN_secure_new := @_BN_secure_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_secure_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_secure_new');
    {$ifend}
  end;


  BN_clear_free := LoadLibFunction(ADllHandle, BN_clear_free_procname);
  FuncLoadError := not assigned(BN_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_clear_free_allownil)}
    BN_clear_free := @ERR_BN_clear_free;
    {$ifend}
    {$if declared(BN_clear_free_introduced)}
    if LibVersion < BN_clear_free_introduced then
    begin
      {$if declared(FC_BN_clear_free)}
      BN_clear_free := @FC_BN_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_clear_free_removed)}
    if BN_clear_free_removed <= LibVersion then
    begin
      {$if declared(_BN_clear_free)}
      BN_clear_free := @_BN_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_clear_free');
    {$ifend}
  end;


  BN_copy := LoadLibFunction(ADllHandle, BN_copy_procname);
  FuncLoadError := not assigned(BN_copy);
  if FuncLoadError then
  begin
    {$if not defined(BN_copy_allownil)}
    BN_copy := @ERR_BN_copy;
    {$ifend}
    {$if declared(BN_copy_introduced)}
    if LibVersion < BN_copy_introduced then
    begin
      {$if declared(FC_BN_copy)}
      BN_copy := @FC_BN_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_copy_removed)}
    if BN_copy_removed <= LibVersion then
    begin
      {$if declared(_BN_copy)}
      BN_copy := @_BN_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_copy');
    {$ifend}
  end;


  BN_swap := LoadLibFunction(ADllHandle, BN_swap_procname);
  FuncLoadError := not assigned(BN_swap);
  if FuncLoadError then
  begin
    {$if not defined(BN_swap_allownil)}
    BN_swap := @ERR_BN_swap;
    {$ifend}
    {$if declared(BN_swap_introduced)}
    if LibVersion < BN_swap_introduced then
    begin
      {$if declared(FC_BN_swap)}
      BN_swap := @FC_BN_swap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_swap_removed)}
    if BN_swap_removed <= LibVersion then
    begin
      {$if declared(_BN_swap)}
      BN_swap := @_BN_swap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_swap_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_swap');
    {$ifend}
  end;


  BN_bin2bn := LoadLibFunction(ADllHandle, BN_bin2bn_procname);
  FuncLoadError := not assigned(BN_bin2bn);
  if FuncLoadError then
  begin
    {$if not defined(BN_bin2bn_allownil)}
    BN_bin2bn := @ERR_BN_bin2bn;
    {$ifend}
    {$if declared(BN_bin2bn_introduced)}
    if LibVersion < BN_bin2bn_introduced then
    begin
      {$if declared(FC_BN_bin2bn)}
      BN_bin2bn := @FC_BN_bin2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bin2bn_removed)}
    if BN_bin2bn_removed <= LibVersion then
    begin
      {$if declared(_BN_bin2bn)}
      BN_bin2bn := @_BN_bin2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bin2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bin2bn');
    {$ifend}
  end;


  BN_bn2bin := LoadLibFunction(ADllHandle, BN_bn2bin_procname);
  FuncLoadError := not assigned(BN_bn2bin);
  if FuncLoadError then
  begin
    {$if not defined(BN_bn2bin_allownil)}
    BN_bn2bin := @ERR_BN_bn2bin;
    {$ifend}
    {$if declared(BN_bn2bin_introduced)}
    if LibVersion < BN_bn2bin_introduced then
    begin
      {$if declared(FC_BN_bn2bin)}
      BN_bn2bin := @FC_BN_bn2bin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bn2bin_removed)}
    if BN_bn2bin_removed <= LibVersion then
    begin
      {$if declared(_BN_bn2bin)}
      BN_bn2bin := @_BN_bn2bin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bn2bin_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bn2bin');
    {$ifend}
  end;


  BN_bn2binpad := LoadLibFunction(ADllHandle, BN_bn2binpad_procname);
  FuncLoadError := not assigned(BN_bn2binpad);
  if FuncLoadError then
  begin
    {$if not defined(BN_bn2binpad_allownil)}
    BN_bn2binpad := @ERR_BN_bn2binpad;
    {$ifend}
    {$if declared(BN_bn2binpad_introduced)}
    if LibVersion < BN_bn2binpad_introduced then
    begin
      {$if declared(FC_BN_bn2binpad)}
      BN_bn2binpad := @FC_BN_bn2binpad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bn2binpad_removed)}
    if BN_bn2binpad_removed <= LibVersion then
    begin
      {$if declared(_BN_bn2binpad)}
      BN_bn2binpad := @_BN_bn2binpad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bn2binpad_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bn2binpad');
    {$ifend}
  end;


  BN_lebin2bn := LoadLibFunction(ADllHandle, BN_lebin2bn_procname);
  FuncLoadError := not assigned(BN_lebin2bn);
  if FuncLoadError then
  begin
    {$if not defined(BN_lebin2bn_allownil)}
    BN_lebin2bn := @ERR_BN_lebin2bn;
    {$ifend}
    {$if declared(BN_lebin2bn_introduced)}
    if LibVersion < BN_lebin2bn_introduced then
    begin
      {$if declared(FC_BN_lebin2bn)}
      BN_lebin2bn := @FC_BN_lebin2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_lebin2bn_removed)}
    if BN_lebin2bn_removed <= LibVersion then
    begin
      {$if declared(_BN_lebin2bn)}
      BN_lebin2bn := @_BN_lebin2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_lebin2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_lebin2bn');
    {$ifend}
  end;


  BN_bn2lebinpad := LoadLibFunction(ADllHandle, BN_bn2lebinpad_procname);
  FuncLoadError := not assigned(BN_bn2lebinpad);
  if FuncLoadError then
  begin
    {$if not defined(BN_bn2lebinpad_allownil)}
    BN_bn2lebinpad := @ERR_BN_bn2lebinpad;
    {$ifend}
    {$if declared(BN_bn2lebinpad_introduced)}
    if LibVersion < BN_bn2lebinpad_introduced then
    begin
      {$if declared(FC_BN_bn2lebinpad)}
      BN_bn2lebinpad := @FC_BN_bn2lebinpad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bn2lebinpad_removed)}
    if BN_bn2lebinpad_removed <= LibVersion then
    begin
      {$if declared(_BN_bn2lebinpad)}
      BN_bn2lebinpad := @_BN_bn2lebinpad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bn2lebinpad_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bn2lebinpad');
    {$ifend}
  end;


  BN_mpi2bn := LoadLibFunction(ADllHandle, BN_mpi2bn_procname);
  FuncLoadError := not assigned(BN_mpi2bn);
  if FuncLoadError then
  begin
    {$if not defined(BN_mpi2bn_allownil)}
    BN_mpi2bn := @ERR_BN_mpi2bn;
    {$ifend}
    {$if declared(BN_mpi2bn_introduced)}
    if LibVersion < BN_mpi2bn_introduced then
    begin
      {$if declared(FC_BN_mpi2bn)}
      BN_mpi2bn := @FC_BN_mpi2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mpi2bn_removed)}
    if BN_mpi2bn_removed <= LibVersion then
    begin
      {$if declared(_BN_mpi2bn)}
      BN_mpi2bn := @_BN_mpi2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mpi2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mpi2bn');
    {$ifend}
  end;


  BN_bn2mpi := LoadLibFunction(ADllHandle, BN_bn2mpi_procname);
  FuncLoadError := not assigned(BN_bn2mpi);
  if FuncLoadError then
  begin
    {$if not defined(BN_bn2mpi_allownil)}
    BN_bn2mpi := @ERR_BN_bn2mpi;
    {$ifend}
    {$if declared(BN_bn2mpi_introduced)}
    if LibVersion < BN_bn2mpi_introduced then
    begin
      {$if declared(FC_BN_bn2mpi)}
      BN_bn2mpi := @FC_BN_bn2mpi;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bn2mpi_removed)}
    if BN_bn2mpi_removed <= LibVersion then
    begin
      {$if declared(_BN_bn2mpi)}
      BN_bn2mpi := @_BN_bn2mpi;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bn2mpi_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bn2mpi');
    {$ifend}
  end;


  BN_sub := LoadLibFunction(ADllHandle, BN_sub_procname);
  FuncLoadError := not assigned(BN_sub);
  if FuncLoadError then
  begin
    {$if not defined(BN_sub_allownil)}
    BN_sub := @ERR_BN_sub;
    {$ifend}
    {$if declared(BN_sub_introduced)}
    if LibVersion < BN_sub_introduced then
    begin
      {$if declared(FC_BN_sub)}
      BN_sub := @FC_BN_sub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_sub_removed)}
    if BN_sub_removed <= LibVersion then
    begin
      {$if declared(_BN_sub)}
      BN_sub := @_BN_sub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_sub_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_sub');
    {$ifend}
  end;


  BN_usub := LoadLibFunction(ADllHandle, BN_usub_procname);
  FuncLoadError := not assigned(BN_usub);
  if FuncLoadError then
  begin
    {$if not defined(BN_usub_allownil)}
    BN_usub := @ERR_BN_usub;
    {$ifend}
    {$if declared(BN_usub_introduced)}
    if LibVersion < BN_usub_introduced then
    begin
      {$if declared(FC_BN_usub)}
      BN_usub := @FC_BN_usub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_usub_removed)}
    if BN_usub_removed <= LibVersion then
    begin
      {$if declared(_BN_usub)}
      BN_usub := @_BN_usub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_usub_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_usub');
    {$ifend}
  end;


  BN_uadd := LoadLibFunction(ADllHandle, BN_uadd_procname);
  FuncLoadError := not assigned(BN_uadd);
  if FuncLoadError then
  begin
    {$if not defined(BN_uadd_allownil)}
    BN_uadd := @ERR_BN_uadd;
    {$ifend}
    {$if declared(BN_uadd_introduced)}
    if LibVersion < BN_uadd_introduced then
    begin
      {$if declared(FC_BN_uadd)}
      BN_uadd := @FC_BN_uadd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_uadd_removed)}
    if BN_uadd_removed <= LibVersion then
    begin
      {$if declared(_BN_uadd)}
      BN_uadd := @_BN_uadd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_uadd_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_uadd');
    {$ifend}
  end;


  BN_add := LoadLibFunction(ADllHandle, BN_add_procname);
  FuncLoadError := not assigned(BN_add);
  if FuncLoadError then
  begin
    {$if not defined(BN_add_allownil)}
    BN_add := @ERR_BN_add;
    {$ifend}
    {$if declared(BN_add_introduced)}
    if LibVersion < BN_add_introduced then
    begin
      {$if declared(FC_BN_add)}
      BN_add := @FC_BN_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_add_removed)}
    if BN_add_removed <= LibVersion then
    begin
      {$if declared(_BN_add)}
      BN_add := @_BN_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_add_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_add');
    {$ifend}
  end;


  BN_mul := LoadLibFunction(ADllHandle, BN_mul_procname);
  FuncLoadError := not assigned(BN_mul);
  if FuncLoadError then
  begin
    {$if not defined(BN_mul_allownil)}
    BN_mul := @ERR_BN_mul;
    {$ifend}
    {$if declared(BN_mul_introduced)}
    if LibVersion < BN_mul_introduced then
    begin
      {$if declared(FC_BN_mul)}
      BN_mul := @FC_BN_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mul_removed)}
    if BN_mul_removed <= LibVersion then
    begin
      {$if declared(_BN_mul)}
      BN_mul := @_BN_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mul_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mul');
    {$ifend}
  end;


  BN_sqr := LoadLibFunction(ADllHandle, BN_sqr_procname);
  FuncLoadError := not assigned(BN_sqr);
  if FuncLoadError then
  begin
    {$if not defined(BN_sqr_allownil)}
    BN_sqr := @ERR_BN_sqr;
    {$ifend}
    {$if declared(BN_sqr_introduced)}
    if LibVersion < BN_sqr_introduced then
    begin
      {$if declared(FC_BN_sqr)}
      BN_sqr := @FC_BN_sqr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_sqr_removed)}
    if BN_sqr_removed <= LibVersion then
    begin
      {$if declared(_BN_sqr)}
      BN_sqr := @_BN_sqr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_sqr_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_sqr');
    {$ifend}
  end;


  BN_set_negative := LoadLibFunction(ADllHandle, BN_set_negative_procname);
  FuncLoadError := not assigned(BN_set_negative);
  if FuncLoadError then
  begin
    {$if not defined(BN_set_negative_allownil)}
    BN_set_negative := @ERR_BN_set_negative;
    {$ifend}
    {$if declared(BN_set_negative_introduced)}
    if LibVersion < BN_set_negative_introduced then
    begin
      {$if declared(FC_BN_set_negative)}
      BN_set_negative := @FC_BN_set_negative;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_set_negative_removed)}
    if BN_set_negative_removed <= LibVersion then
    begin
      {$if declared(_BN_set_negative)}
      BN_set_negative := @_BN_set_negative;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_set_negative_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_set_negative');
    {$ifend}
  end;


  BN_is_negative := LoadLibFunction(ADllHandle, BN_is_negative_procname);
  FuncLoadError := not assigned(BN_is_negative);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_negative_allownil)}
    BN_is_negative := @ERR_BN_is_negative;
    {$ifend}
    {$if declared(BN_is_negative_introduced)}
    if LibVersion < BN_is_negative_introduced then
    begin
      {$if declared(FC_BN_is_negative)}
      BN_is_negative := @FC_BN_is_negative;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_negative_removed)}
    if BN_is_negative_removed <= LibVersion then
    begin
      {$if declared(_BN_is_negative)}
      BN_is_negative := @_BN_is_negative;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_negative_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_negative');
    {$ifend}
  end;


  BN_div := LoadLibFunction(ADllHandle, BN_div_procname);
  FuncLoadError := not assigned(BN_div);
  if FuncLoadError then
  begin
    {$if not defined(BN_div_allownil)}
    BN_div := @ERR_BN_div;
    {$ifend}
    {$if declared(BN_div_introduced)}
    if LibVersion < BN_div_introduced then
    begin
      {$if declared(FC_BN_div)}
      BN_div := @FC_BN_div;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_div_removed)}
    if BN_div_removed <= LibVersion then
    begin
      {$if declared(_BN_div)}
      BN_div := @_BN_div;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_div_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_div');
    {$ifend}
  end;


  BN_nnmod := LoadLibFunction(ADllHandle, BN_nnmod_procname);
  FuncLoadError := not assigned(BN_nnmod);
  if FuncLoadError then
  begin
    {$if not defined(BN_nnmod_allownil)}
    BN_nnmod := @ERR_BN_nnmod;
    {$ifend}
    {$if declared(BN_nnmod_introduced)}
    if LibVersion < BN_nnmod_introduced then
    begin
      {$if declared(FC_BN_nnmod)}
      BN_nnmod := @FC_BN_nnmod;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_nnmod_removed)}
    if BN_nnmod_removed <= LibVersion then
    begin
      {$if declared(_BN_nnmod)}
      BN_nnmod := @_BN_nnmod;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_nnmod_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_nnmod');
    {$ifend}
  end;


  BN_mod_add := LoadLibFunction(ADllHandle, BN_mod_add_procname);
  FuncLoadError := not assigned(BN_mod_add);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_add_allownil)}
    BN_mod_add := @ERR_BN_mod_add;
    {$ifend}
    {$if declared(BN_mod_add_introduced)}
    if LibVersion < BN_mod_add_introduced then
    begin
      {$if declared(FC_BN_mod_add)}
      BN_mod_add := @FC_BN_mod_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_add_removed)}
    if BN_mod_add_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_add)}
      BN_mod_add := @_BN_mod_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_add_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_add');
    {$ifend}
  end;


  BN_mod_add_quick := LoadLibFunction(ADllHandle, BN_mod_add_quick_procname);
  FuncLoadError := not assigned(BN_mod_add_quick);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_add_quick_allownil)}
    BN_mod_add_quick := @ERR_BN_mod_add_quick;
    {$ifend}
    {$if declared(BN_mod_add_quick_introduced)}
    if LibVersion < BN_mod_add_quick_introduced then
    begin
      {$if declared(FC_BN_mod_add_quick)}
      BN_mod_add_quick := @FC_BN_mod_add_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_add_quick_removed)}
    if BN_mod_add_quick_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_add_quick)}
      BN_mod_add_quick := @_BN_mod_add_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_add_quick_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_add_quick');
    {$ifend}
  end;


  BN_mod_sub := LoadLibFunction(ADllHandle, BN_mod_sub_procname);
  FuncLoadError := not assigned(BN_mod_sub);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_sub_allownil)}
    BN_mod_sub := @ERR_BN_mod_sub;
    {$ifend}
    {$if declared(BN_mod_sub_introduced)}
    if LibVersion < BN_mod_sub_introduced then
    begin
      {$if declared(FC_BN_mod_sub)}
      BN_mod_sub := @FC_BN_mod_sub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_sub_removed)}
    if BN_mod_sub_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_sub)}
      BN_mod_sub := @_BN_mod_sub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_sub_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_sub');
    {$ifend}
  end;


  BN_mod_sub_quick := LoadLibFunction(ADllHandle, BN_mod_sub_quick_procname);
  FuncLoadError := not assigned(BN_mod_sub_quick);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_sub_quick_allownil)}
    BN_mod_sub_quick := @ERR_BN_mod_sub_quick;
    {$ifend}
    {$if declared(BN_mod_sub_quick_introduced)}
    if LibVersion < BN_mod_sub_quick_introduced then
    begin
      {$if declared(FC_BN_mod_sub_quick)}
      BN_mod_sub_quick := @FC_BN_mod_sub_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_sub_quick_removed)}
    if BN_mod_sub_quick_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_sub_quick)}
      BN_mod_sub_quick := @_BN_mod_sub_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_sub_quick_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_sub_quick');
    {$ifend}
  end;


  BN_mod_mul := LoadLibFunction(ADllHandle, BN_mod_mul_procname);
  FuncLoadError := not assigned(BN_mod_mul);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_mul_allownil)}
    BN_mod_mul := @ERR_BN_mod_mul;
    {$ifend}
    {$if declared(BN_mod_mul_introduced)}
    if LibVersion < BN_mod_mul_introduced then
    begin
      {$if declared(FC_BN_mod_mul)}
      BN_mod_mul := @FC_BN_mod_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_mul_removed)}
    if BN_mod_mul_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_mul)}
      BN_mod_mul := @_BN_mod_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_mul_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_mul');
    {$ifend}
  end;


  BN_mod_sqr := LoadLibFunction(ADllHandle, BN_mod_sqr_procname);
  FuncLoadError := not assigned(BN_mod_sqr);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_sqr_allownil)}
    BN_mod_sqr := @ERR_BN_mod_sqr;
    {$ifend}
    {$if declared(BN_mod_sqr_introduced)}
    if LibVersion < BN_mod_sqr_introduced then
    begin
      {$if declared(FC_BN_mod_sqr)}
      BN_mod_sqr := @FC_BN_mod_sqr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_sqr_removed)}
    if BN_mod_sqr_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_sqr)}
      BN_mod_sqr := @_BN_mod_sqr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_sqr_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_sqr');
    {$ifend}
  end;


  BN_mod_lshift1 := LoadLibFunction(ADllHandle, BN_mod_lshift1_procname);
  FuncLoadError := not assigned(BN_mod_lshift1);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_lshift1_allownil)}
    BN_mod_lshift1 := @ERR_BN_mod_lshift1;
    {$ifend}
    {$if declared(BN_mod_lshift1_introduced)}
    if LibVersion < BN_mod_lshift1_introduced then
    begin
      {$if declared(FC_BN_mod_lshift1)}
      BN_mod_lshift1 := @FC_BN_mod_lshift1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_lshift1_removed)}
    if BN_mod_lshift1_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_lshift1)}
      BN_mod_lshift1 := @_BN_mod_lshift1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_lshift1_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_lshift1');
    {$ifend}
  end;


  BN_mod_lshift1_quick := LoadLibFunction(ADllHandle, BN_mod_lshift1_quick_procname);
  FuncLoadError := not assigned(BN_mod_lshift1_quick);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_lshift1_quick_allownil)}
    BN_mod_lshift1_quick := @ERR_BN_mod_lshift1_quick;
    {$ifend}
    {$if declared(BN_mod_lshift1_quick_introduced)}
    if LibVersion < BN_mod_lshift1_quick_introduced then
    begin
      {$if declared(FC_BN_mod_lshift1_quick)}
      BN_mod_lshift1_quick := @FC_BN_mod_lshift1_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_lshift1_quick_removed)}
    if BN_mod_lshift1_quick_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_lshift1_quick)}
      BN_mod_lshift1_quick := @_BN_mod_lshift1_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_lshift1_quick_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_lshift1_quick');
    {$ifend}
  end;


  BN_mod_lshift := LoadLibFunction(ADllHandle, BN_mod_lshift_procname);
  FuncLoadError := not assigned(BN_mod_lshift);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_lshift_allownil)}
    BN_mod_lshift := @ERR_BN_mod_lshift;
    {$ifend}
    {$if declared(BN_mod_lshift_introduced)}
    if LibVersion < BN_mod_lshift_introduced then
    begin
      {$if declared(FC_BN_mod_lshift)}
      BN_mod_lshift := @FC_BN_mod_lshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_lshift_removed)}
    if BN_mod_lshift_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_lshift)}
      BN_mod_lshift := @_BN_mod_lshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_lshift_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_lshift');
    {$ifend}
  end;


  BN_mod_lshift_quick := LoadLibFunction(ADllHandle, BN_mod_lshift_quick_procname);
  FuncLoadError := not assigned(BN_mod_lshift_quick);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_lshift_quick_allownil)}
    BN_mod_lshift_quick := @ERR_BN_mod_lshift_quick;
    {$ifend}
    {$if declared(BN_mod_lshift_quick_introduced)}
    if LibVersion < BN_mod_lshift_quick_introduced then
    begin
      {$if declared(FC_BN_mod_lshift_quick)}
      BN_mod_lshift_quick := @FC_BN_mod_lshift_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_lshift_quick_removed)}
    if BN_mod_lshift_quick_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_lshift_quick)}
      BN_mod_lshift_quick := @_BN_mod_lshift_quick;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_lshift_quick_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_lshift_quick');
    {$ifend}
  end;


  BN_mod_word := LoadLibFunction(ADllHandle, BN_mod_word_procname);
  FuncLoadError := not assigned(BN_mod_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_word_allownil)}
    BN_mod_word := @ERR_BN_mod_word;
    {$ifend}
    {$if declared(BN_mod_word_introduced)}
    if LibVersion < BN_mod_word_introduced then
    begin
      {$if declared(FC_BN_mod_word)}
      BN_mod_word := @FC_BN_mod_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_word_removed)}
    if BN_mod_word_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_word)}
      BN_mod_word := @_BN_mod_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_word');
    {$ifend}
  end;


  BN_div_word := LoadLibFunction(ADllHandle, BN_div_word_procname);
  FuncLoadError := not assigned(BN_div_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_div_word_allownil)}
    BN_div_word := @ERR_BN_div_word;
    {$ifend}
    {$if declared(BN_div_word_introduced)}
    if LibVersion < BN_div_word_introduced then
    begin
      {$if declared(FC_BN_div_word)}
      BN_div_word := @FC_BN_div_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_div_word_removed)}
    if BN_div_word_removed <= LibVersion then
    begin
      {$if declared(_BN_div_word)}
      BN_div_word := @_BN_div_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_div_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_div_word');
    {$ifend}
  end;


  BN_mul_word := LoadLibFunction(ADllHandle, BN_mul_word_procname);
  FuncLoadError := not assigned(BN_mul_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_mul_word_allownil)}
    BN_mul_word := @ERR_BN_mul_word;
    {$ifend}
    {$if declared(BN_mul_word_introduced)}
    if LibVersion < BN_mul_word_introduced then
    begin
      {$if declared(FC_BN_mul_word)}
      BN_mul_word := @FC_BN_mul_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mul_word_removed)}
    if BN_mul_word_removed <= LibVersion then
    begin
      {$if declared(_BN_mul_word)}
      BN_mul_word := @_BN_mul_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mul_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mul_word');
    {$ifend}
  end;


  BN_add_word := LoadLibFunction(ADllHandle, BN_add_word_procname);
  FuncLoadError := not assigned(BN_add_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_add_word_allownil)}
    BN_add_word := @ERR_BN_add_word;
    {$ifend}
    {$if declared(BN_add_word_introduced)}
    if LibVersion < BN_add_word_introduced then
    begin
      {$if declared(FC_BN_add_word)}
      BN_add_word := @FC_BN_add_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_add_word_removed)}
    if BN_add_word_removed <= LibVersion then
    begin
      {$if declared(_BN_add_word)}
      BN_add_word := @_BN_add_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_add_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_add_word');
    {$ifend}
  end;


  BN_sub_word := LoadLibFunction(ADllHandle, BN_sub_word_procname);
  FuncLoadError := not assigned(BN_sub_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_sub_word_allownil)}
    BN_sub_word := @ERR_BN_sub_word;
    {$ifend}
    {$if declared(BN_sub_word_introduced)}
    if LibVersion < BN_sub_word_introduced then
    begin
      {$if declared(FC_BN_sub_word)}
      BN_sub_word := @FC_BN_sub_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_sub_word_removed)}
    if BN_sub_word_removed <= LibVersion then
    begin
      {$if declared(_BN_sub_word)}
      BN_sub_word := @_BN_sub_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_sub_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_sub_word');
    {$ifend}
  end;


  BN_set_word := LoadLibFunction(ADllHandle, BN_set_word_procname);
  FuncLoadError := not assigned(BN_set_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_set_word_allownil)}
    BN_set_word := @ERR_BN_set_word;
    {$ifend}
    {$if declared(BN_set_word_introduced)}
    if LibVersion < BN_set_word_introduced then
    begin
      {$if declared(FC_BN_set_word)}
      BN_set_word := @FC_BN_set_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_set_word_removed)}
    if BN_set_word_removed <= LibVersion then
    begin
      {$if declared(_BN_set_word)}
      BN_set_word := @_BN_set_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_set_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_set_word');
    {$ifend}
  end;


  BN_get_word := LoadLibFunction(ADllHandle, BN_get_word_procname);
  FuncLoadError := not assigned(BN_get_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_word_allownil)}
    BN_get_word := @ERR_BN_get_word;
    {$ifend}
    {$if declared(BN_get_word_introduced)}
    if LibVersion < BN_get_word_introduced then
    begin
      {$if declared(FC_BN_get_word)}
      BN_get_word := @FC_BN_get_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_word_removed)}
    if BN_get_word_removed <= LibVersion then
    begin
      {$if declared(_BN_get_word)}
      BN_get_word := @_BN_get_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_word');
    {$ifend}
  end;


  BN_cmp := LoadLibFunction(ADllHandle, BN_cmp_procname);
  FuncLoadError := not assigned(BN_cmp);
  if FuncLoadError then
  begin
    {$if not defined(BN_cmp_allownil)}
    BN_cmp := @ERR_BN_cmp;
    {$ifend}
    {$if declared(BN_cmp_introduced)}
    if LibVersion < BN_cmp_introduced then
    begin
      {$if declared(FC_BN_cmp)}
      BN_cmp := @FC_BN_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_cmp_removed)}
    if BN_cmp_removed <= LibVersion then
    begin
      {$if declared(_BN_cmp)}
      BN_cmp := @_BN_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_cmp');
    {$ifend}
  end;


  BN_free := LoadLibFunction(ADllHandle, BN_free_procname);
  FuncLoadError := not assigned(BN_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_free_allownil)}
    BN_free := @ERR_BN_free;
    {$ifend}
    {$if declared(BN_free_introduced)}
    if LibVersion < BN_free_introduced then
    begin
      {$if declared(FC_BN_free)}
      BN_free := @FC_BN_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_free_removed)}
    if BN_free_removed <= LibVersion then
    begin
      {$if declared(_BN_free)}
      BN_free := @_BN_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_free');
    {$ifend}
  end;


  BN_is_bit_set := LoadLibFunction(ADllHandle, BN_is_bit_set_procname);
  FuncLoadError := not assigned(BN_is_bit_set);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_bit_set_allownil)}
    BN_is_bit_set := @ERR_BN_is_bit_set;
    {$ifend}
    {$if declared(BN_is_bit_set_introduced)}
    if LibVersion < BN_is_bit_set_introduced then
    begin
      {$if declared(FC_BN_is_bit_set)}
      BN_is_bit_set := @FC_BN_is_bit_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_bit_set_removed)}
    if BN_is_bit_set_removed <= LibVersion then
    begin
      {$if declared(_BN_is_bit_set)}
      BN_is_bit_set := @_BN_is_bit_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_bit_set_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_bit_set');
    {$ifend}
  end;


  BN_lshift := LoadLibFunction(ADllHandle, BN_lshift_procname);
  FuncLoadError := not assigned(BN_lshift);
  if FuncLoadError then
  begin
    {$if not defined(BN_lshift_allownil)}
    BN_lshift := @ERR_BN_lshift;
    {$ifend}
    {$if declared(BN_lshift_introduced)}
    if LibVersion < BN_lshift_introduced then
    begin
      {$if declared(FC_BN_lshift)}
      BN_lshift := @FC_BN_lshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_lshift_removed)}
    if BN_lshift_removed <= LibVersion then
    begin
      {$if declared(_BN_lshift)}
      BN_lshift := @_BN_lshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_lshift_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_lshift');
    {$ifend}
  end;


  BN_lshift1 := LoadLibFunction(ADllHandle, BN_lshift1_procname);
  FuncLoadError := not assigned(BN_lshift1);
  if FuncLoadError then
  begin
    {$if not defined(BN_lshift1_allownil)}
    BN_lshift1 := @ERR_BN_lshift1;
    {$ifend}
    {$if declared(BN_lshift1_introduced)}
    if LibVersion < BN_lshift1_introduced then
    begin
      {$if declared(FC_BN_lshift1)}
      BN_lshift1 := @FC_BN_lshift1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_lshift1_removed)}
    if BN_lshift1_removed <= LibVersion then
    begin
      {$if declared(_BN_lshift1)}
      BN_lshift1 := @_BN_lshift1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_lshift1_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_lshift1');
    {$ifend}
  end;


  BN_exp := LoadLibFunction(ADllHandle, BN_exp_procname);
  FuncLoadError := not assigned(BN_exp);
  if FuncLoadError then
  begin
    {$if not defined(BN_exp_allownil)}
    BN_exp := @ERR_BN_exp;
    {$ifend}
    {$if declared(BN_exp_introduced)}
    if LibVersion < BN_exp_introduced then
    begin
      {$if declared(FC_BN_exp)}
      BN_exp := @FC_BN_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_exp_removed)}
    if BN_exp_removed <= LibVersion then
    begin
      {$if declared(_BN_exp)}
      BN_exp := @_BN_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_exp');
    {$ifend}
  end;


  BN_mod_exp := LoadLibFunction(ADllHandle, BN_mod_exp_procname);
  FuncLoadError := not assigned(BN_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp_allownil)}
    BN_mod_exp := @ERR_BN_mod_exp;
    {$ifend}
    {$if declared(BN_mod_exp_introduced)}
    if LibVersion < BN_mod_exp_introduced then
    begin
      {$if declared(FC_BN_mod_exp)}
      BN_mod_exp := @FC_BN_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp_removed)}
    if BN_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp)}
      BN_mod_exp := @_BN_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp');
    {$ifend}
  end;


  BN_mod_exp_mont := LoadLibFunction(ADllHandle, BN_mod_exp_mont_procname);
  FuncLoadError := not assigned(BN_mod_exp_mont);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp_mont_allownil)}
    BN_mod_exp_mont := @ERR_BN_mod_exp_mont;
    {$ifend}
    {$if declared(BN_mod_exp_mont_introduced)}
    if LibVersion < BN_mod_exp_mont_introduced then
    begin
      {$if declared(FC_BN_mod_exp_mont)}
      BN_mod_exp_mont := @FC_BN_mod_exp_mont;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp_mont_removed)}
    if BN_mod_exp_mont_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp_mont)}
      BN_mod_exp_mont := @_BN_mod_exp_mont;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp_mont_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp_mont');
    {$ifend}
  end;


  BN_mod_exp_mont_consttime := LoadLibFunction(ADllHandle, BN_mod_exp_mont_consttime_procname);
  FuncLoadError := not assigned(BN_mod_exp_mont_consttime);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp_mont_consttime_allownil)}
    BN_mod_exp_mont_consttime := @ERR_BN_mod_exp_mont_consttime;
    {$ifend}
    {$if declared(BN_mod_exp_mont_consttime_introduced)}
    if LibVersion < BN_mod_exp_mont_consttime_introduced then
    begin
      {$if declared(FC_BN_mod_exp_mont_consttime)}
      BN_mod_exp_mont_consttime := @FC_BN_mod_exp_mont_consttime;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp_mont_consttime_removed)}
    if BN_mod_exp_mont_consttime_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp_mont_consttime)}
      BN_mod_exp_mont_consttime := @_BN_mod_exp_mont_consttime;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp_mont_consttime_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp_mont_consttime');
    {$ifend}
  end;


  BN_mod_exp_mont_word := LoadLibFunction(ADllHandle, BN_mod_exp_mont_word_procname);
  FuncLoadError := not assigned(BN_mod_exp_mont_word);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp_mont_word_allownil)}
    BN_mod_exp_mont_word := @ERR_BN_mod_exp_mont_word;
    {$ifend}
    {$if declared(BN_mod_exp_mont_word_introduced)}
    if LibVersion < BN_mod_exp_mont_word_introduced then
    begin
      {$if declared(FC_BN_mod_exp_mont_word)}
      BN_mod_exp_mont_word := @FC_BN_mod_exp_mont_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp_mont_word_removed)}
    if BN_mod_exp_mont_word_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp_mont_word)}
      BN_mod_exp_mont_word := @_BN_mod_exp_mont_word;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp_mont_word_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp_mont_word');
    {$ifend}
  end;


  BN_mod_exp2_mont := LoadLibFunction(ADllHandle, BN_mod_exp2_mont_procname);
  FuncLoadError := not assigned(BN_mod_exp2_mont);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp2_mont_allownil)}
    BN_mod_exp2_mont := @ERR_BN_mod_exp2_mont;
    {$ifend}
    {$if declared(BN_mod_exp2_mont_introduced)}
    if LibVersion < BN_mod_exp2_mont_introduced then
    begin
      {$if declared(FC_BN_mod_exp2_mont)}
      BN_mod_exp2_mont := @FC_BN_mod_exp2_mont;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp2_mont_removed)}
    if BN_mod_exp2_mont_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp2_mont)}
      BN_mod_exp2_mont := @_BN_mod_exp2_mont;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp2_mont_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp2_mont');
    {$ifend}
  end;


  BN_mod_exp_simple := LoadLibFunction(ADllHandle, BN_mod_exp_simple_procname);
  FuncLoadError := not assigned(BN_mod_exp_simple);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp_simple_allownil)}
    BN_mod_exp_simple := @ERR_BN_mod_exp_simple;
    {$ifend}
    {$if declared(BN_mod_exp_simple_introduced)}
    if LibVersion < BN_mod_exp_simple_introduced then
    begin
      {$if declared(FC_BN_mod_exp_simple)}
      BN_mod_exp_simple := @FC_BN_mod_exp_simple;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp_simple_removed)}
    if BN_mod_exp_simple_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp_simple)}
      BN_mod_exp_simple := @_BN_mod_exp_simple;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp_simple_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp_simple');
    {$ifend}
  end;


  BN_mask_bits := LoadLibFunction(ADllHandle, BN_mask_bits_procname);
  FuncLoadError := not assigned(BN_mask_bits);
  if FuncLoadError then
  begin
    {$if not defined(BN_mask_bits_allownil)}
    BN_mask_bits := @ERR_BN_mask_bits;
    {$ifend}
    {$if declared(BN_mask_bits_introduced)}
    if LibVersion < BN_mask_bits_introduced then
    begin
      {$if declared(FC_BN_mask_bits)}
      BN_mask_bits := @FC_BN_mask_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mask_bits_removed)}
    if BN_mask_bits_removed <= LibVersion then
    begin
      {$if declared(_BN_mask_bits)}
      BN_mask_bits := @_BN_mask_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mask_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mask_bits');
    {$ifend}
  end;


  BN_print := LoadLibFunction(ADllHandle, BN_print_procname);
  FuncLoadError := not assigned(BN_print);
  if FuncLoadError then
  begin
    {$if not defined(BN_print_allownil)}
    BN_print := @ERR_BN_print;
    {$ifend}
    {$if declared(BN_print_introduced)}
    if LibVersion < BN_print_introduced then
    begin
      {$if declared(FC_BN_print)}
      BN_print := @FC_BN_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_print_removed)}
    if BN_print_removed <= LibVersion then
    begin
      {$if declared(_BN_print)}
      BN_print := @_BN_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_print_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_print');
    {$ifend}
  end;


  BN_reciprocal := LoadLibFunction(ADllHandle, BN_reciprocal_procname);
  FuncLoadError := not assigned(BN_reciprocal);
  if FuncLoadError then
  begin
    {$if not defined(BN_reciprocal_allownil)}
    BN_reciprocal := @ERR_BN_reciprocal;
    {$ifend}
    {$if declared(BN_reciprocal_introduced)}
    if LibVersion < BN_reciprocal_introduced then
    begin
      {$if declared(FC_BN_reciprocal)}
      BN_reciprocal := @FC_BN_reciprocal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_reciprocal_removed)}
    if BN_reciprocal_removed <= LibVersion then
    begin
      {$if declared(_BN_reciprocal)}
      BN_reciprocal := @_BN_reciprocal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_reciprocal_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_reciprocal');
    {$ifend}
  end;


  BN_rshift := LoadLibFunction(ADllHandle, BN_rshift_procname);
  FuncLoadError := not assigned(BN_rshift);
  if FuncLoadError then
  begin
    {$if not defined(BN_rshift_allownil)}
    BN_rshift := @ERR_BN_rshift;
    {$ifend}
    {$if declared(BN_rshift_introduced)}
    if LibVersion < BN_rshift_introduced then
    begin
      {$if declared(FC_BN_rshift)}
      BN_rshift := @FC_BN_rshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_rshift_removed)}
    if BN_rshift_removed <= LibVersion then
    begin
      {$if declared(_BN_rshift)}
      BN_rshift := @_BN_rshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_rshift_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_rshift');
    {$ifend}
  end;


  BN_rshift1 := LoadLibFunction(ADllHandle, BN_rshift1_procname);
  FuncLoadError := not assigned(BN_rshift1);
  if FuncLoadError then
  begin
    {$if not defined(BN_rshift1_allownil)}
    BN_rshift1 := @ERR_BN_rshift1;
    {$ifend}
    {$if declared(BN_rshift1_introduced)}
    if LibVersion < BN_rshift1_introduced then
    begin
      {$if declared(FC_BN_rshift1)}
      BN_rshift1 := @FC_BN_rshift1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_rshift1_removed)}
    if BN_rshift1_removed <= LibVersion then
    begin
      {$if declared(_BN_rshift1)}
      BN_rshift1 := @_BN_rshift1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_rshift1_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_rshift1');
    {$ifend}
  end;


  BN_clear := LoadLibFunction(ADllHandle, BN_clear_procname);
  FuncLoadError := not assigned(BN_clear);
  if FuncLoadError then
  begin
    {$if not defined(BN_clear_allownil)}
    BN_clear := @ERR_BN_clear;
    {$ifend}
    {$if declared(BN_clear_introduced)}
    if LibVersion < BN_clear_introduced then
    begin
      {$if declared(FC_BN_clear)}
      BN_clear := @FC_BN_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_clear_removed)}
    if BN_clear_removed <= LibVersion then
    begin
      {$if declared(_BN_clear)}
      BN_clear := @_BN_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_clear_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_clear');
    {$ifend}
  end;


  BN_dup := LoadLibFunction(ADllHandle, BN_dup_procname);
  FuncLoadError := not assigned(BN_dup);
  if FuncLoadError then
  begin
    {$if not defined(BN_dup_allownil)}
    BN_dup := @ERR_BN_dup;
    {$ifend}
    {$if declared(BN_dup_introduced)}
    if LibVersion < BN_dup_introduced then
    begin
      {$if declared(FC_BN_dup)}
      BN_dup := @FC_BN_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_dup_removed)}
    if BN_dup_removed <= LibVersion then
    begin
      {$if declared(_BN_dup)}
      BN_dup := @_BN_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_dup');
    {$ifend}
  end;


  BN_ucmp := LoadLibFunction(ADllHandle, BN_ucmp_procname);
  FuncLoadError := not assigned(BN_ucmp);
  if FuncLoadError then
  begin
    {$if not defined(BN_ucmp_allownil)}
    BN_ucmp := @ERR_BN_ucmp;
    {$ifend}
    {$if declared(BN_ucmp_introduced)}
    if LibVersion < BN_ucmp_introduced then
    begin
      {$if declared(FC_BN_ucmp)}
      BN_ucmp := @FC_BN_ucmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_ucmp_removed)}
    if BN_ucmp_removed <= LibVersion then
    begin
      {$if declared(_BN_ucmp)}
      BN_ucmp := @_BN_ucmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_ucmp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_ucmp');
    {$ifend}
  end;


  BN_set_bit := LoadLibFunction(ADllHandle, BN_set_bit_procname);
  FuncLoadError := not assigned(BN_set_bit);
  if FuncLoadError then
  begin
    {$if not defined(BN_set_bit_allownil)}
    BN_set_bit := @ERR_BN_set_bit;
    {$ifend}
    {$if declared(BN_set_bit_introduced)}
    if LibVersion < BN_set_bit_introduced then
    begin
      {$if declared(FC_BN_set_bit)}
      BN_set_bit := @FC_BN_set_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_set_bit_removed)}
    if BN_set_bit_removed <= LibVersion then
    begin
      {$if declared(_BN_set_bit)}
      BN_set_bit := @_BN_set_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_set_bit_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_set_bit');
    {$ifend}
  end;


  BN_clear_bit := LoadLibFunction(ADllHandle, BN_clear_bit_procname);
  FuncLoadError := not assigned(BN_clear_bit);
  if FuncLoadError then
  begin
    {$if not defined(BN_clear_bit_allownil)}
    BN_clear_bit := @ERR_BN_clear_bit;
    {$ifend}
    {$if declared(BN_clear_bit_introduced)}
    if LibVersion < BN_clear_bit_introduced then
    begin
      {$if declared(FC_BN_clear_bit)}
      BN_clear_bit := @FC_BN_clear_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_clear_bit_removed)}
    if BN_clear_bit_removed <= LibVersion then
    begin
      {$if declared(_BN_clear_bit)}
      BN_clear_bit := @_BN_clear_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_clear_bit_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_clear_bit');
    {$ifend}
  end;


  BN_bn2hex := LoadLibFunction(ADllHandle, BN_bn2hex_procname);
  FuncLoadError := not assigned(BN_bn2hex);
  if FuncLoadError then
  begin
    {$if not defined(BN_bn2hex_allownil)}
    BN_bn2hex := @ERR_BN_bn2hex;
    {$ifend}
    {$if declared(BN_bn2hex_introduced)}
    if LibVersion < BN_bn2hex_introduced then
    begin
      {$if declared(FC_BN_bn2hex)}
      BN_bn2hex := @FC_BN_bn2hex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bn2hex_removed)}
    if BN_bn2hex_removed <= LibVersion then
    begin
      {$if declared(_BN_bn2hex)}
      BN_bn2hex := @_BN_bn2hex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bn2hex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bn2hex');
    {$ifend}
  end;


  BN_bn2dec := LoadLibFunction(ADllHandle, BN_bn2dec_procname);
  FuncLoadError := not assigned(BN_bn2dec);
  if FuncLoadError then
  begin
    {$if not defined(BN_bn2dec_allownil)}
    BN_bn2dec := @ERR_BN_bn2dec;
    {$ifend}
    {$if declared(BN_bn2dec_introduced)}
    if LibVersion < BN_bn2dec_introduced then
    begin
      {$if declared(FC_BN_bn2dec)}
      BN_bn2dec := @FC_BN_bn2dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bn2dec_removed)}
    if BN_bn2dec_removed <= LibVersion then
    begin
      {$if declared(_BN_bn2dec)}
      BN_bn2dec := @_BN_bn2dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bn2dec_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bn2dec');
    {$ifend}
  end;


  BN_hex2bn := LoadLibFunction(ADllHandle, BN_hex2bn_procname);
  FuncLoadError := not assigned(BN_hex2bn);
  if FuncLoadError then
  begin
    {$if not defined(BN_hex2bn_allownil)}
    BN_hex2bn := @ERR_BN_hex2bn;
    {$ifend}
    {$if declared(BN_hex2bn_introduced)}
    if LibVersion < BN_hex2bn_introduced then
    begin
      {$if declared(FC_BN_hex2bn)}
      BN_hex2bn := @FC_BN_hex2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_hex2bn_removed)}
    if BN_hex2bn_removed <= LibVersion then
    begin
      {$if declared(_BN_hex2bn)}
      BN_hex2bn := @_BN_hex2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_hex2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_hex2bn');
    {$ifend}
  end;


  BN_dec2bn := LoadLibFunction(ADllHandle, BN_dec2bn_procname);
  FuncLoadError := not assigned(BN_dec2bn);
  if FuncLoadError then
  begin
    {$if not defined(BN_dec2bn_allownil)}
    BN_dec2bn := @ERR_BN_dec2bn;
    {$ifend}
    {$if declared(BN_dec2bn_introduced)}
    if LibVersion < BN_dec2bn_introduced then
    begin
      {$if declared(FC_BN_dec2bn)}
      BN_dec2bn := @FC_BN_dec2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_dec2bn_removed)}
    if BN_dec2bn_removed <= LibVersion then
    begin
      {$if declared(_BN_dec2bn)}
      BN_dec2bn := @_BN_dec2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_dec2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_dec2bn');
    {$ifend}
  end;


  BN_asc2bn := LoadLibFunction(ADllHandle, BN_asc2bn_procname);
  FuncLoadError := not assigned(BN_asc2bn);
  if FuncLoadError then
  begin
    {$if not defined(BN_asc2bn_allownil)}
    BN_asc2bn := @ERR_BN_asc2bn;
    {$ifend}
    {$if declared(BN_asc2bn_introduced)}
    if LibVersion < BN_asc2bn_introduced then
    begin
      {$if declared(FC_BN_asc2bn)}
      BN_asc2bn := @FC_BN_asc2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_asc2bn_removed)}
    if BN_asc2bn_removed <= LibVersion then
    begin
      {$if declared(_BN_asc2bn)}
      BN_asc2bn := @_BN_asc2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_asc2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_asc2bn');
    {$ifend}
  end;


  BN_gcd := LoadLibFunction(ADllHandle, BN_gcd_procname);
  FuncLoadError := not assigned(BN_gcd);
  if FuncLoadError then
  begin
    {$if not defined(BN_gcd_allownil)}
    BN_gcd := @ERR_BN_gcd;
    {$ifend}
    {$if declared(BN_gcd_introduced)}
    if LibVersion < BN_gcd_introduced then
    begin
      {$if declared(FC_BN_gcd)}
      BN_gcd := @FC_BN_gcd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_gcd_removed)}
    if BN_gcd_removed <= LibVersion then
    begin
      {$if declared(_BN_gcd)}
      BN_gcd := @_BN_gcd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_gcd_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_gcd');
    {$ifend}
  end;


  BN_kronecker := LoadLibFunction(ADllHandle, BN_kronecker_procname);
  FuncLoadError := not assigned(BN_kronecker);
  if FuncLoadError then
  begin
    {$if not defined(BN_kronecker_allownil)}
    BN_kronecker := @ERR_BN_kronecker;
    {$ifend}
    {$if declared(BN_kronecker_introduced)}
    if LibVersion < BN_kronecker_introduced then
    begin
      {$if declared(FC_BN_kronecker)}
      BN_kronecker := @FC_BN_kronecker;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_kronecker_removed)}
    if BN_kronecker_removed <= LibVersion then
    begin
      {$if declared(_BN_kronecker)}
      BN_kronecker := @_BN_kronecker;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_kronecker_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_kronecker');
    {$ifend}
  end;


  BN_mod_inverse := LoadLibFunction(ADllHandle, BN_mod_inverse_procname);
  FuncLoadError := not assigned(BN_mod_inverse);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_inverse_allownil)}
    BN_mod_inverse := @ERR_BN_mod_inverse;
    {$ifend}
    {$if declared(BN_mod_inverse_introduced)}
    if LibVersion < BN_mod_inverse_introduced then
    begin
      {$if declared(FC_BN_mod_inverse)}
      BN_mod_inverse := @FC_BN_mod_inverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_inverse_removed)}
    if BN_mod_inverse_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_inverse)}
      BN_mod_inverse := @_BN_mod_inverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_inverse_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_inverse');
    {$ifend}
  end;


  BN_mod_sqrt := LoadLibFunction(ADllHandle, BN_mod_sqrt_procname);
  FuncLoadError := not assigned(BN_mod_sqrt);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_sqrt_allownil)}
    BN_mod_sqrt := @ERR_BN_mod_sqrt;
    {$ifend}
    {$if declared(BN_mod_sqrt_introduced)}
    if LibVersion < BN_mod_sqrt_introduced then
    begin
      {$if declared(FC_BN_mod_sqrt)}
      BN_mod_sqrt := @FC_BN_mod_sqrt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_sqrt_removed)}
    if BN_mod_sqrt_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_sqrt)}
      BN_mod_sqrt := @_BN_mod_sqrt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_sqrt_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_sqrt');
    {$ifend}
  end;


  BN_consttime_swap := LoadLibFunction(ADllHandle, BN_consttime_swap_procname);
  FuncLoadError := not assigned(BN_consttime_swap);
  if FuncLoadError then
  begin
    {$if not defined(BN_consttime_swap_allownil)}
    BN_consttime_swap := @ERR_BN_consttime_swap;
    {$ifend}
    {$if declared(BN_consttime_swap_introduced)}
    if LibVersion < BN_consttime_swap_introduced then
    begin
      {$if declared(FC_BN_consttime_swap)}
      BN_consttime_swap := @FC_BN_consttime_swap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_consttime_swap_removed)}
    if BN_consttime_swap_removed <= LibVersion then
    begin
      {$if declared(_BN_consttime_swap)}
      BN_consttime_swap := @_BN_consttime_swap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_consttime_swap_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_consttime_swap');
    {$ifend}
  end;


  BN_generate_prime_ex := LoadLibFunction(ADllHandle, BN_generate_prime_ex_procname);
  FuncLoadError := not assigned(BN_generate_prime_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_generate_prime_ex_allownil)}
    BN_generate_prime_ex := @ERR_BN_generate_prime_ex;
    {$ifend}
    {$if declared(BN_generate_prime_ex_introduced)}
    if LibVersion < BN_generate_prime_ex_introduced then
    begin
      {$if declared(FC_BN_generate_prime_ex)}
      BN_generate_prime_ex := @FC_BN_generate_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_generate_prime_ex_removed)}
    if BN_generate_prime_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_generate_prime_ex)}
      BN_generate_prime_ex := @_BN_generate_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_generate_prime_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_generate_prime_ex');
    {$ifend}
  end;


  BN_is_prime_ex := LoadLibFunction(ADllHandle, BN_is_prime_ex_procname);
  FuncLoadError := not assigned(BN_is_prime_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_prime_ex_allownil)}
    BN_is_prime_ex := @ERR_BN_is_prime_ex;
    {$ifend}
    {$if declared(BN_is_prime_ex_introduced)}
    if LibVersion < BN_is_prime_ex_introduced then
    begin
      {$if declared(FC_BN_is_prime_ex)}
      BN_is_prime_ex := @FC_BN_is_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_prime_ex_removed)}
    if BN_is_prime_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_is_prime_ex)}
      BN_is_prime_ex := @_BN_is_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_prime_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_prime_ex');
    {$ifend}
  end;


  BN_is_prime_fasttest_ex := LoadLibFunction(ADllHandle, BN_is_prime_fasttest_ex_procname);
  FuncLoadError := not assigned(BN_is_prime_fasttest_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_is_prime_fasttest_ex_allownil)}
    BN_is_prime_fasttest_ex := @ERR_BN_is_prime_fasttest_ex;
    {$ifend}
    {$if declared(BN_is_prime_fasttest_ex_introduced)}
    if LibVersion < BN_is_prime_fasttest_ex_introduced then
    begin
      {$if declared(FC_BN_is_prime_fasttest_ex)}
      BN_is_prime_fasttest_ex := @FC_BN_is_prime_fasttest_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_is_prime_fasttest_ex_removed)}
    if BN_is_prime_fasttest_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_is_prime_fasttest_ex)}
      BN_is_prime_fasttest_ex := @_BN_is_prime_fasttest_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_is_prime_fasttest_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_is_prime_fasttest_ex');
    {$ifend}
  end;


  BN_X931_generate_Xpq := LoadLibFunction(ADllHandle, BN_X931_generate_Xpq_procname);
  FuncLoadError := not assigned(BN_X931_generate_Xpq);
  if FuncLoadError then
  begin
    {$if not defined(BN_X931_generate_Xpq_allownil)}
    BN_X931_generate_Xpq := @ERR_BN_X931_generate_Xpq;
    {$ifend}
    {$if declared(BN_X931_generate_Xpq_introduced)}
    if LibVersion < BN_X931_generate_Xpq_introduced then
    begin
      {$if declared(FC_BN_X931_generate_Xpq)}
      BN_X931_generate_Xpq := @FC_BN_X931_generate_Xpq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_X931_generate_Xpq_removed)}
    if BN_X931_generate_Xpq_removed <= LibVersion then
    begin
      {$if declared(_BN_X931_generate_Xpq)}
      BN_X931_generate_Xpq := @_BN_X931_generate_Xpq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_X931_generate_Xpq_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_X931_generate_Xpq');
    {$ifend}
  end;


  BN_X931_derive_prime_ex := LoadLibFunction(ADllHandle, BN_X931_derive_prime_ex_procname);
  FuncLoadError := not assigned(BN_X931_derive_prime_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_X931_derive_prime_ex_allownil)}
    BN_X931_derive_prime_ex := @ERR_BN_X931_derive_prime_ex;
    {$ifend}
    {$if declared(BN_X931_derive_prime_ex_introduced)}
    if LibVersion < BN_X931_derive_prime_ex_introduced then
    begin
      {$if declared(FC_BN_X931_derive_prime_ex)}
      BN_X931_derive_prime_ex := @FC_BN_X931_derive_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_X931_derive_prime_ex_removed)}
    if BN_X931_derive_prime_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_X931_derive_prime_ex)}
      BN_X931_derive_prime_ex := @_BN_X931_derive_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_X931_derive_prime_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_X931_derive_prime_ex');
    {$ifend}
  end;


  BN_X931_generate_prime_ex := LoadLibFunction(ADllHandle, BN_X931_generate_prime_ex_procname);
  FuncLoadError := not assigned(BN_X931_generate_prime_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_X931_generate_prime_ex_allownil)}
    BN_X931_generate_prime_ex := @ERR_BN_X931_generate_prime_ex;
    {$ifend}
    {$if declared(BN_X931_generate_prime_ex_introduced)}
    if LibVersion < BN_X931_generate_prime_ex_introduced then
    begin
      {$if declared(FC_BN_X931_generate_prime_ex)}
      BN_X931_generate_prime_ex := @FC_BN_X931_generate_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_X931_generate_prime_ex_removed)}
    if BN_X931_generate_prime_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_X931_generate_prime_ex)}
      BN_X931_generate_prime_ex := @_BN_X931_generate_prime_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_X931_generate_prime_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_X931_generate_prime_ex');
    {$ifend}
  end;


  BN_MONT_CTX_new := LoadLibFunction(ADllHandle, BN_MONT_CTX_new_procname);
  FuncLoadError := not assigned(BN_MONT_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_MONT_CTX_new_allownil)}
    BN_MONT_CTX_new := @ERR_BN_MONT_CTX_new;
    {$ifend}
    {$if declared(BN_MONT_CTX_new_introduced)}
    if LibVersion < BN_MONT_CTX_new_introduced then
    begin
      {$if declared(FC_BN_MONT_CTX_new)}
      BN_MONT_CTX_new := @FC_BN_MONT_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_MONT_CTX_new_removed)}
    if BN_MONT_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_BN_MONT_CTX_new)}
      BN_MONT_CTX_new := @_BN_MONT_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_MONT_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_MONT_CTX_new');
    {$ifend}
  end;


  BN_mod_mul_montgomery := LoadLibFunction(ADllHandle, BN_mod_mul_montgomery_procname);
  FuncLoadError := not assigned(BN_mod_mul_montgomery);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_mul_montgomery_allownil)}
    BN_mod_mul_montgomery := @ERR_BN_mod_mul_montgomery;
    {$ifend}
    {$if declared(BN_mod_mul_montgomery_introduced)}
    if LibVersion < BN_mod_mul_montgomery_introduced then
    begin
      {$if declared(FC_BN_mod_mul_montgomery)}
      BN_mod_mul_montgomery := @FC_BN_mod_mul_montgomery;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_mul_montgomery_removed)}
    if BN_mod_mul_montgomery_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_mul_montgomery)}
      BN_mod_mul_montgomery := @_BN_mod_mul_montgomery;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_mul_montgomery_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_mul_montgomery');
    {$ifend}
  end;


  BN_to_montgomery := LoadLibFunction(ADllHandle, BN_to_montgomery_procname);
  FuncLoadError := not assigned(BN_to_montgomery);
  if FuncLoadError then
  begin
    {$if not defined(BN_to_montgomery_allownil)}
    BN_to_montgomery := @ERR_BN_to_montgomery;
    {$ifend}
    {$if declared(BN_to_montgomery_introduced)}
    if LibVersion < BN_to_montgomery_introduced then
    begin
      {$if declared(FC_BN_to_montgomery)}
      BN_to_montgomery := @FC_BN_to_montgomery;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_to_montgomery_removed)}
    if BN_to_montgomery_removed <= LibVersion then
    begin
      {$if declared(_BN_to_montgomery)}
      BN_to_montgomery := @_BN_to_montgomery;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_to_montgomery_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_to_montgomery');
    {$ifend}
  end;


  BN_from_montgomery := LoadLibFunction(ADllHandle, BN_from_montgomery_procname);
  FuncLoadError := not assigned(BN_from_montgomery);
  if FuncLoadError then
  begin
    {$if not defined(BN_from_montgomery_allownil)}
    BN_from_montgomery := @ERR_BN_from_montgomery;
    {$ifend}
    {$if declared(BN_from_montgomery_introduced)}
    if LibVersion < BN_from_montgomery_introduced then
    begin
      {$if declared(FC_BN_from_montgomery)}
      BN_from_montgomery := @FC_BN_from_montgomery;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_from_montgomery_removed)}
    if BN_from_montgomery_removed <= LibVersion then
    begin
      {$if declared(_BN_from_montgomery)}
      BN_from_montgomery := @_BN_from_montgomery;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_from_montgomery_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_from_montgomery');
    {$ifend}
  end;


  BN_MONT_CTX_free := LoadLibFunction(ADllHandle, BN_MONT_CTX_free_procname);
  FuncLoadError := not assigned(BN_MONT_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_MONT_CTX_free_allownil)}
    BN_MONT_CTX_free := @ERR_BN_MONT_CTX_free;
    {$ifend}
    {$if declared(BN_MONT_CTX_free_introduced)}
    if LibVersion < BN_MONT_CTX_free_introduced then
    begin
      {$if declared(FC_BN_MONT_CTX_free)}
      BN_MONT_CTX_free := @FC_BN_MONT_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_MONT_CTX_free_removed)}
    if BN_MONT_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_BN_MONT_CTX_free)}
      BN_MONT_CTX_free := @_BN_MONT_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_MONT_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_MONT_CTX_free');
    {$ifend}
  end;


  BN_MONT_CTX_set := LoadLibFunction(ADllHandle, BN_MONT_CTX_set_procname);
  FuncLoadError := not assigned(BN_MONT_CTX_set);
  if FuncLoadError then
  begin
    {$if not defined(BN_MONT_CTX_set_allownil)}
    BN_MONT_CTX_set := @ERR_BN_MONT_CTX_set;
    {$ifend}
    {$if declared(BN_MONT_CTX_set_introduced)}
    if LibVersion < BN_MONT_CTX_set_introduced then
    begin
      {$if declared(FC_BN_MONT_CTX_set)}
      BN_MONT_CTX_set := @FC_BN_MONT_CTX_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_MONT_CTX_set_removed)}
    if BN_MONT_CTX_set_removed <= LibVersion then
    begin
      {$if declared(_BN_MONT_CTX_set)}
      BN_MONT_CTX_set := @_BN_MONT_CTX_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_MONT_CTX_set_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_MONT_CTX_set');
    {$ifend}
  end;


  BN_MONT_CTX_copy := LoadLibFunction(ADllHandle, BN_MONT_CTX_copy_procname);
  FuncLoadError := not assigned(BN_MONT_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(BN_MONT_CTX_copy_allownil)}
    BN_MONT_CTX_copy := @ERR_BN_MONT_CTX_copy;
    {$ifend}
    {$if declared(BN_MONT_CTX_copy_introduced)}
    if LibVersion < BN_MONT_CTX_copy_introduced then
    begin
      {$if declared(FC_BN_MONT_CTX_copy)}
      BN_MONT_CTX_copy := @FC_BN_MONT_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_MONT_CTX_copy_removed)}
    if BN_MONT_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_BN_MONT_CTX_copy)}
      BN_MONT_CTX_copy := @_BN_MONT_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_MONT_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_MONT_CTX_copy');
    {$ifend}
  end;


  BN_BLINDING_new := LoadLibFunction(ADllHandle, BN_BLINDING_new_procname);
  FuncLoadError := not assigned(BN_BLINDING_new);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_new_allownil)}
    BN_BLINDING_new := @ERR_BN_BLINDING_new;
    {$ifend}
    {$if declared(BN_BLINDING_new_introduced)}
    if LibVersion < BN_BLINDING_new_introduced then
    begin
      {$if declared(FC_BN_BLINDING_new)}
      BN_BLINDING_new := @FC_BN_BLINDING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_new_removed)}
    if BN_BLINDING_new_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_new)}
      BN_BLINDING_new := @_BN_BLINDING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_new');
    {$ifend}
  end;


  BN_BLINDING_free := LoadLibFunction(ADllHandle, BN_BLINDING_free_procname);
  FuncLoadError := not assigned(BN_BLINDING_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_free_allownil)}
    BN_BLINDING_free := @ERR_BN_BLINDING_free;
    {$ifend}
    {$if declared(BN_BLINDING_free_introduced)}
    if LibVersion < BN_BLINDING_free_introduced then
    begin
      {$if declared(FC_BN_BLINDING_free)}
      BN_BLINDING_free := @FC_BN_BLINDING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_free_removed)}
    if BN_BLINDING_free_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_free)}
      BN_BLINDING_free := @_BN_BLINDING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_free');
    {$ifend}
  end;


  BN_BLINDING_update := LoadLibFunction(ADllHandle, BN_BLINDING_update_procname);
  FuncLoadError := not assigned(BN_BLINDING_update);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_update_allownil)}
    BN_BLINDING_update := @ERR_BN_BLINDING_update;
    {$ifend}
    {$if declared(BN_BLINDING_update_introduced)}
    if LibVersion < BN_BLINDING_update_introduced then
    begin
      {$if declared(FC_BN_BLINDING_update)}
      BN_BLINDING_update := @FC_BN_BLINDING_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_update_removed)}
    if BN_BLINDING_update_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_update)}
      BN_BLINDING_update := @_BN_BLINDING_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_update_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_update');
    {$ifend}
  end;


  BN_BLINDING_convert := LoadLibFunction(ADllHandle, BN_BLINDING_convert_procname);
  FuncLoadError := not assigned(BN_BLINDING_convert);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_convert_allownil)}
    BN_BLINDING_convert := @ERR_BN_BLINDING_convert;
    {$ifend}
    {$if declared(BN_BLINDING_convert_introduced)}
    if LibVersion < BN_BLINDING_convert_introduced then
    begin
      {$if declared(FC_BN_BLINDING_convert)}
      BN_BLINDING_convert := @FC_BN_BLINDING_convert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_convert_removed)}
    if BN_BLINDING_convert_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_convert)}
      BN_BLINDING_convert := @_BN_BLINDING_convert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_convert_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_convert');
    {$ifend}
  end;


  BN_BLINDING_invert := LoadLibFunction(ADllHandle, BN_BLINDING_invert_procname);
  FuncLoadError := not assigned(BN_BLINDING_invert);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_invert_allownil)}
    BN_BLINDING_invert := @ERR_BN_BLINDING_invert;
    {$ifend}
    {$if declared(BN_BLINDING_invert_introduced)}
    if LibVersion < BN_BLINDING_invert_introduced then
    begin
      {$if declared(FC_BN_BLINDING_invert)}
      BN_BLINDING_invert := @FC_BN_BLINDING_invert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_invert_removed)}
    if BN_BLINDING_invert_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_invert)}
      BN_BLINDING_invert := @_BN_BLINDING_invert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_invert_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_invert');
    {$ifend}
  end;


  BN_BLINDING_convert_ex := LoadLibFunction(ADllHandle, BN_BLINDING_convert_ex_procname);
  FuncLoadError := not assigned(BN_BLINDING_convert_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_convert_ex_allownil)}
    BN_BLINDING_convert_ex := @ERR_BN_BLINDING_convert_ex;
    {$ifend}
    {$if declared(BN_BLINDING_convert_ex_introduced)}
    if LibVersion < BN_BLINDING_convert_ex_introduced then
    begin
      {$if declared(FC_BN_BLINDING_convert_ex)}
      BN_BLINDING_convert_ex := @FC_BN_BLINDING_convert_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_convert_ex_removed)}
    if BN_BLINDING_convert_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_convert_ex)}
      BN_BLINDING_convert_ex := @_BN_BLINDING_convert_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_convert_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_convert_ex');
    {$ifend}
  end;


  BN_BLINDING_invert_ex := LoadLibFunction(ADllHandle, BN_BLINDING_invert_ex_procname);
  FuncLoadError := not assigned(BN_BLINDING_invert_ex);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_invert_ex_allownil)}
    BN_BLINDING_invert_ex := @ERR_BN_BLINDING_invert_ex;
    {$ifend}
    {$if declared(BN_BLINDING_invert_ex_introduced)}
    if LibVersion < BN_BLINDING_invert_ex_introduced then
    begin
      {$if declared(FC_BN_BLINDING_invert_ex)}
      BN_BLINDING_invert_ex := @FC_BN_BLINDING_invert_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_invert_ex_removed)}
    if BN_BLINDING_invert_ex_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_invert_ex)}
      BN_BLINDING_invert_ex := @_BN_BLINDING_invert_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_invert_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_invert_ex');
    {$ifend}
  end;


  BN_BLINDING_is_current_thread := LoadLibFunction(ADllHandle, BN_BLINDING_is_current_thread_procname);
  FuncLoadError := not assigned(BN_BLINDING_is_current_thread);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_is_current_thread_allownil)}
    BN_BLINDING_is_current_thread := @ERR_BN_BLINDING_is_current_thread;
    {$ifend}
    {$if declared(BN_BLINDING_is_current_thread_introduced)}
    if LibVersion < BN_BLINDING_is_current_thread_introduced then
    begin
      {$if declared(FC_BN_BLINDING_is_current_thread)}
      BN_BLINDING_is_current_thread := @FC_BN_BLINDING_is_current_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_is_current_thread_removed)}
    if BN_BLINDING_is_current_thread_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_is_current_thread)}
      BN_BLINDING_is_current_thread := @_BN_BLINDING_is_current_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_is_current_thread_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_is_current_thread');
    {$ifend}
  end;


  BN_BLINDING_set_current_thread := LoadLibFunction(ADllHandle, BN_BLINDING_set_current_thread_procname);
  FuncLoadError := not assigned(BN_BLINDING_set_current_thread);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_set_current_thread_allownil)}
    BN_BLINDING_set_current_thread := @ERR_BN_BLINDING_set_current_thread;
    {$ifend}
    {$if declared(BN_BLINDING_set_current_thread_introduced)}
    if LibVersion < BN_BLINDING_set_current_thread_introduced then
    begin
      {$if declared(FC_BN_BLINDING_set_current_thread)}
      BN_BLINDING_set_current_thread := @FC_BN_BLINDING_set_current_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_set_current_thread_removed)}
    if BN_BLINDING_set_current_thread_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_set_current_thread)}
      BN_BLINDING_set_current_thread := @_BN_BLINDING_set_current_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_set_current_thread_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_set_current_thread');
    {$ifend}
  end;


  BN_BLINDING_lock := LoadLibFunction(ADllHandle, BN_BLINDING_lock_procname);
  FuncLoadError := not assigned(BN_BLINDING_lock);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_lock_allownil)}
    BN_BLINDING_lock := @ERR_BN_BLINDING_lock;
    {$ifend}
    {$if declared(BN_BLINDING_lock_introduced)}
    if LibVersion < BN_BLINDING_lock_introduced then
    begin
      {$if declared(FC_BN_BLINDING_lock)}
      BN_BLINDING_lock := @FC_BN_BLINDING_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_lock_removed)}
    if BN_BLINDING_lock_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_lock)}
      BN_BLINDING_lock := @_BN_BLINDING_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_lock_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_lock');
    {$ifend}
  end;


  BN_BLINDING_unlock := LoadLibFunction(ADllHandle, BN_BLINDING_unlock_procname);
  FuncLoadError := not assigned(BN_BLINDING_unlock);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_unlock_allownil)}
    BN_BLINDING_unlock := @ERR_BN_BLINDING_unlock;
    {$ifend}
    {$if declared(BN_BLINDING_unlock_introduced)}
    if LibVersion < BN_BLINDING_unlock_introduced then
    begin
      {$if declared(FC_BN_BLINDING_unlock)}
      BN_BLINDING_unlock := @FC_BN_BLINDING_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_unlock_removed)}
    if BN_BLINDING_unlock_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_unlock)}
      BN_BLINDING_unlock := @_BN_BLINDING_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_unlock_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_unlock');
    {$ifend}
  end;


  BN_BLINDING_get_flags := LoadLibFunction(ADllHandle, BN_BLINDING_get_flags_procname);
  FuncLoadError := not assigned(BN_BLINDING_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_get_flags_allownil)}
    BN_BLINDING_get_flags := @ERR_BN_BLINDING_get_flags;
    {$ifend}
    {$if declared(BN_BLINDING_get_flags_introduced)}
    if LibVersion < BN_BLINDING_get_flags_introduced then
    begin
      {$if declared(FC_BN_BLINDING_get_flags)}
      BN_BLINDING_get_flags := @FC_BN_BLINDING_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_get_flags_removed)}
    if BN_BLINDING_get_flags_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_get_flags)}
      BN_BLINDING_get_flags := @_BN_BLINDING_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_get_flags');
    {$ifend}
  end;


  BN_BLINDING_set_flags := LoadLibFunction(ADllHandle, BN_BLINDING_set_flags_procname);
  FuncLoadError := not assigned(BN_BLINDING_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(BN_BLINDING_set_flags_allownil)}
    BN_BLINDING_set_flags := @ERR_BN_BLINDING_set_flags;
    {$ifend}
    {$if declared(BN_BLINDING_set_flags_introduced)}
    if LibVersion < BN_BLINDING_set_flags_introduced then
    begin
      {$if declared(FC_BN_BLINDING_set_flags)}
      BN_BLINDING_set_flags := @FC_BN_BLINDING_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_BLINDING_set_flags_removed)}
    if BN_BLINDING_set_flags_removed <= LibVersion then
    begin
      {$if declared(_BN_BLINDING_set_flags)}
      BN_BLINDING_set_flags := @_BN_BLINDING_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_BLINDING_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_BLINDING_set_flags');
    {$ifend}
  end;


  BN_RECP_CTX_free := LoadLibFunction(ADllHandle, BN_RECP_CTX_free_procname);
  FuncLoadError := not assigned(BN_RECP_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(BN_RECP_CTX_free_allownil)}
    BN_RECP_CTX_free := @ERR_BN_RECP_CTX_free;
    {$ifend}
    {$if declared(BN_RECP_CTX_free_introduced)}
    if LibVersion < BN_RECP_CTX_free_introduced then
    begin
      {$if declared(FC_BN_RECP_CTX_free)}
      BN_RECP_CTX_free := @FC_BN_RECP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_RECP_CTX_free_removed)}
    if BN_RECP_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_BN_RECP_CTX_free)}
      BN_RECP_CTX_free := @_BN_RECP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_RECP_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_RECP_CTX_free');
    {$ifend}
  end;


  BN_RECP_CTX_set := LoadLibFunction(ADllHandle, BN_RECP_CTX_set_procname);
  FuncLoadError := not assigned(BN_RECP_CTX_set);
  if FuncLoadError then
  begin
    {$if not defined(BN_RECP_CTX_set_allownil)}
    BN_RECP_CTX_set := @ERR_BN_RECP_CTX_set;
    {$ifend}
    {$if declared(BN_RECP_CTX_set_introduced)}
    if LibVersion < BN_RECP_CTX_set_introduced then
    begin
      {$if declared(FC_BN_RECP_CTX_set)}
      BN_RECP_CTX_set := @FC_BN_RECP_CTX_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_RECP_CTX_set_removed)}
    if BN_RECP_CTX_set_removed <= LibVersion then
    begin
      {$if declared(_BN_RECP_CTX_set)}
      BN_RECP_CTX_set := @_BN_RECP_CTX_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_RECP_CTX_set_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_RECP_CTX_set');
    {$ifend}
  end;


  BN_mod_mul_reciprocal := LoadLibFunction(ADllHandle, BN_mod_mul_reciprocal_procname);
  FuncLoadError := not assigned(BN_mod_mul_reciprocal);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_mul_reciprocal_allownil)}
    BN_mod_mul_reciprocal := @ERR_BN_mod_mul_reciprocal;
    {$ifend}
    {$if declared(BN_mod_mul_reciprocal_introduced)}
    if LibVersion < BN_mod_mul_reciprocal_introduced then
    begin
      {$if declared(FC_BN_mod_mul_reciprocal)}
      BN_mod_mul_reciprocal := @FC_BN_mod_mul_reciprocal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_mul_reciprocal_removed)}
    if BN_mod_mul_reciprocal_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_mul_reciprocal)}
      BN_mod_mul_reciprocal := @_BN_mod_mul_reciprocal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_mul_reciprocal_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_mul_reciprocal');
    {$ifend}
  end;


  BN_mod_exp_recp := LoadLibFunction(ADllHandle, BN_mod_exp_recp_procname);
  FuncLoadError := not assigned(BN_mod_exp_recp);
  if FuncLoadError then
  begin
    {$if not defined(BN_mod_exp_recp_allownil)}
    BN_mod_exp_recp := @ERR_BN_mod_exp_recp;
    {$ifend}
    {$if declared(BN_mod_exp_recp_introduced)}
    if LibVersion < BN_mod_exp_recp_introduced then
    begin
      {$if declared(FC_BN_mod_exp_recp)}
      BN_mod_exp_recp := @FC_BN_mod_exp_recp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_mod_exp_recp_removed)}
    if BN_mod_exp_recp_removed <= LibVersion then
    begin
      {$if declared(_BN_mod_exp_recp)}
      BN_mod_exp_recp := @_BN_mod_exp_recp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_mod_exp_recp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_mod_exp_recp');
    {$ifend}
  end;


  BN_div_recp := LoadLibFunction(ADllHandle, BN_div_recp_procname);
  FuncLoadError := not assigned(BN_div_recp);
  if FuncLoadError then
  begin
    {$if not defined(BN_div_recp_allownil)}
    BN_div_recp := @ERR_BN_div_recp;
    {$ifend}
    {$if declared(BN_div_recp_introduced)}
    if LibVersion < BN_div_recp_introduced then
    begin
      {$if declared(FC_BN_div_recp)}
      BN_div_recp := @FC_BN_div_recp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_div_recp_removed)}
    if BN_div_recp_removed <= LibVersion then
    begin
      {$if declared(_BN_div_recp)}
      BN_div_recp := @_BN_div_recp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_div_recp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_div_recp');
    {$ifend}
  end;


  BN_GF2m_add := LoadLibFunction(ADllHandle, BN_GF2m_add_procname);
  FuncLoadError := not assigned(BN_GF2m_add);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_add_allownil)}
    BN_GF2m_add := @ERR_BN_GF2m_add;
    {$ifend}
    {$if declared(BN_GF2m_add_introduced)}
    if LibVersion < BN_GF2m_add_introduced then
    begin
      {$if declared(FC_BN_GF2m_add)}
      BN_GF2m_add := @FC_BN_GF2m_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_add_removed)}
    if BN_GF2m_add_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_add)}
      BN_GF2m_add := @_BN_GF2m_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_add_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_add');
    {$ifend}
  end;


  BN_GF2m_mod := LoadLibFunction(ADllHandle, BN_GF2m_mod_procname);
  FuncLoadError := not assigned(BN_GF2m_mod);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_allownil)}
    BN_GF2m_mod := @ERR_BN_GF2m_mod;
    {$ifend}
    {$if declared(BN_GF2m_mod_introduced)}
    if LibVersion < BN_GF2m_mod_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod)}
      BN_GF2m_mod := @FC_BN_GF2m_mod;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_removed)}
    if BN_GF2m_mod_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod)}
      BN_GF2m_mod := @_BN_GF2m_mod;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod');
    {$ifend}
  end;


  BN_GF2m_mod_mul := LoadLibFunction(ADllHandle, BN_GF2m_mod_mul_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_mul);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_mul_allownil)}
    BN_GF2m_mod_mul := @ERR_BN_GF2m_mod_mul;
    {$ifend}
    {$if declared(BN_GF2m_mod_mul_introduced)}
    if LibVersion < BN_GF2m_mod_mul_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_mul)}
      BN_GF2m_mod_mul := @FC_BN_GF2m_mod_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_mul_removed)}
    if BN_GF2m_mod_mul_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_mul)}
      BN_GF2m_mod_mul := @_BN_GF2m_mod_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_mul_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_mul');
    {$ifend}
  end;


  BN_GF2m_mod_sqr := LoadLibFunction(ADllHandle, BN_GF2m_mod_sqr_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_sqr);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_sqr_allownil)}
    BN_GF2m_mod_sqr := @ERR_BN_GF2m_mod_sqr;
    {$ifend}
    {$if declared(BN_GF2m_mod_sqr_introduced)}
    if LibVersion < BN_GF2m_mod_sqr_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_sqr)}
      BN_GF2m_mod_sqr := @FC_BN_GF2m_mod_sqr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_sqr_removed)}
    if BN_GF2m_mod_sqr_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_sqr)}
      BN_GF2m_mod_sqr := @_BN_GF2m_mod_sqr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_sqr_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_sqr');
    {$ifend}
  end;


  BN_GF2m_mod_inv := LoadLibFunction(ADllHandle, BN_GF2m_mod_inv_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_inv);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_inv_allownil)}
    BN_GF2m_mod_inv := @ERR_BN_GF2m_mod_inv;
    {$ifend}
    {$if declared(BN_GF2m_mod_inv_introduced)}
    if LibVersion < BN_GF2m_mod_inv_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_inv)}
      BN_GF2m_mod_inv := @FC_BN_GF2m_mod_inv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_inv_removed)}
    if BN_GF2m_mod_inv_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_inv)}
      BN_GF2m_mod_inv := @_BN_GF2m_mod_inv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_inv_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_inv');
    {$ifend}
  end;


  BN_GF2m_mod_div := LoadLibFunction(ADllHandle, BN_GF2m_mod_div_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_div);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_div_allownil)}
    BN_GF2m_mod_div := @ERR_BN_GF2m_mod_div;
    {$ifend}
    {$if declared(BN_GF2m_mod_div_introduced)}
    if LibVersion < BN_GF2m_mod_div_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_div)}
      BN_GF2m_mod_div := @FC_BN_GF2m_mod_div;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_div_removed)}
    if BN_GF2m_mod_div_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_div)}
      BN_GF2m_mod_div := @_BN_GF2m_mod_div;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_div_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_div');
    {$ifend}
  end;


  BN_GF2m_mod_exp := LoadLibFunction(ADllHandle, BN_GF2m_mod_exp_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_exp_allownil)}
    BN_GF2m_mod_exp := @ERR_BN_GF2m_mod_exp;
    {$ifend}
    {$if declared(BN_GF2m_mod_exp_introduced)}
    if LibVersion < BN_GF2m_mod_exp_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_exp)}
      BN_GF2m_mod_exp := @FC_BN_GF2m_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_exp_removed)}
    if BN_GF2m_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_exp)}
      BN_GF2m_mod_exp := @_BN_GF2m_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_exp');
    {$ifend}
  end;


  BN_GF2m_mod_sqrt := LoadLibFunction(ADllHandle, BN_GF2m_mod_sqrt_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_sqrt);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_sqrt_allownil)}
    BN_GF2m_mod_sqrt := @ERR_BN_GF2m_mod_sqrt;
    {$ifend}
    {$if declared(BN_GF2m_mod_sqrt_introduced)}
    if LibVersion < BN_GF2m_mod_sqrt_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_sqrt)}
      BN_GF2m_mod_sqrt := @FC_BN_GF2m_mod_sqrt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_sqrt_removed)}
    if BN_GF2m_mod_sqrt_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_sqrt)}
      BN_GF2m_mod_sqrt := @_BN_GF2m_mod_sqrt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_sqrt_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_sqrt');
    {$ifend}
  end;


  BN_GF2m_mod_solve_quad := LoadLibFunction(ADllHandle, BN_GF2m_mod_solve_quad_procname);
  FuncLoadError := not assigned(BN_GF2m_mod_solve_quad);
  if FuncLoadError then
  begin
    {$if not defined(BN_GF2m_mod_solve_quad_allownil)}
    BN_GF2m_mod_solve_quad := @ERR_BN_GF2m_mod_solve_quad;
    {$ifend}
    {$if declared(BN_GF2m_mod_solve_quad_introduced)}
    if LibVersion < BN_GF2m_mod_solve_quad_introduced then
    begin
      {$if declared(FC_BN_GF2m_mod_solve_quad)}
      BN_GF2m_mod_solve_quad := @FC_BN_GF2m_mod_solve_quad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_GF2m_mod_solve_quad_removed)}
    if BN_GF2m_mod_solve_quad_removed <= LibVersion then
    begin
      {$if declared(_BN_GF2m_mod_solve_quad)}
      BN_GF2m_mod_solve_quad := @_BN_GF2m_mod_solve_quad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_GF2m_mod_solve_quad_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_GF2m_mod_solve_quad');
    {$ifend}
  end;


  BN_nist_mod_192 := LoadLibFunction(ADllHandle, BN_nist_mod_192_procname);
  FuncLoadError := not assigned(BN_nist_mod_192);
  if FuncLoadError then
  begin
    {$if not defined(BN_nist_mod_192_allownil)}
    BN_nist_mod_192 := @ERR_BN_nist_mod_192;
    {$ifend}
    {$if declared(BN_nist_mod_192_introduced)}
    if LibVersion < BN_nist_mod_192_introduced then
    begin
      {$if declared(FC_BN_nist_mod_192)}
      BN_nist_mod_192 := @FC_BN_nist_mod_192;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_nist_mod_192_removed)}
    if BN_nist_mod_192_removed <= LibVersion then
    begin
      {$if declared(_BN_nist_mod_192)}
      BN_nist_mod_192 := @_BN_nist_mod_192;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_nist_mod_192_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_nist_mod_192');
    {$ifend}
  end;


  BN_nist_mod_224 := LoadLibFunction(ADllHandle, BN_nist_mod_224_procname);
  FuncLoadError := not assigned(BN_nist_mod_224);
  if FuncLoadError then
  begin
    {$if not defined(BN_nist_mod_224_allownil)}
    BN_nist_mod_224 := @ERR_BN_nist_mod_224;
    {$ifend}
    {$if declared(BN_nist_mod_224_introduced)}
    if LibVersion < BN_nist_mod_224_introduced then
    begin
      {$if declared(FC_BN_nist_mod_224)}
      BN_nist_mod_224 := @FC_BN_nist_mod_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_nist_mod_224_removed)}
    if BN_nist_mod_224_removed <= LibVersion then
    begin
      {$if declared(_BN_nist_mod_224)}
      BN_nist_mod_224 := @_BN_nist_mod_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_nist_mod_224_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_nist_mod_224');
    {$ifend}
  end;


  BN_nist_mod_256 := LoadLibFunction(ADllHandle, BN_nist_mod_256_procname);
  FuncLoadError := not assigned(BN_nist_mod_256);
  if FuncLoadError then
  begin
    {$if not defined(BN_nist_mod_256_allownil)}
    BN_nist_mod_256 := @ERR_BN_nist_mod_256;
    {$ifend}
    {$if declared(BN_nist_mod_256_introduced)}
    if LibVersion < BN_nist_mod_256_introduced then
    begin
      {$if declared(FC_BN_nist_mod_256)}
      BN_nist_mod_256 := @FC_BN_nist_mod_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_nist_mod_256_removed)}
    if BN_nist_mod_256_removed <= LibVersion then
    begin
      {$if declared(_BN_nist_mod_256)}
      BN_nist_mod_256 := @_BN_nist_mod_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_nist_mod_256_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_nist_mod_256');
    {$ifend}
  end;


  BN_nist_mod_384 := LoadLibFunction(ADllHandle, BN_nist_mod_384_procname);
  FuncLoadError := not assigned(BN_nist_mod_384);
  if FuncLoadError then
  begin
    {$if not defined(BN_nist_mod_384_allownil)}
    BN_nist_mod_384 := @ERR_BN_nist_mod_384;
    {$ifend}
    {$if declared(BN_nist_mod_384_introduced)}
    if LibVersion < BN_nist_mod_384_introduced then
    begin
      {$if declared(FC_BN_nist_mod_384)}
      BN_nist_mod_384 := @FC_BN_nist_mod_384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_nist_mod_384_removed)}
    if BN_nist_mod_384_removed <= LibVersion then
    begin
      {$if declared(_BN_nist_mod_384)}
      BN_nist_mod_384 := @_BN_nist_mod_384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_nist_mod_384_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_nist_mod_384');
    {$ifend}
  end;


  BN_nist_mod_521 := LoadLibFunction(ADllHandle, BN_nist_mod_521_procname);
  FuncLoadError := not assigned(BN_nist_mod_521);
  if FuncLoadError then
  begin
    {$if not defined(BN_nist_mod_521_allownil)}
    BN_nist_mod_521 := @ERR_BN_nist_mod_521;
    {$ifend}
    {$if declared(BN_nist_mod_521_introduced)}
    if LibVersion < BN_nist_mod_521_introduced then
    begin
      {$if declared(FC_BN_nist_mod_521)}
      BN_nist_mod_521 := @FC_BN_nist_mod_521;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_nist_mod_521_removed)}
    if BN_nist_mod_521_removed <= LibVersion then
    begin
      {$if declared(_BN_nist_mod_521)}
      BN_nist_mod_521 := @_BN_nist_mod_521;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_nist_mod_521_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_nist_mod_521');
    {$ifend}
  end;


  BN_get0_nist_prime_192 := LoadLibFunction(ADllHandle, BN_get0_nist_prime_192_procname);
  FuncLoadError := not assigned(BN_get0_nist_prime_192);
  if FuncLoadError then
  begin
    {$if not defined(BN_get0_nist_prime_192_allownil)}
    BN_get0_nist_prime_192 := @ERR_BN_get0_nist_prime_192;
    {$ifend}
    {$if declared(BN_get0_nist_prime_192_introduced)}
    if LibVersion < BN_get0_nist_prime_192_introduced then
    begin
      {$if declared(FC_BN_get0_nist_prime_192)}
      BN_get0_nist_prime_192 := @FC_BN_get0_nist_prime_192;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get0_nist_prime_192_removed)}
    if BN_get0_nist_prime_192_removed <= LibVersion then
    begin
      {$if declared(_BN_get0_nist_prime_192)}
      BN_get0_nist_prime_192 := @_BN_get0_nist_prime_192;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get0_nist_prime_192_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get0_nist_prime_192');
    {$ifend}
  end;


  BN_get0_nist_prime_224 := LoadLibFunction(ADllHandle, BN_get0_nist_prime_224_procname);
  FuncLoadError := not assigned(BN_get0_nist_prime_224);
  if FuncLoadError then
  begin
    {$if not defined(BN_get0_nist_prime_224_allownil)}
    BN_get0_nist_prime_224 := @ERR_BN_get0_nist_prime_224;
    {$ifend}
    {$if declared(BN_get0_nist_prime_224_introduced)}
    if LibVersion < BN_get0_nist_prime_224_introduced then
    begin
      {$if declared(FC_BN_get0_nist_prime_224)}
      BN_get0_nist_prime_224 := @FC_BN_get0_nist_prime_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get0_nist_prime_224_removed)}
    if BN_get0_nist_prime_224_removed <= LibVersion then
    begin
      {$if declared(_BN_get0_nist_prime_224)}
      BN_get0_nist_prime_224 := @_BN_get0_nist_prime_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get0_nist_prime_224_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get0_nist_prime_224');
    {$ifend}
  end;


  BN_get0_nist_prime_256 := LoadLibFunction(ADllHandle, BN_get0_nist_prime_256_procname);
  FuncLoadError := not assigned(BN_get0_nist_prime_256);
  if FuncLoadError then
  begin
    {$if not defined(BN_get0_nist_prime_256_allownil)}
    BN_get0_nist_prime_256 := @ERR_BN_get0_nist_prime_256;
    {$ifend}
    {$if declared(BN_get0_nist_prime_256_introduced)}
    if LibVersion < BN_get0_nist_prime_256_introduced then
    begin
      {$if declared(FC_BN_get0_nist_prime_256)}
      BN_get0_nist_prime_256 := @FC_BN_get0_nist_prime_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get0_nist_prime_256_removed)}
    if BN_get0_nist_prime_256_removed <= LibVersion then
    begin
      {$if declared(_BN_get0_nist_prime_256)}
      BN_get0_nist_prime_256 := @_BN_get0_nist_prime_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get0_nist_prime_256_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get0_nist_prime_256');
    {$ifend}
  end;


  BN_get0_nist_prime_384 := LoadLibFunction(ADllHandle, BN_get0_nist_prime_384_procname);
  FuncLoadError := not assigned(BN_get0_nist_prime_384);
  if FuncLoadError then
  begin
    {$if not defined(BN_get0_nist_prime_384_allownil)}
    BN_get0_nist_prime_384 := @ERR_BN_get0_nist_prime_384;
    {$ifend}
    {$if declared(BN_get0_nist_prime_384_introduced)}
    if LibVersion < BN_get0_nist_prime_384_introduced then
    begin
      {$if declared(FC_BN_get0_nist_prime_384)}
      BN_get0_nist_prime_384 := @FC_BN_get0_nist_prime_384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get0_nist_prime_384_removed)}
    if BN_get0_nist_prime_384_removed <= LibVersion then
    begin
      {$if declared(_BN_get0_nist_prime_384)}
      BN_get0_nist_prime_384 := @_BN_get0_nist_prime_384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get0_nist_prime_384_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get0_nist_prime_384');
    {$ifend}
  end;


  BN_get0_nist_prime_521 := LoadLibFunction(ADllHandle, BN_get0_nist_prime_521_procname);
  FuncLoadError := not assigned(BN_get0_nist_prime_521);
  if FuncLoadError then
  begin
    {$if not defined(BN_get0_nist_prime_521_allownil)}
    BN_get0_nist_prime_521 := @ERR_BN_get0_nist_prime_521;
    {$ifend}
    {$if declared(BN_get0_nist_prime_521_introduced)}
    if LibVersion < BN_get0_nist_prime_521_introduced then
    begin
      {$if declared(FC_BN_get0_nist_prime_521)}
      BN_get0_nist_prime_521 := @FC_BN_get0_nist_prime_521;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get0_nist_prime_521_removed)}
    if BN_get0_nist_prime_521_removed <= LibVersion then
    begin
      {$if declared(_BN_get0_nist_prime_521)}
      BN_get0_nist_prime_521 := @_BN_get0_nist_prime_521;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get0_nist_prime_521_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get0_nist_prime_521');
    {$ifend}
  end;


  BN_generate_dsa_nonce := LoadLibFunction(ADllHandle, BN_generate_dsa_nonce_procname);
  FuncLoadError := not assigned(BN_generate_dsa_nonce);
  if FuncLoadError then
  begin
    {$if not defined(BN_generate_dsa_nonce_allownil)}
    BN_generate_dsa_nonce := @ERR_BN_generate_dsa_nonce;
    {$ifend}
    {$if declared(BN_generate_dsa_nonce_introduced)}
    if LibVersion < BN_generate_dsa_nonce_introduced then
    begin
      {$if declared(FC_BN_generate_dsa_nonce)}
      BN_generate_dsa_nonce := @FC_BN_generate_dsa_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_generate_dsa_nonce_removed)}
    if BN_generate_dsa_nonce_removed <= LibVersion then
    begin
      {$if declared(_BN_generate_dsa_nonce)}
      BN_generate_dsa_nonce := @_BN_generate_dsa_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_generate_dsa_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_generate_dsa_nonce');
    {$ifend}
  end;


  BN_get_rfc2409_prime_768 := LoadLibFunction(ADllHandle, BN_get_rfc2409_prime_768_procname);
  FuncLoadError := not assigned(BN_get_rfc2409_prime_768);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc2409_prime_768_allownil)}
    BN_get_rfc2409_prime_768 := @ERR_BN_get_rfc2409_prime_768;
    {$ifend}
    {$if declared(BN_get_rfc2409_prime_768_introduced)}
    if LibVersion < BN_get_rfc2409_prime_768_introduced then
    begin
      {$if declared(FC_BN_get_rfc2409_prime_768)}
      BN_get_rfc2409_prime_768 := @FC_BN_get_rfc2409_prime_768;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc2409_prime_768_removed)}
    if BN_get_rfc2409_prime_768_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc2409_prime_768)}
      BN_get_rfc2409_prime_768 := @_BN_get_rfc2409_prime_768;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc2409_prime_768_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc2409_prime_768');
    {$ifend}
  end;


  BN_get_rfc2409_prime_1024 := LoadLibFunction(ADllHandle, BN_get_rfc2409_prime_1024_procname);
  FuncLoadError := not assigned(BN_get_rfc2409_prime_1024);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc2409_prime_1024_allownil)}
    BN_get_rfc2409_prime_1024 := @ERR_BN_get_rfc2409_prime_1024;
    {$ifend}
    {$if declared(BN_get_rfc2409_prime_1024_introduced)}
    if LibVersion < BN_get_rfc2409_prime_1024_introduced then
    begin
      {$if declared(FC_BN_get_rfc2409_prime_1024)}
      BN_get_rfc2409_prime_1024 := @FC_BN_get_rfc2409_prime_1024;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc2409_prime_1024_removed)}
    if BN_get_rfc2409_prime_1024_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc2409_prime_1024)}
      BN_get_rfc2409_prime_1024 := @_BN_get_rfc2409_prime_1024;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc2409_prime_1024_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc2409_prime_1024');
    {$ifend}
  end;


  BN_get_rfc3526_prime_1536 := LoadLibFunction(ADllHandle, BN_get_rfc3526_prime_1536_procname);
  FuncLoadError := not assigned(BN_get_rfc3526_prime_1536);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc3526_prime_1536_allownil)}
    BN_get_rfc3526_prime_1536 := @ERR_BN_get_rfc3526_prime_1536;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_1536_introduced)}
    if LibVersion < BN_get_rfc3526_prime_1536_introduced then
    begin
      {$if declared(FC_BN_get_rfc3526_prime_1536)}
      BN_get_rfc3526_prime_1536 := @FC_BN_get_rfc3526_prime_1536;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_1536_removed)}
    if BN_get_rfc3526_prime_1536_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc3526_prime_1536)}
      BN_get_rfc3526_prime_1536 := @_BN_get_rfc3526_prime_1536;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc3526_prime_1536_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc3526_prime_1536');
    {$ifend}
  end;


  BN_get_rfc3526_prime_2048 := LoadLibFunction(ADllHandle, BN_get_rfc3526_prime_2048_procname);
  FuncLoadError := not assigned(BN_get_rfc3526_prime_2048);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc3526_prime_2048_allownil)}
    BN_get_rfc3526_prime_2048 := @ERR_BN_get_rfc3526_prime_2048;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_2048_introduced)}
    if LibVersion < BN_get_rfc3526_prime_2048_introduced then
    begin
      {$if declared(FC_BN_get_rfc3526_prime_2048)}
      BN_get_rfc3526_prime_2048 := @FC_BN_get_rfc3526_prime_2048;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_2048_removed)}
    if BN_get_rfc3526_prime_2048_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc3526_prime_2048)}
      BN_get_rfc3526_prime_2048 := @_BN_get_rfc3526_prime_2048;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc3526_prime_2048_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc3526_prime_2048');
    {$ifend}
  end;


  BN_get_rfc3526_prime_3072 := LoadLibFunction(ADllHandle, BN_get_rfc3526_prime_3072_procname);
  FuncLoadError := not assigned(BN_get_rfc3526_prime_3072);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc3526_prime_3072_allownil)}
    BN_get_rfc3526_prime_3072 := @ERR_BN_get_rfc3526_prime_3072;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_3072_introduced)}
    if LibVersion < BN_get_rfc3526_prime_3072_introduced then
    begin
      {$if declared(FC_BN_get_rfc3526_prime_3072)}
      BN_get_rfc3526_prime_3072 := @FC_BN_get_rfc3526_prime_3072;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_3072_removed)}
    if BN_get_rfc3526_prime_3072_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc3526_prime_3072)}
      BN_get_rfc3526_prime_3072 := @_BN_get_rfc3526_prime_3072;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc3526_prime_3072_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc3526_prime_3072');
    {$ifend}
  end;


  BN_get_rfc3526_prime_4096 := LoadLibFunction(ADllHandle, BN_get_rfc3526_prime_4096_procname);
  FuncLoadError := not assigned(BN_get_rfc3526_prime_4096);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc3526_prime_4096_allownil)}
    BN_get_rfc3526_prime_4096 := @ERR_BN_get_rfc3526_prime_4096;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_4096_introduced)}
    if LibVersion < BN_get_rfc3526_prime_4096_introduced then
    begin
      {$if declared(FC_BN_get_rfc3526_prime_4096)}
      BN_get_rfc3526_prime_4096 := @FC_BN_get_rfc3526_prime_4096;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_4096_removed)}
    if BN_get_rfc3526_prime_4096_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc3526_prime_4096)}
      BN_get_rfc3526_prime_4096 := @_BN_get_rfc3526_prime_4096;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc3526_prime_4096_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc3526_prime_4096');
    {$ifend}
  end;


  BN_get_rfc3526_prime_6144 := LoadLibFunction(ADllHandle, BN_get_rfc3526_prime_6144_procname);
  FuncLoadError := not assigned(BN_get_rfc3526_prime_6144);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc3526_prime_6144_allownil)}
    BN_get_rfc3526_prime_6144 := @ERR_BN_get_rfc3526_prime_6144;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_6144_introduced)}
    if LibVersion < BN_get_rfc3526_prime_6144_introduced then
    begin
      {$if declared(FC_BN_get_rfc3526_prime_6144)}
      BN_get_rfc3526_prime_6144 := @FC_BN_get_rfc3526_prime_6144;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_6144_removed)}
    if BN_get_rfc3526_prime_6144_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc3526_prime_6144)}
      BN_get_rfc3526_prime_6144 := @_BN_get_rfc3526_prime_6144;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc3526_prime_6144_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc3526_prime_6144');
    {$ifend}
  end;


  BN_get_rfc3526_prime_8192 := LoadLibFunction(ADllHandle, BN_get_rfc3526_prime_8192_procname);
  FuncLoadError := not assigned(BN_get_rfc3526_prime_8192);
  if FuncLoadError then
  begin
    {$if not defined(BN_get_rfc3526_prime_8192_allownil)}
    BN_get_rfc3526_prime_8192 := @ERR_BN_get_rfc3526_prime_8192;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_8192_introduced)}
    if LibVersion < BN_get_rfc3526_prime_8192_introduced then
    begin
      {$if declared(FC_BN_get_rfc3526_prime_8192)}
      BN_get_rfc3526_prime_8192 := @FC_BN_get_rfc3526_prime_8192;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_get_rfc3526_prime_8192_removed)}
    if BN_get_rfc3526_prime_8192_removed <= LibVersion then
    begin
      {$if declared(_BN_get_rfc3526_prime_8192)}
      BN_get_rfc3526_prime_8192 := @_BN_get_rfc3526_prime_8192;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_get_rfc3526_prime_8192_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_get_rfc3526_prime_8192');
    {$ifend}
  end;


  BN_bntest_rand := LoadLibFunction(ADllHandle, BN_bntest_rand_procname);
  FuncLoadError := not assigned(BN_bntest_rand);
  if FuncLoadError then
  begin
    {$if not defined(BN_bntest_rand_allownil)}
    BN_bntest_rand := @ERR_BN_bntest_rand;
    {$ifend}
    {$if declared(BN_bntest_rand_introduced)}
    if LibVersion < BN_bntest_rand_introduced then
    begin
      {$if declared(FC_BN_bntest_rand)}
      BN_bntest_rand := @FC_BN_bntest_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_bntest_rand_removed)}
    if BN_bntest_rand_removed <= LibVersion then
    begin
      {$if declared(_BN_bntest_rand)}
      BN_bntest_rand := @_BN_bntest_rand;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_bntest_rand_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_bntest_rand');
    {$ifend}
  end;


end;

procedure Unload;
begin
  BN_set_flags := nil;
  BN_get_flags := nil;
  BN_with_flags := nil;
  BN_GENCB_call := nil;
  BN_GENCB_new := nil;
  BN_GENCB_free := nil;
  BN_GENCB_set_old := nil;
  BN_GENCB_set := nil;
  BN_GENCB_get_arg := nil;
  BN_abs_is_word := nil;
  BN_is_zero := nil;
  BN_is_one := nil;
  BN_is_word := nil;
  BN_is_odd := nil;
  BN_zero_ex := nil;
  BN_value_one := nil;
  BN_options := nil;
  BN_CTX_new := nil;
  BN_CTX_secure_new := nil;
  BN_CTX_free := nil;
  BN_CTX_start := nil;
  BN_CTX_get := nil;
  BN_CTX_end := nil;
  BN_rand := nil;
  BN_priv_rand := nil;
  BN_rand_range := nil;
  BN_priv_rand_range := nil;
  BN_pseudo_rand := nil;
  BN_pseudo_rand_range := nil;
  BN_num_bits := nil;
  BN_num_bits_word := nil;
  BN_security_bits := nil;
  BN_new := nil;
  BN_secure_new := nil;
  BN_clear_free := nil;
  BN_copy := nil;
  BN_swap := nil;
  BN_bin2bn := nil;
  BN_bn2bin := nil;
  BN_bn2binpad := nil;
  BN_lebin2bn := nil;
  BN_bn2lebinpad := nil;
  BN_mpi2bn := nil;
  BN_bn2mpi := nil;
  BN_sub := nil;
  BN_usub := nil;
  BN_uadd := nil;
  BN_add := nil;
  BN_mul := nil;
  BN_sqr := nil;
  BN_set_negative := nil;
  BN_is_negative := nil;
  BN_div := nil;
  BN_nnmod := nil;
  BN_mod_add := nil;
  BN_mod_add_quick := nil;
  BN_mod_sub := nil;
  BN_mod_sub_quick := nil;
  BN_mod_mul := nil;
  BN_mod_sqr := nil;
  BN_mod_lshift1 := nil;
  BN_mod_lshift1_quick := nil;
  BN_mod_lshift := nil;
  BN_mod_lshift_quick := nil;
  BN_mod_word := nil;
  BN_div_word := nil;
  BN_mul_word := nil;
  BN_add_word := nil;
  BN_sub_word := nil;
  BN_set_word := nil;
  BN_get_word := nil;
  BN_cmp := nil;
  BN_free := nil;
  BN_is_bit_set := nil;
  BN_lshift := nil;
  BN_lshift1 := nil;
  BN_exp := nil;
  BN_mod_exp := nil;
  BN_mod_exp_mont := nil;
  BN_mod_exp_mont_consttime := nil;
  BN_mod_exp_mont_word := nil;
  BN_mod_exp2_mont := nil;
  BN_mod_exp_simple := nil;
  BN_mask_bits := nil;
  BN_print := nil;
  BN_reciprocal := nil;
  BN_rshift := nil;
  BN_rshift1 := nil;
  BN_clear := nil;
  BN_dup := nil;
  BN_ucmp := nil;
  BN_set_bit := nil;
  BN_clear_bit := nil;
  BN_bn2hex := nil;
  BN_bn2dec := nil;
  BN_hex2bn := nil;
  BN_dec2bn := nil;
  BN_asc2bn := nil;
  BN_gcd := nil;
  BN_kronecker := nil;
  BN_mod_inverse := nil;
  BN_mod_sqrt := nil;
  BN_consttime_swap := nil;
  BN_generate_prime_ex := nil;
  BN_is_prime_ex := nil;
  BN_is_prime_fasttest_ex := nil;
  BN_X931_generate_Xpq := nil;
  BN_X931_derive_prime_ex := nil;
  BN_X931_generate_prime_ex := nil;
  BN_MONT_CTX_new := nil;
  BN_mod_mul_montgomery := nil;
  BN_to_montgomery := nil;
  BN_from_montgomery := nil;
  BN_MONT_CTX_free := nil;
  BN_MONT_CTX_set := nil;
  BN_MONT_CTX_copy := nil;
  BN_BLINDING_new := nil;
  BN_BLINDING_free := nil;
  BN_BLINDING_update := nil;
  BN_BLINDING_convert := nil;
  BN_BLINDING_invert := nil;
  BN_BLINDING_convert_ex := nil;
  BN_BLINDING_invert_ex := nil;
  BN_BLINDING_is_current_thread := nil;
  BN_BLINDING_set_current_thread := nil;
  BN_BLINDING_lock := nil;
  BN_BLINDING_unlock := nil;
  BN_BLINDING_get_flags := nil;
  BN_BLINDING_set_flags := nil;
  BN_RECP_CTX_free := nil;
  BN_RECP_CTX_set := nil;
  BN_mod_mul_reciprocal := nil;
  BN_mod_exp_recp := nil;
  BN_div_recp := nil;
  BN_GF2m_add := nil;
  BN_GF2m_mod := nil;
  BN_GF2m_mod_mul := nil;
  BN_GF2m_mod_sqr := nil;
  BN_GF2m_mod_inv := nil;
  BN_GF2m_mod_div := nil;
  BN_GF2m_mod_exp := nil;
  BN_GF2m_mod_sqrt := nil;
  BN_GF2m_mod_solve_quad := nil;
  BN_nist_mod_192 := nil;
  BN_nist_mod_224 := nil;
  BN_nist_mod_256 := nil;
  BN_nist_mod_384 := nil;
  BN_nist_mod_521 := nil;
  BN_get0_nist_prime_192 := nil;
  BN_get0_nist_prime_224 := nil;
  BN_get0_nist_prime_256 := nil;
  BN_get0_nist_prime_384 := nil;
  BN_get0_nist_prime_521 := nil;
  BN_generate_dsa_nonce := nil;
  BN_get_rfc2409_prime_768 := nil;
  BN_get_rfc2409_prime_1024 := nil;
  BN_get_rfc3526_prime_1536 := nil;
  BN_get_rfc3526_prime_2048 := nil;
  BN_get_rfc3526_prime_3072 := nil;
  BN_get_rfc3526_prime_4096 := nil;
  BN_get_rfc3526_prime_6144 := nil;
  BN_get_rfc3526_prime_8192 := nil;
  BN_bntest_rand := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
