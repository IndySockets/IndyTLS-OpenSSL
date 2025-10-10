(* This unit was generated from the source file des.h2pas 
It should not be modified directly. All changes should be made to des.h2pas
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



unit IdOpenSSLHeaders_des;


interface


uses
  IdSSLOpenSSLAPI;

{
  Automatically converted by H2Pas 1.0.0 from des.h
  The following command line parameters were used:
    des.h
}

    
Type
    DES_LONG = type cardinal;
    Pconst_DES_cblock  = ^const_DES_cblock;
    PDES_cblock  = ^DES_cblock;
    PDES_key_schedule  = ^DES_key_schedule;
    PDES_LONG  = ^DES_LONG;


     DES_cblock = array[0..7] of byte;
    { const  }
      const_DES_cblock = array[0..7] of byte;
    {
     * With "const", gcc 2.8.1 on Solaris thinks that DES_cblock * and
     * const_DES_cblock * are incompatible pointer types.
      }
    {
             * make sure things are correct size on machines with 8 byte longs
              }

      DES_ks = record
          ks : array[0..15] of record
              case longint of
                0 : ( cblock : DES_cblock );
                1 : ( deslong : array[0..1] of DES_LONG );
              end;
        end;
      DES_key_schedule = DES_ks;

var
  DES_check_key : longint;


    
const
      DES_ENCRYPT = 1;      
      DES_DECRYPT = 0;      
      DES_CBC_MODE = 0;      
      DES_PCBC_MODE = 1;      

    
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM DES_options}
{$EXTERNALSYM DES_ecb3_encrypt}
{$EXTERNALSYM DES_cbc_cksum}
{$EXTERNALSYM DES_cbc_encrypt}
{$EXTERNALSYM DES_ncbc_encrypt}
{$EXTERNALSYM DES_xcbc_encrypt}
{$EXTERNALSYM DES_cfb_encrypt}
{$EXTERNALSYM DES_ecb_encrypt}
{$EXTERNALSYM DES_encrypt1}
{$EXTERNALSYM DES_encrypt2}
{$EXTERNALSYM DES_encrypt3}
{$EXTERNALSYM DES_decrypt3}
{$EXTERNALSYM DES_ede3_cbc_encrypt}
{$EXTERNALSYM DES_ede3_cfb64_encrypt}
{$EXTERNALSYM DES_ede3_cfb_encrypt}
{$EXTERNALSYM DES_ede3_ofb64_encrypt}
{$EXTERNALSYM DES_fcrypt}
{$EXTERNALSYM DES_crypt}
{$EXTERNALSYM DES_ofb_encrypt}
{$EXTERNALSYM DES_pcbc_encrypt}
{$EXTERNALSYM DES_quad_cksum}
{$EXTERNALSYM DES_random_key}
{$EXTERNALSYM DES_set_odd_parity}
{$EXTERNALSYM DES_check_key_parity}
{$EXTERNALSYM DES_is_weak_key}
{$EXTERNALSYM DES_set_key}
{$EXTERNALSYM DES_key_sched}
{$EXTERNALSYM DES_set_key_checked}
{$EXTERNALSYM DES_set_key_unchecked}
{$EXTERNALSYM DES_string_to_key}
{$EXTERNALSYM DES_string_to_2keys}
{$EXTERNALSYM DES_cfb64_encrypt}
{$EXTERNALSYM DES_ofb64_encrypt}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function DES_options: PAnsiChar; cdecl; external CLibCrypto;
procedure DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
function DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl; external CLibCrypto;
procedure DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
procedure DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
procedure DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl; external CLibCrypto;
procedure DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl; external CLibCrypto;
procedure DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl; external CLibCrypto;
procedure DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl; external CLibCrypto;
procedure DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
procedure DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl; external CLibCrypto;
function DES_fcrypt(buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function DES_crypt(buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
procedure DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl; external CLibCrypto;
procedure DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl; external CLibCrypto;
function DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl; external CLibCrypto;
function DES_random_key(ret:PDES_cblock): longint; cdecl; external CLibCrypto;
procedure DES_set_odd_parity(key:PDES_cblock); cdecl; external CLibCrypto;
function DES_check_key_parity(key:Pconst_DES_cblock): longint; cdecl; external CLibCrypto;
function DES_is_weak_key(key:Pconst_DES_cblock): longint; cdecl; external CLibCrypto;
function DES_set_key(key:Pconst_DES_cblock; var schedule: DES_key_schedule): longint; cdecl; external CLibCrypto;
function DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl; external CLibCrypto;
function DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl; external CLibCrypto;
procedure DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl; external CLibCrypto;
procedure DES_string_to_key(str:PAnsiChar; key:PDES_cblock); cdecl; external CLibCrypto;
procedure DES_string_to_2keys(str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl; external CLibCrypto;
procedure DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl; external CLibCrypto;
procedure DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); {removed 1.0.0}
procedure DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); {removed 1.0.0}
procedure DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); {removed 1.0.0}
procedure DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); {removed 1.0.0}
procedure DES_fixup_key_parity(key: PDES_cblock); {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}

{Declare external function initialisers - should not be called directly}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); cdecl;
procedure Load_DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
procedure Load_DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
procedure Load_DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_DES_options: PAnsiChar; cdecl;
procedure Load_DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl;
function Load_DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl;
procedure Load_DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
procedure Load_DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
procedure Load_DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl;
procedure Load_DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
procedure Load_DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl;
procedure Load_DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl;
procedure Load_DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl;
procedure Load_DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl;
procedure Load_DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl;
procedure Load_DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
procedure Load_DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
procedure Load_DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
procedure Load_DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
function Load_DES_fcrypt(buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl;
function Load_DES_crypt(buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl;
procedure Load_DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl;
procedure Load_DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
function Load_DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl;
function Load_DES_random_key(ret:PDES_cblock): longint; cdecl;
function Load_DES_check_key_parity(key:Pconst_DES_cblock): longint; cdecl;
function Load_DES_is_weak_key(key:Pconst_DES_cblock): longint; cdecl;
function Load_DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl;
function Load_DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl;
procedure Load_DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl;
procedure Load_DES_string_to_key(str:PAnsiChar; key:PDES_cblock); cdecl;
procedure Load_DES_string_to_2keys(str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl;
procedure Load_DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
procedure Load_DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_DES_fixup_key_parity(key: PDES_cblock); cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

var
  DES_options: function : PAnsiChar; cdecl = Load_DES_options;
  DES_ecb3_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl = Load_DES_ecb3_encrypt;
  DES_cbc_cksum: function (input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl = Load_DES_cbc_cksum;
  DES_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_cbc_encrypt;
  DES_ncbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_ncbc_encrypt;
  DES_xcbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl = Load_DES_xcbc_encrypt;
  DES_cfb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_cfb_encrypt;
  DES_ecb_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl = Load_DES_ecb_encrypt;
  DES_encrypt1: procedure (data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl = Load_DES_encrypt1;
  DES_encrypt2: procedure (data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl = Load_DES_encrypt2;
  DES_encrypt3: procedure (data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl = Load_DES_encrypt3;
  DES_decrypt3: procedure (data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl = Load_DES_decrypt3;
  DES_ede3_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_ede3_cbc_encrypt;
  DES_ede3_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = Load_DES_ede3_cfb64_encrypt;
  DES_ede3_cfb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_ede3_cfb_encrypt;
  DES_ede3_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = Load_DES_ede3_ofb64_encrypt;
  DES_fcrypt: function (buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl = Load_DES_fcrypt;
  DES_crypt: function (buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl = Load_DES_crypt;
  DES_ofb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl = Load_DES_ofb_encrypt;
  DES_pcbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_pcbc_encrypt;
  DES_quad_cksum: function (input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl = Load_DES_quad_cksum;
  DES_random_key: function (ret:PDES_cblock): longint; cdecl = Load_DES_random_key;
  DES_set_odd_parity: procedure (key:PDES_cblock); cdecl = nil;
  DES_check_key_parity: function (key:Pconst_DES_cblock): longint; cdecl = Load_DES_check_key_parity;
  DES_is_weak_key: function (key:Pconst_DES_cblock): longint; cdecl = Load_DES_is_weak_key;
  DES_set_key: function (key:Pconst_DES_cblock; var schedule: DES_key_schedule): longint; cdecl = nil;
  DES_key_sched: function (key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl = Load_DES_key_sched;
  DES_set_key_checked: function (key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl = Load_DES_set_key_checked;
  DES_set_key_unchecked: procedure (key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl = Load_DES_set_key_unchecked;
  DES_string_to_key: procedure (str:PAnsiChar; key:PDES_cblock); cdecl = Load_DES_string_to_key;
  DES_string_to_2keys: procedure (str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl = Load_DES_string_to_2keys;
  DES_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = Load_DES_cfb64_encrypt;
  DES_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = Load_DES_ofb64_encrypt;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  DES_ecb2_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); cdecl = Load_DES_ecb2_encrypt; {removed 1.0.0}
  DES_ede2_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = Load_DES_ede2_cbc_encrypt; {removed 1.0.0}
  DES_ede2_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = Load_DES_ede2_cfb64_encrypt; {removed 1.0.0}
  DES_ede2_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = Load_DES_ede2_ofb64_encrypt; {removed 1.0.0}
  DES_fixup_key_parity: procedure (key: PDES_cblock); cdecl = Load_DES_fixup_key_parity; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  DES_ecb2_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_ede2_cbc_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_ede2_cfb64_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_ede2_ofb64_encrypt_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  DES_fixup_key_parity_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}


implementation

    
uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: longint);

    begin
      DES_ecb3_encrypt(input,output,ks1,ks2,ks1,enc);
    end;

    

procedure DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; enc: longint);

    begin
      DES_ede3_cbc_encrypt(input,output,length,ks1,ks2,ks1,ivec,enc);
    end;

    

procedure DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint; enc: longint);

    begin
      DES_ede3_cfb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num,enc);
    end;

    

procedure DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint);

    begin
      DES_ede3_ofb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num);
    end;

    

procedure DES_fixup_key_parity(key:PDES_cblock);

    begin
      DES_set_odd_parity(key);
   end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure COMPAT_DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: longint); cdecl;

    begin
      DES_ecb3_encrypt(input,output,ks1,ks2,ks1,enc);
    end;

    

procedure COMPAT_DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; enc: longint); cdecl;

    begin
      DES_ede3_cbc_encrypt(input,output,length,ks1,ks2,ks1,ivec,enc);
    end;

    

procedure COMPAT_DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint; enc: longint); cdecl;

    begin
      DES_ede3_cfb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num,enc);
    end;

    

procedure COMPAT_DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint); cdecl;

    begin
      DES_ede3_ofb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num);
    end;

    

procedure COMPAT_DES_fixup_key_parity(key:PDES_cblock); cdecl;

    begin
      DES_set_odd_parity(key);
   end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); cdecl;
begin
  DES_ecb2_encrypt := LoadLibCryptoFunction('DES_ecb2_encrypt');
  if not assigned(DES_ecb2_encrypt) then
    DES_ecb2_encrypt := @COMPAT_DES_ecb2_encrypt;
  DES_ecb2_encrypt(input,output,ks1,ks2,enc);
end;

procedure Load_DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_ede2_cbc_encrypt := LoadLibCryptoFunction('DES_ede2_cbc_encrypt');
  if not assigned(DES_ede2_cbc_encrypt) then
    DES_ede2_cbc_encrypt := @COMPAT_DES_ede2_cbc_encrypt;
  DES_ede2_cbc_encrypt(input,output,length,ks1,ks2,ivec,enc);
end;

procedure Load_DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
begin
  DES_ede2_cfb64_encrypt := LoadLibCryptoFunction('DES_ede2_cfb64_encrypt');
  if not assigned(DES_ede2_cfb64_encrypt) then
    DES_ede2_cfb64_encrypt := @COMPAT_DES_ede2_cfb64_encrypt;
  DES_ede2_cfb64_encrypt(in_,out_,length,ks1,ks2,ivec,num,enc);
end;

procedure Load_DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
begin
  DES_ede2_ofb64_encrypt := LoadLibCryptoFunction('DES_ede2_ofb64_encrypt');
  if not assigned(DES_ede2_ofb64_encrypt) then
    DES_ede2_ofb64_encrypt := @COMPAT_DES_ede2_ofb64_encrypt;
  DES_ede2_ofb64_encrypt(in_,out_,length,ks1,ks2,ivec,num);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_DES_options: PAnsiChar; cdecl;
begin
  DES_options := LoadLibCryptoFunction('DES_options');
  if not assigned(DES_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_options');
  Result := DES_options();
end;

procedure Load_DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl;
begin
  DES_ecb3_encrypt := LoadLibCryptoFunction('DES_ecb3_encrypt');
  if not assigned(DES_ecb3_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb3_encrypt');
  DES_ecb3_encrypt(input,output,ks1,ks2,ks3,enc);
end;

function Load_DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock): DES_LONG; cdecl;
begin
  DES_cbc_cksum := LoadLibCryptoFunction('DES_cbc_cksum');
  if not assigned(DES_cbc_cksum) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cbc_cksum');
  Result := DES_cbc_cksum(input,output,length,schedule,ivec);
end;

procedure Load_DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_cbc_encrypt := LoadLibCryptoFunction('DES_cbc_encrypt');
  if not assigned(DES_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cbc_encrypt');
  DES_cbc_encrypt(input,output,length,schedule,ivec,enc);
end;

procedure Load_DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_ncbc_encrypt := LoadLibCryptoFunction('DES_ncbc_encrypt');
  if not assigned(DES_ncbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ncbc_encrypt');
  DES_ncbc_encrypt(input,output,length,schedule,ivec,enc);
end;

procedure Load_DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl;
begin
  DES_xcbc_encrypt := LoadLibCryptoFunction('DES_xcbc_encrypt');
  if not assigned(DES_xcbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_xcbc_encrypt');
  DES_xcbc_encrypt(input,output,length,schedule,ivec,inw,outw,enc);
end;

procedure Load_DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_cfb_encrypt := LoadLibCryptoFunction('DES_cfb_encrypt');
  if not assigned(DES_cfb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cfb_encrypt');
  DES_cfb_encrypt(in_,out_,numbits,length,schedule,ivec,enc);
end;

procedure Load_DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl;
begin
  DES_ecb_encrypt := LoadLibCryptoFunction('DES_ecb_encrypt');
  if not assigned(DES_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb_encrypt');
  DES_ecb_encrypt(input,output,ks,enc);
end;

procedure Load_DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl;
begin
  DES_encrypt1 := LoadLibCryptoFunction('DES_encrypt1');
  if not assigned(DES_encrypt1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt1');
  DES_encrypt1(data,ks,enc);
end;

procedure Load_DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl;
begin
  DES_encrypt2 := LoadLibCryptoFunction('DES_encrypt2');
  if not assigned(DES_encrypt2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt2');
  DES_encrypt2(data,ks,enc);
end;

procedure Load_DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl;
begin
  DES_encrypt3 := LoadLibCryptoFunction('DES_encrypt3');
  if not assigned(DES_encrypt3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt3');
  DES_encrypt3(data,ks1,ks2,ks3);
end;

procedure Load_DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl;
begin
  DES_decrypt3 := LoadLibCryptoFunction('DES_decrypt3');
  if not assigned(DES_decrypt3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_decrypt3');
  DES_decrypt3(data,ks1,ks2,ks3);
end;

procedure Load_DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_ede3_cbc_encrypt := LoadLibCryptoFunction('DES_ede3_cbc_encrypt');
  if not assigned(DES_ede3_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cbc_encrypt');
  DES_ede3_cbc_encrypt(input,output,length,ks1,ks2,ks3,ivec,enc);
end;

procedure Load_DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
begin
  DES_ede3_cfb64_encrypt := LoadLibCryptoFunction('DES_ede3_cfb64_encrypt');
  if not assigned(DES_ede3_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cfb64_encrypt');
  DES_ede3_cfb64_encrypt(in_,out_,length,ks1,ks2,ks3,ivec,num,enc);
end;

procedure Load_DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_ede3_cfb_encrypt := LoadLibCryptoFunction('DES_ede3_cfb_encrypt');
  if not assigned(DES_ede3_cfb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cfb_encrypt');
  DES_ede3_cfb_encrypt(in_,out_,numbits,length,ks1,ks2,ks3,ivec,enc);
end;

procedure Load_DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
begin
  DES_ede3_ofb64_encrypt := LoadLibCryptoFunction('DES_ede3_ofb64_encrypt');
  if not assigned(DES_ede3_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_ofb64_encrypt');
  DES_ede3_ofb64_encrypt(in_,out_,length,ks1,ks2,ks3,ivec,num);
end;

function Load_DES_fcrypt(buf:PAnsiChar; salt:PAnsiChar; ret:PAnsiChar): PAnsiChar; cdecl;
begin
  DES_fcrypt := LoadLibCryptoFunction('DES_fcrypt');
  if not assigned(DES_fcrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_fcrypt');
  Result := DES_fcrypt(buf,salt,ret);
end;

function Load_DES_crypt(buf:PAnsiChar; salt:PAnsiChar): PAnsiChar; cdecl;
begin
  DES_crypt := LoadLibCryptoFunction('DES_crypt');
  if not assigned(DES_crypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_crypt');
  Result := DES_crypt(buf,salt);
end;

procedure Load_DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl;
begin
  DES_ofb_encrypt := LoadLibCryptoFunction('DES_ofb_encrypt');
  if not assigned(DES_ofb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ofb_encrypt');
  DES_ofb_encrypt(in_,out_,numbits,length,schedule,ivec);
end;

procedure Load_DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl;
begin
  DES_pcbc_encrypt := LoadLibCryptoFunction('DES_pcbc_encrypt');
  if not assigned(DES_pcbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_pcbc_encrypt');
  DES_pcbc_encrypt(input,output,length,schedule,ivec,enc);
end;

function Load_DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock): DES_LONG; cdecl;
begin
  DES_quad_cksum := LoadLibCryptoFunction('DES_quad_cksum');
  if not assigned(DES_quad_cksum) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_quad_cksum');
  Result := DES_quad_cksum(input,output,length,out_count,seed);
end;

function Load_DES_random_key(ret:PDES_cblock): longint; cdecl;
begin
  DES_random_key := LoadLibCryptoFunction('DES_random_key');
  if not assigned(DES_random_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_random_key');
  Result := DES_random_key(ret);
end;

function Load_DES_check_key_parity(key:Pconst_DES_cblock): longint; cdecl;
begin
  DES_check_key_parity := LoadLibCryptoFunction('DES_check_key_parity');
  if not assigned(DES_check_key_parity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_check_key_parity');
  Result := DES_check_key_parity(key);
end;

function Load_DES_is_weak_key(key:Pconst_DES_cblock): longint; cdecl;
begin
  DES_is_weak_key := LoadLibCryptoFunction('DES_is_weak_key');
  if not assigned(DES_is_weak_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_is_weak_key');
  Result := DES_is_weak_key(key);
end;

function Load_DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl;
begin
  DES_key_sched := LoadLibCryptoFunction('DES_key_sched');
  if not assigned(DES_key_sched) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_key_sched');
  Result := DES_key_sched(key,schedule);
end;

function Load_DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule): longint; cdecl;
begin
  DES_set_key_checked := LoadLibCryptoFunction('DES_set_key_checked');
  if not assigned(DES_set_key_checked) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key_checked');
  Result := DES_set_key_checked(key,schedule);
end;

procedure Load_DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl;
begin
  DES_set_key_unchecked := LoadLibCryptoFunction('DES_set_key_unchecked');
  if not assigned(DES_set_key_unchecked) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key_unchecked');
  DES_set_key_unchecked(key,schedule);
end;

procedure Load_DES_string_to_key(str:PAnsiChar; key:PDES_cblock); cdecl;
begin
  DES_string_to_key := LoadLibCryptoFunction('DES_string_to_key');
  if not assigned(DES_string_to_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_string_to_key');
  DES_string_to_key(str,key);
end;

procedure Load_DES_string_to_2keys(str:PAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl;
begin
  DES_string_to_2keys := LoadLibCryptoFunction('DES_string_to_2keys');
  if not assigned(DES_string_to_2keys) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_string_to_2keys');
  DES_string_to_2keys(str,key1,key2);
end;

procedure Load_DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl;
begin
  DES_cfb64_encrypt := LoadLibCryptoFunction('DES_cfb64_encrypt');
  if not assigned(DES_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cfb64_encrypt');
  DES_cfb64_encrypt(in_,out_,length,schedule,ivec,num,enc);
end;

procedure Load_DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl;
begin
  DES_ofb64_encrypt := LoadLibCryptoFunction('DES_ofb64_encrypt');
  if not assigned(DES_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ofb64_encrypt');
  DES_ofb64_encrypt(in_,out_,length,schedule,ivec,num);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_DES_fixup_key_parity(key: PDES_cblock); cdecl;
begin
  DES_fixup_key_parity := LoadLibCryptoFunction('DES_fixup_key_parity');
  if not assigned(DES_fixup_key_parity) then
    DES_fixup_key_parity := @COMPAT_DES_fixup_key_parity;
  DES_fixup_key_parity(key);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  DES_set_odd_parity := LoadLibCryptoFunction('DES_set_odd_parity');
  FuncLoadError := not assigned(DES_set_odd_parity);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  DES_set_key := LoadLibCryptoFunction('DES_set_key');
  FuncLoadError := not assigned(DES_set_key);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  DES_ecb2_encrypt := Load_DES_ecb2_encrypt;
  DES_ede2_cbc_encrypt := Load_DES_ede2_cbc_encrypt;
  DES_ede2_cfb64_encrypt := Load_DES_ede2_cfb64_encrypt;
  DES_ede2_ofb64_encrypt := Load_DES_ede2_ofb64_encrypt;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  DES_options := Load_DES_options;
  DES_ecb3_encrypt := Load_DES_ecb3_encrypt;
  DES_cbc_cksum := Load_DES_cbc_cksum;
  DES_cbc_encrypt := Load_DES_cbc_encrypt;
  DES_ncbc_encrypt := Load_DES_ncbc_encrypt;
  DES_xcbc_encrypt := Load_DES_xcbc_encrypt;
  DES_cfb_encrypt := Load_DES_cfb_encrypt;
  DES_ecb_encrypt := Load_DES_ecb_encrypt;
  DES_encrypt1 := Load_DES_encrypt1;
  DES_encrypt2 := Load_DES_encrypt2;
  DES_encrypt3 := Load_DES_encrypt3;
  DES_decrypt3 := Load_DES_decrypt3;
  DES_ede3_cbc_encrypt := Load_DES_ede3_cbc_encrypt;
  DES_ede3_cfb64_encrypt := Load_DES_ede3_cfb64_encrypt;
  DES_ede3_cfb_encrypt := Load_DES_ede3_cfb_encrypt;
  DES_ede3_ofb64_encrypt := Load_DES_ede3_ofb64_encrypt;
  DES_fcrypt := Load_DES_fcrypt;
  DES_crypt := Load_DES_crypt;
  DES_ofb_encrypt := Load_DES_ofb_encrypt;
  DES_pcbc_encrypt := Load_DES_pcbc_encrypt;
  DES_quad_cksum := Load_DES_quad_cksum;
  DES_random_key := Load_DES_random_key;
  DES_set_odd_parity := nil;
  DES_check_key_parity := Load_DES_check_key_parity;
  DES_is_weak_key := Load_DES_is_weak_key;
  DES_set_key := nil;
  DES_key_sched := Load_DES_key_sched;
  DES_set_key_checked := Load_DES_set_key_checked;
  DES_set_key_unchecked := Load_DES_set_key_unchecked;
  DES_string_to_key := Load_DES_string_to_key;
  DES_string_to_2keys := Load_DES_string_to_2keys;
  DES_cfb64_encrypt := Load_DES_cfb64_encrypt;
  DES_ofb64_encrypt := Load_DES_ofb64_encrypt;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  DES_fixup_key_parity := Load_DES_fixup_key_parity;
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
