  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_des.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_des.h2pas
     and this file regenerated. IdOpenSSLHeaders_des.h2pas is distributed with the full Indy
     Distribution.
   *)
   
{$i IdCompilerDefines.inc} 
{$i IdSSLOpenSSLDefines.inc} 

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


unit IdOpenSSLHeaders_des;

interface


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts;

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

{$IFNDEF USE_EXTERNAL_LIBRARY}
var
  {$EXTERNALSYM DES_ecb2_encrypt}  {removed 1.0.0}
  {$EXTERNALSYM DES_ede2_cbc_encrypt}  {removed 1.0.0}
  {$EXTERNALSYM DES_ede2_cfb64_encrypt}  {removed 1.0.0}
  {$EXTERNALSYM DES_ede2_ofb64_encrypt}  {removed 1.0.0}
  {$EXTERNALSYM DES_fixup_key_parity} {removed 1.0.0}
  DES_ecb2_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); cdecl = nil;  {removed 1.0.0}
  DES_ede2_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;  {removed 1.0.0}
  DES_ede2_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = nil;  {removed 1.0.0}
  DES_ede2_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = nil;  {removed 1.0.0}


(* Const before type ignored *)
  DES_options: function : PIdAnsiChar; cdecl = nil;

  DES_ecb3_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_cbc_cksum: function (input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock):DES_LONG; cdecl = nil;

    { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead.  }
(* Const before type ignored *)
  DES_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_ncbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_xcbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_cfb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;

  DES_ecb_encrypt: procedure (input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); cdecl = nil; 
   {
     * This is the DES encryption function that gets called by just about every
     * other DES routine in the library.  You should not use this function except
     * to implement 'modes' of DES.  I say this because the functions that call
     * this routine do the conversion from 'char *' to long, and this needs to be
     * done to make sure 'non-aligned' memory access do not occur.  The
     * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
     * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
     * encryption, zero if decryption.
      }
  DES_encrypt1: procedure (data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl = nil;

    {
     * This functions is the same as DES_encrypt1() except that the DES initial
     * permutation (IP) and final permutation (FP) have been left out.  As for
     * DES_encrypt1(), you should not use this function. It is used by the
     * routines in the library that implement triple DES. IP() DES_encrypt2()
     * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
     * DES_encrypt1() DES_encrypt1() except faster :-).
      }
  DES_encrypt2: procedure (data:PDES_LONG; ks:PDES_key_schedule; enc:longint); cdecl = nil;

  DES_encrypt3: procedure (data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl = nil;

  DES_decrypt3: procedure (data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); cdecl = nil;

(* Const before type ignored *)
  DES_ede3_cbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_ede3_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_ede3_cfb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_ede3_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = nil;

(* Const before type ignored *)
(* Const before type ignored *)
  DES_fcrypt: function (buf:PIdAnsiChar; salt:PIdAnsiChar; ret:PIdAnsiChar): PIdAnsiChar; cdecl = nil;

(* Const before type ignored *)
(* Const before type ignored *)
  DES_crypt: function (buf:PIdAnsiChar; salt:PIdAnsiChar): PIdAnsiChar; cdecl = nil;

(* Const before type ignored *)
  DES_ofb_encrypt: procedure (in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); cdecl = nil;

(* Const before type ignored *)
  DES_pcbc_encrypt: procedure (input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_quad_cksum: function (input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock):DES_LONG; cdecl = nil;

  DES_random_key: function (ret:PDES_cblock):longint; cdecl = nil;

  DES_set_odd_parity: procedure (key:PDES_cblock); cdecl = nil;

  DES_check_key_parity: function (key:Pconst_DES_cblock):longint; cdecl = nil;

  DES_is_weak_key: function (key:Pconst_DES_cblock):longint; cdecl = nil;

    {
     * DES_set_key (= set_key = DES_key_sched = key_sched) calls
     * DES_set_key_checked if global variable DES_check_key is set,
     * DES_set_key_unchecked otherwise.
      }
  DES_set_key: function (key:Pconst_DES_cblock; var schedule: DES_key_schedule):longint; cdecl = nil;

  DES_key_sched: function (key:Pconst_DES_cblock; schedule:PDES_key_schedule):longint; cdecl = nil;

  DES_set_key_checked: function (key:Pconst_DES_cblock; schedule:PDES_key_schedule):longint; cdecl = nil;

  DES_set_key_unchecked: procedure (key:Pconst_DES_cblock; schedule:PDES_key_schedule); cdecl = nil;

(* Const before type ignored *)
  DES_string_to_key: procedure (str:PIdAnsiChar; key:PDES_cblock); cdecl = nil;

(* Const before type ignored *)
  DES_string_to_2keys: procedure (str:PIdAnsiChar; key1:PDES_cblock; key2:PDES_cblock); cdecl = nil;

(* Const before type ignored *)
  DES_cfb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); cdecl = nil;

(* Const before type ignored *)
  DES_ofb64_encrypt: procedure (in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); cdecl = nil;

  DES_fixup_key_parity: procedure (key: PDES_cblock); cdecl = nil; {removed 1.0.0}

{$ELSE}


(* Const before type ignored *)
  function DES_options: PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  function DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock):DES_LONG cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

    { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead.  }
(* Const before type ignored *)
  procedure DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF}; 
   {
     * This is the DES encryption function that gets called by just about every
     * other DES routine in the library.  You should not use this function except
     * to implement 'modes' of DES.  I say this because the functions that call
     * this routine do the conversion from 'char *' to long, and this needs to be
     * done to make sure 'non-aligned' memory access do not occur.  The
     * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
     * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
     * encryption, zero if decryption.
      }
  procedure DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

    {
     * This functions is the same as DES_encrypt1() except that the DES initial
     * permutation (IP) and final permutation (FP) have been left out.  As for
     * DES_encrypt1(), you should not use this function. It is used by the
     * routines in the library that implement triple DES. IP() DES_encrypt2()
     * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
     * DES_encrypt1() DES_encrypt1() except faster :-).
      }
  procedure DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
(* Const before type ignored *)
  function DES_fcrypt(buf:PIdAnsiChar; salt:PIdAnsiChar; ret:PIdAnsiChar): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
(* Const before type ignored *)
  function DES_crypt(buf:PIdAnsiChar; salt:PIdAnsiChar): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  function DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock):DES_LONG cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function DES_random_key(ret:PDES_cblock):longint cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure DES_set_odd_parity(key:PDES_cblock) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function DES_check_key_parity(key:Pconst_DES_cblock):longint cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function DES_is_weak_key(key:Pconst_DES_cblock):longint cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

    {
     * DES_set_key (= set_key = DES_key_sched = key_sched) calls
     * DES_set_key_checked if global variable DES_check_key is set,
     * DES_set_key_unchecked otherwise.
      }
  function DES_set_key(key:Pconst_DES_cblock; var schedule: DES_key_schedule):longint cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule):longint cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule):longint cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  procedure DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_string_to_key(str:PIdAnsiChar; key:PDES_cblock) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_string_to_2keys(str:PIdAnsiChar; key1:PDES_cblock; key2:PDES_cblock) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

(* Const before type ignored *)
  procedure DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};


    procedure DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint);  {removed 1.0.0}
    procedure DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint);  {removed 1.0.0}
    procedure DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint);  {removed 1.0.0}
    procedure DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint);  {removed 1.0.0}
    procedure DES_fixup_key_parity(key: PDES_cblock); {removed 1.0.0}
{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF USE_EXTERNAL_LIBRARY}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  
const
  DES_ecb2_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_ede2_cbc_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_ede2_cfb64_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_ede2_ofb64_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_fixup_key_parity_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);

{$IFNDEF USE_EXTERNAL_LIBRARY}
const
  DES_ecb2_encrypt_procname = 'DES_ecb2_encrypt';  {removed 1.0.0}
  DES_ede2_cbc_encrypt_procname = 'DES_ede2_cbc_encrypt';  {removed 1.0.0}
  DES_ede2_cfb64_encrypt_procname = 'DES_ede2_cfb64_encrypt';  {removed 1.0.0}
  DES_ede2_ofb64_encrypt_procname = 'DES_ede2_ofb64_encrypt';  {removed 1.0.0}


(* Const before type ignored *)
  DES_options_procname = 'DES_options';

  DES_ecb3_encrypt_procname = 'DES_ecb3_encrypt';

(* Const before type ignored *)
  DES_cbc_cksum_procname = 'DES_cbc_cksum';

    { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead.  }
(* Const before type ignored *)
  DES_cbc_encrypt_procname = 'DES_cbc_encrypt';

(* Const before type ignored *)
  DES_ncbc_encrypt_procname = 'DES_ncbc_encrypt';

(* Const before type ignored *)
  DES_xcbc_encrypt_procname = 'DES_xcbc_encrypt';

(* Const before type ignored *)
  DES_cfb_encrypt_procname = 'DES_cfb_encrypt';

  DES_ecb_encrypt_procname = 'DES_ecb_encrypt'; 
   {
     * This is the DES encryption function that gets called by just about every
     * other DES routine in the library.  You should not use this function except
     * to implement 'modes' of DES.  I say this because the functions that call
     * this routine do the conversion from 'char *' to long, and this needs to be
     * done to make sure 'non-aligned' memory access do not occur.  The
     * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
     * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
     * encryption, zero if decryption.
      }
  DES_encrypt1_procname = 'DES_encrypt1';

    {
     * This functions is the same as DES_encrypt1() except that the DES initial
     * permutation (IP) and final permutation (FP) have been left out.  As for
     * DES_encrypt1(), you should not use this function. It is used by the
     * routines in the library that implement triple DES. IP() DES_encrypt2()
     * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
     * DES_encrypt1() DES_encrypt1() except faster :-).
      }
  DES_encrypt2_procname = 'DES_encrypt2';

  DES_encrypt3_procname = 'DES_encrypt3';

  DES_decrypt3_procname = 'DES_decrypt3';

(* Const before type ignored *)
  DES_ede3_cbc_encrypt_procname = 'DES_ede3_cbc_encrypt';

(* Const before type ignored *)
  DES_ede3_cfb64_encrypt_procname = 'DES_ede3_cfb64_encrypt';

(* Const before type ignored *)
  DES_ede3_cfb_encrypt_procname = 'DES_ede3_cfb_encrypt';

(* Const before type ignored *)
  DES_ede3_ofb64_encrypt_procname = 'DES_ede3_ofb64_encrypt';

(* Const before type ignored *)
(* Const before type ignored *)
  DES_fcrypt_procname = 'DES_fcrypt';

(* Const before type ignored *)
(* Const before type ignored *)
  DES_crypt_procname = 'DES_crypt';

(* Const before type ignored *)
  DES_ofb_encrypt_procname = 'DES_ofb_encrypt';

(* Const before type ignored *)
  DES_pcbc_encrypt_procname = 'DES_pcbc_encrypt';

(* Const before type ignored *)
  DES_quad_cksum_procname = 'DES_quad_cksum';

  DES_random_key_procname = 'DES_random_key';

  DES_set_odd_parity_procname = 'DES_set_odd_parity';

  DES_check_key_parity_procname = 'DES_check_key_parity';

  DES_is_weak_key_procname = 'DES_is_weak_key';

    {
     * DES_set_key (= set_key = DES_key_sched = key_sched) calls
     * DES_set_key_checked if global variable DES_check_key is set,
     * DES_set_key_unchecked otherwise.
      }
  DES_set_key_procname = 'DES_set_key';

  DES_key_sched_procname = 'DES_key_sched';

  DES_set_key_checked_procname = 'DES_set_key_checked';

  DES_set_key_unchecked_procname = 'DES_set_key_unchecked';

(* Const before type ignored *)
  DES_string_to_key_procname = 'DES_string_to_key';

(* Const before type ignored *)
  DES_string_to_2keys_procname = 'DES_string_to_2keys';

(* Const before type ignored *)
  DES_cfb64_encrypt_procname = 'DES_cfb64_encrypt';

(* Const before type ignored *)
  DES_ofb64_encrypt_procname = 'DES_ofb64_encrypt';

  DES_fixup_key_parity_procname = 'DES_fixup_key_parity'; {removed 1.0.0}


procedure  _DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: longint); cdecl;
    begin
      DES_ecb3_encrypt(input,output,ks1,ks2,ks1,enc);
    end;

procedure  _DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; enc: longint); cdecl;
    begin
      DES_ede3_cbc_encrypt(input,output,length,ks1,ks2,ks1,ivec,enc);
    end;

procedure  _DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint; enc: longint); cdecl;
    begin
      DES_ede3_cfb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num,enc);
    end;

procedure  _DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: longint; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock; num: Plongint); cdecl;
    begin
      DES_ede3_ofb64_encrypt(in_,out_,length,ks1,ks2,ks1,ivec,num);
    end;

procedure  _DES_fixup_key_parity(key:PDES_cblock); cdecl;
    begin
      DES_set_odd_parity(key);
   end;


{$WARN  NO_RETVAL OFF}
procedure  ERR_DES_ecb2_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ecb2_encrypt_procname);
end;

  
procedure  ERR_DES_ede2_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede2_cbc_encrypt_procname);
end;

  
procedure  ERR_DES_ede2_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede2_cfb64_encrypt_procname);
end;

  
procedure  ERR_DES_ede2_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede2_ofb64_encrypt_procname);
end;

  


(* Const before type ignored *)
function  ERR_DES_options: PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_options_procname);
end;



procedure  ERR_DES_ecb3_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ecb3_encrypt_procname);
end;



(* Const before type ignored *)
function  ERR_DES_cbc_cksum(input:Pbyte; output:PDES_cblock; length:longint; schedule:PDES_key_schedule; ivec:Pconst_DES_cblock):DES_LONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_cbc_cksum_procname);
end;



    { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead.  }
(* Const before type ignored *)
procedure  ERR_DES_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_cbc_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ncbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ncbc_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_xcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; inw:Pconst_DES_cblock; outw:Pconst_DES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_xcbc_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_cfb_encrypt_procname);
end;



procedure  ERR_DES_ecb_encrypt(input:Pconst_DES_cblock; output:PDES_cblock; ks:PDES_key_schedule; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ecb_encrypt_procname);
end;

 
   {
     * This is the DES encryption function that gets called by just about every
     * other DES routine in the library.  You should not use this function except
     * to implement 'modes' of DES.  I say this because the functions that call
     * this routine do the conversion from 'char *' to long, and this needs to be
     * done to make sure 'non-aligned' memory access do not occur.  The
     * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
     * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
     * encryption, zero if decryption.
      }
procedure  ERR_DES_encrypt1(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_encrypt1_procname);
end;



    {
     * This functions is the same as DES_encrypt1() except that the DES initial
     * permutation (IP) and final permutation (FP) have been left out.  As for
     * DES_encrypt1(), you should not use this function. It is used by the
     * routines in the library that implement triple DES. IP() DES_encrypt2()
     * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
     * DES_encrypt1() DES_encrypt1() except faster :-).
      }
procedure  ERR_DES_encrypt2(data:PDES_LONG; ks:PDES_key_schedule; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_encrypt2_procname);
end;



procedure  ERR_DES_encrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_encrypt3_procname);
end;



procedure  ERR_DES_decrypt3(data:PDES_LONG; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_decrypt3_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ede3_cbc_encrypt(input:Pbyte; output:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede3_cbc_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ede3_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede3_cfb64_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ede3_cfb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede3_cfb_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ede3_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; ks1:PDES_key_schedule; ks2:PDES_key_schedule; ks3:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ede3_ofb64_encrypt_procname);
end;



(* Const before type ignored *)
(* Const before type ignored *)
function  ERR_DES_fcrypt(buf:PIdAnsiChar; salt:PIdAnsiChar; ret:PIdAnsiChar): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_fcrypt_procname);
end;



(* Const before type ignored *)
(* Const before type ignored *)
function  ERR_DES_crypt(buf:PIdAnsiChar; salt:PIdAnsiChar): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_crypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ofb_encrypt(in_:Pbyte; out_:Pbyte; numbits:longint; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ofb_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_pcbc_encrypt(input:Pbyte; output:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_pcbc_encrypt_procname);
end;



(* Const before type ignored *)
function  ERR_DES_quad_cksum(input:Pbyte; output:PDES_cblock; length:longint; out_count:longint; seed:PDES_cblock):DES_LONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_quad_cksum_procname);
end;



function  ERR_DES_random_key(ret:PDES_cblock):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_random_key_procname);
end;



procedure  ERR_DES_set_odd_parity(key:PDES_cblock); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_set_odd_parity_procname);
end;



function  ERR_DES_check_key_parity(key:Pconst_DES_cblock):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_check_key_parity_procname);
end;



function  ERR_DES_is_weak_key(key:Pconst_DES_cblock):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_is_weak_key_procname);
end;



    {
     * DES_set_key (= set_key = DES_key_sched = key_sched) calls
     * DES_set_key_checked if global variable DES_check_key is set,
     * DES_set_key_unchecked otherwise.
      }
function  ERR_DES_set_key(key:Pconst_DES_cblock; var schedule: DES_key_schedule):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_set_key_procname);
end;



function  ERR_DES_key_sched(key:Pconst_DES_cblock; schedule:PDES_key_schedule):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_key_sched_procname);
end;



function  ERR_DES_set_key_checked(key:Pconst_DES_cblock; schedule:PDES_key_schedule):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_set_key_checked_procname);
end;



procedure  ERR_DES_set_key_unchecked(key:Pconst_DES_cblock; schedule:PDES_key_schedule); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_set_key_unchecked_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_string_to_key(str:PIdAnsiChar; key:PDES_cblock); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_string_to_key_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_string_to_2keys(str:PIdAnsiChar; key1:PDES_cblock; key2:PDES_cblock); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_string_to_2keys_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_cfb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint; enc:longint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_cfb64_encrypt_procname);
end;



(* Const before type ignored *)
procedure  ERR_DES_ofb64_encrypt(in_:Pbyte; out_:Pbyte; length:longint; schedule:PDES_key_schedule; ivec:PDES_cblock; num:Plongint); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_ofb64_encrypt_procname);
end;



procedure  ERR_DES_fixup_key_parity(key: PDES_cblock); 
begin
  EIdAPIFunctionNotPresent.RaiseException(DES_fixup_key_parity_procname);
end;

 

{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  DES_ecb2_encrypt := LoadLibFunction(ADllHandle, DES_ecb2_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb2_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ecb2_encrypt_allownil)}
    DES_ecb2_encrypt := @ERR_DES_ecb2_encrypt;
    {$ifend}
    {$if declared(DES_ecb2_encrypt_introduced)}
    if LibVersion < DES_ecb2_encrypt_introduced then
    begin
      {$if declared(FC_DES_ecb2_encrypt)}
      DES_ecb2_encrypt := @FC_DES_ecb2_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ecb2_encrypt_removed)}
    if DES_ecb2_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ecb2_encrypt)}
      DES_ecb2_encrypt := @_DES_ecb2_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ecb2_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb2_encrypt');
    {$ifend}
  end;

  
  DES_ede2_cbc_encrypt := LoadLibFunction(ADllHandle, DES_ede2_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ede2_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede2_cbc_encrypt_allownil)}
    DES_ede2_cbc_encrypt := @ERR_DES_ede2_cbc_encrypt;
    {$ifend}
    {$if declared(DES_ede2_cbc_encrypt_introduced)}
    if LibVersion < DES_ede2_cbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede2_cbc_encrypt)}
      DES_ede2_cbc_encrypt := @FC_DES_ede2_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede2_cbc_encrypt_removed)}
    if DES_ede2_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede2_cbc_encrypt)}
      DES_ede2_cbc_encrypt := @_DES_ede2_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede2_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede2_cbc_encrypt');
    {$ifend}
  end;

  
  DES_ede2_cfb64_encrypt := LoadLibFunction(ADllHandle, DES_ede2_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede2_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede2_cfb64_encrypt_allownil)}
    DES_ede2_cfb64_encrypt := @ERR_DES_ede2_cfb64_encrypt;
    {$ifend}
    {$if declared(DES_ede2_cfb64_encrypt_introduced)}
    if LibVersion < DES_ede2_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede2_cfb64_encrypt)}
      DES_ede2_cfb64_encrypt := @FC_DES_ede2_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede2_cfb64_encrypt_removed)}
    if DES_ede2_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede2_cfb64_encrypt)}
      DES_ede2_cfb64_encrypt := @_DES_ede2_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede2_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede2_cfb64_encrypt');
    {$ifend}
  end;

  
  DES_ede2_ofb64_encrypt := LoadLibFunction(ADllHandle, DES_ede2_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede2_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede2_ofb64_encrypt_allownil)}
    DES_ede2_ofb64_encrypt := @ERR_DES_ede2_ofb64_encrypt;
    {$ifend}
    {$if declared(DES_ede2_ofb64_encrypt_introduced)}
    if LibVersion < DES_ede2_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede2_ofb64_encrypt)}
      DES_ede2_ofb64_encrypt := @FC_DES_ede2_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede2_ofb64_encrypt_removed)}
    if DES_ede2_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede2_ofb64_encrypt)}
      DES_ede2_ofb64_encrypt := @_DES_ede2_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede2_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede2_ofb64_encrypt');
    {$ifend}
  end;

  
  DES_options := LoadLibFunction(ADllHandle, DES_options_procname);
  FuncLoadError := not assigned(DES_options);
  if FuncLoadError then
  begin
    {$if not defined(DES_options_allownil)}
    DES_options := @ERR_DES_options;
    {$ifend}
    {$if declared(DES_options_introduced)}
    if LibVersion < DES_options_introduced then
    begin
      {$if declared(FC_DES_options)}
      DES_options := @FC_DES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_options_removed)}
    if DES_options_removed <= LibVersion then
    begin
      {$if declared(_DES_options)}
      DES_options := @_DES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_options_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_options');
    {$ifend}
  end;


  DES_ecb3_encrypt := LoadLibFunction(ADllHandle, DES_ecb3_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb3_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ecb3_encrypt_allownil)}
    DES_ecb3_encrypt := @ERR_DES_ecb3_encrypt;
    {$ifend}
    {$if declared(DES_ecb3_encrypt_introduced)}
    if LibVersion < DES_ecb3_encrypt_introduced then
    begin
      {$if declared(FC_DES_ecb3_encrypt)}
      DES_ecb3_encrypt := @FC_DES_ecb3_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ecb3_encrypt_removed)}
    if DES_ecb3_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ecb3_encrypt)}
      DES_ecb3_encrypt := @_DES_ecb3_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ecb3_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb3_encrypt');
    {$ifend}
  end;


  DES_cbc_cksum := LoadLibFunction(ADllHandle, DES_cbc_cksum_procname);
  FuncLoadError := not assigned(DES_cbc_cksum);
  if FuncLoadError then
  begin
    {$if not defined(DES_cbc_cksum_allownil)}
    DES_cbc_cksum := @ERR_DES_cbc_cksum;
    {$ifend}
    {$if declared(DES_cbc_cksum_introduced)}
    if LibVersion < DES_cbc_cksum_introduced then
    begin
      {$if declared(FC_DES_cbc_cksum)}
      DES_cbc_cksum := @FC_DES_cbc_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cbc_cksum_removed)}
    if DES_cbc_cksum_removed <= LibVersion then
    begin
      {$if declared(_DES_cbc_cksum)}
      DES_cbc_cksum := @_DES_cbc_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cbc_cksum_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cbc_cksum');
    {$ifend}
  end;


  DES_cbc_encrypt := LoadLibFunction(ADllHandle, DES_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_cbc_encrypt_allownil)}
    DES_cbc_encrypt := @ERR_DES_cbc_encrypt;
    {$ifend}
    {$if declared(DES_cbc_encrypt_introduced)}
    if LibVersion < DES_cbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_cbc_encrypt)}
      DES_cbc_encrypt := @FC_DES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cbc_encrypt_removed)}
    if DES_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_cbc_encrypt)}
      DES_cbc_encrypt := @_DES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cbc_encrypt');
    {$ifend}
  end;


  DES_ncbc_encrypt := LoadLibFunction(ADllHandle, DES_ncbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ncbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ncbc_encrypt_allownil)}
    DES_ncbc_encrypt := @ERR_DES_ncbc_encrypt;
    {$ifend}
    {$if declared(DES_ncbc_encrypt_introduced)}
    if LibVersion < DES_ncbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_ncbc_encrypt)}
      DES_ncbc_encrypt := @FC_DES_ncbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ncbc_encrypt_removed)}
    if DES_ncbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ncbc_encrypt)}
      DES_ncbc_encrypt := @_DES_ncbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ncbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ncbc_encrypt');
    {$ifend}
  end;


  DES_xcbc_encrypt := LoadLibFunction(ADllHandle, DES_xcbc_encrypt_procname);
  FuncLoadError := not assigned(DES_xcbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_xcbc_encrypt_allownil)}
    DES_xcbc_encrypt := @ERR_DES_xcbc_encrypt;
    {$ifend}
    {$if declared(DES_xcbc_encrypt_introduced)}
    if LibVersion < DES_xcbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_xcbc_encrypt)}
      DES_xcbc_encrypt := @FC_DES_xcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_xcbc_encrypt_removed)}
    if DES_xcbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_xcbc_encrypt)}
      DES_xcbc_encrypt := @_DES_xcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_xcbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_xcbc_encrypt');
    {$ifend}
  end;


  DES_cfb_encrypt := LoadLibFunction(ADllHandle, DES_cfb_encrypt_procname);
  FuncLoadError := not assigned(DES_cfb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_cfb_encrypt_allownil)}
    DES_cfb_encrypt := @ERR_DES_cfb_encrypt;
    {$ifend}
    {$if declared(DES_cfb_encrypt_introduced)}
    if LibVersion < DES_cfb_encrypt_introduced then
    begin
      {$if declared(FC_DES_cfb_encrypt)}
      DES_cfb_encrypt := @FC_DES_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cfb_encrypt_removed)}
    if DES_cfb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_cfb_encrypt)}
      DES_cfb_encrypt := @_DES_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cfb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cfb_encrypt');
    {$ifend}
  end;


  DES_ecb_encrypt := LoadLibFunction(ADllHandle, DES_ecb_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ecb_encrypt_allownil)}
    DES_ecb_encrypt := @ERR_DES_ecb_encrypt;
    {$ifend}
    {$if declared(DES_ecb_encrypt_introduced)}
    if LibVersion < DES_ecb_encrypt_introduced then
    begin
      {$if declared(FC_DES_ecb_encrypt)}
      DES_ecb_encrypt := @FC_DES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ecb_encrypt_removed)}
    if DES_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ecb_encrypt)}
      DES_ecb_encrypt := @_DES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb_encrypt');
    {$ifend}
  end;

 
  DES_encrypt1 := LoadLibFunction(ADllHandle, DES_encrypt1_procname);
  FuncLoadError := not assigned(DES_encrypt1);
  if FuncLoadError then
  begin
    {$if not defined(DES_encrypt1_allownil)}
    DES_encrypt1 := @ERR_DES_encrypt1;
    {$ifend}
    {$if declared(DES_encrypt1_introduced)}
    if LibVersion < DES_encrypt1_introduced then
    begin
      {$if declared(FC_DES_encrypt1)}
      DES_encrypt1 := @FC_DES_encrypt1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_encrypt1_removed)}
    if DES_encrypt1_removed <= LibVersion then
    begin
      {$if declared(_DES_encrypt1)}
      DES_encrypt1 := @_DES_encrypt1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_encrypt1_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt1');
    {$ifend}
  end;


  DES_encrypt2 := LoadLibFunction(ADllHandle, DES_encrypt2_procname);
  FuncLoadError := not assigned(DES_encrypt2);
  if FuncLoadError then
  begin
    {$if not defined(DES_encrypt2_allownil)}
    DES_encrypt2 := @ERR_DES_encrypt2;
    {$ifend}
    {$if declared(DES_encrypt2_introduced)}
    if LibVersion < DES_encrypt2_introduced then
    begin
      {$if declared(FC_DES_encrypt2)}
      DES_encrypt2 := @FC_DES_encrypt2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_encrypt2_removed)}
    if DES_encrypt2_removed <= LibVersion then
    begin
      {$if declared(_DES_encrypt2)}
      DES_encrypt2 := @_DES_encrypt2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_encrypt2_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt2');
    {$ifend}
  end;


  DES_encrypt3 := LoadLibFunction(ADllHandle, DES_encrypt3_procname);
  FuncLoadError := not assigned(DES_encrypt3);
  if FuncLoadError then
  begin
    {$if not defined(DES_encrypt3_allownil)}
    DES_encrypt3 := @ERR_DES_encrypt3;
    {$ifend}
    {$if declared(DES_encrypt3_introduced)}
    if LibVersion < DES_encrypt3_introduced then
    begin
      {$if declared(FC_DES_encrypt3)}
      DES_encrypt3 := @FC_DES_encrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_encrypt3_removed)}
    if DES_encrypt3_removed <= LibVersion then
    begin
      {$if declared(_DES_encrypt3)}
      DES_encrypt3 := @_DES_encrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_encrypt3_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt3');
    {$ifend}
  end;


  DES_decrypt3 := LoadLibFunction(ADllHandle, DES_decrypt3_procname);
  FuncLoadError := not assigned(DES_decrypt3);
  if FuncLoadError then
  begin
    {$if not defined(DES_decrypt3_allownil)}
    DES_decrypt3 := @ERR_DES_decrypt3;
    {$ifend}
    {$if declared(DES_decrypt3_introduced)}
    if LibVersion < DES_decrypt3_introduced then
    begin
      {$if declared(FC_DES_decrypt3)}
      DES_decrypt3 := @FC_DES_decrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_decrypt3_removed)}
    if DES_decrypt3_removed <= LibVersion then
    begin
      {$if declared(_DES_decrypt3)}
      DES_decrypt3 := @_DES_decrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_decrypt3_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_decrypt3');
    {$ifend}
  end;


  DES_ede3_cbc_encrypt := LoadLibFunction(ADllHandle, DES_ede3_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_cbc_encrypt_allownil)}
    DES_ede3_cbc_encrypt := @ERR_DES_ede3_cbc_encrypt;
    {$ifend}
    {$if declared(DES_ede3_cbc_encrypt_introduced)}
    if LibVersion < DES_ede3_cbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_cbc_encrypt)}
      DES_ede3_cbc_encrypt := @FC_DES_ede3_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_cbc_encrypt_removed)}
    if DES_ede3_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_cbc_encrypt)}
      DES_ede3_cbc_encrypt := @_DES_ede3_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cbc_encrypt');
    {$ifend}
  end;


  DES_ede3_cfb64_encrypt := LoadLibFunction(ADllHandle, DES_ede3_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_cfb64_encrypt_allownil)}
    DES_ede3_cfb64_encrypt := @ERR_DES_ede3_cfb64_encrypt;
    {$ifend}
    {$if declared(DES_ede3_cfb64_encrypt_introduced)}
    if LibVersion < DES_ede3_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_cfb64_encrypt)}
      DES_ede3_cfb64_encrypt := @FC_DES_ede3_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_cfb64_encrypt_removed)}
    if DES_ede3_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_cfb64_encrypt)}
      DES_ede3_cfb64_encrypt := @_DES_ede3_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cfb64_encrypt');
    {$ifend}
  end;


  DES_ede3_cfb_encrypt := LoadLibFunction(ADllHandle, DES_ede3_cfb_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cfb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_cfb_encrypt_allownil)}
    DES_ede3_cfb_encrypt := @ERR_DES_ede3_cfb_encrypt;
    {$ifend}
    {$if declared(DES_ede3_cfb_encrypt_introduced)}
    if LibVersion < DES_ede3_cfb_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_cfb_encrypt)}
      DES_ede3_cfb_encrypt := @FC_DES_ede3_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_cfb_encrypt_removed)}
    if DES_ede3_cfb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_cfb_encrypt)}
      DES_ede3_cfb_encrypt := @_DES_ede3_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_cfb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cfb_encrypt');
    {$ifend}
  end;


  DES_ede3_ofb64_encrypt := LoadLibFunction(ADllHandle, DES_ede3_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_ofb64_encrypt_allownil)}
    DES_ede3_ofb64_encrypt := @ERR_DES_ede3_ofb64_encrypt;
    {$ifend}
    {$if declared(DES_ede3_ofb64_encrypt_introduced)}
    if LibVersion < DES_ede3_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_ofb64_encrypt)}
      DES_ede3_ofb64_encrypt := @FC_DES_ede3_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_ofb64_encrypt_removed)}
    if DES_ede3_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_ofb64_encrypt)}
      DES_ede3_ofb64_encrypt := @_DES_ede3_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_ofb64_encrypt');
    {$ifend}
  end;


  DES_fcrypt := LoadLibFunction(ADllHandle, DES_fcrypt_procname);
  FuncLoadError := not assigned(DES_fcrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_fcrypt_allownil)}
    DES_fcrypt := @ERR_DES_fcrypt;
    {$ifend}
    {$if declared(DES_fcrypt_introduced)}
    if LibVersion < DES_fcrypt_introduced then
    begin
      {$if declared(FC_DES_fcrypt)}
      DES_fcrypt := @FC_DES_fcrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_fcrypt_removed)}
    if DES_fcrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_fcrypt)}
      DES_fcrypt := @_DES_fcrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_fcrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_fcrypt');
    {$ifend}
  end;


  DES_crypt := LoadLibFunction(ADllHandle, DES_crypt_procname);
  FuncLoadError := not assigned(DES_crypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_crypt_allownil)}
    DES_crypt := @ERR_DES_crypt;
    {$ifend}
    {$if declared(DES_crypt_introduced)}
    if LibVersion < DES_crypt_introduced then
    begin
      {$if declared(FC_DES_crypt)}
      DES_crypt := @FC_DES_crypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_crypt_removed)}
    if DES_crypt_removed <= LibVersion then
    begin
      {$if declared(_DES_crypt)}
      DES_crypt := @_DES_crypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_crypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_crypt');
    {$ifend}
  end;


  DES_ofb_encrypt := LoadLibFunction(ADllHandle, DES_ofb_encrypt_procname);
  FuncLoadError := not assigned(DES_ofb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ofb_encrypt_allownil)}
    DES_ofb_encrypt := @ERR_DES_ofb_encrypt;
    {$ifend}
    {$if declared(DES_ofb_encrypt_introduced)}
    if LibVersion < DES_ofb_encrypt_introduced then
    begin
      {$if declared(FC_DES_ofb_encrypt)}
      DES_ofb_encrypt := @FC_DES_ofb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ofb_encrypt_removed)}
    if DES_ofb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ofb_encrypt)}
      DES_ofb_encrypt := @_DES_ofb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ofb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ofb_encrypt');
    {$ifend}
  end;


  DES_pcbc_encrypt := LoadLibFunction(ADllHandle, DES_pcbc_encrypt_procname);
  FuncLoadError := not assigned(DES_pcbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_pcbc_encrypt_allownil)}
    DES_pcbc_encrypt := @ERR_DES_pcbc_encrypt;
    {$ifend}
    {$if declared(DES_pcbc_encrypt_introduced)}
    if LibVersion < DES_pcbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_pcbc_encrypt)}
      DES_pcbc_encrypt := @FC_DES_pcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_pcbc_encrypt_removed)}
    if DES_pcbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_pcbc_encrypt)}
      DES_pcbc_encrypt := @_DES_pcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_pcbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_pcbc_encrypt');
    {$ifend}
  end;


  DES_quad_cksum := LoadLibFunction(ADllHandle, DES_quad_cksum_procname);
  FuncLoadError := not assigned(DES_quad_cksum);
  if FuncLoadError then
  begin
    {$if not defined(DES_quad_cksum_allownil)}
    DES_quad_cksum := @ERR_DES_quad_cksum;
    {$ifend}
    {$if declared(DES_quad_cksum_introduced)}
    if LibVersion < DES_quad_cksum_introduced then
    begin
      {$if declared(FC_DES_quad_cksum)}
      DES_quad_cksum := @FC_DES_quad_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_quad_cksum_removed)}
    if DES_quad_cksum_removed <= LibVersion then
    begin
      {$if declared(_DES_quad_cksum)}
      DES_quad_cksum := @_DES_quad_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_quad_cksum_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_quad_cksum');
    {$ifend}
  end;


  DES_random_key := LoadLibFunction(ADllHandle, DES_random_key_procname);
  FuncLoadError := not assigned(DES_random_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_random_key_allownil)}
    DES_random_key := @ERR_DES_random_key;
    {$ifend}
    {$if declared(DES_random_key_introduced)}
    if LibVersion < DES_random_key_introduced then
    begin
      {$if declared(FC_DES_random_key)}
      DES_random_key := @FC_DES_random_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_random_key_removed)}
    if DES_random_key_removed <= LibVersion then
    begin
      {$if declared(_DES_random_key)}
      DES_random_key := @_DES_random_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_random_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_random_key');
    {$ifend}
  end;


  DES_set_odd_parity := LoadLibFunction(ADllHandle, DES_set_odd_parity_procname);
  FuncLoadError := not assigned(DES_set_odd_parity);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_odd_parity_allownil)}
    DES_set_odd_parity := @ERR_DES_set_odd_parity;
    {$ifend}
    {$if declared(DES_set_odd_parity_introduced)}
    if LibVersion < DES_set_odd_parity_introduced then
    begin
      {$if declared(FC_DES_set_odd_parity)}
      DES_set_odd_parity := @FC_DES_set_odd_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_odd_parity_removed)}
    if DES_set_odd_parity_removed <= LibVersion then
    begin
      {$if declared(_DES_set_odd_parity)}
      DES_set_odd_parity := @_DES_set_odd_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_odd_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_odd_parity');
    {$ifend}
  end;


  DES_check_key_parity := LoadLibFunction(ADllHandle, DES_check_key_parity_procname);
  FuncLoadError := not assigned(DES_check_key_parity);
  if FuncLoadError then
  begin
    {$if not defined(DES_check_key_parity_allownil)}
    DES_check_key_parity := @ERR_DES_check_key_parity;
    {$ifend}
    {$if declared(DES_check_key_parity_introduced)}
    if LibVersion < DES_check_key_parity_introduced then
    begin
      {$if declared(FC_DES_check_key_parity)}
      DES_check_key_parity := @FC_DES_check_key_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_check_key_parity_removed)}
    if DES_check_key_parity_removed <= LibVersion then
    begin
      {$if declared(_DES_check_key_parity)}
      DES_check_key_parity := @_DES_check_key_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_check_key_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_check_key_parity');
    {$ifend}
  end;


  DES_is_weak_key := LoadLibFunction(ADllHandle, DES_is_weak_key_procname);
  FuncLoadError := not assigned(DES_is_weak_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_is_weak_key_allownil)}
    DES_is_weak_key := @ERR_DES_is_weak_key;
    {$ifend}
    {$if declared(DES_is_weak_key_introduced)}
    if LibVersion < DES_is_weak_key_introduced then
    begin
      {$if declared(FC_DES_is_weak_key)}
      DES_is_weak_key := @FC_DES_is_weak_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_is_weak_key_removed)}
    if DES_is_weak_key_removed <= LibVersion then
    begin
      {$if declared(_DES_is_weak_key)}
      DES_is_weak_key := @_DES_is_weak_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_is_weak_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_is_weak_key');
    {$ifend}
  end;


  DES_set_key := LoadLibFunction(ADllHandle, DES_set_key_procname);
  FuncLoadError := not assigned(DES_set_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_key_allownil)}
    DES_set_key := @ERR_DES_set_key;
    {$ifend}
    {$if declared(DES_set_key_introduced)}
    if LibVersion < DES_set_key_introduced then
    begin
      {$if declared(FC_DES_set_key)}
      DES_set_key := @FC_DES_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_key_removed)}
    if DES_set_key_removed <= LibVersion then
    begin
      {$if declared(_DES_set_key)}
      DES_set_key := @_DES_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key');
    {$ifend}
  end;


  DES_key_sched := LoadLibFunction(ADllHandle, DES_key_sched_procname);
  FuncLoadError := not assigned(DES_key_sched);
  if FuncLoadError then
  begin
    {$if not defined(DES_key_sched_allownil)}
    DES_key_sched := @ERR_DES_key_sched;
    {$ifend}
    {$if declared(DES_key_sched_introduced)}
    if LibVersion < DES_key_sched_introduced then
    begin
      {$if declared(FC_DES_key_sched)}
      DES_key_sched := @FC_DES_key_sched;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_key_sched_removed)}
    if DES_key_sched_removed <= LibVersion then
    begin
      {$if declared(_DES_key_sched)}
      DES_key_sched := @_DES_key_sched;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_key_sched_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_key_sched');
    {$ifend}
  end;


  DES_set_key_checked := LoadLibFunction(ADllHandle, DES_set_key_checked_procname);
  FuncLoadError := not assigned(DES_set_key_checked);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_key_checked_allownil)}
    DES_set_key_checked := @ERR_DES_set_key_checked;
    {$ifend}
    {$if declared(DES_set_key_checked_introduced)}
    if LibVersion < DES_set_key_checked_introduced then
    begin
      {$if declared(FC_DES_set_key_checked)}
      DES_set_key_checked := @FC_DES_set_key_checked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_key_checked_removed)}
    if DES_set_key_checked_removed <= LibVersion then
    begin
      {$if declared(_DES_set_key_checked)}
      DES_set_key_checked := @_DES_set_key_checked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_key_checked_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key_checked');
    {$ifend}
  end;


  DES_set_key_unchecked := LoadLibFunction(ADllHandle, DES_set_key_unchecked_procname);
  FuncLoadError := not assigned(DES_set_key_unchecked);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_key_unchecked_allownil)}
    DES_set_key_unchecked := @ERR_DES_set_key_unchecked;
    {$ifend}
    {$if declared(DES_set_key_unchecked_introduced)}
    if LibVersion < DES_set_key_unchecked_introduced then
    begin
      {$if declared(FC_DES_set_key_unchecked)}
      DES_set_key_unchecked := @FC_DES_set_key_unchecked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_key_unchecked_removed)}
    if DES_set_key_unchecked_removed <= LibVersion then
    begin
      {$if declared(_DES_set_key_unchecked)}
      DES_set_key_unchecked := @_DES_set_key_unchecked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_key_unchecked_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key_unchecked');
    {$ifend}
  end;


  DES_string_to_key := LoadLibFunction(ADllHandle, DES_string_to_key_procname);
  FuncLoadError := not assigned(DES_string_to_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_string_to_key_allownil)}
    DES_string_to_key := @ERR_DES_string_to_key;
    {$ifend}
    {$if declared(DES_string_to_key_introduced)}
    if LibVersion < DES_string_to_key_introduced then
    begin
      {$if declared(FC_DES_string_to_key)}
      DES_string_to_key := @FC_DES_string_to_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_string_to_key_removed)}
    if DES_string_to_key_removed <= LibVersion then
    begin
      {$if declared(_DES_string_to_key)}
      DES_string_to_key := @_DES_string_to_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_string_to_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_string_to_key');
    {$ifend}
  end;


  DES_string_to_2keys := LoadLibFunction(ADllHandle, DES_string_to_2keys_procname);
  FuncLoadError := not assigned(DES_string_to_2keys);
  if FuncLoadError then
  begin
    {$if not defined(DES_string_to_2keys_allownil)}
    DES_string_to_2keys := @ERR_DES_string_to_2keys;
    {$ifend}
    {$if declared(DES_string_to_2keys_introduced)}
    if LibVersion < DES_string_to_2keys_introduced then
    begin
      {$if declared(FC_DES_string_to_2keys)}
      DES_string_to_2keys := @FC_DES_string_to_2keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_string_to_2keys_removed)}
    if DES_string_to_2keys_removed <= LibVersion then
    begin
      {$if declared(_DES_string_to_2keys)}
      DES_string_to_2keys := @_DES_string_to_2keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_string_to_2keys_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_string_to_2keys');
    {$ifend}
  end;


  DES_cfb64_encrypt := LoadLibFunction(ADllHandle, DES_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_cfb64_encrypt_allownil)}
    DES_cfb64_encrypt := @ERR_DES_cfb64_encrypt;
    {$ifend}
    {$if declared(DES_cfb64_encrypt_introduced)}
    if LibVersion < DES_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_cfb64_encrypt)}
      DES_cfb64_encrypt := @FC_DES_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cfb64_encrypt_removed)}
    if DES_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_cfb64_encrypt)}
      DES_cfb64_encrypt := @_DES_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cfb64_encrypt');
    {$ifend}
  end;


  DES_ofb64_encrypt := LoadLibFunction(ADllHandle, DES_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ofb64_encrypt_allownil)}
    DES_ofb64_encrypt := @ERR_DES_ofb64_encrypt;
    {$ifend}
    {$if declared(DES_ofb64_encrypt_introduced)}
    if LibVersion < DES_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ofb64_encrypt)}
      DES_ofb64_encrypt := @FC_DES_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ofb64_encrypt_removed)}
    if DES_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ofb64_encrypt)}
      DES_ofb64_encrypt := @_DES_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ofb64_encrypt');
    {$ifend}
  end;


  DES_fixup_key_parity := LoadLibFunction(ADllHandle, DES_fixup_key_parity_procname);
  FuncLoadError := not assigned(DES_fixup_key_parity);
  if FuncLoadError then
  begin
    {$if not defined(DES_fixup_key_parity_allownil)}
    DES_fixup_key_parity := @ERR_DES_fixup_key_parity;
    {$ifend}
    {$if declared(DES_fixup_key_parity_introduced)}
    if LibVersion < DES_fixup_key_parity_introduced then
    begin
      {$if declared(FC_DES_fixup_key_parity)}
      DES_fixup_key_parity := @FC_DES_fixup_key_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_fixup_key_parity_removed)}
    if DES_fixup_key_parity_removed <= LibVersion then
    begin
      {$if declared(_DES_fixup_key_parity)}
      DES_fixup_key_parity := @_DES_fixup_key_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_fixup_key_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_fixup_key_parity');
    {$ifend}
  end;

 
end;

procedure Unload;
begin
  DES_ecb2_encrypt := nil;  {removed 1.0.0}
  DES_ede2_cbc_encrypt := nil;  {removed 1.0.0}
  DES_ede2_cfb64_encrypt := nil;  {removed 1.0.0}
  DES_ede2_ofb64_encrypt := nil;  {removed 1.0.0}
  DES_options := nil;
  DES_ecb3_encrypt := nil;
  DES_cbc_cksum := nil;
  DES_cbc_encrypt := nil;
  DES_ncbc_encrypt := nil;
  DES_xcbc_encrypt := nil;
  DES_cfb_encrypt := nil;
  DES_ecb_encrypt := nil; 
  DES_encrypt1 := nil;
  DES_encrypt2 := nil;
  DES_encrypt3 := nil;
  DES_decrypt3 := nil;
  DES_ede3_cbc_encrypt := nil;
  DES_ede3_cfb64_encrypt := nil;
  DES_ede3_cfb_encrypt := nil;
  DES_ede3_ofb64_encrypt := nil;
  DES_fcrypt := nil;
  DES_crypt := nil;
  DES_ofb_encrypt := nil;
  DES_pcbc_encrypt := nil;
  DES_quad_cksum := nil;
  DES_random_key := nil;
  DES_set_odd_parity := nil;
  DES_check_key_parity := nil;
  DES_is_weak_key := nil;
  DES_set_key := nil;
  DES_key_sched := nil;
  DES_set_key_checked := nil;
  DES_set_key_unchecked := nil;
  DES_string_to_key := nil;
  DES_string_to_2keys := nil;
  DES_cfb64_encrypt := nil;
  DES_ofb64_encrypt := nil;
  DES_fixup_key_parity := nil; {removed 1.0.0}
end;
{$ELSE}
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


{$ENDIF}

{$IFNDEF USE_EXTERNAL_LIBRARY}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
