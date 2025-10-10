(* This unit was generated from the source file crypto.h2pas 
It should not be modified directly. All changes should be made to crypto.h2pas
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


unit IdOpenSSLHeaders_crypto;


interface

// Headers for OpenSSL 1.1.1
// crypto.h

{$J+}
{$J+}

uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_provider,
  Types;

{$MINENUMSIZE 4}

const
  CRYPTO_MEM_CHECK_OFF = $0;   //* Control only */
  CRYPTO_MEM_CHECK_ON = $1;   //* Control and mode bit */
  CRYPTO_MEM_CHECK_ENABLE = $2;   //* Control and mode bit */
  CRYPTO_MEM_CHECK_DISABLE = $3;   //* Control only */

  CRYPTO_EX_INDEX_SSL = 0;
  CRYPTO_EX_INDEX_SSL_CTX = 1;
  CRYPTO_EX_INDEX_SSL_SESSION = 2;
  CRYPTO_EX_INDEX_X509 = 3;
  CRYPTO_EX_INDEX_X509_STORE = 4;
  CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
  CRYPTO_EX_INDEX_DH = 6;
  CRYPTO_EX_INDEX_DSA = 7;
  CRYPTO_EX_INDEX_EC_KEY = 8;
  CRYPTO_EX_INDEX_RSA = 9;
  CRYPTO_EX_INDEX_ENGINE = 10;
  CRYPTO_EX_INDEX_UI = 11;
  CRYPTO_EX_INDEX_BIO = 12;
  CRYPTO_EX_INDEX_APP = 13;
  CRYPTO_EX_INDEX_UI_METHOD = 14;
  CRYPTO_EX_INDEX_DRBG = 15;
  CRYPTO_EX_INDEX__COUNT = 16;
  
  // Added _CONST to prevent nameclashes
  OPENSSL_VERSION_CONST = 0;
  OPENSSL_CFLAGS = 1;
  OPENSSL_BUILT_ON = 2;
  OPENSSL_PLATFORM = 3;
  OPENSSL_DIR = 4;
  OPENSSL_ENGINES_DIR = 5;
  SSLEAY_VERSION_CONST = OPENSSL_VERSION_CONST;

  (*
   * These defines where used in combination with the old locking callbacks,
   * they are not called anymore, but old code that's not called might still
   * use them.
   *)
  CRYPTO_LOCK = 1;
  CRYPTO_UNLOCK = 2;
  CRYPTO_READ = 4;
  CRYPTO_WRITE = 8;

  (* Standard initialisation options *)
  OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = TOpenSSL_C_Long($00000001);
  OPENSSL_INIT_LOAD_CRYPTO_STRINGS = TOpenSSL_C_Long($00000002);
  OPENSSL_INIT_ADD_ALL_CIPHERS = TOpenSSL_C_Long($00000004);
  OPENSSL_INIT_ADD_ALL_DIGESTS = TOpenSSL_C_Long($00000008);
  OPENSSL_INIT_NO_ADD_ALL_CIPHERS = TOpenSSL_C_Long($00000010);
  OPENSSL_INIT_NO_ADD_ALL_DIGESTS = TOpenSSL_C_Long($00000020);
  OPENSSL_INIT_LOAD_CONFIG = TOpenSSL_C_Long($00000040);
  OPENSSL_INIT_NO_LOAD_CONFIG = TOpenSSL_C_Long($00000080);
  OPENSSL_INIT_ASYNC = TOpenSSL_C_Long($00000100);
  OPENSSL_INIT_ENGINE_RDRAND = TOpenSSL_C_Long($00000200);
  OPENSSL_INIT_ENGINE_DYNAMIC = TOpenSSL_C_Long($00000400);
  OPENSSL_INIT_ENGINE_OPENSSL = TOpenSSL_C_Long($00000800);
  OPENSSL_INIT_ENGINE_CRYPTODEV = TOpenSSL_C_Long($00001000);
  OPENSSL_INIT_ENGINE_CAPI = TOpenSSL_C_Long($00002000);
  OPENSSL_INIT_ENGINE_PADLOCK = TOpenSSL_C_Long($00004000);
  OPENSSL_INIT_ENGINE_AFALG = TOpenSSL_C_Long($00008000);
  (* OPENSSL_INIT_ZLIB = TOpenSSL_C_Long($00010000); *)
  OPENSSL_INIT_ATFORK = TOpenSSL_C_Long(00020000);
  (* OPENSSL_INIT_BASE_ONLY = TOpenSSL_C_Long(00040000); *)
  OPENSSL_INIT_NO_ATEXIT = TOpenSSL_C_Long(00080000);
  (* OPENSSL_INIT flag range 0xfff00000 reserved for OPENSSL_init_ssl() *)
  (* Max OPENSSL_INIT flag value is 0x80000000 *)

  (* openssl and dasync not counted as builtin *)
  OPENSSL_INIT_ENGINE_ALL_BUILTIN = OPENSSL_INIT_ENGINE_RDRAND
    or OPENSSL_INIT_ENGINE_DYNAMIC or OPENSSL_INIT_ENGINE_CRYPTODEV
    or OPENSSL_INIT_ENGINE_CAPI or OPENSSL_INIT_ENGINE_PADLOCK;

  CRYPTO_ONCE_STATIC_INIT = 0;

type
  CRYPTO_THREADID = record {1.0.x only}
    ptr : Pointer;
    val : TOpenSSL_C_ULONG;
  end;
  PCRYPTO_THREADID = ^CRYPTO_THREADID;
  CRYPTO_RWLOCK = type Pointer;
  PCRYPTO_RWLOCK = ^CRYPTO_RWLOCK;
  //crypto_ex_data_st = record
  //  sk: PStackOfVoid;
  //end;
  //DEFINE_STACK_OF(void)

  Tthreadid_func = procedure (id : PCRYPTO_THREADID) cdecl;    


  // CRYPTO_EX_new = procedure(parent: Pointer; ptr: Pointer; CRYPTO_EX_DATA *ad; idx: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; argp: Pointer);
  //  CRYPTO_EX_free = procedure(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
  //                             int idx, long argl, void *argp);
  //typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
  //                           void *from_d, int idx, long argl, void *argp);
  //__owur int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
  //                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
  //                            CRYPTO_EX_free *free_func);

  CRYPTO_mem_leaks_cb_cb = function(const str: PAnsiChar; len: TOpenSSL_C_SIZET; u: Pointer): TOpenSSL_C_INT; cdecl;
  CRYPTO_THREAD_run_once_init = procedure; cdecl;

  CRYPTO_THREAD_LOCAL = type DWORD;
  PCRYPTO_THREAD_LOCAL = ^CRYPTO_THREAD_LOCAL;
  CRYPTO_THREAD_ID = type DWORD;
  CRYPTO_ONCE = type TOpenSSL_C_LONG;
  PCRYPTO_ONCE = ^CRYPTO_ONCE;

  CRYPTO_set_mem_functions_m = function(size: TOpenSSL_C_SIZET; const filename: PAnsiChar; linenumber: TOpenSSL_C_INT): Pointer; cdecl;
  CRYPTO_set_mem_functions_r = function(buffer: Pointer; size: TOpenSSL_C_SIZET; const filename: PAnsiChar; linenumber: TOpenSSL_C_INT): Pointer; cdecl;
  CRYPTO_set_mem_functions_f = procedure(buffer: Pointer; const filename: PAnsiChar; const linenumber: TOpenSSL_C_INT); cdecl;
  TIdSslIdCallback = function: TOpenSSL_C_ULONG; cdecl;
  TIdSslLockingCallback = procedure (mode, n : TOpenSSL_C_INT; Afile : PAnsiChar; line : TOpenSSL_C_INT); cdecl;



procedure SetLegacyCallbacks;
procedure RemoveLegacyCallbacks;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CRYPTO_THREAD_lock_new}
{$EXTERNALSYM CRYPTO_THREAD_read_lock}
{$EXTERNALSYM CRYPTO_THREAD_write_lock}
{$EXTERNALSYM CRYPTO_THREAD_unlock}
{$EXTERNALSYM CRYPTO_THREAD_lock_free}
{$EXTERNALSYM CRYPTO_atomic_add}
{$EXTERNALSYM OPENSSL_strlcpy}
{$EXTERNALSYM OPENSSL_strlcat}
{$EXTERNALSYM OPENSSL_strnlen}
{$EXTERNALSYM OPENSSL_buf2hexstr}
{$EXTERNALSYM OPENSSL_hexstr2buf}
{$EXTERNALSYM OPENSSL_hexchar2int}
{$EXTERNALSYM OpenSSL_version_num}
{$EXTERNALSYM OpenSSL_version}
{$EXTERNALSYM OPENSSL_issetugid}
{$EXTERNALSYM CRYPTO_new_ex_data}
{$EXTERNALSYM CRYPTO_dup_ex_data}
{$EXTERNALSYM CRYPTO_free_ex_data}
{$EXTERNALSYM CRYPTO_set_ex_data}
{$EXTERNALSYM CRYPTO_get_ex_data}
{$EXTERNALSYM CRYPTO_set_mem_functions}
{$EXTERNALSYM CRYPTO_malloc}
{$EXTERNALSYM CRYPTO_zalloc}
{$EXTERNALSYM CRYPTO_memdup}
{$EXTERNALSYM CRYPTO_strdup}
{$EXTERNALSYM CRYPTO_strndup}
{$EXTERNALSYM CRYPTO_free}
{$EXTERNALSYM CRYPTO_clear_free}
{$EXTERNALSYM CRYPTO_realloc}
{$EXTERNALSYM CRYPTO_clear_realloc}
{$EXTERNALSYM CRYPTO_secure_malloc_init}
{$EXTERNALSYM CRYPTO_secure_malloc_done}
{$EXTERNALSYM CRYPTO_secure_malloc}
{$EXTERNALSYM CRYPTO_secure_zalloc}
{$EXTERNALSYM CRYPTO_secure_free}
{$EXTERNALSYM CRYPTO_secure_clear_free}
{$EXTERNALSYM CRYPTO_secure_allocated}
{$EXTERNALSYM CRYPTO_secure_malloc_initialized}
{$EXTERNALSYM CRYPTO_secure_actual_size}
{$EXTERNALSYM CRYPTO_secure_used}
{$EXTERNALSYM OPENSSL_cleanse}
{$EXTERNALSYM OPENSSL_isservice}
{$EXTERNALSYM OPENSSL_init}
{$EXTERNALSYM CRYPTO_memcmp}
{$EXTERNALSYM OPENSSL_cleanup}
{$EXTERNALSYM OPENSSL_init_crypto}
{$EXTERNALSYM OPENSSL_thread_stop}
{$EXTERNALSYM OPENSSL_INIT_new}
{$EXTERNALSYM OPENSSL_INIT_free}
{$EXTERNALSYM CRYPTO_THREAD_run_once}
{$EXTERNALSYM CRYPTO_THREAD_get_local}
{$EXTERNALSYM CRYPTO_THREAD_set_local}
{$EXTERNALSYM CRYPTO_THREAD_cleanup_local}
{$EXTERNALSYM CRYPTO_THREAD_get_current_id}
{$EXTERNALSYM CRYPTO_THREAD_compare_id}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl; external CLibCrypto;
function CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK); cdecl; external CLibCrypto;
function CRYPTO_atomic_add(val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OPENSSL_strlcpy(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OPENSSL_strlcat(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OPENSSL_strnlen(const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OPENSSL_buf2hexstr(const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl; external CLibCrypto;
function OPENSSL_hexstr2buf(const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl; external CLibCrypto;
function OPENSSL_hexchar2int(c: Byte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function OpenSSL_version(type_: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OPENSSL_issetugid: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_new_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_dup_ex_data(class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CRYPTO_free_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl; external CLibCrypto;
function CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_memdup(const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_strdup(const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function CRYPTO_strndup(const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
procedure CRYPTO_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CRYPTO_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function CRYPTO_realloc(addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc_init(sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc_done: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_secure_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
procedure CRYPTO_secure_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CRYPTO_secure_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function CRYPTO_secure_allocated(const ptr: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc_initialized: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function CRYPTO_secure_used: TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
procedure OPENSSL_cleanse(ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;
function OPENSSL_isservice: TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_init; cdecl; external CLibCrypto;
function CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_cleanup; cdecl; external CLibCrypto;
function OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_thread_stop; cdecl; external CLibCrypto;
function OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl; external CLibCrypto;
procedure OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS); cdecl; external CLibCrypto;
function CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl; external CLibCrypto;
function CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID; cdecl; external CLibCrypto;
function CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl; external CLibCrypto;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
procedure OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); {removed 1.0.0}
procedure OPENSSL_free(addr: Pointer); {removed 1.0.0}
function OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; {removed 1.0.0}
function OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; {removed 1.0.0}
function OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
procedure OPENSSL_secure_free(addr: Pointer); {removed 1.0.0}
procedure OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); {removed 1.0.0}
function OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; {removed 1.0.0}
function FIPS_mode: TOpenSSL_C_INT; {removed 3.0.0}
function FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}

{Declare external function initialisers - should not be called directly}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
function Load_OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
function Load_OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl;
function Load_OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl;
procedure Load_OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;
procedure Load_OPENSSL_free(addr: Pointer); cdecl;
function Load_OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl;
function Load_OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; cdecl;
function Load_OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl;
function Load_OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
function Load_OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
procedure Load_OPENSSL_secure_free(addr: Pointer); cdecl;
procedure Load_OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;
function Load_OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl;
function Load_CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
procedure Load_CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK); cdecl;
function Load_CRYPTO_atomic_add(val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_CRYPTO_mem_ctrl(mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_OPENSSL_strlcpy(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_OPENSSL_strlcat(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_OPENSSL_strnlen(const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_OPENSSL_buf2hexstr(const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl;
function Load_OPENSSL_hexstr2buf(const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl;
function Load_OPENSSL_hexchar2int(c: Byte): TOpenSSL_C_INT; cdecl;
function Load_OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl;
function Load_OpenSSL_version(type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_OPENSSL_issetugid: TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_new_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_dup_ex_data(class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl;
procedure Load_CRYPTO_free_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl;
function Load_CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_CRYPTO_num_locks: TOpenSSL_C_INT; cdecl;
procedure Load_CRYPTO_set_locking_callback(func: TIdSslLockingCallback); cdecl;
procedure Load_CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl;
procedure Load_CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl;
procedure Load_CRYPTO_set_id_callback(func: TIdSslIdCallback); cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_CRYPTO_set_mem_debug(flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_CRYPTO_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CRYPTO_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CRYPTO_memdup(const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CRYPTO_strdup(const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_CRYPTO_strndup(const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl;
procedure Load_CRYPTO_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
procedure Load_CRYPTO_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
function Load_CRYPTO_realloc(addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CRYPTO_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CRYPTO_secure_malloc_init(sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_secure_malloc_done: TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_secure_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CRYPTO_secure_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
procedure Load_CRYPTO_secure_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
procedure Load_CRYPTO_secure_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
function Load_CRYPTO_secure_allocated(const ptr: Pointer): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_secure_malloc_initialized: TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;
function Load_CRYPTO_secure_used: TOpenSSL_C_SIZET; cdecl;
procedure Load_OPENSSL_cleanse(ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl;
function Load_OPENSSL_isservice: TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_FIPS_mode: TOpenSSL_C_INT; cdecl;
function Load_FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_OPENSSL_init; cdecl;
function Load_CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_OPENSSL_cleanup; cdecl;
function Load_OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
procedure Load_OPENSSL_thread_stop; cdecl;
function Load_OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl;
procedure Load_OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS); cdecl;
function Load_CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl;
function Load_CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl;
function Load_CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID; cdecl;
function Load_CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSLeay_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSLeay: TOpenSSL_C_ULONG; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

var
  CRYPTO_THREAD_lock_new: function : PCRYPTO_RWLOCK; cdecl = Load_CRYPTO_THREAD_lock_new;
  CRYPTO_THREAD_read_lock: function (lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_read_lock;
  CRYPTO_THREAD_write_lock: function (lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_write_lock;
  CRYPTO_THREAD_unlock: function (lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_unlock;
  CRYPTO_THREAD_lock_free: procedure (lock: PCRYPTO_RWLOCK); cdecl = Load_CRYPTO_THREAD_lock_free;
  CRYPTO_atomic_add: function (val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = Load_CRYPTO_atomic_add;
  OPENSSL_strlcpy: function (dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_OPENSSL_strlcpy;
  OPENSSL_strlcat: function (dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_OPENSSL_strlcat;
  OPENSSL_strnlen: function (const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_OPENSSL_strnlen;
  OPENSSL_buf2hexstr: function (const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl = Load_OPENSSL_buf2hexstr;
  OPENSSL_hexstr2buf: function (const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl = Load_OPENSSL_hexstr2buf;
  OPENSSL_hexchar2int: function (c: Byte): TOpenSSL_C_INT; cdecl = Load_OPENSSL_hexchar2int;
  OpenSSL_version_num: function : TOpenSSL_C_ULONG; cdecl = Load_OpenSSL_version_num;
  OpenSSL_version: function (type_: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OpenSSL_version;
  OPENSSL_issetugid: function : TOpenSSL_C_INT; cdecl = Load_OPENSSL_issetugid;
  CRYPTO_new_ex_data: function (class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl = Load_CRYPTO_new_ex_data;
  CRYPTO_dup_ex_data: function (class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl = Load_CRYPTO_dup_ex_data;
  CRYPTO_free_ex_data: procedure (class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl = Load_CRYPTO_free_ex_data;
  CRYPTO_set_ex_data: function (ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl = Load_CRYPTO_set_ex_data;
  CRYPTO_get_ex_data: function (const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_get_ex_data;
  CRYPTO_set_mem_functions: function (m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl = Load_CRYPTO_set_mem_functions;
  CRYPTO_malloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_malloc;
  CRYPTO_zalloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_zalloc;
  CRYPTO_memdup: function (const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_memdup;
  CRYPTO_strdup: function (const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_CRYPTO_strdup;
  CRYPTO_strndup: function (const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_CRYPTO_strndup;
  CRYPTO_free: procedure (ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = Load_CRYPTO_free;
  CRYPTO_clear_free: procedure (ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = Load_CRYPTO_clear_free;
  CRYPTO_realloc: function (addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_realloc;
  CRYPTO_clear_realloc: function (addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_clear_realloc;
  CRYPTO_secure_malloc_init: function (sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CRYPTO_secure_malloc_init;
  CRYPTO_secure_malloc_done: function : TOpenSSL_C_INT; cdecl = Load_CRYPTO_secure_malloc_done;
  CRYPTO_secure_malloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_secure_malloc;
  CRYPTO_secure_zalloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = Load_CRYPTO_secure_zalloc;
  CRYPTO_secure_free: procedure (ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = Load_CRYPTO_secure_free;
  CRYPTO_secure_clear_free: procedure (ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = Load_CRYPTO_secure_clear_free;
  CRYPTO_secure_allocated: function (const ptr: Pointer): TOpenSSL_C_INT; cdecl = Load_CRYPTO_secure_allocated;
  CRYPTO_secure_malloc_initialized: function : TOpenSSL_C_INT; cdecl = Load_CRYPTO_secure_malloc_initialized;
  CRYPTO_secure_actual_size: function (ptr: Pointer): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_secure_actual_size;
  CRYPTO_secure_used: function : TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_secure_used;
  OPENSSL_cleanse: procedure (ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl = Load_OPENSSL_cleanse;
  OPENSSL_isservice: function : TOpenSSL_C_INT; cdecl = Load_OPENSSL_isservice;
  OPENSSL_init: procedure ; cdecl = Load_OPENSSL_init;
  CRYPTO_memcmp: function (const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_memcmp;
  OPENSSL_cleanup: procedure ; cdecl = Load_OPENSSL_cleanup;
  OPENSSL_init_crypto: function (opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl = Load_OPENSSL_init_crypto;
  OPENSSL_thread_stop: procedure ; cdecl = Load_OPENSSL_thread_stop;
  OPENSSL_INIT_new: function : POPENSSL_INIT_SETTINGS; cdecl = Load_OPENSSL_INIT_new;
  OPENSSL_INIT_free: procedure (settings: POPENSSL_INIT_SETTINGS); cdecl = Load_OPENSSL_INIT_free;
  CRYPTO_THREAD_run_once: function (once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_run_once;
  CRYPTO_THREAD_get_local: function (key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl = Load_CRYPTO_THREAD_get_local;
  CRYPTO_THREAD_set_local: function (key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_set_local;
  CRYPTO_THREAD_cleanup_local: function (key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_cleanup_local;
  CRYPTO_THREAD_get_current_id: function : CRYPTO_THREAD_ID; cdecl = Load_CRYPTO_THREAD_get_current_id;
  CRYPTO_THREAD_compare_id: function (a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl = Load_CRYPTO_THREAD_compare_id;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  OPENSSL_malloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_malloc; {removed 1.0.0}
  OPENSSL_zalloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_zalloc; {removed 1.0.0}
  OPENSSL_realloc: function (addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_realloc; {removed 1.0.0}
  OPENSSL_clear_realloc: function (addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_clear_realloc; {removed 1.0.0}
  OPENSSL_clear_free: procedure (addr: Pointer; num: TOpenSSL_C_SIZET); cdecl = Load_OPENSSL_clear_free; {removed 1.0.0}
  OPENSSL_free: procedure (addr: Pointer); cdecl = Load_OPENSSL_free; {removed 1.0.0}
  OPENSSL_memdup: function (const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_memdup; {removed 1.0.0}
  OPENSSL_strdup: function (const str: PAnsiChar): PAnsiChar; cdecl = Load_OPENSSL_strdup; {removed 1.0.0}
  OPENSSL_strndup: function (const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl = Load_OPENSSL_strndup; {removed 1.0.0}
  OPENSSL_secure_malloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_secure_malloc; {removed 1.0.0}
  OPENSSL_secure_zalloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = Load_OPENSSL_secure_zalloc; {removed 1.0.0}
  OPENSSL_secure_free: procedure (addr: Pointer); cdecl = Load_OPENSSL_secure_free; {removed 1.0.0}
  OPENSSL_secure_clear_free: procedure (addr: Pointer; num: TOpenSSL_C_SIZET); cdecl = Load_OPENSSL_secure_clear_free; {removed 1.0.0}
  OPENSSL_secure_actual_size: function (ptr: Pointer): TOpenSSL_C_SIZET; cdecl = Load_OPENSSL_secure_actual_size; {removed 1.0.0}
  FIPS_mode: function : TOpenSSL_C_INT; cdecl = Load_FIPS_mode; {removed 3.0.0}
  FIPS_mode_set: function (r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_FIPS_mode_set; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  OPENSSL_malloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_zalloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_realloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_clear_realloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_clear_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_memdup_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_strdup_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_strndup_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_malloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_zalloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_clear_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_actual_size_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  CRYPTO_THREAD_lock_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_read_lock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_write_lock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_unlock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_lock_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_atomic_add_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_mem_ctrl_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  OPENSSL_strlcpy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_strlcat_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_strnlen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_buf2hexstr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_hexstr2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_hexchar2int_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OpenSSL_version_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OpenSSL_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_num_locks_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_set_locking_callback_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_THREADID_set_numeric_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_THREADID_set_callback_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_set_id_callback_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_set_mem_debug_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_set_mem_debug_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  CRYPTO_zalloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_memdup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_strndup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_clear_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_clear_realloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_done_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_zalloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_clear_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_allocated_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_initialized_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_actual_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_used_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  FIPS_mode_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  FIPS_mode_set_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  OPENSSL_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_init_crypto_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_thread_stop_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_INIT_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_INIT_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_run_once_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_get_local_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_set_local_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_cleanup_local_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_get_current_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_compare_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLeay_version_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLeay_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}


implementation

uses SyncObjs,  Sysutils
   {$IFNDEF FPC}
     {$IFDEF POSIX}
       ,Posix.Pthread
     {$ELSE}
       ,Windows
     {$ENDIF}
   {$ENDIF},
Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

// OPENSSL_FILE = __FILE__ = C preprocessor macro
// OPENSSL_LINE = __LINE__ = C preprocessor macro
// FPC hase an equivalent with {$I %FILE%} and {$I %LINENUM%}, see https://www.freepascal.org/docs-html/prog/progsu41.html#x47-460001.1.41
// Delphi has nothing :(

//# define OPENSSL_malloc(num) CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$J+}
var
  CRYPTO_mem_ctrl: function (mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CRYPTO_mem_ctrl; {removed 3.0.0}
  CRYPTO_num_locks: function : TOpenSSL_C_INT; cdecl = Load_CRYPTO_num_locks; {removed 1.1.0}
  CRYPTO_set_locking_callback: procedure (func: TIdSslLockingCallback); cdecl = Load_CRYPTO_set_locking_callback; {removed 1.1.0}
  CRYPTO_THREADID_set_numeric: procedure (id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl = Load_CRYPTO_THREADID_set_numeric; {removed 1.1.0}
  CRYPTO_THREADID_set_callback: procedure (threadid_func: Tthreadid_func); cdecl = Load_CRYPTO_THREADID_set_callback; {removed 1.1.0}
  CRYPTO_set_id_callback: procedure (func: TIdSslIdCallback); cdecl = Load_CRYPTO_set_id_callback; {removed 1.1.0}
  CRYPTO_set_mem_debug: function (flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CRYPTO_set_mem_debug; {removed 3.0.0}
  SSLeay_version: function (type_ : TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSLeay_version; {removed 1.1.0}
  SSLeay: function : TOpenSSL_C_ULONG; cdecl = Load_SSLeay; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
var fips_provider: POSSL_PROVIDER;
    base_provider: POSSL_PROVIDER;



{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$if declared(CRYPTO_num_locks)}
type

  { TOpenSSLLegacyCallbacks }

  TOpenSSLLegacyCallbacks = class(TThreadList)
  private
    procedure PrepareOpenSSLLocking;
    class var FCallbackList: TOpenSSLLegacyCallbacks;
  public
    constructor Create;
    destructor Destroy; override;
  end;

procedure TOpenSSLLegacyCallbacks.PrepareOpenSSLLocking;
var
  i: integer;
  Lock: TCriticalSection;
begin
  LockList;
  try
    for i := 0 to CRYPTO_num_locks - 1 do
    begin
      Lock := TCriticalSection.Create;
      try
        Add(Lock);
      except
        Lock.Free;
        raise;
      end;
    end;
  finally
    UnlockList;
  end;
end;

procedure OpenSSLSetCurrentThreadID(id : PCRYPTO_THREADID); cdecl;
begin
  CRYPTO_THREADID_set_numeric(id, TOpenSSL_C_ULONG(GetCurrentThreadId));
end;

procedure OpenSSLLockingCallback(mode, n: TOpenSSL_C_INT; Afile: PAnsiChar;
  line: TOpenSSL_C_INT); cdecl;
var
  Lock: TCriticalSection;
  LList: TList;
begin
  Assert(TOpenSSLLegacyCallbacks.FCallbackList <> nil);
  Lock := nil;

  LList := TOpenSSLLegacyCallbacks.FCallbackList.LockList;
  try
    if n < LList.Count then
      Lock := TCriticalSection(LList[n]);
  finally
    TOpenSSLLegacyCallbacks.FCallbackList.UnlockList;
  end;
  Assert(Lock <> nil);
  if (mode and CRYPTO_LOCK) = CRYPTO_LOCK then
    Lock.Acquire
  else
    Lock.Release;
end;

constructor TOpenSSLLegacyCallbacks.Create;
begin
  Assert(FCallbackList = nil);
  inherited Create;
  FCallbackList := self;
  PrepareOpenSSLLocking;
  CRYPTO_set_locking_callback(@OpenSSLLockingCallback);
  CRYPTO_THREADID_set_callback(@OpenSSLSetCurrentThreadID);
end;

destructor TOpenSSLLegacyCallbacks.Destroy;
var i: integer;
    LList: TList;
begin
  CRYPTO_set_locking_callback(nil);
  LList := LockList;

  try
    for i := 0 to LList.Count - 1 do
      TCriticalSection(LList[i]).Free;
    Clear;
  finally
    UnlockList;
  end;
  inherited Destroy;
  FCallbackList := nil;
end;
{$IFEND}
{$ENDIF}


procedure SetLegacyCallbacks;
begin
  {$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  {$if declared(CRYPTO_num_locks)}
  if TOpenSSLLegacyCallbacks.FCallbackList = nil then
    TOpenSSLLegacyCallbacks.Create;
  {$ifend}
  {$ENDIF}
end;

procedure RemoveLegacyCallbacks;
begin
  {$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  {$if declared(CRYPTO_num_locks)}
  if TOpenSSLLegacyCallbacks.FCallbackList <> nil then
    FreeAndNil(TOpenSSLLegacyCallbacks.FCallbackList);
    {$ifend}
  {$ENDIF}
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_zalloc(num) CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_realloc(addr, num) CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_realloc(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_realloc(addr, old_num, num) CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_clear_realloc(addr, old_num, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_free(addr, num) CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET);

begin
  CRYPTO_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_free(addr) CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_free(addr: Pointer);

begin
  CRYPTO_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_memdup(str, s) CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_memdup(str, s, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strdup(str) CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_strdup(const str: PAnsiChar): PAnsiChar;

begin
  Result := CRYPTO_strdup(str, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strndup(str, n) CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar;

begin
  Result := CRYPTO_strndup(str, n, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_malloc(num) CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_secure_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_zalloc(num) CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_secure_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_free(addr) CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_secure_free(addr: Pointer);

begin
  CRYPTO_secure_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_clear_free(addr, num) CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET);

begin
  CRYPTO_secure_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_actual_size(ptr) CRYPTO_secure_actual_size(ptr)


function OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET;

begin
  Result := CRYPTO_secure_actual_size(ptr);
end;



function FIPS_mode: TOpenSSL_C_INT;

begin
  Result := OSSL_PROVIDER_available(nil,PAnsiChar(AnsiString('fips')));
end;


function FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider);
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('fips')));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('base')));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_zalloc(num) CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_realloc(addr, num) CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_realloc(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_realloc(addr, old_num, num) CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_clear_realloc(addr, old_num, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_free(addr, num) CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;

begin
  CRYPTO_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_free(addr) CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_free(addr: Pointer); cdecl;

begin
  CRYPTO_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_memdup(str, s) CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_memdup(str, s, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strdup(str) CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; cdecl;

begin
  Result := CRYPTO_strdup(str, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strndup(str, n) CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl;

begin
  Result := CRYPTO_strndup(str, n, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_malloc(num) CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_secure_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_zalloc(num) CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_secure_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_free(addr) CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_secure_free(addr: Pointer); cdecl;

begin
  CRYPTO_secure_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_clear_free(addr, num) CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;

begin
  CRYPTO_secure_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_actual_size(ptr) CRYPTO_secure_actual_size(ptr)


function COMPAT_OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;

begin
  Result := CRYPTO_secure_actual_size(ptr);
end;



function COMPAT_OpenSSL_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl;

begin
  Result := SSLeay_version(type_);
end;



function COMPAT_OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl;

begin
  Result := SSLeay;
end;



function COMPAT_FIPS_mode: TOpenSSL_C_INT; cdecl;

begin
  Result := OSSL_PROVIDER_available(nil,PAnsiChar(AnsiString('fips')));
end;


function COMPAT_FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider);
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('fips')));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('base')));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;




function COMPAT_OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;

var OpenSSL_add_all_ciphers: procedure; cdecl;
    OpenSSL_add_all_digests: procedure; cdecl;
begin
  Result := 0;
  if opts and OPENSSL_INIT_ADD_ALL_CIPHERS <> 0 then
  begin
    OpenSSL_add_all_ciphers := LoadLibCryptoFunction('OpenSSL_add_all_ciphers');
    if not assigned(OpenSSL_add_all_ciphers) then
      EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_ciphers');
    OpenSSL_add_all_ciphers;
  end;
  if opts and OPENSSL_INIT_ADD_ALL_DIGESTS <> 0 then
  begin
    OpenSSL_add_all_digests := LoadLibCryptoFunction('OpenSSL_add_all_digests');
    if not assigned(OpenSSL_add_all_digests) then
      EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_digests');
    OpenSSL_add_all_digests;
  end;
  Result := 1;
end;



procedure COMPAT_OPENSSL_cleanup; cdecl;

begin
 {nothing to do}
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_malloc := LoadLibCryptoFunction('OPENSSL_malloc');
  if not assigned(OPENSSL_malloc) then
    OPENSSL_malloc := @COMPAT_OPENSSL_malloc;
  Result := OPENSSL_malloc(num);
end;

function Load_OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_zalloc := LoadLibCryptoFunction('OPENSSL_zalloc');
  if not assigned(OPENSSL_zalloc) then
    OPENSSL_zalloc := @COMPAT_OPENSSL_zalloc;
  Result := OPENSSL_zalloc(num);
end;

function Load_OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_realloc := LoadLibCryptoFunction('OPENSSL_realloc');
  if not assigned(OPENSSL_realloc) then
    OPENSSL_realloc := @COMPAT_OPENSSL_realloc;
  Result := OPENSSL_realloc(addr,num);
end;

function Load_OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_clear_realloc := LoadLibCryptoFunction('OPENSSL_clear_realloc');
  if not assigned(OPENSSL_clear_realloc) then
    OPENSSL_clear_realloc := @COMPAT_OPENSSL_clear_realloc;
  Result := OPENSSL_clear_realloc(addr,old_num,num);
end;

procedure Load_OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;
begin
  OPENSSL_clear_free := LoadLibCryptoFunction('OPENSSL_clear_free');
  if not assigned(OPENSSL_clear_free) then
    OPENSSL_clear_free := @COMPAT_OPENSSL_clear_free;
  OPENSSL_clear_free(addr,num);
end;

procedure Load_OPENSSL_free(addr: Pointer); cdecl;
begin
  OPENSSL_free := LoadLibCryptoFunction('OPENSSL_free');
  if not assigned(OPENSSL_free) then
    OPENSSL_free := @COMPAT_OPENSSL_free;
  OPENSSL_free(addr);
end;

function Load_OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_memdup := LoadLibCryptoFunction('OPENSSL_memdup');
  if not assigned(OPENSSL_memdup) then
    OPENSSL_memdup := @COMPAT_OPENSSL_memdup;
  Result := OPENSSL_memdup(str,s);
end;

function Load_OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; cdecl;
begin
  OPENSSL_strdup := LoadLibCryptoFunction('OPENSSL_strdup');
  if not assigned(OPENSSL_strdup) then
    OPENSSL_strdup := @COMPAT_OPENSSL_strdup;
  Result := OPENSSL_strdup(str);
end;

function Load_OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl;
begin
  OPENSSL_strndup := LoadLibCryptoFunction('OPENSSL_strndup');
  if not assigned(OPENSSL_strndup) then
    OPENSSL_strndup := @COMPAT_OPENSSL_strndup;
  Result := OPENSSL_strndup(str,n);
end;

function Load_OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_secure_malloc := LoadLibCryptoFunction('OPENSSL_secure_malloc');
  if not assigned(OPENSSL_secure_malloc) then
    OPENSSL_secure_malloc := @COMPAT_OPENSSL_secure_malloc;
  Result := OPENSSL_secure_malloc(num);
end;

function Load_OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;
begin
  OPENSSL_secure_zalloc := LoadLibCryptoFunction('OPENSSL_secure_zalloc');
  if not assigned(OPENSSL_secure_zalloc) then
    OPENSSL_secure_zalloc := @COMPAT_OPENSSL_secure_zalloc;
  Result := OPENSSL_secure_zalloc(num);
end;

procedure Load_OPENSSL_secure_free(addr: Pointer); cdecl;
begin
  OPENSSL_secure_free := LoadLibCryptoFunction('OPENSSL_secure_free');
  if not assigned(OPENSSL_secure_free) then
    OPENSSL_secure_free := @COMPAT_OPENSSL_secure_free;
  OPENSSL_secure_free(addr);
end;

procedure Load_OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;
begin
  OPENSSL_secure_clear_free := LoadLibCryptoFunction('OPENSSL_secure_clear_free');
  if not assigned(OPENSSL_secure_clear_free) then
    OPENSSL_secure_clear_free := @COMPAT_OPENSSL_secure_clear_free;
  OPENSSL_secure_clear_free(addr,num);
end;

function Load_OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;
begin
  OPENSSL_secure_actual_size := LoadLibCryptoFunction('OPENSSL_secure_actual_size');
  if not assigned(OPENSSL_secure_actual_size) then
    OPENSSL_secure_actual_size := @COMPAT_OPENSSL_secure_actual_size;
  Result := OPENSSL_secure_actual_size(ptr);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl;
begin
  CRYPTO_THREAD_lock_new := LoadLibCryptoFunction('CRYPTO_THREAD_lock_new');
  if not assigned(CRYPTO_THREAD_lock_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_lock_new');
  Result := CRYPTO_THREAD_lock_new();
end;

function Load_CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_read_lock := LoadLibCryptoFunction('CRYPTO_THREAD_read_lock');
  if not assigned(CRYPTO_THREAD_read_lock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_read_lock');
  Result := CRYPTO_THREAD_read_lock(lock);
end;

function Load_CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_write_lock := LoadLibCryptoFunction('CRYPTO_THREAD_write_lock');
  if not assigned(CRYPTO_THREAD_write_lock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_write_lock');
  Result := CRYPTO_THREAD_write_lock(lock);
end;

function Load_CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_unlock := LoadLibCryptoFunction('CRYPTO_THREAD_unlock');
  if not assigned(CRYPTO_THREAD_unlock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_unlock');
  Result := CRYPTO_THREAD_unlock(lock);
end;

procedure Load_CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK); cdecl;
begin
  CRYPTO_THREAD_lock_free := LoadLibCryptoFunction('CRYPTO_THREAD_lock_free');
  if not assigned(CRYPTO_THREAD_lock_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_lock_free');
  CRYPTO_THREAD_lock_free(lock);
end;

function Load_CRYPTO_atomic_add(val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_atomic_add := LoadLibCryptoFunction('CRYPTO_atomic_add');
  if not assigned(CRYPTO_atomic_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_atomic_add');
  Result := CRYPTO_atomic_add(val,amount,ret,lock);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_CRYPTO_mem_ctrl(mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_mem_ctrl := LoadLibCryptoFunction('CRYPTO_mem_ctrl');
  if not assigned(CRYPTO_mem_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_mem_ctrl');
  Result := CRYPTO_mem_ctrl(mode);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_OPENSSL_strlcpy(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  OPENSSL_strlcpy := LoadLibCryptoFunction('OPENSSL_strlcpy');
  if not assigned(OPENSSL_strlcpy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strlcpy');
  Result := OPENSSL_strlcpy(dst,src,siz);
end;

function Load_OPENSSL_strlcat(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  OPENSSL_strlcat := LoadLibCryptoFunction('OPENSSL_strlcat');
  if not assigned(OPENSSL_strlcat) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strlcat');
  Result := OPENSSL_strlcat(dst,src,siz);
end;

function Load_OPENSSL_strnlen(const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  OPENSSL_strnlen := LoadLibCryptoFunction('OPENSSL_strnlen');
  if not assigned(OPENSSL_strnlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strnlen');
  Result := OPENSSL_strnlen(str,maxlen);
end;

function Load_OPENSSL_buf2hexstr(const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl;
begin
  OPENSSL_buf2hexstr := LoadLibCryptoFunction('OPENSSL_buf2hexstr');
  if not assigned(OPENSSL_buf2hexstr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_buf2hexstr');
  Result := OPENSSL_buf2hexstr(buffer,len);
end;

function Load_OPENSSL_hexstr2buf(const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl;
begin
  OPENSSL_hexstr2buf := LoadLibCryptoFunction('OPENSSL_hexstr2buf');
  if not assigned(OPENSSL_hexstr2buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_hexstr2buf');
  Result := OPENSSL_hexstr2buf(str,len);
end;

function Load_OPENSSL_hexchar2int(c: Byte): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_hexchar2int := LoadLibCryptoFunction('OPENSSL_hexchar2int');
  if not assigned(OPENSSL_hexchar2int) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_hexchar2int');
  Result := OPENSSL_hexchar2int(c);
end;

function Load_OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl;
begin
  OpenSSL_version_num := LoadLibCryptoFunction('OpenSSL_version_num');
  if not assigned(OpenSSL_version_num) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OpenSSL_version_num := @COMPAT_OpenSSL_version_num;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_version_num');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OpenSSL_version_num();
end;

function Load_OpenSSL_version(type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OpenSSL_version := LoadLibCryptoFunction('OpenSSL_version');
  if not assigned(OpenSSL_version) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OpenSSL_version := @COMPAT_OpenSSL_version;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_version');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OpenSSL_version(type_);
end;

function Load_OPENSSL_issetugid: TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_issetugid := LoadLibCryptoFunction('OPENSSL_issetugid');
  if not assigned(OPENSSL_issetugid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_issetugid');
  Result := OPENSSL_issetugid();
end;

function Load_CRYPTO_new_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_new_ex_data := LoadLibCryptoFunction('CRYPTO_new_ex_data');
  if not assigned(CRYPTO_new_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_new_ex_data');
  Result := CRYPTO_new_ex_data(class_index,obj,ad);
end;

function Load_CRYPTO_dup_ex_data(class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_dup_ex_data := LoadLibCryptoFunction('CRYPTO_dup_ex_data');
  if not assigned(CRYPTO_dup_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_dup_ex_data');
  Result := CRYPTO_dup_ex_data(class_index,to_,from);
end;

procedure Load_CRYPTO_free_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl;
begin
  CRYPTO_free_ex_data := LoadLibCryptoFunction('CRYPTO_free_ex_data');
  if not assigned(CRYPTO_free_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_free_ex_data');
  CRYPTO_free_ex_data(class_index,obj,ad);
end;

function Load_CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_set_ex_data := LoadLibCryptoFunction('CRYPTO_set_ex_data');
  if not assigned(CRYPTO_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_ex_data');
  Result := CRYPTO_set_ex_data(ad,idx,val);
end;

function Load_CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_get_ex_data := LoadLibCryptoFunction('CRYPTO_get_ex_data');
  if not assigned(CRYPTO_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_get_ex_data');
  Result := CRYPTO_get_ex_data(ad,idx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_CRYPTO_num_locks: TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_num_locks := LoadLibCryptoFunction('CRYPTO_num_locks');
  if not assigned(CRYPTO_num_locks) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_num_locks');
  Result := CRYPTO_num_locks();
end;

procedure Load_CRYPTO_set_locking_callback(func: TIdSslLockingCallback); cdecl;
begin
  CRYPTO_set_locking_callback := LoadLibCryptoFunction('CRYPTO_set_locking_callback');
  if not assigned(CRYPTO_set_locking_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_locking_callback');
  CRYPTO_set_locking_callback(func);
end;

procedure Load_CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl;
begin
  CRYPTO_THREADID_set_numeric := LoadLibCryptoFunction('CRYPTO_THREADID_set_numeric');
  if not assigned(CRYPTO_THREADID_set_numeric) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREADID_set_numeric');
  CRYPTO_THREADID_set_numeric(id,val);
end;

procedure Load_CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl;
begin
  CRYPTO_THREADID_set_callback := LoadLibCryptoFunction('CRYPTO_THREADID_set_callback');
  if not assigned(CRYPTO_THREADID_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREADID_set_callback');
  CRYPTO_THREADID_set_callback(threadid_func);
end;

procedure Load_CRYPTO_set_id_callback(func: TIdSslIdCallback); cdecl;
begin
  CRYPTO_set_id_callback := LoadLibCryptoFunction('CRYPTO_set_id_callback');
  if not assigned(CRYPTO_set_id_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_id_callback');
  CRYPTO_set_id_callback(func);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_set_mem_functions := LoadLibCryptoFunction('CRYPTO_set_mem_functions');
  if not assigned(CRYPTO_set_mem_functions) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_mem_functions');
  Result := CRYPTO_set_mem_functions(m,r,f);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_CRYPTO_set_mem_debug(flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_set_mem_debug := LoadLibCryptoFunction('CRYPTO_set_mem_debug');
  if not assigned(CRYPTO_set_mem_debug) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_mem_debug');
  Result := CRYPTO_set_mem_debug(flag);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_CRYPTO_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_malloc := LoadLibCryptoFunction('CRYPTO_malloc');
  if not assigned(CRYPTO_malloc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_malloc');
  Result := CRYPTO_malloc(num,file_,line);
end;

function Load_CRYPTO_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_zalloc := LoadLibCryptoFunction('CRYPTO_zalloc');
  if not assigned(CRYPTO_zalloc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_zalloc');
  Result := CRYPTO_zalloc(num,file_,line);
end;

function Load_CRYPTO_memdup(const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_memdup := LoadLibCryptoFunction('CRYPTO_memdup');
  if not assigned(CRYPTO_memdup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_memdup');
  Result := CRYPTO_memdup(str,siz,file_,line);
end;

function Load_CRYPTO_strdup(const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  CRYPTO_strdup := LoadLibCryptoFunction('CRYPTO_strdup');
  if not assigned(CRYPTO_strdup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_strdup');
  Result := CRYPTO_strdup(str,file_,line);
end;

function Load_CRYPTO_strndup(const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  CRYPTO_strndup := LoadLibCryptoFunction('CRYPTO_strndup');
  if not assigned(CRYPTO_strndup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_strndup');
  Result := CRYPTO_strndup(str,s,file_,line);
end;

procedure Load_CRYPTO_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  CRYPTO_free := LoadLibCryptoFunction('CRYPTO_free');
  if not assigned(CRYPTO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_free');
  CRYPTO_free(ptr,file_,line);
end;

procedure Load_CRYPTO_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  CRYPTO_clear_free := LoadLibCryptoFunction('CRYPTO_clear_free');
  if not assigned(CRYPTO_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_clear_free');
  CRYPTO_clear_free(ptr,num,file_,line);
end;

function Load_CRYPTO_realloc(addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_realloc := LoadLibCryptoFunction('CRYPTO_realloc');
  if not assigned(CRYPTO_realloc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_realloc');
  Result := CRYPTO_realloc(addr,num,file_,line);
end;

function Load_CRYPTO_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_clear_realloc := LoadLibCryptoFunction('CRYPTO_clear_realloc');
  if not assigned(CRYPTO_clear_realloc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_clear_realloc');
  Result := CRYPTO_clear_realloc(addr,old_num,num,file_,line);
end;

function Load_CRYPTO_secure_malloc_init(sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_secure_malloc_init := LoadLibCryptoFunction('CRYPTO_secure_malloc_init');
  if not assigned(CRYPTO_secure_malloc_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc_init');
  Result := CRYPTO_secure_malloc_init(sz,minsize);
end;

function Load_CRYPTO_secure_malloc_done: TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_secure_malloc_done := LoadLibCryptoFunction('CRYPTO_secure_malloc_done');
  if not assigned(CRYPTO_secure_malloc_done) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc_done');
  Result := CRYPTO_secure_malloc_done();
end;

function Load_CRYPTO_secure_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_secure_malloc := LoadLibCryptoFunction('CRYPTO_secure_malloc');
  if not assigned(CRYPTO_secure_malloc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc');
  Result := CRYPTO_secure_malloc(num,file_,line);
end;

function Load_CRYPTO_secure_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CRYPTO_secure_zalloc := LoadLibCryptoFunction('CRYPTO_secure_zalloc');
  if not assigned(CRYPTO_secure_zalloc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_zalloc');
  Result := CRYPTO_secure_zalloc(num,file_,line);
end;

procedure Load_CRYPTO_secure_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  CRYPTO_secure_free := LoadLibCryptoFunction('CRYPTO_secure_free');
  if not assigned(CRYPTO_secure_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_free');
  CRYPTO_secure_free(ptr,file_,line);
end;

procedure Load_CRYPTO_secure_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  CRYPTO_secure_clear_free := LoadLibCryptoFunction('CRYPTO_secure_clear_free');
  if not assigned(CRYPTO_secure_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_clear_free');
  CRYPTO_secure_clear_free(ptr,num,file_,line);
end;

function Load_CRYPTO_secure_allocated(const ptr: Pointer): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_secure_allocated := LoadLibCryptoFunction('CRYPTO_secure_allocated');
  if not assigned(CRYPTO_secure_allocated) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_allocated');
  Result := CRYPTO_secure_allocated(ptr);
end;

function Load_CRYPTO_secure_malloc_initialized: TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_secure_malloc_initialized := LoadLibCryptoFunction('CRYPTO_secure_malloc_initialized');
  if not assigned(CRYPTO_secure_malloc_initialized) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc_initialized');
  Result := CRYPTO_secure_malloc_initialized();
end;

function Load_CRYPTO_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_secure_actual_size := LoadLibCryptoFunction('CRYPTO_secure_actual_size');
  if not assigned(CRYPTO_secure_actual_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_actual_size');
  Result := CRYPTO_secure_actual_size(ptr);
end;

function Load_CRYPTO_secure_used: TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_secure_used := LoadLibCryptoFunction('CRYPTO_secure_used');
  if not assigned(CRYPTO_secure_used) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_used');
  Result := CRYPTO_secure_used();
end;

procedure Load_OPENSSL_cleanse(ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl;
begin
  OPENSSL_cleanse := LoadLibCryptoFunction('OPENSSL_cleanse');
  if not assigned(OPENSSL_cleanse) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_cleanse');
  OPENSSL_cleanse(ptr,len);
end;

function Load_OPENSSL_isservice: TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_isservice := LoadLibCryptoFunction('OPENSSL_isservice');
  if not assigned(OPENSSL_isservice) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_isservice');
  Result := OPENSSL_isservice();
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_FIPS_mode: TOpenSSL_C_INT; cdecl;
begin
  FIPS_mode := LoadLibCryptoFunction('FIPS_mode');
  if not assigned(FIPS_mode) then
    FIPS_mode := @COMPAT_FIPS_mode;
  Result := FIPS_mode();
end;

function Load_FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  FIPS_mode_set := LoadLibCryptoFunction('FIPS_mode_set');
  if not assigned(FIPS_mode_set) then
    FIPS_mode_set := @COMPAT_FIPS_mode_set;
  Result := FIPS_mode_set(r);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_OPENSSL_init; cdecl;
begin
  OPENSSL_init := LoadLibCryptoFunction('OPENSSL_init');
  if not assigned(OPENSSL_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_init');
  OPENSSL_init();
end;

function Load_CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_memcmp := LoadLibCryptoFunction('CRYPTO_memcmp');
  if not assigned(CRYPTO_memcmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_memcmp');
  Result := CRYPTO_memcmp(in_a,in_b,len);
end;

procedure Load_OPENSSL_cleanup; cdecl;
begin
  OPENSSL_cleanup := LoadLibCryptoFunction('OPENSSL_cleanup');
  if not assigned(OPENSSL_cleanup) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_cleanup := @COMPAT_OPENSSL_cleanup;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_cleanup');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_cleanup();
end;

function Load_OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_init_crypto := LoadLibCryptoFunction('OPENSSL_init_crypto');
  if not assigned(OPENSSL_init_crypto) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_init_crypto := @COMPAT_OPENSSL_init_crypto;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_init_crypto');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_init_crypto(opts,settings);
end;

procedure Load_OPENSSL_thread_stop; cdecl;
begin
  OPENSSL_thread_stop := LoadLibCryptoFunction('OPENSSL_thread_stop');
  if not assigned(OPENSSL_thread_stop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_thread_stop');
  OPENSSL_thread_stop();
end;

function Load_OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl;
begin
  OPENSSL_INIT_new := LoadLibCryptoFunction('OPENSSL_INIT_new');
  if not assigned(OPENSSL_INIT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_INIT_new');
  Result := OPENSSL_INIT_new();
end;

procedure Load_OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS); cdecl;
begin
  OPENSSL_INIT_free := LoadLibCryptoFunction('OPENSSL_INIT_free');
  if not assigned(OPENSSL_INIT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_INIT_free');
  OPENSSL_INIT_free(settings);
end;

function Load_CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_run_once := LoadLibCryptoFunction('CRYPTO_THREAD_run_once');
  if not assigned(CRYPTO_THREAD_run_once) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_run_once');
  Result := CRYPTO_THREAD_run_once(once,init);
end;

function Load_CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl;
begin
  CRYPTO_THREAD_get_local := LoadLibCryptoFunction('CRYPTO_THREAD_get_local');
  if not assigned(CRYPTO_THREAD_get_local) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_get_local');
  Result := CRYPTO_THREAD_get_local(key);
end;

function Load_CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_set_local := LoadLibCryptoFunction('CRYPTO_THREAD_set_local');
  if not assigned(CRYPTO_THREAD_set_local) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_set_local');
  Result := CRYPTO_THREAD_set_local(key,val);
end;

function Load_CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_cleanup_local := LoadLibCryptoFunction('CRYPTO_THREAD_cleanup_local');
  if not assigned(CRYPTO_THREAD_cleanup_local) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_cleanup_local');
  Result := CRYPTO_THREAD_cleanup_local(key);
end;

function Load_CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID; cdecl;
begin
  CRYPTO_THREAD_get_current_id := LoadLibCryptoFunction('CRYPTO_THREAD_get_current_id');
  if not assigned(CRYPTO_THREAD_get_current_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_get_current_id');
  Result := CRYPTO_THREAD_get_current_id();
end;

function Load_CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_THREAD_compare_id := LoadLibCryptoFunction('CRYPTO_THREAD_compare_id');
  if not assigned(CRYPTO_THREAD_compare_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_compare_id');
  Result := CRYPTO_THREAD_compare_id(a,b);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSLeay_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSLeay_version := LoadLibCryptoFunction('SSLeay_version');
  if not assigned(SSLeay_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay_version');
  Result := SSLeay_version(type_);
end;

function Load_SSLeay: TOpenSSL_C_ULONG; cdecl;
begin
  SSLeay := LoadLibCryptoFunction('SSLeay');
  if not assigned(SSLeay) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay');
  Result := SSLeay();
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$WARN  NO_RETVAL OFF}
{$J+}
{$WARN  NO_RETVAL ON}

procedure UnLoad;
begin
{$J+}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_malloc := Load_OPENSSL_malloc;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_zalloc := Load_OPENSSL_zalloc;
  OPENSSL_realloc := Load_OPENSSL_realloc;
  OPENSSL_clear_realloc := Load_OPENSSL_clear_realloc;
  OPENSSL_clear_free := Load_OPENSSL_clear_free;
  OPENSSL_free := Load_OPENSSL_free;
  OPENSSL_memdup := Load_OPENSSL_memdup;
  OPENSSL_strdup := Load_OPENSSL_strdup;
  OPENSSL_strndup := Load_OPENSSL_strndup;
  OPENSSL_secure_malloc := Load_OPENSSL_secure_malloc;
  OPENSSL_secure_zalloc := Load_OPENSSL_secure_zalloc;
  OPENSSL_secure_free := Load_OPENSSL_secure_free;
  OPENSSL_secure_clear_free := Load_OPENSSL_secure_clear_free;
  OPENSSL_secure_actual_size := Load_OPENSSL_secure_actual_size;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_THREAD_lock_new := Load_CRYPTO_THREAD_lock_new;
  CRYPTO_THREAD_read_lock := Load_CRYPTO_THREAD_read_lock;
  CRYPTO_THREAD_write_lock := Load_CRYPTO_THREAD_write_lock;
  CRYPTO_THREAD_unlock := Load_CRYPTO_THREAD_unlock;
  CRYPTO_THREAD_lock_free := Load_CRYPTO_THREAD_lock_free;
  CRYPTO_atomic_add := Load_CRYPTO_atomic_add;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_mem_ctrl := Load_CRYPTO_mem_ctrl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  OPENSSL_strlcpy := Load_OPENSSL_strlcpy;
  OPENSSL_strlcat := Load_OPENSSL_strlcat;
  OPENSSL_strnlen := Load_OPENSSL_strnlen;
  OPENSSL_buf2hexstr := Load_OPENSSL_buf2hexstr;
  OPENSSL_hexstr2buf := Load_OPENSSL_hexstr2buf;
  OPENSSL_hexchar2int := Load_OPENSSL_hexchar2int;
  OpenSSL_version_num := Load_OpenSSL_version_num;
  OpenSSL_version := Load_OpenSSL_version;
  OPENSSL_issetugid := Load_OPENSSL_issetugid;
  CRYPTO_new_ex_data := Load_CRYPTO_new_ex_data;
  CRYPTO_dup_ex_data := Load_CRYPTO_dup_ex_data;
  CRYPTO_free_ex_data := Load_CRYPTO_free_ex_data;
  CRYPTO_set_ex_data := Load_CRYPTO_set_ex_data;
  CRYPTO_get_ex_data := Load_CRYPTO_get_ex_data;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_num_locks := Load_CRYPTO_num_locks;
  CRYPTO_set_locking_callback := Load_CRYPTO_set_locking_callback;
  CRYPTO_THREADID_set_numeric := Load_CRYPTO_THREADID_set_numeric;
  CRYPTO_THREADID_set_callback := Load_CRYPTO_THREADID_set_callback;
  CRYPTO_set_id_callback := Load_CRYPTO_set_id_callback;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_set_mem_functions := Load_CRYPTO_set_mem_functions;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_set_mem_debug := Load_CRYPTO_set_mem_debug;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_malloc := Load_CRYPTO_malloc;
  CRYPTO_zalloc := Load_CRYPTO_zalloc;
  CRYPTO_memdup := Load_CRYPTO_memdup;
  CRYPTO_strdup := Load_CRYPTO_strdup;
  CRYPTO_strndup := Load_CRYPTO_strndup;
  CRYPTO_free := Load_CRYPTO_free;
  CRYPTO_clear_free := Load_CRYPTO_clear_free;
  CRYPTO_realloc := Load_CRYPTO_realloc;
  CRYPTO_clear_realloc := Load_CRYPTO_clear_realloc;
  CRYPTO_secure_malloc_init := Load_CRYPTO_secure_malloc_init;
  CRYPTO_secure_malloc_done := Load_CRYPTO_secure_malloc_done;
  CRYPTO_secure_malloc := Load_CRYPTO_secure_malloc;
  CRYPTO_secure_zalloc := Load_CRYPTO_secure_zalloc;
  CRYPTO_secure_free := Load_CRYPTO_secure_free;
  CRYPTO_secure_clear_free := Load_CRYPTO_secure_clear_free;
  CRYPTO_secure_allocated := Load_CRYPTO_secure_allocated;
  CRYPTO_secure_malloc_initialized := Load_CRYPTO_secure_malloc_initialized;
  CRYPTO_secure_actual_size := Load_CRYPTO_secure_actual_size;
  CRYPTO_secure_used := Load_CRYPTO_secure_used;
  OPENSSL_cleanse := Load_OPENSSL_cleanse;
  OPENSSL_isservice := Load_OPENSSL_isservice;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  FIPS_mode := Load_FIPS_mode;
  FIPS_mode_set := Load_FIPS_mode_set;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  OPENSSL_init := Load_OPENSSL_init;
  CRYPTO_memcmp := Load_CRYPTO_memcmp;
  OPENSSL_cleanup := Load_OPENSSL_cleanup;
  OPENSSL_init_crypto := Load_OPENSSL_init_crypto;
  OPENSSL_thread_stop := Load_OPENSSL_thread_stop;
  OPENSSL_INIT_new := Load_OPENSSL_INIT_new;
  OPENSSL_INIT_free := Load_OPENSSL_INIT_free;
  CRYPTO_THREAD_run_once := Load_CRYPTO_THREAD_run_once;
  CRYPTO_THREAD_get_local := Load_CRYPTO_THREAD_get_local;
  CRYPTO_THREAD_set_local := Load_CRYPTO_THREAD_set_local;
  CRYPTO_THREAD_cleanup_local := Load_CRYPTO_THREAD_cleanup_local;
  CRYPTO_THREAD_get_current_id := Load_CRYPTO_THREAD_get_current_id;
  CRYPTO_THREAD_compare_id := Load_CRYPTO_THREAD_compare_id;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLeay_version := Load_SSLeay_version;
  SSLeay := Load_SSLeay;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization


  {$if declared(CRYPTO_num_locks)}
  TOpenSSLLegacyCallbacks.FCallbackList := nil;
  {$ifend}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}

finalization


  RemoveLegacyCallbacks;




end.
