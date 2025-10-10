(* This unit was generated from the source file conf.h2pas 
It should not be modified directly. All changes should be made to conf.h2pas
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


unit IdOpenSSLHeaders_conf;


interface

// Headers for OpenSSL 1.1.1
// conf.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_ossl_typ;

type
  CONF_parse_list_list_cb = function (const elem: PAnsiChar; len: TOpenSSL_C_INT; usr: Pointer): TOpenSSL_C_INT;

  CONF_VALUE = record
    section: PAnsiChar;
    name: PAnsiChar;
    value: PAnsiChar;
  end;
  PCONF_VALUE = ^CONF_VALUE;

//DEFINE_STACK_OF(CONF_VALUE)
//DEFINE_LHASH_OF(CONF_VALUE);

  conf_st = type Pointer;
  conf_method_st = type Pointer;
  CONF_METHOD = conf_method_st;
  PCONF_METHOD = ^conf_method_st;
  CONF = conf_st;
  PCONF = ^CONF;

  {conf_method_st = record
    const char *name;
    CONF *(*create) (CONF_METHOD *meth);
    int (*init) (CONF *conf);
    int (*destroy) (CONF *conf);
    int (*destroy_data) (CONF *conf);
    int (*load_bio) (CONF *conf, BIO *bp, long *eline);
    int (*dump) (const CONF *conf, BIO *bp);
    int (*is_number) (const CONF *conf, char c);
    int (*to_int) (const CONF *conf, char c);
    int (*load) (CONF *conf, const char *name, long *eline);
  end; }

//* Module definitions */

  conf_imodule_st = type Pointer;
  CONF_IMODULE = conf_imodule_st;
  PCONF_IMODULE = ^CONF_IMODULE;
  conf_module_st = type Pointer;
  CONF_MODULE = conf_module_st;
  PCONF_MODULE = ^CONF_MODULE;

//DEFINE_STACK_OF(CONF_MODULE)
//DEFINE_STACK_OF(CONF_IMODULE)

//* DSO module function typedefs */
  conf_init_func = function(md: PCONF_IMODULE; const cnf: PCONF): TOpenSSL_C_INT;
  conf_finish_func = procedure(md: PCONF_IMODULE);

const
  CONF_MFLAGS_IGNORE_ERRORS = $1;
  CONF_MFLAGS_IGNORE_RETURN_CODES = $2;
  CONF_MFLAGS_SILENT = $4;
  CONF_MFLAGS_NO_DSO = $8;
  CONF_MFLAGS_IGNORE_MISSING_FILE = $10;
  CONF_MFLAGS_DEFAULT_SECTION = $20;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CONF_set_default_method}
{$EXTERNALSYM NCONF_new}
{$EXTERNALSYM NCONF_default}
{$EXTERNALSYM NCONF_WIN32}
{$EXTERNALSYM NCONF_free}
{$EXTERNALSYM NCONF_free_data}
{$EXTERNALSYM NCONF_load}
{$EXTERNALSYM NCONF_load_bio}
{$EXTERNALSYM NCONF_get_string}
{$EXTERNALSYM NCONF_get_number_e}
{$EXTERNALSYM NCONF_dump_bio}
{$EXTERNALSYM CONF_modules_load}
{$EXTERNALSYM CONF_modules_load_file}
{$EXTERNALSYM CONF_modules_unload}
{$EXTERNALSYM CONF_modules_finish}
{$EXTERNALSYM CONF_module_add}
{$EXTERNALSYM CONF_imodule_get_usr_data}
{$EXTERNALSYM CONF_imodule_set_usr_data}
{$EXTERNALSYM CONF_imodule_get_module}
{$EXTERNALSYM CONF_imodule_get_flags}
{$EXTERNALSYM CONF_imodule_set_flags}
{$EXTERNALSYM CONF_module_get_usr_data}
{$EXTERNALSYM CONF_module_set_usr_data}
{$EXTERNALSYM CONF_get1_default_config_file}
{$EXTERNALSYM CONF_parse_list}
{$EXTERNALSYM OPENSSL_load_builtin_modules}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CONF_set_default_method(meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_new(meth: PCONF_METHOD): PCONF; cdecl; external CLibCrypto;
function NCONF_default: PCONF_METHOD; cdecl; external CLibCrypto;
function NCONF_WIN32: PCONF_METHOD; cdecl; external CLibCrypto;
procedure NCONF_free(conf: PCONF); cdecl; external CLibCrypto;
procedure NCONF_free_data(conf: PCONF); cdecl; external CLibCrypto;
function NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_load_bio(conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_dump_bio(const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CONF_modules_unload(all: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CONF_modules_finish; cdecl; external CLibCrypto;
function CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer; cdecl; external CLibCrypto;
procedure CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl; external CLibCrypto;
function CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE; cdecl; external CLibCrypto;
function CONF_imodule_get_flags(const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl; external CLibCrypto;
procedure CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl; external CLibCrypto;
function CONF_get1_default_config_file: PAnsiChar; cdecl; external CLibCrypto;
function CONF_parse_list(const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_load_builtin_modules; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_CONF_set_default_method(meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl;
function Load_NCONF_new(meth: PCONF_METHOD): PCONF; cdecl;
function Load_NCONF_default: PCONF_METHOD; cdecl;
function Load_NCONF_WIN32: PCONF_METHOD; cdecl;
procedure Load_NCONF_free(conf: PCONF); cdecl;
procedure Load_NCONF_free_data(conf: PCONF); cdecl;
function Load_NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_NCONF_load_bio(conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
function Load_NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_NCONF_dump_bio(const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl;
function Load_CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
procedure Load_CONF_modules_unload(all: TOpenSSL_C_INT); cdecl;
procedure Load_CONF_modules_finish; cdecl;
function Load_CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl;
function Load_CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer; cdecl;
procedure Load_CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl;
function Load_CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE; cdecl;
function Load_CONF_imodule_get_flags(const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl;
procedure Load_CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl;
function Load_CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl;
procedure Load_CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl;
function Load_CONF_get1_default_config_file: PAnsiChar; cdecl;
function Load_CONF_parse_list(const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl;
procedure Load_OPENSSL_load_builtin_modules; cdecl;

var
  CONF_set_default_method: function (meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl = Load_CONF_set_default_method;
  NCONF_new: function (meth: PCONF_METHOD): PCONF; cdecl = Load_NCONF_new;
  NCONF_default: function : PCONF_METHOD; cdecl = Load_NCONF_default;
  NCONF_WIN32: function : PCONF_METHOD; cdecl = Load_NCONF_WIN32;
  NCONF_free: procedure (conf: PCONF); cdecl = Load_NCONF_free;
  NCONF_free_data: procedure (conf: PCONF); cdecl = Load_NCONF_free_data;
  NCONF_load: function (conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_NCONF_load;
  NCONF_load_bio: function (conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_NCONF_load_bio;
  NCONF_get_string: function (const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl = Load_NCONF_get_string;
  NCONF_get_number_e: function (const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_NCONF_get_number_e;
  NCONF_dump_bio: function (const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl = Load_NCONF_dump_bio;
  CONF_modules_load: function (const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_CONF_modules_load;
  CONF_modules_load_file: function (const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_CONF_modules_load_file;
  CONF_modules_unload: procedure (all: TOpenSSL_C_INT); cdecl = Load_CONF_modules_unload;
  CONF_modules_finish: procedure ; cdecl = Load_CONF_modules_finish;
  CONF_module_add: function (const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl = Load_CONF_module_add;
  CONF_imodule_get_usr_data: function (const md: PCONF_IMODULE): Pointer; cdecl = Load_CONF_imodule_get_usr_data;
  CONF_imodule_set_usr_data: procedure (md: PCONF_IMODULE; usr_data: Pointer); cdecl = Load_CONF_imodule_set_usr_data;
  CONF_imodule_get_module: function (const md: PCONF_IMODULE): PCONF_MODULE; cdecl = Load_CONF_imodule_get_module;
  CONF_imodule_get_flags: function (const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl = Load_CONF_imodule_get_flags;
  CONF_imodule_set_flags: procedure (md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl = Load_CONF_imodule_set_flags;
  CONF_module_get_usr_data: function (pmod: PCONF_MODULE): Pointer; cdecl = Load_CONF_module_get_usr_data;
  CONF_module_set_usr_data: procedure (pmod: PCONF_MODULE; usr_data: Pointer); cdecl = Load_CONF_module_set_usr_data;
  CONF_get1_default_config_file: function : PAnsiChar; cdecl = Load_CONF_get1_default_config_file;
  CONF_parse_list: function (const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_CONF_parse_list;
  OPENSSL_load_builtin_modules: procedure ; cdecl = Load_OPENSSL_load_builtin_modules;
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
function Load_CONF_set_default_method(meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl;
begin
  CONF_set_default_method := LoadLibCryptoFunction('CONF_set_default_method');
  if not assigned(CONF_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_set_default_method');
  Result := CONF_set_default_method(meth);
end;

function Load_NCONF_new(meth: PCONF_METHOD): PCONF; cdecl;
begin
  NCONF_new := LoadLibCryptoFunction('NCONF_new');
  if not assigned(NCONF_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_new');
  Result := NCONF_new(meth);
end;

function Load_NCONF_default: PCONF_METHOD; cdecl;
begin
  NCONF_default := LoadLibCryptoFunction('NCONF_default');
  if not assigned(NCONF_default) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_default');
  Result := NCONF_default();
end;

function Load_NCONF_WIN32: PCONF_METHOD; cdecl;
begin
  NCONF_WIN32 := LoadLibCryptoFunction('NCONF_WIN32');
  if not assigned(NCONF_WIN32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_WIN32');
  Result := NCONF_WIN32();
end;

procedure Load_NCONF_free(conf: PCONF); cdecl;
begin
  NCONF_free := LoadLibCryptoFunction('NCONF_free');
  if not assigned(NCONF_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_free');
  NCONF_free(conf);
end;

procedure Load_NCONF_free_data(conf: PCONF); cdecl;
begin
  NCONF_free_data := LoadLibCryptoFunction('NCONF_free_data');
  if not assigned(NCONF_free_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_free_data');
  NCONF_free_data(conf);
end;

function Load_NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  NCONF_load := LoadLibCryptoFunction('NCONF_load');
  if not assigned(NCONF_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_load');
  Result := NCONF_load(conf,file_,eline);
end;

function Load_NCONF_load_bio(conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  NCONF_load_bio := LoadLibCryptoFunction('NCONF_load_bio');
  if not assigned(NCONF_load_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_load_bio');
  Result := NCONF_load_bio(conf,bp,eline);
end;

function Load_NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
begin
  NCONF_get_string := LoadLibCryptoFunction('NCONF_get_string');
  if not assigned(NCONF_get_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_get_string');
  Result := NCONF_get_string(conf,group,name);
end;

function Load_NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  NCONF_get_number_e := LoadLibCryptoFunction('NCONF_get_number_e');
  if not assigned(NCONF_get_number_e) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_get_number_e');
  Result := NCONF_get_number_e(conf,group,name,result_);
end;

function Load_NCONF_dump_bio(const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  NCONF_dump_bio := LoadLibCryptoFunction('NCONF_dump_bio');
  if not assigned(NCONF_dump_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_dump_bio');
  Result := NCONF_dump_bio(conf,out_);
end;

function Load_CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  CONF_modules_load := LoadLibCryptoFunction('CONF_modules_load');
  if not assigned(CONF_modules_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_load');
  Result := CONF_modules_load(cnf,appname,flags);
end;

function Load_CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  CONF_modules_load_file := LoadLibCryptoFunction('CONF_modules_load_file');
  if not assigned(CONF_modules_load_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_load_file');
  Result := CONF_modules_load_file(filename,appname,flags);
end;

procedure Load_CONF_modules_unload(all: TOpenSSL_C_INT); cdecl;
begin
  CONF_modules_unload := LoadLibCryptoFunction('CONF_modules_unload');
  if not assigned(CONF_modules_unload) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_unload');
  CONF_modules_unload(all);
end;

procedure Load_CONF_modules_finish; cdecl;
begin
  CONF_modules_finish := LoadLibCryptoFunction('CONF_modules_finish');
  if not assigned(CONF_modules_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_finish');
  CONF_modules_finish();
end;

function Load_CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl;
begin
  CONF_module_add := LoadLibCryptoFunction('CONF_module_add');
  if not assigned(CONF_module_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_module_add');
  Result := CONF_module_add(name,ifunc,ffunc);
end;

function Load_CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer; cdecl;
begin
  CONF_imodule_get_usr_data := LoadLibCryptoFunction('CONF_imodule_get_usr_data');
  if not assigned(CONF_imodule_get_usr_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_get_usr_data');
  Result := CONF_imodule_get_usr_data(md);
end;

procedure Load_CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl;
begin
  CONF_imodule_set_usr_data := LoadLibCryptoFunction('CONF_imodule_set_usr_data');
  if not assigned(CONF_imodule_set_usr_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_set_usr_data');
  CONF_imodule_set_usr_data(md,usr_data);
end;

function Load_CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE; cdecl;
begin
  CONF_imodule_get_module := LoadLibCryptoFunction('CONF_imodule_get_module');
  if not assigned(CONF_imodule_get_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_get_module');
  Result := CONF_imodule_get_module(md);
end;

function Load_CONF_imodule_get_flags(const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl;
begin
  CONF_imodule_get_flags := LoadLibCryptoFunction('CONF_imodule_get_flags');
  if not assigned(CONF_imodule_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_get_flags');
  Result := CONF_imodule_get_flags(md);
end;

procedure Load_CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl;
begin
  CONF_imodule_set_flags := LoadLibCryptoFunction('CONF_imodule_set_flags');
  if not assigned(CONF_imodule_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_set_flags');
  CONF_imodule_set_flags(md,flags);
end;

function Load_CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl;
begin
  CONF_module_get_usr_data := LoadLibCryptoFunction('CONF_module_get_usr_data');
  if not assigned(CONF_module_get_usr_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_module_get_usr_data');
  Result := CONF_module_get_usr_data(pmod);
end;

procedure Load_CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl;
begin
  CONF_module_set_usr_data := LoadLibCryptoFunction('CONF_module_set_usr_data');
  if not assigned(CONF_module_set_usr_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_module_set_usr_data');
  CONF_module_set_usr_data(pmod,usr_data);
end;

function Load_CONF_get1_default_config_file: PAnsiChar; cdecl;
begin
  CONF_get1_default_config_file := LoadLibCryptoFunction('CONF_get1_default_config_file');
  if not assigned(CONF_get1_default_config_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_get1_default_config_file');
  Result := CONF_get1_default_config_file();
end;

function Load_CONF_parse_list(const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  CONF_parse_list := LoadLibCryptoFunction('CONF_parse_list');
  if not assigned(CONF_parse_list) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_parse_list');
  Result := CONF_parse_list(list,sep,nospc,list_cb,arg);
end;

procedure Load_OPENSSL_load_builtin_modules; cdecl;
begin
  OPENSSL_load_builtin_modules := LoadLibCryptoFunction('OPENSSL_load_builtin_modules');
  if not assigned(OPENSSL_load_builtin_modules) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_load_builtin_modules');
  OPENSSL_load_builtin_modules();
end;


procedure UnLoad;
begin
  CONF_set_default_method := Load_CONF_set_default_method;
  NCONF_new := Load_NCONF_new;
  NCONF_default := Load_NCONF_default;
  NCONF_WIN32 := Load_NCONF_WIN32;
  NCONF_free := Load_NCONF_free;
  NCONF_free_data := Load_NCONF_free_data;
  NCONF_load := Load_NCONF_load;
  NCONF_load_bio := Load_NCONF_load_bio;
  NCONF_get_string := Load_NCONF_get_string;
  NCONF_get_number_e := Load_NCONF_get_number_e;
  NCONF_dump_bio := Load_NCONF_dump_bio;
  CONF_modules_load := Load_CONF_modules_load;
  CONF_modules_load_file := Load_CONF_modules_load_file;
  CONF_modules_unload := Load_CONF_modules_unload;
  CONF_modules_finish := Load_CONF_modules_finish;
  CONF_module_add := Load_CONF_module_add;
  CONF_imodule_get_usr_data := Load_CONF_imodule_get_usr_data;
  CONF_imodule_set_usr_data := Load_CONF_imodule_set_usr_data;
  CONF_imodule_get_module := Load_CONF_imodule_get_module;
  CONF_imodule_get_flags := Load_CONF_imodule_get_flags;
  CONF_imodule_set_flags := Load_CONF_imodule_set_flags;
  CONF_module_get_usr_data := Load_CONF_module_get_usr_data;
  CONF_module_set_usr_data := Load_CONF_module_set_usr_data;
  CONF_get1_default_config_file := Load_CONF_get1_default_config_file;
  CONF_parse_list := Load_CONF_parse_list;
  OPENSSL_load_builtin_modules := Load_OPENSSL_load_builtin_modules;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
