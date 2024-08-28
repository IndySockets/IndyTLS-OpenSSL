  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_conf.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_conf.h2pas
     and this file regenerated. IdOpenSSLHeaders_conf.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_conf;

interface

// Headers for OpenSSL 1.1.1
// conf.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_ossl_typ;

type
  CONF_parse_list_list_cb = function (const elem: PAnsiChar; len: TIdC_INT; usr: Pointer): TIdC_INT;

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

  (*conf_method_st = record
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
  end; *)

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
  conf_init_func = function(md: PCONF_IMODULE; const cnf: PCONF): TIdC_INT;
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  CONF_set_default_method: function (meth: PCONF_METHOD): TIdC_INT; cdecl = nil;
//  (*
//  void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
//  LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file, long *eline);
//  {$ifndef OPENSSL_NO_STDIO}
//  LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp, long *eline);
//  {$endif}
//  LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
//                                      long *eline);
//  STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
//                                         const char *section);
//  char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                        const char *name);
//  long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                       const char *name);
//  void CONF_free(LHASH_OF(CONF_VALUE) *conf);
//  #ifndef OPENSSL_NO_STDIO
//  int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
//  #endif
//  int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
//
//  DEPRECATEDIN_1_1_0(void OPENSSL_config(const char *config_name))
//
//  #if OPENSSL_API_COMPAT < 0x10100000L
//  # define OPENSSL_no_config() \
//      OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
//  #endif
//  *)

  (*
   * New conf code.  The semantics are different from the functions above. If
   * that wasn't the case, the above functions would have been replaced
   *)

  //type     Doppelt???
  //  conf_st = record
  //    CONF_METHOD *meth;
  //    void *meth_data;
  //    LHASH_OF(CONF_VALUE) *data;
  //  end;

  NCONF_new: function (meth: PCONF_METHOD): PCONF; cdecl = nil;
  NCONF_default: function : PCONF_METHOD; cdecl = nil;
  NCONF_WIN32: function : PCONF_METHOD; cdecl = nil;
  NCONF_free: procedure (conf: PCONF); cdecl = nil;
  NCONF_free_data: procedure (conf: PCONF); cdecl = nil;

  NCONF_load: function (conf: PCONF; const file_: PAnsiChar; eline: PIdC_LONG): TIdC_INT; cdecl = nil;
  NCONF_load_bio: function (conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT; cdecl = nil;
  //STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf,
  //                                        const char *section);
  NCONF_get_string: function (const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl = nil;
  NCONF_get_number_e: function (const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result: PIdC_LONG): TIdC_INT; cdecl = nil;
  NCONF_dump_bio: function (const conf: PCONf; out_: PBIO): TIdC_INT; cdecl = nil;

  //#define NCONF_get_number(c,g,n,r) NCONF_get_number_e(c,g,n,r)

  //* Module functions */

  CONF_modules_load: function (const cnf: PCONF; const appname: PAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  CONF_modules_load_file: function (const filename: PAnsiChar; const appname: PAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;

  CONF_modules_unload: procedure (all: TIdC_INT); cdecl = nil;
  CONF_modules_finish: procedure ; cdecl = nil;
  CONF_module_add: function (const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TIdC_INT; cdecl = nil;

  //const char *CONF_imodule_get_name(const CONF_IMODULE *md);
  //const char *CONF_imodule_get_value(const CONF_IMODULE *md);
  CONF_imodule_get_usr_data: function (const md: PCONF_IMODULE): Pointer; cdecl = nil;
  CONF_imodule_set_usr_data: procedure (md: PCONF_IMODULE; usr_data: Pointer); cdecl = nil;
  CONF_imodule_get_module: function (const md: PCONF_IMODULE): PCONF_MODULE; cdecl = nil;
  CONF_imodule_get_flags: function (const md: PCONF_IMODULE): TIdC_ULONG; cdecl = nil;
  CONF_imodule_set_flags: procedure (md: PCONF_IMODULE; flags: TIdC_ULONG); cdecl = nil;
  CONF_module_get_usr_data: function (pmod: PCONF_MODULE): Pointer; cdecl = nil;
  CONF_module_set_usr_data: procedure (pmod: PCONF_MODULE; usr_data: Pointer); cdecl = nil;

  CONF_get1_default_config_file: function : PAnsiChar; cdecl = nil;
  CONF_parse_list: function (const list: PAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TIdC_INT; cdecl = nil;

  OPENSSL_load_builtin_modules: procedure ; cdecl = nil;

{$ELSE}
  function CONF_set_default_method(meth: PCONF_METHOD): TIdC_INT cdecl; external CLibCrypto;
//  (*
//  void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
//  LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file, long *eline);
//  {$ifndef OPENSSL_NO_STDIO}
//  LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp, long *eline);
//  {$endif}
//  LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
//                                      long *eline);
//  STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
//                                         const char *section);
//  char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                        const char *name);
//  long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                       const char *name);
//  void CONF_free(LHASH_OF(CONF_VALUE) *conf);
//  #ifndef OPENSSL_NO_STDIO
//  int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
//  #endif
//  int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
//
//  DEPRECATEDIN_1_1_0(void OPENSSL_config(const char *config_name))
//
//  #if OPENSSL_API_COMPAT < 0x10100000L
//  # define OPENSSL_no_config() \
//      OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
//  #endif
//  *)

  (*
   * New conf code.  The semantics are different from the functions above. If
   * that wasn't the case, the above functions would have been replaced
   *)

  //type     Doppelt???
  //  conf_st = record
  //    CONF_METHOD *meth;
  //    void *meth_data;
  //    LHASH_OF(CONF_VALUE) *data;
  //  end;

  function NCONF_new(meth: PCONF_METHOD): PCONF cdecl; external CLibCrypto;
  function NCONF_default: PCONF_METHOD cdecl; external CLibCrypto;
  function NCONF_WIN32: PCONF_METHOD cdecl; external CLibCrypto;
  procedure NCONF_free(conf: PCONF) cdecl; external CLibCrypto;
  procedure NCONF_free_data(conf: PCONF) cdecl; external CLibCrypto;

  function NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: PIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  function NCONF_load_bio(conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  //STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf,
  //                                        const char *section);
  function NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar cdecl; external CLibCrypto;
  function NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result: PIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  function NCONF_dump_bio(const conf: PCONf; out_: PBIO): TIdC_INT cdecl; external CLibCrypto;

  //#define NCONF_get_number(c,g,n,r) NCONF_get_number_e(c,g,n,r)

  //* Module functions */

  function CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;

  procedure CONF_modules_unload(all: TIdC_INT) cdecl; external CLibCrypto;
  procedure CONF_modules_finish cdecl; external CLibCrypto;
  function CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TIdC_INT cdecl; external CLibCrypto;

  //const char *CONF_imodule_get_name(const CONF_IMODULE *md);
  //const char *CONF_imodule_get_value(const CONF_IMODULE *md);
  function CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer cdecl; external CLibCrypto;
  procedure CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer) cdecl; external CLibCrypto;
  function CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE cdecl; external CLibCrypto;
  function CONF_imodule_get_flags(const md: PCONF_IMODULE): TIdC_ULONG cdecl; external CLibCrypto;
  procedure CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TIdC_ULONG) cdecl; external CLibCrypto;
  function CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer cdecl; external CLibCrypto;
  procedure CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer) cdecl; external CLibCrypto;

  function CONF_get1_default_config_file: PAnsiChar cdecl; external CLibCrypto;
  function CONF_parse_list(const list: PAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;

  procedure OPENSSL_load_builtin_modules cdecl; external CLibCrypto;

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
  CONF_set_default_method_procname = 'CONF_set_default_method';
//  (*
//  void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
//  LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file, long *eline);
//  {$ifndef OPENSSL_NO_STDIO}
//  LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp, long *eline);
//  {$endif}
//  LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
//                                      long *eline);
//  STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
//                                         const char *section);
//  char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                        const char *name);
//  long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                       const char *name);
//  void CONF_free(LHASH_OF(CONF_VALUE) *conf);
//  #ifndef OPENSSL_NO_STDIO
//  int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
//  #endif
//  int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
//
//  DEPRECATEDIN_1_1_0(void OPENSSL_config(const char *config_name))
//
//  #if OPENSSL_API_COMPAT < 0x10100000L
//  # define OPENSSL_no_config() \
//      OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
//  #endif
//  *)

  (*
   * New conf code.  The semantics are different from the functions above. If
   * that wasn't the case, the above functions would have been replaced
   *)

  //type     Doppelt???
  //  conf_st = record
  //    CONF_METHOD *meth;
  //    void *meth_data;
  //    LHASH_OF(CONF_VALUE) *data;
  //  end;

  NCONF_new_procname = 'NCONF_new';
  NCONF_default_procname = 'NCONF_default';
  NCONF_WIN32_procname = 'NCONF_WIN32';
  NCONF_free_procname = 'NCONF_free';
  NCONF_free_data_procname = 'NCONF_free_data';

  NCONF_load_procname = 'NCONF_load';
  NCONF_load_bio_procname = 'NCONF_load_bio';
  //STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf,
  //                                        const char *section);
  NCONF_get_string_procname = 'NCONF_get_string';
  NCONF_get_number_e_procname = 'NCONF_get_number_e';
  NCONF_dump_bio_procname = 'NCONF_dump_bio';

  //#define NCONF_get_number(c,g,n,r) NCONF_get_number_e(c,g,n,r)

  //* Module functions */

  CONF_modules_load_procname = 'CONF_modules_load';
  CONF_modules_load_file_procname = 'CONF_modules_load_file';

  CONF_modules_unload_procname = 'CONF_modules_unload';
  CONF_modules_finish_procname = 'CONF_modules_finish';
  CONF_module_add_procname = 'CONF_module_add';

  //const char *CONF_imodule_get_name(const CONF_IMODULE *md);
  //const char *CONF_imodule_get_value(const CONF_IMODULE *md);
  CONF_imodule_get_usr_data_procname = 'CONF_imodule_get_usr_data';
  CONF_imodule_set_usr_data_procname = 'CONF_imodule_set_usr_data';
  CONF_imodule_get_module_procname = 'CONF_imodule_get_module';
  CONF_imodule_get_flags_procname = 'CONF_imodule_get_flags';
  CONF_imodule_set_flags_procname = 'CONF_imodule_set_flags';
  CONF_module_get_usr_data_procname = 'CONF_module_get_usr_data';
  CONF_module_set_usr_data_procname = 'CONF_module_set_usr_data';

  CONF_get1_default_config_file_procname = 'CONF_get1_default_config_file';
  CONF_parse_list_procname = 'CONF_parse_list';

  OPENSSL_load_builtin_modules_procname = 'OPENSSL_load_builtin_modules';


{$WARN  NO_RETVAL OFF}
function  ERR_CONF_set_default_method(meth: PCONF_METHOD): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_set_default_method_procname);
end;


//  (*
//  void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
//  LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file, long *eline);
//  {$ifndef OPENSSL_NO_STDIO}
//  LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp, long *eline);
//  {$endif}
//  LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
//                                      long *eline);
//  STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
//                                         const char *section);
//  char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                        const char *name);
//  long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
//                       const char *name);
//  void CONF_free(LHASH_OF(CONF_VALUE) *conf);
//  #ifndef OPENSSL_NO_STDIO
//  int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
//  #endif
//  int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
//
//  DEPRECATEDIN_1_1_0(void OPENSSL_config(const char *config_name))
//
//  #if OPENSSL_API_COMPAT < 0x10100000L
//  # define OPENSSL_no_config() \
//      OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
//  #endif
//  *)

  (*
   * New conf code.  The semantics are different from the functions above. If
   * that wasn't the case, the above functions would have been replaced
   *)

  //type     Doppelt???
  //  conf_st = record
  //    CONF_METHOD *meth;
  //    void *meth_data;
  //    LHASH_OF(CONF_VALUE) *data;
  //  end;

function  ERR_NCONF_new(meth: PCONF_METHOD): PCONF; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_new_procname);
end;


function  ERR_NCONF_default: PCONF_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_default_procname);
end;


function  ERR_NCONF_WIN32: PCONF_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_WIN32_procname);
end;


procedure  ERR_NCONF_free(conf: PCONF); 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_free_procname);
end;


procedure  ERR_NCONF_free_data(conf: PCONF); 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_free_data_procname);
end;



function  ERR_NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: PIdC_LONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_load_procname);
end;


function  ERR_NCONF_load_bio(conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_load_bio_procname);
end;


  //STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf,
  //                                        const char *section);
function  ERR_NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_get_string_procname);
end;


function  ERR_NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result: PIdC_LONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_get_number_e_procname);
end;


function  ERR_NCONF_dump_bio(const conf: PCONf; out_: PBIO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(NCONF_dump_bio_procname);
end;



  //#define NCONF_get_number(c,g,n,r) NCONF_get_number_e(c,g,n,r)

  //* Module functions */

function  ERR_CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TIdC_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_modules_load_procname);
end;


function  ERR_CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TIdC_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_modules_load_file_procname);
end;



procedure  ERR_CONF_modules_unload(all: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_modules_unload_procname);
end;


procedure  ERR_CONF_modules_finish; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_modules_finish_procname);
end;


function  ERR_CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_module_add_procname);
end;



  //const char *CONF_imodule_get_name(const CONF_IMODULE *md);
  //const char *CONF_imodule_get_value(const CONF_IMODULE *md);
function  ERR_CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_imodule_get_usr_data_procname);
end;


procedure  ERR_CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_imodule_set_usr_data_procname);
end;


function  ERR_CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_imodule_get_module_procname);
end;


function  ERR_CONF_imodule_get_flags(const md: PCONF_IMODULE): TIdC_ULONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_imodule_get_flags_procname);
end;


procedure  ERR_CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TIdC_ULONG); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_imodule_set_flags_procname);
end;


function  ERR_CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_module_get_usr_data_procname);
end;


procedure  ERR_CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_module_set_usr_data_procname);
end;



function  ERR_CONF_get1_default_config_file: PAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_get1_default_config_file_procname);
end;


function  ERR_CONF_parse_list(const list: PAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CONF_parse_list_procname);
end;



procedure  ERR_OPENSSL_load_builtin_modules; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_load_builtin_modules_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  CONF_set_default_method := LoadLibFunction(ADllHandle, CONF_set_default_method_procname);
  FuncLoadError := not assigned(CONF_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(CONF_set_default_method_allownil)}
    CONF_set_default_method := @ERR_CONF_set_default_method;
    {$ifend}
    {$if declared(CONF_set_default_method_introduced)}
    if LibVersion < CONF_set_default_method_introduced then
    begin
      {$if declared(FC_CONF_set_default_method)}
      CONF_set_default_method := @FC_CONF_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_set_default_method_removed)}
    if CONF_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_CONF_set_default_method)}
      CONF_set_default_method := @_CONF_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_set_default_method');
    {$ifend}
  end;


  NCONF_new := LoadLibFunction(ADllHandle, NCONF_new_procname);
  FuncLoadError := not assigned(NCONF_new);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_new_allownil)}
    NCONF_new := @ERR_NCONF_new;
    {$ifend}
    {$if declared(NCONF_new_introduced)}
    if LibVersion < NCONF_new_introduced then
    begin
      {$if declared(FC_NCONF_new)}
      NCONF_new := @FC_NCONF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_new_removed)}
    if NCONF_new_removed <= LibVersion then
    begin
      {$if declared(_NCONF_new)}
      NCONF_new := @_NCONF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_new');
    {$ifend}
  end;


  NCONF_default := LoadLibFunction(ADllHandle, NCONF_default_procname);
  FuncLoadError := not assigned(NCONF_default);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_default_allownil)}
    NCONF_default := @ERR_NCONF_default;
    {$ifend}
    {$if declared(NCONF_default_introduced)}
    if LibVersion < NCONF_default_introduced then
    begin
      {$if declared(FC_NCONF_default)}
      NCONF_default := @FC_NCONF_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_default_removed)}
    if NCONF_default_removed <= LibVersion then
    begin
      {$if declared(_NCONF_default)}
      NCONF_default := @_NCONF_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_default_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_default');
    {$ifend}
  end;


  NCONF_WIN32 := LoadLibFunction(ADllHandle, NCONF_WIN32_procname);
  FuncLoadError := not assigned(NCONF_WIN32);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_WIN32_allownil)}
    NCONF_WIN32 := @ERR_NCONF_WIN32;
    {$ifend}
    {$if declared(NCONF_WIN32_introduced)}
    if LibVersion < NCONF_WIN32_introduced then
    begin
      {$if declared(FC_NCONF_WIN32)}
      NCONF_WIN32 := @FC_NCONF_WIN32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_WIN32_removed)}
    if NCONF_WIN32_removed <= LibVersion then
    begin
      {$if declared(_NCONF_WIN32)}
      NCONF_WIN32 := @_NCONF_WIN32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_WIN32_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_WIN32');
    {$ifend}
  end;


  NCONF_free := LoadLibFunction(ADllHandle, NCONF_free_procname);
  FuncLoadError := not assigned(NCONF_free);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_free_allownil)}
    NCONF_free := @ERR_NCONF_free;
    {$ifend}
    {$if declared(NCONF_free_introduced)}
    if LibVersion < NCONF_free_introduced then
    begin
      {$if declared(FC_NCONF_free)}
      NCONF_free := @FC_NCONF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_free_removed)}
    if NCONF_free_removed <= LibVersion then
    begin
      {$if declared(_NCONF_free)}
      NCONF_free := @_NCONF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_free');
    {$ifend}
  end;


  NCONF_free_data := LoadLibFunction(ADllHandle, NCONF_free_data_procname);
  FuncLoadError := not assigned(NCONF_free_data);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_free_data_allownil)}
    NCONF_free_data := @ERR_NCONF_free_data;
    {$ifend}
    {$if declared(NCONF_free_data_introduced)}
    if LibVersion < NCONF_free_data_introduced then
    begin
      {$if declared(FC_NCONF_free_data)}
      NCONF_free_data := @FC_NCONF_free_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_free_data_removed)}
    if NCONF_free_data_removed <= LibVersion then
    begin
      {$if declared(_NCONF_free_data)}
      NCONF_free_data := @_NCONF_free_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_free_data_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_free_data');
    {$ifend}
  end;


  NCONF_load := LoadLibFunction(ADllHandle, NCONF_load_procname);
  FuncLoadError := not assigned(NCONF_load);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_load_allownil)}
    NCONF_load := @ERR_NCONF_load;
    {$ifend}
    {$if declared(NCONF_load_introduced)}
    if LibVersion < NCONF_load_introduced then
    begin
      {$if declared(FC_NCONF_load)}
      NCONF_load := @FC_NCONF_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_load_removed)}
    if NCONF_load_removed <= LibVersion then
    begin
      {$if declared(_NCONF_load)}
      NCONF_load := @_NCONF_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_load_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_load');
    {$ifend}
  end;


  NCONF_load_bio := LoadLibFunction(ADllHandle, NCONF_load_bio_procname);
  FuncLoadError := not assigned(NCONF_load_bio);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_load_bio_allownil)}
    NCONF_load_bio := @ERR_NCONF_load_bio;
    {$ifend}
    {$if declared(NCONF_load_bio_introduced)}
    if LibVersion < NCONF_load_bio_introduced then
    begin
      {$if declared(FC_NCONF_load_bio)}
      NCONF_load_bio := @FC_NCONF_load_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_load_bio_removed)}
    if NCONF_load_bio_removed <= LibVersion then
    begin
      {$if declared(_NCONF_load_bio)}
      NCONF_load_bio := @_NCONF_load_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_load_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_load_bio');
    {$ifend}
  end;


  NCONF_get_string := LoadLibFunction(ADllHandle, NCONF_get_string_procname);
  FuncLoadError := not assigned(NCONF_get_string);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get_string_allownil)}
    NCONF_get_string := @ERR_NCONF_get_string;
    {$ifend}
    {$if declared(NCONF_get_string_introduced)}
    if LibVersion < NCONF_get_string_introduced then
    begin
      {$if declared(FC_NCONF_get_string)}
      NCONF_get_string := @FC_NCONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get_string_removed)}
    if NCONF_get_string_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get_string)}
      NCONF_get_string := @_NCONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get_string');
    {$ifend}
  end;


  NCONF_get_number_e := LoadLibFunction(ADllHandle, NCONF_get_number_e_procname);
  FuncLoadError := not assigned(NCONF_get_number_e);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get_number_e_allownil)}
    NCONF_get_number_e := @ERR_NCONF_get_number_e;
    {$ifend}
    {$if declared(NCONF_get_number_e_introduced)}
    if LibVersion < NCONF_get_number_e_introduced then
    begin
      {$if declared(FC_NCONF_get_number_e)}
      NCONF_get_number_e := @FC_NCONF_get_number_e;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get_number_e_removed)}
    if NCONF_get_number_e_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get_number_e)}
      NCONF_get_number_e := @_NCONF_get_number_e;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get_number_e_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get_number_e');
    {$ifend}
  end;


  NCONF_dump_bio := LoadLibFunction(ADllHandle, NCONF_dump_bio_procname);
  FuncLoadError := not assigned(NCONF_dump_bio);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_dump_bio_allownil)}
    NCONF_dump_bio := @ERR_NCONF_dump_bio;
    {$ifend}
    {$if declared(NCONF_dump_bio_introduced)}
    if LibVersion < NCONF_dump_bio_introduced then
    begin
      {$if declared(FC_NCONF_dump_bio)}
      NCONF_dump_bio := @FC_NCONF_dump_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_dump_bio_removed)}
    if NCONF_dump_bio_removed <= LibVersion then
    begin
      {$if declared(_NCONF_dump_bio)}
      NCONF_dump_bio := @_NCONF_dump_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_dump_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_dump_bio');
    {$ifend}
  end;


  CONF_modules_load := LoadLibFunction(ADllHandle, CONF_modules_load_procname);
  FuncLoadError := not assigned(CONF_modules_load);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_load_allownil)}
    CONF_modules_load := @ERR_CONF_modules_load;
    {$ifend}
    {$if declared(CONF_modules_load_introduced)}
    if LibVersion < CONF_modules_load_introduced then
    begin
      {$if declared(FC_CONF_modules_load)}
      CONF_modules_load := @FC_CONF_modules_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_load_removed)}
    if CONF_modules_load_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_load)}
      CONF_modules_load := @_CONF_modules_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_load_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_load');
    {$ifend}
  end;


  CONF_modules_load_file := LoadLibFunction(ADllHandle, CONF_modules_load_file_procname);
  FuncLoadError := not assigned(CONF_modules_load_file);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_load_file_allownil)}
    CONF_modules_load_file := @ERR_CONF_modules_load_file;
    {$ifend}
    {$if declared(CONF_modules_load_file_introduced)}
    if LibVersion < CONF_modules_load_file_introduced then
    begin
      {$if declared(FC_CONF_modules_load_file)}
      CONF_modules_load_file := @FC_CONF_modules_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_load_file_removed)}
    if CONF_modules_load_file_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_load_file)}
      CONF_modules_load_file := @_CONF_modules_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_load_file');
    {$ifend}
  end;


  CONF_modules_unload := LoadLibFunction(ADllHandle, CONF_modules_unload_procname);
  FuncLoadError := not assigned(CONF_modules_unload);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_unload_allownil)}
    CONF_modules_unload := @ERR_CONF_modules_unload;
    {$ifend}
    {$if declared(CONF_modules_unload_introduced)}
    if LibVersion < CONF_modules_unload_introduced then
    begin
      {$if declared(FC_CONF_modules_unload)}
      CONF_modules_unload := @FC_CONF_modules_unload;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_unload_removed)}
    if CONF_modules_unload_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_unload)}
      CONF_modules_unload := @_CONF_modules_unload;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_unload_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_unload');
    {$ifend}
  end;


  CONF_modules_finish := LoadLibFunction(ADllHandle, CONF_modules_finish_procname);
  FuncLoadError := not assigned(CONF_modules_finish);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_finish_allownil)}
    CONF_modules_finish := @ERR_CONF_modules_finish;
    {$ifend}
    {$if declared(CONF_modules_finish_introduced)}
    if LibVersion < CONF_modules_finish_introduced then
    begin
      {$if declared(FC_CONF_modules_finish)}
      CONF_modules_finish := @FC_CONF_modules_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_finish_removed)}
    if CONF_modules_finish_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_finish)}
      CONF_modules_finish := @_CONF_modules_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_finish');
    {$ifend}
  end;


  CONF_module_add := LoadLibFunction(ADllHandle, CONF_module_add_procname);
  FuncLoadError := not assigned(CONF_module_add);
  if FuncLoadError then
  begin
    {$if not defined(CONF_module_add_allownil)}
    CONF_module_add := @ERR_CONF_module_add;
    {$ifend}
    {$if declared(CONF_module_add_introduced)}
    if LibVersion < CONF_module_add_introduced then
    begin
      {$if declared(FC_CONF_module_add)}
      CONF_module_add := @FC_CONF_module_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_module_add_removed)}
    if CONF_module_add_removed <= LibVersion then
    begin
      {$if declared(_CONF_module_add)}
      CONF_module_add := @_CONF_module_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_module_add_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_module_add');
    {$ifend}
  end;


  CONF_imodule_get_usr_data := LoadLibFunction(ADllHandle, CONF_imodule_get_usr_data_procname);
  FuncLoadError := not assigned(CONF_imodule_get_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_usr_data_allownil)}
    CONF_imodule_get_usr_data := @ERR_CONF_imodule_get_usr_data;
    {$ifend}
    {$if declared(CONF_imodule_get_usr_data_introduced)}
    if LibVersion < CONF_imodule_get_usr_data_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_usr_data)}
      CONF_imodule_get_usr_data := @FC_CONF_imodule_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_usr_data_removed)}
    if CONF_imodule_get_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_usr_data)}
      CONF_imodule_get_usr_data := @_CONF_imodule_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_usr_data');
    {$ifend}
  end;


  CONF_imodule_set_usr_data := LoadLibFunction(ADllHandle, CONF_imodule_set_usr_data_procname);
  FuncLoadError := not assigned(CONF_imodule_set_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_set_usr_data_allownil)}
    CONF_imodule_set_usr_data := @ERR_CONF_imodule_set_usr_data;
    {$ifend}
    {$if declared(CONF_imodule_set_usr_data_introduced)}
    if LibVersion < CONF_imodule_set_usr_data_introduced then
    begin
      {$if declared(FC_CONF_imodule_set_usr_data)}
      CONF_imodule_set_usr_data := @FC_CONF_imodule_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_set_usr_data_removed)}
    if CONF_imodule_set_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_set_usr_data)}
      CONF_imodule_set_usr_data := @_CONF_imodule_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_set_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_set_usr_data');
    {$ifend}
  end;


  CONF_imodule_get_module := LoadLibFunction(ADllHandle, CONF_imodule_get_module_procname);
  FuncLoadError := not assigned(CONF_imodule_get_module);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_module_allownil)}
    CONF_imodule_get_module := @ERR_CONF_imodule_get_module;
    {$ifend}
    {$if declared(CONF_imodule_get_module_introduced)}
    if LibVersion < CONF_imodule_get_module_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_module)}
      CONF_imodule_get_module := @FC_CONF_imodule_get_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_module_removed)}
    if CONF_imodule_get_module_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_module)}
      CONF_imodule_get_module := @_CONF_imodule_get_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_module_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_module');
    {$ifend}
  end;


  CONF_imodule_get_flags := LoadLibFunction(ADllHandle, CONF_imodule_get_flags_procname);
  FuncLoadError := not assigned(CONF_imodule_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_flags_allownil)}
    CONF_imodule_get_flags := @ERR_CONF_imodule_get_flags;
    {$ifend}
    {$if declared(CONF_imodule_get_flags_introduced)}
    if LibVersion < CONF_imodule_get_flags_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_flags)}
      CONF_imodule_get_flags := @FC_CONF_imodule_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_flags_removed)}
    if CONF_imodule_get_flags_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_flags)}
      CONF_imodule_get_flags := @_CONF_imodule_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_flags');
    {$ifend}
  end;


  CONF_imodule_set_flags := LoadLibFunction(ADllHandle, CONF_imodule_set_flags_procname);
  FuncLoadError := not assigned(CONF_imodule_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_set_flags_allownil)}
    CONF_imodule_set_flags := @ERR_CONF_imodule_set_flags;
    {$ifend}
    {$if declared(CONF_imodule_set_flags_introduced)}
    if LibVersion < CONF_imodule_set_flags_introduced then
    begin
      {$if declared(FC_CONF_imodule_set_flags)}
      CONF_imodule_set_flags := @FC_CONF_imodule_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_set_flags_removed)}
    if CONF_imodule_set_flags_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_set_flags)}
      CONF_imodule_set_flags := @_CONF_imodule_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_set_flags');
    {$ifend}
  end;


  CONF_module_get_usr_data := LoadLibFunction(ADllHandle, CONF_module_get_usr_data_procname);
  FuncLoadError := not assigned(CONF_module_get_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_module_get_usr_data_allownil)}
    CONF_module_get_usr_data := @ERR_CONF_module_get_usr_data;
    {$ifend}
    {$if declared(CONF_module_get_usr_data_introduced)}
    if LibVersion < CONF_module_get_usr_data_introduced then
    begin
      {$if declared(FC_CONF_module_get_usr_data)}
      CONF_module_get_usr_data := @FC_CONF_module_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_module_get_usr_data_removed)}
    if CONF_module_get_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_module_get_usr_data)}
      CONF_module_get_usr_data := @_CONF_module_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_module_get_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_module_get_usr_data');
    {$ifend}
  end;


  CONF_module_set_usr_data := LoadLibFunction(ADllHandle, CONF_module_set_usr_data_procname);
  FuncLoadError := not assigned(CONF_module_set_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_module_set_usr_data_allownil)}
    CONF_module_set_usr_data := @ERR_CONF_module_set_usr_data;
    {$ifend}
    {$if declared(CONF_module_set_usr_data_introduced)}
    if LibVersion < CONF_module_set_usr_data_introduced then
    begin
      {$if declared(FC_CONF_module_set_usr_data)}
      CONF_module_set_usr_data := @FC_CONF_module_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_module_set_usr_data_removed)}
    if CONF_module_set_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_module_set_usr_data)}
      CONF_module_set_usr_data := @_CONF_module_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_module_set_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_module_set_usr_data');
    {$ifend}
  end;


  CONF_get1_default_config_file := LoadLibFunction(ADllHandle, CONF_get1_default_config_file_procname);
  FuncLoadError := not assigned(CONF_get1_default_config_file);
  if FuncLoadError then
  begin
    {$if not defined(CONF_get1_default_config_file_allownil)}
    CONF_get1_default_config_file := @ERR_CONF_get1_default_config_file;
    {$ifend}
    {$if declared(CONF_get1_default_config_file_introduced)}
    if LibVersion < CONF_get1_default_config_file_introduced then
    begin
      {$if declared(FC_CONF_get1_default_config_file)}
      CONF_get1_default_config_file := @FC_CONF_get1_default_config_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_get1_default_config_file_removed)}
    if CONF_get1_default_config_file_removed <= LibVersion then
    begin
      {$if declared(_CONF_get1_default_config_file)}
      CONF_get1_default_config_file := @_CONF_get1_default_config_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_get1_default_config_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_get1_default_config_file');
    {$ifend}
  end;


  CONF_parse_list := LoadLibFunction(ADllHandle, CONF_parse_list_procname);
  FuncLoadError := not assigned(CONF_parse_list);
  if FuncLoadError then
  begin
    {$if not defined(CONF_parse_list_allownil)}
    CONF_parse_list := @ERR_CONF_parse_list;
    {$ifend}
    {$if declared(CONF_parse_list_introduced)}
    if LibVersion < CONF_parse_list_introduced then
    begin
      {$if declared(FC_CONF_parse_list)}
      CONF_parse_list := @FC_CONF_parse_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_parse_list_removed)}
    if CONF_parse_list_removed <= LibVersion then
    begin
      {$if declared(_CONF_parse_list)}
      CONF_parse_list := @_CONF_parse_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_parse_list_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_parse_list');
    {$ifend}
  end;


  OPENSSL_load_builtin_modules := LoadLibFunction(ADllHandle, OPENSSL_load_builtin_modules_procname);
  FuncLoadError := not assigned(OPENSSL_load_builtin_modules);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_builtin_modules_allownil)}
    OPENSSL_load_builtin_modules := @ERR_OPENSSL_load_builtin_modules;
    {$ifend}
    {$if declared(OPENSSL_load_builtin_modules_introduced)}
    if LibVersion < OPENSSL_load_builtin_modules_introduced then
    begin
      {$if declared(FC_OPENSSL_load_builtin_modules)}
      OPENSSL_load_builtin_modules := @FC_OPENSSL_load_builtin_modules;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_builtin_modules_removed)}
    if OPENSSL_load_builtin_modules_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_builtin_modules)}
      OPENSSL_load_builtin_modules := @_OPENSSL_load_builtin_modules;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_builtin_modules_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_builtin_modules');
    {$ifend}
  end;


end;

procedure Unload;
begin
  CONF_set_default_method := nil;
  NCONF_new := nil;
  NCONF_default := nil;
  NCONF_WIN32 := nil;
  NCONF_free := nil;
  NCONF_free_data := nil;
  NCONF_load := nil;
  NCONF_load_bio := nil;
  NCONF_get_string := nil;
  NCONF_get_number_e := nil;
  NCONF_dump_bio := nil;
  CONF_modules_load := nil;
  CONF_modules_load_file := nil;
  CONF_modules_unload := nil;
  CONF_modules_finish := nil;
  CONF_module_add := nil;
  CONF_imodule_get_usr_data := nil;
  CONF_imodule_set_usr_data := nil;
  CONF_imodule_get_module := nil;
  CONF_imodule_get_flags := nil;
  CONF_imodule_set_flags := nil;
  CONF_module_get_usr_data := nil;
  CONF_module_set_usr_data := nil;
  CONF_get1_default_config_file := nil;
  CONF_parse_list := nil;
  OPENSSL_load_builtin_modules := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
