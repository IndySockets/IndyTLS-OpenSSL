(* This unit was generated from the source file ui.h2pas 
It should not be modified directly. All changes should be made to ui.h2pas
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


unit IdOpenSSLHeaders_ui;


interface

// Headers for OpenSSL 1.1.1
// ui.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_crypto,
  IdOpenSSLHeaders_pem,
  IdOpenSSLHeaders_uierr;

{$MINENUMSIZE 4}

const
  (* These are the possible flags.  They can be or'ed together. *)
  (* Use to have echoing of input *)
  UI_INPUT_FLAG_ECHO = $01;
  (*
   * Use a default password.  Where that password is found is completely up to
   * the application, it might for example be in the user data set with
   * UI_add_user_data().  It is not recommended to have more than one input in
   * each UI being marked with this flag, or the application might get
   * confused.
   *)
  UI_INPUT_FLAG_DEFAULT_PWD = $02;


  (*
   * The user of these routines may want to define flags of their own.  The core
   * UI won't look at those, but will pass them on to the method routines.  They
   * must use higher bits so they don't get confused with the UI bits above.
   * UI_INPUT_FLAG_USER_BASE tells which is the lowest bit to use.  A good
   * example of use is this:
   *
   *    #define MY_UI_FLAG1       (0x01 << UI_INPUT_FLAG_USER_BASE)
   *
  *)
  UI_INPUT_FLAG_USER_BASE = 16;

  (* The commands *)
  (*
   * Use UI_CONTROL_PRINT_ERRORS with the value 1 to have UI_process print the
   * OpenSSL error stack before printing any info or added error messages and
   * before any prompting.
   *)
  UI_CTRL_PRINT_ERRORS = 1;
  (*
   * Check if a UI_process() is possible to do again with the same instance of
   * a user interface.  This makes UI_ctrl() return 1 if it is redoable, and 0
   * if not.
   *)
  UI_CTRL_IS_REDOABLE = 2;

type
  (*
   * Give a user interface parameterised control commands.  This can be used to
   * send down an integer, a data pointer or a function pointer, as well as be
   * used to get information from a UI.
   *)
  UI_ctrl_f = procedure;

  (*
   * The UI_STRING type is the data structure that contains all the needed info
   * about a string or a prompt, including test data for a verification prompt.
   *)
  ui_string_st = type Pointer;
  UI_STRING = ui_string_st;
  PUI_STRING = ^UI_STRING;
// DEFINE_STACK_OF(UI_STRING)

  (*
   * The different types of strings that are currently supported. This is only
   * needed by method authors.
   *)
  UI_string_types = (
    UIT_NONE = 0,
    UIT_PROMPT,                 (* Prompt for a string *)
    UIT_VERIFY,                 (* Prompt for a string and verify *)
    UIT_BOOLEAN,                (* Prompt for a yes/no response *)
    UIT_INFO,                   (* Send info to the user *)
    UIT_ERROR                   (* Send an error message to the user *)
  );

  (* Create and manipulate methods *)
  UI_method_opener_cb = function(ui: PUI): TOpenSSL_C_INT;
  UI_method_writer_cb = function(ui: PUI; uis: PUI_String): TOpenSSL_C_INT;
  UI_method_flusher_cb = function(ui: PUI): TOpenSSL_C_INT;
  UI_method_reader_cb = function(ui: PUI; uis: PUI_String): TOpenSSL_C_INT;
  UI_method_closer_cb = function(ui: PUI): TOpenSSL_C_INT;
  UI_method_data_duplicator_cb = function(ui: PUI; ui_data: Pointer): Pointer;
  UI_method_data_destructor_cb = procedure(ui: PUI; ui_data: Pointer);
  UI_method_prompt_constructor_cb = function(ui: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar;

  (*
   * All the following functions return -1 or NULL on error and in some cases
   * (UI_process()) -2 if interrupted or in some other way cancelled. When
   * everything is fine, they return 0, a positive value or a non-NULL pointer,
   * all depending on their purpose.
   *)

  (* Creators and destructor.   *)
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM UI_new}
{$EXTERNALSYM UI_new_method}
{$EXTERNALSYM UI_free}
{$EXTERNALSYM UI_add_input_string}
{$EXTERNALSYM UI_dup_input_string}
{$EXTERNALSYM UI_add_verify_string}
{$EXTERNALSYM UI_dup_verify_string}
{$EXTERNALSYM UI_add_input_boolean}
{$EXTERNALSYM UI_dup_input_boolean}
{$EXTERNALSYM UI_add_info_string}
{$EXTERNALSYM UI_dup_info_string}
{$EXTERNALSYM UI_add_error_string}
{$EXTERNALSYM UI_dup_error_string}
{$EXTERNALSYM UI_construct_prompt}
{$EXTERNALSYM UI_add_user_data}
{$EXTERNALSYM UI_dup_user_data}
{$EXTERNALSYM UI_get0_user_data}
{$EXTERNALSYM UI_get0_result}
{$EXTERNALSYM UI_get_result_length}
{$EXTERNALSYM UI_process}
{$EXTERNALSYM UI_ctrl}
{$EXTERNALSYM UI_set_ex_data}
{$EXTERNALSYM UI_get_ex_data}
{$EXTERNALSYM UI_set_default_method}
{$EXTERNALSYM UI_get_default_method}
{$EXTERNALSYM UI_get_method}
{$EXTERNALSYM UI_set_method}
{$EXTERNALSYM UI_OpenSSL}
{$EXTERNALSYM UI_null}
{$EXTERNALSYM UI_create_method}
{$EXTERNALSYM UI_destroy_method}
{$EXTERNALSYM UI_method_set_opener}
{$EXTERNALSYM UI_method_set_writer}
{$EXTERNALSYM UI_method_set_flusher}
{$EXTERNALSYM UI_method_set_reader}
{$EXTERNALSYM UI_method_set_closer}
{$EXTERNALSYM UI_method_set_data_duplicator}
{$EXTERNALSYM UI_method_set_prompt_constructor}
{$EXTERNALSYM UI_method_set_ex_data}
{$EXTERNALSYM UI_method_get_opener}
{$EXTERNALSYM UI_method_get_writer}
{$EXTERNALSYM UI_method_get_flusher}
{$EXTERNALSYM UI_method_get_reader}
{$EXTERNALSYM UI_method_get_closer}
{$EXTERNALSYM UI_method_get_prompt_constructor}
{$EXTERNALSYM UI_method_get_data_duplicator}
{$EXTERNALSYM UI_method_get_data_destructor}
{$EXTERNALSYM UI_method_get_ex_data}
{$EXTERNALSYM UI_get_string_type}
{$EXTERNALSYM UI_get_input_flags}
{$EXTERNALSYM UI_get0_output_string}
{$EXTERNALSYM UI_get0_action_string}
{$EXTERNALSYM UI_get0_result_string}
{$EXTERNALSYM UI_get_result_string_length}
{$EXTERNALSYM UI_get0_test_string}
{$EXTERNALSYM UI_get_result_minsize}
{$EXTERNALSYM UI_get_result_maxsize}
{$EXTERNALSYM UI_set_result}
{$EXTERNALSYM UI_set_result_ex}
{$EXTERNALSYM UI_UTIL_read_pw_string}
{$EXTERNALSYM UI_UTIL_read_pw}
{$EXTERNALSYM UI_UTIL_wrap_read_pem_callback}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function UI_new: PUI; cdecl; external CLibCrypto;
function UI_new_method(const method: PUI_Method): PUI; cdecl; external CLibCrypto;
procedure UI_free(ui: PUI); cdecl; external CLibCrypto;
function UI_add_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_construct_prompt(ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl; external CLibCrypto;
function UI_dup_user_data(ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get0_user_data(ui: PUI): Pointer; cdecl; external CLibCrypto;
function UI_get0_result(ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function UI_get_result_length(ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_process(ui: PUI): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_ctrl(ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_set_ex_data(r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get_ex_data(r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
procedure UI_set_default_method(const meth: PUI_Method); cdecl; external CLibCrypto;
function UI_get_default_method: PUI_METHOD; cdecl; external CLibCrypto;
function UI_get_method(ui: PUI): PUI_METHOD; cdecl; external CLibCrypto;
function UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl; external CLibCrypto;
function UI_OpenSSL: PUI_Method; cdecl; external CLibCrypto;
function UI_null: PUI_METHOD; cdecl; external CLibCrypto;
function UI_create_method(const name: PAnsiChar): PUI_Method; cdecl; external CLibCrypto;
procedure UI_destroy_method(ui_method: PUI_Method); cdecl; external CLibCrypto;
function UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_ex_data(method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb; cdecl; external CLibCrypto;
function UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb; cdecl; external CLibCrypto;
function UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb; cdecl; external CLibCrypto;
function UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb; cdecl; external CLibCrypto;
function UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb; cdecl; external CLibCrypto;
function UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl; external CLibCrypto;
function UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl; external CLibCrypto;
function UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl; external CLibCrypto;
function UI_method_get_ex_data(const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function UI_get_string_type(uis: PUI_String): UI_string_types; cdecl; external CLibCrypto;
function UI_get_input_flags(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get0_output_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get0_action_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get0_result_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get_result_string_length(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get0_test_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get_result_minsize(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get_result_maxsize(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_set_result(ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_set_result_ex(ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_UTIL_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_UTIL_read_pw(buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_UI_new: PUI; cdecl;
function Load_UI_new_method(const method: PUI_Method): PUI; cdecl;
procedure Load_UI_free(ui: PUI); cdecl;
function Load_UI_add_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_UI_dup_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_UI_add_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_dup_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_add_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_dup_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_add_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_dup_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_add_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_dup_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_construct_prompt(ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl;
function Load_UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl;
function Load_UI_dup_user_data(ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_UI_get0_user_data(ui: PUI): Pointer; cdecl;
function Load_UI_get0_result(ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_UI_get_result_length(ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_UI_process(ui: PUI): TOpenSSL_C_INT; cdecl;
function Load_UI_ctrl(ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl;
function Load_UI_set_ex_data(r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_UI_get_ex_data(r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl;
procedure Load_UI_set_default_method(const meth: PUI_Method); cdecl;
function Load_UI_get_default_method: PUI_METHOD; cdecl;
function Load_UI_get_method(ui: PUI): PUI_METHOD; cdecl;
function Load_UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl;
function Load_UI_OpenSSL: PUI_Method; cdecl;
function Load_UI_null: PUI_METHOD; cdecl;
function Load_UI_create_method(const name: PAnsiChar): PUI_Method; cdecl;
procedure Load_UI_destroy_method(ui_method: PUI_Method); cdecl;
function Load_UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl;
function Load_UI_method_set_ex_data(method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb; cdecl;
function Load_UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb; cdecl;
function Load_UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb; cdecl;
function Load_UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb; cdecl;
function Load_UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb; cdecl;
function Load_UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl;
function Load_UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl;
function Load_UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl;
function Load_UI_method_get_ex_data(const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_UI_get_string_type(uis: PUI_String): UI_string_types; cdecl;
function Load_UI_get_input_flags(uis: PUI_String): TOpenSSL_C_INT; cdecl;
function Load_UI_get0_output_string(uis: PUI_String): PAnsiChar; cdecl;
function Load_UI_get0_action_string(uis: PUI_String): PAnsiChar; cdecl;
function Load_UI_get0_result_string(uis: PUI_String): PAnsiChar; cdecl;
function Load_UI_get_result_string_length(uis: PUI_String): TOpenSSL_C_INT; cdecl;
function Load_UI_get0_test_string(uis: PUI_String): PAnsiChar; cdecl;
function Load_UI_get_result_minsize(uis: PUI_String): TOpenSSL_C_INT; cdecl;
function Load_UI_get_result_maxsize(uis: PUI_String): TOpenSSL_C_INT; cdecl;
function Load_UI_set_result(ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UI_set_result_ex(ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_UI_UTIL_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_UI_UTIL_read_pw(buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl;

var
  UI_new: function : PUI; cdecl = Load_UI_new;
  UI_new_method: function (const method: PUI_Method): PUI; cdecl = Load_UI_new_method;
  UI_free: procedure (ui: PUI); cdecl = Load_UI_free;
  UI_add_input_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_UI_add_input_string;
  UI_dup_input_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_UI_dup_input_string;
  UI_add_verify_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_add_verify_string;
  UI_dup_verify_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_dup_verify_string;
  UI_add_input_boolean: function (ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_add_input_boolean;
  UI_dup_input_boolean: function (ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_dup_input_boolean;
  UI_add_info_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_add_info_string;
  UI_dup_info_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_dup_info_string;
  UI_add_error_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_add_error_string;
  UI_dup_error_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_dup_error_string;
  UI_construct_prompt: function (ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl = Load_UI_construct_prompt;
  UI_add_user_data: function (ui: PUI; user_data: Pointer): Pointer; cdecl = Load_UI_add_user_data;
  UI_dup_user_data: function (ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl = Load_UI_dup_user_data;
  UI_get0_user_data: function (ui: PUI): Pointer; cdecl = Load_UI_get0_user_data;
  UI_get0_result: function (ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_UI_get0_result;
  UI_get_result_length: function (ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_UI_get_result_length;
  UI_process: function (ui: PUI): TOpenSSL_C_INT; cdecl = Load_UI_process;
  UI_ctrl: function (ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl = Load_UI_ctrl;
  UI_set_ex_data: function (r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_UI_set_ex_data;
  UI_get_ex_data: function (r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_UI_get_ex_data;
  UI_set_default_method: procedure (const meth: PUI_Method); cdecl = Load_UI_set_default_method;
  UI_get_default_method: function : PUI_METHOD; cdecl = Load_UI_get_default_method;
  UI_get_method: function (ui: PUI): PUI_METHOD; cdecl = Load_UI_get_method;
  UI_set_method: function (ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl = Load_UI_set_method;
  UI_OpenSSL: function : PUI_Method; cdecl = Load_UI_OpenSSL;
  UI_null: function : PUI_METHOD; cdecl = Load_UI_null;
  UI_create_method: function (const name: PAnsiChar): PUI_Method; cdecl = Load_UI_create_method;
  UI_destroy_method: procedure (ui_method: PUI_Method); cdecl = Load_UI_destroy_method;
  UI_method_set_opener: function (method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_opener;
  UI_method_set_writer: function (method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_writer;
  UI_method_set_flusher: function (method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_flusher;
  UI_method_set_reader: function (method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_reader;
  UI_method_set_closer: function (method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_closer;
  UI_method_set_data_duplicator: function (method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_data_duplicator;
  UI_method_set_prompt_constructor: function (method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl = Load_UI_method_set_prompt_constructor;
  UI_method_set_ex_data: function (method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = Load_UI_method_set_ex_data;
  UI_method_get_opener: function (const method: PUI_METHOD): UI_method_opener_cb; cdecl = Load_UI_method_get_opener;
  UI_method_get_writer: function (const method: PUI_METHOD): UI_method_writer_cb; cdecl = Load_UI_method_get_writer;
  UI_method_get_flusher: function (const method: PUI_METHOD): UI_method_flusher_cb; cdecl = Load_UI_method_get_flusher;
  UI_method_get_reader: function (const method: PUI_METHOD): UI_method_reader_cb; cdecl = Load_UI_method_get_reader;
  UI_method_get_closer: function (const method: PUI_METHOD): UI_method_closer_cb; cdecl = Load_UI_method_get_closer;
  UI_method_get_prompt_constructor: function (const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl = Load_UI_method_get_prompt_constructor;
  UI_method_get_data_duplicator: function (const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl = Load_UI_method_get_data_duplicator;
  UI_method_get_data_destructor: function (const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl = Load_UI_method_get_data_destructor;
  UI_method_get_ex_data: function (const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_UI_method_get_ex_data;
  UI_get_string_type: function (uis: PUI_String): UI_string_types; cdecl = Load_UI_get_string_type;
  UI_get_input_flags: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = Load_UI_get_input_flags;
  UI_get0_output_string: function (uis: PUI_String): PAnsiChar; cdecl = Load_UI_get0_output_string;
  UI_get0_action_string: function (uis: PUI_String): PAnsiChar; cdecl = Load_UI_get0_action_string;
  UI_get0_result_string: function (uis: PUI_String): PAnsiChar; cdecl = Load_UI_get0_result_string;
  UI_get_result_string_length: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = Load_UI_get_result_string_length;
  UI_get0_test_string: function (uis: PUI_String): PAnsiChar; cdecl = Load_UI_get0_test_string;
  UI_get_result_minsize: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = Load_UI_get_result_minsize;
  UI_get_result_maxsize: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = Load_UI_get_result_maxsize;
  UI_set_result: function (ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_UI_set_result;
  UI_set_result_ex: function (ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_UI_set_result_ex;
  UI_UTIL_read_pw_string: function (buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_UI_UTIL_read_pw_string;
  UI_UTIL_read_pw: function (buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_UI_UTIL_read_pw;
  UI_UTIL_wrap_read_pem_callback: function (cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl = Load_UI_UTIL_wrap_read_pem_callback;
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
function Load_UI_new: PUI; cdecl;
begin
  UI_new := LoadLibCryptoFunction('UI_new');
  if not assigned(UI_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_new');
  Result := UI_new();
end;

function Load_UI_new_method(const method: PUI_Method): PUI; cdecl;
begin
  UI_new_method := LoadLibCryptoFunction('UI_new_method');
  if not assigned(UI_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_new_method');
  Result := UI_new_method(method);
end;

procedure Load_UI_free(ui: PUI); cdecl;
begin
  UI_free := LoadLibCryptoFunction('UI_free');
  if not assigned(UI_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_free');
  UI_free(ui);
end;

function Load_UI_add_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  UI_add_input_string := LoadLibCryptoFunction('UI_add_input_string');
  if not assigned(UI_add_input_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_input_string');
  Result := UI_add_input_string(ui,prompt,flags,result_buf,minsize,maxsize);
end;

function Load_UI_dup_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  UI_dup_input_string := LoadLibCryptoFunction('UI_dup_input_string');
  if not assigned(UI_dup_input_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_input_string');
  Result := UI_dup_input_string(ui,prompt,flags,result_buf,minsize,maxsize);
end;

function Load_UI_add_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_add_verify_string := LoadLibCryptoFunction('UI_add_verify_string');
  if not assigned(UI_add_verify_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_verify_string');
  Result := UI_add_verify_string(ui,prompt,flags,result_buf,minsize,maxsize,test_buf);
end;

function Load_UI_dup_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_dup_verify_string := LoadLibCryptoFunction('UI_dup_verify_string');
  if not assigned(UI_dup_verify_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_verify_string');
  Result := UI_dup_verify_string(ui,prompt,flags,result_buf,minsize,maxsize,test_buf);
end;

function Load_UI_add_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_add_input_boolean := LoadLibCryptoFunction('UI_add_input_boolean');
  if not assigned(UI_add_input_boolean) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_input_boolean');
  Result := UI_add_input_boolean(ui,prompt,action_desc,ok_chars,cancel_chars,flags,result_buf);
end;

function Load_UI_dup_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_dup_input_boolean := LoadLibCryptoFunction('UI_dup_input_boolean');
  if not assigned(UI_dup_input_boolean) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_input_boolean');
  Result := UI_dup_input_boolean(ui,prompt,action_desc,ok_chars,cancel_chars,flags,result_buf);
end;

function Load_UI_add_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_add_info_string := LoadLibCryptoFunction('UI_add_info_string');
  if not assigned(UI_add_info_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_info_string');
  Result := UI_add_info_string(ui,text);
end;

function Load_UI_dup_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_dup_info_string := LoadLibCryptoFunction('UI_dup_info_string');
  if not assigned(UI_dup_info_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_info_string');
  Result := UI_dup_info_string(ui,text);
end;

function Load_UI_add_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_add_error_string := LoadLibCryptoFunction('UI_add_error_string');
  if not assigned(UI_add_error_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_error_string');
  Result := UI_add_error_string(ui,text);
end;

function Load_UI_dup_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_dup_error_string := LoadLibCryptoFunction('UI_dup_error_string');
  if not assigned(UI_dup_error_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_error_string');
  Result := UI_dup_error_string(ui,text);
end;

function Load_UI_construct_prompt(ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl;
begin
  UI_construct_prompt := LoadLibCryptoFunction('UI_construct_prompt');
  if not assigned(UI_construct_prompt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_construct_prompt');
  Result := UI_construct_prompt(ui_method,object_desc,object_name);
end;

function Load_UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl;
begin
  UI_add_user_data := LoadLibCryptoFunction('UI_add_user_data');
  if not assigned(UI_add_user_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_user_data');
  Result := UI_add_user_data(ui,user_data);
end;

function Load_UI_dup_user_data(ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  UI_dup_user_data := LoadLibCryptoFunction('UI_dup_user_data');
  if not assigned(UI_dup_user_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_user_data');
  Result := UI_dup_user_data(ui,user_data);
end;

function Load_UI_get0_user_data(ui: PUI): Pointer; cdecl;
begin
  UI_get0_user_data := LoadLibCryptoFunction('UI_get0_user_data');
  if not assigned(UI_get0_user_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_user_data');
  Result := UI_get0_user_data(ui);
end;

function Load_UI_get0_result(ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  UI_get0_result := LoadLibCryptoFunction('UI_get0_result');
  if not assigned(UI_get0_result) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_result');
  Result := UI_get0_result(ui,i);
end;

function Load_UI_get_result_length(ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  UI_get_result_length := LoadLibCryptoFunction('UI_get_result_length');
  if not assigned(UI_get_result_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_length');
  Result := UI_get_result_length(ui,i);
end;

function Load_UI_process(ui: PUI): TOpenSSL_C_INT; cdecl;
begin
  UI_process := LoadLibCryptoFunction('UI_process');
  if not assigned(UI_process) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_process');
  Result := UI_process(ui);
end;

function Load_UI_ctrl(ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl;
begin
  UI_ctrl := LoadLibCryptoFunction('UI_ctrl');
  if not assigned(UI_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_ctrl');
  Result := UI_ctrl(ui,cmd,i,p,f);
end;

function Load_UI_set_ex_data(r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  UI_set_ex_data := LoadLibCryptoFunction('UI_set_ex_data');
  if not assigned(UI_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_ex_data');
  Result := UI_set_ex_data(r,idx,arg);
end;

function Load_UI_get_ex_data(r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  UI_get_ex_data := LoadLibCryptoFunction('UI_get_ex_data');
  if not assigned(UI_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_ex_data');
  Result := UI_get_ex_data(r,idx);
end;

procedure Load_UI_set_default_method(const meth: PUI_Method); cdecl;
begin
  UI_set_default_method := LoadLibCryptoFunction('UI_set_default_method');
  if not assigned(UI_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_default_method');
  UI_set_default_method(meth);
end;

function Load_UI_get_default_method: PUI_METHOD; cdecl;
begin
  UI_get_default_method := LoadLibCryptoFunction('UI_get_default_method');
  if not assigned(UI_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_default_method');
  Result := UI_get_default_method();
end;

function Load_UI_get_method(ui: PUI): PUI_METHOD; cdecl;
begin
  UI_get_method := LoadLibCryptoFunction('UI_get_method');
  if not assigned(UI_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_method');
  Result := UI_get_method(ui);
end;

function Load_UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl;
begin
  UI_set_method := LoadLibCryptoFunction('UI_set_method');
  if not assigned(UI_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_method');
  Result := UI_set_method(ui,meth);
end;

function Load_UI_OpenSSL: PUI_Method; cdecl;
begin
  UI_OpenSSL := LoadLibCryptoFunction('UI_OpenSSL');
  if not assigned(UI_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_OpenSSL');
  Result := UI_OpenSSL();
end;

function Load_UI_null: PUI_METHOD; cdecl;
begin
  UI_null := LoadLibCryptoFunction('UI_null');
  if not assigned(UI_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_null');
  Result := UI_null();
end;

function Load_UI_create_method(const name: PAnsiChar): PUI_Method; cdecl;
begin
  UI_create_method := LoadLibCryptoFunction('UI_create_method');
  if not assigned(UI_create_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_create_method');
  Result := UI_create_method(name);
end;

procedure Load_UI_destroy_method(ui_method: PUI_Method); cdecl;
begin
  UI_destroy_method := LoadLibCryptoFunction('UI_destroy_method');
  if not assigned(UI_destroy_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_destroy_method');
  UI_destroy_method(ui_method);
end;

function Load_UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_opener := LoadLibCryptoFunction('UI_method_set_opener');
  if not assigned(UI_method_set_opener) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_opener');
  Result := UI_method_set_opener(method,opener);
end;

function Load_UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_writer := LoadLibCryptoFunction('UI_method_set_writer');
  if not assigned(UI_method_set_writer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_writer');
  Result := UI_method_set_writer(method,writer);
end;

function Load_UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_flusher := LoadLibCryptoFunction('UI_method_set_flusher');
  if not assigned(UI_method_set_flusher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_flusher');
  Result := UI_method_set_flusher(method,flusher);
end;

function Load_UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_reader := LoadLibCryptoFunction('UI_method_set_reader');
  if not assigned(UI_method_set_reader) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_reader');
  Result := UI_method_set_reader(method,reader);
end;

function Load_UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_closer := LoadLibCryptoFunction('UI_method_set_closer');
  if not assigned(UI_method_set_closer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_closer');
  Result := UI_method_set_closer(method,closer);
end;

function Load_UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_data_duplicator := LoadLibCryptoFunction('UI_method_set_data_duplicator');
  if not assigned(UI_method_set_data_duplicator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_data_duplicator');
  Result := UI_method_set_data_duplicator(method,duplicator,destructor_);
end;

function Load_UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_prompt_constructor := LoadLibCryptoFunction('UI_method_set_prompt_constructor');
  if not assigned(UI_method_set_prompt_constructor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_prompt_constructor');
  Result := UI_method_set_prompt_constructor(method,prompt_constructor);
end;

function Load_UI_method_set_ex_data(method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  UI_method_set_ex_data := LoadLibCryptoFunction('UI_method_set_ex_data');
  if not assigned(UI_method_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_ex_data');
  Result := UI_method_set_ex_data(method,idx,data);
end;

function Load_UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb; cdecl;
begin
  UI_method_get_opener := LoadLibCryptoFunction('UI_method_get_opener');
  if not assigned(UI_method_get_opener) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_opener');
  Result := UI_method_get_opener(method);
end;

function Load_UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb; cdecl;
begin
  UI_method_get_writer := LoadLibCryptoFunction('UI_method_get_writer');
  if not assigned(UI_method_get_writer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_writer');
  Result := UI_method_get_writer(method);
end;

function Load_UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb; cdecl;
begin
  UI_method_get_flusher := LoadLibCryptoFunction('UI_method_get_flusher');
  if not assigned(UI_method_get_flusher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_flusher');
  Result := UI_method_get_flusher(method);
end;

function Load_UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb; cdecl;
begin
  UI_method_get_reader := LoadLibCryptoFunction('UI_method_get_reader');
  if not assigned(UI_method_get_reader) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_reader');
  Result := UI_method_get_reader(method);
end;

function Load_UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb; cdecl;
begin
  UI_method_get_closer := LoadLibCryptoFunction('UI_method_get_closer');
  if not assigned(UI_method_get_closer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_closer');
  Result := UI_method_get_closer(method);
end;

function Load_UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl;
begin
  UI_method_get_prompt_constructor := LoadLibCryptoFunction('UI_method_get_prompt_constructor');
  if not assigned(UI_method_get_prompt_constructor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_prompt_constructor');
  Result := UI_method_get_prompt_constructor(method);
end;

function Load_UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl;
begin
  UI_method_get_data_duplicator := LoadLibCryptoFunction('UI_method_get_data_duplicator');
  if not assigned(UI_method_get_data_duplicator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_data_duplicator');
  Result := UI_method_get_data_duplicator(method);
end;

function Load_UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl;
begin
  UI_method_get_data_destructor := LoadLibCryptoFunction('UI_method_get_data_destructor');
  if not assigned(UI_method_get_data_destructor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_data_destructor');
  Result := UI_method_get_data_destructor(method);
end;

function Load_UI_method_get_ex_data(const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  UI_method_get_ex_data := LoadLibCryptoFunction('UI_method_get_ex_data');
  if not assigned(UI_method_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_ex_data');
  Result := UI_method_get_ex_data(method,idx);
end;

function Load_UI_get_string_type(uis: PUI_String): UI_string_types; cdecl;
begin
  UI_get_string_type := LoadLibCryptoFunction('UI_get_string_type');
  if not assigned(UI_get_string_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_string_type');
  Result := UI_get_string_type(uis);
end;

function Load_UI_get_input_flags(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  UI_get_input_flags := LoadLibCryptoFunction('UI_get_input_flags');
  if not assigned(UI_get_input_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_input_flags');
  Result := UI_get_input_flags(uis);
end;

function Load_UI_get0_output_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  UI_get0_output_string := LoadLibCryptoFunction('UI_get0_output_string');
  if not assigned(UI_get0_output_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_output_string');
  Result := UI_get0_output_string(uis);
end;

function Load_UI_get0_action_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  UI_get0_action_string := LoadLibCryptoFunction('UI_get0_action_string');
  if not assigned(UI_get0_action_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_action_string');
  Result := UI_get0_action_string(uis);
end;

function Load_UI_get0_result_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  UI_get0_result_string := LoadLibCryptoFunction('UI_get0_result_string');
  if not assigned(UI_get0_result_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_result_string');
  Result := UI_get0_result_string(uis);
end;

function Load_UI_get_result_string_length(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  UI_get_result_string_length := LoadLibCryptoFunction('UI_get_result_string_length');
  if not assigned(UI_get_result_string_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_string_length');
  Result := UI_get_result_string_length(uis);
end;

function Load_UI_get0_test_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  UI_get0_test_string := LoadLibCryptoFunction('UI_get0_test_string');
  if not assigned(UI_get0_test_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_test_string');
  Result := UI_get0_test_string(uis);
end;

function Load_UI_get_result_minsize(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  UI_get_result_minsize := LoadLibCryptoFunction('UI_get_result_minsize');
  if not assigned(UI_get_result_minsize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_minsize');
  Result := UI_get_result_minsize(uis);
end;

function Load_UI_get_result_maxsize(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  UI_get_result_maxsize := LoadLibCryptoFunction('UI_get_result_maxsize');
  if not assigned(UI_get_result_maxsize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_maxsize');
  Result := UI_get_result_maxsize(uis);
end;

function Load_UI_set_result(ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  UI_set_result := LoadLibCryptoFunction('UI_set_result');
  if not assigned(UI_set_result) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_result');
  Result := UI_set_result(ui,uis,result_);
end;

function Load_UI_set_result_ex(ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  UI_set_result_ex := LoadLibCryptoFunction('UI_set_result_ex');
  if not assigned(UI_set_result_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_result_ex');
  Result := UI_set_result_ex(ui,uis,result_,len);
end;

function Load_UI_UTIL_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  UI_UTIL_read_pw_string := LoadLibCryptoFunction('UI_UTIL_read_pw_string');
  if not assigned(UI_UTIL_read_pw_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_UTIL_read_pw_string');
  Result := UI_UTIL_read_pw_string(buf,length,prompt,verify);
end;

function Load_UI_UTIL_read_pw(buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  UI_UTIL_read_pw := LoadLibCryptoFunction('UI_UTIL_read_pw');
  if not assigned(UI_UTIL_read_pw) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_UTIL_read_pw');
  Result := UI_UTIL_read_pw(buf,buff,size,prompt,verify);
end;

function Load_UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl;
begin
  UI_UTIL_wrap_read_pem_callback := LoadLibCryptoFunction('UI_UTIL_wrap_read_pem_callback');
  if not assigned(UI_UTIL_wrap_read_pem_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UI_UTIL_wrap_read_pem_callback');
  Result := UI_UTIL_wrap_read_pem_callback(cb,rwflag);
end;


procedure UnLoad;
begin
  UI_new := Load_UI_new;
  UI_new_method := Load_UI_new_method;
  UI_free := Load_UI_free;
  UI_add_input_string := Load_UI_add_input_string;
  UI_dup_input_string := Load_UI_dup_input_string;
  UI_add_verify_string := Load_UI_add_verify_string;
  UI_dup_verify_string := Load_UI_dup_verify_string;
  UI_add_input_boolean := Load_UI_add_input_boolean;
  UI_dup_input_boolean := Load_UI_dup_input_boolean;
  UI_add_info_string := Load_UI_add_info_string;
  UI_dup_info_string := Load_UI_dup_info_string;
  UI_add_error_string := Load_UI_add_error_string;
  UI_dup_error_string := Load_UI_dup_error_string;
  UI_construct_prompt := Load_UI_construct_prompt;
  UI_add_user_data := Load_UI_add_user_data;
  UI_dup_user_data := Load_UI_dup_user_data;
  UI_get0_user_data := Load_UI_get0_user_data;
  UI_get0_result := Load_UI_get0_result;
  UI_get_result_length := Load_UI_get_result_length;
  UI_process := Load_UI_process;
  UI_ctrl := Load_UI_ctrl;
  UI_set_ex_data := Load_UI_set_ex_data;
  UI_get_ex_data := Load_UI_get_ex_data;
  UI_set_default_method := Load_UI_set_default_method;
  UI_get_default_method := Load_UI_get_default_method;
  UI_get_method := Load_UI_get_method;
  UI_set_method := Load_UI_set_method;
  UI_OpenSSL := Load_UI_OpenSSL;
  UI_null := Load_UI_null;
  UI_create_method := Load_UI_create_method;
  UI_destroy_method := Load_UI_destroy_method;
  UI_method_set_opener := Load_UI_method_set_opener;
  UI_method_set_writer := Load_UI_method_set_writer;
  UI_method_set_flusher := Load_UI_method_set_flusher;
  UI_method_set_reader := Load_UI_method_set_reader;
  UI_method_set_closer := Load_UI_method_set_closer;
  UI_method_set_data_duplicator := Load_UI_method_set_data_duplicator;
  UI_method_set_prompt_constructor := Load_UI_method_set_prompt_constructor;
  UI_method_set_ex_data := Load_UI_method_set_ex_data;
  UI_method_get_opener := Load_UI_method_get_opener;
  UI_method_get_writer := Load_UI_method_get_writer;
  UI_method_get_flusher := Load_UI_method_get_flusher;
  UI_method_get_reader := Load_UI_method_get_reader;
  UI_method_get_closer := Load_UI_method_get_closer;
  UI_method_get_prompt_constructor := Load_UI_method_get_prompt_constructor;
  UI_method_get_data_duplicator := Load_UI_method_get_data_duplicator;
  UI_method_get_data_destructor := Load_UI_method_get_data_destructor;
  UI_method_get_ex_data := Load_UI_method_get_ex_data;
  UI_get_string_type := Load_UI_get_string_type;
  UI_get_input_flags := Load_UI_get_input_flags;
  UI_get0_output_string := Load_UI_get0_output_string;
  UI_get0_action_string := Load_UI_get0_action_string;
  UI_get0_result_string := Load_UI_get0_result_string;
  UI_get_result_string_length := Load_UI_get_result_string_length;
  UI_get0_test_string := Load_UI_get0_test_string;
  UI_get_result_minsize := Load_UI_get_result_minsize;
  UI_get_result_maxsize := Load_UI_get_result_maxsize;
  UI_set_result := Load_UI_set_result;
  UI_set_result_ex := Load_UI_set_result_ex;
  UI_UTIL_read_pw_string := Load_UI_UTIL_read_pw_string;
  UI_UTIL_read_pw := Load_UI_UTIL_read_pw;
  UI_UTIL_wrap_read_pem_callback := Load_UI_UTIL_wrap_read_pem_callback;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
