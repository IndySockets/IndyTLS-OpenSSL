  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_ui.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_ui.h2pas
     and this file regenerated. IdOpenSSLHeaders_ui.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_ui;

interface

// Headers for OpenSSL 1.1.1
// ui.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSL110Consts,
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
  UI_method_opener_cb = function(ui: PUI): TIdC_INT;
  UI_method_writer_cb = function(ui: PUI; uis: PUI_String): TIdC_INT;
  UI_method_flusher_cb = function(ui: PUI): TIdC_INT;
  UI_method_reader_cb = function(ui: PUI; uis: PUI_String): TIdC_INT;
  UI_method_closer_cb = function(ui: PUI): TIdC_INT;
  UI_method_data_duplicator_cb = function(ui: PUI; ui_data: Pointer): Pointer;
  UI_method_data_destructor_cb = procedure(ui: PUI; ui_data: Pointer);
  UI_method_prompt_constructor_cb = function(ui: PUI; const object_desc: PIdAnsiChar; const object_name: PIdAnsiChar): PIdAnsiChar;

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

{$IFNDEF USE_EXTERNAL_LIBRARY}
var
  UI_new: function : PUI; cdecl = nil;
  UI_new_method: function (const method: PUI_Method): PUI; cdecl = nil;
  UI_free: procedure (ui: PUI); cdecl = nil;

  (*
   * The following functions are used to add strings to be printed and prompt
   * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
   * and UI_{add,dup}_input_boolean.
   *
   * UI_{add,dup}_<function>_string have the following meanings:
   *      add     add a text or prompt string.  The pointers given to these
   *              functions are used verbatim, no copying is done.
   *      dup     make a copy of the text or prompt string, then add the copy
   *              to the collection of strings in the user interface.
   *      <function>
   *              The function is a name for the functionality that the given
   *              string shall be used for.  It can be one of:
   *                      input   use the string as data prompt.
   *                      verify  use the string as verification prompt.  This
   *                              is used to verify a previous input.
   *                      info    use the string for informational output.
   *                      error   use the string for error output.
   * Honestly, there's currently no difference between info and error for the
   * moment.
   *
   * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
   * and are typically used when one wants to prompt for a yes/no response.
   *
   * All of the functions in this group take a UI and a prompt string.
   * The string input and verify addition functions also take a flag argument,
   * a buffer for the result to end up with, a minimum input size and a maximum
   * input size (the result buffer MUST be large enough to be able to contain
   * the maximum number of characters).  Additionally, the verify addition
   * functions takes another buffer to compare the result against.
   * The boolean input functions take an action description string (which should
   * be safe to ignore if the expected user action is obvious, for example with
   * a dialog box with an OK button and a Cancel button), a string of acceptable
   * characters to mean OK and to mean Cancel.  The two last strings are checked
   * to make sure they don't have common characters.  Additionally, the same
   * flag argument as for the string input is taken, as well as a result buffer.
   * The result buffer is required to be at least one byte long.  Depending on
   * the answer, the first character from the OK or the Cancel character strings
   * will be stored in the first byte of the result buffer.  No NUL will be
   * added, so the result is *not* a string.
   *
   * On success, the all return an index of the added information.  That index
   * is useful when retrieving results with UI_get0_result(). *)

  UI_add_input_string: function (ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl = nil;
  UI_dup_input_string: function (ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl = nil;
  UI_add_verify_string: function (ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_dup_verify_string: function (ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_add_input_boolean: function (ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_dup_input_boolean: function (ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_add_info_string: function (ui: PUI; const text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_dup_info_string: function (ui: PUI; const text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_add_error_string: function (ui: PUI; const text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_dup_error_string: function (ui: PUI; const text: PIdAnsiChar): TIdC_INT; cdecl = nil;

  (*
   * The following function helps construct a prompt.  object_desc is a
   * textual short description of the object, for example "pass phrase",
   * and object_name is the name of the object (might be a card name or
   * a file name.
   * The returned string shall always be allocated on the heap with
   * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
   *
   * If the ui_method doesn't contain a pointer to a user-defined prompt
   * constructor, a default string is built, looking like this:
   *
   *       "Enter {object_desc} for {object_name}:"
   *
   * So, if object_desc has the value "pass phrase" and object_name has
   * the value "foo.key", the resulting string is:
   *
   *       "Enter pass phrase for foo.key:"
   *)
  UI_construct_prompt: function (ui_method: PUI; const object_desc: PIdAnsiChar; const object_name: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

  (*
   * The following function is used to store a pointer to user-specific data.
   * Any previous such pointer will be returned and replaced.
   *
   * For callback purposes, this function makes a lot more sense than using
   * ex_data, since the latter requires that different parts of OpenSSL or
   * applications share the same ex_data index.
   *
   * Note that the UI_OpenSSL() method completely ignores the user data. Other
   * methods may not, however.
   *)
  UI_add_user_data: function (ui: PUI; user_data: Pointer): Pointer; cdecl = nil;
  (*
   * Alternatively, this function is used to duplicate the user data.
   * This uses the duplicator method function.  The destroy function will
   * be used to free the user data in this case.
   *)
  UI_dup_user_data: function (ui: PUI; user_data: Pointer): TIdC_INT; cdecl = nil;
  (* We need a user data retrieving function as well.  *)
  UI_get0_user_data: function (ui: PUI): Pointer; cdecl = nil;

  (* Return the result associated with a prompt given with the index i. *)
  UI_get0_result: function (ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl = nil;
  UI_get_result_length: function (ui: PUI; i: TIdC_INT): TIdC_INT; cdecl = nil;

  (* When all strings have been added, process the whole thing. *)
  UI_process: function (ui: PUI): TIdC_INT; cdecl = nil;

  (*
   * Give a user interface parameterised control commands.  This can be used to
   * send down an integer, a data pointer or a function pointer, as well as be
   * used to get information from a UI.
   *)
  UI_ctrl: function (ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: UI_ctrl_f): TIdC_INT; cdecl = nil;


  (* Some methods may use extra data *)
  //# define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
  //# define UI_get_app_data(s)             UI_get_ex_data(s,0)

  //# define UI_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
  UI_set_ex_data: function (r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  UI_get_ex_data: function (r: PUI; idx: TIdC_INT): Pointer; cdecl = nil;

  (* Use specific methods instead of the built-in one *)
  UI_set_default_method: procedure (const meth: PUI_Method); cdecl = nil;
  UI_get_default_method: function : PUI_METHOD; cdecl = nil;
  UI_get_method: function (ui: PUI): PUI_METHOD; cdecl = nil;
  UI_set_method: function (ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl = nil;

  (* The method with all the built-in thingies *)
  UI_OpenSSL: function : PUI_Method; cdecl = nil;

  (*
   * NULL method.  Literally does nothing, but may serve as a placeholder
   * to avoid internal default.
   *)
  UI_null: function : PUI_METHOD; cdecl = nil;

  (* ---------- For method writers ---------- *)
  (*
     A method contains a number of functions that implement the low level
     of the User Interface.  The functions are:

          an opener       This function starts a session, maybe by opening
                          a channel to a tty, or by opening a window.
          a writer        This function is called to write a given string,
                          maybe to the tty, maybe as a field label in a
                          window.
          a flusher       This function is called to flush everything that
                          has been output so far.  It can be used to actually
                          display a dialog box after it has been built.
          a reader        This function is called to read a given prompt,
                          maybe from the tty, maybe from a field in a
                          window.  Note that it's called with all string
                          structures, not only the prompt ones, so it must
                          check such things itself.
          a closer        This function closes the session, maybe by closing
                          the channel to the tty, or closing the window.

     All these functions are expected to return:

          0       on error.
          1       on success.
          -1      on out-of-band events, for example if some prompting has
                  been canceled (by pressing Ctrl-C, for example).  This is
                  only checked when returned by the flusher or the reader.

     The way this is used, the opener is first called, then the writer for all
     strings, then the flusher, then the reader for all strings and finally the
     closer.  Note that if you want to prompt from a terminal or other command
     line interface, the best is to have the reader also write the prompts
     instead of having the writer do it.  If you want to prompt from a dialog
     box, the writer can be used to build up the contents of the box, and the
     flusher to actually display the box and run the event loop until all data
     has been given, after which the reader only grabs the given data and puts
     them back into the UI strings.

     All method functions take a UI as argument.  Additionally, the writer and
     the reader take a UI_STRING.
  *)

  UI_create_method: function (const name: PIdAnsiChar): PUI_Method; cdecl = nil;
  UI_destroy_method: procedure (ui_method: PUI_Method); cdecl = nil;

  UI_method_set_opener: function (method: PUI_Method; opener: UI_method_opener_cb): TIdC_INT; cdecl = nil;
  UI_method_set_writer: function (method: PUI_Method; writer: UI_method_writer_cb): TIdC_INT; cdecl = nil;
  UI_method_set_flusher: function (method: PUI_Method; flusher: UI_method_flusher_cb): TIdC_INT; cdecl = nil;
  UI_method_set_reader: function (method: PUI_Method; reader: UI_method_reader_cb): TIdC_INT; cdecl = nil;
  UI_method_set_closer: function (method: PUI_Method; closer: UI_method_closer_cb): TIdC_INT; cdecl = nil;
  UI_method_set_data_duplicator: function (method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TIdC_INT; cdecl = nil;
  UI_method_set_prompt_constructor: function (method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TIdC_INT; cdecl = nil;
  UI_method_set_ex_data: function (method: PUI_Method; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;

  UI_method_get_opener: function (const method: PUI_METHOD): UI_method_opener_cb; cdecl = nil;
  UI_method_get_writer: function (const method: PUI_METHOD): UI_method_writer_cb; cdecl = nil;
  UI_method_get_flusher: function (const method: PUI_METHOD): UI_method_flusher_cb; cdecl = nil;
  UI_method_get_reader: function (const method: PUI_METHOD): UI_method_reader_cb; cdecl = nil;
  UI_method_get_closer: function (const method: PUI_METHOD): UI_method_closer_cb; cdecl = nil;
  UI_method_get_prompt_constructor: function (const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl = nil;
  UI_method_get_data_duplicator: function (const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl = nil;
  UI_method_get_data_destructor: function (const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl = nil;
  UI_method_get_ex_data: function (const method: PUI_METHOD; idx: TIdC_INT): Pointer; cdecl = nil;

  (*
   * The following functions are helpers for method writers to access relevant
   * data from a UI_STRING.
   *)

  (* Return type of the UI_STRING *)
  UI_get_string_type: function (uis: PUI_String): UI_string_types; cdecl = nil;
  (* Return input flags of the UI_STRING *)
  UI_get_input_flags: function (uis: PUI_String): TIdC_INT; cdecl = nil;
  (* Return the actual string to output (the prompt, info or error) *)
  UI_get0_output_string: function (uis: PUI_String): PIdAnsiChar; cdecl = nil;
  (*
   * Return the optional action string to output (the boolean prompt
   * instruction)
   *)
  UI_get0_action_string: function (uis: PUI_String): PIdAnsiChar; cdecl = nil;
  (* Return the result of a prompt *)
  UI_get0_result_string: function (uis: PUI_String): PIdAnsiChar; cdecl = nil;
  UI_get_result_string_length: function (uis: PUI_String): TIdC_INT; cdecl = nil;
  (*
   * Return the string to test the result against.  Only useful with verifies.
   *)
  UI_get0_test_string: function (uis: PUI_String): PIdAnsiChar; cdecl = nil;
  (* Return the required minimum size of the result *)
  UI_get_result_minsize: function (uis: PUI_String): TIdC_INT; cdecl = nil;
  (* Return the required maximum size of the result *)
  UI_get_result_maxsize: function (uis: PUI_String): TIdC_INT; cdecl = nil;
  (* Set the result of a UI_STRING. *)
  UI_set_result: function (ui: PUI; uis: PUI_String; const result: PIdAnsiChar): TIdC_INT; cdecl = nil;
  UI_set_result_ex: function (ui: PUI; uis: PUI_String; const result: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;

  (* A couple of popular utility functions *)
  UI_UTIL_read_pw_string: function (buf: PIdAnsiChar; length: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl = nil;
  UI_UTIL_read_pw: function (buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl = nil;
  UI_UTIL_wrap_read_pem_callback: function (cb: pem_password_cb; rwflag: TIdC_INT): PUI_Method; cdecl = nil;

{$ELSE}
  function UI_new: PUI cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_new_method(const method: PUI_Method): PUI cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure UI_free(ui: PUI) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (*
   * The following functions are used to add strings to be printed and prompt
   * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
   * and UI_{add,dup}_input_boolean.
   *
   * UI_{add,dup}_<function>_string have the following meanings:
   *      add     add a text or prompt string.  The pointers given to these
   *              functions are used verbatim, no copying is done.
   *      dup     make a copy of the text or prompt string, then add the copy
   *              to the collection of strings in the user interface.
   *      <function>
   *              The function is a name for the functionality that the given
   *              string shall be used for.  It can be one of:
   *                      input   use the string as data prompt.
   *                      verify  use the string as verification prompt.  This
   *                              is used to verify a previous input.
   *                      info    use the string for informational output.
   *                      error   use the string for error output.
   * Honestly, there's currently no difference between info and error for the
   * moment.
   *
   * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
   * and are typically used when one wants to prompt for a yes/no response.
   *
   * All of the functions in this group take a UI and a prompt string.
   * The string input and verify addition functions also take a flag argument,
   * a buffer for the result to end up with, a minimum input size and a maximum
   * input size (the result buffer MUST be large enough to be able to contain
   * the maximum number of characters).  Additionally, the verify addition
   * functions takes another buffer to compare the result against.
   * The boolean input functions take an action description string (which should
   * be safe to ignore if the expected user action is obvious, for example with
   * a dialog box with an OK button and a Cancel button), a string of acceptable
   * characters to mean OK and to mean Cancel.  The two last strings are checked
   * to make sure they don't have common characters.  Additionally, the same
   * flag argument as for the string input is taken, as well as a result buffer.
   * The result buffer is required to be at least one byte long.  Depending on
   * the answer, the first character from the OK or the Cancel character strings
   * will be stored in the first byte of the result buffer.  No NUL will be
   * added, so the result is *not* a string.
   *
   * On success, the all return an index of the added information.  That index
   * is useful when retrieving results with UI_get0_result(). *)

  function UI_add_input_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_dup_input_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_add_verify_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_dup_verify_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_add_input_boolean(ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_dup_input_boolean(ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_add_info_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_dup_info_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_add_error_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_dup_error_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (*
   * The following function helps construct a prompt.  object_desc is a
   * textual short description of the object, for example "pass phrase",
   * and object_name is the name of the object (might be a card name or
   * a file name.
   * The returned string shall always be allocated on the heap with
   * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
   *
   * If the ui_method doesn't contain a pointer to a user-defined prompt
   * constructor, a default string is built, looking like this:
   *
   *       "Enter {object_desc} for {object_name}:"
   *
   * So, if object_desc has the value "pass phrase" and object_name has
   * the value "foo.key", the resulting string is:
   *
   *       "Enter pass phrase for foo.key:"
   *)
  function UI_construct_prompt(ui_method: PUI; const object_desc: PIdAnsiChar; const object_name: PIdAnsiChar): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (*
   * The following function is used to store a pointer to user-specific data.
   * Any previous such pointer will be returned and replaced.
   *
   * For callback purposes, this function makes a lot more sense than using
   * ex_data, since the latter requires that different parts of OpenSSL or
   * applications share the same ex_data index.
   *
   * Note that the UI_OpenSSL() method completely ignores the user data. Other
   * methods may not, however.
   *)
  function UI_add_user_data(ui: PUI; user_data: Pointer): Pointer cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (*
   * Alternatively, this function is used to duplicate the user data.
   * This uses the duplicator method function.  The destroy function will
   * be used to free the user data in this case.
   *)
  function UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* We need a user data retrieving function as well.  *)
  function UI_get0_user_data(ui: PUI): Pointer cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* Return the result associated with a prompt given with the index i. *)
  function UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* When all strings have been added, process the whole thing. *)
  function UI_process(ui: PUI): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (*
   * Give a user interface parameterised control commands.  This can be used to
   * send down an integer, a data pointer or a function pointer, as well as be
   * used to get information from a UI.
   *)
  function UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: UI_ctrl_f): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};


  (* Some methods may use extra data *)
  //# define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
  //# define UI_get_app_data(s)             UI_get_ex_data(s,0)

  //# define UI_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
  function UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* Use specific methods instead of the built-in one *)
  procedure UI_set_default_method(const meth: PUI_Method) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_get_default_method: PUI_METHOD cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_get_method(ui: PUI): PUI_METHOD cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* The method with all the built-in thingies *)
  function UI_OpenSSL: PUI_Method cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (*
   * NULL method.  Literally does nothing, but may serve as a placeholder
   * to avoid internal default.
   *)
  function UI_null: PUI_METHOD cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* ---------- For method writers ---------- *)
  (*
     A method contains a number of functions that implement the low level
     of the User Interface.  The functions are:

          an opener       This function starts a session, maybe by opening
                          a channel to a tty, or by opening a window.
          a writer        This function is called to write a given string,
                          maybe to the tty, maybe as a field label in a
                          window.
          a flusher       This function is called to flush everything that
                          has been output so far.  It can be used to actually
                          display a dialog box after it has been built.
          a reader        This function is called to read a given prompt,
                          maybe from the tty, maybe from a field in a
                          window.  Note that it's called with all string
                          structures, not only the prompt ones, so it must
                          check such things itself.
          a closer        This function closes the session, maybe by closing
                          the channel to the tty, or closing the window.

     All these functions are expected to return:

          0       on error.
          1       on success.
          -1      on out-of-band events, for example if some prompting has
                  been canceled (by pressing Ctrl-C, for example).  This is
                  only checked when returned by the flusher or the reader.

     The way this is used, the opener is first called, then the writer for all
     strings, then the flusher, then the reader for all strings and finally the
     closer.  Note that if you want to prompt from a terminal or other command
     line interface, the best is to have the reader also write the prompts
     instead of having the writer do it.  If you want to prompt from a dialog
     box, the writer can be used to build up the contents of the box, and the
     flusher to actually display the box and run the event loop until all data
     has been given, after which the reader only grabs the given data and puts
     them back into the UI strings.

     All method functions take a UI as argument.  Additionally, the writer and
     the reader take a UI_STRING.
  *)

  function UI_create_method(const name: PIdAnsiChar): PUI_Method cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  procedure UI_destroy_method(ui_method: PUI_Method) cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_set_ex_data(method: PUI_Method; idx: TIdC_INT; data: Pointer): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  function UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_method_get_ex_data(const method: PUI_METHOD; idx: TIdC_INT): Pointer cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (*
   * The following functions are helpers for method writers to access relevant
   * data from a UI_STRING.
   *)

  (* Return type of the UI_STRING *)
  function UI_get_string_type(uis: PUI_String): UI_string_types cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* Return input flags of the UI_STRING *)
  function UI_get_input_flags(uis: PUI_String): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* Return the actual string to output (the prompt, info or error) *)
  function UI_get0_output_string(uis: PUI_String): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (*
   * Return the optional action string to output (the boolean prompt
   * instruction)
   *)
  function UI_get0_action_string(uis: PUI_String): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* Return the result of a prompt *)
  function UI_get0_result_string(uis: PUI_String): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_get_result_string_length(uis: PUI_String): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (*
   * Return the string to test the result against.  Only useful with verifies.
   *)
  function UI_get0_test_string(uis: PUI_String): PIdAnsiChar cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* Return the required minimum size of the result *)
  function UI_get_result_minsize(uis: PUI_String): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* Return the required maximum size of the result *)
  function UI_get_result_maxsize(uis: PUI_String): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  (* Set the result of a UI_STRING. *)
  function UI_set_result(ui: PUI; uis: PUI_String; const result: PIdAnsiChar): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_set_result_ex(ui: PUI; uis: PUI_String; const result: PIdAnsiChar; len: TIdC_INT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

  (* A couple of popular utility functions *)
  function UI_UTIL_read_pw_string(buf: PIdAnsiChar; length: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};
  function UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TIdC_INT): PUI_Method cdecl; external {$IFNDEF OPENSSL_USE_STATIC_LIBRARY}CLibCrypto{$ENDIF};

{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF USE_EXTERNAL_LIBRARY}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  

{$IFNDEF USE_EXTERNAL_LIBRARY}
const
  UI_new_procname = 'UI_new';
  UI_new_method_procname = 'UI_new_method';
  UI_free_procname = 'UI_free';

  (*
   * The following functions are used to add strings to be printed and prompt
   * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
   * and UI_{add,dup}_input_boolean.
   *
   * UI_{add,dup}_<function>_string have the following meanings:
   *      add     add a text or prompt string.  The pointers given to these
   *              functions are used verbatim, no copying is done.
   *      dup     make a copy of the text or prompt string, then add the copy
   *              to the collection of strings in the user interface.
   *      <function>
   *              The function is a name for the functionality that the given
   *              string shall be used for.  It can be one of:
   *                      input   use the string as data prompt.
   *                      verify  use the string as verification prompt.  This
   *                              is used to verify a previous input.
   *                      info    use the string for informational output.
   *                      error   use the string for error output.
   * Honestly, there's currently no difference between info and error for the
   * moment.
   *
   * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
   * and are typically used when one wants to prompt for a yes/no response.
   *
   * All of the functions in this group take a UI and a prompt string.
   * The string input and verify addition functions also take a flag argument,
   * a buffer for the result to end up with, a minimum input size and a maximum
   * input size (the result buffer MUST be large enough to be able to contain
   * the maximum number of characters).  Additionally, the verify addition
   * functions takes another buffer to compare the result against.
   * The boolean input functions take an action description string (which should
   * be safe to ignore if the expected user action is obvious, for example with
   * a dialog box with an OK button and a Cancel button), a string of acceptable
   * characters to mean OK and to mean Cancel.  The two last strings are checked
   * to make sure they don't have common characters.  Additionally, the same
   * flag argument as for the string input is taken, as well as a result buffer.
   * The result buffer is required to be at least one byte long.  Depending on
   * the answer, the first character from the OK or the Cancel character strings
   * will be stored in the first byte of the result buffer.  No NUL will be
   * added, so the result is *not* a string.
   *
   * On success, the all return an index of the added information.  That index
   * is useful when retrieving results with UI_get0_result(). *)

  UI_add_input_string_procname = 'UI_add_input_string';
  UI_dup_input_string_procname = 'UI_dup_input_string';
  UI_add_verify_string_procname = 'UI_add_verify_string';
  UI_dup_verify_string_procname = 'UI_dup_verify_string';
  UI_add_input_boolean_procname = 'UI_add_input_boolean';
  UI_dup_input_boolean_procname = 'UI_dup_input_boolean';
  UI_add_info_string_procname = 'UI_add_info_string';
  UI_dup_info_string_procname = 'UI_dup_info_string';
  UI_add_error_string_procname = 'UI_add_error_string';
  UI_dup_error_string_procname = 'UI_dup_error_string';

  (*
   * The following function helps construct a prompt.  object_desc is a
   * textual short description of the object, for example "pass phrase",
   * and object_name is the name of the object (might be a card name or
   * a file name.
   * The returned string shall always be allocated on the heap with
   * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
   *
   * If the ui_method doesn't contain a pointer to a user-defined prompt
   * constructor, a default string is built, looking like this:
   *
   *       "Enter {object_desc} for {object_name}:"
   *
   * So, if object_desc has the value "pass phrase" and object_name has
   * the value "foo.key", the resulting string is:
   *
   *       "Enter pass phrase for foo.key:"
   *)
  UI_construct_prompt_procname = 'UI_construct_prompt';

  (*
   * The following function is used to store a pointer to user-specific data.
   * Any previous such pointer will be returned and replaced.
   *
   * For callback purposes, this function makes a lot more sense than using
   * ex_data, since the latter requires that different parts of OpenSSL or
   * applications share the same ex_data index.
   *
   * Note that the UI_OpenSSL() method completely ignores the user data. Other
   * methods may not, however.
   *)
  UI_add_user_data_procname = 'UI_add_user_data';
  (*
   * Alternatively, this function is used to duplicate the user data.
   * This uses the duplicator method function.  The destroy function will
   * be used to free the user data in this case.
   *)
  UI_dup_user_data_procname = 'UI_dup_user_data';
  (* We need a user data retrieving function as well.  *)
  UI_get0_user_data_procname = 'UI_get0_user_data';

  (* Return the result associated with a prompt given with the index i. *)
  UI_get0_result_procname = 'UI_get0_result';
  UI_get_result_length_procname = 'UI_get_result_length';

  (* When all strings have been added, process the whole thing. *)
  UI_process_procname = 'UI_process';

  (*
   * Give a user interface parameterised control commands.  This can be used to
   * send down an integer, a data pointer or a function pointer, as well as be
   * used to get information from a UI.
   *)
  UI_ctrl_procname = 'UI_ctrl';


  (* Some methods may use extra data *)
  //# define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
  //# define UI_get_app_data(s)             UI_get_ex_data(s,0)

  //# define UI_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
  UI_set_ex_data_procname = 'UI_set_ex_data';
  UI_get_ex_data_procname = 'UI_get_ex_data';

  (* Use specific methods instead of the built-in one *)
  UI_set_default_method_procname = 'UI_set_default_method';
  UI_get_default_method_procname = 'UI_get_default_method';
  UI_get_method_procname = 'UI_get_method';
  UI_set_method_procname = 'UI_set_method';

  (* The method with all the built-in thingies *)
  UI_OpenSSL_procname = 'UI_OpenSSL';

  (*
   * NULL method.  Literally does nothing, but may serve as a placeholder
   * to avoid internal default.
   *)
  UI_null_procname = 'UI_null';

  (* ---------- For method writers ---------- *)
  (*
     A method contains a number of functions that implement the low level
     of the User Interface.  The functions are:

          an opener       This function starts a session, maybe by opening
                          a channel to a tty, or by opening a window.
          a writer        This function is called to write a given string,
                          maybe to the tty, maybe as a field label in a
                          window.
          a flusher       This function is called to flush everything that
                          has been output so far.  It can be used to actually
                          display a dialog box after it has been built.
          a reader        This function is called to read a given prompt,
                          maybe from the tty, maybe from a field in a
                          window.  Note that it's called with all string
                          structures, not only the prompt ones, so it must
                          check such things itself.
          a closer        This function closes the session, maybe by closing
                          the channel to the tty, or closing the window.

     All these functions are expected to return:

          0       on error.
          1       on success.
          -1      on out-of-band events, for example if some prompting has
                  been canceled (by pressing Ctrl-C, for example).  This is
                  only checked when returned by the flusher or the reader.

     The way this is used, the opener is first called, then the writer for all
     strings, then the flusher, then the reader for all strings and finally the
     closer.  Note that if you want to prompt from a terminal or other command
     line interface, the best is to have the reader also write the prompts
     instead of having the writer do it.  If you want to prompt from a dialog
     box, the writer can be used to build up the contents of the box, and the
     flusher to actually display the box and run the event loop until all data
     has been given, after which the reader only grabs the given data and puts
     them back into the UI strings.

     All method functions take a UI as argument.  Additionally, the writer and
     the reader take a UI_STRING.
  *)

  UI_create_method_procname = 'UI_create_method';
  UI_destroy_method_procname = 'UI_destroy_method';

  UI_method_set_opener_procname = 'UI_method_set_opener';
  UI_method_set_writer_procname = 'UI_method_set_writer';
  UI_method_set_flusher_procname = 'UI_method_set_flusher';
  UI_method_set_reader_procname = 'UI_method_set_reader';
  UI_method_set_closer_procname = 'UI_method_set_closer';
  UI_method_set_data_duplicator_procname = 'UI_method_set_data_duplicator';
  UI_method_set_prompt_constructor_procname = 'UI_method_set_prompt_constructor';
  UI_method_set_ex_data_procname = 'UI_method_set_ex_data';

  UI_method_get_opener_procname = 'UI_method_get_opener';
  UI_method_get_writer_procname = 'UI_method_get_writer';
  UI_method_get_flusher_procname = 'UI_method_get_flusher';
  UI_method_get_reader_procname = 'UI_method_get_reader';
  UI_method_get_closer_procname = 'UI_method_get_closer';
  UI_method_get_prompt_constructor_procname = 'UI_method_get_prompt_constructor';
  UI_method_get_data_duplicator_procname = 'UI_method_get_data_duplicator';
  UI_method_get_data_destructor_procname = 'UI_method_get_data_destructor';
  UI_method_get_ex_data_procname = 'UI_method_get_ex_data';

  (*
   * The following functions are helpers for method writers to access relevant
   * data from a UI_STRING.
   *)

  (* Return type of the UI_STRING *)
  UI_get_string_type_procname = 'UI_get_string_type';
  (* Return input flags of the UI_STRING *)
  UI_get_input_flags_procname = 'UI_get_input_flags';
  (* Return the actual string to output (the prompt, info or error) *)
  UI_get0_output_string_procname = 'UI_get0_output_string';
  (*
   * Return the optional action string to output (the boolean prompt
   * instruction)
   *)
  UI_get0_action_string_procname = 'UI_get0_action_string';
  (* Return the result of a prompt *)
  UI_get0_result_string_procname = 'UI_get0_result_string';
  UI_get_result_string_length_procname = 'UI_get_result_string_length';
  (*
   * Return the string to test the result against.  Only useful with verifies.
   *)
  UI_get0_test_string_procname = 'UI_get0_test_string';
  (* Return the required minimum size of the result *)
  UI_get_result_minsize_procname = 'UI_get_result_minsize';
  (* Return the required maximum size of the result *)
  UI_get_result_maxsize_procname = 'UI_get_result_maxsize';
  (* Set the result of a UI_STRING. *)
  UI_set_result_procname = 'UI_set_result';
  UI_set_result_ex_procname = 'UI_set_result_ex';

  (* A couple of popular utility functions *)
  UI_UTIL_read_pw_string_procname = 'UI_UTIL_read_pw_string';
  UI_UTIL_read_pw_procname = 'UI_UTIL_read_pw';
  UI_UTIL_wrap_read_pem_callback_procname = 'UI_UTIL_wrap_read_pem_callback';


{$WARN  NO_RETVAL OFF}
function  ERR_UI_new: PUI; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_new_procname);
end;


function  ERR_UI_new_method(const method: PUI_Method): PUI; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_new_method_procname);
end;


procedure  ERR_UI_free(ui: PUI); 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_free_procname);
end;



  (*
   * The following functions are used to add strings to be printed and prompt
   * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
   * and UI_{add,dup}_input_boolean.
   *
   * UI_{add,dup}_<function>_string have the following meanings:
   *      add     add a text or prompt string.  The pointers given to these
   *              functions are used verbatim, no copying is done.
   *      dup     make a copy of the text or prompt string, then add the copy
   *              to the collection of strings in the user interface.
   *      <function>
   *              The function is a name for the functionality that the given
   *              string shall be used for.  It can be one of:
   *                      input   use the string as data prompt.
   *                      verify  use the string as verification prompt.  This
   *                              is used to verify a previous input.
   *                      info    use the string for informational output.
   *                      error   use the string for error output.
   * Honestly, there's currently no difference between info and error for the
   * moment.
   *
   * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
   * and are typically used when one wants to prompt for a yes/no response.
   *
   * All of the functions in this group take a UI and a prompt string.
   * The string input and verify addition functions also take a flag argument,
   * a buffer for the result to end up with, a minimum input size and a maximum
   * input size (the result buffer MUST be large enough to be able to contain
   * the maximum number of characters).  Additionally, the verify addition
   * functions takes another buffer to compare the result against.
   * The boolean input functions take an action description string (which should
   * be safe to ignore if the expected user action is obvious, for example with
   * a dialog box with an OK button and a Cancel button), a string of acceptable
   * characters to mean OK and to mean Cancel.  The two last strings are checked
   * to make sure they don't have common characters.  Additionally, the same
   * flag argument as for the string input is taken, as well as a result buffer.
   * The result buffer is required to be at least one byte long.  Depending on
   * the answer, the first character from the OK or the Cancel character strings
   * will be stored in the first byte of the result buffer.  No NUL will be
   * added, so the result is *not* a string.
   *
   * On success, the all return an index of the added information.  That index
   * is useful when retrieving results with UI_get0_result(). *)

function  ERR_UI_add_input_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_add_input_string_procname);
end;


function  ERR_UI_dup_input_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_dup_input_string_procname);
end;


function  ERR_UI_add_verify_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_add_verify_string_procname);
end;


function  ERR_UI_dup_verify_string(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_dup_verify_string_procname);
end;


function  ERR_UI_add_input_boolean(ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_add_input_boolean_procname);
end;


function  ERR_UI_dup_input_boolean(ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_dup_input_boolean_procname);
end;


function  ERR_UI_add_info_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_add_info_string_procname);
end;


function  ERR_UI_dup_info_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_dup_info_string_procname);
end;


function  ERR_UI_add_error_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_add_error_string_procname);
end;


function  ERR_UI_dup_error_string(ui: PUI; const text: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_dup_error_string_procname);
end;



  (*
   * The following function helps construct a prompt.  object_desc is a
   * textual short description of the object, for example "pass phrase",
   * and object_name is the name of the object (might be a card name or
   * a file name.
   * The returned string shall always be allocated on the heap with
   * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
   *
   * If the ui_method doesn't contain a pointer to a user-defined prompt
   * constructor, a default string is built, looking like this:
   *
   *       "Enter {object_desc} for {object_name}:"
   *
   * So, if object_desc has the value "pass phrase" and object_name has
   * the value "foo.key", the resulting string is:
   *
   *       "Enter pass phrase for foo.key:"
   *)
function  ERR_UI_construct_prompt(ui_method: PUI; const object_desc: PIdAnsiChar; const object_name: PIdAnsiChar): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_construct_prompt_procname);
end;



  (*
   * The following function is used to store a pointer to user-specific data.
   * Any previous such pointer will be returned and replaced.
   *
   * For callback purposes, this function makes a lot more sense than using
   * ex_data, since the latter requires that different parts of OpenSSL or
   * applications share the same ex_data index.
   *
   * Note that the UI_OpenSSL() method completely ignores the user data. Other
   * methods may not, however.
   *)
function  ERR_UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_add_user_data_procname);
end;


  (*
   * Alternatively, this function is used to duplicate the user data.
   * This uses the duplicator method function.  The destroy function will
   * be used to free the user data in this case.
   *)
function  ERR_UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_dup_user_data_procname);
end;


  (* We need a user data retrieving function as well.  *)
function  ERR_UI_get0_user_data(ui: PUI): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get0_user_data_procname);
end;



  (* Return the result associated with a prompt given with the index i. *)
function  ERR_UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get0_result_procname);
end;


function  ERR_UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_result_length_procname);
end;



  (* When all strings have been added, process the whole thing. *)
function  ERR_UI_process(ui: PUI): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_process_procname);
end;



  (*
   * Give a user interface parameterised control commands.  This can be used to
   * send down an integer, a data pointer or a function pointer, as well as be
   * used to get information from a UI.
   *)
function  ERR_UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: UI_ctrl_f): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_ctrl_procname);
end;




  (* Some methods may use extra data *)
  //# define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
  //# define UI_get_app_data(s)             UI_get_ex_data(s,0)

  //# define UI_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
function  ERR_UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_set_ex_data_procname);
end;


function  ERR_UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_ex_data_procname);
end;



  (* Use specific methods instead of the built-in one *)
procedure  ERR_UI_set_default_method(const meth: PUI_Method); 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_set_default_method_procname);
end;


function  ERR_UI_get_default_method: PUI_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_default_method_procname);
end;


function  ERR_UI_get_method(ui: PUI): PUI_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_method_procname);
end;


function  ERR_UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_set_method_procname);
end;



  (* The method with all the built-in thingies *)
function  ERR_UI_OpenSSL: PUI_Method; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_OpenSSL_procname);
end;



  (*
   * NULL method.  Literally does nothing, but may serve as a placeholder
   * to avoid internal default.
   *)
function  ERR_UI_null: PUI_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_null_procname);
end;



  (* ---------- For method writers ---------- *)
  (*
     A method contains a number of functions that implement the low level
     of the User Interface.  The functions are:

          an opener       This function starts a session, maybe by opening
                          a channel to a tty, or by opening a window.
          a writer        This function is called to write a given string,
                          maybe to the tty, maybe as a field label in a
                          window.
          a flusher       This function is called to flush everything that
                          has been output so far.  It can be used to actually
                          display a dialog box after it has been built.
          a reader        This function is called to read a given prompt,
                          maybe from the tty, maybe from a field in a
                          window.  Note that it's called with all string
                          structures, not only the prompt ones, so it must
                          check such things itself.
          a closer        This function closes the session, maybe by closing
                          the channel to the tty, or closing the window.

     All these functions are expected to return:

          0       on error.
          1       on success.
          -1      on out-of-band events, for example if some prompting has
                  been canceled (by pressing Ctrl-C, for example).  This is
                  only checked when returned by the flusher or the reader.

     The way this is used, the opener is first called, then the writer for all
     strings, then the flusher, then the reader for all strings and finally the
     closer.  Note that if you want to prompt from a terminal or other command
     line interface, the best is to have the reader also write the prompts
     instead of having the writer do it.  If you want to prompt from a dialog
     box, the writer can be used to build up the contents of the box, and the
     flusher to actually display the box and run the event loop until all data
     has been given, after which the reader only grabs the given data and puts
     them back into the UI strings.

     All method functions take a UI as argument.  Additionally, the writer and
     the reader take a UI_STRING.
  *)

function  ERR_UI_create_method(const name: PIdAnsiChar): PUI_Method; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_create_method_procname);
end;


procedure  ERR_UI_destroy_method(ui_method: PUI_Method); 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_destroy_method_procname);
end;



function  ERR_UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_opener_procname);
end;


function  ERR_UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_writer_procname);
end;


function  ERR_UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_flusher_procname);
end;


function  ERR_UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_reader_procname);
end;


function  ERR_UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_closer_procname);
end;


function  ERR_UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_data_duplicator_procname);
end;


function  ERR_UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_prompt_constructor_procname);
end;


function  ERR_UI_method_set_ex_data(method: PUI_Method; idx: TIdC_INT; data: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_set_ex_data_procname);
end;



function  ERR_UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_opener_procname);
end;


function  ERR_UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_writer_procname);
end;


function  ERR_UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_flusher_procname);
end;


function  ERR_UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_reader_procname);
end;


function  ERR_UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_closer_procname);
end;


function  ERR_UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_prompt_constructor_procname);
end;


function  ERR_UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_data_duplicator_procname);
end;


function  ERR_UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_data_destructor_procname);
end;


function  ERR_UI_method_get_ex_data(const method: PUI_METHOD; idx: TIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_method_get_ex_data_procname);
end;



  (*
   * The following functions are helpers for method writers to access relevant
   * data from a UI_STRING.
   *)

  (* Return type of the UI_STRING *)
function  ERR_UI_get_string_type(uis: PUI_String): UI_string_types; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_string_type_procname);
end;


  (* Return input flags of the UI_STRING *)
function  ERR_UI_get_input_flags(uis: PUI_String): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_input_flags_procname);
end;


  (* Return the actual string to output (the prompt, info or error) *)
function  ERR_UI_get0_output_string(uis: PUI_String): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get0_output_string_procname);
end;


  (*
   * Return the optional action string to output (the boolean prompt
   * instruction)
   *)
function  ERR_UI_get0_action_string(uis: PUI_String): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get0_action_string_procname);
end;


  (* Return the result of a prompt *)
function  ERR_UI_get0_result_string(uis: PUI_String): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get0_result_string_procname);
end;


function  ERR_UI_get_result_string_length(uis: PUI_String): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_result_string_length_procname);
end;


  (*
   * Return the string to test the result against.  Only useful with verifies.
   *)
function  ERR_UI_get0_test_string(uis: PUI_String): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get0_test_string_procname);
end;


  (* Return the required minimum size of the result *)
function  ERR_UI_get_result_minsize(uis: PUI_String): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_result_minsize_procname);
end;


  (* Return the required maximum size of the result *)
function  ERR_UI_get_result_maxsize(uis: PUI_String): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_get_result_maxsize_procname);
end;


  (* Set the result of a UI_STRING. *)
// Got [dcc32 Error] IdOpenSSLHeaders_ui.pas(1466): E2004 Identifier redeclared: 'Result'
// Don't know why.
//function  ERR_UI_set_result(ui: PUI; uis: PUI_String; const result: PIdAnsiChar): TIdC_INT;
//begin
//  EIdAPIFunctionNotPresent.RaiseException(UI_set_result_procname);
//end;

//Go [dcc32 Error] IdOpenSSLHeaders_ui.pas(1474): E2004 Identifier redeclared: 'Result'
// Don't know why.
//function  ERR_UI_set_result_ex(ui: PUI; uis: PUI_String; const result: PIdAnsiChar; len: TIdC_INT): TIdC_INT;
//begin
//  EIdAPIFunctionNotPresent.RaiseException(UI_set_result_ex_procname);
//end;



  (* A couple of popular utility functions *)
function  ERR_UI_UTIL_read_pw_string(buf: PIdAnsiChar; length: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_UTIL_read_pw_string_procname);
end;


function  ERR_UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_UTIL_read_pw_procname);
end;


function  ERR_UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TIdC_INT): PUI_Method; 
begin
  EIdAPIFunctionNotPresent.RaiseException(UI_UTIL_wrap_read_pem_callback_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  UI_new := LoadLibFunction(ADllHandle, UI_new_procname);
  FuncLoadError := not assigned(UI_new);
  if FuncLoadError then
  begin
    {$if not defined(UI_new_allownil)}
    UI_new := @ERR_UI_new;
    {$ifend}
    {$if declared(UI_new_introduced)}
    if LibVersion < UI_new_introduced then
    begin
      {$if declared(FC_UI_new)}
      UI_new := @FC_UI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_new_removed)}
    if UI_new_removed <= LibVersion then
    begin
      {$if declared(_UI_new)}
      UI_new := @_UI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_new_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_new');
    {$ifend}
  end;


  UI_new_method := LoadLibFunction(ADllHandle, UI_new_method_procname);
  FuncLoadError := not assigned(UI_new_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_new_method_allownil)}
    UI_new_method := @ERR_UI_new_method;
    {$ifend}
    {$if declared(UI_new_method_introduced)}
    if LibVersion < UI_new_method_introduced then
    begin
      {$if declared(FC_UI_new_method)}
      UI_new_method := @FC_UI_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_new_method_removed)}
    if UI_new_method_removed <= LibVersion then
    begin
      {$if declared(_UI_new_method)}
      UI_new_method := @_UI_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_new_method');
    {$ifend}
  end;


  UI_free := LoadLibFunction(ADllHandle, UI_free_procname);
  FuncLoadError := not assigned(UI_free);
  if FuncLoadError then
  begin
    {$if not defined(UI_free_allownil)}
    UI_free := @ERR_UI_free;
    {$ifend}
    {$if declared(UI_free_introduced)}
    if LibVersion < UI_free_introduced then
    begin
      {$if declared(FC_UI_free)}
      UI_free := @FC_UI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_free_removed)}
    if UI_free_removed <= LibVersion then
    begin
      {$if declared(_UI_free)}
      UI_free := @_UI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_free_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_free');
    {$ifend}
  end;


  UI_add_input_string := LoadLibFunction(ADllHandle, UI_add_input_string_procname);
  FuncLoadError := not assigned(UI_add_input_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_input_string_allownil)}
    UI_add_input_string := @ERR_UI_add_input_string;
    {$ifend}
    {$if declared(UI_add_input_string_introduced)}
    if LibVersion < UI_add_input_string_introduced then
    begin
      {$if declared(FC_UI_add_input_string)}
      UI_add_input_string := @FC_UI_add_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_input_string_removed)}
    if UI_add_input_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_input_string)}
      UI_add_input_string := @_UI_add_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_input_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_input_string');
    {$ifend}
  end;


  UI_dup_input_string := LoadLibFunction(ADllHandle, UI_dup_input_string_procname);
  FuncLoadError := not assigned(UI_dup_input_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_input_string_allownil)}
    UI_dup_input_string := @ERR_UI_dup_input_string;
    {$ifend}
    {$if declared(UI_dup_input_string_introduced)}
    if LibVersion < UI_dup_input_string_introduced then
    begin
      {$if declared(FC_UI_dup_input_string)}
      UI_dup_input_string := @FC_UI_dup_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_input_string_removed)}
    if UI_dup_input_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_input_string)}
      UI_dup_input_string := @_UI_dup_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_input_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_input_string');
    {$ifend}
  end;


  UI_add_verify_string := LoadLibFunction(ADllHandle, UI_add_verify_string_procname);
  FuncLoadError := not assigned(UI_add_verify_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_verify_string_allownil)}
    UI_add_verify_string := @ERR_UI_add_verify_string;
    {$ifend}
    {$if declared(UI_add_verify_string_introduced)}
    if LibVersion < UI_add_verify_string_introduced then
    begin
      {$if declared(FC_UI_add_verify_string)}
      UI_add_verify_string := @FC_UI_add_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_verify_string_removed)}
    if UI_add_verify_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_verify_string)}
      UI_add_verify_string := @_UI_add_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_verify_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_verify_string');
    {$ifend}
  end;


  UI_dup_verify_string := LoadLibFunction(ADllHandle, UI_dup_verify_string_procname);
  FuncLoadError := not assigned(UI_dup_verify_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_verify_string_allownil)}
    UI_dup_verify_string := @ERR_UI_dup_verify_string;
    {$ifend}
    {$if declared(UI_dup_verify_string_introduced)}
    if LibVersion < UI_dup_verify_string_introduced then
    begin
      {$if declared(FC_UI_dup_verify_string)}
      UI_dup_verify_string := @FC_UI_dup_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_verify_string_removed)}
    if UI_dup_verify_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_verify_string)}
      UI_dup_verify_string := @_UI_dup_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_verify_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_verify_string');
    {$ifend}
  end;


  UI_add_input_boolean := LoadLibFunction(ADllHandle, UI_add_input_boolean_procname);
  FuncLoadError := not assigned(UI_add_input_boolean);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_input_boolean_allownil)}
    UI_add_input_boolean := @ERR_UI_add_input_boolean;
    {$ifend}
    {$if declared(UI_add_input_boolean_introduced)}
    if LibVersion < UI_add_input_boolean_introduced then
    begin
      {$if declared(FC_UI_add_input_boolean)}
      UI_add_input_boolean := @FC_UI_add_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_input_boolean_removed)}
    if UI_add_input_boolean_removed <= LibVersion then
    begin
      {$if declared(_UI_add_input_boolean)}
      UI_add_input_boolean := @_UI_add_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_input_boolean_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_input_boolean');
    {$ifend}
  end;


  UI_dup_input_boolean := LoadLibFunction(ADllHandle, UI_dup_input_boolean_procname);
  FuncLoadError := not assigned(UI_dup_input_boolean);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_input_boolean_allownil)}
    UI_dup_input_boolean := @ERR_UI_dup_input_boolean;
    {$ifend}
    {$if declared(UI_dup_input_boolean_introduced)}
    if LibVersion < UI_dup_input_boolean_introduced then
    begin
      {$if declared(FC_UI_dup_input_boolean)}
      UI_dup_input_boolean := @FC_UI_dup_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_input_boolean_removed)}
    if UI_dup_input_boolean_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_input_boolean)}
      UI_dup_input_boolean := @_UI_dup_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_input_boolean_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_input_boolean');
    {$ifend}
  end;


  UI_add_info_string := LoadLibFunction(ADllHandle, UI_add_info_string_procname);
  FuncLoadError := not assigned(UI_add_info_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_info_string_allownil)}
    UI_add_info_string := @ERR_UI_add_info_string;
    {$ifend}
    {$if declared(UI_add_info_string_introduced)}
    if LibVersion < UI_add_info_string_introduced then
    begin
      {$if declared(FC_UI_add_info_string)}
      UI_add_info_string := @FC_UI_add_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_info_string_removed)}
    if UI_add_info_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_info_string)}
      UI_add_info_string := @_UI_add_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_info_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_info_string');
    {$ifend}
  end;


  UI_dup_info_string := LoadLibFunction(ADllHandle, UI_dup_info_string_procname);
  FuncLoadError := not assigned(UI_dup_info_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_info_string_allownil)}
    UI_dup_info_string := @ERR_UI_dup_info_string;
    {$ifend}
    {$if declared(UI_dup_info_string_introduced)}
    if LibVersion < UI_dup_info_string_introduced then
    begin
      {$if declared(FC_UI_dup_info_string)}
      UI_dup_info_string := @FC_UI_dup_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_info_string_removed)}
    if UI_dup_info_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_info_string)}
      UI_dup_info_string := @_UI_dup_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_info_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_info_string');
    {$ifend}
  end;


  UI_add_error_string := LoadLibFunction(ADllHandle, UI_add_error_string_procname);
  FuncLoadError := not assigned(UI_add_error_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_error_string_allownil)}
    UI_add_error_string := @ERR_UI_add_error_string;
    {$ifend}
    {$if declared(UI_add_error_string_introduced)}
    if LibVersion < UI_add_error_string_introduced then
    begin
      {$if declared(FC_UI_add_error_string)}
      UI_add_error_string := @FC_UI_add_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_error_string_removed)}
    if UI_add_error_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_error_string)}
      UI_add_error_string := @_UI_add_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_error_string');
    {$ifend}
  end;


  UI_dup_error_string := LoadLibFunction(ADllHandle, UI_dup_error_string_procname);
  FuncLoadError := not assigned(UI_dup_error_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_error_string_allownil)}
    UI_dup_error_string := @ERR_UI_dup_error_string;
    {$ifend}
    {$if declared(UI_dup_error_string_introduced)}
    if LibVersion < UI_dup_error_string_introduced then
    begin
      {$if declared(FC_UI_dup_error_string)}
      UI_dup_error_string := @FC_UI_dup_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_error_string_removed)}
    if UI_dup_error_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_error_string)}
      UI_dup_error_string := @_UI_dup_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_error_string');
    {$ifend}
  end;


  UI_construct_prompt := LoadLibFunction(ADllHandle, UI_construct_prompt_procname);
  FuncLoadError := not assigned(UI_construct_prompt);
  if FuncLoadError then
  begin
    {$if not defined(UI_construct_prompt_allownil)}
    UI_construct_prompt := @ERR_UI_construct_prompt;
    {$ifend}
    {$if declared(UI_construct_prompt_introduced)}
    if LibVersion < UI_construct_prompt_introduced then
    begin
      {$if declared(FC_UI_construct_prompt)}
      UI_construct_prompt := @FC_UI_construct_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_construct_prompt_removed)}
    if UI_construct_prompt_removed <= LibVersion then
    begin
      {$if declared(_UI_construct_prompt)}
      UI_construct_prompt := @_UI_construct_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_construct_prompt_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_construct_prompt');
    {$ifend}
  end;


  UI_add_user_data := LoadLibFunction(ADllHandle, UI_add_user_data_procname);
  FuncLoadError := not assigned(UI_add_user_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_user_data_allownil)}
    UI_add_user_data := @ERR_UI_add_user_data;
    {$ifend}
    {$if declared(UI_add_user_data_introduced)}
    if LibVersion < UI_add_user_data_introduced then
    begin
      {$if declared(FC_UI_add_user_data)}
      UI_add_user_data := @FC_UI_add_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_user_data_removed)}
    if UI_add_user_data_removed <= LibVersion then
    begin
      {$if declared(_UI_add_user_data)}
      UI_add_user_data := @_UI_add_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_user_data');
    {$ifend}
  end;


  UI_dup_user_data := LoadLibFunction(ADllHandle, UI_dup_user_data_procname);
  FuncLoadError := not assigned(UI_dup_user_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_user_data_allownil)}
    UI_dup_user_data := @ERR_UI_dup_user_data;
    {$ifend}
    {$if declared(UI_dup_user_data_introduced)}
    if LibVersion < UI_dup_user_data_introduced then
    begin
      {$if declared(FC_UI_dup_user_data)}
      UI_dup_user_data := @FC_UI_dup_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_user_data_removed)}
    if UI_dup_user_data_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_user_data)}
      UI_dup_user_data := @_UI_dup_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_user_data');
    {$ifend}
  end;


  UI_get0_user_data := LoadLibFunction(ADllHandle, UI_get0_user_data_procname);
  FuncLoadError := not assigned(UI_get0_user_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_user_data_allownil)}
    UI_get0_user_data := @ERR_UI_get0_user_data;
    {$ifend}
    {$if declared(UI_get0_user_data_introduced)}
    if LibVersion < UI_get0_user_data_introduced then
    begin
      {$if declared(FC_UI_get0_user_data)}
      UI_get0_user_data := @FC_UI_get0_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_user_data_removed)}
    if UI_get0_user_data_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_user_data)}
      UI_get0_user_data := @_UI_get0_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_user_data');
    {$ifend}
  end;


  UI_get0_result := LoadLibFunction(ADllHandle, UI_get0_result_procname);
  FuncLoadError := not assigned(UI_get0_result);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_result_allownil)}
    UI_get0_result := @ERR_UI_get0_result;
    {$ifend}
    {$if declared(UI_get0_result_introduced)}
    if LibVersion < UI_get0_result_introduced then
    begin
      {$if declared(FC_UI_get0_result)}
      UI_get0_result := @FC_UI_get0_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_result_removed)}
    if UI_get0_result_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_result)}
      UI_get0_result := @_UI_get0_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_result_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_result');
    {$ifend}
  end;


  UI_get_result_length := LoadLibFunction(ADllHandle, UI_get_result_length_procname);
  FuncLoadError := not assigned(UI_get_result_length);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_length_allownil)}
    UI_get_result_length := @ERR_UI_get_result_length;
    {$ifend}
    {$if declared(UI_get_result_length_introduced)}
    if LibVersion < UI_get_result_length_introduced then
    begin
      {$if declared(FC_UI_get_result_length)}
      UI_get_result_length := @FC_UI_get_result_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_length_removed)}
    if UI_get_result_length_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_length)}
      UI_get_result_length := @_UI_get_result_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_length_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_length');
    {$ifend}
  end;


  UI_process := LoadLibFunction(ADllHandle, UI_process_procname);
  FuncLoadError := not assigned(UI_process);
  if FuncLoadError then
  begin
    {$if not defined(UI_process_allownil)}
    UI_process := @ERR_UI_process;
    {$ifend}
    {$if declared(UI_process_introduced)}
    if LibVersion < UI_process_introduced then
    begin
      {$if declared(FC_UI_process)}
      UI_process := @FC_UI_process;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_process_removed)}
    if UI_process_removed <= LibVersion then
    begin
      {$if declared(_UI_process)}
      UI_process := @_UI_process;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_process_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_process');
    {$ifend}
  end;


  UI_ctrl := LoadLibFunction(ADllHandle, UI_ctrl_procname);
  FuncLoadError := not assigned(UI_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(UI_ctrl_allownil)}
    UI_ctrl := @ERR_UI_ctrl;
    {$ifend}
    {$if declared(UI_ctrl_introduced)}
    if LibVersion < UI_ctrl_introduced then
    begin
      {$if declared(FC_UI_ctrl)}
      UI_ctrl := @FC_UI_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_ctrl_removed)}
    if UI_ctrl_removed <= LibVersion then
    begin
      {$if declared(_UI_ctrl)}
      UI_ctrl := @_UI_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_ctrl');
    {$ifend}
  end;


  UI_set_ex_data := LoadLibFunction(ADllHandle, UI_set_ex_data_procname);
  FuncLoadError := not assigned(UI_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_ex_data_allownil)}
    UI_set_ex_data := @ERR_UI_set_ex_data;
    {$ifend}
    {$if declared(UI_set_ex_data_introduced)}
    if LibVersion < UI_set_ex_data_introduced then
    begin
      {$if declared(FC_UI_set_ex_data)}
      UI_set_ex_data := @FC_UI_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_ex_data_removed)}
    if UI_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_set_ex_data)}
      UI_set_ex_data := @_UI_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_ex_data');
    {$ifend}
  end;


  UI_get_ex_data := LoadLibFunction(ADllHandle, UI_get_ex_data_procname);
  FuncLoadError := not assigned(UI_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_ex_data_allownil)}
    UI_get_ex_data := @ERR_UI_get_ex_data;
    {$ifend}
    {$if declared(UI_get_ex_data_introduced)}
    if LibVersion < UI_get_ex_data_introduced then
    begin
      {$if declared(FC_UI_get_ex_data)}
      UI_get_ex_data := @FC_UI_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_ex_data_removed)}
    if UI_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_get_ex_data)}
      UI_get_ex_data := @_UI_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_ex_data');
    {$ifend}
  end;


  UI_set_default_method := LoadLibFunction(ADllHandle, UI_set_default_method_procname);
  FuncLoadError := not assigned(UI_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_default_method_allownil)}
    UI_set_default_method := @ERR_UI_set_default_method;
    {$ifend}
    {$if declared(UI_set_default_method_introduced)}
    if LibVersion < UI_set_default_method_introduced then
    begin
      {$if declared(FC_UI_set_default_method)}
      UI_set_default_method := @FC_UI_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_default_method_removed)}
    if UI_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_UI_set_default_method)}
      UI_set_default_method := @_UI_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_default_method');
    {$ifend}
  end;


  UI_get_default_method := LoadLibFunction(ADllHandle, UI_get_default_method_procname);
  FuncLoadError := not assigned(UI_get_default_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_default_method_allownil)}
    UI_get_default_method := @ERR_UI_get_default_method;
    {$ifend}
    {$if declared(UI_get_default_method_introduced)}
    if LibVersion < UI_get_default_method_introduced then
    begin
      {$if declared(FC_UI_get_default_method)}
      UI_get_default_method := @FC_UI_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_default_method_removed)}
    if UI_get_default_method_removed <= LibVersion then
    begin
      {$if declared(_UI_get_default_method)}
      UI_get_default_method := @_UI_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_default_method');
    {$ifend}
  end;


  UI_get_method := LoadLibFunction(ADllHandle, UI_get_method_procname);
  FuncLoadError := not assigned(UI_get_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_method_allownil)}
    UI_get_method := @ERR_UI_get_method;
    {$ifend}
    {$if declared(UI_get_method_introduced)}
    if LibVersion < UI_get_method_introduced then
    begin
      {$if declared(FC_UI_get_method)}
      UI_get_method := @FC_UI_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_method_removed)}
    if UI_get_method_removed <= LibVersion then
    begin
      {$if declared(_UI_get_method)}
      UI_get_method := @_UI_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_method');
    {$ifend}
  end;


  UI_set_method := LoadLibFunction(ADllHandle, UI_set_method_procname);
  FuncLoadError := not assigned(UI_set_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_method_allownil)}
    UI_set_method := @ERR_UI_set_method;
    {$ifend}
    {$if declared(UI_set_method_introduced)}
    if LibVersion < UI_set_method_introduced then
    begin
      {$if declared(FC_UI_set_method)}
      UI_set_method := @FC_UI_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_method_removed)}
    if UI_set_method_removed <= LibVersion then
    begin
      {$if declared(_UI_set_method)}
      UI_set_method := @_UI_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_method');
    {$ifend}
  end;


  UI_OpenSSL := LoadLibFunction(ADllHandle, UI_OpenSSL_procname);
  FuncLoadError := not assigned(UI_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(UI_OpenSSL_allownil)}
    UI_OpenSSL := @ERR_UI_OpenSSL;
    {$ifend}
    {$if declared(UI_OpenSSL_introduced)}
    if LibVersion < UI_OpenSSL_introduced then
    begin
      {$if declared(FC_UI_OpenSSL)}
      UI_OpenSSL := @FC_UI_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_OpenSSL_removed)}
    if UI_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_UI_OpenSSL)}
      UI_OpenSSL := @_UI_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_OpenSSL');
    {$ifend}
  end;


  UI_null := LoadLibFunction(ADllHandle, UI_null_procname);
  FuncLoadError := not assigned(UI_null);
  if FuncLoadError then
  begin
    {$if not defined(UI_null_allownil)}
    UI_null := @ERR_UI_null;
    {$ifend}
    {$if declared(UI_null_introduced)}
    if LibVersion < UI_null_introduced then
    begin
      {$if declared(FC_UI_null)}
      UI_null := @FC_UI_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_null_removed)}
    if UI_null_removed <= LibVersion then
    begin
      {$if declared(_UI_null)}
      UI_null := @_UI_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_null_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_null');
    {$ifend}
  end;


  UI_create_method := LoadLibFunction(ADllHandle, UI_create_method_procname);
  FuncLoadError := not assigned(UI_create_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_create_method_allownil)}
    UI_create_method := @ERR_UI_create_method;
    {$ifend}
    {$if declared(UI_create_method_introduced)}
    if LibVersion < UI_create_method_introduced then
    begin
      {$if declared(FC_UI_create_method)}
      UI_create_method := @FC_UI_create_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_create_method_removed)}
    if UI_create_method_removed <= LibVersion then
    begin
      {$if declared(_UI_create_method)}
      UI_create_method := @_UI_create_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_create_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_create_method');
    {$ifend}
  end;


  UI_destroy_method := LoadLibFunction(ADllHandle, UI_destroy_method_procname);
  FuncLoadError := not assigned(UI_destroy_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_destroy_method_allownil)}
    UI_destroy_method := @ERR_UI_destroy_method;
    {$ifend}
    {$if declared(UI_destroy_method_introduced)}
    if LibVersion < UI_destroy_method_introduced then
    begin
      {$if declared(FC_UI_destroy_method)}
      UI_destroy_method := @FC_UI_destroy_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_destroy_method_removed)}
    if UI_destroy_method_removed <= LibVersion then
    begin
      {$if declared(_UI_destroy_method)}
      UI_destroy_method := @_UI_destroy_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_destroy_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_destroy_method');
    {$ifend}
  end;


  UI_method_set_opener := LoadLibFunction(ADllHandle, UI_method_set_opener_procname);
  FuncLoadError := not assigned(UI_method_set_opener);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_opener_allownil)}
    UI_method_set_opener := @ERR_UI_method_set_opener;
    {$ifend}
    {$if declared(UI_method_set_opener_introduced)}
    if LibVersion < UI_method_set_opener_introduced then
    begin
      {$if declared(FC_UI_method_set_opener)}
      UI_method_set_opener := @FC_UI_method_set_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_opener_removed)}
    if UI_method_set_opener_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_opener)}
      UI_method_set_opener := @_UI_method_set_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_opener_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_opener');
    {$ifend}
  end;


  UI_method_set_writer := LoadLibFunction(ADllHandle, UI_method_set_writer_procname);
  FuncLoadError := not assigned(UI_method_set_writer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_writer_allownil)}
    UI_method_set_writer := @ERR_UI_method_set_writer;
    {$ifend}
    {$if declared(UI_method_set_writer_introduced)}
    if LibVersion < UI_method_set_writer_introduced then
    begin
      {$if declared(FC_UI_method_set_writer)}
      UI_method_set_writer := @FC_UI_method_set_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_writer_removed)}
    if UI_method_set_writer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_writer)}
      UI_method_set_writer := @_UI_method_set_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_writer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_writer');
    {$ifend}
  end;


  UI_method_set_flusher := LoadLibFunction(ADllHandle, UI_method_set_flusher_procname);
  FuncLoadError := not assigned(UI_method_set_flusher);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_flusher_allownil)}
    UI_method_set_flusher := @ERR_UI_method_set_flusher;
    {$ifend}
    {$if declared(UI_method_set_flusher_introduced)}
    if LibVersion < UI_method_set_flusher_introduced then
    begin
      {$if declared(FC_UI_method_set_flusher)}
      UI_method_set_flusher := @FC_UI_method_set_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_flusher_removed)}
    if UI_method_set_flusher_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_flusher)}
      UI_method_set_flusher := @_UI_method_set_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_flusher_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_flusher');
    {$ifend}
  end;


  UI_method_set_reader := LoadLibFunction(ADllHandle, UI_method_set_reader_procname);
  FuncLoadError := not assigned(UI_method_set_reader);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_reader_allownil)}
    UI_method_set_reader := @ERR_UI_method_set_reader;
    {$ifend}
    {$if declared(UI_method_set_reader_introduced)}
    if LibVersion < UI_method_set_reader_introduced then
    begin
      {$if declared(FC_UI_method_set_reader)}
      UI_method_set_reader := @FC_UI_method_set_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_reader_removed)}
    if UI_method_set_reader_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_reader)}
      UI_method_set_reader := @_UI_method_set_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_reader_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_reader');
    {$ifend}
  end;


  UI_method_set_closer := LoadLibFunction(ADllHandle, UI_method_set_closer_procname);
  FuncLoadError := not assigned(UI_method_set_closer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_closer_allownil)}
    UI_method_set_closer := @ERR_UI_method_set_closer;
    {$ifend}
    {$if declared(UI_method_set_closer_introduced)}
    if LibVersion < UI_method_set_closer_introduced then
    begin
      {$if declared(FC_UI_method_set_closer)}
      UI_method_set_closer := @FC_UI_method_set_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_closer_removed)}
    if UI_method_set_closer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_closer)}
      UI_method_set_closer := @_UI_method_set_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_closer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_closer');
    {$ifend}
  end;


  UI_method_set_data_duplicator := LoadLibFunction(ADllHandle, UI_method_set_data_duplicator_procname);
  FuncLoadError := not assigned(UI_method_set_data_duplicator);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_data_duplicator_allownil)}
    UI_method_set_data_duplicator := @ERR_UI_method_set_data_duplicator;
    {$ifend}
    {$if declared(UI_method_set_data_duplicator_introduced)}
    if LibVersion < UI_method_set_data_duplicator_introduced then
    begin
      {$if declared(FC_UI_method_set_data_duplicator)}
      UI_method_set_data_duplicator := @FC_UI_method_set_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_data_duplicator_removed)}
    if UI_method_set_data_duplicator_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_data_duplicator)}
      UI_method_set_data_duplicator := @_UI_method_set_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_data_duplicator_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_data_duplicator');
    {$ifend}
  end;


  UI_method_set_prompt_constructor := LoadLibFunction(ADllHandle, UI_method_set_prompt_constructor_procname);
  FuncLoadError := not assigned(UI_method_set_prompt_constructor);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_prompt_constructor_allownil)}
    UI_method_set_prompt_constructor := @ERR_UI_method_set_prompt_constructor;
    {$ifend}
    {$if declared(UI_method_set_prompt_constructor_introduced)}
    if LibVersion < UI_method_set_prompt_constructor_introduced then
    begin
      {$if declared(FC_UI_method_set_prompt_constructor)}
      UI_method_set_prompt_constructor := @FC_UI_method_set_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_prompt_constructor_removed)}
    if UI_method_set_prompt_constructor_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_prompt_constructor)}
      UI_method_set_prompt_constructor := @_UI_method_set_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_prompt_constructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_prompt_constructor');
    {$ifend}
  end;


  UI_method_set_ex_data := LoadLibFunction(ADllHandle, UI_method_set_ex_data_procname);
  FuncLoadError := not assigned(UI_method_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_ex_data_allownil)}
    UI_method_set_ex_data := @ERR_UI_method_set_ex_data;
    {$ifend}
    {$if declared(UI_method_set_ex_data_introduced)}
    if LibVersion < UI_method_set_ex_data_introduced then
    begin
      {$if declared(FC_UI_method_set_ex_data)}
      UI_method_set_ex_data := @FC_UI_method_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_ex_data_removed)}
    if UI_method_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_ex_data)}
      UI_method_set_ex_data := @_UI_method_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_ex_data');
    {$ifend}
  end;


  UI_method_get_opener := LoadLibFunction(ADllHandle, UI_method_get_opener_procname);
  FuncLoadError := not assigned(UI_method_get_opener);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_opener_allownil)}
    UI_method_get_opener := @ERR_UI_method_get_opener;
    {$ifend}
    {$if declared(UI_method_get_opener_introduced)}
    if LibVersion < UI_method_get_opener_introduced then
    begin
      {$if declared(FC_UI_method_get_opener)}
      UI_method_get_opener := @FC_UI_method_get_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_opener_removed)}
    if UI_method_get_opener_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_opener)}
      UI_method_get_opener := @_UI_method_get_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_opener_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_opener');
    {$ifend}
  end;


  UI_method_get_writer := LoadLibFunction(ADllHandle, UI_method_get_writer_procname);
  FuncLoadError := not assigned(UI_method_get_writer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_writer_allownil)}
    UI_method_get_writer := @ERR_UI_method_get_writer;
    {$ifend}
    {$if declared(UI_method_get_writer_introduced)}
    if LibVersion < UI_method_get_writer_introduced then
    begin
      {$if declared(FC_UI_method_get_writer)}
      UI_method_get_writer := @FC_UI_method_get_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_writer_removed)}
    if UI_method_get_writer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_writer)}
      UI_method_get_writer := @_UI_method_get_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_writer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_writer');
    {$ifend}
  end;


  UI_method_get_flusher := LoadLibFunction(ADllHandle, UI_method_get_flusher_procname);
  FuncLoadError := not assigned(UI_method_get_flusher);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_flusher_allownil)}
    UI_method_get_flusher := @ERR_UI_method_get_flusher;
    {$ifend}
    {$if declared(UI_method_get_flusher_introduced)}
    if LibVersion < UI_method_get_flusher_introduced then
    begin
      {$if declared(FC_UI_method_get_flusher)}
      UI_method_get_flusher := @FC_UI_method_get_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_flusher_removed)}
    if UI_method_get_flusher_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_flusher)}
      UI_method_get_flusher := @_UI_method_get_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_flusher_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_flusher');
    {$ifend}
  end;


  UI_method_get_reader := LoadLibFunction(ADllHandle, UI_method_get_reader_procname);
  FuncLoadError := not assigned(UI_method_get_reader);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_reader_allownil)}
    UI_method_get_reader := @ERR_UI_method_get_reader;
    {$ifend}
    {$if declared(UI_method_get_reader_introduced)}
    if LibVersion < UI_method_get_reader_introduced then
    begin
      {$if declared(FC_UI_method_get_reader)}
      UI_method_get_reader := @FC_UI_method_get_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_reader_removed)}
    if UI_method_get_reader_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_reader)}
      UI_method_get_reader := @_UI_method_get_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_reader_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_reader');
    {$ifend}
  end;


  UI_method_get_closer := LoadLibFunction(ADllHandle, UI_method_get_closer_procname);
  FuncLoadError := not assigned(UI_method_get_closer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_closer_allownil)}
    UI_method_get_closer := @ERR_UI_method_get_closer;
    {$ifend}
    {$if declared(UI_method_get_closer_introduced)}
    if LibVersion < UI_method_get_closer_introduced then
    begin
      {$if declared(FC_UI_method_get_closer)}
      UI_method_get_closer := @FC_UI_method_get_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_closer_removed)}
    if UI_method_get_closer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_closer)}
      UI_method_get_closer := @_UI_method_get_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_closer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_closer');
    {$ifend}
  end;


  UI_method_get_prompt_constructor := LoadLibFunction(ADllHandle, UI_method_get_prompt_constructor_procname);
  FuncLoadError := not assigned(UI_method_get_prompt_constructor);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_prompt_constructor_allownil)}
    UI_method_get_prompt_constructor := @ERR_UI_method_get_prompt_constructor;
    {$ifend}
    {$if declared(UI_method_get_prompt_constructor_introduced)}
    if LibVersion < UI_method_get_prompt_constructor_introduced then
    begin
      {$if declared(FC_UI_method_get_prompt_constructor)}
      UI_method_get_prompt_constructor := @FC_UI_method_get_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_prompt_constructor_removed)}
    if UI_method_get_prompt_constructor_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_prompt_constructor)}
      UI_method_get_prompt_constructor := @_UI_method_get_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_prompt_constructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_prompt_constructor');
    {$ifend}
  end;


  UI_method_get_data_duplicator := LoadLibFunction(ADllHandle, UI_method_get_data_duplicator_procname);
  FuncLoadError := not assigned(UI_method_get_data_duplicator);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_data_duplicator_allownil)}
    UI_method_get_data_duplicator := @ERR_UI_method_get_data_duplicator;
    {$ifend}
    {$if declared(UI_method_get_data_duplicator_introduced)}
    if LibVersion < UI_method_get_data_duplicator_introduced then
    begin
      {$if declared(FC_UI_method_get_data_duplicator)}
      UI_method_get_data_duplicator := @FC_UI_method_get_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_data_duplicator_removed)}
    if UI_method_get_data_duplicator_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_data_duplicator)}
      UI_method_get_data_duplicator := @_UI_method_get_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_data_duplicator_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_data_duplicator');
    {$ifend}
  end;


  UI_method_get_data_destructor := LoadLibFunction(ADllHandle, UI_method_get_data_destructor_procname);
  FuncLoadError := not assigned(UI_method_get_data_destructor);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_data_destructor_allownil)}
    UI_method_get_data_destructor := @ERR_UI_method_get_data_destructor;
    {$ifend}
    {$if declared(UI_method_get_data_destructor_introduced)}
    if LibVersion < UI_method_get_data_destructor_introduced then
    begin
      {$if declared(FC_UI_method_get_data_destructor)}
      UI_method_get_data_destructor := @FC_UI_method_get_data_destructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_data_destructor_removed)}
    if UI_method_get_data_destructor_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_data_destructor)}
      UI_method_get_data_destructor := @_UI_method_get_data_destructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_data_destructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_data_destructor');
    {$ifend}
  end;


  UI_method_get_ex_data := LoadLibFunction(ADllHandle, UI_method_get_ex_data_procname);
  FuncLoadError := not assigned(UI_method_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_ex_data_allownil)}
    UI_method_get_ex_data := @ERR_UI_method_get_ex_data;
    {$ifend}
    {$if declared(UI_method_get_ex_data_introduced)}
    if LibVersion < UI_method_get_ex_data_introduced then
    begin
      {$if declared(FC_UI_method_get_ex_data)}
      UI_method_get_ex_data := @FC_UI_method_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_ex_data_removed)}
    if UI_method_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_ex_data)}
      UI_method_get_ex_data := @_UI_method_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_ex_data');
    {$ifend}
  end;


  UI_get_string_type := LoadLibFunction(ADllHandle, UI_get_string_type_procname);
  FuncLoadError := not assigned(UI_get_string_type);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_string_type_allownil)}
    UI_get_string_type := @ERR_UI_get_string_type;
    {$ifend}
    {$if declared(UI_get_string_type_introduced)}
    if LibVersion < UI_get_string_type_introduced then
    begin
      {$if declared(FC_UI_get_string_type)}
      UI_get_string_type := @FC_UI_get_string_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_string_type_removed)}
    if UI_get_string_type_removed <= LibVersion then
    begin
      {$if declared(_UI_get_string_type)}
      UI_get_string_type := @_UI_get_string_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_string_type_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_string_type');
    {$ifend}
  end;


  UI_get_input_flags := LoadLibFunction(ADllHandle, UI_get_input_flags_procname);
  FuncLoadError := not assigned(UI_get_input_flags);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_input_flags_allownil)}
    UI_get_input_flags := @ERR_UI_get_input_flags;
    {$ifend}
    {$if declared(UI_get_input_flags_introduced)}
    if LibVersion < UI_get_input_flags_introduced then
    begin
      {$if declared(FC_UI_get_input_flags)}
      UI_get_input_flags := @FC_UI_get_input_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_input_flags_removed)}
    if UI_get_input_flags_removed <= LibVersion then
    begin
      {$if declared(_UI_get_input_flags)}
      UI_get_input_flags := @_UI_get_input_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_input_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_input_flags');
    {$ifend}
  end;


  UI_get0_output_string := LoadLibFunction(ADllHandle, UI_get0_output_string_procname);
  FuncLoadError := not assigned(UI_get0_output_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_output_string_allownil)}
    UI_get0_output_string := @ERR_UI_get0_output_string;
    {$ifend}
    {$if declared(UI_get0_output_string_introduced)}
    if LibVersion < UI_get0_output_string_introduced then
    begin
      {$if declared(FC_UI_get0_output_string)}
      UI_get0_output_string := @FC_UI_get0_output_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_output_string_removed)}
    if UI_get0_output_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_output_string)}
      UI_get0_output_string := @_UI_get0_output_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_output_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_output_string');
    {$ifend}
  end;


  UI_get0_action_string := LoadLibFunction(ADllHandle, UI_get0_action_string_procname);
  FuncLoadError := not assigned(UI_get0_action_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_action_string_allownil)}
    UI_get0_action_string := @ERR_UI_get0_action_string;
    {$ifend}
    {$if declared(UI_get0_action_string_introduced)}
    if LibVersion < UI_get0_action_string_introduced then
    begin
      {$if declared(FC_UI_get0_action_string)}
      UI_get0_action_string := @FC_UI_get0_action_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_action_string_removed)}
    if UI_get0_action_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_action_string)}
      UI_get0_action_string := @_UI_get0_action_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_action_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_action_string');
    {$ifend}
  end;


  UI_get0_result_string := LoadLibFunction(ADllHandle, UI_get0_result_string_procname);
  FuncLoadError := not assigned(UI_get0_result_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_result_string_allownil)}
    UI_get0_result_string := @ERR_UI_get0_result_string;
    {$ifend}
    {$if declared(UI_get0_result_string_introduced)}
    if LibVersion < UI_get0_result_string_introduced then
    begin
      {$if declared(FC_UI_get0_result_string)}
      UI_get0_result_string := @FC_UI_get0_result_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_result_string_removed)}
    if UI_get0_result_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_result_string)}
      UI_get0_result_string := @_UI_get0_result_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_result_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_result_string');
    {$ifend}
  end;


  UI_get_result_string_length := LoadLibFunction(ADllHandle, UI_get_result_string_length_procname);
  FuncLoadError := not assigned(UI_get_result_string_length);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_string_length_allownil)}
    UI_get_result_string_length := @ERR_UI_get_result_string_length;
    {$ifend}
    {$if declared(UI_get_result_string_length_introduced)}
    if LibVersion < UI_get_result_string_length_introduced then
    begin
      {$if declared(FC_UI_get_result_string_length)}
      UI_get_result_string_length := @FC_UI_get_result_string_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_string_length_removed)}
    if UI_get_result_string_length_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_string_length)}
      UI_get_result_string_length := @_UI_get_result_string_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_string_length_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_string_length');
    {$ifend}
  end;


  UI_get0_test_string := LoadLibFunction(ADllHandle, UI_get0_test_string_procname);
  FuncLoadError := not assigned(UI_get0_test_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_test_string_allownil)}
    UI_get0_test_string := @ERR_UI_get0_test_string;
    {$ifend}
    {$if declared(UI_get0_test_string_introduced)}
    if LibVersion < UI_get0_test_string_introduced then
    begin
      {$if declared(FC_UI_get0_test_string)}
      UI_get0_test_string := @FC_UI_get0_test_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_test_string_removed)}
    if UI_get0_test_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_test_string)}
      UI_get0_test_string := @_UI_get0_test_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_test_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_test_string');
    {$ifend}
  end;


  UI_get_result_minsize := LoadLibFunction(ADllHandle, UI_get_result_minsize_procname);
  FuncLoadError := not assigned(UI_get_result_minsize);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_minsize_allownil)}
    UI_get_result_minsize := @ERR_UI_get_result_minsize;
    {$ifend}
    {$if declared(UI_get_result_minsize_introduced)}
    if LibVersion < UI_get_result_minsize_introduced then
    begin
      {$if declared(FC_UI_get_result_minsize)}
      UI_get_result_minsize := @FC_UI_get_result_minsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_minsize_removed)}
    if UI_get_result_minsize_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_minsize)}
      UI_get_result_minsize := @_UI_get_result_minsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_minsize_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_minsize');
    {$ifend}
  end;


  UI_get_result_maxsize := LoadLibFunction(ADllHandle, UI_get_result_maxsize_procname);
  FuncLoadError := not assigned(UI_get_result_maxsize);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_maxsize_allownil)}
    UI_get_result_maxsize := @ERR_UI_get_result_maxsize;
    {$ifend}
    {$if declared(UI_get_result_maxsize_introduced)}
    if LibVersion < UI_get_result_maxsize_introduced then
    begin
      {$if declared(FC_UI_get_result_maxsize)}
      UI_get_result_maxsize := @FC_UI_get_result_maxsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_maxsize_removed)}
    if UI_get_result_maxsize_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_maxsize)}
      UI_get_result_maxsize := @_UI_get_result_maxsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_maxsize_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_maxsize');
    {$ifend}
  end;


  UI_set_result := LoadLibFunction(ADllHandle, UI_set_result_procname);
  FuncLoadError := not assigned(UI_set_result);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_result_allownil)}
//    UI_set_result := @ERR_UI_set_result;
    {$ifend}
    {$if declared(UI_set_result_introduced)}
    if LibVersion < UI_set_result_introduced then
    begin
      {$if declared(FC_UI_set_result)}
      UI_set_result := @FC_UI_set_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_result_removed)}
    if UI_set_result_removed <= LibVersion then
    begin
      {$if declared(_UI_set_result)}
      UI_set_result := @_UI_set_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_result_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_result');
    {$ifend}
  end;


  UI_set_result_ex := LoadLibFunction(ADllHandle, UI_set_result_ex_procname);
  FuncLoadError := not assigned(UI_set_result_ex);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_result_ex_allownil)}
//    UI_set_result_ex := @ERR_UI_set_result_ex;
    {$ifend}
    {$if declared(UI_set_result_ex_introduced)}
    if LibVersion < UI_set_result_ex_introduced then
    begin
      {$if declared(FC_UI_set_result_ex)}
      UI_set_result_ex := @FC_UI_set_result_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_result_ex_removed)}
    if UI_set_result_ex_removed <= LibVersion then
    begin
      {$if declared(_UI_set_result_ex)}
      UI_set_result_ex := @_UI_set_result_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_result_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_result_ex');
    {$ifend}
  end;


  UI_UTIL_read_pw_string := LoadLibFunction(ADllHandle, UI_UTIL_read_pw_string_procname);
  FuncLoadError := not assigned(UI_UTIL_read_pw_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_UTIL_read_pw_string_allownil)}
    UI_UTIL_read_pw_string := @ERR_UI_UTIL_read_pw_string;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_string_introduced)}
    if LibVersion < UI_UTIL_read_pw_string_introduced then
    begin
      {$if declared(FC_UI_UTIL_read_pw_string)}
      UI_UTIL_read_pw_string := @FC_UI_UTIL_read_pw_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_string_removed)}
    if UI_UTIL_read_pw_string_removed <= LibVersion then
    begin
      {$if declared(_UI_UTIL_read_pw_string)}
      UI_UTIL_read_pw_string := @_UI_UTIL_read_pw_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_UTIL_read_pw_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_read_pw_string');
    {$ifend}
  end;


  UI_UTIL_read_pw := LoadLibFunction(ADllHandle, UI_UTIL_read_pw_procname);
  FuncLoadError := not assigned(UI_UTIL_read_pw);
  if FuncLoadError then
  begin
    {$if not defined(UI_UTIL_read_pw_allownil)}
    UI_UTIL_read_pw := @ERR_UI_UTIL_read_pw;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_introduced)}
    if LibVersion < UI_UTIL_read_pw_introduced then
    begin
      {$if declared(FC_UI_UTIL_read_pw)}
      UI_UTIL_read_pw := @FC_UI_UTIL_read_pw;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_removed)}
    if UI_UTIL_read_pw_removed <= LibVersion then
    begin
      {$if declared(_UI_UTIL_read_pw)}
      UI_UTIL_read_pw := @_UI_UTIL_read_pw;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_UTIL_read_pw_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_read_pw');
    {$ifend}
  end;


  UI_UTIL_wrap_read_pem_callback := LoadLibFunction(ADllHandle, UI_UTIL_wrap_read_pem_callback_procname);
  FuncLoadError := not assigned(UI_UTIL_wrap_read_pem_callback);
  if FuncLoadError then
  begin
    {$if not defined(UI_UTIL_wrap_read_pem_callback_allownil)}
    UI_UTIL_wrap_read_pem_callback := @ERR_UI_UTIL_wrap_read_pem_callback;
    {$ifend}
    {$if declared(UI_UTIL_wrap_read_pem_callback_introduced)}
    if LibVersion < UI_UTIL_wrap_read_pem_callback_introduced then
    begin
      {$if declared(FC_UI_UTIL_wrap_read_pem_callback)}
      UI_UTIL_wrap_read_pem_callback := @FC_UI_UTIL_wrap_read_pem_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_UTIL_wrap_read_pem_callback_removed)}
    if UI_UTIL_wrap_read_pem_callback_removed <= LibVersion then
    begin
      {$if declared(_UI_UTIL_wrap_read_pem_callback)}
      UI_UTIL_wrap_read_pem_callback := @_UI_UTIL_wrap_read_pem_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_UTIL_wrap_read_pem_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_wrap_read_pem_callback');
    {$ifend}
  end;


end;

procedure Unload;
begin
  UI_new := nil;
  UI_new_method := nil;
  UI_free := nil;
  UI_add_input_string := nil;
  UI_dup_input_string := nil;
  UI_add_verify_string := nil;
  UI_dup_verify_string := nil;
  UI_add_input_boolean := nil;
  UI_dup_input_boolean := nil;
  UI_add_info_string := nil;
  UI_dup_info_string := nil;
  UI_add_error_string := nil;
  UI_dup_error_string := nil;
  UI_construct_prompt := nil;
  UI_add_user_data := nil;
  UI_dup_user_data := nil;
  UI_get0_user_data := nil;
  UI_get0_result := nil;
  UI_get_result_length := nil;
  UI_process := nil;
  UI_ctrl := nil;
  UI_set_ex_data := nil;
  UI_get_ex_data := nil;
  UI_set_default_method := nil;
  UI_get_default_method := nil;
  UI_get_method := nil;
  UI_set_method := nil;
  UI_OpenSSL := nil;
  UI_null := nil;
  UI_create_method := nil;
  UI_destroy_method := nil;
  UI_method_set_opener := nil;
  UI_method_set_writer := nil;
  UI_method_set_flusher := nil;
  UI_method_set_reader := nil;
  UI_method_set_closer := nil;
  UI_method_set_data_duplicator := nil;
  UI_method_set_prompt_constructor := nil;
  UI_method_set_ex_data := nil;
  UI_method_get_opener := nil;
  UI_method_get_writer := nil;
  UI_method_get_flusher := nil;
  UI_method_get_reader := nil;
  UI_method_get_closer := nil;
  UI_method_get_prompt_constructor := nil;
  UI_method_get_data_duplicator := nil;
  UI_method_get_data_destructor := nil;
  UI_method_get_ex_data := nil;
  UI_get_string_type := nil;
  UI_get_input_flags := nil;
  UI_get0_output_string := nil;
  UI_get0_action_string := nil;
  UI_get0_result_string := nil;
  UI_get_result_string_length := nil;
  UI_get0_test_string := nil;
  UI_get_result_minsize := nil;
  UI_get_result_maxsize := nil;
  UI_set_result := nil;
  UI_set_result_ex := nil;
  UI_UTIL_read_pw_string := nil;
  UI_UTIL_read_pw := nil;
  UI_UTIL_wrap_read_pem_callback := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF USE_EXTERNAL_LIBRARY}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.

