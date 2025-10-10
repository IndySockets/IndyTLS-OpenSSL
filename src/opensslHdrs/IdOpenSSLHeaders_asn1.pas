(* This unit was generated from the source file asn1.h2pas 
It should not be modified directly. All changes should be made to asn1.h2pas
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


unit IdOpenSSLHeaders_asn1;


interface

// Headers for OpenSSL 1.1.1
// asn1.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_asn1t,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_ossl_typ;

{$MINENUMSIZE 4}

const
  (*
   * NB the constants below are used internally by ASN1_INTEGER
   * and ASN1_ENUMERATED to indicate the sign. They are *not* on
   * the wire tag values.
   *)

  V_ASN1_NEG = $100;
  V_ASN1_NEG_INTEGER = 2 or V_ASN1_NEG;
  V_ASN1_NEG_ENUMERATED = 10 or V_ASN1_NEG;

  (* For use with d2i_ASN1_type_bytes() *)
  B_ASN1_NUMERICSTRING = $0001;
  B_ASN1_PRINTABLESTRING = $0002;
  B_ASN1_T61STRING = $0004;
  B_ASN1_TELETEXSTRING = $0004;
  B_ASN1_VIDEOTEXSTRING = $0008;
  B_ASN1_IA5STRING = $0010;
  B_ASN1_GRAPHICSTRING = $0020;
  B_ASN1_ISO64STRING = $0040;
  B_ASN1_VISIBLESTRING = $0040;
  B_ASN1_GENERALSTRING = $0080;
  B_ASN1_UNIVERSALSTRING = $0100;
  B_ASN1_OCTET_STRING = $0200;
  B_ASN1_BIT_STRING = $0400;
  B_ASN1_BMPSTRING = $0800;
  B_ASN1_UNKNOWN = $1000;
  B_ASN1_UTF8STRING = $2000;
  B_ASN1_UTCTIME = $4000;
  B_ASN1_GENERALIZEDTIME = $8000;
  B_ASN1_SEQUENCE = $10000;
 (* For use with ASN1_mbstring_copy() *)
  MBSTRING_FLAG = $1000;
  MBSTRING_UTF8 = MBSTRING_FLAG;
  MBSTRING_ASC = MBSTRING_FLAG or 1;
  MBSTRING_BMP = MBSTRING_FLAG or 2;
  MBSTRING_UNIV = MBSTRING_FLAG or 4;
  SMIME_OLDMIME = $400;
  SMIME_CRLFEOL = $800;
  SMIME_STREAM = $1000;

//    struct X509_algor_st;
//DEFINE_STACK_OF(X509_ALGOR)

  ASN1_STRING_FLAG_BITS_LEFT = $08;   (* Set if $07 has bits left value *)
  (*
   * This indicates that the ASN1_STRING is not a real value but just a place
   * holder for the location where indefinite length constructed data should be
   * inserted in the memory buffer
   *)
  ASN1_STRING_FLAG_NDEF = $010;

  (*
   * This flag is used by the CMS code to indicate that a string is not
   * complete and is a place holder for content when it had all been accessed.
   * The flag will be reset when content has been written to it.
   *)

  ASN1_STRING_FLAG_CONT = $020;
  (*
   * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
   * type.
   *)
  ASN1_STRING_FLAG_MSTRING = $040;
  (* String is embedded and only content should be freed *)
  ASN1_STRING_FLAG_EMBED = $080;
  (* String should be parsed in RFC 5280's time format *)
  ASN1_STRING_FLAG_X509_TIME = $100;

  (* Used with ASN1 LONG type: if a long is set to this it is omitted *)
  ASN1_LONG_UNDEF = TOpenSSL_C_LONG($7fffffff);

  STABLE_FLAGS_MALLOC = $01;
  (*
   * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
   * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
   * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
   * STABLE_FLAGS_CLEAR to reflect this.
   *)
  STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;
  STABLE_NO_MASK = $02;
  DIRSTRING_TYPE = B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;
  PKCS9STRING_TYPE = DIRSTRING_TYPE or B_ASN1_IA5STRING;

  (* size limits: this stuff is taken straight from RFC2459 *)
  ub_name = 32768;
  ub_common_name = 64;
  ub_locality_name = 128;
  ub_state_name = 128;
  ub_organization_name = 64;
  ub_organization_unit_name = 64;
  ub_title = 64;
  ub_email_address = 128;

  (* Parameters used by ASN1_STRING_print_ex() *)

  (*
   * These determine which characters to escape: RFC2253 special characters,
   * control characters and MSB set characters
   *)
  ASN1_STRFLGS_ESC_2253 = 1;
  ASN1_STRFLGS_ESC_CTRL = 2;
  ASN1_STRFLGS_ESC_MSB = 4;

  (*
   * This flag determines how we do escaping: normally RC2253 backslash only,
   * set this to use backslash and quote.
   *)

  ASN1_STRFLGS_ESC_QUOTE = 8;

  (* These three flags are internal use only. *)

  (* Character is a valid PrintableString character *)
  CHARTYPE_PRINTABLESTRING = $10;
  (* Character needs escaping if it is the first character *)
  CHARTYPE_FIRST_ESC_2253 = $20;
  (* Character needs escaping if it is the last character *)
  CHARTYPE_LAST_ESC_2253 = $40;

  (*
   * NB the internal flags are safely reused below by flags handled at the top
   * level.
   *)

  (*
   * If this is set we convert all character strings to UTF8 first
   *)

  ASN1_STRFLGS_UTF8_CONVERT = $10;

  (*
   * If this is set we don't attempt to interpret content: just assume all
   * strings are 1 byte per character. This will produce some pretty odd
   * looking output!
   *)

  ASN1_STRFLGS_IGNORE_TYPE = $20;

  (* If this is set we include the string type in the output *)
  ASN1_STRFLGS_SHOW_TYPE = $40;

  (*
   * This determines which strings to display and which to 'dump' (hex dump of
   * content octets or DER encoding). We can only dump non character strings or
   * everything. If we don't dump 'unknown' they are interpreted as character
   * strings with 1 octet per character and are subject to the usual escaping
   * options.
   *)

  ASN1_STRFLGS_DUMP_ALL = $80;
  ASN1_STRFLGS_DUMP_UNKNOWN = $100;

  (*
   * These determine what 'dumping' does, we can dump the content octets or the
   * DER encoding: both use the RFC2253 #XXXXX notation.
   *)

  ASN1_STRFLGS_DUMP_DER = $200;

  (*
   * This flag specifies that RC2254 escaping shall be performed.
   *)

  ASN1_STRFLGS_ESC_2254 = $400;

  (*
   * All the string flags consistent with RFC2253, escaping control characters
   * isn't essential in RFC2253 but it is advisable anyway.
   *)

  ASN1_STRFLGS_RFC2253 = ASN1_STRFLGS_ESC_2253 or ASN1_STRFLGS_ESC_CTRL or
    ASN1_STRFLGS_ESC_MSB or ASN1_STRFLGS_UTF8_CONVERT or
    ASN1_STRFLGS_DUMP_UNKNOWN or ASN1_STRFLGS_DUMP_DER;

  B_ASN1_TIME = B_ASN1_UTCTIME or B_ASN1_GENERALIZEDTIME;

  B_ASN1_PRINTABLE = B_ASN1_NUMERICSTRING or B_ASN1_PRINTABLESTRING or
    B_ASN1_T61STRING or B_ASN1_IA5STRING or B_ASN1_BIT_STRING or
    B_ASN1_UNIVERSALSTRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING or
    B_ASN1_SEQUENCE or B_ASN1_UNKNOWN;

  B_ASN1_DIRECTORYSTRING = B_ASN1_PRINTABLESTRING or B_ASN1_TELETEXSTRING or
    B_ASN1_BMPSTRING or B_ASN1_UNIVERSALSTRING or B_ASN1_UTF8STRING;

  B_ASN1_DISPLAYTEXT = B_ASN1_IA5STRING or B_ASN1_VISIBLESTRING or
    B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;

  (* ASN1 Print flags *)
  (* Indicate missing OPTIONAL fields *)
  ASN1_PCTX_FLAGS_SHOW_ABSENT = $001;
  (* Mark start and end of SEQUENCE *)
  ASN1_PCTX_FLAGS_SHOW_SEQUENCE = $002;
  (* Mark start and end of SEQUENCE/SET OF *)
  ASN1_PCTX_FLAGS_SHOW_SSOF = $004;
  (* Show the ASN1 type of primitives *)
  ASN1_PCTX_FLAGS_SHOW_TYPE = $008;
  (* Don't show ASN1 type of ANY *)
  ASN1_PCTX_FLAGS_NO_ANY_TYPE = $010;
  (* Don't show ASN1 type of MSTRINGs *)
  ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = $020;
  (* Don't show field names in SEQUENCE *)
  ASN1_PCTX_FLAGS_NO_FIELD_NAME = $040;
  (* Show structure names of each SEQUENCE field *)
  ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;
  (* Don't show structure name even at top level *)
  ASN1_PCTX_FLAGS_NO_STRUCT_NAME = $100;

type
// Moved to ossl_type to prevent circular references
///(* This is the base type that holds just about everything :-) *)
//  asn1_string_st = record
//    length: TOpenSSL_C_int;
//    type_: TOpenSSL_C_int;
//    data: PByte;
//    (*
//     * The value of the following field depends on the type being held.  It
//     * is mostly being used for BIT_STRING so if the input data has a
//     * non-zero 'unused bits' value, it will be handled correctly
//     *)
//    flags: TOpenSSL_C_long;
//  end;

  pxnew = function: Pointer; cdecl;

  (*
   * ASN1_ENCODING structure: this is used to save the received encoding of an
   * ASN1 type. This is useful to get round problems with invalid encodings
   * which can break signatures.
   *)

  ASN1_ENCODING_st = record
    enc: PAnsiChar;           (* DER encoding *)
    len: TOpenSSL_C_LONG;                     (* Length of encoding *)
    modified: TOpenSSL_C_INT;                 (* set to 1 if 'enc' is invalid *)
  end;
  ASN1_ENCODING = ASN1_ENCODING_st;

  asn1_string_table_st = record
    nid: TOpenSSL_C_INT;
    minsize: TOpenSSL_C_LONG;
    maxsize: TOpenSSL_C_LONG;
    mask: TOpenSSL_C_ULONG;
    flags: TOpenSSL_C_ULONG;
  end;
  ASN1_STRING_TABLE = asn1_string_table_st;
  PASN1_STRING_TABLE = ^ASN1_STRING_TABLE;

// DEFINE_STACK_OF(ASN1_STRING_TABLE)

  (*                  !!!
   * Declarations for template structures: for full definitions see asn1t.h
   *)
  (* This is just an opaque pointer *)
// typedef struct ASN1_VALUE_st ASN1_VALUE;

  (* Declare ASN1 functions: the implement macro in in asn1t.h *)

//# define DECLARE_ASN1_FUNCTIONS(type) DECLARE_ASN1_FUNCTIONS_name(type, type)
//
//# define DECLARE_ASN1_ALLOC_FUNCTIONS(type) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)
//
//# define DECLARE_ASN1_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)
//
//# define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)
//
//# define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) \
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(type *a, unsigned char **out); \
//        DECLARE_ASN1_ITEM(itname)
//
//# define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(const type *a, unsigned char **out); \
//        DECLARE_ASN1_ITEM(name)
//
//# define DECLARE_ASN1_NDEF_FUNCTION(name) \
//        int i2d_##name##_NDEF(name *a, unsigned char **out);
//
//# define DECLARE_ASN1_FUNCTIONS_const(name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)
//
//# define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        type *name##_new(void); \
//        void name##_free(type *a);
//
//# define DECLARE_ASN1_PRINT_FUNCTION(stname) \
//        DECLARE_ASN1_PRINT_FUNCTION_fname(stname, stname)
//
//# define DECLARE_ASN1_PRINT_FUNCTION_fname(stname, fname) \
//        int fname##_print_ctx(BIO *out, stname *x, int indent, \
//                                         const ASN1_PCTX *pctx);
//
//# define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
//# define I2D_OF(type) int (*)(type *,unsigned char **)
//# define I2D_OF_const(type) int (*)(const type *,unsigned char **)
//
//# define CHECKED_D2I_OF(type, d2i) \
//    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
//# define CHECKED_I2D_OF(type, i2d) \
//    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
//# define CHECKED_NEW_OF(type, xnew) \
//    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
//# define CHECKED_PTR_OF(type, p) \
//    ((void*) (1 ? p : (type*)0))
//# define CHECKED_PPTR_OF(type, p) \
//    ((void**) (1 ? p : (type**)0))
//
//# define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
//# define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
//# define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)
//
//TYPEDEF_D2I2D_OF(void);

  (*-
   * The following macros and typedefs allow an ASN1_ITEM
   * to be embedded in a structure and referenced. Since
   * the ASN1_ITEM pointers need to be globally accessible
   * (possibly from shared libraries) they may exist in
   * different forms. On platforms that support it the
   * ASN1_ITEM structure itself will be globally exported.
   * Other platforms will export a function that returns
   * an ASN1_ITEM pointer.
   *
   * To handle both cases transparently the macros below
   * should be used instead of hard coding an ASN1_ITEM
   * pointer in a structure.
   *
   * The structure will look like this:
   *
   * typedef struct SOMETHING_st {
   *      ...
   *      ASN1_ITEM_EXP *iptr;
   *      ...
   * } SOMETHING;
   *
   * It would be initialised as e.g.:
   *
   * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
   *
   * and the actual pointer extracted with:
   *
   * const ASN1_ITEM *it = ASN1_ITEM_ptr(somevar.iptr);
   *
   * Finally an ASN1_ITEM pointer can be extracted from an
   * appropriate reference with: ASN1_ITEM_rptr(X509). This
   * would be used when a function takes an ASN1_ITEM * argument.
   *
   *)

// # ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

///(* ASN1_ITEM pointer exported type *)
//typedef const ASN1_ITEM ASN1_ITEM_EXP;
//
///(* Macro to obtain ASN1_ITEM pointer from exported type *)
//#  define ASN1_ITEM_ptr(iptr) (iptr)
//
// (* Macro to include ASN1_ITEM pointer from base type *)
//#  define ASN1_ITEM_ref(iptr) (&(iptr##_it))
//
//#  define ASN1_ITEM_rptr(ref) (&(ref##_it))
//
//#  define DECLARE_ASN1_ITEM(name) \
//        OPENSSL_EXTERN const ASN1_ITEM name##_it;
//
//# else

// (*
// * Platforms that can't easily handle shared global variables are declared as
// * functions returning ASN1_ITEM pointers.
// *)

///(* ASN1_ITEM pointer exported type *)
//typedef const ASN1_ITEM *ASN1_ITEM_EXP (void);
//
///(* Macro to obtain ASN1_ITEM pointer from exported type *)
//#  define ASN1_ITEM_ptr(iptr) (iptr())
//
///(* Macro to include ASN1_ITEM pointer from base type *)
//#  define ASN1_ITEM_ref(iptr) (iptr##_it)
//
//#  define ASN1_ITEM_rptr(ref) (ref##_it())
//
//#  define DECLARE_ASN1_ITEM(name) \
//        const ASN1_ITEM * name##_it(void);
//
//# endif

//DEFINE_STACK_OF(ASN1_INTEGER)
//
//DEFINE_STACK_OF(ASN1_GENERALSTRING)
//
//DEFINE_STACK_OF(ASN1_UTF8STRING)

//DEFINE_STACK_OF(ASN1_TYPE)
//
//typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
//
//DECLARE_ASN1_ENCODE_FUNCTIONS_const(ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY)
//DECLARE_ASN1_ENCODE_FUNCTIONS_const(ASN1_SEQUENCE_ANY, ASN1_SET_ANY)

  (* This is used to contain a list of bit names *)

  BIT_STRING_BITNAME_st = record
    bitnum: TOpenSSL_C_INT;
    lname: PAnsiChar;
    sname: PAnsiChar;
  end;
  BIT_STRING_BITNAME = BIT_STRING_BITNAME_st;
  PBIT_STRING_BITNAME = ^BIT_STRING_BITNAME;

//DECLARE_ASN1_FUNCTIONS(type) -->
//        type *name##_new(void); \
//        void name##_free(type *a);
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(type *a, unsigned char **out); \
//#  define DECLARE_ASN1_ITEM(name) \
//        OPENSSL_EXTERN const ASN1_ITEM name##_it;

// DECLARE_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ASN1_TYPE_get}
{$EXTERNALSYM ASN1_TYPE_set}
{$EXTERNALSYM ASN1_TYPE_set1}
{$EXTERNALSYM ASN1_TYPE_cmp}
{$EXTERNALSYM ASN1_TYPE_pack_sequence}
{$EXTERNALSYM ASN1_TYPE_unpack_sequence}
{$EXTERNALSYM ASN1_OBJECT_new}
{$EXTERNALSYM ASN1_OBJECT_free}
{$EXTERNALSYM i2d_ASN1_OBJECT}
{$EXTERNALSYM d2i_ASN1_OBJECT}
{$EXTERNALSYM ASN1_STRING_new}
{$EXTERNALSYM ASN1_STRING_free}
{$EXTERNALSYM ASN1_STRING_clear_free}
{$EXTERNALSYM ASN1_STRING_copy}
{$EXTERNALSYM ASN1_STRING_dup}
{$EXTERNALSYM ASN1_STRING_type_new}
{$EXTERNALSYM ASN1_STRING_cmp}
{$EXTERNALSYM ASN1_STRING_set}
{$EXTERNALSYM ASN1_STRING_set0}
{$EXTERNALSYM ASN1_STRING_length}
{$EXTERNALSYM ASN1_STRING_length_set}
{$EXTERNALSYM ASN1_STRING_type}
{$EXTERNALSYM ASN1_STRING_get0_data}
{$EXTERNALSYM ASN1_BIT_STRING_set}
{$EXTERNALSYM ASN1_BIT_STRING_set_bit}
{$EXTERNALSYM ASN1_BIT_STRING_get_bit}
{$EXTERNALSYM ASN1_BIT_STRING_check}
{$EXTERNALSYM ASN1_BIT_STRING_name_print}
{$EXTERNALSYM ASN1_BIT_STRING_num_asc}
{$EXTERNALSYM ASN1_BIT_STRING_set_asc}
{$EXTERNALSYM ASN1_INTEGER_new}
{$EXTERNALSYM ASN1_INTEGER_free}
{$EXTERNALSYM d2i_ASN1_INTEGER}
{$EXTERNALSYM i2d_ASN1_INTEGER}
{$EXTERNALSYM d2i_ASN1_UINTEGER}
{$EXTERNALSYM ASN1_INTEGER_dup}
{$EXTERNALSYM ASN1_INTEGER_cmp}
{$EXTERNALSYM ASN1_UTCTIME_check}
{$EXTERNALSYM ASN1_UTCTIME_set}
{$EXTERNALSYM ASN1_UTCTIME_adj}
{$EXTERNALSYM ASN1_UTCTIME_set_string}
{$EXTERNALSYM ASN1_UTCTIME_cmp_time_t}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_check}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_set}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_adj}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_set_string}
{$EXTERNALSYM ASN1_TIME_diff}
{$EXTERNALSYM ASN1_OCTET_STRING_dup}
{$EXTERNALSYM ASN1_OCTET_STRING_cmp}
{$EXTERNALSYM ASN1_OCTET_STRING_set}
{$EXTERNALSYM ASN1_OCTET_STRING_new}
{$EXTERNALSYM ASN1_OCTET_STRING_free}
{$EXTERNALSYM d2i_ASN1_OCTET_STRING}
{$EXTERNALSYM i2d_ASN1_OCTET_STRING}
{$EXTERNALSYM UTF8_getc}
{$EXTERNALSYM UTF8_putc}
{$EXTERNALSYM ASN1_UTCTIME_new}
{$EXTERNALSYM ASN1_UTCTIME_free}
{$EXTERNALSYM d2i_ASN1_UTCTIME}
{$EXTERNALSYM i2d_ASN1_UTCTIME}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_new}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_free}
{$EXTERNALSYM d2i_ASN1_GENERALIZEDTIME}
{$EXTERNALSYM i2d_ASN1_GENERALIZEDTIME}
{$EXTERNALSYM ASN1_TIME_new}
{$EXTERNALSYM ASN1_TIME_free}
{$EXTERNALSYM d2i_ASN1_TIME}
{$EXTERNALSYM i2d_ASN1_TIME}
{$EXTERNALSYM ASN1_TIME_set}
{$EXTERNALSYM ASN1_TIME_adj}
{$EXTERNALSYM ASN1_TIME_check}
{$EXTERNALSYM ASN1_TIME_to_generalizedtime}
{$EXTERNALSYM ASN1_TIME_set_string}
{$EXTERNALSYM ASN1_TIME_set_string_X509}
{$EXTERNALSYM ASN1_TIME_to_tm}
{$EXTERNALSYM ASN1_TIME_normalize}
{$EXTERNALSYM ASN1_TIME_cmp_time_t}
{$EXTERNALSYM ASN1_TIME_compare}
{$EXTERNALSYM i2a_ASN1_INTEGER}
{$EXTERNALSYM a2i_ASN1_INTEGER}
{$EXTERNALSYM i2a_ASN1_ENUMERATED}
{$EXTERNALSYM a2i_ASN1_ENUMERATED}
{$EXTERNALSYM i2a_ASN1_OBJECT}
{$EXTERNALSYM a2i_ASN1_STRING}
{$EXTERNALSYM i2a_ASN1_STRING}
{$EXTERNALSYM i2t_ASN1_OBJECT}
{$EXTERNALSYM a2d_ASN1_OBJECT}
{$EXTERNALSYM ASN1_OBJECT_create}
{$EXTERNALSYM ASN1_INTEGER_get_int64}
{$EXTERNALSYM ASN1_INTEGER_set_int64}
{$EXTERNALSYM ASN1_INTEGER_get_uint64}
{$EXTERNALSYM ASN1_INTEGER_set_uint64}
{$EXTERNALSYM ASN1_INTEGER_set}
{$EXTERNALSYM ASN1_INTEGER_get}
{$EXTERNALSYM BN_to_ASN1_INTEGER}
{$EXTERNALSYM ASN1_INTEGER_to_BN}
{$EXTERNALSYM ASN1_ENUMERATED_get_int64}
{$EXTERNALSYM ASN1_ENUMERATED_set_int64}
{$EXTERNALSYM ASN1_ENUMERATED_set}
{$EXTERNALSYM ASN1_ENUMERATED_get}
{$EXTERNALSYM BN_to_ASN1_ENUMERATED}
{$EXTERNALSYM ASN1_ENUMERATED_to_BN}
{$EXTERNALSYM ASN1_PRINTABLE_type}
{$EXTERNALSYM ASN1_tag2bit}
{$EXTERNALSYM ASN1_get_object}
{$EXTERNALSYM ASN1_check_infinite_end}
{$EXTERNALSYM ASN1_const_check_infinite_end}
{$EXTERNALSYM ASN1_put_object}
{$EXTERNALSYM ASN1_put_eoc}
{$EXTERNALSYM ASN1_object_size}
{$EXTERNALSYM ASN1_item_dup}
{$EXTERNALSYM ASN1_STRING_to_UTF8}
{$EXTERNALSYM ASN1_d2i_bio}
{$EXTERNALSYM ASN1_item_d2i_bio}
{$EXTERNALSYM ASN1_i2d_bio}
{$EXTERNALSYM ASN1_item_i2d_bio}
{$EXTERNALSYM ASN1_UTCTIME_print}
{$EXTERNALSYM ASN1_GENERALIZEDTIME_print}
{$EXTERNALSYM ASN1_TIME_print}
{$EXTERNALSYM ASN1_STRING_print}
{$EXTERNALSYM ASN1_STRING_print_ex}
{$EXTERNALSYM ASN1_buf_print}
{$EXTERNALSYM ASN1_bn_print}
{$EXTERNALSYM ASN1_parse}
{$EXTERNALSYM ASN1_parse_dump}
{$EXTERNALSYM ASN1_tag2str}
{$EXTERNALSYM ASN1_UNIVERSALSTRING_to_string}
{$EXTERNALSYM ASN1_TYPE_set_octetstring}
{$EXTERNALSYM ASN1_TYPE_get_octetstring}
{$EXTERNALSYM ASN1_TYPE_set_int_octetstring}
{$EXTERNALSYM ASN1_TYPE_get_int_octetstring}
{$EXTERNALSYM ASN1_item_unpack}
{$EXTERNALSYM ASN1_item_pack}
{$EXTERNALSYM ASN1_STRING_set_default_mask}
{$EXTERNALSYM ASN1_STRING_set_default_mask_asc}
{$EXTERNALSYM ASN1_STRING_get_default_mask}
{$EXTERNALSYM ASN1_mbstring_copy}
{$EXTERNALSYM ASN1_mbstring_ncopy}
{$EXTERNALSYM ASN1_STRING_set_by_NID}
{$EXTERNALSYM ASN1_STRING_TABLE_get}
{$EXTERNALSYM ASN1_STRING_TABLE_add}
{$EXTERNALSYM ASN1_STRING_TABLE_cleanup}
{$EXTERNALSYM ASN1_item_new}
{$EXTERNALSYM ASN1_item_free}
{$EXTERNALSYM ASN1_item_d2i}
{$EXTERNALSYM ASN1_item_i2d}
{$EXTERNALSYM ASN1_item_ndef_i2d}
{$EXTERNALSYM ASN1_add_oid_module}
{$EXTERNALSYM ASN1_add_stable_module}
{$EXTERNALSYM ASN1_generate_nconf}
{$EXTERNALSYM ASN1_generate_v3}
{$EXTERNALSYM ASN1_str2mask}
{$EXTERNALSYM ASN1_item_print}
{$EXTERNALSYM ASN1_PCTX_new}
{$EXTERNALSYM ASN1_PCTX_free}
{$EXTERNALSYM ASN1_PCTX_get_flags}
{$EXTERNALSYM ASN1_PCTX_set_flags}
{$EXTERNALSYM ASN1_PCTX_get_nm_flags}
{$EXTERNALSYM ASN1_PCTX_set_nm_flags}
{$EXTERNALSYM ASN1_PCTX_get_cert_flags}
{$EXTERNALSYM ASN1_PCTX_set_cert_flags}
{$EXTERNALSYM ASN1_PCTX_get_oid_flags}
{$EXTERNALSYM ASN1_PCTX_set_oid_flags}
{$EXTERNALSYM ASN1_PCTX_get_str_flags}
{$EXTERNALSYM ASN1_PCTX_set_str_flags}
{$EXTERNALSYM ASN1_SCTX_free}
{$EXTERNALSYM ASN1_SCTX_get_item}
{$EXTERNALSYM ASN1_SCTX_get_template}
{$EXTERNALSYM ASN1_SCTX_get_flags}
{$EXTERNALSYM ASN1_SCTX_set_app_data}
{$EXTERNALSYM ASN1_SCTX_get_app_data}
{$EXTERNALSYM BIO_f_asn1}
{$EXTERNALSYM BIO_new_NDEF}
{$EXTERNALSYM i2d_ASN1_bio_stream}
{$EXTERNALSYM PEM_write_bio_ASN1_stream}
{$EXTERNALSYM SMIME_read_ASN1}
{$EXTERNALSYM SMIME_crlf_copy}
{$EXTERNALSYM SMIME_text}
{$EXTERNALSYM ASN1_ITEM_lookup}
{$EXTERNALSYM ASN1_ITEM_get}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ASN1_TYPE_get(const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_TYPE_set(a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl; external CLibCrypto;
function ASN1_TYPE_set1(a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl; external CLibCrypto;
function ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl; external CLibCrypto;
function ASN1_OBJECT_new: PASN1_OBJECT; cdecl; external CLibCrypto;
procedure ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl; external CLibCrypto;
function i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl; external CLibCrypto;
function ASN1_STRING_new: PASN1_STRING; cdecl; external CLibCrypto;
procedure ASN1_STRING_free(a: PASN1_STRING); cdecl; external CLibCrypto;
procedure ASN1_STRING_clear_free(a: PASN1_STRING); cdecl; external CLibCrypto;
function ASN1_STRING_copy(dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING; cdecl; external CLibCrypto;
function ASN1_STRING_type_new(type_: TOpenSSL_C_INT): PASN1_STRING; cdecl; external CLibCrypto;
function ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_set(str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ASN1_STRING_length(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_STRING_length_set(x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ASN1_STRING_type(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_get0_data(const x: PASN1_STRING): PByte; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_num_asc(const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_new: PASN1_INTEGER; cdecl; external CLibCrypto;
procedure ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl; external CLibCrypto;
function d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl; external CLibCrypto;
function i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl; external CLibCrypto;
function d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl; external CLibCrypto;
function ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER; cdecl; external CLibCrypto;
function ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl; external CLibCrypto;
function ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl; external CLibCrypto;
function ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_diff(pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl; external CLibCrypto;
procedure ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl; external CLibCrypto;
function d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UTF8_getc(const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UTF8_putc(str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl; external CLibCrypto;
procedure ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl; external CLibCrypto;
function d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl; external CLibCrypto;
function i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
procedure ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl; external CLibCrypto;
function d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_new: PASN1_TIME; cdecl; external CLibCrypto;
procedure ASN1_TIME_free(a: PASN1_TIME); cdecl; external CLibCrypto;
function d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl; external CLibCrypto;
function i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_set(s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl; external CLibCrypto;
function ASN1_TIME_adj(s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl; external CLibCrypto;
function ASN1_TIME_check(const t: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_to_generalizedtime(const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function ASN1_TIME_set_string(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_set_string_X509(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_to_tm(const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_normalize(s: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2t_ASN1_OBJECT(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function a2d_ASN1_OBJECT(out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_OBJECT_create(nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl; external CLibCrypto;
function ASN1_INTEGER_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_get_uint64(pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_set(a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_INTEGER_get(const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl; external CLibCrypto;
function ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl; external CLibCrypto;
function ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function ASN1_PRINTABLE_type(const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_tag2bit(tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ASN1_get_object(const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_check_infinite_end(p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_const_check_infinite_end(const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_put_object(pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ASN1_put_eoc(pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_object_size(constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer; cdecl; external CLibCrypto;
function ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_d2i_bio(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl; external CLibCrypto;
function ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl; external CLibCrypto;
function ASN1_i2d_bio(i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_print_ex(out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_bn_print(bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_parse(bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_tag2str(tag: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl; external CLibCrypto;
function ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl; external CLibCrypto;
procedure ASN1_STRING_set_default_mask(mask: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_STRING_set_default_mask_asc(const p: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_get_default_mask: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl; external CLibCrypto;
function ASN1_STRING_TABLE_get(nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl; external CLibCrypto;
function ASN1_STRING_TABLE_add(v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_STRING_TABLE_cleanup; cdecl; external CLibCrypto;
function ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE; cdecl; external CLibCrypto;
procedure ASN1_item_free(val: PASN1_VALUE; const it: PASN1_ITEM); cdecl; external CLibCrypto;
function ASN1_item_d2i(val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl; external CLibCrypto;
function ASN1_item_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_ndef_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASN1_add_oid_module; cdecl; external CLibCrypto;
procedure ASN1_add_stable_module; cdecl; external CLibCrypto;
function ASN1_generate_nconf(const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl; external CLibCrypto;
function ASN1_generate_v3(const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl; external CLibCrypto;
function ASN1_str2mask(const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_PCTX_new: PASN1_PCTX; cdecl; external CLibCrypto;
procedure ASN1_PCTX_free(p: PASN1_PCTX); cdecl; external CLibCrypto;
function ASN1_PCTX_get_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
procedure ASN1_SCTX_free(p: PASN1_SCTX); cdecl; external CLibCrypto;
function ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl; external CLibCrypto;
function ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl; external CLibCrypto;
function ASN1_SCTX_get_flags(p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl; external CLibCrypto;
function ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl; external CLibCrypto;
function BIO_f_asn1: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_new_NDEF(out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl; external CLibCrypto;
function i2d_ASN1_bio_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_ASN1_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl; external CLibCrypto;
function SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_text(in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASN1_ITEM_lookup(const name: PAnsiChar): PASN1_ITEM; cdecl; external CLibCrypto;
function ASN1_ITEM_get(i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ASN1_TYPE_get(const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
procedure Load_ASN1_TYPE_set(a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl;
function Load_ASN1_TYPE_set1(a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl;
function Load_ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl;
function Load_ASN1_OBJECT_new: PASN1_OBJECT; cdecl;
procedure Load_ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl;
function Load_i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl;
function Load_ASN1_STRING_new: PASN1_STRING; cdecl;
procedure Load_ASN1_STRING_free(a: PASN1_STRING); cdecl;
procedure Load_ASN1_STRING_clear_free(a: PASN1_STRING); cdecl;
function Load_ASN1_STRING_copy(dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING; cdecl;
function Load_ASN1_STRING_type_new(type_: TOpenSSL_C_INT): PASN1_STRING; cdecl;
function Load_ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_set(str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl;
function Load_ASN1_STRING_length(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl;
procedure Load_ASN1_STRING_length_set(x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl;
function Load_ASN1_STRING_type(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_get0_data(const x: PASN1_STRING): PByte; cdecl;
function Load_ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_BIT_STRING_num_asc(const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_INTEGER_new: PASN1_INTEGER; cdecl;
procedure Load_ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl;
function Load_d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl;
function Load_i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl;
function Load_d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl;
function Load_ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER; cdecl;
function Load_ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl;
function Load_ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl;
function Load_ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
function Load_ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl;
function Load_ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl;
function Load_ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_diff(pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl;
function Load_ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl;
procedure Load_ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl;
function Load_d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl;
function Load_i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_UTF8_getc(const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_UTF8_putc(str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl;
procedure Load_ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl;
function Load_d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl;
function Load_i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl;
procedure Load_ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl;
function Load_d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl;
function Load_i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_new: PASN1_TIME; cdecl;
procedure Load_ASN1_TIME_free(a: PASN1_TIME); cdecl;
function Load_d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
function Load_i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_set(s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl;
function Load_ASN1_TIME_adj(s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
function Load_ASN1_TIME_check(const t: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_to_generalizedtime(const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl;
function Load_ASN1_TIME_set_string(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_set_string_X509(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_to_tm(const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_normalize(s: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl;
function Load_a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_i2t_ASN1_OBJECT(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_a2d_ASN1_OBJECT(out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_OBJECT_create(nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl;
function Load_ASN1_INTEGER_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl;
function Load_ASN1_INTEGER_get_uint64(pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl;
function Load_ASN1_INTEGER_set(a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_INTEGER_get(const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl;
function Load_BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl;
function Load_ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl;
function Load_ASN1_ENUMERATED_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl;
function Load_ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl;
function Load_ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl;
function Load_BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl;
function Load_ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl;
function Load_ASN1_PRINTABLE_type(const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_tag2bit(tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
function Load_ASN1_get_object(const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_check_infinite_end(p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_const_check_infinite_end(const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
procedure Load_ASN1_put_object(pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl;
function Load_ASN1_put_eoc(pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_ASN1_object_size(constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer; cdecl;
function Load_ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_d2i_bio(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl;
function Load_ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl;
function Load_ASN1_i2d_bio(i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl;
function Load_ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_print_ex(out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_bn_print(bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_parse(bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_tag2str(tag: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl;
function Load_ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl;
procedure Load_ASN1_STRING_set_default_mask(mask: TOpenSSL_C_ULONG); cdecl;
function Load_ASN1_STRING_set_default_mask_asc(const p: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_get_default_mask: TOpenSSL_C_ULONG; cdecl;
function Load_ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl;
function Load_ASN1_STRING_TABLE_get(nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl;
function Load_ASN1_STRING_TABLE_add(v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
procedure Load_ASN1_STRING_TABLE_cleanup; cdecl;
function Load_ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE; cdecl;
procedure Load_ASN1_item_free(val: PASN1_VALUE; const it: PASN1_ITEM); cdecl;
function Load_ASN1_item_d2i(val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
function Load_ASN1_item_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_ndef_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
procedure Load_ASN1_add_oid_module; cdecl;
procedure Load_ASN1_add_stable_module; cdecl;
function Load_ASN1_generate_nconf(const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl;
function Load_ASN1_generate_v3(const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl;
function Load_ASN1_str2mask(const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
function Load_ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
function Load_ASN1_PCTX_new: PASN1_PCTX; cdecl;
procedure Load_ASN1_PCTX_free(p: PASN1_PCTX); cdecl;
function Load_ASN1_PCTX_get_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
procedure Load_ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
function Load_ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
procedure Load_ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
function Load_ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
procedure Load_ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
function Load_ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
procedure Load_ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
function Load_ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
procedure Load_ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
procedure Load_ASN1_SCTX_free(p: PASN1_SCTX); cdecl;
function Load_ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl;
function Load_ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl;
function Load_ASN1_SCTX_get_flags(p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl;
procedure Load_ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl;
function Load_ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl;
function Load_BIO_f_asn1: PBIO_METHOD; cdecl;
function Load_BIO_new_NDEF(out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl;
function Load_i2d_ASN1_bio_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_ASN1_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
function Load_SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
function Load_SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SMIME_text(in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl;
function Load_ASN1_ITEM_lookup(const name: PAnsiChar): PASN1_ITEM; cdecl;
function Load_ASN1_ITEM_get(i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl;

var
  ASN1_TYPE_get: function (const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_get;
  ASN1_TYPE_set: procedure (a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl = Load_ASN1_TYPE_set;
  ASN1_TYPE_set1: function (a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_set1;
  ASN1_TYPE_cmp: function (const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_cmp;
  ASN1_TYPE_pack_sequence: function (const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl = Load_ASN1_TYPE_pack_sequence;
  ASN1_TYPE_unpack_sequence: function (const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl = Load_ASN1_TYPE_unpack_sequence;
  ASN1_OBJECT_new: function : PASN1_OBJECT; cdecl = Load_ASN1_OBJECT_new;
  ASN1_OBJECT_free: procedure (a: PASN1_OBJECT); cdecl = Load_ASN1_OBJECT_free;
  i2d_ASN1_OBJECT: function (const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ASN1_OBJECT;
  d2i_ASN1_OBJECT: function (a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl = Load_d2i_ASN1_OBJECT;
  ASN1_STRING_new: function : PASN1_STRING; cdecl = Load_ASN1_STRING_new;
  ASN1_STRING_free: procedure (a: PASN1_STRING); cdecl = Load_ASN1_STRING_free;
  ASN1_STRING_clear_free: procedure (a: PASN1_STRING); cdecl = Load_ASN1_STRING_clear_free;
  ASN1_STRING_copy: function (dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_copy;
  ASN1_STRING_dup: function (const a: PASN1_STRING): PASN1_STRING; cdecl = Load_ASN1_STRING_dup;
  ASN1_STRING_type_new: function (type_: TOpenSSL_C_INT): PASN1_STRING; cdecl = Load_ASN1_STRING_type_new;
  ASN1_STRING_cmp: function (const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_cmp;
  ASN1_STRING_set: function (str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_set;
  ASN1_STRING_set0: procedure (str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl = Load_ASN1_STRING_set0;
  ASN1_STRING_length: function (const x: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_length;
  ASN1_STRING_length_set: procedure (x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl = Load_ASN1_STRING_length_set;
  ASN1_STRING_type: function (const x: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_type;
  ASN1_STRING_get0_data: function (const x: PASN1_STRING): PByte; cdecl = Load_ASN1_STRING_get0_data;
  ASN1_BIT_STRING_set: function (a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_set;
  ASN1_BIT_STRING_set_bit: function (a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_set_bit;
  ASN1_BIT_STRING_get_bit: function (const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_get_bit;
  ASN1_BIT_STRING_check: function (const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_check;
  ASN1_BIT_STRING_name_print: function (out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_name_print;
  ASN1_BIT_STRING_num_asc: function (const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_num_asc;
  ASN1_BIT_STRING_set_asc: function (bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl = Load_ASN1_BIT_STRING_set_asc;
  ASN1_INTEGER_new: function : PASN1_INTEGER; cdecl = Load_ASN1_INTEGER_new;
  ASN1_INTEGER_free: procedure (a: PASN1_INTEGER); cdecl = Load_ASN1_INTEGER_free;
  d2i_ASN1_INTEGER: function (a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl = Load_d2i_ASN1_INTEGER;
  i2d_ASN1_INTEGER: function (a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl = Load_i2d_ASN1_INTEGER;
  d2i_ASN1_UINTEGER: function (a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl = Load_d2i_ASN1_UINTEGER;
  ASN1_INTEGER_dup: function (const x: PASN1_INTEGER): PASN1_INTEGER; cdecl = Load_ASN1_INTEGER_dup;
  ASN1_INTEGER_cmp: function (const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_ASN1_INTEGER_cmp;
  ASN1_UTCTIME_check: function (const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl = Load_ASN1_UTCTIME_check;
  ASN1_UTCTIME_set: function (s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl = Load_ASN1_UTCTIME_set;
  ASN1_UTCTIME_adj: function (s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl = Load_ASN1_UTCTIME_adj;
  ASN1_UTCTIME_set_string: function (s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ASN1_UTCTIME_set_string;
  ASN1_UTCTIME_cmp_time_t: function (const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_ASN1_UTCTIME_cmp_time_t;
  ASN1_GENERALIZEDTIME_check: function (const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = Load_ASN1_GENERALIZEDTIME_check;
  ASN1_GENERALIZEDTIME_set: function (s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl = Load_ASN1_GENERALIZEDTIME_set;
  ASN1_GENERALIZEDTIME_adj: function (s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl = Load_ASN1_GENERALIZEDTIME_adj;
  ASN1_GENERALIZEDTIME_set_string: function (s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ASN1_GENERALIZEDTIME_set_string;
  ASN1_TIME_diff: function (pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_diff;
  ASN1_OCTET_STRING_dup: function (const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl = Load_ASN1_OCTET_STRING_dup;
  ASN1_OCTET_STRING_cmp: function (const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_OCTET_STRING_cmp;
  ASN1_OCTET_STRING_set: function (str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_OCTET_STRING_set;
  ASN1_OCTET_STRING_new: function : PASN1_OCTET_STRING; cdecl = Load_ASN1_OCTET_STRING_new;
  ASN1_OCTET_STRING_free: procedure (a: PASN1_OCTET_STRING); cdecl = Load_ASN1_OCTET_STRING_free;
  d2i_ASN1_OCTET_STRING: function (val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl = Load_d2i_ASN1_OCTET_STRING;
  i2d_ASN1_OCTET_STRING: function (val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_i2d_ASN1_OCTET_STRING;
  UTF8_getc: function (const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_UTF8_getc;
  UTF8_putc: function (str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_UTF8_putc;
  ASN1_UTCTIME_new: function : PASN1_UTCTIME; cdecl = Load_ASN1_UTCTIME_new;
  ASN1_UTCTIME_free: procedure (a: PASN1_UTCTIME); cdecl = Load_ASN1_UTCTIME_free;
  d2i_ASN1_UTCTIME: function (a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl = Load_d2i_ASN1_UTCTIME;
  i2d_ASN1_UTCTIME: function (a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ASN1_UTCTIME;
  ASN1_GENERALIZEDTIME_new: function : PASN1_GENERALIZEDTIME; cdecl = Load_ASN1_GENERALIZEDTIME_new;
  ASN1_GENERALIZEDTIME_free: procedure (a: PASN1_GENERALIZEDTIME); cdecl = Load_ASN1_GENERALIZEDTIME_free;
  d2i_ASN1_GENERALIZEDTIME: function (a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl = Load_d2i_ASN1_GENERALIZEDTIME;
  i2d_ASN1_GENERALIZEDTIME: function (a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ASN1_GENERALIZEDTIME;
  ASN1_TIME_new: function : PASN1_TIME; cdecl = Load_ASN1_TIME_new;
  ASN1_TIME_free: procedure (a: PASN1_TIME); cdecl = Load_ASN1_TIME_free;
  d2i_ASN1_TIME: function (a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl = Load_d2i_ASN1_TIME;
  i2d_ASN1_TIME: function (a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ASN1_TIME;
  ASN1_TIME_set: function (s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl = Load_ASN1_TIME_set;
  ASN1_TIME_adj: function (s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl = Load_ASN1_TIME_adj;
  ASN1_TIME_check: function (const t: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_check;
  ASN1_TIME_to_generalizedtime: function (const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl = Load_ASN1_TIME_to_generalizedtime;
  ASN1_TIME_set_string: function (s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_set_string;
  ASN1_TIME_set_string_X509: function (s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_set_string_X509;
  ASN1_TIME_to_tm: function (const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_to_tm;
  ASN1_TIME_normalize: function (s: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_normalize;
  ASN1_TIME_cmp_time_t: function (const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_cmp_time_t;
  ASN1_TIME_compare: function (const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_compare;
  i2a_ASN1_INTEGER: function (bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_i2a_ASN1_INTEGER;
  a2i_ASN1_INTEGER: function (bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_a2i_ASN1_INTEGER;
  i2a_ASN1_ENUMERATED: function (bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl = Load_i2a_ASN1_ENUMERATED;
  a2i_ASN1_ENUMERATED: function (bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_a2i_ASN1_ENUMERATED;
  i2a_ASN1_OBJECT: function (bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_i2a_ASN1_OBJECT;
  a2i_ASN1_STRING: function (bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_a2i_ASN1_STRING;
  i2a_ASN1_STRING: function (bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_i2a_ASN1_STRING;
  i2t_ASN1_OBJECT: function (buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_i2t_ASN1_OBJECT;
  a2d_ASN1_OBJECT: function (out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_a2d_ASN1_OBJECT;
  ASN1_OBJECT_create: function (nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl = Load_ASN1_OBJECT_create;
  ASN1_INTEGER_get_int64: function (pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_ASN1_INTEGER_get_int64;
  ASN1_INTEGER_set_int64: function (a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl = Load_ASN1_INTEGER_set_int64;
  ASN1_INTEGER_get_uint64: function (pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_ASN1_INTEGER_get_uint64;
  ASN1_INTEGER_set_uint64: function (a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl = Load_ASN1_INTEGER_set_uint64;
  ASN1_INTEGER_set: function (a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_ASN1_INTEGER_set;
  ASN1_INTEGER_get: function (const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl = Load_ASN1_INTEGER_get;
  BN_to_ASN1_INTEGER: function (const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl = Load_BN_to_ASN1_INTEGER;
  ASN1_INTEGER_to_BN: function (const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl = Load_ASN1_INTEGER_to_BN;
  ASN1_ENUMERATED_get_int64: function (pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl = Load_ASN1_ENUMERATED_get_int64;
  ASN1_ENUMERATED_set_int64: function (a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl = Load_ASN1_ENUMERATED_set_int64;
  ASN1_ENUMERATED_set: function (a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_ASN1_ENUMERATED_set;
  ASN1_ENUMERATED_get: function (const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl = Load_ASN1_ENUMERATED_get;
  BN_to_ASN1_ENUMERATED: function (const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl = Load_BN_to_ASN1_ENUMERATED;
  ASN1_ENUMERATED_to_BN: function (const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl = Load_ASN1_ENUMERATED_to_BN;
  ASN1_PRINTABLE_type: function (const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_PRINTABLE_type;
  ASN1_tag2bit: function (tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = Load_ASN1_tag2bit;
  ASN1_get_object: function (const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_ASN1_get_object;
  ASN1_check_infinite_end: function (p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_ASN1_check_infinite_end;
  ASN1_const_check_infinite_end: function (const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_ASN1_const_check_infinite_end;
  ASN1_put_object: procedure (pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl = Load_ASN1_put_object;
  ASN1_put_eoc: function (pp: PPByte): TOpenSSL_C_INT; cdecl = Load_ASN1_put_eoc;
  ASN1_object_size: function (constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_object_size;
  ASN1_item_dup: function (const it: PASN1_ITEM; x: Pointer): Pointer; cdecl = Load_ASN1_item_dup;
  ASN1_STRING_to_UTF8: function (out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_to_UTF8;
  ASN1_d2i_bio: function (xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl = Load_ASN1_d2i_bio;
  ASN1_item_d2i_bio: function (const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl = Load_ASN1_item_d2i_bio;
  ASN1_i2d_bio: function (i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl = Load_ASN1_i2d_bio;
  ASN1_item_i2d_bio: function (const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl = Load_ASN1_item_i2d_bio;
  ASN1_UTCTIME_print: function (fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl = Load_ASN1_UTCTIME_print;
  ASN1_GENERALIZEDTIME_print: function (fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = Load_ASN1_GENERALIZEDTIME_print;
  ASN1_TIME_print: function (fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl = Load_ASN1_TIME_print;
  ASN1_STRING_print: function (bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_print;
  ASN1_STRING_print_ex: function (out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_print_ex;
  ASN1_buf_print: function (bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_buf_print;
  ASN1_bn_print: function (bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_bn_print;
  ASN1_parse: function (bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_parse;
  ASN1_parse_dump: function (bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_parse_dump;
  ASN1_tag2str: function (tag: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_ASN1_tag2str;
  ASN1_UNIVERSALSTRING_to_string: function (s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl = Load_ASN1_UNIVERSALSTRING_to_string;
  ASN1_TYPE_set_octetstring: function (a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_set_octetstring;
  ASN1_TYPE_get_octetstring: function (const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_get_octetstring;
  ASN1_TYPE_set_int_octetstring: function (a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_set_int_octetstring;
  ASN1_TYPE_get_int_octetstring: function (const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ASN1_TYPE_get_int_octetstring;
  ASN1_item_unpack: function (const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl = Load_ASN1_item_unpack;
  ASN1_item_pack: function (obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl = Load_ASN1_item_pack;
  ASN1_STRING_set_default_mask: procedure (mask: TOpenSSL_C_ULONG); cdecl = Load_ASN1_STRING_set_default_mask;
  ASN1_STRING_set_default_mask_asc: function (const p: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_set_default_mask_asc;
  ASN1_STRING_get_default_mask: function : TOpenSSL_C_ULONG; cdecl = Load_ASN1_STRING_get_default_mask;
  ASN1_mbstring_copy: function (out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_ASN1_mbstring_copy;
  ASN1_mbstring_ncopy: function (out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_ASN1_mbstring_ncopy;
  ASN1_STRING_set_by_NID: function (out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl = Load_ASN1_STRING_set_by_NID;
  ASN1_STRING_TABLE_get: function (nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl = Load_ASN1_STRING_TABLE_get;
  ASN1_STRING_TABLE_add: function (v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_ASN1_STRING_TABLE_add;
  ASN1_STRING_TABLE_cleanup: procedure ; cdecl = Load_ASN1_STRING_TABLE_cleanup;
  ASN1_item_new: function (const it: PASN1_ITEM): PASN1_VALUE; cdecl = Load_ASN1_item_new;
  ASN1_item_free: procedure (val: PASN1_VALUE; const it: PASN1_ITEM); cdecl = Load_ASN1_item_free;
  ASN1_item_d2i: function (val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl = Load_ASN1_item_d2i;
  ASN1_item_i2d: function (val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = Load_ASN1_item_i2d;
  ASN1_item_ndef_i2d: function (val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = Load_ASN1_item_ndef_i2d;
  ASN1_add_oid_module: procedure ; cdecl = Load_ASN1_add_oid_module;
  ASN1_add_stable_module: procedure ; cdecl = Load_ASN1_add_stable_module;
  ASN1_generate_nconf: function (const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl = Load_ASN1_generate_nconf;
  ASN1_generate_v3: function (const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl = Load_ASN1_generate_v3;
  ASN1_str2mask: function (const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = Load_ASN1_str2mask;
  ASN1_item_print: function (out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_ASN1_item_print;
  ASN1_PCTX_new: function : PASN1_PCTX; cdecl = Load_ASN1_PCTX_new;
  ASN1_PCTX_free: procedure (p: PASN1_PCTX); cdecl = Load_ASN1_PCTX_free;
  ASN1_PCTX_get_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = Load_ASN1_PCTX_get_flags;
  ASN1_PCTX_set_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = Load_ASN1_PCTX_set_flags;
  ASN1_PCTX_get_nm_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = Load_ASN1_PCTX_get_nm_flags;
  ASN1_PCTX_set_nm_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = Load_ASN1_PCTX_set_nm_flags;
  ASN1_PCTX_get_cert_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = Load_ASN1_PCTX_get_cert_flags;
  ASN1_PCTX_set_cert_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = Load_ASN1_PCTX_set_cert_flags;
  ASN1_PCTX_get_oid_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = Load_ASN1_PCTX_get_oid_flags;
  ASN1_PCTX_set_oid_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = Load_ASN1_PCTX_set_oid_flags;
  ASN1_PCTX_get_str_flags: function (const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl = Load_ASN1_PCTX_get_str_flags;
  ASN1_PCTX_set_str_flags: procedure (p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl = Load_ASN1_PCTX_set_str_flags;
  ASN1_SCTX_free: procedure (p: PASN1_SCTX); cdecl = Load_ASN1_SCTX_free;
  ASN1_SCTX_get_item: function (p: PASN1_SCTX): PASN1_ITEM; cdecl = Load_ASN1_SCTX_get_item;
  ASN1_SCTX_get_template: function (p: PASN1_SCTX): PASN1_TEMPLATE; cdecl = Load_ASN1_SCTX_get_template;
  ASN1_SCTX_get_flags: function (p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl = Load_ASN1_SCTX_get_flags;
  ASN1_SCTX_set_app_data: procedure (p: PASN1_SCTX; data: Pointer); cdecl = Load_ASN1_SCTX_set_app_data;
  ASN1_SCTX_get_app_data: function (p: PASN1_SCTX): Pointer; cdecl = Load_ASN1_SCTX_get_app_data;
  BIO_f_asn1: function : PBIO_METHOD; cdecl = Load_BIO_f_asn1;
  BIO_new_NDEF: function (out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl = Load_BIO_new_NDEF;
  i2d_ASN1_bio_stream: function (out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = Load_i2d_ASN1_bio_stream;
  PEM_write_bio_ASN1_stream: function (out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_ASN1_stream;
  SMIME_read_ASN1: function (bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl = Load_SMIME_read_ASN1;
  SMIME_crlf_copy: function (in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SMIME_crlf_copy;
  SMIME_text: function (in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl = Load_SMIME_text;
  ASN1_ITEM_lookup: function (const name: PAnsiChar): PASN1_ITEM; cdecl = Load_ASN1_ITEM_lookup;
  ASN1_ITEM_get: function (i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl = Load_ASN1_ITEM_get;
{$ENDIF}
const
  ASN1_TYPE_pack_sequence_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TYPE_unpack_sequence_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_STRING_get0_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_set_string_X509_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_to_tm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_normalize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_cmp_time_t_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_TIME_compare_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_get_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_set_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_get_uint64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_INTEGER_set_uint64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ENUMERATED_get_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ENUMERATED_set_int64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_buf_print_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_add_stable_module_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_str2mask_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_item_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_template_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_set_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_SCTX_get_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ITEM_lookup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASN1_ITEM_get_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function Load_ASN1_TYPE_get(const a: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_get := LoadLibCryptoFunction('ASN1_TYPE_get');
  if not assigned(ASN1_TYPE_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_get');
  Result := ASN1_TYPE_get(a);
end;

procedure Load_ASN1_TYPE_set(a: PASN1_TYPE; type_: TOpenSSL_C_INT; value: Pointer); cdecl;
begin
  ASN1_TYPE_set := LoadLibCryptoFunction('ASN1_TYPE_set');
  if not assigned(ASN1_TYPE_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set');
  ASN1_TYPE_set(a,type_,value);
end;

function Load_ASN1_TYPE_set1(a: PASN1_TYPE; type_: TOpenSSL_C_INT; const value: Pointer): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_set1 := LoadLibCryptoFunction('ASN1_TYPE_set1');
  if not assigned(ASN1_TYPE_set1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set1');
  Result := ASN1_TYPE_set1(a,type_,value);
end;

function Load_ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_cmp := LoadLibCryptoFunction('ASN1_TYPE_cmp');
  if not assigned(ASN1_TYPE_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_cmp');
  Result := ASN1_TYPE_cmp(a,b);
end;

function Load_ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl;
begin
  ASN1_TYPE_pack_sequence := LoadLibCryptoFunction('ASN1_TYPE_pack_sequence');
  if not assigned(ASN1_TYPE_pack_sequence) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_pack_sequence');
  Result := ASN1_TYPE_pack_sequence(it,s,t);
end;

function Load_ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl;
begin
  ASN1_TYPE_unpack_sequence := LoadLibCryptoFunction('ASN1_TYPE_unpack_sequence');
  if not assigned(ASN1_TYPE_unpack_sequence) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_unpack_sequence');
  Result := ASN1_TYPE_unpack_sequence(it,t);
end;

function Load_ASN1_OBJECT_new: PASN1_OBJECT; cdecl;
begin
  ASN1_OBJECT_new := LoadLibCryptoFunction('ASN1_OBJECT_new');
  if not assigned(ASN1_OBJECT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OBJECT_new');
  Result := ASN1_OBJECT_new();
end;

procedure Load_ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl;
begin
  ASN1_OBJECT_free := LoadLibCryptoFunction('ASN1_OBJECT_free');
  if not assigned(ASN1_OBJECT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OBJECT_free');
  ASN1_OBJECT_free(a);
end;

function Load_i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ASN1_OBJECT := LoadLibCryptoFunction('i2d_ASN1_OBJECT');
  if not assigned(i2d_ASN1_OBJECT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_OBJECT');
  Result := i2d_ASN1_OBJECT(a,pp);
end;

function Load_d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_OBJECT; cdecl;
begin
  d2i_ASN1_OBJECT := LoadLibCryptoFunction('d2i_ASN1_OBJECT');
  if not assigned(d2i_ASN1_OBJECT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_OBJECT');
  Result := d2i_ASN1_OBJECT(a,pp,length);
end;

function Load_ASN1_STRING_new: PASN1_STRING; cdecl;
begin
  ASN1_STRING_new := LoadLibCryptoFunction('ASN1_STRING_new');
  if not assigned(ASN1_STRING_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_new');
  Result := ASN1_STRING_new();
end;

procedure Load_ASN1_STRING_free(a: PASN1_STRING); cdecl;
begin
  ASN1_STRING_free := LoadLibCryptoFunction('ASN1_STRING_free');
  if not assigned(ASN1_STRING_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_free');
  ASN1_STRING_free(a);
end;

procedure Load_ASN1_STRING_clear_free(a: PASN1_STRING); cdecl;
begin
  ASN1_STRING_clear_free := LoadLibCryptoFunction('ASN1_STRING_clear_free');
  if not assigned(ASN1_STRING_clear_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_clear_free');
  ASN1_STRING_clear_free(a);
end;

function Load_ASN1_STRING_copy(dst: PASN1_STRING; const str: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_copy := LoadLibCryptoFunction('ASN1_STRING_copy');
  if not assigned(ASN1_STRING_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_copy');
  Result := ASN1_STRING_copy(dst,str);
end;

function Load_ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING; cdecl;
begin
  ASN1_STRING_dup := LoadLibCryptoFunction('ASN1_STRING_dup');
  if not assigned(ASN1_STRING_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_dup');
  Result := ASN1_STRING_dup(a);
end;

function Load_ASN1_STRING_type_new(type_: TOpenSSL_C_INT): PASN1_STRING; cdecl;
begin
  ASN1_STRING_type_new := LoadLibCryptoFunction('ASN1_STRING_type_new');
  if not assigned(ASN1_STRING_type_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_type_new');
  Result := ASN1_STRING_type_new(type_);
end;

function Load_ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_cmp := LoadLibCryptoFunction('ASN1_STRING_cmp');
  if not assigned(ASN1_STRING_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_cmp');
  Result := ASN1_STRING_cmp(a,b);
end;

function Load_ASN1_STRING_set(str: PASN1_STRING; const data: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_set := LoadLibCryptoFunction('ASN1_STRING_set');
  if not assigned(ASN1_STRING_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set');
  Result := ASN1_STRING_set(str,data,len);
end;

procedure Load_ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TOpenSSL_C_INT); cdecl;
begin
  ASN1_STRING_set0 := LoadLibCryptoFunction('ASN1_STRING_set0');
  if not assigned(ASN1_STRING_set0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set0');
  ASN1_STRING_set0(str,data,len);
end;

function Load_ASN1_STRING_length(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_length := LoadLibCryptoFunction('ASN1_STRING_length');
  if not assigned(ASN1_STRING_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_length');
  Result := ASN1_STRING_length(x);
end;

procedure Load_ASN1_STRING_length_set(x: PASN1_STRING; n: TOpenSSL_C_INT); cdecl;
begin
  ASN1_STRING_length_set := LoadLibCryptoFunction('ASN1_STRING_length_set');
  if not assigned(ASN1_STRING_length_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_length_set');
  ASN1_STRING_length_set(x,n);
end;

function Load_ASN1_STRING_type(const x: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_type := LoadLibCryptoFunction('ASN1_STRING_type');
  if not assigned(ASN1_STRING_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_type');
  Result := ASN1_STRING_type(x);
end;

function Load_ASN1_STRING_get0_data(const x: PASN1_STRING): PByte; cdecl;
begin
  ASN1_STRING_get0_data := LoadLibCryptoFunction('ASN1_STRING_get0_data');
  if not assigned(ASN1_STRING_get0_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_get0_data');
  Result := ASN1_STRING_get0_data(x);
end;

function Load_ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_set := LoadLibCryptoFunction('ASN1_BIT_STRING_set');
  if not assigned(ASN1_BIT_STRING_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_set');
  Result := ASN1_BIT_STRING_set(a,d,length);
end;

function Load_ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TOpenSSL_C_INT; value: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_set_bit := LoadLibCryptoFunction('ASN1_BIT_STRING_set_bit');
  if not assigned(ASN1_BIT_STRING_set_bit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_set_bit');
  Result := ASN1_BIT_STRING_set_bit(a,n,value);
end;

function Load_ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_get_bit := LoadLibCryptoFunction('ASN1_BIT_STRING_get_bit');
  if not assigned(ASN1_BIT_STRING_get_bit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_get_bit');
  Result := ASN1_BIT_STRING_get_bit(a,n);
end;

function Load_ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_check := LoadLibCryptoFunction('ASN1_BIT_STRING_check');
  if not assigned(ASN1_BIT_STRING_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_check');
  Result := ASN1_BIT_STRING_check(a,flags,flags_len);
end;

function Load_ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_name_print := LoadLibCryptoFunction('ASN1_BIT_STRING_name_print');
  if not assigned(ASN1_BIT_STRING_name_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_name_print');
  Result := ASN1_BIT_STRING_name_print(out_,bs,tbl,indent);
end;

function Load_ASN1_BIT_STRING_num_asc(const name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_num_asc := LoadLibCryptoFunction('ASN1_BIT_STRING_num_asc');
  if not assigned(ASN1_BIT_STRING_num_asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_num_asc');
  Result := ASN1_BIT_STRING_num_asc(name,tbl);
end;

function Load_ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PAnsiChar; value: TOpenSSL_C_INT; tbl: PBIT_STRING_BITNAME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_BIT_STRING_set_asc := LoadLibCryptoFunction('ASN1_BIT_STRING_set_asc');
  if not assigned(ASN1_BIT_STRING_set_asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_BIT_STRING_set_asc');
  Result := ASN1_BIT_STRING_set_asc(bs,name,value,tbl);
end;

function Load_ASN1_INTEGER_new: PASN1_INTEGER; cdecl;
begin
  ASN1_INTEGER_new := LoadLibCryptoFunction('ASN1_INTEGER_new');
  if not assigned(ASN1_INTEGER_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_new');
  Result := ASN1_INTEGER_new();
end;

procedure Load_ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl;
begin
  ASN1_INTEGER_free := LoadLibCryptoFunction('ASN1_INTEGER_free');
  if not assigned(ASN1_INTEGER_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_free');
  ASN1_INTEGER_free(a);
end;

function Load_d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TOpenSSL_C_Long): PASN1_INTEGER; cdecl;
begin
  d2i_ASN1_INTEGER := LoadLibCryptoFunction('d2i_ASN1_INTEGER');
  if not assigned(d2i_ASN1_INTEGER) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_INTEGER');
  Result := d2i_ASN1_INTEGER(a,in_,len);
end;

function Load_i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TOpenSSL_C_Int; cdecl;
begin
  i2d_ASN1_INTEGER := LoadLibCryptoFunction('i2d_ASN1_INTEGER');
  if not assigned(i2d_ASN1_INTEGER) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_INTEGER');
  Result := i2d_ASN1_INTEGER(a,out_);
end;

function Load_d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; length: TOpenSSL_C_LONG): PASN1_INTEGER; cdecl;
begin
  d2i_ASN1_UINTEGER := LoadLibCryptoFunction('d2i_ASN1_UINTEGER');
  if not assigned(d2i_ASN1_UINTEGER) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_UINTEGER');
  Result := d2i_ASN1_UINTEGER(a,pp,length);
end;

function Load_ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER; cdecl;
begin
  ASN1_INTEGER_dup := LoadLibCryptoFunction('ASN1_INTEGER_dup');
  if not assigned(ASN1_INTEGER_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_dup');
  Result := ASN1_INTEGER_dup(x);
end;

function Load_ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  ASN1_INTEGER_cmp := LoadLibCryptoFunction('ASN1_INTEGER_cmp');
  if not assigned(ASN1_INTEGER_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_cmp');
  Result := ASN1_INTEGER_cmp(x,y);
end;

function Load_ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_UTCTIME_check := LoadLibCryptoFunction('ASN1_UTCTIME_check');
  if not assigned(ASN1_UTCTIME_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_check');
  Result := ASN1_UTCTIME_check(a);
end;

function Load_ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): PASN1_UTCTIME; cdecl;
begin
  ASN1_UTCTIME_set := LoadLibCryptoFunction('ASN1_UTCTIME_set');
  if not assigned(ASN1_UTCTIME_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_set');
  Result := ASN1_UTCTIME_set(s,t);
end;

function Load_ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl;
begin
  ASN1_UTCTIME_adj := LoadLibCryptoFunction('ASN1_UTCTIME_adj');
  if not assigned(ASN1_UTCTIME_adj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_adj');
  Result := ASN1_UTCTIME_adj(s,t,offset_day,offset_sec);
end;

function Load_ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ASN1_UTCTIME_set_string := LoadLibCryptoFunction('ASN1_UTCTIME_set_string');
  if not assigned(ASN1_UTCTIME_set_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_set_string');
  Result := ASN1_UTCTIME_set_string(s,str);
end;

function Load_ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  ASN1_UTCTIME_cmp_time_t := LoadLibCryptoFunction('ASN1_UTCTIME_cmp_time_t');
  if not assigned(ASN1_UTCTIME_cmp_time_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_cmp_time_t');
  Result := ASN1_UTCTIME_cmp_time_t(s,t);
end;

function Load_ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_GENERALIZEDTIME_check := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_check');
  if not assigned(ASN1_GENERALIZEDTIME_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_check');
  Result := ASN1_GENERALIZEDTIME_check(a);
end;

function Load_ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET): PASN1_GENERALIZEDTIME; cdecl;
begin
  ASN1_GENERALIZEDTIME_set := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_set');
  if not assigned(ASN1_GENERALIZEDTIME_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_set');
  Result := ASN1_GENERALIZEDTIME_set(s,t);
end;

function Load_ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl;
begin
  ASN1_GENERALIZEDTIME_adj := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_adj');
  if not assigned(ASN1_GENERALIZEDTIME_adj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_adj');
  Result := ASN1_GENERALIZEDTIME_adj(s,t,offset_day,offset_sec);
end;

function Load_ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ASN1_GENERALIZEDTIME_set_string := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_set_string');
  if not assigned(ASN1_GENERALIZEDTIME_set_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_set_string');
  Result := ASN1_GENERALIZEDTIME_set_string(s,str);
end;

function Load_ASN1_TIME_diff(pday: POpenSSL_C_INT; psec: POpenSSL_C_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_diff := LoadLibCryptoFunction('ASN1_TIME_diff');
  if not assigned(ASN1_TIME_diff) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_diff');
  Result := ASN1_TIME_diff(pday,psec,from,to_);
end;

function Load_ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl;
begin
  ASN1_OCTET_STRING_dup := LoadLibCryptoFunction('ASN1_OCTET_STRING_dup');
  if not assigned(ASN1_OCTET_STRING_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_dup');
  Result := ASN1_OCTET_STRING_dup(a);
end;

function Load_ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_OCTET_STRING_cmp := LoadLibCryptoFunction('ASN1_OCTET_STRING_cmp');
  if not assigned(ASN1_OCTET_STRING_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_cmp');
  Result := ASN1_OCTET_STRING_cmp(a,b);
end;

function Load_ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; const data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_OCTET_STRING_set := LoadLibCryptoFunction('ASN1_OCTET_STRING_set');
  if not assigned(ASN1_OCTET_STRING_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_set');
  Result := ASN1_OCTET_STRING_set(str,data,len);
end;

function Load_ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl;
begin
  ASN1_OCTET_STRING_new := LoadLibCryptoFunction('ASN1_OCTET_STRING_new');
  if not assigned(ASN1_OCTET_STRING_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_new');
  Result := ASN1_OCTET_STRING_new();
end;

procedure Load_ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl;
begin
  ASN1_OCTET_STRING_free := LoadLibCryptoFunction('ASN1_OCTET_STRING_free');
  if not assigned(ASN1_OCTET_STRING_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OCTET_STRING_free');
  ASN1_OCTET_STRING_free(a);
end;

function Load_d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPAnsiChar; length : TOpenSSL_C_LONG): PASN1_OCTET_STRING; cdecl;
begin
  d2i_ASN1_OCTET_STRING := LoadLibCryptoFunction('d2i_ASN1_OCTET_STRING');
  if not assigned(d2i_ASN1_OCTET_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_OCTET_STRING');
  Result := d2i_ASN1_OCTET_STRING(val_out,der_in,length);
end;

function Load_i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  i2d_ASN1_OCTET_STRING := LoadLibCryptoFunction('i2d_ASN1_OCTET_STRING');
  if not assigned(i2d_ASN1_OCTET_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_OCTET_STRING');
  Result := i2d_ASN1_OCTET_STRING(val_in,der_out);
end;

function Load_UTF8_getc(const str: PByte; len: TOpenSSL_C_INT; val: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  UTF8_getc := LoadLibCryptoFunction('UTF8_getc');
  if not assigned(UTF8_getc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UTF8_getc');
  Result := UTF8_getc(str,len,val);
end;

function Load_UTF8_putc(str: PAnsiChar; len: TOpenSSL_C_INT; value: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  UTF8_putc := LoadLibCryptoFunction('UTF8_putc');
  if not assigned(UTF8_putc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('UTF8_putc');
  Result := UTF8_putc(str,len,value);
end;

function Load_ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl;
begin
  ASN1_UTCTIME_new := LoadLibCryptoFunction('ASN1_UTCTIME_new');
  if not assigned(ASN1_UTCTIME_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_new');
  Result := ASN1_UTCTIME_new();
end;

procedure Load_ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl;
begin
  ASN1_UTCTIME_free := LoadLibCryptoFunction('ASN1_UTCTIME_free');
  if not assigned(ASN1_UTCTIME_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_free');
  ASN1_UTCTIME_free(a);
end;

function Load_d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_UTCTIME; cdecl;
begin
  d2i_ASN1_UTCTIME := LoadLibCryptoFunction('d2i_ASN1_UTCTIME');
  if not assigned(d2i_ASN1_UTCTIME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_UTCTIME');
  Result := d2i_ASN1_UTCTIME(a,in_,len);
end;

function Load_i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ASN1_UTCTIME := LoadLibCryptoFunction('i2d_ASN1_UTCTIME');
  if not assigned(i2d_ASN1_UTCTIME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_UTCTIME');
  Result := i2d_ASN1_UTCTIME(a,out_);
end;

function Load_ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl;
begin
  ASN1_GENERALIZEDTIME_new := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_new');
  if not assigned(ASN1_GENERALIZEDTIME_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_new');
  Result := ASN1_GENERALIZEDTIME_new();
end;

procedure Load_ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl;
begin
  ASN1_GENERALIZEDTIME_free := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_free');
  if not assigned(ASN1_GENERALIZEDTIME_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_free');
  ASN1_GENERALIZEDTIME_free(a);
end;

function Load_d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_GENERALIZEDTIME; cdecl;
begin
  d2i_ASN1_GENERALIZEDTIME := LoadLibCryptoFunction('d2i_ASN1_GENERALIZEDTIME');
  if not assigned(d2i_ASN1_GENERALIZEDTIME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_GENERALIZEDTIME');
  Result := d2i_ASN1_GENERALIZEDTIME(a,in_,len);
end;

function Load_i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ASN1_GENERALIZEDTIME := LoadLibCryptoFunction('i2d_ASN1_GENERALIZEDTIME');
  if not assigned(i2d_ASN1_GENERALIZEDTIME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_GENERALIZEDTIME');
  Result := i2d_ASN1_GENERALIZEDTIME(a,out_);
end;

function Load_ASN1_TIME_new: PASN1_TIME; cdecl;
begin
  ASN1_TIME_new := LoadLibCryptoFunction('ASN1_TIME_new');
  if not assigned(ASN1_TIME_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_new');
  Result := ASN1_TIME_new();
end;

procedure Load_ASN1_TIME_free(a: PASN1_TIME); cdecl;
begin
  ASN1_TIME_free := LoadLibCryptoFunction('ASN1_TIME_free');
  if not assigned(ASN1_TIME_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_free');
  ASN1_TIME_free(a);
end;

function Load_d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
begin
  d2i_ASN1_TIME := LoadLibCryptoFunction('d2i_ASN1_TIME');
  if not assigned(d2i_ASN1_TIME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ASN1_TIME');
  Result := d2i_ASN1_TIME(a,in_,len);
end;

function Load_i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ASN1_TIME := LoadLibCryptoFunction('i2d_ASN1_TIME');
  if not assigned(i2d_ASN1_TIME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_TIME');
  Result := i2d_ASN1_TIME(a,out_);
end;

function Load_ASN1_TIME_set(s: PASN1_TIME; t: TOpenSSL_C_TIMET): PASN1_TIME; cdecl;
begin
  ASN1_TIME_set := LoadLibCryptoFunction('ASN1_TIME_set');
  if not assigned(ASN1_TIME_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_set');
  Result := ASN1_TIME_set(s,t);
end;

function Load_ASN1_TIME_adj(s: PASN1_TIME; t: TOpenSSL_C_TIMET; offset_day: TOpenSSL_C_INT; offset_sec: TOpenSSL_C_LONG): PASN1_TIME; cdecl;
begin
  ASN1_TIME_adj := LoadLibCryptoFunction('ASN1_TIME_adj');
  if not assigned(ASN1_TIME_adj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_adj');
  Result := ASN1_TIME_adj(s,t,offset_day,offset_sec);
end;

function Load_ASN1_TIME_check(const t: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_check := LoadLibCryptoFunction('ASN1_TIME_check');
  if not assigned(ASN1_TIME_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_check');
  Result := ASN1_TIME_check(t);
end;

function Load_ASN1_TIME_to_generalizedtime(const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl;
begin
  ASN1_TIME_to_generalizedtime := LoadLibCryptoFunction('ASN1_TIME_to_generalizedtime');
  if not assigned(ASN1_TIME_to_generalizedtime) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_to_generalizedtime');
  Result := ASN1_TIME_to_generalizedtime(t,out_);
end;

function Load_ASN1_TIME_set_string(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_set_string := LoadLibCryptoFunction('ASN1_TIME_set_string');
  if not assigned(ASN1_TIME_set_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_set_string');
  Result := ASN1_TIME_set_string(s,str);
end;

function Load_ASN1_TIME_set_string_X509(s: PASN1_TIME; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_set_string_X509 := LoadLibCryptoFunction('ASN1_TIME_set_string_X509');
  if not assigned(ASN1_TIME_set_string_X509) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_set_string_X509');
  Result := ASN1_TIME_set_string_X509(s,str);
end;

function Load_ASN1_TIME_to_tm(const s: PASN1_TIME; tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_to_tm := LoadLibCryptoFunction('ASN1_TIME_to_tm');
  if not assigned(ASN1_TIME_to_tm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_to_tm');
  Result := ASN1_TIME_to_tm(s,tm);
end;

function Load_ASN1_TIME_normalize(s: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_normalize := LoadLibCryptoFunction('ASN1_TIME_normalize');
  if not assigned(ASN1_TIME_normalize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_normalize');
  Result := ASN1_TIME_normalize(s);
end;

function Load_ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_cmp_time_t := LoadLibCryptoFunction('ASN1_TIME_cmp_time_t');
  if not assigned(ASN1_TIME_cmp_time_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_cmp_time_t');
  Result := ASN1_TIME_cmp_time_t(s,t);
end;

function Load_ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_compare := LoadLibCryptoFunction('ASN1_TIME_compare');
  if not assigned(ASN1_TIME_compare) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_compare');
  Result := ASN1_TIME_compare(a,b);
end;

function Load_i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  i2a_ASN1_INTEGER := LoadLibCryptoFunction('i2a_ASN1_INTEGER');
  if not assigned(i2a_ASN1_INTEGER) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_INTEGER');
  Result := i2a_ASN1_INTEGER(bp,a);
end;

function Load_a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  a2i_ASN1_INTEGER := LoadLibCryptoFunction('a2i_ASN1_INTEGER');
  if not assigned(a2i_ASN1_INTEGER) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_ASN1_INTEGER');
  Result := a2i_ASN1_INTEGER(bp,bs,buf,size);
end;

function Load_i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl;
begin
  i2a_ASN1_ENUMERATED := LoadLibCryptoFunction('i2a_ASN1_ENUMERATED');
  if not assigned(i2a_ASN1_ENUMERATED) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_ENUMERATED');
  Result := i2a_ASN1_ENUMERATED(bp,a);
end;

function Load_a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  a2i_ASN1_ENUMERATED := LoadLibCryptoFunction('a2i_ASN1_ENUMERATED');
  if not assigned(a2i_ASN1_ENUMERATED) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_ASN1_ENUMERATED');
  Result := a2i_ASN1_ENUMERATED(bp,bs,buf,size);
end;

function Load_i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  i2a_ASN1_OBJECT := LoadLibCryptoFunction('i2a_ASN1_OBJECT');
  if not assigned(i2a_ASN1_OBJECT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_OBJECT');
  Result := i2a_ASN1_OBJECT(bp,a);
end;

function Load_a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  a2i_ASN1_STRING := LoadLibCryptoFunction('a2i_ASN1_STRING');
  if not assigned(a2i_ASN1_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('a2i_ASN1_STRING');
  Result := a2i_ASN1_STRING(bp,bs,buf,size);
end;

function Load_i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  i2a_ASN1_STRING := LoadLibCryptoFunction('i2a_ASN1_STRING');
  if not assigned(i2a_ASN1_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2a_ASN1_STRING');
  Result := i2a_ASN1_STRING(bp,a,type_);
end;

function Load_i2t_ASN1_OBJECT(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  i2t_ASN1_OBJECT := LoadLibCryptoFunction('i2t_ASN1_OBJECT');
  if not assigned(i2t_ASN1_OBJECT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2t_ASN1_OBJECT');
  Result := i2t_ASN1_OBJECT(buf,buf_len,a);
end;

function Load_a2d_ASN1_OBJECT(out_: PByte; olen: TOpenSSL_C_INT; const buf: PAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  a2d_ASN1_OBJECT := LoadLibCryptoFunction('a2d_ASN1_OBJECT');
  if not assigned(a2d_ASN1_OBJECT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('a2d_ASN1_OBJECT');
  Result := a2d_ASN1_OBJECT(out_,olen,buf,num);
end;

function Load_ASN1_OBJECT_create(nid: TOpenSSL_C_INT; data: PByte; len: TOpenSSL_C_INT; const sn: PAnsiChar; const ln: PAnsiChar): PASN1_OBJECT; cdecl;
begin
  ASN1_OBJECT_create := LoadLibCryptoFunction('ASN1_OBJECT_create');
  if not assigned(ASN1_OBJECT_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_OBJECT_create');
  Result := ASN1_OBJECT_create(nid,data,len,sn,ln);
end;

function Load_ASN1_INTEGER_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  ASN1_INTEGER_get_int64 := LoadLibCryptoFunction('ASN1_INTEGER_get_int64');
  if not assigned(ASN1_INTEGER_get_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_get_int64');
  Result := ASN1_INTEGER_get_int64(pr,a);
end;

function Load_ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl;
begin
  ASN1_INTEGER_set_int64 := LoadLibCryptoFunction('ASN1_INTEGER_set_int64');
  if not assigned(ASN1_INTEGER_set_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_set_int64');
  Result := ASN1_INTEGER_set_int64(a,r);
end;

function Load_ASN1_INTEGER_get_uint64(pr: POpenSSL_C_UInt64; const a: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  ASN1_INTEGER_get_uint64 := LoadLibCryptoFunction('ASN1_INTEGER_get_uint64');
  if not assigned(ASN1_INTEGER_get_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_get_uint64');
  Result := ASN1_INTEGER_get_uint64(pr,a);
end;

function Load_ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TOpenSSL_C_UInt64): TOpenSSL_C_INT; cdecl;
begin
  ASN1_INTEGER_set_uint64 := LoadLibCryptoFunction('ASN1_INTEGER_set_uint64');
  if not assigned(ASN1_INTEGER_set_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_set_uint64');
  Result := ASN1_INTEGER_set_uint64(a,r);
end;

function Load_ASN1_INTEGER_set(a: PASN1_INTEGER; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_INTEGER_set := LoadLibCryptoFunction('ASN1_INTEGER_set');
  if not assigned(ASN1_INTEGER_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_set');
  Result := ASN1_INTEGER_set(a,v);
end;

function Load_ASN1_INTEGER_get(const a: PASN1_INTEGER): TOpenSSL_C_LONG; cdecl;
begin
  ASN1_INTEGER_get := LoadLibCryptoFunction('ASN1_INTEGER_get');
  if not assigned(ASN1_INTEGER_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_get');
  Result := ASN1_INTEGER_get(a);
end;

function Load_BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl;
begin
  BN_to_ASN1_INTEGER := LoadLibCryptoFunction('BN_to_ASN1_INTEGER');
  if not assigned(BN_to_ASN1_INTEGER) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_to_ASN1_INTEGER');
  Result := BN_to_ASN1_INTEGER(bn,ai);
end;

function Load_ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl;
begin
  ASN1_INTEGER_to_BN := LoadLibCryptoFunction('ASN1_INTEGER_to_BN');
  if not assigned(ASN1_INTEGER_to_BN) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_INTEGER_to_BN');
  Result := ASN1_INTEGER_to_BN(ai,bn);
end;

function Load_ASN1_ENUMERATED_get_int64(pr: POpenSSL_C_Int64; const a: PASN1_ENUMERATED): TOpenSSL_C_INT; cdecl;
begin
  ASN1_ENUMERATED_get_int64 := LoadLibCryptoFunction('ASN1_ENUMERATED_get_int64');
  if not assigned(ASN1_ENUMERATED_get_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_get_int64');
  Result := ASN1_ENUMERATED_get_int64(pr,a);
end;

function Load_ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TOpenSSL_C_Int64): TOpenSSL_C_INT; cdecl;
begin
  ASN1_ENUMERATED_set_int64 := LoadLibCryptoFunction('ASN1_ENUMERATED_set_int64');
  if not assigned(ASN1_ENUMERATED_set_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_set_int64');
  Result := ASN1_ENUMERATED_set_int64(a,r);
end;

function Load_ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_ENUMERATED_set := LoadLibCryptoFunction('ASN1_ENUMERATED_set');
  if not assigned(ASN1_ENUMERATED_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_set');
  Result := ASN1_ENUMERATED_set(a,v);
end;

function Load_ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TOpenSSL_C_LONG; cdecl;
begin
  ASN1_ENUMERATED_get := LoadLibCryptoFunction('ASN1_ENUMERATED_get');
  if not assigned(ASN1_ENUMERATED_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_get');
  Result := ASN1_ENUMERATED_get(a);
end;

function Load_BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl;
begin
  BN_to_ASN1_ENUMERATED := LoadLibCryptoFunction('BN_to_ASN1_ENUMERATED');
  if not assigned(BN_to_ASN1_ENUMERATED) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BN_to_ASN1_ENUMERATED');
  Result := BN_to_ASN1_ENUMERATED(bn,ai);
end;

function Load_ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl;
begin
  ASN1_ENUMERATED_to_BN := LoadLibCryptoFunction('ASN1_ENUMERATED_to_BN');
  if not assigned(ASN1_ENUMERATED_to_BN) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ENUMERATED_to_BN');
  Result := ASN1_ENUMERATED_to_BN(ai,bn);
end;

function Load_ASN1_PRINTABLE_type(const s: PByte; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_PRINTABLE_type := LoadLibCryptoFunction('ASN1_PRINTABLE_type');
  if not assigned(ASN1_PRINTABLE_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PRINTABLE_type');
  Result := ASN1_PRINTABLE_type(s,max);
end;

function Load_ASN1_tag2bit(tag: TOpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_tag2bit := LoadLibCryptoFunction('ASN1_tag2bit');
  if not assigned(ASN1_tag2bit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_tag2bit');
  Result := ASN1_tag2bit(tag);
end;

function Load_ASN1_get_object(const pp: PPByte; plength: POpenSSL_C_LONG; ptag: POpenSSL_C_INT; pclass: POpenSSL_C_INT; omax: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_get_object := LoadLibCryptoFunction('ASN1_get_object');
  if not assigned(ASN1_get_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_get_object');
  Result := ASN1_get_object(pp,plength,ptag,pclass,omax);
end;

function Load_ASN1_check_infinite_end(p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_check_infinite_end := LoadLibCryptoFunction('ASN1_check_infinite_end');
  if not assigned(ASN1_check_infinite_end) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_check_infinite_end');
  Result := ASN1_check_infinite_end(p,len);
end;

function Load_ASN1_const_check_infinite_end(const p: PPByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_const_check_infinite_end := LoadLibCryptoFunction('ASN1_const_check_infinite_end');
  if not assigned(ASN1_const_check_infinite_end) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_const_check_infinite_end');
  Result := ASN1_const_check_infinite_end(p,len);
end;

procedure Load_ASN1_put_object(pp: PPByte; constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT; xclass: TOpenSSL_C_INT); cdecl;
begin
  ASN1_put_object := LoadLibCryptoFunction('ASN1_put_object');
  if not assigned(ASN1_put_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_put_object');
  ASN1_put_object(pp,constructed,length,tag,xclass);
end;

function Load_ASN1_put_eoc(pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  ASN1_put_eoc := LoadLibCryptoFunction('ASN1_put_eoc');
  if not assigned(ASN1_put_eoc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_put_eoc');
  Result := ASN1_put_eoc(pp);
end;

function Load_ASN1_object_size(constructed: TOpenSSL_C_INT; length: TOpenSSL_C_INT; tag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_object_size := LoadLibCryptoFunction('ASN1_object_size');
  if not assigned(ASN1_object_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_object_size');
  Result := ASN1_object_size(constructed,length,tag);
end;

function Load_ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer; cdecl;
begin
  ASN1_item_dup := LoadLibCryptoFunction('ASN1_item_dup');
  if not assigned(ASN1_item_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_dup');
  Result := ASN1_item_dup(it,x);
end;

function Load_ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_to_UTF8 := LoadLibCryptoFunction('ASN1_STRING_to_UTF8');
  if not assigned(ASN1_STRING_to_UTF8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_to_UTF8');
  Result := ASN1_STRING_to_UTF8(out_,in_);
end;

function Load_ASN1_d2i_bio(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl;
begin
  ASN1_d2i_bio := LoadLibCryptoFunction('ASN1_d2i_bio');
  if not assigned(ASN1_d2i_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_d2i_bio');
  Result := ASN1_d2i_bio(xnew,d2i,in_,x);
end;

function Load_ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl;
begin
  ASN1_item_d2i_bio := LoadLibCryptoFunction('ASN1_item_d2i_bio');
  if not assigned(ASN1_item_d2i_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_d2i_bio');
  Result := ASN1_item_d2i_bio(it,in_,x);
end;

function Load_ASN1_i2d_bio(i2d: Pi2d_of_void; out_: PBIO; x: PByte): TOpenSSL_C_INT; cdecl;
begin
  ASN1_i2d_bio := LoadLibCryptoFunction('ASN1_i2d_bio');
  if not assigned(ASN1_i2d_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_i2d_bio');
  Result := ASN1_i2d_bio(i2d,out_,x);
end;

function Load_ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_i2d_bio := LoadLibCryptoFunction('ASN1_item_i2d_bio');
  if not assigned(ASN1_item_i2d_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_i2d_bio');
  Result := ASN1_item_i2d_bio(it,out_,x);
end;

function Load_ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_UTCTIME_print := LoadLibCryptoFunction('ASN1_UTCTIME_print');
  if not assigned(ASN1_UTCTIME_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UTCTIME_print');
  Result := ASN1_UTCTIME_print(fp,a);
end;

function Load_ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_GENERALIZEDTIME_print := LoadLibCryptoFunction('ASN1_GENERALIZEDTIME_print');
  if not assigned(ASN1_GENERALIZEDTIME_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_GENERALIZEDTIME_print');
  Result := ASN1_GENERALIZEDTIME_print(fp,a);
end;

function Load_ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TIME_print := LoadLibCryptoFunction('ASN1_TIME_print');
  if not assigned(ASN1_TIME_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TIME_print');
  Result := ASN1_TIME_print(fp,a);
end;

function Load_ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_print := LoadLibCryptoFunction('ASN1_STRING_print');
  if not assigned(ASN1_STRING_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_print');
  Result := ASN1_STRING_print(bp,v);
end;

function Load_ASN1_STRING_print_ex(out_: PBIO; const str: PASN1_STRING; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_print_ex := LoadLibCryptoFunction('ASN1_STRING_print_ex');
  if not assigned(ASN1_STRING_print_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_print_ex');
  Result := ASN1_STRING_print_ex(out_,str,flags);
end;

function Load_ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TOpenSSL_C_SIZET; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_buf_print := LoadLibCryptoFunction('ASN1_buf_print');
  if not assigned(ASN1_buf_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_buf_print');
  Result := ASN1_buf_print(bp,buf,buflen,off);
end;

function Load_ASN1_bn_print(bp: PBIO; const number: PAnsiChar; const num: PBIGNUM; buf: PByte; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_bn_print := LoadLibCryptoFunction('ASN1_bn_print');
  if not assigned(ASN1_bn_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_bn_print');
  Result := ASN1_bn_print(bp,number,num,buf,off);
end;

function Load_ASN1_parse(bp: PBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_parse := LoadLibCryptoFunction('ASN1_parse');
  if not assigned(ASN1_parse) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_parse');
  Result := ASN1_parse(bp,pp,len,indent);
end;

function Load_ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TOpenSSL_C_LONG; indent: TOpenSSL_C_INT; dump: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_parse_dump := LoadLibCryptoFunction('ASN1_parse_dump');
  if not assigned(ASN1_parse_dump) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_parse_dump');
  Result := ASN1_parse_dump(bp,pp,len,indent,dump);
end;

function Load_ASN1_tag2str(tag: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  ASN1_tag2str := LoadLibCryptoFunction('ASN1_tag2str');
  if not assigned(ASN1_tag2str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_tag2str');
  Result := ASN1_tag2str(tag);
end;

function Load_ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TOpenSSL_C_INT; cdecl;
begin
  ASN1_UNIVERSALSTRING_to_string := LoadLibCryptoFunction('ASN1_UNIVERSALSTRING_to_string');
  if not assigned(ASN1_UNIVERSALSTRING_to_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_UNIVERSALSTRING_to_string');
  Result := ASN1_UNIVERSALSTRING_to_string(s);
end;

function Load_ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_set_octetstring := LoadLibCryptoFunction('ASN1_TYPE_set_octetstring');
  if not assigned(ASN1_TYPE_set_octetstring) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set_octetstring');
  Result := ASN1_TYPE_set_octetstring(a,data,len);
end;

function Load_ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_get_octetstring := LoadLibCryptoFunction('ASN1_TYPE_get_octetstring');
  if not assigned(ASN1_TYPE_get_octetstring) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_get_octetstring');
  Result := ASN1_TYPE_get_octetstring(a,data,max_len);
end;

function Load_ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TOpenSSL_C_LONG; data: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_set_int_octetstring := LoadLibCryptoFunction('ASN1_TYPE_set_int_octetstring');
  if not assigned(ASN1_TYPE_set_int_octetstring) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_set_int_octetstring');
  Result := ASN1_TYPE_set_int_octetstring(a,num,data,len);
end;

function Load_ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: POpenSSL_C_LONG; data: PByte; max_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ASN1_TYPE_get_int_octetstring := LoadLibCryptoFunction('ASN1_TYPE_get_int_octetstring');
  if not assigned(ASN1_TYPE_get_int_octetstring) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_TYPE_get_int_octetstring');
  Result := ASN1_TYPE_get_int_octetstring(a,num,data,max_len);
end;

function Load_ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl;
begin
  ASN1_item_unpack := LoadLibCryptoFunction('ASN1_item_unpack');
  if not assigned(ASN1_item_unpack) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_unpack');
  Result := ASN1_item_unpack(oct,it);
end;

function Load_ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl;
begin
  ASN1_item_pack := LoadLibCryptoFunction('ASN1_item_pack');
  if not assigned(ASN1_item_pack) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_pack');
  Result := ASN1_item_pack(obj,it,oct);
end;

procedure Load_ASN1_STRING_set_default_mask(mask: TOpenSSL_C_ULONG); cdecl;
begin
  ASN1_STRING_set_default_mask := LoadLibCryptoFunction('ASN1_STRING_set_default_mask');
  if not assigned(ASN1_STRING_set_default_mask) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set_default_mask');
  ASN1_STRING_set_default_mask(mask);
end;

function Load_ASN1_STRING_set_default_mask_asc(const p: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_set_default_mask_asc := LoadLibCryptoFunction('ASN1_STRING_set_default_mask_asc');
  if not assigned(ASN1_STRING_set_default_mask_asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set_default_mask_asc');
  Result := ASN1_STRING_set_default_mask_asc(p);
end;

function Load_ASN1_STRING_get_default_mask: TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_STRING_get_default_mask := LoadLibCryptoFunction('ASN1_STRING_get_default_mask');
  if not assigned(ASN1_STRING_get_default_mask) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_get_default_mask');
  Result := ASN1_STRING_get_default_mask();
end;

function Load_ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_mbstring_copy := LoadLibCryptoFunction('ASN1_mbstring_copy');
  if not assigned(ASN1_mbstring_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_mbstring_copy');
  Result := ASN1_mbstring_copy(out_,in_,len,inform,mask);
end;

function Load_ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; mask: TOpenSSL_C_ULONG; minsize: TOpenSSL_C_LONG; maxsize: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_mbstring_ncopy := LoadLibCryptoFunction('ASN1_mbstring_ncopy');
  if not assigned(ASN1_mbstring_ncopy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_mbstring_ncopy');
  Result := ASN1_mbstring_ncopy(out_,in_,len,inform,mask,minsize,maxsize);
end;

function Load_ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TOpenSSL_C_INT; inform: TOpenSSL_C_INT; nid: TOpenSSL_C_INT): PASN1_STRING; cdecl;
begin
  ASN1_STRING_set_by_NID := LoadLibCryptoFunction('ASN1_STRING_set_by_NID');
  if not assigned(ASN1_STRING_set_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_set_by_NID');
  Result := ASN1_STRING_set_by_NID(out_,in_,inlen,inform,nid);
end;

function Load_ASN1_STRING_TABLE_get(nid: TOpenSSL_C_INT): PASN1_STRING_TABLE; cdecl;
begin
  ASN1_STRING_TABLE_get := LoadLibCryptoFunction('ASN1_STRING_TABLE_get');
  if not assigned(ASN1_STRING_TABLE_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_TABLE_get');
  Result := ASN1_STRING_TABLE_get(nid);
end;

function Load_ASN1_STRING_TABLE_add(v1: TOpenSSL_C_INT; v2: TOpenSSL_C_LONG; v3: TOpenSSL_C_LONG; v4: TOpenSSL_C_ULONG; v5: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_STRING_TABLE_add := LoadLibCryptoFunction('ASN1_STRING_TABLE_add');
  if not assigned(ASN1_STRING_TABLE_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_TABLE_add');
  Result := ASN1_STRING_TABLE_add(v1,v2,v3,v4,v5);
end;

procedure Load_ASN1_STRING_TABLE_cleanup; cdecl;
begin
  ASN1_STRING_TABLE_cleanup := LoadLibCryptoFunction('ASN1_STRING_TABLE_cleanup');
  if not assigned(ASN1_STRING_TABLE_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_STRING_TABLE_cleanup');
  ASN1_STRING_TABLE_cleanup();
end;

function Load_ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  ASN1_item_new := LoadLibCryptoFunction('ASN1_item_new');
  if not assigned(ASN1_item_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_new');
  Result := ASN1_item_new(it);
end;

procedure Load_ASN1_item_free(val: PASN1_VALUE; const it: PASN1_ITEM); cdecl;
begin
  ASN1_item_free := LoadLibCryptoFunction('ASN1_item_free');
  if not assigned(ASN1_item_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_free');
  ASN1_item_free(val,it);
end;

function Load_ASN1_item_d2i(val: PPASN1_VALUE; const in_: PPByte; len: TOpenSSL_C_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  ASN1_item_d2i := LoadLibCryptoFunction('ASN1_item_d2i');
  if not assigned(ASN1_item_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_d2i');
  Result := ASN1_item_d2i(val,in_,len,it);
end;

function Load_ASN1_item_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_i2d := LoadLibCryptoFunction('ASN1_item_i2d');
  if not assigned(ASN1_item_i2d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_i2d');
  Result := ASN1_item_i2d(val,out_,it);
end;

function Load_ASN1_item_ndef_i2d(val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_ndef_i2d := LoadLibCryptoFunction('ASN1_item_ndef_i2d');
  if not assigned(ASN1_item_ndef_i2d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_ndef_i2d');
  Result := ASN1_item_ndef_i2d(val,out_,it);
end;

procedure Load_ASN1_add_oid_module; cdecl;
begin
  ASN1_add_oid_module := LoadLibCryptoFunction('ASN1_add_oid_module');
  if not assigned(ASN1_add_oid_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_add_oid_module');
  ASN1_add_oid_module();
end;

procedure Load_ASN1_add_stable_module; cdecl;
begin
  ASN1_add_stable_module := LoadLibCryptoFunction('ASN1_add_stable_module');
  if not assigned(ASN1_add_stable_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_add_stable_module');
  ASN1_add_stable_module();
end;

function Load_ASN1_generate_nconf(const str: PAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl;
begin
  ASN1_generate_nconf := LoadLibCryptoFunction('ASN1_generate_nconf');
  if not assigned(ASN1_generate_nconf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_generate_nconf');
  Result := ASN1_generate_nconf(str,nconf);
end;

function Load_ASN1_generate_v3(const str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl;
begin
  ASN1_generate_v3 := LoadLibCryptoFunction('ASN1_generate_v3');
  if not assigned(ASN1_generate_v3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_generate_v3');
  Result := ASN1_generate_v3(str,cnf);
end;

function Load_ASN1_str2mask(const str: PByte; pmask: POpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  ASN1_str2mask := LoadLibCryptoFunction('ASN1_str2mask');
  if not assigned(ASN1_str2mask) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_str2mask');
  Result := ASN1_str2mask(str,pmask);
end;

function Load_ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TOpenSSL_C_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  ASN1_item_print := LoadLibCryptoFunction('ASN1_item_print');
  if not assigned(ASN1_item_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_item_print');
  Result := ASN1_item_print(out_,ifld,indent,it,pctx);
end;

function Load_ASN1_PCTX_new: PASN1_PCTX; cdecl;
begin
  ASN1_PCTX_new := LoadLibCryptoFunction('ASN1_PCTX_new');
  if not assigned(ASN1_PCTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_new');
  Result := ASN1_PCTX_new();
end;

procedure Load_ASN1_PCTX_free(p: PASN1_PCTX); cdecl;
begin
  ASN1_PCTX_free := LoadLibCryptoFunction('ASN1_PCTX_free');
  if not assigned(ASN1_PCTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_free');
  ASN1_PCTX_free(p);
end;

function Load_ASN1_PCTX_get_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_PCTX_get_flags := LoadLibCryptoFunction('ASN1_PCTX_get_flags');
  if not assigned(ASN1_PCTX_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_flags');
  Result := ASN1_PCTX_get_flags(p);
end;

procedure Load_ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  ASN1_PCTX_set_flags := LoadLibCryptoFunction('ASN1_PCTX_set_flags');
  if not assigned(ASN1_PCTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_flags');
  ASN1_PCTX_set_flags(p,flags);
end;

function Load_ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_PCTX_get_nm_flags := LoadLibCryptoFunction('ASN1_PCTX_get_nm_flags');
  if not assigned(ASN1_PCTX_get_nm_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_nm_flags');
  Result := ASN1_PCTX_get_nm_flags(p);
end;

procedure Load_ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  ASN1_PCTX_set_nm_flags := LoadLibCryptoFunction('ASN1_PCTX_set_nm_flags');
  if not assigned(ASN1_PCTX_set_nm_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_nm_flags');
  ASN1_PCTX_set_nm_flags(p,flags);
end;

function Load_ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_PCTX_get_cert_flags := LoadLibCryptoFunction('ASN1_PCTX_get_cert_flags');
  if not assigned(ASN1_PCTX_get_cert_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_cert_flags');
  Result := ASN1_PCTX_get_cert_flags(p);
end;

procedure Load_ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  ASN1_PCTX_set_cert_flags := LoadLibCryptoFunction('ASN1_PCTX_set_cert_flags');
  if not assigned(ASN1_PCTX_set_cert_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_cert_flags');
  ASN1_PCTX_set_cert_flags(p,flags);
end;

function Load_ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_PCTX_get_oid_flags := LoadLibCryptoFunction('ASN1_PCTX_get_oid_flags');
  if not assigned(ASN1_PCTX_get_oid_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_oid_flags');
  Result := ASN1_PCTX_get_oid_flags(p);
end;

procedure Load_ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  ASN1_PCTX_set_oid_flags := LoadLibCryptoFunction('ASN1_PCTX_set_oid_flags');
  if not assigned(ASN1_PCTX_set_oid_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_oid_flags');
  ASN1_PCTX_set_oid_flags(p,flags);
end;

function Load_ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_PCTX_get_str_flags := LoadLibCryptoFunction('ASN1_PCTX_get_str_flags');
  if not assigned(ASN1_PCTX_get_str_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_get_str_flags');
  Result := ASN1_PCTX_get_str_flags(p);
end;

procedure Load_ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  ASN1_PCTX_set_str_flags := LoadLibCryptoFunction('ASN1_PCTX_set_str_flags');
  if not assigned(ASN1_PCTX_set_str_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_PCTX_set_str_flags');
  ASN1_PCTX_set_str_flags(p,flags);
end;

procedure Load_ASN1_SCTX_free(p: PASN1_SCTX); cdecl;
begin
  ASN1_SCTX_free := LoadLibCryptoFunction('ASN1_SCTX_free');
  if not assigned(ASN1_SCTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_free');
  ASN1_SCTX_free(p);
end;

function Load_ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl;
begin
  ASN1_SCTX_get_item := LoadLibCryptoFunction('ASN1_SCTX_get_item');
  if not assigned(ASN1_SCTX_get_item) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_item');
  Result := ASN1_SCTX_get_item(p);
end;

function Load_ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl;
begin
  ASN1_SCTX_get_template := LoadLibCryptoFunction('ASN1_SCTX_get_template');
  if not assigned(ASN1_SCTX_get_template) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_template');
  Result := ASN1_SCTX_get_template(p);
end;

function Load_ASN1_SCTX_get_flags(p: PASN1_SCTX): TOpenSSL_C_ULONG; cdecl;
begin
  ASN1_SCTX_get_flags := LoadLibCryptoFunction('ASN1_SCTX_get_flags');
  if not assigned(ASN1_SCTX_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_flags');
  Result := ASN1_SCTX_get_flags(p);
end;

procedure Load_ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl;
begin
  ASN1_SCTX_set_app_data := LoadLibCryptoFunction('ASN1_SCTX_set_app_data');
  if not assigned(ASN1_SCTX_set_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_set_app_data');
  ASN1_SCTX_set_app_data(p,data);
end;

function Load_ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl;
begin
  ASN1_SCTX_get_app_data := LoadLibCryptoFunction('ASN1_SCTX_get_app_data');
  if not assigned(ASN1_SCTX_get_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_SCTX_get_app_data');
  Result := ASN1_SCTX_get_app_data(p);
end;

function Load_BIO_f_asn1: PBIO_METHOD; cdecl;
begin
  BIO_f_asn1 := LoadLibCryptoFunction('BIO_f_asn1');
  if not assigned(BIO_f_asn1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_asn1');
  Result := BIO_f_asn1();
end;

function Load_BIO_new_NDEF(out_: PBIO; val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl;
begin
  BIO_new_NDEF := LoadLibCryptoFunction('BIO_new_NDEF');
  if not assigned(BIO_new_NDEF) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_NDEF');
  Result := BIO_new_NDEF(out_,val,it);
end;

function Load_i2d_ASN1_bio_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  i2d_ASN1_bio_stream := LoadLibCryptoFunction('i2d_ASN1_bio_stream');
  if not assigned(i2d_ASN1_bio_stream) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ASN1_bio_stream');
  Result := i2d_ASN1_bio_stream(out_,val,in_,flags,it);
end;

function Load_PEM_write_bio_ASN1_stream(out_: PBIO; val: PASN1_VALUE; in_: PBIO; flags: TOpenSSL_C_INT; const hdr: PAnsiChar; const it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_ASN1_stream := LoadLibCryptoFunction('PEM_write_bio_ASN1_stream');
  if not assigned(PEM_write_bio_ASN1_stream) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_ASN1_stream');
  Result := PEM_write_bio_ASN1_stream(out_,val,in_,flags,hdr,it);
end;

function Load_SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  SMIME_read_ASN1 := LoadLibCryptoFunction('SMIME_read_ASN1');
  if not assigned(SMIME_read_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_read_ASN1');
  Result := SMIME_read_ASN1(bio,bcont,it);
end;

function Load_SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SMIME_crlf_copy := LoadLibCryptoFunction('SMIME_crlf_copy');
  if not assigned(SMIME_crlf_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_crlf_copy');
  Result := SMIME_crlf_copy(in_,out_,flags);
end;

function Load_SMIME_text(in_: PBIO; out_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  SMIME_text := LoadLibCryptoFunction('SMIME_text');
  if not assigned(SMIME_text) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_text');
  Result := SMIME_text(in_,out_);
end;

function Load_ASN1_ITEM_lookup(const name: PAnsiChar): PASN1_ITEM; cdecl;
begin
  ASN1_ITEM_lookup := LoadLibCryptoFunction('ASN1_ITEM_lookup');
  if not assigned(ASN1_ITEM_lookup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ITEM_lookup');
  Result := ASN1_ITEM_lookup(name);
end;

function Load_ASN1_ITEM_get(i: TOpenSSL_C_SIZET): PASN1_ITEM; cdecl;
begin
  ASN1_ITEM_get := LoadLibCryptoFunction('ASN1_ITEM_get');
  if not assigned(ASN1_ITEM_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASN1_ITEM_get');
  Result := ASN1_ITEM_get(i);
end;


procedure UnLoad;
begin
  ASN1_TYPE_get := Load_ASN1_TYPE_get;
  ASN1_TYPE_set := Load_ASN1_TYPE_set;
  ASN1_TYPE_set1 := Load_ASN1_TYPE_set1;
  ASN1_TYPE_cmp := Load_ASN1_TYPE_cmp;
  ASN1_TYPE_pack_sequence := Load_ASN1_TYPE_pack_sequence;
  ASN1_TYPE_unpack_sequence := Load_ASN1_TYPE_unpack_sequence;
  ASN1_OBJECT_new := Load_ASN1_OBJECT_new;
  ASN1_OBJECT_free := Load_ASN1_OBJECT_free;
  i2d_ASN1_OBJECT := Load_i2d_ASN1_OBJECT;
  d2i_ASN1_OBJECT := Load_d2i_ASN1_OBJECT;
  ASN1_STRING_new := Load_ASN1_STRING_new;
  ASN1_STRING_free := Load_ASN1_STRING_free;
  ASN1_STRING_clear_free := Load_ASN1_STRING_clear_free;
  ASN1_STRING_copy := Load_ASN1_STRING_copy;
  ASN1_STRING_dup := Load_ASN1_STRING_dup;
  ASN1_STRING_type_new := Load_ASN1_STRING_type_new;
  ASN1_STRING_cmp := Load_ASN1_STRING_cmp;
  ASN1_STRING_set := Load_ASN1_STRING_set;
  ASN1_STRING_set0 := Load_ASN1_STRING_set0;
  ASN1_STRING_length := Load_ASN1_STRING_length;
  ASN1_STRING_length_set := Load_ASN1_STRING_length_set;
  ASN1_STRING_type := Load_ASN1_STRING_type;
  ASN1_STRING_get0_data := Load_ASN1_STRING_get0_data;
  ASN1_BIT_STRING_set := Load_ASN1_BIT_STRING_set;
  ASN1_BIT_STRING_set_bit := Load_ASN1_BIT_STRING_set_bit;
  ASN1_BIT_STRING_get_bit := Load_ASN1_BIT_STRING_get_bit;
  ASN1_BIT_STRING_check := Load_ASN1_BIT_STRING_check;
  ASN1_BIT_STRING_name_print := Load_ASN1_BIT_STRING_name_print;
  ASN1_BIT_STRING_num_asc := Load_ASN1_BIT_STRING_num_asc;
  ASN1_BIT_STRING_set_asc := Load_ASN1_BIT_STRING_set_asc;
  ASN1_INTEGER_new := Load_ASN1_INTEGER_new;
  ASN1_INTEGER_free := Load_ASN1_INTEGER_free;
  d2i_ASN1_INTEGER := Load_d2i_ASN1_INTEGER;
  i2d_ASN1_INTEGER := Load_i2d_ASN1_INTEGER;
  d2i_ASN1_UINTEGER := Load_d2i_ASN1_UINTEGER;
  ASN1_INTEGER_dup := Load_ASN1_INTEGER_dup;
  ASN1_INTEGER_cmp := Load_ASN1_INTEGER_cmp;
  ASN1_UTCTIME_check := Load_ASN1_UTCTIME_check;
  ASN1_UTCTIME_set := Load_ASN1_UTCTIME_set;
  ASN1_UTCTIME_adj := Load_ASN1_UTCTIME_adj;
  ASN1_UTCTIME_set_string := Load_ASN1_UTCTIME_set_string;
  ASN1_UTCTIME_cmp_time_t := Load_ASN1_UTCTIME_cmp_time_t;
  ASN1_GENERALIZEDTIME_check := Load_ASN1_GENERALIZEDTIME_check;
  ASN1_GENERALIZEDTIME_set := Load_ASN1_GENERALIZEDTIME_set;
  ASN1_GENERALIZEDTIME_adj := Load_ASN1_GENERALIZEDTIME_adj;
  ASN1_GENERALIZEDTIME_set_string := Load_ASN1_GENERALIZEDTIME_set_string;
  ASN1_TIME_diff := Load_ASN1_TIME_diff;
  ASN1_OCTET_STRING_dup := Load_ASN1_OCTET_STRING_dup;
  ASN1_OCTET_STRING_cmp := Load_ASN1_OCTET_STRING_cmp;
  ASN1_OCTET_STRING_set := Load_ASN1_OCTET_STRING_set;
  ASN1_OCTET_STRING_new := Load_ASN1_OCTET_STRING_new;
  ASN1_OCTET_STRING_free := Load_ASN1_OCTET_STRING_free;
  d2i_ASN1_OCTET_STRING := Load_d2i_ASN1_OCTET_STRING;
  i2d_ASN1_OCTET_STRING := Load_i2d_ASN1_OCTET_STRING;
  UTF8_getc := Load_UTF8_getc;
  UTF8_putc := Load_UTF8_putc;
  ASN1_UTCTIME_new := Load_ASN1_UTCTIME_new;
  ASN1_UTCTIME_free := Load_ASN1_UTCTIME_free;
  d2i_ASN1_UTCTIME := Load_d2i_ASN1_UTCTIME;
  i2d_ASN1_UTCTIME := Load_i2d_ASN1_UTCTIME;
  ASN1_GENERALIZEDTIME_new := Load_ASN1_GENERALIZEDTIME_new;
  ASN1_GENERALIZEDTIME_free := Load_ASN1_GENERALIZEDTIME_free;
  d2i_ASN1_GENERALIZEDTIME := Load_d2i_ASN1_GENERALIZEDTIME;
  i2d_ASN1_GENERALIZEDTIME := Load_i2d_ASN1_GENERALIZEDTIME;
  ASN1_TIME_new := Load_ASN1_TIME_new;
  ASN1_TIME_free := Load_ASN1_TIME_free;
  d2i_ASN1_TIME := Load_d2i_ASN1_TIME;
  i2d_ASN1_TIME := Load_i2d_ASN1_TIME;
  ASN1_TIME_set := Load_ASN1_TIME_set;
  ASN1_TIME_adj := Load_ASN1_TIME_adj;
  ASN1_TIME_check := Load_ASN1_TIME_check;
  ASN1_TIME_to_generalizedtime := Load_ASN1_TIME_to_generalizedtime;
  ASN1_TIME_set_string := Load_ASN1_TIME_set_string;
  ASN1_TIME_set_string_X509 := Load_ASN1_TIME_set_string_X509;
  ASN1_TIME_to_tm := Load_ASN1_TIME_to_tm;
  ASN1_TIME_normalize := Load_ASN1_TIME_normalize;
  ASN1_TIME_cmp_time_t := Load_ASN1_TIME_cmp_time_t;
  ASN1_TIME_compare := Load_ASN1_TIME_compare;
  i2a_ASN1_INTEGER := Load_i2a_ASN1_INTEGER;
  a2i_ASN1_INTEGER := Load_a2i_ASN1_INTEGER;
  i2a_ASN1_ENUMERATED := Load_i2a_ASN1_ENUMERATED;
  a2i_ASN1_ENUMERATED := Load_a2i_ASN1_ENUMERATED;
  i2a_ASN1_OBJECT := Load_i2a_ASN1_OBJECT;
  a2i_ASN1_STRING := Load_a2i_ASN1_STRING;
  i2a_ASN1_STRING := Load_i2a_ASN1_STRING;
  i2t_ASN1_OBJECT := Load_i2t_ASN1_OBJECT;
  a2d_ASN1_OBJECT := Load_a2d_ASN1_OBJECT;
  ASN1_OBJECT_create := Load_ASN1_OBJECT_create;
  ASN1_INTEGER_get_int64 := Load_ASN1_INTEGER_get_int64;
  ASN1_INTEGER_set_int64 := Load_ASN1_INTEGER_set_int64;
  ASN1_INTEGER_get_uint64 := Load_ASN1_INTEGER_get_uint64;
  ASN1_INTEGER_set_uint64 := Load_ASN1_INTEGER_set_uint64;
  ASN1_INTEGER_set := Load_ASN1_INTEGER_set;
  ASN1_INTEGER_get := Load_ASN1_INTEGER_get;
  BN_to_ASN1_INTEGER := Load_BN_to_ASN1_INTEGER;
  ASN1_INTEGER_to_BN := Load_ASN1_INTEGER_to_BN;
  ASN1_ENUMERATED_get_int64 := Load_ASN1_ENUMERATED_get_int64;
  ASN1_ENUMERATED_set_int64 := Load_ASN1_ENUMERATED_set_int64;
  ASN1_ENUMERATED_set := Load_ASN1_ENUMERATED_set;
  ASN1_ENUMERATED_get := Load_ASN1_ENUMERATED_get;
  BN_to_ASN1_ENUMERATED := Load_BN_to_ASN1_ENUMERATED;
  ASN1_ENUMERATED_to_BN := Load_ASN1_ENUMERATED_to_BN;
  ASN1_PRINTABLE_type := Load_ASN1_PRINTABLE_type;
  ASN1_tag2bit := Load_ASN1_tag2bit;
  ASN1_get_object := Load_ASN1_get_object;
  ASN1_check_infinite_end := Load_ASN1_check_infinite_end;
  ASN1_const_check_infinite_end := Load_ASN1_const_check_infinite_end;
  ASN1_put_object := Load_ASN1_put_object;
  ASN1_put_eoc := Load_ASN1_put_eoc;
  ASN1_object_size := Load_ASN1_object_size;
  ASN1_item_dup := Load_ASN1_item_dup;
  ASN1_STRING_to_UTF8 := Load_ASN1_STRING_to_UTF8;
  ASN1_d2i_bio := Load_ASN1_d2i_bio;
  ASN1_item_d2i_bio := Load_ASN1_item_d2i_bio;
  ASN1_i2d_bio := Load_ASN1_i2d_bio;
  ASN1_item_i2d_bio := Load_ASN1_item_i2d_bio;
  ASN1_UTCTIME_print := Load_ASN1_UTCTIME_print;
  ASN1_GENERALIZEDTIME_print := Load_ASN1_GENERALIZEDTIME_print;
  ASN1_TIME_print := Load_ASN1_TIME_print;
  ASN1_STRING_print := Load_ASN1_STRING_print;
  ASN1_STRING_print_ex := Load_ASN1_STRING_print_ex;
  ASN1_buf_print := Load_ASN1_buf_print;
  ASN1_bn_print := Load_ASN1_bn_print;
  ASN1_parse := Load_ASN1_parse;
  ASN1_parse_dump := Load_ASN1_parse_dump;
  ASN1_tag2str := Load_ASN1_tag2str;
  ASN1_UNIVERSALSTRING_to_string := Load_ASN1_UNIVERSALSTRING_to_string;
  ASN1_TYPE_set_octetstring := Load_ASN1_TYPE_set_octetstring;
  ASN1_TYPE_get_octetstring := Load_ASN1_TYPE_get_octetstring;
  ASN1_TYPE_set_int_octetstring := Load_ASN1_TYPE_set_int_octetstring;
  ASN1_TYPE_get_int_octetstring := Load_ASN1_TYPE_get_int_octetstring;
  ASN1_item_unpack := Load_ASN1_item_unpack;
  ASN1_item_pack := Load_ASN1_item_pack;
  ASN1_STRING_set_default_mask := Load_ASN1_STRING_set_default_mask;
  ASN1_STRING_set_default_mask_asc := Load_ASN1_STRING_set_default_mask_asc;
  ASN1_STRING_get_default_mask := Load_ASN1_STRING_get_default_mask;
  ASN1_mbstring_copy := Load_ASN1_mbstring_copy;
  ASN1_mbstring_ncopy := Load_ASN1_mbstring_ncopy;
  ASN1_STRING_set_by_NID := Load_ASN1_STRING_set_by_NID;
  ASN1_STRING_TABLE_get := Load_ASN1_STRING_TABLE_get;
  ASN1_STRING_TABLE_add := Load_ASN1_STRING_TABLE_add;
  ASN1_STRING_TABLE_cleanup := Load_ASN1_STRING_TABLE_cleanup;
  ASN1_item_new := Load_ASN1_item_new;
  ASN1_item_free := Load_ASN1_item_free;
  ASN1_item_d2i := Load_ASN1_item_d2i;
  ASN1_item_i2d := Load_ASN1_item_i2d;
  ASN1_item_ndef_i2d := Load_ASN1_item_ndef_i2d;
  ASN1_add_oid_module := Load_ASN1_add_oid_module;
  ASN1_add_stable_module := Load_ASN1_add_stable_module;
  ASN1_generate_nconf := Load_ASN1_generate_nconf;
  ASN1_generate_v3 := Load_ASN1_generate_v3;
  ASN1_str2mask := Load_ASN1_str2mask;
  ASN1_item_print := Load_ASN1_item_print;
  ASN1_PCTX_new := Load_ASN1_PCTX_new;
  ASN1_PCTX_free := Load_ASN1_PCTX_free;
  ASN1_PCTX_get_flags := Load_ASN1_PCTX_get_flags;
  ASN1_PCTX_set_flags := Load_ASN1_PCTX_set_flags;
  ASN1_PCTX_get_nm_flags := Load_ASN1_PCTX_get_nm_flags;
  ASN1_PCTX_set_nm_flags := Load_ASN1_PCTX_set_nm_flags;
  ASN1_PCTX_get_cert_flags := Load_ASN1_PCTX_get_cert_flags;
  ASN1_PCTX_set_cert_flags := Load_ASN1_PCTX_set_cert_flags;
  ASN1_PCTX_get_oid_flags := Load_ASN1_PCTX_get_oid_flags;
  ASN1_PCTX_set_oid_flags := Load_ASN1_PCTX_set_oid_flags;
  ASN1_PCTX_get_str_flags := Load_ASN1_PCTX_get_str_flags;
  ASN1_PCTX_set_str_flags := Load_ASN1_PCTX_set_str_flags;
  ASN1_SCTX_free := Load_ASN1_SCTX_free;
  ASN1_SCTX_get_item := Load_ASN1_SCTX_get_item;
  ASN1_SCTX_get_template := Load_ASN1_SCTX_get_template;
  ASN1_SCTX_get_flags := Load_ASN1_SCTX_get_flags;
  ASN1_SCTX_set_app_data := Load_ASN1_SCTX_set_app_data;
  ASN1_SCTX_get_app_data := Load_ASN1_SCTX_get_app_data;
  BIO_f_asn1 := Load_BIO_f_asn1;
  BIO_new_NDEF := Load_BIO_new_NDEF;
  i2d_ASN1_bio_stream := Load_i2d_ASN1_bio_stream;
  PEM_write_bio_ASN1_stream := Load_PEM_write_bio_ASN1_stream;
  SMIME_read_ASN1 := Load_SMIME_read_ASN1;
  SMIME_crlf_copy := Load_SMIME_crlf_copy;
  SMIME_text := Load_SMIME_text;
  ASN1_ITEM_lookup := Load_ASN1_ITEM_lookup;
  ASN1_ITEM_get := Load_ASN1_ITEM_get;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
