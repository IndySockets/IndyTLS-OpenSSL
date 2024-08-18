unit IdOpenSSLasn1;

interface

uses
  IdOpenSSLopensslconf,
  IdOpenSSLossl_typ,
  IdCTypes;

{
  Automatically converted by H2Pas 1.0.0 from asn1.h
  The following command line parameters were used:
  -p
  -P
  -t
  -T
  -C
  asn1.h
}

{ Pointers to basic pascal types, inserted by h2pas conversion program. }

Type
  PFILE = ^ FILE;
  // Ptype = ^_type;
{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}
  {
    * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
    *
    * Licensed under the OpenSSL license (the "License").  You may not use
    * this file except in compliance with the License.  You can obtain a copy
    * in the file LICENSE in the source distribution or at
    * https://www.openssl.org/source/license.html
  }
{$IFNDEF HEADER_ASN1_H}
{$DEFINE HEADER_ASN1_H}
  { /$include <time.h> }
  { /$include <openssl/e_os2.h> }
  { /$include <openssl/opensslconf.h> }
  { /$include <openssl/bio.h> }
  { /$include <openssl/stack.h> }
  { /$include <openssl/safestack.h> }
  { /$include <openssl/symhacks.h> }
  { /$include <openssl/ossl_typ.h> }
  { /$if OPENSSL_API_COMPAT < 0x10100000L }
  { /$include <openssl/bn.h> }
  { /$endif }
{$IFDEF OPENSSL_BUILD_SHLIBCRYPTO}
{$UNDEF OPENSSL_EXTERN}

const
  OPENSSL_EXTERN = OPENSSL_EXPORT;
{$ENDIF}
  { C++ extern C conditionnal removed }

const
  V_ASN1_UNIVERSAL = $00;
  V_ASN1_APPLICATION = $40;
  V_ASN1_CONTEXT_SPECIFIC = $80;
  V_ASN1_PRIVATE = $C0;
  V_ASN1_CONSTRUCTED = $20;
  V_ASN1_PRIMITIVE_TAG = $1F;
  V_ASN1_PRIMATIVE_TAG = $1F;
  { let the recipient choose }
  V_ASN1_APP_CHOOSE = -(2);
  { used in ASN1_TYPE }
  V_ASN1_OTHER = -(3);
  { used in ASN1 template code }
  V_ASN1_ANY = -(4);
  V_ASN1_UNDEF = -(1);
  { ASN.1 tag values }
  V_ASN1_EOC = 0;
  { }
  V_ASN1_BOOLEAN = 1;
  V_ASN1_INTEGER = 2;
  V_ASN1_BIT_STRING = 3;
  V_ASN1_OCTET_STRING = 4;
  V_ASN1_NULL = 5;
  V_ASN1_OBJECT = 6;
  V_ASN1_OBJECT_DESCRIPTOR = 7;
  V_ASN1_EXTERNAL = 8;
  V_ASN1_REAL = 9;
  V_ASN1_ENUMERATED = 10;
  V_ASN1_UTF8STRING = 12;
  V_ASN1_SEQUENCE = 16;
  V_ASN1_SET = 17;
  { }
  V_ASN1_NUMERICSTRING = 18;
  V_ASN1_PRINTABLESTRING = 19;
  V_ASN1_T61STRING = 20;
  { alias }
  V_ASN1_TELETEXSTRING = 20;
  { }
  V_ASN1_VIDEOTEXSTRING = 21;
  V_ASN1_IA5STRING = 22;
  V_ASN1_UTCTIME = 23;
  { }
  V_ASN1_GENERALIZEDTIME = 24;
  { }
  V_ASN1_GRAPHICSTRING = 25;
  { }
  V_ASN1_ISO64STRING = 26;
  { alias }
  V_ASN1_VISIBLESTRING = 26;
  { }
  V_ASN1_GENERALSTRING = 27;
  { }
  V_ASN1_UNIVERSALSTRING = 28;
  V_ASN1_BMPSTRING = 30;
  {
    * NB the constants below are used internally by ASN1_INTEGER
    * and ASN1_ENUMERATED to indicate the sign. They are *not* on
    * the wire tag values.
  }
  V_ASN1_NEG = $100;
  V_ASN1_NEG_INTEGER = 2 or V_ASN1_NEG;
  V_ASN1_NEG_ENUMERATED = 10 or V_ASN1_NEG;
  { For use with d2i_ASN1_type_bytes() }
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
  { For use with ASN1_mbstring_copy() }
  MBSTRING_FLAG = $1000;
  MBSTRING_UTF8 = MBSTRING_FLAG;
  MBSTRING_ASC = MBSTRING_FLAG or 1;
  MBSTRING_BMP = MBSTRING_FLAG or 2;
  MBSTRING_UNIV = MBSTRING_FLAG or 4;
  SMIME_OLDMIME = $400;
  SMIME_CRLFEOL = $800;
  SMIME_STREAM = $1000;
  ASN1_STRING_FLAG_BITS_LEFT = $08; // * Set if 0x07 has bits left value */

type
  PX509_algor_st = ^TX509_algor_st;

  TX509_algor_st = record
    { undefined structure }
  end;

  {
    * This indicates that the ASN1_STRING is not a real value but just a place
    * holder for the location where indefinite length constructed data should be
    * inserted in the memory buffer
  }
  {
    * This flag is used by the CMS code to indicate that a string is not
    * complete and is a place holder for content when it had all been accessed.
    * The flag will be reset when content has been written to it.
  }
  {
    * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
    * type.
  }
  { String is embedded and only content should be freed }
  { This is the base type that holds just about everything :-)
    in declarator_list *)
    * ASN1_ENCODING structure: this is used to save the received encoding of an
    * ASN1 type. This is useful to get round problems with invalid encodings
    * which can break signatures.
  }
  { DER encoding }
  { Length of encoding }
  { set to 1 if 'enc' is invalid }

type
  PASN1_ENCODING_st = ^TASN1_ENCODING_st;

  TASN1_ENCODING_st = record
    enc: PAnsiChar; // PAnsiChar;
    len: TIdC_LONG; // TIdC_LONG;
    modified: TIdC_INT; // TIdC_INT;
  end;

  ASN1_ENCODING = TASN1_ENCODING_st;
  TASN1_ENCODING = TASN1_ENCODING_st;
  PASN1_ENCODING = ^TASN1_ENCODING;

  { Used with ASN1 LONG type: if a long is set to this it is omitted }

const
  ASN1_LONG_UNDEF = $7FFFFFFF;
  STABLE_FLAGS_MALLOC = $01;
  {
    * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
    * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
    * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
    * STABLE_FLAGS_CLEAR to reflect this.
  }
  STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;
  STABLE_NO_MASK = $02;
  DIRSTRING_TYPE = ((B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING) or
    B_ASN1_BMPSTRING) or B_ASN1_UTF8STRING;
  PKCS9STRING_TYPE = DIRSTRING_TYPE or B_ASN1_IA5STRING;

type
  Pasn1_string_table_st = ^Tasn1_string_table_st;

  Tasn1_string_table_st = record
    nid: TIdC_INT;
    minsize: TIdC_LONG;
    maxsize: TIdC_LONG;
    mask: TIdC_ULONG;
    flags: TIdC_ULONG;
  end;

  TASN1_STRING_TABLE = Tasn1_string_table_st;
  PASN1_STRING_TABLE = ^TASN1_STRING_TABLE;
  { size limits: this stuff is taken straight from RFC2459 }
  (* error
    # define ub_name                         32768
    {
    * Declarations for template structures: for full definitions see asn1t.h
    }
    in declarator_list *)
  // TASN1_TLC_st = TASN1_TLC;
  { This is just an opaque pointer }
  PASN1_VALUE_st = Pointer;
  PASN1_VALUE = PASN1_VALUE_st;
  PPASN1_VALUE = ^PASN1_VALUE;

type

  { -
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
    * typedef struct SOMETHING_st
    *      ...
    *      ASN1_ITEM_EXP *iptr;
    *      ...
    *  SOMETHING;
    *
    * It would be initialised as e.g.:
    *
    * SOMETHING somevar = ...,ASN1_ITEM_ref(X509),...;
    *
    * and the actual pointer extracted with:
    *
    * const ASN1_ITEM *it = ASN1_ITEM_ptr(somevar.iptr);
    *
    * Finally an ASN1_ITEM pointer can be extracted from an
    * appropriate reference with: ASN1_ITEM_rptr(X509). This
    * would be used when a function takes an ASN1_ITEM * argument.
    *
  }
  PASN1_ITEM_EXP = ^ASN1_ITEM_EXP;

  ASN1_TEMPLATE_st = record
    flags: TIdC_ULONG; // * Various flags */
    tag: TIdC_LONG; // * tag, not used if no tagging */
    offset: TIdC_ULONG; // * Offset of this field in structure */
    field_name: PAnsiChar; // * Field name */
    item: PASN1_ITEM_EXP; // * Relevant ASN1_ITEM or ASN1_ADB */
  end;

  ASN1_TEMPLATE = ASN1_TEMPLATE_st;
  PASN1_TEMPLATE = ^ASN1_TEMPLATE;

  ASN1_ITEM_st = record
    itype: AnsiChar; { * The item type, primitive, SEQUENCE, CHOICE
      * or extern * }
    utype: TIdC_LONG; // * underlying type */
    templates: PASN1_TEMPLATE; { * If SEQUENCE or CHOICE this contains
      * the contents * }
    tcount: TIdC_LONG; // * Number of templates if SEQUENCE or CHOICE */
    funcs: Pointer; // * functions that handle this type */
    size: TIdC_LONG; // * Structure size (usually) */
    sname: PAnsiChar; // * Structure name */
  end;

  ASN1_ITEM = ASN1_ITEM_st;
  PASN1_ITEM = ^ASN1_ITEM;
{$IFNDEF OPENSSL_EXPORT_VAR_AS_FUNCTION}
  { ASN1_ITEM pointer exported type }
  ASN1_ITEM_EXP = ASN1_ITEM;

  { Macro to include ASN1_ITEM pointer from base type }
{$ELSE}
  {
    * Platforms that can't easily handle shared global variables are declared as
    * functions returning ASN1_ITEM pointers.
  }
  { ASN1_ITEM pointer exported type }
  { typedef const ASN1_ITEM *ASN1_ITEM_EXP (void);

    /* Macro to obtain ASN1_ITEM pointer from exported type }
  { was #define dname(params) para_def_expr }
  { argument types are unknown }
  { return type might be wrong }

function ASN1_ITEM_ptr(iptr: Longint): Longint;

{ Macro to include ASN1_ITEM pointer from base type }
(* error
  #  define ASN1_ITEM_ref(iptr) (iptr##_it)
  in define line 344 *)
(* error
  #  define ASN1_ITEM_rptr(ref) (ref##_it())
  in define line 346 *)
(* error
  const ASN1_ITEM * name##_it(void);
  in declaration at line 349 *)
{$ENDIF}
{ Parameters used by ASN1_STRING_print_ex() }
{
  * These determine which characters to escape: RFC2253 special characters,
  * control characters and MSB set characters
}

const
  ASN1_STRFLGS_ESC_2253 = 1;
  ASN1_STRFLGS_ESC_CTRL = 2;
  ASN1_STRFLGS_ESC_MSB = 4;
  {
    * This flag determines how we do escaping: normally RC2253 backslash only,
    * set this to use backslash and quote.
  }
  ASN1_STRFLGS_ESC_QUOTE = 8;
  { These three flags are internal use only. }
  { Character is a valid PrintableString character }
  CHARTYPE_PRINTABLESTRING = $10;
  { Character needs escaping if it is the first character }
  CHARTYPE_FIRST_ESC_2253 = $20;
  { Character needs escaping if it is the last character }
  CHARTYPE_LAST_ESC_2253 = $40;
  {
    * NB the internal flags are safely reused below by flags handled at the top
    * level.
  }
  {
    * If this is set we convert all character strings to UTF8 first
  }
  ASN1_STRFLGS_UTF8_CONVERT = $10;
  {
    * If this is set we don't attempt to interpret content: just assume all
    * strings are 1 byte per character. This will produce some pretty odd
    * looking output!
  }
  ASN1_STRFLGS_IGNORE_TYPE = $20;
  { If this is set we include the string type in the output }
  ASN1_STRFLGS_SHOW_TYPE = $40;
  {
    * This determines which strings to display and which to 'dump' (hex dump of
    * content octets or DER encoding). We can only dump non character strings or
    * everything. If we don't dump 'unknown' they are interpreted as character
    * strings with 1 octet per character and are subject to the usual escaping
    * options.
  }
  ASN1_STRFLGS_DUMP_ALL = $80;
  ASN1_STRFLGS_DUMP_UNKNOWN = $100;
  {
    * These determine what 'dumping' does, we can dump the content octets or the
    * DER encoding: both use the RFC2253 #XXXXX notation.
  }
  ASN1_STRFLGS_DUMP_DER = $200;
  {
    * This flag specifies that RC2254 escaping shall be performed.
  }
  ASN1_STRFLGS_ESC_2254 = $400;
  {
    * All the string flags consistent with RFC2253, escaping control characters
    * isn't essential in RFC2253 but it is advisable anyway.
  }
  ASN1_STRFLGS_RFC2253 = ((((ASN1_STRFLGS_ESC_2253 or ASN1_STRFLGS_ESC_CTRL) or
    ASN1_STRFLGS_ESC_MSB) or ASN1_STRFLGS_UTF8_CONVERT) or
    ASN1_STRFLGS_DUMP_UNKNOWN) or ASN1_STRFLGS_DUMP_DER;

type
  asn1_type_st = record
    _type: TIdC_INT;
    case Integer of
      0:
        (ptr: PAnsiChar);
      1:
        (_boolean: ASN1_BOOLEAN);
      2:
        (ASN1_STRING: PASN1_STRING);
      3:
        (_object: PASN1_OBJECT);
      4:
        (_integer: PASN1_INTEGER);
      5:
        (enumerated: PASN1_ENUMERATED);
      6:
        (bit_string: PASN1_BIT_STRING);
      7:
        (octet_string: PASN1_OCTET_STRING);
      8:
        (printablestring: PASN1_PRINTABLESTRING);
      9:
        (t61string: PASN1_T61STRING);
      10:
        (ia5string: PASN1_IA5STRING);
      11:
        (generalstring: PASN1_GENERALSTRING);
      12:
        (bmpstring: PASN1_BMPSTRING);
      13:
        (universalstring: ASN1_UNIVERSALSTRING);
      14:
        (utctime: PASN1_UTCTIME);
      15:
        (generalizedtime: PASN1_GENERALIZEDTIME);
      16:
        (visiblestring: PASN1_VISIBLESTRING);
      17:
        (utf8string: PASN1_UTF8STRING);
      { *
        * set and sequence are left complete and still contain the set or
        * sequence bytes
        * }
      18:
        (_set: PASN1_STRING);
      19:
        (sequence: PASN1_STRING);
      20:
        (_asn1_value: PASN1_VALUE);
  end;

  ASN1_TYPE = asn1_type_st;
  TASN1_TYPE = ASN1_TYPE;
  PASN1_TYPE = ^TASN1_TYPE;
  PPASN1_TYPE = ^PASN1_TYPE;

  PSTACK_OF_ASN1_TYPE = Pointer;
  ASN1_SEQUENCE_ANY = PSTACK_OF_ASN1_TYPE;

  // * This is used to contain a list of bit names */
  BIT_STRING_BITNAME_st = record
    bitnum: TIdC_INT;
    lname: PAnsiChar;
    sname: PAnsiChar;
  end;

  BIT_STRING_BITNAME = BIT_STRING_BITNAME_st;
  PBIT_STRING_BITNAME = ^BIT_STRING_BITNAME;

const
  B_ASN1_TIME = B_ASN1_UTCTIME or B_ASN1_GENERALIZEDTIME;

  B_ASN1_PRINTABLE = B_ASN1_NUMERICSTRING or B_ASN1_PRINTABLESTRING or
    B_ASN1_T61STRING or B_ASN1_IA5STRING or B_ASN1_BIT_STRING or
    B_ASN1_UNIVERSALSTRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING or
    B_ASN1_SEQUENCE or B_ASN1_UNKNOWN;

  B_ASN1_DIRECTORYSTRING = B_ASN1_PRINTABLESTRING or B_ASN1_TELETEXSTRING or
    B_ASN1_BMPSTRING or B_ASN1_UNIVERSALSTRING or B_ASN1_UTF8STRING;

  B_ASN1_DISPLAYTEXT = B_ASN1_IA5STRING or B_ASN1_VISIBLESTRING or
    B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;

  ASN1_PCTX_FLAGS_SHOW_ABSENT = $001;
  { Mark start and end of SEQUENCE }
  ASN1_PCTX_FLAGS_SHOW_SEQUENCE = $002;
  { Mark start and end of SEQUENCE/SET OF }
  ASN1_PCTX_FLAGS_SHOW_SSOF = $004;
  { Show the ASN1 type of primitives }
  ASN1_PCTX_FLAGS_SHOW_TYPE = $008;
  { Don't show ASN1 type of ANY }
  ASN1_PCTX_FLAGS_NO_ANY_TYPE = $010;
  { Don't show ASN1 type of MSTRINGs }
  ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = $020;
  { Don't show field names in SEQUENCE }
  ASN1_PCTX_FLAGS_NO_FIELD_NAME = $040;
  { Show structure names of each SEQUENCE field }
  ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;
  { Don't show structure name even at top level }
  ASN1_PCTX_FLAGS_NO_STRUCT_NAME = $100;

type
  Pd2i_of_void = function(a: PPointer; b: PPAnsiChar; c: TIdC_LONG)
    : Pointer cdecl;
  Pi2d_of_void = function(a: Pointer; b: PPAnsiChar): TIdC_INT cdecl;
  LPN_ASN1_TYPE_set = procedure(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer);
  LPN_ASN1_TYPE_set1 = function(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer)
    : TIdC_INT;
  LPN_ASN1_TYPE_cmp = function(a: PASN1_TYPE; b: PASN1_TYPE): TIdC_INT;
  LPN_ASN1_TYPE_pack_sequence = function(it: PASN1_ITEM; s: Pointer;
    t: PPASN1_TYPE): PASN1_TYPE;
  LPN_ASN1_TYPE_unpack_sequence = function(it: PASN1_ITEM;
    t: PASN1_TYPE): Pointer;
  LPN_ASN1_OBJECT_new = function: PASN1_OBJECT;
  LPN_ASN1_OBJECT_free = procedure(a: PASN1_OBJECT);
  LPN_i2d_ASN1_OBJECT = function(a: PASN1_OBJECT; pp: PPAnsiChar): TIdC_INT;
  LPN_d2i_ASN1_OBJECT = function(a: PPASN1_OBJECT; pp: PPAnsiChar;
    length: TIdC_LONG): PASN1_OBJECT;
  LPN_ASN1_STRING_free = procedure(a: PASN1_STRING);
  LPN_ASN1_STRING_clear_free = procedure(a: PASN1_STRING);
  LPN_ASN1_STRING_copy = function(dst: PASN1_STRING; str: PASN1_STRING)
    : TIdC_INT;
  LPN_ASN1_STRING_dup = function(a: PASN1_STRING): PASN1_STRING;
  LPN_ASN1_STRING_type_new = function(_type: TIdC_INT): PASN1_STRING;
  LPN_ASN1_STRING_cmp = function(a: PASN1_STRING; b: PASN1_STRING): TIdC_INT;
  {
    * Since this is used to store all sorts of things, via macros, for now,
    * make its data void *
  }
  LPN_ASN1_STRING_set = function(str: PASN1_STRING; data: Pointer;
    len: TIdC_INT): TIdC_INT;
  LPN_ASN1_STRING_set0 = procedure(str: PASN1_STRING; data: Pointer;
    len: TIdC_INT);
  LPN_ASN1_STRING_length = function(x: PASN1_STRING): TIdC_INT;
  LPN_ASN1_STRING_length_set = procedure(x: PASN1_STRING; n: TIdC_INT);
  LPN_ASN1_STRING_type = function(x: PASN1_STRING): TIdC_INT;

  LPN_ASN1_BIT_STRING_set = function(a: PASN1_BIT_STRING; d: PAnsiChar;
    length: TIdC_INT): TIdC_INT cdecl;
  LPN_ASN1_BIT_STRING_set_bit = function(a: PASN1_BIT_STRING; n: TIdC_INT;
    value: TIdC_INT): TIdC_INT cdecl;
  LPN_ASN1_BIT_STRING_get_bit = function(a: PASN1_BIT_STRING; n: TIdC_INT)
    : TIdC_INT cdecl;
  LPN_ASN1_BIT_STRING_check = function(a: ASN1_BIT_STRING; flags: PAnsiChar;
    flags_len: TIdC_INT): TIdC_INT cdecl;

  LPN_ASN1_BIT_STRING_name_print = function(_out: PBIO; bs: PASN1_BIT_STRING;
    tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT cdecl;
  LPN_ASN1_BIT_STRING_num_asc = function(name: PAnsiChar;
    tbl: PBIT_STRING_BITNAME): TIdC_INT;

  LPN_ASN1_BIT_STRING_set_asc = function(bs: PASN1_BIT_STRING; name: PAnsiChar;
    value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT;

  LPN_d2i_ASN1_UINTEGER = function(a: PPASN1_INTEGER; pp: PPAnsiChar;
    length: TIdC_LONG): PASN1_INTEGER cdecl;
  LPN_ASN1_INTEGER_dup = function(x: PASN1_INTEGER): PASN1_INTEGER cdecl;

  LPN_ASN1_INTEGER_cmp = function(x: PASN1_INTEGER; y: PASN1_INTEGER)
    : TIdC_INT cdecl;

  LPN_ASN1_UTCTIME_check = function(a: PASN1_UTCTIME): TIdC_INT;
  LPN_ASN1_UTCTIME_set = function(s: PASN1_UTCTIME; t: TIdC_TIMET)
    : PASN1_UTCTIME;
  LPN_ASN1_UTCTIME_adj = function(s: PASN1_UTCTIME; t: TIdC_TIMET;
    offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME;

  LPN_ASN1_UTCTIME_set_string = function(s: PASN1_UTCTIME; str: PAnsiChar)
    : TIdC_INT;

  LPN_ASN1_UTCTIME_cmp_time_t = function(s: PASN1_UTCTIME; t: TIdC_TIMET)
    : TIdC_INT;

  LPN_ASN1_GENERALIZEDTIME_check = function(a: PASN1_GENERALIZEDTIME): TIdC_INT;
  LPN_ASN1_GENERALIZEDTIME_set = function(s: PASN1_GENERALIZEDTIME;
    t: TIdC_TIMET): PASN1_GENERALIZEDTIME;
  LPN_ASN1_GENERALIZEDTIME_adj = function(s: PASN1_GENERALIZEDTIME;
    t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG)
    : PASN1_GENERALIZEDTIME;

  LPN_ASN1_GENERALIZEDTIME_set_string = function(s: PASN1_GENERALIZEDTIME;
    str: PAnsiChar): TIdC_INT;

  LPN_ASN1_TIME_diff = function(pday: TIdC_INT; psec: TIdC_INT;
    from: PASN1_TIME; _to: PASN1_TIME): TIdC_INT;

  LPN_ASN1_OCTET_STRING_dup = function(a: PASN1_OCTET_STRING)
    : PASN1_OCTET_STRING;

  LPN_ASN1_OCTET_STRING_cmp = function(a: PASN1_OCTET_STRING;
    b: PASN1_OCTET_STRING): TIdC_INT;

  LPN_ASN1_OCTET_STRING_set = function(str: PASN1_OCTET_STRING; data: PAnsiChar;
    len: TIdC_INT): TIdC_INT;

  LPN_UTF8_getc = function(str: PAnsiChar; len: TIdC_INT; val: PIdC_ULONG)
    : TIdC_INT cdecl;
  LPN_UTF8_putc = function(str: PAnsiChar; len: TIdC_INT; value: TIdC_ULONG)
    : TIdC_INT cdecl;
  LPN_ASN1_TIME_set = function(s: PASN1_TIME; t: TIdC_TIMET): PASN1_TIME cdecl;

  LPN_ASN1_TIME_adj = function(s: PASN1_TIME; t: TIdC_TIMET;
    offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME;

  LPN_ASN1_TIME_check = function(t: PASN1_TIME): TIdC_INT;

  LPN_ASN1_TIME_to_generalizedtime = function(t: PASN1_TIME;
    _out: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME;

  LPN_ASN1_TIME_set_string = function(s: PASN1_TIME; str: PAnsiChar): TIdC_INT;

  LPN_i2a_ASN1_INTEGER = function(bp: PBIO; a: PASN1_INTEGER): TIdC_INT;
  LPN_a2i_ASN1_INTEGER = function(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar;
    size: TIdC_INT): TIdC_INT;

  LPN_i2a_ASN1_ENUMERATED = function(bp: PBIO; a: PASN1_ENUMERATED): TIdC_INT;
  LPN_a2i_ASN1_ENUMERATED = function(bp: PBIO; bs: PASN1_ENUMERATED;
    buf: PAnsiChar; size: TIdC_INT): TIdC_INT;

  LPN_i2a_ASN1_OBJECT = function(bp: PBIO; a: PASN1_OBJECT): TIdC_INT;
  LPN_a2i_ASN1_STRING = function(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar;
    size: TIdC_INT): TIdC_INT;

  LPN_i2a_ASN1_STRING = function(bp: PBIO; a: PASN1_STRING; _type: TIdC_INT)
    : TIdC_INT;

  LPN_i2t_ASN1_OBJECT = function(buf: PAnsiChar; buf_len: TIdC_INT;
    a: PASN1_OBJECT): TIdC_INT;

  LPN_a2d_ASN1_OBJECT = function(out : PAnsiChar; olen: TIdC_INT;
    buf: PAnsiChar; num: TIdC_INT): TIdC_INT;

  LPN_ASN1_OBJECT_create = function(nid: TIdC_INT; data: PAnsiChar;
    len: TIdC_INT; sn: PAnsiChar; ln: PAnsiChar): PASN1_OBJECT;

  LPN_ASN1_INTEGER_get_int64 = function(pr: PIdC_INT64; a: PASN1_INTEGER)
    : TIdC_INT;
  LPN_ASN1_INTEGER_set_int64 = function(a: PASN1_INTEGER; r: TIdC_INT64)
    : TIdC_INT;

  LPN_ASN1_INTEGER_get_uint64 = function(pr: PIdC_UINT64; a: PASN1_INTEGER)
    : TIdC_INT;
  LPN_ASN1_INTEGER_set_uint64 = function(a: PASN1_INTEGER; r: TIdC_UINT64)
    : TIdC_INT;
  LPN_ASN1_INTEGER_set = function(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT;

  LPN_ASN1_INTEGER_get = function(a: PASN1_INTEGER): TIdC_LONG;

  LPN_BN_to_ASN1_INTEGER = function(bn: PBIGNUM; ai: PASN1_INTEGER)
    : PASN1_INTEGER;

  LPN_ASN1_INTEGER_to_BN = function(ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM;

  LPN_ASN1_ENUMERATED_get_int64 = function(pr: PIdC_INT64; a: PASN1_ENUMERATED)
    : TIdC_INT;
  LPN_ASN1_ENUMERATED_set_int64 = function(a: PASN1_ENUMERATED; r: TIdC_INT64)
    : TIdC_INT;
  LPN_ASN1_ENUMERATED_set = function(a: PASN1_ENUMERATED; v: TIdC_LONG)
    : TIdC_INT;

  LPN_ASN1_ENUMERATED_get = function(a: PASN1_ENUMERATED): TIdC_LONG;

  LPN_BN_to_ASN1_ENUMERATED = function(bn: PBIGNUM; ai: PASN1_ENUMERATED)
    : PASN1_ENUMERATED;

  LPN_ASN1_ENUMERATED_to_BN = function(ai: PASN1_ENUMERATED;
    bn: PBIGNUM): PBIGNUM;
  { General }
  { given a string, return the correct type, max is the maximum length }

  LPN_ASN1_PRINTABLE_type = function(s: PAnsiChar; max: TIdC_INT): TIdC_INT;
  LPN_ASN1_tag2bit = function(tag: TIdC_INT): TIdC_ULONG;
  { SPECIALS }

  LPN_ASN1_get_object = function(pp: PPAnsiChar; plength: PIdC_LONG;
    ptag: TIdC_INT; pclass: TIdC_INT; omax: TIdC_LONG): TIdC_INT;
  LPN_ASN1_check_infinite_end = function(p: PPAnsiChar; len: TIdC_LONG)
    : TIdC_INT;

  LPN_ASN1_const_check_infinite_end = function(p: PPAnsiChar; len: TIdC_LONG)
    : TIdC_INT;
  LPN_ASN1_put_object = procedure(pp: PPAnsiChar; constructed: TIdC_INT;
    length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT);
  LPN_ASN1_put_eoc = function(pp: PPAnsiChar): TIdC_INT;
  LPN_ASN1_object_size = function(constructed: TIdC_INT; length: TIdC_INT;
    tag: TIdC_INT): TIdC_INT;
  { Used to implement other functions }
  LPN_ASN1_dup = function(i2d: Pi2d_of_void; d2i: Pd2i_of_void;
    x: Pointer): Pointer;
  { was #define dname(params) para_def_expr }

  LPN_ASN1_item_dup = function(it: PASN1_ITEM; x: Pointer): Pointer;
  { ASN1 alloc/free macros for when a type is only used internally }
  { was #define dname(params) para_def_expr }
  { argument types are unknown }

  { was #define dname(params) para_def_expr }
  { argument types are unknown }
  { return type might be wrong }

{$IFNDEF OPENSSL_NO_STDIO}
  PASN1_d2i_fp_xnew = function: Pointer cdecl;

  LPN_ASN1_d2i_fp = function(xnew: PASN1_d2i_fp_xnew; d2i: Pd2i_of_void;
    _in: PFILE; x: PPointer): Pointer cdecl;

  LPN_ASN1_item_d2i_fp = function(it: PASN1_ITEM; _in: PFILE;
    x: Pointer): Pointer;
  LPN_ASN1_i2d_fp = function(i2d: Pi2d_of_void; _out: PFILE; x: Pointer)
    : TIdC_INT;
  { was #define dname(params) para_def_expr }
  { argument types are unknown }
  { return type might be wrong }
  LPN_ASN1_item_i2d_fp = function(it: PASN1_ITEM; out : PFILE; x: Pointer)
    : TIdC_INT;

  LPN_ASN1_STRING_print_ex_fp = function(fp: PFILE; str: PASN1_STRING;
    flags: TIdC_ULONG): TIdC_INT;
{$ENDIF}
  PASN1_d2i_bio_xnew = function: Pointer;
  LPN_ASN1_STRING_to_UTF8 = function(out : PPAnsiChar; _in: PASN1_STRING)
    : TIdC_INT;
  LPN_ASN1_d2i_bio = function(xnew: PASN1_d2i_bio_xnew; d2i: Pd2i_of_void;
    _in: PBIO; x: PPointer): Pointer;
  LPN_ASN1_item_d2i_bio = function(it: PASN1_ITEM; _in: PBIO;
    x: Pointer): Pointer;
  LPN_ASN1_i2d_bio = function(i2d: Pi2d_of_void; out : PBIO; x: PAnsiChar)
    : TIdC_INT;
  LPN_ASN1_item_i2d_bio = function(it: PASN1_ITEM; out : PBIO; x: Pointer)
    : TIdC_INT;

  LPN_ASN1_UTCTIME_print = function(fp: PBIO; a: PASN1_UTCTIME): TIdC_INT;

  LPN_ASN1_GENERALIZEDTIME_print = function(fp: PBIO; a: PASN1_GENERALIZEDTIME)
    : TIdC_INT;

  LPN_ASN1_TIME_print = function(fp: PBIO; a: PASN1_TIME): TIdC_INT;

  LPN_ASN1_STRING_print = function(bp: PBIO; v: PASN1_STRING): TIdC_INT;

  LPN_ASN1_STRING_print_ex = function(out : PBIO; str: PASN1_STRING;
    flags: TIdC_ULONG): TIdC_INT;

  LPN_ASN1_buf_print = function(bp: PBIO; buf: PAnsiChar; buflen: TIdC_SIZET;
    off: TIdC_INT): TIdC_INT;

  LPN_ASN1_bn_print = function(bp: PBIO; number: PAnsiChar; num: PBIGNUM;
    buf: PAnsiChar; off: TIdC_INT): TIdC_INT;

  LPN_ASN1_parse = function(bp: PBIO; pp: PAnsiChar; len: TIdC_LONG;
    indent: TIdC_INT): TIdC_INT;

  LPN_ASN1_parse_dump = function(bp: PBIO; pp: PAnsiChar; len: TIdC_LONG;
    indent: TIdC_INT; dump: TIdC_INT): TIdC_INT;

  LPN_ASN1_tag2str = function(tag: TIdC_INT): PAnsiChar;
  { Used to load and write Netscape format cert }
  LPN_ASN1_UNIVERSALSTRING_to_string = function(s: PASN1_UNIVERSALSTRING)
    : TIdC_INT;
  LPN_ASN1_TYPE_set_octetstring = function(a: PASN1_TYPE; data: PAnsiChar;
    len: TIdC_INT): TIdC_INT;

  LPN_ASN1_TYPE_get_octetstring = function(a: PASN1_TYPE; data: PAnsiChar;
    max_len: TIdC_INT): TIdC_INT;
  LPN_ASN1_TYPE_set_int_octetstring = function(a: PASN1_TYPE; num: TIdC_LONG;
    data: PAnsiChar; len: TIdC_INT): TIdC_INT;

  LPN_ASN1_TYPE_get_int_octetstring = function(a: PASN1_TYPE; num: PIdC_LONG;
    data: PAnsiChar; max_len: TIdC_INT): TIdC_INT;

  LPN_ASN1_item_unpack = function(oct: PASN1_STRING; it: PASN1_ITEM): Pointer;

  LPN_ASN1_item_pack = function(obj: Pointer; it: PASN1_ITEM;
    oct: PPASN1_OCTET_STRING): PASN1_STRING;
  LPN_ASN1_STRING_set_default_mask = procedure(mask: TIdC_ULONG);

  LPN_ASN1_STRING_set_default_mask_asc = function(p: PAnsiChar): TIdC_INT;
  LPN_ASN1_STRING_get_default_mask = function: TIdC_ULONG;

  LPN_ASN1_mbstring_copy = function(_out: PPASN1_STRING; _in: PAnsiChar;
    len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT;

  LPN_ASN1_mbstring_ncopy = function(_out: PPASN1_STRING; _in: PAnsiChar;
    len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG;
    maxsize: TIdC_LONG): TIdC_INT;

  LPN_ASN1_STRING_set_by_NID = function(_out: PPASN1_STRING; _in: PAnsiChar;
    inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING;
  LPN_ASN1_STRING_TABLE_get = function(nid: TIdC_INT): PASN1_STRING_TABLE;
  LPN_ASN1_STRING_TABLE_add = function(para1: TIdC_INT; para2: TIdC_LONG;
    para3: TIdC_LONG; para4: TIdC_ULONG; para5: TIdC_ULONG): TIdC_INT;
  LPN_ASN1_STRING_TABLE_cleanup = procedure cdecl;
  { ASN1 template functions }
  { Old API compatible functions }

  LPN_ASN1_item_new = function(it: PASN1_ITEM): PASN1_VALUE;

  LPN_ASN1_item_free = procedure(val: PASN1_VALUE; it: PASN1_ITEM);

  LPN_ASN1_item_d2i = function(val: PPASN1_VALUE; _in: PPAnsiChar;
    len: TIdC_LONG; it: PASN1_ITEM): PASN1_VALUE;

  LPN_ASN1_item_i2d = function(val: PASN1_VALUE; out : PPAnsiChar;
    it: PASN1_ITEM): TIdC_INT;

  LPN_ASN1_item_ndef_i2d = function(val: PASN1_VALUE; out : PPAnsiChar;
    it: PASN1_ITEM): TIdC_INT;
  LPN_ASN1_add_oid_module = procedure;
  LPN_ASN1_add_stable_module = procedure;

  LPN_ASN1_generate_nconf = function(str: PAnsiChar; nconf: PCONF): PASN1_TYPE;

  LPN_ASN1_generate_v3 = function(str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE;

  LPN_ASN1_str2mask = function(str: PAnsiChar; pmask: PIdC_ULONG): TIdC_INT;
  { ASN1 Print flags }
  { Indicate missing OPTIONAL fields }

  PASN1_SCTX_new_cb = function(ctx: PASN1_SCTX): TIdC_INT cdecl;

  LPN_ASN1_item_print = function(out : PBIO; ifld: PASN1_VALUE;
    indent: TIdC_INT; it: PASN1_ITEM; pctx: PASN1_PCTX): TIdC_INT;
  LPN_ASN1_PCTX_new = function: PASN1_PCTX;
  LPN_ASN1_PCTX_free = procedure(p: PASN1_PCTX);

  LPN_ASN1_PCTX_get_flags = function(p: PASN1_PCTX): TIdC_ULONG;
  LPN_ASN1_PCTX_set_flags = procedure(p: PASN1_PCTX; flags: TIdC_ULONG);

  LPN_ASN1_PCTX_get_nm_flags = function(p: PASN1_PCTX): TIdC_ULONG;
  LPN_ASN1_PCTX_set_nm_flags = procedure(p: PASN1_PCTX; flags: TIdC_ULONG);

  LPN_ASN1_PCTX_get_cert_flags = function(p: PASN1_PCTX): TIdC_ULONG;
  LPN_ASN1_PCTX_set_cert_flags = procedure(p: PASN1_PCTX; flags: TIdC_ULONG);

  LPN_ASN1_PCTX_get_oid_flags = function(p: PASN1_PCTX): TIdC_ULONG;
  LPN_ASN1_PCTX_set_oid_flags = procedure(p: PASN1_PCTX; flags: TIdC_ULONG);

  LPN_ASN1_PCTX_get_str_flags = function(p: PASN1_PCTX): TIdC_ULONG;
  LPN_ASN1_PCTX_set_str_flags = procedure(p: PASN1_PCTX; flags: TIdC_ULONG);
  LPN_ASN1_SCTX_new = function(scan_cb: PASN1_SCTX_new_cb): PASN1_SCTX;
  LPN_ASN1_SCTX_free = procedure(p: PASN1_SCTX);

  LPN_ASN1_SCTX_get_item = function(p: PASN1_SCTX): PASN1_ITEM;

  LPN_ASN1_SCTX_get_template = function(p: PASN1_SCTX): PASN1_TEMPLATE;
  LPN_ASN1_SCTX_get_flags = function(p: PASN1_SCTX): TIdC_ULONG;
  LPN_ASN1_SCTX_set_app_data = procedure(p: PASN1_SCTX; data: Pointer);
  LPN_ASN1_SCTX_get_app_data = function(p: PASN1_SCTX): Pointer;

  LPN_BIO_f_asn1 = function: PBIO_METHOD;

  LPN_BIO_new_NDEF = function(out : PBIO; val: PASN1_VALUE;
    it: PASN1_ITEM): PBIO;

  LPN_i2d_ASN1_bio_stream = function(out : PBIO; val: PASN1_VALUE; _in: PBIO;
    flags: TIdC_INT; it: PASN1_ITEM): TIdC_INT;

  LPN_PEM_write_bio_ASN1_stream = function(out : PBIO; val: PASN1_VALUE;
    _in: PBIO; flags: TIdC_INT; hdr: PAnsiChar; it: PASN1_ITEM): TIdC_INT;

  LPN_SMIME_read_ASN1 = function(bio: PBIO; bcont: PPBIO; it: PASN1_ITEM)
    : PASN1_VALUE cdecl;
  LPN_SMIME_crlf_copy = function(_in: PBIO; _out: PBIO; flags: TIdC_INT)
    : TIdC_INT cdecl;
  LPN_SMIME_text = function(_in: PBIO; _out: PBIO): TIdC_INT cdecl;

  { BEGIN ERROR CODES }
  {
    * The following lines are auto generated by the script mkerr.pl. Any changes
    * made after this point may be overwritten when the script is next run.
  }
  LPN_ERR_load_ASN1_strings = function: TIdC_INT;
  { Error codes for the ASN1 functions. }
  { Function codes. }

const
  ASN1_F_A2D_ASN1_OBJECT = 100;
  ASN1_F_A2I_ASN1_INTEGER = 102;
  ASN1_F_A2I_ASN1_STRING = 103;
  ASN1_F_APPEND_EXP = 176;
  ASN1_F_ASN1_BIT_STRING_SET_BIT = 183;
  ASN1_F_ASN1_CB = 177;
  ASN1_F_ASN1_CHECK_TLEN = 104;
  ASN1_F_ASN1_COLLECT = 106;
  ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108;
  ASN1_F_ASN1_D2I_FP = 109;
  ASN1_F_ASN1_D2I_READ_BIO = 107;
  ASN1_F_ASN1_DIGEST = 184;
  ASN1_F_ASN1_DO_ADB = 110;
  ASN1_F_ASN1_DO_LOCK = 233;
  ASN1_F_ASN1_DUP = 111;
  ASN1_F_ASN1_EX_C2I = 204;
  ASN1_F_ASN1_FIND_END = 190;
  ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216;
  ASN1_F_ASN1_GENERATE_V3 = 178;
  ASN1_F_ASN1_GET_INT64 = 224;
  ASN1_F_ASN1_GET_OBJECT = 114;
  ASN1_F_ASN1_GET_UINT64 = 225;
  ASN1_F_ASN1_I2D_BIO = 116;
  ASN1_F_ASN1_I2D_FP = 117;
  ASN1_F_ASN1_ITEM_D2I_FP = 206;
  ASN1_F_ASN1_ITEM_DUP = 191;
  ASN1_F_ASN1_ITEM_EMBED_D2I = 120;
  ASN1_F_ASN1_ITEM_EMBED_NEW = 121;
  ASN1_F_ASN1_ITEM_I2D_BIO = 192;
  ASN1_F_ASN1_ITEM_I2D_FP = 193;
  ASN1_F_ASN1_ITEM_PACK = 198;
  ASN1_F_ASN1_ITEM_SIGN = 195;
  ASN1_F_ASN1_ITEM_SIGN_CTX = 220;
  ASN1_F_ASN1_ITEM_UNPACK = 199;
  ASN1_F_ASN1_ITEM_VERIFY = 197;
  ASN1_F_ASN1_MBSTRING_NCOPY = 122;
  ASN1_F_ASN1_OBJECT_NEW = 123;
  ASN1_F_ASN1_OUTPUT_DATA = 214;
  ASN1_F_ASN1_PCTX_NEW = 205;
  ASN1_F_ASN1_SCTX_NEW = 221;
  ASN1_F_ASN1_SIGN = 128;
  ASN1_F_ASN1_STR2TYPE = 179;
  ASN1_F_ASN1_STRING_GET_INT64 = 227;
  ASN1_F_ASN1_STRING_GET_UINT64 = 230;
  ASN1_F_ASN1_STRING_SET = 186;
  ASN1_F_ASN1_STRING_TABLE_ADD = 129;
  ASN1_F_ASN1_STRING_TO_BN = 228;
  ASN1_F_ASN1_STRING_TYPE_NEW = 130;
  ASN1_F_ASN1_TEMPLATE_EX_D2I = 132;
  ASN1_F_ASN1_TEMPLATE_NEW = 133;
  ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131;
  ASN1_F_ASN1_TIME_ADJ = 217;
  ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134;
  ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135;
  ASN1_F_ASN1_UTCTIME_ADJ = 218;
  ASN1_F_ASN1_VERIFY = 137;
  ASN1_F_B64_READ_ASN1 = 209;
  ASN1_F_B64_WRITE_ASN1 = 210;
  ASN1_F_BIO_NEW_NDEF = 208;
  ASN1_F_BITSTR_CB = 180;
  ASN1_F_BN_TO_ASN1_STRING = 229;
  ASN1_F_C2I_ASN1_BIT_STRING = 189;
  ASN1_F_C2I_ASN1_INTEGER = 194;
  ASN1_F_C2I_ASN1_OBJECT = 196;
  ASN1_F_C2I_IBUF = 226;
  ASN1_F_C2I_UINT64_INT = 101;
  ASN1_F_COLLECT_DATA = 140;
  ASN1_F_D2I_ASN1_OBJECT = 147;
  ASN1_F_D2I_ASN1_UINTEGER = 150;
  ASN1_F_D2I_AUTOPRIVATEKEY = 207;
  ASN1_F_D2I_PRIVATEKEY = 154;
  ASN1_F_D2I_PUBLICKEY = 155;
  ASN1_F_DO_BUF = 142;
  ASN1_F_DO_TCREATE = 222;
  ASN1_F_I2D_ASN1_BIO_STREAM = 211;
  ASN1_F_I2D_ASN1_OBJECT = 143;
  ASN1_F_I2D_DSA_PUBKEY = 161;
  ASN1_F_I2D_EC_PUBKEY = 181;
  ASN1_F_I2D_PRIVATEKEY = 163;
  ASN1_F_I2D_PUBLICKEY = 164;
  ASN1_F_I2D_RSA_PUBKEY = 165;
  ASN1_F_LONG_C2I = 166;
  ASN1_F_OID_MODULE_INIT = 174;
  ASN1_F_PARSE_TAGGING = 182;
  ASN1_F_PKCS5_PBE2_SET_IV = 167;
  ASN1_F_PKCS5_PBE2_SET_SCRYPT = 231;
  ASN1_F_PKCS5_PBE_SET = 202;
  ASN1_F_PKCS5_PBE_SET0_ALGOR = 215;
  ASN1_F_PKCS5_PBKDF2_SET = 219;
  ASN1_F_PKCS5_SCRYPT_SET = 232;
  ASN1_F_SMIME_READ_ASN1 = 212;
  ASN1_F_SMIME_TEXT = 213;
  ASN1_F_STBL_MODULE_INIT = 223;
  ASN1_F_UINT32_C2I = 105;
  ASN1_F_UINT64_C2I = 112;
  ASN1_F_X509_CRL_ADD0_REVOKED = 169;
  ASN1_F_X509_INFO_NEW = 170;
  ASN1_F_X509_NAME_ENCODE = 203;
  ASN1_F_X509_NAME_EX_D2I = 158;
  ASN1_F_X509_NAME_EX_NEW = 171;
  ASN1_F_X509_PKEY_NEW = 173;
  { Reason codes. }
  ASN1_R_ADDING_OBJECT = 171;
  ASN1_R_ASN1_PARSE_ERROR = 203;
  ASN1_R_ASN1_SIG_PARSE_ERROR = 204;
  ASN1_R_AUX_ERROR = 100;
  ASN1_R_BAD_OBJECT_HEADER = 102;
  ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214;
  ASN1_R_BN_LIB = 105;
  ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106;
  ASN1_R_BUFFER_TOO_SMALL = 107;
  ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108;
  ASN1_R_CONTEXT_NOT_INITIALISED = 217;
  ASN1_R_DATA_IS_WRONG = 109;
  ASN1_R_DECODE_ERROR = 110;
  ASN1_R_DEPTH_EXCEEDED = 174;
  ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198;
  ASN1_R_ENCODE_ERROR = 112;
  ASN1_R_ERROR_GETTING_TIME = 173;
  ASN1_R_ERROR_LOADING_SECTION = 172;
  ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114;
  ASN1_R_EXPECTING_AN_INTEGER = 115;
  ASN1_R_EXPECTING_AN_OBJECT = 116;
  ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119;
  ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120;
  ASN1_R_FIELD_MISSING = 121;
  ASN1_R_FIRST_NUM_TOO_LARGE = 122;
  ASN1_R_HEADER_TOO_LONG = 123;
  ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175;
  ASN1_R_ILLEGAL_BOOLEAN = 176;
  ASN1_R_ILLEGAL_CHARACTERS = 124;
  ASN1_R_ILLEGAL_FORMAT = 177;
  ASN1_R_ILLEGAL_HEX = 178;
  ASN1_R_ILLEGAL_IMPLICIT_TAG = 179;
  ASN1_R_ILLEGAL_INTEGER = 180;
  ASN1_R_ILLEGAL_NEGATIVE_VALUE = 226;
  ASN1_R_ILLEGAL_NESTED_TAGGING = 181;
  ASN1_R_ILLEGAL_NULL = 125;
  ASN1_R_ILLEGAL_NULL_VALUE = 182;
  ASN1_R_ILLEGAL_OBJECT = 183;
  ASN1_R_ILLEGAL_OPTIONAL_ANY = 126;
  ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170;
  ASN1_R_ILLEGAL_PADDING = 221;
  ASN1_R_ILLEGAL_TAGGED_ANY = 127;
  ASN1_R_ILLEGAL_TIME_VALUE = 184;
  ASN1_R_ILLEGAL_ZERO_CONTENT = 222;
  ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185;
  ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128;
  ASN1_R_INVALID_BIT_STRING_BITS_LEFT = 220;
  ASN1_R_INVALID_BMPSTRING_LENGTH = 129;
  ASN1_R_INVALID_DIGIT = 130;
  ASN1_R_INVALID_MIME_TYPE = 205;
  ASN1_R_INVALID_MODIFIER = 186;
  ASN1_R_INVALID_NUMBER = 187;
  ASN1_R_INVALID_OBJECT_ENCODING = 216;
  ASN1_R_INVALID_SCRYPT_PARAMETERS = 227;
  ASN1_R_INVALID_SEPARATOR = 131;
  ASN1_R_INVALID_STRING_TABLE_VALUE = 218;
  ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133;
  ASN1_R_INVALID_UTF8STRING = 134;
  ASN1_R_INVALID_VALUE = 219;
  ASN1_R_LIST_ERROR = 188;
  ASN1_R_MIME_NO_CONTENT_TYPE = 206;
  ASN1_R_MIME_PARSE_ERROR = 207;
  ASN1_R_MIME_SIG_PARSE_ERROR = 208;
  ASN1_R_MISSING_EOC = 137;
  ASN1_R_MISSING_SECOND_NUMBER = 138;
  ASN1_R_MISSING_VALUE = 189;
  ASN1_R_MSTRING_NOT_UNIVERSAL = 139;
  ASN1_R_MSTRING_WRONG_TAG = 140;
  ASN1_R_NESTED_ASN1_STRING = 197;
  ASN1_R_NESTED_TOO_DEEP = 201;
  ASN1_R_NON_HEX_CHARACTERS = 141;
  ASN1_R_NOT_ASCII_FORMAT = 190;
  ASN1_R_NOT_ENOUGH_DATA = 142;
  ASN1_R_NO_CONTENT_TYPE = 209;
  ASN1_R_NO_MATCHING_CHOICE_TYPE = 143;
  ASN1_R_NO_MULTIPART_BODY_FAILURE = 210;
  ASN1_R_NO_MULTIPART_BOUNDARY = 211;
  ASN1_R_NO_SIG_CONTENT_TYPE = 212;
  ASN1_R_NULL_IS_WRONG_LENGTH = 144;
  ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191;
  ASN1_R_ODD_NUMBER_OF_CHARS = 145;
  ASN1_R_SECOND_NUMBER_TOO_LARGE = 147;
  ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148;
  ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149;
  ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192;
  ASN1_R_SHORT_LINE = 150;
  ASN1_R_SIG_INVALID_MIME_TYPE = 213;
  ASN1_R_STREAMING_NOT_SUPPORTED = 202;
  ASN1_R_STRING_TOO_LONG = 151;
  ASN1_R_STRING_TOO_SHORT = 152;
  ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;
  ASN1_R_TIME_NOT_ASCII_FORMAT = 193;
  ASN1_R_TOO_LARGE = 223;
  ASN1_R_TOO_LONG = 155;
  ASN1_R_TOO_SMALL = 224;
  ASN1_R_TYPE_NOT_CONSTRUCTED = 156;
  ASN1_R_TYPE_NOT_PRIMITIVE = 195;
  ASN1_R_UNEXPECTED_EOC = 159;
  ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215;
  ASN1_R_UNKNOWN_FORMAT = 160;
  ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161;
  ASN1_R_UNKNOWN_OBJECT_TYPE = 162;
  ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163;
  ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199;
  ASN1_R_UNKNOWN_TAG = 194;
  ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164;
  ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167;
  ASN1_R_UNSUPPORTED_TYPE = 196;
  ASN1_R_WRONG_INTEGER_TYPE = 225;
  ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200;
  ASN1_R_WRONG_TAG = 168;
{$ENDIF}

var
  ASN1_TYPE_set: LPN_ASN1_TYPE_set;
  ASN1_TYPE_set1: LPN_ASN1_TYPE_set1;
  ASN1_TYPE_cmp: LPN_ASN1_TYPE_cmp;
  ASN1_TYPE_pack_sequence: LPN_ASN1_TYPE_pack_sequence;
  ASN1_TYPE_unpack_sequence: LPN_ASN1_TYPE_unpack_sequence;
  ASN1_OBJECT_new: LPN_ASN1_OBJECT_new;
  ASN1_OBJECT_free: LPN_ASN1_OBJECT_free;
  i2d_ASN1_OBJECT: LPN_i2d_ASN1_OBJECT;
  d2i_ASN1_OBJECT: LPN_d2i_ASN1_OBJECT;
  ASN1_STRING_free: LPN_ASN1_STRING_free;
  ASN1_STRING_clear_free: LPN_ASN1_STRING_clear_free;
  ASN1_STRING_copy: LPN_ASN1_STRING_copy;
  ASN1_STRING_dup: LPN_ASN1_STRING_dup;
  ASN1_STRING_type_new: LPN_ASN1_STRING_type_new;
  ASN1_STRING_cmp: LPN_ASN1_STRING_cmp;
  ASN1_STRING_set: LPN_ASN1_STRING_set;
  ASN1_STRING_set0: LPN_ASN1_STRING_set0;
  ASN1_STRING_length: LPN_ASN1_STRING_length;
  ASN1_STRING_length_set: LPN_ASN1_STRING_length_set;
  ASN1_STRING_type: LPN_ASN1_STRING_type;
  ASN1_BIT_STRING_set: LPN_ASN1_BIT_STRING_set;
  ASN1_BIT_STRING_set_bit: LPN_ASN1_BIT_STRING_set_bit;
  ASN1_BIT_STRING_get_bit: LPN_ASN1_BIT_STRING_get_bit;
  ASN1_BIT_STRING_check: LPN_ASN1_BIT_STRING_check;
  ASN1_BIT_STRING_name_print: LPN_ASN1_BIT_STRING_name_print;
  ASN1_BIT_STRING_num_asc: LPN_ASN1_BIT_STRING_num_asc;
  ASN1_BIT_STRING_set_asc: LPN_ASN1_BIT_STRING_set_asc;
  d2i_ASN1_UINTEGER: LPN_d2i_ASN1_UINTEGER;
  ASN1_INTEGER_dup: LPN_ASN1_INTEGER_dup;
  ASN1_INTEGER_cmp: LPN_ASN1_INTEGER_cmp;
  ASN1_UTCTIME_check: LPN_ASN1_UTCTIME_check;
  ASN1_UTCTIME_set: LPN_ASN1_UTCTIME_set;
  ASN1_UTCTIME_adj: LPN_ASN1_UTCTIME_adj;
  ASN1_UTCTIME_set_string: LPN_ASN1_UTCTIME_set_string;

  ASN1_UTCTIME_cmp_time_t: LPN_ASN1_UTCTIME_cmp_time_t;

  ASN1_GENERALIZEDTIME_check: LPN_ASN1_GENERALIZEDTIME_check;
  ASN1_GENERALIZEDTIME_set: LPN_ASN1_GENERALIZEDTIME_set;
  ASN1_GENERALIZEDTIME_adj: LPN_ASN1_GENERALIZEDTIME_adj;
  ASN1_GENERALIZEDTIME_set_string: LPN_ASN1_GENERALIZEDTIME_set_string;
  ASN1_TIME_diff: LPN_ASN1_TIME_diff;
  ASN1_OCTET_STRING_dup: LPN_ASN1_OCTET_STRING_dup;
  ASN1_OCTET_STRING_cmp: LPN_ASN1_OCTET_STRING_cmp;
  ASN1_OCTET_STRING_set: LPN_ASN1_OCTET_STRING_set;
  UTF8_getc: LPN_UTF8_getc;
  UTF8_putc: LPN_UTF8_putc;
  ASN1_TIME_adj: LPN_ASN1_TIME_adj;
  ASN1_TIME_check: LPN_ASN1_TIME_check;
  ASN1_TIME_to_generalizedtime: LPN_ASN1_TIME_to_generalizedtime;
  ASN1_TIME_set_string: LPN_ASN1_TIME_set_string;
  i2a_ASN1_INTEGER: LPN_i2a_ASN1_INTEGER;
  a2i_ASN1_INTEGER: LPN_a2i_ASN1_INTEGER;
  i2a_ASN1_ENUMERATED: LPN_i2a_ASN1_ENUMERATED;
  a2i_ASN1_ENUMERATED: LPN_a2i_ASN1_ENUMERATED;
  i2a_ASN1_OBJECT: LPN_i2a_ASN1_OBJECT;
  a2i_ASN1_STRING: LPN_a2i_ASN1_STRING;
  i2a_ASN1_STRING: LPN_i2a_ASN1_STRING;
  i2t_ASN1_OBJECT: LPN_i2t_ASN1_OBJECT;
  a2d_ASN1_OBJECT: LPN_a2d_ASN1_OBJECT;
  ASN1_OBJECT_create: LPN_ASN1_OBJECT_create;
  ASN1_INTEGER_get_int64: LPN_ASN1_INTEGER_get_int64;
  ASN1_INTEGER_set_int64: LPN_ASN1_INTEGER_set_int64;
  ASN1_INTEGER_get_uint64: LPN_ASN1_INTEGER_get_uint64;
  ASN1_INTEGER_set: LPN_ASN1_INTEGER_set;
  ASN1_INTEGER_get: LPN_ASN1_INTEGER_get;
  BN_to_ASN1_INTEGER: LPN_BN_to_ASN1_INTEGER;
  ASN1_INTEGER_to_BN: LPN_ASN1_INTEGER_to_BN;
  ASN1_ENUMERATED_get_int64: LPN_ASN1_ENUMERATED_get_int64;
  ASN1_ENUMERATED_set_int64: LPN_ASN1_ENUMERATED_set_int64;
  ASN1_ENUMERATED_set: LPN_ASN1_ENUMERATED_set;
  ASN1_ENUMERATED_get: LPN_ASN1_ENUMERATED_get;
  BN_to_ASN1_ENUMERATED: LPN_BN_to_ASN1_ENUMERATED;
  ASN1_ENUMERATED_to_BN: LPN_ASN1_ENUMERATED_to_BN;
  ASN1_PRINTABLE_type: LPN_ASN1_PRINTABLE_type;
  ASN1_tag2bit: LPN_ASN1_tag2bit;
  ASN1_get_object: LPN_ASN1_get_object;
  ASN1_check_infinite_end: LPN_ASN1_check_infinite_end;
  ASN1_const_check_infinite_end: LPN_ASN1_const_check_infinite_end;
  ASN1_put_object: LPN_ASN1_put_object;
  ASN1_put_eoc: LPN_ASN1_put_eoc;
  ASN1_dup: LPN_ASN1_dup;
  ASN1_item_dup: LPN_ASN1_item_dup;
  ASN1_d2i_fp: LPN_ASN1_d2i_fp;
  ASN1_item_d2i_fp: LPN_ASN1_item_d2i_fp;
  ASN1_i2d_fp: LPN_ASN1_i2d_fp;
  ASN1_item_i2d_fp: LPN_ASN1_item_i2d_fp;
  ASN1_STRING_print_ex_fp: LPN_ASN1_STRING_print_ex_fp;
  ASN1_STRING_to_UTF8: LPN_ASN1_STRING_to_UTF8;
  ASN1_d2i_bio: LPN_ASN1_d2i_bio;
  ASN1_item_d2i_bio: LPN_ASN1_item_d2i_bio;
  ASN1_i2d_bio: LPN_ASN1_i2d_bio;
  ASN1_item_i2d_bio: LPN_ASN1_item_i2d_bio;
  ASN1_UTCTIME_print: LPN_ASN1_UTCTIME_print;
  ASN1_GENERALIZEDTIME_print: LPN_ASN1_GENERALIZEDTIME_print;
  ASN1_TIME_print: LPN_ASN1_TIME_print;
  ASN1_STRING_print: LPN_ASN1_STRING_print;
  ASN1_STRING_print_ex: LPN_ASN1_STRING_print_ex;
  ASN1_buf_print: LPN_ASN1_buf_print;
  ASN1_bn_print: LPN_ASN1_bn_print;
  ASN1_parse: LPN_ASN1_parse;
  ASN1_parse_dump: LPN_ASN1_parse_dump;
  ASN1_tag2str: LPN_ASN1_tag2str;
  ASN1_TYPE_set_octetstring: LPN_ASN1_TYPE_set_octetstring;
  ASN1_TYPE_get_octetstring: LPN_ASN1_TYPE_get_octetstring;
  ASN1_TYPE_set_int_octetstring: LPN_ASN1_TYPE_set_int_octetstring;
  ASN1_TYPE_get_int_octetstring: LPN_ASN1_TYPE_get_int_octetstring;
  ASN1_item_unpack: LPN_ASN1_item_unpack;
  ASN1_item_pack: LPN_ASN1_item_pack;
  ASN1_STRING_set_default_mask: LPN_ASN1_STRING_set_default_mask;
  ASN1_STRING_set_default_mask_asc: LPN_ASN1_STRING_set_default_mask_asc;
  ASN1_STRING_get_default_mask: LPN_ASN1_STRING_get_default_mask;
  ASN1_mbstring_copy: LPN_ASN1_mbstring_copy;
  ASN1_mbstring_ncopy: LPN_ASN1_mbstring_ncopy;
  ASN1_STRING_set_by_NID: LPN_ASN1_STRING_set_by_NID;
  ASN1_STRING_TABLE_get: LPN_ASN1_STRING_TABLE_get;
  ASN1_STRING_TABLE_add: LPN_ASN1_STRING_TABLE_add;
  ASN1_STRING_TABLE_cleanup: LPN_ASN1_STRING_TABLE_cleanup;
  ASN1_item_new: LPN_ASN1_item_new;
  ASN1_item_free: LPN_ASN1_item_free;
  ASN1_item_d2i: LPN_ASN1_item_d2i;
  ASN1_item_i2d: LPN_ASN1_item_i2d;
  ASN1_item_ndef_i2d: LPN_ASN1_item_ndef_i2d;
  ASN1_add_oid_module: LPN_ASN1_add_oid_module;
  ASN1_add_stable_module: LPN_ASN1_add_stable_module;
  ASN1_generate_nconf: LPN_ASN1_generate_nconf;
  ASN1_generate_v3: LPN_ASN1_generate_v3;
  ASN1_str2mask: LPN_ASN1_str2mask;
  ASN1_PCTX_new: LPN_ASN1_PCTX_new;
  ASN1_PCTX_free: LPN_ASN1_PCTX_free;
  ASN1_PCTX_get_flags: LPN_ASN1_PCTX_get_flags;
  ASN1_PCTX_set_flags: LPN_ASN1_PCTX_set_flags;
  ASN1_PCTX_get_nm_flags: LPN_ASN1_PCTX_get_nm_flags;
  ASN1_PCTX_set_nm_flags: LPN_ASN1_PCTX_set_nm_flags;
  ASN1_PCTX_get_cert_flags: LPN_ASN1_PCTX_get_cert_flags;
  ASN1_PCTX_set_cert_flags: LPN_ASN1_PCTX_set_cert_flags;
  ASN1_PCTX_get_oid_flags: LPN_ASN1_PCTX_get_oid_flags;
  ASN1_PCTX_set_oid_flags: LPN_ASN1_PCTX_set_oid_flags;
  ASN1_PCTX_get_str_flags: LPN_ASN1_PCTX_get_str_flags;
  ASN1_PCTX_set_str_flags: LPN_ASN1_PCTX_set_str_flags;
  ASN1_SCTX_new: LPN_ASN1_SCTX_new;
  ASN1_SCTX_free: LPN_ASN1_SCTX_free;
  ASN1_SCTX_get_item: LPN_ASN1_SCTX_get_item;
  ASN1_SCTX_get_template: LPN_ASN1_SCTX_get_template;
  ASN1_SCTX_get_flags: LPN_ASN1_SCTX_get_flags;
  ASN1_SCTX_set_app_data: LPN_ASN1_SCTX_set_app_data;
  ASN1_UNIVERSALSTRING_to_string: LPN_ASN1_UNIVERSALSTRING_to_string;
  ASN1_SCTX_get_app_data: LPN_ASN1_SCTX_get_app_data;
  ASN1_INTEGER_set_uint64: LPN_ASN1_INTEGER_set_uint64;
  ASN1_item_print: LPN_ASN1_item_print;
  BIO_f_asn1: LPN_BIO_f_asn1;
  BIO_new_NDEF: LPN_BIO_new_NDEF;
  i2d_ASN1_bio_stream: LPN_i2d_ASN1_bio_stream;
  PEM_write_bio_ASN1_stream: LPN_PEM_write_bio_ASN1_stream;
  SMIME_read_ASN1: LPN_SMIME_read_ASN1;
  ASN1_TIME_set: LPN_ASN1_TIME_set;
  SMIME_crlf_copy: LPN_SMIME_crlf_copy;
  ASN1_object_size: LPN_ASN1_object_size;
  SMIME_text: LPN_SMIME_text;

  { BEGIN ERROR CODES }
  {
    * The following lines are auto generated by the script mkerr.pl. Any changes
    * made after this point may be overwritten when the script is next run.
  }
  ERR_load_ASN1_strings: LPN_ERR_load_ASN1_strings;

implementation

procedure stub_ASN1_TYPE_set(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer);
begin
  ASN1_TYPE_set := CryptoFixupStub('BIO_f_asn1');
  ASN1_TYPE_set(a, _type, value);
end;

function stub_ASN1_TYPE_set1(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer)
  : TIdC_INT;
begin
  ASN1_TYPE_set1 := CryptoFixupStub('ASN1_TYPE_set1');
  Result := ASN1_TYPE_set1(a, _type, value);
end;

function stub_ASN1_TYPE_cmp(a: PASN1_TYPE; b: PASN1_TYPE): TIdC_INT;
begin
  ASN1_TYPE_cmp := CryptoFixupStub('ASN1_TYPE_cmp');
  Result := ASN1_TYPE_cmp(a, b);
end;

function stub_ASN1_TYPE_pack_sequence(it: PASN1_ITEM; s: Pointer;
  t: PPASN1_TYPE): PASN1_TYPE;
begin
  ASN1_TYPE_pack_sequence := CryptoFixupStub('ASN1_TYPE_pack_sequence');
  Result := ASN1_TYPE_pack_sequence(it, s, t);
end;

function stub_ASN1_TYPE_unpack_sequence(it: PASN1_ITEM; t: PASN1_TYPE): Pointer;
begin
  ASN1_TYPE_unpack_sequence := CryptoFixupStub('ASN1_TYPE_unpack_sequence');
  Result := ASN1_TYPE_unpack_sequence(it, t);
end;

function stub_ASN1_OBJECT_new: PASN1_OBJECT;
begin
  ASN1_OBJECT_new := CryptoFixupStub('ASN1_OBJECT_new');
  Result := ASN1_OBJECT_new;
end;

procedure stub_ASN1_OBJECT_free(a: PASN1_OBJECT);
begin
  ASN1_OBJECT_free := CryptoFixupStub('ASN1_OBJECT_free');
  ASN1_OBJECT_free(a);
end;

function stub_i2d_ASN1_OBJECT(a: PASN1_OBJECT; pp: PPAnsiChar): TIdC_INT;
begin
  i2d_ASN1_OBJECT := CryptoFixupStub('i2d_ASN1_OBJECT');
  Result := i2d_ASN1_OBJECT(a, pp);
end;

function stub_d2i_ASN1_OBJECT(a: PPASN1_OBJECT; pp: PPAnsiChar;
  length: TIdC_LONG): PASN1_OBJECT;
begin
  d2i_ASN1_OBJECT := CryptoFixupStub('d2i_ASN1_OBJECT');
  Result := d2i_ASN1_OBJECT(a, pp, length);
end;

procedure stub_ASN1_STRING_free(a: PASN1_STRING);
begin
  ASN1_STRING_free := CryptoFixupStub('ASN1_STRING_free');
  ASN1_STRING_free(a);
end;

procedure stub_ASN1_STRING_clear_free(a: PASN1_STRING);
begin
  ASN1_STRING_clear_free := CryptoFixupStub('ASN1_STRING_clear_free(');
  ASN1_STRING_clear_free(a);
end;

function stub_ASN1_STRING_copy(dst: PASN1_STRING; str: PASN1_STRING): TIdC_INT;
begin
  ASN1_STRING_copy := CryptoFixupStub('ASN1_STRING_copy');
  Result := ASN1_STRING_copy(dst, str);
end;

function stub_ASN1_STRING_dup(a: PASN1_STRING): PASN1_STRING;
begin
  ASN1_STRING_dup := CryptoFixupStub('ASN1_STRING_dup');
  Result := ASN1_STRING_dup(a);
end;

function stub_ASN1_STRING_type_new(_type: TIdC_INT): PASN1_STRING;
begin
  ASN1_STRING_type_new := CryptoFixupStub('ASN1_STRING_type_new');
  Result := ASN1_STRING_type_new(_type);
end;

function stub_ASN1_STRING_cmp(a: PASN1_STRING; b: PASN1_STRING): TIdC_INT;
begin
  ASN1_STRING_cmp := CryptoFixupStub('ASN1_STRING_cmp');
  Result := stub_ASN1_STRING_cmp(a, b);
end;

function stub_ASN1_STRING_set(str: PASN1_STRING; data: Pointer; len: TIdC_INT)
  : TIdC_INT;
begin
  ASN1_STRING_set := CryptoFixupStub('ASN1_STRING_set');
  Result := ASN1_STRING_set(str, data, len);
end;

procedure stub_ASN1_STRING_set0(str: PASN1_STRING; data: Pointer;
  len: TIdC_INT);
begin
  ASN1_STRING_set0 := CryptoFixupStub('ASN1_STRING_set0');
  ASN1_STRING_set0(str, data, len);
end;

function stub_ASN1_STRING_length(x: PASN1_STRING): TIdC_INT;
begin
  ASN1_STRING_length := CryptoFixupStub('ASN1_STRING_length');
  Result := ASN1_STRING_length(x);
end;

procedure stub_ASN1_STRING_length_set(x: PASN1_STRING; n: TIdC_INT);
begin
  ASN1_STRING_length_set := CryptoFixupStub('ASN1_STRING_length_set');
  ASN1_STRING_length_set(x, n);
end;

function stub_ASN1_STRING_type(x: PASN1_STRING): TIdC_INT;
begin
  ASN1_STRING_type := CryptoFixupStub('ASN1_STRING_type');
  Result := ASN1_STRING_type(x);
end;

function stub_ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PAnsiChar;
  length: TIdC_INT): TIdC_INT cdecl;
begin
  ASN1_BIT_STRING_set := CryptoFixupStub('ASN1_BIT_STRING_set');
  Result := ASN1_BIT_STRING_set(a, d, length);
end;

function stub_ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TIdC_INT;
  value: TIdC_INT): TIdC_INT cdecl;
begin
  ASN1_BIT_STRING_set_bit := CryptoFixupStub('ASN1_BIT_STRING_set_bit');
  Result := ASN1_BIT_STRING_set_bit(a, n, value);
end;

function stub_ASN1_BIT_STRING_get_bit(a: PASN1_BIT_STRING; n: TIdC_INT)
  : TIdC_INT cdecl;
begin
  ASN1_BIT_STRING_get_bit := CryptoFixupStub('stub_ASN1_BIT_STRING_get_bit');
  Result := ASN1_BIT_STRING_get_bit(a, n);
end;

function stub_ASN1_BIT_STRING_check(a: ASN1_BIT_STRING; flags: PAnsiChar;
  flags_len: TIdC_INT): TIdC_INT cdecl;
begin
  ASN1_BIT_STRING_check := CryptoFixupStub('ASN1_BIT_STRING_check');
  Result := ASN1_BIT_STRING_check(a, flags, flags_len);
end;

function stub_ASN1_BIT_STRING_name_print(_out: PBIO; bs: PASN1_BIT_STRING;
  tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT cdecl;
begin
  ASN1_BIT_STRING_name_print := CryptoFixupStub('ASN1_BIT_STRING_name_print');
  Result := ASN1_BIT_STRING_name_print(_out, bs, tbl, indent);
end;

function stub_ASN1_BIT_STRING_num_asc(name: PAnsiChar; tbl: PBIT_STRING_BITNAME)
  : TIdC_INT;
begin
  ASN1_BIT_STRING_num_asc := CryptoFixupStub('ASN1_BIT_STRING_num_asc');
  Result := ASN1_BIT_STRING_num_asc(name, tbl);
end;

function stub_ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; name: PAnsiChar;
  value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT;
begin
  ASN1_BIT_STRING_set_asc := CryptoFixupStub('ASN1_BIT_STRING_set_asc');
  Result := ASN1_BIT_STRING_set_asc(bs, name, value, tbl);
end;

function stub_d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; pp: PPAnsiChar;
  length: TIdC_LONG): PASN1_INTEGER cdecl;
begin
  d2i_ASN1_UINTEGER := CryptoFixupStub('d2i_ASN1_UINTEGER');
  Result := d2i_ASN1_UINTEGER(a, pp, length);
end;

function stub_ASN1_INTEGER_dup(x: PASN1_INTEGER): PASN1_INTEGER cdecl;
begin
  ASN1_INTEGER_dup := CryptoFixupStub('stub_ASN1_INTEGER_dup');
  Result := stub_ASN1_INTEGER_dup(x);
end;

function stub_ASN1_INTEGER_cmp(x: PASN1_INTEGER; y: PASN1_INTEGER)
  : TIdC_INT cdecl;
begin
  ASN1_INTEGER_cmp := CryptoFixupStub('ASN1_INTEGER_cmp');
  Result := ASN1_INTEGER_cmp(x, y);
end;

function stub_ASN1_UTCTIME_check(a: PASN1_UTCTIME): TIdC_INT;
begin
  ASN1_UTCTIME_check := CryptoFixupStub('ASN1_UTCTIME_check');
  Result := ASN1_UTCTIME_check(a);
end;

function stub_ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TIdC_TIMET): PASN1_UTCTIME;
begin
  ASN1_UTCTIME_set := CryptoFixupStub('ASN1_UTCTIME_set');
  Result := ASN1_UTCTIME_set(s, t);
end;

function stub_ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TIdC_TIMET;
  offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME;
begin
  ASN1_UTCTIME_adj := CryptoFixupStub('ASN1_UTCTIME_adj');
  Result := ASN1_UTCTIME_adj(s, t, offset_day, offset_sec);
end;

function stub_ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; str: PAnsiChar)
  : TIdC_INT;
begin
  ASN1_UTCTIME_set_string := CryptoFixupStub('ASN1_UTCTIME_set_string');
  Result := ASN1_UTCTIME_set_string(s, str);
end;

function stub_ASN1_UTCTIME_cmp_time_t(s: PASN1_UTCTIME; t: TIdC_TIMET)
  : TIdC_INT;
begin
  ASN1_UTCTIME_cmp_time_t := CryptoFixupStub('ASN1_UTCTIME_cmp_time_t');
  Result := ASN1_UTCTIME_cmp_time_t(s, t);
end;

function stub_ASN1_GENERALIZEDTIME_check(a: PASN1_GENERALIZEDTIME): TIdC_INT;
begin
  ASN1_GENERALIZEDTIME_check := CryptoFixupStub('ASN1_GENERALIZEDTIME_check');
  Result := ASN1_GENERALIZEDTIME_check(a);
end;

function stub_ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET)
  : PASN1_GENERALIZEDTIME;
begin
  ASN1_GENERALIZEDTIME_set := CryptoFixupStub('ASN1_GENERALIZEDTIME_set');
  Result := ASN1_GENERALIZEDTIME_set(s, t);
end;

function stub_ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET;
  offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME;
begin
  ASN1_GENERALIZEDTIME_adj := CryptoFixupStub('ASN1_GENERALIZEDTIME_adj');
  Result := ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec);
end;

function stub_ASN1_GENERALIZEDTIME_set_string(s: PASN1_GENERALIZEDTIME;
  str: PAnsiChar): TIdC_INT;
begin
  ASN1_GENERALIZEDTIME_set_string :=
    CryptoFixupStub('ASN1_GENERALIZEDTIME_set_string');
  Result := ASN1_GENERALIZEDTIME_set_string(s, str);
end;

function stub_ASN1_TIME_diff(pday: TIdC_INT; psec: TIdC_INT; from: PASN1_TIME;
  _to: PASN1_TIME): TIdC_INT;
begin
  ASN1_TIME_diff := CryptoFixupStub('ASN1_TIME_diff');
  Result := ASN1_TIME_diff(pday, psec, from, _to);
end;

function stub_ASN1_OCTET_STRING_dup(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING;
begin
  ASN1_OCTET_STRING_dup := CryptoFixupStub('ASN1_OCTET_STRING_dup');
  Result := ASN1_OCTET_STRING_dup(a);
end;

function stub_ASN1_OCTET_STRING_cmp(a: PASN1_OCTET_STRING;
  b: PASN1_OCTET_STRING): TIdC_INT;
begin
  ASN1_OCTET_STRING_cmp := CryptoFixupStub('ASN1_OCTET_STRING_cmp');
  Result := ASN1_OCTET_STRING_cmp(a, b);
end;

function stub_ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; data: PAnsiChar;
  len: TIdC_INT): TIdC_INT;
begin
  ASN1_OCTET_STRING_set := CryptoFixupStub('ASN1_OCTET_STRING_set');
  Result := ASN1_OCTET_STRING_set(str, data, len);
end;

function stub_UTF8_getc(str: PAnsiChar; len: TIdC_INT; val: PIdC_ULONG)
  : TIdC_INT cdecl;
begin
  UTF8_getc := CryptoFixupStub('UTF8_getc');
  Result := UTF8_getc(str, len, val);
end;

function stub_UTF8_putc(str: PAnsiChar; len: TIdC_INT; value: TIdC_ULONG)
  : TIdC_INT cdecl;
begin
  UTF8_putc := CryptoFixupStub('UTF8_putc');
  Result := UTF8_putc(str, len, value);
end;

function stub_ASN1_TIME_set(s: PASN1_TIME; t: TIdC_TIMET): PASN1_TIME cdecl;
begin
  ASN1_TIME_set := CryptoFixupStub('ASN1_TIME_set');
  Result := ASN1_TIME_set(s, t);
end;

function stub_ASN1_TIME_adj(s: PASN1_TIME; t: TIdC_TIMET; offset_day: TIdC_INT;
  offset_sec: TIdC_LONG): PASN1_TIME;
begin
  ASN1_TIME_adj := CryptoFixupStub('ASN1_TIME_adj');
  Result := ASN1_TIME_adj(s, t, offset_day, offset_sec);
end;

function stub_ASN1_TIME_check(t: PASN1_TIME): TIdC_INT;
begin
  ASN1_TIME_check := CryptoFixupStub('stub_ASN1_TIME_check');
  Result := ASN1_TIME_check(t);
end;

function stub_ASN1_TIME_to_generalizedtime(t: PASN1_TIME;
  _out: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME;
begin
  ASN1_TIME_to_generalizedtime :=
    CryptoFixupStub('ASN1_TIME_to_generalizedtime');
  Result := ASN1_TIME_to_generalizedtime(t, _out);
end;

function stub_ASN1_TIME_set_string(s: PASN1_TIME; str: PAnsiChar): TIdC_INT;
begin
  ASN1_TIME_set_string := CryptoFixupStub('ASN1_TIME_set_string');
  Result := ASN1_TIME_set_string(s, str);
end;

function stub_i2a_ASN1_INTEGER(bp: PBIO; a: PASN1_INTEGER): TIdC_INT;
begin
  i2a_ASN1_INTEGER := CryptoFixupStub('i2a_ASN1_INTEGER');
  Result := i2a_ASN1_INTEGER(bp, a);
end;

function stub_a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PAnsiChar;
  size: TIdC_INT): TIdC_INT;
begin
  a2i_ASN1_INTEGER := CryptoFixupStub('a2i_ASN1_INTEGER');
  Result := a2i_ASN1_INTEGER(bp, bs, buf, size);
end;

function stub_i2a_ASN1_ENUMERATED(bp: PBIO; a: PASN1_ENUMERATED): TIdC_INT;
begin
  i2a_ASN1_ENUMERATED := CryptoFixupStub('i2a_ASN1_ENUMERATED');
  Result := i2a_ASN1_ENUMERATED(bp, a);
end;

function Stub_a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED;
  buf: PAnsiChar; size: TIdC_INT): TIdC_INT;
begin
  a2i_ASN1_ENUMERATED := CryptoFixupStub('Stub_a2i_ASN1_ENUMERATED');
  Result := a2i_ASN1_ENUMERATED(bp, bs, buf, size);
end;

function stub_i2a_ASN1_OBJECT(bp: PBIO; a: PASN1_OBJECT): TIdC_INT;
begin
  i2a_ASN1_OBJECT := CryptoFixupStub('i2a_ASN1_OBJECT');
  Result := i2a_ASN1_OBJECT(bp, a);
end;

function stub_a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PAnsiChar;
  size: TIdC_INT): TIdC_INT;
begin
  a2i_ASN1_STRING := CryptoFixupStub('a2i_ASN1_STRING');
  Result := a2i_ASN1_STRING(bp, bs, buf, size);
end;

function stub_i2a_ASN1_STRING(bp: PBIO; a: PASN1_STRING; _type: TIdC_INT)
  : TIdC_INT;
begin
  i2a_ASN1_STRING := CryptoFixupStub('i2a_ASN1_STRING');
  Result := i2a_ASN1_STRING(bp, a, _type);
end;

function stub_i2t_ASN1_OBJECT(buf: PAnsiChar; buf_len: TIdC_INT;
  a: PASN1_OBJECT): TIdC_INT;
begin
  i2t_ASN1_OBJECT := CryptoFixupStub('i2t_ASN1_OBJECT');
  Result := i2t_ASN1_OBJECT(buf, buf_len, a);
end;

function stub_a2d_ASN1_OBJECT(_out: PAnsiChar; olen: TIdC_INT; buf: PAnsiChar;
  num: TIdC_INT): TIdC_INT;
begin
  a2d_ASN1_OBJECT := CryptoFixupStub('a2d_ASN1_OBJECT');
  Result := a2d_ASN1_OBJECT(_out, olen, buf, num);
end;

function stub_ASN1_OBJECT_create(nid: TIdC_INT; data: PAnsiChar; len: TIdC_INT;
  sn: PAnsiChar; ln: PAnsiChar): PASN1_OBJECT;
begin
  ASN1_OBJECT_create := CryptoFixupStub('ASN1_OBJECT_create');
  Result := ASN1_OBJECT_create(nid, data, len, sn, ln);
end;

function stub_ASN1_INTEGER_get_int64(pr: PIdC_INT64; a: PASN1_INTEGER)
  : TIdC_INT;
begin
  ASN1_INTEGER_get_int64 := CryptoFixupStub('ASN1_INTEGER_get_int64');
  Result := ASN1_INTEGER_get_int64(pr, a);
end;

function stub_ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TIdC_INT64): TIdC_INT;
begin
  ASN1_INTEGER_set_int64 := CryptoFixupStub('ASN1_INTEGER_set_int64');
  Result := ASN1_INTEGER_set_int64(a, r);
end;

function stub_ASN1_INTEGER_get_uint64(pr: PIdC_UINT64; a: PASN1_INTEGER)
  : TIdC_INT;
begin
  ASN1_INTEGER_get_uint64 := CryptoFixupStub('ASN1_INTEGER_get_uint64');
  Result := ASN1_INTEGER_get_uint64(pr, a);
end;

function stub_ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TIdC_UINT64)
  : TIdC_INT;
begin
  ASN1_INTEGER_set_uint64 := CryptoFixupStub('ASN1_INTEGER_set_uint64');
  Result := ASN1_INTEGER_set_uint64(a, r);
end;

function stub_ASN1_INTEGER_set(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT;
begin
  ASN1_INTEGER_set := CryptoFixupStub('ASN1_INTEGER_set');
  Result := ASN1_INTEGER_set(a, v);
end;

function stub_ASN1_INTEGER_get(a: PASN1_INTEGER): TIdC_LONG;
begin
  ASN1_INTEGER_get := CryptoFixupStub('ASN1_INTEGER_get');
  Result := ASN1_INTEGER_get(a);
end;

function stub_BN_to_ASN1_INTEGER(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER;
begin
  BN_to_ASN1_INTEGER := CryptoFixupStub('BN_to_ASN1_INTEGER');
  Result := BN_to_ASN1_INTEGER(bn, ai);
end;

function stub_ASN1_INTEGER_to_BN(ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM;
begin
  ASN1_INTEGER_to_BN := CryptoFixupStub('stub_ASN1_INTEGER_to_BN');
  Result := stub_ASN1_INTEGER_to_BN(ai, bn);
end;

function stub_ASN1_ENUMERATED_get_int64(pr: PIdC_INT64; a: PASN1_ENUMERATED)
  : TIdC_INT;
begin
  ASN1_ENUMERATED_get_int64 := CryptoFixupStub('ASN1_ENUMERATED_get_int64');
  Result := ASN1_ENUMERATED_get_int64(pr, a);
end;

function stub_ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TIdC_INT64)
  : TIdC_INT;
begin
  ASN1_ENUMERATED_set_int64 := CryptoFixupStub('ASN1_ENUMERATED_set_int64');
  Result := ASN1_ENUMERATED_set_int64(a, r);
end;

function stub_ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT;
begin
  ASN1_ENUMERATED_set := CryptoFixupStub('ASN1_ENUMERATED_set');
  Result := ASN1_ENUMERATED_set(a, v);
end;

function stub_ASN1_ENUMERATED_get(a: PASN1_ENUMERATED): TIdC_LONG;
begin
  ASN1_ENUMERATED_get := CryptoFixupStub('ASN1_ENUMERATED_get');
  Result := ASN1_ENUMERATED_get(a);
end;

function stub_BN_to_ASN1_ENUMERATED(bn: PBIGNUM; ai: PASN1_ENUMERATED)
  : PASN1_ENUMERATED;
begin
  BN_to_ASN1_ENUMERATED := CryptoFixupStub('BN_to_ASN1_ENUMERATED');
  Result := BN_to_ASN1_ENUMERATED(bn, ai);
end;

function stub_ASN1_ENUMERATED_to_BN(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM;
begin
  ASN1_ENUMERATED_to_BN := CryptoFixupStub('ASN1_ENUMERATED_to_BN');
  Result := ASN1_ENUMERATED_to_BN(ai, bn);
end;

function stub_ASN1_PRINTABLE_type(s: PAnsiChar; max: TIdC_INT): TIdC_INT;
begin
  ASN1_PRINTABLE_type := CryptoFixupStub('ASN1_PRINTABLE_type');
  Result := ASN1_PRINTABLE_type(s, max);
end;

function stub_ASN1_tag2bit(tag: TIdC_INT): TIdC_ULONG;
begin
  ASN1_tag2bit := CryptoFixupStub('ASN1_tag2bit');
  Result := stub_ASN1_tag2bit(tag);
end;

function stub_ASN1_get_object(pp: PPAnsiChar; plength: PIdC_LONG;
  ptag: TIdC_INT; pclass: TIdC_INT; omax: TIdC_LONG): TIdC_INT;
begin
  ASN1_get_object := CryptoFixupStub('ASN1_get_object');
  Result := ASN1_get_object(pp, plength, ptag, pclass, omax);
end;

function stub_ASN1_check_infinite_end(p: PPAnsiChar; len: TIdC_LONG): TIdC_INT;
begin
  ASN1_check_infinite_end := CryptoFixupStub('ASN1_check_infinite_end');
  Result := ASN1_check_infinite_end(p, len);
end;

function stub_ASN1_const_check_infinite_end(p: PPAnsiChar; len: TIdC_LONG)
  : TIdC_INT;
begin
  ASN1_const_check_infinite_end :=
    CryptoFixupStub('ASN1_const_check_infinite_end');
  Result := ASN1_const_check_infinite_end(p, len);
end;

procedure stub_ASN1_put_object(pp: PPAnsiChar; constructed: TIdC_INT;
  length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT);
begin
  ASN1_put_object := CryptoFixupStub('ASN1_put_object');
  ASN1_put_object(pp, constructed, length, tag, xclass);
end;

function stub_ASN1_put_eoc(pp: PPAnsiChar): TIdC_INT;
begin
  ASN1_put_eoc := CryptoFixupStub('ASN1_put_eoc');
  Result := ASN1_put_eoc(pp);
end;

function stub_ASN1_object_size(constructed: TIdC_INT; length: TIdC_INT;
  tag: TIdC_INT): TIdC_INT;
begin
  ASN1_object_size := CryptoFixupStub('ASN1_object_size');
  Result := ASN1_object_size(constructed, length, tag);
end;

function stub_ASN1_dup(i2d: Pi2d_of_void; d2i: Pd2i_of_void;
  x: Pointer): Pointer;
begin
  ASN1_dup := CryptoFixupStub('LPN_ASN1_dup');
  Result := ASN1_dup(i2d, d2i, x);
end;

function stub_ASN1_item_dup(it: PASN1_ITEM; x: Pointer): Pointer;
begin
  ASN1_item_dup := CryptoFixupStub('ASN1_item_dup');
  Result := ASN1_item_dup(it, x);
end;
{$IFNDEF OPENSSL_NO_STDIO}

function stub_ASN1_d2i_fp(xnew: PASN1_d2i_fp_xnew; d2i: Pd2i_of_void;
  _in: PFILE; x: PPointer): Pointer cdecl;
begin
  ASN1_d2i_fp := CryptoFixupStub('ASN1_d2i_fp');
  Result := ASN1_d2i_fp(xnew, d2i, _in, x);
end;

function stub_ASN1_item_d2i_fp(it: PASN1_ITEM; _in: PFILE; x: Pointer): Pointer;
begin
  ASN1_item_d2i_fp := CryptoFixupStub('ASN1_item_d2i_fp');
  Result := ASN1_item_d2i_fp(it, _in, x);
end;

function stub_ASN1_i2d_fp(i2d: Pi2d_of_void; _out: PFILE; x: Pointer): TIdC_INT;
begin
  ASN1_i2d_fp := CryptoFixupStub('ASN1_i2d_fp');
  Result := ASN1_i2d_fp(i2d, _out, x);
end;

function stub_ASN1_item_i2d_fp(it: PASN1_ITEM; _out: PFILE; x: Pointer)
  : TIdC_INT;
begin
  ASN1_item_i2d_fp := CryptoFixupStub('ASN1_item_i2d_fp');
  Result := ASN1_item_i2d_fp(it, _out, x);
end;

function stub_ASN1_STRING_print_ex_fp(fp: PFILE; str: PASN1_STRING;
  flags: TIdC_ULONG): TIdC_INT;
begin
  ASN1_STRING_print_ex_fp := CryptoFixupStub('stub_ASN1_STRING_print_ex_fp');
  Result := ASN1_STRING_print_ex_fp(fp, str, flags);
end;
{$ENDIF}

function stub_ASN1_STRING_to_UTF8(_out: PPAnsiChar; _in: PASN1_STRING)
  : TIdC_INT;
begin
  ASN1_STRING_to_UTF8 := CryptoFixupStub('ASN1_STRING_to_UTF8');
  Result := ASN1_STRING_to_UTF8(_out, _in);
end;

function stub_ASN1_d2i_bio(xnew: PASN1_d2i_bio_xnew; d2i: Pd2i_of_void;
  _in: PBIO; x: PPointer): Pointer;
begin
  ASN1_d2i_bio := CryptoFixupStub('ASN1_d2i_bio');
  Result := ASN1_d2i_bio(xnew, d2i, _in, x);
end;

function stub_ASN1_item_d2i_bio(it: PASN1_ITEM; _in: PBIO; x: Pointer): Pointer;
begin
  ASN1_item_d2i_bio := CryptoFixupStub('ASN1_item_d2i_bio');
  Result := ASN1_item_d2i_bio(it, _in, x);
end;

function stub_ASN1_i2d_bio(i2d: Pi2d_of_void; _out: PBIO; x: PAnsiChar)
  : TIdC_INT;
begin
  ASN1_i2d_bio := CryptoFixupStub('ASN1_i2d_bio');
  Result := ASN1_i2d_bio(i2d, _out, x);
end;

function stub_ASN1_item_i2d_bio(it: PASN1_ITEM; _out: PBIO; x: Pointer)
  : TIdC_INT;
begin
  ASN1_item_i2d_bio := CryptoFixupStub('ASN1_item_i2d_bio');
  Result := ASN1_item_i2d_bio(it, _out, x);
end;

function stub_ASN1_UTCTIME_print(fp: PBIO; a: PASN1_UTCTIME): TIdC_INT;
begin
  ASN1_UTCTIME_print := CryptoFixupStub('stub_ASN1_UTCTIME_print');
  Result := ASN1_UTCTIME_print(fp, a);
end;

function stub_ASN1_GENERALIZEDTIME_print(fp: PBIO; a: PASN1_GENERALIZEDTIME)
  : TIdC_INT;
begin
  ASN1_GENERALIZEDTIME_print := CryptoFixupStub('ASN1_GENERALIZEDTIME_print');
  Result := ASN1_GENERALIZEDTIME_print(fp, a);
end;

function stub_ASN1_TIME_print(fp: PBIO; a: PASN1_TIME): TIdC_INT;
begin
  ASN1_TIME_print := CryptoFixupStub('ASN1_TIME_print');
  Result := ASN1_TIME_print(fp, a);
end;

function stub_ASN1_STRING_print(bp: PBIO; v: PASN1_STRING): TIdC_INT;
begin
  ASN1_STRING_print := CryptoFixupStub('ASN1_STRING_print');
  Result := ASN1_STRING_print(bp, v);
end;

function stub_ASN1_STRING_print_ex(_out: PBIO; str: PASN1_STRING;
  flags: TIdC_ULONG): TIdC_INT;
begin
  ASN1_STRING_print_ex := CryptoFixupStub('ASN1_STRING_print_ex');
  Result := ASN1_STRING_print_ex(_out, str, flags);
end;

function stub_ASN1_buf_print(bp: PBIO; buf: PAnsiChar; buflen: TIdC_SIZET;
  off: TIdC_INT): TIdC_INT;
begin
  ASN1_buf_print := CryptoFixupStub('ASN1_buf_print');
  Result := ASN1_buf_print(bp, buf, buflen, off);
end;

function stub_ASN1_bn_print(bp: PBIO; number: PAnsiChar; num: PBIGNUM;
  buf: PAnsiChar; off: TIdC_INT): TIdC_INT;
begin
  ASN1_bn_print := CryptoFixupStub('ASN1_bn_print');
  Result := ASN1_bn_print(bp, number, num, buf, off);
end;

function stub_ASN1_parse(bp: PBIO; pp: PAnsiChar; len: TIdC_LONG;
  indent: TIdC_INT): TIdC_INT;
begin
  ASN1_parse := CryptoFixupStub('ASN1_parse');
  Result := ASN1_parse(bp, pp, len, indent);
end;

function stub_ASN1_parse_dump(bp: PBIO; pp: PAnsiChar; len: TIdC_LONG;
  indent: TIdC_INT; dump: TIdC_INT): TIdC_INT;
begin
  ASN1_parse_dump := CryptoFixupStub('ASN1_parse_dump');
  Result := ASN1_parse_dump(bp, pp, len, indent, dump);
end;

function stub_ASN1_tag2str(tag: TIdC_INT): PAnsiChar;
begin
  ASN1_tag2str := CryptoFixupStub('ASN1_tag2str');
  Result := ASN1_tag2str(tag);
end;

function stub_ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING)
  : TIdC_INT;
begin
  ASN1_UNIVERSALSTRING_to_string :=
    CryptoFixupStub('ASN1_UNIVERSALSTRING_to_string');
  Result := ASN1_UNIVERSALSTRING_to_string(s);
end;

function stub_ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PAnsiChar;
  len: TIdC_INT): TIdC_INT;
begin
  ASN1_TYPE_set_octetstring :=
    CryptoFixupStub('stub_ASN1_TYPE_set_octetstring');
  Result := ASN1_TYPE_set_octetstring(a, data, len);
end;

function stub_ASN1_TYPE_get_octetstring(a: PASN1_TYPE; data: PAnsiChar;
  max_len: TIdC_INT): TIdC_INT;
begin
  ASN1_TYPE_get_octetstring := CryptoFixupStub('ASN1_TYPE_get_octetstring');
  Result := ASN1_TYPE_get_octetstring(a, data, max_len);
end;

function stub_ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TIdC_LONG;
  data: PAnsiChar; len: TIdC_INT): TIdC_INT;
begin
  ASN1_TYPE_set_int_octetstring :=
    CryptoFixupStub('ASN1_TYPE_set_int_octetstring');
  Result := ASN1_TYPE_set_int_octetstring(a, num, data, len);
end;

function stub_ASN1_TYPE_get_int_octetstring(a: PASN1_TYPE; num: PIdC_LONG;
  data: PAnsiChar; max_len: TIdC_INT): TIdC_INT;
begin
  ASN1_TYPE_get_int_octetstring :=
    CryptoFixupStub('ASN1_TYPE_get_int_octetstring');
  Result := ASN1_TYPE_get_int_octetstring(a, num, data, max_len);

end;

function stub_ASN1_item_unpack(oct: PASN1_STRING; it: PASN1_ITEM): Pointer;
begin
  ASN1_item_unpack := CryptoFixupStub('ASN1_item_unpack');
  Result := ASN1_item_unpack(oct, it);
end;

function stub_ASN1_item_pack(obj: Pointer; it: PASN1_ITEM;
  oct: PPASN1_OCTET_STRING): PASN1_STRING;
begin
  ASN1_item_pack := CryptoFixupStub('ASN1_item_pack');
  Result := ASN1_item_pack(obj, it, oct);
end;

procedure stub_ASN1_STRING_set_default_mask(mask: TIdC_ULONG);
begin
  ASN1_STRING_set_default_mask :=
    CryptoFixupStub('ASN1_STRING_set_default_mask');
  ASN1_STRING_set_default_mask(mask);
end;

function stub_ASN1_STRING_set_default_mask_asc(p: PAnsiChar): TIdC_INT;
begin
  ASN1_STRING_set_default_mask_asc :=
    CryptoFixupStub('ASN1_STRING_set_default_mask_asc');
  Result := ASN1_STRING_set_default_mask_asc(p);
end;

function stub_ASN1_STRING_get_default_mask: TIdC_ULONG;
begin
  ASN1_STRING_get_default_mask :=
    CryptoFixupStub('ASN1_STRING_get_default_mask');
  Result := ASN1_STRING_get_default_mask;
end;

function stub_ASN1_mbstring_copy(_out: PPASN1_STRING; _in: PAnsiChar;
  len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT;
begin
  ASN1_mbstring_copy := CryptoFixupStub('ASN1_mbstring_copy');
  Result := ASN1_mbstring_copy(_out, _in, len, inform, mask);
end;

function stub_ASN1_mbstring_ncopy(_out: PPASN1_STRING; _in: PAnsiChar;
  len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG;
  maxsize: TIdC_LONG): TIdC_INT;
begin
  ASN1_mbstring_ncopy := CryptoFixupStub('ASN1_mbstring_ncopy');
  Result := ASN1_mbstring_ncopy(_out, _in, len, inform, mask, minsize, maxsize);
end;

function stub_ASN1_STRING_set_by_NID(_out: PPASN1_STRING; _in: PAnsiChar;
  inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING;
begin
  ASN1_STRING_set_by_NID := CryptoFixupStub('ASN1_STRING_set_by_NID');
  Result := ASN1_STRING_set_by_NID(_out, _in, inlen, inform, nid);
end;

function stub_ASN1_STRING_TABLE_get(nid: TIdC_INT): PASN1_STRING_TABLE;
begin
  ASN1_STRING_TABLE_get := CryptoFixupStub('ASN1_STRING_TABLE_get');
  Result := ASN1_STRING_TABLE_get(nid);
end;

function stub_ASN1_STRING_TABLE_add(para1: TIdC_INT; para2: TIdC_LONG;
  para3: TIdC_LONG; para4: TIdC_ULONG; para5: TIdC_ULONG): TIdC_INT;
begin
  ASN1_STRING_TABLE_add := CryptoFixupStub('ASN1_STRING_TABLE_add');
  Result := ASN1_STRING_TABLE_add(para1, para2, para3, para4, para5);
end;

procedure stub_ASN1_STRING_TABLE_cleanup cdecl;
begin
  ASN1_STRING_TABLE_cleanup := CryptoFixupStub('ASN1_STRING_TABLE_cleanup');
  ASN1_STRING_TABLE_cleanup;
end;

function stub_ASN1_item_new(it: PASN1_ITEM): PASN1_VALUE;
begin
  ASN1_item_new := CryptoFixupStub('ASN1_item_new');
  Result := ASN1_item_new(it);
end;

procedure stub_ASN1_item_free(val: PASN1_VALUE; it: PASN1_ITEM);
begin
  ASN1_item_free := CryptoFixupStub('ASN1_item_free');
  ASN1_item_free(val, it);
end;

function stub_ASN1_item_d2i(val: PPASN1_VALUE; _in: PPAnsiChar; len: TIdC_LONG;
  it: PASN1_ITEM): PASN1_VALUE;
begin
  ASN1_item_d2i := CryptoFixupStub('ASN1_item_d2i');
  Result := ASN1_item_d2i(val, _in, len, it);
end;

function stub_ASN1_item_i2d(val: PASN1_VALUE; _out: PPAnsiChar; it: PASN1_ITEM)
  : TIdC_INT;
begin
  ASN1_item_i2d := CryptoFixupStub('ASN1_item_i2d');
  Result := ASN1_item_i2d(val, _out, it);
end;

function stub_ASN1_item_ndef_i2d(val: PASN1_VALUE; _out: PPAnsiChar;
  it: PASN1_ITEM): TIdC_INT;
begin
  ASN1_item_ndef_i2d := CryptoFixupStub('ASN1_item_ndef_i2d');
  Result := ASN1_item_ndef_i2d(val, _out, it);
end;

procedure stub_ASN1_add_oid_module;
begin
  ASN1_add_oid_module := CryptoFixupStub('stub_ASN1_add_oid_module');
  ASN1_add_oid_module;
end;

procedure stub_ASN1_add_stable_module;
begin
  ASN1_add_stable_module := CryptoFixupStub('ASN1_add_stable_module');
  ASN1_add_stable_module;
end;

function stub_ASN1_generate_nconf(str: PAnsiChar; nconf: PCONF): PASN1_TYPE;
begin
  ASN1_generate_nconf := CryptoFixupStub('LPN_ASN1_generate_nconf');
  Result := ASN1_generate_nconf(str, nconf);
end;

function stub_ASN1_generate_v3(str: PAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE;
begin
  ASN1_generate_v3 := CryptoFixupStub('ASN1_generate_v3');
  Result := ASN1_generate_v3(str, cnf);
end;

function stub_ASN1_str2mask(str: PAnsiChar; pmask: PIdC_ULONG): TIdC_INT;
begin
  ASN1_str2mask := CryptoFixupStub('ASN1_str2mask');
  Result := ASN1_str2mask(str, pmask);
end;

function stub_ASN1_item_print(_out: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT;
  it: PASN1_ITEM; pctx: PASN1_PCTX): TIdC_INT;
begin
  ASN1_item_print := CryptoFixupStub('ASN1_item_print');
  Result := ASN1_item_print(_out, ifld, indent, it, pctx);
end;

function stub_ASN1_PCTX_new: PASN1_PCTX;
begin
  ASN1_PCTX_new := CryptoFixupStub('ASN1_PCTX_new');
  Result := ASN1_PCTX_new;
end;

procedure stub_ASN1_PCTX_free(p: PASN1_PCTX);
begin
  ASN1_PCTX_free := CryptoFixupStub('ASN1_PCTX_free');
  ASN1_PCTX_free(p);
end;

function stub_ASN1_PCTX_get_flags(p: PASN1_PCTX): TIdC_ULONG;
begin
  ASN1_PCTX_get_flags := CryptoFixupStub('ASN1_PCTX_get_flags');
  Result := ASN1_PCTX_get_flags(p);
end;

procedure stub_ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TIdC_ULONG);
begin
  ASN1_PCTX_set_flags := CryptoFixupStub('ASN1_PCTX_set_flags');
  ASN1_PCTX_set_flags(p, flags);
end;

function stub_ASN1_PCTX_get_nm_flags(p: PASN1_PCTX): TIdC_ULONG;
begin
  ASN1_PCTX_get_nm_flags := CryptoFixupStub('ASN1_PCTX_get_nm_flags');
  Result := ASN1_PCTX_get_nm_flags(p);
end;

procedure stub_ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TIdC_ULONG);
begin
  ASN1_PCTX_set_nm_flags := CryptoFixupStub('ASN1_PCTX_set_nm_flags');
  ASN1_PCTX_set_nm_flags(p, flags);
end;

function stub_ASN1_PCTX_get_cert_flags(p: PASN1_PCTX): TIdC_ULONG;
begin
  ASN1_PCTX_get_cert_flags := CryptoFixupStub('ASN1_PCTX_get_cert_flags');
  Result := ASN1_PCTX_get_cert_flags(p);
end;

procedure stub_ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TIdC_ULONG);
begin
  ASN1_PCTX_set_cert_flags := CryptoFixupStub('ASN1_PCTX_set_cert_flags');
  ASN1_PCTX_set_cert_flags(p, flags);
end;

function stub_ASN1_PCTX_get_oid_flags(p: PASN1_PCTX): TIdC_ULONG;
begin
  ASN1_PCTX_get_oid_flags := CryptoFixupStub('ASN1_PCTX_get_oid_flags');
  Result := ASN1_PCTX_get_oid_flags(p);
end;

procedure stub_ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TIdC_ULONG);
begin
  ASN1_PCTX_set_oid_flags := CryptoFixupStub('LPN_ASN1_PCTX_set_oid_flags');
  ASN1_PCTX_set_oid_flags(p, flags);
end;

function stub_ASN1_PCTX_get_str_flags(p: PASN1_PCTX): TIdC_ULONG;
begin
  ASN1_PCTX_get_str_flags := CryptoFixupStub('ASN1_PCTX_get_str_flags');
  Result := ASN1_PCTX_get_str_flags(p);
end;

procedure stub_ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TIdC_ULONG);
begin
  ASN1_PCTX_set_str_flags := CryptoFixupStub('LPN_ASN1_PCTX_set_str_flags');
  ASN1_PCTX_set_str_flags(p, flags);
end;

function stub_ASN1_SCTX_new(scan_cb: PASN1_SCTX_new_cb): PASN1_SCTX;
begin
  ASN1_SCTX_new := CryptoFixupStub('ASN1_SCTX_new');
  Result := ASN1_SCTX_new(scan_cb);
end;

procedure stub_ASN1_SCTX_free(p: PASN1_SCTX);
begin
  ASN1_SCTX_free := CryptoFixupStub('stub_ASN1_SCTX_free');
  ASN1_SCTX_free(p);
end;

function stub_ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM;
begin
  ASN1_SCTX_get_item := CryptoFixupStub('ASN1_SCTX_get_item');
  Result := ASN1_SCTX_get_item(p);
end;

function stub_ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE;
begin
  ASN1_SCTX_get_template := CryptoFixupStub('ASN1_SCTX_get_template');
  Result := ASN1_SCTX_get_template(p);
end;

function stub_ASN1_SCTX_get_flags(p: PASN1_SCTX): TIdC_ULONG;
begin
  ASN1_SCTX_get_flags := CryptoFixupStub('ASN1_SCTX_get_flags');
  Result := ASN1_SCTX_get_flags(p);
end;

procedure stub_ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer);
begin
  ASN1_SCTX_set_app_data := CryptoFixupStub('ASN1_SCTX_set_app_data');
  ASN1_SCTX_set_app_data(p, data);
end;

function stub_ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer;
begin
  ASN1_SCTX_get_app_data := CryptoFixupStub('ASN1_SCTX_get_app_data');
  Result := ASN1_SCTX_get_app_data(p);
end;

function stub_BIO_f_asn1: PBIO_METHOD;
begin
  BIO_f_asn1 := CryptoFixupStub('BIO_f_asn1');
  Result := BIO_f_asn1;
end;

function stub_BIO_new_NDEF(_out : PBIO; val: PASN1_VALUE; it: PASN1_ITEM): PBIO;
begin
  BIO_new_NDEF := CryptoFixupStub('BIO_new_NDEF');
  Result := BIO_new_NDEF(_out,val,it);
end;

function stub_i2d_ASN1_bio_stream(_out : PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT;
  it: PASN1_ITEM): TIdC_INT;
begin
  i2d_ASN1_bio_stream := CryptoFixupStub('i2d_ASN1_bio_stream');
  Result := i2d_ASN1_bio_stream(_out,val,_in,flags,it);
end;

function stub_PEM_write_bio_ASN1_stream(_out : PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT;
  hdr: PAnsiChar; it: PASN1_ITEM): TIdC_INT;
begin
  PEM_write_bio_ASN1_stream := CryptoFixupStub('PEM_write_bio_ASN1_stream');
  Result := PEM_write_bio_ASN1_stream(_out,val,_in,flags,hdr,it);
end;

function stub_SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; it: PASN1_ITEM): PASN1_VALUE cdecl;
begin
  SMIME_read_ASN1 := CryptoFixupStub('SMIME_read_ASN1');
  Result := SMIME_read_ASN1(bio,bcont,it);
end;


function stub_SMIME_crlf_copy(_in: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT cdecl;
begin
  SMIME_crlf_copy := CryptoFixupStub('SMIME_crlf_copy');
  Result := SMIME_crlf_copy(_in,_out,flags);
end;

function stub_SMIME_text(_in: PBIO; _out: PBIO): TIdC_INT cdecl;
begin
  SMIME_text := CryptoFixupStub('SMIME_text');
  Result := SMIME_text(_in, _out);
end;

function stub_ERR_load_ASN1_strings: TIdC_INT;
begin
  ERR_load_ASN1_strings := CryptoFixupStub('ERR_load_ASN1_strings');
  Result := ERR_load_ASN1_strings;
end;

procedure ResetValues;
begin
  ASN1_TYPE_set := stub_ASN1_TYPE_set;
  ASN1_TYPE_set1 := stub_ASN1_TYPE_set1;
  ASN1_TYPE_cmp := stub_ASN1_TYPE_cmp;
  ASN1_TYPE_pack_sequence := stub_ASN1_TYPE_pack_sequence;
  ASN1_TYPE_unpack_sequence := stub_ASN1_TYPE_unpack_sequence;
  ASN1_OBJECT_new := stub_ASN1_OBJECT_new;
  ASN1_OBJECT_free := stub_ASN1_OBJECT_free;
  i2d_ASN1_OBJECT := stub_i2d_ASN1_OBJECT;
  d2i_ASN1_OBJECT := stub_d2i_ASN1_OBJECT;
  ASN1_STRING_free := stub_ASN1_STRING_free;
  ASN1_STRING_clear_free := stub_ASN1_STRING_clear_free;
  ASN1_STRING_copy := stub_ASN1_STRING_copy;
  ASN1_STRING_dup := stub_ASN1_STRING_dup;
  ASN1_STRING_type_new := stub_ASN1_STRING_type_new;
  ASN1_STRING_cmp := stub_ASN1_STRING_cmp;
  ASN1_STRING_set := stub_ASN1_STRING_set;
  ASN1_STRING_set0 := stub_ASN1_STRING_set0;
  ASN1_STRING_length := stub_ASN1_STRING_length;
  ASN1_STRING_length_set := stub_ASN1_STRING_length_set;
  ASN1_STRING_type := stub_ASN1_STRING_type;
  ASN1_BIT_STRING_set := stub_ASN1_BIT_STRING_set;
  ASN1_BIT_STRING_set_bit := stub_ASN1_BIT_STRING_set_bit;
  ASN1_BIT_STRING_get_bit := stub_ASN1_BIT_STRING_get_bit;
  ASN1_BIT_STRING_check := stub_ASN1_BIT_STRING_check;
  ASN1_BIT_STRING_name_print := stub_ASN1_BIT_STRING_name_print;
  ASN1_BIT_STRING_num_asc := stub_ASN1_BIT_STRING_num_asc;
  ASN1_BIT_STRING_set_asc := stub_ASN1_BIT_STRING_set_asc;
  d2i_ASN1_UINTEGER := stub_d2i_ASN1_UINTEGER;
  ASN1_INTEGER_dup := stub_ASN1_INTEGER_dup;
  ASN1_INTEGER_cmp := stub_ASN1_INTEGER_cmp;
  ASN1_UTCTIME_check := stub_ASN1_UTCTIME_check;
  ASN1_UTCTIME_set := stub_ASN1_UTCTIME_set;
  ASN1_UTCTIME_adj := stub_ASN1_UTCTIME_adj;
  ASN1_UTCTIME_set_string := stub_ASN1_UTCTIME_set_string;
  ASN1_UTCTIME_cmp_time_t := stub_ASN1_UTCTIME_cmp_time_t;
  ASN1_GENERALIZEDTIME_check := stub_ASN1_GENERALIZEDTIME_check;
  ASN1_GENERALIZEDTIME_set := stub_ASN1_GENERALIZEDTIME_set;
  ASN1_GENERALIZEDTIME_adj := stub_ASN1_GENERALIZEDTIME_adj;
  ASN1_GENERALIZEDTIME_set_string := stub_ASN1_GENERALIZEDTIME_set_string;
  ASN1_TIME_diff := stub_ASN1_TIME_diff;
  ASN1_OCTET_STRING_dup := stub_ASN1_OCTET_STRING_dup;
  ASN1_OCTET_STRING_cmp := stub_ASN1_OCTET_STRING_cmp;
  ASN1_OCTET_STRING_set := stub_ASN1_OCTET_STRING_set;
  UTF8_getc := stub_UTF8_getc;
  UTF8_putc := stub_UTF8_putc;
  ASN1_TIME_adj := stub_ASN1_TIME_adj;
  ASN1_TIME_check := stub_ASN1_TIME_check;
  ASN1_TIME_to_generalizedtime := stub_ASN1_TIME_to_generalizedtime;
  ASN1_TIME_set_string := stub_ASN1_TIME_set_string;
  i2a_ASN1_INTEGER := stub_i2a_ASN1_INTEGER;
  a2i_ASN1_INTEGER := stub_a2i_ASN1_INTEGER;
  i2a_ASN1_ENUMERATED := stub_i2a_ASN1_ENUMERATED;
  a2i_ASN1_ENUMERATED := Stub_a2i_ASN1_ENUMERATED;
  i2a_ASN1_OBJECT := stub_i2a_ASN1_OBJECT;
  a2i_ASN1_STRING := stub_a2i_ASN1_STRING;
  i2a_ASN1_STRING := stub_i2a_ASN1_STRING;
  i2t_ASN1_OBJECT := stub_i2t_ASN1_OBJECT;
  a2d_ASN1_OBJECT := stub_a2d_ASN1_OBJECT;
  ASN1_OBJECT_create := stub_ASN1_OBJECT_create;
  ASN1_INTEGER_get_int64 := stub_ASN1_INTEGER_get_int64;
  ASN1_INTEGER_set_int64 := stub_ASN1_INTEGER_set_int64;
  ASN1_INTEGER_get_uint64 := stub_ASN1_INTEGER_get_uint64;
  ASN1_INTEGER_set := stub_ASN1_INTEGER_set;
  ASN1_INTEGER_get := stub_ASN1_INTEGER_get;
  BN_to_ASN1_INTEGER := stub_BN_to_ASN1_INTEGER;
  ASN1_INTEGER_to_BN := stub_ASN1_INTEGER_to_BN;
  ASN1_ENUMERATED_get_int64 := stub_ASN1_ENUMERATED_get_int64;
  ASN1_ENUMERATED_set_int64 := stub_ASN1_ENUMERATED_set_int64;
  ASN1_ENUMERATED_set := stub_ASN1_ENUMERATED_set;
  ASN1_ENUMERATED_get := stub_ASN1_ENUMERATED_get;
  BN_to_ASN1_ENUMERATED := stub_BN_to_ASN1_ENUMERATED;
  ASN1_ENUMERATED_to_BN := stub_ASN1_ENUMERATED_to_BN;
  ASN1_PRINTABLE_type := stub_ASN1_PRINTABLE_type;
  ASN1_tag2bit := stub_ASN1_tag2bit;
  ASN1_get_object := stub_ASN1_get_object;
  ASN1_check_infinite_end := stub_ASN1_check_infinite_end;
  ASN1_const_check_infinite_end := stub_ASN1_const_check_infinite_end;
  ASN1_put_object := stub_ASN1_put_object;
  ASN1_put_eoc := stub_ASN1_put_eoc;
  ASN1_dup := stub_ASN1_dup;
  ASN1_item_dup := stub_ASN1_item_dup;
{$IFNDEF OPENSSL_NO_STDIO}
  ASN1_d2i_fp := stub_ASN1_d2i_fp;
  ASN1_item_d2i_fp := stub_ASN1_item_d2i_fp;
  ASN1_i2d_fp := stub_ASN1_i2d_fp;
  ASN1_item_i2d_fp := stub_ASN1_item_i2d_fp;
  ASN1_STRING_print_ex_fp := stub_ASN1_STRING_print_ex_fp;
{$ENDIF}
  ASN1_STRING_to_UTF8 := stub_ASN1_STRING_to_UTF8;
  ASN1_d2i_bio := stub_ASN1_d2i_bio;
  ASN1_item_d2i_bio := stub_ASN1_item_d2i_bio;
  ASN1_i2d_bio := stub_ASN1_i2d_bio;
  ASN1_item_i2d_bio := stub_ASN1_item_i2d_bio;
  ASN1_UTCTIME_print := stub_ASN1_UTCTIME_print;
  ASN1_GENERALIZEDTIME_print := stub_ASN1_GENERALIZEDTIME_print;
  ASN1_TIME_print := stub_ASN1_TIME_print;
  ASN1_STRING_print := stub_ASN1_STRING_print;
  ASN1_STRING_print_ex := stub_ASN1_STRING_print_ex;
  ASN1_buf_print := stub_ASN1_buf_print;
  ASN1_bn_print := stub_ASN1_bn_print;
  ASN1_parse := stub_ASN1_parse;
  ASN1_parse_dump := stub_ASN1_parse_dump;
  ASN1_tag2str := stub_ASN1_tag2str;
  ASN1_TYPE_set_octetstring := stub_ASN1_TYPE_set_octetstring;
  ASN1_TYPE_get_octetstring := stub_ASN1_TYPE_get_octetstring;
  ASN1_TYPE_set_int_octetstring := stub_ASN1_TYPE_set_int_octetstring;
  ASN1_TYPE_get_int_octetstring := stub_ASN1_TYPE_get_int_octetstring;
  ASN1_item_unpack := stub_ASN1_item_unpack;
  ASN1_item_pack := stub_ASN1_item_pack;
  ASN1_STRING_set_default_mask := stub_ASN1_STRING_set_default_mask;
  ASN1_STRING_set_default_mask_asc := stub_ASN1_STRING_set_default_mask_asc;
  ASN1_STRING_get_default_mask := stub_ASN1_STRING_get_default_mask;
  ASN1_mbstring_copy := stub_ASN1_mbstring_copy;
  ASN1_mbstring_ncopy := stub_ASN1_mbstring_ncopy;
  ASN1_STRING_set_by_NID := stub_ASN1_STRING_set_by_NID;
  ASN1_STRING_TABLE_get := stub_ASN1_STRING_TABLE_get;
  ASN1_STRING_TABLE_add := stub_ASN1_STRING_TABLE_add;
  ASN1_STRING_TABLE_cleanup := stub_ASN1_STRING_TABLE_cleanup;
  ASN1_item_new := stub_ASN1_item_new;
  ASN1_item_free := stub_ASN1_item_free;
  ASN1_item_d2i := stub_ASN1_item_d2i;
  ASN1_item_i2d := stub_ASN1_item_i2d;
  ASN1_item_ndef_i2d := stub_ASN1_item_ndef_i2d;
  ASN1_add_oid_module := stub_ASN1_add_oid_module;
  ASN1_add_stable_module := stub_ASN1_add_stable_module;
  ASN1_generate_nconf := stub_ASN1_generate_nconf;
    ASN1_generate_v3 := stub_ASN1_generate_v3;
    ASN1_str2mask := stub_ASN1_str2mask;
    ASN1_PCTX_new := stub_ASN1_PCTX_new;
    ASN1_PCTX_free := stub_ASN1_PCTX_free;
    ASN1_PCTX_get_flags := stub_ASN1_PCTX_get_flags;
    ASN1_PCTX_set_flags := stub_ASN1_PCTX_set_flags;
    ASN1_PCTX_get_nm_flags := stub_ASN1_PCTX_get_nm_flags;
    ASN1_PCTX_set_nm_flags := stub_ASN1_PCTX_set_nm_flags;
    ASN1_PCTX_get_cert_flags := stub_ASN1_PCTX_get_cert_flags;
    ASN1_PCTX_set_cert_flags := stub_ASN1_PCTX_set_cert_flags;
    ASN1_PCTX_get_oid_flags := stub_ASN1_PCTX_get_oid_flags;
    ASN1_PCTX_set_oid_flags := stub_ASN1_PCTX_set_oid_flags;
    ASN1_PCTX_get_str_flags := stub_ASN1_PCTX_get_str_flags;
    ASN1_PCTX_set_str_flags := stub_ASN1_PCTX_set_str_flags;
    ASN1_SCTX_new := stub_ASN1_SCTX_new;
    ASN1_SCTX_free := stub_ASN1_SCTX_free;
    ASN1_SCTX_get_item := stub_ASN1_SCTX_get_item;
    ASN1_SCTX_get_template := stub_ASN1_SCTX_get_template;
    ASN1_SCTX_get_flags := stub_ASN1_SCTX_get_flags;
    ASN1_SCTX_set_app_data := stub_ASN1_SCTX_set_app_data;

    ASN1_SCTX_get_app_data := stub_ASN1_SCTX_get_app_data;

    BIO_f_asn1 := stub_BIO_f_asn1;
    BIO_new_NDEF := stub_BIO_new_NDEF;
    i2d_ASN1_bio_stream := stub_i2d_ASN1_bio_stream;
    PEM_write_bio_ASN1_stream := stub_PEM_write_bio_ASN1_stream;
    SMIME_read_ASN1 := stub_SMIME_read_ASN1;
    ASN1_TIME_set := stub_ASN1_TIME_set;
    SMIME_crlf_copy := stub_SMIME_crlf_copy;
    SMIME_text := stub_SMIME_text;

    { BEGIN ERROR CODES }
  {
    * The following lines are auto generated by the script mkerr.pl. Any changes
    * made after this point may be overwritten when the script is next run.
  }
  ERR_load_ASN1_strings := stub_ERR_load_ASN1_strings;

end;

initialization

ResetValues;

end.
