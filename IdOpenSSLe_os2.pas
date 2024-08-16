unit IdOpenSSLe_os2;
interface

uses
  IdCTypes;

{
  Automatically converted by H2Pas 1.0.0 from openssl-1.1.0l/include/openssl/e_os2.h
  The following command line parameters were used:
    -p
    -P
    -t
    -T
    -C
    openssl-1.1.0l/include/openssl/e_os2.h
}

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
{$ifndef HEADER_E_OS2_H}
{$define HEADER_E_OS2_H}

{ C++ extern C conditionnal removed }
  {*****************************************************************************
   * Detect operating systems.  This probably needs completing.
   * The result is that at least one OPENSSL_SYS_os macro should be defined.
   * However, if none is defined, Unix is assumed.
   * }
{$define OPENSSL_SYS_UNIX}  
  { --------------------- Microsoft operating systems ----------------------  }
  {
   * Note that MSDOS actually denotes 32-bit environments running on top of
   * MS-DOS, such as DJGPP one.
    }
{$if defined(OPENSSL_SYS_MSDOS)}
{$undef OPENSSL_SYS_UNIX}
{$endif}
  {
   * For 32 bit environment, there seems to be the CygWin environment and then
   * all the others that try to do the same thing Microsoft does...
    }
  {
   * UEFI lives here because it might be built with a Microsoft toolchain and
   * we need to avoid the false positive match on Windows.
    }
{$if defined(OPENSSL_SYS_UEFI)}
{$undef OPENSSL_SYS_UNIX}
(*** was #elif ****){$else defined(OPENSSL_SYS_UWIN)}
{$undef OPENSSL_SYS_UNIX}
{$define OPENSSL_SYS_WIN32_UWIN}  
{$else}
{$if defined(__CYGWIN__) || defined(OPENSSL_SYS_CYGWIN)}
{$define OPENSSL_SYS_WIN32_CYGWIN}  
{$else}
{$if defined(_WIN32) || defined(OPENSSL_SYS_WIN32)}
{$undef OPENSSL_SYS_UNIX}
{$if !defined(OPENSSL_SYS_WIN32)}
{$define OPENSSL_SYS_WIN32}  
{$endif}
{$endif}
{$if defined(_WIN64) || defined(OPENSSL_SYS_WIN64)}
{$undef OPENSSL_SYS_UNIX}
{$if !defined(OPENSSL_SYS_WIN64)}
{$define OPENSSL_SYS_WIN64}  
{$endif}
{$endif}
{$if defined(OPENSSL_SYS_WINNT)}
{$undef OPENSSL_SYS_UNIX}
{$endif}
{$if defined(OPENSSL_SYS_WINCE)}
{$undef OPENSSL_SYS_UNIX}
{$endif}
{$endif}
{$endif}
  { Anything that tries to look like Microsoft is "Windows"  }
{$if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WIN64) || defined(OPENSSL_SYS_WINNT) || defined(OPENSSL_SYS_WINCE)}
{$undef OPENSSL_SYS_UNIX}
{$define OPENSSL_SYS_WINDOWS}  
{$ifndef OPENSSL_SYS_MSDOS}
{$define OPENSSL_SYS_MSDOS}  
{$endif}
{$endif}
  {
   * DLL settings.  This part is a bit tough, because it's up to the
   * application implementor how he or she will link the application, so it
   * requires some macro to be used.
    }
{$ifdef OPENSSL_SYS_WINDOWS}
{$ifndef OPENSSL_OPT_WINDLL}
{$if defined(_WINDLL)
{$endif}
{$endif}
{$endif}
    { ------------------------------- OpenVMS --------------------------------  }
{$if defined(__VMS) || defined(VMS) || defined(OPENSSL_SYS_VMS)}
{$if !defined(OPENSSL_SYS_VMS)}
{$undef OPENSSL_SYS_UNIX}
{$endif}
{$define OPENSSL_SYS_VMS}    
{$if defined(__DECC)}
{$define OPENSSL_SYS_VMS_DECC}    
(*** was #elif ****){$else defined(__DECCXX)}
{$define OPENSSL_SYS_VMS_DECC}    
{$define OPENSSL_SYS_VMS_DECCXX}    
{$else}
{$define OPENSSL_SYS_VMS_NODECC}    
{$endif}
{$endif}
    { -------------------------------- Unix ----------------------------------  }
{$ifdef OPENSSL_SYS_UNIX}
{$if defined(linux) || defined(__linux__) && !defined(OPENSSL_SYS_LINUX)}
{$define OPENSSL_SYS_LINUX}    
{$endif}
{$if defined(_AIX) && !defined(OPENSSL_SYS_AIX)}
{$define OPENSSL_SYS_AIX}    
{$endif}
{$endif}
    { -------------------------------- VOS -----------------------------------  }
{$if defined(__VOS__) && !defined(OPENSSL_SYS_VOS)}
{$define OPENSSL_SYS_VOS}    
{$ifdef __HPPA__}
{$define OPENSSL_SYS_VOS_HPPA}    
{$endif}
{$ifdef __IA32__}
{$define OPENSSL_SYS_VOS_IA32}    
{$endif}
{$endif}
    {*
     * That's it for OS-specific stuff
     **************************************************************************** }
    { Specials for I/O an exit  }
{$ifdef OPENSSL_SYS_MSDOS}
(* error 
#  define OPENSSL_UNISTD_IO <io.h>
in define line 141 *)
(* error 
#  define OPENSSL_DECLARE_EXIT extern void exit(int);
in declaration at line 142 *)
{$else}

//    const
//      OPENSSL_UNISTD_IO = OPENSSL_UNISTD;
//    { declared in unistd.h  }
{$define OPENSSL_DECLARE_EXIT}    
{$endif}
    {-
     * Definitions of OPENSSL_GLOBAL and OPENSSL_EXTERN, to define and declare
     * certain global symbols that, with some compilers under VMS, have to be
     * defined and declared explicitly with globaldef and globalref.
     * Definitions of OPENSSL_EXPORT and OPENSSL_IMPORT, to define and declare
     * DLL exports and imports for compilers under Win32.  These are a little
     * more complicated to use.  Basically, for any library that exports some
     * global variables, the following code must be present in the header file
     * that declares them, before OPENSSL_EXTERN is used:
     *
     * #ifdef SOME_BUILD_FLAG_MACRO
     * # undef OPENSSL_EXTERN
     * # define OPENSSL_EXTERN OPENSSL_EXPORT
     * #endif
     *
     * The default is to have OPENSSL_EXPORT, OPENSSL_EXTERN and OPENSSL_GLOBAL
     * have some generally sensible values.
      }
{$if defined(OPENSSL_SYS_VMS_NODECC)}

    const
      OPENSSL_EXPORT = globalref;      
      OPENSSL_EXTERN = globalref;      
      OPENSSL_GLOBAL = globaldef;      
(*** was #elif ****){$else defined(OPENSSL_SYS_WINDOWS) && defined(OPENSSL_OPT_WINDLL)}
(* error 
#  define OPENSSL_EXPORT extern __declspec(dllexport)
in define line 172 *)
(* error 
#  define OPENSSL_EXTERN extern __declspec(dllimport)
in define line 173 *)
{$define OPENSSL_GLOBAL}    
{$else}
(* error 
#  define OPENSSL_EXPORT extern
in define line 176 *)
(* error 
#  define OPENSSL_EXTERN extern
in define line 177 *)
{$define OPENSSL_GLOBAL}    
{$endif}
    {-
     * Macros to allow global variables to be reached through function calls when
     * required (if a shared library version requires it, for example.
     * The way it's done allows definitions like this:
     *
     *      // in foobar.c
     *      OPENSSL_IMPLEMENT_GLOBAL(int,foobar,0)
     *      // in foobar.h
     *      OPENSSL_DECLARE_GLOBAL(int,foobar);
     *      #define foobar OPENSSL_GLOBAL_REF(foobar)
      }
{$ifdef OPENSSL_EXPORT_VAR_AS_FUNCTION}
(* error 
        type *_shadow_##name(void)                                      \
in declaration at line 195 *)
(* error 
        { static type _hide_##name=value; return &_hide_##name; }
 in declarator_list *)
(* error 
        { static type _hide_##name=value; return &_hide_##name; }
in define line 196 *)
(* error 
#  define OPENSSL_GLOBAL_REF(name) (*(_shadow_##name()))
in define line 197 *)
{$else}
(* error 
#  define OPENSSL_IMPLEMENT_GLOBAL(type,name,value) OPENSSL_GLOBAL type _shadow_##name=value;
in declaration at line 199 *)
(* error 
#  define OPENSSL_DECLARE_GLOBAL(type,name) OPENSSL_EXPORT type _shadow_##name
in define line 200 *)
(* error 
#  define OPENSSL_GLOBAL_REF(name) _shadow_##name
in define line 201 *)
{$endif}
{$ifdef _WIN32}
{$ifdef _WIN64}

    const
      ossl_ssize_t = cint64;      
      OSSL_SSIZE_MAX = _I64_MAX;      
{$else}

    const
      ossl_ssize_t = cint;      
      OSSL_SSIZE_MAX = INT_MAX;      
{$endif}
{$endif}
{$if defined(OPENSSL_SYS_UEFI) && !defined(ossl_ssize_t)}

    const
      ossl_ssize_t = INTN;      
      OSSL_SSIZE_MAX = MAX_INTN;      
{$endif}
{$ifndef ossl_ssize_t}

    type
      ossl_ssize_t = TIdC_SSIZET;
{$if defined(SSIZE_MAX)}

    const
      OSSL_SSIZE_MAX = SSIZE_MAX;      
(*** was #elif ****){$else defined(_POSIX_SSIZE_MAX)}

//    const
//      OSSL_SSIZE_MAX = _POSIX_SSIZE_MAX;
{$endif}
{$endif}
{$ifdef DEBUG_UNUSED}

    { was #define dname def_expr }
    function __owur : longint; { return type might be wrong }

{$else}
{$define __owur}    
{$endif}
    { Standard integer types  }
{$if defined(OPENSSL_SYS_UEFI)}

    type
      Pint8_t = ^Tint8_t;
      Tint8_t = TINT8;

      Puint8_t = ^Tuint8_t;
      Tuint8_t = TUINT8;

      Pint16_t = ^Tint16_t;
      Tint16_t = TINT16;

      Puint16_t = ^Tuint16_t;
      Tuint16_t = TUINT16;

      Pint32_t = ^Tint32_t;
      Tint32_t = TINT32;

      Puint32_t = ^Tuint32_t;
      Tuint32_t = TUINT32;

      Pint64_t = ^Tint64_t;
      Tint64_t = TINT64;

      Puint64_t = ^Tuint64_t;
      Tuint64_t = TUINT64;
(*** was #elif ****){$else (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || \}
(* error 
     defined(__osf__) || defined(__sgi) || defined(__hpux) || \
{$include <inttypes.h>}
(*** was #elif ****){$else defined(_MSC_VER) && _MSC_VER<=1500}
    {
     * minimally required typdefs for systems not supporting inttypes.h or
     * stdint.h: currently just older VC++
      }
 in declarator_list *)

    type
      Puint8_t = ^Tuint8_t;
      Tuint8_t = Tcuchar;

      Pint16_t = ^Tint16_t;
      Tint16_t = Tcshort;

      Puint16_t = ^Tuint16_t;
      Tuint16_t = Tcushort;

      Pint32_t = ^Tint32_t;
      Tint32_t = Tcint;

      Puint32_t = ^Tuint32_t;
      Tuint32_t = Tcuint;

      Pint64_t = ^Tint64_t;
      Tint64_t = Tcint64;

      Puint64_t = ^Tuint64_t;
      Tuint64_t = Tcuint64;
{$else}
{$include <stdint.h>}
{$endif}
    { ossl_inline: portable inline definition usable in public headers  }
{$if !defined(inline) && !defined(__cplusplus)}
{$if defined(__STDC_VERSION__) && __STDC_VERSION__>=199901L}
    { just use inline  }

    const
      ossl_inline = inline;      
(*** was #elif ****){$else defined(__GNUC__) && __GNUC__>=2}

    const
      ossl_inline = __inline__;      
(*** was #elif ****){$else defined(_MSC_VER)}
    {
       * Visual Studio: inline is available in C++ only, however
       * __inline is available for C, see
       * http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
        }

    const
      ossl_inline = __inline;      
{$else}
{$define ossl_inline}    
{$endif}
{$else}

//    const
//      ossl_inline = inline;
{$endif}
{$if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L}

    const
      ossl_noreturn = _Noreturn;      
(*** was #elif ****){$else defined(__GNUC__) && __GNUC__ >= 2}


{$else}
{$define ossl_noreturn}    
{$endif}
{ C++ end of extern C conditionnal removed }
{$endif}

implementation

  uses
    SysUtils;

end.
