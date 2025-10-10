(* This unit was generated from the source file rc4.h2pas 
It should not be modified directly. All changes should be made to rc4.h2pas
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

unit IdOpenSSLHeaders_rc4;


interface

{
  Automatically converted by H2Pas 1.0.0 from rc4.h
  The following command line parameters were used:
    rc4.h
}

uses
  IdSSLOpenSSLAPI;

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}


  { crypto/rc4/rc4.h  }
  { Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
   * All rights reserved.
   *
   * This package is an SSL implementation written
   * by Eric Young (eay@cryptsoft.com).
   * The implementation was written so as to conform with Netscapes SSL.
   *
   * This library is free for commercial and non-commercial use as long as
   * the following conditions are aheared to.  The following conditions
   * apply to all code found in this distribution, be it the RC4, RSA,
   * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
   * included with this distribution is covered by the same copyright terms
   * except that the holder is Tim Hudson (tjh@cryptsoft.com).
   *
   * Copyright remains Eric Young's, and as such any Copyright notices in
   * the code are not to be removed.
   * If this package is used in a product, Eric Young should be given attribution
   * as the author of the parts of the library used.
   * This can be in the form of a textual message at program startup or
   * in documentation (online or textual) provided with the package.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. All advertising materials mentioning features or use of this software
   *    must display the following acknowledgement:
   *    "This product includes cryptographic software written by
   *     Eric Young (eay@cryptsoft.com)"
   *    The word 'cryptographic' can be left out if the rouines from the library
   *    being used are not cryptographic related :-).
   * 4. If you include any Windows specific code (or a derivative thereof) from
   *    the apps directory (application code) you must include an acknowledgement:
   *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
   *
   * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
   * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   * SUCH DAMAGE.
   *
   * The licence and distribution terms for any publically available version or
   * derivative of this code cannot be changed.  i.e. this code cannot simply be
   * copied and put under another distribution licence
   * [including the GNU Public Licence.]
    }

  
type
    PRC4_KEY  = ^RC4_KEY;
    RC4_INT = TOpenSSL_C_UINT;
    rc4_key_st = record
        x : RC4_INT;
        y : RC4_INT;
        data : array[0..255] of RC4_INT;
      end;
    RC4_KEY = rc4_key_st;

{interface_body}
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$IFNDEF OPENSSL_NO_RC4}
{$EXTERNALSYM RC4_options}
{$EXTERNALSYM RC4_set_key}
{$EXTERNALSYM private_RC4_set_key}
{$EXTERNALSYM RC4}
{$ENDIF}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_RC4}
{$IFNDEF OPENSSL_NO_RC4}
  
function RC4_options: PAnsiChar; cdecl; external CLibCrypto;
procedure RC4_set_key(key:PRC4_KEY; len: TOpenSSL_C_LONG; const data:Pbyte); cdecl; external CLibCrypto;
procedure private_RC4_set_key(key:PRC4_KEY; len: TOpenSSL_C_LONG; const data:Pbyte); cdecl; external CLibCrypto;
procedure RC4(key:PRC4_KEY; len: TOpenSSL_C_SIZET; const indata: Pbyte; outdata: Pbyte); cdecl; external CLibCrypto;
{$ENDIF}
{$ENDIF}



{$ELSE}
{$IFNDEF OPENSSL_NO_RC4}
{$ENDIF}

{$IFNDEF OPENSSL_NO_RC4}
{$IFNDEF OPENSSL_NO_RC4}
  
var
  RC4_options: function : PAnsiChar; cdecl = nil;
  RC4_set_key: procedure (key:PRC4_KEY; len: TOpenSSL_C_LONG; const data:Pbyte); cdecl = nil;
  private_RC4_set_key: procedure (key:PRC4_KEY; len: TOpenSSL_C_LONG; const data:Pbyte); cdecl = nil;
  RC4: procedure (key:PRC4_KEY; len: TOpenSSL_C_SIZET; const indata: Pbyte; outdata: Pbyte); cdecl = nil;
{$ENDIF}
{$ENDIF}


{$ENDIF}

implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_RC4}
{$ENDIF}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_RC4}
{$ENDIF}

{$WARN  NO_RETVAL OFF}
{$IFNDEF OPENSSL_NO_RC4}
{$ENDIF}
{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_RC4}
  RC4_options := LoadLibCryptoFunction('RC4_options');
  FuncLoadError := not assigned(RC4_options);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  RC4_set_key := LoadLibCryptoFunction('RC4_set_key');
  FuncLoadError := not assigned(RC4_set_key);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  private_RC4_set_key := LoadLibCryptoFunction('private_RC4_set_key');
  FuncLoadError := not assigned(private_RC4_set_key);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  RC4 := LoadLibCryptoFunction('RC4');
  FuncLoadError := not assigned(RC4);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

{$ENDIF}
end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_RC4}
  RC4_options := nil;
  RC4_set_key := nil;
  private_RC4_set_key := nil;
  RC4 := nil;
{$ENDIF}
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
