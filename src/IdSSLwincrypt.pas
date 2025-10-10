unit IdSSLwincrypt;

{
  $Project$
  $Workfile$
  $Revision$
  $DateUTC$
  $Id$
  }
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
  {   (c) 1993-2024, the Indy Pit Crew. All rights reserved.   }
  {                                                                              }
  {******************************************************************************}
  {                                                                              }
  {        Contributers:                                                         }
  {                               Here could be your name                        }
  {                                                                              }
  {******************************************************************************}

{
  $Log$
}


interface

{$I IdCompilerDefines.inc}

{$IFDEF WINDOWS}
{$IFNDEF OPENSSL_DONT_USE_WINDOWS_CERT_STORE}
{$DEFINE USE_WINDOWS_CERT_STORE}
{$ENDIF}
{$ENDIF}


{$IFNDEF USE_OPENSSL}
  {$message error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}

{$TYPEDADDRESS OFF}


uses
  Classes,
  SysUtils,
  {$IFDEF WINDOWS} Windows, {$ENDIF}
  IdCTypes,
  IdGlobal;

{$IFDEF USE_WINDOWS_CERT_STORE}

const
  wincryptdll = 'crypt32.dll';
  RootStore = 'ROOT';

type
  HCERTSTORE = THandle;
  HCRYPTPROV_LEGACY = PIdC_LONG;
  PCERT_INFO = pointer; {don't need to know this structure}
  PCCERT_CONTEXT = ^CERT_CONTEXT;
  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    CertInfo: PCERT_INFO;
    certstore: HCERTSTORE
  end;

{$IFDEF STRING_IS_ANSI}
{$EXTERNALSYM CertOpenSystemStoreA}
function CertOpenSystemStoreA(hProv: HCRYPTPROV_LEGACY; szSubsystemProtocol: PIdAnsiChar):HCERTSTORE;
  stdcall; external wincryptdll;
{$ELSE}
{$EXTERNALSYM CertOpenSystemStoreW}
function CertOpenSystemStoreW(hProv: HCRYPTPROV_LEGACY; szSubsystemProtocol: PCHar):HCERTSTORE;
  stdcall; external wincryptdll;
{$ENDIF}

{$EXTERNALSYM CertCloseStore}
function CertCloseStore(certstore: HCERTSTORE; dwFlags: DWORD): boolean; stdcall; external wincryptdll;

{$EXTERNALSYM CertEnumCertificatesInStore}
function CertEnumCertificatesInStore(certstore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT;
  stdcall; external wincryptdll;
{$ENDIF}

implementation

end.

