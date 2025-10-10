(* This unit was generated from the source file pkcs12.h2pas 
It should not be modified directly. All changes should be made to pkcs12.h2pas
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


unit IdOpenSSLHeaders_pkcs12;


interface

// Headers for OpenSSL 1.1.1
// pkcs12.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_pkcs7,
  IdOpenSSLHeaders_x509;

const
  PKCS12_KEY_ID = 1;
  PKCS12_IV_ID = 2;
  PKCS12_MAC_ID = 3;

  ///* Default iteration count */
  //# ifndef PKCS12_DEFAULT_ITER
  //#  define PKCS12_DEFAULT_ITER     PKCS5_DEFAULT_ITER
  //# endif
  
  PKCS12_MAC_KEY_LENGTH = 20;

  PKCS12_SALT_LEN = 8;

  ///* It's not clear if these are actually needed... */
  //# define PKCS12_key_gen PKCS12_key_gen_utf8
  //# define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8

  (* MS key usage constants *)
  KEY_EX  = $10;
  KEY_SIG = $80;

  PKCS12_ERROR    = 0;
  PKCS12_OK       = 1;
  
type
  PKCS12_MAC_DATA_st = type Pointer;
  PKCS12_MAC_DATA = PKCS12_MAC_DATA_st;
  PPKCS12_MAC_DATA = ^PKCS12_MAC_DATA;
  PPPKCS12_MAC_DATA = ^PPKCS12_MAC_DATA;

  PKCS12_st = type Pointer;
  PKCS12 = PKCS12_st;
  PPKCS12 = ^PKCS12;
  PPPKCS12 = ^PPKCS12;

  PKCS12_SAFEBAG_st = type Pointer;
  PKCS12_SAFEBAG = PKCS12_SAFEBAG_st;
  PPKCS12_SAFEBAG = ^PKCS12_SAFEBAG;
  PPPKCS12_SAFEBAG = ^PPKCS12_SAFEBAG;

//  DEFINE_STACK_OF(PKCS12_SAFEBAG)

  pkcs12_bag_st = type Pointer;
  PKCS12_BAGS = pkcs12_bag_st;
  PPKCS12_BAGS = ^PKCS12_BAGS;
  PPPKCS12_BAGS = ^PPKCS12_BAGS;

  //ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, TOpenSSL_C_INT attr_nid);
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM PKCS12_mac_present}
{$EXTERNALSYM PKCS12_get0_mac}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_attr}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_type}
{$EXTERNALSYM PKCS12_SAFEBAG_get_nid}
{$EXTERNALSYM PKCS12_SAFEBAG_get_bag_nid}
{$EXTERNALSYM PKCS12_SAFEBAG_get1_cert}
{$EXTERNALSYM PKCS12_SAFEBAG_get1_crl}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_p8inf}
{$EXTERNALSYM PKCS12_SAFEBAG_get0_pkcs8}
{$EXTERNALSYM PKCS12_SAFEBAG_create_cert}
{$EXTERNALSYM PKCS12_SAFEBAG_create_crl}
{$EXTERNALSYM PKCS12_SAFEBAG_create0_p8inf}
{$EXTERNALSYM PKCS12_SAFEBAG_create0_pkcs8}
{$EXTERNALSYM PKCS12_SAFEBAG_create_pkcs8_encrypt}
{$EXTERNALSYM PKCS12_item_pack_safebag}
{$EXTERNALSYM PKCS8_decrypt}
{$EXTERNALSYM PKCS12_decrypt_skey}
{$EXTERNALSYM PKCS8_encrypt}
{$EXTERNALSYM PKCS8_set0_pbe}
{$EXTERNALSYM PKCS12_add_localkeyid}
{$EXTERNALSYM PKCS12_add_friendlyname_asc}
{$EXTERNALSYM PKCS12_add_friendlyname_utf8}
{$EXTERNALSYM PKCS12_add_CSPName_asc}
{$EXTERNALSYM PKCS12_add_friendlyname_uni}
{$EXTERNALSYM PKCS8_add_keyusage}
{$EXTERNALSYM PKCS12_get_friendlyname}
{$EXTERNALSYM PKCS12_pbe_crypt}
{$EXTERNALSYM PKCS12_item_decrypt_d2i}
{$EXTERNALSYM PKCS12_item_i2d_encrypt}
{$EXTERNALSYM PKCS12_init}
{$EXTERNALSYM PKCS12_key_gen_asc}
{$EXTERNALSYM PKCS12_key_gen_uni}
{$EXTERNALSYM PKCS12_key_gen_utf8}
{$EXTERNALSYM PKCS12_PBE_keyivgen}
{$EXTERNALSYM PKCS12_gen_mac}
{$EXTERNALSYM PKCS12_verify_mac}
{$EXTERNALSYM PKCS12_set_mac}
{$EXTERNALSYM PKCS12_setup_mac}
{$EXTERNALSYM OPENSSL_asc2uni}
{$EXTERNALSYM OPENSSL_uni2asc}
{$EXTERNALSYM OPENSSL_utf82uni}
{$EXTERNALSYM OPENSSL_uni2utf8}
{$EXTERNALSYM PKCS12_new}
{$EXTERNALSYM PKCS12_free}
{$EXTERNALSYM d2i_PKCS12}
{$EXTERNALSYM i2d_PKCS12}
{$EXTERNALSYM PKCS12_it}
{$EXTERNALSYM PKCS12_MAC_DATA_new}
{$EXTERNALSYM PKCS12_MAC_DATA_free}
{$EXTERNALSYM d2i_PKCS12_MAC_DATA}
{$EXTERNALSYM i2d_PKCS12_MAC_DATA}
{$EXTERNALSYM PKCS12_MAC_DATA_it}
{$EXTERNALSYM PKCS12_SAFEBAG_new}
{$EXTERNALSYM PKCS12_SAFEBAG_free}
{$EXTERNALSYM d2i_PKCS12_SAFEBAG}
{$EXTERNALSYM i2d_PKCS12_SAFEBAG}
{$EXTERNALSYM PKCS12_SAFEBAG_it}
{$EXTERNALSYM PKCS12_BAGS_new}
{$EXTERNALSYM PKCS12_BAGS_free}
{$EXTERNALSYM d2i_PKCS12_BAGS}
{$EXTERNALSYM i2d_PKCS12_BAGS}
{$EXTERNALSYM PKCS12_BAGS_it}
{$EXTERNALSYM PKCS12_PBE_add}
{$EXTERNALSYM PKCS12_parse}
{$EXTERNALSYM PKCS12_create}
{$EXTERNALSYM i2d_PKCS12_bio}
{$EXTERNALSYM d2i_PKCS12_bio}
{$EXTERNALSYM PKCS12_newpass}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function PKCS12_mac_present(const p12: PPKCS12): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function PKCS8_decrypt(const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl; external CLibCrypto;
function PKCS8_encrypt(pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl; external CLibCrypto;
function PKCS8_set0_pbe(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl; external CLibCrypto;
function PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl; external CLibCrypto;
function PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function PKCS12_init(mode: TOpenSSL_C_INT): PPKCS12; cdecl; external CLibCrypto;
function PKCS12_key_gen_asc(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_key_gen_uni(pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_key_gen_utf8(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_gen_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_verify_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_set_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_setup_mac(p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OPENSSL_asc2uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function OPENSSL_uni2asc(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OPENSSL_utf82uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function OPENSSL_uni2utf8(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function PKCS12_new: PPKCS12; cdecl; external CLibCrypto;
procedure PKCS12_free(a: PPKCS12); cdecl; external CLibCrypto;
function d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl; external CLibCrypto;
function i2d_PKCS12(a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_it: PASN1_ITEM; cdecl; external CLibCrypto;
function PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl; external CLibCrypto;
procedure PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl; external CLibCrypto;
function d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl; external CLibCrypto;
function i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
procedure PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl; external CLibCrypto;
function d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl; external CLibCrypto;
function i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl; external CLibCrypto;
function PKCS12_BAGS_new: PPKCS12_BAGS; cdecl; external CLibCrypto;
procedure PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl; external CLibCrypto;
function d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl; external CLibCrypto;
function i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_BAGS_it: PASN1_ITEM; cdecl; external CLibCrypto;
procedure PKCS12_PBE_add(v: Pointer); cdecl; external CLibCrypto;
function PKCS12_parse(p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS12_create(const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl; external CLibCrypto;
function i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl; external CLibCrypto;
function PKCS12_newpass(p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_PKCS12_mac_present(const p12: PPKCS12): TOpenSSL_C_INT; cdecl;
procedure Load_PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl;
function Load_PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
function Load_PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl;
function Load_PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509; cdecl;
function Load_PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl;
function Load_PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl;
function Load_PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl;
function Load_PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl;
function Load_PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl;
function Load_PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
function Load_PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl;
function Load_PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
function Load_PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl;
function Load_PKCS8_decrypt(const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
function Load_PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
function Load_PKCS8_encrypt(pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl;
function Load_PKCS8_set0_pbe(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl;
function Load_PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl;
function Load_PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl;
function Load_PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl;
function Load_PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl;
function Load_PKCS12_init(mode: TOpenSSL_C_INT): PPKCS12; cdecl;
function Load_PKCS12_key_gen_asc(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_key_gen_uni(pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_key_gen_utf8(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_gen_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_verify_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_set_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_setup_mac(p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_OPENSSL_asc2uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl;
function Load_OPENSSL_uni2asc(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_OPENSSL_utf82uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl;
function Load_OPENSSL_uni2utf8(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_PKCS12_new: PPKCS12; cdecl;
procedure Load_PKCS12_free(a: PPKCS12); cdecl;
function Load_d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl;
function Load_i2d_PKCS12(a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_it: PASN1_ITEM; cdecl;
function Load_PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl;
procedure Load_PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl;
function Load_d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl;
function Load_i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl;
function Load_PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl;
procedure Load_PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl;
function Load_d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl;
function Load_i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl;
function Load_PKCS12_BAGS_new: PPKCS12_BAGS; cdecl;
procedure Load_PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl;
function Load_d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl;
function Load_i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_BAGS_it: PASN1_ITEM; cdecl;
procedure Load_PKCS12_PBE_add(v: Pointer); cdecl;
function Load_PKCS12_parse(p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl;
function Load_PKCS12_create(const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl;
function Load_i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl;
function Load_d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl;
function Load_PKCS12_newpass(p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  PKCS12_mac_present: function (const p12: PPKCS12): TOpenSSL_C_INT; cdecl = Load_PKCS12_mac_present;
  PKCS12_get0_mac: procedure (const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl = Load_PKCS12_get0_mac;
  PKCS12_SAFEBAG_get0_attr: function (const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl = Load_PKCS12_SAFEBAG_get0_attr;
  PKCS12_SAFEBAG_get0_type: function (const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl = Load_PKCS12_SAFEBAG_get0_type;
  PKCS12_SAFEBAG_get_nid: function (const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl = Load_PKCS12_SAFEBAG_get_nid;
  PKCS12_SAFEBAG_get_bag_nid: function (const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl = Load_PKCS12_SAFEBAG_get_bag_nid;
  PKCS12_SAFEBAG_get1_cert: function (const bag: PPKCS12_SAFEBAG): PX509; cdecl = Load_PKCS12_SAFEBAG_get1_cert;
  PKCS12_SAFEBAG_get1_crl: function (const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl = Load_PKCS12_SAFEBAG_get1_crl;
  PKCS12_SAFEBAG_get0_p8inf: function (const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl = Load_PKCS12_SAFEBAG_get0_p8inf;
  PKCS12_SAFEBAG_get0_pkcs8: function (const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl = Load_PKCS12_SAFEBAG_get0_pkcs8;
  PKCS12_SAFEBAG_create_cert: function (x509: PX509): PPKCS12_SAFEBAG; cdecl = Load_PKCS12_SAFEBAG_create_cert;
  PKCS12_SAFEBAG_create_crl: function (crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl = Load_PKCS12_SAFEBAG_create_crl;
  PKCS12_SAFEBAG_create0_p8inf: function (p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = Load_PKCS12_SAFEBAG_create0_p8inf;
  PKCS12_SAFEBAG_create0_pkcs8: function (p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl = Load_PKCS12_SAFEBAG_create0_pkcs8;
  PKCS12_SAFEBAG_create_pkcs8_encrypt: function (pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = Load_PKCS12_SAFEBAG_create_pkcs8_encrypt;
  PKCS12_item_pack_safebag: function (obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl = Load_PKCS12_item_pack_safebag;
  PKCS8_decrypt: function (const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl = Load_PKCS8_decrypt;
  PKCS12_decrypt_skey: function (const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl = Load_PKCS12_decrypt_skey;
  PKCS8_encrypt: function (pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl = Load_PKCS8_encrypt;
  PKCS8_set0_pbe: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl = Load_PKCS8_set0_pbe;
  PKCS12_add_localkeyid: function (bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_add_localkeyid;
  PKCS12_add_friendlyname_asc: function (bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_add_friendlyname_asc;
  PKCS12_add_friendlyname_utf8: function (bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_add_friendlyname_utf8;
  PKCS12_add_CSPName_asc: function (bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_add_CSPName_asc;
  PKCS12_add_friendlyname_uni: function (bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_add_friendlyname_uni;
  PKCS8_add_keyusage: function (p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS8_add_keyusage;
  PKCS12_get_friendlyname: function (bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl = Load_PKCS12_get_friendlyname;
  PKCS12_pbe_crypt: function (const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl = Load_PKCS12_pbe_crypt;
  PKCS12_item_decrypt_d2i: function (const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl = Load_PKCS12_item_decrypt_d2i;
  PKCS12_item_i2d_encrypt: function (algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl = Load_PKCS12_item_i2d_encrypt;
  PKCS12_init: function (mode: TOpenSSL_C_INT): PPKCS12; cdecl = Load_PKCS12_init;
  PKCS12_key_gen_asc: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS12_key_gen_asc;
  PKCS12_key_gen_uni: function (pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS12_key_gen_uni;
  PKCS12_key_gen_utf8: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS12_key_gen_utf8;
  PKCS12_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_PBE_keyivgen;
  PKCS12_gen_mac: function (p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_PKCS12_gen_mac;
  PKCS12_verify_mac: function (p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS12_verify_mac;
  PKCS12_set_mac: function (p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS12_set_mac;
  PKCS12_setup_mac: function (p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS12_setup_mac;
  OPENSSL_asc2uni: function (const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl = Load_OPENSSL_asc2uni;
  OPENSSL_uni2asc: function (const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OPENSSL_uni2asc;
  OPENSSL_utf82uni: function (const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl = Load_OPENSSL_utf82uni;
  OPENSSL_uni2utf8: function (const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OPENSSL_uni2utf8;
  PKCS12_new: function : PPKCS12; cdecl = Load_PKCS12_new;
  PKCS12_free: procedure (a: PPKCS12); cdecl = Load_PKCS12_free;
  d2i_PKCS12: function (a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl = Load_d2i_PKCS12;
  i2d_PKCS12: function (a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS12;
  PKCS12_it: function : PASN1_ITEM; cdecl = Load_PKCS12_it;
  PKCS12_MAC_DATA_new: function : PPKCS12_MAC_DATA; cdecl = Load_PKCS12_MAC_DATA_new;
  PKCS12_MAC_DATA_free: procedure (a: PPKCS12_MAC_DATA); cdecl = Load_PKCS12_MAC_DATA_free;
  d2i_PKCS12_MAC_DATA: function (a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl = Load_d2i_PKCS12_MAC_DATA;
  i2d_PKCS12_MAC_DATA: function (a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS12_MAC_DATA;
  PKCS12_MAC_DATA_it: function : PASN1_ITEM; cdecl = Load_PKCS12_MAC_DATA_it;
  PKCS12_SAFEBAG_new: function : PPKCS12_SAFEBAG; cdecl = Load_PKCS12_SAFEBAG_new;
  PKCS12_SAFEBAG_free: procedure (a: PPKCS12_SAFEBAG); cdecl = Load_PKCS12_SAFEBAG_free;
  d2i_PKCS12_SAFEBAG: function (a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl = Load_d2i_PKCS12_SAFEBAG;
  i2d_PKCS12_SAFEBAG: function (a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS12_SAFEBAG;
  PKCS12_SAFEBAG_it: function : PASN1_ITEM; cdecl = Load_PKCS12_SAFEBAG_it;
  PKCS12_BAGS_new: function : PPKCS12_BAGS; cdecl = Load_PKCS12_BAGS_new;
  PKCS12_BAGS_free: procedure (a: PPKCS12_BAGS); cdecl = Load_PKCS12_BAGS_free;
  d2i_PKCS12_BAGS: function (a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl = Load_d2i_PKCS12_BAGS;
  i2d_PKCS12_BAGS: function (a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS12_BAGS;
  PKCS12_BAGS_it: function : PASN1_ITEM; cdecl = Load_PKCS12_BAGS_it;
  PKCS12_PBE_add: procedure (v: Pointer); cdecl = Load_PKCS12_PBE_add;
  PKCS12_parse: function (p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl = Load_PKCS12_parse;
  PKCS12_create: function (const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl = Load_PKCS12_create;
  i2d_PKCS12_bio: function (bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS12_bio;
  d2i_PKCS12_bio: function (bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl = Load_d2i_PKCS12_bio;
  PKCS12_newpass: function (p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PKCS12_newpass;
{$ENDIF}
const
  PKCS12_mac_present_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_get0_mac_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_attr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_bag_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_cert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_p8inf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_pkcs8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_cert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_crl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_p8inf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_pkcs8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_pkcs8_encrypt_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS8_set0_pbe_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_add_friendlyname_utf8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS12_key_gen_utf8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_utf82uni_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_uni2utf8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function Load_PKCS12_mac_present(const p12: PPKCS12): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_mac_present := LoadLibCryptoFunction('PKCS12_mac_present');
  if not assigned(PKCS12_mac_present) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_mac_present');
  Result := PKCS12_mac_present(p12);
end;

procedure Load_PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl;
begin
  PKCS12_get0_mac := LoadLibCryptoFunction('PKCS12_get0_mac');
  if not assigned(PKCS12_get0_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_get0_mac');
  PKCS12_get0_mac(pmac,pmacalg,psalt,piter,p12);
end;

function Load_PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TOpenSSL_C_INT): PASN1_TYPE; cdecl;
begin
  PKCS12_SAFEBAG_get0_attr := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_attr');
  if not assigned(PKCS12_SAFEBAG_get0_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_attr');
  Result := PKCS12_SAFEBAG_get0_attr(bag,attr_nid);
end;

function Load_PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl;
begin
  PKCS12_SAFEBAG_get0_type := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_type');
  if not assigned(PKCS12_SAFEBAG_get0_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_type');
  Result := PKCS12_SAFEBAG_get0_type(bag);
end;

function Load_PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_SAFEBAG_get_nid := LoadLibCryptoFunction('PKCS12_SAFEBAG_get_nid');
  if not assigned(PKCS12_SAFEBAG_get_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get_nid');
  Result := PKCS12_SAFEBAG_get_nid(bag);
end;

function Load_PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_SAFEBAG_get_bag_nid := LoadLibCryptoFunction('PKCS12_SAFEBAG_get_bag_nid');
  if not assigned(PKCS12_SAFEBAG_get_bag_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get_bag_nid');
  Result := PKCS12_SAFEBAG_get_bag_nid(bag);
end;

function Load_PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509; cdecl;
begin
  PKCS12_SAFEBAG_get1_cert := LoadLibCryptoFunction('PKCS12_SAFEBAG_get1_cert');
  if not assigned(PKCS12_SAFEBAG_get1_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get1_cert');
  Result := PKCS12_SAFEBAG_get1_cert(bag);
end;

function Load_PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl;
begin
  PKCS12_SAFEBAG_get1_crl := LoadLibCryptoFunction('PKCS12_SAFEBAG_get1_crl');
  if not assigned(PKCS12_SAFEBAG_get1_crl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get1_crl');
  Result := PKCS12_SAFEBAG_get1_crl(bag);
end;

function Load_PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  PKCS12_SAFEBAG_get0_p8inf := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_p8inf');
  if not assigned(PKCS12_SAFEBAG_get0_p8inf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_p8inf');
  Result := PKCS12_SAFEBAG_get0_p8inf(bag);
end;

function Load_PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl;
begin
  PKCS12_SAFEBAG_get0_pkcs8 := LoadLibCryptoFunction('PKCS12_SAFEBAG_get0_pkcs8');
  if not assigned(PKCS12_SAFEBAG_get0_pkcs8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_get0_pkcs8');
  Result := PKCS12_SAFEBAG_get0_pkcs8(bag);
end;

function Load_PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_SAFEBAG_create_cert := LoadLibCryptoFunction('PKCS12_SAFEBAG_create_cert');
  if not assigned(PKCS12_SAFEBAG_create_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create_cert');
  Result := PKCS12_SAFEBAG_create_cert(x509);
end;

function Load_PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_SAFEBAG_create_crl := LoadLibCryptoFunction('PKCS12_SAFEBAG_create_crl');
  if not assigned(PKCS12_SAFEBAG_create_crl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create_crl');
  Result := PKCS12_SAFEBAG_create_crl(crl);
end;

function Load_PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_SAFEBAG_create0_p8inf := LoadLibCryptoFunction('PKCS12_SAFEBAG_create0_p8inf');
  if not assigned(PKCS12_SAFEBAG_create0_p8inf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create0_p8inf');
  Result := PKCS12_SAFEBAG_create0_p8inf(p8);
end;

function Load_PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_SAFEBAG_create0_pkcs8 := LoadLibCryptoFunction('PKCS12_SAFEBAG_create0_pkcs8');
  if not assigned(PKCS12_SAFEBAG_create0_pkcs8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create0_pkcs8');
  Result := PKCS12_SAFEBAG_create0_pkcs8(p8);
end;

function Load_PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TOpenSSL_C_INT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_SAFEBAG_create_pkcs8_encrypt := LoadLibCryptoFunction('PKCS12_SAFEBAG_create_pkcs8_encrypt');
  if not assigned(PKCS12_SAFEBAG_create_pkcs8_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_create_pkcs8_encrypt');
  Result := PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid,pass,passlen,salt,saltlen,iter,p8inf);
end;

function Load_PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TOpenSSL_C_INT; nid2: TOpenSSL_C_INT): PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_item_pack_safebag := LoadLibCryptoFunction('PKCS12_item_pack_safebag');
  if not assigned(PKCS12_item_pack_safebag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_item_pack_safebag');
  Result := PKCS12_item_pack_safebag(obj,it,nid1,nid2);
end;

function Load_PKCS8_decrypt(const p8: PX509_SIG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  PKCS8_decrypt := LoadLibCryptoFunction('PKCS8_decrypt');
  if not assigned(PKCS8_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_decrypt');
  Result := PKCS8_decrypt(p8,pass,passlen);
end;

function Load_PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
begin
  PKCS12_decrypt_skey := LoadLibCryptoFunction('PKCS12_decrypt_skey');
  if not assigned(PKCS12_decrypt_skey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_decrypt_skey');
  Result := PKCS12_decrypt_skey(bag,pass,passlen);
end;

function Load_PKCS8_encrypt(pbe_nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl;
begin
  PKCS8_encrypt := LoadLibCryptoFunction('PKCS8_encrypt');
  if not assigned(PKCS8_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_encrypt');
  Result := PKCS8_encrypt(pbe_nid,cipher,pass,passlen,salt,saltlen,iter,p8);
end;

function Load_PKCS8_set0_pbe(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl;
begin
  PKCS8_set0_pbe := LoadLibCryptoFunction('PKCS8_set0_pbe');
  if not assigned(PKCS8_set0_pbe) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_set0_pbe');
  Result := PKCS8_set0_pbe(pass,passlen,p8inf,pbe);
end;

function Load_PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_add_localkeyid := LoadLibCryptoFunction('PKCS12_add_localkeyid');
  if not assigned(PKCS12_add_localkeyid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_localkeyid');
  Result := PKCS12_add_localkeyid(bag,name,namelen);
end;

function Load_PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_add_friendlyname_asc := LoadLibCryptoFunction('PKCS12_add_friendlyname_asc');
  if not assigned(PKCS12_add_friendlyname_asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_friendlyname_asc');
  Result := PKCS12_add_friendlyname_asc(bag,name,namelen);
end;

function Load_PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_add_friendlyname_utf8 := LoadLibCryptoFunction('PKCS12_add_friendlyname_utf8');
  if not assigned(PKCS12_add_friendlyname_utf8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_friendlyname_utf8');
  Result := PKCS12_add_friendlyname_utf8(bag,name,namelen);
end;

function Load_PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PAnsiChar; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_add_CSPName_asc := LoadLibCryptoFunction('PKCS12_add_CSPName_asc');
  if not assigned(PKCS12_add_CSPName_asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_CSPName_asc');
  Result := PKCS12_add_CSPName_asc(bag,name,namelen);
end;

function Load_PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_add_friendlyname_uni := LoadLibCryptoFunction('PKCS12_add_friendlyname_uni');
  if not assigned(PKCS12_add_friendlyname_uni) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_add_friendlyname_uni');
  Result := PKCS12_add_friendlyname_uni(bag,name,namelen);
end;

function Load_PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS8_add_keyusage := LoadLibCryptoFunction('PKCS8_add_keyusage');
  if not assigned(PKCS8_add_keyusage) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS8_add_keyusage');
  Result := PKCS8_add_keyusage(p8,usage);
end;

function Load_PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl;
begin
  PKCS12_get_friendlyname := LoadLibCryptoFunction('PKCS12_get_friendlyname');
  if not assigned(PKCS12_get_friendlyname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_get_friendlyname');
  Result := PKCS12_get_friendlyname(bag);
end;

function Load_PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const in_: PByte; inlen: TOpenSSL_C_INT; data: PPByte; datalen: POpenSSL_C_INT; en_de: TOpenSSL_C_INT): PByte; cdecl;
begin
  PKCS12_pbe_crypt := LoadLibCryptoFunction('PKCS12_pbe_crypt');
  if not assigned(PKCS12_pbe_crypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_pbe_crypt');
  Result := PKCS12_pbe_crypt(algor,pass,passlen,in_,inlen,data,datalen,en_de);
end;

function Load_PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const oct: PASN1_OCTET_STRING; zbuf: TOpenSSL_C_INT): Pointer; cdecl;
begin
  PKCS12_item_decrypt_d2i := LoadLibCryptoFunction('PKCS12_item_decrypt_d2i');
  if not assigned(PKCS12_item_decrypt_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_item_decrypt_d2i');
  Result := PKCS12_item_decrypt_d2i(algor,it,pass,passlen,oct,zbuf);
end;

function Load_PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; obj: Pointer; zbuf: TOpenSSL_C_INT): PASN1_OCTET_STRING; cdecl;
begin
  PKCS12_item_i2d_encrypt := LoadLibCryptoFunction('PKCS12_item_i2d_encrypt');
  if not assigned(PKCS12_item_i2d_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_item_i2d_encrypt');
  Result := PKCS12_item_i2d_encrypt(algor,it,pass,passlen,obj,zbuf);
end;

function Load_PKCS12_init(mode: TOpenSSL_C_INT): PPKCS12; cdecl;
begin
  PKCS12_init := LoadLibCryptoFunction('PKCS12_init');
  if not assigned(PKCS12_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_init');
  Result := PKCS12_init(mode);
end;

function Load_PKCS12_key_gen_asc(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_key_gen_asc := LoadLibCryptoFunction('PKCS12_key_gen_asc');
  if not assigned(PKCS12_key_gen_asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_key_gen_asc');
  Result := PKCS12_key_gen_asc(pass,passlen,salt,saltlen,id,iter,n,out_,md_type);
end;

function Load_PKCS12_key_gen_uni(pass: PByte; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_key_gen_uni := LoadLibCryptoFunction('PKCS12_key_gen_uni');
  if not assigned(PKCS12_key_gen_uni) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_key_gen_uni');
  Result := PKCS12_key_gen_uni(pass,passlen,salt,saltlen,id,iter,n,out_,md_type);
end;

function Load_PKCS12_key_gen_utf8(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; id: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; n: TOpenSSL_C_INT; out_: PByte; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_key_gen_utf8 := LoadLibCryptoFunction('PKCS12_key_gen_utf8');
  if not assigned(PKCS12_key_gen_utf8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_key_gen_utf8');
  Result := PKCS12_key_gen_utf8(pass,passlen,salt,saltlen,id,iter,n,out_,md_type);
end;

function Load_PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_PBE_keyivgen := LoadLibCryptoFunction('PKCS12_PBE_keyivgen');
  if not assigned(PKCS12_PBE_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_PBE_keyivgen');
  Result := PKCS12_PBE_keyivgen(ctx,pass,passlen,param,cipher,md_type,en_de);
end;

function Load_PKCS12_gen_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; mac: PByte; maclen: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_gen_mac := LoadLibCryptoFunction('PKCS12_gen_mac');
  if not assigned(PKCS12_gen_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_gen_mac');
  Result := PKCS12_gen_mac(p12,pass,passlen,mac,maclen);
end;

function Load_PKCS12_verify_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_verify_mac := LoadLibCryptoFunction('PKCS12_verify_mac');
  if not assigned(PKCS12_verify_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_verify_mac');
  Result := PKCS12_verify_mac(p12,pass,passlen);
end;

function Load_PKCS12_set_mac(p12: PPKCS12; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_set_mac := LoadLibCryptoFunction('PKCS12_set_mac');
  if not assigned(PKCS12_set_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_set_mac');
  Result := PKCS12_set_mac(p12,pass,passlen,salt,saltlen,iter,md_type);
end;

function Load_PKCS12_setup_mac(p12: PPKCS12; iter: TOpenSSL_C_INT; salt: PByte; saltlen: TOpenSSL_C_INT; const md_type: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_setup_mac := LoadLibCryptoFunction('PKCS12_setup_mac');
  if not assigned(PKCS12_setup_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_setup_mac');
  Result := PKCS12_setup_mac(p12,iter,salt,saltlen,md_type);
end;

function Load_OPENSSL_asc2uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl;
begin
  OPENSSL_asc2uni := LoadLibCryptoFunction('OPENSSL_asc2uni');
  if not assigned(OPENSSL_asc2uni) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_asc2uni');
  Result := OPENSSL_asc2uni(asc,asclen,uni,unilen);
end;

function Load_OPENSSL_uni2asc(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OPENSSL_uni2asc := LoadLibCryptoFunction('OPENSSL_uni2asc');
  if not assigned(OPENSSL_uni2asc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_uni2asc');
  Result := OPENSSL_uni2asc(uni,unilen);
end;

function Load_OPENSSL_utf82uni(const asc: PAnsiChar; asclen: TOpenSSL_C_INT; uni: PPByte; unilen: POpenSSL_C_INT): PByte; cdecl;
begin
  OPENSSL_utf82uni := LoadLibCryptoFunction('OPENSSL_utf82uni');
  if not assigned(OPENSSL_utf82uni) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_utf82uni');
  Result := OPENSSL_utf82uni(asc,asclen,uni,unilen);
end;

function Load_OPENSSL_uni2utf8(const uni: PByte; unilen: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OPENSSL_uni2utf8 := LoadLibCryptoFunction('OPENSSL_uni2utf8');
  if not assigned(OPENSSL_uni2utf8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_uni2utf8');
  Result := OPENSSL_uni2utf8(uni,unilen);
end;

function Load_PKCS12_new: PPKCS12; cdecl;
begin
  PKCS12_new := LoadLibCryptoFunction('PKCS12_new');
  if not assigned(PKCS12_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_new');
  Result := PKCS12_new();
end;

procedure Load_PKCS12_free(a: PPKCS12); cdecl;
begin
  PKCS12_free := LoadLibCryptoFunction('PKCS12_free');
  if not assigned(PKCS12_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_free');
  PKCS12_free(a);
end;

function Load_d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12; cdecl;
begin
  d2i_PKCS12 := LoadLibCryptoFunction('d2i_PKCS12');
  if not assigned(d2i_PKCS12) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12');
  Result := d2i_PKCS12(a,in_,len);
end;

function Load_i2d_PKCS12(a: PPKCS12; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS12 := LoadLibCryptoFunction('i2d_PKCS12');
  if not assigned(i2d_PKCS12) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12');
  Result := i2d_PKCS12(a,out_);
end;

function Load_PKCS12_it: PASN1_ITEM; cdecl;
begin
  PKCS12_it := LoadLibCryptoFunction('PKCS12_it');
  if not assigned(PKCS12_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_it');
  Result := PKCS12_it();
end;

function Load_PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl;
begin
  PKCS12_MAC_DATA_new := LoadLibCryptoFunction('PKCS12_MAC_DATA_new');
  if not assigned(PKCS12_MAC_DATA_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_MAC_DATA_new');
  Result := PKCS12_MAC_DATA_new();
end;

procedure Load_PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl;
begin
  PKCS12_MAC_DATA_free := LoadLibCryptoFunction('PKCS12_MAC_DATA_free');
  if not assigned(PKCS12_MAC_DATA_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_MAC_DATA_free');
  PKCS12_MAC_DATA_free(a);
end;

function Load_d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_MAC_DATA; cdecl;
begin
  d2i_PKCS12_MAC_DATA := LoadLibCryptoFunction('d2i_PKCS12_MAC_DATA');
  if not assigned(d2i_PKCS12_MAC_DATA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_MAC_DATA');
  Result := d2i_PKCS12_MAC_DATA(a,in_,len);
end;

function Load_i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS12_MAC_DATA := LoadLibCryptoFunction('i2d_PKCS12_MAC_DATA');
  if not assigned(i2d_PKCS12_MAC_DATA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_MAC_DATA');
  Result := i2d_PKCS12_MAC_DATA(a,out_);
end;

function Load_PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl;
begin
  PKCS12_MAC_DATA_it := LoadLibCryptoFunction('PKCS12_MAC_DATA_it');
  if not assigned(PKCS12_MAC_DATA_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_MAC_DATA_it');
  Result := PKCS12_MAC_DATA_it();
end;

function Load_PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl;
begin
  PKCS12_SAFEBAG_new := LoadLibCryptoFunction('PKCS12_SAFEBAG_new');
  if not assigned(PKCS12_SAFEBAG_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_new');
  Result := PKCS12_SAFEBAG_new();
end;

procedure Load_PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl;
begin
  PKCS12_SAFEBAG_free := LoadLibCryptoFunction('PKCS12_SAFEBAG_free');
  if not assigned(PKCS12_SAFEBAG_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_free');
  PKCS12_SAFEBAG_free(a);
end;

function Load_d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_SAFEBAG; cdecl;
begin
  d2i_PKCS12_SAFEBAG := LoadLibCryptoFunction('d2i_PKCS12_SAFEBAG');
  if not assigned(d2i_PKCS12_SAFEBAG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_SAFEBAG');
  Result := d2i_PKCS12_SAFEBAG(a,in_,len);
end;

function Load_i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS12_SAFEBAG := LoadLibCryptoFunction('i2d_PKCS12_SAFEBAG');
  if not assigned(i2d_PKCS12_SAFEBAG) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_SAFEBAG');
  Result := i2d_PKCS12_SAFEBAG(a,out_);
end;

function Load_PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl;
begin
  PKCS12_SAFEBAG_it := LoadLibCryptoFunction('PKCS12_SAFEBAG_it');
  if not assigned(PKCS12_SAFEBAG_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_SAFEBAG_it');
  Result := PKCS12_SAFEBAG_it();
end;

function Load_PKCS12_BAGS_new: PPKCS12_BAGS; cdecl;
begin
  PKCS12_BAGS_new := LoadLibCryptoFunction('PKCS12_BAGS_new');
  if not assigned(PKCS12_BAGS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_BAGS_new');
  Result := PKCS12_BAGS_new();
end;

procedure Load_PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl;
begin
  PKCS12_BAGS_free := LoadLibCryptoFunction('PKCS12_BAGS_free');
  if not assigned(PKCS12_BAGS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_BAGS_free');
  PKCS12_BAGS_free(a);
end;

function Load_d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TOpenSSL_C_LONG): PPKCS12_BAGS; cdecl;
begin
  d2i_PKCS12_BAGS := LoadLibCryptoFunction('d2i_PKCS12_BAGS');
  if not assigned(d2i_PKCS12_BAGS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_BAGS');
  Result := d2i_PKCS12_BAGS(a,in_,len);
end;

function Load_i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS12_BAGS := LoadLibCryptoFunction('i2d_PKCS12_BAGS');
  if not assigned(i2d_PKCS12_BAGS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_BAGS');
  Result := i2d_PKCS12_BAGS(a,out_);
end;

function Load_PKCS12_BAGS_it: PASN1_ITEM; cdecl;
begin
  PKCS12_BAGS_it := LoadLibCryptoFunction('PKCS12_BAGS_it');
  if not assigned(PKCS12_BAGS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_BAGS_it');
  Result := PKCS12_BAGS_it();
end;

procedure Load_PKCS12_PBE_add(v: Pointer); cdecl;
begin
  PKCS12_PBE_add := LoadLibCryptoFunction('PKCS12_PBE_add');
  if not assigned(PKCS12_PBE_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_PBE_add');
  PKCS12_PBE_add(v);
end;

function Load_PKCS12_parse(p12: PPKCS12; const pass: PAnsiChar; out pkey: PEVP_PKEY; out cert: PX509; ca: PPStack_Of_X509): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_parse := LoadLibCryptoFunction('PKCS12_parse');
  if not assigned(PKCS12_parse) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_parse');
  Result := PKCS12_parse(p12,pass,pkey,cert,ca);
end;

function Load_PKCS12_create(const pass: PAnsiChar; const name: PAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TOpenSSL_C_INT; nid_cert: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; mac_iter: TOpenSSL_C_INT; keytype: TOpenSSL_C_INT): PPKCS12; cdecl;
begin
  PKCS12_create := LoadLibCryptoFunction('PKCS12_create');
  if not assigned(PKCS12_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_create');
  Result := PKCS12_create(pass,name,pkey,cert,ca,nid_key,nid_cert,iter,mac_iter,keytype);
end;

function Load_i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS12_bio := LoadLibCryptoFunction('i2d_PKCS12_bio');
  if not assigned(i2d_PKCS12_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS12_bio');
  Result := i2d_PKCS12_bio(bp,p12);
end;

function Load_d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl;
begin
  d2i_PKCS12_bio := LoadLibCryptoFunction('d2i_PKCS12_bio');
  if not assigned(d2i_PKCS12_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PKCS12_bio');
  Result := d2i_PKCS12_bio(bp,p12);
end;

function Load_PKCS12_newpass(p12: PPKCS12; const oldpass: PAnsiChar; const newpass: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PKCS12_newpass := LoadLibCryptoFunction('PKCS12_newpass');
  if not assigned(PKCS12_newpass) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS12_newpass');
  Result := PKCS12_newpass(p12,oldpass,newpass);
end;


procedure UnLoad;
begin
  PKCS12_mac_present := Load_PKCS12_mac_present;
  PKCS12_get0_mac := Load_PKCS12_get0_mac;
  PKCS12_SAFEBAG_get0_attr := Load_PKCS12_SAFEBAG_get0_attr;
  PKCS12_SAFEBAG_get0_type := Load_PKCS12_SAFEBAG_get0_type;
  PKCS12_SAFEBAG_get_nid := Load_PKCS12_SAFEBAG_get_nid;
  PKCS12_SAFEBAG_get_bag_nid := Load_PKCS12_SAFEBAG_get_bag_nid;
  PKCS12_SAFEBAG_get1_cert := Load_PKCS12_SAFEBAG_get1_cert;
  PKCS12_SAFEBAG_get1_crl := Load_PKCS12_SAFEBAG_get1_crl;
  PKCS12_SAFEBAG_get0_p8inf := Load_PKCS12_SAFEBAG_get0_p8inf;
  PKCS12_SAFEBAG_get0_pkcs8 := Load_PKCS12_SAFEBAG_get0_pkcs8;
  PKCS12_SAFEBAG_create_cert := Load_PKCS12_SAFEBAG_create_cert;
  PKCS12_SAFEBAG_create_crl := Load_PKCS12_SAFEBAG_create_crl;
  PKCS12_SAFEBAG_create0_p8inf := Load_PKCS12_SAFEBAG_create0_p8inf;
  PKCS12_SAFEBAG_create0_pkcs8 := Load_PKCS12_SAFEBAG_create0_pkcs8;
  PKCS12_SAFEBAG_create_pkcs8_encrypt := Load_PKCS12_SAFEBAG_create_pkcs8_encrypt;
  PKCS12_item_pack_safebag := Load_PKCS12_item_pack_safebag;
  PKCS8_decrypt := Load_PKCS8_decrypt;
  PKCS12_decrypt_skey := Load_PKCS12_decrypt_skey;
  PKCS8_encrypt := Load_PKCS8_encrypt;
  PKCS8_set0_pbe := Load_PKCS8_set0_pbe;
  PKCS12_add_localkeyid := Load_PKCS12_add_localkeyid;
  PKCS12_add_friendlyname_asc := Load_PKCS12_add_friendlyname_asc;
  PKCS12_add_friendlyname_utf8 := Load_PKCS12_add_friendlyname_utf8;
  PKCS12_add_CSPName_asc := Load_PKCS12_add_CSPName_asc;
  PKCS12_add_friendlyname_uni := Load_PKCS12_add_friendlyname_uni;
  PKCS8_add_keyusage := Load_PKCS8_add_keyusage;
  PKCS12_get_friendlyname := Load_PKCS12_get_friendlyname;
  PKCS12_pbe_crypt := Load_PKCS12_pbe_crypt;
  PKCS12_item_decrypt_d2i := Load_PKCS12_item_decrypt_d2i;
  PKCS12_item_i2d_encrypt := Load_PKCS12_item_i2d_encrypt;
  PKCS12_init := Load_PKCS12_init;
  PKCS12_key_gen_asc := Load_PKCS12_key_gen_asc;
  PKCS12_key_gen_uni := Load_PKCS12_key_gen_uni;
  PKCS12_key_gen_utf8 := Load_PKCS12_key_gen_utf8;
  PKCS12_PBE_keyivgen := Load_PKCS12_PBE_keyivgen;
  PKCS12_gen_mac := Load_PKCS12_gen_mac;
  PKCS12_verify_mac := Load_PKCS12_verify_mac;
  PKCS12_set_mac := Load_PKCS12_set_mac;
  PKCS12_setup_mac := Load_PKCS12_setup_mac;
  OPENSSL_asc2uni := Load_OPENSSL_asc2uni;
  OPENSSL_uni2asc := Load_OPENSSL_uni2asc;
  OPENSSL_utf82uni := Load_OPENSSL_utf82uni;
  OPENSSL_uni2utf8 := Load_OPENSSL_uni2utf8;
  PKCS12_new := Load_PKCS12_new;
  PKCS12_free := Load_PKCS12_free;
  d2i_PKCS12 := Load_d2i_PKCS12;
  i2d_PKCS12 := Load_i2d_PKCS12;
  PKCS12_it := Load_PKCS12_it;
  PKCS12_MAC_DATA_new := Load_PKCS12_MAC_DATA_new;
  PKCS12_MAC_DATA_free := Load_PKCS12_MAC_DATA_free;
  d2i_PKCS12_MAC_DATA := Load_d2i_PKCS12_MAC_DATA;
  i2d_PKCS12_MAC_DATA := Load_i2d_PKCS12_MAC_DATA;
  PKCS12_MAC_DATA_it := Load_PKCS12_MAC_DATA_it;
  PKCS12_SAFEBAG_new := Load_PKCS12_SAFEBAG_new;
  PKCS12_SAFEBAG_free := Load_PKCS12_SAFEBAG_free;
  d2i_PKCS12_SAFEBAG := Load_d2i_PKCS12_SAFEBAG;
  i2d_PKCS12_SAFEBAG := Load_i2d_PKCS12_SAFEBAG;
  PKCS12_SAFEBAG_it := Load_PKCS12_SAFEBAG_it;
  PKCS12_BAGS_new := Load_PKCS12_BAGS_new;
  PKCS12_BAGS_free := Load_PKCS12_BAGS_free;
  d2i_PKCS12_BAGS := Load_d2i_PKCS12_BAGS;
  i2d_PKCS12_BAGS := Load_i2d_PKCS12_BAGS;
  PKCS12_BAGS_it := Load_PKCS12_BAGS_it;
  PKCS12_PBE_add := Load_PKCS12_PBE_add;
  PKCS12_parse := Load_PKCS12_parse;
  PKCS12_create := Load_PKCS12_create;
  i2d_PKCS12_bio := Load_i2d_PKCS12_bio;
  d2i_PKCS12_bio := Load_d2i_PKCS12_bio;
  PKCS12_newpass := Load_PKCS12_newpass;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
