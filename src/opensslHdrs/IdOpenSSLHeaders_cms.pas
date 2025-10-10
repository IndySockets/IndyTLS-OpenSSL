(* This unit was generated from the source file cms.h2pas 
It should not be modified directly. All changes should be made to cms.h2pas
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


unit IdOpenSSLHeaders_cms;


interface

// Headers for OpenSSL 1.1.1
// cms.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_x509;

type
  CMS_ContentInfo_st = type Pointer;
  CMS_ContentInfo = CMS_ContentInfo_st;
  PCMS_ContentInfo = ^CMS_ContentInfo;
  PPCMS_ContentInfo = ^PCMS_ContentInfo;

  CMS_SignerInfo_st = type Pointer;
  CMS_SignerInfo = CMS_SignerInfo_st;
  PCMS_SignerInfo = ^CMS_SignerInfo;

  CMS_CertificateChoices_st = type Pointer;
  CMS_CertificateChoices = CMS_CertificateChoices_st;
  PCMS_CertificateChoices = ^CMS_CertificateChoices;

  CMS_RevocationInfoChoice_st = type Pointer;
  CMS_RevocationInfoChoice = CMS_RevocationInfoChoice_st;
  PCMS_RevocationInfoChoice = ^CMS_RevocationInfoChoice;

  CMS_RecipientInfo_st = type Pointer;
  CMS_RecipientInfo = CMS_RecipientInfo_st;
  PCMS_RecipientInfo = ^CMS_RecipientInfo;
  PPCMS_RecipientInfo = ^PCMS_RecipientInfo;

  CMS_ReceiptRequest_st = type Pointer;
  CMS_ReceiptRequest = CMS_ReceiptRequest_st;
  PCMS_ReceiptRequest = ^CMS_ReceiptRequest;
  PPCMS_ReceiptRequest = ^PCMS_ReceiptRequest;

  CMS_Receipt_st = type Pointer;
  CMS_Receipt = CMS_Receipt_st;
  PCMS_Receipt = ^CMS_Receipt;

  CMS_RecipientEncryptedKey_st = type Pointer;
  CMS_RecipientEncryptedKey = CMS_RecipientEncryptedKey_st;
  PCMS_RecipientEncryptedKey = ^CMS_RecipientEncryptedKey;

  CMS_OtherKeyAttribute_st = type Pointer;
  CMS_OtherKeyAttribute = CMS_OtherKeyAttribute_st;
  PCMS_OtherKeyAttribute = ^CMS_OtherKeyAttribute;
  PPCMS_OtherKeyAttribute = ^PCMS_OtherKeyAttribute;

//DEFINE_STACK_OF(CMS_SignerInfo)
//DEFINE_STACK_OF(CMS_RecipientEncryptedKey)
//DEFINE_STACK_OF(CMS_RecipientInfo)
//DEFINE_STACK_OF(CMS_RevocationInfoChoice)
//DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)
//DECLARE_ASN1_FUNCTIONS(CMS_ReceiptRequest)
//DECLARE_ASN1_PRINT_FUNCTION(CMS_ContentInfo)

const
  CMS_SIGNERINFO_ISSUER_SERIAL    = 0;
  CMS_SIGNERINFO_KEYIDENTIFIER    = 1;

  CMS_RECIPINFO_NONE              = -1;
  CMS_RECIPINFO_TRANS             = 0;
  CMS_RECIPINFO_AGREE             = 1;
  CMS_RECIPINFO_KEK               = 2;
  CMS_RECIPINFO_PASS              = 3;
  CMS_RECIPINFO_OTHER             = 4;

// S/MIME related flags /

  CMS_TEXT                        = $1;
  CMS_NOCERTS                     = $2;
  CMS_NO_CONTENT_VERIFY           = $4;
  CMS_NO_ATTR_VERIFY              = $8;
  CMS_NOSIGS                      = (CMS_NO_CONTENT_VERIFY or CMS_NO_ATTR_VERIFY);
  CMS_NOINTERN                    = $10;
  CMS_NO_SIGNER_CERT_VERIFY       = $20;
  CMS_NOVERIFY                    = $20;
  CMS_DETACHED                    = $40;
  CMS_BINARY                      = $80;
  CMS_NOATTR                      = $100;
  CMS_NOSMIMECAP                  = $200;
  CMS_NOOLDMIMETYPE               = $400;
  CMS_CRLFEOL                     = $800;
  CMS_STREAM_CONST                = $1000;
  CMS_NOCRL                       = $2000;
  CMS_PARTIAL                     = $4000;
  CMS_REUSE_DIGEST                = $8000;
  CMS_USE_KEYID                   = $10000;
  CMS_DEBUG_DECRYPT               = $20000;
  CMS_KEY_PARAM                   = $40000;
  CMS_ASCIICRLF                   = $80000;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CMS_get0_type}
{$EXTERNALSYM CMS_dataInit}
{$EXTERNALSYM CMS_dataFinal}
{$EXTERNALSYM CMS_get0_content}
{$EXTERNALSYM CMS_is_detached}
{$EXTERNALSYM CMS_set_detached}
{$EXTERNALSYM CMS_stream}
{$EXTERNALSYM d2i_CMS_bio}
{$EXTERNALSYM i2d_CMS_bio}
{$EXTERNALSYM BIO_new_CMS}
{$EXTERNALSYM i2d_CMS_bio_stream}
{$EXTERNALSYM PEM_write_bio_CMS_stream}
{$EXTERNALSYM SMIME_read_CMS}
{$EXTERNALSYM SMIME_write_CMS}
{$EXTERNALSYM CMS_final}
{$EXTERNALSYM CMS_data}
{$EXTERNALSYM CMS_data_create}
{$EXTERNALSYM CMS_digest_verify}
{$EXTERNALSYM CMS_digest_create}
{$EXTERNALSYM CMS_EncryptedData_decrypt}
{$EXTERNALSYM CMS_EncryptedData_encrypt}
{$EXTERNALSYM CMS_EncryptedData_set1_key}
{$EXTERNALSYM CMS_decrypt}
{$EXTERNALSYM CMS_decrypt_set1_pkey}
{$EXTERNALSYM CMS_decrypt_set1_key}
{$EXTERNALSYM CMS_decrypt_set1_password}
{$EXTERNALSYM CMS_RecipientInfo_type}
{$EXTERNALSYM CMS_RecipientInfo_get0_pkey_ctx}
{$EXTERNALSYM CMS_EnvelopedData_create}
{$EXTERNALSYM CMS_add1_recipient_cert}
{$EXTERNALSYM CMS_RecipientInfo_set0_pkey}
{$EXTERNALSYM CMS_RecipientInfo_ktri_cert_cmp}
{$EXTERNALSYM CMS_RecipientInfo_ktri_get0_algs}
{$EXTERNALSYM CMS_RecipientInfo_ktri_get0_signer_id}
{$EXTERNALSYM CMS_add0_recipient_key}
{$EXTERNALSYM CMS_RecipientInfo_kekri_get0_id}
{$EXTERNALSYM CMS_RecipientInfo_set0_key}
{$EXTERNALSYM CMS_RecipientInfo_kekri_id_cmp}
{$EXTERNALSYM CMS_RecipientInfo_set0_password}
{$EXTERNALSYM CMS_add0_recipient_password}
{$EXTERNALSYM CMS_RecipientInfo_decrypt}
{$EXTERNALSYM CMS_RecipientInfo_encrypt}
{$EXTERNALSYM CMS_uncompress}
{$EXTERNALSYM CMS_compress}
{$EXTERNALSYM CMS_set1_eContentType}
{$EXTERNALSYM CMS_get0_eContentType}
{$EXTERNALSYM CMS_add0_CertificateChoices}
{$EXTERNALSYM CMS_add0_cert}
{$EXTERNALSYM CMS_add1_cert}
{$EXTERNALSYM CMS_add0_RevocationInfoChoice}
{$EXTERNALSYM CMS_add0_crl}
{$EXTERNALSYM CMS_add1_crl}
{$EXTERNALSYM CMS_SignedData_init}
{$EXTERNALSYM CMS_add1_signer}
{$EXTERNALSYM CMS_SignerInfo_get0_pkey_ctx}
{$EXTERNALSYM CMS_SignerInfo_get0_md_ctx}
{$EXTERNALSYM CMS_SignerInfo_set1_signer_cert}
{$EXTERNALSYM CMS_SignerInfo_get0_signer_id}
{$EXTERNALSYM CMS_SignerInfo_cert_cmp}
{$EXTERNALSYM CMS_SignerInfo_get0_algs}
{$EXTERNALSYM CMS_SignerInfo_get0_signature}
{$EXTERNALSYM CMS_SignerInfo_sign}
{$EXTERNALSYM CMS_SignerInfo_verify}
{$EXTERNALSYM CMS_SignerInfo_verify_content}
{$EXTERNALSYM CMS_signed_get_attr_count}
{$EXTERNALSYM CMS_signed_get_attr_by_NID}
{$EXTERNALSYM CMS_signed_get_attr_by_OBJ}
{$EXTERNALSYM CMS_signed_get_attr}
{$EXTERNALSYM CMS_signed_delete_attr}
{$EXTERNALSYM CMS_signed_add1_attr}
{$EXTERNALSYM CMS_signed_add1_attr_by_OBJ}
{$EXTERNALSYM CMS_signed_add1_attr_by_NID}
{$EXTERNALSYM CMS_signed_add1_attr_by_txt}
{$EXTERNALSYM CMS_signed_get0_data_by_OBJ}
{$EXTERNALSYM CMS_unsigned_get_attr_count}
{$EXTERNALSYM CMS_unsigned_get_attr_by_NID}
{$EXTERNALSYM CMS_unsigned_get_attr_by_OBJ}
{$EXTERNALSYM CMS_unsigned_get_attr}
{$EXTERNALSYM CMS_unsigned_delete_attr}
{$EXTERNALSYM CMS_unsigned_add1_attr}
{$EXTERNALSYM CMS_unsigned_add1_attr_by_OBJ}
{$EXTERNALSYM CMS_unsigned_add1_attr_by_NID}
{$EXTERNALSYM CMS_unsigned_add1_attr_by_txt}
{$EXTERNALSYM CMS_unsigned_get0_data_by_OBJ}
{$EXTERNALSYM CMS_get1_ReceiptRequest}
{$EXTERNALSYM CMS_add1_ReceiptRequest}
{$EXTERNALSYM CMS_RecipientInfo_kari_get0_orig_id}
{$EXTERNALSYM CMS_RecipientInfo_kari_orig_id_cmp}
{$EXTERNALSYM CMS_RecipientEncryptedKey_get0_id}
{$EXTERNALSYM CMS_RecipientEncryptedKey_cert_cmp}
{$EXTERNALSYM CMS_RecipientInfo_kari_set0_pkey}
{$EXTERNALSYM CMS_RecipientInfo_kari_get0_ctx}
{$EXTERNALSYM CMS_RecipientInfo_kari_decrypt}
{$EXTERNALSYM CMS_SharedInfo_encode}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl; external CLibCrypto;
function CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl; external CLibCrypto;
function CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl; external CLibCrypto;
function CMS_is_detached(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_set_detached(cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl; external CLibCrypto;
function i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl; external CLibCrypto;
function i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl; external CLibCrypto;
function SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_data_create(in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl; external CLibCrypto;
function CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl; external CLibCrypto;
function CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_compress(in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl; external CLibCrypto;
function CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl; external CLibCrypto;
function CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl; external CLibCrypto;
function CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl; external CLibCrypto;
function CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignedData_init(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl; external CLibCrypto;
procedure CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509); cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl; external CLibCrypto;
function CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function CMS_SignerInfo_sign(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignerInfo_verify(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl; external CLibCrypto;
function CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
function Load_CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl;
function Load_CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl;
function Load_CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl;
function Load_CMS_is_detached(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_set_detached(cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl;
function Load_i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
function Load_BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl;
function Load_i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl;
function Load_SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_CMS_data_create(in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
function Load_CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
function Load_CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
function Load_CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl;
function Load_CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl;
function Load_CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl;
function Load_CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl;
function Load_CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl;
function Load_CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl;
function Load_CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl;
function Load_CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_CMS_compress(in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
function Load_CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
function Load_CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl;
function Load_CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
function Load_CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
function Load_CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl;
function Load_CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
function Load_CMS_SignedData_init(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl;
function Load_CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl;
function Load_CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl;
procedure Load_CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509); cdecl;
function Load_CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
procedure Load_CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl;
function Load_CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl;
function Load_CMS_SignerInfo_sign(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_SignerInfo_verify(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
function Load_CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl;
function Load_CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl;
function Load_CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl;
function Load_CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl;
function Load_CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  CMS_get0_type: function (const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = Load_CMS_get0_type;
  CMS_dataInit: function (cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl = Load_CMS_dataInit;
  CMS_dataFinal: function (cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl = Load_CMS_dataFinal;
  CMS_get0_content: function (cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl = Load_CMS_get0_content;
  CMS_is_detached: function (cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl = Load_CMS_is_detached;
  CMS_set_detached: function (cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_set_detached;
  CMS_stream: function (cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl = Load_CMS_stream;
  d2i_CMS_bio: function (bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl = Load_d2i_CMS_bio;
  i2d_CMS_bio: function (bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl = Load_i2d_CMS_bio;
  BIO_new_CMS: function (out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl = Load_BIO_new_CMS;
  i2d_CMS_bio_stream: function (out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_i2d_CMS_bio_stream;
  PEM_write_bio_CMS_stream: function (out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PEM_write_bio_CMS_stream;
  SMIME_read_CMS: function (bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl = Load_SMIME_read_CMS;
  SMIME_write_CMS: function (bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SMIME_write_CMS;
  CMS_final: function (cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_CMS_final;
  CMS_data: function (cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_CMS_data;
  CMS_data_create: function (in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = Load_CMS_data_create;
  CMS_digest_verify: function (cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_CMS_digest_verify;
  CMS_digest_create: function (in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = Load_CMS_digest_create;
  CMS_EncryptedData_decrypt: function (cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_CMS_EncryptedData_decrypt;
  CMS_EncryptedData_encrypt: function (in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = Load_CMS_EncryptedData_encrypt;
  CMS_EncryptedData_set1_key: function (cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMS_EncryptedData_set1_key;
  CMS_decrypt: function (cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_CMS_decrypt;
  CMS_decrypt_set1_pkey: function (cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_decrypt_set1_pkey;
  CMS_decrypt_set1_key: function (cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMS_decrypt_set1_key;
  CMS_decrypt_set1_password: function (cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl = Load_CMS_decrypt_set1_password;
  CMS_RecipientInfo_type: function (ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_type;
  CMS_RecipientInfo_get0_pkey_ctx: function (ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl = Load_CMS_RecipientInfo_get0_pkey_ctx;
  CMS_EnvelopedData_create: function (const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl = Load_CMS_EnvelopedData_create;
  CMS_add1_recipient_cert: function (cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl = Load_CMS_add1_recipient_cert;
  CMS_RecipientInfo_set0_pkey: function (ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_set0_pkey;
  CMS_RecipientInfo_ktri_cert_cmp: function (ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_ktri_cert_cmp;
  CMS_RecipientInfo_ktri_get0_algs: function (ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_ktri_get0_algs;
  CMS_RecipientInfo_ktri_get0_signer_id: function (ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_ktri_get0_signer_id;
  CMS_add0_recipient_key: function (cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl = Load_CMS_add0_recipient_key;
  CMS_RecipientInfo_kekri_get0_id: function (ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_kekri_get0_id;
  CMS_RecipientInfo_set0_key: function (ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_set0_key;
  CMS_RecipientInfo_kekri_id_cmp: function (ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_kekri_id_cmp;
  CMS_RecipientInfo_set0_password: function (ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_set0_password;
  CMS_add0_recipient_password: function (cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl = Load_CMS_add0_recipient_password;
  CMS_RecipientInfo_decrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_decrypt;
  CMS_RecipientInfo_encrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_encrypt;
  CMS_uncompress: function (cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_CMS_uncompress;
  CMS_compress: function (in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl = Load_CMS_compress;
  CMS_set1_eContentType: function (cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_CMS_set1_eContentType;
  CMS_get0_eContentType: function (cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = Load_CMS_get0_eContentType;
  CMS_add0_CertificateChoices: function (cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl = Load_CMS_add0_CertificateChoices;
  CMS_add0_cert: function (cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_add0_cert;
  CMS_add1_cert: function (cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_add1_cert;
  CMS_add0_RevocationInfoChoice: function (cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl = Load_CMS_add0_RevocationInfoChoice;
  CMS_add0_crl: function (cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_CMS_add0_crl;
  CMS_add1_crl: function (cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl = Load_CMS_add1_crl;
  CMS_SignedData_init: function (cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl = Load_CMS_SignedData_init;
  CMS_add1_signer: function (cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl = Load_CMS_add1_signer;
  CMS_SignerInfo_get0_pkey_ctx: function (si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl = Load_CMS_SignerInfo_get0_pkey_ctx;
  CMS_SignerInfo_get0_md_ctx: function (si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl = Load_CMS_SignerInfo_get0_md_ctx;
  CMS_SignerInfo_set1_signer_cert: procedure (si: PCMS_SignerInfo; signer: PX509); cdecl = Load_CMS_SignerInfo_set1_signer_cert;
  CMS_SignerInfo_get0_signer_id: function (si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_CMS_SignerInfo_get0_signer_id;
  CMS_SignerInfo_cert_cmp: function (si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_SignerInfo_cert_cmp;
  CMS_SignerInfo_get0_algs: procedure (si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl = Load_CMS_SignerInfo_get0_algs;
  CMS_SignerInfo_get0_signature: function (si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl = Load_CMS_SignerInfo_get0_signature;
  CMS_SignerInfo_sign: function (si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = Load_CMS_SignerInfo_sign;
  CMS_SignerInfo_verify: function (si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = Load_CMS_SignerInfo_verify;
  CMS_SignerInfo_verify_content: function (si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl = Load_CMS_SignerInfo_verify_content;
  CMS_signed_get_attr_count: function (const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = Load_CMS_signed_get_attr_count;
  CMS_signed_get_attr_by_NID: function (const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_signed_get_attr_by_NID;
  CMS_signed_get_attr_by_OBJ: function (const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_signed_get_attr_by_OBJ;
  CMS_signed_get_attr: function (const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_CMS_signed_get_attr;
  CMS_signed_delete_attr: function (const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_CMS_signed_delete_attr;
  CMS_signed_add1_attr: function (si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_signed_add1_attr;
  CMS_signed_add1_attr_by_OBJ: function (si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_signed_add1_attr_by_OBJ;
  CMS_signed_add1_attr_by_NID: function (si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_signed_add1_attr_by_NID;
  CMS_signed_add1_attr_by_txt: function (si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_signed_add1_attr_by_txt;
  CMS_signed_get0_data_by_OBJ: function (si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl = Load_CMS_signed_get0_data_by_OBJ;
  CMS_unsigned_get_attr_count: function (const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_get_attr_count;
  CMS_unsigned_get_attr_by_NID: function (const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_get_attr_by_NID;
  CMS_unsigned_get_attr_by_OBJ: function (const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_get_attr_by_OBJ;
  CMS_unsigned_get_attr: function (const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_CMS_unsigned_get_attr;
  CMS_unsigned_delete_attr: function (si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl = Load_CMS_unsigned_delete_attr;
  CMS_unsigned_add1_attr: function (si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_add1_attr;
  CMS_unsigned_add1_attr_by_OBJ: function (si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_add1_attr_by_OBJ;
  CMS_unsigned_add1_attr_by_NID: function (si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_add1_attr_by_NID;
  CMS_unsigned_add1_attr_by_txt: function (si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_unsigned_add1_attr_by_txt;
  CMS_unsigned_get0_data_by_OBJ: function (si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl = Load_CMS_unsigned_get0_data_by_OBJ;
  CMS_get1_ReceiptRequest: function (si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl = Load_CMS_get1_ReceiptRequest;
  CMS_add1_ReceiptRequest: function (si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl = Load_CMS_add1_ReceiptRequest;
  CMS_RecipientInfo_kari_get0_orig_id: function (ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_kari_get0_orig_id;
  CMS_RecipientInfo_kari_orig_id_cmp: function (ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_kari_orig_id_cmp;
  CMS_RecipientEncryptedKey_get0_id: function (rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientEncryptedKey_get0_id;
  CMS_RecipientEncryptedKey_cert_cmp: function (rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientEncryptedKey_cert_cmp;
  CMS_RecipientInfo_kari_set0_pkey: function (ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_kari_set0_pkey;
  CMS_RecipientInfo_kari_get0_ctx: function (ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl = Load_CMS_RecipientInfo_kari_get0_ctx;
  CMS_RecipientInfo_kari_decrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl = Load_CMS_RecipientInfo_kari_decrypt;
  CMS_SharedInfo_encode: function (pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CMS_SharedInfo_encode;
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
function Load_CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
begin
  CMS_get0_type := LoadLibCryptoFunction('CMS_get0_type');
  if not assigned(CMS_get0_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get0_type');
  Result := CMS_get0_type(cms);
end;

function Load_CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl;
begin
  CMS_dataInit := LoadLibCryptoFunction('CMS_dataInit');
  if not assigned(CMS_dataInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_dataInit');
  Result := CMS_dataInit(cms,icont);
end;

function Load_CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TOpenSSL_C_INT; cdecl;
begin
  CMS_dataFinal := LoadLibCryptoFunction('CMS_dataFinal');
  if not assigned(CMS_dataFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_dataFinal');
  Result := CMS_dataFinal(cms,bio);
end;

function Load_CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl;
begin
  CMS_get0_content := LoadLibCryptoFunction('CMS_get0_content');
  if not assigned(CMS_get0_content) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get0_content');
  Result := CMS_get0_content(cms);
end;

function Load_CMS_is_detached(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_is_detached := LoadLibCryptoFunction('CMS_is_detached');
  if not assigned(CMS_is_detached) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_is_detached');
  Result := CMS_is_detached(cms);
end;

function Load_CMS_set_detached(cms: PCMS_ContentInfo; detached: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_set_detached := LoadLibCryptoFunction('CMS_set_detached');
  if not assigned(CMS_set_detached) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_set_detached');
  Result := CMS_set_detached(cms,detached);
end;

function Load_CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TOpenSSL_C_INT; cdecl;
begin
  CMS_stream := LoadLibCryptoFunction('CMS_stream');
  if not assigned(CMS_stream) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_stream');
  Result := CMS_stream(cms,boundary);
end;

function Load_d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl;
begin
  d2i_CMS_bio := LoadLibCryptoFunction('d2i_CMS_bio');
  if not assigned(d2i_CMS_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_CMS_bio');
  Result := d2i_CMS_bio(bp,cms);
end;

function Load_i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
begin
  i2d_CMS_bio := LoadLibCryptoFunction('i2d_CMS_bio');
  if not assigned(i2d_CMS_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_CMS_bio');
  Result := i2d_CMS_bio(bp,cms);
end;

function Load_BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl;
begin
  BIO_new_CMS := LoadLibCryptoFunction('BIO_new_CMS');
  if not assigned(BIO_new_CMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_CMS');
  Result := BIO_new_CMS(out_,cms);
end;

function Load_i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  i2d_CMS_bio_stream := LoadLibCryptoFunction('i2d_CMS_bio_stream');
  if not assigned(i2d_CMS_bio_stream) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_CMS_bio_stream');
  Result := i2d_CMS_bio_stream(out_,cms,in_,flags);
end;

function Load_PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PEM_write_bio_CMS_stream := LoadLibCryptoFunction('PEM_write_bio_CMS_stream');
  if not assigned(PEM_write_bio_CMS_stream) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PEM_write_bio_CMS_stream');
  Result := PEM_write_bio_CMS_stream(out_,cms,in_,flags);
end;

function Load_SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl;
begin
  SMIME_read_CMS := LoadLibCryptoFunction('SMIME_read_CMS');
  if not assigned(SMIME_read_CMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_read_CMS');
  Result := SMIME_read_CMS(bio,bcont);
end;

function Load_SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SMIME_write_CMS := LoadLibCryptoFunction('SMIME_write_CMS');
  if not assigned(SMIME_write_CMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SMIME_write_CMS');
  Result := SMIME_write_CMS(bio,cms,data,flags);
end;

function Load_CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  CMS_final := LoadLibCryptoFunction('CMS_final');
  if not assigned(CMS_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_final');
  Result := CMS_final(cms,data,dcont,flags);
end;

function Load_CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  CMS_data := LoadLibCryptoFunction('CMS_data');
  if not assigned(CMS_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_data');
  Result := CMS_data(cms,out_,flags);
end;

function Load_CMS_data_create(in_: PBIO; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  CMS_data_create := LoadLibCryptoFunction('CMS_data_create');
  if not assigned(CMS_data_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_data_create');
  Result := CMS_data_create(in_,flags);
end;

function Load_CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  CMS_digest_verify := LoadLibCryptoFunction('CMS_digest_verify');
  if not assigned(CMS_digest_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_digest_verify');
  Result := CMS_digest_verify(cms,dcont,out_,flags);
end;

function Load_CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  CMS_digest_create := LoadLibCryptoFunction('CMS_digest_create');
  if not assigned(CMS_digest_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_digest_create');
  Result := CMS_digest_create(in_,md,flags);
end;

function Load_CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TOpenSSL_C_SIZET; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  CMS_EncryptedData_decrypt := LoadLibCryptoFunction('CMS_EncryptedData_decrypt');
  if not assigned(CMS_EncryptedData_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EncryptedData_decrypt');
  Result := CMS_EncryptedData_decrypt(cms,key,keylen,dcont,out_,flags);
end;

function Load_CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  CMS_EncryptedData_encrypt := LoadLibCryptoFunction('CMS_EncryptedData_encrypt');
  if not assigned(CMS_EncryptedData_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EncryptedData_encrypt');
  Result := CMS_EncryptedData_encrypt(in_,cipher,key,keylen,flags);
end;

function Load_CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMS_EncryptedData_set1_key := LoadLibCryptoFunction('CMS_EncryptedData_set1_key');
  if not assigned(CMS_EncryptedData_set1_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EncryptedData_set1_key');
  Result := CMS_EncryptedData_set1_key(cms,ciph,key,keylen);
end;

function Load_CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  CMS_decrypt := LoadLibCryptoFunction('CMS_decrypt');
  if not assigned(CMS_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt');
  Result := CMS_decrypt(cms,pkey,cert,dcont,out_,flags);
end;

function Load_CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_decrypt_set1_pkey := LoadLibCryptoFunction('CMS_decrypt_set1_pkey');
  if not assigned(CMS_decrypt_set1_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt_set1_pkey');
  Result := CMS_decrypt_set1_pkey(cms,pk,cert);
end;

function Load_CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TOpenSSL_C_SIZET; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMS_decrypt_set1_key := LoadLibCryptoFunction('CMS_decrypt_set1_key');
  if not assigned(CMS_decrypt_set1_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt_set1_key');
  Result := CMS_decrypt_set1_key(cms,key,keylen,id,idlen);
end;

function Load_CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl;
begin
  CMS_decrypt_set1_password := LoadLibCryptoFunction('CMS_decrypt_set1_password');
  if not assigned(CMS_decrypt_set1_password) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_decrypt_set1_password');
  Result := CMS_decrypt_set1_password(cms,pass,passlen);
end;

function Load_CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_type := LoadLibCryptoFunction('CMS_RecipientInfo_type');
  if not assigned(CMS_RecipientInfo_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_type');
  Result := CMS_RecipientInfo_type(ri);
end;

function Load_CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl;
begin
  CMS_RecipientInfo_get0_pkey_ctx := LoadLibCryptoFunction('CMS_RecipientInfo_get0_pkey_ctx');
  if not assigned(CMS_RecipientInfo_get0_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_get0_pkey_ctx');
  Result := CMS_RecipientInfo_get0_pkey_ctx(ri);
end;

function Load_CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl;
begin
  CMS_EnvelopedData_create := LoadLibCryptoFunction('CMS_EnvelopedData_create');
  if not assigned(CMS_EnvelopedData_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_EnvelopedData_create');
  Result := CMS_EnvelopedData_create(cipher);
end;

function Load_CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TOpenSSL_C_UINT): PCMS_RecipientInfo; cdecl;
begin
  CMS_add1_recipient_cert := LoadLibCryptoFunction('CMS_add1_recipient_cert');
  if not assigned(CMS_add1_recipient_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_recipient_cert');
  Result := CMS_add1_recipient_cert(cms,recip,flags);
end;

function Load_CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_set0_pkey := LoadLibCryptoFunction('CMS_RecipientInfo_set0_pkey');
  if not assigned(CMS_RecipientInfo_set0_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_set0_pkey');
  Result := CMS_RecipientInfo_set0_pkey(ri,pkey);
end;

function Load_CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_ktri_cert_cmp := LoadLibCryptoFunction('CMS_RecipientInfo_ktri_cert_cmp');
  if not assigned(CMS_RecipientInfo_ktri_cert_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_ktri_cert_cmp');
  Result := CMS_RecipientInfo_ktri_cert_cmp(ri,cert);
end;

function Load_CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_ktri_get0_algs := LoadLibCryptoFunction('CMS_RecipientInfo_ktri_get0_algs');
  if not assigned(CMS_RecipientInfo_ktri_get0_algs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_ktri_get0_algs');
  Result := CMS_RecipientInfo_ktri_get0_algs(ri,pk,recip,palg);
end;

function Load_CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_ktri_get0_signer_id := LoadLibCryptoFunction('CMS_RecipientInfo_ktri_get0_signer_id');
  if not assigned(CMS_RecipientInfo_ktri_get0_signer_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_ktri_get0_signer_id');
  Result := CMS_RecipientInfo_ktri_get0_signer_id(ri,keyid,issuer,sno);
end;

function Load_CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TOpenSSL_C_INT; key: PByte; keylen: TOpenSSL_C_SIZET; id: PByte; idlen: TOpenSSL_C_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl;
begin
  CMS_add0_recipient_key := LoadLibCryptoFunction('CMS_add0_recipient_key');
  if not assigned(CMS_add0_recipient_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_recipient_key');
  Result := CMS_add0_recipient_key(cms,nid,key,keylen,id,idlen,date,otherTypeId,otherType);
end;

function Load_CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_kekri_get0_id := LoadLibCryptoFunction('CMS_RecipientInfo_kekri_get0_id');
  if not assigned(CMS_RecipientInfo_kekri_get0_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kekri_get0_id');
  Result := CMS_RecipientInfo_kekri_get0_id(ri,palg,pid,pdate,potherid,pothertype);
end;

function Load_CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_set0_key := LoadLibCryptoFunction('CMS_RecipientInfo_set0_key');
  if not assigned(CMS_RecipientInfo_set0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_set0_key');
  Result := CMS_RecipientInfo_set0_key(ri,key,keylen);
end;

function Load_CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_kekri_id_cmp := LoadLibCryptoFunction('CMS_RecipientInfo_kekri_id_cmp');
  if not assigned(CMS_RecipientInfo_kekri_id_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kekri_id_cmp');
  Result := CMS_RecipientInfo_kekri_id_cmp(ri,id,idlen);
end;

function Load_CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_set0_password := LoadLibCryptoFunction('CMS_RecipientInfo_set0_password');
  if not assigned(CMS_RecipientInfo_set0_password) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_set0_password');
  Result := CMS_RecipientInfo_set0_password(ri,pass,passlen);
end;

function Load_CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TOpenSSL_C_INT; wrap_nid: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl;
begin
  CMS_add0_recipient_password := LoadLibCryptoFunction('CMS_add0_recipient_password');
  if not assigned(CMS_add0_recipient_password) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_recipient_password');
  Result := CMS_add0_recipient_password(cms,iter,wrap_nid,pbe_nid,pass,passlen,kekciph);
end;

function Load_CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_decrypt := LoadLibCryptoFunction('CMS_RecipientInfo_decrypt');
  if not assigned(CMS_RecipientInfo_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_decrypt');
  Result := CMS_RecipientInfo_decrypt(cms,ri);
end;

function Load_CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_encrypt := LoadLibCryptoFunction('CMS_RecipientInfo_encrypt');
  if not assigned(CMS_RecipientInfo_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_encrypt');
  Result := CMS_RecipientInfo_encrypt(cms,ri);
end;

function Load_CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  CMS_uncompress := LoadLibCryptoFunction('CMS_uncompress');
  if not assigned(CMS_uncompress) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_uncompress');
  Result := CMS_uncompress(cms,dcont,out_,flags);
end;

function Load_CMS_compress(in_: PBIO; comp_nid: TOpenSSL_C_INT; flags: TOpenSSL_C_UINT): PCMS_ContentInfo; cdecl;
begin
  CMS_compress := LoadLibCryptoFunction('CMS_compress');
  if not assigned(CMS_compress) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_compress');
  Result := CMS_compress(in_,comp_nid,flags);
end;

function Load_CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  CMS_set1_eContentType := LoadLibCryptoFunction('CMS_set1_eContentType');
  if not assigned(CMS_set1_eContentType) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_set1_eContentType');
  Result := CMS_set1_eContentType(cms,oit);
end;

function Load_CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
begin
  CMS_get0_eContentType := LoadLibCryptoFunction('CMS_get0_eContentType');
  if not assigned(CMS_get0_eContentType) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get0_eContentType');
  Result := CMS_get0_eContentType(cms);
end;

function Load_CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl;
begin
  CMS_add0_CertificateChoices := LoadLibCryptoFunction('CMS_add0_CertificateChoices');
  if not assigned(CMS_add0_CertificateChoices) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_CertificateChoices');
  Result := CMS_add0_CertificateChoices(cms);
end;

function Load_CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_add0_cert := LoadLibCryptoFunction('CMS_add0_cert');
  if not assigned(CMS_add0_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_cert');
  Result := CMS_add0_cert(cms,cert);
end;

function Load_CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_add1_cert := LoadLibCryptoFunction('CMS_add1_cert');
  if not assigned(CMS_add1_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_cert');
  Result := CMS_add1_cert(cms,cert);
end;

function Load_CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl;
begin
  CMS_add0_RevocationInfoChoice := LoadLibCryptoFunction('CMS_add0_RevocationInfoChoice');
  if not assigned(CMS_add0_RevocationInfoChoice) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_RevocationInfoChoice');
  Result := CMS_add0_RevocationInfoChoice(cms);
end;

function Load_CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  CMS_add0_crl := LoadLibCryptoFunction('CMS_add0_crl');
  if not assigned(CMS_add0_crl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add0_crl');
  Result := CMS_add0_crl(cms,crl);
end;

function Load_CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TOpenSSL_C_INT; cdecl;
begin
  CMS_add1_crl := LoadLibCryptoFunction('CMS_add1_crl');
  if not assigned(CMS_add1_crl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_crl');
  Result := CMS_add1_crl(cms,crl);
end;

function Load_CMS_SignedData_init(cms: PCMS_ContentInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_SignedData_init := LoadLibCryptoFunction('CMS_SignedData_init');
  if not assigned(CMS_SignedData_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignedData_init');
  Result := CMS_SignedData_init(cms);
end;

function Load_CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TOpenSSL_C_UINT): PCMS_SignerInfo; cdecl;
begin
  CMS_add1_signer := LoadLibCryptoFunction('CMS_add1_signer');
  if not assigned(CMS_add1_signer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_signer');
  Result := CMS_add1_signer(cms,signer,pk,md,flags);
end;

function Load_CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl;
begin
  CMS_SignerInfo_get0_pkey_ctx := LoadLibCryptoFunction('CMS_SignerInfo_get0_pkey_ctx');
  if not assigned(CMS_SignerInfo_get0_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_pkey_ctx');
  Result := CMS_SignerInfo_get0_pkey_ctx(si);
end;

function Load_CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl;
begin
  CMS_SignerInfo_get0_md_ctx := LoadLibCryptoFunction('CMS_SignerInfo_get0_md_ctx');
  if not assigned(CMS_SignerInfo_get0_md_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_md_ctx');
  Result := CMS_SignerInfo_get0_md_ctx(si);
end;

procedure Load_CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509); cdecl;
begin
  CMS_SignerInfo_set1_signer_cert := LoadLibCryptoFunction('CMS_SignerInfo_set1_signer_cert');
  if not assigned(CMS_SignerInfo_set1_signer_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_set1_signer_cert');
  CMS_SignerInfo_set1_signer_cert(si,signer);
end;

function Load_CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  CMS_SignerInfo_get0_signer_id := LoadLibCryptoFunction('CMS_SignerInfo_get0_signer_id');
  if not assigned(CMS_SignerInfo_get0_signer_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_signer_id');
  Result := CMS_SignerInfo_get0_signer_id(si,keyid,issuer,sno);
end;

function Load_CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_SignerInfo_cert_cmp := LoadLibCryptoFunction('CMS_SignerInfo_cert_cmp');
  if not assigned(CMS_SignerInfo_cert_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_cert_cmp');
  Result := CMS_SignerInfo_cert_cmp(si,cert);
end;

procedure Load_CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl;
begin
  CMS_SignerInfo_get0_algs := LoadLibCryptoFunction('CMS_SignerInfo_get0_algs');
  if not assigned(CMS_SignerInfo_get0_algs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_algs');
  CMS_SignerInfo_get0_algs(si,pk,signer,pdig,psig);
end;

function Load_CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl;
begin
  CMS_SignerInfo_get0_signature := LoadLibCryptoFunction('CMS_SignerInfo_get0_signature');
  if not assigned(CMS_SignerInfo_get0_signature) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_get0_signature');
  Result := CMS_SignerInfo_get0_signature(si);
end;

function Load_CMS_SignerInfo_sign(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_SignerInfo_sign := LoadLibCryptoFunction('CMS_SignerInfo_sign');
  if not assigned(CMS_SignerInfo_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_sign');
  Result := CMS_SignerInfo_sign(si);
end;

function Load_CMS_SignerInfo_verify(si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_SignerInfo_verify := LoadLibCryptoFunction('CMS_SignerInfo_verify');
  if not assigned(CMS_SignerInfo_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_verify');
  Result := CMS_SignerInfo_verify(si);
end;

function Load_CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TOpenSSL_C_INT; cdecl;
begin
  CMS_SignerInfo_verify_content := LoadLibCryptoFunction('CMS_SignerInfo_verify_content');
  if not assigned(CMS_SignerInfo_verify_content) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SignerInfo_verify_content');
  Result := CMS_SignerInfo_verify_content(si,chain);
end;

function Load_CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_get_attr_count := LoadLibCryptoFunction('CMS_signed_get_attr_count');
  if not assigned(CMS_signed_get_attr_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr_count');
  Result := CMS_signed_get_attr_count(si);
end;

function Load_CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_get_attr_by_NID := LoadLibCryptoFunction('CMS_signed_get_attr_by_NID');
  if not assigned(CMS_signed_get_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr_by_NID');
  Result := CMS_signed_get_attr_by_NID(si,nid,lastpos);
end;

function Load_CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_get_attr_by_OBJ := LoadLibCryptoFunction('CMS_signed_get_attr_by_OBJ');
  if not assigned(CMS_signed_get_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr_by_OBJ');
  Result := CMS_signed_get_attr_by_OBJ(si,obj,lastpos);
end;

function Load_CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  CMS_signed_get_attr := LoadLibCryptoFunction('CMS_signed_get_attr');
  if not assigned(CMS_signed_get_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get_attr');
  Result := CMS_signed_get_attr(si,loc);
end;

function Load_CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  CMS_signed_delete_attr := LoadLibCryptoFunction('CMS_signed_delete_attr');
  if not assigned(CMS_signed_delete_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_delete_attr');
  Result := CMS_signed_delete_attr(si,loc);
end;

function Load_CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_add1_attr := LoadLibCryptoFunction('CMS_signed_add1_attr');
  if not assigned(CMS_signed_add1_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr');
  Result := CMS_signed_add1_attr(si,loc);
end;

function Load_CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_add1_attr_by_OBJ := LoadLibCryptoFunction('CMS_signed_add1_attr_by_OBJ');
  if not assigned(CMS_signed_add1_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr_by_OBJ');
  Result := CMS_signed_add1_attr_by_OBJ(si,obj,type_,bytes,len);
end;

function Load_CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_add1_attr_by_NID := LoadLibCryptoFunction('CMS_signed_add1_attr_by_NID');
  if not assigned(CMS_signed_add1_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr_by_NID');
  Result := CMS_signed_add1_attr_by_NID(si,nid,type_,bytes,len);
end;

function Load_CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_signed_add1_attr_by_txt := LoadLibCryptoFunction('CMS_signed_add1_attr_by_txt');
  if not assigned(CMS_signed_add1_attr_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_add1_attr_by_txt');
  Result := CMS_signed_add1_attr_by_txt(si,attrname,type_,bytes,len);
end;

function Load_CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CMS_signed_get0_data_by_OBJ := LoadLibCryptoFunction('CMS_signed_get0_data_by_OBJ');
  if not assigned(CMS_signed_get0_data_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_signed_get0_data_by_OBJ');
  Result := CMS_signed_get0_data_by_OBJ(si,oid,lastpos,type_);
end;

function Load_CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_get_attr_count := LoadLibCryptoFunction('CMS_unsigned_get_attr_count');
  if not assigned(CMS_unsigned_get_attr_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr_count');
  Result := CMS_unsigned_get_attr_count(si);
end;

function Load_CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_get_attr_by_NID := LoadLibCryptoFunction('CMS_unsigned_get_attr_by_NID');
  if not assigned(CMS_unsigned_get_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr_by_NID');
  Result := CMS_unsigned_get_attr_by_NID(si,nid,lastpos);
end;

function Load_CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_get_attr_by_OBJ := LoadLibCryptoFunction('CMS_unsigned_get_attr_by_OBJ');
  if not assigned(CMS_unsigned_get_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr_by_OBJ');
  Result := CMS_unsigned_get_attr_by_OBJ(si,obj,lastpos);
end;

function Load_CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  CMS_unsigned_get_attr := LoadLibCryptoFunction('CMS_unsigned_get_attr');
  if not assigned(CMS_unsigned_get_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get_attr');
  Result := CMS_unsigned_get_attr(si,loc);
end;

function Load_CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TOpenSSL_C_INT): PX509_ATTRIBUTE; cdecl;
begin
  CMS_unsigned_delete_attr := LoadLibCryptoFunction('CMS_unsigned_delete_attr');
  if not assigned(CMS_unsigned_delete_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_delete_attr');
  Result := CMS_unsigned_delete_attr(si,loc);
end;

function Load_CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_add1_attr := LoadLibCryptoFunction('CMS_unsigned_add1_attr');
  if not assigned(CMS_unsigned_add1_attr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr');
  Result := CMS_unsigned_add1_attr(si,attr);
end;

function Load_CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_add1_attr_by_OBJ := LoadLibCryptoFunction('CMS_unsigned_add1_attr_by_OBJ');
  if not assigned(CMS_unsigned_add1_attr_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr_by_OBJ');
  Result := CMS_unsigned_add1_attr_by_OBJ(si,obj,type_,bytes,len);
end;

function Load_CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TOpenSSL_C_INT; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_add1_attr_by_NID := LoadLibCryptoFunction('CMS_unsigned_add1_attr_by_NID');
  if not assigned(CMS_unsigned_add1_attr_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr_by_NID');
  Result := CMS_unsigned_add1_attr_by_NID(si,nid,type_,bytes,len);
end;

function Load_CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TOpenSSL_C_INT; const bytes: Pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_unsigned_add1_attr_by_txt := LoadLibCryptoFunction('CMS_unsigned_add1_attr_by_txt');
  if not assigned(CMS_unsigned_add1_attr_by_txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_add1_attr_by_txt');
  Result := CMS_unsigned_add1_attr_by_txt(si,attrname,type_,bytes,len);
end;

function Load_CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TOpenSSL_C_INT; type_: TOpenSSL_C_INT): Pointer; cdecl;
begin
  CMS_unsigned_get0_data_by_OBJ := LoadLibCryptoFunction('CMS_unsigned_get0_data_by_OBJ');
  if not assigned(CMS_unsigned_get0_data_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_unsigned_get0_data_by_OBJ');
  Result := CMS_unsigned_get0_data_by_OBJ(si,oid,lastpos,type_);
end;

function Load_CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl;
begin
  CMS_get1_ReceiptRequest := LoadLibCryptoFunction('CMS_get1_ReceiptRequest');
  if not assigned(CMS_get1_ReceiptRequest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_get1_ReceiptRequest');
  Result := CMS_get1_ReceiptRequest(si,prr);
end;

function Load_CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TOpenSSL_C_INT; cdecl;
begin
  CMS_add1_ReceiptRequest := LoadLibCryptoFunction('CMS_add1_ReceiptRequest');
  if not assigned(CMS_add1_ReceiptRequest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_add1_ReceiptRequest');
  Result := CMS_add1_ReceiptRequest(si,rr);
end;

function Load_CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_kari_get0_orig_id := LoadLibCryptoFunction('CMS_RecipientInfo_kari_get0_orig_id');
  if not assigned(CMS_RecipientInfo_kari_get0_orig_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_get0_orig_id');
  Result := CMS_RecipientInfo_kari_get0_orig_id(ri,pubalg,pubkey,keyid,issuer,sno);
end;

function Load_CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_kari_orig_id_cmp := LoadLibCryptoFunction('CMS_RecipientInfo_kari_orig_id_cmp');
  if not assigned(CMS_RecipientInfo_kari_orig_id_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_orig_id_cmp');
  Result := CMS_RecipientInfo_kari_orig_id_cmp(ri,cert);
end;

function Load_CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientEncryptedKey_get0_id := LoadLibCryptoFunction('CMS_RecipientEncryptedKey_get0_id');
  if not assigned(CMS_RecipientEncryptedKey_get0_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientEncryptedKey_get0_id');
  Result := CMS_RecipientEncryptedKey_get0_id(rek,keyid,tm,other,issuer,sno);
end;

function Load_CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientEncryptedKey_cert_cmp := LoadLibCryptoFunction('CMS_RecipientEncryptedKey_cert_cmp');
  if not assigned(CMS_RecipientEncryptedKey_cert_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientEncryptedKey_cert_cmp');
  Result := CMS_RecipientEncryptedKey_cert_cmp(rek,cert);
end;

function Load_CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_kari_set0_pkey := LoadLibCryptoFunction('CMS_RecipientInfo_kari_set0_pkey');
  if not assigned(CMS_RecipientInfo_kari_set0_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_set0_pkey');
  Result := CMS_RecipientInfo_kari_set0_pkey(ri,pk);
end;

function Load_CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl;
begin
  CMS_RecipientInfo_kari_get0_ctx := LoadLibCryptoFunction('CMS_RecipientInfo_kari_get0_ctx');
  if not assigned(CMS_RecipientInfo_kari_get0_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_get0_ctx');
  Result := CMS_RecipientInfo_kari_get0_ctx(ri);
end;

function Load_CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TOpenSSL_C_INT; cdecl;
begin
  CMS_RecipientInfo_kari_decrypt := LoadLibCryptoFunction('CMS_RecipientInfo_kari_decrypt');
  if not assigned(CMS_RecipientInfo_kari_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_RecipientInfo_kari_decrypt');
  Result := CMS_RecipientInfo_kari_decrypt(cms,ri,rek);
end;

function Load_CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CMS_SharedInfo_encode := LoadLibCryptoFunction('CMS_SharedInfo_encode');
  if not assigned(CMS_SharedInfo_encode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMS_SharedInfo_encode');
  Result := CMS_SharedInfo_encode(pder,kekalg,ukm,keylen);
end;


procedure UnLoad;
begin
  CMS_get0_type := Load_CMS_get0_type;
  CMS_dataInit := Load_CMS_dataInit;
  CMS_dataFinal := Load_CMS_dataFinal;
  CMS_get0_content := Load_CMS_get0_content;
  CMS_is_detached := Load_CMS_is_detached;
  CMS_set_detached := Load_CMS_set_detached;
  CMS_stream := Load_CMS_stream;
  d2i_CMS_bio := Load_d2i_CMS_bio;
  i2d_CMS_bio := Load_i2d_CMS_bio;
  BIO_new_CMS := Load_BIO_new_CMS;
  i2d_CMS_bio_stream := Load_i2d_CMS_bio_stream;
  PEM_write_bio_CMS_stream := Load_PEM_write_bio_CMS_stream;
  SMIME_read_CMS := Load_SMIME_read_CMS;
  SMIME_write_CMS := Load_SMIME_write_CMS;
  CMS_final := Load_CMS_final;
  CMS_data := Load_CMS_data;
  CMS_data_create := Load_CMS_data_create;
  CMS_digest_verify := Load_CMS_digest_verify;
  CMS_digest_create := Load_CMS_digest_create;
  CMS_EncryptedData_decrypt := Load_CMS_EncryptedData_decrypt;
  CMS_EncryptedData_encrypt := Load_CMS_EncryptedData_encrypt;
  CMS_EncryptedData_set1_key := Load_CMS_EncryptedData_set1_key;
  CMS_decrypt := Load_CMS_decrypt;
  CMS_decrypt_set1_pkey := Load_CMS_decrypt_set1_pkey;
  CMS_decrypt_set1_key := Load_CMS_decrypt_set1_key;
  CMS_decrypt_set1_password := Load_CMS_decrypt_set1_password;
  CMS_RecipientInfo_type := Load_CMS_RecipientInfo_type;
  CMS_RecipientInfo_get0_pkey_ctx := Load_CMS_RecipientInfo_get0_pkey_ctx;
  CMS_EnvelopedData_create := Load_CMS_EnvelopedData_create;
  CMS_add1_recipient_cert := Load_CMS_add1_recipient_cert;
  CMS_RecipientInfo_set0_pkey := Load_CMS_RecipientInfo_set0_pkey;
  CMS_RecipientInfo_ktri_cert_cmp := Load_CMS_RecipientInfo_ktri_cert_cmp;
  CMS_RecipientInfo_ktri_get0_algs := Load_CMS_RecipientInfo_ktri_get0_algs;
  CMS_RecipientInfo_ktri_get0_signer_id := Load_CMS_RecipientInfo_ktri_get0_signer_id;
  CMS_add0_recipient_key := Load_CMS_add0_recipient_key;
  CMS_RecipientInfo_kekri_get0_id := Load_CMS_RecipientInfo_kekri_get0_id;
  CMS_RecipientInfo_set0_key := Load_CMS_RecipientInfo_set0_key;
  CMS_RecipientInfo_kekri_id_cmp := Load_CMS_RecipientInfo_kekri_id_cmp;
  CMS_RecipientInfo_set0_password := Load_CMS_RecipientInfo_set0_password;
  CMS_add0_recipient_password := Load_CMS_add0_recipient_password;
  CMS_RecipientInfo_decrypt := Load_CMS_RecipientInfo_decrypt;
  CMS_RecipientInfo_encrypt := Load_CMS_RecipientInfo_encrypt;
  CMS_uncompress := Load_CMS_uncompress;
  CMS_compress := Load_CMS_compress;
  CMS_set1_eContentType := Load_CMS_set1_eContentType;
  CMS_get0_eContentType := Load_CMS_get0_eContentType;
  CMS_add0_CertificateChoices := Load_CMS_add0_CertificateChoices;
  CMS_add0_cert := Load_CMS_add0_cert;
  CMS_add1_cert := Load_CMS_add1_cert;
  CMS_add0_RevocationInfoChoice := Load_CMS_add0_RevocationInfoChoice;
  CMS_add0_crl := Load_CMS_add0_crl;
  CMS_add1_crl := Load_CMS_add1_crl;
  CMS_SignedData_init := Load_CMS_SignedData_init;
  CMS_add1_signer := Load_CMS_add1_signer;
  CMS_SignerInfo_get0_pkey_ctx := Load_CMS_SignerInfo_get0_pkey_ctx;
  CMS_SignerInfo_get0_md_ctx := Load_CMS_SignerInfo_get0_md_ctx;
  CMS_SignerInfo_set1_signer_cert := Load_CMS_SignerInfo_set1_signer_cert;
  CMS_SignerInfo_get0_signer_id := Load_CMS_SignerInfo_get0_signer_id;
  CMS_SignerInfo_cert_cmp := Load_CMS_SignerInfo_cert_cmp;
  CMS_SignerInfo_get0_algs := Load_CMS_SignerInfo_get0_algs;
  CMS_SignerInfo_get0_signature := Load_CMS_SignerInfo_get0_signature;
  CMS_SignerInfo_sign := Load_CMS_SignerInfo_sign;
  CMS_SignerInfo_verify := Load_CMS_SignerInfo_verify;
  CMS_SignerInfo_verify_content := Load_CMS_SignerInfo_verify_content;
  CMS_signed_get_attr_count := Load_CMS_signed_get_attr_count;
  CMS_signed_get_attr_by_NID := Load_CMS_signed_get_attr_by_NID;
  CMS_signed_get_attr_by_OBJ := Load_CMS_signed_get_attr_by_OBJ;
  CMS_signed_get_attr := Load_CMS_signed_get_attr;
  CMS_signed_delete_attr := Load_CMS_signed_delete_attr;
  CMS_signed_add1_attr := Load_CMS_signed_add1_attr;
  CMS_signed_add1_attr_by_OBJ := Load_CMS_signed_add1_attr_by_OBJ;
  CMS_signed_add1_attr_by_NID := Load_CMS_signed_add1_attr_by_NID;
  CMS_signed_add1_attr_by_txt := Load_CMS_signed_add1_attr_by_txt;
  CMS_signed_get0_data_by_OBJ := Load_CMS_signed_get0_data_by_OBJ;
  CMS_unsigned_get_attr_count := Load_CMS_unsigned_get_attr_count;
  CMS_unsigned_get_attr_by_NID := Load_CMS_unsigned_get_attr_by_NID;
  CMS_unsigned_get_attr_by_OBJ := Load_CMS_unsigned_get_attr_by_OBJ;
  CMS_unsigned_get_attr := Load_CMS_unsigned_get_attr;
  CMS_unsigned_delete_attr := Load_CMS_unsigned_delete_attr;
  CMS_unsigned_add1_attr := Load_CMS_unsigned_add1_attr;
  CMS_unsigned_add1_attr_by_OBJ := Load_CMS_unsigned_add1_attr_by_OBJ;
  CMS_unsigned_add1_attr_by_NID := Load_CMS_unsigned_add1_attr_by_NID;
  CMS_unsigned_add1_attr_by_txt := Load_CMS_unsigned_add1_attr_by_txt;
  CMS_unsigned_get0_data_by_OBJ := Load_CMS_unsigned_get0_data_by_OBJ;
  CMS_get1_ReceiptRequest := Load_CMS_get1_ReceiptRequest;
  CMS_add1_ReceiptRequest := Load_CMS_add1_ReceiptRequest;
  CMS_RecipientInfo_kari_get0_orig_id := Load_CMS_RecipientInfo_kari_get0_orig_id;
  CMS_RecipientInfo_kari_orig_id_cmp := Load_CMS_RecipientInfo_kari_orig_id_cmp;
  CMS_RecipientEncryptedKey_get0_id := Load_CMS_RecipientEncryptedKey_get0_id;
  CMS_RecipientEncryptedKey_cert_cmp := Load_CMS_RecipientEncryptedKey_cert_cmp;
  CMS_RecipientInfo_kari_set0_pkey := Load_CMS_RecipientInfo_kari_set0_pkey;
  CMS_RecipientInfo_kari_get0_ctx := Load_CMS_RecipientInfo_kari_get0_ctx;
  CMS_RecipientInfo_kari_decrypt := Load_CMS_RecipientInfo_kari_decrypt;
  CMS_SharedInfo_encode := Load_CMS_SharedInfo_encode;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
