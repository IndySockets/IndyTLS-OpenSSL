  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_cms.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_cms.h2pas
     and this file regenerated. IdOpenSSLHeaders_cms.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_cms;

interface

// Headers for OpenSSL 1.1.1
// cms.h


uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  CMS_get0_type: function (const cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;

  CMS_dataInit: function (cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl = nil;
  CMS_dataFinal: function (cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT; cdecl = nil;

  CMS_get0_content: function (cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl = nil;
  CMS_is_detached: function (cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;
  CMS_set_detached: function (cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT; cdecl = nil;

  CMS_stream: function (cms: PCMS_ContentInfo; boundary: PPPByte): TIdC_INT; cdecl = nil;
  d2i_CMS_bio: function (bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl = nil;
  i2d_CMS_bio: function (bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;

  BIO_new_CMS: function (out_: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl = nil;
  i2d_CMS_bio_stream: function (out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  PEM_write_bio_CMS_stream: function (out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  SMIME_read_CMS: function (bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl = nil;
  SMIME_write_CMS: function (bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;

  CMS_final: function (cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;

//  function CMS_sign(signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(x509) *certs;} data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo;

//  function CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(X509) *certs;} flags: TIdC_UINT): PCMS_ContentInfo;

  CMS_data: function (cms: PCMS_ContentInfo; out_: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  CMS_data_create: function (in_: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;

  CMS_digest_verify: function (cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  CMS_digest_create: function (in_: PBIO; const md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;

  CMS_EncryptedData_decrypt: function (cms: PCMS_ContentInfo; const key: PByte; keylen: TIdC_SIZET; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;

  CMS_EncryptedData_encrypt: function (in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;

  CMS_EncryptedData_set1_key: function (cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TIdC_SIZET): TIdC_INT; cdecl = nil;

//  function CMS_verify(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} store: PX509_STORE; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT;

//  function CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; {STACK_OF(x509) *certs;} store: PX509_STORE; flags: TIdC_UINT): TIdC_INT;

  // STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);

//  function CMS_encrypt({STACK_OF(x509) *certs;} in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo;

  CMS_decrypt: function (cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;

  CMS_decrypt_set1_pkey: function (cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT; cdecl = nil;
  CMS_decrypt_set1_key: function (cms: PCMS_ContentInfo; key: PByte; keylen: TIdC_SIZET; const id: PByte; idlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  CMS_decrypt_set1_password: function (cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TIdC_INT; cdecl = nil;

  //STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
  CMS_RecipientInfo_type: function (ri: PCMS_RecipientInfo): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_get0_pkey_ctx: function (ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl = nil;
  CMS_EnvelopedData_create: function (const cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl = nil;
  CMS_add1_recipient_cert: function (cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl = nil;
  CMS_RecipientInfo_set0_pkey: function (ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_ktri_cert_cmp: function (ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_ktri_get0_algs: function (ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_ktri_get0_signer_id: function (ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;

  CMS_add0_recipient_key: function (cms: PCMS_ContentInfo; nid: TIdC_INT; key: PByte; keylen: TIdC_SIZET; id: PByte; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; cdecl = nil;

  CMS_RecipientInfo_kekri_get0_id: function (ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TIdC_INT; cdecl = nil;

  CMS_RecipientInfo_set0_key: function (ri: PCMS_RecipientInfo; key: PByte; keylen: TIdC_SIZET): TIdC_INT; cdecl = nil;

  CMS_RecipientInfo_kekri_id_cmp: function (ri: PCMS_RecipientInfo; const id: PByte; idlen: TIdC_SIZET): TIdC_INT; cdecl = nil;

  CMS_RecipientInfo_set0_password: function (ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TIdC_INT; cdecl = nil;

  CMS_add0_recipient_password: function (cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl = nil;

  CMS_RecipientInfo_decrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_encrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl = nil;

  CMS_uncompress: function (cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  CMS_compress: function (in_: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;

  CMS_set1_eContentType: function (cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  CMS_get0_eContentType: function (cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;

  CMS_add0_CertificateChoices: function (cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl = nil;
  CMS_add0_cert: function (cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl = nil;
  CMS_add1_cert: function (cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl = nil;
  // STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms);

  CMS_add0_RevocationInfoChoice: function (cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl = nil;
  CMS_add0_crl: function (cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  CMS_add1_crl: function (cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  // STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);

  CMS_SignedData_init: function (cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;
  CMS_add1_signer: function (cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo; cdecl = nil;
  CMS_SignerInfo_get0_pkey_ctx: function (si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl = nil;
  CMS_SignerInfo_get0_md_ctx: function (si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl = nil;
  // STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);

  CMS_SignerInfo_set1_signer_cert: procedure (si: PCMS_SignerInfo; signer: PX509); cdecl = nil;
  CMS_SignerInfo_get0_signer_id: function (si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  CMS_SignerInfo_cert_cmp: function (si: PCMS_SignerInfo; cert: PX509): TIdC_INT; cdecl = nil;
//  function CMS_set1_signers_certs(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} flags: TIdC_UINT): TIdC_INT;
  CMS_SignerInfo_get0_algs: procedure (si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl = nil;
  CMS_SignerInfo_get0_signature: function (si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl = nil;
  CMS_SignerInfo_sign: function (si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  CMS_SignerInfo_verify: function (si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  CMS_SignerInfo_verify_content: function (si: PCMS_SignerInfo; chain: PBIO): TIdC_INT; cdecl = nil;

//  function CMS_add_smimecap(si: PCMS_SignerInfo{; STACK_OF(X509_ALGOR) *algs}): TIdC_INT;
//  function CMS_add_simple_smimecap({STACK_OF(X509_ALGOR) **algs;} algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT;
//  function CMS_add_standard_smimecap({STACK_OF(X509_ALGOR) **smcap}): TIdC_INT;

  CMS_signed_get_attr_count: function (const si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  CMS_signed_get_attr_by_NID: function (const si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_signed_get_attr_by_OBJ: function (const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_signed_get_attr: function (const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_signed_delete_attr: function (const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_signed_add1_attr: function (si: PCMS_SignerInfo; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_signed_add1_attr_by_OBJ: function (si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_signed_add1_attr_by_NID: function (si: PCMS_SignerInfo; nid: TIdC_INT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_signed_add1_attr_by_txt: function (si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_signed_get0_data_by_OBJ: function (si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TIdC_INT; type_: TIdC_INT): Pointer; cdecl = nil;

  CMS_unsigned_get_attr_count: function (const si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  CMS_unsigned_get_attr_by_NID: function (const si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_unsigned_get_attr_by_OBJ: function (const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_unsigned_get_attr: function (const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_unsigned_delete_attr: function (si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  CMS_unsigned_add1_attr: function (si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  CMS_unsigned_add1_attr_by_OBJ: function (si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_unsigned_add1_attr_by_NID: function (si: PCMS_SignerInfo; nid: TIdC_INT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_unsigned_add1_attr_by_txt: function (si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  CMS_unsigned_get0_data_by_OBJ: function (si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; type_: TIdC_INT): Pointer; cdecl = nil;

  CMS_get1_ReceiptRequest: function (si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT; cdecl = nil;
//  function CMS_ReceiptRequest_create0(id: PByte; idlen: TIdC_INT; allorfirst: TIdC_INT
//    {;STACK_OF(GENERAL_NAMES) *receiptList;} {STACK_OF(GENERAL_NAMES) *receiptsTo}): PCMS_ReceiptRequest;
  CMS_add1_ReceiptRequest: function (si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT; cdecl = nil;
//  procedure CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING;
//    pallorfirst: PIdC_INT {;STACK_OF(GENERAL_NAMES) **plist;}
//    {STACK_OF(GENERAL_NAMES) **prto});
//  function CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR;
//    pukm: PPASN1_OCTET_STRING): TIdC_INT;
//  // STACK_OF(CMS_RecipientEncryptedKey) *CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);

  CMS_RecipientInfo_kari_get0_orig_id: function (ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;

  CMS_RecipientInfo_kari_orig_id_cmp: function (ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl = nil;

  CMS_RecipientEncryptedKey_get0_id: function (rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  CMS_RecipientEncryptedKey_cert_cmp: function (rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_kari_set0_pkey: function (ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  CMS_RecipientInfo_kari_get0_ctx: function (ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl = nil;
  CMS_RecipientInfo_kari_decrypt: function (cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT; cdecl = nil;

  CMS_SharedInfo_encode: function (pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT; cdecl = nil;

  ///* Backward compatibility for spelling errors. */
  //# define CMS_R_UNKNOWN_DIGEST_ALGORITM CMS_R_UNKNOWN_DIGEST_ALGORITHM
  //# define CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE \ CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE

{$ELSE}
  function CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT cdecl; external CLibCrypto;

  function CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO cdecl; external CLibCrypto;
  function CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT cdecl; external CLibCrypto;

  function CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING cdecl; external CLibCrypto;
  function CMS_is_detached(cms: PCMS_ContentInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_set_detached(cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TIdC_INT cdecl; external CLibCrypto;
  function d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo cdecl; external CLibCrypto;
  function i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT cdecl; external CLibCrypto;

  function BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO cdecl; external CLibCrypto;
  function i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo cdecl; external CLibCrypto;
  function SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

//  function CMS_sign(signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(x509) *certs;} data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo;

//  function CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(X509) *certs;} flags: TIdC_UINT): PCMS_ContentInfo;

  function CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_data_create(in_: PBIO; flags: TIdC_UINT): PCMS_ContentInfo cdecl; external CLibCrypto;

  function CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo cdecl; external CLibCrypto;

  function CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TIdC_SIZET; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  function CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo cdecl; external CLibCrypto;

  function CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

//  function CMS_verify(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} store: PX509_STORE; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT;

//  function CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; {STACK_OF(x509) *certs;} store: PX509_STORE; flags: TIdC_UINT): TIdC_INT;

  // STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);

//  function CMS_encrypt({STACK_OF(x509) *certs;} in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo;

  function CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  function CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  function CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TIdC_SIZET; const id: PByte; idlen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TIdC_INT cdecl; external CLibCrypto;

  //STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
  function CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX cdecl; external CLibCrypto;
  function CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo cdecl; external CLibCrypto;
  function CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo cdecl; external CLibCrypto;
  function CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;

  function CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TIdC_INT; key: PByte; keylen: TIdC_SIZET; id: PByte; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo cdecl; external CLibCrypto;

  function CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;

  function CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  function CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  function CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TIdC_INT cdecl; external CLibCrypto;

  function CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo cdecl; external CLibCrypto;

  function CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT cdecl; external CLibCrypto;

  function CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_compress(in_: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo cdecl; external CLibCrypto;

  function CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT cdecl; external CLibCrypto;

  function CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices cdecl; external CLibCrypto;
  function CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  function CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  // STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms);

  function CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice cdecl; external CLibCrypto;
  function CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  function CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  // STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);

  function CMS_SignedData_init(cms: PCMS_ContentInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo cdecl; external CLibCrypto;
  function CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX cdecl; external CLibCrypto;
  function CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX cdecl; external CLibCrypto;
  // STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);

  procedure CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509) cdecl; external CLibCrypto;
  function CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  function CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
//  function CMS_set1_signers_certs(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} flags: TIdC_UINT): TIdC_INT;
  procedure CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR) cdecl; external CLibCrypto;
  function CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  function CMS_SignerInfo_sign(si: PCMS_SignerInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_SignerInfo_verify(si: PCMS_SignerInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TIdC_INT cdecl; external CLibCrypto;

//  function CMS_add_smimecap(si: PCMS_SignerInfo{; STACK_OF(X509_ALGOR) *algs}): TIdC_INT;
//  function CMS_add_simple_smimecap({STACK_OF(X509_ALGOR) **algs;} algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT;
//  function CMS_add_standard_smimecap({STACK_OF(X509_ALGOR) **smcap}): TIdC_INT;

  function CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  function CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  function CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TIdC_INT; type_: TIdC_INT): Pointer cdecl; external CLibCrypto;

  function CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  function CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  function CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; type_: TIdC_INT): Pointer cdecl; external CLibCrypto;

  function CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT cdecl; external CLibCrypto;
//  function CMS_ReceiptRequest_create0(id: PByte; idlen: TIdC_INT; allorfirst: TIdC_INT
//    {;STACK_OF(GENERAL_NAMES) *receiptList;} {STACK_OF(GENERAL_NAMES) *receiptsTo}): PCMS_ReceiptRequest;
  function CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT cdecl; external CLibCrypto;
//  procedure CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING;
//    pallorfirst: PIdC_INT {;STACK_OF(GENERAL_NAMES) **plist;}
//    {STACK_OF(GENERAL_NAMES) **prto});
//  function CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR;
//    pukm: PPASN1_OCTET_STRING): TIdC_INT;
//  // STACK_OF(CMS_RecipientEncryptedKey) *CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);

  function CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;

  function CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT cdecl; external CLibCrypto;

  function CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  function CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX cdecl; external CLibCrypto;
  function CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT cdecl; external CLibCrypto;

  function CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  ///* Backward compatibility for spelling errors. */
  //# define CMS_R_UNKNOWN_DIGEST_ALGORITM CMS_R_UNKNOWN_DIGEST_ALGORITHM
  //# define CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE \ CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE

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
  CMS_get0_type_procname = 'CMS_get0_type';

  CMS_dataInit_procname = 'CMS_dataInit';
  CMS_dataFinal_procname = 'CMS_dataFinal';

  CMS_get0_content_procname = 'CMS_get0_content';
  CMS_is_detached_procname = 'CMS_is_detached';
  CMS_set_detached_procname = 'CMS_set_detached';

  CMS_stream_procname = 'CMS_stream';
  d2i_CMS_bio_procname = 'd2i_CMS_bio';
  i2d_CMS_bio_procname = 'i2d_CMS_bio';

  BIO_new_CMS_procname = 'BIO_new_CMS';
  i2d_CMS_bio_stream_procname = 'i2d_CMS_bio_stream';
  PEM_write_bio_CMS_stream_procname = 'PEM_write_bio_CMS_stream';
  SMIME_read_CMS_procname = 'SMIME_read_CMS';
  SMIME_write_CMS_procname = 'SMIME_write_CMS';

  CMS_final_procname = 'CMS_final';

//  function CMS_sign(signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(x509) *certs;} data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo;

//  function CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(X509) *certs;} flags: TIdC_UINT): PCMS_ContentInfo;

  CMS_data_procname = 'CMS_data';
  CMS_data_create_procname = 'CMS_data_create';

  CMS_digest_verify_procname = 'CMS_digest_verify';
  CMS_digest_create_procname = 'CMS_digest_create';

  CMS_EncryptedData_decrypt_procname = 'CMS_EncryptedData_decrypt';

  CMS_EncryptedData_encrypt_procname = 'CMS_EncryptedData_encrypt';

  CMS_EncryptedData_set1_key_procname = 'CMS_EncryptedData_set1_key';

//  function CMS_verify(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} store: PX509_STORE; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT;

//  function CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; {STACK_OF(x509) *certs;} store: PX509_STORE; flags: TIdC_UINT): TIdC_INT;

  // STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);

//  function CMS_encrypt({STACK_OF(x509) *certs;} in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo;

  CMS_decrypt_procname = 'CMS_decrypt';

  CMS_decrypt_set1_pkey_procname = 'CMS_decrypt_set1_pkey';
  CMS_decrypt_set1_key_procname = 'CMS_decrypt_set1_key';
  CMS_decrypt_set1_password_procname = 'CMS_decrypt_set1_password';

  //STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
  CMS_RecipientInfo_type_procname = 'CMS_RecipientInfo_type';
  CMS_RecipientInfo_get0_pkey_ctx_procname = 'CMS_RecipientInfo_get0_pkey_ctx';
  CMS_EnvelopedData_create_procname = 'CMS_EnvelopedData_create';
  CMS_add1_recipient_cert_procname = 'CMS_add1_recipient_cert';
  CMS_RecipientInfo_set0_pkey_procname = 'CMS_RecipientInfo_set0_pkey';
  CMS_RecipientInfo_ktri_cert_cmp_procname = 'CMS_RecipientInfo_ktri_cert_cmp';
  CMS_RecipientInfo_ktri_get0_algs_procname = 'CMS_RecipientInfo_ktri_get0_algs';
  CMS_RecipientInfo_ktri_get0_signer_id_procname = 'CMS_RecipientInfo_ktri_get0_signer_id';

  CMS_add0_recipient_key_procname = 'CMS_add0_recipient_key';

  CMS_RecipientInfo_kekri_get0_id_procname = 'CMS_RecipientInfo_kekri_get0_id';

  CMS_RecipientInfo_set0_key_procname = 'CMS_RecipientInfo_set0_key';

  CMS_RecipientInfo_kekri_id_cmp_procname = 'CMS_RecipientInfo_kekri_id_cmp';

  CMS_RecipientInfo_set0_password_procname = 'CMS_RecipientInfo_set0_password';

  CMS_add0_recipient_password_procname = 'CMS_add0_recipient_password';

  CMS_RecipientInfo_decrypt_procname = 'CMS_RecipientInfo_decrypt';
  CMS_RecipientInfo_encrypt_procname = 'CMS_RecipientInfo_encrypt';

  CMS_uncompress_procname = 'CMS_uncompress';
  CMS_compress_procname = 'CMS_compress';

  CMS_set1_eContentType_procname = 'CMS_set1_eContentType';
  CMS_get0_eContentType_procname = 'CMS_get0_eContentType';

  CMS_add0_CertificateChoices_procname = 'CMS_add0_CertificateChoices';
  CMS_add0_cert_procname = 'CMS_add0_cert';
  CMS_add1_cert_procname = 'CMS_add1_cert';
  // STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms);

  CMS_add0_RevocationInfoChoice_procname = 'CMS_add0_RevocationInfoChoice';
  CMS_add0_crl_procname = 'CMS_add0_crl';
  CMS_add1_crl_procname = 'CMS_add1_crl';
  // STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);

  CMS_SignedData_init_procname = 'CMS_SignedData_init';
  CMS_add1_signer_procname = 'CMS_add1_signer';
  CMS_SignerInfo_get0_pkey_ctx_procname = 'CMS_SignerInfo_get0_pkey_ctx';
  CMS_SignerInfo_get0_md_ctx_procname = 'CMS_SignerInfo_get0_md_ctx';
  // STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);

  CMS_SignerInfo_set1_signer_cert_procname = 'CMS_SignerInfo_set1_signer_cert';
  CMS_SignerInfo_get0_signer_id_procname = 'CMS_SignerInfo_get0_signer_id';
  CMS_SignerInfo_cert_cmp_procname = 'CMS_SignerInfo_cert_cmp';
//  function CMS_set1_signers_certs(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} flags: TIdC_UINT): TIdC_INT;
  CMS_SignerInfo_get0_algs_procname = 'CMS_SignerInfo_get0_algs';
  CMS_SignerInfo_get0_signature_procname = 'CMS_SignerInfo_get0_signature';
  CMS_SignerInfo_sign_procname = 'CMS_SignerInfo_sign';
  CMS_SignerInfo_verify_procname = 'CMS_SignerInfo_verify';
  CMS_SignerInfo_verify_content_procname = 'CMS_SignerInfo_verify_content';

//  function CMS_add_smimecap(si: PCMS_SignerInfo{; STACK_OF(X509_ALGOR) *algs}): TIdC_INT;
//  function CMS_add_simple_smimecap({STACK_OF(X509_ALGOR) **algs;} algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT;
//  function CMS_add_standard_smimecap({STACK_OF(X509_ALGOR) **smcap}): TIdC_INT;

  CMS_signed_get_attr_count_procname = 'CMS_signed_get_attr_count';
  CMS_signed_get_attr_by_NID_procname = 'CMS_signed_get_attr_by_NID';
  CMS_signed_get_attr_by_OBJ_procname = 'CMS_signed_get_attr_by_OBJ';
  CMS_signed_get_attr_procname = 'CMS_signed_get_attr';
  CMS_signed_delete_attr_procname = 'CMS_signed_delete_attr';
  CMS_signed_add1_attr_procname = 'CMS_signed_add1_attr';
  CMS_signed_add1_attr_by_OBJ_procname = 'CMS_signed_add1_attr_by_OBJ';
  CMS_signed_add1_attr_by_NID_procname = 'CMS_signed_add1_attr_by_NID';
  CMS_signed_add1_attr_by_txt_procname = 'CMS_signed_add1_attr_by_txt';
  CMS_signed_get0_data_by_OBJ_procname = 'CMS_signed_get0_data_by_OBJ';

  CMS_unsigned_get_attr_count_procname = 'CMS_unsigned_get_attr_count';
  CMS_unsigned_get_attr_by_NID_procname = 'CMS_unsigned_get_attr_by_NID';
  CMS_unsigned_get_attr_by_OBJ_procname = 'CMS_unsigned_get_attr_by_OBJ';
  CMS_unsigned_get_attr_procname = 'CMS_unsigned_get_attr';
  CMS_unsigned_delete_attr_procname = 'CMS_unsigned_delete_attr';
  CMS_unsigned_add1_attr_procname = 'CMS_unsigned_add1_attr';
  CMS_unsigned_add1_attr_by_OBJ_procname = 'CMS_unsigned_add1_attr_by_OBJ';
  CMS_unsigned_add1_attr_by_NID_procname = 'CMS_unsigned_add1_attr_by_NID';
  CMS_unsigned_add1_attr_by_txt_procname = 'CMS_unsigned_add1_attr_by_txt';
  CMS_unsigned_get0_data_by_OBJ_procname = 'CMS_unsigned_get0_data_by_OBJ';

  CMS_get1_ReceiptRequest_procname = 'CMS_get1_ReceiptRequest';
//  function CMS_ReceiptRequest_create0(id: PByte; idlen: TIdC_INT; allorfirst: TIdC_INT
//    {;STACK_OF(GENERAL_NAMES) *receiptList;} {STACK_OF(GENERAL_NAMES) *receiptsTo}): PCMS_ReceiptRequest;
  CMS_add1_ReceiptRequest_procname = 'CMS_add1_ReceiptRequest';
//  procedure CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING;
//    pallorfirst: PIdC_INT {;STACK_OF(GENERAL_NAMES) **plist;}
//    {STACK_OF(GENERAL_NAMES) **prto});
//  function CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR;
//    pukm: PPASN1_OCTET_STRING): TIdC_INT;
//  // STACK_OF(CMS_RecipientEncryptedKey) *CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);

  CMS_RecipientInfo_kari_get0_orig_id_procname = 'CMS_RecipientInfo_kari_get0_orig_id';

  CMS_RecipientInfo_kari_orig_id_cmp_procname = 'CMS_RecipientInfo_kari_orig_id_cmp';

  CMS_RecipientEncryptedKey_get0_id_procname = 'CMS_RecipientEncryptedKey_get0_id';
  CMS_RecipientEncryptedKey_cert_cmp_procname = 'CMS_RecipientEncryptedKey_cert_cmp';
  CMS_RecipientInfo_kari_set0_pkey_procname = 'CMS_RecipientInfo_kari_set0_pkey';
  CMS_RecipientInfo_kari_get0_ctx_procname = 'CMS_RecipientInfo_kari_get0_ctx';
  CMS_RecipientInfo_kari_decrypt_procname = 'CMS_RecipientInfo_kari_decrypt';

  CMS_SharedInfo_encode_procname = 'CMS_SharedInfo_encode';

  ///* Backward compatibility for spelling errors. */
  //# define CMS_R_UNKNOWN_DIGEST_ALGORITM CMS_R_UNKNOWN_DIGEST_ALGORITHM
  //# define CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE \ CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE


{$WARN  NO_RETVAL OFF}
function  ERR_CMS_get0_type(const cms: PCMS_ContentInfo): PASN1_OBJECT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_get0_type_procname);
end;



function  ERR_CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_dataInit_procname);
end;


function  ERR_CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_dataFinal_procname);
end;



function  ERR_CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_get0_content_procname);
end;


function  ERR_CMS_is_detached(cms: PCMS_ContentInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_is_detached_procname);
end;


function  ERR_CMS_set_detached(cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_set_detached_procname);
end;



function  ERR_CMS_stream(cms: PCMS_ContentInfo; boundary: PPPByte): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_stream_procname);
end;


function  ERR_d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(d2i_CMS_bio_procname);
end;


function  ERR_i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2d_CMS_bio_procname);
end;



function  ERR_BIO_new_CMS(out_: PBIO; cms: PCMS_ContentInfo): PBIO; 
begin
  EIdAPIFunctionNotPresent.RaiseException(BIO_new_CMS_procname);
end;


function  ERR_i2d_CMS_bio_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(i2d_CMS_bio_stream_procname);
end;


function  ERR_PEM_write_bio_CMS_stream(out_: PBIO; cms: PCMS_ContentInfo; in_: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(PEM_write_bio_CMS_stream_procname);
end;


function  ERR_SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SMIME_read_CMS_procname);
end;


function  ERR_SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(SMIME_write_CMS_procname);
end;



function  ERR_CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_final_procname);
end;



//  function CMS_sign(signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(x509) *certs;} data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo;

//  function CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; {STACK_OF(X509) *certs;} flags: TIdC_UINT): PCMS_ContentInfo;

function  ERR_CMS_data(cms: PCMS_ContentInfo; out_: PBIO; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_data_procname);
end;


function  ERR_CMS_data_create(in_: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_data_create_procname);
end;



function  ERR_CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_digest_verify_procname);
end;


function  ERR_CMS_digest_create(in_: PBIO; const md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_digest_create_procname);
end;



function  ERR_CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; const key: PByte; keylen: TIdC_SIZET; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_decrypt_procname);
end;



function  ERR_CMS_EncryptedData_encrypt(in_: PBIO; const cipher: PEVP_CIPHER; const key: PByte; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_encrypt_procname);
end;



function  ERR_CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; const ciph: PEVP_CIPHER; const key: PByte; keylen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_set1_key_procname);
end;



//  function CMS_verify(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} store: PX509_STORE; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT;

//  function CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; {STACK_OF(x509) *certs;} store: PX509_STORE; flags: TIdC_UINT): TIdC_INT;

  // STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);

//  function CMS_encrypt({STACK_OF(x509) *certs;} in_: PBIO; const cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo;

function  ERR_CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_decrypt_procname);
end;



function  ERR_CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_pkey_procname);
end;


function  ERR_CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PByte; keylen: TIdC_SIZET; const id: PByte; idlen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_key_procname);
end;


function  ERR_CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PByte; passlen: ossl_ssize_t): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_password_procname);
end;



  //STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
function  ERR_CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_type_procname);
end;


function  ERR_CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_get0_pkey_ctx_procname);
end;


function  ERR_CMS_EnvelopedData_create(const cipher: PEVP_CIPHER): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_EnvelopedData_create_procname);
end;


function  ERR_CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add1_recipient_cert_procname);
end;


function  ERR_CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_set0_pkey_procname);
end;


function  ERR_CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_ktri_cert_cmp_procname);
end;


function  ERR_CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_ktri_get0_algs_procname);
end;


function  ERR_CMS_RecipientInfo_ktri_get0_signer_id(ri: PPCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_ktri_get0_signer_id_procname);
end;



function  ERR_CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TIdC_INT; key: PByte; keylen: TIdC_SIZET; id: PByte; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: ASN1_TYPE): PCMS_RecipientInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add0_recipient_key_procname);
end;



function  ERR_CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PASN1_TYPE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kekri_get0_id_procname);
end;



function  ERR_CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PByte; keylen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_set0_key_procname);
end;



function  ERR_CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; const id: PByte; idlen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kekri_id_cmp_procname);
end;



function  ERR_CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PByte; passlen: ossl_ssize_t): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_set0_password_procname);
end;



function  ERR_CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PByte; passlen: ossl_ssize_t; const kekciph: PEVP_CIPHER): PCMS_RecipientInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add0_recipient_password_procname);
end;



function  ERR_CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_decrypt_procname);
end;


function  ERR_CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_encrypt_procname);
end;



function  ERR_CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; out_: PBIO; flags: TIdC_UINT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_uncompress_procname);
end;


function  ERR_CMS_compress(in_: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_compress_procname);
end;



function  ERR_CMS_set1_eContentType(cms: CMS_ContentInfo; const oit: PASN1_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_set1_eContentType_procname);
end;


function  ERR_CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_get0_eContentType_procname);
end;



function  ERR_CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add0_CertificateChoices_procname);
end;


function  ERR_CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add0_cert_procname);
end;


function  ERR_CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add1_cert_procname);
end;


  // STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms);

function  ERR_CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add0_RevocationInfoChoice_procname);
end;


function  ERR_CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add0_crl_procname);
end;


function  ERR_CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add1_crl_procname);
end;


  // STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);

function  ERR_CMS_SignedData_init(cms: PCMS_ContentInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignedData_init_procname);
end;


function  ERR_CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add1_signer_procname);
end;


function  ERR_CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_pkey_ctx_procname);
end;


function  ERR_CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_md_ctx_procname);
end;


  // STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);

procedure  ERR_CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_set1_signer_cert_procname);
end;


function  ERR_CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_signer_id_procname);
end;


function  ERR_CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_cert_cmp_procname);
end;


//  function CMS_set1_signers_certs(cms: PCMS_ContentInfo; {STACK_OF(X509) *certs;} flags: TIdC_UINT): TIdC_INT;
procedure  ERR_CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_algs_procname);
end;


function  ERR_CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_signature_procname);
end;


function  ERR_CMS_SignerInfo_sign(si: PCMS_SignerInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_sign_procname);
end;


function  ERR_CMS_SignerInfo_verify(si: PCMS_SignerInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_verify_procname);
end;


function  ERR_CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_verify_content_procname);
end;



//  function CMS_add_smimecap(si: PCMS_SignerInfo{; STACK_OF(X509_ALGOR) *algs}): TIdC_INT;
//  function CMS_add_simple_smimecap({STACK_OF(X509_ALGOR) **algs;} algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT;
//  function CMS_add_standard_smimecap({STACK_OF(X509_ALGOR) **smcap}): TIdC_INT;

function  ERR_CMS_signed_get_attr_count(const si: PCMS_SignerInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_count_procname);
end;


function  ERR_CMS_signed_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_by_NID_procname);
end;


function  ERR_CMS_signed_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: ASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_by_OBJ_procname);
end;


function  ERR_CMS_signed_get_attr(const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_procname);
end;


function  ERR_CMS_signed_delete_attr(const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_delete_attr_procname);
end;


function  ERR_CMS_signed_add1_attr(si: PCMS_SignerInfo; loc: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_procname);
end;


function  ERR_CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_by_OBJ_procname);
end;


function  ERR_CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_by_NID_procname);
end;


function  ERR_CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_by_txt_procname);
end;


function  ERR_CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; const oid: PASN1_OBJECT; lastpos: TIdC_INT; type_: TIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_signed_get0_data_by_OBJ_procname);
end;



function  ERR_CMS_unsigned_get_attr_count(const si: PCMS_SignerInfo): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_count_procname);
end;


function  ERR_CMS_unsigned_get_attr_by_NID(const si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_by_NID_procname);
end;


function  ERR_CMS_unsigned_get_attr_by_OBJ(const si: PCMS_SignerInfo; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_by_OBJ_procname);
end;


function  ERR_CMS_unsigned_get_attr(const si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_procname);
end;


function  ERR_CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_delete_attr_procname);
end;


function  ERR_CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_procname);
end;


function  ERR_CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_by_OBJ_procname);
end;


function  ERR_CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_by_NID_procname);
end;


function  ERR_CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; const attrname: PAnsiChar; type_: TIdC_INT; const bytes: Pointer; len: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_by_txt_procname);
end;


function  ERR_CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; type_: TIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_unsigned_get0_data_by_OBJ_procname);
end;



function  ERR_CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_get1_ReceiptRequest_procname);
end;


//  function CMS_ReceiptRequest_create0(id: PByte; idlen: TIdC_INT; allorfirst: TIdC_INT
//    {;STACK_OF(GENERAL_NAMES) *receiptList;} {STACK_OF(GENERAL_NAMES) *receiptsTo}): PCMS_ReceiptRequest;
function  ERR_CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_add1_ReceiptRequest_procname);
end;


//  procedure CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING;
//    pallorfirst: PIdC_INT {;STACK_OF(GENERAL_NAMES) **plist;}
//    {STACK_OF(GENERAL_NAMES) **prto});
//  function CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR;
//    pukm: PPASN1_OCTET_STRING): TIdC_INT;
//  // STACK_OF(CMS_RecipientEncryptedKey) *CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);

function  ERR_CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_get0_orig_id_procname);
end;



function  ERR_CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_orig_id_cmp_procname);
end;



function  ERR_CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientEncryptedKey_get0_id_procname);
end;


function  ERR_CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientEncryptedKey_cert_cmp_procname);
end;


function  ERR_CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_set0_pkey_procname);
end;


function  ERR_CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_get0_ctx_procname);
end;


function  ERR_CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_decrypt_procname);
end;



function  ERR_CMS_SharedInfo_encode(pder: PPByte; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(CMS_SharedInfo_encode_procname);
end;



  ///* Backward compatibility for spelling errors. */
  //# define CMS_R_UNKNOWN_DIGEST_ALGORITM CMS_R_UNKNOWN_DIGEST_ALGORITHM
  //# define CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE \ CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE

{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  CMS_get0_type := LoadLibFunction(ADllHandle, CMS_get0_type_procname);
  FuncLoadError := not assigned(CMS_get0_type);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_type_allownil)}
    CMS_get0_type := @ERR_CMS_get0_type;
    {$ifend}
    {$if declared(CMS_get0_type_introduced)}
    if LibVersion < CMS_get0_type_introduced then
    begin
      {$if declared(FC_CMS_get0_type)}
      CMS_get0_type := @FC_CMS_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_type_removed)}
    if CMS_get0_type_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_type)}
      CMS_get0_type := @_CMS_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_type_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_type');
    {$ifend}
  end;


  CMS_dataInit := LoadLibFunction(ADllHandle, CMS_dataInit_procname);
  FuncLoadError := not assigned(CMS_dataInit);
  if FuncLoadError then
  begin
    {$if not defined(CMS_dataInit_allownil)}
    CMS_dataInit := @ERR_CMS_dataInit;
    {$ifend}
    {$if declared(CMS_dataInit_introduced)}
    if LibVersion < CMS_dataInit_introduced then
    begin
      {$if declared(FC_CMS_dataInit)}
      CMS_dataInit := @FC_CMS_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_dataInit_removed)}
    if CMS_dataInit_removed <= LibVersion then
    begin
      {$if declared(_CMS_dataInit)}
      CMS_dataInit := @_CMS_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_dataInit_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_dataInit');
    {$ifend}
  end;


  CMS_dataFinal := LoadLibFunction(ADllHandle, CMS_dataFinal_procname);
  FuncLoadError := not assigned(CMS_dataFinal);
  if FuncLoadError then
  begin
    {$if not defined(CMS_dataFinal_allownil)}
    CMS_dataFinal := @ERR_CMS_dataFinal;
    {$ifend}
    {$if declared(CMS_dataFinal_introduced)}
    if LibVersion < CMS_dataFinal_introduced then
    begin
      {$if declared(FC_CMS_dataFinal)}
      CMS_dataFinal := @FC_CMS_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_dataFinal_removed)}
    if CMS_dataFinal_removed <= LibVersion then
    begin
      {$if declared(_CMS_dataFinal)}
      CMS_dataFinal := @_CMS_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_dataFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_dataFinal');
    {$ifend}
  end;


  CMS_get0_content := LoadLibFunction(ADllHandle, CMS_get0_content_procname);
  FuncLoadError := not assigned(CMS_get0_content);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_content_allownil)}
    CMS_get0_content := @ERR_CMS_get0_content;
    {$ifend}
    {$if declared(CMS_get0_content_introduced)}
    if LibVersion < CMS_get0_content_introduced then
    begin
      {$if declared(FC_CMS_get0_content)}
      CMS_get0_content := @FC_CMS_get0_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_content_removed)}
    if CMS_get0_content_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_content)}
      CMS_get0_content := @_CMS_get0_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_content_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_content');
    {$ifend}
  end;


  CMS_is_detached := LoadLibFunction(ADllHandle, CMS_is_detached_procname);
  FuncLoadError := not assigned(CMS_is_detached);
  if FuncLoadError then
  begin
    {$if not defined(CMS_is_detached_allownil)}
    CMS_is_detached := @ERR_CMS_is_detached;
    {$ifend}
    {$if declared(CMS_is_detached_introduced)}
    if LibVersion < CMS_is_detached_introduced then
    begin
      {$if declared(FC_CMS_is_detached)}
      CMS_is_detached := @FC_CMS_is_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_is_detached_removed)}
    if CMS_is_detached_removed <= LibVersion then
    begin
      {$if declared(_CMS_is_detached)}
      CMS_is_detached := @_CMS_is_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_is_detached_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_is_detached');
    {$ifend}
  end;


  CMS_set_detached := LoadLibFunction(ADllHandle, CMS_set_detached_procname);
  FuncLoadError := not assigned(CMS_set_detached);
  if FuncLoadError then
  begin
    {$if not defined(CMS_set_detached_allownil)}
    CMS_set_detached := @ERR_CMS_set_detached;
    {$ifend}
    {$if declared(CMS_set_detached_introduced)}
    if LibVersion < CMS_set_detached_introduced then
    begin
      {$if declared(FC_CMS_set_detached)}
      CMS_set_detached := @FC_CMS_set_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_set_detached_removed)}
    if CMS_set_detached_removed <= LibVersion then
    begin
      {$if declared(_CMS_set_detached)}
      CMS_set_detached := @_CMS_set_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_set_detached_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_set_detached');
    {$ifend}
  end;


  CMS_stream := LoadLibFunction(ADllHandle, CMS_stream_procname);
  FuncLoadError := not assigned(CMS_stream);
  if FuncLoadError then
  begin
    {$if not defined(CMS_stream_allownil)}
    CMS_stream := @ERR_CMS_stream;
    {$ifend}
    {$if declared(CMS_stream_introduced)}
    if LibVersion < CMS_stream_introduced then
    begin
      {$if declared(FC_CMS_stream)}
      CMS_stream := @FC_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_stream_removed)}
    if CMS_stream_removed <= LibVersion then
    begin
      {$if declared(_CMS_stream)}
      CMS_stream := @_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_stream');
    {$ifend}
  end;


  d2i_CMS_bio := LoadLibFunction(ADllHandle, d2i_CMS_bio_procname);
  FuncLoadError := not assigned(d2i_CMS_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_CMS_bio_allownil)}
    d2i_CMS_bio := @ERR_d2i_CMS_bio;
    {$ifend}
    {$if declared(d2i_CMS_bio_introduced)}
    if LibVersion < d2i_CMS_bio_introduced then
    begin
      {$if declared(FC_d2i_CMS_bio)}
      d2i_CMS_bio := @FC_d2i_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_CMS_bio_removed)}
    if d2i_CMS_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_CMS_bio)}
      d2i_CMS_bio := @_d2i_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_CMS_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_CMS_bio');
    {$ifend}
  end;


  i2d_CMS_bio := LoadLibFunction(ADllHandle, i2d_CMS_bio_procname);
  FuncLoadError := not assigned(i2d_CMS_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CMS_bio_allownil)}
    i2d_CMS_bio := @ERR_i2d_CMS_bio;
    {$ifend}
    {$if declared(i2d_CMS_bio_introduced)}
    if LibVersion < i2d_CMS_bio_introduced then
    begin
      {$if declared(FC_i2d_CMS_bio)}
      i2d_CMS_bio := @FC_i2d_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CMS_bio_removed)}
    if i2d_CMS_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_CMS_bio)}
      i2d_CMS_bio := @_i2d_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CMS_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CMS_bio');
    {$ifend}
  end;


  BIO_new_CMS := LoadLibFunction(ADllHandle, BIO_new_CMS_procname);
  FuncLoadError := not assigned(BIO_new_CMS);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_CMS_allownil)}
    BIO_new_CMS := @ERR_BIO_new_CMS;
    {$ifend}
    {$if declared(BIO_new_CMS_introduced)}
    if LibVersion < BIO_new_CMS_introduced then
    begin
      {$if declared(FC_BIO_new_CMS)}
      BIO_new_CMS := @FC_BIO_new_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_CMS_removed)}
    if BIO_new_CMS_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_CMS)}
      BIO_new_CMS := @_BIO_new_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_CMS_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_CMS');
    {$ifend}
  end;


  i2d_CMS_bio_stream := LoadLibFunction(ADllHandle, i2d_CMS_bio_stream_procname);
  FuncLoadError := not assigned(i2d_CMS_bio_stream);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CMS_bio_stream_allownil)}
    i2d_CMS_bio_stream := @ERR_i2d_CMS_bio_stream;
    {$ifend}
    {$if declared(i2d_CMS_bio_stream_introduced)}
    if LibVersion < i2d_CMS_bio_stream_introduced then
    begin
      {$if declared(FC_i2d_CMS_bio_stream)}
      i2d_CMS_bio_stream := @FC_i2d_CMS_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CMS_bio_stream_removed)}
    if i2d_CMS_bio_stream_removed <= LibVersion then
    begin
      {$if declared(_i2d_CMS_bio_stream)}
      i2d_CMS_bio_stream := @_i2d_CMS_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CMS_bio_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CMS_bio_stream');
    {$ifend}
  end;


  PEM_write_bio_CMS_stream := LoadLibFunction(ADllHandle, PEM_write_bio_CMS_stream_procname);
  FuncLoadError := not assigned(PEM_write_bio_CMS_stream);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_CMS_stream_allownil)}
    PEM_write_bio_CMS_stream := @ERR_PEM_write_bio_CMS_stream;
    {$ifend}
    {$if declared(PEM_write_bio_CMS_stream_introduced)}
    if LibVersion < PEM_write_bio_CMS_stream_introduced then
    begin
      {$if declared(FC_PEM_write_bio_CMS_stream)}
      PEM_write_bio_CMS_stream := @FC_PEM_write_bio_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_CMS_stream_removed)}
    if PEM_write_bio_CMS_stream_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_CMS_stream)}
      PEM_write_bio_CMS_stream := @_PEM_write_bio_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_CMS_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_CMS_stream');
    {$ifend}
  end;


  SMIME_read_CMS := LoadLibFunction(ADllHandle, SMIME_read_CMS_procname);
  FuncLoadError := not assigned(SMIME_read_CMS);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_CMS_allownil)}
    SMIME_read_CMS := @ERR_SMIME_read_CMS;
    {$ifend}
    {$if declared(SMIME_read_CMS_introduced)}
    if LibVersion < SMIME_read_CMS_introduced then
    begin
      {$if declared(FC_SMIME_read_CMS)}
      SMIME_read_CMS := @FC_SMIME_read_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_CMS_removed)}
    if SMIME_read_CMS_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_CMS)}
      SMIME_read_CMS := @_SMIME_read_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_CMS_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_CMS');
    {$ifend}
  end;


  SMIME_write_CMS := LoadLibFunction(ADllHandle, SMIME_write_CMS_procname);
  FuncLoadError := not assigned(SMIME_write_CMS);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_write_CMS_allownil)}
    SMIME_write_CMS := @ERR_SMIME_write_CMS;
    {$ifend}
    {$if declared(SMIME_write_CMS_introduced)}
    if LibVersion < SMIME_write_CMS_introduced then
    begin
      {$if declared(FC_SMIME_write_CMS)}
      SMIME_write_CMS := @FC_SMIME_write_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_write_CMS_removed)}
    if SMIME_write_CMS_removed <= LibVersion then
    begin
      {$if declared(_SMIME_write_CMS)}
      SMIME_write_CMS := @_SMIME_write_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_write_CMS_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_write_CMS');
    {$ifend}
  end;


  CMS_final := LoadLibFunction(ADllHandle, CMS_final_procname);
  FuncLoadError := not assigned(CMS_final);
  if FuncLoadError then
  begin
    {$if not defined(CMS_final_allownil)}
    CMS_final := @ERR_CMS_final;
    {$ifend}
    {$if declared(CMS_final_introduced)}
    if LibVersion < CMS_final_introduced then
    begin
      {$if declared(FC_CMS_final)}
      CMS_final := @FC_CMS_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_final_removed)}
    if CMS_final_removed <= LibVersion then
    begin
      {$if declared(_CMS_final)}
      CMS_final := @_CMS_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_final_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_final');
    {$ifend}
  end;


  CMS_data := LoadLibFunction(ADllHandle, CMS_data_procname);
  FuncLoadError := not assigned(CMS_data);
  if FuncLoadError then
  begin
    {$if not defined(CMS_data_allownil)}
    CMS_data := @ERR_CMS_data;
    {$ifend}
    {$if declared(CMS_data_introduced)}
    if LibVersion < CMS_data_introduced then
    begin
      {$if declared(FC_CMS_data)}
      CMS_data := @FC_CMS_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_data_removed)}
    if CMS_data_removed <= LibVersion then
    begin
      {$if declared(_CMS_data)}
      CMS_data := @_CMS_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_data');
    {$ifend}
  end;


  CMS_data_create := LoadLibFunction(ADllHandle, CMS_data_create_procname);
  FuncLoadError := not assigned(CMS_data_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_data_create_allownil)}
    CMS_data_create := @ERR_CMS_data_create;
    {$ifend}
    {$if declared(CMS_data_create_introduced)}
    if LibVersion < CMS_data_create_introduced then
    begin
      {$if declared(FC_CMS_data_create)}
      CMS_data_create := @FC_CMS_data_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_data_create_removed)}
    if CMS_data_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_data_create)}
      CMS_data_create := @_CMS_data_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_data_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_data_create');
    {$ifend}
  end;


  CMS_digest_verify := LoadLibFunction(ADllHandle, CMS_digest_verify_procname);
  FuncLoadError := not assigned(CMS_digest_verify);
  if FuncLoadError then
  begin
    {$if not defined(CMS_digest_verify_allownil)}
    CMS_digest_verify := @ERR_CMS_digest_verify;
    {$ifend}
    {$if declared(CMS_digest_verify_introduced)}
    if LibVersion < CMS_digest_verify_introduced then
    begin
      {$if declared(FC_CMS_digest_verify)}
      CMS_digest_verify := @FC_CMS_digest_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_digest_verify_removed)}
    if CMS_digest_verify_removed <= LibVersion then
    begin
      {$if declared(_CMS_digest_verify)}
      CMS_digest_verify := @_CMS_digest_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_digest_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_digest_verify');
    {$ifend}
  end;


  CMS_digest_create := LoadLibFunction(ADllHandle, CMS_digest_create_procname);
  FuncLoadError := not assigned(CMS_digest_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_digest_create_allownil)}
    CMS_digest_create := @ERR_CMS_digest_create;
    {$ifend}
    {$if declared(CMS_digest_create_introduced)}
    if LibVersion < CMS_digest_create_introduced then
    begin
      {$if declared(FC_CMS_digest_create)}
      CMS_digest_create := @FC_CMS_digest_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_digest_create_removed)}
    if CMS_digest_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_digest_create)}
      CMS_digest_create := @_CMS_digest_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_digest_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_digest_create');
    {$ifend}
  end;


  CMS_EncryptedData_decrypt := LoadLibFunction(ADllHandle, CMS_EncryptedData_decrypt_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_decrypt_allownil)}
    CMS_EncryptedData_decrypt := @ERR_CMS_EncryptedData_decrypt;
    {$ifend}
    {$if declared(CMS_EncryptedData_decrypt_introduced)}
    if LibVersion < CMS_EncryptedData_decrypt_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_decrypt)}
      CMS_EncryptedData_decrypt := @FC_CMS_EncryptedData_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_decrypt_removed)}
    if CMS_EncryptedData_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_decrypt)}
      CMS_EncryptedData_decrypt := @_CMS_EncryptedData_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_decrypt');
    {$ifend}
  end;


  CMS_EncryptedData_encrypt := LoadLibFunction(ADllHandle, CMS_EncryptedData_encrypt_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_encrypt_allownil)}
    CMS_EncryptedData_encrypt := @ERR_CMS_EncryptedData_encrypt;
    {$ifend}
    {$if declared(CMS_EncryptedData_encrypt_introduced)}
    if LibVersion < CMS_EncryptedData_encrypt_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_encrypt)}
      CMS_EncryptedData_encrypt := @FC_CMS_EncryptedData_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_encrypt_removed)}
    if CMS_EncryptedData_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_encrypt)}
      CMS_EncryptedData_encrypt := @_CMS_EncryptedData_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_encrypt');
    {$ifend}
  end;


  CMS_EncryptedData_set1_key := LoadLibFunction(ADllHandle, CMS_EncryptedData_set1_key_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_set1_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_set1_key_allownil)}
    CMS_EncryptedData_set1_key := @ERR_CMS_EncryptedData_set1_key;
    {$ifend}
    {$if declared(CMS_EncryptedData_set1_key_introduced)}
    if LibVersion < CMS_EncryptedData_set1_key_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_set1_key)}
      CMS_EncryptedData_set1_key := @FC_CMS_EncryptedData_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_set1_key_removed)}
    if CMS_EncryptedData_set1_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_set1_key)}
      CMS_EncryptedData_set1_key := @_CMS_EncryptedData_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_set1_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_set1_key');
    {$ifend}
  end;


  CMS_decrypt := LoadLibFunction(ADllHandle, CMS_decrypt_procname);
  FuncLoadError := not assigned(CMS_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_allownil)}
    CMS_decrypt := @ERR_CMS_decrypt;
    {$ifend}
    {$if declared(CMS_decrypt_introduced)}
    if LibVersion < CMS_decrypt_introduced then
    begin
      {$if declared(FC_CMS_decrypt)}
      CMS_decrypt := @FC_CMS_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_removed)}
    if CMS_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt)}
      CMS_decrypt := @_CMS_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt');
    {$ifend}
  end;


  CMS_decrypt_set1_pkey := LoadLibFunction(ADllHandle, CMS_decrypt_set1_pkey_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_pkey_allownil)}
    CMS_decrypt_set1_pkey := @ERR_CMS_decrypt_set1_pkey;
    {$ifend}
    {$if declared(CMS_decrypt_set1_pkey_introduced)}
    if LibVersion < CMS_decrypt_set1_pkey_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_pkey)}
      CMS_decrypt_set1_pkey := @FC_CMS_decrypt_set1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_pkey_removed)}
    if CMS_decrypt_set1_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_pkey)}
      CMS_decrypt_set1_pkey := @_CMS_decrypt_set1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_pkey');
    {$ifend}
  end;


  CMS_decrypt_set1_key := LoadLibFunction(ADllHandle, CMS_decrypt_set1_key_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_key_allownil)}
    CMS_decrypt_set1_key := @ERR_CMS_decrypt_set1_key;
    {$ifend}
    {$if declared(CMS_decrypt_set1_key_introduced)}
    if LibVersion < CMS_decrypt_set1_key_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_key)}
      CMS_decrypt_set1_key := @FC_CMS_decrypt_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_key_removed)}
    if CMS_decrypt_set1_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_key)}
      CMS_decrypt_set1_key := @_CMS_decrypt_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_key');
    {$ifend}
  end;


  CMS_decrypt_set1_password := LoadLibFunction(ADllHandle, CMS_decrypt_set1_password_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_password);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_password_allownil)}
    CMS_decrypt_set1_password := @ERR_CMS_decrypt_set1_password;
    {$ifend}
    {$if declared(CMS_decrypt_set1_password_introduced)}
    if LibVersion < CMS_decrypt_set1_password_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_password)}
      CMS_decrypt_set1_password := @FC_CMS_decrypt_set1_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_password_removed)}
    if CMS_decrypt_set1_password_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_password)}
      CMS_decrypt_set1_password := @_CMS_decrypt_set1_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_password_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_password');
    {$ifend}
  end;


  CMS_RecipientInfo_type := LoadLibFunction(ADllHandle, CMS_RecipientInfo_type_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_type);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_type_allownil)}
    CMS_RecipientInfo_type := @ERR_CMS_RecipientInfo_type;
    {$ifend}
    {$if declared(CMS_RecipientInfo_type_introduced)}
    if LibVersion < CMS_RecipientInfo_type_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_type)}
      CMS_RecipientInfo_type := @FC_CMS_RecipientInfo_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_type_removed)}
    if CMS_RecipientInfo_type_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_type)}
      CMS_RecipientInfo_type := @_CMS_RecipientInfo_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_type_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_type');
    {$ifend}
  end;


  CMS_RecipientInfo_get0_pkey_ctx := LoadLibFunction(ADllHandle, CMS_RecipientInfo_get0_pkey_ctx_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_get0_pkey_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_get0_pkey_ctx_allownil)}
    CMS_RecipientInfo_get0_pkey_ctx := @ERR_CMS_RecipientInfo_get0_pkey_ctx;
    {$ifend}
    {$if declared(CMS_RecipientInfo_get0_pkey_ctx_introduced)}
    if LibVersion < CMS_RecipientInfo_get0_pkey_ctx_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_get0_pkey_ctx)}
      CMS_RecipientInfo_get0_pkey_ctx := @FC_CMS_RecipientInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_get0_pkey_ctx_removed)}
    if CMS_RecipientInfo_get0_pkey_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_get0_pkey_ctx)}
      CMS_RecipientInfo_get0_pkey_ctx := @_CMS_RecipientInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_get0_pkey_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_get0_pkey_ctx');
    {$ifend}
  end;


  CMS_EnvelopedData_create := LoadLibFunction(ADllHandle, CMS_EnvelopedData_create_procname);
  FuncLoadError := not assigned(CMS_EnvelopedData_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EnvelopedData_create_allownil)}
    CMS_EnvelopedData_create := @ERR_CMS_EnvelopedData_create;
    {$ifend}
    {$if declared(CMS_EnvelopedData_create_introduced)}
    if LibVersion < CMS_EnvelopedData_create_introduced then
    begin
      {$if declared(FC_CMS_EnvelopedData_create)}
      CMS_EnvelopedData_create := @FC_CMS_EnvelopedData_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EnvelopedData_create_removed)}
    if CMS_EnvelopedData_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_EnvelopedData_create)}
      CMS_EnvelopedData_create := @_CMS_EnvelopedData_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EnvelopedData_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EnvelopedData_create');
    {$ifend}
  end;


  CMS_add1_recipient_cert := LoadLibFunction(ADllHandle, CMS_add1_recipient_cert_procname);
  FuncLoadError := not assigned(CMS_add1_recipient_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_recipient_cert_allownil)}
    CMS_add1_recipient_cert := @ERR_CMS_add1_recipient_cert;
    {$ifend}
    {$if declared(CMS_add1_recipient_cert_introduced)}
    if LibVersion < CMS_add1_recipient_cert_introduced then
    begin
      {$if declared(FC_CMS_add1_recipient_cert)}
      CMS_add1_recipient_cert := @FC_CMS_add1_recipient_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_recipient_cert_removed)}
    if CMS_add1_recipient_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_recipient_cert)}
      CMS_add1_recipient_cert := @_CMS_add1_recipient_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_recipient_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_recipient_cert');
    {$ifend}
  end;


  CMS_RecipientInfo_set0_pkey := LoadLibFunction(ADllHandle, CMS_RecipientInfo_set0_pkey_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_set0_pkey_allownil)}
    CMS_RecipientInfo_set0_pkey := @ERR_CMS_RecipientInfo_set0_pkey;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_pkey_introduced)}
    if LibVersion < CMS_RecipientInfo_set0_pkey_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_set0_pkey)}
      CMS_RecipientInfo_set0_pkey := @FC_CMS_RecipientInfo_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_pkey_removed)}
    if CMS_RecipientInfo_set0_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_set0_pkey)}
      CMS_RecipientInfo_set0_pkey := @_CMS_RecipientInfo_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_set0_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_set0_pkey');
    {$ifend}
  end;


  CMS_RecipientInfo_ktri_cert_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_ktri_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_ktri_cert_cmp_allownil)}
    CMS_RecipientInfo_ktri_cert_cmp := @ERR_CMS_RecipientInfo_ktri_cert_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_cert_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_ktri_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_ktri_cert_cmp)}
      CMS_RecipientInfo_ktri_cert_cmp := @FC_CMS_RecipientInfo_ktri_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_cert_cmp_removed)}
    if CMS_RecipientInfo_ktri_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_ktri_cert_cmp)}
      CMS_RecipientInfo_ktri_cert_cmp := @_CMS_RecipientInfo_ktri_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_ktri_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_ktri_cert_cmp');
    {$ifend}
  end;


  CMS_RecipientInfo_ktri_get0_algs := LoadLibFunction(ADllHandle, CMS_RecipientInfo_ktri_get0_algs_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_get0_algs);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_ktri_get0_algs_allownil)}
    CMS_RecipientInfo_ktri_get0_algs := @ERR_CMS_RecipientInfo_ktri_get0_algs;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_algs_introduced)}
    if LibVersion < CMS_RecipientInfo_ktri_get0_algs_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_ktri_get0_algs)}
      CMS_RecipientInfo_ktri_get0_algs := @FC_CMS_RecipientInfo_ktri_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_algs_removed)}
    if CMS_RecipientInfo_ktri_get0_algs_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_ktri_get0_algs)}
      CMS_RecipientInfo_ktri_get0_algs := @_CMS_RecipientInfo_ktri_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_ktri_get0_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_ktri_get0_algs');
    {$ifend}
  end;


  CMS_RecipientInfo_ktri_get0_signer_id := LoadLibFunction(ADllHandle, CMS_RecipientInfo_ktri_get0_signer_id_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_get0_signer_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_ktri_get0_signer_id_allownil)}
    CMS_RecipientInfo_ktri_get0_signer_id := @ERR_CMS_RecipientInfo_ktri_get0_signer_id;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_signer_id_introduced)}
    if LibVersion < CMS_RecipientInfo_ktri_get0_signer_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_ktri_get0_signer_id)}
      CMS_RecipientInfo_ktri_get0_signer_id := @FC_CMS_RecipientInfo_ktri_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_signer_id_removed)}
    if CMS_RecipientInfo_ktri_get0_signer_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_ktri_get0_signer_id)}
      CMS_RecipientInfo_ktri_get0_signer_id := @_CMS_RecipientInfo_ktri_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_ktri_get0_signer_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_ktri_get0_signer_id');
    {$ifend}
  end;


  CMS_add0_recipient_key := LoadLibFunction(ADllHandle, CMS_add0_recipient_key_procname);
  FuncLoadError := not assigned(CMS_add0_recipient_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_recipient_key_allownil)}
    CMS_add0_recipient_key := @ERR_CMS_add0_recipient_key;
    {$ifend}
    {$if declared(CMS_add0_recipient_key_introduced)}
    if LibVersion < CMS_add0_recipient_key_introduced then
    begin
      {$if declared(FC_CMS_add0_recipient_key)}
      CMS_add0_recipient_key := @FC_CMS_add0_recipient_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_recipient_key_removed)}
    if CMS_add0_recipient_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_recipient_key)}
      CMS_add0_recipient_key := @_CMS_add0_recipient_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_recipient_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_recipient_key');
    {$ifend}
  end;


  CMS_RecipientInfo_kekri_get0_id := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kekri_get0_id_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kekri_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kekri_get0_id_allownil)}
    CMS_RecipientInfo_kekri_get0_id := @ERR_CMS_RecipientInfo_kekri_get0_id;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_get0_id_introduced)}
    if LibVersion < CMS_RecipientInfo_kekri_get0_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kekri_get0_id)}
      CMS_RecipientInfo_kekri_get0_id := @FC_CMS_RecipientInfo_kekri_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_get0_id_removed)}
    if CMS_RecipientInfo_kekri_get0_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kekri_get0_id)}
      CMS_RecipientInfo_kekri_get0_id := @_CMS_RecipientInfo_kekri_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kekri_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kekri_get0_id');
    {$ifend}
  end;


  CMS_RecipientInfo_set0_key := LoadLibFunction(ADllHandle, CMS_RecipientInfo_set0_key_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_set0_key_allownil)}
    CMS_RecipientInfo_set0_key := @ERR_CMS_RecipientInfo_set0_key;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_key_introduced)}
    if LibVersion < CMS_RecipientInfo_set0_key_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_set0_key)}
      CMS_RecipientInfo_set0_key := @FC_CMS_RecipientInfo_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_key_removed)}
    if CMS_RecipientInfo_set0_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_set0_key)}
      CMS_RecipientInfo_set0_key := @_CMS_RecipientInfo_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_set0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_set0_key');
    {$ifend}
  end;


  CMS_RecipientInfo_kekri_id_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kekri_id_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kekri_id_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kekri_id_cmp_allownil)}
    CMS_RecipientInfo_kekri_id_cmp := @ERR_CMS_RecipientInfo_kekri_id_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_id_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_kekri_id_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kekri_id_cmp)}
      CMS_RecipientInfo_kekri_id_cmp := @FC_CMS_RecipientInfo_kekri_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_id_cmp_removed)}
    if CMS_RecipientInfo_kekri_id_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kekri_id_cmp)}
      CMS_RecipientInfo_kekri_id_cmp := @_CMS_RecipientInfo_kekri_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kekri_id_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kekri_id_cmp');
    {$ifend}
  end;


  CMS_RecipientInfo_set0_password := LoadLibFunction(ADllHandle, CMS_RecipientInfo_set0_password_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_password);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_set0_password_allownil)}
    CMS_RecipientInfo_set0_password := @ERR_CMS_RecipientInfo_set0_password;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_password_introduced)}
    if LibVersion < CMS_RecipientInfo_set0_password_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_set0_password)}
      CMS_RecipientInfo_set0_password := @FC_CMS_RecipientInfo_set0_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_password_removed)}
    if CMS_RecipientInfo_set0_password_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_set0_password)}
      CMS_RecipientInfo_set0_password := @_CMS_RecipientInfo_set0_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_set0_password_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_set0_password');
    {$ifend}
  end;


  CMS_add0_recipient_password := LoadLibFunction(ADllHandle, CMS_add0_recipient_password_procname);
  FuncLoadError := not assigned(CMS_add0_recipient_password);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_recipient_password_allownil)}
    CMS_add0_recipient_password := @ERR_CMS_add0_recipient_password;
    {$ifend}
    {$if declared(CMS_add0_recipient_password_introduced)}
    if LibVersion < CMS_add0_recipient_password_introduced then
    begin
      {$if declared(FC_CMS_add0_recipient_password)}
      CMS_add0_recipient_password := @FC_CMS_add0_recipient_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_recipient_password_removed)}
    if CMS_add0_recipient_password_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_recipient_password)}
      CMS_add0_recipient_password := @_CMS_add0_recipient_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_recipient_password_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_recipient_password');
    {$ifend}
  end;


  CMS_RecipientInfo_decrypt := LoadLibFunction(ADllHandle, CMS_RecipientInfo_decrypt_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_decrypt_allownil)}
    CMS_RecipientInfo_decrypt := @ERR_CMS_RecipientInfo_decrypt;
    {$ifend}
    {$if declared(CMS_RecipientInfo_decrypt_introduced)}
    if LibVersion < CMS_RecipientInfo_decrypt_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_decrypt)}
      CMS_RecipientInfo_decrypt := @FC_CMS_RecipientInfo_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_decrypt_removed)}
    if CMS_RecipientInfo_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_decrypt)}
      CMS_RecipientInfo_decrypt := @_CMS_RecipientInfo_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_decrypt');
    {$ifend}
  end;


  CMS_RecipientInfo_encrypt := LoadLibFunction(ADllHandle, CMS_RecipientInfo_encrypt_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_encrypt_allownil)}
    CMS_RecipientInfo_encrypt := @ERR_CMS_RecipientInfo_encrypt;
    {$ifend}
    {$if declared(CMS_RecipientInfo_encrypt_introduced)}
    if LibVersion < CMS_RecipientInfo_encrypt_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_encrypt)}
      CMS_RecipientInfo_encrypt := @FC_CMS_RecipientInfo_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_encrypt_removed)}
    if CMS_RecipientInfo_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_encrypt)}
      CMS_RecipientInfo_encrypt := @_CMS_RecipientInfo_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_encrypt');
    {$ifend}
  end;


  CMS_uncompress := LoadLibFunction(ADllHandle, CMS_uncompress_procname);
  FuncLoadError := not assigned(CMS_uncompress);
  if FuncLoadError then
  begin
    {$if not defined(CMS_uncompress_allownil)}
    CMS_uncompress := @ERR_CMS_uncompress;
    {$ifend}
    {$if declared(CMS_uncompress_introduced)}
    if LibVersion < CMS_uncompress_introduced then
    begin
      {$if declared(FC_CMS_uncompress)}
      CMS_uncompress := @FC_CMS_uncompress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_uncompress_removed)}
    if CMS_uncompress_removed <= LibVersion then
    begin
      {$if declared(_CMS_uncompress)}
      CMS_uncompress := @_CMS_uncompress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_uncompress_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_uncompress');
    {$ifend}
  end;


  CMS_compress := LoadLibFunction(ADllHandle, CMS_compress_procname);
  FuncLoadError := not assigned(CMS_compress);
  if FuncLoadError then
  begin
    {$if not defined(CMS_compress_allownil)}
    CMS_compress := @ERR_CMS_compress;
    {$ifend}
    {$if declared(CMS_compress_introduced)}
    if LibVersion < CMS_compress_introduced then
    begin
      {$if declared(FC_CMS_compress)}
      CMS_compress := @FC_CMS_compress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_compress_removed)}
    if CMS_compress_removed <= LibVersion then
    begin
      {$if declared(_CMS_compress)}
      CMS_compress := @_CMS_compress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_compress_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_compress');
    {$ifend}
  end;


  CMS_set1_eContentType := LoadLibFunction(ADllHandle, CMS_set1_eContentType_procname);
  FuncLoadError := not assigned(CMS_set1_eContentType);
  if FuncLoadError then
  begin
    {$if not defined(CMS_set1_eContentType_allownil)}
    CMS_set1_eContentType := @ERR_CMS_set1_eContentType;
    {$ifend}
    {$if declared(CMS_set1_eContentType_introduced)}
    if LibVersion < CMS_set1_eContentType_introduced then
    begin
      {$if declared(FC_CMS_set1_eContentType)}
      CMS_set1_eContentType := @FC_CMS_set1_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_set1_eContentType_removed)}
    if CMS_set1_eContentType_removed <= LibVersion then
    begin
      {$if declared(_CMS_set1_eContentType)}
      CMS_set1_eContentType := @_CMS_set1_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_set1_eContentType_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_set1_eContentType');
    {$ifend}
  end;


  CMS_get0_eContentType := LoadLibFunction(ADllHandle, CMS_get0_eContentType_procname);
  FuncLoadError := not assigned(CMS_get0_eContentType);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_eContentType_allownil)}
    CMS_get0_eContentType := @ERR_CMS_get0_eContentType;
    {$ifend}
    {$if declared(CMS_get0_eContentType_introduced)}
    if LibVersion < CMS_get0_eContentType_introduced then
    begin
      {$if declared(FC_CMS_get0_eContentType)}
      CMS_get0_eContentType := @FC_CMS_get0_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_eContentType_removed)}
    if CMS_get0_eContentType_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_eContentType)}
      CMS_get0_eContentType := @_CMS_get0_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_eContentType_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_eContentType');
    {$ifend}
  end;


  CMS_add0_CertificateChoices := LoadLibFunction(ADllHandle, CMS_add0_CertificateChoices_procname);
  FuncLoadError := not assigned(CMS_add0_CertificateChoices);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_CertificateChoices_allownil)}
    CMS_add0_CertificateChoices := @ERR_CMS_add0_CertificateChoices;
    {$ifend}
    {$if declared(CMS_add0_CertificateChoices_introduced)}
    if LibVersion < CMS_add0_CertificateChoices_introduced then
    begin
      {$if declared(FC_CMS_add0_CertificateChoices)}
      CMS_add0_CertificateChoices := @FC_CMS_add0_CertificateChoices;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_CertificateChoices_removed)}
    if CMS_add0_CertificateChoices_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_CertificateChoices)}
      CMS_add0_CertificateChoices := @_CMS_add0_CertificateChoices;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_CertificateChoices_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_CertificateChoices');
    {$ifend}
  end;


  CMS_add0_cert := LoadLibFunction(ADllHandle, CMS_add0_cert_procname);
  FuncLoadError := not assigned(CMS_add0_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_cert_allownil)}
    CMS_add0_cert := @ERR_CMS_add0_cert;
    {$ifend}
    {$if declared(CMS_add0_cert_introduced)}
    if LibVersion < CMS_add0_cert_introduced then
    begin
      {$if declared(FC_CMS_add0_cert)}
      CMS_add0_cert := @FC_CMS_add0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_cert_removed)}
    if CMS_add0_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_cert)}
      CMS_add0_cert := @_CMS_add0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_cert');
    {$ifend}
  end;


  CMS_add1_cert := LoadLibFunction(ADllHandle, CMS_add1_cert_procname);
  FuncLoadError := not assigned(CMS_add1_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_cert_allownil)}
    CMS_add1_cert := @ERR_CMS_add1_cert;
    {$ifend}
    {$if declared(CMS_add1_cert_introduced)}
    if LibVersion < CMS_add1_cert_introduced then
    begin
      {$if declared(FC_CMS_add1_cert)}
      CMS_add1_cert := @FC_CMS_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_cert_removed)}
    if CMS_add1_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_cert)}
      CMS_add1_cert := @_CMS_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_cert');
    {$ifend}
  end;


  CMS_add0_RevocationInfoChoice := LoadLibFunction(ADllHandle, CMS_add0_RevocationInfoChoice_procname);
  FuncLoadError := not assigned(CMS_add0_RevocationInfoChoice);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_RevocationInfoChoice_allownil)}
    CMS_add0_RevocationInfoChoice := @ERR_CMS_add0_RevocationInfoChoice;
    {$ifend}
    {$if declared(CMS_add0_RevocationInfoChoice_introduced)}
    if LibVersion < CMS_add0_RevocationInfoChoice_introduced then
    begin
      {$if declared(FC_CMS_add0_RevocationInfoChoice)}
      CMS_add0_RevocationInfoChoice := @FC_CMS_add0_RevocationInfoChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_RevocationInfoChoice_removed)}
    if CMS_add0_RevocationInfoChoice_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_RevocationInfoChoice)}
      CMS_add0_RevocationInfoChoice := @_CMS_add0_RevocationInfoChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_RevocationInfoChoice_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_RevocationInfoChoice');
    {$ifend}
  end;


  CMS_add0_crl := LoadLibFunction(ADllHandle, CMS_add0_crl_procname);
  FuncLoadError := not assigned(CMS_add0_crl);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_crl_allownil)}
    CMS_add0_crl := @ERR_CMS_add0_crl;
    {$ifend}
    {$if declared(CMS_add0_crl_introduced)}
    if LibVersion < CMS_add0_crl_introduced then
    begin
      {$if declared(FC_CMS_add0_crl)}
      CMS_add0_crl := @FC_CMS_add0_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_crl_removed)}
    if CMS_add0_crl_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_crl)}
      CMS_add0_crl := @_CMS_add0_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_crl');
    {$ifend}
  end;


  CMS_add1_crl := LoadLibFunction(ADllHandle, CMS_add1_crl_procname);
  FuncLoadError := not assigned(CMS_add1_crl);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_crl_allownil)}
    CMS_add1_crl := @ERR_CMS_add1_crl;
    {$ifend}
    {$if declared(CMS_add1_crl_introduced)}
    if LibVersion < CMS_add1_crl_introduced then
    begin
      {$if declared(FC_CMS_add1_crl)}
      CMS_add1_crl := @FC_CMS_add1_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_crl_removed)}
    if CMS_add1_crl_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_crl)}
      CMS_add1_crl := @_CMS_add1_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_crl');
    {$ifend}
  end;


  CMS_SignedData_init := LoadLibFunction(ADllHandle, CMS_SignedData_init_procname);
  FuncLoadError := not assigned(CMS_SignedData_init);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignedData_init_allownil)}
    CMS_SignedData_init := @ERR_CMS_SignedData_init;
    {$ifend}
    {$if declared(CMS_SignedData_init_introduced)}
    if LibVersion < CMS_SignedData_init_introduced then
    begin
      {$if declared(FC_CMS_SignedData_init)}
      CMS_SignedData_init := @FC_CMS_SignedData_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignedData_init_removed)}
    if CMS_SignedData_init_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignedData_init)}
      CMS_SignedData_init := @_CMS_SignedData_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignedData_init_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignedData_init');
    {$ifend}
  end;


  CMS_add1_signer := LoadLibFunction(ADllHandle, CMS_add1_signer_procname);
  FuncLoadError := not assigned(CMS_add1_signer);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_signer_allownil)}
    CMS_add1_signer := @ERR_CMS_add1_signer;
    {$ifend}
    {$if declared(CMS_add1_signer_introduced)}
    if LibVersion < CMS_add1_signer_introduced then
    begin
      {$if declared(FC_CMS_add1_signer)}
      CMS_add1_signer := @FC_CMS_add1_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_signer_removed)}
    if CMS_add1_signer_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_signer)}
      CMS_add1_signer := @_CMS_add1_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_signer');
    {$ifend}
  end;


  CMS_SignerInfo_get0_pkey_ctx := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_pkey_ctx_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_pkey_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_pkey_ctx_allownil)}
    CMS_SignerInfo_get0_pkey_ctx := @ERR_CMS_SignerInfo_get0_pkey_ctx;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_pkey_ctx_introduced)}
    if LibVersion < CMS_SignerInfo_get0_pkey_ctx_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_pkey_ctx)}
      CMS_SignerInfo_get0_pkey_ctx := @FC_CMS_SignerInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_pkey_ctx_removed)}
    if CMS_SignerInfo_get0_pkey_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_pkey_ctx)}
      CMS_SignerInfo_get0_pkey_ctx := @_CMS_SignerInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_pkey_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_pkey_ctx');
    {$ifend}
  end;


  CMS_SignerInfo_get0_md_ctx := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_md_ctx_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_md_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_md_ctx_allownil)}
    CMS_SignerInfo_get0_md_ctx := @ERR_CMS_SignerInfo_get0_md_ctx;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_md_ctx_introduced)}
    if LibVersion < CMS_SignerInfo_get0_md_ctx_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_md_ctx)}
      CMS_SignerInfo_get0_md_ctx := @FC_CMS_SignerInfo_get0_md_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_md_ctx_removed)}
    if CMS_SignerInfo_get0_md_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_md_ctx)}
      CMS_SignerInfo_get0_md_ctx := @_CMS_SignerInfo_get0_md_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_md_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_md_ctx');
    {$ifend}
  end;


  CMS_SignerInfo_set1_signer_cert := LoadLibFunction(ADllHandle, CMS_SignerInfo_set1_signer_cert_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_set1_signer_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_set1_signer_cert_allownil)}
    CMS_SignerInfo_set1_signer_cert := @ERR_CMS_SignerInfo_set1_signer_cert;
    {$ifend}
    {$if declared(CMS_SignerInfo_set1_signer_cert_introduced)}
    if LibVersion < CMS_SignerInfo_set1_signer_cert_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_set1_signer_cert)}
      CMS_SignerInfo_set1_signer_cert := @FC_CMS_SignerInfo_set1_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_set1_signer_cert_removed)}
    if CMS_SignerInfo_set1_signer_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_set1_signer_cert)}
      CMS_SignerInfo_set1_signer_cert := @_CMS_SignerInfo_set1_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_set1_signer_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_set1_signer_cert');
    {$ifend}
  end;


  CMS_SignerInfo_get0_signer_id := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_signer_id_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_signer_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_signer_id_allownil)}
    CMS_SignerInfo_get0_signer_id := @ERR_CMS_SignerInfo_get0_signer_id;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signer_id_introduced)}
    if LibVersion < CMS_SignerInfo_get0_signer_id_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_signer_id)}
      CMS_SignerInfo_get0_signer_id := @FC_CMS_SignerInfo_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signer_id_removed)}
    if CMS_SignerInfo_get0_signer_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_signer_id)}
      CMS_SignerInfo_get0_signer_id := @_CMS_SignerInfo_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_signer_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_signer_id');
    {$ifend}
  end;


  CMS_SignerInfo_cert_cmp := LoadLibFunction(ADllHandle, CMS_SignerInfo_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_cert_cmp_allownil)}
    CMS_SignerInfo_cert_cmp := @ERR_CMS_SignerInfo_cert_cmp;
    {$ifend}
    {$if declared(CMS_SignerInfo_cert_cmp_introduced)}
    if LibVersion < CMS_SignerInfo_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_cert_cmp)}
      CMS_SignerInfo_cert_cmp := @FC_CMS_SignerInfo_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_cert_cmp_removed)}
    if CMS_SignerInfo_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_cert_cmp)}
      CMS_SignerInfo_cert_cmp := @_CMS_SignerInfo_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_cert_cmp');
    {$ifend}
  end;


  CMS_SignerInfo_get0_algs := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_algs_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_algs);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_algs_allownil)}
    CMS_SignerInfo_get0_algs := @ERR_CMS_SignerInfo_get0_algs;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_algs_introduced)}
    if LibVersion < CMS_SignerInfo_get0_algs_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_algs)}
      CMS_SignerInfo_get0_algs := @FC_CMS_SignerInfo_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_algs_removed)}
    if CMS_SignerInfo_get0_algs_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_algs)}
      CMS_SignerInfo_get0_algs := @_CMS_SignerInfo_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_algs');
    {$ifend}
  end;


  CMS_SignerInfo_get0_signature := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_signature_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_signature_allownil)}
    CMS_SignerInfo_get0_signature := @ERR_CMS_SignerInfo_get0_signature;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signature_introduced)}
    if LibVersion < CMS_SignerInfo_get0_signature_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_signature)}
      CMS_SignerInfo_get0_signature := @FC_CMS_SignerInfo_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signature_removed)}
    if CMS_SignerInfo_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_signature)}
      CMS_SignerInfo_get0_signature := @_CMS_SignerInfo_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_signature');
    {$ifend}
  end;


  CMS_SignerInfo_sign := LoadLibFunction(ADllHandle, CMS_SignerInfo_sign_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_sign);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_sign_allownil)}
    CMS_SignerInfo_sign := @ERR_CMS_SignerInfo_sign;
    {$ifend}
    {$if declared(CMS_SignerInfo_sign_introduced)}
    if LibVersion < CMS_SignerInfo_sign_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_sign)}
      CMS_SignerInfo_sign := @FC_CMS_SignerInfo_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_sign_removed)}
    if CMS_SignerInfo_sign_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_sign)}
      CMS_SignerInfo_sign := @_CMS_SignerInfo_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_sign');
    {$ifend}
  end;


  CMS_SignerInfo_verify := LoadLibFunction(ADllHandle, CMS_SignerInfo_verify_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_verify);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_verify_allownil)}
    CMS_SignerInfo_verify := @ERR_CMS_SignerInfo_verify;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_introduced)}
    if LibVersion < CMS_SignerInfo_verify_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_verify)}
      CMS_SignerInfo_verify := @FC_CMS_SignerInfo_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_removed)}
    if CMS_SignerInfo_verify_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_verify)}
      CMS_SignerInfo_verify := @_CMS_SignerInfo_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_verify');
    {$ifend}
  end;


  CMS_SignerInfo_verify_content := LoadLibFunction(ADllHandle, CMS_SignerInfo_verify_content_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_verify_content);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_verify_content_allownil)}
    CMS_SignerInfo_verify_content := @ERR_CMS_SignerInfo_verify_content;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_content_introduced)}
    if LibVersion < CMS_SignerInfo_verify_content_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_verify_content)}
      CMS_SignerInfo_verify_content := @FC_CMS_SignerInfo_verify_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_content_removed)}
    if CMS_SignerInfo_verify_content_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_verify_content)}
      CMS_SignerInfo_verify_content := @_CMS_SignerInfo_verify_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_verify_content_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_verify_content');
    {$ifend}
  end;


  CMS_signed_get_attr_count := LoadLibFunction(ADllHandle, CMS_signed_get_attr_count_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_count_allownil)}
    CMS_signed_get_attr_count := @ERR_CMS_signed_get_attr_count;
    {$ifend}
    {$if declared(CMS_signed_get_attr_count_introduced)}
    if LibVersion < CMS_signed_get_attr_count_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr_count)}
      CMS_signed_get_attr_count := @FC_CMS_signed_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_count_removed)}
    if CMS_signed_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr_count)}
      CMS_signed_get_attr_count := @_CMS_signed_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr_count');
    {$ifend}
  end;


  CMS_signed_get_attr_by_NID := LoadLibFunction(ADllHandle, CMS_signed_get_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_by_NID_allownil)}
    CMS_signed_get_attr_by_NID := @ERR_CMS_signed_get_attr_by_NID;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_NID_introduced)}
    if LibVersion < CMS_signed_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr_by_NID)}
      CMS_signed_get_attr_by_NID := @FC_CMS_signed_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_NID_removed)}
    if CMS_signed_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr_by_NID)}
      CMS_signed_get_attr_by_NID := @_CMS_signed_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr_by_NID');
    {$ifend}
  end;


  CMS_signed_get_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_signed_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_by_OBJ_allownil)}
    CMS_signed_get_attr_by_OBJ := @ERR_CMS_signed_get_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_OBJ_introduced)}
    if LibVersion < CMS_signed_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr_by_OBJ)}
      CMS_signed_get_attr_by_OBJ := @FC_CMS_signed_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_OBJ_removed)}
    if CMS_signed_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr_by_OBJ)}
      CMS_signed_get_attr_by_OBJ := @_CMS_signed_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr_by_OBJ');
    {$ifend}
  end;


  CMS_signed_get_attr := LoadLibFunction(ADllHandle, CMS_signed_get_attr_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_allownil)}
    CMS_signed_get_attr := @ERR_CMS_signed_get_attr;
    {$ifend}
    {$if declared(CMS_signed_get_attr_introduced)}
    if LibVersion < CMS_signed_get_attr_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr)}
      CMS_signed_get_attr := @FC_CMS_signed_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_removed)}
    if CMS_signed_get_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr)}
      CMS_signed_get_attr := @_CMS_signed_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr');
    {$ifend}
  end;


  CMS_signed_delete_attr := LoadLibFunction(ADllHandle, CMS_signed_delete_attr_procname);
  FuncLoadError := not assigned(CMS_signed_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_delete_attr_allownil)}
    CMS_signed_delete_attr := @ERR_CMS_signed_delete_attr;
    {$ifend}
    {$if declared(CMS_signed_delete_attr_introduced)}
    if LibVersion < CMS_signed_delete_attr_introduced then
    begin
      {$if declared(FC_CMS_signed_delete_attr)}
      CMS_signed_delete_attr := @FC_CMS_signed_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_delete_attr_removed)}
    if CMS_signed_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_delete_attr)}
      CMS_signed_delete_attr := @_CMS_signed_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_delete_attr');
    {$ifend}
  end;


  CMS_signed_add1_attr := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_allownil)}
    CMS_signed_add1_attr := @ERR_CMS_signed_add1_attr;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_introduced)}
    if LibVersion < CMS_signed_add1_attr_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr)}
      CMS_signed_add1_attr := @FC_CMS_signed_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_removed)}
    if CMS_signed_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr)}
      CMS_signed_add1_attr := @_CMS_signed_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr');
    {$ifend}
  end;


  CMS_signed_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_by_OBJ_allownil)}
    CMS_signed_add1_attr_by_OBJ := @ERR_CMS_signed_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_OBJ_introduced)}
    if LibVersion < CMS_signed_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr_by_OBJ)}
      CMS_signed_add1_attr_by_OBJ := @FC_CMS_signed_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_OBJ_removed)}
    if CMS_signed_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr_by_OBJ)}
      CMS_signed_add1_attr_by_OBJ := @_CMS_signed_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr_by_OBJ');
    {$ifend}
  end;


  CMS_signed_add1_attr_by_NID := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_by_NID_allownil)}
    CMS_signed_add1_attr_by_NID := @ERR_CMS_signed_add1_attr_by_NID;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_NID_introduced)}
    if LibVersion < CMS_signed_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr_by_NID)}
      CMS_signed_add1_attr_by_NID := @FC_CMS_signed_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_NID_removed)}
    if CMS_signed_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr_by_NID)}
      CMS_signed_add1_attr_by_NID := @_CMS_signed_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr_by_NID');
    {$ifend}
  end;


  CMS_signed_add1_attr_by_txt := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_by_txt_allownil)}
    CMS_signed_add1_attr_by_txt := @ERR_CMS_signed_add1_attr_by_txt;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_txt_introduced)}
    if LibVersion < CMS_signed_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr_by_txt)}
      CMS_signed_add1_attr_by_txt := @FC_CMS_signed_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_txt_removed)}
    if CMS_signed_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr_by_txt)}
      CMS_signed_add1_attr_by_txt := @_CMS_signed_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr_by_txt');
    {$ifend}
  end;


  CMS_signed_get0_data_by_OBJ := LoadLibFunction(ADllHandle, CMS_signed_get0_data_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_signed_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get0_data_by_OBJ_allownil)}
    CMS_signed_get0_data_by_OBJ := @ERR_CMS_signed_get0_data_by_OBJ;
    {$ifend}
    {$if declared(CMS_signed_get0_data_by_OBJ_introduced)}
    if LibVersion < CMS_signed_get0_data_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_signed_get0_data_by_OBJ)}
      CMS_signed_get0_data_by_OBJ := @FC_CMS_signed_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get0_data_by_OBJ_removed)}
    if CMS_signed_get0_data_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get0_data_by_OBJ)}
      CMS_signed_get0_data_by_OBJ := @_CMS_signed_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get0_data_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get0_data_by_OBJ');
    {$ifend}
  end;


  CMS_unsigned_get_attr_count := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_count_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_count_allownil)}
    CMS_unsigned_get_attr_count := @ERR_CMS_unsigned_get_attr_count;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_count_introduced)}
    if LibVersion < CMS_unsigned_get_attr_count_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr_count)}
      CMS_unsigned_get_attr_count := @FC_CMS_unsigned_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_count_removed)}
    if CMS_unsigned_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr_count)}
      CMS_unsigned_get_attr_count := @_CMS_unsigned_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr_count');
    {$ifend}
  end;


  CMS_unsigned_get_attr_by_NID := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_by_NID_allownil)}
    CMS_unsigned_get_attr_by_NID := @ERR_CMS_unsigned_get_attr_by_NID;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_NID_introduced)}
    if LibVersion < CMS_unsigned_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr_by_NID)}
      CMS_unsigned_get_attr_by_NID := @FC_CMS_unsigned_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_NID_removed)}
    if CMS_unsigned_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr_by_NID)}
      CMS_unsigned_get_attr_by_NID := @_CMS_unsigned_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr_by_NID');
    {$ifend}
  end;


  CMS_unsigned_get_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_by_OBJ_allownil)}
    CMS_unsigned_get_attr_by_OBJ := @ERR_CMS_unsigned_get_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_OBJ_introduced)}
    if LibVersion < CMS_unsigned_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr_by_OBJ)}
      CMS_unsigned_get_attr_by_OBJ := @FC_CMS_unsigned_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_OBJ_removed)}
    if CMS_unsigned_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr_by_OBJ)}
      CMS_unsigned_get_attr_by_OBJ := @_CMS_unsigned_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr_by_OBJ');
    {$ifend}
  end;


  CMS_unsigned_get_attr := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_allownil)}
    CMS_unsigned_get_attr := @ERR_CMS_unsigned_get_attr;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_introduced)}
    if LibVersion < CMS_unsigned_get_attr_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr)}
      CMS_unsigned_get_attr := @FC_CMS_unsigned_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_removed)}
    if CMS_unsigned_get_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr)}
      CMS_unsigned_get_attr := @_CMS_unsigned_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr');
    {$ifend}
  end;


  CMS_unsigned_delete_attr := LoadLibFunction(ADllHandle, CMS_unsigned_delete_attr_procname);
  FuncLoadError := not assigned(CMS_unsigned_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_delete_attr_allownil)}
    CMS_unsigned_delete_attr := @ERR_CMS_unsigned_delete_attr;
    {$ifend}
    {$if declared(CMS_unsigned_delete_attr_introduced)}
    if LibVersion < CMS_unsigned_delete_attr_introduced then
    begin
      {$if declared(FC_CMS_unsigned_delete_attr)}
      CMS_unsigned_delete_attr := @FC_CMS_unsigned_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_delete_attr_removed)}
    if CMS_unsigned_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_delete_attr)}
      CMS_unsigned_delete_attr := @_CMS_unsigned_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_delete_attr');
    {$ifend}
  end;


  CMS_unsigned_add1_attr := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_allownil)}
    CMS_unsigned_add1_attr := @ERR_CMS_unsigned_add1_attr;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr)}
      CMS_unsigned_add1_attr := @FC_CMS_unsigned_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_removed)}
    if CMS_unsigned_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr)}
      CMS_unsigned_add1_attr := @_CMS_unsigned_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr');
    {$ifend}
  end;


  CMS_unsigned_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_by_OBJ_allownil)}
    CMS_unsigned_add1_attr_by_OBJ := @ERR_CMS_unsigned_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_OBJ_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr_by_OBJ)}
      CMS_unsigned_add1_attr_by_OBJ := @FC_CMS_unsigned_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_OBJ_removed)}
    if CMS_unsigned_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr_by_OBJ)}
      CMS_unsigned_add1_attr_by_OBJ := @_CMS_unsigned_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr_by_OBJ');
    {$ifend}
  end;


  CMS_unsigned_add1_attr_by_NID := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_by_NID_allownil)}
    CMS_unsigned_add1_attr_by_NID := @ERR_CMS_unsigned_add1_attr_by_NID;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_NID_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr_by_NID)}
      CMS_unsigned_add1_attr_by_NID := @FC_CMS_unsigned_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_NID_removed)}
    if CMS_unsigned_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr_by_NID)}
      CMS_unsigned_add1_attr_by_NID := @_CMS_unsigned_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr_by_NID');
    {$ifend}
  end;


  CMS_unsigned_add1_attr_by_txt := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_by_txt_allownil)}
    CMS_unsigned_add1_attr_by_txt := @ERR_CMS_unsigned_add1_attr_by_txt;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_txt_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr_by_txt)}
      CMS_unsigned_add1_attr_by_txt := @FC_CMS_unsigned_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_txt_removed)}
    if CMS_unsigned_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr_by_txt)}
      CMS_unsigned_add1_attr_by_txt := @_CMS_unsigned_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr_by_txt');
    {$ifend}
  end;


  CMS_unsigned_get0_data_by_OBJ := LoadLibFunction(ADllHandle, CMS_unsigned_get0_data_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_unsigned_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get0_data_by_OBJ_allownil)}
    CMS_unsigned_get0_data_by_OBJ := @ERR_CMS_unsigned_get0_data_by_OBJ;
    {$ifend}
    {$if declared(CMS_unsigned_get0_data_by_OBJ_introduced)}
    if LibVersion < CMS_unsigned_get0_data_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get0_data_by_OBJ)}
      CMS_unsigned_get0_data_by_OBJ := @FC_CMS_unsigned_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get0_data_by_OBJ_removed)}
    if CMS_unsigned_get0_data_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get0_data_by_OBJ)}
      CMS_unsigned_get0_data_by_OBJ := @_CMS_unsigned_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get0_data_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get0_data_by_OBJ');
    {$ifend}
  end;


  CMS_get1_ReceiptRequest := LoadLibFunction(ADllHandle, CMS_get1_ReceiptRequest_procname);
  FuncLoadError := not assigned(CMS_get1_ReceiptRequest);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get1_ReceiptRequest_allownil)}
    CMS_get1_ReceiptRequest := @ERR_CMS_get1_ReceiptRequest;
    {$ifend}
    {$if declared(CMS_get1_ReceiptRequest_introduced)}
    if LibVersion < CMS_get1_ReceiptRequest_introduced then
    begin
      {$if declared(FC_CMS_get1_ReceiptRequest)}
      CMS_get1_ReceiptRequest := @FC_CMS_get1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get1_ReceiptRequest_removed)}
    if CMS_get1_ReceiptRequest_removed <= LibVersion then
    begin
      {$if declared(_CMS_get1_ReceiptRequest)}
      CMS_get1_ReceiptRequest := @_CMS_get1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get1_ReceiptRequest_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get1_ReceiptRequest');
    {$ifend}
  end;


  CMS_add1_ReceiptRequest := LoadLibFunction(ADllHandle, CMS_add1_ReceiptRequest_procname);
  FuncLoadError := not assigned(CMS_add1_ReceiptRequest);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_ReceiptRequest_allownil)}
    CMS_add1_ReceiptRequest := @ERR_CMS_add1_ReceiptRequest;
    {$ifend}
    {$if declared(CMS_add1_ReceiptRequest_introduced)}
    if LibVersion < CMS_add1_ReceiptRequest_introduced then
    begin
      {$if declared(FC_CMS_add1_ReceiptRequest)}
      CMS_add1_ReceiptRequest := @FC_CMS_add1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_ReceiptRequest_removed)}
    if CMS_add1_ReceiptRequest_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_ReceiptRequest)}
      CMS_add1_ReceiptRequest := @_CMS_add1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_ReceiptRequest_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_ReceiptRequest');
    {$ifend}
  end;


  CMS_RecipientInfo_kari_get0_orig_id := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_get0_orig_id_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_orig_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_get0_orig_id_allownil)}
    CMS_RecipientInfo_kari_get0_orig_id := @ERR_CMS_RecipientInfo_kari_get0_orig_id;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_orig_id_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_get0_orig_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_get0_orig_id)}
      CMS_RecipientInfo_kari_get0_orig_id := @FC_CMS_RecipientInfo_kari_get0_orig_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_orig_id_removed)}
    if CMS_RecipientInfo_kari_get0_orig_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_get0_orig_id)}
      CMS_RecipientInfo_kari_get0_orig_id := @_CMS_RecipientInfo_kari_get0_orig_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_get0_orig_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_get0_orig_id');
    {$ifend}
  end;


  CMS_RecipientInfo_kari_orig_id_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_orig_id_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_orig_id_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_orig_id_cmp_allownil)}
    CMS_RecipientInfo_kari_orig_id_cmp := @ERR_CMS_RecipientInfo_kari_orig_id_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_orig_id_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_orig_id_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_orig_id_cmp)}
      CMS_RecipientInfo_kari_orig_id_cmp := @FC_CMS_RecipientInfo_kari_orig_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_orig_id_cmp_removed)}
    if CMS_RecipientInfo_kari_orig_id_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_orig_id_cmp)}
      CMS_RecipientInfo_kari_orig_id_cmp := @_CMS_RecipientInfo_kari_orig_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_orig_id_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_orig_id_cmp');
    {$ifend}
  end;


  CMS_RecipientEncryptedKey_get0_id := LoadLibFunction(ADllHandle, CMS_RecipientEncryptedKey_get0_id_procname);
  FuncLoadError := not assigned(CMS_RecipientEncryptedKey_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientEncryptedKey_get0_id_allownil)}
    CMS_RecipientEncryptedKey_get0_id := @ERR_CMS_RecipientEncryptedKey_get0_id;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_get0_id_introduced)}
    if LibVersion < CMS_RecipientEncryptedKey_get0_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientEncryptedKey_get0_id)}
      CMS_RecipientEncryptedKey_get0_id := @FC_CMS_RecipientEncryptedKey_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_get0_id_removed)}
    if CMS_RecipientEncryptedKey_get0_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientEncryptedKey_get0_id)}
      CMS_RecipientEncryptedKey_get0_id := @_CMS_RecipientEncryptedKey_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientEncryptedKey_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientEncryptedKey_get0_id');
    {$ifend}
  end;


  CMS_RecipientEncryptedKey_cert_cmp := LoadLibFunction(ADllHandle, CMS_RecipientEncryptedKey_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientEncryptedKey_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientEncryptedKey_cert_cmp_allownil)}
    CMS_RecipientEncryptedKey_cert_cmp := @ERR_CMS_RecipientEncryptedKey_cert_cmp;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_cert_cmp_introduced)}
    if LibVersion < CMS_RecipientEncryptedKey_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientEncryptedKey_cert_cmp)}
      CMS_RecipientEncryptedKey_cert_cmp := @FC_CMS_RecipientEncryptedKey_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_cert_cmp_removed)}
    if CMS_RecipientEncryptedKey_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientEncryptedKey_cert_cmp)}
      CMS_RecipientEncryptedKey_cert_cmp := @_CMS_RecipientEncryptedKey_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientEncryptedKey_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientEncryptedKey_cert_cmp');
    {$ifend}
  end;


  CMS_RecipientInfo_kari_set0_pkey := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_set0_pkey_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_set0_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_set0_pkey_allownil)}
    CMS_RecipientInfo_kari_set0_pkey := @ERR_CMS_RecipientInfo_kari_set0_pkey;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_set0_pkey_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_set0_pkey_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_set0_pkey)}
      CMS_RecipientInfo_kari_set0_pkey := @FC_CMS_RecipientInfo_kari_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_set0_pkey_removed)}
    if CMS_RecipientInfo_kari_set0_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_set0_pkey)}
      CMS_RecipientInfo_kari_set0_pkey := @_CMS_RecipientInfo_kari_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_set0_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_set0_pkey');
    {$ifend}
  end;


  CMS_RecipientInfo_kari_get0_ctx := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_get0_ctx_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_get0_ctx_allownil)}
    CMS_RecipientInfo_kari_get0_ctx := @ERR_CMS_RecipientInfo_kari_get0_ctx;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_ctx_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_get0_ctx_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_get0_ctx)}
      CMS_RecipientInfo_kari_get0_ctx := @FC_CMS_RecipientInfo_kari_get0_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_ctx_removed)}
    if CMS_RecipientInfo_kari_get0_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_get0_ctx)}
      CMS_RecipientInfo_kari_get0_ctx := @_CMS_RecipientInfo_kari_get0_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_get0_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_get0_ctx');
    {$ifend}
  end;


  CMS_RecipientInfo_kari_decrypt := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_decrypt_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_decrypt_allownil)}
    CMS_RecipientInfo_kari_decrypt := @ERR_CMS_RecipientInfo_kari_decrypt;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_decrypt_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_decrypt_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_decrypt)}
      CMS_RecipientInfo_kari_decrypt := @FC_CMS_RecipientInfo_kari_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_decrypt_removed)}
    if CMS_RecipientInfo_kari_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_decrypt)}
      CMS_RecipientInfo_kari_decrypt := @_CMS_RecipientInfo_kari_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_decrypt');
    {$ifend}
  end;


  CMS_SharedInfo_encode := LoadLibFunction(ADllHandle, CMS_SharedInfo_encode_procname);
  FuncLoadError := not assigned(CMS_SharedInfo_encode);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SharedInfo_encode_allownil)}
    CMS_SharedInfo_encode := @ERR_CMS_SharedInfo_encode;
    {$ifend}
    {$if declared(CMS_SharedInfo_encode_introduced)}
    if LibVersion < CMS_SharedInfo_encode_introduced then
    begin
      {$if declared(FC_CMS_SharedInfo_encode)}
      CMS_SharedInfo_encode := @FC_CMS_SharedInfo_encode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SharedInfo_encode_removed)}
    if CMS_SharedInfo_encode_removed <= LibVersion then
    begin
      {$if declared(_CMS_SharedInfo_encode)}
      CMS_SharedInfo_encode := @_CMS_SharedInfo_encode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SharedInfo_encode_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SharedInfo_encode');
    {$ifend}
  end;


end;

procedure Unload;
begin
  CMS_get0_type := nil;
  CMS_dataInit := nil;
  CMS_dataFinal := nil;
  CMS_get0_content := nil;
  CMS_is_detached := nil;
  CMS_set_detached := nil;
  CMS_stream := nil;
  d2i_CMS_bio := nil;
  i2d_CMS_bio := nil;
  BIO_new_CMS := nil;
  i2d_CMS_bio_stream := nil;
  PEM_write_bio_CMS_stream := nil;
  SMIME_read_CMS := nil;
  SMIME_write_CMS := nil;
  CMS_final := nil;
  CMS_data := nil;
  CMS_data_create := nil;
  CMS_digest_verify := nil;
  CMS_digest_create := nil;
  CMS_EncryptedData_decrypt := nil;
  CMS_EncryptedData_encrypt := nil;
  CMS_EncryptedData_set1_key := nil;
  CMS_decrypt := nil;
  CMS_decrypt_set1_pkey := nil;
  CMS_decrypt_set1_key := nil;
  CMS_decrypt_set1_password := nil;
  CMS_RecipientInfo_type := nil;
  CMS_RecipientInfo_get0_pkey_ctx := nil;
  CMS_EnvelopedData_create := nil;
  CMS_add1_recipient_cert := nil;
  CMS_RecipientInfo_set0_pkey := nil;
  CMS_RecipientInfo_ktri_cert_cmp := nil;
  CMS_RecipientInfo_ktri_get0_algs := nil;
  CMS_RecipientInfo_ktri_get0_signer_id := nil;
  CMS_add0_recipient_key := nil;
  CMS_RecipientInfo_kekri_get0_id := nil;
  CMS_RecipientInfo_set0_key := nil;
  CMS_RecipientInfo_kekri_id_cmp := nil;
  CMS_RecipientInfo_set0_password := nil;
  CMS_add0_recipient_password := nil;
  CMS_RecipientInfo_decrypt := nil;
  CMS_RecipientInfo_encrypt := nil;
  CMS_uncompress := nil;
  CMS_compress := nil;
  CMS_set1_eContentType := nil;
  CMS_get0_eContentType := nil;
  CMS_add0_CertificateChoices := nil;
  CMS_add0_cert := nil;
  CMS_add1_cert := nil;
  CMS_add0_RevocationInfoChoice := nil;
  CMS_add0_crl := nil;
  CMS_add1_crl := nil;
  CMS_SignedData_init := nil;
  CMS_add1_signer := nil;
  CMS_SignerInfo_get0_pkey_ctx := nil;
  CMS_SignerInfo_get0_md_ctx := nil;
  CMS_SignerInfo_set1_signer_cert := nil;
  CMS_SignerInfo_get0_signer_id := nil;
  CMS_SignerInfo_cert_cmp := nil;
  CMS_SignerInfo_get0_algs := nil;
  CMS_SignerInfo_get0_signature := nil;
  CMS_SignerInfo_sign := nil;
  CMS_SignerInfo_verify := nil;
  CMS_SignerInfo_verify_content := nil;
  CMS_signed_get_attr_count := nil;
  CMS_signed_get_attr_by_NID := nil;
  CMS_signed_get_attr_by_OBJ := nil;
  CMS_signed_get_attr := nil;
  CMS_signed_delete_attr := nil;
  CMS_signed_add1_attr := nil;
  CMS_signed_add1_attr_by_OBJ := nil;
  CMS_signed_add1_attr_by_NID := nil;
  CMS_signed_add1_attr_by_txt := nil;
  CMS_signed_get0_data_by_OBJ := nil;
  CMS_unsigned_get_attr_count := nil;
  CMS_unsigned_get_attr_by_NID := nil;
  CMS_unsigned_get_attr_by_OBJ := nil;
  CMS_unsigned_get_attr := nil;
  CMS_unsigned_delete_attr := nil;
  CMS_unsigned_add1_attr := nil;
  CMS_unsigned_add1_attr_by_OBJ := nil;
  CMS_unsigned_add1_attr_by_NID := nil;
  CMS_unsigned_add1_attr_by_txt := nil;
  CMS_unsigned_get0_data_by_OBJ := nil;
  CMS_get1_ReceiptRequest := nil;
  CMS_add1_ReceiptRequest := nil;
  CMS_RecipientInfo_kari_get0_orig_id := nil;
  CMS_RecipientInfo_kari_orig_id_cmp := nil;
  CMS_RecipientEncryptedKey_get0_id := nil;
  CMS_RecipientEncryptedKey_cert_cmp := nil;
  CMS_RecipientInfo_kari_set0_pkey := nil;
  CMS_RecipientInfo_kari_get0_ctx := nil;
  CMS_RecipientInfo_kari_decrypt := nil;
  CMS_SharedInfo_encode := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
