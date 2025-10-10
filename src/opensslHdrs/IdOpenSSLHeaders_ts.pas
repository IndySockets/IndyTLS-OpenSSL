(* This unit was generated from the source file ts.h2pas 
It should not be modified directly. All changes should be made to ts.h2pas
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


unit IdOpenSSLHeaders_ts;


interface

// Headers for OpenSSL 1.1.1
// ts.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_asn1,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_pkcs7,
  IdOpenSSLHeaders_rsa,
  IdOpenSSLHeaders_tserr,
  IdOpenSSLHeaders_x509,
  IdOpenSSLHeaders_x509v3;

const
  (* Possible values for status. *)
  TS_STATUS_GRANTED = 0;
  TS_STATUS_GRANTED_WITH_MODS = 1;
  TS_STATUS_REJECTION = 2;
  TS_STATUS_WAITING = 3;
  TS_STATUS_REVOCATION_WARNING = 4;
  TS_STATUS_REVOCATION_NOTIFICATION = 5;


  (* Possible values for failure_info. *)
  TS_INFO_BAD_ALG = 0;
  TS_INFO_BAD_REQUEST = 2;
  TS_INFO_BAD_DATA_FORMAT = 5;
  TS_INFO_TIME_NOT_AVAILABLE = 14;
  TS_INFO_UNACCEPTED_POLICY = 15;
  TS_INFO_UNACCEPTED_EXTENSION = 16;
  TS_INFO_ADD_INFO_NOT_AVAILABLE = 17;
  TS_INFO_SYSTEM_FAILURE = 25;

  (* Optional flags for response generation. *)

  (* Don't include the TSA name in response. *)
  TS_TSA_NAME = $01;

  (* Set ordering to true in response. *)
  TS_ORDERING = $02;

  (*
   * Include the signer certificate and the other specified certificates in
   * the ESS signing certificate attribute beside the PKCS7 signed data.
   * Only the signer certificates is included by default.
   *)
  TS_ESS_CERT_ID_CHAIN = $04;

  (* At most we accept usec precision. *)
  TS_MAX_CLOCK_PRECISION_DIGITS = 6;

  (* Maximum status message length *)
  TS_MAX_STATUS_LENGTH = 1024 * 1024;

  (* Verify the signer's certificate and the signature of the response. *)
  TS_VFY_SIGNATURE = TOpenSSL_C_UINT(1) shl 0;
  (* Verify the version number of the response. *)
  TS_VFY_VERSION = TOpenSSL_C_UINT(1) shl 1;
  (* Verify if the policy supplied by the user matches the policy of the TSA. *)
  TS_VFY_POLICY = TOpenSSL_C_UINT(1) shl 2;
  (*
   * Verify the message imprint provided by the user. This flag should not be
   * specified with TS_VFY_DATA.
   *)
  TS_VFY_IMPRINT = TOpenSSL_C_UINT(1) shl 3;
  (*
   * Verify the message imprint computed by the verify method from the user
   * provided data and the MD algorithm of the response. This flag should not
   * be specified with TS_VFY_IMPRINT.
   *)
  TS_VFY_DATA = TOpenSSL_C_UINT(1) shl 4;
  (* Verify the nonce value. *)
  TS_VFY_NONCE = TOpenSSL_C_UINT(1) shl 5;
  (* Verify if the TSA name field matches the signer certificate. *)
  TS_VFY_SIGNER = TOpenSSL_C_UINT(1) shl 6;
  (* Verify if the TSA name field equals to the user provided name. *)
  TS_VFY_TSA_NAME = TOpenSSL_C_UINT(1) shl 7;

  (* You can use the following convenience constants. *)
  TS_VFY_ALL_IMPRINT = TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY
    or TS_VFY_IMPRINT or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME;

  TS_VFY_ALL_DATA = TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY
    or TS_VFY_DATA or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME;

type
  TS_msg_imprint_st = type Pointer;
  TS_req_st = type Pointer;
  TS_accuracy_st = type Pointer;
  TS_tst_info_st = type Pointer;

  TS_MSG_IMPRINT = TS_msg_imprint_st;
  PTS_MSG_IMPRINT = ^TS_MSG_IMPRINT;
  PPTS_MSG_IMPRINT = ^PTS_MSG_IMPRINT;

  TS_REQ = TS_req_st;
  PTS_REQ = ^TS_REQ;
  PPTS_REQ = ^PTS_REQ;

  TS_ACCURACY = TS_accuracy_st;
  PTS_ACCURACY = ^TS_ACCURACY;
  PPTS_ACCURACY = ^PTS_ACCURACY;

  TS_TST_INFO = TS_tst_info_st;
  PTS_TST_INFO = ^TS_TST_INFO;
  PPTS_TST_INFO = ^PTS_TST_INFO;

  TS_status_info_st = type Pointer;
  ESS_issuer_serial_st = type Pointer;
  ESS_cert_id_st = type Pointer;
  ESS_signing_cert_st = type Pointer;
  ESS_cert_id_v2_st = type Pointer;
  ESS_signing_cert_v2_st = type Pointer;

  TS_STATUS_INFO = TS_status_info_st;
  PTS_STATUS_INFO = ^TS_STATUS_INFO;
  PPTS_STATUS_INFO = ^PTS_STATUS_INFO;

  ESS_ISSUER_SERIAL = ESS_issuer_serial_st;
  PESS_ISSUER_SERIAL = ^ESS_ISSUER_SERIAL;
  PPESS_ISSUER_SERIAL = ^PESS_ISSUER_SERIAL;

  ESS_CERT_ID = ESS_cert_id_st;
  PESS_CERT_ID = ^ESS_CERT_ID;
  PPESS_CERT_ID = ^PESS_CERT_ID;

  ESS_SIGNING_CERT = ESS_signing_cert_st;
  PESS_SIGNING_CERT = ^ESS_SIGNING_CERT;
  PPESS_SIGNING_CERT = ^PESS_SIGNING_CERT;

// DEFINE_STACK_OF(ESS_CERT_ID)

  ESS_CERT_ID_V2 = ESS_cert_id_v2_st;
  PESS_CERT_ID_V2 = ^ESS_CERT_ID_V2;
  PPESS_CERT_ID_V2 = ^PESS_CERT_ID_V2;

  ESS_SIGNING_CERT_V2 = ESS_signing_cert_v2_st;
  PESS_SIGNING_CERT_V2 = ^ESS_SIGNING_CERT_V2;
  PPESS_SIGNING_CERT_V2 = ^PESS_SIGNING_CERT_V2;

// DEFINE_STACK_OF(ESS_CERT_ID_V2)
  TS_resp_st = type Pointer;
  TS_RESP = TS_resp_st;
  PTS_RESP = ^TS_RESP;
  PPTS_RESP = ^PTS_RESP;

  (* Forward declaration. *)
  TS_resp_ctx = type Pointer;
  PTS_resp_ctx = ^TS_resp_ctx;
  PPTS_resp_ctx = ^PTS_resp_ctx;

  (* This must return a unique number less than 160 bits long. *)
  TS_serial_cb = function({struct} v1: PTS_resp_ctx; v2: Pointer): PASN1_INTEGER;

  (*
   * This must return the seconds and microseconds since Jan 1, 1970 in the sec
   * and usec variables allocated by the caller. Return non-zero for success
   * and zero for failure.
   *)
  TS_time_cb = function({struct} v1: PTS_resp_ctx; v2: Pointer; sec: POpenSSL_C_LONG; usec: POpenSSL_C_LONG): TOpenSSL_C_INT;

  (*
   * This must process the given extension. It can modify the TS_TST_INFO
   * object of the context. Return values: !0 (processed), 0 (error, it must
   * set the status info/failure info of the response).
   *)
  TS_extension_cb = function({struct} v1: PTS_resp_ctx; v2: PX509_Extension; v3: Pointer): TOpenSSL_C_INT;

//  TS_VERIFY_CTX = TS_verify_ctx;
  TS_VERIFY_CTX = type Pointer;
  PTS_VERIFY_CTX = ^TS_VERIFY_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM TS_REQ_new}
{$EXTERNALSYM TS_REQ_free}
{$EXTERNALSYM i2d_TS_REQ}
{$EXTERNALSYM d2i_TS_REQ}
{$EXTERNALSYM TS_REQ_dup}
{$EXTERNALSYM d2i_TS_REQ_bio}
{$EXTERNALSYM i2d_TS_REQ_bio}
{$EXTERNALSYM TS_MSG_IMPRINT_new}
{$EXTERNALSYM TS_MSG_IMPRINT_free}
{$EXTERNALSYM i2d_TS_MSG_IMPRINT}
{$EXTERNALSYM d2i_TS_MSG_IMPRINT}
{$EXTERNALSYM TS_MSG_IMPRINT_dup}
{$EXTERNALSYM d2i_TS_MSG_IMPRINT_bio}
{$EXTERNALSYM i2d_TS_MSG_IMPRINT_bio}
{$EXTERNALSYM TS_RESP_new}
{$EXTERNALSYM TS_RESP_free}
{$EXTERNALSYM i2d_TS_RESP}
{$EXTERNALSYM d2i_TS_RESP}
{$EXTERNALSYM PKCS7_to_TS_TST_INFO}
{$EXTERNALSYM TS_RESP_dup}
{$EXTERNALSYM d2i_TS_RESP_bio}
{$EXTERNALSYM i2d_TS_RESP_bio}
{$EXTERNALSYM TS_STATUS_INFO_new}
{$EXTERNALSYM TS_STATUS_INFO_free}
{$EXTERNALSYM i2d_TS_STATUS_INFO}
{$EXTERNALSYM d2i_TS_STATUS_INFO}
{$EXTERNALSYM TS_STATUS_INFO_dup}
{$EXTERNALSYM TS_TST_INFO_new}
{$EXTERNALSYM TS_TST_INFO_free}
{$EXTERNALSYM i2d_TS_TST_INFO}
{$EXTERNALSYM d2i_TS_TST_INFO}
{$EXTERNALSYM TS_TST_INFO_dup}
{$EXTERNALSYM d2i_TS_TST_INFO_bio}
{$EXTERNALSYM i2d_TS_TST_INFO_bio}
{$EXTERNALSYM TS_ACCURACY_new}
{$EXTERNALSYM TS_ACCURACY_free}
{$EXTERNALSYM i2d_TS_ACCURACY}
{$EXTERNALSYM d2i_TS_ACCURACY}
{$EXTERNALSYM TS_ACCURACY_dup}
{$EXTERNALSYM ESS_ISSUER_SERIAL_new}
{$EXTERNALSYM ESS_ISSUER_SERIAL_free}
{$EXTERNALSYM i2d_ESS_ISSUER_SERIAL}
{$EXTERNALSYM d2i_ESS_ISSUER_SERIAL}
{$EXTERNALSYM ESS_ISSUER_SERIAL_dup}
{$EXTERNALSYM ESS_CERT_ID_new}
{$EXTERNALSYM ESS_CERT_ID_free}
{$EXTERNALSYM i2d_ESS_CERT_ID}
{$EXTERNALSYM d2i_ESS_CERT_ID}
{$EXTERNALSYM ESS_CERT_ID_dup}
{$EXTERNALSYM ESS_SIGNING_CERT_new}
{$EXTERNALSYM ESS_SIGNING_CERT_free}
{$EXTERNALSYM i2d_ESS_SIGNING_CERT}
{$EXTERNALSYM d2i_ESS_SIGNING_CERT}
{$EXTERNALSYM ESS_SIGNING_CERT_dup}
{$EXTERNALSYM ESS_CERT_ID_V2_new}
{$EXTERNALSYM ESS_CERT_ID_V2_free}
{$EXTERNALSYM i2d_ESS_CERT_ID_V2}
{$EXTERNALSYM d2i_ESS_CERT_ID_V2}
{$EXTERNALSYM ESS_CERT_ID_V2_dup}
{$EXTERNALSYM ESS_SIGNING_CERT_V2_new}
{$EXTERNALSYM ESS_SIGNING_CERT_V2_free}
{$EXTERNALSYM i2d_ESS_SIGNING_CERT_V2}
{$EXTERNALSYM d2i_ESS_SIGNING_CERT_V2}
{$EXTERNALSYM ESS_SIGNING_CERT_V2_dup}
{$EXTERNALSYM TS_REQ_set_version}
{$EXTERNALSYM TS_REQ_get_version}
{$EXTERNALSYM TS_STATUS_INFO_set_status}
{$EXTERNALSYM TS_STATUS_INFO_get0_status}
{$EXTERNALSYM TS_REQ_set_msg_imprint}
{$EXTERNALSYM TS_REQ_get_msg_imprint}
{$EXTERNALSYM TS_MSG_IMPRINT_set_algo}
{$EXTERNALSYM TS_MSG_IMPRINT_get_algo}
{$EXTERNALSYM TS_MSG_IMPRINT_set_msg}
{$EXTERNALSYM TS_MSG_IMPRINT_get_msg}
{$EXTERNALSYM TS_REQ_set_policy_id}
{$EXTERNALSYM TS_REQ_get_policy_id}
{$EXTERNALSYM TS_REQ_set_nonce}
{$EXTERNALSYM TS_REQ_get_nonce}
{$EXTERNALSYM TS_REQ_set_cert_req}
{$EXTERNALSYM TS_REQ_get_cert_req}
{$EXTERNALSYM TS_REQ_ext_free}
{$EXTERNALSYM TS_REQ_get_ext_count}
{$EXTERNALSYM TS_REQ_get_ext_by_NID}
{$EXTERNALSYM TS_REQ_get_ext_by_OBJ}
{$EXTERNALSYM TS_REQ_get_ext_by_critical}
{$EXTERNALSYM TS_REQ_get_ext}
{$EXTERNALSYM TS_REQ_delete_ext}
{$EXTERNALSYM TS_REQ_add_ext}
{$EXTERNALSYM TS_REQ_get_ext_d2i}
{$EXTERNALSYM TS_REQ_print_bio}
{$EXTERNALSYM TS_RESP_set_status_info}
{$EXTERNALSYM TS_RESP_get_status_info}
{$EXTERNALSYM TS_RESP_set_tst_info}
{$EXTERNALSYM TS_RESP_get_token}
{$EXTERNALSYM TS_RESP_get_tst_info}
{$EXTERNALSYM TS_TST_INFO_set_version}
{$EXTERNALSYM TS_TST_INFO_get_version}
{$EXTERNALSYM TS_TST_INFO_set_policy_id}
{$EXTERNALSYM TS_TST_INFO_get_policy_id}
{$EXTERNALSYM TS_TST_INFO_set_msg_imprint}
{$EXTERNALSYM TS_TST_INFO_get_msg_imprint}
{$EXTERNALSYM TS_TST_INFO_set_serial}
{$EXTERNALSYM TS_TST_INFO_get_serial}
{$EXTERNALSYM TS_TST_INFO_set_time}
{$EXTERNALSYM TS_TST_INFO_get_time}
{$EXTERNALSYM TS_TST_INFO_set_accuracy}
{$EXTERNALSYM TS_TST_INFO_get_accuracy}
{$EXTERNALSYM TS_ACCURACY_set_seconds}
{$EXTERNALSYM TS_ACCURACY_get_seconds}
{$EXTERNALSYM TS_ACCURACY_set_millis}
{$EXTERNALSYM TS_ACCURACY_get_millis}
{$EXTERNALSYM TS_ACCURACY_set_micros}
{$EXTERNALSYM TS_ACCURACY_get_micros}
{$EXTERNALSYM TS_TST_INFO_set_ordering}
{$EXTERNALSYM TS_TST_INFO_get_ordering}
{$EXTERNALSYM TS_TST_INFO_set_nonce}
{$EXTERNALSYM TS_TST_INFO_get_nonce}
{$EXTERNALSYM TS_TST_INFO_set_tsa}
{$EXTERNALSYM TS_TST_INFO_get_tsa}
{$EXTERNALSYM TS_TST_INFO_ext_free}
{$EXTERNALSYM TS_TST_INFO_get_ext_count}
{$EXTERNALSYM TS_TST_INFO_get_ext_by_NID}
{$EXTERNALSYM TS_TST_INFO_get_ext_by_OBJ}
{$EXTERNALSYM TS_TST_INFO_get_ext_by_critical}
{$EXTERNALSYM TS_TST_INFO_get_ext}
{$EXTERNALSYM TS_TST_INFO_delete_ext}
{$EXTERNALSYM TS_TST_INFO_add_ext}
{$EXTERNALSYM TS_TST_INFO_get_ext_d2i}
{$EXTERNALSYM TS_RESP_CTX_new}
{$EXTERNALSYM TS_RESP_CTX_free}
{$EXTERNALSYM TS_RESP_CTX_set_signer_cert}
{$EXTERNALSYM TS_RESP_CTX_set_signer_key}
{$EXTERNALSYM TS_RESP_CTX_set_signer_digest}
{$EXTERNALSYM TS_RESP_CTX_set_ess_cert_id_digest}
{$EXTERNALSYM TS_RESP_CTX_set_def_policy}
{$EXTERNALSYM TS_RESP_CTX_add_policy}
{$EXTERNALSYM TS_RESP_CTX_add_md}
{$EXTERNALSYM TS_RESP_CTX_set_accuracy}
{$EXTERNALSYM TS_RESP_CTX_set_clock_precision_digits}
{$EXTERNALSYM TS_RESP_CTX_add_flags}
{$EXTERNALSYM TS_RESP_CTX_set_serial_cb}
{$EXTERNALSYM TS_RESP_CTX_set_time_cb}
{$EXTERNALSYM TS_RESP_CTX_set_extension_cb}
{$EXTERNALSYM TS_RESP_CTX_set_status_info}
{$EXTERNALSYM TS_RESP_CTX_set_status_info_cond}
{$EXTERNALSYM TS_RESP_CTX_add_failure_info}
{$EXTERNALSYM TS_RESP_CTX_get_request}
{$EXTERNALSYM TS_RESP_CTX_get_tst_info}
{$EXTERNALSYM TS_RESP_create_response}
{$EXTERNALSYM TS_RESP_verify_response}
{$EXTERNALSYM TS_RESP_verify_token}
{$EXTERNALSYM TS_VERIFY_CTX_new}
{$EXTERNALSYM TS_VERIFY_CTX_init}
{$EXTERNALSYM TS_VERIFY_CTX_free}
{$EXTERNALSYM TS_VERIFY_CTX_cleanup}
{$EXTERNALSYM TS_VERIFY_CTX_set_flags}
{$EXTERNALSYM TS_VERIFY_CTX_add_flags}
{$EXTERNALSYM TS_VERIFY_CTX_set_data}
{$EXTERNALSYM TS_VERIFY_CTX_set_imprint}
{$EXTERNALSYM TS_VERIFY_CTX_set_store}
{$EXTERNALSYM TS_REQ_to_TS_VERIFY_CTX}
{$EXTERNALSYM TS_RESP_print_bio}
{$EXTERNALSYM TS_STATUS_INFO_print_bio}
{$EXTERNALSYM TS_TST_INFO_print_bio}
{$EXTERNALSYM TS_ASN1_INTEGER_print_bio}
{$EXTERNALSYM TS_OBJ_print_bio}
{$EXTERNALSYM TS_X509_ALGOR_print_bio}
{$EXTERNALSYM TS_MSG_IMPRINT_print_bio}
{$EXTERNALSYM TS_CONF_load_cert}
{$EXTERNALSYM TS_CONF_load_key}
{$EXTERNALSYM TS_CONF_set_serial}
{$EXTERNALSYM TS_CONF_get_tsa_section}
{$EXTERNALSYM TS_CONF_set_crypto_device}
{$EXTERNALSYM TS_CONF_set_default_engine}
{$EXTERNALSYM TS_CONF_set_signer_cert}
{$EXTERNALSYM TS_CONF_set_certs}
{$EXTERNALSYM TS_CONF_set_signer_key}
{$EXTERNALSYM TS_CONF_set_signer_digest}
{$EXTERNALSYM TS_CONF_set_def_policy}
{$EXTERNALSYM TS_CONF_set_policies}
{$EXTERNALSYM TS_CONF_set_digests}
{$EXTERNALSYM TS_CONF_set_accuracy}
{$EXTERNALSYM TS_CONF_set_clock_precision_digits}
{$EXTERNALSYM TS_CONF_set_ordering}
{$EXTERNALSYM TS_CONF_set_tsa_name}
{$EXTERNALSYM TS_CONF_set_ess_cert_id_chain}
{$EXTERNALSYM TS_CONF_set_ess_cert_id_digest}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function TS_REQ_new: PTS_REQ; cdecl; external CLibCrypto;
procedure TS_REQ_free(a: PTS_REQ); cdecl; external CLibCrypto;
function i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl; external CLibCrypto;
function TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl; external CLibCrypto;
function d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl; external CLibCrypto;
function i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
procedure TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl; external CLibCrypto;
function i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_new: PTS_RESP; cdecl; external CLibCrypto;
procedure TS_RESP_free(a: PTS_RESP); cdecl; external CLibCrypto;
function i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl; external CLibCrypto;
function PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl; external CLibCrypto;
function d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl; external CLibCrypto;
function i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl; external CLibCrypto;
procedure TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl; external CLibCrypto;
function i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl; external CLibCrypto;
function TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl; external CLibCrypto;
function TS_TST_INFO_new: PTS_TST_Info; cdecl; external CLibCrypto;
procedure TS_TST_INFO_free(a: PTS_TST_Info); cdecl; external CLibCrypto;
function i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info; cdecl; external CLibCrypto;
function d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl; external CLibCrypto;
function i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_new: PTS_ACCURACY; cdecl; external CLibCrypto;
procedure TS_ACCURACY_free(a: PTS_ACCURACY); cdecl; external CLibCrypto;
function i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl; external CLibCrypto;
function TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl; external CLibCrypto;
function ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl; external CLibCrypto;
procedure ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl; external CLibCrypto;
function i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl; external CLibCrypto;
function ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl; external CLibCrypto;
function ESS_CERT_ID_new: PESS_CERT_ID; cdecl; external CLibCrypto;
procedure ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl; external CLibCrypto;
function i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl; external CLibCrypto;
function ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_new: PESS_SIGNING_Cert; cdecl; external CLibCrypto;
procedure ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert); cdecl; external CLibCrypto;
function i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl; external CLibCrypto;
function ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl; external CLibCrypto;
procedure ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl; external CLibCrypto;
function i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl; external CLibCrypto;
function ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl; external CLibCrypto;
procedure ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl; external CLibCrypto;
function i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl; external CLibCrypto;
function TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl; external CLibCrypto;
function TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure TS_REQ_ext_free(a: PTS_REQ); cdecl; external CLibCrypto;
function TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl; external CLibCrypto;
procedure TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl; external CLibCrypto;
function TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl; external CLibCrypto;
function TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_TST_INFO_set_version(a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_version(const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object; cdecl; external CLibCrypto;
function TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY; cdecl; external CLibCrypto;
function TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME; cdecl; external CLibCrypto;
procedure TS_TST_INFO_ext_free(a: PTS_TST_Info); cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function TS_RESP_CTX_new: PTS_RESP_CTX; cdecl; external CLibCrypto;
procedure TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl; external CLibCrypto;
function TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl; external CLibCrypto;
procedure TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl; external CLibCrypto;
procedure TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl; external CLibCrypto;
function TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl; external CLibCrypto;
function TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl; external CLibCrypto;
function TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl; external CLibCrypto;
procedure TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto;
procedure TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto;
procedure TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl; external CLibCrypto;
function TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl; external CLibCrypto;
function TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl; external CLibCrypto;
function TS_CONF_load_key( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl; external CLibCrypto;
function TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_get_tsa_section(conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_signer_key(conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_TS_REQ_new: PTS_REQ; cdecl;
procedure Load_TS_REQ_free(a: PTS_REQ); cdecl;
function Load_i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl;
function Load_TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl;
function Load_d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl;
function Load_i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
function Load_TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl;
procedure Load_TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl;
function Load_i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl;
function Load_TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
function Load_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
function Load_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_new: PTS_RESP; cdecl;
procedure Load_TS_RESP_free(a: PTS_RESP); cdecl;
function Load_i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl;
function Load_PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info; cdecl;
function Load_TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl;
function Load_d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl;
function Load_i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
function Load_TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl;
procedure Load_TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl;
function Load_i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl;
function Load_TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl;
function Load_TS_TST_INFO_new: PTS_TST_Info; cdecl;
procedure Load_TS_TST_INFO_free(a: PTS_TST_Info); cdecl;
function Load_i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl;
function Load_TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info; cdecl;
function Load_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl;
function Load_i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
function Load_TS_ACCURACY_new: PTS_ACCURACY; cdecl;
procedure Load_TS_ACCURACY_free(a: PTS_ACCURACY); cdecl;
function Load_i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl;
function Load_TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl;
function Load_ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl;
procedure Load_ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl;
function Load_i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl;
function Load_ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl;
function Load_ESS_CERT_ID_new: PESS_CERT_ID; cdecl;
procedure Load_ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl;
function Load_i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl;
function Load_ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl;
function Load_ESS_SIGNING_CERT_new: PESS_SIGNING_Cert; cdecl;
procedure Load_ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert); cdecl;
function Load_i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl;
function Load_ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl;
function Load_ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl;
procedure Load_ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl;
function Load_i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl;
function Load_ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl;
function Load_ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl;
procedure Load_ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl;
function Load_i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl;
function Load_d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl;
function Load_ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl;
function Load_TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_LONG; cdecl;
function Load_TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl;
function Load_TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl;
function Load_TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl;
function Load_TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl;
function Load_TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl;
function Load_TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl;
function Load_TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER; cdecl;
function Load_TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
procedure Load_TS_REQ_ext_free(a: PTS_REQ); cdecl;
function Load_TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
function Load_TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
function Load_TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
function Load_TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl;
procedure Load_TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl;
function Load_TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl;
function Load_TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info; cdecl;
function Load_TS_TST_INFO_set_version(a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_version(const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl;
function Load_TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object; cdecl;
function Load_TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl;
function Load_TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
function Load_TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl;
function Load_TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY; cdecl;
function Load_TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
function Load_TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
function Load_TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
function Load_TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
function Load_TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME; cdecl;
procedure Load_TS_TST_INFO_ext_free(a: PTS_TST_Info); cdecl;
function Load_TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
function Load_TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
function Load_TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
function Load_TS_RESP_CTX_new: PTS_RESP_CTX; cdecl;
procedure Load_TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl;
function Load_TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
procedure Load_TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl;
procedure Load_TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl;
procedure Load_TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl;
procedure Load_TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl;
function Load_TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl;
function Load_TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl;
function Load_TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl;
function Load_TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl;
function Load_TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl;
function Load_TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl;
procedure Load_TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl;
procedure Load_TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl;
procedure Load_TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl;
function Load_TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl;
function Load_TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl;
function Load_TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl;
function Load_TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl;
function Load_TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
function Load_TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
function Load_TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
function Load_TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
function Load_TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl;
function Load_TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl;
function Load_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl;
function Load_TS_CONF_load_key( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl;
function Load_TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_get_tsa_section(conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl;
function Load_TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_signer_key(conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
function Load_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;

var
  TS_REQ_new: function : PTS_REQ; cdecl = Load_TS_REQ_new;
  TS_REQ_free: procedure (a: PTS_REQ); cdecl = Load_TS_REQ_free;
  i2d_TS_REQ: function (a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_REQ;
  d2i_TS_REQ: function (a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl = Load_d2i_TS_REQ;
  TS_REQ_dup: function (a: PTS_REQ): PTS_REQ; cdecl = Load_TS_REQ_dup;
  d2i_TS_REQ_bio: function (fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl = Load_d2i_TS_REQ_bio;
  i2d_TS_REQ_bio: function (fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_i2d_TS_REQ_bio;
  TS_MSG_IMPRINT_new: function : PTS_MSG_IMPRINT; cdecl = Load_TS_MSG_IMPRINT_new;
  TS_MSG_IMPRINT_free: procedure (a: PTS_MSG_IMPRINT); cdecl = Load_TS_MSG_IMPRINT_free;
  i2d_TS_MSG_IMPRINT: function (a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_MSG_IMPRINT;
  d2i_TS_MSG_IMPRINT: function (a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl = Load_d2i_TS_MSG_IMPRINT;
  TS_MSG_IMPRINT_dup: function (a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = Load_TS_MSG_IMPRINT_dup;
  d2i_TS_MSG_IMPRINT_bio: function (bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = Load_d2i_TS_MSG_IMPRINT_bio;
  i2d_TS_MSG_IMPRINT_bio: function (bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_i2d_TS_MSG_IMPRINT_bio;
  TS_RESP_new: function : PTS_RESP; cdecl = Load_TS_RESP_new;
  TS_RESP_free: procedure (a: PTS_RESP); cdecl = Load_TS_RESP_free;
  i2d_TS_RESP: function (a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_RESP;
  d2i_TS_RESP: function (a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl = Load_d2i_TS_RESP;
  PKCS7_to_TS_TST_INFO: function (token: PPKCS7): PTS_TST_Info; cdecl = Load_PKCS7_to_TS_TST_INFO;
  TS_RESP_dup: function (a: PTS_RESP): PTS_RESP; cdecl = Load_TS_RESP_dup;
  d2i_TS_RESP_bio: function (bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl = Load_d2i_TS_RESP_bio;
  i2d_TS_RESP_bio: function (bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_i2d_TS_RESP_bio;
  TS_STATUS_INFO_new: function : PTS_STATUS_INFO; cdecl = Load_TS_STATUS_INFO_new;
  TS_STATUS_INFO_free: procedure (a: PTS_STATUS_INFO); cdecl = Load_TS_STATUS_INFO_free;
  i2d_TS_STATUS_INFO: function (a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_STATUS_INFO;
  d2i_TS_STATUS_INFO: function (a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl = Load_d2i_TS_STATUS_INFO;
  TS_STATUS_INFO_dup: function (a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl = Load_TS_STATUS_INFO_dup;
  TS_TST_INFO_new: function : PTS_TST_Info; cdecl = Load_TS_TST_INFO_new;
  TS_TST_INFO_free: procedure (a: PTS_TST_Info); cdecl = Load_TS_TST_INFO_free;
  i2d_TS_TST_INFO: function (a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_TST_INFO;
  d2i_TS_TST_INFO: function (a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl = Load_d2i_TS_TST_INFO;
  TS_TST_INFO_dup: function (a: PTS_TST_Info): PTS_TST_Info; cdecl = Load_TS_TST_INFO_dup;
  d2i_TS_TST_INFO_bio: function (bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl = Load_d2i_TS_TST_INFO_bio;
  i2d_TS_TST_INFO_bio: function (bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = Load_i2d_TS_TST_INFO_bio;
  TS_ACCURACY_new: function : PTS_ACCURACY; cdecl = Load_TS_ACCURACY_new;
  TS_ACCURACY_free: procedure (a: PTS_ACCURACY); cdecl = Load_TS_ACCURACY_free;
  i2d_TS_ACCURACY: function (a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_ACCURACY;
  d2i_TS_ACCURACY: function (a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl = Load_d2i_TS_ACCURACY;
  TS_ACCURACY_dup: function (a: PTS_ACCURACY): PTS_ACCURACY; cdecl = Load_TS_ACCURACY_dup;
  ESS_ISSUER_SERIAL_new: function : PESS_ISSUER_SERIAL; cdecl = Load_ESS_ISSUER_SERIAL_new;
  ESS_ISSUER_SERIAL_free: procedure (a: PESS_ISSUER_SERIAL); cdecl = Load_ESS_ISSUER_SERIAL_free;
  i2d_ESS_ISSUER_SERIAL: function ( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ESS_ISSUER_SERIAL;
  d2i_ESS_ISSUER_SERIAL: function (a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl = Load_d2i_ESS_ISSUER_SERIAL;
  ESS_ISSUER_SERIAL_dup: function (a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl = Load_ESS_ISSUER_SERIAL_dup;
  ESS_CERT_ID_new: function : PESS_CERT_ID; cdecl = Load_ESS_CERT_ID_new;
  ESS_CERT_ID_free: procedure (a: PESS_CERT_ID); cdecl = Load_ESS_CERT_ID_free;
  i2d_ESS_CERT_ID: function (a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ESS_CERT_ID;
  d2i_ESS_CERT_ID: function (a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl = Load_d2i_ESS_CERT_ID;
  ESS_CERT_ID_dup: function (a: PESS_CERT_ID): PESS_CERT_ID; cdecl = Load_ESS_CERT_ID_dup;
  ESS_SIGNING_CERT_new: function : PESS_SIGNING_Cert; cdecl = Load_ESS_SIGNING_CERT_new;
  ESS_SIGNING_CERT_free: procedure (a: PESS_SIGNING_Cert); cdecl = Load_ESS_SIGNING_CERT_free;
  i2d_ESS_SIGNING_CERT: function ( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ESS_SIGNING_CERT;
  d2i_ESS_SIGNING_CERT: function (a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl = Load_d2i_ESS_SIGNING_CERT;
  ESS_SIGNING_CERT_dup: function (a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl = Load_ESS_SIGNING_CERT_dup;
  ESS_CERT_ID_V2_new: function : PESS_CERT_ID_V2; cdecl = Load_ESS_CERT_ID_V2_new;
  ESS_CERT_ID_V2_free: procedure (a: PESS_CERT_ID_V2); cdecl = Load_ESS_CERT_ID_V2_free;
  i2d_ESS_CERT_ID_V2: function ( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ESS_CERT_ID_V2;
  d2i_ESS_CERT_ID_V2: function (a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl = Load_d2i_ESS_CERT_ID_V2;
  ESS_CERT_ID_V2_dup: function (a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl = Load_ESS_CERT_ID_V2_dup;
  ESS_SIGNING_CERT_V2_new: function : PESS_SIGNING_CERT_V2; cdecl = Load_ESS_SIGNING_CERT_V2_new;
  ESS_SIGNING_CERT_V2_free: procedure (a: PESS_SIGNING_CERT_V2); cdecl = Load_ESS_SIGNING_CERT_V2_free;
  i2d_ESS_SIGNING_CERT_V2: function (a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl = Load_i2d_ESS_SIGNING_CERT_V2;
  d2i_ESS_SIGNING_CERT_V2: function (a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl = Load_d2i_ESS_SIGNING_CERT_V2;
  ESS_SIGNING_CERT_V2_dup: function (a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl = Load_ESS_SIGNING_CERT_V2_dup;
  TS_REQ_set_version: function (a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_version;
  TS_REQ_get_version: function (a: PTS_REQ): TOpenSSL_C_LONG; cdecl = Load_TS_REQ_get_version;
  TS_STATUS_INFO_set_status: function (a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_STATUS_INFO_set_status;
  TS_STATUS_INFO_get0_status: function (const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl = Load_TS_STATUS_INFO_get0_status;
  TS_REQ_set_msg_imprint: function (a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_msg_imprint;
  TS_REQ_get_msg_imprint: function (a: PTS_REQ): PTS_MSG_IMPRINT; cdecl = Load_TS_REQ_get_msg_imprint;
  TS_MSG_IMPRINT_set_algo: function (a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl = Load_TS_MSG_IMPRINT_set_algo;
  TS_MSG_IMPRINT_get_algo: function (a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl = Load_TS_MSG_IMPRINT_get_algo;
  TS_MSG_IMPRINT_set_msg: function (a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_MSG_IMPRINT_set_msg;
  TS_MSG_IMPRINT_get_msg: function (a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl = Load_TS_MSG_IMPRINT_get_msg;
  TS_REQ_set_policy_id: function (a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_policy_id;
  TS_REQ_get_policy_id: function (a: PTS_REQ): PASN1_OBJECT; cdecl = Load_TS_REQ_get_policy_id;
  TS_REQ_set_nonce: function (a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_nonce;
  TS_REQ_get_nonce: function (const a: PTS_REQ): PASN1_INTEGER; cdecl = Load_TS_REQ_get_nonce;
  TS_REQ_set_cert_req: function (a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_cert_req;
  TS_REQ_get_cert_req: function (a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_cert_req;
  TS_REQ_ext_free: procedure (a: PTS_REQ); cdecl = Load_TS_REQ_ext_free;
  TS_REQ_get_ext_count: function (a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_count;
  TS_REQ_get_ext_by_NID: function (a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_by_NID;
  TS_REQ_get_ext_by_OBJ: function (a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_by_OBJ;
  TS_REQ_get_ext_by_critical: function (a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_by_critical;
  TS_REQ_get_ext: function (a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = Load_TS_REQ_get_ext;
  TS_REQ_delete_ext: function (a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = Load_TS_REQ_delete_ext;
  TS_REQ_add_ext: function (a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_add_ext;
  TS_REQ_get_ext_d2i: function (a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = Load_TS_REQ_get_ext_d2i;
  TS_REQ_print_bio: function (bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_print_bio;
  TS_RESP_set_status_info: function (a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl = Load_TS_RESP_set_status_info;
  TS_RESP_get_status_info: function (a: PTS_RESP): PTS_STATUS_INFO; cdecl = Load_TS_RESP_get_status_info;
  TS_RESP_set_tst_info: procedure (a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl = Load_TS_RESP_set_tst_info;
  TS_RESP_get_token: function (a: PTS_RESP): PPKCS7; cdecl = Load_TS_RESP_get_token;
  TS_RESP_get_tst_info: function (a: PTS_RESP): PTS_TST_Info; cdecl = Load_TS_RESP_get_tst_info;
  TS_TST_INFO_set_version: function (a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_version;
  TS_TST_INFO_get_version: function (const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl = Load_TS_TST_INFO_get_version;
  TS_TST_INFO_set_policy_id: function (a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_policy_id;
  TS_TST_INFO_get_policy_id: function (a: PTS_TST_Info): PASN1_Object; cdecl = Load_TS_TST_INFO_get_policy_id;
  TS_TST_INFO_set_msg_imprint: function (a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_msg_imprint;
  TS_TST_INFO_get_msg_imprint: function (a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl = Load_TS_TST_INFO_get_msg_imprint;
  TS_TST_INFO_set_serial: function (a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_serial;
  TS_TST_INFO_get_serial: function (const a: PTS_TST_INFO): PASN1_INTEGER; cdecl = Load_TS_TST_INFO_get_serial;
  TS_TST_INFO_set_time: function (a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_time;
  TS_TST_INFO_get_time: function (const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl = Load_TS_TST_INFO_get_time;
  TS_TST_INFO_set_accuracy: function (a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_accuracy;
  TS_TST_INFO_get_accuracy: function (a: PTS_TST_Info): PTS_ACCURACY; cdecl = Load_TS_TST_INFO_get_accuracy;
  TS_ACCURACY_set_seconds: function (a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ACCURACY_set_seconds;
  TS_ACCURACY_get_seconds: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = Load_TS_ACCURACY_get_seconds;
  TS_ACCURACY_set_millis: function (a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ACCURACY_set_millis;
  TS_ACCURACY_get_millis: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = Load_TS_ACCURACY_get_millis;
  TS_ACCURACY_set_micros: function (a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ACCURACY_set_micros;
  TS_ACCURACY_get_micros: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = Load_TS_ACCURACY_get_micros;
  TS_TST_INFO_set_ordering: function (a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_ordering;
  TS_TST_INFO_get_ordering: function (const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ordering;
  TS_TST_INFO_set_nonce: function (a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_nonce;
  TS_TST_INFO_get_nonce: function (const a: PTS_TST_INFO): PASN1_INTEGER; cdecl = Load_TS_TST_INFO_get_nonce;
  TS_TST_INFO_set_tsa: function (a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_tsa;
  TS_TST_INFO_get_tsa: function (a: PTS_TST_Info): PGENERAL_NAME; cdecl = Load_TS_TST_INFO_get_tsa;
  TS_TST_INFO_ext_free: procedure (a: PTS_TST_Info); cdecl = Load_TS_TST_INFO_ext_free;
  TS_TST_INFO_get_ext_count: function (a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_count;
  TS_TST_INFO_get_ext_by_NID: function (a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_by_NID;
  TS_TST_INFO_get_ext_by_OBJ: function (a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_by_OBJ;
  TS_TST_INFO_get_ext_by_critical: function (a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_by_critical;
  TS_TST_INFO_get_ext: function (a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = Load_TS_TST_INFO_get_ext;
  TS_TST_INFO_delete_ext: function (a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = Load_TS_TST_INFO_delete_ext;
  TS_TST_INFO_add_ext: function (a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_add_ext;
  TS_TST_INFO_get_ext_d2i: function (a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = Load_TS_TST_INFO_get_ext_d2i;
  TS_RESP_CTX_new: function : PTS_RESP_CTX; cdecl = Load_TS_RESP_CTX_new;
  TS_RESP_CTX_free: procedure (ctx: PTS_RESP_CTX); cdecl = Load_TS_RESP_CTX_free;
  TS_RESP_CTX_set_signer_cert: function (ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_signer_cert;
  TS_RESP_CTX_set_signer_key: function (ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_signer_key;
  TS_RESP_CTX_set_signer_digest: function (ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_signer_digest;
  TS_RESP_CTX_set_ess_cert_id_digest: function (ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_ess_cert_id_digest;
  TS_RESP_CTX_set_def_policy: function (ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_def_policy;
  TS_RESP_CTX_add_policy: function (ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_add_policy;
  TS_RESP_CTX_add_md: function (ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_add_md;
  TS_RESP_CTX_set_accuracy: function (ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_accuracy;
  TS_RESP_CTX_set_clock_precision_digits: function (ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_clock_precision_digits;
  TS_RESP_CTX_add_flags: procedure (ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl = Load_TS_RESP_CTX_add_flags;
  TS_RESP_CTX_set_serial_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl = Load_TS_RESP_CTX_set_serial_cb;
  TS_RESP_CTX_set_time_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl = Load_TS_RESP_CTX_set_time_cb;
  TS_RESP_CTX_set_extension_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl = Load_TS_RESP_CTX_set_extension_cb;
  TS_RESP_CTX_set_status_info: function (ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_status_info;
  TS_RESP_CTX_set_status_info_cond: function (ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_status_info_cond;
  TS_RESP_CTX_add_failure_info: function (ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_add_failure_info;
  TS_RESP_CTX_get_request: function (ctx: PTS_RESP_CTX): PTS_REQ; cdecl = Load_TS_RESP_CTX_get_request;
  TS_RESP_CTX_get_tst_info: function (ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl = Load_TS_RESP_CTX_get_tst_info;
  TS_RESP_create_response: function (ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl = Load_TS_RESP_create_response;
  TS_RESP_verify_response: function (ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_TS_RESP_verify_response;
  TS_RESP_verify_token: function (ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl = Load_TS_RESP_verify_token;
  TS_VERIFY_CTX_new: function : PTS_VERIFY_CTX; cdecl = Load_TS_VERIFY_CTX_new;
  TS_VERIFY_CTX_init: procedure (ctx: PTS_VERIFY_CTX); cdecl = Load_TS_VERIFY_CTX_init;
  TS_VERIFY_CTX_free: procedure (ctx: PTS_VERIFY_CTX); cdecl = Load_TS_VERIFY_CTX_free;
  TS_VERIFY_CTX_cleanup: procedure (ctx: PTS_VERIFY_CTX); cdecl = Load_TS_VERIFY_CTX_cleanup;
  TS_VERIFY_CTX_set_flags: function (ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_VERIFY_CTX_set_flags;
  TS_VERIFY_CTX_add_flags: function (ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_VERIFY_CTX_add_flags;
  TS_VERIFY_CTX_set_data: function (ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl = Load_TS_VERIFY_CTX_set_data;
  TS_VERIFY_CTX_set_imprint: function (ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl = Load_TS_VERIFY_CTX_set_imprint;
  TS_VERIFY_CTX_set_store: function (ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl = Load_TS_VERIFY_CTX_set_store;
  TS_REQ_to_TS_VERIFY_CTX: function (req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl = Load_TS_REQ_to_TS_VERIFY_CTX;
  TS_RESP_print_bio: function (bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_TS_RESP_print_bio;
  TS_STATUS_INFO_print_bio: function (bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl = Load_TS_STATUS_INFO_print_bio;
  TS_TST_INFO_print_bio: function (bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_print_bio;
  TS_ASN1_INTEGER_print_bio: function (bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ASN1_INTEGER_print_bio;
  TS_OBJ_print_bio: function (bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl = Load_TS_OBJ_print_bio;
  TS_X509_ALGOR_print_bio: function (bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl = Load_TS_X509_ALGOR_print_bio;
  TS_MSG_IMPRINT_print_bio: function (bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_TS_MSG_IMPRINT_print_bio;
  TS_CONF_load_cert: function (file_: PAnsiChar): PX509; cdecl = Load_TS_CONF_load_cert;
  TS_CONF_load_key: function ( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl = Load_TS_CONF_load_key;
  TS_CONF_set_serial: function (conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_serial;
  TS_CONF_get_tsa_section: function (conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl = Load_TS_CONF_get_tsa_section;
  TS_CONF_set_crypto_device: function (conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_crypto_device;
  TS_CONF_set_default_engine: function (name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_default_engine;
  TS_CONF_set_signer_cert: function (conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_signer_cert;
  TS_CONF_set_certs: function (conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_certs;
  TS_CONF_set_signer_key: function (conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_signer_key;
  TS_CONF_set_signer_digest: function (conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_signer_digest;
  TS_CONF_set_def_policy: function (conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_def_policy;
  TS_CONF_set_policies: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_policies;
  TS_CONF_set_digests: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_digests;
  TS_CONF_set_accuracy: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_accuracy;
  TS_CONF_set_clock_precision_digits: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_clock_precision_digits;
  TS_CONF_set_ordering: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_ordering;
  TS_CONF_set_tsa_name: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_tsa_name;
  TS_CONF_set_ess_cert_id_chain: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_ess_cert_id_chain;
  TS_CONF_set_ess_cert_id_digest: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_ess_cert_id_digest;
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
function Load_TS_REQ_new: PTS_REQ; cdecl;
begin
  TS_REQ_new := LoadLibCryptoFunction('TS_REQ_new');
  if not assigned(TS_REQ_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_new');
  Result := TS_REQ_new();
end;

procedure Load_TS_REQ_free(a: PTS_REQ); cdecl;
begin
  TS_REQ_free := LoadLibCryptoFunction('TS_REQ_free');
  if not assigned(TS_REQ_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_free');
  TS_REQ_free(a);
end;

function Load_i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_REQ := LoadLibCryptoFunction('i2d_TS_REQ');
  if not assigned(i2d_TS_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ');
  Result := i2d_TS_REQ(a,pp);
end;

function Load_d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl;
begin
  d2i_TS_REQ := LoadLibCryptoFunction('d2i_TS_REQ');
  if not assigned(d2i_TS_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ');
  Result := d2i_TS_REQ(a,pp,length);
end;

function Load_TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl;
begin
  TS_REQ_dup := LoadLibCryptoFunction('TS_REQ_dup');
  if not assigned(TS_REQ_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_dup');
  Result := TS_REQ_dup(a);
end;

function Load_d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl;
begin
  d2i_TS_REQ_bio := LoadLibCryptoFunction('d2i_TS_REQ_bio');
  if not assigned(d2i_TS_REQ_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ_bio');
  Result := d2i_TS_REQ_bio(fp,a);
end;

function Load_i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_REQ_bio := LoadLibCryptoFunction('i2d_TS_REQ_bio');
  if not assigned(i2d_TS_REQ_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ_bio');
  Result := i2d_TS_REQ_bio(fp,a);
end;

function Load_TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl;
begin
  TS_MSG_IMPRINT_new := LoadLibCryptoFunction('TS_MSG_IMPRINT_new');
  if not assigned(TS_MSG_IMPRINT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_new');
  Result := TS_MSG_IMPRINT_new();
end;

procedure Load_TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl;
begin
  TS_MSG_IMPRINT_free := LoadLibCryptoFunction('TS_MSG_IMPRINT_free');
  if not assigned(TS_MSG_IMPRINT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_free');
  TS_MSG_IMPRINT_free(a);
end;

function Load_i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_MSG_IMPRINT := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT');
  if not assigned(i2d_TS_MSG_IMPRINT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT');
  Result := i2d_TS_MSG_IMPRINT(a,pp);
end;

function Load_d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl;
begin
  d2i_TS_MSG_IMPRINT := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT');
  if not assigned(d2i_TS_MSG_IMPRINT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT');
  Result := d2i_TS_MSG_IMPRINT(a,pp,length);
end;

function Load_TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  TS_MSG_IMPRINT_dup := LoadLibCryptoFunction('TS_MSG_IMPRINT_dup');
  if not assigned(TS_MSG_IMPRINT_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_dup');
  Result := TS_MSG_IMPRINT_dup(a);
end;

function Load_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  d2i_TS_MSG_IMPRINT_bio := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT_bio');
  if not assigned(d2i_TS_MSG_IMPRINT_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT_bio');
  Result := d2i_TS_MSG_IMPRINT_bio(bio,a);
end;

function Load_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_MSG_IMPRINT_bio := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT_bio');
  if not assigned(i2d_TS_MSG_IMPRINT_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT_bio');
  Result := i2d_TS_MSG_IMPRINT_bio(bio,a);
end;

function Load_TS_RESP_new: PTS_RESP; cdecl;
begin
  TS_RESP_new := LoadLibCryptoFunction('TS_RESP_new');
  if not assigned(TS_RESP_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_new');
  Result := TS_RESP_new();
end;

procedure Load_TS_RESP_free(a: PTS_RESP); cdecl;
begin
  TS_RESP_free := LoadLibCryptoFunction('TS_RESP_free');
  if not assigned(TS_RESP_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_free');
  TS_RESP_free(a);
end;

function Load_i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_RESP := LoadLibCryptoFunction('i2d_TS_RESP');
  if not assigned(i2d_TS_RESP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP');
  Result := i2d_TS_RESP(a,pp);
end;

function Load_d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl;
begin
  d2i_TS_RESP := LoadLibCryptoFunction('d2i_TS_RESP');
  if not assigned(d2i_TS_RESP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP');
  Result := d2i_TS_RESP(a,pp,length);
end;

function Load_PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info; cdecl;
begin
  PKCS7_to_TS_TST_INFO := LoadLibCryptoFunction('PKCS7_to_TS_TST_INFO');
  if not assigned(PKCS7_to_TS_TST_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_to_TS_TST_INFO');
  Result := PKCS7_to_TS_TST_INFO(token);
end;

function Load_TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl;
begin
  TS_RESP_dup := LoadLibCryptoFunction('TS_RESP_dup');
  if not assigned(TS_RESP_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_dup');
  Result := TS_RESP_dup(a);
end;

function Load_d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl;
begin
  d2i_TS_RESP_bio := LoadLibCryptoFunction('d2i_TS_RESP_bio');
  if not assigned(d2i_TS_RESP_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP_bio');
  Result := d2i_TS_RESP_bio(bio,a);
end;

function Load_i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_RESP_bio := LoadLibCryptoFunction('i2d_TS_RESP_bio');
  if not assigned(i2d_TS_RESP_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP_bio');
  Result := i2d_TS_RESP_bio(bio,a);
end;

function Load_TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl;
begin
  TS_STATUS_INFO_new := LoadLibCryptoFunction('TS_STATUS_INFO_new');
  if not assigned(TS_STATUS_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_new');
  Result := TS_STATUS_INFO_new();
end;

procedure Load_TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl;
begin
  TS_STATUS_INFO_free := LoadLibCryptoFunction('TS_STATUS_INFO_free');
  if not assigned(TS_STATUS_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_free');
  TS_STATUS_INFO_free(a);
end;

function Load_i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_STATUS_INFO := LoadLibCryptoFunction('i2d_TS_STATUS_INFO');
  if not assigned(i2d_TS_STATUS_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_STATUS_INFO');
  Result := i2d_TS_STATUS_INFO(a,pp);
end;

function Load_d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl;
begin
  d2i_TS_STATUS_INFO := LoadLibCryptoFunction('d2i_TS_STATUS_INFO');
  if not assigned(d2i_TS_STATUS_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_STATUS_INFO');
  Result := d2i_TS_STATUS_INFO(a,pp,length);
end;

function Load_TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl;
begin
  TS_STATUS_INFO_dup := LoadLibCryptoFunction('TS_STATUS_INFO_dup');
  if not assigned(TS_STATUS_INFO_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_dup');
  Result := TS_STATUS_INFO_dup(a);
end;

function Load_TS_TST_INFO_new: PTS_TST_Info; cdecl;
begin
  TS_TST_INFO_new := LoadLibCryptoFunction('TS_TST_INFO_new');
  if not assigned(TS_TST_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_new');
  Result := TS_TST_INFO_new();
end;

procedure Load_TS_TST_INFO_free(a: PTS_TST_Info); cdecl;
begin
  TS_TST_INFO_free := LoadLibCryptoFunction('TS_TST_INFO_free');
  if not assigned(TS_TST_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_free');
  TS_TST_INFO_free(a);
end;

function Load_i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_TST_INFO := LoadLibCryptoFunction('i2d_TS_TST_INFO');
  if not assigned(i2d_TS_TST_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO');
  Result := i2d_TS_TST_INFO(a,pp);
end;

function Load_d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl;
begin
  d2i_TS_TST_INFO := LoadLibCryptoFunction('d2i_TS_TST_INFO');
  if not assigned(d2i_TS_TST_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO');
  Result := d2i_TS_TST_INFO(a,pp,length);
end;

function Load_TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info; cdecl;
begin
  TS_TST_INFO_dup := LoadLibCryptoFunction('TS_TST_INFO_dup');
  if not assigned(TS_TST_INFO_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_dup');
  Result := TS_TST_INFO_dup(a);
end;

function Load_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl;
begin
  d2i_TS_TST_INFO_bio := LoadLibCryptoFunction('d2i_TS_TST_INFO_bio');
  if not assigned(d2i_TS_TST_INFO_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO_bio');
  Result := d2i_TS_TST_INFO_bio(bio,a);
end;

function Load_i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_TST_INFO_bio := LoadLibCryptoFunction('i2d_TS_TST_INFO_bio');
  if not assigned(i2d_TS_TST_INFO_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO_bio');
  Result := i2d_TS_TST_INFO_bio(bio,a);
end;

function Load_TS_ACCURACY_new: PTS_ACCURACY; cdecl;
begin
  TS_ACCURACY_new := LoadLibCryptoFunction('TS_ACCURACY_new');
  if not assigned(TS_ACCURACY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_new');
  Result := TS_ACCURACY_new();
end;

procedure Load_TS_ACCURACY_free(a: PTS_ACCURACY); cdecl;
begin
  TS_ACCURACY_free := LoadLibCryptoFunction('TS_ACCURACY_free');
  if not assigned(TS_ACCURACY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_free');
  TS_ACCURACY_free(a);
end;

function Load_i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_ACCURACY := LoadLibCryptoFunction('i2d_TS_ACCURACY');
  if not assigned(i2d_TS_ACCURACY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_ACCURACY');
  Result := i2d_TS_ACCURACY(a,pp);
end;

function Load_d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl;
begin
  d2i_TS_ACCURACY := LoadLibCryptoFunction('d2i_TS_ACCURACY');
  if not assigned(d2i_TS_ACCURACY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_ACCURACY');
  Result := d2i_TS_ACCURACY(a,pp,length);
end;

function Load_TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl;
begin
  TS_ACCURACY_dup := LoadLibCryptoFunction('TS_ACCURACY_dup');
  if not assigned(TS_ACCURACY_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_dup');
  Result := TS_ACCURACY_dup(a);
end;

function Load_ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl;
begin
  ESS_ISSUER_SERIAL_new := LoadLibCryptoFunction('ESS_ISSUER_SERIAL_new');
  if not assigned(ESS_ISSUER_SERIAL_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_ISSUER_SERIAL_new');
  Result := ESS_ISSUER_SERIAL_new();
end;

procedure Load_ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl;
begin
  ESS_ISSUER_SERIAL_free := LoadLibCryptoFunction('ESS_ISSUER_SERIAL_free');
  if not assigned(ESS_ISSUER_SERIAL_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_ISSUER_SERIAL_free');
  ESS_ISSUER_SERIAL_free(a);
end;

function Load_i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ESS_ISSUER_SERIAL := LoadLibCryptoFunction('i2d_ESS_ISSUER_SERIAL');
  if not assigned(i2d_ESS_ISSUER_SERIAL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_ISSUER_SERIAL');
  Result := i2d_ESS_ISSUER_SERIAL(a,pp);
end;

function Load_d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl;
begin
  d2i_ESS_ISSUER_SERIAL := LoadLibCryptoFunction('d2i_ESS_ISSUER_SERIAL');
  if not assigned(d2i_ESS_ISSUER_SERIAL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_ISSUER_SERIAL');
  Result := d2i_ESS_ISSUER_SERIAL(a,pp,length);
end;

function Load_ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl;
begin
  ESS_ISSUER_SERIAL_dup := LoadLibCryptoFunction('ESS_ISSUER_SERIAL_dup');
  if not assigned(ESS_ISSUER_SERIAL_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_ISSUER_SERIAL_dup');
  Result := ESS_ISSUER_SERIAL_dup(a);
end;

function Load_ESS_CERT_ID_new: PESS_CERT_ID; cdecl;
begin
  ESS_CERT_ID_new := LoadLibCryptoFunction('ESS_CERT_ID_new');
  if not assigned(ESS_CERT_ID_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_new');
  Result := ESS_CERT_ID_new();
end;

procedure Load_ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl;
begin
  ESS_CERT_ID_free := LoadLibCryptoFunction('ESS_CERT_ID_free');
  if not assigned(ESS_CERT_ID_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_free');
  ESS_CERT_ID_free(a);
end;

function Load_i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ESS_CERT_ID := LoadLibCryptoFunction('i2d_ESS_CERT_ID');
  if not assigned(i2d_ESS_CERT_ID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_CERT_ID');
  Result := i2d_ESS_CERT_ID(a,pp);
end;

function Load_d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl;
begin
  d2i_ESS_CERT_ID := LoadLibCryptoFunction('d2i_ESS_CERT_ID');
  if not assigned(d2i_ESS_CERT_ID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_CERT_ID');
  Result := d2i_ESS_CERT_ID(a,pp,length);
end;

function Load_ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl;
begin
  ESS_CERT_ID_dup := LoadLibCryptoFunction('ESS_CERT_ID_dup');
  if not assigned(ESS_CERT_ID_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_dup');
  Result := ESS_CERT_ID_dup(a);
end;

function Load_ESS_SIGNING_CERT_new: PESS_SIGNING_Cert; cdecl;
begin
  ESS_SIGNING_CERT_new := LoadLibCryptoFunction('ESS_SIGNING_CERT_new');
  if not assigned(ESS_SIGNING_CERT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_new');
  Result := ESS_SIGNING_CERT_new();
end;

procedure Load_ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert); cdecl;
begin
  ESS_SIGNING_CERT_free := LoadLibCryptoFunction('ESS_SIGNING_CERT_free');
  if not assigned(ESS_SIGNING_CERT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_free');
  ESS_SIGNING_CERT_free(a);
end;

function Load_i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ESS_SIGNING_CERT := LoadLibCryptoFunction('i2d_ESS_SIGNING_CERT');
  if not assigned(i2d_ESS_SIGNING_CERT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_SIGNING_CERT');
  Result := i2d_ESS_SIGNING_CERT(a,pp);
end;

function Load_d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl;
begin
  d2i_ESS_SIGNING_CERT := LoadLibCryptoFunction('d2i_ESS_SIGNING_CERT');
  if not assigned(d2i_ESS_SIGNING_CERT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_SIGNING_CERT');
  Result := d2i_ESS_SIGNING_CERT(a,pp,length);
end;

function Load_ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl;
begin
  ESS_SIGNING_CERT_dup := LoadLibCryptoFunction('ESS_SIGNING_CERT_dup');
  if not assigned(ESS_SIGNING_CERT_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_dup');
  Result := ESS_SIGNING_CERT_dup(a);
end;

function Load_ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl;
begin
  ESS_CERT_ID_V2_new := LoadLibCryptoFunction('ESS_CERT_ID_V2_new');
  if not assigned(ESS_CERT_ID_V2_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_V2_new');
  Result := ESS_CERT_ID_V2_new();
end;

procedure Load_ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl;
begin
  ESS_CERT_ID_V2_free := LoadLibCryptoFunction('ESS_CERT_ID_V2_free');
  if not assigned(ESS_CERT_ID_V2_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_V2_free');
  ESS_CERT_ID_V2_free(a);
end;

function Load_i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ESS_CERT_ID_V2 := LoadLibCryptoFunction('i2d_ESS_CERT_ID_V2');
  if not assigned(i2d_ESS_CERT_ID_V2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_CERT_ID_V2');
  Result := i2d_ESS_CERT_ID_V2(a,pp);
end;

function Load_d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl;
begin
  d2i_ESS_CERT_ID_V2 := LoadLibCryptoFunction('d2i_ESS_CERT_ID_V2');
  if not assigned(d2i_ESS_CERT_ID_V2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_CERT_ID_V2');
  Result := d2i_ESS_CERT_ID_V2(a,pp,length);
end;

function Load_ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl;
begin
  ESS_CERT_ID_V2_dup := LoadLibCryptoFunction('ESS_CERT_ID_V2_dup');
  if not assigned(ESS_CERT_ID_V2_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_V2_dup');
  Result := ESS_CERT_ID_V2_dup(a);
end;

function Load_ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl;
begin
  ESS_SIGNING_CERT_V2_new := LoadLibCryptoFunction('ESS_SIGNING_CERT_V2_new');
  if not assigned(ESS_SIGNING_CERT_V2_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_V2_new');
  Result := ESS_SIGNING_CERT_V2_new();
end;

procedure Load_ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl;
begin
  ESS_SIGNING_CERT_V2_free := LoadLibCryptoFunction('ESS_SIGNING_CERT_V2_free');
  if not assigned(ESS_SIGNING_CERT_V2_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_V2_free');
  ESS_SIGNING_CERT_V2_free(a);
end;

function Load_i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  i2d_ESS_SIGNING_CERT_V2 := LoadLibCryptoFunction('i2d_ESS_SIGNING_CERT_V2');
  if not assigned(i2d_ESS_SIGNING_CERT_V2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_SIGNING_CERT_V2');
  Result := i2d_ESS_SIGNING_CERT_V2(a,pp);
end;

function Load_d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl;
begin
  d2i_ESS_SIGNING_CERT_V2 := LoadLibCryptoFunction('d2i_ESS_SIGNING_CERT_V2');
  if not assigned(d2i_ESS_SIGNING_CERT_V2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_SIGNING_CERT_V2');
  Result := d2i_ESS_SIGNING_CERT_V2(a,pp,length);
end;

function Load_ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl;
begin
  ESS_SIGNING_CERT_V2_dup := LoadLibCryptoFunction('ESS_SIGNING_CERT_V2_dup');
  if not assigned(ESS_SIGNING_CERT_V2_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_V2_dup');
  Result := ESS_SIGNING_CERT_V2_dup(a);
end;

function Load_TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_version := LoadLibCryptoFunction('TS_REQ_set_version');
  if not assigned(TS_REQ_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_version');
  Result := TS_REQ_set_version(a,version);
end;

function Load_TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_LONG; cdecl;
begin
  TS_REQ_get_version := LoadLibCryptoFunction('TS_REQ_get_version');
  if not assigned(TS_REQ_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_version');
  Result := TS_REQ_get_version(a);
end;

function Load_TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_STATUS_INFO_set_status := LoadLibCryptoFunction('TS_STATUS_INFO_set_status');
  if not assigned(TS_STATUS_INFO_set_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_set_status');
  Result := TS_STATUS_INFO_set_status(a,i);
end;

function Load_TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl;
begin
  TS_STATUS_INFO_get0_status := LoadLibCryptoFunction('TS_STATUS_INFO_get0_status');
  if not assigned(TS_STATUS_INFO_get0_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_get0_status');
  Result := TS_STATUS_INFO_get0_status(a);
end;

function Load_TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_msg_imprint := LoadLibCryptoFunction('TS_REQ_set_msg_imprint');
  if not assigned(TS_REQ_set_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_msg_imprint');
  Result := TS_REQ_set_msg_imprint(a,msg_imprint);
end;

function Load_TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl;
begin
  TS_REQ_get_msg_imprint := LoadLibCryptoFunction('TS_REQ_get_msg_imprint');
  if not assigned(TS_REQ_get_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_msg_imprint');
  Result := TS_REQ_get_msg_imprint(a);
end;

function Load_TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl;
begin
  TS_MSG_IMPRINT_set_algo := LoadLibCryptoFunction('TS_MSG_IMPRINT_set_algo');
  if not assigned(TS_MSG_IMPRINT_set_algo) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_set_algo');
  Result := TS_MSG_IMPRINT_set_algo(a,alg);
end;

function Load_TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl;
begin
  TS_MSG_IMPRINT_get_algo := LoadLibCryptoFunction('TS_MSG_IMPRINT_get_algo');
  if not assigned(TS_MSG_IMPRINT_get_algo) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_get_algo');
  Result := TS_MSG_IMPRINT_get_algo(a);
end;

function Load_TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_MSG_IMPRINT_set_msg := LoadLibCryptoFunction('TS_MSG_IMPRINT_set_msg');
  if not assigned(TS_MSG_IMPRINT_set_msg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_set_msg');
  Result := TS_MSG_IMPRINT_set_msg(a,d,len);
end;

function Load_TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl;
begin
  TS_MSG_IMPRINT_get_msg := LoadLibCryptoFunction('TS_MSG_IMPRINT_get_msg');
  if not assigned(TS_MSG_IMPRINT_get_msg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_get_msg');
  Result := TS_MSG_IMPRINT_get_msg(a);
end;

function Load_TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_policy_id := LoadLibCryptoFunction('TS_REQ_set_policy_id');
  if not assigned(TS_REQ_set_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_policy_id');
  Result := TS_REQ_set_policy_id(a,policy);
end;

function Load_TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl;
begin
  TS_REQ_get_policy_id := LoadLibCryptoFunction('TS_REQ_get_policy_id');
  if not assigned(TS_REQ_get_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_policy_id');
  Result := TS_REQ_get_policy_id(a);
end;

function Load_TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_nonce := LoadLibCryptoFunction('TS_REQ_set_nonce');
  if not assigned(TS_REQ_set_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_nonce');
  Result := TS_REQ_set_nonce(a,nonce);
end;

function Load_TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER; cdecl;
begin
  TS_REQ_get_nonce := LoadLibCryptoFunction('TS_REQ_get_nonce');
  if not assigned(TS_REQ_get_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_nonce');
  Result := TS_REQ_get_nonce(a);
end;

function Load_TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_cert_req := LoadLibCryptoFunction('TS_REQ_set_cert_req');
  if not assigned(TS_REQ_set_cert_req) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_cert_req');
  Result := TS_REQ_set_cert_req(a,cert_req);
end;

function Load_TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_cert_req := LoadLibCryptoFunction('TS_REQ_get_cert_req');
  if not assigned(TS_REQ_get_cert_req) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_cert_req');
  Result := TS_REQ_get_cert_req(a);
end;

procedure Load_TS_REQ_ext_free(a: PTS_REQ); cdecl;
begin
  TS_REQ_ext_free := LoadLibCryptoFunction('TS_REQ_ext_free');
  if not assigned(TS_REQ_ext_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_ext_free');
  TS_REQ_ext_free(a);
end;

function Load_TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_count := LoadLibCryptoFunction('TS_REQ_get_ext_count');
  if not assigned(TS_REQ_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_count');
  Result := TS_REQ_get_ext_count(a);
end;

function Load_TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_by_NID := LoadLibCryptoFunction('TS_REQ_get_ext_by_NID');
  if not assigned(TS_REQ_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_NID');
  Result := TS_REQ_get_ext_by_NID(a,nid,lastpos);
end;

function Load_TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_by_OBJ := LoadLibCryptoFunction('TS_REQ_get_ext_by_OBJ');
  if not assigned(TS_REQ_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_OBJ');
  Result := TS_REQ_get_ext_by_OBJ(a,obj,lastpos);
end;

function Load_TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_by_critical := LoadLibCryptoFunction('TS_REQ_get_ext_by_critical');
  if not assigned(TS_REQ_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_critical');
  Result := TS_REQ_get_ext_by_critical(a,crit,lastpos);
end;

function Load_TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  TS_REQ_get_ext := LoadLibCryptoFunction('TS_REQ_get_ext');
  if not assigned(TS_REQ_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext');
  Result := TS_REQ_get_ext(a,loc);
end;

function Load_TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  TS_REQ_delete_ext := LoadLibCryptoFunction('TS_REQ_delete_ext');
  if not assigned(TS_REQ_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_delete_ext');
  Result := TS_REQ_delete_ext(a,loc);
end;

function Load_TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_add_ext := LoadLibCryptoFunction('TS_REQ_add_ext');
  if not assigned(TS_REQ_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_add_ext');
  Result := TS_REQ_add_ext(a,ex,loc);
end;

function Load_TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  TS_REQ_get_ext_d2i := LoadLibCryptoFunction('TS_REQ_get_ext_d2i');
  if not assigned(TS_REQ_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_d2i');
  Result := TS_REQ_get_ext_d2i(a,nid,crit,idx);
end;

function Load_TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_print_bio := LoadLibCryptoFunction('TS_REQ_print_bio');
  if not assigned(TS_REQ_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_print_bio');
  Result := TS_REQ_print_bio(bio,a);
end;

function Load_TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_set_status_info := LoadLibCryptoFunction('TS_RESP_set_status_info');
  if not assigned(TS_RESP_set_status_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_set_status_info');
  Result := TS_RESP_set_status_info(a,info);
end;

function Load_TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl;
begin
  TS_RESP_get_status_info := LoadLibCryptoFunction('TS_RESP_get_status_info');
  if not assigned(TS_RESP_get_status_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_status_info');
  Result := TS_RESP_get_status_info(a);
end;

procedure Load_TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl;
begin
  TS_RESP_set_tst_info := LoadLibCryptoFunction('TS_RESP_set_tst_info');
  if not assigned(TS_RESP_set_tst_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_set_tst_info');
  TS_RESP_set_tst_info(a,p7,tst_info);
end;

function Load_TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl;
begin
  TS_RESP_get_token := LoadLibCryptoFunction('TS_RESP_get_token');
  if not assigned(TS_RESP_get_token) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_token');
  Result := TS_RESP_get_token(a);
end;

function Load_TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info; cdecl;
begin
  TS_RESP_get_tst_info := LoadLibCryptoFunction('TS_RESP_get_tst_info');
  if not assigned(TS_RESP_get_tst_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_tst_info');
  Result := TS_RESP_get_tst_info(a);
end;

function Load_TS_TST_INFO_set_version(a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_version := LoadLibCryptoFunction('TS_TST_INFO_set_version');
  if not assigned(TS_TST_INFO_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_version');
  Result := TS_TST_INFO_set_version(a,version);
end;

function Load_TS_TST_INFO_get_version(const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl;
begin
  TS_TST_INFO_get_version := LoadLibCryptoFunction('TS_TST_INFO_get_version');
  if not assigned(TS_TST_INFO_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_version');
  Result := TS_TST_INFO_get_version(a);
end;

function Load_TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_policy_id := LoadLibCryptoFunction('TS_TST_INFO_set_policy_id');
  if not assigned(TS_TST_INFO_set_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_policy_id');
  Result := TS_TST_INFO_set_policy_id(a,policy_id);
end;

function Load_TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object; cdecl;
begin
  TS_TST_INFO_get_policy_id := LoadLibCryptoFunction('TS_TST_INFO_get_policy_id');
  if not assigned(TS_TST_INFO_get_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_policy_id');
  Result := TS_TST_INFO_get_policy_id(a);
end;

function Load_TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_msg_imprint := LoadLibCryptoFunction('TS_TST_INFO_set_msg_imprint');
  if not assigned(TS_TST_INFO_set_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_msg_imprint');
  Result := TS_TST_INFO_set_msg_imprint(a,msg_imprint);
end;

function Load_TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl;
begin
  TS_TST_INFO_get_msg_imprint := LoadLibCryptoFunction('TS_TST_INFO_get_msg_imprint');
  if not assigned(TS_TST_INFO_get_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_msg_imprint');
  Result := TS_TST_INFO_get_msg_imprint(a);
end;

function Load_TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_serial := LoadLibCryptoFunction('TS_TST_INFO_set_serial');
  if not assigned(TS_TST_INFO_set_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_serial');
  Result := TS_TST_INFO_set_serial(a,serial);
end;

function Load_TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
begin
  TS_TST_INFO_get_serial := LoadLibCryptoFunction('TS_TST_INFO_get_serial');
  if not assigned(TS_TST_INFO_get_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_serial');
  Result := TS_TST_INFO_get_serial(a);
end;

function Load_TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_time := LoadLibCryptoFunction('TS_TST_INFO_set_time');
  if not assigned(TS_TST_INFO_set_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_time');
  Result := TS_TST_INFO_set_time(a,gtime);
end;

function Load_TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl;
begin
  TS_TST_INFO_get_time := LoadLibCryptoFunction('TS_TST_INFO_get_time');
  if not assigned(TS_TST_INFO_get_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_time');
  Result := TS_TST_INFO_get_time(a);
end;

function Load_TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_accuracy := LoadLibCryptoFunction('TS_TST_INFO_set_accuracy');
  if not assigned(TS_TST_INFO_set_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_accuracy');
  Result := TS_TST_INFO_set_accuracy(a,accuracy);
end;

function Load_TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY; cdecl;
begin
  TS_TST_INFO_get_accuracy := LoadLibCryptoFunction('TS_TST_INFO_get_accuracy');
  if not assigned(TS_TST_INFO_get_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_accuracy');
  Result := TS_TST_INFO_get_accuracy(a);
end;

function Load_TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ACCURACY_set_seconds := LoadLibCryptoFunction('TS_ACCURACY_set_seconds');
  if not assigned(TS_ACCURACY_set_seconds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_seconds');
  Result := TS_ACCURACY_set_seconds(a,seconds);
end;

function Load_TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  TS_ACCURACY_get_seconds := LoadLibCryptoFunction('TS_ACCURACY_get_seconds');
  if not assigned(TS_ACCURACY_get_seconds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_seconds');
  Result := TS_ACCURACY_get_seconds(a);
end;

function Load_TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ACCURACY_set_millis := LoadLibCryptoFunction('TS_ACCURACY_set_millis');
  if not assigned(TS_ACCURACY_set_millis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_millis');
  Result := TS_ACCURACY_set_millis(a,millis);
end;

function Load_TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  TS_ACCURACY_get_millis := LoadLibCryptoFunction('TS_ACCURACY_get_millis');
  if not assigned(TS_ACCURACY_get_millis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_millis');
  Result := TS_ACCURACY_get_millis(a);
end;

function Load_TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ACCURACY_set_micros := LoadLibCryptoFunction('TS_ACCURACY_set_micros');
  if not assigned(TS_ACCURACY_set_micros) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_micros');
  Result := TS_ACCURACY_set_micros(a,micros);
end;

function Load_TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  TS_ACCURACY_get_micros := LoadLibCryptoFunction('TS_ACCURACY_get_micros');
  if not assigned(TS_ACCURACY_get_micros) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_micros');
  Result := TS_ACCURACY_get_micros(a);
end;

function Load_TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_ordering := LoadLibCryptoFunction('TS_TST_INFO_set_ordering');
  if not assigned(TS_TST_INFO_set_ordering) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_ordering');
  Result := TS_TST_INFO_set_ordering(a,ordering);
end;

function Load_TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ordering := LoadLibCryptoFunction('TS_TST_INFO_get_ordering');
  if not assigned(TS_TST_INFO_get_ordering) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ordering');
  Result := TS_TST_INFO_get_ordering(a);
end;

function Load_TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_nonce := LoadLibCryptoFunction('TS_TST_INFO_set_nonce');
  if not assigned(TS_TST_INFO_set_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_nonce');
  Result := TS_TST_INFO_set_nonce(a,nonce);
end;

function Load_TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
begin
  TS_TST_INFO_get_nonce := LoadLibCryptoFunction('TS_TST_INFO_get_nonce');
  if not assigned(TS_TST_INFO_get_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_nonce');
  Result := TS_TST_INFO_get_nonce(a);
end;

function Load_TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_tsa := LoadLibCryptoFunction('TS_TST_INFO_set_tsa');
  if not assigned(TS_TST_INFO_set_tsa) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_tsa');
  Result := TS_TST_INFO_set_tsa(a,tsa);
end;

function Load_TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME; cdecl;
begin
  TS_TST_INFO_get_tsa := LoadLibCryptoFunction('TS_TST_INFO_get_tsa');
  if not assigned(TS_TST_INFO_get_tsa) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_tsa');
  Result := TS_TST_INFO_get_tsa(a);
end;

procedure Load_TS_TST_INFO_ext_free(a: PTS_TST_Info); cdecl;
begin
  TS_TST_INFO_ext_free := LoadLibCryptoFunction('TS_TST_INFO_ext_free');
  if not assigned(TS_TST_INFO_ext_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_ext_free');
  TS_TST_INFO_ext_free(a);
end;

function Load_TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_count := LoadLibCryptoFunction('TS_TST_INFO_get_ext_count');
  if not assigned(TS_TST_INFO_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_count');
  Result := TS_TST_INFO_get_ext_count(a);
end;

function Load_TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_by_NID := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_NID');
  if not assigned(TS_TST_INFO_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_NID');
  Result := TS_TST_INFO_get_ext_by_NID(a,nid,lastpos);
end;

function Load_TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_by_OBJ := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_OBJ');
  if not assigned(TS_TST_INFO_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_OBJ');
  Result := TS_TST_INFO_get_ext_by_OBJ(a,obj,lastpos);
end;

function Load_TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_by_critical := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_critical');
  if not assigned(TS_TST_INFO_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_critical');
  Result := TS_TST_INFO_get_ext_by_critical(a,crit,lastpos);
end;

function Load_TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  TS_TST_INFO_get_ext := LoadLibCryptoFunction('TS_TST_INFO_get_ext');
  if not assigned(TS_TST_INFO_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext');
  Result := TS_TST_INFO_get_ext(a,loc);
end;

function Load_TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  TS_TST_INFO_delete_ext := LoadLibCryptoFunction('TS_TST_INFO_delete_ext');
  if not assigned(TS_TST_INFO_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_delete_ext');
  Result := TS_TST_INFO_delete_ext(a,loc);
end;

function Load_TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_add_ext := LoadLibCryptoFunction('TS_TST_INFO_add_ext');
  if not assigned(TS_TST_INFO_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_add_ext');
  Result := TS_TST_INFO_add_ext(a,ex,loc);
end;

function Load_TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  TS_TST_INFO_get_ext_d2i := LoadLibCryptoFunction('TS_TST_INFO_get_ext_d2i');
  if not assigned(TS_TST_INFO_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_d2i');
  Result := TS_TST_INFO_get_ext_d2i(a,nid,crit,idx);
end;

function Load_TS_RESP_CTX_new: PTS_RESP_CTX; cdecl;
begin
  TS_RESP_CTX_new := LoadLibCryptoFunction('TS_RESP_CTX_new');
  if not assigned(TS_RESP_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_new');
  Result := TS_RESP_CTX_new();
end;

procedure Load_TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl;
begin
  TS_RESP_CTX_free := LoadLibCryptoFunction('TS_RESP_CTX_free');
  if not assigned(TS_RESP_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_free');
  TS_RESP_CTX_free(ctx);
end;

function Load_TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_signer_cert := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_cert');
  if not assigned(TS_RESP_CTX_set_signer_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_cert');
  Result := TS_RESP_CTX_set_signer_cert(ctx,signer);
end;

function Load_TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_signer_key := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_key');
  if not assigned(TS_RESP_CTX_set_signer_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_key');
  Result := TS_RESP_CTX_set_signer_key(ctx,key);
end;

function Load_TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_signer_digest := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_digest');
  if not assigned(TS_RESP_CTX_set_signer_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_digest');
  Result := TS_RESP_CTX_set_signer_digest(ctx,signer_digest);
end;

function Load_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_ess_cert_id_digest := LoadLibCryptoFunction('TS_RESP_CTX_set_ess_cert_id_digest');
  if not assigned(TS_RESP_CTX_set_ess_cert_id_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_ess_cert_id_digest');
  Result := TS_RESP_CTX_set_ess_cert_id_digest(ctx,md);
end;

function Load_TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_def_policy := LoadLibCryptoFunction('TS_RESP_CTX_set_def_policy');
  if not assigned(TS_RESP_CTX_set_def_policy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_def_policy');
  Result := TS_RESP_CTX_set_def_policy(ctx,def_policy);
end;

function Load_TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_add_policy := LoadLibCryptoFunction('TS_RESP_CTX_add_policy');
  if not assigned(TS_RESP_CTX_add_policy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_policy');
  Result := TS_RESP_CTX_add_policy(ctx,policy);
end;

function Load_TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_add_md := LoadLibCryptoFunction('TS_RESP_CTX_add_md');
  if not assigned(TS_RESP_CTX_add_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_md');
  Result := TS_RESP_CTX_add_md(ctx,md);
end;

function Load_TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_accuracy := LoadLibCryptoFunction('TS_RESP_CTX_set_accuracy');
  if not assigned(TS_RESP_CTX_set_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_accuracy');
  Result := TS_RESP_CTX_set_accuracy(ctx,secs,millis,micros);
end;

function Load_TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_clock_precision_digits := LoadLibCryptoFunction('TS_RESP_CTX_set_clock_precision_digits');
  if not assigned(TS_RESP_CTX_set_clock_precision_digits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_clock_precision_digits');
  Result := TS_RESP_CTX_set_clock_precision_digits(ctx,clock_precision_digits);
end;

procedure Load_TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  TS_RESP_CTX_add_flags := LoadLibCryptoFunction('TS_RESP_CTX_add_flags');
  if not assigned(TS_RESP_CTX_add_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_flags');
  TS_RESP_CTX_add_flags(ctx,flags);
end;

procedure Load_TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl;
begin
  TS_RESP_CTX_set_serial_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_serial_cb');
  if not assigned(TS_RESP_CTX_set_serial_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_serial_cb');
  TS_RESP_CTX_set_serial_cb(ctx,cb,data);
end;

procedure Load_TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl;
begin
  TS_RESP_CTX_set_time_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_time_cb');
  if not assigned(TS_RESP_CTX_set_time_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_time_cb');
  TS_RESP_CTX_set_time_cb(ctx,cb,data);
end;

procedure Load_TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl;
begin
  TS_RESP_CTX_set_extension_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_extension_cb');
  if not assigned(TS_RESP_CTX_set_extension_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_extension_cb');
  TS_RESP_CTX_set_extension_cb(ctx,cb,data);
end;

function Load_TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_status_info := LoadLibCryptoFunction('TS_RESP_CTX_set_status_info');
  if not assigned(TS_RESP_CTX_set_status_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_status_info');
  Result := TS_RESP_CTX_set_status_info(ctx,status,text);
end;

function Load_TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_status_info_cond := LoadLibCryptoFunction('TS_RESP_CTX_set_status_info_cond');
  if not assigned(TS_RESP_CTX_set_status_info_cond) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_status_info_cond');
  Result := TS_RESP_CTX_set_status_info_cond(ctx,status,text);
end;

function Load_TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_add_failure_info := LoadLibCryptoFunction('TS_RESP_CTX_add_failure_info');
  if not assigned(TS_RESP_CTX_add_failure_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_failure_info');
  Result := TS_RESP_CTX_add_failure_info(ctx,failure);
end;

function Load_TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl;
begin
  TS_RESP_CTX_get_request := LoadLibCryptoFunction('TS_RESP_CTX_get_request');
  if not assigned(TS_RESP_CTX_get_request) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_get_request');
  Result := TS_RESP_CTX_get_request(ctx);
end;

function Load_TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl;
begin
  TS_RESP_CTX_get_tst_info := LoadLibCryptoFunction('TS_RESP_CTX_get_tst_info');
  if not assigned(TS_RESP_CTX_get_tst_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_get_tst_info');
  Result := TS_RESP_CTX_get_tst_info(ctx);
end;

function Load_TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl;
begin
  TS_RESP_create_response := LoadLibCryptoFunction('TS_RESP_create_response');
  if not assigned(TS_RESP_create_response) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_create_response');
  Result := TS_RESP_create_response(ctx,req_bio);
end;

function Load_TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_verify_response := LoadLibCryptoFunction('TS_RESP_verify_response');
  if not assigned(TS_RESP_verify_response) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_response');
  Result := TS_RESP_verify_response(ctx,response);
end;

function Load_TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_verify_token := LoadLibCryptoFunction('TS_RESP_verify_token');
  if not assigned(TS_RESP_verify_token) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_token');
  Result := TS_RESP_verify_token(ctx,token);
end;

function Load_TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl;
begin
  TS_VERIFY_CTX_new := LoadLibCryptoFunction('TS_VERIFY_CTX_new');
  if not assigned(TS_VERIFY_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_new');
  Result := TS_VERIFY_CTX_new();
end;

procedure Load_TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl;
begin
  TS_VERIFY_CTX_init := LoadLibCryptoFunction('TS_VERIFY_CTX_init');
  if not assigned(TS_VERIFY_CTX_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_init');
  TS_VERIFY_CTX_init(ctx);
end;

procedure Load_TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl;
begin
  TS_VERIFY_CTX_free := LoadLibCryptoFunction('TS_VERIFY_CTX_free');
  if not assigned(TS_VERIFY_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_free');
  TS_VERIFY_CTX_free(ctx);
end;

procedure Load_TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl;
begin
  TS_VERIFY_CTX_cleanup := LoadLibCryptoFunction('TS_VERIFY_CTX_cleanup');
  if not assigned(TS_VERIFY_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_cleanup');
  TS_VERIFY_CTX_cleanup(ctx);
end;

function Load_TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_VERIFY_CTX_set_flags := LoadLibCryptoFunction('TS_VERIFY_CTX_set_flags');
  if not assigned(TS_VERIFY_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_flags');
  Result := TS_VERIFY_CTX_set_flags(ctx,f);
end;

function Load_TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_VERIFY_CTX_add_flags := LoadLibCryptoFunction('TS_VERIFY_CTX_add_flags');
  if not assigned(TS_VERIFY_CTX_add_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_add_flags');
  Result := TS_VERIFY_CTX_add_flags(ctx,f);
end;

function Load_TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl;
begin
  TS_VERIFY_CTX_set_data := LoadLibCryptoFunction('TS_VERIFY_CTX_set_data');
  if not assigned(TS_VERIFY_CTX_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_data');
  Result := TS_VERIFY_CTX_set_data(ctx,b);
end;

function Load_TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl;
begin
  TS_VERIFY_CTX_set_imprint := LoadLibCryptoFunction('TS_VERIFY_CTX_set_imprint');
  if not assigned(TS_VERIFY_CTX_set_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_imprint');
  Result := TS_VERIFY_CTX_set_imprint(ctx,hexstr,len);
end;

function Load_TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl;
begin
  TS_VERIFY_CTX_set_store := LoadLibCryptoFunction('TS_VERIFY_CTX_set_store');
  if not assigned(TS_VERIFY_CTX_set_store) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_store');
  Result := TS_VERIFY_CTX_set_store(ctx,s);
end;

function Load_TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl;
begin
  TS_REQ_to_TS_VERIFY_CTX := LoadLibCryptoFunction('TS_REQ_to_TS_VERIFY_CTX');
  if not assigned(TS_REQ_to_TS_VERIFY_CTX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_to_TS_VERIFY_CTX');
  Result := TS_REQ_to_TS_VERIFY_CTX(req,ctx);
end;

function Load_TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_print_bio := LoadLibCryptoFunction('TS_RESP_print_bio');
  if not assigned(TS_RESP_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_print_bio');
  Result := TS_RESP_print_bio(bio,a);
end;

function Load_TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_STATUS_INFO_print_bio := LoadLibCryptoFunction('TS_STATUS_INFO_print_bio');
  if not assigned(TS_STATUS_INFO_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_print_bio');
  Result := TS_STATUS_INFO_print_bio(bio,a);
end;

function Load_TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_print_bio := LoadLibCryptoFunction('TS_TST_INFO_print_bio');
  if not assigned(TS_TST_INFO_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_print_bio');
  Result := TS_TST_INFO_print_bio(bio,a);
end;

function Load_TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ASN1_INTEGER_print_bio := LoadLibCryptoFunction('TS_ASN1_INTEGER_print_bio');
  if not assigned(TS_ASN1_INTEGER_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ASN1_INTEGER_print_bio');
  Result := TS_ASN1_INTEGER_print_bio(bio,num);
end;

function Load_TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  TS_OBJ_print_bio := LoadLibCryptoFunction('TS_OBJ_print_bio');
  if not assigned(TS_OBJ_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_OBJ_print_bio');
  Result := TS_OBJ_print_bio(bio,obj);
end;

function Load_TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl;
begin
  TS_X509_ALGOR_print_bio := LoadLibCryptoFunction('TS_X509_ALGOR_print_bio');
  if not assigned(TS_X509_ALGOR_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_X509_ALGOR_print_bio');
  Result := TS_X509_ALGOR_print_bio(bio,alg);
end;

function Load_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  TS_MSG_IMPRINT_print_bio := LoadLibCryptoFunction('TS_MSG_IMPRINT_print_bio');
  if not assigned(TS_MSG_IMPRINT_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_print_bio');
  Result := TS_MSG_IMPRINT_print_bio(bio,msg);
end;

function Load_TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl;
begin
  TS_CONF_load_cert := LoadLibCryptoFunction('TS_CONF_load_cert');
  if not assigned(TS_CONF_load_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_cert');
  Result := TS_CONF_load_cert(file_);
end;

function Load_TS_CONF_load_key( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl;
begin
  TS_CONF_load_key := LoadLibCryptoFunction('TS_CONF_load_key');
  if not assigned(TS_CONF_load_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_key');
  Result := TS_CONF_load_key(file_,pass);
end;

function Load_TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_serial := LoadLibCryptoFunction('TS_CONF_set_serial');
  if not assigned(TS_CONF_set_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_serial');
  Result := TS_CONF_set_serial(conf,section,cb,ctx);
end;

function Load_TS_CONF_get_tsa_section(conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl;
begin
  TS_CONF_get_tsa_section := LoadLibCryptoFunction('TS_CONF_get_tsa_section');
  if not assigned(TS_CONF_get_tsa_section) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_get_tsa_section');
  Result := TS_CONF_get_tsa_section(conf,section);
end;

function Load_TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_crypto_device := LoadLibCryptoFunction('TS_CONF_set_crypto_device');
  if not assigned(TS_CONF_set_crypto_device) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_crypto_device');
  Result := TS_CONF_set_crypto_device(conf,section,device);
end;

function Load_TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_default_engine := LoadLibCryptoFunction('TS_CONF_set_default_engine');
  if not assigned(TS_CONF_set_default_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_default_engine');
  Result := TS_CONF_set_default_engine(name);
end;

function Load_TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_signer_cert := LoadLibCryptoFunction('TS_CONF_set_signer_cert');
  if not assigned(TS_CONF_set_signer_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_cert');
  Result := TS_CONF_set_signer_cert(conf,section,cert,ctx);
end;

function Load_TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_certs := LoadLibCryptoFunction('TS_CONF_set_certs');
  if not assigned(TS_CONF_set_certs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_certs');
  Result := TS_CONF_set_certs(conf,section,certs,ctx);
end;

function Load_TS_CONF_set_signer_key(conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_signer_key := LoadLibCryptoFunction('TS_CONF_set_signer_key');
  if not assigned(TS_CONF_set_signer_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_key');
  Result := TS_CONF_set_signer_key(conf,section,key,pass,ctx);
end;

function Load_TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_signer_digest := LoadLibCryptoFunction('TS_CONF_set_signer_digest');
  if not assigned(TS_CONF_set_signer_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_digest');
  Result := TS_CONF_set_signer_digest(conf,section,md,ctx);
end;

function Load_TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_def_policy := LoadLibCryptoFunction('TS_CONF_set_def_policy');
  if not assigned(TS_CONF_set_def_policy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_def_policy');
  Result := TS_CONF_set_def_policy(conf,section,policy,ctx);
end;

function Load_TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_policies := LoadLibCryptoFunction('TS_CONF_set_policies');
  if not assigned(TS_CONF_set_policies) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_policies');
  Result := TS_CONF_set_policies(conf,section,ctx);
end;

function Load_TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_digests := LoadLibCryptoFunction('TS_CONF_set_digests');
  if not assigned(TS_CONF_set_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_digests');
  Result := TS_CONF_set_digests(conf,section,ctx);
end;

function Load_TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_accuracy := LoadLibCryptoFunction('TS_CONF_set_accuracy');
  if not assigned(TS_CONF_set_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_accuracy');
  Result := TS_CONF_set_accuracy(conf,section,ctx);
end;

function Load_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_clock_precision_digits := LoadLibCryptoFunction('TS_CONF_set_clock_precision_digits');
  if not assigned(TS_CONF_set_clock_precision_digits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_clock_precision_digits');
  Result := TS_CONF_set_clock_precision_digits(conf,section,ctx);
end;

function Load_TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_ordering := LoadLibCryptoFunction('TS_CONF_set_ordering');
  if not assigned(TS_CONF_set_ordering) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ordering');
  Result := TS_CONF_set_ordering(conf,section,ctx);
end;

function Load_TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_tsa_name := LoadLibCryptoFunction('TS_CONF_set_tsa_name');
  if not assigned(TS_CONF_set_tsa_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_tsa_name');
  Result := TS_CONF_set_tsa_name(conf,section,ctx);
end;

function Load_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_ess_cert_id_chain := LoadLibCryptoFunction('TS_CONF_set_ess_cert_id_chain');
  if not assigned(TS_CONF_set_ess_cert_id_chain) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ess_cert_id_chain');
  Result := TS_CONF_set_ess_cert_id_chain(conf,section,ctx);
end;

function Load_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_ess_cert_id_digest := LoadLibCryptoFunction('TS_CONF_set_ess_cert_id_digest');
  if not assigned(TS_CONF_set_ess_cert_id_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ess_cert_id_digest');
  Result := TS_CONF_set_ess_cert_id_digest(conf,section,ctx);
end;


procedure UnLoad;
begin
  TS_REQ_new := Load_TS_REQ_new;
  TS_REQ_free := Load_TS_REQ_free;
  i2d_TS_REQ := Load_i2d_TS_REQ;
  d2i_TS_REQ := Load_d2i_TS_REQ;
  TS_REQ_dup := Load_TS_REQ_dup;
  d2i_TS_REQ_bio := Load_d2i_TS_REQ_bio;
  i2d_TS_REQ_bio := Load_i2d_TS_REQ_bio;
  TS_MSG_IMPRINT_new := Load_TS_MSG_IMPRINT_new;
  TS_MSG_IMPRINT_free := Load_TS_MSG_IMPRINT_free;
  i2d_TS_MSG_IMPRINT := Load_i2d_TS_MSG_IMPRINT;
  d2i_TS_MSG_IMPRINT := Load_d2i_TS_MSG_IMPRINT;
  TS_MSG_IMPRINT_dup := Load_TS_MSG_IMPRINT_dup;
  d2i_TS_MSG_IMPRINT_bio := Load_d2i_TS_MSG_IMPRINT_bio;
  i2d_TS_MSG_IMPRINT_bio := Load_i2d_TS_MSG_IMPRINT_bio;
  TS_RESP_new := Load_TS_RESP_new;
  TS_RESP_free := Load_TS_RESP_free;
  i2d_TS_RESP := Load_i2d_TS_RESP;
  d2i_TS_RESP := Load_d2i_TS_RESP;
  PKCS7_to_TS_TST_INFO := Load_PKCS7_to_TS_TST_INFO;
  TS_RESP_dup := Load_TS_RESP_dup;
  d2i_TS_RESP_bio := Load_d2i_TS_RESP_bio;
  i2d_TS_RESP_bio := Load_i2d_TS_RESP_bio;
  TS_STATUS_INFO_new := Load_TS_STATUS_INFO_new;
  TS_STATUS_INFO_free := Load_TS_STATUS_INFO_free;
  i2d_TS_STATUS_INFO := Load_i2d_TS_STATUS_INFO;
  d2i_TS_STATUS_INFO := Load_d2i_TS_STATUS_INFO;
  TS_STATUS_INFO_dup := Load_TS_STATUS_INFO_dup;
  TS_TST_INFO_new := Load_TS_TST_INFO_new;
  TS_TST_INFO_free := Load_TS_TST_INFO_free;
  i2d_TS_TST_INFO := Load_i2d_TS_TST_INFO;
  d2i_TS_TST_INFO := Load_d2i_TS_TST_INFO;
  TS_TST_INFO_dup := Load_TS_TST_INFO_dup;
  d2i_TS_TST_INFO_bio := Load_d2i_TS_TST_INFO_bio;
  i2d_TS_TST_INFO_bio := Load_i2d_TS_TST_INFO_bio;
  TS_ACCURACY_new := Load_TS_ACCURACY_new;
  TS_ACCURACY_free := Load_TS_ACCURACY_free;
  i2d_TS_ACCURACY := Load_i2d_TS_ACCURACY;
  d2i_TS_ACCURACY := Load_d2i_TS_ACCURACY;
  TS_ACCURACY_dup := Load_TS_ACCURACY_dup;
  ESS_ISSUER_SERIAL_new := Load_ESS_ISSUER_SERIAL_new;
  ESS_ISSUER_SERIAL_free := Load_ESS_ISSUER_SERIAL_free;
  i2d_ESS_ISSUER_SERIAL := Load_i2d_ESS_ISSUER_SERIAL;
  d2i_ESS_ISSUER_SERIAL := Load_d2i_ESS_ISSUER_SERIAL;
  ESS_ISSUER_SERIAL_dup := Load_ESS_ISSUER_SERIAL_dup;
  ESS_CERT_ID_new := Load_ESS_CERT_ID_new;
  ESS_CERT_ID_free := Load_ESS_CERT_ID_free;
  i2d_ESS_CERT_ID := Load_i2d_ESS_CERT_ID;
  d2i_ESS_CERT_ID := Load_d2i_ESS_CERT_ID;
  ESS_CERT_ID_dup := Load_ESS_CERT_ID_dup;
  ESS_SIGNING_CERT_new := Load_ESS_SIGNING_CERT_new;
  ESS_SIGNING_CERT_free := Load_ESS_SIGNING_CERT_free;
  i2d_ESS_SIGNING_CERT := Load_i2d_ESS_SIGNING_CERT;
  d2i_ESS_SIGNING_CERT := Load_d2i_ESS_SIGNING_CERT;
  ESS_SIGNING_CERT_dup := Load_ESS_SIGNING_CERT_dup;
  ESS_CERT_ID_V2_new := Load_ESS_CERT_ID_V2_new;
  ESS_CERT_ID_V2_free := Load_ESS_CERT_ID_V2_free;
  i2d_ESS_CERT_ID_V2 := Load_i2d_ESS_CERT_ID_V2;
  d2i_ESS_CERT_ID_V2 := Load_d2i_ESS_CERT_ID_V2;
  ESS_CERT_ID_V2_dup := Load_ESS_CERT_ID_V2_dup;
  ESS_SIGNING_CERT_V2_new := Load_ESS_SIGNING_CERT_V2_new;
  ESS_SIGNING_CERT_V2_free := Load_ESS_SIGNING_CERT_V2_free;
  i2d_ESS_SIGNING_CERT_V2 := Load_i2d_ESS_SIGNING_CERT_V2;
  d2i_ESS_SIGNING_CERT_V2 := Load_d2i_ESS_SIGNING_CERT_V2;
  ESS_SIGNING_CERT_V2_dup := Load_ESS_SIGNING_CERT_V2_dup;
  TS_REQ_set_version := Load_TS_REQ_set_version;
  TS_REQ_get_version := Load_TS_REQ_get_version;
  TS_STATUS_INFO_set_status := Load_TS_STATUS_INFO_set_status;
  TS_STATUS_INFO_get0_status := Load_TS_STATUS_INFO_get0_status;
  TS_REQ_set_msg_imprint := Load_TS_REQ_set_msg_imprint;
  TS_REQ_get_msg_imprint := Load_TS_REQ_get_msg_imprint;
  TS_MSG_IMPRINT_set_algo := Load_TS_MSG_IMPRINT_set_algo;
  TS_MSG_IMPRINT_get_algo := Load_TS_MSG_IMPRINT_get_algo;
  TS_MSG_IMPRINT_set_msg := Load_TS_MSG_IMPRINT_set_msg;
  TS_MSG_IMPRINT_get_msg := Load_TS_MSG_IMPRINT_get_msg;
  TS_REQ_set_policy_id := Load_TS_REQ_set_policy_id;
  TS_REQ_get_policy_id := Load_TS_REQ_get_policy_id;
  TS_REQ_set_nonce := Load_TS_REQ_set_nonce;
  TS_REQ_get_nonce := Load_TS_REQ_get_nonce;
  TS_REQ_set_cert_req := Load_TS_REQ_set_cert_req;
  TS_REQ_get_cert_req := Load_TS_REQ_get_cert_req;
  TS_REQ_ext_free := Load_TS_REQ_ext_free;
  TS_REQ_get_ext_count := Load_TS_REQ_get_ext_count;
  TS_REQ_get_ext_by_NID := Load_TS_REQ_get_ext_by_NID;
  TS_REQ_get_ext_by_OBJ := Load_TS_REQ_get_ext_by_OBJ;
  TS_REQ_get_ext_by_critical := Load_TS_REQ_get_ext_by_critical;
  TS_REQ_get_ext := Load_TS_REQ_get_ext;
  TS_REQ_delete_ext := Load_TS_REQ_delete_ext;
  TS_REQ_add_ext := Load_TS_REQ_add_ext;
  TS_REQ_get_ext_d2i := Load_TS_REQ_get_ext_d2i;
  TS_REQ_print_bio := Load_TS_REQ_print_bio;
  TS_RESP_set_status_info := Load_TS_RESP_set_status_info;
  TS_RESP_get_status_info := Load_TS_RESP_get_status_info;
  TS_RESP_set_tst_info := Load_TS_RESP_set_tst_info;
  TS_RESP_get_token := Load_TS_RESP_get_token;
  TS_RESP_get_tst_info := Load_TS_RESP_get_tst_info;
  TS_TST_INFO_set_version := Load_TS_TST_INFO_set_version;
  TS_TST_INFO_get_version := Load_TS_TST_INFO_get_version;
  TS_TST_INFO_set_policy_id := Load_TS_TST_INFO_set_policy_id;
  TS_TST_INFO_get_policy_id := Load_TS_TST_INFO_get_policy_id;
  TS_TST_INFO_set_msg_imprint := Load_TS_TST_INFO_set_msg_imprint;
  TS_TST_INFO_get_msg_imprint := Load_TS_TST_INFO_get_msg_imprint;
  TS_TST_INFO_set_serial := Load_TS_TST_INFO_set_serial;
  TS_TST_INFO_get_serial := Load_TS_TST_INFO_get_serial;
  TS_TST_INFO_set_time := Load_TS_TST_INFO_set_time;
  TS_TST_INFO_get_time := Load_TS_TST_INFO_get_time;
  TS_TST_INFO_set_accuracy := Load_TS_TST_INFO_set_accuracy;
  TS_TST_INFO_get_accuracy := Load_TS_TST_INFO_get_accuracy;
  TS_ACCURACY_set_seconds := Load_TS_ACCURACY_set_seconds;
  TS_ACCURACY_get_seconds := Load_TS_ACCURACY_get_seconds;
  TS_ACCURACY_set_millis := Load_TS_ACCURACY_set_millis;
  TS_ACCURACY_get_millis := Load_TS_ACCURACY_get_millis;
  TS_ACCURACY_set_micros := Load_TS_ACCURACY_set_micros;
  TS_ACCURACY_get_micros := Load_TS_ACCURACY_get_micros;
  TS_TST_INFO_set_ordering := Load_TS_TST_INFO_set_ordering;
  TS_TST_INFO_get_ordering := Load_TS_TST_INFO_get_ordering;
  TS_TST_INFO_set_nonce := Load_TS_TST_INFO_set_nonce;
  TS_TST_INFO_get_nonce := Load_TS_TST_INFO_get_nonce;
  TS_TST_INFO_set_tsa := Load_TS_TST_INFO_set_tsa;
  TS_TST_INFO_get_tsa := Load_TS_TST_INFO_get_tsa;
  TS_TST_INFO_ext_free := Load_TS_TST_INFO_ext_free;
  TS_TST_INFO_get_ext_count := Load_TS_TST_INFO_get_ext_count;
  TS_TST_INFO_get_ext_by_NID := Load_TS_TST_INFO_get_ext_by_NID;
  TS_TST_INFO_get_ext_by_OBJ := Load_TS_TST_INFO_get_ext_by_OBJ;
  TS_TST_INFO_get_ext_by_critical := Load_TS_TST_INFO_get_ext_by_critical;
  TS_TST_INFO_get_ext := Load_TS_TST_INFO_get_ext;
  TS_TST_INFO_delete_ext := Load_TS_TST_INFO_delete_ext;
  TS_TST_INFO_add_ext := Load_TS_TST_INFO_add_ext;
  TS_TST_INFO_get_ext_d2i := Load_TS_TST_INFO_get_ext_d2i;
  TS_RESP_CTX_new := Load_TS_RESP_CTX_new;
  TS_RESP_CTX_free := Load_TS_RESP_CTX_free;
  TS_RESP_CTX_set_signer_cert := Load_TS_RESP_CTX_set_signer_cert;
  TS_RESP_CTX_set_signer_key := Load_TS_RESP_CTX_set_signer_key;
  TS_RESP_CTX_set_signer_digest := Load_TS_RESP_CTX_set_signer_digest;
  TS_RESP_CTX_set_ess_cert_id_digest := Load_TS_RESP_CTX_set_ess_cert_id_digest;
  TS_RESP_CTX_set_def_policy := Load_TS_RESP_CTX_set_def_policy;
  TS_RESP_CTX_add_policy := Load_TS_RESP_CTX_add_policy;
  TS_RESP_CTX_add_md := Load_TS_RESP_CTX_add_md;
  TS_RESP_CTX_set_accuracy := Load_TS_RESP_CTX_set_accuracy;
  TS_RESP_CTX_set_clock_precision_digits := Load_TS_RESP_CTX_set_clock_precision_digits;
  TS_RESP_CTX_add_flags := Load_TS_RESP_CTX_add_flags;
  TS_RESP_CTX_set_serial_cb := Load_TS_RESP_CTX_set_serial_cb;
  TS_RESP_CTX_set_time_cb := Load_TS_RESP_CTX_set_time_cb;
  TS_RESP_CTX_set_extension_cb := Load_TS_RESP_CTX_set_extension_cb;
  TS_RESP_CTX_set_status_info := Load_TS_RESP_CTX_set_status_info;
  TS_RESP_CTX_set_status_info_cond := Load_TS_RESP_CTX_set_status_info_cond;
  TS_RESP_CTX_add_failure_info := Load_TS_RESP_CTX_add_failure_info;
  TS_RESP_CTX_get_request := Load_TS_RESP_CTX_get_request;
  TS_RESP_CTX_get_tst_info := Load_TS_RESP_CTX_get_tst_info;
  TS_RESP_create_response := Load_TS_RESP_create_response;
  TS_RESP_verify_response := Load_TS_RESP_verify_response;
  TS_RESP_verify_token := Load_TS_RESP_verify_token;
  TS_VERIFY_CTX_new := Load_TS_VERIFY_CTX_new;
  TS_VERIFY_CTX_init := Load_TS_VERIFY_CTX_init;
  TS_VERIFY_CTX_free := Load_TS_VERIFY_CTX_free;
  TS_VERIFY_CTX_cleanup := Load_TS_VERIFY_CTX_cleanup;
  TS_VERIFY_CTX_set_flags := Load_TS_VERIFY_CTX_set_flags;
  TS_VERIFY_CTX_add_flags := Load_TS_VERIFY_CTX_add_flags;
  TS_VERIFY_CTX_set_data := Load_TS_VERIFY_CTX_set_data;
  TS_VERIFY_CTX_set_imprint := Load_TS_VERIFY_CTX_set_imprint;
  TS_VERIFY_CTX_set_store := Load_TS_VERIFY_CTX_set_store;
  TS_REQ_to_TS_VERIFY_CTX := Load_TS_REQ_to_TS_VERIFY_CTX;
  TS_RESP_print_bio := Load_TS_RESP_print_bio;
  TS_STATUS_INFO_print_bio := Load_TS_STATUS_INFO_print_bio;
  TS_TST_INFO_print_bio := Load_TS_TST_INFO_print_bio;
  TS_ASN1_INTEGER_print_bio := Load_TS_ASN1_INTEGER_print_bio;
  TS_OBJ_print_bio := Load_TS_OBJ_print_bio;
  TS_X509_ALGOR_print_bio := Load_TS_X509_ALGOR_print_bio;
  TS_MSG_IMPRINT_print_bio := Load_TS_MSG_IMPRINT_print_bio;
  TS_CONF_load_cert := Load_TS_CONF_load_cert;
  TS_CONF_load_key := Load_TS_CONF_load_key;
  TS_CONF_set_serial := Load_TS_CONF_set_serial;
  TS_CONF_get_tsa_section := Load_TS_CONF_get_tsa_section;
  TS_CONF_set_crypto_device := Load_TS_CONF_set_crypto_device;
  TS_CONF_set_default_engine := Load_TS_CONF_set_default_engine;
  TS_CONF_set_signer_cert := Load_TS_CONF_set_signer_cert;
  TS_CONF_set_certs := Load_TS_CONF_set_certs;
  TS_CONF_set_signer_key := Load_TS_CONF_set_signer_key;
  TS_CONF_set_signer_digest := Load_TS_CONF_set_signer_digest;
  TS_CONF_set_def_policy := Load_TS_CONF_set_def_policy;
  TS_CONF_set_policies := Load_TS_CONF_set_policies;
  TS_CONF_set_digests := Load_TS_CONF_set_digests;
  TS_CONF_set_accuracy := Load_TS_CONF_set_accuracy;
  TS_CONF_set_clock_precision_digits := Load_TS_CONF_set_clock_precision_digits;
  TS_CONF_set_ordering := Load_TS_CONF_set_ordering;
  TS_CONF_set_tsa_name := Load_TS_CONF_set_tsa_name;
  TS_CONF_set_ess_cert_id_chain := Load_TS_CONF_set_ess_cert_id_chain;
  TS_CONF_set_ess_cert_id_digest := Load_TS_CONF_set_ess_cert_id_digest;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
