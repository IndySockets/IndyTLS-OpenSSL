  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_x509_vfy.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_x509_vfy.h2pas
     and this file regenerated. IdOpenSSLHeaders_x509_vfy.h2pas is distributed with the full Indy
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

unit IdOpenSSLHeaders_x509_vfy;

interface

// Headers for OpenSSL 1.1.1
// x509_vfy.h


{$MINENUMSIZE 4}

uses
  IdCTypes,
  IdGlobal,
  IdSSLOpenSSLConsts,
  IdOpenSSLHeaders_ssl,
  IdOpenSSLHeaders_ossl_typ;

const
  X509_L_FILE_LOAD = 1;
  X509_L_ADD_DIR   = 2;

  X509_V_OK                                       = 0;
  X509_V_ERR_UNSPECIFIED                          = 1;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            = 2;
  X509_V_ERR_UNABLE_TO_GET_CRL                    = 3;
  X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     = 4;
  X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      = 5;
  X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   = 6;
  X509_V_ERR_CERT_SIGNATURE_FAILURE               = 7;
  X509_V_ERR_CRL_SIGNATURE_FAILURE                = 8;
  X509_V_ERR_CERT_NOT_YET_VALID                   = 9;
  X509_V_ERR_CERT_HAS_EXPIRED                     = 10;
  X509_V_ERR_CRL_NOT_YET_VALID                    = 11;
  X509_V_ERR_CRL_HAS_EXPIRED                      = 12;
  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       = 13;
  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        = 14;
  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       = 15;
  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       = 16;
  X509_V_ERR_OUT_OF_MEM                           = 17;
  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          = 18;
  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            = 19;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    = 20;
  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      = 21;
  X509_V_ERR_CERT_CHAIN_TOO_LONG                  = 22;
  X509_V_ERR_CERT_REVOKED                         = 23;
  X509_V_ERR_INVALID_CA                           = 24;
  X509_V_ERR_PATH_LENGTH_EXCEEDED                 = 25;
  X509_V_ERR_INVALID_PURPOSE                      = 26;
  X509_V_ERR_CERT_UNTRUSTED                       = 27;
  X509_V_ERR_CERT_REJECTED                        = 28;
  (* These are 'informational' when looking for issuer cert *)
  X509_V_ERR_SUBJECT_ISSUER_MISMATCH              = 29;
  X509_V_ERR_AKID_SKID_MISMATCH                   = 30;
  X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          = 31;
  X509_V_ERR_KEYUSAGE_NO_CERTSIGN                 = 32;
  X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             = 33;
  X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         = 34;
  X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 = 35;
  X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     = 36;
  X509_V_ERR_INVALID_NON_CA                       = 37;
  X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED           = 38;
  X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        = 39;
  X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED       = 40;
  X509_V_ERR_INVALID_EXTENSION                    = 41;
  X509_V_ERR_INVALID_POLICY_EXTENSION             = 42;
  X509_V_ERR_NO_EXPLICIT_POLICY                   = 43;
  X509_V_ERR_DIFFERENT_CRL_SCOPE                  = 44;
  X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE        = 45;
  X509_V_ERR_UNNESTED_RESOURCE                    = 46;
  X509_V_ERR_PERMITTED_VIOLATION                  = 47;
  X509_V_ERR_EXCLUDED_VIOLATION                   = 48;
  X509_V_ERR_SUBTREE_MINMAX                       = 49;
  (* The application is not happy *)
  X509_V_ERR_APPLICATION_VERIFICATION             = 50;
  X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE          = 51;
  X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX        = 52;
  X509_V_ERR_UNSUPPORTED_NAME_SYNTAX              = 53;
  X509_V_ERR_CRL_PATH_VALIDATION_ERROR            = 54;
  (* Another issuer check debug option *)
  X509_V_ERR_PATH_LOOP                            = 55;
  (* Suite B mode algorithm violation *)
  X509_V_ERR_SUITE_B_INVALID_VERSION              = 56;
  X509_V_ERR_SUITE_B_INVALID_ALGORITHM            = 57;
  X509_V_ERR_SUITE_B_INVALID_CURVE                = 58;
  X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM  = 59;
  X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED              = 60;
  X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61;
  (* Host, email and IP check errors *)
  X509_V_ERR_HOSTNAME_MISMATCH                    = 62;
  X509_V_ERR_EMAIL_MISMATCH                       = 63;
  X509_V_ERR_IP_ADDRESS_MISMATCH                  = 64;
  (* DANE TLSA errors *)
  X509_V_ERR_DANE_NO_MATCH                        = 65;
  (* security level errors *)
  X509_V_ERR_EE_KEY_TOO_SMALL                     = 66;
  X509_V_ERR_CA_KEY_TOO_SMALL                     = 67;
  X509_V_ERR_CA_MD_TOO_WEAK                       = 68;
  (* Caller error *)
  X509_V_ERR_INVALID_CALL                         = 69;
  (* Issuer lookup error *)
  X509_V_ERR_STORE_LOOKUP                         = 70;
  (* Certificate transparency *)
  X509_V_ERR_NO_VALID_SCTS                        = 71;

  X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION         = 72;
  (* OCSP status errors *)
  X509_V_ERR_OCSP_VERIFY_NEEDED                   = 73;  (* Need OCSP verification *)
  X509_V_ERR_OCSP_VERIFY_FAILED                   = 74;  (* Couldn't verify cert through OCSP *)
  X509_V_ERR_OCSP_CERT_UNKNOWN                    = 75;  (* Certificate wasn't recognized by the OCSP responder *)

  (* Certificate verify flags *)

  (* Use check time instead of current time *)
  X509_V_FLAG_USE_CHECK_TIME       = $2;
  (* Lookup CRLs *)
  X509_V_FLAG_CRL_CHECK            = $4;
  (* Lookup CRLs for whole chain *)
  X509_V_FLAG_CRL_CHECK_ALL        = $8;
  (* Ignore unhandled critical extensions *)
  X509_V_FLAG_IGNORE_CRITICAL      = $10;
  (* Disable workarounds for broken certificates *)
  X509_V_FLAG_X509_STRICT          = $20;
  (* Enable proxy certificate validation *)
  X509_V_FLAG_ALLOW_PROXY_CERTS    = $40;
  (* Enable policy checking *)
  X509_V_FLAG_POLICY_CHECK         = $80;
  (* Policy variable require-explicit-policy *)
  X509_V_FLAG_EXPLICIT_POLICY      = $100;
  (* Policy variable inhibit-any-policy *)
  X509_V_FLAG_INHIBIT_ANY          = $200;
  (* Policy variable inhibit-policy-mapping *)
  X509_V_FLAG_INHIBIT_MAP          = $400;
  (* Notify callback that policy is OK *)
  X509_V_FLAG_NOTIFY_POLICY        = $800;
  (* Extended CRL features such as indirect CRLs, alternate CRL signing keys *)
  X509_V_FLAG_EXTENDED_CRL_SUPPORT = $1000;
  (* Delta CRL support *)
  X509_V_FLAG_USE_DELTAS           = $2000;
  (* Check self-signed CA signature *)
  X509_V_FLAG_CHECK_SS_SIGNATURE   = $4000;
  (* Use trusted store first *)
  X509_V_FLAG_TRUSTED_FIRST        = $8000;
  (* Suite B 128 bit only mode: not normally used *)
  X509_V_FLAG_SUITEB_128_LOS_ONLY  = $10000;
  (* Suite B 192 bit only mode *)
  X509_V_FLAG_SUITEB_192_LOS       = $20000;
  (* Suite B 128 bit mode allowing 192 bit algorithms *)
  X509_V_FLAG_SUITEB_128_LOS       = $30000;
  (* Allow partial chains if at least one certificate is in trusted store *)
  X509_V_FLAG_PARTIAL_CHAIN        = $80000;
  (*
   * If the initial chain is not trusted, do not attempt to build an alternative
   * chain. Alternate chain checking was introduced 1.1.0. Setting this flag
   * will force the behaviour to match that of previous versions.
   *)
  X509_V_FLAG_NO_ALT_CHAINS        = $100000;
  (* Do not check certificate/CRL validity against current time *)
  X509_V_FLAG_NO_CHECK_TIME        = $200000;

  X509_VP_FLAG_DEFAULT             = $1;
  X509_VP_FLAG_OVERWRITE           = $2;
  X509_VP_FLAG_RESET_FLAGS         = $4;
  X509_VP_FLAG_LOCKED              = $8;
  X509_VP_FLAG_ONCE                = $10;

  (* Internal use: mask of policy related options *)
  X509_V_FLAG_POLICY_MASK = X509_V_FLAG_POLICY_CHECK or X509_V_FLAG_EXPLICIT_POLICY
    or X509_V_FLAG_INHIBIT_ANY or X509_V_FLAG_INHIBIT_MAP;


  DANE_FLAG_NO_DANE_EE_NAMECHECKS = TIdC_Long(1) shl 0;

  (* Non positive return values are errors *)
  X509_PCY_TREE_FAILURE  = -2; (* Failure to satisfy explicit policy *)
  X509_PCY_TREE_INVALID  = -1; (* Inconsistent or invalid extensions *)
  X509_PCY_TREE_INTERNAL = 0; (* Internal error, most likely malloc *)

  (*
   * Positive return values form a bit mask, all but the first are internal to
   * the library and don't appear in results from X509_policy_check().
   *)
  X509_PCY_TREE_VALID    = 1; (* The policy tree is valid *)
  X509_PCY_TREE_EMPTY    = 2; (* The policy tree is empty *)
  X509_PCY_TREE_EXPLICIT = 4; (* Explicit policy required *)

type
  (*-
  SSL_CTX -> X509_STORE
                  -> X509_LOOKUP
                          ->X509_LOOKUP_METHOD
                  -> X509_LOOKUP
                          ->X509_LOOKUP_METHOD

  SSL     -> X509_STORE_CTX
                  ->X509_STORE

  The X509_STORE holds the tables etc for verification stuff.
  A X509_STORE_CTX is used while validating a single certificate.
  The X509_STORE has X509_LOOKUPs for looking up certs.
  The X509_STORE then calls a function to actually verify the
  certificate chain.
  *)

  X509_LOOKUP_TYPE = (
    X509_LU_NONE = 0,
    X509_LU_X509,
    X509_LU_CRL
  );

  X509_STORE_CTX_verify_cb = function(v1: TIdC_INT; v2: PX509_STORE_CTX): TIdC_INT;
  X509_STORE_CTX_verify_fn = function(v1: PX509_STORE_CTX): TIdC_INT;
  X509_STORE_CTX_get_issuer_fn = function(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT;
  X509_STORE_CTX_check_issued_fn = function(ctx: PX509_STORE_CTX; x: PX509; issuer: PX509): TIdC_INT;
  X509_STORE_CTX_check_revocation_fn = function(ctx: PX509_STORE_CTX): TIdC_INT;
  X509_STORE_CTX_get_crl_fn = function(ctx: PX509_STORE_CTX; crl: PPX509_CRL; x: PX509): TIdC_INT;
  X509_STORE_CTX_check_crl_fn = function(ctx: PX509_STORE_CTX; crl: PX509_CRL): TIdC_INT;
  X509_STORE_CTX_cert_crl_fn = function(ctx: PX509_STORE_CTX; crl: PX509_CRL; x: PX509): TIdC_INT;
  X509_STORE_CTX_check_policy_fn = function(ctx: PX509_STORE_CTX): TIdC_INT;
//  typedef STACK_OF(X509) *(*X509_STORE_CTX_lookup_certs_fn)(X509_STORE_CTX *ctx,
//                                                            X509_NAME *nm);
//  typedef STACK_OF(X509_CRL) *(*X509_STORE_CTX_lookup_crls_fn)(X509_STORE_CTX *ctx,
//                                                               X509_NAME *nm);
  X509_STORE_CTX_cleanup_fn = function(ctx: PX509_STORE_CTX): TIdC_INT;

  X509_LOOKUP_ctrl_fn = function(ctx: PX509_LOOKUP; cmd: TIdC_INT;
    const argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl;
  X509_LOOKUP_get_by_subject_fn = function(ctx: PX509_LOOKUP;
    type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl;
  X509_LOOKUP_get_by_issuer_serial_fn = function(ctx: PX509_LOOKUP;
    type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl;
  X509_LOOKUP_get_by_fingerprint_fn = function(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE;
    const bytes: PByte; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl;
  X509_LOOKUP_get_by_alias_fn = function(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE;
    const str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl;

  //DEFINE_STACK_OF(X509_LOOKUP)
  //DEFINE_STACK_OF(X509_OBJECT)
  //DEFINE_STACK_OF(X509_VERIFY_PARAM)

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM X509_STORE_set_depth}
  {$EXTERNALSYM X509_STORE_CTX_set_depth}
  {$EXTERNALSYM X509_OBJECT_up_ref_count}
  {$EXTERNALSYM X509_OBJECT_new} {introduced 1.1.0}
  {$EXTERNALSYM X509_OBJECT_free} {introduced 1.1.0}
  {$EXTERNALSYM X509_OBJECT_get_type} {introduced 1.1.0}
  {$EXTERNALSYM X509_OBJECT_get0_X509} {introduced 1.1.0}
  {$EXTERNALSYM X509_OBJECT_set1_X509} {introduced 1.1.0}
  {$EXTERNALSYM X509_OBJECT_get0_X509_CRL} {introduced 1.1.0}
  {$EXTERNALSYM X509_OBJECT_set1_X509_CRL} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_new}
  {$EXTERNALSYM X509_STORE_free}
  {$EXTERNALSYM X509_STORE_lock} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_unlock} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_up_ref} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_flags}
  {$EXTERNALSYM X509_STORE_set_purpose}
  {$EXTERNALSYM X509_STORE_set_trust}
  {$EXTERNALSYM X509_STORE_set1_param}
  {$EXTERNALSYM X509_STORE_get0_param} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_verify} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_set_verify} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_verify} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_verify_cb}
  {$EXTERNALSYM X509_STORE_get_verify_cb} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_get_issuer} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_get_issuer} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_check_issued} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_check_issued} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_check_revocation} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_check_revocation} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_get_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_get_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_check_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_check_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_cert_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_cert_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_check_policy} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_check_policy} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_cleanup} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_cleanup} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_set_ex_data} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_get_ex_data} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_new}
  {$EXTERNALSYM X509_STORE_CTX_get1_issuer}
  {$EXTERNALSYM X509_STORE_CTX_free}
  {$EXTERNALSYM X509_STORE_CTX_cleanup}
  {$EXTERNALSYM X509_STORE_CTX_get0_store}
  {$EXTERNALSYM X509_STORE_CTX_get0_cert} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_set_verify_cb}
  {$EXTERNALSYM X509_STORE_CTX_get_verify_cb} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_verify} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_get_issuer} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_check_issued} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_check_revocation} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_get_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_check_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_cert_crl} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_check_policy} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_cleanup} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_add_lookup}
  {$EXTERNALSYM X509_LOOKUP_hash_dir}
  {$EXTERNALSYM X509_LOOKUP_file}
  {$EXTERNALSYM X509_LOOKUP_meth_new} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_free} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_set_ctrl} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_get_ctrl} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_subject} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_subject} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_issuer_serial} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_issuer_serial} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_fingerprint} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_fingerprint} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_alias} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_alias} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_add_cert}
  {$EXTERNALSYM X509_STORE_add_crl}
  {$EXTERNALSYM X509_STORE_CTX_get_by_subject} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_obj_by_subject} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_ctrl}
  {$EXTERNALSYM X509_load_cert_file}
  {$EXTERNALSYM X509_load_crl_file}
  {$EXTERNALSYM X509_load_cert_crl_file}
  {$EXTERNALSYM X509_LOOKUP_new}
  {$EXTERNALSYM X509_LOOKUP_free}
  {$EXTERNALSYM X509_LOOKUP_init}
  {$EXTERNALSYM X509_LOOKUP_by_subject}
  {$EXTERNALSYM X509_LOOKUP_by_issuer_serial}
  {$EXTERNALSYM X509_LOOKUP_by_fingerprint}
  {$EXTERNALSYM X509_LOOKUP_by_alias}
  {$EXTERNALSYM X509_LOOKUP_set_method_data} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_get_method_data} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_get_store} {introduced 1.1.0}
  {$EXTERNALSYM X509_LOOKUP_shutdown}
  {$EXTERNALSYM X509_STORE_load_locations}
  {$EXTERNALSYM X509_STORE_set_default_paths}
  {$EXTERNALSYM X509_STORE_CTX_set_ex_data}
  {$EXTERNALSYM X509_STORE_CTX_get_ex_data}
  {$EXTERNALSYM X509_STORE_CTX_get_error}
  {$EXTERNALSYM X509_STORE_CTX_set_error}
  {$EXTERNALSYM X509_STORE_CTX_get_error_depth}
  {$EXTERNALSYM X509_STORE_CTX_set_error_depth} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get_current_cert}
  {$EXTERNALSYM X509_STORE_CTX_set_current_cert} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get0_current_issuer}
  {$EXTERNALSYM X509_STORE_CTX_get0_current_crl}
  {$EXTERNALSYM X509_STORE_CTX_get0_parent_ctx}
  {$EXTERNALSYM X509_STORE_CTX_set_cert}
  {$EXTERNALSYM X509_STORE_CTX_set_purpose}
  {$EXTERNALSYM X509_STORE_CTX_set_trust}
  {$EXTERNALSYM X509_STORE_CTX_purpose_inherit}
  {$EXTERNALSYM X509_STORE_CTX_set_flags}
  {$EXTERNALSYM X509_STORE_CTX_get0_policy_tree}
  {$EXTERNALSYM X509_STORE_CTX_get_explicit_policy}
  {$EXTERNALSYM X509_STORE_CTX_get_num_untrusted} {introduced 1.1.0}
  {$EXTERNALSYM X509_STORE_CTX_get0_param}
  {$EXTERNALSYM X509_STORE_CTX_set0_param}
  {$EXTERNALSYM X509_STORE_CTX_set_default}
  {$EXTERNALSYM X509_STORE_CTX_set0_dane} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_new}
  {$EXTERNALSYM X509_VERIFY_PARAM_free}
  {$EXTERNALSYM X509_VERIFY_PARAM_inherit}
  {$EXTERNALSYM X509_VERIFY_PARAM_set1}
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_name}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_flags}
  {$EXTERNALSYM X509_VERIFY_PARAM_clear_flags}
  {$EXTERNALSYM X509_VERIFY_PARAM_get_flags}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_purpose}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_trust}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_depth}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_auth_level} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_add0_policy}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_inh_flags} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_get_inh_flags} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_host}
  {$EXTERNALSYM X509_VERIFY_PARAM_add1_host}
  {$EXTERNALSYM X509_VERIFY_PARAM_set_hostflags}
  {$EXTERNALSYM X509_VERIFY_PARAM_get_hostflags} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_get0_peername}
  {$EXTERNALSYM X509_VERIFY_PARAM_move_peername} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_email}
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_ip}
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_ip_asc}
  {$EXTERNALSYM X509_VERIFY_PARAM_get_depth}
  {$EXTERNALSYM X509_VERIFY_PARAM_get_auth_level} {introduced 1.1.0}
  {$EXTERNALSYM X509_VERIFY_PARAM_get0_name}
  {$EXTERNALSYM X509_VERIFY_PARAM_add0_table}
  {$EXTERNALSYM X509_VERIFY_PARAM_get_count}
  {$EXTERNALSYM X509_VERIFY_PARAM_get0}
  {$EXTERNALSYM X509_VERIFY_PARAM_lookup}
  {$EXTERNALSYM X509_VERIFY_PARAM_table_cleanup}
  {$EXTERNALSYM X509_policy_tree_free}
  {$EXTERNALSYM X509_policy_tree_level_count}
  {$EXTERNALSYM X509_policy_tree_get0_level}
  {$EXTERNALSYM X509_policy_level_node_count}
  {$EXTERNALSYM X509_policy_level_get0_node}
  {$EXTERNALSYM X509_policy_node_get0_policy}
  {$EXTERNALSYM X509_policy_node_get0_parent}
{helper_functions}
function X509_LOOKUP_load_file(ctx: PX509_LOOKUP; name: PIdAnsiChar; type_: TIdC_LONG): TIdC_INT;
{\helper_functions}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM X509_STORE_CTX_get_app_data} {removed 1.0.0}
  X509_STORE_set_depth: function (store: PX509_STORE; depth: TIdC_INT): TIdC_INT; cdecl = nil;

  X509_STORE_CTX_set_depth: procedure (ctx: PX509_STORE_CTX; depth: TIdC_INT); cdecl = nil;

  //# define X509_STORE_CTX_set_app_data(ctx,data) \
  //        X509_STORE_CTX_set_ex_data(ctx,0,data)
  //# define X509_STORE_CTX_get_app_data(ctx) \
  //        X509_STORE_CTX_get_ex_data(ctx,0)
  X509_STORE_CTX_get_app_data: function (ctx: PX509_STORE_CTX): Pointer; cdecl = nil; {removed 1.0.0}
  //
  //# define X509_LOOKUP_load_file(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(TIdC_LONG)(type),NULL)
  //
  //# define X509_LOOKUP_add_dir(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(TIdC_LONG)(type),NULL)
  //
  //TIdC_INT X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
  //                               X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
  //                                             X509_LOOKUP_TYPE type,
  //                                             X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
  //                                        X509_OBJECT *x);
  X509_OBJECT_up_ref_count: function (a: PX509_OBJECT): TIdC_INT; cdecl = nil;
  X509_OBJECT_new: function : PX509_OBJECT; cdecl = nil; {introduced 1.1.0}
  X509_OBJECT_free: procedure (a: PX509_OBJECT); cdecl = nil; {introduced 1.1.0}
  X509_OBJECT_get_type: function (const a: PX509_OBJECT): X509_LOOKUP_TYPE; cdecl = nil; {introduced 1.1.0}
  X509_OBJECT_get0_X509: function (const a: PX509_OBJECT): PX509; cdecl = nil; {introduced 1.1.0}
  X509_OBJECT_set1_X509: function (a: PX509_OBJECT; obj: PX509): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_OBJECT_get0_X509_CRL: function (a: PX509_OBJECT): PX509_CRL; cdecl = nil; {introduced 1.1.0}
  X509_OBJECT_set1_X509_CRL: function (a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_STORE_new: function : PX509_STORE; cdecl = nil;
  X509_STORE_free: procedure (v: PX509_STORE); cdecl = nil;
  X509_STORE_lock: function (ctx: PX509_STORE): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_STORE_unlock: function (ctx: PX509_STORE): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_STORE_up_ref: function (v: PX509_STORE): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  //STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *v);

  //STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *st, X509_NAME *nm);
  //STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(X509_STORE_CTX *st, X509_NAME *nm);
  X509_STORE_set_flags: function (ctx: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  X509_STORE_set_purpose: function (ctx: PX509_STORE; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_STORE_set_trust: function (ctx: PX509_STORE; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_STORE_set1_param: function (ctx: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  X509_STORE_get0_param: function (ctx: PX509_STORE): PX509_VERIFY_PARAM; cdecl = nil; {introduced 1.1.0}

  X509_STORE_set_verify: procedure (ctx: PX509_STORE; verify: X509_STORE_CTX_verify_fn); cdecl = nil; {introduced 1.1.0}
  //#define X509_STORE_set_verify_func(ctx, func) \
  //            X509_STORE_set_verify((ctx),(func))
  X509_STORE_CTX_set_verify: procedure (ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_verify: function (ctx: PX509_STORE): X509_STORE_CTX_verify_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_verify_cb: procedure (ctx: PX509_STORE; verify_cb: X509_STORE_CTX_verify_cb); cdecl = nil;
  //# define X509_STORE_set_verify_cb_func(ctx,func) \
  //            X509_STORE_set_verify_cb((ctx),(func))
  X509_STORE_get_verify_cb: function (ctx: PX509_STORE): X509_STORE_CTX_verify_cb; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_get_issuer: procedure (ctx: PX509_STORE; get_issuer: X509_STORE_CTX_get_issuer_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_get_issuer: function (ctx: PX509_STORE): X509_STORE_CTX_get_issuer_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_check_issued: procedure (ctx: PX509_STORE; check_issued: X509_STORE_CTX_check_issued_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_check_issued: function (ctx: PX509_STORE): X509_STORE_CTX_check_issued_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_check_revocation: procedure (ctx: PX509_STORE; check_revocation: X509_STORE_CTX_check_revocation_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_check_revocation: function (ctx: PX509_STORE): X509_STORE_CTX_check_revocation_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_get_crl: procedure (ctx: PX509_STORE; get_crl: X509_STORE_CTX_get_crl_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_get_crl: function (ctx: PX509_STORE): X509_STORE_CTX_get_crl_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_check_crl: procedure (ctx: PX509_STORE; check_crl: X509_STORE_CTX_check_crl_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_check_crl: function (ctx: PX509_STORE): X509_STORE_CTX_check_crl_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_cert_crl: procedure (ctx: PX509_STORE; cert_crl: X509_STORE_CTX_cert_crl_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_cert_crl: function (ctx: PX509_STORE): X509_STORE_CTX_cert_crl_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_set_check_policy: procedure (ctx: PX509_STORE; check_policy: X509_STORE_CTX_check_policy_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_check_policy: function (ctx: PX509_STORE): X509_STORE_CTX_check_policy_fn; cdecl = nil; {introduced 1.1.0}
//  procedure X509_STORE_set_lookup_certs(ctx: PX509_STORE; lookup_certs: X509_STORE_CTX_lookup_certs_fn);
//  function X509_STORE_get_lookup_certs(ctx: PX509_STORE): X509_STORE_CTX_lookup_certs_fn;
//  procedure X509_STORE_set_lookup_crls(ctx: PX509_STORE; lookup_crls: X509_STORE_CTX_lookup_crls_fn);
//  #define X509_STORE_set_lookup_crls_cb(ctx, func) \
//      X509_STORE_set_lookup_crls((ctx), (func))
//  function X509_STORE_get_lookup_crls(ctx: PX509_STORE): X509_STORE_CTX_lookup_crls_fn;
  X509_STORE_set_cleanup: procedure (ctx: PX509_STORE; cleanup: X509_STORE_CTX_cleanup_fn); cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_cleanup: function (ctx: PX509_STORE): X509_STORE_CTX_cleanup_fn; cdecl = nil; {introduced 1.1.0}

  //#define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)
  X509_STORE_set_ex_data: function (ctx: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_STORE_get_ex_data: function (ctx: PX509_STORE; idx: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}

  X509_STORE_CTX_new: function : PX509_STORE_CTX; cdecl = nil;

  X509_STORE_CTX_get1_issuer: function (issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; cdecl = nil;

  X509_STORE_CTX_free: procedure (ctx: PX509_STORE_CTX); cdecl = nil;
//  TIdC_INT X509_STORE_CTX_init(ctx: PX509_STORE_CTX; store: PX509_STORE; x509: PX509; chain: P STACK_OF(X509));
//  procedure X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: P STACK_OF(X509));
  X509_STORE_CTX_cleanup: procedure (ctx: PX509_STORE_CTX); cdecl = nil;

  X509_STORE_CTX_get0_store: function (ctx: PX509_STORE_CTX): PX509_STORE; cdecl = nil;
  X509_STORE_CTX_get0_cert: function (ctx: PX509_STORE_CTX): PX509; cdecl = nil; {introduced 1.1.0}
  //STACK_OF(X509)* X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *ctx);
  //void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
  X509_STORE_CTX_set_verify_cb: procedure (ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_cb); cdecl = nil;
  X509_STORE_CTX_get_verify_cb: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_cb; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_verify: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_get_issuer: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_get_issuer_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_issued: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_issued_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_revocation: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_revocation_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_get_crl: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_get_crl_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_crl: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_crl_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_cert_crl: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_cert_crl_fn; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_policy: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_check_policy_fn; cdecl = nil; {introduced 1.1.0}
//  function X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_certs_fn;
//  function X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_crls_fn;
  X509_STORE_CTX_get_cleanup: function (ctx: PX509_STORE_CTX): X509_STORE_CTX_cleanup_fn; cdecl = nil; {introduced 1.1.0}

  X509_STORE_add_lookup: function (v: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl = nil;
  X509_LOOKUP_hash_dir: function : PX509_LOOKUP_METHOD; cdecl = nil;
  X509_LOOKUP_file: function : PX509_LOOKUP_METHOD; cdecl = nil;

  X509_LOOKUP_meth_new: function (const name: PIdAnsiChar): PX509_LOOKUP_METHOD; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_meth_free: procedure (method: PX509_LOOKUP_METHOD); cdecl = nil; {introduced 1.1.0}

  //TIdC_INT X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*new_item) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
  //                              void (*free_fn) (X509_LOOKUP *ctx));
  //void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
  //                              TIdC_INT (*init) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*shutdown) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);

  X509_LOOKUP_meth_set_ctrl: function (method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_ctrl: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_ctrl_fn; cdecl = nil; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_subject: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_subject_fn): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_subject: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_subject_fn; cdecl = nil; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_issuer_serial: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_issuer_serial: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_issuer_serial_fn; cdecl = nil; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_fingerprint: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_fingerprint_fn): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_fingerprint: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_fingerprint_fn; cdecl = nil; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_alias: function (method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_alias_fn): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_alias: function (const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_alias_fn; cdecl = nil; {introduced 1.1.0}

  X509_STORE_add_cert: function (ctx: PX509_STORE; x: PX509): TIdC_INT; cdecl = nil;
  X509_STORE_add_crl: function (ctx: PX509_STORE; x: PX509_CRL): TIdC_INT; cdecl = nil;

  X509_STORE_CTX_get_by_subject: function (vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_obj_by_subject: function (vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl = nil; {introduced 1.1.0}

  X509_LOOKUP_ctrl: function (ctx: PX509_LOOKUP; cmd: TIdC_INT; const argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl = nil;

  X509_load_cert_file: function (ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_load_crl_file: function (ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_load_cert_crl_file: function (ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT; cdecl = nil;

  X509_LOOKUP_new: function (method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl = nil;
  X509_LOOKUP_free: procedure (ctx: PX509_LOOKUP); cdecl = nil;
  X509_LOOKUP_init: function (ctx: PX509_LOOKUP): TIdC_INT; cdecl = nil;
  X509_LOOKUP_by_subject: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  X509_LOOKUP_by_issuer_serial: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  X509_LOOKUP_by_fingerprint: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const bytes: PByte; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  X509_LOOKUP_by_alias: function (ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  X509_LOOKUP_set_method_data: function (ctx: PX509_LOOKUP; data: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_get_method_data: function (const ctx: PX509_LOOKUP): Pointer; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_get_store: function (const ctx: PX509_LOOKUP): PX509_STORE; cdecl = nil; {introduced 1.1.0}
  X509_LOOKUP_shutdown: function (ctx: PX509_LOOKUP): TIdC_INT; cdecl = nil;

  X509_STORE_load_locations: function (ctx: PX509_STORE; const file_: PIdAnsiChar; const dir: PIdAnsiChar): TIdC_INT; cdecl = nil;
  X509_STORE_set_default_paths: function (ctx: PX509_STORE): TIdC_INT; cdecl = nil;

  //#define X509_STORE_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef)
  X509_STORE_CTX_set_ex_data: function (ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_get_ex_data: function (ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer; cdecl = nil;
  X509_STORE_CTX_get_error: function (ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_set_error: procedure (ctx: X509_STORE_CTX; s: TIdC_INT); cdecl = nil;
  X509_STORE_CTX_get_error_depth: function (ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_set_error_depth: procedure (ctx: PX509_STORE_CTX; depth: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get_current_cert: function (ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  X509_STORE_CTX_set_current_cert: procedure (ctx: PX509_STORE_CTX; x: PX509); cdecl = nil; {introduced 1.1.0}
  X509_STORE_CTX_get0_current_issuer: function (ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  X509_STORE_CTX_get0_current_crl: function (ctx: PX509_STORE_CTX): PX509_CRL; cdecl = nil;
  X509_STORE_CTX_get0_parent_ctx: function (ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl = nil;
//  STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
//  STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
  X509_STORE_CTX_set_cert: procedure (c: PX509_STORE_CTX; x: PX509); cdecl = nil;
//  void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
//  void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c, STACK_OF(X509_CRL) *sk);
  X509_STORE_CTX_set_purpose: function (ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_set_trust: function (ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_purpose_inherit: function (ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_set_flags: procedure (ctx: PX509_STORE_CTX; flags: TIdC_ULONG); cdecl = nil;
//  procedure X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET);

  X509_STORE_CTX_get0_policy_tree: function (ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl = nil;
  X509_STORE_CTX_get_explicit_policy: function (ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  X509_STORE_CTX_get_num_untrusted: function (ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  X509_STORE_CTX_get0_param: function (ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl = nil;
  X509_STORE_CTX_set0_param: procedure (ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM); cdecl = nil;
  X509_STORE_CTX_set_default: function (ctx: PX509_STORE_CTX; const name: PIdAnsiChar): TIdC_INT; cdecl = nil;

  (*
   * Bridge opacity barrier between libcrypt and libssl, also needed to support
   * offline testing in test/danetest.c
   *)
  X509_STORE_CTX_set0_dane: procedure (ctx: PX509_STORE_CTX; dane: PSSL_DANE); cdecl = nil; {introduced 1.1.0}

  (* X509_VERIFY_PARAM functions *)

  X509_VERIFY_PARAM_new: function : PX509_VERIFY_PARAM; cdecl = nil;
  X509_VERIFY_PARAM_free: procedure (param: PX509_VERIFY_PARAM); cdecl = nil;
  X509_VERIFY_PARAM_inherit: function (to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1: function (to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1_name: function (param: PX509_VERIFY_PARAM; const name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_flags: function (param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_clear_flags: function (param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_flags: function (param: PX509_VERIFY_PARAM): TIdC_ULONG; cdecl = nil;
  X509_VERIFY_PARAM_set_purpose: function (param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_trust: function (param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_depth: procedure (param: PX509_VERIFY_PARAM; depth: TIdC_INT); cdecl = nil;
  X509_VERIFY_PARAM_set_auth_level: procedure (param: PX509_VERIFY_PARAM; auth_level: TIdC_INT); cdecl = nil; {introduced 1.1.0}
//  function X509_VERIFY_PARAM_get_time(const param: PX509_VERIFY_PARAM): TIdC_TIMET;
//  procedure X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET);
  X509_VERIFY_PARAM_add0_policy: function (param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  //TIdC_INT X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
  //                                    STACK_OF(ASN1_OBJECT) *policies);

  X509_VERIFY_PARAM_set_inh_flags: function (param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_get_inh_flags: function (const param: PX509_VERIFY_PARAM): TIdC_UINT32; cdecl = nil; {introduced 1.1.0}

  X509_VERIFY_PARAM_set1_host: function (param: PX509_VERIFY_PARAM; const name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_add1_host: function (param: PX509_VERIFY_PARAM; const name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set_hostflags: procedure (param: PX509_VERIFY_PARAM; flags: TIdC_UINT); cdecl = nil;
  X509_VERIFY_PARAM_get_hostflags: function (const param: PX509_VERIFY_PARAM): TIdC_UINT; cdecl = nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_peername: function (v1: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl = nil;
  X509_VERIFY_PARAM_move_peername: procedure (v1: PX509_VERIFY_PARAM; v2: PX509_VERIFY_PARAM); cdecl = nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_set1_email: function (param: PX509_VERIFY_PARAM; const email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1_ip: function (param: PX509_VERIFY_PARAM; const ip: PByte; iplen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_set1_ip_asc: function (param: PX509_VERIFY_PARAM; const ipasc: PIdAnsiChar): TIdC_INT; cdecl = nil;

  X509_VERIFY_PARAM_get_depth: function (const param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_auth_level: function (const param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_name: function (const param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl = nil;

  X509_VERIFY_PARAM_add0_table: function (param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_get_count: function : TIdC_INT; cdecl = nil;
  X509_VERIFY_PARAM_get0: function (id: TIdC_INT): PX509_VERIFY_PARAM; cdecl = nil;
  X509_VERIFY_PARAM_lookup: function (const name: PIdAnsiChar): X509_VERIFY_PARAM; cdecl = nil;
  X509_VERIFY_PARAM_table_cleanup: procedure ; cdecl = nil;

  //TIdC_INT X509_policy_check(X509_POLICY_TREE **ptree, TIdC_INT *pexplicit_policy,
  //                      STACK_OF(X509) *certs,
  //                      STACK_OF(ASN1_OBJECT) *policy_oids, TIdC_UINT flags);

  X509_policy_tree_free: procedure (tree: PX509_POLICY_TREE); cdecl = nil;

  X509_policy_tree_level_count: function (const tree: PX509_POLICY_TREE): TIdC_INT; cdecl = nil;
  X509_policy_tree_get0_level: function (const tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL; cdecl = nil;

  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_policies(const
  //                                                           X509_POLICY_TREE
  //                                                           *tree);
  //
  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_user_policies(const
  //                                                                X509_POLICY_TREE
  //                                                                *tree);

  X509_policy_level_node_count: function (level: PX509_POLICY_LEVEL): TIdC_INT; cdecl = nil;

  X509_policy_level_get0_node: function (level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE; cdecl = nil;

  X509_policy_node_get0_policy: function (const node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl = nil;

  //STACK_OF(POLICYQUALINFO) *X509_policy_node_get0_qualifiers(const
  //                                                           X509_POLICY_NODE
  //                                                           *node);
  X509_policy_node_get0_parent: function (const node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl = nil;

{$ELSE}
  function X509_STORE_set_depth(store: PX509_STORE; depth: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  procedure X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT) cdecl; external CLibCrypto;

  //# define X509_STORE_CTX_set_app_data(ctx,data) \
  //        X509_STORE_CTX_set_ex_data(ctx,0,data)
  //# define X509_STORE_CTX_get_app_data(ctx) \
  //        X509_STORE_CTX_get_ex_data(ctx,0)
  //
  //# define X509_LOOKUP_load_file(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(TIdC_LONG)(type),NULL)
  //
  //# define X509_LOOKUP_add_dir(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(TIdC_LONG)(type),NULL)
  //
  //TIdC_INT X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
  //                               X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
  //                                             X509_LOOKUP_TYPE type,
  //                                             X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
  //                                        X509_OBJECT *x);
  function X509_OBJECT_up_ref_count(a: PX509_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function X509_OBJECT_new: PX509_OBJECT cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_OBJECT_free(a: PX509_OBJECT) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_OBJECT_get_type(const a: PX509_OBJECT): X509_LOOKUP_TYPE cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_OBJECT_get0_X509(const a: PX509_OBJECT): PX509 cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_new: PX509_STORE cdecl; external CLibCrypto;
  procedure X509_STORE_free(v: PX509_STORE) cdecl; external CLibCrypto;
  function X509_STORE_lock(ctx: PX509_STORE): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_unlock(ctx: PX509_STORE): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_up_ref(v: PX509_STORE): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  //STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *v);

  //STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *st, X509_NAME *nm);
  //STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(X509_STORE_CTX *st, X509_NAME *nm);
  function X509_STORE_set_flags(ctx: PX509_STORE; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_set_purpose(ctx: PX509_STORE; purpose: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_set_trust(ctx: PX509_STORE; trust: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_set1_param(ctx: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_get0_param(ctx: PX509_STORE): PX509_VERIFY_PARAM cdecl; external CLibCrypto; {introduced 1.1.0}

  procedure X509_STORE_set_verify(ctx: PX509_STORE; verify: X509_STORE_CTX_verify_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  //#define X509_STORE_set_verify_func(ctx, func) \
  //            X509_STORE_set_verify((ctx),(func))
  procedure X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_verify(ctx: PX509_STORE): X509_STORE_CTX_verify_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_verify_cb(ctx: PX509_STORE; verify_cb: X509_STORE_CTX_verify_cb) cdecl; external CLibCrypto;
  //# define X509_STORE_set_verify_cb_func(ctx,func) \
  //            X509_STORE_set_verify_cb((ctx),(func))
  function X509_STORE_get_verify_cb(ctx: PX509_STORE): X509_STORE_CTX_verify_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_get_issuer(ctx: PX509_STORE; get_issuer: X509_STORE_CTX_get_issuer_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_get_issuer(ctx: PX509_STORE): X509_STORE_CTX_get_issuer_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_check_issued(ctx: PX509_STORE; check_issued: X509_STORE_CTX_check_issued_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_check_issued(ctx: PX509_STORE): X509_STORE_CTX_check_issued_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_check_revocation(ctx: PX509_STORE; check_revocation: X509_STORE_CTX_check_revocation_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_check_revocation(ctx: PX509_STORE): X509_STORE_CTX_check_revocation_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_get_crl(ctx: PX509_STORE; get_crl: X509_STORE_CTX_get_crl_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_get_crl(ctx: PX509_STORE): X509_STORE_CTX_get_crl_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_check_crl(ctx: PX509_STORE; check_crl: X509_STORE_CTX_check_crl_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_check_crl(ctx: PX509_STORE): X509_STORE_CTX_check_crl_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_cert_crl(ctx: PX509_STORE; cert_crl: X509_STORE_CTX_cert_crl_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_cert_crl(ctx: PX509_STORE): X509_STORE_CTX_cert_crl_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_STORE_set_check_policy(ctx: PX509_STORE; check_policy: X509_STORE_CTX_check_policy_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_check_policy(ctx: PX509_STORE): X509_STORE_CTX_check_policy_fn cdecl; external CLibCrypto; {introduced 1.1.0}
//  procedure X509_STORE_set_lookup_certs(ctx: PX509_STORE; lookup_certs: X509_STORE_CTX_lookup_certs_fn);
//  function X509_STORE_get_lookup_certs(ctx: PX509_STORE): X509_STORE_CTX_lookup_certs_fn;
//  procedure X509_STORE_set_lookup_crls(ctx: PX509_STORE; lookup_crls: X509_STORE_CTX_lookup_crls_fn);
//  #define X509_STORE_set_lookup_crls_cb(ctx, func) \
//      X509_STORE_set_lookup_crls((ctx), (func))
//  function X509_STORE_get_lookup_crls(ctx: PX509_STORE): X509_STORE_CTX_lookup_crls_fn;
  procedure X509_STORE_set_cleanup(ctx: PX509_STORE; cleanup: X509_STORE_CTX_cleanup_fn) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_cleanup(ctx: PX509_STORE): X509_STORE_CTX_cleanup_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  //#define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)
  function X509_STORE_set_ex_data(ctx: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_get_ex_data(ctx: PX509_STORE; idx: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_STORE_CTX_new: PX509_STORE_CTX cdecl; external CLibCrypto;

  function X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT cdecl; external CLibCrypto;

  procedure X509_STORE_CTX_free(ctx: PX509_STORE_CTX) cdecl; external CLibCrypto;
//  TIdC_INT X509_STORE_CTX_init(ctx: PX509_STORE_CTX; store: PX509_STORE; x509: PX509; chain: P STACK_OF(X509));
//  procedure X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: P STACK_OF(X509));
  procedure X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX) cdecl; external CLibCrypto;

  function X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE cdecl; external CLibCrypto;
  function X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509 cdecl; external CLibCrypto; {introduced 1.1.0}
  //STACK_OF(X509)* X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *ctx);
  //void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
  procedure X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_cb) cdecl; external CLibCrypto;
  function X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_issuer_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_issued_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_revocation_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_crl_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_crl_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_cert_crl_fn cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_policy_fn cdecl; external CLibCrypto; {introduced 1.1.0}
//  function X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_certs_fn;
//  function X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_crls_fn;
  function X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): X509_STORE_CTX_cleanup_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_STORE_add_lookup(v: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP cdecl; external CLibCrypto;
  function X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD cdecl; external CLibCrypto;
  function X509_LOOKUP_file: PX509_LOOKUP_METHOD cdecl; external CLibCrypto;

  function X509_LOOKUP_meth_new(const name: PIdAnsiChar): PX509_LOOKUP_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD) cdecl; external CLibCrypto; {introduced 1.1.0}

  //TIdC_INT X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*new_item) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
  //                              void (*free_fn) (X509_LOOKUP *ctx));
  //void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
  //                              TIdC_INT (*init) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*shutdown) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);

  function X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_meth_get_ctrl(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_ctrl_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_subject_fn): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_meth_get_get_by_subject(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_subject_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_meth_get_get_by_issuer_serial(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_issuer_serial_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_fingerprint_fn): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_meth_get_get_by_fingerprint(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_fingerprint_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_alias_fn): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_meth_get_get_by_alias(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_alias_fn cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_STORE_add_cert(ctx: PX509_STORE; x: PX509): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_add_crl(ctx: PX509_STORE; x: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;

  function X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT; const argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  function X509_load_cert_file(ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_load_crl_file(ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_load_cert_crl_file(ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP cdecl; external CLibCrypto;
  procedure X509_LOOKUP_free(ctx: PX509_LOOKUP) cdecl; external CLibCrypto;
  function X509_LOOKUP_init(ctx: PX509_LOOKUP): TIdC_INT cdecl; external CLibCrypto;
  function X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const bytes: PByte; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  function X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_get_method_data(const ctx: PX509_LOOKUP): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TIdC_INT cdecl; external CLibCrypto;

  function X509_STORE_load_locations(ctx: PX509_STORE; const file_: PIdAnsiChar; const dir: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_set_default_paths(ctx: PX509_STORE): TIdC_INT cdecl; external CLibCrypto;

  //#define X509_STORE_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef)
  function X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;
  function X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_STORE_CTX_set_error(ctx: X509_STORE_CTX; s: TIdC_INT) cdecl; external CLibCrypto;
  function X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509 cdecl; external CLibCrypto;
  procedure X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509 cdecl; external CLibCrypto;
  function X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL cdecl; external CLibCrypto;
  function X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX cdecl; external CLibCrypto;
//  STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
//  STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
  procedure X509_STORE_CTX_set_cert(c: PX509_STORE_CTX; x: PX509) cdecl; external CLibCrypto;
//  void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
//  void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c, STACK_OF(X509_CRL) *sk);
  function X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;
//  procedure X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET);

  function X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE cdecl; external CLibCrypto;
  function X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
  function X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM cdecl; external CLibCrypto;
  procedure X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM) cdecl; external CLibCrypto;
  function X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Bridge opacity barrier between libcrypt and libssl, also needed to support
   * offline testing in test/danetest.c
   *)
  procedure X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE) cdecl; external CLibCrypto; {introduced 1.1.0}

  (* X509_VERIFY_PARAM functions *)

  function X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM cdecl; external CLibCrypto;
  procedure X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM) cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_inherit(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set1(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TIdC_ULONG cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TIdC_INT) cdecl; external CLibCrypto;
  procedure X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
//  function X509_VERIFY_PARAM_get_time(const param: PX509_VERIFY_PARAM): TIdC_TIMET;
//  procedure X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET);
  function X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  //TIdC_INT X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
  //                                    STACK_OF(ASN1_OBJECT) *policies);

  function X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_VERIFY_PARAM_get_inh_flags(const param: PX509_VERIFY_PARAM): TIdC_UINT32 cdecl; external CLibCrypto; {introduced 1.1.0}

  function X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; const name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; const name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  procedure X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT) cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_get_hostflags(const param: PX509_VERIFY_PARAM): TIdC_UINT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_VERIFY_PARAM_get0_peername(v1: PX509_VERIFY_PARAM): PIdAnsiChar cdecl; external CLibCrypto;
  procedure X509_VERIFY_PARAM_move_peername(v1: PX509_VERIFY_PARAM; v2: PX509_VERIFY_PARAM) cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; const email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; const ip: PByte; iplen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; const ipasc: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  function X509_VERIFY_PARAM_get_depth(const param: PX509_VERIFY_PARAM): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_get_auth_level(const param: PX509_VERIFY_PARAM): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function X509_VERIFY_PARAM_get0_name(const param: PX509_VERIFY_PARAM): PIdAnsiChar cdecl; external CLibCrypto;

  function X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_get_count: TIdC_INT cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_get0(id: TIdC_INT): PX509_VERIFY_PARAM cdecl; external CLibCrypto;
  function X509_VERIFY_PARAM_lookup(const name: PIdAnsiChar): X509_VERIFY_PARAM cdecl; external CLibCrypto;
  procedure X509_VERIFY_PARAM_table_cleanup cdecl; external CLibCrypto;

  //TIdC_INT X509_policy_check(X509_POLICY_TREE **ptree, TIdC_INT *pexplicit_policy,
  //                      STACK_OF(X509) *certs,
  //                      STACK_OF(ASN1_OBJECT) *policy_oids, TIdC_UINT flags);

  procedure X509_policy_tree_free(tree: PX509_POLICY_TREE) cdecl; external CLibCrypto;

  function X509_policy_tree_level_count(const tree: PX509_POLICY_TREE): TIdC_INT cdecl; external CLibCrypto;
  function X509_policy_tree_get0_level(const tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL cdecl; external CLibCrypto;

  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_policies(const
  //                                                           X509_POLICY_TREE
  //                                                           *tree);
  //
  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_user_policies(const
  //                                                                X509_POLICY_TREE
  //                                                                *tree);

  function X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TIdC_INT cdecl; external CLibCrypto;

  function X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE cdecl; external CLibCrypto;

  function X509_policy_node_get0_policy(const node: PX509_POLICY_NODE): PASN1_OBJECT cdecl; external CLibCrypto;

  //STACK_OF(POLICYQUALINFO) *X509_policy_node_get0_qualifiers(const
  //                                                           X509_POLICY_NODE
  //                                                           *node);
  function X509_policy_node_get0_parent(const node: PX509_POLICY_NODE): PX509_POLICY_NODE cdecl; external CLibCrypto;

function X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer; {removed 1.0.0}
{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  
const
  X509_OBJECT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_OBJECT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_OBJECT_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_OBJECT_get0_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_OBJECT_set1_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_OBJECT_get0_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_OBJECT_set1_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_lock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_unlock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get0_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_verify_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_check_revocation_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_check_revocation_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_get_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_get_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_check_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_check_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_cert_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_cert_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_check_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_check_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get0_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_verify_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_check_revocation_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_get_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_check_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_cert_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_check_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_set_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_get_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_set_get_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_get_get_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_set_get_by_issuer_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_get_get_by_issuer_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_set_get_by_fingerprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_get_get_by_fingerprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_set_get_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_meth_get_get_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_obj_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_set_method_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_get_method_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_LOOKUP_get_store_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_set_error_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_set_current_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_num_untrusted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_set0_dane_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_VERIFY_PARAM_set_auth_level_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_VERIFY_PARAM_set_inh_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_VERIFY_PARAM_get_inh_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_VERIFY_PARAM_get_hostflags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_VERIFY_PARAM_move_peername_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_VERIFY_PARAM_get_auth_level_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_STORE_CTX_get_app_data_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);

{helper_functions}
function X509_LOOKUP_load_file(ctx: PX509_LOOKUP; name: PIdAnsiChar; type_: TIdC_LONG): TIdC_INT;
begin
  Result := X509_LOOKUP_ctrl(ctx,X509_L_FILE_LOAD,name,type_,nil);
end;
{\helper_functions}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  X509_STORE_set_depth_procname = 'X509_STORE_set_depth';

  X509_STORE_CTX_set_depth_procname = 'X509_STORE_CTX_set_depth';

  //# define X509_STORE_CTX_set_app_data(ctx,data) \
  //        X509_STORE_CTX_set_ex_data(ctx,0,data)
  //# define X509_STORE_CTX_get_app_data(ctx) \
  //        X509_STORE_CTX_get_ex_data(ctx,0)
  X509_STORE_CTX_get_app_data_procname = 'X509_STORE_CTX_get_app_data'; {removed 1.0.0}
  //
  //# define X509_LOOKUP_load_file(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(TIdC_LONG)(type),NULL)
  //
  //# define X509_LOOKUP_add_dir(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(TIdC_LONG)(type),NULL)
  //
  //TIdC_INT X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
  //                               X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
  //                                             X509_LOOKUP_TYPE type,
  //                                             X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
  //                                        X509_OBJECT *x);
  X509_OBJECT_up_ref_count_procname = 'X509_OBJECT_up_ref_count';
  X509_OBJECT_new_procname = 'X509_OBJECT_new'; {introduced 1.1.0}
  X509_OBJECT_free_procname = 'X509_OBJECT_free'; {introduced 1.1.0}
  X509_OBJECT_get_type_procname = 'X509_OBJECT_get_type'; {introduced 1.1.0}
  X509_OBJECT_get0_X509_procname = 'X509_OBJECT_get0_X509'; {introduced 1.1.0}
  X509_OBJECT_set1_X509_procname = 'X509_OBJECT_set1_X509'; {introduced 1.1.0}
  X509_OBJECT_get0_X509_CRL_procname = 'X509_OBJECT_get0_X509_CRL'; {introduced 1.1.0}
  X509_OBJECT_set1_X509_CRL_procname = 'X509_OBJECT_set1_X509_CRL'; {introduced 1.1.0}
  X509_STORE_new_procname = 'X509_STORE_new';
  X509_STORE_free_procname = 'X509_STORE_free';
  X509_STORE_lock_procname = 'X509_STORE_lock'; {introduced 1.1.0}
  X509_STORE_unlock_procname = 'X509_STORE_unlock'; {introduced 1.1.0}
  X509_STORE_up_ref_procname = 'X509_STORE_up_ref'; {introduced 1.1.0}
  //STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *v);

  //STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *st, X509_NAME *nm);
  //STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(X509_STORE_CTX *st, X509_NAME *nm);
  X509_STORE_set_flags_procname = 'X509_STORE_set_flags';
  X509_STORE_set_purpose_procname = 'X509_STORE_set_purpose';
  X509_STORE_set_trust_procname = 'X509_STORE_set_trust';
  X509_STORE_set1_param_procname = 'X509_STORE_set1_param';
  X509_STORE_get0_param_procname = 'X509_STORE_get0_param'; {introduced 1.1.0}

  X509_STORE_set_verify_procname = 'X509_STORE_set_verify'; {introduced 1.1.0}
  //#define X509_STORE_set_verify_func(ctx, func) \
  //            X509_STORE_set_verify((ctx),(func))
  X509_STORE_CTX_set_verify_procname = 'X509_STORE_CTX_set_verify'; {introduced 1.1.0}
  X509_STORE_get_verify_procname = 'X509_STORE_get_verify'; {introduced 1.1.0}
  X509_STORE_set_verify_cb_procname = 'X509_STORE_set_verify_cb';
  //# define X509_STORE_set_verify_cb_func(ctx,func) \
  //            X509_STORE_set_verify_cb((ctx),(func))
  X509_STORE_get_verify_cb_procname = 'X509_STORE_get_verify_cb'; {introduced 1.1.0}
  X509_STORE_set_get_issuer_procname = 'X509_STORE_set_get_issuer'; {introduced 1.1.0}
  X509_STORE_get_get_issuer_procname = 'X509_STORE_get_get_issuer'; {introduced 1.1.0}
  X509_STORE_set_check_issued_procname = 'X509_STORE_set_check_issued'; {introduced 1.1.0}
  X509_STORE_get_check_issued_procname = 'X509_STORE_get_check_issued'; {introduced 1.1.0}
  X509_STORE_set_check_revocation_procname = 'X509_STORE_set_check_revocation'; {introduced 1.1.0}
  X509_STORE_get_check_revocation_procname = 'X509_STORE_get_check_revocation'; {introduced 1.1.0}
  X509_STORE_set_get_crl_procname = 'X509_STORE_set_get_crl'; {introduced 1.1.0}
  X509_STORE_get_get_crl_procname = 'X509_STORE_get_get_crl'; {introduced 1.1.0}
  X509_STORE_set_check_crl_procname = 'X509_STORE_set_check_crl'; {introduced 1.1.0}
  X509_STORE_get_check_crl_procname = 'X509_STORE_get_check_crl'; {introduced 1.1.0}
  X509_STORE_set_cert_crl_procname = 'X509_STORE_set_cert_crl'; {introduced 1.1.0}
  X509_STORE_get_cert_crl_procname = 'X509_STORE_get_cert_crl'; {introduced 1.1.0}
  X509_STORE_set_check_policy_procname = 'X509_STORE_set_check_policy'; {introduced 1.1.0}
  X509_STORE_get_check_policy_procname = 'X509_STORE_get_check_policy'; {introduced 1.1.0}
//  procedure X509_STORE_set_lookup_certs(ctx: PX509_STORE; lookup_certs: X509_STORE_CTX_lookup_certs_fn);
//  function X509_STORE_get_lookup_certs(ctx: PX509_STORE): X509_STORE_CTX_lookup_certs_fn;
//  procedure X509_STORE_set_lookup_crls(ctx: PX509_STORE; lookup_crls: X509_STORE_CTX_lookup_crls_fn);
//  #define X509_STORE_set_lookup_crls_cb(ctx, func) \
//      X509_STORE_set_lookup_crls((ctx), (func))
//  function X509_STORE_get_lookup_crls(ctx: PX509_STORE): X509_STORE_CTX_lookup_crls_fn;
  X509_STORE_set_cleanup_procname = 'X509_STORE_set_cleanup'; {introduced 1.1.0}
  X509_STORE_get_cleanup_procname = 'X509_STORE_get_cleanup'; {introduced 1.1.0}

  //#define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)
  X509_STORE_set_ex_data_procname = 'X509_STORE_set_ex_data'; {introduced 1.1.0}
  X509_STORE_get_ex_data_procname = 'X509_STORE_get_ex_data'; {introduced 1.1.0}

  X509_STORE_CTX_new_procname = 'X509_STORE_CTX_new';

  X509_STORE_CTX_get1_issuer_procname = 'X509_STORE_CTX_get1_issuer';

  X509_STORE_CTX_free_procname = 'X509_STORE_CTX_free';
//  TIdC_INT X509_STORE_CTX_init(ctx: PX509_STORE_CTX; store: PX509_STORE; x509: PX509; chain: P STACK_OF(X509));
//  procedure X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: P STACK_OF(X509));
  X509_STORE_CTX_cleanup_procname = 'X509_STORE_CTX_cleanup';

  X509_STORE_CTX_get0_store_procname = 'X509_STORE_CTX_get0_store';
  X509_STORE_CTX_get0_cert_procname = 'X509_STORE_CTX_get0_cert'; {introduced 1.1.0}
  //STACK_OF(X509)* X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *ctx);
  //void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
  X509_STORE_CTX_set_verify_cb_procname = 'X509_STORE_CTX_set_verify_cb';
  X509_STORE_CTX_get_verify_cb_procname = 'X509_STORE_CTX_get_verify_cb'; {introduced 1.1.0}
  X509_STORE_CTX_get_verify_procname = 'X509_STORE_CTX_get_verify'; {introduced 1.1.0}
  X509_STORE_CTX_get_get_issuer_procname = 'X509_STORE_CTX_get_get_issuer'; {introduced 1.1.0}
  X509_STORE_CTX_get_check_issued_procname = 'X509_STORE_CTX_get_check_issued'; {introduced 1.1.0}
  X509_STORE_CTX_get_check_revocation_procname = 'X509_STORE_CTX_get_check_revocation'; {introduced 1.1.0}
  X509_STORE_CTX_get_get_crl_procname = 'X509_STORE_CTX_get_get_crl'; {introduced 1.1.0}
  X509_STORE_CTX_get_check_crl_procname = 'X509_STORE_CTX_get_check_crl'; {introduced 1.1.0}
  X509_STORE_CTX_get_cert_crl_procname = 'X509_STORE_CTX_get_cert_crl'; {introduced 1.1.0}
  X509_STORE_CTX_get_check_policy_procname = 'X509_STORE_CTX_get_check_policy'; {introduced 1.1.0}
//  function X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_certs_fn;
//  function X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_crls_fn;
  X509_STORE_CTX_get_cleanup_procname = 'X509_STORE_CTX_get_cleanup'; {introduced 1.1.0}

  X509_STORE_add_lookup_procname = 'X509_STORE_add_lookup';
  X509_LOOKUP_hash_dir_procname = 'X509_LOOKUP_hash_dir';
  X509_LOOKUP_file_procname = 'X509_LOOKUP_file';

  X509_LOOKUP_meth_new_procname = 'X509_LOOKUP_meth_new'; {introduced 1.1.0}
  X509_LOOKUP_meth_free_procname = 'X509_LOOKUP_meth_free'; {introduced 1.1.0}

  //TIdC_INT X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*new_item) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
  //                              void (*free_fn) (X509_LOOKUP *ctx));
  //void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
  //                              TIdC_INT (*init) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*shutdown) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);

  X509_LOOKUP_meth_set_ctrl_procname = 'X509_LOOKUP_meth_set_ctrl'; {introduced 1.1.0}
  X509_LOOKUP_meth_get_ctrl_procname = 'X509_LOOKUP_meth_get_ctrl'; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_subject_procname = 'X509_LOOKUP_meth_set_get_by_subject'; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_subject_procname = 'X509_LOOKUP_meth_get_get_by_subject'; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_issuer_serial_procname = 'X509_LOOKUP_meth_set_get_by_issuer_serial'; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_issuer_serial_procname = 'X509_LOOKUP_meth_get_get_by_issuer_serial'; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_fingerprint_procname = 'X509_LOOKUP_meth_set_get_by_fingerprint'; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_fingerprint_procname = 'X509_LOOKUP_meth_get_get_by_fingerprint'; {introduced 1.1.0}

  X509_LOOKUP_meth_set_get_by_alias_procname = 'X509_LOOKUP_meth_set_get_by_alias'; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_alias_procname = 'X509_LOOKUP_meth_get_get_by_alias'; {introduced 1.1.0}

  X509_STORE_add_cert_procname = 'X509_STORE_add_cert';
  X509_STORE_add_crl_procname = 'X509_STORE_add_crl';

  X509_STORE_CTX_get_by_subject_procname = 'X509_STORE_CTX_get_by_subject'; {introduced 1.1.0}
  X509_STORE_CTX_get_obj_by_subject_procname = 'X509_STORE_CTX_get_obj_by_subject'; {introduced 1.1.0}

  X509_LOOKUP_ctrl_procname = 'X509_LOOKUP_ctrl';

  X509_load_cert_file_procname = 'X509_load_cert_file';
  X509_load_crl_file_procname = 'X509_load_crl_file';
  X509_load_cert_crl_file_procname = 'X509_load_cert_crl_file';

  X509_LOOKUP_new_procname = 'X509_LOOKUP_new';
  X509_LOOKUP_free_procname = 'X509_LOOKUP_free';
  X509_LOOKUP_init_procname = 'X509_LOOKUP_init';
  X509_LOOKUP_by_subject_procname = 'X509_LOOKUP_by_subject';
  X509_LOOKUP_by_issuer_serial_procname = 'X509_LOOKUP_by_issuer_serial';
  X509_LOOKUP_by_fingerprint_procname = 'X509_LOOKUP_by_fingerprint';
  X509_LOOKUP_by_alias_procname = 'X509_LOOKUP_by_alias';
  X509_LOOKUP_set_method_data_procname = 'X509_LOOKUP_set_method_data'; {introduced 1.1.0}
  X509_LOOKUP_get_method_data_procname = 'X509_LOOKUP_get_method_data'; {introduced 1.1.0}
  X509_LOOKUP_get_store_procname = 'X509_LOOKUP_get_store'; {introduced 1.1.0}
  X509_LOOKUP_shutdown_procname = 'X509_LOOKUP_shutdown';

  X509_STORE_load_locations_procname = 'X509_STORE_load_locations';
  X509_STORE_set_default_paths_procname = 'X509_STORE_set_default_paths';

  //#define X509_STORE_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef)
  X509_STORE_CTX_set_ex_data_procname = 'X509_STORE_CTX_set_ex_data';
  X509_STORE_CTX_get_ex_data_procname = 'X509_STORE_CTX_get_ex_data';
  X509_STORE_CTX_get_error_procname = 'X509_STORE_CTX_get_error';
  X509_STORE_CTX_set_error_procname = 'X509_STORE_CTX_set_error';
  X509_STORE_CTX_get_error_depth_procname = 'X509_STORE_CTX_get_error_depth';
  X509_STORE_CTX_set_error_depth_procname = 'X509_STORE_CTX_set_error_depth'; {introduced 1.1.0}
  X509_STORE_CTX_get_current_cert_procname = 'X509_STORE_CTX_get_current_cert';
  X509_STORE_CTX_set_current_cert_procname = 'X509_STORE_CTX_set_current_cert'; {introduced 1.1.0}
  X509_STORE_CTX_get0_current_issuer_procname = 'X509_STORE_CTX_get0_current_issuer';
  X509_STORE_CTX_get0_current_crl_procname = 'X509_STORE_CTX_get0_current_crl';
  X509_STORE_CTX_get0_parent_ctx_procname = 'X509_STORE_CTX_get0_parent_ctx';
//  STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
//  STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
  X509_STORE_CTX_set_cert_procname = 'X509_STORE_CTX_set_cert';
//  void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
//  void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c, STACK_OF(X509_CRL) *sk);
  X509_STORE_CTX_set_purpose_procname = 'X509_STORE_CTX_set_purpose';
  X509_STORE_CTX_set_trust_procname = 'X509_STORE_CTX_set_trust';
  X509_STORE_CTX_purpose_inherit_procname = 'X509_STORE_CTX_purpose_inherit';
  X509_STORE_CTX_set_flags_procname = 'X509_STORE_CTX_set_flags';
//  procedure X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET);

  X509_STORE_CTX_get0_policy_tree_procname = 'X509_STORE_CTX_get0_policy_tree';
  X509_STORE_CTX_get_explicit_policy_procname = 'X509_STORE_CTX_get_explicit_policy';
  X509_STORE_CTX_get_num_untrusted_procname = 'X509_STORE_CTX_get_num_untrusted'; {introduced 1.1.0}

  X509_STORE_CTX_get0_param_procname = 'X509_STORE_CTX_get0_param';
  X509_STORE_CTX_set0_param_procname = 'X509_STORE_CTX_set0_param';
  X509_STORE_CTX_set_default_procname = 'X509_STORE_CTX_set_default';

  (*
   * Bridge opacity barrier between libcrypt and libssl, also needed to support
   * offline testing in test/danetest.c
   *)
  X509_STORE_CTX_set0_dane_procname = 'X509_STORE_CTX_set0_dane'; {introduced 1.1.0}

  (* X509_VERIFY_PARAM functions *)

  X509_VERIFY_PARAM_new_procname = 'X509_VERIFY_PARAM_new';
  X509_VERIFY_PARAM_free_procname = 'X509_VERIFY_PARAM_free';
  X509_VERIFY_PARAM_inherit_procname = 'X509_VERIFY_PARAM_inherit';
  X509_VERIFY_PARAM_set1_procname = 'X509_VERIFY_PARAM_set1';
  X509_VERIFY_PARAM_set1_name_procname = 'X509_VERIFY_PARAM_set1_name';
  X509_VERIFY_PARAM_set_flags_procname = 'X509_VERIFY_PARAM_set_flags';
  X509_VERIFY_PARAM_clear_flags_procname = 'X509_VERIFY_PARAM_clear_flags';
  X509_VERIFY_PARAM_get_flags_procname = 'X509_VERIFY_PARAM_get_flags';
  X509_VERIFY_PARAM_set_purpose_procname = 'X509_VERIFY_PARAM_set_purpose';
  X509_VERIFY_PARAM_set_trust_procname = 'X509_VERIFY_PARAM_set_trust';
  X509_VERIFY_PARAM_set_depth_procname = 'X509_VERIFY_PARAM_set_depth';
  X509_VERIFY_PARAM_set_auth_level_procname = 'X509_VERIFY_PARAM_set_auth_level'; {introduced 1.1.0}
//  function X509_VERIFY_PARAM_get_time(const param: PX509_VERIFY_PARAM): TIdC_TIMET;
//  procedure X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET);
  X509_VERIFY_PARAM_add0_policy_procname = 'X509_VERIFY_PARAM_add0_policy';
  //TIdC_INT X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
  //                                    STACK_OF(ASN1_OBJECT) *policies);

  X509_VERIFY_PARAM_set_inh_flags_procname = 'X509_VERIFY_PARAM_set_inh_flags'; {introduced 1.1.0}
  X509_VERIFY_PARAM_get_inh_flags_procname = 'X509_VERIFY_PARAM_get_inh_flags'; {introduced 1.1.0}

  X509_VERIFY_PARAM_set1_host_procname = 'X509_VERIFY_PARAM_set1_host';
  X509_VERIFY_PARAM_add1_host_procname = 'X509_VERIFY_PARAM_add1_host';
  X509_VERIFY_PARAM_set_hostflags_procname = 'X509_VERIFY_PARAM_set_hostflags';
  X509_VERIFY_PARAM_get_hostflags_procname = 'X509_VERIFY_PARAM_get_hostflags'; {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_peername_procname = 'X509_VERIFY_PARAM_get0_peername';
  X509_VERIFY_PARAM_move_peername_procname = 'X509_VERIFY_PARAM_move_peername'; {introduced 1.1.0}
  X509_VERIFY_PARAM_set1_email_procname = 'X509_VERIFY_PARAM_set1_email';
  X509_VERIFY_PARAM_set1_ip_procname = 'X509_VERIFY_PARAM_set1_ip';
  X509_VERIFY_PARAM_set1_ip_asc_procname = 'X509_VERIFY_PARAM_set1_ip_asc';

  X509_VERIFY_PARAM_get_depth_procname = 'X509_VERIFY_PARAM_get_depth';
  X509_VERIFY_PARAM_get_auth_level_procname = 'X509_VERIFY_PARAM_get_auth_level'; {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_name_procname = 'X509_VERIFY_PARAM_get0_name';

  X509_VERIFY_PARAM_add0_table_procname = 'X509_VERIFY_PARAM_add0_table';
  X509_VERIFY_PARAM_get_count_procname = 'X509_VERIFY_PARAM_get_count';
  X509_VERIFY_PARAM_get0_procname = 'X509_VERIFY_PARAM_get0';
  X509_VERIFY_PARAM_lookup_procname = 'X509_VERIFY_PARAM_lookup';
  X509_VERIFY_PARAM_table_cleanup_procname = 'X509_VERIFY_PARAM_table_cleanup';

  //TIdC_INT X509_policy_check(X509_POLICY_TREE **ptree, TIdC_INT *pexplicit_policy,
  //                      STACK_OF(X509) *certs,
  //                      STACK_OF(ASN1_OBJECT) *policy_oids, TIdC_UINT flags);

  X509_policy_tree_free_procname = 'X509_policy_tree_free';

  X509_policy_tree_level_count_procname = 'X509_policy_tree_level_count';
  X509_policy_tree_get0_level_procname = 'X509_policy_tree_get0_level';

  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_policies(const
  //                                                           X509_POLICY_TREE
  //                                                           *tree);
  //
  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_user_policies(const
  //                                                                X509_POLICY_TREE
  //                                                                *tree);

  X509_policy_level_node_count_procname = 'X509_policy_level_node_count';

  X509_policy_level_get0_node_procname = 'X509_policy_level_get0_node';

  X509_policy_node_get0_policy_procname = 'X509_policy_node_get0_policy';

  //STACK_OF(POLICYQUALINFO) *X509_policy_node_get0_qualifiers(const
  //                                                           X509_POLICY_NODE
  //                                                           *node);
  X509_policy_node_get0_parent_procname = 'X509_policy_node_get0_parent';


function  _X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer; cdecl;
begin
  Result := X509_STORE_CTX_get_ex_data(ctx,SSL_get_ex_data_X509_STORE_CTX_idx);
end;


{forward_compatibility}
type
 _PX509_LOOKUP_METHOD      = ^_X509_LOOKUP_METHOD;
 _X509_LOOKUP_METHOD = record
    name : PIdAnsiChar;
    new_item : function (ctx : PX509_LOOKUP): TIdC_INT; cdecl;
    free : procedure (ctx : PX509_LOOKUP); cdecl;
    init : function(ctx : PX509_LOOKUP) : TIdC_INT; cdecl;
    shutdown : function(ctx : PX509_LOOKUP) : TIdC_INT; cdecl;
    ctrl: function(ctx : PX509_LOOKUP; cmd : TIdC_INT; const argc : PIdAnsiChar; argl : TIdC_LONG; out ret : PIdAnsiChar ) : TIdC_INT; cdecl;
    get_by_subject: function(ctx : PX509_LOOKUP; _type : TIdC_INT; name : PX509_NAME; ret : PX509_OBJECT ) : TIdC_INT; cdecl;
    get_by_issuer_serial : function(ctx : PX509_LOOKUP; _type : TIdC_INT; name : PX509_NAME; serial : PASN1_INTEGER; ret : PX509_OBJECT) : TIdC_INT; cdecl;
    get_by_fingerprint : function (ctx : PX509_LOOKUP; _type : TIdC_INT; bytes : PIdAnsiChar; len : TIdC_INT; ret : PX509_OBJECT): TIdC_INT; cdecl;
    get_by_alias : function(ctx : PX509_LOOKUP; _type : TIdC_INT; str : PIdAnsiChar; ret : PX509_OBJECT) : TIdC_INT; cdecl;
  end;

const
  Indy_x509_unicode_file_lookup: _X509_LOOKUP_METHOD =
    (
    name: 'Load file into cache';
    new_item: nil; // * new */
    free: nil; // * free */
    init: nil; // * init */
    shutdown: nil; // * shutdown */
    ctrl: nil; // * ctrl */
    get_by_subject: nil; // * get_by_subject */
    get_by_issuer_serial: nil; // * get_by_issuer_serial */
    get_by_fingerprint: nil; // * get_by_fingerprint */
    get_by_alias: nil // * get_by_alias */
    );

function  FC_X509_LOOKUP_meth_new(const name: PIdAnsiChar): PX509_LOOKUP_METHOD; cdecl;
begin
  Result := @Indy_x509_unicode_file_lookup;
end;

procedure  FC_X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD); cdecl;
begin
  //Do nothing
end;

function  FC_X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TIdC_INT; cdecl;
begin
  _PX509_LOOKUP_METHOD(method)^.ctrl := @ctrl_fn;
  Result := 1;
end;
(*
struct x509_lookup_st {
    int init;                   /* have we been started */
    int skip;                   /* don't use us. */
    X509_LOOKUP_METHOD *method; /* the functions */
    char *method_data;          /* method data */
    X509_STORE *store_ctx;      /* who owns us */
} /* X509_LOOKUP */ ;
*)

type
  _PX509_LOOKUP = ^_X509_LOOKUP;
  _X509_LOOKUP = record
    init: TIdC_INT;
    skip: TIdC_INT;
    method: PX509_LOOKUP_METHOD;
    method_data: PIdAnsiChar;
    store_ctx: PX509_STORE;
  end;

function  FC_X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE; cdecl;
begin
  Result := _PX509_LOOKUP(ctx)^.store_ctx;
end;

{/forward_compatibility}
{$WARN  NO_RETVAL OFF}
function  ERR_X509_STORE_set_depth(store: PX509_STORE; depth: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_depth_procname);
end;



procedure  ERR_X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_depth_procname);
end;



  //# define X509_STORE_CTX_set_app_data(ctx,data) \
  //        X509_STORE_CTX_set_ex_data(ctx,0,data)
  //# define X509_STORE_CTX_get_app_data(ctx) \
  //        X509_STORE_CTX_get_ex_data(ctx,0)
function  ERR_X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_app_data_procname);
end;

 
  //
  //# define X509_LOOKUP_load_file(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(TIdC_LONG)(type),NULL)
  //
  //# define X509_LOOKUP_add_dir(x,name,type) \
  //                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(TIdC_LONG)(type),NULL)
  //
  //TIdC_INT X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
  //                               X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
  //                                             X509_LOOKUP_TYPE type,
  //                                             X509_NAME *name);
  //X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
  //                                        X509_OBJECT *x);
function  ERR_X509_OBJECT_up_ref_count(a: PX509_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_up_ref_count_procname);
end;


function  ERR_X509_OBJECT_new: PX509_OBJECT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_new_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_OBJECT_free(a: PX509_OBJECT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_free_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_OBJECT_get_type(const a: PX509_OBJECT): X509_LOOKUP_TYPE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_get_type_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_OBJECT_get0_X509(const a: PX509_OBJECT): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_get0_X509_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_set1_X509_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_get0_X509_CRL_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_OBJECT_set1_X509_CRL_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_new: PX509_STORE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_new_procname);
end;


procedure  ERR_X509_STORE_free(v: PX509_STORE); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_free_procname);
end;


function  ERR_X509_STORE_lock(ctx: PX509_STORE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_lock_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_unlock(ctx: PX509_STORE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_unlock_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_up_ref(v: PX509_STORE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_up_ref_procname);
end;

 {introduced 1.1.0}
  //STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *v);

  //STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *st, X509_NAME *nm);
  //STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(X509_STORE_CTX *st, X509_NAME *nm);
function  ERR_X509_STORE_set_flags(ctx: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_flags_procname);
end;


function  ERR_X509_STORE_set_purpose(ctx: PX509_STORE; purpose: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_purpose_procname);
end;


function  ERR_X509_STORE_set_trust(ctx: PX509_STORE; trust: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_trust_procname);
end;


function  ERR_X509_STORE_set1_param(ctx: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set1_param_procname);
end;


function  ERR_X509_STORE_get0_param(ctx: PX509_STORE): PX509_VERIFY_PARAM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get0_param_procname);
end;

 {introduced 1.1.0}

procedure  ERR_X509_STORE_set_verify(ctx: PX509_STORE; verify: X509_STORE_CTX_verify_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_verify_procname);
end;

 {introduced 1.1.0}
  //#define X509_STORE_set_verify_func(ctx, func) \
  //            X509_STORE_set_verify((ctx),(func))
procedure  ERR_X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_verify_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_verify(ctx: PX509_STORE): X509_STORE_CTX_verify_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_verify_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_verify_cb(ctx: PX509_STORE; verify_cb: X509_STORE_CTX_verify_cb); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_verify_cb_procname);
end;


  //# define X509_STORE_set_verify_cb_func(ctx,func) \
  //            X509_STORE_set_verify_cb((ctx),(func))
function  ERR_X509_STORE_get_verify_cb(ctx: PX509_STORE): X509_STORE_CTX_verify_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_verify_cb_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_get_issuer(ctx: PX509_STORE; get_issuer: X509_STORE_CTX_get_issuer_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_get_issuer_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_get_issuer(ctx: PX509_STORE): X509_STORE_CTX_get_issuer_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_get_issuer_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_check_issued(ctx: PX509_STORE; check_issued: X509_STORE_CTX_check_issued_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_issued_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_check_issued(ctx: PX509_STORE): X509_STORE_CTX_check_issued_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_issued_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_check_revocation(ctx: PX509_STORE; check_revocation: X509_STORE_CTX_check_revocation_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_revocation_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_check_revocation(ctx: PX509_STORE): X509_STORE_CTX_check_revocation_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_revocation_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_get_crl(ctx: PX509_STORE; get_crl: X509_STORE_CTX_get_crl_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_get_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_get_crl(ctx: PX509_STORE): X509_STORE_CTX_get_crl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_get_crl_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_check_crl(ctx: PX509_STORE; check_crl: X509_STORE_CTX_check_crl_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_check_crl(ctx: PX509_STORE): X509_STORE_CTX_check_crl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_crl_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_cert_crl(ctx: PX509_STORE; cert_crl: X509_STORE_CTX_cert_crl_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_cert_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_cert_crl(ctx: PX509_STORE): X509_STORE_CTX_cert_crl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_cert_crl_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_STORE_set_check_policy(ctx: PX509_STORE; check_policy: X509_STORE_CTX_check_policy_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_policy_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_check_policy(ctx: PX509_STORE): X509_STORE_CTX_check_policy_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_policy_procname);
end;

 {introduced 1.1.0}
//  procedure X509_STORE_set_lookup_certs(ctx: PX509_STORE; lookup_certs: X509_STORE_CTX_lookup_certs_fn);
//  function X509_STORE_get_lookup_certs(ctx: PX509_STORE): X509_STORE_CTX_lookup_certs_fn;
//  procedure X509_STORE_set_lookup_crls(ctx: PX509_STORE; lookup_crls: X509_STORE_CTX_lookup_crls_fn);
//  #define X509_STORE_set_lookup_crls_cb(ctx, func) \
//      X509_STORE_set_lookup_crls((ctx), (func))
//  function X509_STORE_get_lookup_crls(ctx: PX509_STORE): X509_STORE_CTX_lookup_crls_fn;
procedure  ERR_X509_STORE_set_cleanup(ctx: PX509_STORE; cleanup: X509_STORE_CTX_cleanup_fn); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_cleanup_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_cleanup(ctx: PX509_STORE): X509_STORE_CTX_cleanup_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_cleanup_procname);
end;

 {introduced 1.1.0}

  //#define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)
function  ERR_X509_STORE_set_ex_data(ctx: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_ex_data_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_get_ex_data(ctx: PX509_STORE; idx: TIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_get_ex_data_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_STORE_CTX_new: PX509_STORE_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_new_procname);
end;



function  ERR_X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get1_issuer_procname);
end;



procedure  ERR_X509_STORE_CTX_free(ctx: PX509_STORE_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_free_procname);
end;


//  TIdC_INT X509_STORE_CTX_init(ctx: PX509_STORE_CTX; store: PX509_STORE; x509: PX509; chain: P STACK_OF(X509));
//  procedure X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: P STACK_OF(X509));
procedure  ERR_X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_cleanup_procname);
end;



function  ERR_X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_store_procname);
end;


function  ERR_X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_cert_procname);
end;

 {introduced 1.1.0}
  //STACK_OF(X509)* X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *ctx);
  //void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
procedure  ERR_X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: X509_STORE_CTX_verify_cb); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_verify_cb_procname);
end;


function  ERR_X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_cb; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_verify_cb_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): X509_STORE_CTX_verify_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_verify_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_issuer_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_get_issuer_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_issued_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_issued_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_revocation_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_revocation_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_get_crl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_get_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_crl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): X509_STORE_CTX_cert_crl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_cert_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): X509_STORE_CTX_check_policy_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_policy_procname);
end;

 {introduced 1.1.0}
//  function X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_certs_fn;
//  function X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): X509_STORE_CTX_lookup_crls_fn;
function  ERR_X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): X509_STORE_CTX_cleanup_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_cleanup_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_STORE_add_lookup(v: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_add_lookup_procname);
end;


function  ERR_X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_hash_dir_procname);
end;


function  ERR_X509_LOOKUP_file: PX509_LOOKUP_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_file_procname);
end;



function  ERR_X509_LOOKUP_meth_new(const name: PIdAnsiChar): PX509_LOOKUP_METHOD; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_new_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_free_procname);
end;

 {introduced 1.1.0}

  //TIdC_INT X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*new_item) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
  //                              void (*free_fn) (X509_LOOKUP *ctx));
  //void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
  //                              TIdC_INT (*init) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);
  //
  //TIdC_INT X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD *method,
  //                                  TIdC_INT (*shutdown) (X509_LOOKUP *ctx));
  //TIdC_INT (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* method))
  //    (X509_LOOKUP *ctx);

function  ERR_X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: X509_LOOKUP_ctrl_fn): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_ctrl_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_meth_get_ctrl(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_ctrl_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_ctrl_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_subject_fn): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_subject_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_meth_get_get_by_subject(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_subject_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_subject_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_issuer_serial_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_meth_get_get_by_issuer_serial(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_issuer_serial_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_issuer_serial_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_fingerprint_fn): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_fingerprint_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_meth_get_get_by_fingerprint(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_fingerprint_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_fingerprint_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: X509_LOOKUP_get_by_alias_fn): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_alias_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_meth_get_get_by_alias(const method: PX509_LOOKUP_METHOD): X509_LOOKUP_get_by_alias_fn; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_alias_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_STORE_add_cert(ctx: PX509_STORE; x: PX509): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_add_cert_procname);
end;


function  ERR_X509_STORE_add_crl(ctx: PX509_STORE; x: PX509_CRL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_add_crl_procname);
end;



function  ERR_X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_by_subject_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; type_: X509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_obj_by_subject_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT; const argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_ctrl_procname);
end;



function  ERR_X509_load_cert_file(ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_load_cert_file_procname);
end;


function  ERR_X509_load_crl_file(ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_load_crl_file_procname);
end;


function  ERR_X509_load_cert_crl_file(ctx: PX509_LOOKUP; const file_: PIdAnsiChar; type_: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_load_cert_crl_file_procname);
end;



function  ERR_X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_new_procname);
end;


procedure  ERR_X509_LOOKUP_free(ctx: PX509_LOOKUP); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_free_procname);
end;


function  ERR_X509_LOOKUP_init(ctx: PX509_LOOKUP): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_init_procname);
end;


function  ERR_X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_subject_procname);
end;


function  ERR_X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_issuer_serial_procname);
end;


function  ERR_X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const bytes: PByte; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_fingerprint_procname);
end;


function  ERR_X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; type_: X509_LOOKUP_TYPE; const str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_alias_procname);
end;


function  ERR_X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_set_method_data_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_get_method_data(const ctx: PX509_LOOKUP): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_get_method_data_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_get_store_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_LOOKUP_shutdown_procname);
end;



function  ERR_X509_STORE_load_locations(ctx: PX509_STORE; const file_: PIdAnsiChar; const dir: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_load_locations_procname);
end;


function  ERR_X509_STORE_set_default_paths(ctx: PX509_STORE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_set_default_paths_procname);
end;



  //#define X509_STORE_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef)
function  ERR_X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_ex_data_procname);
end;


function  ERR_X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_ex_data_procname);
end;


function  ERR_X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_error_procname);
end;


procedure  ERR_X509_STORE_CTX_set_error(ctx: X509_STORE_CTX; s: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_error_procname);
end;


function  ERR_X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_error_depth_procname);
end;


procedure  ERR_X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_error_depth_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_current_cert_procname);
end;


procedure  ERR_X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_current_cert_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_current_issuer_procname);
end;


function  ERR_X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_current_crl_procname);
end;


function  ERR_X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_parent_ctx_procname);
end;


//  STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
//  STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
procedure  ERR_X509_STORE_CTX_set_cert(c: PX509_STORE_CTX; x: PX509); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_cert_procname);
end;


//  void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
//  void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c, STACK_OF(X509_CRL) *sk);
function  ERR_X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_purpose_procname);
end;


function  ERR_X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_trust_procname);
end;


function  ERR_X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_purpose_inherit_procname);
end;


procedure  ERR_X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TIdC_ULONG); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_flags_procname);
end;


//  procedure X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET);

function  ERR_X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_policy_tree_procname);
end;


function  ERR_X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_explicit_policy_procname);
end;


function  ERR_X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_num_untrusted_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_param_procname);
end;


procedure  ERR_X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_param_procname);
end;


function  ERR_X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; const name: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_default_procname);
end;



  (*
   * Bridge opacity barrier between libcrypt and libssl, also needed to support
   * offline testing in test/danetest.c
   *)
procedure  ERR_X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_dane_procname);
end;

 {introduced 1.1.0}

  (* X509_VERIFY_PARAM functions *)

function  ERR_X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_new_procname);
end;


procedure  ERR_X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_free_procname);
end;


function  ERR_X509_VERIFY_PARAM_inherit(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_inherit_procname);
end;


function  ERR_X509_VERIFY_PARAM_set1(to_: PX509_VERIFY_PARAM; const from: PX509_VERIFY_PARAM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_procname);
end;


function  ERR_X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; const name: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_name_procname);
end;


function  ERR_X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_flags_procname);
end;


function  ERR_X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_clear_flags_procname);
end;


function  ERR_X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TIdC_ULONG; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_flags_procname);
end;


function  ERR_X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_purpose_procname);
end;


function  ERR_X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_trust_procname);
end;


procedure  ERR_X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_depth_procname);
end;


procedure  ERR_X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TIdC_INT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_auth_level_procname);
end;

 {introduced 1.1.0}
//  function X509_VERIFY_PARAM_get_time(const param: PX509_VERIFY_PARAM): TIdC_TIMET;
//  procedure X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET);
function  ERR_X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_add0_policy_procname);
end;


  //TIdC_INT X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
  //                                    STACK_OF(ASN1_OBJECT) *policies);

function  ERR_X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_inh_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_VERIFY_PARAM_get_inh_flags(const param: PX509_VERIFY_PARAM): TIdC_UINT32; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_inh_flags_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; const name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_host_procname);
end;


function  ERR_X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; const name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_add1_host_procname);
end;


procedure  ERR_X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_hostflags_procname);
end;


function  ERR_X509_VERIFY_PARAM_get_hostflags(const param: PX509_VERIFY_PARAM): TIdC_UINT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_hostflags_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_VERIFY_PARAM_get0_peername(v1: PX509_VERIFY_PARAM): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_peername_procname);
end;


procedure  ERR_X509_VERIFY_PARAM_move_peername(v1: PX509_VERIFY_PARAM; v2: PX509_VERIFY_PARAM); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_move_peername_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; const email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_email_procname);
end;


function  ERR_X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; const ip: PByte; iplen: TIdC_SIZET): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_ip_procname);
end;


function  ERR_X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; const ipasc: PIdAnsiChar): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_ip_asc_procname);
end;



function  ERR_X509_VERIFY_PARAM_get_depth(const param: PX509_VERIFY_PARAM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_depth_procname);
end;


function  ERR_X509_VERIFY_PARAM_get_auth_level(const param: PX509_VERIFY_PARAM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_auth_level_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_VERIFY_PARAM_get0_name(const param: PX509_VERIFY_PARAM): PIdAnsiChar; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_name_procname);
end;



function  ERR_X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_add0_table_procname);
end;


function  ERR_X509_VERIFY_PARAM_get_count: TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_count_procname);
end;


function  ERR_X509_VERIFY_PARAM_get0(id: TIdC_INT): PX509_VERIFY_PARAM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_procname);
end;


function  ERR_X509_VERIFY_PARAM_lookup(const name: PIdAnsiChar): X509_VERIFY_PARAM; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_lookup_procname);
end;


procedure  ERR_X509_VERIFY_PARAM_table_cleanup; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_table_cleanup_procname);
end;



  //TIdC_INT X509_policy_check(X509_POLICY_TREE **ptree, TIdC_INT *pexplicit_policy,
  //                      STACK_OF(X509) *certs,
  //                      STACK_OF(ASN1_OBJECT) *policy_oids, TIdC_UINT flags);

procedure  ERR_X509_policy_tree_free(tree: PX509_POLICY_TREE); 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_tree_free_procname);
end;



function  ERR_X509_policy_tree_level_count(const tree: PX509_POLICY_TREE): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_tree_level_count_procname);
end;


function  ERR_X509_policy_tree_get0_level(const tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_tree_get0_level_procname);
end;



  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_policies(const
  //                                                           X509_POLICY_TREE
  //                                                           *tree);
  //
  //STACK_OF(X509_POLICY_NODE) *X509_policy_tree_get0_user_policies(const
  //                                                                X509_POLICY_TREE
  //                                                                *tree);

function  ERR_X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TIdC_INT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_level_node_count_procname);
end;



function  ERR_X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_level_get0_node_procname);
end;



function  ERR_X509_policy_node_get0_policy(const node: PX509_POLICY_NODE): PASN1_OBJECT; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_node_get0_policy_procname);
end;



  //STACK_OF(POLICYQUALINFO) *X509_policy_node_get0_qualifiers(const
  //                                                           X509_POLICY_NODE
  //                                                           *node);
function  ERR_X509_policy_node_get0_parent(const node: PX509_POLICY_NODE): PX509_POLICY_NODE; 
begin
  EIdAPIFunctionNotPresent.RaiseException(X509_policy_node_get0_parent_procname);
end;



{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  X509_STORE_set_depth := LoadLibFunction(ADllHandle, X509_STORE_set_depth_procname);
  FuncLoadError := not assigned(X509_STORE_set_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_depth_allownil)}
    X509_STORE_set_depth := @ERR_X509_STORE_set_depth;
    {$ifend}
    {$if declared(X509_STORE_set_depth_introduced)}
    if LibVersion < X509_STORE_set_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_set_depth)}
      X509_STORE_set_depth := @FC_X509_STORE_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_depth_removed)}
    if X509_STORE_set_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_depth)}
      X509_STORE_set_depth := @_X509_STORE_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_depth');
    {$ifend}
  end;


  X509_STORE_CTX_set_depth := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_depth_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_depth_allownil)}
    X509_STORE_CTX_set_depth := @ERR_X509_STORE_CTX_set_depth;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_depth_introduced)}
    if LibVersion < X509_STORE_CTX_set_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_depth)}
      X509_STORE_CTX_set_depth := @FC_X509_STORE_CTX_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_depth_removed)}
    if X509_STORE_CTX_set_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_depth)}
      X509_STORE_CTX_set_depth := @_X509_STORE_CTX_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_depth');
    {$ifend}
  end;


  X509_STORE_CTX_get_app_data := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_app_data_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_app_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_app_data_allownil)}
    X509_STORE_CTX_get_app_data := @ERR_X509_STORE_CTX_get_app_data;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_app_data_introduced)}
    if LibVersion < X509_STORE_CTX_get_app_data_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_app_data)}
      X509_STORE_CTX_get_app_data := @FC_X509_STORE_CTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_app_data_removed)}
    if X509_STORE_CTX_get_app_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_app_data)}
      X509_STORE_CTX_get_app_data := @_X509_STORE_CTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_app_data');
    {$ifend}
  end;

 
  X509_OBJECT_up_ref_count := LoadLibFunction(ADllHandle, X509_OBJECT_up_ref_count_procname);
  FuncLoadError := not assigned(X509_OBJECT_up_ref_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_up_ref_count_allownil)}
    X509_OBJECT_up_ref_count := @ERR_X509_OBJECT_up_ref_count;
    {$ifend}
    {$if declared(X509_OBJECT_up_ref_count_introduced)}
    if LibVersion < X509_OBJECT_up_ref_count_introduced then
    begin
      {$if declared(FC_X509_OBJECT_up_ref_count)}
      X509_OBJECT_up_ref_count := @FC_X509_OBJECT_up_ref_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_up_ref_count_removed)}
    if X509_OBJECT_up_ref_count_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_up_ref_count)}
      X509_OBJECT_up_ref_count := @_X509_OBJECT_up_ref_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_up_ref_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_up_ref_count');
    {$ifend}
  end;


  X509_OBJECT_new := LoadLibFunction(ADllHandle, X509_OBJECT_new_procname);
  FuncLoadError := not assigned(X509_OBJECT_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_new_allownil)}
    X509_OBJECT_new := @ERR_X509_OBJECT_new;
    {$ifend}
    {$if declared(X509_OBJECT_new_introduced)}
    if LibVersion < X509_OBJECT_new_introduced then
    begin
      {$if declared(FC_X509_OBJECT_new)}
      X509_OBJECT_new := @FC_X509_OBJECT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_new_removed)}
    if X509_OBJECT_new_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_new)}
      X509_OBJECT_new := @_X509_OBJECT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_OBJECT_free := LoadLibFunction(ADllHandle, X509_OBJECT_free_procname);
  FuncLoadError := not assigned(X509_OBJECT_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_free_allownil)}
    X509_OBJECT_free := @ERR_X509_OBJECT_free;
    {$ifend}
    {$if declared(X509_OBJECT_free_introduced)}
    if LibVersion < X509_OBJECT_free_introduced then
    begin
      {$if declared(FC_X509_OBJECT_free)}
      X509_OBJECT_free := @FC_X509_OBJECT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_free_removed)}
    if X509_OBJECT_free_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_free)}
      X509_OBJECT_free := @_X509_OBJECT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_OBJECT_get_type := LoadLibFunction(ADllHandle, X509_OBJECT_get_type_procname);
  FuncLoadError := not assigned(X509_OBJECT_get_type);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_get_type_allownil)}
    X509_OBJECT_get_type := @ERR_X509_OBJECT_get_type;
    {$ifend}
    {$if declared(X509_OBJECT_get_type_introduced)}
    if LibVersion < X509_OBJECT_get_type_introduced then
    begin
      {$if declared(FC_X509_OBJECT_get_type)}
      X509_OBJECT_get_type := @FC_X509_OBJECT_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_get_type_removed)}
    if X509_OBJECT_get_type_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_get_type)}
      X509_OBJECT_get_type := @_X509_OBJECT_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_get_type');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_OBJECT_get0_X509 := LoadLibFunction(ADllHandle, X509_OBJECT_get0_X509_procname);
  FuncLoadError := not assigned(X509_OBJECT_get0_X509);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_get0_X509_allownil)}
    X509_OBJECT_get0_X509 := @ERR_X509_OBJECT_get0_X509;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_introduced)}
    if LibVersion < X509_OBJECT_get0_X509_introduced then
    begin
      {$if declared(FC_X509_OBJECT_get0_X509)}
      X509_OBJECT_get0_X509 := @FC_X509_OBJECT_get0_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_removed)}
    if X509_OBJECT_get0_X509_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_get0_X509)}
      X509_OBJECT_get0_X509 := @_X509_OBJECT_get0_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_get0_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_get0_X509');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_OBJECT_set1_X509 := LoadLibFunction(ADllHandle, X509_OBJECT_set1_X509_procname);
  FuncLoadError := not assigned(X509_OBJECT_set1_X509);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_set1_X509_allownil)}
    X509_OBJECT_set1_X509 := @ERR_X509_OBJECT_set1_X509;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_introduced)}
    if LibVersion < X509_OBJECT_set1_X509_introduced then
    begin
      {$if declared(FC_X509_OBJECT_set1_X509)}
      X509_OBJECT_set1_X509 := @FC_X509_OBJECT_set1_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_removed)}
    if X509_OBJECT_set1_X509_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_set1_X509)}
      X509_OBJECT_set1_X509 := @_X509_OBJECT_set1_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_set1_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_set1_X509');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_OBJECT_get0_X509_CRL := LoadLibFunction(ADllHandle, X509_OBJECT_get0_X509_CRL_procname);
  FuncLoadError := not assigned(X509_OBJECT_get0_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_get0_X509_CRL_allownil)}
    X509_OBJECT_get0_X509_CRL := @ERR_X509_OBJECT_get0_X509_CRL;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_CRL_introduced)}
    if LibVersion < X509_OBJECT_get0_X509_CRL_introduced then
    begin
      {$if declared(FC_X509_OBJECT_get0_X509_CRL)}
      X509_OBJECT_get0_X509_CRL := @FC_X509_OBJECT_get0_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_CRL_removed)}
    if X509_OBJECT_get0_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_get0_X509_CRL)}
      X509_OBJECT_get0_X509_CRL := @_X509_OBJECT_get0_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_get0_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_get0_X509_CRL');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_OBJECT_set1_X509_CRL := LoadLibFunction(ADllHandle, X509_OBJECT_set1_X509_CRL_procname);
  FuncLoadError := not assigned(X509_OBJECT_set1_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_set1_X509_CRL_allownil)}
    X509_OBJECT_set1_X509_CRL := @ERR_X509_OBJECT_set1_X509_CRL;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_CRL_introduced)}
    if LibVersion < X509_OBJECT_set1_X509_CRL_introduced then
    begin
      {$if declared(FC_X509_OBJECT_set1_X509_CRL)}
      X509_OBJECT_set1_X509_CRL := @FC_X509_OBJECT_set1_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_CRL_removed)}
    if X509_OBJECT_set1_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_set1_X509_CRL)}
      X509_OBJECT_set1_X509_CRL := @_X509_OBJECT_set1_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_set1_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_set1_X509_CRL');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_new := LoadLibFunction(ADllHandle, X509_STORE_new_procname);
  FuncLoadError := not assigned(X509_STORE_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_new_allownil)}
    X509_STORE_new := @ERR_X509_STORE_new;
    {$ifend}
    {$if declared(X509_STORE_new_introduced)}
    if LibVersion < X509_STORE_new_introduced then
    begin
      {$if declared(FC_X509_STORE_new)}
      X509_STORE_new := @FC_X509_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_new_removed)}
    if X509_STORE_new_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_new)}
      X509_STORE_new := @_X509_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_new');
    {$ifend}
  end;


  X509_STORE_free := LoadLibFunction(ADllHandle, X509_STORE_free_procname);
  FuncLoadError := not assigned(X509_STORE_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_free_allownil)}
    X509_STORE_free := @ERR_X509_STORE_free;
    {$ifend}
    {$if declared(X509_STORE_free_introduced)}
    if LibVersion < X509_STORE_free_introduced then
    begin
      {$if declared(FC_X509_STORE_free)}
      X509_STORE_free := @FC_X509_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_free_removed)}
    if X509_STORE_free_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_free)}
      X509_STORE_free := @_X509_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_free');
    {$ifend}
  end;


  X509_STORE_lock := LoadLibFunction(ADllHandle, X509_STORE_lock_procname);
  FuncLoadError := not assigned(X509_STORE_lock);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_lock_allownil)}
    X509_STORE_lock := @ERR_X509_STORE_lock;
    {$ifend}
    {$if declared(X509_STORE_lock_introduced)}
    if LibVersion < X509_STORE_lock_introduced then
    begin
      {$if declared(FC_X509_STORE_lock)}
      X509_STORE_lock := @FC_X509_STORE_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_lock_removed)}
    if X509_STORE_lock_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_lock)}
      X509_STORE_lock := @_X509_STORE_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_lock_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_lock');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_unlock := LoadLibFunction(ADllHandle, X509_STORE_unlock_procname);
  FuncLoadError := not assigned(X509_STORE_unlock);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_unlock_allownil)}
    X509_STORE_unlock := @ERR_X509_STORE_unlock;
    {$ifend}
    {$if declared(X509_STORE_unlock_introduced)}
    if LibVersion < X509_STORE_unlock_introduced then
    begin
      {$if declared(FC_X509_STORE_unlock)}
      X509_STORE_unlock := @FC_X509_STORE_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_unlock_removed)}
    if X509_STORE_unlock_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_unlock)}
      X509_STORE_unlock := @_X509_STORE_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_unlock_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_unlock');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_up_ref := LoadLibFunction(ADllHandle, X509_STORE_up_ref_procname);
  FuncLoadError := not assigned(X509_STORE_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_up_ref_allownil)}
    X509_STORE_up_ref := @ERR_X509_STORE_up_ref;
    {$ifend}
    {$if declared(X509_STORE_up_ref_introduced)}
    if LibVersion < X509_STORE_up_ref_introduced then
    begin
      {$if declared(FC_X509_STORE_up_ref)}
      X509_STORE_up_ref := @FC_X509_STORE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_up_ref_removed)}
    if X509_STORE_up_ref_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_up_ref)}
      X509_STORE_up_ref := @_X509_STORE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_up_ref');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_flags := LoadLibFunction(ADllHandle, X509_STORE_set_flags_procname);
  FuncLoadError := not assigned(X509_STORE_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_flags_allownil)}
    X509_STORE_set_flags := @ERR_X509_STORE_set_flags;
    {$ifend}
    {$if declared(X509_STORE_set_flags_introduced)}
    if LibVersion < X509_STORE_set_flags_introduced then
    begin
      {$if declared(FC_X509_STORE_set_flags)}
      X509_STORE_set_flags := @FC_X509_STORE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_flags_removed)}
    if X509_STORE_set_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_flags)}
      X509_STORE_set_flags := @_X509_STORE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_flags');
    {$ifend}
  end;


  X509_STORE_set_purpose := LoadLibFunction(ADllHandle, X509_STORE_set_purpose_procname);
  FuncLoadError := not assigned(X509_STORE_set_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_purpose_allownil)}
    X509_STORE_set_purpose := @ERR_X509_STORE_set_purpose;
    {$ifend}
    {$if declared(X509_STORE_set_purpose_introduced)}
    if LibVersion < X509_STORE_set_purpose_introduced then
    begin
      {$if declared(FC_X509_STORE_set_purpose)}
      X509_STORE_set_purpose := @FC_X509_STORE_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_purpose_removed)}
    if X509_STORE_set_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_purpose)}
      X509_STORE_set_purpose := @_X509_STORE_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_purpose');
    {$ifend}
  end;


  X509_STORE_set_trust := LoadLibFunction(ADllHandle, X509_STORE_set_trust_procname);
  FuncLoadError := not assigned(X509_STORE_set_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_trust_allownil)}
    X509_STORE_set_trust := @ERR_X509_STORE_set_trust;
    {$ifend}
    {$if declared(X509_STORE_set_trust_introduced)}
    if LibVersion < X509_STORE_set_trust_introduced then
    begin
      {$if declared(FC_X509_STORE_set_trust)}
      X509_STORE_set_trust := @FC_X509_STORE_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_trust_removed)}
    if X509_STORE_set_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_trust)}
      X509_STORE_set_trust := @_X509_STORE_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_trust');
    {$ifend}
  end;


  X509_STORE_set1_param := LoadLibFunction(ADllHandle, X509_STORE_set1_param_procname);
  FuncLoadError := not assigned(X509_STORE_set1_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set1_param_allownil)}
    X509_STORE_set1_param := @ERR_X509_STORE_set1_param;
    {$ifend}
    {$if declared(X509_STORE_set1_param_introduced)}
    if LibVersion < X509_STORE_set1_param_introduced then
    begin
      {$if declared(FC_X509_STORE_set1_param)}
      X509_STORE_set1_param := @FC_X509_STORE_set1_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set1_param_removed)}
    if X509_STORE_set1_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set1_param)}
      X509_STORE_set1_param := @_X509_STORE_set1_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set1_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set1_param');
    {$ifend}
  end;


  X509_STORE_get0_param := LoadLibFunction(ADllHandle, X509_STORE_get0_param_procname);
  FuncLoadError := not assigned(X509_STORE_get0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get0_param_allownil)}
    X509_STORE_get0_param := @ERR_X509_STORE_get0_param;
    {$ifend}
    {$if declared(X509_STORE_get0_param_introduced)}
    if LibVersion < X509_STORE_get0_param_introduced then
    begin
      {$if declared(FC_X509_STORE_get0_param)}
      X509_STORE_get0_param := @FC_X509_STORE_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get0_param_removed)}
    if X509_STORE_get0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get0_param)}
      X509_STORE_get0_param := @_X509_STORE_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get0_param');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_verify := LoadLibFunction(ADllHandle, X509_STORE_set_verify_procname);
  FuncLoadError := not assigned(X509_STORE_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_verify_allownil)}
    X509_STORE_set_verify := @ERR_X509_STORE_set_verify;
    {$ifend}
    {$if declared(X509_STORE_set_verify_introduced)}
    if LibVersion < X509_STORE_set_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_set_verify)}
      X509_STORE_set_verify := @FC_X509_STORE_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_verify_removed)}
    if X509_STORE_set_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_verify)}
      X509_STORE_set_verify := @_X509_STORE_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_verify');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_set_verify := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_verify_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_verify_allownil)}
    X509_STORE_CTX_set_verify := @ERR_X509_STORE_CTX_set_verify;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_introduced)}
    if LibVersion < X509_STORE_CTX_set_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_verify)}
      X509_STORE_CTX_set_verify := @FC_X509_STORE_CTX_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_removed)}
    if X509_STORE_CTX_set_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_verify)}
      X509_STORE_CTX_set_verify := @_X509_STORE_CTX_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_verify');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_verify := LoadLibFunction(ADllHandle, X509_STORE_get_verify_procname);
  FuncLoadError := not assigned(X509_STORE_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_verify_allownil)}
    X509_STORE_get_verify := @ERR_X509_STORE_get_verify;
    {$ifend}
    {$if declared(X509_STORE_get_verify_introduced)}
    if LibVersion < X509_STORE_get_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_get_verify)}
      X509_STORE_get_verify := @FC_X509_STORE_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_verify_removed)}
    if X509_STORE_get_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_verify)}
      X509_STORE_get_verify := @_X509_STORE_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_verify');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_set_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_set_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_verify_cb_allownil)}
    X509_STORE_set_verify_cb := @ERR_X509_STORE_set_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_set_verify_cb_introduced)}
    if LibVersion < X509_STORE_set_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_set_verify_cb)}
      X509_STORE_set_verify_cb := @FC_X509_STORE_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_verify_cb_removed)}
    if X509_STORE_set_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_verify_cb)}
      X509_STORE_set_verify_cb := @_X509_STORE_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_verify_cb');
    {$ifend}
  end;


  X509_STORE_get_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_get_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_get_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_verify_cb_allownil)}
    X509_STORE_get_verify_cb := @ERR_X509_STORE_get_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_get_verify_cb_introduced)}
    if LibVersion < X509_STORE_get_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_get_verify_cb)}
      X509_STORE_get_verify_cb := @FC_X509_STORE_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_verify_cb_removed)}
    if X509_STORE_get_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_verify_cb)}
      X509_STORE_get_verify_cb := @_X509_STORE_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_verify_cb');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_get_issuer := LoadLibFunction(ADllHandle, X509_STORE_set_get_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_set_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_get_issuer_allownil)}
    X509_STORE_set_get_issuer := @ERR_X509_STORE_set_get_issuer;
    {$ifend}
    {$if declared(X509_STORE_set_get_issuer_introduced)}
    if LibVersion < X509_STORE_set_get_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_set_get_issuer)}
      X509_STORE_set_get_issuer := @FC_X509_STORE_set_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_get_issuer_removed)}
    if X509_STORE_set_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_get_issuer)}
      X509_STORE_set_get_issuer := @_X509_STORE_set_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_get_issuer');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_get_issuer := LoadLibFunction(ADllHandle, X509_STORE_get_get_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_get_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_get_issuer_allownil)}
    X509_STORE_get_get_issuer := @ERR_X509_STORE_get_get_issuer;
    {$ifend}
    {$if declared(X509_STORE_get_get_issuer_introduced)}
    if LibVersion < X509_STORE_get_get_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_get_get_issuer)}
      X509_STORE_get_get_issuer := @FC_X509_STORE_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_get_issuer_removed)}
    if X509_STORE_get_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_get_issuer)}
      X509_STORE_get_get_issuer := @_X509_STORE_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_get_issuer');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_check_issued := LoadLibFunction(ADllHandle, X509_STORE_set_check_issued_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_issued_allownil)}
    X509_STORE_set_check_issued := @ERR_X509_STORE_set_check_issued;
    {$ifend}
    {$if declared(X509_STORE_set_check_issued_introduced)}
    if LibVersion < X509_STORE_set_check_issued_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_issued)}
      X509_STORE_set_check_issued := @FC_X509_STORE_set_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_issued_removed)}
    if X509_STORE_set_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_issued)}
      X509_STORE_set_check_issued := @_X509_STORE_set_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_issued');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_check_issued := LoadLibFunction(ADllHandle, X509_STORE_get_check_issued_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_issued_allownil)}
    X509_STORE_get_check_issued := @ERR_X509_STORE_get_check_issued;
    {$ifend}
    {$if declared(X509_STORE_get_check_issued_introduced)}
    if LibVersion < X509_STORE_get_check_issued_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_issued)}
      X509_STORE_get_check_issued := @FC_X509_STORE_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_issued_removed)}
    if X509_STORE_get_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_issued)}
      X509_STORE_get_check_issued := @_X509_STORE_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_issued');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_check_revocation := LoadLibFunction(ADllHandle, X509_STORE_set_check_revocation_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_revocation);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_revocation_allownil)}
    X509_STORE_set_check_revocation := @ERR_X509_STORE_set_check_revocation;
    {$ifend}
    {$if declared(X509_STORE_set_check_revocation_introduced)}
    if LibVersion < X509_STORE_set_check_revocation_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_revocation)}
      X509_STORE_set_check_revocation := @FC_X509_STORE_set_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_revocation_removed)}
    if X509_STORE_set_check_revocation_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_revocation)}
      X509_STORE_set_check_revocation := @_X509_STORE_set_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_revocation_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_revocation');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_check_revocation := LoadLibFunction(ADllHandle, X509_STORE_get_check_revocation_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_revocation);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_revocation_allownil)}
    X509_STORE_get_check_revocation := @ERR_X509_STORE_get_check_revocation;
    {$ifend}
    {$if declared(X509_STORE_get_check_revocation_introduced)}
    if LibVersion < X509_STORE_get_check_revocation_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_revocation)}
      X509_STORE_get_check_revocation := @FC_X509_STORE_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_revocation_removed)}
    if X509_STORE_get_check_revocation_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_revocation)}
      X509_STORE_get_check_revocation := @_X509_STORE_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_revocation_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_revocation');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_get_crl := LoadLibFunction(ADllHandle, X509_STORE_set_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_set_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_get_crl_allownil)}
    X509_STORE_set_get_crl := @ERR_X509_STORE_set_get_crl;
    {$ifend}
    {$if declared(X509_STORE_set_get_crl_introduced)}
    if LibVersion < X509_STORE_set_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_set_get_crl)}
      X509_STORE_set_get_crl := @FC_X509_STORE_set_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_get_crl_removed)}
    if X509_STORE_set_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_get_crl)}
      X509_STORE_set_get_crl := @_X509_STORE_set_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_get_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_get_crl := LoadLibFunction(ADllHandle, X509_STORE_get_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_get_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_get_crl_allownil)}
    X509_STORE_get_get_crl := @ERR_X509_STORE_get_get_crl;
    {$ifend}
    {$if declared(X509_STORE_get_get_crl_introduced)}
    if LibVersion < X509_STORE_get_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_get_get_crl)}
      X509_STORE_get_get_crl := @FC_X509_STORE_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_get_crl_removed)}
    if X509_STORE_get_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_get_crl)}
      X509_STORE_get_get_crl := @_X509_STORE_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_get_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_check_crl := LoadLibFunction(ADllHandle, X509_STORE_set_check_crl_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_crl_allownil)}
    X509_STORE_set_check_crl := @ERR_X509_STORE_set_check_crl;
    {$ifend}
    {$if declared(X509_STORE_set_check_crl_introduced)}
    if LibVersion < X509_STORE_set_check_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_crl)}
      X509_STORE_set_check_crl := @FC_X509_STORE_set_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_crl_removed)}
    if X509_STORE_set_check_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_crl)}
      X509_STORE_set_check_crl := @_X509_STORE_set_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_check_crl := LoadLibFunction(ADllHandle, X509_STORE_get_check_crl_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_crl_allownil)}
    X509_STORE_get_check_crl := @ERR_X509_STORE_get_check_crl;
    {$ifend}
    {$if declared(X509_STORE_get_check_crl_introduced)}
    if LibVersion < X509_STORE_get_check_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_crl)}
      X509_STORE_get_check_crl := @FC_X509_STORE_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_crl_removed)}
    if X509_STORE_get_check_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_crl)}
      X509_STORE_get_check_crl := @_X509_STORE_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_cert_crl := LoadLibFunction(ADllHandle, X509_STORE_set_cert_crl_procname);
  FuncLoadError := not assigned(X509_STORE_set_cert_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_cert_crl_allownil)}
    X509_STORE_set_cert_crl := @ERR_X509_STORE_set_cert_crl;
    {$ifend}
    {$if declared(X509_STORE_set_cert_crl_introduced)}
    if LibVersion < X509_STORE_set_cert_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_set_cert_crl)}
      X509_STORE_set_cert_crl := @FC_X509_STORE_set_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_cert_crl_removed)}
    if X509_STORE_set_cert_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_cert_crl)}
      X509_STORE_set_cert_crl := @_X509_STORE_set_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_cert_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_cert_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_cert_crl := LoadLibFunction(ADllHandle, X509_STORE_get_cert_crl_procname);
  FuncLoadError := not assigned(X509_STORE_get_cert_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_cert_crl_allownil)}
    X509_STORE_get_cert_crl := @ERR_X509_STORE_get_cert_crl;
    {$ifend}
    {$if declared(X509_STORE_get_cert_crl_introduced)}
    if LibVersion < X509_STORE_get_cert_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_get_cert_crl)}
      X509_STORE_get_cert_crl := @FC_X509_STORE_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_cert_crl_removed)}
    if X509_STORE_get_cert_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_cert_crl)}
      X509_STORE_get_cert_crl := @_X509_STORE_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_cert_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_cert_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_check_policy := LoadLibFunction(ADllHandle, X509_STORE_set_check_policy_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_policy_allownil)}
    X509_STORE_set_check_policy := @ERR_X509_STORE_set_check_policy;
    {$ifend}
    {$if declared(X509_STORE_set_check_policy_introduced)}
    if LibVersion < X509_STORE_set_check_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_policy)}
      X509_STORE_set_check_policy := @FC_X509_STORE_set_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_policy_removed)}
    if X509_STORE_set_check_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_policy)}
      X509_STORE_set_check_policy := @_X509_STORE_set_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_policy');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_check_policy := LoadLibFunction(ADllHandle, X509_STORE_get_check_policy_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_policy_allownil)}
    X509_STORE_get_check_policy := @ERR_X509_STORE_get_check_policy;
    {$ifend}
    {$if declared(X509_STORE_get_check_policy_introduced)}
    if LibVersion < X509_STORE_get_check_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_policy)}
      X509_STORE_get_check_policy := @FC_X509_STORE_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_policy_removed)}
    if X509_STORE_get_check_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_policy)}
      X509_STORE_get_check_policy := @_X509_STORE_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_policy');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_cleanup := LoadLibFunction(ADllHandle, X509_STORE_set_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_cleanup_allownil)}
    X509_STORE_set_cleanup := @ERR_X509_STORE_set_cleanup;
    {$ifend}
    {$if declared(X509_STORE_set_cleanup_introduced)}
    if LibVersion < X509_STORE_set_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_set_cleanup)}
      X509_STORE_set_cleanup := @FC_X509_STORE_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_cleanup_removed)}
    if X509_STORE_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_cleanup)}
      X509_STORE_set_cleanup := @_X509_STORE_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_cleanup := LoadLibFunction(ADllHandle, X509_STORE_get_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_cleanup_allownil)}
    X509_STORE_get_cleanup := @ERR_X509_STORE_get_cleanup;
    {$ifend}
    {$if declared(X509_STORE_get_cleanup_introduced)}
    if LibVersion < X509_STORE_get_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_get_cleanup)}
      X509_STORE_get_cleanup := @FC_X509_STORE_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_cleanup_removed)}
    if X509_STORE_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_cleanup)}
      X509_STORE_get_cleanup := @_X509_STORE_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_set_ex_data := LoadLibFunction(ADllHandle, X509_STORE_set_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_ex_data_allownil)}
    X509_STORE_set_ex_data := @ERR_X509_STORE_set_ex_data;
    {$ifend}
    {$if declared(X509_STORE_set_ex_data_introduced)}
    if LibVersion < X509_STORE_set_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_set_ex_data)}
      X509_STORE_set_ex_data := @FC_X509_STORE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_ex_data_removed)}
    if X509_STORE_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_ex_data)}
      X509_STORE_set_ex_data := @_X509_STORE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_ex_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_get_ex_data := LoadLibFunction(ADllHandle, X509_STORE_get_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_ex_data_allownil)}
    X509_STORE_get_ex_data := @ERR_X509_STORE_get_ex_data;
    {$ifend}
    {$if declared(X509_STORE_get_ex_data_introduced)}
    if LibVersion < X509_STORE_get_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_get_ex_data)}
      X509_STORE_get_ex_data := @FC_X509_STORE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_ex_data_removed)}
    if X509_STORE_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_ex_data)}
      X509_STORE_get_ex_data := @_X509_STORE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_ex_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_new := LoadLibFunction(ADllHandle, X509_STORE_CTX_new_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_new_allownil)}
    X509_STORE_CTX_new := @ERR_X509_STORE_CTX_new;
    {$ifend}
    {$if declared(X509_STORE_CTX_new_introduced)}
    if LibVersion < X509_STORE_CTX_new_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_new)}
      X509_STORE_CTX_new := @FC_X509_STORE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_new_removed)}
    if X509_STORE_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_new)}
      X509_STORE_CTX_new := @_X509_STORE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_new');
    {$ifend}
  end;


  X509_STORE_CTX_get1_issuer := LoadLibFunction(ADllHandle, X509_STORE_CTX_get1_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get1_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get1_issuer_allownil)}
    X509_STORE_CTX_get1_issuer := @ERR_X509_STORE_CTX_get1_issuer;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_issuer_introduced)}
    if LibVersion < X509_STORE_CTX_get1_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get1_issuer)}
      X509_STORE_CTX_get1_issuer := @FC_X509_STORE_CTX_get1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_issuer_removed)}
    if X509_STORE_CTX_get1_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get1_issuer)}
      X509_STORE_CTX_get1_issuer := @_X509_STORE_CTX_get1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get1_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get1_issuer');
    {$ifend}
  end;


  X509_STORE_CTX_free := LoadLibFunction(ADllHandle, X509_STORE_CTX_free_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_free_allownil)}
    X509_STORE_CTX_free := @ERR_X509_STORE_CTX_free;
    {$ifend}
    {$if declared(X509_STORE_CTX_free_introduced)}
    if LibVersion < X509_STORE_CTX_free_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_free)}
      X509_STORE_CTX_free := @FC_X509_STORE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_free_removed)}
    if X509_STORE_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_free)}
      X509_STORE_CTX_free := @_X509_STORE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_free');
    {$ifend}
  end;


  X509_STORE_CTX_cleanup := LoadLibFunction(ADllHandle, X509_STORE_CTX_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_cleanup_allownil)}
    X509_STORE_CTX_cleanup := @ERR_X509_STORE_CTX_cleanup;
    {$ifend}
    {$if declared(X509_STORE_CTX_cleanup_introduced)}
    if LibVersion < X509_STORE_CTX_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_cleanup)}
      X509_STORE_CTX_cleanup := @FC_X509_STORE_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_cleanup_removed)}
    if X509_STORE_CTX_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_cleanup)}
      X509_STORE_CTX_cleanup := @_X509_STORE_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_cleanup');
    {$ifend}
  end;


  X509_STORE_CTX_get0_store := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_store_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_store);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_store_allownil)}
    X509_STORE_CTX_get0_store := @ERR_X509_STORE_CTX_get0_store;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_store_introduced)}
    if LibVersion < X509_STORE_CTX_get0_store_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_store)}
      X509_STORE_CTX_get0_store := @FC_X509_STORE_CTX_get0_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_store_removed)}
    if X509_STORE_CTX_get0_store_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_store)}
      X509_STORE_CTX_get0_store := @_X509_STORE_CTX_get0_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_store_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_store');
    {$ifend}
  end;


  X509_STORE_CTX_get0_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_cert_allownil)}
    X509_STORE_CTX_get0_cert := @ERR_X509_STORE_CTX_get0_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_cert_introduced)}
    if LibVersion < X509_STORE_CTX_get0_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_cert)}
      X509_STORE_CTX_get0_cert := @FC_X509_STORE_CTX_get0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_cert_removed)}
    if X509_STORE_CTX_get0_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_cert)}
      X509_STORE_CTX_get0_cert := @_X509_STORE_CTX_get0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_cert');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_set_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_verify_cb_allownil)}
    X509_STORE_CTX_set_verify_cb := @ERR_X509_STORE_CTX_set_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_cb_introduced)}
    if LibVersion < X509_STORE_CTX_set_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_verify_cb)}
      X509_STORE_CTX_set_verify_cb := @FC_X509_STORE_CTX_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_cb_removed)}
    if X509_STORE_CTX_set_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_verify_cb)}
      X509_STORE_CTX_set_verify_cb := @_X509_STORE_CTX_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_verify_cb');
    {$ifend}
  end;


  X509_STORE_CTX_get_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_verify_cb_allownil)}
    X509_STORE_CTX_get_verify_cb := @ERR_X509_STORE_CTX_get_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_cb_introduced)}
    if LibVersion < X509_STORE_CTX_get_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_verify_cb)}
      X509_STORE_CTX_get_verify_cb := @FC_X509_STORE_CTX_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_cb_removed)}
    if X509_STORE_CTX_get_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_verify_cb)}
      X509_STORE_CTX_get_verify_cb := @_X509_STORE_CTX_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_verify_cb');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_verify := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_verify_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_verify_allownil)}
    X509_STORE_CTX_get_verify := @ERR_X509_STORE_CTX_get_verify;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_introduced)}
    if LibVersion < X509_STORE_CTX_get_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_verify)}
      X509_STORE_CTX_get_verify := @FC_X509_STORE_CTX_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_removed)}
    if X509_STORE_CTX_get_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_verify)}
      X509_STORE_CTX_get_verify := @_X509_STORE_CTX_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_verify');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_get_issuer := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_get_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_get_issuer_allownil)}
    X509_STORE_CTX_get_get_issuer := @ERR_X509_STORE_CTX_get_get_issuer;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_issuer_introduced)}
    if LibVersion < X509_STORE_CTX_get_get_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_get_issuer)}
      X509_STORE_CTX_get_get_issuer := @FC_X509_STORE_CTX_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_issuer_removed)}
    if X509_STORE_CTX_get_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_get_issuer)}
      X509_STORE_CTX_get_get_issuer := @_X509_STORE_CTX_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_get_issuer');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_check_issued := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_issued_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_issued_allownil)}
    X509_STORE_CTX_get_check_issued := @ERR_X509_STORE_CTX_get_check_issued;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_issued_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_issued_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_issued)}
      X509_STORE_CTX_get_check_issued := @FC_X509_STORE_CTX_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_issued_removed)}
    if X509_STORE_CTX_get_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_issued)}
      X509_STORE_CTX_get_check_issued := @_X509_STORE_CTX_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_issued');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_check_revocation := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_revocation_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_revocation);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_revocation_allownil)}
    X509_STORE_CTX_get_check_revocation := @ERR_X509_STORE_CTX_get_check_revocation;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_revocation_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_revocation_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_revocation)}
      X509_STORE_CTX_get_check_revocation := @FC_X509_STORE_CTX_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_revocation_removed)}
    if X509_STORE_CTX_get_check_revocation_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_revocation)}
      X509_STORE_CTX_get_check_revocation := @_X509_STORE_CTX_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_revocation_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_revocation');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_get_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_get_crl_allownil)}
    X509_STORE_CTX_get_get_crl := @ERR_X509_STORE_CTX_get_get_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_get_crl)}
      X509_STORE_CTX_get_get_crl := @FC_X509_STORE_CTX_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_crl_removed)}
    if X509_STORE_CTX_get_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_get_crl)}
      X509_STORE_CTX_get_get_crl := @_X509_STORE_CTX_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_get_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_check_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_crl_allownil)}
    X509_STORE_CTX_get_check_crl := @ERR_X509_STORE_CTX_get_check_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_crl)}
      X509_STORE_CTX_get_check_crl := @FC_X509_STORE_CTX_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_crl_removed)}
    if X509_STORE_CTX_get_check_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_crl)}
      X509_STORE_CTX_get_check_crl := @_X509_STORE_CTX_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_cert_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_cert_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_cert_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_cert_crl_allownil)}
    X509_STORE_CTX_get_cert_crl := @ERR_X509_STORE_CTX_get_cert_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cert_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get_cert_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_cert_crl)}
      X509_STORE_CTX_get_cert_crl := @FC_X509_STORE_CTX_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cert_crl_removed)}
    if X509_STORE_CTX_get_cert_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_cert_crl)}
      X509_STORE_CTX_get_cert_crl := @_X509_STORE_CTX_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_cert_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_cert_crl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_check_policy := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_policy_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_policy_allownil)}
    X509_STORE_CTX_get_check_policy := @ERR_X509_STORE_CTX_get_check_policy;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_policy_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_policy)}
      X509_STORE_CTX_get_check_policy := @FC_X509_STORE_CTX_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_policy_removed)}
    if X509_STORE_CTX_get_check_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_policy)}
      X509_STORE_CTX_get_check_policy := @_X509_STORE_CTX_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_policy');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_cleanup := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_cleanup_allownil)}
    X509_STORE_CTX_get_cleanup := @ERR_X509_STORE_CTX_get_cleanup;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cleanup_introduced)}
    if LibVersion < X509_STORE_CTX_get_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_cleanup)}
      X509_STORE_CTX_get_cleanup := @FC_X509_STORE_CTX_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cleanup_removed)}
    if X509_STORE_CTX_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_cleanup)}
      X509_STORE_CTX_get_cleanup := @_X509_STORE_CTX_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_add_lookup := LoadLibFunction(ADllHandle, X509_STORE_add_lookup_procname);
  FuncLoadError := not assigned(X509_STORE_add_lookup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_add_lookup_allownil)}
    X509_STORE_add_lookup := @ERR_X509_STORE_add_lookup;
    {$ifend}
    {$if declared(X509_STORE_add_lookup_introduced)}
    if LibVersion < X509_STORE_add_lookup_introduced then
    begin
      {$if declared(FC_X509_STORE_add_lookup)}
      X509_STORE_add_lookup := @FC_X509_STORE_add_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_add_lookup_removed)}
    if X509_STORE_add_lookup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_add_lookup)}
      X509_STORE_add_lookup := @_X509_STORE_add_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_add_lookup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_add_lookup');
    {$ifend}
  end;


  X509_LOOKUP_hash_dir := LoadLibFunction(ADllHandle, X509_LOOKUP_hash_dir_procname);
  FuncLoadError := not assigned(X509_LOOKUP_hash_dir);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_hash_dir_allownil)}
    X509_LOOKUP_hash_dir := @ERR_X509_LOOKUP_hash_dir;
    {$ifend}
    {$if declared(X509_LOOKUP_hash_dir_introduced)}
    if LibVersion < X509_LOOKUP_hash_dir_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_hash_dir)}
      X509_LOOKUP_hash_dir := @FC_X509_LOOKUP_hash_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_hash_dir_removed)}
    if X509_LOOKUP_hash_dir_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_hash_dir)}
      X509_LOOKUP_hash_dir := @_X509_LOOKUP_hash_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_hash_dir_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_hash_dir');
    {$ifend}
  end;


  X509_LOOKUP_file := LoadLibFunction(ADllHandle, X509_LOOKUP_file_procname);
  FuncLoadError := not assigned(X509_LOOKUP_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_file_allownil)}
    X509_LOOKUP_file := @ERR_X509_LOOKUP_file;
    {$ifend}
    {$if declared(X509_LOOKUP_file_introduced)}
    if LibVersion < X509_LOOKUP_file_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_file)}
      X509_LOOKUP_file := @FC_X509_LOOKUP_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_file_removed)}
    if X509_LOOKUP_file_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_file)}
      X509_LOOKUP_file := @_X509_LOOKUP_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_file');
    {$ifend}
  end;


  X509_LOOKUP_meth_new := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_new_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_new_allownil)}
    X509_LOOKUP_meth_new := @ERR_X509_LOOKUP_meth_new;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_new_introduced)}
    if LibVersion < X509_LOOKUP_meth_new_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_new)}
      X509_LOOKUP_meth_new := @FC_X509_LOOKUP_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_new_removed)}
    if X509_LOOKUP_meth_new_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_new)}
      X509_LOOKUP_meth_new := @_X509_LOOKUP_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_free := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_free_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_free_allownil)}
    X509_LOOKUP_meth_free := @ERR_X509_LOOKUP_meth_free;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_free_introduced)}
    if LibVersion < X509_LOOKUP_meth_free_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_free)}
      X509_LOOKUP_meth_free := @FC_X509_LOOKUP_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_free_removed)}
    if X509_LOOKUP_meth_free_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_free)}
      X509_LOOKUP_meth_free := @_X509_LOOKUP_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_set_ctrl := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_ctrl_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_ctrl_allownil)}
    X509_LOOKUP_meth_set_ctrl := @ERR_X509_LOOKUP_meth_set_ctrl;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_ctrl_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_ctrl_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_ctrl)}
      X509_LOOKUP_meth_set_ctrl := @FC_X509_LOOKUP_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_ctrl_removed)}
    if X509_LOOKUP_meth_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_ctrl)}
      X509_LOOKUP_meth_set_ctrl := @_X509_LOOKUP_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_get_ctrl := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_ctrl_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_ctrl_allownil)}
    X509_LOOKUP_meth_get_ctrl := @ERR_X509_LOOKUP_meth_get_ctrl;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_ctrl_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_ctrl_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_ctrl)}
      X509_LOOKUP_meth_get_ctrl := @FC_X509_LOOKUP_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_ctrl_removed)}
    if X509_LOOKUP_meth_get_ctrl_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_ctrl)}
      X509_LOOKUP_meth_get_ctrl := @_X509_LOOKUP_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_subject := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_subject_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_subject_allownil)}
    X509_LOOKUP_meth_set_get_by_subject := @ERR_X509_LOOKUP_meth_set_get_by_subject;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_subject_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_subject_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_subject)}
      X509_LOOKUP_meth_set_get_by_subject := @FC_X509_LOOKUP_meth_set_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_subject_removed)}
    if X509_LOOKUP_meth_set_get_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_subject)}
      X509_LOOKUP_meth_set_get_by_subject := @_X509_LOOKUP_meth_set_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_subject');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_subject := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_subject_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_subject_allownil)}
    X509_LOOKUP_meth_get_get_by_subject := @ERR_X509_LOOKUP_meth_get_get_by_subject;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_subject_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_subject_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_subject)}
      X509_LOOKUP_meth_get_get_by_subject := @FC_X509_LOOKUP_meth_get_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_subject_removed)}
    if X509_LOOKUP_meth_get_get_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_subject)}
      X509_LOOKUP_meth_get_get_by_subject := @_X509_LOOKUP_meth_get_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_subject');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_issuer_serial := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_issuer_serial_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_issuer_serial_allownil)}
    X509_LOOKUP_meth_set_get_by_issuer_serial := @ERR_X509_LOOKUP_meth_set_get_by_issuer_serial;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_issuer_serial_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_issuer_serial_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_issuer_serial)}
      X509_LOOKUP_meth_set_get_by_issuer_serial := @FC_X509_LOOKUP_meth_set_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_issuer_serial_removed)}
    if X509_LOOKUP_meth_set_get_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_issuer_serial)}
      X509_LOOKUP_meth_set_get_by_issuer_serial := @_X509_LOOKUP_meth_set_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_issuer_serial');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_issuer_serial := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_issuer_serial_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_issuer_serial_allownil)}
    X509_LOOKUP_meth_get_get_by_issuer_serial := @ERR_X509_LOOKUP_meth_get_get_by_issuer_serial;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_issuer_serial_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_issuer_serial_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_issuer_serial)}
      X509_LOOKUP_meth_get_get_by_issuer_serial := @FC_X509_LOOKUP_meth_get_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_issuer_serial_removed)}
    if X509_LOOKUP_meth_get_get_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_issuer_serial)}
      X509_LOOKUP_meth_get_get_by_issuer_serial := @_X509_LOOKUP_meth_get_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_issuer_serial');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_fingerprint := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_fingerprint_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_fingerprint_allownil)}
    X509_LOOKUP_meth_set_get_by_fingerprint := @ERR_X509_LOOKUP_meth_set_get_by_fingerprint;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_fingerprint_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_fingerprint_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_fingerprint)}
      X509_LOOKUP_meth_set_get_by_fingerprint := @FC_X509_LOOKUP_meth_set_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_fingerprint_removed)}
    if X509_LOOKUP_meth_set_get_by_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_fingerprint)}
      X509_LOOKUP_meth_set_get_by_fingerprint := @_X509_LOOKUP_meth_set_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_fingerprint');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_fingerprint := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_fingerprint_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_fingerprint_allownil)}
    X509_LOOKUP_meth_get_get_by_fingerprint := @ERR_X509_LOOKUP_meth_get_get_by_fingerprint;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_fingerprint_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_fingerprint_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_fingerprint)}
      X509_LOOKUP_meth_get_get_by_fingerprint := @FC_X509_LOOKUP_meth_get_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_fingerprint_removed)}
    if X509_LOOKUP_meth_get_get_by_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_fingerprint)}
      X509_LOOKUP_meth_get_get_by_fingerprint := @_X509_LOOKUP_meth_get_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_fingerprint');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_alias := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_alias_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_alias_allownil)}
    X509_LOOKUP_meth_set_get_by_alias := @ERR_X509_LOOKUP_meth_set_get_by_alias;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_alias_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_alias_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_alias)}
      X509_LOOKUP_meth_set_get_by_alias := @FC_X509_LOOKUP_meth_set_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_alias_removed)}
    if X509_LOOKUP_meth_set_get_by_alias_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_alias)}
      X509_LOOKUP_meth_set_get_by_alias := @_X509_LOOKUP_meth_set_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_alias');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_alias := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_alias_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_alias_allownil)}
    X509_LOOKUP_meth_get_get_by_alias := @ERR_X509_LOOKUP_meth_get_get_by_alias;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_alias_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_alias_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_alias)}
      X509_LOOKUP_meth_get_get_by_alias := @FC_X509_LOOKUP_meth_get_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_alias_removed)}
    if X509_LOOKUP_meth_get_get_by_alias_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_alias)}
      X509_LOOKUP_meth_get_get_by_alias := @_X509_LOOKUP_meth_get_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_alias');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_add_cert := LoadLibFunction(ADllHandle, X509_STORE_add_cert_procname);
  FuncLoadError := not assigned(X509_STORE_add_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_add_cert_allownil)}
    X509_STORE_add_cert := @ERR_X509_STORE_add_cert;
    {$ifend}
    {$if declared(X509_STORE_add_cert_introduced)}
    if LibVersion < X509_STORE_add_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_add_cert)}
      X509_STORE_add_cert := @FC_X509_STORE_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_add_cert_removed)}
    if X509_STORE_add_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_add_cert)}
      X509_STORE_add_cert := @_X509_STORE_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_add_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_add_cert');
    {$ifend}
  end;


  X509_STORE_add_crl := LoadLibFunction(ADllHandle, X509_STORE_add_crl_procname);
  FuncLoadError := not assigned(X509_STORE_add_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_add_crl_allownil)}
    X509_STORE_add_crl := @ERR_X509_STORE_add_crl;
    {$ifend}
    {$if declared(X509_STORE_add_crl_introduced)}
    if LibVersion < X509_STORE_add_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_add_crl)}
      X509_STORE_add_crl := @FC_X509_STORE_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_add_crl_removed)}
    if X509_STORE_add_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_add_crl)}
      X509_STORE_add_crl := @_X509_STORE_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_add_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_add_crl');
    {$ifend}
  end;


  X509_STORE_CTX_get_by_subject := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_by_subject_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_by_subject_allownil)}
    X509_STORE_CTX_get_by_subject := @ERR_X509_STORE_CTX_get_by_subject;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_by_subject_introduced)}
    if LibVersion < X509_STORE_CTX_get_by_subject_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_by_subject)}
      X509_STORE_CTX_get_by_subject := @FC_X509_STORE_CTX_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_by_subject_removed)}
    if X509_STORE_CTX_get_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_by_subject)}
      X509_STORE_CTX_get_by_subject := @_X509_STORE_CTX_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_by_subject');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_obj_by_subject := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_obj_by_subject_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_obj_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_obj_by_subject_allownil)}
    X509_STORE_CTX_get_obj_by_subject := @ERR_X509_STORE_CTX_get_obj_by_subject;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_obj_by_subject_introduced)}
    if LibVersion < X509_STORE_CTX_get_obj_by_subject_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_obj_by_subject)}
      X509_STORE_CTX_get_obj_by_subject := @FC_X509_STORE_CTX_get_obj_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_obj_by_subject_removed)}
    if X509_STORE_CTX_get_obj_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_obj_by_subject)}
      X509_STORE_CTX_get_obj_by_subject := @_X509_STORE_CTX_get_obj_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_obj_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_obj_by_subject');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_ctrl := LoadLibFunction(ADllHandle, X509_LOOKUP_ctrl_procname);
  FuncLoadError := not assigned(X509_LOOKUP_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_ctrl_allownil)}
    X509_LOOKUP_ctrl := @ERR_X509_LOOKUP_ctrl;
    {$ifend}
    {$if declared(X509_LOOKUP_ctrl_introduced)}
    if LibVersion < X509_LOOKUP_ctrl_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_ctrl)}
      X509_LOOKUP_ctrl := @FC_X509_LOOKUP_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_ctrl_removed)}
    if X509_LOOKUP_ctrl_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_ctrl)}
      X509_LOOKUP_ctrl := @_X509_LOOKUP_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_ctrl');
    {$ifend}
  end;


  X509_load_cert_file := LoadLibFunction(ADllHandle, X509_load_cert_file_procname);
  FuncLoadError := not assigned(X509_load_cert_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_cert_file_allownil)}
    X509_load_cert_file := @ERR_X509_load_cert_file;
    {$ifend}
    {$if declared(X509_load_cert_file_introduced)}
    if LibVersion < X509_load_cert_file_introduced then
    begin
      {$if declared(FC_X509_load_cert_file)}
      X509_load_cert_file := @FC_X509_load_cert_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_cert_file_removed)}
    if X509_load_cert_file_removed <= LibVersion then
    begin
      {$if declared(_X509_load_cert_file)}
      X509_load_cert_file := @_X509_load_cert_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_cert_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_cert_file');
    {$ifend}
  end;


  X509_load_crl_file := LoadLibFunction(ADllHandle, X509_load_crl_file_procname);
  FuncLoadError := not assigned(X509_load_crl_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_crl_file_allownil)}
    X509_load_crl_file := @ERR_X509_load_crl_file;
    {$ifend}
    {$if declared(X509_load_crl_file_introduced)}
    if LibVersion < X509_load_crl_file_introduced then
    begin
      {$if declared(FC_X509_load_crl_file)}
      X509_load_crl_file := @FC_X509_load_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_crl_file_removed)}
    if X509_load_crl_file_removed <= LibVersion then
    begin
      {$if declared(_X509_load_crl_file)}
      X509_load_crl_file := @_X509_load_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_crl_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_crl_file');
    {$ifend}
  end;


  X509_load_cert_crl_file := LoadLibFunction(ADllHandle, X509_load_cert_crl_file_procname);
  FuncLoadError := not assigned(X509_load_cert_crl_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_cert_crl_file_allownil)}
    X509_load_cert_crl_file := @ERR_X509_load_cert_crl_file;
    {$ifend}
    {$if declared(X509_load_cert_crl_file_introduced)}
    if LibVersion < X509_load_cert_crl_file_introduced then
    begin
      {$if declared(FC_X509_load_cert_crl_file)}
      X509_load_cert_crl_file := @FC_X509_load_cert_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_cert_crl_file_removed)}
    if X509_load_cert_crl_file_removed <= LibVersion then
    begin
      {$if declared(_X509_load_cert_crl_file)}
      X509_load_cert_crl_file := @_X509_load_cert_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_cert_crl_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_cert_crl_file');
    {$ifend}
  end;


  X509_LOOKUP_new := LoadLibFunction(ADllHandle, X509_LOOKUP_new_procname);
  FuncLoadError := not assigned(X509_LOOKUP_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_new_allownil)}
    X509_LOOKUP_new := @ERR_X509_LOOKUP_new;
    {$ifend}
    {$if declared(X509_LOOKUP_new_introduced)}
    if LibVersion < X509_LOOKUP_new_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_new)}
      X509_LOOKUP_new := @FC_X509_LOOKUP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_new_removed)}
    if X509_LOOKUP_new_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_new)}
      X509_LOOKUP_new := @_X509_LOOKUP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_new');
    {$ifend}
  end;


  X509_LOOKUP_free := LoadLibFunction(ADllHandle, X509_LOOKUP_free_procname);
  FuncLoadError := not assigned(X509_LOOKUP_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_free_allownil)}
    X509_LOOKUP_free := @ERR_X509_LOOKUP_free;
    {$ifend}
    {$if declared(X509_LOOKUP_free_introduced)}
    if LibVersion < X509_LOOKUP_free_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_free)}
      X509_LOOKUP_free := @FC_X509_LOOKUP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_free_removed)}
    if X509_LOOKUP_free_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_free)}
      X509_LOOKUP_free := @_X509_LOOKUP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_free');
    {$ifend}
  end;


  X509_LOOKUP_init := LoadLibFunction(ADllHandle, X509_LOOKUP_init_procname);
  FuncLoadError := not assigned(X509_LOOKUP_init);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_init_allownil)}
    X509_LOOKUP_init := @ERR_X509_LOOKUP_init;
    {$ifend}
    {$if declared(X509_LOOKUP_init_introduced)}
    if LibVersion < X509_LOOKUP_init_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_init)}
      X509_LOOKUP_init := @FC_X509_LOOKUP_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_init_removed)}
    if X509_LOOKUP_init_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_init)}
      X509_LOOKUP_init := @_X509_LOOKUP_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_init_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_init');
    {$ifend}
  end;


  X509_LOOKUP_by_subject := LoadLibFunction(ADllHandle, X509_LOOKUP_by_subject_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_subject_allownil)}
    X509_LOOKUP_by_subject := @ERR_X509_LOOKUP_by_subject;
    {$ifend}
    {$if declared(X509_LOOKUP_by_subject_introduced)}
    if LibVersion < X509_LOOKUP_by_subject_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_subject)}
      X509_LOOKUP_by_subject := @FC_X509_LOOKUP_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_subject_removed)}
    if X509_LOOKUP_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_subject)}
      X509_LOOKUP_by_subject := @_X509_LOOKUP_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_subject');
    {$ifend}
  end;


  X509_LOOKUP_by_issuer_serial := LoadLibFunction(ADllHandle, X509_LOOKUP_by_issuer_serial_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_issuer_serial_allownil)}
    X509_LOOKUP_by_issuer_serial := @ERR_X509_LOOKUP_by_issuer_serial;
    {$ifend}
    {$if declared(X509_LOOKUP_by_issuer_serial_introduced)}
    if LibVersion < X509_LOOKUP_by_issuer_serial_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_issuer_serial)}
      X509_LOOKUP_by_issuer_serial := @FC_X509_LOOKUP_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_issuer_serial_removed)}
    if X509_LOOKUP_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_issuer_serial)}
      X509_LOOKUP_by_issuer_serial := @_X509_LOOKUP_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_issuer_serial');
    {$ifend}
  end;


  X509_LOOKUP_by_fingerprint := LoadLibFunction(ADllHandle, X509_LOOKUP_by_fingerprint_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_fingerprint_allownil)}
    X509_LOOKUP_by_fingerprint := @ERR_X509_LOOKUP_by_fingerprint;
    {$ifend}
    {$if declared(X509_LOOKUP_by_fingerprint_introduced)}
    if LibVersion < X509_LOOKUP_by_fingerprint_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_fingerprint)}
      X509_LOOKUP_by_fingerprint := @FC_X509_LOOKUP_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_fingerprint_removed)}
    if X509_LOOKUP_by_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_fingerprint)}
      X509_LOOKUP_by_fingerprint := @_X509_LOOKUP_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_fingerprint');
    {$ifend}
  end;


  X509_LOOKUP_by_alias := LoadLibFunction(ADllHandle, X509_LOOKUP_by_alias_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_alias_allownil)}
    X509_LOOKUP_by_alias := @ERR_X509_LOOKUP_by_alias;
    {$ifend}
    {$if declared(X509_LOOKUP_by_alias_introduced)}
    if LibVersion < X509_LOOKUP_by_alias_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_alias)}
      X509_LOOKUP_by_alias := @FC_X509_LOOKUP_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_alias_removed)}
    if X509_LOOKUP_by_alias_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_alias)}
      X509_LOOKUP_by_alias := @_X509_LOOKUP_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_alias');
    {$ifend}
  end;


  X509_LOOKUP_set_method_data := LoadLibFunction(ADllHandle, X509_LOOKUP_set_method_data_procname);
  FuncLoadError := not assigned(X509_LOOKUP_set_method_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_set_method_data_allownil)}
    X509_LOOKUP_set_method_data := @ERR_X509_LOOKUP_set_method_data;
    {$ifend}
    {$if declared(X509_LOOKUP_set_method_data_introduced)}
    if LibVersion < X509_LOOKUP_set_method_data_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_set_method_data)}
      X509_LOOKUP_set_method_data := @FC_X509_LOOKUP_set_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_set_method_data_removed)}
    if X509_LOOKUP_set_method_data_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_set_method_data)}
      X509_LOOKUP_set_method_data := @_X509_LOOKUP_set_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_set_method_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_set_method_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_get_method_data := LoadLibFunction(ADllHandle, X509_LOOKUP_get_method_data_procname);
  FuncLoadError := not assigned(X509_LOOKUP_get_method_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_get_method_data_allownil)}
    X509_LOOKUP_get_method_data := @ERR_X509_LOOKUP_get_method_data;
    {$ifend}
    {$if declared(X509_LOOKUP_get_method_data_introduced)}
    if LibVersion < X509_LOOKUP_get_method_data_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_get_method_data)}
      X509_LOOKUP_get_method_data := @FC_X509_LOOKUP_get_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_get_method_data_removed)}
    if X509_LOOKUP_get_method_data_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_get_method_data)}
      X509_LOOKUP_get_method_data := @_X509_LOOKUP_get_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_get_method_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_get_method_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_get_store := LoadLibFunction(ADllHandle, X509_LOOKUP_get_store_procname);
  FuncLoadError := not assigned(X509_LOOKUP_get_store);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_get_store_allownil)}
    X509_LOOKUP_get_store := @ERR_X509_LOOKUP_get_store;
    {$ifend}
    {$if declared(X509_LOOKUP_get_store_introduced)}
    if LibVersion < X509_LOOKUP_get_store_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_get_store)}
      X509_LOOKUP_get_store := @FC_X509_LOOKUP_get_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_get_store_removed)}
    if X509_LOOKUP_get_store_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_get_store)}
      X509_LOOKUP_get_store := @_X509_LOOKUP_get_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_get_store_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_get_store');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_LOOKUP_shutdown := LoadLibFunction(ADllHandle, X509_LOOKUP_shutdown_procname);
  FuncLoadError := not assigned(X509_LOOKUP_shutdown);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_shutdown_allownil)}
    X509_LOOKUP_shutdown := @ERR_X509_LOOKUP_shutdown;
    {$ifend}
    {$if declared(X509_LOOKUP_shutdown_introduced)}
    if LibVersion < X509_LOOKUP_shutdown_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_shutdown)}
      X509_LOOKUP_shutdown := @FC_X509_LOOKUP_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_shutdown_removed)}
    if X509_LOOKUP_shutdown_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_shutdown)}
      X509_LOOKUP_shutdown := @_X509_LOOKUP_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_shutdown_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_shutdown');
    {$ifend}
  end;


  X509_STORE_load_locations := LoadLibFunction(ADllHandle, X509_STORE_load_locations_procname);
  FuncLoadError := not assigned(X509_STORE_load_locations);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_locations_allownil)}
    X509_STORE_load_locations := @ERR_X509_STORE_load_locations;
    {$ifend}
    {$if declared(X509_STORE_load_locations_introduced)}
    if LibVersion < X509_STORE_load_locations_introduced then
    begin
      {$if declared(FC_X509_STORE_load_locations)}
      X509_STORE_load_locations := @FC_X509_STORE_load_locations;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_locations_removed)}
    if X509_STORE_load_locations_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_locations)}
      X509_STORE_load_locations := @_X509_STORE_load_locations;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_locations_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_locations');
    {$ifend}
  end;


  X509_STORE_set_default_paths := LoadLibFunction(ADllHandle, X509_STORE_set_default_paths_procname);
  FuncLoadError := not assigned(X509_STORE_set_default_paths);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_default_paths_allownil)}
    X509_STORE_set_default_paths := @ERR_X509_STORE_set_default_paths;
    {$ifend}
    {$if declared(X509_STORE_set_default_paths_introduced)}
    if LibVersion < X509_STORE_set_default_paths_introduced then
    begin
      {$if declared(FC_X509_STORE_set_default_paths)}
      X509_STORE_set_default_paths := @FC_X509_STORE_set_default_paths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_default_paths_removed)}
    if X509_STORE_set_default_paths_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_default_paths)}
      X509_STORE_set_default_paths := @_X509_STORE_set_default_paths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_default_paths_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_default_paths');
    {$ifend}
  end;


  X509_STORE_CTX_set_ex_data := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_ex_data_allownil)}
    X509_STORE_CTX_set_ex_data := @ERR_X509_STORE_CTX_set_ex_data;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_ex_data_introduced)}
    if LibVersion < X509_STORE_CTX_set_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_ex_data)}
      X509_STORE_CTX_set_ex_data := @FC_X509_STORE_CTX_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_ex_data_removed)}
    if X509_STORE_CTX_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_ex_data)}
      X509_STORE_CTX_set_ex_data := @_X509_STORE_CTX_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_ex_data');
    {$ifend}
  end;


  X509_STORE_CTX_get_ex_data := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_ex_data_allownil)}
    X509_STORE_CTX_get_ex_data := @ERR_X509_STORE_CTX_get_ex_data;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_ex_data_introduced)}
    if LibVersion < X509_STORE_CTX_get_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_ex_data)}
      X509_STORE_CTX_get_ex_data := @FC_X509_STORE_CTX_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_ex_data_removed)}
    if X509_STORE_CTX_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_ex_data)}
      X509_STORE_CTX_get_ex_data := @_X509_STORE_CTX_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_ex_data');
    {$ifend}
  end;


  X509_STORE_CTX_get_error := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_error_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_error);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_error_allownil)}
    X509_STORE_CTX_get_error := @ERR_X509_STORE_CTX_get_error;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_introduced)}
    if LibVersion < X509_STORE_CTX_get_error_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_error)}
      X509_STORE_CTX_get_error := @FC_X509_STORE_CTX_get_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_removed)}
    if X509_STORE_CTX_get_error_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_error)}
      X509_STORE_CTX_get_error := @_X509_STORE_CTX_get_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_error_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_error');
    {$ifend}
  end;


  X509_STORE_CTX_set_error := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_error_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_error);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_error_allownil)}
    X509_STORE_CTX_set_error := @ERR_X509_STORE_CTX_set_error;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_introduced)}
    if LibVersion < X509_STORE_CTX_set_error_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_error)}
      X509_STORE_CTX_set_error := @FC_X509_STORE_CTX_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_removed)}
    if X509_STORE_CTX_set_error_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_error)}
      X509_STORE_CTX_set_error := @_X509_STORE_CTX_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_error_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_error');
    {$ifend}
  end;


  X509_STORE_CTX_get_error_depth := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_error_depth_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_error_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_error_depth_allownil)}
    X509_STORE_CTX_get_error_depth := @ERR_X509_STORE_CTX_get_error_depth;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_depth_introduced)}
    if LibVersion < X509_STORE_CTX_get_error_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_error_depth)}
      X509_STORE_CTX_get_error_depth := @FC_X509_STORE_CTX_get_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_depth_removed)}
    if X509_STORE_CTX_get_error_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_error_depth)}
      X509_STORE_CTX_get_error_depth := @_X509_STORE_CTX_get_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_error_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_error_depth');
    {$ifend}
  end;


  X509_STORE_CTX_set_error_depth := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_error_depth_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_error_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_error_depth_allownil)}
    X509_STORE_CTX_set_error_depth := @ERR_X509_STORE_CTX_set_error_depth;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_depth_introduced)}
    if LibVersion < X509_STORE_CTX_set_error_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_error_depth)}
      X509_STORE_CTX_set_error_depth := @FC_X509_STORE_CTX_set_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_depth_removed)}
    if X509_STORE_CTX_set_error_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_error_depth)}
      X509_STORE_CTX_set_error_depth := @_X509_STORE_CTX_set_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_error_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_error_depth');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get_current_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_current_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_current_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_current_cert_allownil)}
    X509_STORE_CTX_get_current_cert := @ERR_X509_STORE_CTX_get_current_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_current_cert_introduced)}
    if LibVersion < X509_STORE_CTX_get_current_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_current_cert)}
      X509_STORE_CTX_get_current_cert := @FC_X509_STORE_CTX_get_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_current_cert_removed)}
    if X509_STORE_CTX_get_current_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_current_cert)}
      X509_STORE_CTX_get_current_cert := @_X509_STORE_CTX_get_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_current_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_current_cert');
    {$ifend}
  end;


  X509_STORE_CTX_set_current_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_current_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_current_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_current_cert_allownil)}
    X509_STORE_CTX_set_current_cert := @ERR_X509_STORE_CTX_set_current_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_current_cert_introduced)}
    if LibVersion < X509_STORE_CTX_set_current_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_current_cert)}
      X509_STORE_CTX_set_current_cert := @FC_X509_STORE_CTX_set_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_current_cert_removed)}
    if X509_STORE_CTX_set_current_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_current_cert)}
      X509_STORE_CTX_set_current_cert := @_X509_STORE_CTX_set_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_current_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_current_cert');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get0_current_issuer := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_current_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_current_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_current_issuer_allownil)}
    X509_STORE_CTX_get0_current_issuer := @ERR_X509_STORE_CTX_get0_current_issuer;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_issuer_introduced)}
    if LibVersion < X509_STORE_CTX_get0_current_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_current_issuer)}
      X509_STORE_CTX_get0_current_issuer := @FC_X509_STORE_CTX_get0_current_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_issuer_removed)}
    if X509_STORE_CTX_get0_current_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_current_issuer)}
      X509_STORE_CTX_get0_current_issuer := @_X509_STORE_CTX_get0_current_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_current_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_current_issuer');
    {$ifend}
  end;


  X509_STORE_CTX_get0_current_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_current_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_current_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_current_crl_allownil)}
    X509_STORE_CTX_get0_current_crl := @ERR_X509_STORE_CTX_get0_current_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get0_current_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_current_crl)}
      X509_STORE_CTX_get0_current_crl := @FC_X509_STORE_CTX_get0_current_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_crl_removed)}
    if X509_STORE_CTX_get0_current_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_current_crl)}
      X509_STORE_CTX_get0_current_crl := @_X509_STORE_CTX_get0_current_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_current_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_current_crl');
    {$ifend}
  end;


  X509_STORE_CTX_get0_parent_ctx := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_parent_ctx_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_parent_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_parent_ctx_allownil)}
    X509_STORE_CTX_get0_parent_ctx := @ERR_X509_STORE_CTX_get0_parent_ctx;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_parent_ctx_introduced)}
    if LibVersion < X509_STORE_CTX_get0_parent_ctx_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_parent_ctx)}
      X509_STORE_CTX_get0_parent_ctx := @FC_X509_STORE_CTX_get0_parent_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_parent_ctx_removed)}
    if X509_STORE_CTX_get0_parent_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_parent_ctx)}
      X509_STORE_CTX_get0_parent_ctx := @_X509_STORE_CTX_get0_parent_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_parent_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_parent_ctx');
    {$ifend}
  end;


  X509_STORE_CTX_set_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_cert_allownil)}
    X509_STORE_CTX_set_cert := @ERR_X509_STORE_CTX_set_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_cert_introduced)}
    if LibVersion < X509_STORE_CTX_set_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_cert)}
      X509_STORE_CTX_set_cert := @FC_X509_STORE_CTX_set_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_cert_removed)}
    if X509_STORE_CTX_set_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_cert)}
      X509_STORE_CTX_set_cert := @_X509_STORE_CTX_set_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_cert');
    {$ifend}
  end;


  X509_STORE_CTX_set_purpose := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_purpose_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_purpose_allownil)}
    X509_STORE_CTX_set_purpose := @ERR_X509_STORE_CTX_set_purpose;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_purpose_introduced)}
    if LibVersion < X509_STORE_CTX_set_purpose_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_purpose)}
      X509_STORE_CTX_set_purpose := @FC_X509_STORE_CTX_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_purpose_removed)}
    if X509_STORE_CTX_set_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_purpose)}
      X509_STORE_CTX_set_purpose := @_X509_STORE_CTX_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_purpose');
    {$ifend}
  end;


  X509_STORE_CTX_set_trust := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_trust_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_trust_allownil)}
    X509_STORE_CTX_set_trust := @ERR_X509_STORE_CTX_set_trust;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_trust_introduced)}
    if LibVersion < X509_STORE_CTX_set_trust_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_trust)}
      X509_STORE_CTX_set_trust := @FC_X509_STORE_CTX_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_trust_removed)}
    if X509_STORE_CTX_set_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_trust)}
      X509_STORE_CTX_set_trust := @_X509_STORE_CTX_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_trust');
    {$ifend}
  end;


  X509_STORE_CTX_purpose_inherit := LoadLibFunction(ADllHandle, X509_STORE_CTX_purpose_inherit_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_purpose_inherit);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_purpose_inherit_allownil)}
    X509_STORE_CTX_purpose_inherit := @ERR_X509_STORE_CTX_purpose_inherit;
    {$ifend}
    {$if declared(X509_STORE_CTX_purpose_inherit_introduced)}
    if LibVersion < X509_STORE_CTX_purpose_inherit_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_purpose_inherit)}
      X509_STORE_CTX_purpose_inherit := @FC_X509_STORE_CTX_purpose_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_purpose_inherit_removed)}
    if X509_STORE_CTX_purpose_inherit_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_purpose_inherit)}
      X509_STORE_CTX_purpose_inherit := @_X509_STORE_CTX_purpose_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_purpose_inherit_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_purpose_inherit');
    {$ifend}
  end;


  X509_STORE_CTX_set_flags := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_flags_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_flags_allownil)}
    X509_STORE_CTX_set_flags := @ERR_X509_STORE_CTX_set_flags;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_flags_introduced)}
    if LibVersion < X509_STORE_CTX_set_flags_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_flags)}
      X509_STORE_CTX_set_flags := @FC_X509_STORE_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_flags_removed)}
    if X509_STORE_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_flags)}
      X509_STORE_CTX_set_flags := @_X509_STORE_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_flags');
    {$ifend}
  end;


  X509_STORE_CTX_get0_policy_tree := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_policy_tree_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_policy_tree);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_policy_tree_allownil)}
    X509_STORE_CTX_get0_policy_tree := @ERR_X509_STORE_CTX_get0_policy_tree;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_policy_tree_introduced)}
    if LibVersion < X509_STORE_CTX_get0_policy_tree_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_policy_tree)}
      X509_STORE_CTX_get0_policy_tree := @FC_X509_STORE_CTX_get0_policy_tree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_policy_tree_removed)}
    if X509_STORE_CTX_get0_policy_tree_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_policy_tree)}
      X509_STORE_CTX_get0_policy_tree := @_X509_STORE_CTX_get0_policy_tree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_policy_tree_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_policy_tree');
    {$ifend}
  end;


  X509_STORE_CTX_get_explicit_policy := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_explicit_policy_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_explicit_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_explicit_policy_allownil)}
    X509_STORE_CTX_get_explicit_policy := @ERR_X509_STORE_CTX_get_explicit_policy;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_explicit_policy_introduced)}
    if LibVersion < X509_STORE_CTX_get_explicit_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_explicit_policy)}
      X509_STORE_CTX_get_explicit_policy := @FC_X509_STORE_CTX_get_explicit_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_explicit_policy_removed)}
    if X509_STORE_CTX_get_explicit_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_explicit_policy)}
      X509_STORE_CTX_get_explicit_policy := @_X509_STORE_CTX_get_explicit_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_explicit_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_explicit_policy');
    {$ifend}
  end;


  X509_STORE_CTX_get_num_untrusted := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_num_untrusted_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_num_untrusted);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_num_untrusted_allownil)}
    X509_STORE_CTX_get_num_untrusted := @ERR_X509_STORE_CTX_get_num_untrusted;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_num_untrusted_introduced)}
    if LibVersion < X509_STORE_CTX_get_num_untrusted_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_num_untrusted)}
      X509_STORE_CTX_get_num_untrusted := @FC_X509_STORE_CTX_get_num_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_num_untrusted_removed)}
    if X509_STORE_CTX_get_num_untrusted_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_num_untrusted)}
      X509_STORE_CTX_get_num_untrusted := @_X509_STORE_CTX_get_num_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_num_untrusted_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_num_untrusted');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_STORE_CTX_get0_param := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_param_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_param_allownil)}
    X509_STORE_CTX_get0_param := @ERR_X509_STORE_CTX_get0_param;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_param_introduced)}
    if LibVersion < X509_STORE_CTX_get0_param_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_param)}
      X509_STORE_CTX_get0_param := @FC_X509_STORE_CTX_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_param_removed)}
    if X509_STORE_CTX_get0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_param)}
      X509_STORE_CTX_get0_param := @_X509_STORE_CTX_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_param');
    {$ifend}
  end;


  X509_STORE_CTX_set0_param := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_param_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_param_allownil)}
    X509_STORE_CTX_set0_param := @ERR_X509_STORE_CTX_set0_param;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_param_introduced)}
    if LibVersion < X509_STORE_CTX_set0_param_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_param)}
      X509_STORE_CTX_set0_param := @FC_X509_STORE_CTX_set0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_param_removed)}
    if X509_STORE_CTX_set0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_param)}
      X509_STORE_CTX_set0_param := @_X509_STORE_CTX_set0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_param');
    {$ifend}
  end;


  X509_STORE_CTX_set_default := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_default_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_default);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_default_allownil)}
    X509_STORE_CTX_set_default := @ERR_X509_STORE_CTX_set_default;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_default_introduced)}
    if LibVersion < X509_STORE_CTX_set_default_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_default)}
      X509_STORE_CTX_set_default := @FC_X509_STORE_CTX_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_default_removed)}
    if X509_STORE_CTX_set_default_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_default)}
      X509_STORE_CTX_set_default := @_X509_STORE_CTX_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_default_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_default');
    {$ifend}
  end;


  X509_STORE_CTX_set0_dane := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_dane_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_dane);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_dane_allownil)}
    X509_STORE_CTX_set0_dane := @ERR_X509_STORE_CTX_set0_dane;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_dane_introduced)}
    if LibVersion < X509_STORE_CTX_set0_dane_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_dane)}
      X509_STORE_CTX_set0_dane := @FC_X509_STORE_CTX_set0_dane;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_dane_removed)}
    if X509_STORE_CTX_set0_dane_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_dane)}
      X509_STORE_CTX_set0_dane := @_X509_STORE_CTX_set0_dane;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_dane_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_dane');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_new := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_new_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_new_allownil)}
    X509_VERIFY_PARAM_new := @ERR_X509_VERIFY_PARAM_new;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_new_introduced)}
    if LibVersion < X509_VERIFY_PARAM_new_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_new)}
      X509_VERIFY_PARAM_new := @FC_X509_VERIFY_PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_new_removed)}
    if X509_VERIFY_PARAM_new_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_new)}
      X509_VERIFY_PARAM_new := @_X509_VERIFY_PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_new');
    {$ifend}
  end;


  X509_VERIFY_PARAM_free := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_free_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_free_allownil)}
    X509_VERIFY_PARAM_free := @ERR_X509_VERIFY_PARAM_free;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_free_introduced)}
    if LibVersion < X509_VERIFY_PARAM_free_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_free)}
      X509_VERIFY_PARAM_free := @FC_X509_VERIFY_PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_free_removed)}
    if X509_VERIFY_PARAM_free_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_free)}
      X509_VERIFY_PARAM_free := @_X509_VERIFY_PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_free');
    {$ifend}
  end;


  X509_VERIFY_PARAM_inherit := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_inherit_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_inherit);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_inherit_allownil)}
    X509_VERIFY_PARAM_inherit := @ERR_X509_VERIFY_PARAM_inherit;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_inherit_introduced)}
    if LibVersion < X509_VERIFY_PARAM_inherit_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_inherit)}
      X509_VERIFY_PARAM_inherit := @FC_X509_VERIFY_PARAM_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_inherit_removed)}
    if X509_VERIFY_PARAM_inherit_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_inherit)}
      X509_VERIFY_PARAM_inherit := @_X509_VERIFY_PARAM_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_inherit_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_inherit');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set1 := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_allownil)}
    X509_VERIFY_PARAM_set1 := @ERR_X509_VERIFY_PARAM_set1;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1)}
      X509_VERIFY_PARAM_set1 := @FC_X509_VERIFY_PARAM_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_removed)}
    if X509_VERIFY_PARAM_set1_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1)}
      X509_VERIFY_PARAM_set1 := @_X509_VERIFY_PARAM_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set1_name := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_name_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_name_allownil)}
    X509_VERIFY_PARAM_set1_name := @ERR_X509_VERIFY_PARAM_set1_name;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_name_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_name_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_name)}
      X509_VERIFY_PARAM_set1_name := @FC_X509_VERIFY_PARAM_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_name_removed)}
    if X509_VERIFY_PARAM_set1_name_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_name)}
      X509_VERIFY_PARAM_set1_name := @_X509_VERIFY_PARAM_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_name');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_flags_allownil)}
    X509_VERIFY_PARAM_set_flags := @ERR_X509_VERIFY_PARAM_set_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_flags)}
      X509_VERIFY_PARAM_set_flags := @FC_X509_VERIFY_PARAM_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_flags_removed)}
    if X509_VERIFY_PARAM_set_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_flags)}
      X509_VERIFY_PARAM_set_flags := @_X509_VERIFY_PARAM_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_flags');
    {$ifend}
  end;


  X509_VERIFY_PARAM_clear_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_clear_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_clear_flags_allownil)}
    X509_VERIFY_PARAM_clear_flags := @ERR_X509_VERIFY_PARAM_clear_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_clear_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_clear_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_clear_flags)}
      X509_VERIFY_PARAM_clear_flags := @FC_X509_VERIFY_PARAM_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_clear_flags_removed)}
    if X509_VERIFY_PARAM_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_clear_flags)}
      X509_VERIFY_PARAM_clear_flags := @_X509_VERIFY_PARAM_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_clear_flags');
    {$ifend}
  end;


  X509_VERIFY_PARAM_get_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_flags_allownil)}
    X509_VERIFY_PARAM_get_flags := @ERR_X509_VERIFY_PARAM_get_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_flags)}
      X509_VERIFY_PARAM_get_flags := @FC_X509_VERIFY_PARAM_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_flags_removed)}
    if X509_VERIFY_PARAM_get_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_flags)}
      X509_VERIFY_PARAM_get_flags := @_X509_VERIFY_PARAM_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_flags');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_purpose := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_purpose_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_purpose_allownil)}
    X509_VERIFY_PARAM_set_purpose := @ERR_X509_VERIFY_PARAM_set_purpose;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_purpose_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_purpose_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_purpose)}
      X509_VERIFY_PARAM_set_purpose := @FC_X509_VERIFY_PARAM_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_purpose_removed)}
    if X509_VERIFY_PARAM_set_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_purpose)}
      X509_VERIFY_PARAM_set_purpose := @_X509_VERIFY_PARAM_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_purpose');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_trust := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_trust_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_trust_allownil)}
    X509_VERIFY_PARAM_set_trust := @ERR_X509_VERIFY_PARAM_set_trust;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_trust_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_trust_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_trust)}
      X509_VERIFY_PARAM_set_trust := @FC_X509_VERIFY_PARAM_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_trust_removed)}
    if X509_VERIFY_PARAM_set_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_trust)}
      X509_VERIFY_PARAM_set_trust := @_X509_VERIFY_PARAM_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_trust');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_depth := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_depth_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_depth_allownil)}
    X509_VERIFY_PARAM_set_depth := @ERR_X509_VERIFY_PARAM_set_depth;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_depth_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_depth_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_depth)}
      X509_VERIFY_PARAM_set_depth := @FC_X509_VERIFY_PARAM_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_depth_removed)}
    if X509_VERIFY_PARAM_set_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_depth)}
      X509_VERIFY_PARAM_set_depth := @_X509_VERIFY_PARAM_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_depth');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_auth_level := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_auth_level_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_auth_level);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_auth_level_allownil)}
    X509_VERIFY_PARAM_set_auth_level := @ERR_X509_VERIFY_PARAM_set_auth_level;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_auth_level_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_auth_level_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_auth_level)}
      X509_VERIFY_PARAM_set_auth_level := @FC_X509_VERIFY_PARAM_set_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_auth_level_removed)}
    if X509_VERIFY_PARAM_set_auth_level_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_auth_level)}
      X509_VERIFY_PARAM_set_auth_level := @_X509_VERIFY_PARAM_set_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_auth_level_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_auth_level');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_add0_policy := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_add0_policy_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add0_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_add0_policy_allownil)}
    X509_VERIFY_PARAM_add0_policy := @ERR_X509_VERIFY_PARAM_add0_policy;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_policy_introduced)}
    if LibVersion < X509_VERIFY_PARAM_add0_policy_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_add0_policy)}
      X509_VERIFY_PARAM_add0_policy := @FC_X509_VERIFY_PARAM_add0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_policy_removed)}
    if X509_VERIFY_PARAM_add0_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_add0_policy)}
      X509_VERIFY_PARAM_add0_policy := @_X509_VERIFY_PARAM_add0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_add0_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_add0_policy');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_inh_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_inh_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_inh_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_inh_flags_allownil)}
    X509_VERIFY_PARAM_set_inh_flags := @ERR_X509_VERIFY_PARAM_set_inh_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_inh_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_inh_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_inh_flags)}
      X509_VERIFY_PARAM_set_inh_flags := @FC_X509_VERIFY_PARAM_set_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_inh_flags_removed)}
    if X509_VERIFY_PARAM_set_inh_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_inh_flags)}
      X509_VERIFY_PARAM_set_inh_flags := @_X509_VERIFY_PARAM_set_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_inh_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_inh_flags');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_get_inh_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_inh_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_inh_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_inh_flags_allownil)}
    X509_VERIFY_PARAM_get_inh_flags := @ERR_X509_VERIFY_PARAM_get_inh_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_inh_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_inh_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_inh_flags)}
      X509_VERIFY_PARAM_get_inh_flags := @FC_X509_VERIFY_PARAM_get_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_inh_flags_removed)}
    if X509_VERIFY_PARAM_get_inh_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_inh_flags)}
      X509_VERIFY_PARAM_get_inh_flags := @_X509_VERIFY_PARAM_get_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_inh_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_inh_flags');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_set1_host := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_host_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_host_allownil)}
    X509_VERIFY_PARAM_set1_host := @ERR_X509_VERIFY_PARAM_set1_host;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_host_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_host_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_host)}
      X509_VERIFY_PARAM_set1_host := @FC_X509_VERIFY_PARAM_set1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_host_removed)}
    if X509_VERIFY_PARAM_set1_host_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_host)}
      X509_VERIFY_PARAM_set1_host := @_X509_VERIFY_PARAM_set1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_host');
    {$ifend}
  end;


  X509_VERIFY_PARAM_add1_host := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_add1_host_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add1_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_add1_host_allownil)}
    X509_VERIFY_PARAM_add1_host := @ERR_X509_VERIFY_PARAM_add1_host;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add1_host_introduced)}
    if LibVersion < X509_VERIFY_PARAM_add1_host_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_add1_host)}
      X509_VERIFY_PARAM_add1_host := @FC_X509_VERIFY_PARAM_add1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add1_host_removed)}
    if X509_VERIFY_PARAM_add1_host_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_add1_host)}
      X509_VERIFY_PARAM_add1_host := @_X509_VERIFY_PARAM_add1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_add1_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_add1_host');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set_hostflags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_hostflags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_hostflags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_hostflags_allownil)}
    X509_VERIFY_PARAM_set_hostflags := @ERR_X509_VERIFY_PARAM_set_hostflags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_hostflags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_hostflags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_hostflags)}
      X509_VERIFY_PARAM_set_hostflags := @FC_X509_VERIFY_PARAM_set_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_hostflags_removed)}
    if X509_VERIFY_PARAM_set_hostflags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_hostflags)}
      X509_VERIFY_PARAM_set_hostflags := @_X509_VERIFY_PARAM_set_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_hostflags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_hostflags');
    {$ifend}
  end;


  X509_VERIFY_PARAM_get_hostflags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_hostflags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_hostflags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_hostflags_allownil)}
    X509_VERIFY_PARAM_get_hostflags := @ERR_X509_VERIFY_PARAM_get_hostflags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_hostflags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_hostflags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_hostflags)}
      X509_VERIFY_PARAM_get_hostflags := @FC_X509_VERIFY_PARAM_get_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_hostflags_removed)}
    if X509_VERIFY_PARAM_get_hostflags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_hostflags)}
      X509_VERIFY_PARAM_get_hostflags := @_X509_VERIFY_PARAM_get_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_hostflags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_hostflags');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_peername := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_peername_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_peername);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_peername_allownil)}
    X509_VERIFY_PARAM_get0_peername := @ERR_X509_VERIFY_PARAM_get0_peername;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_peername_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_peername_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0_peername)}
      X509_VERIFY_PARAM_get0_peername := @FC_X509_VERIFY_PARAM_get0_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_peername_removed)}
    if X509_VERIFY_PARAM_get0_peername_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0_peername)}
      X509_VERIFY_PARAM_get0_peername := @_X509_VERIFY_PARAM_get0_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_peername_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0_peername');
    {$ifend}
  end;


  X509_VERIFY_PARAM_move_peername := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_move_peername_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_move_peername);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_move_peername_allownil)}
    X509_VERIFY_PARAM_move_peername := @ERR_X509_VERIFY_PARAM_move_peername;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_move_peername_introduced)}
    if LibVersion < X509_VERIFY_PARAM_move_peername_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_move_peername)}
      X509_VERIFY_PARAM_move_peername := @FC_X509_VERIFY_PARAM_move_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_move_peername_removed)}
    if X509_VERIFY_PARAM_move_peername_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_move_peername)}
      X509_VERIFY_PARAM_move_peername := @_X509_VERIFY_PARAM_move_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_move_peername_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_move_peername');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_set1_email := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_email_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_email_allownil)}
    X509_VERIFY_PARAM_set1_email := @ERR_X509_VERIFY_PARAM_set1_email;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_email_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_email_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_email)}
      X509_VERIFY_PARAM_set1_email := @FC_X509_VERIFY_PARAM_set1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_email_removed)}
    if X509_VERIFY_PARAM_set1_email_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_email)}
      X509_VERIFY_PARAM_set1_email := @_X509_VERIFY_PARAM_set1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_email');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set1_ip := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_ip_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_ip);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_ip_allownil)}
    X509_VERIFY_PARAM_set1_ip := @ERR_X509_VERIFY_PARAM_set1_ip;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_ip_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_ip)}
      X509_VERIFY_PARAM_set1_ip := @FC_X509_VERIFY_PARAM_set1_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_removed)}
    if X509_VERIFY_PARAM_set1_ip_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_ip)}
      X509_VERIFY_PARAM_set1_ip := @_X509_VERIFY_PARAM_set1_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_ip_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_ip');
    {$ifend}
  end;


  X509_VERIFY_PARAM_set1_ip_asc := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_ip_asc_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_ip_asc);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_ip_asc_allownil)}
    X509_VERIFY_PARAM_set1_ip_asc := @ERR_X509_VERIFY_PARAM_set1_ip_asc;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_asc_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_ip_asc_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_ip_asc)}
      X509_VERIFY_PARAM_set1_ip_asc := @FC_X509_VERIFY_PARAM_set1_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_asc_removed)}
    if X509_VERIFY_PARAM_set1_ip_asc_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_ip_asc)}
      X509_VERIFY_PARAM_set1_ip_asc := @_X509_VERIFY_PARAM_set1_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_ip_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_ip_asc');
    {$ifend}
  end;


  X509_VERIFY_PARAM_get_depth := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_depth_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_depth_allownil)}
    X509_VERIFY_PARAM_get_depth := @ERR_X509_VERIFY_PARAM_get_depth;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_depth_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_depth_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_depth)}
      X509_VERIFY_PARAM_get_depth := @FC_X509_VERIFY_PARAM_get_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_depth_removed)}
    if X509_VERIFY_PARAM_get_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_depth)}
      X509_VERIFY_PARAM_get_depth := @_X509_VERIFY_PARAM_get_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_depth');
    {$ifend}
  end;


  X509_VERIFY_PARAM_get_auth_level := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_auth_level_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_auth_level);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_auth_level_allownil)}
    X509_VERIFY_PARAM_get_auth_level := @ERR_X509_VERIFY_PARAM_get_auth_level;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_auth_level_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_auth_level_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_auth_level)}
      X509_VERIFY_PARAM_get_auth_level := @FC_X509_VERIFY_PARAM_get_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_auth_level_removed)}
    if X509_VERIFY_PARAM_get_auth_level_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_auth_level)}
      X509_VERIFY_PARAM_get_auth_level := @_X509_VERIFY_PARAM_get_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_auth_level_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_auth_level');
    {$ifend}
  end;

 {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_name := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_name_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_name_allownil)}
    X509_VERIFY_PARAM_get0_name := @ERR_X509_VERIFY_PARAM_get0_name;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_name_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_name_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0_name)}
      X509_VERIFY_PARAM_get0_name := @FC_X509_VERIFY_PARAM_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_name_removed)}
    if X509_VERIFY_PARAM_get0_name_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0_name)}
      X509_VERIFY_PARAM_get0_name := @_X509_VERIFY_PARAM_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0_name');
    {$ifend}
  end;


  X509_VERIFY_PARAM_add0_table := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_add0_table_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add0_table);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_add0_table_allownil)}
    X509_VERIFY_PARAM_add0_table := @ERR_X509_VERIFY_PARAM_add0_table;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_table_introduced)}
    if LibVersion < X509_VERIFY_PARAM_add0_table_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_add0_table)}
      X509_VERIFY_PARAM_add0_table := @FC_X509_VERIFY_PARAM_add0_table;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_table_removed)}
    if X509_VERIFY_PARAM_add0_table_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_add0_table)}
      X509_VERIFY_PARAM_add0_table := @_X509_VERIFY_PARAM_add0_table;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_add0_table_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_add0_table');
    {$ifend}
  end;


  X509_VERIFY_PARAM_get_count := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_count_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_count_allownil)}
    X509_VERIFY_PARAM_get_count := @ERR_X509_VERIFY_PARAM_get_count;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_count_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_count_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_count)}
      X509_VERIFY_PARAM_get_count := @FC_X509_VERIFY_PARAM_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_count_removed)}
    if X509_VERIFY_PARAM_get_count_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_count)}
      X509_VERIFY_PARAM_get_count := @_X509_VERIFY_PARAM_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_count');
    {$ifend}
  end;


  X509_VERIFY_PARAM_get0 := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_allownil)}
    X509_VERIFY_PARAM_get0 := @ERR_X509_VERIFY_PARAM_get0;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0)}
      X509_VERIFY_PARAM_get0 := @FC_X509_VERIFY_PARAM_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_removed)}
    if X509_VERIFY_PARAM_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0)}
      X509_VERIFY_PARAM_get0 := @_X509_VERIFY_PARAM_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0');
    {$ifend}
  end;


  X509_VERIFY_PARAM_lookup := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_lookup_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_lookup);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_lookup_allownil)}
    X509_VERIFY_PARAM_lookup := @ERR_X509_VERIFY_PARAM_lookup;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_lookup_introduced)}
    if LibVersion < X509_VERIFY_PARAM_lookup_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_lookup)}
      X509_VERIFY_PARAM_lookup := @FC_X509_VERIFY_PARAM_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_lookup_removed)}
    if X509_VERIFY_PARAM_lookup_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_lookup)}
      X509_VERIFY_PARAM_lookup := @_X509_VERIFY_PARAM_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_lookup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_lookup');
    {$ifend}
  end;


  X509_VERIFY_PARAM_table_cleanup := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_table_cleanup_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_table_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_table_cleanup_allownil)}
    X509_VERIFY_PARAM_table_cleanup := @ERR_X509_VERIFY_PARAM_table_cleanup;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_table_cleanup_introduced)}
    if LibVersion < X509_VERIFY_PARAM_table_cleanup_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_table_cleanup)}
      X509_VERIFY_PARAM_table_cleanup := @FC_X509_VERIFY_PARAM_table_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_table_cleanup_removed)}
    if X509_VERIFY_PARAM_table_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_table_cleanup)}
      X509_VERIFY_PARAM_table_cleanup := @_X509_VERIFY_PARAM_table_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_table_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_table_cleanup');
    {$ifend}
  end;


  X509_policy_tree_free := LoadLibFunction(ADllHandle, X509_policy_tree_free_procname);
  FuncLoadError := not assigned(X509_policy_tree_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_free_allownil)}
    X509_policy_tree_free := @ERR_X509_policy_tree_free;
    {$ifend}
    {$if declared(X509_policy_tree_free_introduced)}
    if LibVersion < X509_policy_tree_free_introduced then
    begin
      {$if declared(FC_X509_policy_tree_free)}
      X509_policy_tree_free := @FC_X509_policy_tree_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_free_removed)}
    if X509_policy_tree_free_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_free)}
      X509_policy_tree_free := @_X509_policy_tree_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_free');
    {$ifend}
  end;


  X509_policy_tree_level_count := LoadLibFunction(ADllHandle, X509_policy_tree_level_count_procname);
  FuncLoadError := not assigned(X509_policy_tree_level_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_level_count_allownil)}
    X509_policy_tree_level_count := @ERR_X509_policy_tree_level_count;
    {$ifend}
    {$if declared(X509_policy_tree_level_count_introduced)}
    if LibVersion < X509_policy_tree_level_count_introduced then
    begin
      {$if declared(FC_X509_policy_tree_level_count)}
      X509_policy_tree_level_count := @FC_X509_policy_tree_level_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_level_count_removed)}
    if X509_policy_tree_level_count_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_level_count)}
      X509_policy_tree_level_count := @_X509_policy_tree_level_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_level_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_level_count');
    {$ifend}
  end;


  X509_policy_tree_get0_level := LoadLibFunction(ADllHandle, X509_policy_tree_get0_level_procname);
  FuncLoadError := not assigned(X509_policy_tree_get0_level);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_get0_level_allownil)}
    X509_policy_tree_get0_level := @ERR_X509_policy_tree_get0_level;
    {$ifend}
    {$if declared(X509_policy_tree_get0_level_introduced)}
    if LibVersion < X509_policy_tree_get0_level_introduced then
    begin
      {$if declared(FC_X509_policy_tree_get0_level)}
      X509_policy_tree_get0_level := @FC_X509_policy_tree_get0_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_get0_level_removed)}
    if X509_policy_tree_get0_level_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_get0_level)}
      X509_policy_tree_get0_level := @_X509_policy_tree_get0_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_get0_level_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_get0_level');
    {$ifend}
  end;


  X509_policy_level_node_count := LoadLibFunction(ADllHandle, X509_policy_level_node_count_procname);
  FuncLoadError := not assigned(X509_policy_level_node_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_level_node_count_allownil)}
    X509_policy_level_node_count := @ERR_X509_policy_level_node_count;
    {$ifend}
    {$if declared(X509_policy_level_node_count_introduced)}
    if LibVersion < X509_policy_level_node_count_introduced then
    begin
      {$if declared(FC_X509_policy_level_node_count)}
      X509_policy_level_node_count := @FC_X509_policy_level_node_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_level_node_count_removed)}
    if X509_policy_level_node_count_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_level_node_count)}
      X509_policy_level_node_count := @_X509_policy_level_node_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_level_node_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_level_node_count');
    {$ifend}
  end;


  X509_policy_level_get0_node := LoadLibFunction(ADllHandle, X509_policy_level_get0_node_procname);
  FuncLoadError := not assigned(X509_policy_level_get0_node);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_level_get0_node_allownil)}
    X509_policy_level_get0_node := @ERR_X509_policy_level_get0_node;
    {$ifend}
    {$if declared(X509_policy_level_get0_node_introduced)}
    if LibVersion < X509_policy_level_get0_node_introduced then
    begin
      {$if declared(FC_X509_policy_level_get0_node)}
      X509_policy_level_get0_node := @FC_X509_policy_level_get0_node;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_level_get0_node_removed)}
    if X509_policy_level_get0_node_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_level_get0_node)}
      X509_policy_level_get0_node := @_X509_policy_level_get0_node;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_level_get0_node_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_level_get0_node');
    {$ifend}
  end;


  X509_policy_node_get0_policy := LoadLibFunction(ADllHandle, X509_policy_node_get0_policy_procname);
  FuncLoadError := not assigned(X509_policy_node_get0_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_node_get0_policy_allownil)}
    X509_policy_node_get0_policy := @ERR_X509_policy_node_get0_policy;
    {$ifend}
    {$if declared(X509_policy_node_get0_policy_introduced)}
    if LibVersion < X509_policy_node_get0_policy_introduced then
    begin
      {$if declared(FC_X509_policy_node_get0_policy)}
      X509_policy_node_get0_policy := @FC_X509_policy_node_get0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_node_get0_policy_removed)}
    if X509_policy_node_get0_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_node_get0_policy)}
      X509_policy_node_get0_policy := @_X509_policy_node_get0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_node_get0_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_node_get0_policy');
    {$ifend}
  end;


  X509_policy_node_get0_parent := LoadLibFunction(ADllHandle, X509_policy_node_get0_parent_procname);
  FuncLoadError := not assigned(X509_policy_node_get0_parent);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_node_get0_parent_allownil)}
    X509_policy_node_get0_parent := @ERR_X509_policy_node_get0_parent;
    {$ifend}
    {$if declared(X509_policy_node_get0_parent_introduced)}
    if LibVersion < X509_policy_node_get0_parent_introduced then
    begin
      {$if declared(FC_X509_policy_node_get0_parent)}
      X509_policy_node_get0_parent := @FC_X509_policy_node_get0_parent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_node_get0_parent_removed)}
    if X509_policy_node_get0_parent_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_node_get0_parent)}
      X509_policy_node_get0_parent := @_X509_policy_node_get0_parent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_node_get0_parent_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_node_get0_parent');
    {$ifend}
  end;


end;

procedure Unload;
begin
  X509_STORE_set_depth := nil;
  X509_STORE_CTX_set_depth := nil;
  X509_STORE_CTX_get_app_data := nil; {removed 1.0.0}
  X509_OBJECT_up_ref_count := nil;
  X509_OBJECT_new := nil; {introduced 1.1.0}
  X509_OBJECT_free := nil; {introduced 1.1.0}
  X509_OBJECT_get_type := nil; {introduced 1.1.0}
  X509_OBJECT_get0_X509 := nil; {introduced 1.1.0}
  X509_OBJECT_set1_X509 := nil; {introduced 1.1.0}
  X509_OBJECT_get0_X509_CRL := nil; {introduced 1.1.0}
  X509_OBJECT_set1_X509_CRL := nil; {introduced 1.1.0}
  X509_STORE_new := nil;
  X509_STORE_free := nil;
  X509_STORE_lock := nil; {introduced 1.1.0}
  X509_STORE_unlock := nil; {introduced 1.1.0}
  X509_STORE_up_ref := nil; {introduced 1.1.0}
  X509_STORE_set_flags := nil;
  X509_STORE_set_purpose := nil;
  X509_STORE_set_trust := nil;
  X509_STORE_set1_param := nil;
  X509_STORE_get0_param := nil; {introduced 1.1.0}
  X509_STORE_set_verify := nil; {introduced 1.1.0}
  X509_STORE_CTX_set_verify := nil; {introduced 1.1.0}
  X509_STORE_get_verify := nil; {introduced 1.1.0}
  X509_STORE_set_verify_cb := nil;
  X509_STORE_get_verify_cb := nil; {introduced 1.1.0}
  X509_STORE_set_get_issuer := nil; {introduced 1.1.0}
  X509_STORE_get_get_issuer := nil; {introduced 1.1.0}
  X509_STORE_set_check_issued := nil; {introduced 1.1.0}
  X509_STORE_get_check_issued := nil; {introduced 1.1.0}
  X509_STORE_set_check_revocation := nil; {introduced 1.1.0}
  X509_STORE_get_check_revocation := nil; {introduced 1.1.0}
  X509_STORE_set_get_crl := nil; {introduced 1.1.0}
  X509_STORE_get_get_crl := nil; {introduced 1.1.0}
  X509_STORE_set_check_crl := nil; {introduced 1.1.0}
  X509_STORE_get_check_crl := nil; {introduced 1.1.0}
  X509_STORE_set_cert_crl := nil; {introduced 1.1.0}
  X509_STORE_get_cert_crl := nil; {introduced 1.1.0}
  X509_STORE_set_check_policy := nil; {introduced 1.1.0}
  X509_STORE_get_check_policy := nil; {introduced 1.1.0}
  X509_STORE_set_cleanup := nil; {introduced 1.1.0}
  X509_STORE_get_cleanup := nil; {introduced 1.1.0}
  X509_STORE_set_ex_data := nil; {introduced 1.1.0}
  X509_STORE_get_ex_data := nil; {introduced 1.1.0}
  X509_STORE_CTX_new := nil;
  X509_STORE_CTX_get1_issuer := nil;
  X509_STORE_CTX_free := nil;
  X509_STORE_CTX_cleanup := nil;
  X509_STORE_CTX_get0_store := nil;
  X509_STORE_CTX_get0_cert := nil; {introduced 1.1.0}
  X509_STORE_CTX_set_verify_cb := nil;
  X509_STORE_CTX_get_verify_cb := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_verify := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_get_issuer := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_issued := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_revocation := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_get_crl := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_crl := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_cert_crl := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_check_policy := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_cleanup := nil; {introduced 1.1.0}
  X509_STORE_add_lookup := nil;
  X509_LOOKUP_hash_dir := nil;
  X509_LOOKUP_file := nil;
  X509_LOOKUP_meth_new := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_free := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_set_ctrl := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_ctrl := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_subject := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_subject := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_issuer_serial := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_issuer_serial := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_fingerprint := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_fingerprint := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_set_get_by_alias := nil; {introduced 1.1.0}
  X509_LOOKUP_meth_get_get_by_alias := nil; {introduced 1.1.0}
  X509_STORE_add_cert := nil;
  X509_STORE_add_crl := nil;
  X509_STORE_CTX_get_by_subject := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_obj_by_subject := nil; {introduced 1.1.0}
  X509_LOOKUP_ctrl := nil;
  X509_load_cert_file := nil;
  X509_load_crl_file := nil;
  X509_load_cert_crl_file := nil;
  X509_LOOKUP_new := nil;
  X509_LOOKUP_free := nil;
  X509_LOOKUP_init := nil;
  X509_LOOKUP_by_subject := nil;
  X509_LOOKUP_by_issuer_serial := nil;
  X509_LOOKUP_by_fingerprint := nil;
  X509_LOOKUP_by_alias := nil;
  X509_LOOKUP_set_method_data := nil; {introduced 1.1.0}
  X509_LOOKUP_get_method_data := nil; {introduced 1.1.0}
  X509_LOOKUP_get_store := nil; {introduced 1.1.0}
  X509_LOOKUP_shutdown := nil;
  X509_STORE_load_locations := nil;
  X509_STORE_set_default_paths := nil;
  X509_STORE_CTX_set_ex_data := nil;
  X509_STORE_CTX_get_ex_data := nil;
  X509_STORE_CTX_get_error := nil;
  X509_STORE_CTX_set_error := nil;
  X509_STORE_CTX_get_error_depth := nil;
  X509_STORE_CTX_set_error_depth := nil; {introduced 1.1.0}
  X509_STORE_CTX_get_current_cert := nil;
  X509_STORE_CTX_set_current_cert := nil; {introduced 1.1.0}
  X509_STORE_CTX_get0_current_issuer := nil;
  X509_STORE_CTX_get0_current_crl := nil;
  X509_STORE_CTX_get0_parent_ctx := nil;
  X509_STORE_CTX_set_cert := nil;
  X509_STORE_CTX_set_purpose := nil;
  X509_STORE_CTX_set_trust := nil;
  X509_STORE_CTX_purpose_inherit := nil;
  X509_STORE_CTX_set_flags := nil;
  X509_STORE_CTX_get0_policy_tree := nil;
  X509_STORE_CTX_get_explicit_policy := nil;
  X509_STORE_CTX_get_num_untrusted := nil; {introduced 1.1.0}
  X509_STORE_CTX_get0_param := nil;
  X509_STORE_CTX_set0_param := nil;
  X509_STORE_CTX_set_default := nil;
  X509_STORE_CTX_set0_dane := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_new := nil;
  X509_VERIFY_PARAM_free := nil;
  X509_VERIFY_PARAM_inherit := nil;
  X509_VERIFY_PARAM_set1 := nil;
  X509_VERIFY_PARAM_set1_name := nil;
  X509_VERIFY_PARAM_set_flags := nil;
  X509_VERIFY_PARAM_clear_flags := nil;
  X509_VERIFY_PARAM_get_flags := nil;
  X509_VERIFY_PARAM_set_purpose := nil;
  X509_VERIFY_PARAM_set_trust := nil;
  X509_VERIFY_PARAM_set_depth := nil;
  X509_VERIFY_PARAM_set_auth_level := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_add0_policy := nil;
  X509_VERIFY_PARAM_set_inh_flags := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_get_inh_flags := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_set1_host := nil;
  X509_VERIFY_PARAM_add1_host := nil;
  X509_VERIFY_PARAM_set_hostflags := nil;
  X509_VERIFY_PARAM_get_hostflags := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_peername := nil;
  X509_VERIFY_PARAM_move_peername := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_set1_email := nil;
  X509_VERIFY_PARAM_set1_ip := nil;
  X509_VERIFY_PARAM_set1_ip_asc := nil;
  X509_VERIFY_PARAM_get_depth := nil;
  X509_VERIFY_PARAM_get_auth_level := nil; {introduced 1.1.0}
  X509_VERIFY_PARAM_get0_name := nil;
  X509_VERIFY_PARAM_add0_table := nil;
  X509_VERIFY_PARAM_get_count := nil;
  X509_VERIFY_PARAM_get0 := nil;
  X509_VERIFY_PARAM_lookup := nil;
  X509_VERIFY_PARAM_table_cleanup := nil;
  X509_policy_tree_free := nil;
  X509_policy_tree_level_count := nil;
  X509_policy_tree_get0_level := nil;
  X509_policy_level_node_count := nil;
  X509_policy_level_get0_node := nil;
  X509_policy_node_get0_policy := nil;
  X509_policy_node_get0_parent := nil;
end;
{$ELSE}
function X509_STORE_CTX_get_app_data(ctx: PX509_STORE_CTX): Pointer;
begin
  Result := X509_STORE_CTX_get_ex_data(ctx,SSL_get_ex_data_X509_STORE_CTX_idx);
end;


{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
