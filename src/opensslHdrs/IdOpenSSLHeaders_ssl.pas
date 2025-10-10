(* This unit was generated from the source file ssl.h2pas 
It should not be modified directly. All changes should be made to ssl.h2pas
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


unit IdOpenSSLHeaders_ssl;




interface

// Headers for OpenSSL 1.1.1
// ssl.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_async,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_crypto,
  IdOpenSSLHeaders_pem,
  IdOpenSSLHeaders_tls1,
  IdOpenSSLHeaders_ssl3,
  IdOpenSSLHeaders_x509;

{$MINENUMSIZE 4}

const
  (* OpenSSL version number for ASN.1 encoding of the session information *)
  (*-
   * Version 0 - initial version
   * Version 1 - added the optional peer certificate
   *)
  SSL_SESSION_ASN1_VERSION = $0001;
  
  SSL_MAX_SSL_SESSION_ID_LENGTH = 32;
  SSL_MAX_SID_CTX_LENGTH = 32;

  SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES = 512/8;
  SSL_MAX_KEY_ARG_LENGTH = 8;
  SSL_MAX_MASTER_KEY_LENGTH = 48;

  (* The maximum number of encrypt/decrypt pipelines we can support *)
  SSL_MAX_PIPELINES = 32;

  (* text strings for the ciphers *)

  (* These are used to specify which ciphers to use and not to use *)

  SSL_TXT_LOW = AnsiString('LOW');
  SSL_TXT_MEDIUM = AnsiString('MEDIUM');
  SSL_TXT_HIGH = AnsiString('HIGH');
  SSL_TXT_FIPS = AnsiString('FIPS');

  SSL_TXT_aNULL = AnsiString('aNULL');
  SSL_TXT_eNULL = AnsiString('eNULL');
  SSL_TXT_NULL = AnsiString('NULL');

  SSL_TXT_kRSA = AnsiString('kRSA');
  SSL_TXT_kDHr = AnsiString('kDHr');
  SSL_TXT_kDHd = AnsiString('kDHd');
  SSL_TXT_kDH = AnsiString('kDH');
  SSL_TXT_kEDH = AnsiString('kEDH');
  SSL_TXT_kDHE = AnsiString('kDHE');
  SSL_TXT_kECDHr = AnsiString('kECDHr');
//const SSL_TXT_kECDHe = AnsiString('kECDHe');
  SSL_TXT_kECDH = AnsiString('kECDH');
  SSL_TXT_kEECDH = AnsiString('kEECDH');
  SSL_TXT_kECDHE = AnsiString('kECDHE');
  SSL_TXT_kPSK = AnsiString('kPSK');
  SSL_TXT_kRSAPSK = AnsiString('kRSAPSK');
  SSL_TXT_kECDHEPSK = AnsiString('kECDHEPSK');
  SSL_TXT_kDHEPSK = AnsiString('kDHEPSK');
  SSL_TXT_kGOST = AnsiString('kGOST');
  SSL_TXT_kSRP = AnsiString('kSRP');

  SSL_TXT_aRSA = AnsiString('aRSA');
  SSL_TXT_aDSS = AnsiString('aDSS');
  SSL_TXT_aDH = AnsiString('aDH');
  SSL_TXT_aECDH = AnsiString('aECDH');
  SSL_TXT_aECDSA = AnsiString('aECDSA');
  SSL_TXT_aPSK = AnsiString('aPSK');
  SSL_TXT_aGOST94 = AnsiString('aGOST94');
  SSL_TXT_aGOST01 = AnsiString('aGOST01');
  SSL_TXT_aGOST12 = AnsiString('aGOST12');
  SSL_TXT_aGOST = AnsiString('aGOST');
  SSL_TXT_aSRP = AnsiString('aSRP');

  SSL_TXT_DSS = AnsiString('DSS');
  SSL_TXT_DH = AnsiString('DH');
  SSL_TXT_DHE = AnsiString('DHE');
  SSL_TXT_EDH = AnsiString('EDH');
  //SSL_TXT_ADH = AnsiString('ADH');
  SSL_TXT_RSA = AnsiString('RSA');
  SSL_TXT_ECDH = AnsiString('ECDH');
  SSL_TXT_EECDH = AnsiString('EECDH');
  SSL_TXT_ECDHE = AnsiString('ECDHE');
  //SSL_TXT_AECDH = AnsiString('AECDH');
  SSL_TXT_ECDSA = AnsiString('ECDSA');
  SSL_TXT_PSK = AnsiString('PSK');
  SSL_TXT_SRP = AnsiString('SRP');

  SSL_TXT_DES = AnsiString('DES');
  SSL_TXT_3DES = AnsiString('3DES');
  SSL_TXT_RC4 = AnsiString('RC4');
  SSL_TXT_RC2 = AnsiString('RC2');
  SSL_TXT_IDEA = AnsiString('IDEA');
  SSL_TXT_SEED = AnsiString('SEED');
  SSL_TXT_AES128 = AnsiString('AES128');
  SSL_TXT_AES256 = AnsiString('AES256');
  SSL_TXT_AES = AnsiString('AES');
  SSL_TXT_AES_GCM = AnsiString('AESGCM');
  SSL_TXT_AES_CCM = AnsiString('AESCCM');
  SSL_TXT_AES_CCM_8 = AnsiString('AESCCM8');
  SSL_TXT_CAMELLIA128 = AnsiString('CAMELLIA128');
  SSL_TXT_CAMELLIA256 = AnsiString('CAMELLIA256');
  SSL_TXT_CAMELLIA = AnsiString('CAMELLIA');
  SSL_TXT_CHACHA20 = AnsiString('CHACHA20');
  SSL_TXT_GOST = AnsiString('GOST89');
  SSL_TXT_ARIA = AnsiString('ARIA');
  SSL_TXT_ARIA_GCM = AnsiString('ARIAGCM');
  SSL_TXT_ARIA128 = AnsiString('ARIA128');
  SSL_TXT_ARIA256 = AnsiString('ARIA256');

  SSL_TXT_MD5 = AnsiString('MD5');
  SSL_TXT_SHA1 = AnsiString('SHA1');
  SSL_TXT_SHA = AnsiString('SHA');
  SSL_TXT_GOST94 = AnsiString('GOST94');
  SSL_TXT_GOST89MAC = AnsiString('GOST89MAC');
  SSL_TXT_GOST12 = AnsiString('GOST12');
  SSL_TXT_GOST89MAC12 = AnsiString('GOST89MAC12');
  SSL_TXT_SHA256 = AnsiString('SHA256');
  SSL_TXT_SHA384 = AnsiString('SHA384');

  SSL_TXT_SSLV3 = AnsiString('SSLv3');
  SSL_TXT_TLSV1 = AnsiString('TLSv1');
  SSL_TXT_TLSV1_1 = AnsiString('TLSv1.1');
  SSL_TXT_TLSV1_2 = AnsiString('TLSv1.2');

  SSL_TXT_ALL = AnsiString('ALL');

  (*-
   * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
   * ciphers normally not being used.
   * Example: "RC4" will activate all ciphers using RC4 including ciphers
   * without authentication, which would normally disabled by DEFAULT (due
   * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
   * will make sure that it is also disabled in the specific selection.
   * COMPLEMENTOF* identifiers are portable between version, as adjustments
   * to the default cipher setup will also be included here.
   *
   * COMPLEMENTOFDEFAULT does not experience the same special treatment that
   * DEFAULT gets, as only selection is being done and no sorting as needed
   * for DEFAULT.
   *)
  SSL_TXT_CMPALL = AnsiString('COMPLEMENTOFALL');
  SSL_TXT_CMPDEF = AnsiString('COMPLEMENTOFDEFAULT');

  (*
   * The following cipher list is used by default. It also is substituted when
   * an application-defined cipher list string starts with 'DEFAULT'.
   * This applies to ciphersuites for TLSv1.2 and below.
   *)
  SSL_DEFAULT_CIPHER_LIST = AnsiString('ALL:!COMPLEMENTOFDEFAULT:!eNULL');
  (* This is the default set of TLSv1.3 ciphersuites *)
  TLS_DEFAULT_CIPHERSUITES = AnsiString('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256');

  (*
   * As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
   * starts with a reasonable order, and all we have to do for DEFAULT is
   * throwing out anonymous and unencrypted ciphersuites! (The latter are not
   * actually enabled by ALL, but "ALL:RSA" would enable some of them.)
   *)

  (* Used in SSL_set_shutdown()/SSL_get_shutdown(); *)
  SSL_SENT_SHUTDOWN = 1;
  SSL_RECEIVED_SHUTDOWN = 2;

  SSL_FILETYPE_ASN1 = X509_FILETYPE_ASN1;
  SSL_FILETYPE_PEM = X509_FILETYPE_PEM;

  {Error codes for the SSL functions.}
  SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = 220;

  (* Extension context codes *)
  (* This extension is only allowed in TLS *)
  SSL_EXT_TLS_ONLY = $0001;
  (* This extension is only allowed in DTLS *)
  SSL_EXT_DTLS_ONLY = $0002;
  (* Some extensions may be allowed in DTLS but we don't implement them for it *)
  SSL_EXT_TLS_IMPLEMENTATION_ONLY = $0004;
  (* Most extensions are not defined for SSLv3 but EXT_TYPE_renegotiate is *)
  SSL_EXT_SSL3_ALLOWED = $0008;
  (* Extension is only defined for TLS1.2 and below *)
  SSL_EXT_TLS1_2_AND_BELOW_ONLY = $0010;
  (* Extension is only defined for TLS1.3 and above *)
  SSL_EXT_TLS1_3_ONLY = $0020;
  (* Ignore this extension during parsing if we are resuming *)
  SSL_EXT_IGNORE_ON_RESUMPTION = $0040;
  SSL_EXT_CLIENT_HELLO = $0080;
  (* Really means TLS1.2 or below *)
  SSL_EXT_TLS1_2_SERVER_HELLO = $0100;
  SSL_EXT_TLS1_3_SERVER_HELLO = $0200;
  SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS = $0400;
  SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST = $0800;
  SSL_EXT_TLS1_3_CERTIFICATE = $1000;
  SSL_EXT_TLS1_3_NEW_SESSION_TICKET = $2000;
  SSL_EXT_TLS1_3_CERTIFICATE_REQUEST = $4000;

  (*
   * Some values are reserved until OpenSSL 1.2.0 because they were previously
   * included in SSL_OP_ALL in a 1.1.x release.
   *
   * Reserved value (until OpenSSL 1.2.0)                  $00000001U
   * Reserved value (until OpenSSL 1.2.0)                  $00000002U
   *)
  (* Allow initial connection to servers that don't support RI *)
  SSL_OP_LEGACY_SERVER_CONNECT = TOpenSSL_C_UINT($00000004);

  (* Reserved value (until OpenSSL 1.2.0)                  $00000008U *)
  SSL_OP_TLSEXT_PADDING =      TOpenSSL_C_UINT($00000010);
  (* Reserved value (until OpenSSL 1.2.0)                  $00000020U *)
  SSL_OP_SAFARI_ECDHE_ECDSA_BUG = TOpenSSL_C_UINT($00000040);
  (*
   * Reserved value (until OpenSSL 1.2.0)                  $00000080U
   * Reserved value (until OpenSSL 1.2.0)                  $00000100U
   * Reserved value (until OpenSSL 1.2.0)                  $00000200U
   *)

  (* In TLSv1.3 allow a non-(ec)dhe based kex_mode *)
  SSL_OP_ALLOW_NO_DHE_KEX                         = TOpenSSL_C_UINT($00000400);

  (*
   * Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added in
   * OpenSSL 0.9.6d.  Usually (depending on the application protocol) the
   * workaround is not needed.  Unfortunately some broken SSL/TLS
   * implementations cannot handle it at all, which is why we include it in
   * SSL_OP_ALL. Added in 0.9.6e
   *)
  SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              = TOpenSSL_C_UINT($00000800);

  (* DTLS options *)
  SSL_OP_NO_QUERY_MTU                             = TOpenSSL_C_UINT($00001000);
  (* Turn on Cookie Exchange (on relevant for servers) *)
  SSL_OP_COOKIE_EXCHANGE                          = TOpenSSL_C_UINT($00002000);
  (* Don't use RFC4507 ticket extension *)
  SSL_OP_NO_TICKET                                = TOpenSSL_C_UINT($00004000);
  (* Use Cisco's "speshul" version of DTLS_BAD_VER
   * (only with deprecated DTLSv1_client_method())  *)
  SSL_OP_CISCO_ANYCONNECT                        = TOpenSSL_C_UINT($00008000);

  (* As server, disallow session resumption on renegotiation *)
  SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   = TOpenSSL_C_UINT($00010000);
  (* Don't use compression even if supported *)
  SSL_OP_NO_COMPRESSION                           = TOpenSSL_C_UINT($00020000);
  (* Permit unsafe legacy renegotiation *)
  SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        = TOpenSSL_C_UINT($00040000);
  (* Disable encrypt-then-mac *)
  SSL_OP_NO_ENCRYPT_THEN_MAC                      = TOpenSSL_C_UINT($00080000);

  (*
   * Enable TLSv1.3 Compatibility mode. This is on by default. A future version
   * of OpenSSL may have this disabled by default.
   *)
  SSL_OP_ENABLE_MIDDLEBOX_COMPAT                  = TOpenSSL_C_UINT($00100000);

  (* Prioritize Chacha20Poly1305 when client does.
   * Modifies SSL_OP_CIPHER_SERVER_PREFERENCE *)
  SSL_OP_PRIORITIZE_CHACHA                        = TOpenSSL_C_UINT($00200000);

  (*
   * Set on servers to choose the cipher according to the server's preferences
   *)
  SSL_OP_CIPHER_SERVER_PREFERENCE                 = TOpenSSL_C_UINT($00400000);
  (*
   * If set, a server will allow a client to issue a SSLv3.0 version number as
   * latest version supported in the premaster secret, even when TLSv1.0
   * (version 3.1) was announced in the client hello. Normally this is
   * forbidden to prevent version rollback attacks.
   *)
  SSL_OP_TLS_ROLLBACK_BUG                         = TOpenSSL_C_UINT($00800000);

  (*
   * Switches off automatic TLSv1.3 anti-replay protection for early data. This
   * is a server-side option only (no effect on the client).
   *)
  SSL_OP_NO_ANTI_REPLAY                           = TOpenSSL_C_UINT($01000000);

  SSL_OP_NO_SSLv3                                 = TOpenSSL_C_UINT($02000000);
  SSL_OP_NO_TLSv1                                 = TOpenSSL_C_UINT($04000000);
  SSL_OP_NO_TLSv1_2                               = TOpenSSL_C_UINT($08000000);
  SSL_OP_NO_TLSv1_1                               = TOpenSSL_C_UINT($10000000);
  SSL_OP_NO_TLSv1_3                               = TOpenSSL_C_UINT($20000000);

  SSL_OP_NO_DTLSv1                                = TOpenSSL_C_UINT($04000000);
  SSL_OP_NO_DTLSv1_2                              = TOpenSSL_C_UINT($08000000);

  SSL_OP_NO_SSL_MASK = SSL_OP_NO_SSLv3 or SSL_OP_NO_TLSv1 or SSL_OP_NO_TLSv1_1
    or SSL_OP_NO_TLSv1_2 or SSL_OP_NO_TLSv1_3;
  SSL_OP_NO_DTLS_MASK = SSL_OP_NO_DTLSv1 or SSL_OP_NO_DTLSv1_2;

  (* Disallow all renegotiation *)
  SSL_OP_NO_RENEGOTIATION                         = TOpenSSL_C_UINT($40000000);

  (*
   * Make server add server-hello extension from early version of cryptopro
   * draft, when GOST ciphersuite is negotiated. Required for interoperability
   * with CryptoPro CSP 3.x
   *)
  SSL_OP_CRYPTOPRO_TLSEXT_BUG                     = TOpenSSL_C_UINT($80000000);

  (*
   * SSL_OP_ALL: various bug workarounds that should be rather harmless.
   * This used to be $000FFFFFL before 0.9.7.
   * This used to be $80000BFFU before 1.1.1.
   *)
  SSL_OP_ALL = SSL_OP_CRYPTOPRO_TLSEXT_BUG or SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    or SSL_OP_LEGACY_SERVER_CONNECT or SSL_OP_TLSEXT_PADDING or SSL_OP_SAFARI_ECDHE_ECDSA_BUG;

  (* OBSOLETE OPTIONS: retained for compatibility *)

  (* Removed from OpenSSL 1.1.0. Was $00000001L *)
  (* Related to removed SSLv2. *)
  SSL_OP_MICROSOFT_SESS_ID_BUG                    = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000002L *)
  (* Related to removed SSLv2. *)
  SSL_OP_NETSCAPE_CHALLENGE_BUG                   = $0;
  (* Removed from OpenSSL 0.9.8q and 1.0.0c. Was $00000008L *)
  (* Dead forever, see CVE-2010-4180 *)
  SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         = $0;
  (* Removed from OpenSSL 1.0.1h and 1.0.2. Was $00000010L *)
  (* Refers to ancient SSLREF and SSLv2. *)
  SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000020 *)
  SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               = $0;
  (* Removed from OpenSSL 0.9.7h and 0.9.8b. Was $00000040L *)
  SSL_OP_MSIE_SSLV2_RSA_PADDING                   = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000080 *)
  (* Ancient SSLeay version. *)
  SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000100L *)
  SSL_OP_TLS_D5_BUG                               = $0;
  (* Removed from OpenSSL 1.1.0. Was $00000200L *)
  SSL_OP_TLS_BLOCK_PADDING_BUG                    = $0;
  (* Removed from OpenSSL 1.1.0. Was $00080000L *)
  SSL_OP_SINGLE_ECDH_USE                          = $0;
  (* Removed from OpenSSL 1.1.0. Was $00100000L *)
  SSL_OP_SINGLE_DH_USE                            = $0;
  (* Removed from OpenSSL 1.0.1k and 1.0.2. Was $00200000L *)
  SSL_OP_EPHEMERAL_RSA                            = $0;
  (* Removed from OpenSSL 1.1.0. Was $01000000L *)
  SSL_OP_NO_SSLv2                                 = $0;
  (* Removed from OpenSSL 1.0.1. Was $08000000L *)
  SSL_OP_PKCS1_CHECK_1                            = $0;
  (* Removed from OpenSSL 1.0.1. Was $10000000L *)
  SSL_OP_PKCS1_CHECK_2                            = $0;
  (* Removed from OpenSSL 1.1.0. Was $20000000L *)
  SSL_OP_NETSCAPE_CA_DN_BUG                       = $0;
  (* Removed from OpenSSL 1.1.0. Was $40000000L *)
  SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          = $0;

  (*
   * Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
   * when just a single record has been written):
   *)
  SSL_MODE_ENABLE_PARTIAL_WRITE = TOpenSSL_C_UINT($00000001);
  (*
   * Make it possible to retry SSL_write() with changed buffer location (buffer
   * contents must stay the same!); this is not the default to avoid the
   * misconception that non-blocking SSL_write() behaves like non-blocking
   * write():
   *)
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = TOpenSSL_C_UINT($00000002);
  (*
   * Never bother the application with retries if the transport is blocking:
   *)
  SSL_MODE_AUTO_RETRY = TOpenSSL_C_UINT($00000004);
  (* Don't attempt to automatically build certificate chain *)
  SSL_MODE_NO_AUTO_CHAIN = TOpenSSL_C_UINT($00000008);
  (*
   * Save RAM by releasing read and write buffers when they're empty. (SSL3 and
   * TLS only.) Released buffers are freed.
   *)
  SSL_MODE_RELEASE_BUFFERS = TOpenSSL_C_UINT($00000010);
  (*
   * Send the current time in the Random fields of the ClientHello and
   * ServerHello records for compatibility with hypothetical implementations
   * that require it.
   *)
  SSL_MODE_SEND_CLIENTHELLO_TIME = TOpenSSL_C_UINT($00000020);
  SSL_MODE_SEND_SERVERHELLO_TIME = TOpenSSL_C_UINT($00000040);
  (*
   * Send TLS_FALLBACK_SCSV in the ClientHello. To be set only by applications
   * that reconnect with a downgraded protocol version; see
   * draft-ietf-tls-downgrade-scsv-00 for details. DO NOT ENABLE THIS if your
   * application attempts a normal handshake. Only use this in explicit
   * fallback retries, following the guidance in
   * draft-ietf-tls-downgrade-scsv-00.
   *)
  SSL_MODE_SEND_FALLBACK_SCSV = TOpenSSL_C_UINT($00000080);
  (*
   * Support Asynchronous operation
   *)
  SSL_MODE_ASYNC = TOpenSSL_C_UINT($00000100);

  (*
   * When using DTLS/SCTP, include the terminating zero in the label
   * used for computing the endpoint-pair shared secret. Required for
   * interoperability with implementations having this bug like these
   * older version of OpenSSL:
   * - OpenSSL 1.0.0 series
   * - OpenSSL 1.0.1 series
   * - OpenSSL 1.0.2 series
   * - OpenSSL 1.1.0 series
   * - OpenSSL 1.1.1 and 1.1.1a
   *)
  SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG = TOpenSSL_C_UINT($00000400);

  (* Cert related flags *)
  (*
   * Many implementations ignore some aspects of the TLS standards such as
   * enforcing certificate chain algorithms. When this is set we enforce them.
   *)
  SSL_CERT_FLAG_TLS_STRICT = TOpenSSL_C_UINT($00000001);
  (* Suite B modes, takes same values as certificate verify flags *)
  SSL_CERT_FLAG_SUITEB_128_LOS_ONLY = $10000;
  (* Suite B 192 bit only mode *)
  SSL_CERT_FLAG_SUITEB_192_LOS = $20000;
  (* Suite B 128 bit mode allowing 192 bit algorithms *)
  SSL_CERT_FLAG_SUITEB_128_LOS = $30000;

  (* Perform all sorts of protocol violations for testing purposes *)
  SSL_CERT_FLAG_BROKEN_PROTOCOL = $10000000;

  (* Flags for building certificate chains *)
  (* Treat any existing certificates as untrusted CAs *)
  SSL_BUILD_CHAIN_FLAG_UNTRUSTED = $1;
  (* Don't include root CA in chain *)
  SSL_BUILD_CHAIN_FLAG_NO_ROOT = $2;
  (* Just check certificates already there *)
  SSL_BUILD_CHAIN_FLAG_CHECK = $4;
  (* Ignore verification errors *)
  SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR = $8;
  (* Clear verification errors from queue *)
  SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR = $10;

  (* Flags returned by SSL_check_chain *)
  (* Certificate can be used with this session *)
  CERT_PKEY_VALID = $1;
  (* Certificate can also be used for signing *)
  CERT_PKEY_SIGN = $2;
  (* EE certificate signing algorithm OK *)
  CERT_PKEY_EE_SIGNATURE = $10;
  (* CA signature algorithms OK *)
  CERT_PKEY_CA_SIGNATURE = $20;
  (* EE certificate parameters OK *)
  CERT_PKEY_EE_PARAM = $40;
  (* CA certificate parameters OK *)
  CERT_PKEY_CA_PARAM = $80;
  (* Signing explicitly allowed as opposed to SHA1 fallback *)
  CERT_PKEY_EXPLICIT_SIGN = $100;
  (* Client CA issuer names match (always set for server cert) *)
  CERT_PKEY_ISSUER_NAME = $200;
  (* Cert type matches client types (always set for server cert) *)
  CERT_PKEY_CERT_TYPE = $400;
  (* Cert chain suitable to Suite B *)
  CERT_PKEY_SUITEB = $800;

  SSL_CONF_FLAG_CMDLINE = $1;
  SSL_CONF_FLAG_FILE = $2;
  SSL_CONF_FLAG_CLIENT = $4;
  SSL_CONF_FLAG_SERVER = $8;
  SSL_CONF_FLAG_SHOW_ERRORS = $10;
  SSL_CONF_FLAG_CERTIFICATE = $20;
  SSL_CONF_FLAG_REQUIRE_PRIVATE = $40;
  (* Configuration value types *)
  SSL_CONF_TYPE_UNKNOWN = $0;
  SSL_CONF_TYPE_STRING = $1;
  SSL_CONF_TYPE_FILE = $2;
  SSL_CONF_TYPE_DIR = $3;
  SSL_CONF_TYPE_NONE = $4;

  (* Maximum length of the application-controlled segment of a a TLSv1.3 cookie *)
  SSL_COOKIE_LENGTH = 4096;

  (* 100k max cert list *)
  SSL_MAX_CERT_LIST_DEFAULT = 1024 * 100;
  SSL_SESSION_CACHE_MAX_SIZE_DEFAULT = 1024 * 20;

  SSL_SESS_CACHE_OFF = $0000;
  SSL_SESS_CACHE_CLIENT = $0001;
  SSL_SESS_CACHE_SERVER = $0002;
  SSL_SESS_CACHE_BOTH = (SSL_SESS_CACHE_CLIENT or SSL_SESS_CACHE_SERVER);
  SSL_SESS_CACHE_NO_AUTO_CLEAR = $0080;
  (* enough comments already ... see SSL_CTX_set_session_cache_mode(3) *)
  SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = $0100;
  SSL_SESS_CACHE_NO_INTERNAL_STORE = $0200;
  SSL_SESS_CACHE_NO_INTERNAL = (SSL_SESS_CACHE_NO_INTERNAL_LOOKUP or SSL_SESS_CACHE_NO_INTERNAL_STORE);

  OPENSSL_NPN_UNSUPPORTED = 0;
  OPENSSL_NPN_NEGOTIATED = 1;
  OPENSSL_NPN_NO_OVERLAP = 2;

  (*
   * the maximum length of the buffer given to callbacks containing the
   * resulting identity/psk
   *)
  PSK_MAX_IDENTITY_LEN = 128;
  PSK_MAX_PSK_LEN = 256;

  SSL_NOTHING = 1;
  SSL_WRITING = 2;
  SSL_READING = 3;
  SSL_X509_LOOKUP = 4;
  SSL_ASYNC_PAUSED = 5;
  SSL_ASYNC_NO_JOBS = 6;
  SSL_CLIENT_HELLO_CB = 7;

  SSL_MAC_FLAG_READ_MAC_STREAM = 1;
  SSL_MAC_FLAG_WRITE_MAC_STREAM = 2;

  (* TLSv1.3 KeyUpdate message types *)
  (* -1 used so that this is an invalid value for the on-the-wire protocol *)
  SSL_KEY_UPDATE_NONE = -1;
  (* Values as defined for the on-the-wire protocol *)
  SSL_KEY_UPDATE_NOT_REQUESTED = 0;
  SSL_KEY_UPDATE_REQUESTED = 1;

  (*
   * Most of the following state values are no longer used and are defined to be
   * the closest equivalent value in_ the current state machine code. Not all
   * defines have an equivalent and are set to a dummy value (-1). SSL_ST_CONNECT
   * and SSL_ST_ACCEPT are still in_ use in_ the definition of SSL_CB_ACCEPT_LOOP,
   * SSL_CB_ACCEPT_EXIT, SSL_CB_CONNECT_LOOP and SSL_CB_CONNECT_EXIT.
   *)
  SSL_ST_CONNECT = $1000;
  SSL_ST_ACCEPT = $2000;
  
  SSL_ST_MASK = $0FFF;
  
  SSL_CB_LOOP = $01;
  SSL_CB_EXIT = $02;
  SSL_CB_READ = $04;
  SSL_CB_WRITE = $08;
  SSL_CB_ALERT = $4000;
  SSL_CB_READ_ALERT = SSL_CB_ALERT or SSL_CB_READ;
  SSL_CB_WRITE_ALERT = SSL_CB_ALERT or SSL_CB_WRITE;
  SSL_CB_ACCEPT_LOOP = SSL_ST_ACCEPT or SSL_CB_LOOP;
  SSL_CB_ACCEPT_EXIT = SSL_ST_ACCEPT or SSL_CB_EXIT;
  SSL_CB_CONNECT_LOOP = SSL_ST_CONNECT or SSL_CB_LOOP;
  SSL_CB_CONNECT_EXIT = SSL_ST_CONNECT or SSL_CB_EXIT;
  SSL_CB_HANDSHAKE_START = $10;
  SSL_CB_HANDSHAKE_DONE = $20;

  (*
   * The following 3 states are kept in ssl->rlayer.rstate when reads fail, you
   * should not need these
   *)
  SSL_ST_READ_HEADER = $F0;
  SSL_ST_READ_BODY = $F1;
  SSL_ST_READ_DONE = $F2;

  (*
   * use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 3 options are
   * 'ored' with SSL_VERIFY_PEER if they are desired
   *)
  SSL_VERIFY_NONE = $00;
  SSL_VERIFY_PEER = $01;
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT = $02;
  SSL_VERIFY_CLIENT_ONCE = $04;
  SSL_VERIFY_POST_HANDSHAKE = $08;

  SSL_AD_REASON_OFFSET = 1000; (* offset to get SSL_R_... value
                                * from SSL_AD_... *)
  (* These alert types are for SSLv3 and TLSv1 *)
  SSL_AD_CLOSE_NOTIFY = SSL3_AD_CLOSE_NOTIFY;
  (* fatal *)
  SSL_AD_UNEXPECTED_MESSAGE = SSL3_AD_UNEXPECTED_MESSAGE;
  (* fatal *)
  SSL_AD_BAD_RECORD_MAC = SSL3_AD_BAD_RECORD_MAC;
  SSL_AD_DECRYPTION_FAILED = TLS1_AD_DECRYPTION_FAILED;
  SSL_AD_RECORD_OVERFLOW = TLS1_AD_RECORD_OVERFLOW;
  (* fatal *)
  SSL_AD_DECOMPRESSION_FAILURE = SSL3_AD_DECOMPRESSION_FAILURE;
  (* fatal *)
  SSL_AD_HANDSHAKE_FAILURE = SSL3_AD_HANDSHAKE_FAILURE;
  (* Not for TLS *)
  SSL_AD_NO_CERTIFICATE = SSL3_AD_NO_CERTIFICATE;
  SSL_AD_BAD_CERTIFICATE = SSL3_AD_BAD_CERTIFICATE;
  SSL_AD_UNSUPPORTED_CERTIFICATE = SSL3_AD_UNSUPPORTED_CERTIFICATE;
  SSL_AD_CERTIFICATE_REVOKED = SSL3_AD_CERTIFICATE_REVOKED;
  SSL_AD_CERTIFICATE_EXPIRED = SSL3_AD_CERTIFICATE_EXPIRED;
  SSL_AD_CERTIFICATE_UNKNOWN = SSL3_AD_CERTIFICATE_UNKNOWN;
  (* fatal *)
  SSL_AD_ILLEGAL_PARAMETER = SSL3_AD_ILLEGAL_PARAMETER;
  (* fatal *)
  SSL_AD_UNKNOWN_CA = TLS1_AD_UNKNOWN_CA;
  (* fatal *)
  SSL_AD_ACCESS_DENIED = TLS1_AD_ACCESS_DENIED;
  (* fatal *)
  SSL_AD_DECODE_ERROR = TLS1_AD_DECODE_ERROR;
  SSL_AD_DECRYPT_ERROR = TLS1_AD_DECRYPT_ERROR;
  (* fatal *)
  SSL_AD_EXPORT_RESTRICTION = TLS1_AD_EXPORT_RESTRICTION;
  (* fatal *)
  SSL_AD_PROTOCOL_VERSION = TLS1_AD_PROTOCOL_VERSION;
  (* fatal *)
  SSL_AD_INSUFFICIENT_SECURITY = TLS1_AD_INSUFFICIENT_SECURITY;
  (* fatal *)
  SSL_AD_INTERNAL_ERROR = TLS1_AD_INTERNAL_ERROR;
  SSL_AD_USER_CANCELLED = TLS1_AD_USER_CANCELLED;
  SSL_AD_NO_RENEGOTIATION = TLS1_AD_NO_RENEGOTIATION;
  SSL_AD_MISSING_EXTENSION = TLS13_AD_MISSING_EXTENSION;
  SSL_AD_CERTIFICATE_REQUIRED = TLS13_AD_CERTIFICATE_REQUIRED;
  SSL_AD_UNSUPPORTED_EXTENSION = TLS1_AD_UNSUPPORTED_EXTENSION;
  SSL_AD_CERTIFICATE_UNOBTAINABLE = TLS1_AD_CERTIFICATE_UNOBTAINABLE;
  SSL_AD_UNRECOGNIZED_NAME = TLS1_AD_UNRECOGNIZED_NAME;
  SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE = TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
  SSL_AD_BAD_CERTIFICATE_HASH_VALUE = TLS1_AD_BAD_CERTIFICATE_HASH_VALUE;
  (* fatal *)
  SSL_AD_UNKNOWN_PSK_IDENTITY = TLS1_AD_UNKNOWN_PSK_IDENTITY;
  (* fatal *)
  SSL_AD_INAPPROPRIATE_FALLBACK = TLS1_AD_INAPPROPRIATE_FALLBACK;
  SSL_AD_NO_APPLICATION_PROTOCOL = TLS1_AD_NO_APPLICATION_PROTOCOL;
  SSL_ERROR_NONE = 0;
  SSL_ERROR_SSL = 1;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_WANT_X509_LOOKUP = 4;
  SSL_ERROR_SYSCALL = 5; (* look at error stack/return
                          * value/errno *)
  SSL_ERROR_ZERO_RETURN = 6;
  SSL_ERROR_WANT_CONNECT = 7;
  SSL_ERROR_WANT_ACCEPT = 8;
  SSL_ERROR_WANT_ASYNC = 9;
  SSL_ERROR_WANT_ASYNC_JOB = 10;
  SSL_ERROR_WANT_CLIENT_HELLO_CB = 11;
  SSL_CTRL_SET_TMP_DH = 3;
  SSL_CTRL_SET_TMP_ECDH = 4;
  SSL_CTRL_SET_TMP_DH_CB = 6;
  SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9;
  SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10;
  SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11;
  SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12;
  SSL_CTRL_GET_FLAGS = 13;
  SSL_CTRL_EXTRA_CHAIN_CERT = 14;
  SSL_CTRL_SET_MSG_CALLBACK = 15;
  SSL_CTRL_SET_MSG_CALLBACK_ARG = 16;
  (* only applies to datagram connections *)
  SSL_CTRL_SET_MTU = 17;
  (* Stats *)
  SSL_CTRL_SESS_NUMBER = 20;
  SSL_CTRL_SESS_CONNECT = 21;
  SSL_CTRL_SESS_CONNECT_GOOD = 22;
  SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23;
  SSL_CTRL_SESS_ACCEPT = 24;
  SSL_CTRL_SESS_ACCEPT_GOOD = 25;
  SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26;
  SSL_CTRL_SESS_HIT = 27;
  SSL_CTRL_SESS_CB_HIT = 28;
  SSL_CTRL_SESS_MISSES = 29;
  SSL_CTRL_SESS_TIMEOUTS = 30;
  SSL_CTRL_SESS_CACHE_FULL = 31;
  SSL_CTRL_MODE = 33;
  SSL_CTRL_GET_READ_AHEAD = 40;
  SSL_CTRL_SET_READ_AHEAD = 41;
  SSL_CTRL_SET_SESS_CACHE_SIZE = 42;
  SSL_CTRL_GET_SESS_CACHE_SIZE = 43;
  SSL_CTRL_SET_SESS_CACHE_MODE = 44;
  SSL_CTRL_GET_SESS_CACHE_MODE = 45;
  SSL_CTRL_GET_MAX_CERT_LIST = 50;
  SSL_CTRL_SET_MAX_CERT_LIST = 51;
  SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52;
  (* see tls1.h for macros based on these *)
  SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;
  SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;
  SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
  SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56;
  SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57;
  SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58;
  SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70;
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71;
  SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB = 72;
  SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75;
  SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76;
  SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77;
  SSL_CTRL_SET_SRP_ARG = 78;
  SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79;
  SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80;
  SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81;
  SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT = 85;
  SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING = 86;
  SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS = 87;
  DTLS_CTRL_GET_TIMEOUT = 73;
  DTLS_CTRL_HANDLE_TIMEOUT = 74;
  SSL_CTRL_GET_RI_SUPPORT = 76;
  SSL_CTRL_CLEAR_MODE = 78;
  SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB = 79;
  SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82;
  SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83;
  SSL_CTRL_CHAIN = 88;
  SSL_CTRL_CHAIN_CERT = 89;
  SSL_CTRL_GET_GROUPS = 90;
  SSL_CTRL_SET_GROUPS = 91;
  SSL_CTRL_SET_GROUPS_LIST = 92;
  SSL_CTRL_GET_SHARED_GROUP = 93;
  SSL_CTRL_SET_SIGALGS = 97;
  SSL_CTRL_SET_SIGALGS_LIST = 98;
  SSL_CTRL_CERT_FLAGS = 99;
  SSL_CTRL_CLEAR_CERT_FLAGS = 100;
  SSL_CTRL_SET_CLIENT_SIGALGS = 101;
  SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102;
  SSL_CTRL_GET_CLIENT_CERT_TYPES = 103;
  SSL_CTRL_SET_CLIENT_CERT_TYPES = 104;
  SSL_CTRL_BUILD_CERT_CHAIN = 105;
  SSL_CTRL_SET_VERIFY_CERT_STORE = 106;
  SSL_CTRL_SET_CHAIN_CERT_STORE = 107;
  SSL_CTRL_GET_PEER_SIGNATURE_NID = 108;
  SSL_CTRL_GET_PEER_TMP_KEY = 109;
  SSL_CTRL_GET_RAW_CIPHERLIST = 110;
  SSL_CTRL_GET_EC_POINT_FORMATS = 111;
  SSL_CTRL_GET_CHAIN_CERTS = 115;
  SSL_CTRL_SELECT_CURRENT_CERT = 116;
  SSL_CTRL_SET_CURRENT_CERT = 117;
  SSL_CTRL_SET_DH_AUTO = 118;
  DTLS_CTRL_SET_LINK_MTU = 120;
  DTLS_CTRL_GET_LINK_MIN_MTU = 121;
  SSL_CTRL_GET_EXTMS_SUPPORT = 122;
  SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
  SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
  SSL_CTRL_SET_SPLIT_SEND_FRAGMENT = 125;
  SSL_CTRL_SET_MAX_PIPELINES = 126;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128;
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129;
  SSL_CTRL_GET_MIN_PROTO_VERSION = 130;
  SSL_CTRL_GET_MAX_PROTO_VERSION = 131;
  SSL_CTRL_GET_SIGNATURE_NID = 132;
  SSL_CTRL_GET_TMP_KEY = 133;
  SSL_CERT_SET_FIRST = 1;
  SSL_CERT_SET_NEXT = 2;
  SSL_CERT_SET_SERVER = 3;

  (*
   * The following symbol names are old and obsolete. They are kept
   * for compatibility reasons only and should not be used anymore.
   *)
  SSL_CTRL_GET_CURVES = SSL_CTRL_GET_GROUPS;
  SSL_CTRL_SET_CURVES = SSL_CTRL_SET_GROUPS;
  SSL_CTRL_SET_CURVES_LIST = SSL_CTRL_SET_GROUPS_LIST;
  SSL_CTRL_GET_SHARED_CURVE = SSL_CTRL_GET_SHARED_GROUP;
  
//  SSL_get1_curves = SSL_get1_groups;
//  SSL_CTX_set1_curves = SSL_CTX_set1_groups;
//  SSL_CTX_set1_curves_list = SSL_CTX_set1_groups_list;
//  SSL_set1_curves = SSL_set1_groups;
//  SSL_set1_curves_list = SSL_set1_groups_list;
//  SSL_get_shared_curve = SSL_get_shared_group;

  (* serverinfo file format versions *)
  SSL_SERVERINFOV1 = 1;
  SSL_SERVERINFOV2 = 2;

  SSL_CLIENT_HELLO_SUCCESS = 1;
  SSL_CLIENT_HELLO_ERROR = 0;
  SSL_CLIENT_HELLO_RETRY = -1;

  SSL_READ_EARLY_DATA_ERROR = 0;
  SSL_READ_EARLY_DATA_SUCCESS = 1;
  SSL_READ_EARLY_DATA_FINISH = 2;

  SSL_EARLY_DATA_NOT_SENT = 0;
  SSL_EARLY_DATA_REJECTED = 1;
  SSL_EARLY_DATA_ACCEPTED = 2;

  //SSLv23_method = TLS_method;
  //SSLv23_server_method = TLS_server_method;
  //SSLv23_client_method = TLS_client_method;

  (* What the 'other' parameter contains in_ security callback *)
  (* Mask for type *)
  SSL_SECOP_OTHER_TYPE = $ffff0000;
  SSL_SECOP_OTHER_NONE = 0;
  SSL_SECOP_OTHER_CIPHER = (1 shl 16);
  SSL_SECOP_OTHER_CURVE = (2 shl 16);
  SSL_SECOP_OTHER_DH = (3 shl 16);
  SSL_SECOP_OTHER_PKEY = (4 shl 16);
  SSL_SECOP_OTHER_SIGALG = (5 shl 16);
  SSL_SECOP_OTHER_CERT = (6 shl 16);

  (* Indicated operation refers to peer key or certificate *)
  SSL_SECOP_PEER = $1000;

  (* Values for "op" parameter in security callback *)

  (* Called to filter ciphers *)
  (* Ciphers client supports *)
  SSL_SECOP_CIPHER_SUPPORTED = 1 or SSL_SECOP_OTHER_CIPHER;
  (* Cipher shared by client/server *)
  SSL_SECOP_CIPHER_SHARED = 2 or SSL_SECOP_OTHER_CIPHER;
  (* Sanity check of cipher server selects *)
  SSL_SECOP_CIPHER_CHECK = 3 or SSL_SECOP_OTHER_CIPHER;
  (* Curves supported by client *)
  SSL_SECOP_CURVE_SUPPORTED = 4 or SSL_SECOP_OTHER_CURVE;
  (* Curves shared by client/server *)
  SSL_SECOP_CURVE_SHARED = 5 or SSL_SECOP_OTHER_CURVE;
  (* Sanity check of curve server selects *)
  SSL_SECOP_CURVE_CHECK = 6 or SSL_SECOP_OTHER_CURVE;
  (* Temporary DH key *)
  SSL_SECOP_TMP_DH = 7 or SSL_SECOP_OTHER_PKEY;
  (* SSL/TLS version *)
  SSL_SECOP_VERSION = 9 or SSL_SECOP_OTHER_NONE;
  (* Session tickets *)
  SSL_SECOP_TICKET = 10 or SSL_SECOP_OTHER_NONE;
  (* Supported signature algorithms sent to peer *)
  SSL_SECOP_SIGALG_SUPPORTED = 11 or SSL_SECOP_OTHER_SIGALG;
  (* Shared signature algorithm *)
  SSL_SECOP_SIGALG_SHARED = 12 or SSL_SECOP_OTHER_SIGALG;
  (* Sanity check signature algorithm allowed *)
  SSL_SECOP_SIGALG_CHECK = 13 or SSL_SECOP_OTHER_SIGALG;
  (* Used to get mask of supported public key signature algorithms *)
  SSL_SECOP_SIGALG_MASK = 14 or SSL_SECOP_OTHER_SIGALG;
  (* Use to see if compression is allowed *)
  SSL_SECOP_COMPRESSION = 15 or SSL_SECOP_OTHER_NONE;
  (* EE key in certificate *)
  SSL_SECOP_EE_KEY = 16 or SSL_SECOP_OTHER_CERT;
  (* CA key in certificate *)
  SSL_SECOP_CA_KEY = 17 or SSL_SECOP_OTHER_CERT;
  (* CA digest algorithm in certificate *)
  SSL_SECOP_CA_MD = 18 or SSL_SECOP_OTHER_CERT;
  (* Peer EE key in certificate *)
  SSL_SECOP_PEER_EE_KEY = SSL_SECOP_EE_KEY or SSL_SECOP_PEER;
  (* Peer CA key in certificate *)
  SSL_SECOP_PEER_CA_KEY = SSL_SECOP_CA_KEY or SSL_SECOP_PEER;
  (* Peer CA digest algorithm in certificate *)
  SSL_SECOP_PEER_CA_MD = SSL_SECOP_CA_MD or SSL_SECOP_PEER;

  (* OPENSSL_INIT flag 0x010000 reserved for internal use *)
  OPENSSL_INIT_NO_LOAD_SSL_STRINGS = TOpenSSL_C_LONG($00100000);
  OPENSSL_INIT_LOAD_SSL_STRINGS = TOpenSSL_C_LONG($00200000);
  OPENSSL_INIT_SSL_DEFAULT = OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS;

  (* Support for ticket appdata *)
  (* fatal error, malloc failure *)
  SSL_TICKET_FATAL_ERR_MALLOC = 0;
  (* fatal error, either from parsing or decrypting the ticket *)
  SSL_TICKET_FATAL_ERR_OTHER = 1;
  (* No ticket present *)
  SSL_TICKET_NONE = 2;
  (* Empty ticket present *)
  SSL_TICKET_EMPTY = 3;
  (* the ticket couldn't be decrypted *)
  SSL_TICKET_NO_DECRYPT = 4;
  (* a ticket was successfully decrypted *)
  SSL_TICKET_SUCCESS = 5;
  (* same as above but the ticket needs to be renewed *)
  SSL_TICKET_SUCCESS_RENEW = 6;

  (* An error occurred *)
  SSL_TICKET_RETURN_ABORT = 0;
  (* Do not use the ticket, do not send a renewed ticket to the client *)
  SSL_TICKET_RETURN_IGNORE = 1;
  (* Do not use the ticket, send a renewed ticket to the client *)
  SSL_TICKET_RETURN_IGNORE_RENEW = 2;
  (* Use the ticket, do not send a renewed ticket to the client *)
  SSL_TICKET_RETURN_USE = 3;
  (* Use the ticket, send a renewed ticket to the client *)
  SSL_TICKET_RETURN_USE_RENEW = 4;

type
  (*
   * This is needed to stop compilers complaining about the 'struct ssl_st *'
   * function parameters used to prototype callbacks in SSL_CTX.
   *)
  ssl_crock_st = ^ssl_st;
  TLS_SESSION_TICKET_EXT = tls_session_ticket_ext_st;
  ssl_method_st = type Pointer;
  SSL_METHOD = ssl_method_st;
  PSSL_METHOD = ^SSL_METHOD;
  ssl_session_st = type Pointer;
  SSL_CIPHER = ssl_session_st;
  PSSL_CIPHER = ^SSL_CIPHER;
  SSL_SESSION = ssl_session_st;
  PSSL_SESSION = ^SSL_SESSION;
  PPSSL_SESSION = ^PSSL_SESSION;
  tls_sigalgs_st = type Pointer;
  TLS_SIGALGS = tls_sigalgs_st;
  ssl_conf_ctx_st = type Pointer;
  SSL_CONF_CTX = ssl_conf_ctx_st;
  PSSL_CONF_CTX = ^SSL_CONF_CTX;
  ssl_comp_st = type Pointer;
  SSL_COMP = ssl_comp_st;


  //STACK_OF(SSL_CIPHER);
  //STACK_OF(SSL_COMP);

  (* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*)
  srtp_protection_profile_st = record
    name: PAnsiChar;
    id: TOpenSSL_C_ULONG;
  end;
  SRTP_PROTECTION_PROFILE = srtp_protection_profile_st;
  PSRTP_PROTECTION_PROFILE = ^SRTP_PROTECTION_PROFILE;

  //DEFINE_STACK_OF(SRTP_PROTECTION_PROFILE)

  (* Typedefs for handling custom extensions *)
  custom_ext_add_cb = function (s: PSSL; ext_type: TOpenSSL_C_UINT; const out_: PByte; outlen: POpenSSL_C_SIZET; al: POpenSSL_C_INT; add_arg: Pointer): TOpenSSL_C_INT; cdecl;
  custom_ext_free_cb = procedure (s: PSSL; ext_type: TOpenSSL_C_UINT; const out_: PByte; add_arg: Pointer); cdecl;
  custom_ext_parse_cb = function (s: PSSL; ext_type: TOpenSSL_C_UINT; const in_: PByte; inlen: TOpenSSL_C_SIZET; al: POpenSSL_C_INT; parse_arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_custom_ext_add_cb_ex = function (s: PSSL; ext_type: TOpenSSL_C_UINT; context: TOpenSSL_C_UINT; const out_: PByte; outlen: POpenSSL_C_SIZET; x: Px509; chainidx: TOpenSSL_C_SIZET; al: POpenSSL_C_INT; add_arg: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_custom_ext_free_cb_ex = procedure (s: PSSL; ext_type: TOpenSSL_C_UINT; context: TOpenSSL_C_UINT; const out_: PByte; add_arg: Pointer); cdecl;
  SSL_custom_ext_parse_cb_ex = function (s: PSSL; ext_type: TOpenSSL_C_UINT; context: TOpenSSL_C_UINT; const in_: PByte; inlen: TOpenSSL_C_SIZET; x: Px509; chainidx: TOpenSSL_C_SIZET; al: POpenSSL_C_INT; parse_arg: Pointer): TOpenSSL_C_INT; cdecl;

  (* Typedef for verification callback *)
  SSL_verify_cb = function (preverify_ok: TOpenSSL_C_INT; x509_ctx: PX509_STORE_CTX): TOpenSSL_C_INT; cdecl;

  tls_session_ticket_ext_cb_fn = function (s: PSSL; const data: PByte; len: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;

  (*
   * This callback type is used inside SSL_CTX, SSL, and in_ the functions that
   * set them. It is used to override the generation of SSL/TLS session IDs in_
   * a server. Return value should be zero on an error, non-zero to proceed.
   * Also, callbacks should themselves check if the id they generate is unique
   * otherwise the SSL handshake will fail with an error - callbacks can do
   * this using the 'ssl' value they're passed by;
   * SSL_has_matching_session_id(ssl, id, *id_len) The length value passed in_
   * is set at the maximum size the session ID can be. in_ SSLv3/TLSv1 it is 32
   * bytes. The callback can alter this length to be less if desired. It is
   * also an error for the callback to set the size to zero.
   *)
  GEN_SESSION_CB = function (ssl: PSSL; id: PByte; id_len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

  SSL_CTX_info_callback = procedure (const ssl: PSSL; type_: TOpenSSL_C_INT; val: TOpenSSL_C_INT); cdecl;
  SSL_CTX_client_cert_cb = function (ssl: PSSL; x509: PPx509; pkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;

  SSL_CTX_cookie_verify_cb = function (ssl: PSSL; cookie: PByte; cookie_len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb = function (ssl: PSSL; const cookie: PByte; cookie_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb = function (ssl: PSSL; cookie: PByte; cookie_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb = function (ssl: PSSL; const cookie: PByte; cookie_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

  SSL_CTX_alpn_select_cb_func = function (ssl: PSSL; const out_: PPByte; outlen: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT; arg: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_psk_client_cb_func = function (ssl: PSSL; const hint: PAnsiChar; identity: PAnsiChar; max_identity_len: TOpenSSL_C_UINT; psk: PByte; max_psk_len: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  SSL_psk_server_cb_func = function (ssl: PSSL; const identity: PAnsiChar; psk: PByte; max_psk_len: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  SSL_psk_find_session_cb_func = function (ssl: PSSL; const identity: PByte; identity_len: TOpenSSL_C_SIZET; sess: PPSSL_SESSION): TOpenSSL_C_INT; cdecl;
  SSL_psk_use_session_cb_func = function (ssl: PSSL; const md: PEVP_MD; const id: PPByte; idlen: POpenSSL_C_SIZET; sess: PPSSL_SESSION): TOpenSSL_C_INT; cdecl;

  (*
   * A callback for logging out TLS key material. This callback should log out
   * |line| followed by a newline.
   *)
  SSL_CTX_keylog_cb_func = procedure(const ssl: PSSL; const line: PAnsiChar); cdecl;

  (*
   * The valid handshake states (one for each type message sent and one for each
   * type of message received). There are also two "special" states:
   * TLS = TLS or DTLS state
   * DTLS = DTLS specific state
   * CR/SR = Client Read/Server Read
   * CW/SW = Client Write/Server Write
   *
   * The "special" states are:
   * TLS_ST_BEFORE = No handshake has been initiated yet
   * TLS_ST_OK = A handshake has been successfully completed
   *)
  TLS_ST_OK = (
    DTLS_ST_CR_HELLO_VERIFY_REQUEST,
    TLS_ST_CR_SRVR_HELLO,
    TLS_ST_CR_CERT,
    TLS_ST_CR_CERT_STATUS,
    TLS_ST_CR_KEY_EXCH,
    TLS_ST_CR_CERT_REQ,
    TLS_ST_CR_SRVR_DONE,
    TLS_ST_CR_SESSION_TICKET,
    TLS_ST_CR_CHANGE,
    TLS_ST_CR_FINISHED,
    TLS_ST_CW_CLNT_HELLO,
    TLS_ST_CW_CERT,
    TLS_ST_CW_KEY_EXCH,
    TLS_ST_CW_CERT_VRFY,
    TLS_ST_CW_CHANGE,
    TLS_ST_CW_NEXT_PROTO,
    TLS_ST_CW_FINISHED,
    TLS_ST_SW_HELLO_REQ,
    TLS_ST_SR_CLNT_HELLO,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST,
    TLS_ST_SW_SRVR_HELLO,
    TLS_ST_SW_CERT,
    TLS_ST_SW_KEY_EXCH,
    TLS_ST_SW_CERT_REQ,
    TLS_ST_SW_SRVR_DONE,
    TLS_ST_SR_CERT,
    TLS_ST_SR_KEY_EXCH,
    TLS_ST_SR_CERT_VRFY,
    TLS_ST_SR_NEXT_PROTO,
    TLS_ST_SR_CHANGE,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SESSION_TICKET,
    TLS_ST_SW_CERT_STATUS,
    TLS_ST_SW_CHANGE,
    TLS_ST_SW_FINISHED,
    TLS_ST_SW_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_CERT_VRFY,
    TLS_ST_SW_CERT_VRFY,
    TLS_ST_CR_HELLO_REQ,
    TLS_ST_SW_KEY_UPDATE,
    TLS_ST_CW_KEY_UPDATE,
    TLS_ST_SR_KEY_UPDATE,
    TLS_ST_CR_KEY_UPDATE,
    TLS_ST_EARLY_DATA,
    TLS_ST_PENDING_EARLY_DATA_END,
    TLS_ST_CW_END_OF_EARLY_DATA
  );
  OSSL_HANDSHAKE_STATE = TLS_ST_OK;

  SSL_CTX_set_cert_verify_callback_cb = function (v1: PX509_STORE_CTX; v2: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_cert_cb_cb = function (ssl: PSSL; arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_CTX_set_srp_client_pwd_callback_cb = function (v1: PSSL; v2: Pointer): PAnsiChar; cdecl;
  SSL_CTX_set_srp_verify_param_callback_cb = function (v1: PSSL; v2: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_srp_username_callback_cb = function (v1: PSSL; v2: POpenSSL_C_INT; v3: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_client_hello_cb_fn = function (s: PSSL; al: POpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
  SSL_callback_ctrl_v3 = procedure; cdecl;
  SSL_CTX_callback_ctrl_v3 = procedure; cdecl;
  SSL_info_callback = procedure (const ssl: PSSL; type_: TOpenSSL_C_INT; val: TOpenSSL_C_INT); cdecl;

  (* NB: the |keylength| is only applicable when is_export is true *)
  SSL_CTX_set_tmp_dh_callback_dh = function (ssl: PSSL; is_export: TOpenSSL_C_INT; keylength: TOpenSSL_C_INT): PDH; cdecl;
  SSL_set_tmp_dh_callback_dh = function (ssl: PSSL; is_export: TOpenSSL_C_INT; keylength: TOpenSSL_C_INT): PDH; cdecl;
  SSL_CTX_set_not_resumable_session_callback_cb = function (ssl: PSSL; is_forward_secure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  SSL_set_not_resumable_session_callback_cb = function (ssl: PSSL; is_forward_secure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  SSL_CTX_set_record_padding_callback_cb = function (ssl: PSSL; type_: TOpenSSL_C_INT; len: TOpenSSL_C_SIZET; arg: Pointer): TOpenSSL_C_SIZET; cdecl;
  SSL_set_record_padding_callback_cb = function (ssl: PSSL; type_: TOpenSSL_C_INT; len: TOpenSSL_C_SIZET; arg: Pointer): TOpenSSL_C_SIZET; cdecl;
  
  (*
   * The validation type enumerates the available behaviours of the built-in SSL
   * CT validation callback selected via SSL_enable_ct() and SSL_CTX_enable_ct().
   * The underlying callback is a static function in libssl.
   *)
  SSL_CT_VALIDATION = (         
    SSL_CT_VALIDATION_PERMISSIVE = 0,
    SSL_CT_VALIDATION_STRICT
  );
  SSL_security_callback = function (const s: PSSL; const ctx: PSSL_CTX; op: TOpenSSL_C_INT; bits: TOpenSSL_C_INT; nid: TOpenSSL_C_INT; other: Pointer; ex: Pointer): TOpenSSL_C_INT; cdecl;

  (* Status codes passed to the decrypt session ticket callback. Some of these
   * are for internal use only and are never passed to the callback. *)
  SSL_TICKET_STATUS = TOpenSSL_C_INT;
  SSL_TICKET_RETURN = TOpenSSL_C_INT;

  SSL_CTX_generate_session_ticket_fn = function(s: PSSL; arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_CTX_decrypt_session_ticket_fn = function (s: PSSL; ss: PSSL_SESSION; const keyname: PByte; keyname_length: TOpenSSL_C_SIZET; status: SSL_TICKET_STATUS; arg: Pointer): SSL_TICKET_RETURN; cdecl;

  DTLS_timer_cb = function(s: PSSL; timer_us: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  SSL_allow_early_data_cb_fn = function(s: PSSL; arg: Pointer): TOpenSSL_C_INT; cdecl;

  SSL_CTX_sess_new_cb = function (ssl: PSSL; sess: PSSL_SESSION): TOpenSSL_C_INT; cdecl;

  SSL_CTX_sess_remove_cb = procedure(ctx: PSSL_CTX; sess: PSSL_SESSION); cdecl;

  TSSL_CTX_set_verify_callback = function (ok : TOpenSSL_C_INT; ctx : PX509_STORE_CTX) : TOpenSSL_C_INT; cdecl;



type
  TOpenSSL_Version = (sslUnknown,sslvSSLv2, sslvSSLv23, sslvSSLv3, sslvTLSv1,sslvTLSv1_1,
                      sslvTLSv1_2, sslvTLSv1_3);

  procedure OpenSSL_SetMethod(aMethod: TOpenSSL_Version); {used for pre 1.1.0 OpenSSL}

  function IsOpenSSL_SSLv2_Available : Boolean;
  function IsOpenSSL_SSLv3_Available : Boolean;
  function IsOpenSSL_SSLv23_Available : Boolean;
  function IsOpenSSL_TLSv1_0_Available : Boolean;
  function IsOpenSSL_TLSv1_1_Available : Boolean;
  function IsOpenSSL_TLSv1_2_Available : Boolean;
  function HasTLS_method: boolean;
  function SSL_CTX_set_min_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_CTX_set_max_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_CTX_get_min_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
  function SSL_CTX_get_max_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
  function SSL_set_min_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_set_max_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  function SSL_get_min_proto_version(s: PSSL): TOpenSSL_C_LONG;
  function SSL_get_max_proto_version(s: PSSL): TOpenSSL_C_LONG;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM SSL_CTX_get_options}
{$EXTERNALSYM SSL_get_options}
{$EXTERNALSYM SSL_CTX_clear_options}
{$EXTERNALSYM SSL_clear_options}
{$EXTERNALSYM SSL_CTX_set_options}
{$EXTERNALSYM SSL_set_options}
{$EXTERNALSYM SSL_CTX_sess_set_new_cb}
{$EXTERNALSYM SSL_CTX_sess_get_new_cb}
{$EXTERNALSYM SSL_CTX_sess_set_remove_cb}
{$EXTERNALSYM SSL_CTX_sess_get_remove_cb}
{$EXTERNALSYM SSL_CTX_set_info_callback}
{$EXTERNALSYM SSL_CTX_get_info_callback}
{$EXTERNALSYM SSL_CTX_set_client_cert_cb}
{$EXTERNALSYM SSL_CTX_get_client_cert_cb}
{$EXTERNALSYM SSL_CTX_set_client_cert_engine}
{$EXTERNALSYM SSL_CTX_set_cookie_generate_cb}
{$EXTERNALSYM SSL_CTX_set_cookie_verify_cb}
{$EXTERNALSYM SSL_CTX_set_stateless_cookie_generate_cb}
{$EXTERNALSYM SSL_CTX_set_stateless_cookie_verify_cb}
{$EXTERNALSYM SSL_CTX_set_alpn_select_cb}
{$EXTERNALSYM SSL_get0_alpn_selected}
{$EXTERNALSYM SSL_CTX_set_psk_client_callback}
{$EXTERNALSYM SSL_set_psk_client_callback}
{$EXTERNALSYM SSL_CTX_set_psk_server_callback}
{$EXTERNALSYM SSL_set_psk_server_callback}
{$EXTERNALSYM SSL_set_psk_find_session_callback}
{$EXTERNALSYM SSL_CTX_set_psk_find_session_callback}
{$EXTERNALSYM SSL_set_psk_use_session_callback}
{$EXTERNALSYM SSL_CTX_set_psk_use_session_callback}
{$EXTERNALSYM SSL_CTX_set_keylog_callback}
{$EXTERNALSYM SSL_CTX_get_keylog_callback}
{$EXTERNALSYM SSL_CTX_set_max_early_data}
{$EXTERNALSYM SSL_CTX_get_max_early_data}
{$EXTERNALSYM SSL_set_max_early_data}
{$EXTERNALSYM SSL_get_max_early_data}
{$EXTERNALSYM SSL_CTX_set_recv_max_early_data}
{$EXTERNALSYM SSL_CTX_get_recv_max_early_data}
{$EXTERNALSYM SSL_set_recv_max_early_data}
{$EXTERNALSYM SSL_get_recv_max_early_data}
{$EXTERNALSYM SSL_in_init}
{$EXTERNALSYM SSL_in_before}
{$EXTERNALSYM SSL_is_init_finished}
{$EXTERNALSYM SSL_get_finished}
{$EXTERNALSYM SSL_get_peer_finished}
{$EXTERNALSYM BIO_f_ssl}
{$EXTERNALSYM BIO_new_ssl}
{$EXTERNALSYM BIO_new_ssl_connect}
{$EXTERNALSYM BIO_new_buffer_ssl_connect}
{$EXTERNALSYM BIO_ssl_copy_session_id}
{$EXTERNALSYM SSL_CTX_set_cipher_list}
{$EXTERNALSYM SSL_CTX_new}
{$EXTERNALSYM SSL_CTX_set_timeout}
{$EXTERNALSYM SSL_CTX_get_timeout}
{$EXTERNALSYM SSL_CTX_get_cert_store}
{$EXTERNALSYM SSL_want}
{$EXTERNALSYM SSL_clear}
{$EXTERNALSYM BIO_ssl_shutdown}
{$EXTERNALSYM SSL_CTX_up_ref}
{$EXTERNALSYM SSL_CTX_free}
{$EXTERNALSYM SSL_CTX_set_cert_store}
{$EXTERNALSYM SSL_CTX_set1_cert_store}
{$EXTERNALSYM SSL_CTX_flush_sessions}
{$EXTERNALSYM SSL_get_current_cipher}
{$EXTERNALSYM SSL_get_pending_cipher}
{$EXTERNALSYM SSL_CIPHER_get_bits}
{$EXTERNALSYM SSL_CIPHER_get_version}
{$EXTERNALSYM SSL_CIPHER_get_name}
{$EXTERNALSYM SSL_CIPHER_standard_name}
{$EXTERNALSYM OPENSSL_cipher_name}
{$EXTERNALSYM SSL_CIPHER_get_id}
{$EXTERNALSYM SSL_CIPHER_get_protocol_id}
{$EXTERNALSYM SSL_CIPHER_get_kx_nid}
{$EXTERNALSYM SSL_CIPHER_get_auth_nid}
{$EXTERNALSYM SSL_CIPHER_get_handshake_digest}
{$EXTERNALSYM SSL_CIPHER_is_aead}
{$EXTERNALSYM SSL_get_fd}
{$EXTERNALSYM SSL_get_rfd}
{$EXTERNALSYM SSL_get_wfd}
{$EXTERNALSYM SSL_get_cipher_list}
{$EXTERNALSYM SSL_get_shared_ciphers}
{$EXTERNALSYM SSL_get_read_ahead}
{$EXTERNALSYM SSL_pending}
{$EXTERNALSYM SSL_has_pending}
{$EXTERNALSYM SSL_set_fd}
{$EXTERNALSYM SSL_set_rfd}
{$EXTERNALSYM SSL_set_wfd}
{$EXTERNALSYM SSL_set0_rbio}
{$EXTERNALSYM SSL_set0_wbio}
{$EXTERNALSYM SSL_set_bio}
{$EXTERNALSYM SSL_get_rbio}
{$EXTERNALSYM SSL_get_wbio}
{$EXTERNALSYM SSL_set_cipher_list}
{$EXTERNALSYM SSL_CTX_set_ciphersuites}
{$EXTERNALSYM SSL_set_ciphersuites}
{$EXTERNALSYM SSL_get_verify_mode}
{$EXTERNALSYM SSL_get_verify_depth}
{$EXTERNALSYM SSL_get_verify_callback}
{$EXTERNALSYM SSL_set_read_ahead}
{$EXTERNALSYM SSL_set_verify}
{$EXTERNALSYM SSL_set_verify_depth}
{$EXTERNALSYM SSL_use_RSAPrivateKey}
{$EXTERNALSYM SSL_use_RSAPrivateKey_ASN1}
{$EXTERNALSYM SSL_use_PrivateKey}
{$EXTERNALSYM SSL_use_PrivateKey_ASN1}
{$EXTERNALSYM SSL_use_certificate}
{$EXTERNALSYM SSL_use_certificate_ASN1}
{$EXTERNALSYM SSL_CTX_use_serverinfo}
{$EXTERNALSYM SSL_CTX_use_serverinfo_ex}
{$EXTERNALSYM SSL_CTX_use_serverinfo_file}
{$EXTERNALSYM SSL_use_RSAPrivateKey_file}
{$EXTERNALSYM SSL_use_PrivateKey_file}
{$EXTERNALSYM SSL_use_certificate_file}
{$EXTERNALSYM SSL_CTX_use_RSAPrivateKey_file}
{$EXTERNALSYM SSL_CTX_use_PrivateKey_file}
{$EXTERNALSYM SSL_CTX_use_certificate_file}
{$EXTERNALSYM SSL_CTX_use_certificate_chain_file}
{$EXTERNALSYM SSL_use_certificate_chain_file}
{$EXTERNALSYM SSL_load_client_CA_file}
{$EXTERNALSYM SSL_add_file_cert_subjects_to_stack}
{$EXTERNALSYM SSL_add_dir_cert_subjects_to_stack}
{$EXTERNALSYM SSL_state_string}
{$EXTERNALSYM SSL_rstate_string}
{$EXTERNALSYM SSL_state_string_long}
{$EXTERNALSYM SSL_rstate_string_long}
{$EXTERNALSYM SSL_SESSION_get_time}
{$EXTERNALSYM SSL_SESSION_set_time}
{$EXTERNALSYM SSL_SESSION_get_timeout}
{$EXTERNALSYM SSL_SESSION_set_timeout}
{$EXTERNALSYM SSL_SESSION_get_protocol_version}
{$EXTERNALSYM SSL_SESSION_set_protocol_version}
{$EXTERNALSYM SSL_SESSION_get0_hostname}
{$EXTERNALSYM SSL_SESSION_set1_hostname}
{$EXTERNALSYM SSL_SESSION_get0_alpn_selected}
{$EXTERNALSYM SSL_SESSION_set1_alpn_selected}
{$EXTERNALSYM SSL_SESSION_get0_cipher}
{$EXTERNALSYM SSL_SESSION_set_cipher}
{$EXTERNALSYM SSL_SESSION_has_ticket}
{$EXTERNALSYM SSL_SESSION_get_ticket_lifetime_hint}
{$EXTERNALSYM SSL_SESSION_get0_ticket}
{$EXTERNALSYM SSL_SESSION_get_max_early_data}
{$EXTERNALSYM SSL_SESSION_set_max_early_data}
{$EXTERNALSYM SSL_copy_session_id}
{$EXTERNALSYM SSL_SESSION_get0_peer}
{$EXTERNALSYM SSL_SESSION_set1_id_context}
{$EXTERNALSYM SSL_SESSION_set1_id}
{$EXTERNALSYM SSL_SESSION_is_resumable}
{$EXTERNALSYM SSL_SESSION_new}
{$EXTERNALSYM SSL_SESSION_dup}
{$EXTERNALSYM SSL_SESSION_get_id}
{$EXTERNALSYM SSL_SESSION_get0_id_context}
{$EXTERNALSYM SSL_SESSION_get_compress_id}
{$EXTERNALSYM SSL_SESSION_print}
{$EXTERNALSYM SSL_SESSION_print_keylog}
{$EXTERNALSYM SSL_SESSION_up_ref}
{$EXTERNALSYM SSL_SESSION_free}
{$EXTERNALSYM SSL_set_session}
{$EXTERNALSYM SSL_CTX_add_session}
{$EXTERNALSYM SSL_CTX_remove_session}
{$EXTERNALSYM SSL_CTX_set_generate_session_id}
{$EXTERNALSYM SSL_set_generate_session_id}
{$EXTERNALSYM SSL_has_matching_session_id}
{$EXTERNALSYM d2i_SSL_SESSION}
{$EXTERNALSYM SSL_CTX_get_verify_mode}
{$EXTERNALSYM SSL_CTX_get_verify_depth}
{$EXTERNALSYM SSL_CTX_get_verify_callback}
{$EXTERNALSYM SSL_CTX_set_verify}
{$EXTERNALSYM SSL_CTX_set_verify_depth}
{$EXTERNALSYM SSL_CTX_set_cert_verify_callback}
{$EXTERNALSYM SSL_CTX_set_cert_cb}
{$EXTERNALSYM SSL_CTX_use_RSAPrivateKey}
{$EXTERNALSYM SSL_CTX_use_RSAPrivateKey_ASN1}
{$EXTERNALSYM SSL_CTX_use_PrivateKey}
{$EXTERNALSYM SSL_CTX_use_PrivateKey_ASN1}
{$EXTERNALSYM SSL_CTX_use_certificate}
{$EXTERNALSYM SSL_CTX_use_certificate_ASN1}
{$EXTERNALSYM SSL_CTX_set_default_passwd_cb}
{$EXTERNALSYM SSL_CTX_set_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_CTX_get_default_passwd_cb}
{$EXTERNALSYM SSL_CTX_get_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_set_default_passwd_cb}
{$EXTERNALSYM SSL_set_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_get_default_passwd_cb}
{$EXTERNALSYM SSL_get_default_passwd_cb_userdata}
{$EXTERNALSYM SSL_CTX_check_private_key}
{$EXTERNALSYM SSL_check_private_key}
{$EXTERNALSYM SSL_CTX_set_session_id_context}
{$EXTERNALSYM SSL_new}
{$EXTERNALSYM SSL_up_ref}
{$EXTERNALSYM SSL_is_dtls}
{$EXTERNALSYM SSL_set_session_id_context}
{$EXTERNALSYM SSL_CTX_set_purpose}
{$EXTERNALSYM SSL_set_purpose}
{$EXTERNALSYM SSL_CTX_set_trust}
{$EXTERNALSYM SSL_set_trust}
{$EXTERNALSYM SSL_set1_host}
{$EXTERNALSYM SSL_add1_host}
{$EXTERNALSYM SSL_get0_peername}
{$EXTERNALSYM SSL_set_hostflags}
{$EXTERNALSYM SSL_CTX_dane_enable}
{$EXTERNALSYM SSL_CTX_dane_mtype_set}
{$EXTERNALSYM SSL_dane_enable}
{$EXTERNALSYM SSL_dane_tlsa_add}
{$EXTERNALSYM SSL_get0_dane_authority}
{$EXTERNALSYM SSL_get0_dane_tlsa}
{$EXTERNALSYM SSL_get0_dane}
{$EXTERNALSYM SSL_CTX_dane_set_flags}
{$EXTERNALSYM SSL_CTX_dane_clear_flags}
{$EXTERNALSYM SSL_dane_set_flags}
{$EXTERNALSYM SSL_dane_clear_flags}
{$EXTERNALSYM SSL_CTX_set1_param}
{$EXTERNALSYM SSL_set1_param}
{$EXTERNALSYM SSL_CTX_get0_param}
{$EXTERNALSYM SSL_get0_param}
{$EXTERNALSYM SSL_CTX_set_srp_username}
{$EXTERNALSYM SSL_CTX_set_srp_password}
{$EXTERNALSYM SSL_CTX_set_srp_strength}
{$EXTERNALSYM SSL_CTX_set_srp_client_pwd_callback}
{$EXTERNALSYM SSL_CTX_set_srp_verify_param_callback}
{$EXTERNALSYM SSL_CTX_set_srp_username_callback}
{$EXTERNALSYM SSL_CTX_set_srp_cb_arg}
{$EXTERNALSYM SSL_set_srp_server_param}
{$EXTERNALSYM SSL_set_srp_server_param_pw}
{$EXTERNALSYM SSL_CTX_set_client_hello_cb}
{$EXTERNALSYM SSL_client_hello_isv2}
{$EXTERNALSYM SSL_client_hello_get0_legacy_version}
{$EXTERNALSYM SSL_client_hello_get0_random}
{$EXTERNALSYM SSL_client_hello_get0_session_id}
{$EXTERNALSYM SSL_client_hello_get0_ciphers}
{$EXTERNALSYM SSL_client_hello_get0_compression_methods}
{$EXTERNALSYM SSL_client_hello_get1_extensions_present}
{$EXTERNALSYM SSL_client_hello_get0_ext}
{$EXTERNALSYM SSL_certs_clear}
{$EXTERNALSYM SSL_free}
{$EXTERNALSYM SSL_waiting_for_async}
{$EXTERNALSYM SSL_get_all_async_fds}
{$EXTERNALSYM SSL_get_changed_async_fds}
{$EXTERNALSYM SSL_accept}
{$EXTERNALSYM SSL_stateless}
{$EXTERNALSYM SSL_connect}
{$EXTERNALSYM SSL_read}
{$EXTERNALSYM SSL_read_ex}
{$EXTERNALSYM SSL_read_early_data}
{$EXTERNALSYM SSL_peek}
{$EXTERNALSYM SSL_peek_ex}
{$EXTERNALSYM SSL_write}
{$EXTERNALSYM SSL_write_ex}
{$EXTERNALSYM SSL_write_early_data}
{$EXTERNALSYM SSL_callback_ctrl}
{$EXTERNALSYM SSL_ctrl}
{$EXTERNALSYM SSL_CTX_ctrl}
{$EXTERNALSYM SSL_CTX_callback_ctrl}
{$EXTERNALSYM SSL_get_early_data_status}
{$EXTERNALSYM SSL_get_error}
{$EXTERNALSYM SSL_get_version}
{$EXTERNALSYM SSL_CTX_set_ssl_version}
{$EXTERNALSYM TLS_method}
{$EXTERNALSYM TLS_server_method}
{$EXTERNALSYM TLS_client_method}
{$EXTERNALSYM SSL_do_handshake}
{$EXTERNALSYM SSL_key_update}
{$EXTERNALSYM SSL_get_key_update_type}
{$EXTERNALSYM SSL_renegotiate}
{$EXTERNALSYM SSL_renegotiate_abbreviated}
{$EXTERNALSYM SSL_new_session_ticket}
{$EXTERNALSYM SSL_shutdown}
{$EXTERNALSYM SSL_CTX_set_post_handshake_auth}
{$EXTERNALSYM SSL_set_post_handshake_auth}
{$EXTERNALSYM SSL_renegotiate_pending}
{$EXTERNALSYM SSL_verify_client_post_handshake}
{$EXTERNALSYM SSL_CTX_get_ssl_method}
{$EXTERNALSYM SSL_get_ssl_method}
{$EXTERNALSYM SSL_set_ssl_method}
{$EXTERNALSYM SSL_alert_type_string_long}
{$EXTERNALSYM SSL_alert_type_string}
{$EXTERNALSYM SSL_alert_desc_string_long}
{$EXTERNALSYM SSL_alert_desc_string}
{$EXTERNALSYM SSL_CTX_set_client_CA_list}
{$EXTERNALSYM SSL_add_client_CA}
{$EXTERNALSYM SSL_CTX_add_client_CA}
{$EXTERNALSYM SSL_set_connect_state}
{$EXTERNALSYM SSL_set_accept_state}
{$EXTERNALSYM SSL_CIPHER_description}
{$EXTERNALSYM SSL_dup}
{$EXTERNALSYM SSL_get_certificate}
{$EXTERNALSYM SSL_get_privatekey}
{$EXTERNALSYM SSL_CTX_get0_certificate}
{$EXTERNALSYM SSL_CTX_get0_privatekey}
{$EXTERNALSYM SSL_CTX_set_quiet_shutdown}
{$EXTERNALSYM SSL_CTX_get_quiet_shutdown}
{$EXTERNALSYM SSL_set_quiet_shutdown}
{$EXTERNALSYM SSL_get_quiet_shutdown}
{$EXTERNALSYM SSL_set_shutdown}
{$EXTERNALSYM SSL_get_shutdown}
{$EXTERNALSYM SSL_version}
{$EXTERNALSYM SSL_client_version}
{$EXTERNALSYM SSL_CTX_set_default_verify_paths}
{$EXTERNALSYM SSL_CTX_set_default_verify_dir}
{$EXTERNALSYM SSL_CTX_set_default_verify_file}
{$EXTERNALSYM SSL_CTX_load_verify_locations}
{$EXTERNALSYM SSL_get_session}
{$EXTERNALSYM SSL_get1_session}
{$EXTERNALSYM SSL_get_SSL_CTX}
{$EXTERNALSYM SSL_set_SSL_CTX}
{$EXTERNALSYM SSL_set_info_callback}
{$EXTERNALSYM SSL_get_info_callback}
{$EXTERNALSYM SSL_get_state}
{$EXTERNALSYM SSL_set_verify_result}
{$EXTERNALSYM SSL_get_verify_result}
{$EXTERNALSYM SSL_get_client_random}
{$EXTERNALSYM SSL_get_server_random}
{$EXTERNALSYM SSL_SESSION_get_master_key}
{$EXTERNALSYM SSL_SESSION_set1_master_key}
{$EXTERNALSYM SSL_SESSION_get_max_fragment_length}
{$EXTERNALSYM SSL_set_ex_data}
{$EXTERNALSYM SSL_get_ex_data}
{$EXTERNALSYM SSL_SESSION_set_ex_data}
{$EXTERNALSYM SSL_SESSION_get_ex_data}
{$EXTERNALSYM SSL_CTX_set_ex_data}
{$EXTERNALSYM SSL_CTX_get_ex_data}
{$EXTERNALSYM SSL_get_ex_data_X509_STORE_CTX_idx}
{$EXTERNALSYM SSL_CTX_set_default_read_buffer_len}
{$EXTERNALSYM SSL_set_default_read_buffer_len}
{$EXTERNALSYM SSL_CTX_set_tmp_dh_callback}
{$EXTERNALSYM SSL_set_tmp_dh_callback}
{$EXTERNALSYM SSL_CIPHER_find}
{$EXTERNALSYM SSL_CIPHER_get_cipher_nid}
{$EXTERNALSYM SSL_CIPHER_get_digest_nid}
{$EXTERNALSYM SSL_set_session_ticket_ext}
{$EXTERNALSYM SSL_set_session_ticket_ext_cb}
{$EXTERNALSYM SSL_CTX_set_not_resumable_session_callback}
{$EXTERNALSYM SSL_set_not_resumable_session_callback}
{$EXTERNALSYM SSL_CTX_set_record_padding_callback}
{$EXTERNALSYM SSL_CTX_set_record_padding_callback_arg}
{$EXTERNALSYM SSL_CTX_get_record_padding_callback_arg}
{$EXTERNALSYM SSL_CTX_set_block_padding}
{$EXTERNALSYM SSL_set_record_padding_callback}
{$EXTERNALSYM SSL_set_record_padding_callback_arg}
{$EXTERNALSYM SSL_get_record_padding_callback_arg}
{$EXTERNALSYM SSL_set_block_padding}
{$EXTERNALSYM SSL_set_num_tickets}
{$EXTERNALSYM SSL_get_num_tickets}
{$EXTERNALSYM SSL_CTX_set_num_tickets}
{$EXTERNALSYM SSL_CTX_get_num_tickets}
{$EXTERNALSYM SSL_session_reused}
{$EXTERNALSYM SSL_is_server}
{$EXTERNALSYM SSL_CONF_CTX_new}
{$EXTERNALSYM SSL_CONF_CTX_finish}
{$EXTERNALSYM SSL_CONF_CTX_free}
{$EXTERNALSYM SSL_CONF_CTX_set_flags}
{$EXTERNALSYM SSL_CONF_CTX_clear_flags}
{$EXTERNALSYM SSL_CONF_CTX_set1_prefix}
{$EXTERNALSYM SSL_CONF_cmd}
{$EXTERNALSYM SSL_CONF_cmd_argv}
{$EXTERNALSYM SSL_CONF_cmd_value_type}
{$EXTERNALSYM SSL_CONF_CTX_set_ssl}
{$EXTERNALSYM SSL_CONF_CTX_set_ssl_ctx}
{$EXTERNALSYM SSL_add_ssl_module}
{$EXTERNALSYM SSL_config}
{$EXTERNALSYM SSL_CTX_config}
{$EXTERNALSYM DTLSv1_listen}
{$EXTERNALSYM SSL_enable_ct}
{$EXTERNALSYM SSL_CTX_enable_ct}
{$EXTERNALSYM SSL_ct_is_enabled}
{$EXTERNALSYM SSL_CTX_ct_is_enabled}
{$EXTERNALSYM SSL_CTX_set_default_ctlog_list_file}
{$EXTERNALSYM SSL_CTX_set_ctlog_list_file}
{$EXTERNALSYM SSL_CTX_set0_ctlog_store}
{$EXTERNALSYM SSL_set_security_level}
{$EXTERNALSYM SSL_set_security_callback}
{$EXTERNALSYM SSL_get_security_callback}
{$EXTERNALSYM SSL_set0_security_ex_data}
{$EXTERNALSYM SSL_get0_security_ex_data}
{$EXTERNALSYM SSL_CTX_set_security_level}
{$EXTERNALSYM SSL_CTX_get_security_level}
{$EXTERNALSYM SSL_CTX_get0_security_ex_data}
{$EXTERNALSYM SSL_CTX_set0_security_ex_data}
{$EXTERNALSYM OPENSSL_init_ssl}
{$EXTERNALSYM SSL_free_buffers}
{$EXTERNALSYM SSL_alloc_buffers}
{$EXTERNALSYM SSL_CTX_set_session_ticket_cb}
{$EXTERNALSYM SSL_SESSION_set1_ticket_appdata}
{$EXTERNALSYM SSL_SESSION_get0_ticket_appdata}
{$EXTERNALSYM DTLS_set_timer_cb}
{$EXTERNALSYM SSL_CTX_set_allow_early_data_cb}
{$EXTERNALSYM SSL_set_allow_early_data_cb}
{$EXTERNALSYM SSL_get0_peer_certificate}
{$EXTERNALSYM SSL_get1_peer_certificate}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function SSL_CTX_get_options(const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_get_options(const s: PSSL): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_clear_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_clear_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_set_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
procedure SSL_CTX_sess_set_new_cb(ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl; external CLibSSL;
function SSL_CTX_sess_get_new_cb(ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl; external CLibSSL;
procedure SSL_CTX_sess_set_remove_cb(ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl; external CLibSSL;
function SSL_CTX_sess_get_remove_cb(ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl; external CLibSSL;
procedure SSL_CTX_set_info_callback(ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl; external CLibSSL;
function SSL_CTX_get_info_callback(ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl; external CLibSSL;
procedure SSL_CTX_set_client_cert_cb(ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl; external CLibSSL;
function SSL_CTX_get_client_cert_cb(ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl; external CLibSSL;
function SSL_CTX_set_client_cert_engine(ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_cookie_generate_cb(ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_cookie_verify_cb(ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_stateless_cookie_generate_cb(ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_stateless_cookie_verify_cb(ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_alpn_select_cb(ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl; external CLibSSL;
procedure SSL_get0_alpn_selected(const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_client_callback(ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_client_callback(ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_server_callback(ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_server_callback(ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_find_session_callback(s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_find_session_callback(ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl; external CLibSSL;
procedure SSL_set_psk_use_session_callback(s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_psk_use_session_callback(ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl; external CLibSSL;
procedure SSL_CTX_set_keylog_callback(ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl; external CLibSSL;
function SSL_CTX_get_keylog_callback(const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl; external CLibSSL;
function SSL_CTX_set_max_early_data(ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_set_max_early_data(s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_CTX_set_recv_max_early_data(ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_recv_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_set_recv_max_early_data(s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_recv_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_in_init(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_in_before(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_is_init_finished(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_get_peer_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function BIO_f_ssl: PBIO_METHOD; cdecl; external CLibSSL;
function BIO_new_ssl(ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl; external CLibSSL;
function BIO_new_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl; external CLibSSL;
function BIO_new_buffer_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl; external CLibSSL;
function BIO_ssl_copy_session_id(to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_cipher_list(v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_new(const meth: PSSL_METHOD): PSSL_CTX; cdecl; external CLibSSL;
function SSL_CTX_set_timeout(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_get_timeout(const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_get_cert_store(const v1: PSSL_CTX): PX509_STORE; cdecl; external CLibSSL;
function SSL_want(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_clear(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure BIO_ssl_shutdown(ssl_bio: PBIO); cdecl; external CLibSSL;
function SSL_CTX_up_ref(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_free(v1: PSSL_CTX); cdecl; external CLibSSL;
procedure SSL_CTX_set_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl; external CLibSSL;
procedure SSL_CTX_set1_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl; external CLibSSL;
procedure SSL_CTX_flush_sessions(ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl; external CLibSSL;
function SSL_get_current_cipher(const s: PSSL): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_get_pending_cipher(const s: PSSL): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_CIPHER_get_bits(const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_version(const c: PSSL_CIPHER): PAnsiChar; cdecl; external CLibSSL;
function SSL_CIPHER_get_name(const c: PSSL_CIPHER): PAnsiChar; cdecl; external CLibSSL;
function SSL_CIPHER_standard_name(const c: PSSL_CIPHER): PAnsiChar; cdecl; external CLibSSL;
function OPENSSL_cipher_name(const rfc_name: PAnsiChar): PAnsiChar; cdecl; external CLibSSL;
function SSL_CIPHER_get_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_CIPHER_get_protocol_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl; external CLibSSL;
function SSL_CIPHER_get_kx_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_auth_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_handshake_digest(const c: PSSL_CIPHER): PEVP_MD; cdecl; external CLibSSL;
function SSL_CIPHER_is_aead(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_fd(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_rfd(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_wfd(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_cipher_list(const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_get_shared_ciphers(const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_get_read_ahead(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_pending(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_has_pending(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_fd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_rfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_wfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set0_rbio(s: PSSL; rbio: PBIO); cdecl; external CLibSSL;
procedure SSL_set0_wbio(s: PSSL; wbio: PBIO); cdecl; external CLibSSL;
procedure SSL_set_bio(s: PSSL; rbio: PBIO; wbio: PBIO); cdecl; external CLibSSL;
function SSL_get_rbio(const s: PSSL): PBIO; cdecl; external CLibSSL;
function SSL_get_wbio(const s: PSSL): PBIO; cdecl; external CLibSSL;
function SSL_set_cipher_list(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_ciphersuites(ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_ciphersuites(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_verify_mode(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_verify_depth(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_verify_callback(const s: PSSL): SSL_verify_cb; cdecl; external CLibSSL;
procedure SSL_set_read_ahead(s: PSSL; yes: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_set_verify(s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl; external CLibSSL;
procedure SSL_set_verify_depth(s: PSSL; depth: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_use_RSAPrivateKey(ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_RSAPrivateKey_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_PrivateKey(ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_serverinfo(ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_serverinfo_ex(ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_serverinfo_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_RSAPrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_PrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_RSAPrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_use_certificate_chain_file(ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_load_client_CA_file(const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl; external CLibSSL;
function SSL_add_file_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_add_dir_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_state_string(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_rstate_string(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_state_string_long(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_rstate_string_long(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_SESSION_get_time(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_set_time(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_get_timeout(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_set_timeout(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_set_protocol_version(s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_hostname(const s: PSSL_SESSION): PAnsiChar; cdecl; external CLibSSL;
function SSL_SESSION_set1_hostname(s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_SESSION_get0_alpn_selected(const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl; external CLibSSL;
function SSL_SESSION_set1_alpn_selected(s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_cipher(const s: PSSL_SESSION): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_SESSION_set_cipher(s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_has_ticket(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get_ticket_lifetime_hint(const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
procedure SSL_SESSION_get0_ticket(const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl; external CLibSSL;
function SSL_SESSION_get_max_early_data(const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl; external CLibSSL;
function SSL_SESSION_set_max_early_data(s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_copy_session_id(to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_peer(s: PSSL_SESSION): PX509; cdecl; external CLibSSL;
function SSL_SESSION_set1_id_context(s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_set1_id(s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_is_resumable(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_new: PSSL_SESSION; cdecl; external CLibSSL;
function SSL_SESSION_dup(src: PSSL_SESSION): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_SESSION_get_id(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl; external CLibSSL;
function SSL_SESSION_get0_id_context(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl; external CLibSSL;
function SSL_SESSION_get_compress_id(const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_SESSION_print(fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_print_keylog(bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_up_ref(ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_SESSION_free(ses: PSSL_SESSION); cdecl; external CLibSSL;
function SSL_set_session(to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_add_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_remove_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_generate_session_id(ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_generate_session_id(s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_has_matching_session_id(const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function d2i_SSL_SESSION(a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_CTX_get_verify_mode(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_verify_depth(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_verify_callback(const ctx: PSSL_CTX): SSL_verify_cb; cdecl; external CLibSSL;
procedure SSL_CTX_set_verify(ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_verify_depth(ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_CTX_set_cert_verify_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl; external CLibSSL;
procedure SSL_CTX_set_cert_cb(c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl; external CLibSSL;
function SSL_CTX_use_RSAPrivateKey(ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_RSAPrivateKey_ASN1(ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_PrivateKey(ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate(ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_use_certificate_ASN1(ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl; external CLibSSL;
function SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl; external CLibSSL;
function SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl; external CLibSSL;
procedure SSL_set_default_passwd_cb(s: PSSL; cb: pem_password_cb); cdecl; external CLibSSL;
procedure SSL_set_default_passwd_cb_userdata(s: PSSL; u: Pointer); cdecl; external CLibSSL;
function SSL_get_default_passwd_cb(s: PSSL): pem_password_cb; cdecl; external CLibSSL;
function SSL_get_default_passwd_cb_userdata(s: PSSL): Pointer; cdecl; external CLibSSL;
function SSL_CTX_check_private_key(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_check_private_key(const ctx: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_session_id_context(ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_new(ctx: PSSL_CTX): PSSL; cdecl; external CLibSSL;
function SSL_up_ref(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_is_dtls(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_session_id_context(ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_purpose(ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_purpose(ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_trust(ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_trust(ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_add1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_peername(s: PSSL): PAnsiChar; cdecl; external CLibSSL;
procedure SSL_set_hostflags(s: PSSL; flags: TOpenSSL_C_UINT); cdecl; external CLibSSL;
function SSL_CTX_dane_enable(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_dane_mtype_set(ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_dane_enable(s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_dane_tlsa_add(s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_dane_authority(s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_dane_tlsa(s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get0_dane(ssl: PSSL): PSSL_DANE; cdecl; external CLibSSL;
function SSL_CTX_dane_set_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_dane_clear_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_dane_set_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_dane_clear_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl; external CLibSSL;
function SSL_CTX_set1_param(ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set1_param(ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get0_param(ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl; external CLibSSL;
function SSL_get0_param(ssl: PSSL): PX509_VERIFY_PARAM; cdecl; external CLibSSL;
function SSL_CTX_set_srp_username(ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_password(ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_strength(ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_client_pwd_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_verify_param_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_username_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_srp_cb_arg(ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_srp_server_param(s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_srp_server_param_pw(s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_client_hello_cb(c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl; external CLibSSL;
function SSL_client_hello_isv2(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_client_hello_get0_legacy_version(s: PSSL): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_client_hello_get0_random(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get0_session_id(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get0_ciphers(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get0_compression_methods(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_client_hello_get1_extensions_present(s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_client_hello_get0_ext(s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_certs_clear(s: PSSL); cdecl; external CLibSSL;
procedure SSL_free(ssl: PSSL); cdecl; external CLibSSL;
function SSL_waiting_for_async(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_all_async_fds(s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_changed_async_fds(s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_accept(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_stateless(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_connect(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_read(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_read_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_read_early_data(s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_peek(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_peek_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_write(ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_write_ex(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_write_early_data(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_callback_ctrl(v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_ctrl(ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_ctrl(ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_CTX_callback_ctrl(v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_get_early_data_status(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_error(const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_version(const s: PSSL): PAnsiChar; cdecl; external CLibSSL;
function SSL_CTX_set_ssl_version(ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl; external CLibSSL;
function TLS_method: PSSL_METHOD; cdecl; external CLibSSL;
function TLS_server_method: PSSL_METHOD; cdecl; external CLibSSL;
function TLS_client_method: PSSL_METHOD; cdecl; external CLibSSL;
function SSL_do_handshake(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_key_update(s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_key_update_type(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_renegotiate(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_renegotiate_abbreviated(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_shutdown(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_post_handshake_auth(ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_set_post_handshake_auth(s: PSSL; val: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_renegotiate_pending(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_verify_client_post_handshake(s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_ssl_method(const ctx: PSSL_CTX): PSSL_METHOD; cdecl; external CLibSSL;
function SSL_get_ssl_method(const s: PSSL): PSSL_METHOD; cdecl; external CLibSSL;
function SSL_set_ssl_method(s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_alert_type_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_alert_type_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_alert_desc_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_alert_desc_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
procedure SSL_CTX_set_client_CA_list(ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl; external CLibSSL;
function SSL_add_client_CA(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_add_client_CA(ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_connect_state(s: PSSL); cdecl; external CLibSSL;
procedure SSL_set_accept_state(s: PSSL); cdecl; external CLibSSL;
function SSL_CIPHER_description(cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibSSL;
function SSL_dup(ssl: PSSL): PSSL; cdecl; external CLibSSL;
function SSL_get_certificate(const ssl: PSSL): PX509; cdecl; external CLibSSL;
function SSL_get_privatekey(const ssl: PSSL): PEVP_PKEY; cdecl; external CLibSSL;
function SSL_CTX_get0_certificate(const ctx: PSSL_CTX): PX509; cdecl; external CLibSSL;
function SSL_CTX_get0_privatekey(const ctx: PSSL_CTX): PEVP_PKEY; cdecl; external CLibSSL;
procedure SSL_CTX_set_quiet_shutdown(ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_CTX_get_quiet_shutdown(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_quiet_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_get_quiet_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_get_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_version(const ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_client_version(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_verify_paths(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_verify_dir(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_verify_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_load_verify_locations(ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_session(const ssl: PSSL): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_get1_session(ssl: PSSL): PSSL_SESSION; cdecl; external CLibSSL;
function SSL_get_SSL_CTX(const ssl: PSSL): PSSL_CTX; cdecl; external CLibSSL;
function SSL_set_SSL_CTX(ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl; external CLibSSL;
procedure SSL_set_info_callback(ssl: PSSL; cb: SSL_info_callback); cdecl; external CLibSSL;
function SSL_get_info_callback(const ssl: PSSL): SSL_info_callback; cdecl; external CLibSSL;
function SSL_get_state(const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl; external CLibSSL;
procedure SSL_set_verify_result(ssl: PSSL; v: TOpenSSL_C_LONG); cdecl; external CLibSSL;
function SSL_get_verify_result(const ssl: PSSL): TOpenSSL_C_LONG; cdecl; external CLibSSL;
function SSL_get_client_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_get_server_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_SESSION_get_master_key(const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_SESSION_set1_master_key(sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get_max_fragment_length(const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl; external CLibSSL;
function SSL_set_ex_data(ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_ex_data(const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibSSL;
function SSL_SESSION_set_ex_data(ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get_ex_data(const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibSSL;
function SSL_CTX_set_ex_data(ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_ex_data(const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibSSL;
function SSL_get_ex_data_X509_STORE_CTX_idx: TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_default_read_buffer_len(ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl; external CLibSSL;
procedure SSL_set_default_read_buffer_len(s: PSSL; len: TOpenSSL_C_SIZET); cdecl; external CLibSSL;
procedure SSL_CTX_set_tmp_dh_callback(ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl; external CLibSSL;
procedure SSL_set_tmp_dh_callback(ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl; external CLibSSL;
function SSL_CIPHER_find(ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl; external CLibSSL;
function SSL_CIPHER_get_cipher_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CIPHER_get_digest_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_session_ticket_ext(s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_session_ticket_ext_cb(s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set_not_resumable_session_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl; external CLibSSL;
procedure SSL_set_not_resumable_session_callback(ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_record_padding_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_record_padding_callback_arg(ctx: PSSL_CTX; arg: Pointer); cdecl; external CLibSSL;
function SSL_CTX_get_record_padding_callback_arg(const ctx: PSSL_CTX): Pointer; cdecl; external CLibSSL;
function SSL_CTX_set_block_padding(ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_set_record_padding_callback(ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl; external CLibSSL;
procedure SSL_set_record_padding_callback_arg(ssl: PSSL; arg: Pointer); cdecl; external CLibSSL;
function SSL_get_record_padding_callback_arg(const ssl: PSSL): Pointer; cdecl; external CLibSSL;
function SSL_set_block_padding(ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_set_num_tickets(s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_get_num_tickets(const s: PSSL): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_CTX_set_num_tickets(ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get_num_tickets(const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl; external CLibSSL;
function SSL_session_reused(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_is_server(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_CTX_new: PSSL_CONF_CTX; cdecl; external CLibSSL;
function SSL_CONF_CTX_finish(cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CONF_CTX_free(cctx: PSSL_CONF_CTX); cdecl; external CLibSSL;
function SSL_CONF_CTX_set_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_CONF_CTX_clear_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl; external CLibSSL;
function SSL_CONF_CTX_set1_prefix(cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_cmd(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_cmd_argv(cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CONF_cmd_value_type(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CONF_CTX_set_ssl(cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl; external CLibSSL;
procedure SSL_CONF_CTX_set_ssl_ctx(cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl; external CLibSSL;
procedure SSL_add_ssl_module; cdecl; external CLibSSL;
function SSL_config(s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_config(ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
function DTLSv1_listen(s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_enable_ct(s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_enable_ct(ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_ct_is_enabled(const s: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_ct_is_enabled(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_default_ctlog_list_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_ctlog_list_file(ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure SSL_CTX_set0_ctlog_store(ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl; external CLibSSL;
procedure SSL_set_security_level(s: PSSL; level: TOpenSSL_C_INT); cdecl; external CLibSSL;
procedure SSL_set_security_callback(s: PSSL; cb: SSL_security_callback); cdecl; external CLibSSL;
function SSL_get_security_callback(const s: PSSL): SSL_security_callback; cdecl; external CLibSSL;
procedure SSL_set0_security_ex_data(s: PSSL; ex: Pointer); cdecl; external CLibSSL;
function SSL_get0_security_ex_data(const s: PSSL): Pointer; cdecl; external CLibSSL;
procedure SSL_CTX_set_security_level(ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl; external CLibSSL;
function SSL_CTX_get_security_level(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_get0_security_ex_data(const ctx: PSSL_CTX): Pointer; cdecl; external CLibSSL;
procedure SSL_CTX_set0_security_ex_data(ctx: PSSL_CTX; ex: Pointer); cdecl; external CLibSSL;
function OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_free_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_alloc_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_CTX_set_session_ticket_cb(ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_set1_ticket_appdata(ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
function SSL_SESSION_get0_ticket_appdata(ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibSSL;
procedure DTLS_set_timer_cb(s: PSSL; cb: DTLS_timer_cb); cdecl; external CLibSSL;
procedure SSL_CTX_set_allow_early_data_cb(ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl; external CLibSSL;
procedure SSL_set_allow_early_data_cb(s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl; external CLibSSL;
function SSL_get0_peer_certificate(const s: PSSL): PX509; cdecl; {introduced 3.3.0 } external CLibSSL;
function SSL_get1_peer_certificate(const s: PSSL): PX509; cdecl; {introduced 3.3.0 } external CLibSSL;





{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; {removed 1.0.0}
function SSL_get_app_data(const ssl: PSSL): Pointer; {removed 1.0.0}
function SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; {removed 1.0.0}
procedure SSL_load_error_strings; {removed 1.1.0}
function SSL_get_peer_certificate(const s: PSSL): PX509; {removed 3.0.0}
function SSL_library_init: TOpenSSL_C_INT; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}

{Declare external function initialisers - should not be called directly}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
function Load_SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;
function Load_SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; cdecl;
function Load_SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_CTX_get_options(const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_get_options(const s: PSSL): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_CTX_clear_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_clear_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_set_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
procedure Load_SSL_CTX_sess_set_new_cb(ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl;
function Load_SSL_CTX_sess_get_new_cb(ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl;
procedure Load_SSL_CTX_sess_set_remove_cb(ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl;
function Load_SSL_CTX_sess_get_remove_cb(ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl;
procedure Load_SSL_CTX_set_info_callback(ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl;
function Load_SSL_CTX_get_info_callback(ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl;
procedure Load_SSL_CTX_set_client_cert_cb(ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl;
function Load_SSL_CTX_get_client_cert_cb(ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl;
function Load_SSL_CTX_set_client_cert_engine(ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set_cookie_generate_cb(ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl;
procedure Load_SSL_CTX_set_cookie_verify_cb(ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl;
procedure Load_SSL_CTX_set_stateless_cookie_generate_cb(ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl;
procedure Load_SSL_CTX_set_stateless_cookie_verify_cb(ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl;
procedure Load_SSL_CTX_set_alpn_select_cb(ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl;
procedure Load_SSL_get0_alpn_selected(const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl;
procedure Load_SSL_CTX_set_psk_client_callback(ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl;
procedure Load_SSL_set_psk_client_callback(ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl;
procedure Load_SSL_CTX_set_psk_server_callback(ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl;
procedure Load_SSL_set_psk_server_callback(ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl;
procedure Load_SSL_set_psk_find_session_callback(s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl;
procedure Load_SSL_CTX_set_psk_find_session_callback(ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl;
procedure Load_SSL_set_psk_use_session_callback(s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl;
procedure Load_SSL_CTX_set_psk_use_session_callback(ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl;
procedure Load_SSL_CTX_set_keylog_callback(ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl;
function Load_SSL_CTX_get_keylog_callback(const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl;
function Load_SSL_CTX_set_max_early_data(ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl;
function Load_SSL_set_max_early_data(s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl;
function Load_SSL_CTX_set_recv_max_early_data(ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_recv_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl;
function Load_SSL_set_recv_max_early_data(s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_recv_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_get_app_data(const ssl: PSSL): Pointer; cdecl;
function Load_SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_in_init(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_in_before(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_is_init_finished(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_get_peer_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_BIO_f_ssl: PBIO_METHOD; cdecl;
function Load_BIO_new_ssl(ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_new_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl;
function Load_BIO_new_buffer_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl;
function Load_BIO_ssl_copy_session_id(to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_cipher_list(v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_new(const meth: PSSL_METHOD): PSSL_CTX; cdecl;
function Load_SSL_CTX_set_timeout(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_get_timeout(const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_get_cert_store(const v1: PSSL_CTX): PX509_STORE; cdecl;
function Load_SSL_want(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_clear(s: PSSL): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_ssl_shutdown(ssl_bio: PBIO); cdecl;
function Load_SSL_CTX_up_ref(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_free(v1: PSSL_CTX); cdecl;
procedure Load_SSL_CTX_set_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl;
procedure Load_SSL_CTX_set1_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl;
procedure Load_SSL_CTX_flush_sessions(ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl;
function Load_SSL_get_current_cipher(const s: PSSL): PSSL_CIPHER; cdecl;
function Load_SSL_get_pending_cipher(const s: PSSL): PSSL_CIPHER; cdecl;
function Load_SSL_CIPHER_get_bits(const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CIPHER_get_version(const c: PSSL_CIPHER): PAnsiChar; cdecl;
function Load_SSL_CIPHER_get_name(const c: PSSL_CIPHER): PAnsiChar; cdecl;
function Load_SSL_CIPHER_standard_name(const c: PSSL_CIPHER): PAnsiChar; cdecl;
function Load_OPENSSL_cipher_name(const rfc_name: PAnsiChar): PAnsiChar; cdecl;
function Load_SSL_CIPHER_get_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl;
function Load_SSL_CIPHER_get_protocol_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl;
function Load_SSL_CIPHER_get_kx_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_SSL_CIPHER_get_auth_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_SSL_CIPHER_get_handshake_digest(const c: PSSL_CIPHER): PEVP_MD; cdecl;
function Load_SSL_CIPHER_is_aead(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_fd(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_rfd(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_wfd(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_cipher_list(const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSL_get_shared_ciphers(const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSL_get_read_ahead(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_has_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_fd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_rfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_wfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_set0_rbio(s: PSSL; rbio: PBIO); cdecl;
procedure Load_SSL_set0_wbio(s: PSSL; wbio: PBIO); cdecl;
procedure Load_SSL_set_bio(s: PSSL; rbio: PBIO; wbio: PBIO); cdecl;
function Load_SSL_get_rbio(const s: PSSL): PBIO; cdecl;
function Load_SSL_get_wbio(const s: PSSL): PBIO; cdecl;
function Load_SSL_set_cipher_list(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_ciphersuites(ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_ciphersuites(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_verify_mode(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_verify_depth(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_verify_callback(const s: PSSL): SSL_verify_cb; cdecl;
procedure Load_SSL_set_read_ahead(s: PSSL; yes: TOpenSSL_C_INT); cdecl;
procedure Load_SSL_set_verify(s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl;
procedure Load_SSL_set_verify_depth(s: PSSL; depth: TOpenSSL_C_INT); cdecl;
function Load_SSL_use_RSAPrivateKey(ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_RSAPrivateKey_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_PrivateKey(ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_certificate(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_certificate_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_serverinfo(ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_serverinfo_ex(ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_serverinfo_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_RSAPrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_PrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_certificate_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_RSAPrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_certificate_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_use_certificate_chain_file(ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_load_client_CA_file(const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl;
function Load_SSL_add_file_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_add_dir_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_SSL_load_error_strings; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_state_string(const s: PSSL): PAnsiChar; cdecl;
function Load_SSL_rstate_string(const s: PSSL): PAnsiChar; cdecl;
function Load_SSL_state_string_long(const s: PSSL): PAnsiChar; cdecl;
function Load_SSL_rstate_string_long(const s: PSSL): PAnsiChar; cdecl;
function Load_SSL_SESSION_get_time(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl;
function Load_SSL_SESSION_set_time(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_SESSION_get_timeout(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl;
function Load_SSL_SESSION_set_timeout(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_set_protocol_version(s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get0_hostname(const s: PSSL_SESSION): PAnsiChar; cdecl;
function Load_SSL_SESSION_set1_hostname(s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_SESSION_get0_alpn_selected(const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl;
function Load_SSL_SESSION_set1_alpn_selected(s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get0_cipher(const s: PSSL_SESSION): PSSL_CIPHER; cdecl;
function Load_SSL_SESSION_set_cipher(s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_has_ticket(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get_ticket_lifetime_hint(const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl;
procedure Load_SSL_SESSION_get0_ticket(const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl;
function Load_SSL_SESSION_get_max_early_data(const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl;
function Load_SSL_SESSION_set_max_early_data(s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
function Load_SSL_copy_session_id(to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get0_peer(s: PSSL_SESSION): PX509; cdecl;
function Load_SSL_SESSION_set1_id_context(s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_set1_id(s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_is_resumable(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_new: PSSL_SESSION; cdecl;
function Load_SSL_SESSION_dup(src: PSSL_SESSION): PSSL_SESSION; cdecl;
function Load_SSL_SESSION_get_id(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl;
function Load_SSL_SESSION_get0_id_context(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl;
function Load_SSL_SESSION_get_compress_id(const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl;
function Load_SSL_SESSION_print(fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_print_keylog(bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_up_ref(ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_SESSION_free(ses: PSSL_SESSION); cdecl;
function Load_SSL_set_session(to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_add_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_remove_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_generate_session_id(ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_generate_session_id(s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl;
function Load_SSL_has_matching_session_id(const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_d2i_SSL_SESSION(a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_CTX_get_verify_mode(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_verify_depth(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_verify_callback(const ctx: PSSL_CTX): SSL_verify_cb; cdecl;
procedure Load_SSL_CTX_set_verify(ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl;
procedure Load_SSL_CTX_set_verify_depth(ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl;
procedure Load_SSL_CTX_set_cert_verify_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl;
procedure Load_SSL_CTX_set_cert_cb(c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl;
function Load_SSL_CTX_use_RSAPrivateKey(ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_RSAPrivateKey_ASN1(ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_PrivateKey(ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_certificate(ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_use_certificate_ASN1(ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl;
procedure Load_SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl;
function Load_SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl;
function Load_SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl;
procedure Load_SSL_set_default_passwd_cb(s: PSSL; cb: pem_password_cb); cdecl;
procedure Load_SSL_set_default_passwd_cb_userdata(s: PSSL; u: Pointer); cdecl;
function Load_SSL_get_default_passwd_cb(s: PSSL): pem_password_cb; cdecl;
function Load_SSL_get_default_passwd_cb_userdata(s: PSSL): Pointer; cdecl;
function Load_SSL_CTX_check_private_key(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_check_private_key(const ctx: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_session_id_context(ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_SSL_new(ctx: PSSL_CTX): PSSL; cdecl;
function Load_SSL_up_ref(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_is_dtls(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_session_id_context(ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_purpose(ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_purpose(ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_trust(ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_trust(ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_set1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_add1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_get0_peername(s: PSSL): PAnsiChar; cdecl;
procedure Load_SSL_set_hostflags(s: PSSL; flags: TOpenSSL_C_UINT); cdecl;
function Load_SSL_CTX_dane_enable(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_dane_mtype_set(ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl;
function Load_SSL_dane_enable(s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_dane_tlsa_add(s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_get0_dane_authority(s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
function Load_SSL_get0_dane_tlsa(s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_get0_dane(ssl: PSSL): PSSL_DANE; cdecl;
function Load_SSL_CTX_dane_set_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_CTX_dane_clear_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_dane_set_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_dane_clear_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
function Load_SSL_CTX_set1_param(ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
function Load_SSL_set1_param(ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get0_param(ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl;
function Load_SSL_get0_param(ssl: PSSL): PX509_VERIFY_PARAM; cdecl;
function Load_SSL_CTX_set_srp_username(ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_srp_password(ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_srp_strength(ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_srp_client_pwd_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_srp_verify_param_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_srp_username_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_srp_cb_arg(ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_srp_server_param(s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_srp_server_param_pw(s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set_client_hello_cb(c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl;
function Load_SSL_client_hello_isv2(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_client_hello_get0_legacy_version(s: PSSL): TOpenSSL_C_UINT; cdecl;
function Load_SSL_client_hello_get0_random(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_client_hello_get0_session_id(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_client_hello_get0_ciphers(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_client_hello_get0_compression_methods(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_client_hello_get1_extensions_present(s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_client_hello_get0_ext(s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_certs_clear(s: PSSL); cdecl;
procedure Load_SSL_free(ssl: PSSL); cdecl;
function Load_SSL_waiting_for_async(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_all_async_fds(s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_changed_async_fds(s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_accept(ssl: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_stateless(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_connect(ssl: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_read(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_read_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_read_early_data(s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_peek(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_peek_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_write(ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_write_ex(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_write_early_data(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_callback_ctrl(v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl;
function Load_SSL_ctrl(ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_ctrl(ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_SSL_CTX_callback_ctrl(v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_early_data_status(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_error(const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_version(const s: PSSL): PAnsiChar; cdecl;
function Load_SSL_CTX_set_ssl_version(ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl;
function Load_TLS_method: PSSL_METHOD; cdecl;
function Load_TLS_server_method: PSSL_METHOD; cdecl;
function Load_TLS_client_method: PSSL_METHOD; cdecl;
function Load_SSL_do_handshake(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_key_update(s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_key_update_type(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_renegotiate(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_renegotiate_abbreviated(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_shutdown(s: PSSL): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set_post_handshake_auth(ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl;
procedure Load_SSL_set_post_handshake_auth(s: PSSL; val: TOpenSSL_C_INT); cdecl;
function Load_SSL_renegotiate_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_verify_client_post_handshake(s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_ssl_method(const ctx: PSSL_CTX): PSSL_METHOD; cdecl;
function Load_SSL_get_ssl_method(const s: PSSL): PSSL_METHOD; cdecl;
function Load_SSL_set_ssl_method(s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl;
function Load_SSL_alert_type_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSL_alert_type_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSL_alert_desc_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSL_alert_desc_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
procedure Load_SSL_CTX_set_client_CA_list(ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl;
function Load_SSL_add_client_CA(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_add_client_CA(ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_set_connect_state(s: PSSL); cdecl;
procedure Load_SSL_set_accept_state(s: PSSL); cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_library_init: TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_CIPHER_description(cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_SSL_dup(ssl: PSSL): PSSL; cdecl;
function Load_SSL_get_certificate(const ssl: PSSL): PX509; cdecl;
function Load_SSL_get_privatekey(const ssl: PSSL): PEVP_PKEY; cdecl;
function Load_SSL_CTX_get0_certificate(const ctx: PSSL_CTX): PX509; cdecl;
function Load_SSL_CTX_get0_privatekey(const ctx: PSSL_CTX): PEVP_PKEY; cdecl;
procedure Load_SSL_CTX_set_quiet_shutdown(ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl;
function Load_SSL_CTX_get_quiet_shutdown(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_set_quiet_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl;
function Load_SSL_get_quiet_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_set_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl;
function Load_SSL_get_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_version(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_client_version(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_default_verify_paths(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_default_verify_dir(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_default_verify_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_load_verify_locations(ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_session(const ssl: PSSL): PSSL_SESSION; cdecl;
function Load_SSL_get1_session(ssl: PSSL): PSSL_SESSION; cdecl;
function Load_SSL_get_SSL_CTX(const ssl: PSSL): PSSL_CTX; cdecl;
function Load_SSL_set_SSL_CTX(ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl;
procedure Load_SSL_set_info_callback(ssl: PSSL; cb: SSL_info_callback); cdecl;
function Load_SSL_get_info_callback(const ssl: PSSL): SSL_info_callback; cdecl;
function Load_SSL_get_state(const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl;
procedure Load_SSL_set_verify_result(ssl: PSSL; v: TOpenSSL_C_LONG); cdecl;
function Load_SSL_get_verify_result(const ssl: PSSL): TOpenSSL_C_LONG; cdecl;
function Load_SSL_get_client_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_get_server_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_SESSION_get_master_key(const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_SESSION_set1_master_key(sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get_max_fragment_length(const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl;
function Load_SSL_set_ex_data(ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_ex_data(const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_SSL_SESSION_set_ex_data(ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get_ex_data(const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_SSL_CTX_set_ex_data(ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_ex_data(const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_SSL_get_ex_data_X509_STORE_CTX_idx: TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set_default_read_buffer_len(ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl;
procedure Load_SSL_set_default_read_buffer_len(s: PSSL; len: TOpenSSL_C_SIZET); cdecl;
procedure Load_SSL_CTX_set_tmp_dh_callback(ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl;
procedure Load_SSL_set_tmp_dh_callback(ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl;
function Load_SSL_CIPHER_find(ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl;
function Load_SSL_CIPHER_get_cipher_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl;
function Load_SSL_CIPHER_get_digest_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_session_ticket_ext(s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_session_ticket_ext_cb(s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set_not_resumable_session_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl;
procedure Load_SSL_set_not_resumable_session_callback(ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl;
procedure Load_SSL_CTX_set_record_padding_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl;
procedure Load_SSL_CTX_set_record_padding_callback_arg(ctx: PSSL_CTX; arg: Pointer); cdecl;
function Load_SSL_CTX_get_record_padding_callback_arg(const ctx: PSSL_CTX): Pointer; cdecl;
function Load_SSL_CTX_set_block_padding(ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_set_record_padding_callback(ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl;
procedure Load_SSL_set_record_padding_callback_arg(ssl: PSSL; arg: Pointer); cdecl;
function Load_SSL_get_record_padding_callback_arg(const ssl: PSSL): Pointer; cdecl;
function Load_SSL_set_block_padding(ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_set_num_tickets(s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_get_num_tickets(const s: PSSL): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_CTX_set_num_tickets(ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get_num_tickets(const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl;
function Load_SSL_session_reused(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_is_server(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_CONF_CTX_new: PSSL_CONF_CTX; cdecl;
function Load_SSL_CONF_CTX_finish(cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CONF_CTX_free(cctx: PSSL_CONF_CTX); cdecl;
function Load_SSL_CONF_CTX_set_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
function Load_SSL_CONF_CTX_clear_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
function Load_SSL_CONF_CTX_set1_prefix(cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CONF_cmd(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CONF_cmd_argv(cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CONF_cmd_value_type(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CONF_CTX_set_ssl(cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl;
procedure Load_SSL_CONF_CTX_set_ssl_ctx(cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl;
procedure Load_SSL_add_ssl_module; cdecl;
function Load_SSL_config(s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_config(ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_DTLSv1_listen(s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl;
function Load_SSL_enable_ct(s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_enable_ct(ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_SSL_ct_is_enabled(const s: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_ct_is_enabled(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_default_ctlog_list_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_ctlog_list_file(ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl;
procedure Load_SSL_CTX_set0_ctlog_store(ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl;
procedure Load_SSL_set_security_level(s: PSSL; level: TOpenSSL_C_INT); cdecl;
procedure Load_SSL_set_security_callback(s: PSSL; cb: SSL_security_callback); cdecl;
function Load_SSL_get_security_callback(const s: PSSL): SSL_security_callback; cdecl;
procedure Load_SSL_set0_security_ex_data(s: PSSL; ex: Pointer); cdecl;
function Load_SSL_get0_security_ex_data(const s: PSSL): Pointer; cdecl;
procedure Load_SSL_CTX_set_security_level(ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl;
function Load_SSL_CTX_get_security_level(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_get0_security_ex_data(const ctx: PSSL_CTX): Pointer; cdecl;
procedure Load_SSL_CTX_set0_security_ex_data(ctx: PSSL_CTX; ex: Pointer); cdecl;
function Load_OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
function Load_SSL_free_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_alloc_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl;
function Load_SSL_CTX_set_session_ticket_cb(ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_set1_ticket_appdata(ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SSL_SESSION_get0_ticket_appdata(ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_DTLS_set_timer_cb(s: PSSL; cb: DTLS_timer_cb); cdecl;
procedure Load_SSL_CTX_set_allow_early_data_cb(ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl;
procedure Load_SSL_set_allow_early_data_cb(s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl;
function Load_SSL_get0_peer_certificate(const s: PSSL): PX509; cdecl;
function Load_SSL_get1_peer_certificate(const s: PSSL): PX509; cdecl;

var
  SSL_CTX_get_options: function (const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl = Load_SSL_CTX_get_options;
  SSL_get_options: function (const s: PSSL): TOpenSSL_C_ULONG; cdecl = Load_SSL_get_options;
  SSL_CTX_clear_options: function (ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_CTX_clear_options;
  SSL_clear_options: function (s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_clear_options;
  SSL_CTX_set_options: function (ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_CTX_set_options;
  SSL_set_options: function (s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_set_options;
  SSL_CTX_sess_set_new_cb: procedure (ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl = Load_SSL_CTX_sess_set_new_cb;
  SSL_CTX_sess_get_new_cb: function (ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl = Load_SSL_CTX_sess_get_new_cb;
  SSL_CTX_sess_set_remove_cb: procedure (ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl = Load_SSL_CTX_sess_set_remove_cb;
  SSL_CTX_sess_get_remove_cb: function (ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl = Load_SSL_CTX_sess_get_remove_cb;
  SSL_CTX_set_info_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl = Load_SSL_CTX_set_info_callback;
  SSL_CTX_get_info_callback: function (ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl = Load_SSL_CTX_get_info_callback;
  SSL_CTX_set_client_cert_cb: procedure (ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl = Load_SSL_CTX_set_client_cert_cb;
  SSL_CTX_get_client_cert_cb: function (ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl = Load_SSL_CTX_get_client_cert_cb;
  SSL_CTX_set_client_cert_engine: function (ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_client_cert_engine;
  SSL_CTX_set_cookie_generate_cb: procedure (ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl = Load_SSL_CTX_set_cookie_generate_cb;
  SSL_CTX_set_cookie_verify_cb: procedure (ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl = Load_SSL_CTX_set_cookie_verify_cb;
  SSL_CTX_set_stateless_cookie_generate_cb: procedure (ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl = Load_SSL_CTX_set_stateless_cookie_generate_cb;
  SSL_CTX_set_stateless_cookie_verify_cb: procedure (ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl = Load_SSL_CTX_set_stateless_cookie_verify_cb;
  SSL_CTX_set_alpn_select_cb: procedure (ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl = Load_SSL_CTX_set_alpn_select_cb;
  SSL_get0_alpn_selected: procedure (const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl = Load_SSL_get0_alpn_selected;
  SSL_CTX_set_psk_client_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl = Load_SSL_CTX_set_psk_client_callback;
  SSL_set_psk_client_callback: procedure (ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl = Load_SSL_set_psk_client_callback;
  SSL_CTX_set_psk_server_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl = Load_SSL_CTX_set_psk_server_callback;
  SSL_set_psk_server_callback: procedure (ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl = Load_SSL_set_psk_server_callback;
  SSL_set_psk_find_session_callback: procedure (s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl = Load_SSL_set_psk_find_session_callback;
  SSL_CTX_set_psk_find_session_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl = Load_SSL_CTX_set_psk_find_session_callback;
  SSL_set_psk_use_session_callback: procedure (s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl = Load_SSL_set_psk_use_session_callback;
  SSL_CTX_set_psk_use_session_callback: procedure (ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl = Load_SSL_CTX_set_psk_use_session_callback;
  SSL_CTX_set_keylog_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl = Load_SSL_CTX_set_keylog_callback;
  SSL_CTX_get_keylog_callback: function (const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl = Load_SSL_CTX_get_keylog_callback;
  SSL_CTX_set_max_early_data: function (ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_max_early_data;
  SSL_CTX_get_max_early_data: function (const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl = Load_SSL_CTX_get_max_early_data;
  SSL_set_max_early_data: function (s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_SSL_set_max_early_data;
  SSL_get_max_early_data: function (const s: PSSL): TOpenSSL_C_UINT32; cdecl = Load_SSL_get_max_early_data;
  SSL_CTX_set_recv_max_early_data: function (ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_recv_max_early_data;
  SSL_CTX_get_recv_max_early_data: function (const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl = Load_SSL_CTX_get_recv_max_early_data;
  SSL_set_recv_max_early_data: function (s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_SSL_set_recv_max_early_data;
  SSL_get_recv_max_early_data: function (const s: PSSL): TOpenSSL_C_UINT32; cdecl = Load_SSL_get_recv_max_early_data;
  SSL_in_init: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_in_init;
  SSL_in_before: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_in_before;
  SSL_is_init_finished: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_is_init_finished;
  SSL_get_finished: function (const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_SSL_get_finished;
  SSL_get_peer_finished: function (const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_SSL_get_peer_finished;
  BIO_f_ssl: function : PBIO_METHOD; cdecl = Load_BIO_f_ssl;
  BIO_new_ssl: function (ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_new_ssl;
  BIO_new_ssl_connect: function (ctx: PSSL_CTX): PBIO; cdecl = Load_BIO_new_ssl_connect;
  BIO_new_buffer_ssl_connect: function (ctx: PSSL_CTX): PBIO; cdecl = Load_BIO_new_buffer_ssl_connect;
  BIO_ssl_copy_session_id: function (to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_ssl_copy_session_id;
  SSL_CTX_set_cipher_list: function (v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_cipher_list;
  SSL_CTX_new: function (const meth: PSSL_METHOD): PSSL_CTX; cdecl = Load_SSL_CTX_new;
  SSL_CTX_set_timeout: function (ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_timeout;
  SSL_CTX_get_timeout: function (const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_get_timeout;
  SSL_CTX_get_cert_store: function (const v1: PSSL_CTX): PX509_STORE; cdecl = Load_SSL_CTX_get_cert_store;
  SSL_want: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_want;
  SSL_clear: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_clear;
  BIO_ssl_shutdown: procedure (ssl_bio: PBIO); cdecl = Load_BIO_ssl_shutdown;
  SSL_CTX_up_ref: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_up_ref;
  SSL_CTX_free: procedure (v1: PSSL_CTX); cdecl = Load_SSL_CTX_free;
  SSL_CTX_set_cert_store: procedure (v1: PSSL_CTX; v2: PX509_STORE); cdecl = Load_SSL_CTX_set_cert_store;
  SSL_CTX_set1_cert_store: procedure (v1: PSSL_CTX; v2: PX509_STORE); cdecl = Load_SSL_CTX_set1_cert_store;
  SSL_CTX_flush_sessions: procedure (ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl = Load_SSL_CTX_flush_sessions;
  SSL_get_current_cipher: function (const s: PSSL): PSSL_CIPHER; cdecl = Load_SSL_get_current_cipher;
  SSL_get_pending_cipher: function (const s: PSSL): PSSL_CIPHER; cdecl = Load_SSL_get_pending_cipher;
  SSL_CIPHER_get_bits: function (const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CIPHER_get_bits;
  SSL_CIPHER_get_version: function (const c: PSSL_CIPHER): PAnsiChar; cdecl = Load_SSL_CIPHER_get_version;
  SSL_CIPHER_get_name: function (const c: PSSL_CIPHER): PAnsiChar; cdecl = Load_SSL_CIPHER_get_name;
  SSL_CIPHER_standard_name: function (const c: PSSL_CIPHER): PAnsiChar; cdecl = Load_SSL_CIPHER_standard_name;
  OPENSSL_cipher_name: function (const rfc_name: PAnsiChar): PAnsiChar; cdecl = Load_OPENSSL_cipher_name;
  SSL_CIPHER_get_id: function (const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl = Load_SSL_CIPHER_get_id;
  SSL_CIPHER_get_protocol_id: function (const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl = Load_SSL_CIPHER_get_protocol_id;
  SSL_CIPHER_get_kx_nid: function (const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = Load_SSL_CIPHER_get_kx_nid;
  SSL_CIPHER_get_auth_nid: function (const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = Load_SSL_CIPHER_get_auth_nid;
  SSL_CIPHER_get_handshake_digest: function (const c: PSSL_CIPHER): PEVP_MD; cdecl = Load_SSL_CIPHER_get_handshake_digest;
  SSL_CIPHER_is_aead: function (const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = Load_SSL_CIPHER_is_aead;
  SSL_get_fd: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_fd;
  SSL_get_rfd: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_rfd;
  SSL_get_wfd: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_wfd;
  SSL_get_cipher_list: function (const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_get_cipher_list;
  SSL_get_shared_ciphers: function (const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_get_shared_ciphers;
  SSL_get_read_ahead: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_read_ahead;
  SSL_pending: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_pending;
  SSL_has_pending: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_has_pending;
  SSL_set_fd: function (s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_set_fd;
  SSL_set_rfd: function (s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_set_rfd;
  SSL_set_wfd: function (s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_set_wfd;
  SSL_set0_rbio: procedure (s: PSSL; rbio: PBIO); cdecl = Load_SSL_set0_rbio;
  SSL_set0_wbio: procedure (s: PSSL; wbio: PBIO); cdecl = Load_SSL_set0_wbio;
  SSL_set_bio: procedure (s: PSSL; rbio: PBIO; wbio: PBIO); cdecl = Load_SSL_set_bio;
  SSL_get_rbio: function (const s: PSSL): PBIO; cdecl = Load_SSL_get_rbio;
  SSL_get_wbio: function (const s: PSSL): PBIO; cdecl = Load_SSL_get_wbio;
  SSL_set_cipher_list: function (s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set_cipher_list;
  SSL_CTX_set_ciphersuites: function (ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_ciphersuites;
  SSL_set_ciphersuites: function (s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set_ciphersuites;
  SSL_get_verify_mode: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_verify_mode;
  SSL_get_verify_depth: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_verify_depth;
  SSL_get_verify_callback: function (const s: PSSL): SSL_verify_cb; cdecl = Load_SSL_get_verify_callback;
  SSL_set_read_ahead: procedure (s: PSSL; yes: TOpenSSL_C_INT); cdecl = Load_SSL_set_read_ahead;
  SSL_set_verify: procedure (s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl = Load_SSL_set_verify;
  SSL_set_verify_depth: procedure (s: PSSL; depth: TOpenSSL_C_INT); cdecl = Load_SSL_set_verify_depth;
  SSL_use_RSAPrivateKey: function (ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_SSL_use_RSAPrivateKey;
  SSL_use_RSAPrivateKey_ASN1: function (ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_SSL_use_RSAPrivateKey_ASN1;
  SSL_use_PrivateKey: function (ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_SSL_use_PrivateKey;
  SSL_use_PrivateKey_ASN1: function (pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_SSL_use_PrivateKey_ASN1;
  SSL_use_certificate: function (ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl = Load_SSL_use_certificate;
  SSL_use_certificate_ASN1: function (ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_use_certificate_ASN1;
  SSL_CTX_use_serverinfo: function (ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_serverinfo;
  SSL_CTX_use_serverinfo_ex: function (ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_serverinfo_ex;
  SSL_CTX_use_serverinfo_file: function (ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_serverinfo_file;
  SSL_use_RSAPrivateKey_file: function (ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_use_RSAPrivateKey_file;
  SSL_use_PrivateKey_file: function (ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_use_PrivateKey_file;
  SSL_use_certificate_file: function (ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_use_certificate_file;
  SSL_CTX_use_RSAPrivateKey_file: function (ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_RSAPrivateKey_file;
  SSL_CTX_use_PrivateKey_file: function (ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_PrivateKey_file;
  SSL_CTX_use_certificate_file: function (ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_certificate_file;
  SSL_CTX_use_certificate_chain_file: function (ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_certificate_chain_file;
  SSL_use_certificate_chain_file: function (ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_use_certificate_chain_file;
  SSL_load_client_CA_file: function (const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl = Load_SSL_load_client_CA_file;
  SSL_add_file_cert_subjects_to_stack: function (stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_add_file_cert_subjects_to_stack;
  SSL_add_dir_cert_subjects_to_stack: function (stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_add_dir_cert_subjects_to_stack;
  SSL_state_string: function (const s: PSSL): PAnsiChar; cdecl = Load_SSL_state_string;
  SSL_rstate_string: function (const s: PSSL): PAnsiChar; cdecl = Load_SSL_rstate_string;
  SSL_state_string_long: function (const s: PSSL): PAnsiChar; cdecl = Load_SSL_state_string_long;
  SSL_rstate_string_long: function (const s: PSSL): PAnsiChar; cdecl = Load_SSL_rstate_string_long;
  SSL_SESSION_get_time: function (const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl = Load_SSL_SESSION_get_time;
  SSL_SESSION_set_time: function (s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_SESSION_set_time;
  SSL_SESSION_get_timeout: function (const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl = Load_SSL_SESSION_get_timeout;
  SSL_SESSION_set_timeout: function (s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_SESSION_set_timeout;
  SSL_SESSION_get_protocol_version: function (const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_get_protocol_version;
  SSL_SESSION_set_protocol_version: function (s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set_protocol_version;
  SSL_SESSION_get0_hostname: function (const s: PSSL_SESSION): PAnsiChar; cdecl = Load_SSL_SESSION_get0_hostname;
  SSL_SESSION_set1_hostname: function (s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set1_hostname;
  SSL_SESSION_get0_alpn_selected: procedure (const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl = Load_SSL_SESSION_get0_alpn_selected;
  SSL_SESSION_set1_alpn_selected: function (s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set1_alpn_selected;
  SSL_SESSION_get0_cipher: function (const s: PSSL_SESSION): PSSL_CIPHER; cdecl = Load_SSL_SESSION_get0_cipher;
  SSL_SESSION_set_cipher: function (s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set_cipher;
  SSL_SESSION_has_ticket: function (const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_has_ticket;
  SSL_SESSION_get_ticket_lifetime_hint: function (const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl = Load_SSL_SESSION_get_ticket_lifetime_hint;
  SSL_SESSION_get0_ticket: procedure (const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl = Load_SSL_SESSION_get0_ticket;
  SSL_SESSION_get_max_early_data: function (const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl = Load_SSL_SESSION_get_max_early_data;
  SSL_SESSION_set_max_early_data: function (s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set_max_early_data;
  SSL_copy_session_id: function (to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_copy_session_id;
  SSL_SESSION_get0_peer: function (s: PSSL_SESSION): PX509; cdecl = Load_SSL_SESSION_get0_peer;
  SSL_SESSION_set1_id_context: function (s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set1_id_context;
  SSL_SESSION_set1_id: function (s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set1_id;
  SSL_SESSION_is_resumable: function (const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_is_resumable;
  SSL_SESSION_new: function : PSSL_SESSION; cdecl = Load_SSL_SESSION_new;
  SSL_SESSION_dup: function (src: PSSL_SESSION): PSSL_SESSION; cdecl = Load_SSL_SESSION_dup;
  SSL_SESSION_get_id: function (const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl = Load_SSL_SESSION_get_id;
  SSL_SESSION_get0_id_context: function (const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl = Load_SSL_SESSION_get0_id_context;
  SSL_SESSION_get_compress_id: function (const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl = Load_SSL_SESSION_get_compress_id;
  SSL_SESSION_print: function (fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_print;
  SSL_SESSION_print_keylog: function (bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_print_keylog;
  SSL_SESSION_up_ref: function (ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_up_ref;
  SSL_SESSION_free: procedure (ses: PSSL_SESSION); cdecl = Load_SSL_SESSION_free;
  SSL_set_session: function (to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_set_session;
  SSL_CTX_add_session: function (ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_add_session;
  SSL_CTX_remove_session: function (ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_remove_session;
  SSL_CTX_set_generate_session_id: function (ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_generate_session_id;
  SSL_set_generate_session_id: function (s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl = Load_SSL_set_generate_session_id;
  SSL_has_matching_session_id: function (const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_SSL_has_matching_session_id;
  d2i_SSL_SESSION: function (a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl = Load_d2i_SSL_SESSION;
  SSL_CTX_get_verify_mode: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_get_verify_mode;
  SSL_CTX_get_verify_depth: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_get_verify_depth;
  SSL_CTX_get_verify_callback: function (const ctx: PSSL_CTX): SSL_verify_cb; cdecl = Load_SSL_CTX_get_verify_callback;
  SSL_CTX_set_verify: procedure (ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl = Load_SSL_CTX_set_verify;
  SSL_CTX_set_verify_depth: procedure (ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl = Load_SSL_CTX_set_verify_depth;
  SSL_CTX_set_cert_verify_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl = Load_SSL_CTX_set_cert_verify_callback;
  SSL_CTX_set_cert_cb: procedure (c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl = Load_SSL_CTX_set_cert_cb;
  SSL_CTX_use_RSAPrivateKey: function (ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_RSAPrivateKey;
  SSL_CTX_use_RSAPrivateKey_ASN1: function (ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_RSAPrivateKey_ASN1;
  SSL_CTX_use_PrivateKey: function (ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_PrivateKey;
  SSL_CTX_use_PrivateKey_ASN1: function (pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_PrivateKey_ASN1;
  SSL_CTX_use_certificate: function (ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_certificate;
  SSL_CTX_use_certificate_ASN1: function (ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_use_certificate_ASN1;
  SSL_CTX_set_default_passwd_cb: procedure (ctx: PSSL_CTX; cb: pem_password_cb); cdecl = Load_SSL_CTX_set_default_passwd_cb;
  SSL_CTX_set_default_passwd_cb_userdata: procedure (ctx: PSSL_CTX; u: Pointer); cdecl = Load_SSL_CTX_set_default_passwd_cb_userdata;
  SSL_CTX_get_default_passwd_cb: function (ctx: PSSL_CTX): pem_password_cb; cdecl = Load_SSL_CTX_get_default_passwd_cb;
  SSL_CTX_get_default_passwd_cb_userdata: function (ctx: PSSL_CTX): Pointer; cdecl = Load_SSL_CTX_get_default_passwd_cb_userdata;
  SSL_set_default_passwd_cb: procedure (s: PSSL; cb: pem_password_cb); cdecl = Load_SSL_set_default_passwd_cb;
  SSL_set_default_passwd_cb_userdata: procedure (s: PSSL; u: Pointer); cdecl = Load_SSL_set_default_passwd_cb_userdata;
  SSL_get_default_passwd_cb: function (s: PSSL): pem_password_cb; cdecl = Load_SSL_get_default_passwd_cb;
  SSL_get_default_passwd_cb_userdata: function (s: PSSL): Pointer; cdecl = Load_SSL_get_default_passwd_cb_userdata;
  SSL_CTX_check_private_key: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_check_private_key;
  SSL_check_private_key: function (const ctx: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_check_private_key;
  SSL_CTX_set_session_id_context: function (ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_session_id_context;
  SSL_new: function (ctx: PSSL_CTX): PSSL; cdecl = Load_SSL_new;
  SSL_up_ref: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_up_ref;
  SSL_is_dtls: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_is_dtls;
  SSL_set_session_id_context: function (ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_SSL_set_session_id_context;
  SSL_CTX_set_purpose: function (ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_purpose;
  SSL_set_purpose: function (ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_set_purpose;
  SSL_CTX_set_trust: function (ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_trust;
  SSL_set_trust: function (ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_set_trust;
  SSL_set1_host: function (s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set1_host;
  SSL_add1_host: function (s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_add1_host;
  SSL_get0_peername: function (s: PSSL): PAnsiChar; cdecl = Load_SSL_get0_peername;
  SSL_set_hostflags: procedure (s: PSSL; flags: TOpenSSL_C_UINT); cdecl = Load_SSL_set_hostflags;
  SSL_CTX_dane_enable: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_dane_enable;
  SSL_CTX_dane_mtype_set: function (ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_dane_mtype_set;
  SSL_dane_enable: function (s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_dane_enable;
  SSL_dane_tlsa_add: function (s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_dane_tlsa_add;
  SSL_get0_dane_authority: function (s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_SSL_get0_dane_authority;
  SSL_get0_dane_tlsa: function (s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_get0_dane_tlsa;
  SSL_get0_dane: function (ssl: PSSL): PSSL_DANE; cdecl = Load_SSL_get0_dane;
  SSL_CTX_dane_set_flags: function (ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_CTX_dane_set_flags;
  SSL_CTX_dane_clear_flags: function (ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_CTX_dane_clear_flags;
  SSL_dane_set_flags: function (ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_dane_set_flags;
  SSL_dane_clear_flags: function (ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl = Load_SSL_dane_clear_flags;
  SSL_CTX_set1_param: function (ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set1_param;
  SSL_set1_param: function (ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl = Load_SSL_set1_param;
  SSL_CTX_get0_param: function (ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl = Load_SSL_CTX_get0_param;
  SSL_get0_param: function (ssl: PSSL): PX509_VERIFY_PARAM; cdecl = Load_SSL_get0_param;
  SSL_CTX_set_srp_username: function (ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_username;
  SSL_CTX_set_srp_password: function (ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_password;
  SSL_CTX_set_srp_strength: function (ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_strength;
  SSL_CTX_set_srp_client_pwd_callback: function (ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_client_pwd_callback;
  SSL_CTX_set_srp_verify_param_callback: function (ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_verify_param_callback;
  SSL_CTX_set_srp_username_callback: function (ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_username_callback;
  SSL_CTX_set_srp_cb_arg: function (ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_srp_cb_arg;
  SSL_set_srp_server_param: function (s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set_srp_server_param;
  SSL_set_srp_server_param_pw: function (s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set_srp_server_param_pw;
  SSL_CTX_set_client_hello_cb: procedure (c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl = Load_SSL_CTX_set_client_hello_cb;
  SSL_client_hello_isv2: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_client_hello_isv2;
  SSL_client_hello_get0_legacy_version: function (s: PSSL): TOpenSSL_C_UINT; cdecl = Load_SSL_client_hello_get0_legacy_version;
  SSL_client_hello_get0_random: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = Load_SSL_client_hello_get0_random;
  SSL_client_hello_get0_session_id: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = Load_SSL_client_hello_get0_session_id;
  SSL_client_hello_get0_ciphers: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = Load_SSL_client_hello_get0_ciphers;
  SSL_client_hello_get0_compression_methods: function (s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl = Load_SSL_client_hello_get0_compression_methods;
  SSL_client_hello_get1_extensions_present: function (s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_client_hello_get1_extensions_present;
  SSL_client_hello_get0_ext: function (s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_client_hello_get0_ext;
  SSL_certs_clear: procedure (s: PSSL); cdecl = Load_SSL_certs_clear;
  SSL_free: procedure (ssl: PSSL); cdecl = Load_SSL_free;
  SSL_waiting_for_async: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_waiting_for_async;
  SSL_get_all_async_fds: function (s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_get_all_async_fds;
  SSL_get_changed_async_fds: function (s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_get_changed_async_fds;
  SSL_accept: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_accept;
  SSL_stateless: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_stateless;
  SSL_connect: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_connect;
  SSL_read: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_read;
  SSL_read_ex: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_read_ex;
  SSL_read_early_data: function (s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_read_early_data;
  SSL_peek: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_peek;
  SSL_peek_ex: function (ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_peek_ex;
  SSL_write: function (ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_write;
  SSL_write_ex: function (s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_write_ex;
  SSL_write_early_data: function (s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_write_early_data;
  SSL_callback_ctrl: function (v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl = Load_SSL_callback_ctrl;
  SSL_ctrl: function (ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_ctrl;
  SSL_CTX_ctrl: function (ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_ctrl;
  SSL_CTX_callback_ctrl: function (v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_callback_ctrl;
  SSL_get_early_data_status: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_early_data_status;
  SSL_get_error: function (const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_get_error;
  SSL_get_version: function (const s: PSSL): PAnsiChar; cdecl = Load_SSL_get_version;
  SSL_CTX_set_ssl_version: function (ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_ssl_version;
  TLS_method: function : PSSL_METHOD; cdecl = Load_TLS_method;
  TLS_server_method: function : PSSL_METHOD; cdecl = Load_TLS_server_method;
  TLS_client_method: function : PSSL_METHOD; cdecl = Load_TLS_client_method;
  SSL_do_handshake: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_do_handshake;
  SSL_key_update: function (s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_key_update;
  SSL_get_key_update_type: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_key_update_type;
  SSL_renegotiate: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_renegotiate;
  SSL_renegotiate_abbreviated: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_renegotiate_abbreviated;
  SSL_new_session_ticket: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_new_session_ticket;
  SSL_shutdown: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_shutdown;
  SSL_CTX_set_post_handshake_auth: procedure (ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl = Load_SSL_CTX_set_post_handshake_auth;
  SSL_set_post_handshake_auth: procedure (s: PSSL; val: TOpenSSL_C_INT); cdecl = Load_SSL_set_post_handshake_auth;
  SSL_renegotiate_pending: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_renegotiate_pending;
  SSL_verify_client_post_handshake: function (s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_verify_client_post_handshake;
  SSL_CTX_get_ssl_method: function (const ctx: PSSL_CTX): PSSL_METHOD; cdecl = Load_SSL_CTX_get_ssl_method;
  SSL_get_ssl_method: function (const s: PSSL): PSSL_METHOD; cdecl = Load_SSL_get_ssl_method;
  SSL_set_ssl_method: function (s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl = Load_SSL_set_ssl_method;
  SSL_alert_type_string_long: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_alert_type_string_long;
  SSL_alert_type_string: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_alert_type_string;
  SSL_alert_desc_string_long: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_alert_desc_string_long;
  SSL_alert_desc_string: function (value: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_alert_desc_string;
  SSL_CTX_set_client_CA_list: procedure (ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl = Load_SSL_CTX_set_client_CA_list;
  SSL_add_client_CA: function (ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl = Load_SSL_add_client_CA;
  SSL_CTX_add_client_CA: function (ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_add_client_CA;
  SSL_set_connect_state: procedure (s: PSSL); cdecl = Load_SSL_set_connect_state;
  SSL_set_accept_state: procedure (s: PSSL); cdecl = Load_SSL_set_accept_state;
  SSL_CIPHER_description: function (cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl = Load_SSL_CIPHER_description;
  SSL_dup: function (ssl: PSSL): PSSL; cdecl = Load_SSL_dup;
  SSL_get_certificate: function (const ssl: PSSL): PX509; cdecl = Load_SSL_get_certificate;
  SSL_get_privatekey: function (const ssl: PSSL): PEVP_PKEY; cdecl = Load_SSL_get_privatekey;
  SSL_CTX_get0_certificate: function (const ctx: PSSL_CTX): PX509; cdecl = Load_SSL_CTX_get0_certificate;
  SSL_CTX_get0_privatekey: function (const ctx: PSSL_CTX): PEVP_PKEY; cdecl = Load_SSL_CTX_get0_privatekey;
  SSL_CTX_set_quiet_shutdown: procedure (ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl = Load_SSL_CTX_set_quiet_shutdown;
  SSL_CTX_get_quiet_shutdown: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_get_quiet_shutdown;
  SSL_set_quiet_shutdown: procedure (ssl: PSSL; mode: TOpenSSL_C_INT); cdecl = Load_SSL_set_quiet_shutdown;
  SSL_get_quiet_shutdown: function (const ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_quiet_shutdown;
  SSL_set_shutdown: procedure (ssl: PSSL; mode: TOpenSSL_C_INT); cdecl = Load_SSL_set_shutdown;
  SSL_get_shutdown: function (const ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_get_shutdown;
  SSL_version: function (const ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_version;
  SSL_client_version: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_client_version;
  SSL_CTX_set_default_verify_paths: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_default_verify_paths;
  SSL_CTX_set_default_verify_dir: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_default_verify_dir;
  SSL_CTX_set_default_verify_file: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_default_verify_file;
  SSL_CTX_load_verify_locations: function (ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_load_verify_locations;
  SSL_get_session: function (const ssl: PSSL): PSSL_SESSION; cdecl = Load_SSL_get_session;
  SSL_get1_session: function (ssl: PSSL): PSSL_SESSION; cdecl = Load_SSL_get1_session;
  SSL_get_SSL_CTX: function (const ssl: PSSL): PSSL_CTX; cdecl = Load_SSL_get_SSL_CTX;
  SSL_set_SSL_CTX: function (ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl = Load_SSL_set_SSL_CTX;
  SSL_set_info_callback: procedure (ssl: PSSL; cb: SSL_info_callback); cdecl = Load_SSL_set_info_callback;
  SSL_get_info_callback: function (const ssl: PSSL): SSL_info_callback; cdecl = Load_SSL_get_info_callback;
  SSL_get_state: function (const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl = Load_SSL_get_state;
  SSL_set_verify_result: procedure (ssl: PSSL; v: TOpenSSL_C_LONG); cdecl = Load_SSL_set_verify_result;
  SSL_get_verify_result: function (const ssl: PSSL): TOpenSSL_C_LONG; cdecl = Load_SSL_get_verify_result;
  SSL_get_client_random: function (const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_SSL_get_client_random;
  SSL_get_server_random: function (const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_SSL_get_server_random;
  SSL_SESSION_get_master_key: function (const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_SSL_SESSION_get_master_key;
  SSL_SESSION_set1_master_key: function (sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set1_master_key;
  SSL_SESSION_get_max_fragment_length: function (const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl = Load_SSL_SESSION_get_max_fragment_length;
  SSL_set_ex_data: function (ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_set_ex_data;
  SSL_get_ex_data: function (const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_SSL_get_ex_data;
  SSL_SESSION_set_ex_data: function (ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set_ex_data;
  SSL_SESSION_get_ex_data: function (const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_SSL_SESSION_get_ex_data;
  SSL_CTX_set_ex_data: function (ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_ex_data;
  SSL_CTX_get_ex_data: function (const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_SSL_CTX_get_ex_data;
  SSL_get_ex_data_X509_STORE_CTX_idx: function : TOpenSSL_C_INT; cdecl = Load_SSL_get_ex_data_X509_STORE_CTX_idx;
  SSL_CTX_set_default_read_buffer_len: procedure (ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl = Load_SSL_CTX_set_default_read_buffer_len;
  SSL_set_default_read_buffer_len: procedure (s: PSSL; len: TOpenSSL_C_SIZET); cdecl = Load_SSL_set_default_read_buffer_len;
  SSL_CTX_set_tmp_dh_callback: procedure (ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl = Load_SSL_CTX_set_tmp_dh_callback;
  SSL_set_tmp_dh_callback: procedure (ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl = Load_SSL_set_tmp_dh_callback;
  SSL_CIPHER_find: function (ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl = Load_SSL_CIPHER_find;
  SSL_CIPHER_get_cipher_nid: function (const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl = Load_SSL_CIPHER_get_cipher_nid;
  SSL_CIPHER_get_digest_nid: function (const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl = Load_SSL_CIPHER_get_digest_nid;
  SSL_set_session_ticket_ext: function (s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_set_session_ticket_ext;
  SSL_set_session_ticket_ext_cb: function (s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_set_session_ticket_ext_cb;
  SSL_CTX_set_not_resumable_session_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl = Load_SSL_CTX_set_not_resumable_session_callback;
  SSL_set_not_resumable_session_callback: procedure (ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl = Load_SSL_set_not_resumable_session_callback;
  SSL_CTX_set_record_padding_callback: procedure (ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl = Load_SSL_CTX_set_record_padding_callback;
  SSL_CTX_set_record_padding_callback_arg: procedure (ctx: PSSL_CTX; arg: Pointer); cdecl = Load_SSL_CTX_set_record_padding_callback_arg;
  SSL_CTX_get_record_padding_callback_arg: function (const ctx: PSSL_CTX): Pointer; cdecl = Load_SSL_CTX_get_record_padding_callback_arg;
  SSL_CTX_set_block_padding: function (ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_block_padding;
  SSL_set_record_padding_callback: procedure (ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl = Load_SSL_set_record_padding_callback;
  SSL_set_record_padding_callback_arg: procedure (ssl: PSSL; arg: Pointer); cdecl = Load_SSL_set_record_padding_callback_arg;
  SSL_get_record_padding_callback_arg: function (const ssl: PSSL): Pointer; cdecl = Load_SSL_get_record_padding_callback_arg;
  SSL_set_block_padding: function (ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_set_block_padding;
  SSL_set_num_tickets: function (s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_set_num_tickets;
  SSL_get_num_tickets: function (const s: PSSL): TOpenSSL_C_SIZET; cdecl = Load_SSL_get_num_tickets;
  SSL_CTX_set_num_tickets: function (ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_num_tickets;
  SSL_CTX_get_num_tickets: function (const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl = Load_SSL_CTX_get_num_tickets;
  SSL_session_reused: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_session_reused;
  SSL_is_server: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_is_server;
  SSL_CONF_CTX_new: function : PSSL_CONF_CTX; cdecl = Load_SSL_CONF_CTX_new;
  SSL_CONF_CTX_finish: function (cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CONF_CTX_finish;
  SSL_CONF_CTX_free: procedure (cctx: PSSL_CONF_CTX); cdecl = Load_SSL_CONF_CTX_free;
  SSL_CONF_CTX_set_flags: function (cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl = Load_SSL_CONF_CTX_set_flags;
  SSL_CONF_CTX_clear_flags: function (cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl = Load_SSL_CONF_CTX_clear_flags;
  SSL_CONF_CTX_set1_prefix: function (cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CONF_CTX_set1_prefix;
  SSL_CONF_cmd: function (cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CONF_cmd;
  SSL_CONF_cmd_argv: function (cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CONF_cmd_argv;
  SSL_CONF_cmd_value_type: function (cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CONF_cmd_value_type;
  SSL_CONF_CTX_set_ssl: procedure (cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl = Load_SSL_CONF_CTX_set_ssl;
  SSL_CONF_CTX_set_ssl_ctx: procedure (cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl = Load_SSL_CONF_CTX_set_ssl_ctx;
  SSL_add_ssl_module: procedure ; cdecl = Load_SSL_add_ssl_module;
  SSL_config: function (s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_config;
  SSL_CTX_config: function (ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_config;
  DTLSv1_listen: function (s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl = Load_DTLSv1_listen;
  SSL_enable_ct: function (s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_enable_ct;
  SSL_CTX_enable_ct: function (ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_enable_ct;
  SSL_ct_is_enabled: function (const s: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_ct_is_enabled;
  SSL_CTX_ct_is_enabled: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_ct_is_enabled;
  SSL_CTX_set_default_ctlog_list_file: function (ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_default_ctlog_list_file;
  SSL_CTX_set_ctlog_list_file: function (ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_ctlog_list_file;
  SSL_CTX_set0_ctlog_store: procedure (ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl = Load_SSL_CTX_set0_ctlog_store;
  SSL_set_security_level: procedure (s: PSSL; level: TOpenSSL_C_INT); cdecl = Load_SSL_set_security_level;
  SSL_set_security_callback: procedure (s: PSSL; cb: SSL_security_callback); cdecl = Load_SSL_set_security_callback;
  SSL_get_security_callback: function (const s: PSSL): SSL_security_callback; cdecl = Load_SSL_get_security_callback;
  SSL_set0_security_ex_data: procedure (s: PSSL; ex: Pointer); cdecl = Load_SSL_set0_security_ex_data;
  SSL_get0_security_ex_data: function (const s: PSSL): Pointer; cdecl = Load_SSL_get0_security_ex_data;
  SSL_CTX_set_security_level: procedure (ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl = Load_SSL_CTX_set_security_level;
  SSL_CTX_get_security_level: function (const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_get_security_level;
  SSL_CTX_get0_security_ex_data: function (const ctx: PSSL_CTX): Pointer; cdecl = Load_SSL_CTX_get0_security_ex_data;
  SSL_CTX_set0_security_ex_data: procedure (ctx: PSSL_CTX; ex: Pointer); cdecl = Load_SSL_CTX_set0_security_ex_data;
  OPENSSL_init_ssl: function (opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl = Load_OPENSSL_init_ssl;
  SSL_free_buffers: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_free_buffers;
  SSL_alloc_buffers: function (ssl: PSSL): TOpenSSL_C_INT; cdecl = Load_SSL_alloc_buffers;
  SSL_CTX_set_session_ticket_cb: function (ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_session_ticket_cb;
  SSL_SESSION_set1_ticket_appdata: function (ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_set1_ticket_appdata;
  SSL_SESSION_get0_ticket_appdata: function (ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_SESSION_get0_ticket_appdata;
  DTLS_set_timer_cb: procedure (s: PSSL; cb: DTLS_timer_cb); cdecl = Load_DTLS_set_timer_cb;
  SSL_CTX_set_allow_early_data_cb: procedure (ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl = Load_SSL_CTX_set_allow_early_data_cb;
  SSL_set_allow_early_data_cb: procedure (s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl = Load_SSL_set_allow_early_data_cb;
  SSL_get0_peer_certificate: function (const s: PSSL): PX509; cdecl = Load_SSL_get0_peer_certificate; {introduced 3.3.0 }
  SSL_get1_peer_certificate: function (const s: PSSL): PX509; cdecl = Load_SSL_get1_peer_certificate; {introduced 3.3.0 }





{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  SSL_CTX_set_mode: function (ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_mode; {removed 1.0.0}
  SSL_CTX_clear_mode: function (ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_clear_mode; {removed 1.0.0}
  SSL_CTX_sess_set_cache_size: function (ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_sess_set_cache_size; {removed 1.0.0}
  SSL_CTX_sess_get_cache_size: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_sess_get_cache_size; {removed 1.0.0}
  SSL_CTX_set_session_cache_mode: function (ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_session_cache_mode; {removed 1.0.0}
  SSL_CTX_get_session_cache_mode: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_get_session_cache_mode; {removed 1.0.0}
  SSL_clear_num_renegotiations: function (ssl: PSSL): TOpenSSL_C_LONG; cdecl = Load_SSL_clear_num_renegotiations; {removed 1.0.0}
  SSL_total_renegotiations: function (ssl: PSSL): TOpenSSL_C_LONG; cdecl = Load_SSL_total_renegotiations; {removed 1.0.0}
  SSL_CTX_set_tmp_dh: function (ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_tmp_dh; {removed 1.0.0}
  SSL_CTX_set_tmp_ecdh: function (ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_tmp_ecdh; {removed 1.0.0}
  SSL_CTX_set_dh_auto: function (ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_dh_auto; {removed 1.0.0}
  SSL_set_dh_auto: function (s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_set_dh_auto; {removed 1.0.0}
  SSL_set_tmp_dh: function (ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl = Load_SSL_set_tmp_dh; {removed 1.0.0}
  SSL_set_tmp_ecdh: function (ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set_tmp_ecdh; {removed 1.0.0}
  SSL_CTX_add_extra_chain_cert: function (ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_add_extra_chain_cert; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs: function (ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_get_extra_chain_certs; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs_only: function (ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_get_extra_chain_certs_only; {removed 1.0.0}
  SSL_CTX_clear_extra_chain_certs: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_clear_extra_chain_certs; {removed 1.0.0}
  SSL_CTX_set0_chain: function (ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set0_chain; {removed 1.0.0}
  SSL_CTX_set1_chain: function (ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_chain; {removed 1.0.0}
  SSL_CTX_add0_chain_cert: function (ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_add0_chain_cert; {removed 1.0.0}
  SSL_CTX_add1_chain_cert: function (ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_add1_chain_cert; {removed 1.0.0}
  SSL_CTX_get0_chain_certs: function (ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_get0_chain_certs; {removed 1.0.0}
  SSL_CTX_clear_chain_certs: function (ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_clear_chain_certs; {removed 1.0.0}
  SSL_CTX_build_cert_chain: function (ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_build_cert_chain; {removed 1.0.0}
  SSL_CTX_select_current_cert: function (ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_select_current_cert; {removed 1.0.0}
  SSL_CTX_set_current_cert: function (ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set_current_cert; {removed 1.0.0}
  SSL_CTX_set0_verify_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set0_verify_cert_store; {removed 1.0.0}
  SSL_CTX_set1_verify_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_verify_cert_store; {removed 1.0.0}
  SSL_CTX_set0_chain_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set0_chain_cert_store; {removed 1.0.0}
  SSL_CTX_set1_chain_cert_store: function (ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_chain_cert_store; {removed 1.0.0}
  SSL_set0_chain: function (s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set0_chain; {removed 1.0.0}
  SSL_set1_chain: function (s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_chain; {removed 1.0.0}
  SSL_add0_chain_cert: function (s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_add0_chain_cert; {removed 1.0.0}
  SSL_add1_chain_cert: function (s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_add1_chain_cert; {removed 1.0.0}
  SSL_get0_chain_certs: function (s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get0_chain_certs; {removed 1.0.0}
  SSL_clear_chain_certs: function (s: PSSL): TOpenSSL_C_LONG; cdecl = Load_SSL_clear_chain_certs; {removed 1.0.0}
  SSL_build_cert_chain: function (s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_build_cert_chain; {removed 1.0.0}
  SSL_select_current_cert: function (s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_select_current_cert; {removed 1.0.0}
  SSL_set_current_cert: function (s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_set_current_cert; {removed 1.0.0}
  SSL_set0_verify_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set0_verify_cert_store; {removed 1.0.0}
  SSL_set1_verify_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_verify_cert_store; {removed 1.0.0}
  SSL_set0_chain_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set0_chain_cert_store; {removed 1.0.0}
  SSL_set1_chain_cert_store: function (s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_chain_cert_store; {removed 1.0.0}
  SSL_get1_groups: function (s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl = Load_SSL_get1_groups; {removed 1.0.0}
  SSL_CTX_set1_groups: function (ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_groups; {removed 1.0.0}
  SSL_CTX_set1_groups_list: function (ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_groups_list; {removed 1.0.0}
  SSL_set1_groups: function (s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_groups; {removed 1.0.0}
  SSL_set1_groups_list: function (s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_groups_list; {removed 1.0.0}
  SSL_get_shared_group: function (s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_get_shared_group; {removed 1.0.0}
  SSL_CTX_set1_sigalgs: function (ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_sigalgs; {removed 1.0.0}
  SSL_CTX_set1_sigalgs_list: function (ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_sigalgs_list; {removed 1.0.0}
  SSL_set1_sigalgs: function (s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_sigalgs; {removed 1.0.0}
  SSL_set1_sigalgs_list: function (s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_sigalgs_list; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs: function (ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_client_sigalgs; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs_list: function (ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_client_sigalgs_list; {removed 1.0.0}
  SSL_set1_client_sigalgs: function (s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_client_sigalgs; {removed 1.0.0}
  SSL_set1_client_sigalgs_list: function (s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_client_sigalgs_list; {removed 1.0.0}
  SSL_get0_certificate_types: function (s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl = Load_SSL_get0_certificate_types; {removed 1.0.0}
  SSL_CTX_set1_client_certificate_types: function (ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_CTX_set1_client_certificate_types; {removed 1.0.0}
  SSL_set1_client_certificate_types: function (s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_SSL_set1_client_certificate_types; {removed 1.0.0}
  SSL_get_signature_nid: function (s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get_signature_nid; {removed 1.0.0}
  SSL_get_peer_signature_nid: function (s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get_peer_signature_nid; {removed 1.0.0}
  SSL_get_peer_tmp_key: function (s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get_peer_tmp_key; {removed 1.0.0}
  SSL_get_tmp_key: function (s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get_tmp_key; {removed 1.0.0}
  SSL_get0_raw_cipherlist: function (s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get0_raw_cipherlist; {removed 1.0.0}
  SSL_get0_ec_point_formats: function (s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl = Load_SSL_get0_ec_point_formats; {removed 1.0.0}
  SSL_get_app_data: function (const ssl: PSSL): Pointer; cdecl = Load_SSL_get_app_data; {removed 1.0.0}
  SSL_set_app_data: function (ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl = Load_SSL_set_app_data; {removed 1.0.0}
  SSLeay_add_ssl_algorithms: function : TOpenSSL_C_INT; cdecl = Load_SSLeay_add_ssl_algorithms; {removed 1.0.0}
  SSL_load_error_strings: procedure ; cdecl = Load_SSL_load_error_strings; {removed 1.1.0}
  SSL_get_peer_certificate: function (const s: PSSL): PX509; cdecl = Load_SSL_get_peer_certificate; {removed 3.0.0}
  SSL_library_init: function : TOpenSSL_C_INT; cdecl = Load_SSL_library_init; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  SSL_CTX_set_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_clear_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_sess_set_cache_size_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_sess_get_cache_size_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_session_cache_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_session_cache_mode_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_clear_num_renegotiations_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_total_renegotiations_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_tmp_dh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_tmp_ecdh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_dh_auto_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_dh_auto_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_tmp_dh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_tmp_ecdh_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_add_extra_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_extra_chain_certs_only_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_clear_extra_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set0_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_add0_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_add1_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get0_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_clear_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_build_cert_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_select_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set0_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set0_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set0_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_add0_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_add1_chain_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_clear_chain_certs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_build_cert_chain_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_select_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_current_cert_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set0_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_verify_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set0_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_chain_cert_store_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get1_groups_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_groups_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_groups_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_groups_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_groups_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_shared_group_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_client_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_client_sigalgs_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_client_sigalgs_list_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_certificate_types_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_set1_client_certificate_types_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set1_client_certificate_types_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_signature_nid_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_peer_signature_nid_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_peer_tmp_key_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get_tmp_key_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_raw_cipherlist_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_get0_ec_point_formats_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_get_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_clear_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_clear_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_options_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_stateless_cookie_generate_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_stateless_cookie_verify_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_psk_find_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_psk_find_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_psk_use_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_psk_use_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_keylog_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_keylog_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_recv_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_app_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_set_app_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_in_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_in_before_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_is_init_finished_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLeay_add_ssl_algorithms_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  SSL_CTX_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set1_cert_store_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_pending_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_standard_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_cipher_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_protocol_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_kx_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_auth_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_handshake_digest_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_is_aead_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_has_pending_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set0_rbio_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set0_wbio_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_ciphersuites_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_ciphersuites_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_use_serverinfo_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_load_error_strings_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSL_SESSION_get_protocol_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set_protocol_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_hostname_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_hostname_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_alpn_selected_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_alpn_selected_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_has_ticket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_ticket_lifetime_hint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_ticket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set_max_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_is_resumable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_id_context_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_print_keylog_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_peer_certificate_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  SSL_CTX_set_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_default_passwd_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_default_passwd_cb_userdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_is_dtls_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set1_host_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_add1_host_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_peername_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_hostflags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_enable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_mtype_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_enable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_tlsa_add_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_dane_authority_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_dane_tlsa_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_dane_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_dane_clear_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_dane_clear_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_client_hello_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_isv2_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_legacy_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_random_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_session_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_ciphers_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_compression_methods_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get1_extensions_present_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_client_hello_get0_ext_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_waiting_for_async_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_all_async_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_changed_async_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_stateless_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_read_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_read_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_peek_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_write_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_write_early_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_early_data_status_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  TLS_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  TLS_server_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  TLS_client_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_key_update_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_key_update_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_new_session_ticket_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  SSL_CTX_set_post_handshake_auth_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_post_handshake_auth_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_verify_client_post_handshake_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_library_init_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSL_client_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_verify_dir_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_verify_file_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_state_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_client_random_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_server_random_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_master_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_master_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get_max_fragment_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_read_buffer_len_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_default_read_buffer_len_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_cipher_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CIPHER_get_digest_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_not_resumable_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_not_resumable_session_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_record_padding_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_block_padding_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_record_padding_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_record_padding_callback_arg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_block_padding_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_num_tickets_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_session_reused_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_add_ssl_module_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_config_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_config_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DTLSv1_listen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_enable_ct_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_enable_ct_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_ct_is_enabled_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_ct_is_enabled_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_default_ctlog_list_file_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_ctlog_list_file_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set0_ctlog_store_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_security_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_security_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get_security_callback_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_get0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_security_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get_security_level_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_get0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set0_security_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_init_ssl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_free_buffers_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_alloc_buffers_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_session_ticket_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_set1_ticket_appdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_SESSION_get0_ticket_appdata_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DTLS_set_timer_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_CTX_set_allow_early_data_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSL_set_allow_early_data_cb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLv2_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv2_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv2_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv3_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv3_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv3_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv23_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv23_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLv23_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_1_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_1_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_1_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_2_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_2_server_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  TLSv1_2_client_method_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSL_get0_peer_certificate_introduced = ((((((byte(3) shl 8) or byte(3)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.3.0}
  SSL_get1_peer_certificate_introduced = ((((((byte(3) shl 8) or byte(3)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.3.0}


implementation

//#   define SSL_get_peer_certificate SSL_get1_peer_certificate

uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  SSLv2_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv2_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv2_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv3_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv3_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv3_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv23_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv23_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  SSLv23_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_1_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_1_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_1_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_2_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_2_server_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
  TLSv1_2_client_method: function : PSSL_METHOD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}


function IsOpenSSL_SSLv2_Available : Boolean;
  begin
    {$if declared(SSLv2_method)}
    Result := Assigned(SSLv2_method) and
      Assigned(SSLv2_server_method) and
      Assigned(SSLv2_client_method);
    {$ELSE}
      Result := false;
    {$ifend}
  end;

  function IsOpenSSL_SSLv3_Available : Boolean;
  begin
    {$if declared(SSLv3_method)}
    Result := Assigned(SSLv3_method) and
      Assigned(SSLv3_server_method) and
      Assigned(SSLv3_client_method);
    {$ELSE}
      Result := true;
    {$ifend}
  end;

  function IsOpenSSL_SSLv23_Available : Boolean;
  begin
    {$if declared(SSLv23_method)}
    Result := Assigned(SSLv23_method) and
      Assigned(SSLv23_server_method) and
      Assigned(SSLv23_client_method);
  {$ELSE}
    Result := false;
    {$ifend}
  end;

  function IsOpenSSL_TLSv1_0_Available : Boolean;
  begin
    {$if declared(TLSv1_method)}
    Result := Assigned(TLSv1_method) and
      Assigned(TLSv1_server_method) and
      Assigned(TLSv1_client_method);
    {$ELSE}
    Result := true;
    {$ifend}
  end;

  function IsOpenSSL_TLSv1_1_Available : Boolean;
  begin
    {$if declared(TLSv1_1_method)}
    Result := Assigned(TLSv1_1_method) and
      Assigned(TLSv1_1_server_method) and
      Assigned(TLSv1_1_client_method);
    {$ELSE}
    Result := true;
    {$ifend}
  end;

  function IsOpenSSL_TLSv1_2_Available : Boolean;
  begin
    {$if declared(TLSv1_2_method)}
     Result := Assigned(TLSv1_2_method) and
      Assigned(TLSv1_2_server_method) and
      Assigned(TLSv1_2_client_method);
     {$ELSE}
     Result := true;
     {$ifend}
  end;



function HasTLS_method: boolean;
begin
  Result := (GetIOpenSSL = nil) or (TLS_method_introduced <= GetIOpenSSL.GetOpenSSLVersion);
end;


//# define SSL_CTX_set_min_proto_version(ctx, version)       SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
function SSL_CTX_set_min_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nil);
end;

//# define SSL_CTX_set_max_proto_version(ctx, version)       SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
function SSL_CTX_set_max_proto_version(ctx: PSSL_CTX; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, nil);
end;

//# define SSL_CTX_get_min_proto_version(ctx)                SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)
function SSL_CTX_get_min_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, nil);
end;

//# define SSL_CTX_get_max_proto_version(ctx)                SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)
function SSL_CTX_get_max_proto_version(ctx: PSSL_CTX): TOpenSSL_C_LONG;
begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, nil);
end;

//# define SSL_set_min_proto_version(s, version)             SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
function SSL_set_min_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nil);
end;

//# define SSL_set_max_proto_version(s, version)             SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
function SSL_set_max_proto_version(s: PSSL; version: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, nil);
end;

//# define SSL_get_min_proto_version(s)                      SSL_ctrl(s, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)
function SSL_get_min_proto_version(s: PSSL): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, nil);
end;

//# define SSL_get_max_proto_version(s)                      SSL_ctrl(s, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)
function SSL_get_max_proto_version(s: PSSL): TOpenSSL_C_LONG;
begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, nil);
end;

type
  PSTACK_OF_SSL_CIPHER = pointer;
  Plash_of_SSL_SESSION = pointer;
  SSL_CTX_stats = record
    sess_connect: TOpenSSL_C_INT;  // SSL new conn - started
    sess_connect_renegotiate: TOpenSSL_C_INT;  // SSL reneg - requested
    sess_connect_good: TOpenSSL_C_INT; // SSL new conne/reneg - finished
    sess_accept: TOpenSSL_C_INT;    // SSL new accept - started
    sess_accept_renegotiate: TOpenSSL_C_INT; // SSL reneg - requested
    sess_accept_good: TOpenSSL_C_INT;  // SSL accept/reneg - finished
    sess_miss: TOpenSSL_C_INT;  // session lookup misses
    sess_timeout: TOpenSSL_C_INT; // reuse attempt on timeouted session
    sess_cache_full: TOpenSSL_C_INT; // session removed due to full cache
    sess_hit: TOpenSSL_C_INT; // session reuse actually done
    sess_cb_hit: TOpenSSL_C_INT; // session-id that was not
                          // in the cache was
                          // passed back via the callback.  This
                          // indicates that the application is
                          // supplying session-id's from other
                          // processes - spooky :-)
  end;
  PSTACK_OF_COMP = pointer;
  PSSL_CTX_info_callback = pointer;
  PCERT = pointer;
  size_t = type integer;
  PGEN_SESSION_CB = pointer;
  PSSL_CTEX_tlsext_servername_callback = pointer;
  Ptlsext_status_cb = pointer;
  Ptlsext_ticket_key_cb = pointer;
  Pssl3_buf_freelist_st = pointer;
  PSRP_CTX = ^SRP_CTX;
  SRP_CTX = record
	//* param for all the callbacks */
	  SRP_cb_arg : Pointer;
	//* set client Hello login callback */
    TLS_ext_srp_username_callback : function(para1 : PSSL; para2 : TOpenSSL_C_INT; para3 : Pointer) : TOpenSSL_C_INT cdecl;
	//int (*TLS_ext_srp_username_callback)(SSL *, int *, void *);
	//* set SRP N/g param callback for verification */
    SRP_verify_param_callback : function(para1 : PSSL; para2 : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*SRP_verify_param_callback)(SSL *, void *);
	//* set SRP client passwd callback */
    SRP_give_srp_client_pwd_callback : function(para1 : PSSL; para2 : Pointer) : PAnsiChar cdecl;
  //	char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *);
    login : PAnsiChar;
   	N, g, s, B, A : PBIGNUM;
   	_a, _b, v : PBIGNUM;
	  info : PAnsiChar;
	  strength : TOpenSSL_C_INT;
    srp_Mask : TOpenSSL_C_ULONG;
	end;
  PSTACK_OF_SRTP_PROTECTION_PROFILE = pointer;

  _PSSL_CTX = ^SSL_CTX;
  SSL_CTX = record
    method: PSSL_METHOD;
    cipher_list: PSTACK_OF_SSL_CIPHER;
    // same as above but sorted for lookup
    cipher_list_by_id: PSTACK_OF_SSL_CIPHER;
    cert_store: PX509_STORE;
    sessions: Plash_of_SSL_SESSION;
    // a set of SSL_SESSIONs
    // Most session-ids that will be cached, default is
    // SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
    session_cache_size: TOpenSSL_C_ULONG;
    session_cache_head: PSSL_SESSION;
    session_cache_tail: PSSL_SESSION;
    // This can have one of 2 values, ored together,
    // SSL_SESS_CACHE_CLIENT,
    // SSL_SESS_CACHE_SERVER,
    // Default is SSL_SESSION_CACHE_SERVER, which means only
    // SSL_accept which cache SSL_SESSIONS.
    session_cache_mode: TOpenSSL_C_INT;
    session_timeout: TOpenSSL_C_LONG;
    // If this callback is not null, it will be called each
    // time a session id is added to the cache.  If this function
    // returns 1, it means that the callback will do a
    // SSL_SESSION_free() when it has finished using it.  Otherwise,
    // on 0, it means the callback has finished with it.
    // If remove_session_cb is not null, it will be called when
    // a session-id is removed from the cache.  After the call,
    // OpenSSL will SSL_SESSION_free() it.
    new_session_cb: function (ssl : PSSL; sess: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
    remove_session_cb: procedure (ctx : PSSL_CTX; sess : PSSL_SESSION); cdecl;
    get_session_cb: function (ssl : PSSL; data : PByte; len: TOpenSSL_C_INT; copy : POpenSSL_C_INT) : PSSL_SESSION; cdecl;
    stats : SSL_CTX_stats;

    references: TOpenSSL_C_INT;
    // if defined, these override the X509_verify_cert() calls
    app_verify_callback: function (_para1 : PX509_STORE_CTX; _para2 : Pointer) : TOpenSSL_C_INT; cdecl;
    app_verify_arg: Pointer;
    // before OpenSSL 0.9.7, 'app_verify_arg' was ignored
    // ('app_verify_callback' was called with just one argument)
    // Default password callback.
    default_passwd_callback: pem_password_cb;
    // Default password callback user data.
    default_passwd_callback_userdata: Pointer;
    // get client cert callback
    client_cert_cb: function (SSL : PSSL; x509 : PPX509; pkey : PPEVP_PKEY) : TOpenSSL_C_INT; cdecl;
    // verify cookie callback
    app_gen_cookie_cb: function (ssl : PSSL; cookie : PByte; cookie_len : TOpenSSL_C_UINT) : TOpenSSL_C_INT; cdecl;
    app_verify_cookie_cb: Pointer;
    ex_data : CRYPTO_EX_DATA;
    rsa_md5 : PEVP_MD; // For SSLv2 - name is 'ssl2-md5'
    md5: PEVP_MD; // For SSLv3/TLSv1 'ssl3-md5'
    sha1: PEVP_MD; // For SSLv3/TLSv1 'ssl3->sha1'
    extra_certs: PSTACK_OF_X509;
    comp_methods: PSTACK_OF_COMP; // stack of SSL_COMP, SSLv3/TLSv1
    // Default values used when no per-SSL value is defined follow
    info_callback: PSSL_CTX_info_callback; // used if SSL's info_callback is NULL
    // what we put in client cert requests
    client_CA : PSTACK_OF_X509_NAME;
    // Default values to use in SSL structures follow (these are copied by SSL_new)
    options : TOpenSSL_C_ULONG;
    mode : TOpenSSL_C_ULONG;
    max_cert_list : TOpenSSL_C_LONG;
    cert : PCERT;
    read_ahead : TOpenSSL_C_INT;
    // callback that allows applications to peek at protocol messages
    msg_callback : procedure (write_p, version, content_type : TOpenSSL_C_INT; const buf : Pointer; len : size_t; ssl : PSSL; arg : Pointer); cdecl;
    msg_callback_arg : Pointer;
    verify_mode : TOpenSSL_C_INT;
    sid_ctx_length : TOpenSSL_C_UINT;
    sid_ctx : array[0..SSL_MAX_SID_CTX_LENGTH - 1] of AnsiChar;
    default_verify_callback : function(ok : TOpenSSL_C_INT; ctx : PX509_STORE_CTX) : TOpenSSL_C_INT; cdecl; // called 'verify_callback' in the SSL
    // Default generate session ID callback.
    generate_session_id : PGEN_SESSION_CB;
    param : PX509_VERIFY_PARAM;
    {$IFDEF OMIT_THIS}
    purpose : TOpenSSL_C_INT;  // Purpose setting
    trust : TOpenSSL_C_INT;    // Trust setting
    {$ENDIF}

    quiet_shutdown : TOpenSSL_C_INT;
	//* Maximum amount of data to send in one fragment.
	// * actual record size can be more than this due to
	// * padding and MAC overheads.
	// */
	  max_send_fragment : TOpenSSL_C_UINT;
    {$IFNDEF OPENSSL_ENGINE}
	///* Engine to pass requests for client certs to
	// */
	  client_cert_engine : PENGINE;
    {$ENDIF}
    {$IFNDEF OPENSSL_NO_TLSEXT}
//* TLS extensions servername callback */
    tlsext_servername_callback : PSSL_CTEX_tlsext_servername_callback;
    tlsext_servername_arg : Pointer;
    //* RFC 4507 session ticket keys */
    tlsext_tick_key_name : array [0..(16-1)] of AnsiChar;
    tlsext_tick_hmac_key : array [0..(16-1)] of AnsiChar;
    tlsext_tick_aes_key : array [0..(16-1)] of AnsiChar;
	//* Callback to support customisation of ticket key setting */
 //	int (*tlsext_ticket_key_cb)(SSL *ssl,
 //					unsigned char *name, unsigned char *iv,
 //					EVP_CIPHER_CTX *ectx,
 //					HMAC_CTX *hctx, int enc);
    tlsext_ticket_key_cb : Ptlsext_ticket_key_cb;
	//* certificate status request info */
	//* Callback for status request */
	//int (*tlsext_status_cb)(SSL *ssl, void *arg);
    tlsext_status_cb : Ptlsext_status_cb;
	  tlsext_status_arg : Pointer;
    {$ENDIF}
	//* draft-rescorla-tls-opaque-prf-input-00.txt information */
     tlsext_opaque_prf_input_callback : function(para1 : PSSL; peerinput : Pointer; len : size_t; arg : Pointer ) : TOpenSSL_C_INT cdecl;
	//int (*tlsext_opaque_prf_input_callback)(SSL *, void *peerinput, size_t len, void *arg);
     tlsext_opaque_prf_input_callback_arg : Pointer;

{$ifndef OPENSSL_NO_PSK}
	   psk_identity_hint : PAnsiChar;
     psk_client_callback : function (ssl : PSSL; hint : PAnsiChar;
       identity : PAnsiChar; max_identity_len : TOpenSSL_C_UINT;
       psk : PAnsiChar; max_psk_len : TOpenSSL_C_UINT ) : TOpenSSL_C_UINT cdecl;
 //	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
//		unsigned int max_identity_len, unsigned char *psk,
//		unsigned int max_psk_len);
     psk_server_callback : function (ssl : PSSL; identity, psk : PAnsiChar; max_psk_len : TOpenSSL_C_UINT) : TOpenSSL_C_UINT cdecl;
//	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
//		unsigned char *psk, unsigned int max_psk_len);
{$endif}

{$ifndef OPENSSL_NO_BUF_FREELISTS}
	  freelist_max_len : TOpenSSL_C_UINT;
	  wbuf_freelist : Pssl3_buf_freelist_st;
	  rbuf_freelist : Pssl3_buf_freelist_st;
{$endif}
{$ifndef OPENSSL_NO_SRP}
	  srp_ctx : SRP_CTX; //* ctx for SRP authentication */
{$endif}

{$ifndef OPENSSL_NO_TLSEXT}
//# ifndef OPENSSL_NO_NEXTPROTONEG
	//* Next protocol negotiation information */
	//* (for experimental NPN extension). */

	//* For a server, this contains a callback function by which the set of
	// * advertised protocols can be provided. */
    next_protos_advertised_cb : function(s : PSSL; out but : PAnsiChar;
     out len : TOpenSSL_C_UINT; arg : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,
//			                 unsigned int *len, void *arg);
	  next_protos_advertised_cb_arg : Pointer;
	//* For a client, this contains a callback function that selects the
	// * next protocol from the list provided by the server. */
    next_proto_select_cb : function(s : PSSL; out _out : PAnsiChar;
      outlen : PAnsiChar;
      _in : PAnsiChar;
      inlen : TOpenSSL_C_UINT;
      arg : Pointer) : TOpenSSL_C_INT cdecl;
//	int (*next_proto_select_cb)(SSL *s, unsigned char **out,
//				    unsigned char *outlen,
//				    const unsigned char *in,
//				    unsigned int inlen,
//				    void *arg);
	  next_proto_select_cb_arg : Pointer;
//# endif
        //* SRTP profiles we are willing to do from RFC 5764 */
      srtp_profiles : PSTACK_OF_SRTP_PROTECTION_PROFILE;
{$endif}
  end;

const
  SSL_CTRL_OPTIONS = 32;
  SSL_CTRL_CLEAR_OPTIONS = 77;


const
  SSL_MAX_KRB5_PRINCIPAL_LENGTH = 256;

type
   PSESS_CERT = pointer;
  _PSSL_SESSION = ^_SSL_SESSION;
  _SSL_SESSION = record
    ssl_version : TOpenSSL_C_INT; // what ssl version session info is being kept in here?
    // only really used in SSLv2
    key_arg_length: TOpenSSL_C_UINT;
    key_arg: Array[0..SSL_MAX_KEY_ARG_LENGTH-1] of Byte;
    master_key_length: TOpenSSL_C_INT;
    master_key: Array[0..SSL_MAX_MASTER_KEY_LENGTH-1] of Byte;
    // session_id - valid?
    session_id_length: TOpenSSL_C_UINT;
    session_id: Array[0..SSL_MAX_SSL_SESSION_ID_LENGTH-1] of Byte;
    // this is used to determine whether the session is being reused in
    // the appropriate context. It is up to the application to set this,
    // via SSL_new
    sid_ctx_length: TOpenSSL_C_UINT;
    sid_ctx: array[0..SSL_MAX_SID_CTX_LENGTH-1] of Byte;
    {$IFNDEF OPENSSL_NO_KRB5}
    krb5_client_princ_len: TOpenSSL_C_UINT;
    krb5_client_princ: array[0..SSL_MAX_KRB5_PRINCIPAL_LENGTH-1] of Byte;
    {$ENDIF}
{$ifndef OPENSSL_NO_PSK}
	  psk_identity_hint : PAnsiChar;
	  psk_identity : PAnsiChar;
{$endif}
    not_resumable: TOpenSSL_C_INT;
    // The cert is the certificate used to establish this connection
    sess_cert :  PSESS_CERT;

	//* This is the cert for the other end.
	// * On clients, it will be the same as sess_cert->peer_key->x509
	// * (the latter is not enough as sess_cert is not retained
	// * in the external representation of sessions, see ssl_asn1.c). */
	  peer : PX509;
	//* when app_verify_callback accepts a session where the peer's certificate
	// * is not ok, we must remember the error for session reuse: */
	  verify_result : TOpenSSL_C_LONG; //* only for servers */
	  references : TOpenSSL_C_INT;
	  timeout : TOpenSSL_C_LONG;
	  time : TOpenSSL_C_LONG;
	  compress_meth : TOpenSSL_C_UINT;	//* Need to lookup the method */

	  cipher : PSSL_CIPHER;
	  cipher_id : TOpenSSL_C_ULONG;	//* when ASN.1 loaded, this
					// * needs to be used to load
					// * the 'cipher' structure */
    ciphers : PSTACK_OF_SSL_CIPHER; //* shared ciphers? */
    ex_data : CRYPTO_EX_DATA; // application specific data */
	//* These are used to make removal of session-ids more
	// * efficient and to implement a maximum cache size. */
	  prev, next : PSSL_SESSION;

    {$IFNDEF OPENSSL_NO_TLSEXT}
    tlsext_hostname : PAnsiChar;
      {$IFDEF OPENSSL_NO_EC}
	  tlsext_ecpointformatlist_length : size_t;
	  tlsext_ecpointformatlist : PAnsiChar; //* peer's list */
	  tlsext_ellipticcurvelist_length : size_t;
	  tlsext_ellipticcurvelist : PAnsiChar; //* peer's list */
      {$ENDIF} //* OPENSSL_NO_EC */

 //* RFC4507 info */
    tlsext_tick : PAnsiChar;//* Session ticket */
    tlsext_ticklen : size_t;//* Session ticket length */
    tlsext_tick_lifetime_hint : TOpenSSL_C_LONG;//* Session lifetime hint in seconds */
    {$ENDIF}
{$ifndef OPENSSL_NO_SRP}
	  srp_username : PAnsiChar;
{$endif}
  end;



threadvar SelectedMethod: TOpenSSL_Version;

procedure OpenSSL_SetMethod(aMethod: TOpenSSL_Version);
begin
  SelectedMethod := aMethod;
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function SSL_get_peer_certificate(const s: PSSL): PX509;

begin
  Result := SSL_get1_peer_certificate(s);
end;


//# define SSL_CTX_set_mode(ctx,op)      SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)


function SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, nil);
end;

//# define SSL_CTX_clear_mode(ctx,op)   SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)


function SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, op, nil);
end;

//# define SSL_CTX_sess_set_cache_size(ctx,t)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)


function SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, t, nil);
end;

//# define SSL_CTX_sess_get_cache_size(ctx)           SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)


function SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_SIZE, 0, nil);
end;

//# define SSL_CTX_set_session_cache_mode(ctx,m)      SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)


function SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, nil);
end;

//# define SSL_CTX_get_session_cache_mode(ctx)        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)


function SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, nil);
end;

//# define SSL_num_renegotiations(ssl)                       SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)


function SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_total_renegotiations(ssl)                     SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)


function SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_CTX_set_tmp_dh(ctx,dh)                        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_CTX_set_tmp_ecdh(ctx,ecdh)                    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_set_dh_auto(ctx, onoff)                   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_dh_auto(s, onoff)                         SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_tmp_dh(ssl,dh)                            SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_set_tmp_ecdh(ssl,ecdh)                        SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_add_extra_chain_cert(ctx,x509)            SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))


function SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_get_extra_chain_certs(ctx,px509)          SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)


function SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_get_extra_chain_certs_only(ctx,px509)     SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)


function SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 1, px509);
end;

//# define SSL_CTX_clear_extra_chain_certs(ctx)              SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)


function SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0, nil);
end;

//# define SSL_CTX_set0_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)(sk))


function SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_CTX_set1_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)(sk))


function SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_CTX_add0_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_add1_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_CTX_get0_chain_certs(ctx,px509)               SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_clear_chain_certs(ctx)                    SSL_CTX_set0_chain(ctx,NULL)


function SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_set0_chain(ctx, nil);
end;

//# define SSL_CTX_build_cert_chain(ctx, flags)              SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_CTX_select_current_cert(ctx,x509)             SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_CTX_set_current_cert(ctx, op)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_CTX_set0_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_CTX_set0_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,0,(char *)(sk))


function SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_set1_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,1,(char *)(sk))


function SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_add0_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_add1_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_get0_chain_certs(s,px509)                     SSL_ctrl(s,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_clear_chain_certs(s)                          SSL_set0_chain(s,NULL)


function SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG;

begin
  Result := SSL_set0_chain(s, nil);
end;

//# define SSL_build_cert_chain(s, flags)                    SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_select_current_cert(s,x509)                   SSL_ctrl(s,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_set_current_cert(s,op)                        SSL_ctrl(s,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_set0_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_set1_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_set1_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_get1_groups(s, glist)                         SSL_ctrl(s,SSL_CTRL_GET_GROUPS,0,(TOpenSSL_C_INT*)(glist))


function SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_GROUPS, 0, glist);
end;

//# define SSL_CTX_set1_groups(ctx, glist, glistlen)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_CTX_set1_groups_list(ctx, s)                  SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))


function SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, s);
end;

//# define SSL_set1_groups(s, glist, glistlen)               SSL_ctrl(s,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_set1_groups_list(s, str)                      SSL_ctrl(s,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(str))


function SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS_LIST, 0, str);
end;

//# define SSL_get_shared_group(s, n)                        SSL_ctrl(s,SSL_CTRL_GET_SHARED_GROUP,n,NULL)


function SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SHARED_GROUP, n, nil);
end;

//# define SSL_CTX_set1_sigalgs(ctx, slist, slistlen)        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_sigalgs_list(ctx, s)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(s))


function SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_sigalgs(s, slist, slistlen)              SSL_ctrl(s,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_sigalgs_list(s, str)                     SSL_ctrl(s,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(str))


function SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS_LIST, 0, str);
end;

//# define SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen) SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_client_sigalgs_list(ctx, s)          SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(s))


function SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_client_sigalgs(s, slist, slistlen)       SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_client_sigalgs_list(s, str)              SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(str))


function SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, str);
end;

//# define SSL_get0_certificate_types(s, clist)              SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)(clist))


function SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, clist);
end;

//# define SSL_CTX_set1_client_certificate_types(ctx, clist, clistlen)   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen, (char *)(clist))


function SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_set1_client_certificate_types(s, clist, clistlen)         SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)(clist))


function SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_get_signature_nid(s, pn)                      SSL_ctrl(s,SSL_CTRL_GET_SIGNATURE_NID,0,pn)


function SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_signature_nid(s, pn)                 SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)


function SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_tmp_key(s, pk)                       SSL_ctrl(s,SSL_CTRL_GET_PEER_TMP_KEY,0,pk)


function SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_TMP_KEY, 0, pk);
end;

//# define SSL_get_tmp_key(s, pk)                            SSL_ctrl(s,SSL_CTRL_GET_TMP_KEY,0,pk)


function SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_TMP_KEY, 0, pk);
end;

//# define SSL_get0_raw_cipherlist(s, plst)                  SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst)


function SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_RAW_CIPHERLIST, 0, plst);
end;

//# define SSL_get0_ec_point_formats(s, plst)                SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst)


function SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_EC_POINT_FORMATS, 0, plst);
end;


function SSL_get_app_data(const ssl: PSSL): Pointer;

begin
  Result := SSL_get_ex_data(ssl,0);
end;



procedure SSL_load_error_strings;
 
begin
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS,nil); 
end;



function SSL_library_init: TOpenSSL_C_INT;

begin
  Result := OPENSSL_init_ssl(0, nil);
end;



function SSLeay_add_ssl_algorithms: TOpenSSL_C_INT;

begin
  Result := SSL_library_init;
end;



function SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT;

begin
  Result := SSL_set_ex_data(ssl,0,data);
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl;

begin
  Result := SSL_get1_peer_certificate(s);
end;


//# define SSL_CTX_set_mode(ctx,op)      SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)


function COMPAT_SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, nil);
end;

//# define SSL_CTX_clear_mode(ctx,op)   SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)


function COMPAT_SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, op, nil);
end;

//# define SSL_CTX_sess_set_cache_size(ctx,t)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)


function COMPAT_SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, t, nil);
end;

//# define SSL_CTX_sess_get_cache_size(ctx)           SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)


function COMPAT_SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_SIZE, 0, nil);
end;

//# define SSL_CTX_set_session_cache_mode(ctx,m)      SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)


function COMPAT_SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, nil);
end;

//# define SSL_CTX_get_session_cache_mode(ctx)        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)


function COMPAT_SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, nil);
end;

//# define SSL_num_renegotiations(ssl)                       SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)


function COMPAT_SSL_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_GET_NUM_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_clear_num_renegotiations(ssl)                 SSL_ctrl((ssl),SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)


function COMPAT_SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_total_renegotiations(ssl)                     SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)


function COMPAT_SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, nil);
end;

//# define SSL_CTX_set_tmp_dh(ctx,dh)                        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function COMPAT_SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_CTX_set_tmp_ecdh(ctx,ecdh)                    SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function COMPAT_SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_set_dh_auto(ctx, onoff)                   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function COMPAT_SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_dh_auto(s, onoff)                         SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,NULL)


function COMPAT_SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_DH_AUTO, onoff, nil);
end;

//# define SSL_set_tmp_dh(ssl,dh)                            SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))


function COMPAT_SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_DH, 0, dh);
end;

//# define SSL_set_tmp_ecdh(ssl,ecdh)                        SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))


function COMPAT_SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
end;

//# define SSL_CTX_add_extra_chain_cert(ctx,x509)            SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))


function COMPAT_SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_get_extra_chain_certs(ctx,px509)          SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)


function COMPAT_SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_get_extra_chain_certs_only(ctx,px509)     SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)


function COMPAT_SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 1, px509);
end;

//# define SSL_CTX_clear_extra_chain_certs(ctx)              SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)


function COMPAT_SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0, nil);
end;

//# define SSL_CTX_set0_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)(sk))


function COMPAT_SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_CTX_set1_chain(ctx,sk)                        SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)(sk))


function COMPAT_SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_CTX_add0_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function COMPAT_SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_CTX_add1_chain_cert(ctx,x509)                 SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function COMPAT_SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_CTX_get0_chain_certs(ctx,px509)               SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function COMPAT_SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_CTX_clear_chain_certs(ctx)                    SSL_CTX_set0_chain(ctx,NULL)


function COMPAT_SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_set0_chain(ctx, nil);
end;

//# define SSL_CTX_build_cert_chain(ctx, flags)              SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function COMPAT_SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_CTX_select_current_cert(ctx,x509)             SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function COMPAT_SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_CTX_set_current_cert(ctx, op)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function COMPAT_SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_CTX_set0_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_verify_cert_store(ctx,st)            SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_CTX_set0_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_CTX_set1_chain_cert_store(ctx,st)             SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,0,(char *)(sk))


function COMPAT_SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 0, sk);
end;

//# define SSL_set1_chain(s,sk)                              SSL_ctrl(s,SSL_CTRL_CHAIN,1,(char *)(sk))


function COMPAT_SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN, 1, sk);
end;

//# define SSL_add0_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))


function COMPAT_SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 0, x509);
end;

//# define SSL_add1_chain_cert(s,x509)                       SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))


function COMPAT_SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_CHAIN_CERT, 1, x509);
end;

//# define SSL_get0_chain_certs(s,px509)                     SSL_ctrl(s,SSL_CTRL_GET_CHAIN_CERTS,0,px509)


function COMPAT_SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CHAIN_CERTS, 0, px509);
end;

//# define SSL_clear_chain_certs(s)                          SSL_set0_chain(s,NULL)


function COMPAT_SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_set0_chain(s, nil);
end;

//# define SSL_build_cert_chain(s, flags)                    SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)


function COMPAT_SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_BUILD_CERT_CHAIN, flags, nil);
end;

//# define SSL_select_current_cert(s,x509)                   SSL_ctrl(s,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))


function COMPAT_SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SELECT_CURRENT_CERT, 0, x509);
end;

//# define SSL_set_current_cert(s,op)                        SSL_ctrl(s,SSL_CTRL_SET_CURRENT_CERT, op, NULL)


function COMPAT_SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CURRENT_CERT, op, nil);
end;

//# define SSL_set0_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 0, st);
end;

//# define SSL_set1_verify_cert_store(s,st)                  SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st);
end;

//# define SSL_set0_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))


function COMPAT_SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 0, st);
end;

//# define SSL_set1_chain_cert_store(s,st)                   SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))


function COMPAT_SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st);
end;

//# define SSL_get1_groups(s, glist)                         SSL_ctrl(s,SSL_CTRL_GET_GROUPS,0,(TOpenSSL_C_INT*)(glist))


function COMPAT_SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_GROUPS, 0, glist);
end;

//# define SSL_CTX_set1_groups(ctx, glist, glistlen)         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function COMPAT_SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_CTX_set1_groups_list(ctx, s)                  SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))


function COMPAT_SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, s);
end;

//# define SSL_set1_groups(s, glist, glistlen)               SSL_ctrl(s,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))


function COMPAT_SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS, glistlen, glist);
end;

//# define SSL_set1_groups_list(s, str)                      SSL_ctrl(s,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(str))


function COMPAT_SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_GROUPS_LIST, 0, str);
end;

//# define SSL_get_shared_group(s, n)                        SSL_ctrl(s,SSL_CTRL_GET_SHARED_GROUP,n,NULL)


function COMPAT_SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SHARED_GROUP, n, nil);
end;

//# define SSL_CTX_set1_sigalgs(ctx, slist, slistlen)        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_sigalgs_list(ctx, s)                 SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(s))


function COMPAT_SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_sigalgs(s, slist, slistlen)              SSL_ctrl(s,SSL_CTRL_SET_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_sigalgs_list(s, str)                     SSL_ctrl(s,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(str))


function COMPAT_SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_SIGALGS_LIST, 0, str);
end;

//# define SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen) SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_CTX_set1_client_sigalgs_list(ctx, s)          SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(s))


function COMPAT_SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, s);
end;

//# define SSL_set1_client_sigalgs(s, slist, slistlen)       SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(TOpenSSL_C_INT *)(slist))


function COMPAT_SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS, slistlen, slist);
end;

//# define SSL_set1_client_sigalgs_list(s, str)              SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(str))


function COMPAT_SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, str);
end;

//# define SSL_get0_certificate_types(s, clist)              SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)(clist))


function COMPAT_SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, clist);
end;

//# define SSL_CTX_set1_client_certificate_types(ctx, clist, clistlen)   SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen, (char *)(clist))


function COMPAT_SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_set1_client_certificate_types(s, clist, clistlen)         SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)(clist))


function COMPAT_SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_SET_CLIENT_CERT_TYPES, clistlen, clist);
end;

//# define SSL_get_signature_nid(s, pn)                      SSL_ctrl(s,SSL_CTRL_GET_SIGNATURE_NID,0,pn)


function COMPAT_SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_signature_nid(s, pn)                 SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)


function COMPAT_SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, pn);
end;

//# define SSL_get_peer_tmp_key(s, pk)                       SSL_ctrl(s,SSL_CTRL_GET_PEER_TMP_KEY,0,pk)


function COMPAT_SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_PEER_TMP_KEY, 0, pk);
end;

//# define SSL_get_tmp_key(s, pk)                            SSL_ctrl(s,SSL_CTRL_GET_TMP_KEY,0,pk)


function COMPAT_SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_TMP_KEY, 0, pk);
end;

//# define SSL_get0_raw_cipherlist(s, plst)                  SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst)


function COMPAT_SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_RAW_CIPHERLIST, 0, plst);
end;

//# define SSL_get0_ec_point_formats(s, plst)                SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst)


function COMPAT_SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_ctrl(s, SSL_CTRL_GET_EC_POINT_FORMATS, 0, plst);
end;


function COMPAT_SSL_get_app_data(const ssl: PSSL): Pointer; cdecl;

begin
  Result := SSL_get_ex_data(ssl,0);
end;



procedure COMPAT_SSL_load_error_strings; cdecl;
 
begin
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS,nil); 
end;



function COMPAT_SSL_library_init: TOpenSSL_C_INT; cdecl;

begin
  Result := OPENSSL_init_ssl(0, nil);
end;



function COMPAT_SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; cdecl;

begin
  Result := SSL_library_init;
end;



function COMPAT_SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := SSL_set_ex_data(ssl,0,data);
end;


function COMPAT_SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl;

begin
  Result := _PSSL_CTX(ctx)^.default_passwd_callback;
end;



function COMPAT_SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl;

begin
  Result := _PSSL_CTX(ctx)^.default_passwd_callback_userdata;
end;



procedure COMPAT_SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl;

begin
  _PSSL_CTX(ctx)^.default_passwd_callback := cb;
end;



procedure COMPAT_SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl;

begin
  _PSSL_CTX(ctx)^.default_passwd_callback_userdata := u;
end;

//* Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value,
// * they cannot be used to clear bits. */



function COMPAT_SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, nil);
end;



function COMPAT_SSL_CTX_clear_options(ctx : PSSL_CTX; op : TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_OPTIONS,op,nil);
end;



function COMPAT_SSL_CTX_get_options(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;

begin
  Result := SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS,0,nil);
end;



function COMPAT_SSL_CTX_get_cert_store(const ctx: PSSL_CTX): PX509_STORE; cdecl;

begin
  Result :=  _PSSL_CTX(ctx)^.cert_store;
end;


function COMPAT_SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;

begin
  Result := _PSSL_SESSION(s).ssl_version;
end;



function COMPAT_OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;

begin
  if opts and OPENSSL_INIT_LOAD_SSL_STRINGS <> 0 then
    SSL_load_error_strings;
  SSL_library_init;
  Result := OPENSSL_init_crypto(opts,settings);
end;


function COMPAT_TLS_method: PSSL_METHOD; cdecl;

begin
  Result := nil;
  case SelectedMethod of
    sslvSSLv2:
        if Assigned(SSLv2_method) then
          Result := SSLv2_method();

    sslvSSLv23:
          if Assigned(SSLv23_client_method) then
            Result := SSLv23_client_method();

    sslvSSLv3:
        if Assigned(SSLv3_method) then
          Result := SSLv3_method();

    sslvTLSv1:
        if Assigned(TLSv1_method) then
          Result := TLSv1_method();

    sslvTLSv1_1:
        if Assigned(TLSv1_1_method) then
          Result := TLSv1_1_method()
        else
        if Assigned(TLSv1_method) then
          Result := TLSv1_method();

    sslvTLSv1_2:
        if Assigned(TLSv1_2_method) then
          Result := TLSv1_2_method()
        else
        if Assigned(TLSv1_method) then
          Result := TLSv1_method();
  end;
end;



function COMPAT_TLS_server_method: PSSL_METHOD; cdecl;

begin
  Result := nil;
  case SelectedMethod of
    sslvSSLv2:
          if Assigned(SSLv2_server_method) then
            Result := SSLv2_server_method();

    sslvSSLv23:
          if Assigned(SSLv23_server_method) then
            Result := SSLv23_server_method();

    sslvSSLv3:
          if Assigned(SSLv3_server_method) then
            Result := SSLv3_server_method();

    sslvTLSv1:
      if Assigned(TLSv1_server_method) then
        Result := TLSv1_server_method();

    sslvTLSv1_1:
          if Assigned(TLSv1_1_server_method) then
            Result := TLSv1_1_server_method()
          else
          if Assigned(TLSv1_server_method) then
            Result := TLSv1_server_method();

    sslvTLSv1_2:
          if Assigned(TLSv1_2_server_method) then
            Result := TLSv1_2_server_method()
          else
          if Assigned(TLSv1_server_method) then
            Result := TLSv1_server_method();
  end;
end;



function COMPAT_TLS_client_method: PSSL_METHOD; cdecl;

begin
  Result := nil;
  case SelectedMethod of
    sslvSSLv2:
          if Assigned(SSLv2_client_method) then
            Result := SSLv2_client_method();

    sslvSSLv23:
          if Assigned(SSLv23_client_method) then
            Result := SSLv23_client_method();

    sslvSSLv3:
          if Assigned(SSLv3_client_method) then
            Result := SSLv3_client_method();

    sslvTLSv1:
      if Assigned(TLSv1_client_method) then
        Result := TLSv1_client_method();

    sslvTLSv1_1:
          if Assigned(TLSv1_1_client_method) then
            Result := TLSv1_1_client_method()
          else
          if Assigned(TLSv1_client_method) then
            Result := TLSv1_client_method();

    sslvTLSv1_2:
          if Assigned(TLSv1_2_client_method) then
            Result := TLSv1_2_client_method()
          else
          if Assigned(TLSv1_client_method) then
            Result := TLSv1_client_method();
  end;
end;



function COMPAT_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;

begin
  Result := SSL_CTX_use_certificate_file(ctx, file_, SSL_FILETYPE_PEM);
end;



function COMPAT_SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl;

begin
// no op
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_CTX_set_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_mode := LoadLibSSLFunction('SSL_CTX_set_mode');
  if not assigned(SSL_CTX_set_mode) then
    SSL_CTX_set_mode := @COMPAT_SSL_CTX_set_mode;
  Result := SSL_CTX_set_mode(ctx,op);
end;

function Load_SSL_CTX_clear_mode(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_clear_mode := LoadLibSSLFunction('SSL_CTX_clear_mode');
  if not assigned(SSL_CTX_clear_mode) then
    SSL_CTX_clear_mode := @COMPAT_SSL_CTX_clear_mode;
  Result := SSL_CTX_clear_mode(ctx,op);
end;

function Load_SSL_CTX_sess_set_cache_size(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_sess_set_cache_size := LoadLibSSLFunction('SSL_CTX_sess_set_cache_size');
  if not assigned(SSL_CTX_sess_set_cache_size) then
    SSL_CTX_sess_set_cache_size := @COMPAT_SSL_CTX_sess_set_cache_size;
  Result := SSL_CTX_sess_set_cache_size(ctx,t);
end;

function Load_SSL_CTX_sess_get_cache_size(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_sess_get_cache_size := LoadLibSSLFunction('SSL_CTX_sess_get_cache_size');
  if not assigned(SSL_CTX_sess_get_cache_size) then
    SSL_CTX_sess_get_cache_size := @COMPAT_SSL_CTX_sess_get_cache_size;
  Result := SSL_CTX_sess_get_cache_size(ctx);
end;

function Load_SSL_CTX_set_session_cache_mode(ctx: PSSL_CTX; m: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_session_cache_mode := LoadLibSSLFunction('SSL_CTX_set_session_cache_mode');
  if not assigned(SSL_CTX_set_session_cache_mode) then
    SSL_CTX_set_session_cache_mode := @COMPAT_SSL_CTX_set_session_cache_mode;
  Result := SSL_CTX_set_session_cache_mode(ctx,m);
end;

function Load_SSL_CTX_get_session_cache_mode(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_get_session_cache_mode := LoadLibSSLFunction('SSL_CTX_get_session_cache_mode');
  if not assigned(SSL_CTX_get_session_cache_mode) then
    SSL_CTX_get_session_cache_mode := @COMPAT_SSL_CTX_get_session_cache_mode;
  Result := SSL_CTX_get_session_cache_mode(ctx);
end;

function Load_SSL_clear_num_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;
begin
  SSL_clear_num_renegotiations := LoadLibSSLFunction('SSL_clear_num_renegotiations');
  if not assigned(SSL_clear_num_renegotiations) then
    SSL_clear_num_renegotiations := @COMPAT_SSL_clear_num_renegotiations;
  Result := SSL_clear_num_renegotiations(ssl);
end;

function Load_SSL_total_renegotiations(ssl: PSSL): TOpenSSL_C_LONG; cdecl;
begin
  SSL_total_renegotiations := LoadLibSSLFunction('SSL_total_renegotiations');
  if not assigned(SSL_total_renegotiations) then
    SSL_total_renegotiations := @COMPAT_SSL_total_renegotiations;
  Result := SSL_total_renegotiations(ssl);
end;

function Load_SSL_CTX_set_tmp_dh(ctx: PSSL_CTX; dh: PDH): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_tmp_dh := LoadLibSSLFunction('SSL_CTX_set_tmp_dh');
  if not assigned(SSL_CTX_set_tmp_dh) then
    SSL_CTX_set_tmp_dh := @COMPAT_SSL_CTX_set_tmp_dh;
  Result := SSL_CTX_set_tmp_dh(ctx,dh);
end;

function Load_SSL_CTX_set_tmp_ecdh(ctx: PSSL_CTX; ecdh: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_tmp_ecdh := LoadLibSSLFunction('SSL_CTX_set_tmp_ecdh');
  if not assigned(SSL_CTX_set_tmp_ecdh) then
    SSL_CTX_set_tmp_ecdh := @COMPAT_SSL_CTX_set_tmp_ecdh;
  Result := SSL_CTX_set_tmp_ecdh(ctx,ecdh);
end;

function Load_SSL_CTX_set_dh_auto(ctx: PSSL_CTX; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_dh_auto := LoadLibSSLFunction('SSL_CTX_set_dh_auto');
  if not assigned(SSL_CTX_set_dh_auto) then
    SSL_CTX_set_dh_auto := @COMPAT_SSL_CTX_set_dh_auto;
  Result := SSL_CTX_set_dh_auto(ctx,onoff);
end;

function Load_SSL_set_dh_auto(s: PSSL; onoff: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set_dh_auto := LoadLibSSLFunction('SSL_set_dh_auto');
  if not assigned(SSL_set_dh_auto) then
    SSL_set_dh_auto := @COMPAT_SSL_set_dh_auto;
  Result := SSL_set_dh_auto(s,onoff);
end;

function Load_SSL_set_tmp_dh(ssl: PSSL; dh: PDH): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set_tmp_dh := LoadLibSSLFunction('SSL_set_tmp_dh');
  if not assigned(SSL_set_tmp_dh) then
    SSL_set_tmp_dh := @COMPAT_SSL_set_tmp_dh;
  Result := SSL_set_tmp_dh(ssl,dh);
end;

function Load_SSL_set_tmp_ecdh(ssl: PSSL; ecdh: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set_tmp_ecdh := LoadLibSSLFunction('SSL_set_tmp_ecdh');
  if not assigned(SSL_set_tmp_ecdh) then
    SSL_set_tmp_ecdh := @COMPAT_SSL_set_tmp_ecdh;
  Result := SSL_set_tmp_ecdh(ssl,ecdh);
end;

function Load_SSL_CTX_add_extra_chain_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_add_extra_chain_cert := LoadLibSSLFunction('SSL_CTX_add_extra_chain_cert');
  if not assigned(SSL_CTX_add_extra_chain_cert) then
    SSL_CTX_add_extra_chain_cert := @COMPAT_SSL_CTX_add_extra_chain_cert;
  Result := SSL_CTX_add_extra_chain_cert(ctx,x509);
end;

function Load_SSL_CTX_get_extra_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_get_extra_chain_certs := LoadLibSSLFunction('SSL_CTX_get_extra_chain_certs');
  if not assigned(SSL_CTX_get_extra_chain_certs) then
    SSL_CTX_get_extra_chain_certs := @COMPAT_SSL_CTX_get_extra_chain_certs;
  Result := SSL_CTX_get_extra_chain_certs(ctx,px509);
end;

function Load_SSL_CTX_get_extra_chain_certs_only(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_get_extra_chain_certs_only := LoadLibSSLFunction('SSL_CTX_get_extra_chain_certs_only');
  if not assigned(SSL_CTX_get_extra_chain_certs_only) then
    SSL_CTX_get_extra_chain_certs_only := @COMPAT_SSL_CTX_get_extra_chain_certs_only;
  Result := SSL_CTX_get_extra_chain_certs_only(ctx,px509);
end;

function Load_SSL_CTX_clear_extra_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_clear_extra_chain_certs := LoadLibSSLFunction('SSL_CTX_clear_extra_chain_certs');
  if not assigned(SSL_CTX_clear_extra_chain_certs) then
    SSL_CTX_clear_extra_chain_certs := @COMPAT_SSL_CTX_clear_extra_chain_certs;
  Result := SSL_CTX_clear_extra_chain_certs(ctx);
end;

function Load_SSL_CTX_set0_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set0_chain := LoadLibSSLFunction('SSL_CTX_set0_chain');
  if not assigned(SSL_CTX_set0_chain) then
    SSL_CTX_set0_chain := @COMPAT_SSL_CTX_set0_chain;
  Result := SSL_CTX_set0_chain(ctx,sk);
end;

function Load_SSL_CTX_set1_chain(ctx: PSSL_CTX; sk: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_chain := LoadLibSSLFunction('SSL_CTX_set1_chain');
  if not assigned(SSL_CTX_set1_chain) then
    SSL_CTX_set1_chain := @COMPAT_SSL_CTX_set1_chain;
  Result := SSL_CTX_set1_chain(ctx,sk);
end;

function Load_SSL_CTX_add0_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_add0_chain_cert := LoadLibSSLFunction('SSL_CTX_add0_chain_cert');
  if not assigned(SSL_CTX_add0_chain_cert) then
    SSL_CTX_add0_chain_cert := @COMPAT_SSL_CTX_add0_chain_cert;
  Result := SSL_CTX_add0_chain_cert(ctx,x509);
end;

function Load_SSL_CTX_add1_chain_cert(ctx: PSSL_CTX; x509: PX509): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_add1_chain_cert := LoadLibSSLFunction('SSL_CTX_add1_chain_cert');
  if not assigned(SSL_CTX_add1_chain_cert) then
    SSL_CTX_add1_chain_cert := @COMPAT_SSL_CTX_add1_chain_cert;
  Result := SSL_CTX_add1_chain_cert(ctx,x509);
end;

function Load_SSL_CTX_get0_chain_certs(ctx: PSSL_CTX; px509: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_get0_chain_certs := LoadLibSSLFunction('SSL_CTX_get0_chain_certs');
  if not assigned(SSL_CTX_get0_chain_certs) then
    SSL_CTX_get0_chain_certs := @COMPAT_SSL_CTX_get0_chain_certs;
  Result := SSL_CTX_get0_chain_certs(ctx,px509);
end;

function Load_SSL_CTX_clear_chain_certs(ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_clear_chain_certs := LoadLibSSLFunction('SSL_CTX_clear_chain_certs');
  if not assigned(SSL_CTX_clear_chain_certs) then
    SSL_CTX_clear_chain_certs := @COMPAT_SSL_CTX_clear_chain_certs;
  Result := SSL_CTX_clear_chain_certs(ctx);
end;

function Load_SSL_CTX_build_cert_chain(ctx: PSSL_CTX; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_build_cert_chain := LoadLibSSLFunction('SSL_CTX_build_cert_chain');
  if not assigned(SSL_CTX_build_cert_chain) then
    SSL_CTX_build_cert_chain := @COMPAT_SSL_CTX_build_cert_chain;
  Result := SSL_CTX_build_cert_chain(ctx,flags);
end;

function Load_SSL_CTX_select_current_cert(ctx: PSSL_CTX; x509: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_select_current_cert := LoadLibSSLFunction('SSL_CTX_select_current_cert');
  if not assigned(SSL_CTX_select_current_cert) then
    SSL_CTX_select_current_cert := @COMPAT_SSL_CTX_select_current_cert;
  Result := SSL_CTX_select_current_cert(ctx,x509);
end;

function Load_SSL_CTX_set_current_cert(ctx: PSSL_CTX; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_current_cert := LoadLibSSLFunction('SSL_CTX_set_current_cert');
  if not assigned(SSL_CTX_set_current_cert) then
    SSL_CTX_set_current_cert := @COMPAT_SSL_CTX_set_current_cert;
  Result := SSL_CTX_set_current_cert(ctx,op);
end;

function Load_SSL_CTX_set0_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set0_verify_cert_store := LoadLibSSLFunction('SSL_CTX_set0_verify_cert_store');
  if not assigned(SSL_CTX_set0_verify_cert_store) then
    SSL_CTX_set0_verify_cert_store := @COMPAT_SSL_CTX_set0_verify_cert_store;
  Result := SSL_CTX_set0_verify_cert_store(ctx,st);
end;

function Load_SSL_CTX_set1_verify_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_verify_cert_store := LoadLibSSLFunction('SSL_CTX_set1_verify_cert_store');
  if not assigned(SSL_CTX_set1_verify_cert_store) then
    SSL_CTX_set1_verify_cert_store := @COMPAT_SSL_CTX_set1_verify_cert_store;
  Result := SSL_CTX_set1_verify_cert_store(ctx,st);
end;

function Load_SSL_CTX_set0_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set0_chain_cert_store := LoadLibSSLFunction('SSL_CTX_set0_chain_cert_store');
  if not assigned(SSL_CTX_set0_chain_cert_store) then
    SSL_CTX_set0_chain_cert_store := @COMPAT_SSL_CTX_set0_chain_cert_store;
  Result := SSL_CTX_set0_chain_cert_store(ctx,st);
end;

function Load_SSL_CTX_set1_chain_cert_store(ctx: PSSL_CTX; st: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_chain_cert_store := LoadLibSSLFunction('SSL_CTX_set1_chain_cert_store');
  if not assigned(SSL_CTX_set1_chain_cert_store) then
    SSL_CTX_set1_chain_cert_store := @COMPAT_SSL_CTX_set1_chain_cert_store;
  Result := SSL_CTX_set1_chain_cert_store(ctx,st);
end;

function Load_SSL_set0_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set0_chain := LoadLibSSLFunction('SSL_set0_chain');
  if not assigned(SSL_set0_chain) then
    SSL_set0_chain := @COMPAT_SSL_set0_chain;
  Result := SSL_set0_chain(s,sk);
end;

function Load_SSL_set1_chain(s: PSSL; sk: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_chain := LoadLibSSLFunction('SSL_set1_chain');
  if not assigned(SSL_set1_chain) then
    SSL_set1_chain := @COMPAT_SSL_set1_chain;
  Result := SSL_set1_chain(s,sk);
end;

function Load_SSL_add0_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_add0_chain_cert := LoadLibSSLFunction('SSL_add0_chain_cert');
  if not assigned(SSL_add0_chain_cert) then
    SSL_add0_chain_cert := @COMPAT_SSL_add0_chain_cert;
  Result := SSL_add0_chain_cert(s,x509);
end;

function Load_SSL_add1_chain_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_add1_chain_cert := LoadLibSSLFunction('SSL_add1_chain_cert');
  if not assigned(SSL_add1_chain_cert) then
    SSL_add1_chain_cert := @COMPAT_SSL_add1_chain_cert;
  Result := SSL_add1_chain_cert(s,x509);
end;

function Load_SSL_get0_chain_certs(s: PSSL; px509: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get0_chain_certs := LoadLibSSLFunction('SSL_get0_chain_certs');
  if not assigned(SSL_get0_chain_certs) then
    SSL_get0_chain_certs := @COMPAT_SSL_get0_chain_certs;
  Result := SSL_get0_chain_certs(s,px509);
end;

function Load_SSL_clear_chain_certs(s: PSSL): TOpenSSL_C_LONG; cdecl;
begin
  SSL_clear_chain_certs := LoadLibSSLFunction('SSL_clear_chain_certs');
  if not assigned(SSL_clear_chain_certs) then
    SSL_clear_chain_certs := @COMPAT_SSL_clear_chain_certs;
  Result := SSL_clear_chain_certs(s);
end;

function Load_SSL_build_cert_chain(s: PSSL; flags: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_build_cert_chain := LoadLibSSLFunction('SSL_build_cert_chain');
  if not assigned(SSL_build_cert_chain) then
    SSL_build_cert_chain := @COMPAT_SSL_build_cert_chain;
  Result := SSL_build_cert_chain(s,flags);
end;

function Load_SSL_select_current_cert(s: PSSL; x509: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_select_current_cert := LoadLibSSLFunction('SSL_select_current_cert');
  if not assigned(SSL_select_current_cert) then
    SSL_select_current_cert := @COMPAT_SSL_select_current_cert;
  Result := SSL_select_current_cert(s,x509);
end;

function Load_SSL_set_current_cert(s: PSSL; op: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set_current_cert := LoadLibSSLFunction('SSL_set_current_cert');
  if not assigned(SSL_set_current_cert) then
    SSL_set_current_cert := @COMPAT_SSL_set_current_cert;
  Result := SSL_set_current_cert(s,op);
end;

function Load_SSL_set0_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set0_verify_cert_store := LoadLibSSLFunction('SSL_set0_verify_cert_store');
  if not assigned(SSL_set0_verify_cert_store) then
    SSL_set0_verify_cert_store := @COMPAT_SSL_set0_verify_cert_store;
  Result := SSL_set0_verify_cert_store(s,st);
end;

function Load_SSL_set1_verify_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_verify_cert_store := LoadLibSSLFunction('SSL_set1_verify_cert_store');
  if not assigned(SSL_set1_verify_cert_store) then
    SSL_set1_verify_cert_store := @COMPAT_SSL_set1_verify_cert_store;
  Result := SSL_set1_verify_cert_store(s,st);
end;

function Load_SSL_set0_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set0_chain_cert_store := LoadLibSSLFunction('SSL_set0_chain_cert_store');
  if not assigned(SSL_set0_chain_cert_store) then
    SSL_set0_chain_cert_store := @COMPAT_SSL_set0_chain_cert_store;
  Result := SSL_set0_chain_cert_store(s,st);
end;

function Load_SSL_set1_chain_cert_store(s: PSSL; st: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_chain_cert_store := LoadLibSSLFunction('SSL_set1_chain_cert_store');
  if not assigned(SSL_set1_chain_cert_store) then
    SSL_set1_chain_cert_store := @COMPAT_SSL_set1_chain_cert_store;
  Result := SSL_set1_chain_cert_store(s,st);
end;

function Load_SSL_get1_groups(s: PSSL; glist: POpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get1_groups := LoadLibSSLFunction('SSL_get1_groups');
  if not assigned(SSL_get1_groups) then
    SSL_get1_groups := @COMPAT_SSL_get1_groups;
  Result := SSL_get1_groups(s,glist);
end;

function Load_SSL_CTX_set1_groups(ctx: PSSL_CTX; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_groups := LoadLibSSLFunction('SSL_CTX_set1_groups');
  if not assigned(SSL_CTX_set1_groups) then
    SSL_CTX_set1_groups := @COMPAT_SSL_CTX_set1_groups;
  Result := SSL_CTX_set1_groups(ctx,glist,glistlen);
end;

function Load_SSL_CTX_set1_groups_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_groups_list := LoadLibSSLFunction('SSL_CTX_set1_groups_list');
  if not assigned(SSL_CTX_set1_groups_list) then
    SSL_CTX_set1_groups_list := @COMPAT_SSL_CTX_set1_groups_list;
  Result := SSL_CTX_set1_groups_list(ctx,s);
end;

function Load_SSL_set1_groups(s: PSSL; glist: PByte; glistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_groups := LoadLibSSLFunction('SSL_set1_groups');
  if not assigned(SSL_set1_groups) then
    SSL_set1_groups := @COMPAT_SSL_set1_groups;
  Result := SSL_set1_groups(s,glist,glistlen);
end;

function Load_SSL_set1_groups_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_groups_list := LoadLibSSLFunction('SSL_set1_groups_list');
  if not assigned(SSL_set1_groups_list) then
    SSL_set1_groups_list := @COMPAT_SSL_set1_groups_list;
  Result := SSL_set1_groups_list(s,str);
end;

function Load_SSL_get_shared_group(s: PSSL; n: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get_shared_group := LoadLibSSLFunction('SSL_get_shared_group');
  if not assigned(SSL_get_shared_group) then
    SSL_get_shared_group := @COMPAT_SSL_get_shared_group;
  Result := SSL_get_shared_group(s,n);
end;

function Load_SSL_CTX_set1_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_sigalgs := LoadLibSSLFunction('SSL_CTX_set1_sigalgs');
  if not assigned(SSL_CTX_set1_sigalgs) then
    SSL_CTX_set1_sigalgs := @COMPAT_SSL_CTX_set1_sigalgs;
  Result := SSL_CTX_set1_sigalgs(ctx,slist,slistlen);
end;

function Load_SSL_CTX_set1_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_sigalgs_list := LoadLibSSLFunction('SSL_CTX_set1_sigalgs_list');
  if not assigned(SSL_CTX_set1_sigalgs_list) then
    SSL_CTX_set1_sigalgs_list := @COMPAT_SSL_CTX_set1_sigalgs_list;
  Result := SSL_CTX_set1_sigalgs_list(ctx,s);
end;

function Load_SSL_set1_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_sigalgs := LoadLibSSLFunction('SSL_set1_sigalgs');
  if not assigned(SSL_set1_sigalgs) then
    SSL_set1_sigalgs := @COMPAT_SSL_set1_sigalgs;
  Result := SSL_set1_sigalgs(s,slist,slistlen);
end;

function Load_SSL_set1_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_sigalgs_list := LoadLibSSLFunction('SSL_set1_sigalgs_list');
  if not assigned(SSL_set1_sigalgs_list) then
    SSL_set1_sigalgs_list := @COMPAT_SSL_set1_sigalgs_list;
  Result := SSL_set1_sigalgs_list(s,str);
end;

function Load_SSL_CTX_set1_client_sigalgs(ctx: PSSL_CTX; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_client_sigalgs := LoadLibSSLFunction('SSL_CTX_set1_client_sigalgs');
  if not assigned(SSL_CTX_set1_client_sigalgs) then
    SSL_CTX_set1_client_sigalgs := @COMPAT_SSL_CTX_set1_client_sigalgs;
  Result := SSL_CTX_set1_client_sigalgs(ctx,slist,slistlen);
end;

function Load_SSL_CTX_set1_client_sigalgs_list(ctx: PSSL_CTX; s: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_client_sigalgs_list := LoadLibSSLFunction('SSL_CTX_set1_client_sigalgs_list');
  if not assigned(SSL_CTX_set1_client_sigalgs_list) then
    SSL_CTX_set1_client_sigalgs_list := @COMPAT_SSL_CTX_set1_client_sigalgs_list;
  Result := SSL_CTX_set1_client_sigalgs_list(ctx,s);
end;

function Load_SSL_set1_client_sigalgs(s: PSSL; slist: POpenSSL_C_INT; slistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_client_sigalgs := LoadLibSSLFunction('SSL_set1_client_sigalgs');
  if not assigned(SSL_set1_client_sigalgs) then
    SSL_set1_client_sigalgs := @COMPAT_SSL_set1_client_sigalgs;
  Result := SSL_set1_client_sigalgs(s,slist,slistlen);
end;

function Load_SSL_set1_client_sigalgs_list(s: PSSL; str: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_client_sigalgs_list := LoadLibSSLFunction('SSL_set1_client_sigalgs_list');
  if not assigned(SSL_set1_client_sigalgs_list) then
    SSL_set1_client_sigalgs_list := @COMPAT_SSL_set1_client_sigalgs_list;
  Result := SSL_set1_client_sigalgs_list(s,str);
end;

function Load_SSL_get0_certificate_types(s: PSSL; clist: PByte): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get0_certificate_types := LoadLibSSLFunction('SSL_get0_certificate_types');
  if not assigned(SSL_get0_certificate_types) then
    SSL_get0_certificate_types := @COMPAT_SSL_get0_certificate_types;
  Result := SSL_get0_certificate_types(s,clist);
end;

function Load_SSL_CTX_set1_client_certificate_types(ctx: PSSL_CTX; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set1_client_certificate_types := LoadLibSSLFunction('SSL_CTX_set1_client_certificate_types');
  if not assigned(SSL_CTX_set1_client_certificate_types) then
    SSL_CTX_set1_client_certificate_types := @COMPAT_SSL_CTX_set1_client_certificate_types;
  Result := SSL_CTX_set1_client_certificate_types(ctx,clist,clistlen);
end;

function Load_SSL_set1_client_certificate_types(s: PSSL; clist: PByte; clistlen: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_set1_client_certificate_types := LoadLibSSLFunction('SSL_set1_client_certificate_types');
  if not assigned(SSL_set1_client_certificate_types) then
    SSL_set1_client_certificate_types := @COMPAT_SSL_set1_client_certificate_types;
  Result := SSL_set1_client_certificate_types(s,clist,clistlen);
end;

function Load_SSL_get_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get_signature_nid := LoadLibSSLFunction('SSL_get_signature_nid');
  if not assigned(SSL_get_signature_nid) then
    SSL_get_signature_nid := @COMPAT_SSL_get_signature_nid;
  Result := SSL_get_signature_nid(s,pn);
end;

function Load_SSL_get_peer_signature_nid(s: PSSL; pn: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get_peer_signature_nid := LoadLibSSLFunction('SSL_get_peer_signature_nid');
  if not assigned(SSL_get_peer_signature_nid) then
    SSL_get_peer_signature_nid := @COMPAT_SSL_get_peer_signature_nid;
  Result := SSL_get_peer_signature_nid(s,pn);
end;

function Load_SSL_get_peer_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get_peer_tmp_key := LoadLibSSLFunction('SSL_get_peer_tmp_key');
  if not assigned(SSL_get_peer_tmp_key) then
    SSL_get_peer_tmp_key := @COMPAT_SSL_get_peer_tmp_key;
  Result := SSL_get_peer_tmp_key(s,pk);
end;

function Load_SSL_get_tmp_key(s: PSSL; pk: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get_tmp_key := LoadLibSSLFunction('SSL_get_tmp_key');
  if not assigned(SSL_get_tmp_key) then
    SSL_get_tmp_key := @COMPAT_SSL_get_tmp_key;
  Result := SSL_get_tmp_key(s,pk);
end;

function Load_SSL_get0_raw_cipherlist(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get0_raw_cipherlist := LoadLibSSLFunction('SSL_get0_raw_cipherlist');
  if not assigned(SSL_get0_raw_cipherlist) then
    SSL_get0_raw_cipherlist := @COMPAT_SSL_get0_raw_cipherlist;
  Result := SSL_get0_raw_cipherlist(s,plst);
end;

function Load_SSL_get0_ec_point_formats(s: PSSL; plst: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get0_ec_point_formats := LoadLibSSLFunction('SSL_get0_ec_point_formats');
  if not assigned(SSL_get0_ec_point_formats) then
    SSL_get0_ec_point_formats := @COMPAT_SSL_get0_ec_point_formats;
  Result := SSL_get0_ec_point_formats(s,plst);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_CTX_get_options(const ctx: PSSL_CTX): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_CTX_get_options := LoadLibSSLFunction('SSL_CTX_get_options');
  if not assigned(SSL_CTX_get_options) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_options := @COMPAT_SSL_CTX_get_options;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_options');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_get_options(ctx);
end;

function Load_SSL_get_options(const s: PSSL): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_get_options := LoadLibSSLFunction('SSL_get_options');
  if not assigned(SSL_get_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_options');
  Result := SSL_get_options(s);
end;

function Load_SSL_CTX_clear_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_CTX_clear_options := LoadLibSSLFunction('SSL_CTX_clear_options');
  if not assigned(SSL_CTX_clear_options) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_clear_options := @COMPAT_SSL_CTX_clear_options;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_clear_options');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_clear_options(ctx,op);
end;

function Load_SSL_clear_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_clear_options := LoadLibSSLFunction('SSL_clear_options');
  if not assigned(SSL_clear_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_clear_options');
  Result := SSL_clear_options(s,op);
end;

function Load_SSL_CTX_set_options(ctx: PSSL_CTX; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_CTX_set_options := LoadLibSSLFunction('SSL_CTX_set_options');
  if not assigned(SSL_CTX_set_options) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_set_options := @COMPAT_SSL_CTX_set_options;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_options');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_set_options(ctx,op);
end;

function Load_SSL_set_options(s: PSSL; op: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_set_options := LoadLibSSLFunction('SSL_set_options');
  if not assigned(SSL_set_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_options');
  Result := SSL_set_options(s,op);
end;

procedure Load_SSL_CTX_sess_set_new_cb(ctx: PSSL_CTX; new_session_cb: SSL_CTX_sess_new_cb); cdecl;
begin
  SSL_CTX_sess_set_new_cb := LoadLibSSLFunction('SSL_CTX_sess_set_new_cb');
  if not assigned(SSL_CTX_sess_set_new_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_set_new_cb');
  SSL_CTX_sess_set_new_cb(ctx,new_session_cb);
end;

function Load_SSL_CTX_sess_get_new_cb(ctx: PSSL_CTX): SSL_CTX_sess_new_cb; cdecl;
begin
  SSL_CTX_sess_get_new_cb := LoadLibSSLFunction('SSL_CTX_sess_get_new_cb');
  if not assigned(SSL_CTX_sess_get_new_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_get_new_cb');
  Result := SSL_CTX_sess_get_new_cb(ctx);
end;

procedure Load_SSL_CTX_sess_set_remove_cb(ctx: PSSL_CTX; remove_session_cb: SSL_CTX_sess_remove_cb); cdecl;
begin
  SSL_CTX_sess_set_remove_cb := LoadLibSSLFunction('SSL_CTX_sess_set_remove_cb');
  if not assigned(SSL_CTX_sess_set_remove_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_set_remove_cb');
  SSL_CTX_sess_set_remove_cb(ctx,remove_session_cb);
end;

function Load_SSL_CTX_sess_get_remove_cb(ctx: PSSL_CTX): SSL_CTX_sess_remove_cb; cdecl;
begin
  SSL_CTX_sess_get_remove_cb := LoadLibSSLFunction('SSL_CTX_sess_get_remove_cb');
  if not assigned(SSL_CTX_sess_get_remove_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_sess_get_remove_cb');
  Result := SSL_CTX_sess_get_remove_cb(ctx);
end;

procedure Load_SSL_CTX_set_info_callback(ctx: PSSL_CTX; cb: SSL_CTX_info_callback); cdecl;
begin
  SSL_CTX_set_info_callback := LoadLibSSLFunction('SSL_CTX_set_info_callback');
  if not assigned(SSL_CTX_set_info_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_info_callback');
  SSL_CTX_set_info_callback(ctx,cb);
end;

function Load_SSL_CTX_get_info_callback(ctx: PSSL_CTX): SSL_CTX_info_callback; cdecl;
begin
  SSL_CTX_get_info_callback := LoadLibSSLFunction('SSL_CTX_get_info_callback');
  if not assigned(SSL_CTX_get_info_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_info_callback');
  Result := SSL_CTX_get_info_callback(ctx);
end;

procedure Load_SSL_CTX_set_client_cert_cb(ctx: PSSL_CTX; client_cert_cb: SSL_CTX_client_cert_cb); cdecl;
begin
  SSL_CTX_set_client_cert_cb := LoadLibSSLFunction('SSL_CTX_set_client_cert_cb');
  if not assigned(SSL_CTX_set_client_cert_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_cert_cb');
  SSL_CTX_set_client_cert_cb(ctx,client_cert_cb);
end;

function Load_SSL_CTX_get_client_cert_cb(ctx: PSSL_CTX): SSL_CTX_client_cert_cb; cdecl;
begin
  SSL_CTX_get_client_cert_cb := LoadLibSSLFunction('SSL_CTX_get_client_cert_cb');
  if not assigned(SSL_CTX_get_client_cert_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_client_cert_cb');
  Result := SSL_CTX_get_client_cert_cb(ctx);
end;

function Load_SSL_CTX_set_client_cert_engine(ctx: PSSL_CTX; e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_client_cert_engine := LoadLibSSLFunction('SSL_CTX_set_client_cert_engine');
  if not assigned(SSL_CTX_set_client_cert_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_cert_engine');
  Result := SSL_CTX_set_client_cert_engine(ctx,e);
end;

procedure Load_SSL_CTX_set_cookie_generate_cb(ctx: PSSL_CTX; app_gen_cookie_cb: SSL_CTX_cookie_verify_cb); cdecl;
begin
  SSL_CTX_set_cookie_generate_cb := LoadLibSSLFunction('SSL_CTX_set_cookie_generate_cb');
  if not assigned(SSL_CTX_set_cookie_generate_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cookie_generate_cb');
  SSL_CTX_set_cookie_generate_cb(ctx,app_gen_cookie_cb);
end;

procedure Load_SSL_CTX_set_cookie_verify_cb(ctx: PSSL_CTX; app_verify_cookie_cb: SSL_CTX_set_cookie_verify_cb_app_verify_cookie_cb); cdecl;
begin
  SSL_CTX_set_cookie_verify_cb := LoadLibSSLFunction('SSL_CTX_set_cookie_verify_cb');
  if not assigned(SSL_CTX_set_cookie_verify_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cookie_verify_cb');
  SSL_CTX_set_cookie_verify_cb(ctx,app_verify_cookie_cb);
end;

procedure Load_SSL_CTX_set_stateless_cookie_generate_cb(ctx: PSSL_CTX; gen_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_generate_cb_gen_stateless_cookie_cb); cdecl;
begin
  SSL_CTX_set_stateless_cookie_generate_cb := LoadLibSSLFunction('SSL_CTX_set_stateless_cookie_generate_cb');
  if not assigned(SSL_CTX_set_stateless_cookie_generate_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_stateless_cookie_generate_cb');
  SSL_CTX_set_stateless_cookie_generate_cb(ctx,gen_stateless_cookie_cb);
end;

procedure Load_SSL_CTX_set_stateless_cookie_verify_cb(ctx: PSSL_CTX; verify_stateless_cookie_cb: SSL_CTX_set_stateless_cookie_verify_cb_verify_stateless_cookie_cb); cdecl;
begin
  SSL_CTX_set_stateless_cookie_verify_cb := LoadLibSSLFunction('SSL_CTX_set_stateless_cookie_verify_cb');
  if not assigned(SSL_CTX_set_stateless_cookie_verify_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_stateless_cookie_verify_cb');
  SSL_CTX_set_stateless_cookie_verify_cb(ctx,verify_stateless_cookie_cb);
end;

procedure Load_SSL_CTX_set_alpn_select_cb(ctx: PSSL_CTX; cb: SSL_CTX_alpn_select_cb_func; arg: Pointer); cdecl;
begin
  SSL_CTX_set_alpn_select_cb := LoadLibSSLFunction('SSL_CTX_set_alpn_select_cb');
  if not assigned(SSL_CTX_set_alpn_select_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_alpn_select_cb');
  SSL_CTX_set_alpn_select_cb(ctx,cb,arg);
end;

procedure Load_SSL_get0_alpn_selected(const ssl: PSSL; const data: PPByte; len: POpenSSL_C_UINT); cdecl;
begin
  SSL_get0_alpn_selected := LoadLibSSLFunction('SSL_get0_alpn_selected');
  if not assigned(SSL_get0_alpn_selected) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_alpn_selected');
  SSL_get0_alpn_selected(ssl,data,len);
end;

procedure Load_SSL_CTX_set_psk_client_callback(ctx: PSSL_CTX; cb: SSL_psk_client_cb_func); cdecl;
begin
  SSL_CTX_set_psk_client_callback := LoadLibSSLFunction('SSL_CTX_set_psk_client_callback');
  if not assigned(SSL_CTX_set_psk_client_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_client_callback');
  SSL_CTX_set_psk_client_callback(ctx,cb);
end;

procedure Load_SSL_set_psk_client_callback(ssl: PSSL; cb: SSL_psk_client_cb_func); cdecl;
begin
  SSL_set_psk_client_callback := LoadLibSSLFunction('SSL_set_psk_client_callback');
  if not assigned(SSL_set_psk_client_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_client_callback');
  SSL_set_psk_client_callback(ssl,cb);
end;

procedure Load_SSL_CTX_set_psk_server_callback(ctx: PSSL_CTX; cb: SSL_psk_server_cb_func); cdecl;
begin
  SSL_CTX_set_psk_server_callback := LoadLibSSLFunction('SSL_CTX_set_psk_server_callback');
  if not assigned(SSL_CTX_set_psk_server_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_server_callback');
  SSL_CTX_set_psk_server_callback(ctx,cb);
end;

procedure Load_SSL_set_psk_server_callback(ssl: PSSL; cb: SSL_psk_server_cb_func); cdecl;
begin
  SSL_set_psk_server_callback := LoadLibSSLFunction('SSL_set_psk_server_callback');
  if not assigned(SSL_set_psk_server_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_server_callback');
  SSL_set_psk_server_callback(ssl,cb);
end;

procedure Load_SSL_set_psk_find_session_callback(s: PSSL; cb: SSL_psk_find_session_cb_func); cdecl;
begin
  SSL_set_psk_find_session_callback := LoadLibSSLFunction('SSL_set_psk_find_session_callback');
  if not assigned(SSL_set_psk_find_session_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_find_session_callback');
  SSL_set_psk_find_session_callback(s,cb);
end;

procedure Load_SSL_CTX_set_psk_find_session_callback(ctx: PSSL_CTX; cb: SSL_psk_find_session_cb_func); cdecl;
begin
  SSL_CTX_set_psk_find_session_callback := LoadLibSSLFunction('SSL_CTX_set_psk_find_session_callback');
  if not assigned(SSL_CTX_set_psk_find_session_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_find_session_callback');
  SSL_CTX_set_psk_find_session_callback(ctx,cb);
end;

procedure Load_SSL_set_psk_use_session_callback(s: PSSL; cb: SSL_psk_use_session_cb_func); cdecl;
begin
  SSL_set_psk_use_session_callback := LoadLibSSLFunction('SSL_set_psk_use_session_callback');
  if not assigned(SSL_set_psk_use_session_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_psk_use_session_callback');
  SSL_set_psk_use_session_callback(s,cb);
end;

procedure Load_SSL_CTX_set_psk_use_session_callback(ctx: PSSL_CTX; cb: SSL_psk_use_session_cb_func); cdecl;
begin
  SSL_CTX_set_psk_use_session_callback := LoadLibSSLFunction('SSL_CTX_set_psk_use_session_callback');
  if not assigned(SSL_CTX_set_psk_use_session_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_psk_use_session_callback');
  SSL_CTX_set_psk_use_session_callback(ctx,cb);
end;

procedure Load_SSL_CTX_set_keylog_callback(ctx: PSSL_CTX; cb: SSL_CTX_keylog_cb_func); cdecl;
begin
  SSL_CTX_set_keylog_callback := LoadLibSSLFunction('SSL_CTX_set_keylog_callback');
  if not assigned(SSL_CTX_set_keylog_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_keylog_callback');
  SSL_CTX_set_keylog_callback(ctx,cb);
end;

function Load_SSL_CTX_get_keylog_callback(const ctx: PSSL_CTX): SSL_CTX_keylog_cb_func; cdecl;
begin
  SSL_CTX_get_keylog_callback := LoadLibSSLFunction('SSL_CTX_get_keylog_callback');
  if not assigned(SSL_CTX_get_keylog_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_keylog_callback');
  Result := SSL_CTX_get_keylog_callback(ctx);
end;

function Load_SSL_CTX_set_max_early_data(ctx: PSSL_CTX; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_max_early_data := LoadLibSSLFunction('SSL_CTX_set_max_early_data');
  if not assigned(SSL_CTX_set_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_max_early_data');
  Result := SSL_CTX_set_max_early_data(ctx,max_early_data);
end;

function Load_SSL_CTX_get_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl;
begin
  SSL_CTX_get_max_early_data := LoadLibSSLFunction('SSL_CTX_get_max_early_data');
  if not assigned(SSL_CTX_get_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_max_early_data');
  Result := SSL_CTX_get_max_early_data(ctx);
end;

function Load_SSL_set_max_early_data(s: PSSL; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_max_early_data := LoadLibSSLFunction('SSL_set_max_early_data');
  if not assigned(SSL_set_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_max_early_data');
  Result := SSL_set_max_early_data(s,max_early_data);
end;

function Load_SSL_get_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl;
begin
  SSL_get_max_early_data := LoadLibSSLFunction('SSL_get_max_early_data');
  if not assigned(SSL_get_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_max_early_data');
  Result := SSL_get_max_early_data(s);
end;

function Load_SSL_CTX_set_recv_max_early_data(ctx: PSSL_CTX; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_recv_max_early_data := LoadLibSSLFunction('SSL_CTX_set_recv_max_early_data');
  if not assigned(SSL_CTX_set_recv_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_recv_max_early_data');
  Result := SSL_CTX_set_recv_max_early_data(ctx,recv_max_early_data);
end;

function Load_SSL_CTX_get_recv_max_early_data(const ctx: PSSL_CTX): TOpenSSL_C_UINT32; cdecl;
begin
  SSL_CTX_get_recv_max_early_data := LoadLibSSLFunction('SSL_CTX_get_recv_max_early_data');
  if not assigned(SSL_CTX_get_recv_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_recv_max_early_data');
  Result := SSL_CTX_get_recv_max_early_data(ctx);
end;

function Load_SSL_set_recv_max_early_data(s: PSSL; recv_max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_recv_max_early_data := LoadLibSSLFunction('SSL_set_recv_max_early_data');
  if not assigned(SSL_set_recv_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_recv_max_early_data');
  Result := SSL_set_recv_max_early_data(s,recv_max_early_data);
end;

function Load_SSL_get_recv_max_early_data(const s: PSSL): TOpenSSL_C_UINT32; cdecl;
begin
  SSL_get_recv_max_early_data := LoadLibSSLFunction('SSL_get_recv_max_early_data');
  if not assigned(SSL_get_recv_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_recv_max_early_data');
  Result := SSL_get_recv_max_early_data(s);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_get_app_data(const ssl: PSSL): Pointer; cdecl;
begin
  SSL_get_app_data := LoadLibSSLFunction('SSL_get_app_data');
  if not assigned(SSL_get_app_data) then
    SSL_get_app_data := @COMPAT_SSL_get_app_data;
  Result := SSL_get_app_data(ssl);
end;

function Load_SSL_set_app_data(ssl: PSSL; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_app_data := LoadLibSSLFunction('SSL_set_app_data');
  if not assigned(SSL_set_app_data) then
    SSL_set_app_data := @COMPAT_SSL_set_app_data;
  Result := SSL_set_app_data(ssl,data);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_in_init(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_in_init := LoadLibSSLFunction('SSL_in_init');
  if not assigned(SSL_in_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_in_init');
  Result := SSL_in_init(s);
end;

function Load_SSL_in_before(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_in_before := LoadLibSSLFunction('SSL_in_before');
  if not assigned(SSL_in_before) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_in_before');
  Result := SSL_in_before(s);
end;

function Load_SSL_is_init_finished(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_is_init_finished := LoadLibSSLFunction('SSL_is_init_finished');
  if not assigned(SSL_is_init_finished) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_is_init_finished');
  Result := SSL_is_init_finished(s);
end;

function Load_SSL_get_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_get_finished := LoadLibSSLFunction('SSL_get_finished');
  if not assigned(SSL_get_finished) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_finished');
  Result := SSL_get_finished(s,buf,count);
end;

function Load_SSL_get_peer_finished(const s: PSSL; buf: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_get_peer_finished := LoadLibSSLFunction('SSL_get_peer_finished');
  if not assigned(SSL_get_peer_finished) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_peer_finished');
  Result := SSL_get_peer_finished(s,buf,count);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSLeay_add_ssl_algorithms: TOpenSSL_C_INT; cdecl;
begin
  SSLeay_add_ssl_algorithms := LoadLibSSLFunction('SSLeay_add_ssl_algorithms');
  if not assigned(SSLeay_add_ssl_algorithms) then
    SSLeay_add_ssl_algorithms := @COMPAT_SSLeay_add_ssl_algorithms;
  Result := SSLeay_add_ssl_algorithms();
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_BIO_f_ssl: PBIO_METHOD; cdecl;
begin
  BIO_f_ssl := LoadLibSSLFunction('BIO_f_ssl');
  if not assigned(BIO_f_ssl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_ssl');
  Result := BIO_f_ssl();
end;

function Load_BIO_new_ssl(ctx: PSSL_CTX; client: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_new_ssl := LoadLibSSLFunction('BIO_new_ssl');
  if not assigned(BIO_new_ssl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_ssl');
  Result := BIO_new_ssl(ctx,client);
end;

function Load_BIO_new_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl;
begin
  BIO_new_ssl_connect := LoadLibSSLFunction('BIO_new_ssl_connect');
  if not assigned(BIO_new_ssl_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_ssl_connect');
  Result := BIO_new_ssl_connect(ctx);
end;

function Load_BIO_new_buffer_ssl_connect(ctx: PSSL_CTX): PBIO; cdecl;
begin
  BIO_new_buffer_ssl_connect := LoadLibSSLFunction('BIO_new_buffer_ssl_connect');
  if not assigned(BIO_new_buffer_ssl_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_buffer_ssl_connect');
  Result := BIO_new_buffer_ssl_connect(ctx);
end;

function Load_BIO_ssl_copy_session_id(to_: PBIO; from: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_ssl_copy_session_id := LoadLibSSLFunction('BIO_ssl_copy_session_id');
  if not assigned(BIO_ssl_copy_session_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ssl_copy_session_id');
  Result := BIO_ssl_copy_session_id(to_,from);
end;

function Load_SSL_CTX_set_cipher_list(v1: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_cipher_list := LoadLibSSLFunction('SSL_CTX_set_cipher_list');
  if not assigned(SSL_CTX_set_cipher_list) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cipher_list');
  Result := SSL_CTX_set_cipher_list(v1,str);
end;

function Load_SSL_CTX_new(const meth: PSSL_METHOD): PSSL_CTX; cdecl;
begin
  SSL_CTX_new := LoadLibSSLFunction('SSL_CTX_new');
  if not assigned(SSL_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_new');
  Result := SSL_CTX_new(meth);
end;

function Load_SSL_CTX_set_timeout(ctx: PSSL_CTX; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_set_timeout := LoadLibSSLFunction('SSL_CTX_set_timeout');
  if not assigned(SSL_CTX_set_timeout) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_timeout');
  Result := SSL_CTX_set_timeout(ctx,t);
end;

function Load_SSL_CTX_get_timeout(const ctx: PSSL_CTX): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_get_timeout := LoadLibSSLFunction('SSL_CTX_get_timeout');
  if not assigned(SSL_CTX_get_timeout) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_timeout');
  Result := SSL_CTX_get_timeout(ctx);
end;

function Load_SSL_CTX_get_cert_store(const v1: PSSL_CTX): PX509_STORE; cdecl;
begin
  SSL_CTX_get_cert_store := LoadLibSSLFunction('SSL_CTX_get_cert_store');
  if not assigned(SSL_CTX_get_cert_store) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_cert_store := @COMPAT_SSL_CTX_get_cert_store;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_cert_store');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_get_cert_store(v1);
end;

function Load_SSL_want(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_want := LoadLibSSLFunction('SSL_want');
  if not assigned(SSL_want) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_want');
  Result := SSL_want(s);
end;

function Load_SSL_clear(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_clear := LoadLibSSLFunction('SSL_clear');
  if not assigned(SSL_clear) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_clear');
  Result := SSL_clear(s);
end;

procedure Load_BIO_ssl_shutdown(ssl_bio: PBIO); cdecl;
begin
  BIO_ssl_shutdown := LoadLibSSLFunction('BIO_ssl_shutdown');
  if not assigned(BIO_ssl_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ssl_shutdown');
  BIO_ssl_shutdown(ssl_bio);
end;

function Load_SSL_CTX_up_ref(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_up_ref := LoadLibSSLFunction('SSL_CTX_up_ref');
  if not assigned(SSL_CTX_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_up_ref');
  Result := SSL_CTX_up_ref(ctx);
end;

procedure Load_SSL_CTX_free(v1: PSSL_CTX); cdecl;
begin
  SSL_CTX_free := LoadLibSSLFunction('SSL_CTX_free');
  if not assigned(SSL_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_free');
  SSL_CTX_free(v1);
end;

procedure Load_SSL_CTX_set_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl;
begin
  SSL_CTX_set_cert_store := LoadLibSSLFunction('SSL_CTX_set_cert_store');
  if not assigned(SSL_CTX_set_cert_store) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cert_store');
  SSL_CTX_set_cert_store(v1,v2);
end;

procedure Load_SSL_CTX_set1_cert_store(v1: PSSL_CTX; v2: PX509_STORE); cdecl;
begin
  SSL_CTX_set1_cert_store := LoadLibSSLFunction('SSL_CTX_set1_cert_store');
  if not assigned(SSL_CTX_set1_cert_store) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_cert_store');
  SSL_CTX_set1_cert_store(v1,v2);
end;

procedure Load_SSL_CTX_flush_sessions(ctx: PSSL_CTX; tm: TOpenSSL_C_LONG); cdecl;
begin
  SSL_CTX_flush_sessions := LoadLibSSLFunction('SSL_CTX_flush_sessions');
  if not assigned(SSL_CTX_flush_sessions) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_flush_sessions');
  SSL_CTX_flush_sessions(ctx,tm);
end;

function Load_SSL_get_current_cipher(const s: PSSL): PSSL_CIPHER; cdecl;
begin
  SSL_get_current_cipher := LoadLibSSLFunction('SSL_get_current_cipher');
  if not assigned(SSL_get_current_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_current_cipher');
  Result := SSL_get_current_cipher(s);
end;

function Load_SSL_get_pending_cipher(const s: PSSL): PSSL_CIPHER; cdecl;
begin
  SSL_get_pending_cipher := LoadLibSSLFunction('SSL_get_pending_cipher');
  if not assigned(SSL_get_pending_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_pending_cipher');
  Result := SSL_get_pending_cipher(s);
end;

function Load_SSL_CIPHER_get_bits(const c: PSSL_CIPHER; var alg_bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CIPHER_get_bits := LoadLibSSLFunction('SSL_CIPHER_get_bits');
  if not assigned(SSL_CIPHER_get_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_bits');
  Result := SSL_CIPHER_get_bits(c,alg_bits);
end;

function Load_SSL_CIPHER_get_version(const c: PSSL_CIPHER): PAnsiChar; cdecl;
begin
  SSL_CIPHER_get_version := LoadLibSSLFunction('SSL_CIPHER_get_version');
  if not assigned(SSL_CIPHER_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_version');
  Result := SSL_CIPHER_get_version(c);
end;

function Load_SSL_CIPHER_get_name(const c: PSSL_CIPHER): PAnsiChar; cdecl;
begin
  SSL_CIPHER_get_name := LoadLibSSLFunction('SSL_CIPHER_get_name');
  if not assigned(SSL_CIPHER_get_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_name');
  Result := SSL_CIPHER_get_name(c);
end;

function Load_SSL_CIPHER_standard_name(const c: PSSL_CIPHER): PAnsiChar; cdecl;
begin
  SSL_CIPHER_standard_name := LoadLibSSLFunction('SSL_CIPHER_standard_name');
  if not assigned(SSL_CIPHER_standard_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_standard_name');
  Result := SSL_CIPHER_standard_name(c);
end;

function Load_OPENSSL_cipher_name(const rfc_name: PAnsiChar): PAnsiChar; cdecl;
begin
  OPENSSL_cipher_name := LoadLibSSLFunction('OPENSSL_cipher_name');
  if not assigned(OPENSSL_cipher_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_cipher_name');
  Result := OPENSSL_cipher_name(rfc_name);
end;

function Load_SSL_CIPHER_get_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT32; cdecl;
begin
  SSL_CIPHER_get_id := LoadLibSSLFunction('SSL_CIPHER_get_id');
  if not assigned(SSL_CIPHER_get_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_id');
  Result := SSL_CIPHER_get_id(c);
end;

function Load_SSL_CIPHER_get_protocol_id(const c: PSSL_CIPHER): TOpenSSL_C_UINT16; cdecl;
begin
  SSL_CIPHER_get_protocol_id := LoadLibSSLFunction('SSL_CIPHER_get_protocol_id');
  if not assigned(SSL_CIPHER_get_protocol_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_protocol_id');
  Result := SSL_CIPHER_get_protocol_id(c);
end;

function Load_SSL_CIPHER_get_kx_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  SSL_CIPHER_get_kx_nid := LoadLibSSLFunction('SSL_CIPHER_get_kx_nid');
  if not assigned(SSL_CIPHER_get_kx_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_kx_nid');
  Result := SSL_CIPHER_get_kx_nid(c);
end;

function Load_SSL_CIPHER_get_auth_nid(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  SSL_CIPHER_get_auth_nid := LoadLibSSLFunction('SSL_CIPHER_get_auth_nid');
  if not assigned(SSL_CIPHER_get_auth_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_auth_nid');
  Result := SSL_CIPHER_get_auth_nid(c);
end;

function Load_SSL_CIPHER_get_handshake_digest(const c: PSSL_CIPHER): PEVP_MD; cdecl;
begin
  SSL_CIPHER_get_handshake_digest := LoadLibSSLFunction('SSL_CIPHER_get_handshake_digest');
  if not assigned(SSL_CIPHER_get_handshake_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_handshake_digest');
  Result := SSL_CIPHER_get_handshake_digest(c);
end;

function Load_SSL_CIPHER_is_aead(const c: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  SSL_CIPHER_is_aead := LoadLibSSLFunction('SSL_CIPHER_is_aead');
  if not assigned(SSL_CIPHER_is_aead) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_is_aead');
  Result := SSL_CIPHER_is_aead(c);
end;

function Load_SSL_get_fd(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_fd := LoadLibSSLFunction('SSL_get_fd');
  if not assigned(SSL_get_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_fd');
  Result := SSL_get_fd(s);
end;

function Load_SSL_get_rfd(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_rfd := LoadLibSSLFunction('SSL_get_rfd');
  if not assigned(SSL_get_rfd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_rfd');
  Result := SSL_get_rfd(s);
end;

function Load_SSL_get_wfd(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_wfd := LoadLibSSLFunction('SSL_get_wfd');
  if not assigned(SSL_get_wfd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_wfd');
  Result := SSL_get_wfd(s);
end;

function Load_SSL_get_cipher_list(const s: PSSL; n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_get_cipher_list := LoadLibSSLFunction('SSL_get_cipher_list');
  if not assigned(SSL_get_cipher_list) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_cipher_list');
  Result := SSL_get_cipher_list(s,n);
end;

function Load_SSL_get_shared_ciphers(const s: PSSL; buf: PAnsiChar; size: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_get_shared_ciphers := LoadLibSSLFunction('SSL_get_shared_ciphers');
  if not assigned(SSL_get_shared_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_shared_ciphers');
  Result := SSL_get_shared_ciphers(s,buf,size);
end;

function Load_SSL_get_read_ahead(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_read_ahead := LoadLibSSLFunction('SSL_get_read_ahead');
  if not assigned(SSL_get_read_ahead) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_read_ahead');
  Result := SSL_get_read_ahead(s);
end;

function Load_SSL_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_pending := LoadLibSSLFunction('SSL_pending');
  if not assigned(SSL_pending) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_pending');
  Result := SSL_pending(s);
end;

function Load_SSL_has_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_has_pending := LoadLibSSLFunction('SSL_has_pending');
  if not assigned(SSL_has_pending) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_has_pending');
  Result := SSL_has_pending(s);
end;

function Load_SSL_set_fd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_fd := LoadLibSSLFunction('SSL_set_fd');
  if not assigned(SSL_set_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_fd');
  Result := SSL_set_fd(s,fd);
end;

function Load_SSL_set_rfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_rfd := LoadLibSSLFunction('SSL_set_rfd');
  if not assigned(SSL_set_rfd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_rfd');
  Result := SSL_set_rfd(s,fd);
end;

function Load_SSL_set_wfd(s: PSSL; fd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_wfd := LoadLibSSLFunction('SSL_set_wfd');
  if not assigned(SSL_set_wfd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_wfd');
  Result := SSL_set_wfd(s,fd);
end;

procedure Load_SSL_set0_rbio(s: PSSL; rbio: PBIO); cdecl;
begin
  SSL_set0_rbio := LoadLibSSLFunction('SSL_set0_rbio');
  if not assigned(SSL_set0_rbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_rbio');
  SSL_set0_rbio(s,rbio);
end;

procedure Load_SSL_set0_wbio(s: PSSL; wbio: PBIO); cdecl;
begin
  SSL_set0_wbio := LoadLibSSLFunction('SSL_set0_wbio');
  if not assigned(SSL_set0_wbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_wbio');
  SSL_set0_wbio(s,wbio);
end;

procedure Load_SSL_set_bio(s: PSSL; rbio: PBIO; wbio: PBIO); cdecl;
begin
  SSL_set_bio := LoadLibSSLFunction('SSL_set_bio');
  if not assigned(SSL_set_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_bio');
  SSL_set_bio(s,rbio,wbio);
end;

function Load_SSL_get_rbio(const s: PSSL): PBIO; cdecl;
begin
  SSL_get_rbio := LoadLibSSLFunction('SSL_get_rbio');
  if not assigned(SSL_get_rbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_rbio');
  Result := SSL_get_rbio(s);
end;

function Load_SSL_get_wbio(const s: PSSL): PBIO; cdecl;
begin
  SSL_get_wbio := LoadLibSSLFunction('SSL_get_wbio');
  if not assigned(SSL_get_wbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_wbio');
  Result := SSL_get_wbio(s);
end;

function Load_SSL_set_cipher_list(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_cipher_list := LoadLibSSLFunction('SSL_set_cipher_list');
  if not assigned(SSL_set_cipher_list) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_cipher_list');
  Result := SSL_set_cipher_list(s,str);
end;

function Load_SSL_CTX_set_ciphersuites(ctx: PSSL_CTX; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_ciphersuites := LoadLibSSLFunction('SSL_CTX_set_ciphersuites');
  if not assigned(SSL_CTX_set_ciphersuites) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ciphersuites');
  Result := SSL_CTX_set_ciphersuites(ctx,str);
end;

function Load_SSL_set_ciphersuites(s: PSSL; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_ciphersuites := LoadLibSSLFunction('SSL_set_ciphersuites');
  if not assigned(SSL_set_ciphersuites) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_ciphersuites');
  Result := SSL_set_ciphersuites(s,str);
end;

function Load_SSL_get_verify_mode(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_verify_mode := LoadLibSSLFunction('SSL_get_verify_mode');
  if not assigned(SSL_get_verify_mode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_mode');
  Result := SSL_get_verify_mode(s);
end;

function Load_SSL_get_verify_depth(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_verify_depth := LoadLibSSLFunction('SSL_get_verify_depth');
  if not assigned(SSL_get_verify_depth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_depth');
  Result := SSL_get_verify_depth(s);
end;

function Load_SSL_get_verify_callback(const s: PSSL): SSL_verify_cb; cdecl;
begin
  SSL_get_verify_callback := LoadLibSSLFunction('SSL_get_verify_callback');
  if not assigned(SSL_get_verify_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_callback');
  Result := SSL_get_verify_callback(s);
end;

procedure Load_SSL_set_read_ahead(s: PSSL; yes: TOpenSSL_C_INT); cdecl;
begin
  SSL_set_read_ahead := LoadLibSSLFunction('SSL_set_read_ahead');
  if not assigned(SSL_set_read_ahead) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_read_ahead');
  SSL_set_read_ahead(s,yes);
end;

procedure Load_SSL_set_verify(s: PSSL; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl;
begin
  SSL_set_verify := LoadLibSSLFunction('SSL_set_verify');
  if not assigned(SSL_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_verify');
  SSL_set_verify(s,mode,callback);
end;

procedure Load_SSL_set_verify_depth(s: PSSL; depth: TOpenSSL_C_INT); cdecl;
begin
  SSL_set_verify_depth := LoadLibSSLFunction('SSL_set_verify_depth');
  if not assigned(SSL_set_verify_depth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_verify_depth');
  SSL_set_verify_depth(s,depth);
end;

function Load_SSL_use_RSAPrivateKey(ssl: PSSL; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_RSAPrivateKey := LoadLibSSLFunction('SSL_use_RSAPrivateKey');
  if not assigned(SSL_use_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_RSAPrivateKey');
  Result := SSL_use_RSAPrivateKey(ssl,rsa);
end;

function Load_SSL_use_RSAPrivateKey_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_RSAPrivateKey_ASN1 := LoadLibSSLFunction('SSL_use_RSAPrivateKey_ASN1');
  if not assigned(SSL_use_RSAPrivateKey_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_RSAPrivateKey_ASN1');
  Result := SSL_use_RSAPrivateKey_ASN1(ssl,d,len);
end;

function Load_SSL_use_PrivateKey(ssl: PSSL; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_PrivateKey := LoadLibSSLFunction('SSL_use_PrivateKey');
  if not assigned(SSL_use_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_PrivateKey');
  Result := SSL_use_PrivateKey(ssl,pkey);
end;

function Load_SSL_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ssl: PSSL; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_PrivateKey_ASN1 := LoadLibSSLFunction('SSL_use_PrivateKey_ASN1');
  if not assigned(SSL_use_PrivateKey_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_PrivateKey_ASN1');
  Result := SSL_use_PrivateKey_ASN1(pk,ssl,d,len);
end;

function Load_SSL_use_certificate(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_certificate := LoadLibSSLFunction('SSL_use_certificate');
  if not assigned(SSL_use_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate');
  Result := SSL_use_certificate(ssl,x);
end;

function Load_SSL_use_certificate_ASN1(ssl: PSSL; const d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_certificate_ASN1 := LoadLibSSLFunction('SSL_use_certificate_ASN1');
  if not assigned(SSL_use_certificate_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate_ASN1');
  Result := SSL_use_certificate_ASN1(ssl,d,len);
end;

function Load_SSL_CTX_use_serverinfo(ctx: PSSL_CTX; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_serverinfo := LoadLibSSLFunction('SSL_CTX_use_serverinfo');
  if not assigned(SSL_CTX_use_serverinfo) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_serverinfo');
  Result := SSL_CTX_use_serverinfo(ctx,serverinfo,serverinfo_length);
end;

function Load_SSL_CTX_use_serverinfo_ex(ctx: PSSL_CTX; version: TOpenSSL_C_UINT; const serverinfo: PByte; serverinfo_length: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_serverinfo_ex := LoadLibSSLFunction('SSL_CTX_use_serverinfo_ex');
  if not assigned(SSL_CTX_use_serverinfo_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_serverinfo_ex');
  Result := SSL_CTX_use_serverinfo_ex(ctx,version,serverinfo,serverinfo_length);
end;

function Load_SSL_CTX_use_serverinfo_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_serverinfo_file := LoadLibSSLFunction('SSL_CTX_use_serverinfo_file');
  if not assigned(SSL_CTX_use_serverinfo_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_serverinfo_file');
  Result := SSL_CTX_use_serverinfo_file(ctx,file_);
end;

function Load_SSL_use_RSAPrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_RSAPrivateKey_file := LoadLibSSLFunction('SSL_use_RSAPrivateKey_file');
  if not assigned(SSL_use_RSAPrivateKey_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_RSAPrivateKey_file');
  Result := SSL_use_RSAPrivateKey_file(ssl,file_,type_);
end;

function Load_SSL_use_PrivateKey_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_PrivateKey_file := LoadLibSSLFunction('SSL_use_PrivateKey_file');
  if not assigned(SSL_use_PrivateKey_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_PrivateKey_file');
  Result := SSL_use_PrivateKey_file(ssl,file_,type_);
end;

function Load_SSL_use_certificate_file(ssl: PSSL; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_certificate_file := LoadLibSSLFunction('SSL_use_certificate_file');
  if not assigned(SSL_use_certificate_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate_file');
  Result := SSL_use_certificate_file(ssl,file_,type_);
end;

function Load_SSL_CTX_use_RSAPrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_RSAPrivateKey_file := LoadLibSSLFunction('SSL_CTX_use_RSAPrivateKey_file');
  if not assigned(SSL_CTX_use_RSAPrivateKey_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_RSAPrivateKey_file');
  Result := SSL_CTX_use_RSAPrivateKey_file(ctx,file_,type_);
end;

function Load_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_PrivateKey_file := LoadLibSSLFunction('SSL_CTX_use_PrivateKey_file');
  if not assigned(SSL_CTX_use_PrivateKey_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_PrivateKey_file');
  Result := SSL_CTX_use_PrivateKey_file(ctx,file_,type_);
end;

function Load_SSL_CTX_use_certificate_file(ctx: PSSL_CTX; const file_: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_certificate_file := LoadLibSSLFunction('SSL_CTX_use_certificate_file');
  if not assigned(SSL_CTX_use_certificate_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate_file');
  Result := SSL_CTX_use_certificate_file(ctx,file_,type_);
end;

function Load_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_certificate_chain_file := LoadLibSSLFunction('SSL_CTX_use_certificate_chain_file');
  if not assigned(SSL_CTX_use_certificate_chain_file) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_use_certificate_chain_file := @COMPAT_SSL_CTX_use_certificate_chain_file;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate_chain_file');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_use_certificate_chain_file(ctx,file_);
end;

function Load_SSL_use_certificate_chain_file(ssl: PSSL; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_use_certificate_chain_file := LoadLibSSLFunction('SSL_use_certificate_chain_file');
  if not assigned(SSL_use_certificate_chain_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_use_certificate_chain_file');
  Result := SSL_use_certificate_chain_file(ssl,file_);
end;

function Load_SSL_load_client_CA_file(const file_: PAnsiChar): PSTACK_OF_X509_NAME; cdecl;
begin
  SSL_load_client_CA_file := LoadLibSSLFunction('SSL_load_client_CA_file');
  if not assigned(SSL_load_client_CA_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_load_client_CA_file');
  Result := SSL_load_client_CA_file(file_);
end;

function Load_SSL_add_file_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_add_file_cert_subjects_to_stack := LoadLibSSLFunction('SSL_add_file_cert_subjects_to_stack');
  if not assigned(SSL_add_file_cert_subjects_to_stack) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_file_cert_subjects_to_stack');
  Result := SSL_add_file_cert_subjects_to_stack(stackCAs,file_);
end;

function Load_SSL_add_dir_cert_subjects_to_stack(stackCAs: PSTACK_OF_X509_NAME; const dir_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_add_dir_cert_subjects_to_stack := LoadLibSSLFunction('SSL_add_dir_cert_subjects_to_stack');
  if not assigned(SSL_add_dir_cert_subjects_to_stack) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_dir_cert_subjects_to_stack');
  Result := SSL_add_dir_cert_subjects_to_stack(stackCAs,dir_);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_SSL_load_error_strings; cdecl;
begin
  SSL_load_error_strings := LoadLibSSLFunction('SSL_load_error_strings');
  if not assigned(SSL_load_error_strings) then
    SSL_load_error_strings := @COMPAT_SSL_load_error_strings;
  SSL_load_error_strings();
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_state_string(const s: PSSL): PAnsiChar; cdecl;
begin
  SSL_state_string := LoadLibSSLFunction('SSL_state_string');
  if not assigned(SSL_state_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_state_string');
  Result := SSL_state_string(s);
end;

function Load_SSL_rstate_string(const s: PSSL): PAnsiChar; cdecl;
begin
  SSL_rstate_string := LoadLibSSLFunction('SSL_rstate_string');
  if not assigned(SSL_rstate_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_rstate_string');
  Result := SSL_rstate_string(s);
end;

function Load_SSL_state_string_long(const s: PSSL): PAnsiChar; cdecl;
begin
  SSL_state_string_long := LoadLibSSLFunction('SSL_state_string_long');
  if not assigned(SSL_state_string_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_state_string_long');
  Result := SSL_state_string_long(s);
end;

function Load_SSL_rstate_string_long(const s: PSSL): PAnsiChar; cdecl;
begin
  SSL_rstate_string_long := LoadLibSSLFunction('SSL_rstate_string_long');
  if not assigned(SSL_rstate_string_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_rstate_string_long');
  Result := SSL_rstate_string_long(s);
end;

function Load_SSL_SESSION_get_time(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl;
begin
  SSL_SESSION_get_time := LoadLibSSLFunction('SSL_SESSION_get_time');
  if not assigned(SSL_SESSION_get_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_time');
  Result := SSL_SESSION_get_time(s);
end;

function Load_SSL_SESSION_set_time(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_SESSION_set_time := LoadLibSSLFunction('SSL_SESSION_set_time');
  if not assigned(SSL_SESSION_set_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_time');
  Result := SSL_SESSION_set_time(s,t);
end;

function Load_SSL_SESSION_get_timeout(const s: PSSL_SESSION): TOpenSSL_C_LONG; cdecl;
begin
  SSL_SESSION_get_timeout := LoadLibSSLFunction('SSL_SESSION_get_timeout');
  if not assigned(SSL_SESSION_get_timeout) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_timeout');
  Result := SSL_SESSION_get_timeout(s);
end;

function Load_SSL_SESSION_set_timeout(s: PSSL_SESSION; t: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  SSL_SESSION_set_timeout := LoadLibSSLFunction('SSL_SESSION_set_timeout');
  if not assigned(SSL_SESSION_set_timeout) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_timeout');
  Result := SSL_SESSION_set_timeout(s,t);
end;

function Load_SSL_SESSION_get_protocol_version(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_get_protocol_version := LoadLibSSLFunction('SSL_SESSION_get_protocol_version');
  if not assigned(SSL_SESSION_get_protocol_version) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_SESSION_get_protocol_version := @COMPAT_SSL_SESSION_get_protocol_version;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_protocol_version');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_SESSION_get_protocol_version(s);
end;

function Load_SSL_SESSION_set_protocol_version(s: PSSL_SESSION; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set_protocol_version := LoadLibSSLFunction('SSL_SESSION_set_protocol_version');
  if not assigned(SSL_SESSION_set_protocol_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_protocol_version');
  Result := SSL_SESSION_set_protocol_version(s,version);
end;

function Load_SSL_SESSION_get0_hostname(const s: PSSL_SESSION): PAnsiChar; cdecl;
begin
  SSL_SESSION_get0_hostname := LoadLibSSLFunction('SSL_SESSION_get0_hostname');
  if not assigned(SSL_SESSION_get0_hostname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_hostname');
  Result := SSL_SESSION_get0_hostname(s);
end;

function Load_SSL_SESSION_set1_hostname(s: PSSL_SESSION; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set1_hostname := LoadLibSSLFunction('SSL_SESSION_set1_hostname');
  if not assigned(SSL_SESSION_set1_hostname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_hostname');
  Result := SSL_SESSION_set1_hostname(s,hostname);
end;

procedure Load_SSL_SESSION_get0_alpn_selected(const s: PSSL_SESSION; const alpn: PPByte; len: POpenSSL_C_SIZET); cdecl;
begin
  SSL_SESSION_get0_alpn_selected := LoadLibSSLFunction('SSL_SESSION_get0_alpn_selected');
  if not assigned(SSL_SESSION_get0_alpn_selected) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_alpn_selected');
  SSL_SESSION_get0_alpn_selected(s,alpn,len);
end;

function Load_SSL_SESSION_set1_alpn_selected(s: PSSL_SESSION; const alpn: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set1_alpn_selected := LoadLibSSLFunction('SSL_SESSION_set1_alpn_selected');
  if not assigned(SSL_SESSION_set1_alpn_selected) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_alpn_selected');
  Result := SSL_SESSION_set1_alpn_selected(s,alpn,len);
end;

function Load_SSL_SESSION_get0_cipher(const s: PSSL_SESSION): PSSL_CIPHER; cdecl;
begin
  SSL_SESSION_get0_cipher := LoadLibSSLFunction('SSL_SESSION_get0_cipher');
  if not assigned(SSL_SESSION_get0_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_cipher');
  Result := SSL_SESSION_get0_cipher(s);
end;

function Load_SSL_SESSION_set_cipher(s: PSSL_SESSION; const cipher: PSSL_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set_cipher := LoadLibSSLFunction('SSL_SESSION_set_cipher');
  if not assigned(SSL_SESSION_set_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_cipher');
  Result := SSL_SESSION_set_cipher(s,cipher);
end;

function Load_SSL_SESSION_has_ticket(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_has_ticket := LoadLibSSLFunction('SSL_SESSION_has_ticket');
  if not assigned(SSL_SESSION_has_ticket) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_has_ticket');
  Result := SSL_SESSION_has_ticket(s);
end;

function Load_SSL_SESSION_get_ticket_lifetime_hint(const s: PSSL_SESSION): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_SESSION_get_ticket_lifetime_hint := LoadLibSSLFunction('SSL_SESSION_get_ticket_lifetime_hint');
  if not assigned(SSL_SESSION_get_ticket_lifetime_hint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_ticket_lifetime_hint');
  Result := SSL_SESSION_get_ticket_lifetime_hint(s);
end;

procedure Load_SSL_SESSION_get0_ticket(const s: PSSL_SESSION; const tick: PPByte; len: POpenSSL_C_SIZET); cdecl;
begin
  SSL_SESSION_get0_ticket := LoadLibSSLFunction('SSL_SESSION_get0_ticket');
  if not assigned(SSL_SESSION_get0_ticket) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_ticket');
  SSL_SESSION_get0_ticket(s,tick,len);
end;

function Load_SSL_SESSION_get_max_early_data(const s: PSSL_SESSION): TOpenSSL_C_UINT32; cdecl;
begin
  SSL_SESSION_get_max_early_data := LoadLibSSLFunction('SSL_SESSION_get_max_early_data');
  if not assigned(SSL_SESSION_get_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_max_early_data');
  Result := SSL_SESSION_get_max_early_data(s);
end;

function Load_SSL_SESSION_set_max_early_data(s: PSSL_SESSION; max_early_data: TOpenSSL_C_UINT32): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set_max_early_data := LoadLibSSLFunction('SSL_SESSION_set_max_early_data');
  if not assigned(SSL_SESSION_set_max_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_max_early_data');
  Result := SSL_SESSION_set_max_early_data(s,max_early_data);
end;

function Load_SSL_copy_session_id(to_: PSSL; const from: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_copy_session_id := LoadLibSSLFunction('SSL_copy_session_id');
  if not assigned(SSL_copy_session_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_copy_session_id');
  Result := SSL_copy_session_id(to_,from);
end;

function Load_SSL_SESSION_get0_peer(s: PSSL_SESSION): PX509; cdecl;
begin
  SSL_SESSION_get0_peer := LoadLibSSLFunction('SSL_SESSION_get0_peer');
  if not assigned(SSL_SESSION_get0_peer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_peer');
  Result := SSL_SESSION_get0_peer(s);
end;

function Load_SSL_SESSION_set1_id_context(s: PSSL_SESSION; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set1_id_context := LoadLibSSLFunction('SSL_SESSION_set1_id_context');
  if not assigned(SSL_SESSION_set1_id_context) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_id_context');
  Result := SSL_SESSION_set1_id_context(s,sid_ctx,sid_ctx_len);
end;

function Load_SSL_SESSION_set1_id(s: PSSL_SESSION; const sid: PByte; sid_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set1_id := LoadLibSSLFunction('SSL_SESSION_set1_id');
  if not assigned(SSL_SESSION_set1_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_id');
  Result := SSL_SESSION_set1_id(s,sid,sid_len);
end;

function Load_SSL_SESSION_is_resumable(const s: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_is_resumable := LoadLibSSLFunction('SSL_SESSION_is_resumable');
  if not assigned(SSL_SESSION_is_resumable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_is_resumable');
  Result := SSL_SESSION_is_resumable(s);
end;

function Load_SSL_SESSION_new: PSSL_SESSION; cdecl;
begin
  SSL_SESSION_new := LoadLibSSLFunction('SSL_SESSION_new');
  if not assigned(SSL_SESSION_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_new');
  Result := SSL_SESSION_new();
end;

function Load_SSL_SESSION_dup(src: PSSL_SESSION): PSSL_SESSION; cdecl;
begin
  SSL_SESSION_dup := LoadLibSSLFunction('SSL_SESSION_dup');
  if not assigned(SSL_SESSION_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_dup');
  Result := SSL_SESSION_dup(src);
end;

function Load_SSL_SESSION_get_id(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl;
begin
  SSL_SESSION_get_id := LoadLibSSLFunction('SSL_SESSION_get_id');
  if not assigned(SSL_SESSION_get_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_id');
  Result := SSL_SESSION_get_id(s,len);
end;

function Load_SSL_SESSION_get0_id_context(const s: PSSL_SESSION; len: POpenSSL_C_UINT): PByte; cdecl;
begin
  SSL_SESSION_get0_id_context := LoadLibSSLFunction('SSL_SESSION_get0_id_context');
  if not assigned(SSL_SESSION_get0_id_context) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_id_context');
  Result := SSL_SESSION_get0_id_context(s,len);
end;

function Load_SSL_SESSION_get_compress_id(const s: PSSL_SESSION): TOpenSSL_C_UINT; cdecl;
begin
  SSL_SESSION_get_compress_id := LoadLibSSLFunction('SSL_SESSION_get_compress_id');
  if not assigned(SSL_SESSION_get_compress_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_compress_id');
  Result := SSL_SESSION_get_compress_id(s);
end;

function Load_SSL_SESSION_print(fp: PBIO; const ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_print := LoadLibSSLFunction('SSL_SESSION_print');
  if not assigned(SSL_SESSION_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_print');
  Result := SSL_SESSION_print(fp,ses);
end;

function Load_SSL_SESSION_print_keylog(bp: PBIO; const x: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_print_keylog := LoadLibSSLFunction('SSL_SESSION_print_keylog');
  if not assigned(SSL_SESSION_print_keylog) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_print_keylog');
  Result := SSL_SESSION_print_keylog(bp,x);
end;

function Load_SSL_SESSION_up_ref(ses: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_up_ref := LoadLibSSLFunction('SSL_SESSION_up_ref');
  if not assigned(SSL_SESSION_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_up_ref');
  Result := SSL_SESSION_up_ref(ses);
end;

procedure Load_SSL_SESSION_free(ses: PSSL_SESSION); cdecl;
begin
  SSL_SESSION_free := LoadLibSSLFunction('SSL_SESSION_free');
  if not assigned(SSL_SESSION_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_free');
  SSL_SESSION_free(ses);
end;

function Load_SSL_set_session(to_: PSSL; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_session := LoadLibSSLFunction('SSL_set_session');
  if not assigned(SSL_set_session) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session');
  Result := SSL_set_session(to_,session);
end;

function Load_SSL_CTX_add_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_add_session := LoadLibSSLFunction('SSL_CTX_add_session');
  if not assigned(SSL_CTX_add_session) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add_session');
  Result := SSL_CTX_add_session(ctx,session);
end;

function Load_SSL_CTX_remove_session(ctx: PSSL_CTX; session: PSSL_SESSION): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_remove_session := LoadLibSSLFunction('SSL_CTX_remove_session');
  if not assigned(SSL_CTX_remove_session) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_remove_session');
  Result := SSL_CTX_remove_session(ctx,session);
end;

function Load_SSL_CTX_set_generate_session_id(ctx: PSSL_CTX; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_generate_session_id := LoadLibSSLFunction('SSL_CTX_set_generate_session_id');
  if not assigned(SSL_CTX_set_generate_session_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_generate_session_id');
  Result := SSL_CTX_set_generate_session_id(ctx,cb);
end;

function Load_SSL_set_generate_session_id(s: PSSL; cb: GEN_SESSION_CB): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_generate_session_id := LoadLibSSLFunction('SSL_set_generate_session_id');
  if not assigned(SSL_set_generate_session_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_generate_session_id');
  Result := SSL_set_generate_session_id(s,cb);
end;

function Load_SSL_has_matching_session_id(const s: PSSL; const id: PByte; id_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  SSL_has_matching_session_id := LoadLibSSLFunction('SSL_has_matching_session_id');
  if not assigned(SSL_has_matching_session_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_has_matching_session_id');
  Result := SSL_has_matching_session_id(s,id,id_len);
end;

function Load_d2i_SSL_SESSION(a: PPSSL_SESSION; const pp: PPByte; length: TOpenSSL_C_LONG): PSSL_SESSION; cdecl;
begin
  d2i_SSL_SESSION := LoadLibSSLFunction('d2i_SSL_SESSION');
  if not assigned(d2i_SSL_SESSION) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_SSL_SESSION');
  Result := d2i_SSL_SESSION(a,pp,length);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_get_peer_certificate(const s: PSSL): PX509; cdecl;
begin
  SSL_get_peer_certificate := LoadLibSSLFunction('SSL_get_peer_certificate');
  if not assigned(SSL_get_peer_certificate) then
    SSL_get_peer_certificate := @COMPAT_SSL_get_peer_certificate;
  Result := SSL_get_peer_certificate(s);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_CTX_get_verify_mode(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_get_verify_mode := LoadLibSSLFunction('SSL_CTX_get_verify_mode');
  if not assigned(SSL_CTX_get_verify_mode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_verify_mode');
  Result := SSL_CTX_get_verify_mode(ctx);
end;

function Load_SSL_CTX_get_verify_depth(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_get_verify_depth := LoadLibSSLFunction('SSL_CTX_get_verify_depth');
  if not assigned(SSL_CTX_get_verify_depth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_verify_depth');
  Result := SSL_CTX_get_verify_depth(ctx);
end;

function Load_SSL_CTX_get_verify_callback(const ctx: PSSL_CTX): SSL_verify_cb; cdecl;
begin
  SSL_CTX_get_verify_callback := LoadLibSSLFunction('SSL_CTX_get_verify_callback');
  if not assigned(SSL_CTX_get_verify_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_verify_callback');
  Result := SSL_CTX_get_verify_callback(ctx);
end;

procedure Load_SSL_CTX_set_verify(ctx: PSSL_CTX; mode: TOpenSSL_C_INT; callback: SSL_verify_cb); cdecl;
begin
  SSL_CTX_set_verify := LoadLibSSLFunction('SSL_CTX_set_verify');
  if not assigned(SSL_CTX_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_verify');
  SSL_CTX_set_verify(ctx,mode,callback);
end;

procedure Load_SSL_CTX_set_verify_depth(ctx: PSSL_CTX; depth: TOpenSSL_C_INT); cdecl;
begin
  SSL_CTX_set_verify_depth := LoadLibSSLFunction('SSL_CTX_set_verify_depth');
  if not assigned(SSL_CTX_set_verify_depth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_verify_depth');
  SSL_CTX_set_verify_depth(ctx,depth);
end;

procedure Load_SSL_CTX_set_cert_verify_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_cert_verify_callback_cb; arg: Pointer); cdecl;
begin
  SSL_CTX_set_cert_verify_callback := LoadLibSSLFunction('SSL_CTX_set_cert_verify_callback');
  if not assigned(SSL_CTX_set_cert_verify_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cert_verify_callback');
  SSL_CTX_set_cert_verify_callback(ctx,cb,arg);
end;

procedure Load_SSL_CTX_set_cert_cb(c: PSSL_CTX; cb: SSL_CTX_set_cert_cb_cb; arg: Pointer); cdecl;
begin
  SSL_CTX_set_cert_cb := LoadLibSSLFunction('SSL_CTX_set_cert_cb');
  if not assigned(SSL_CTX_set_cert_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_cert_cb');
  SSL_CTX_set_cert_cb(c,cb,arg);
end;

function Load_SSL_CTX_use_RSAPrivateKey(ctx: PSSL_CTX; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_RSAPrivateKey := LoadLibSSLFunction('SSL_CTX_use_RSAPrivateKey');
  if not assigned(SSL_CTX_use_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_RSAPrivateKey');
  Result := SSL_CTX_use_RSAPrivateKey(ctx,rsa);
end;

function Load_SSL_CTX_use_RSAPrivateKey_ASN1(ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_RSAPrivateKey_ASN1 := LoadLibSSLFunction('SSL_CTX_use_RSAPrivateKey_ASN1');
  if not assigned(SSL_CTX_use_RSAPrivateKey_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_RSAPrivateKey_ASN1');
  Result := SSL_CTX_use_RSAPrivateKey_ASN1(ctx,d,len);
end;

function Load_SSL_CTX_use_PrivateKey(ctx: PSSL_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_PrivateKey := LoadLibSSLFunction('SSL_CTX_use_PrivateKey');
  if not assigned(SSL_CTX_use_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_PrivateKey');
  Result := SSL_CTX_use_PrivateKey(ctx,pkey);
end;

function Load_SSL_CTX_use_PrivateKey_ASN1(pk: TOpenSSL_C_INT; ctx: PSSL_CTX; const d: PByte; len: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_PrivateKey_ASN1 := LoadLibSSLFunction('SSL_CTX_use_PrivateKey_ASN1');
  if not assigned(SSL_CTX_use_PrivateKey_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_PrivateKey_ASN1');
  Result := SSL_CTX_use_PrivateKey_ASN1(pk,ctx,d,len);
end;

function Load_SSL_CTX_use_certificate(ctx: PSSL_CTX; x: X509): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_certificate := LoadLibSSLFunction('SSL_CTX_use_certificate');
  if not assigned(SSL_CTX_use_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate');
  Result := SSL_CTX_use_certificate(ctx,x);
end;

function Load_SSL_CTX_use_certificate_ASN1(ctx: PSSL_CTX; len: TOpenSSL_C_INT; const d: PByte): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_use_certificate_ASN1 := LoadLibSSLFunction('SSL_CTX_use_certificate_ASN1');
  if not assigned(SSL_CTX_use_certificate_ASN1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_use_certificate_ASN1');
  Result := SSL_CTX_use_certificate_ASN1(ctx,len,d);
end;

procedure Load_SSL_CTX_set_default_passwd_cb(ctx: PSSL_CTX; cb: pem_password_cb); cdecl;
begin
  SSL_CTX_set_default_passwd_cb := LoadLibSSLFunction('SSL_CTX_set_default_passwd_cb');
  if not assigned(SSL_CTX_set_default_passwd_cb) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_set_default_passwd_cb := @COMPAT_SSL_CTX_set_default_passwd_cb;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_passwd_cb');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  SSL_CTX_set_default_passwd_cb(ctx,cb);
end;

procedure Load_SSL_CTX_set_default_passwd_cb_userdata(ctx: PSSL_CTX; u: Pointer); cdecl;
begin
  SSL_CTX_set_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_CTX_set_default_passwd_cb_userdata');
  if not assigned(SSL_CTX_set_default_passwd_cb_userdata) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_set_default_passwd_cb_userdata := @COMPAT_SSL_CTX_set_default_passwd_cb_userdata;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_passwd_cb_userdata');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  SSL_CTX_set_default_passwd_cb_userdata(ctx,u);
end;

function Load_SSL_CTX_get_default_passwd_cb(ctx: PSSL_CTX): pem_password_cb; cdecl;
begin
  SSL_CTX_get_default_passwd_cb := LoadLibSSLFunction('SSL_CTX_get_default_passwd_cb');
  if not assigned(SSL_CTX_get_default_passwd_cb) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_default_passwd_cb := @COMPAT_SSL_CTX_get_default_passwd_cb;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_default_passwd_cb');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_get_default_passwd_cb(ctx);
end;

function Load_SSL_CTX_get_default_passwd_cb_userdata(ctx: PSSL_CTX): Pointer; cdecl;
begin
  SSL_CTX_get_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_CTX_get_default_passwd_cb_userdata');
  if not assigned(SSL_CTX_get_default_passwd_cb_userdata) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_CTX_get_default_passwd_cb_userdata := @COMPAT_SSL_CTX_get_default_passwd_cb_userdata;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_default_passwd_cb_userdata');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_CTX_get_default_passwd_cb_userdata(ctx);
end;

procedure Load_SSL_set_default_passwd_cb(s: PSSL; cb: pem_password_cb); cdecl;
begin
  SSL_set_default_passwd_cb := LoadLibSSLFunction('SSL_set_default_passwd_cb');
  if not assigned(SSL_set_default_passwd_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_default_passwd_cb');
  SSL_set_default_passwd_cb(s,cb);
end;

procedure Load_SSL_set_default_passwd_cb_userdata(s: PSSL; u: Pointer); cdecl;
begin
  SSL_set_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_set_default_passwd_cb_userdata');
  if not assigned(SSL_set_default_passwd_cb_userdata) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_default_passwd_cb_userdata');
  SSL_set_default_passwd_cb_userdata(s,u);
end;

function Load_SSL_get_default_passwd_cb(s: PSSL): pem_password_cb; cdecl;
begin
  SSL_get_default_passwd_cb := LoadLibSSLFunction('SSL_get_default_passwd_cb');
  if not assigned(SSL_get_default_passwd_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_default_passwd_cb');
  Result := SSL_get_default_passwd_cb(s);
end;

function Load_SSL_get_default_passwd_cb_userdata(s: PSSL): Pointer; cdecl;
begin
  SSL_get_default_passwd_cb_userdata := LoadLibSSLFunction('SSL_get_default_passwd_cb_userdata');
  if not assigned(SSL_get_default_passwd_cb_userdata) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_default_passwd_cb_userdata');
  Result := SSL_get_default_passwd_cb_userdata(s);
end;

function Load_SSL_CTX_check_private_key(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_check_private_key := LoadLibSSLFunction('SSL_CTX_check_private_key');
  if not assigned(SSL_CTX_check_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_check_private_key');
  Result := SSL_CTX_check_private_key(ctx);
end;

function Load_SSL_check_private_key(const ctx: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_check_private_key := LoadLibSSLFunction('SSL_check_private_key');
  if not assigned(SSL_check_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_check_private_key');
  Result := SSL_check_private_key(ctx);
end;

function Load_SSL_CTX_set_session_id_context(ctx: PSSL_CTX; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_session_id_context := LoadLibSSLFunction('SSL_CTX_set_session_id_context');
  if not assigned(SSL_CTX_set_session_id_context) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_session_id_context');
  Result := SSL_CTX_set_session_id_context(ctx,sid_ctx,sid_ctx_len);
end;

function Load_SSL_new(ctx: PSSL_CTX): PSSL; cdecl;
begin
  SSL_new := LoadLibSSLFunction('SSL_new');
  if not assigned(SSL_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_new');
  Result := SSL_new(ctx);
end;

function Load_SSL_up_ref(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_up_ref := LoadLibSSLFunction('SSL_up_ref');
  if not assigned(SSL_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_up_ref');
  Result := SSL_up_ref(s);
end;

function Load_SSL_is_dtls(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_is_dtls := LoadLibSSLFunction('SSL_is_dtls');
  if not assigned(SSL_is_dtls) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_is_dtls');
  Result := SSL_is_dtls(s);
end;

function Load_SSL_set_session_id_context(ssl: PSSL; const sid_ctx: PByte; sid_ctx_len: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_session_id_context := LoadLibSSLFunction('SSL_set_session_id_context');
  if not assigned(SSL_set_session_id_context) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session_id_context');
  Result := SSL_set_session_id_context(ssl,sid_ctx,sid_ctx_len);
end;

function Load_SSL_CTX_set_purpose(ctx: PSSL_CTX; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_purpose := LoadLibSSLFunction('SSL_CTX_set_purpose');
  if not assigned(SSL_CTX_set_purpose) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_purpose');
  Result := SSL_CTX_set_purpose(ctx,purpose);
end;

function Load_SSL_set_purpose(ssl: PSSL; purpose: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_purpose := LoadLibSSLFunction('SSL_set_purpose');
  if not assigned(SSL_set_purpose) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_purpose');
  Result := SSL_set_purpose(ssl,purpose);
end;

function Load_SSL_CTX_set_trust(ctx: PSSL_CTX; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_trust := LoadLibSSLFunction('SSL_CTX_set_trust');
  if not assigned(SSL_CTX_set_trust) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_trust');
  Result := SSL_CTX_set_trust(ctx,trust);
end;

function Load_SSL_set_trust(ssl: PSSL; trust: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_trust := LoadLibSSLFunction('SSL_set_trust');
  if not assigned(SSL_set_trust) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_trust');
  Result := SSL_set_trust(ssl,trust);
end;

function Load_SSL_set1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set1_host := LoadLibSSLFunction('SSL_set1_host');
  if not assigned(SSL_set1_host) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_host');
  Result := SSL_set1_host(s,hostname);
end;

function Load_SSL_add1_host(s: PSSL; const hostname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_add1_host := LoadLibSSLFunction('SSL_add1_host');
  if not assigned(SSL_add1_host) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add1_host');
  Result := SSL_add1_host(s,hostname);
end;

function Load_SSL_get0_peername(s: PSSL): PAnsiChar; cdecl;
begin
  SSL_get0_peername := LoadLibSSLFunction('SSL_get0_peername');
  if not assigned(SSL_get0_peername) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_peername');
  Result := SSL_get0_peername(s);
end;

procedure Load_SSL_set_hostflags(s: PSSL; flags: TOpenSSL_C_UINT); cdecl;
begin
  SSL_set_hostflags := LoadLibSSLFunction('SSL_set_hostflags');
  if not assigned(SSL_set_hostflags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_hostflags');
  SSL_set_hostflags(s,flags);
end;

function Load_SSL_CTX_dane_enable(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_dane_enable := LoadLibSSLFunction('SSL_CTX_dane_enable');
  if not assigned(SSL_CTX_dane_enable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_enable');
  Result := SSL_CTX_dane_enable(ctx);
end;

function Load_SSL_CTX_dane_mtype_set(ctx: PSSL_CTX; const md: PEVP_MD; mtype: TOpenSSL_C_UINT8; ord: TOpenSSL_C_UINT8): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_dane_mtype_set := LoadLibSSLFunction('SSL_CTX_dane_mtype_set');
  if not assigned(SSL_CTX_dane_mtype_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_mtype_set');
  Result := SSL_CTX_dane_mtype_set(ctx,md,mtype,ord);
end;

function Load_SSL_dane_enable(s: PSSL; const basedomain: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_dane_enable := LoadLibSSLFunction('SSL_dane_enable');
  if not assigned(SSL_dane_enable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_enable');
  Result := SSL_dane_enable(s,basedomain);
end;

function Load_SSL_dane_tlsa_add(s: PSSL; usage: TOpenSSL_C_UINT8; selector: TOpenSSL_C_UINT8; mtype: TOpenSSL_C_UINT8; const data: PByte; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_dane_tlsa_add := LoadLibSSLFunction('SSL_dane_tlsa_add');
  if not assigned(SSL_dane_tlsa_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_tlsa_add');
  Result := SSL_dane_tlsa_add(s,usage,selector,mtype,data,dlen);
end;

function Load_SSL_get0_dane_authority(s: PSSL; mcert: PPX509; mspki: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  SSL_get0_dane_authority := LoadLibSSLFunction('SSL_get0_dane_authority');
  if not assigned(SSL_get0_dane_authority) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_dane_authority');
  Result := SSL_get0_dane_authority(s,mcert,mspki);
end;

function Load_SSL_get0_dane_tlsa(s: PSSL; usage: POpenSSL_C_UINT8; selector: POpenSSL_C_UINT8; mtype: POpenSSL_C_UINT8; const data: PPByte; dlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_get0_dane_tlsa := LoadLibSSLFunction('SSL_get0_dane_tlsa');
  if not assigned(SSL_get0_dane_tlsa) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_dane_tlsa');
  Result := SSL_get0_dane_tlsa(s,usage,selector,mtype,data,dlen);
end;

function Load_SSL_get0_dane(ssl: PSSL): PSSL_DANE; cdecl;
begin
  SSL_get0_dane := LoadLibSSLFunction('SSL_get0_dane');
  if not assigned(SSL_get0_dane) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_dane');
  Result := SSL_get0_dane(ssl);
end;

function Load_SSL_CTX_dane_set_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_CTX_dane_set_flags := LoadLibSSLFunction('SSL_CTX_dane_set_flags');
  if not assigned(SSL_CTX_dane_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_set_flags');
  Result := SSL_CTX_dane_set_flags(ctx,flags);
end;

function Load_SSL_CTX_dane_clear_flags(ctx: PSSL_CTX; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_CTX_dane_clear_flags := LoadLibSSLFunction('SSL_CTX_dane_clear_flags');
  if not assigned(SSL_CTX_dane_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_dane_clear_flags');
  Result := SSL_CTX_dane_clear_flags(ctx,flags);
end;

function Load_SSL_dane_set_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_dane_set_flags := LoadLibSSLFunction('SSL_dane_set_flags');
  if not assigned(SSL_dane_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_set_flags');
  Result := SSL_dane_set_flags(ssl,flags);
end;

function Load_SSL_dane_clear_flags(ssl: PSSL; flags: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
begin
  SSL_dane_clear_flags := LoadLibSSLFunction('SSL_dane_clear_flags');
  if not assigned(SSL_dane_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dane_clear_flags');
  Result := SSL_dane_clear_flags(ssl,flags);
end;

function Load_SSL_CTX_set1_param(ctx: PSSL_CTX; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set1_param := LoadLibSSLFunction('SSL_CTX_set1_param');
  if not assigned(SSL_CTX_set1_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_param');
  Result := SSL_CTX_set1_param(ctx,vpm);
end;

function Load_SSL_set1_param(ssl: PSSL; vpm: PX509_VERIFY_PARAM): TOpenSSL_C_INT; cdecl;
begin
  SSL_set1_param := LoadLibSSLFunction('SSL_set1_param');
  if not assigned(SSL_set1_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_param');
  Result := SSL_set1_param(ssl,vpm);
end;

function Load_SSL_CTX_get0_param(ctx: PSSL_CTX): PX509_VERIFY_PARAM; cdecl;
begin
  SSL_CTX_get0_param := LoadLibSSLFunction('SSL_CTX_get0_param');
  if not assigned(SSL_CTX_get0_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_param');
  Result := SSL_CTX_get0_param(ctx);
end;

function Load_SSL_get0_param(ssl: PSSL): PX509_VERIFY_PARAM; cdecl;
begin
  SSL_get0_param := LoadLibSSLFunction('SSL_get0_param');
  if not assigned(SSL_get0_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_param');
  Result := SSL_get0_param(ssl);
end;

function Load_SSL_CTX_set_srp_username(ctx: PSSL_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_username := LoadLibSSLFunction('SSL_CTX_set_srp_username');
  if not assigned(SSL_CTX_set_srp_username) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_username');
  Result := SSL_CTX_set_srp_username(ctx,name);
end;

function Load_SSL_CTX_set_srp_password(ctx: PSSL_CTX; password: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_password := LoadLibSSLFunction('SSL_CTX_set_srp_password');
  if not assigned(SSL_CTX_set_srp_password) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_password');
  Result := SSL_CTX_set_srp_password(ctx,password);
end;

function Load_SSL_CTX_set_srp_strength(ctx: PSSL_CTX; strength: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_strength := LoadLibSSLFunction('SSL_CTX_set_srp_strength');
  if not assigned(SSL_CTX_set_srp_strength) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_strength');
  Result := SSL_CTX_set_srp_strength(ctx,strength);
end;

function Load_SSL_CTX_set_srp_client_pwd_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_client_pwd_callback_cb): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_client_pwd_callback := LoadLibSSLFunction('SSL_CTX_set_srp_client_pwd_callback');
  if not assigned(SSL_CTX_set_srp_client_pwd_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_client_pwd_callback');
  Result := SSL_CTX_set_srp_client_pwd_callback(ctx,cb);
end;

function Load_SSL_CTX_set_srp_verify_param_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_verify_param_callback_cb): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_verify_param_callback := LoadLibSSLFunction('SSL_CTX_set_srp_verify_param_callback');
  if not assigned(SSL_CTX_set_srp_verify_param_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_verify_param_callback');
  Result := SSL_CTX_set_srp_verify_param_callback(ctx,cb);
end;

function Load_SSL_CTX_set_srp_username_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_srp_username_callback_cb): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_username_callback := LoadLibSSLFunction('SSL_CTX_set_srp_username_callback');
  if not assigned(SSL_CTX_set_srp_username_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_username_callback');
  Result := SSL_CTX_set_srp_username_callback(ctx,cb);
end;

function Load_SSL_CTX_set_srp_cb_arg(ctx: PSSL_CTX; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_srp_cb_arg := LoadLibSSLFunction('SSL_CTX_set_srp_cb_arg');
  if not assigned(SSL_CTX_set_srp_cb_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_srp_cb_arg');
  Result := SSL_CTX_set_srp_cb_arg(ctx,arg);
end;

function Load_SSL_set_srp_server_param(s: PSSL; const N: PBIGNUm; const g: PBIGNUm; sa: PBIGNUm; v: PBIGNUm; info: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_srp_server_param := LoadLibSSLFunction('SSL_set_srp_server_param');
  if not assigned(SSL_set_srp_server_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_srp_server_param');
  Result := SSL_set_srp_server_param(s,N,g,sa,v,info);
end;

function Load_SSL_set_srp_server_param_pw(s: PSSL; const user: PAnsiChar; const pass: PAnsiChar; const grp: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_srp_server_param_pw := LoadLibSSLFunction('SSL_set_srp_server_param_pw');
  if not assigned(SSL_set_srp_server_param_pw) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_srp_server_param_pw');
  Result := SSL_set_srp_server_param_pw(s,user,pass,grp);
end;

procedure Load_SSL_CTX_set_client_hello_cb(c: PSSL_CTX; cb: SSL_client_hello_cb_fn; arg: Pointer); cdecl;
begin
  SSL_CTX_set_client_hello_cb := LoadLibSSLFunction('SSL_CTX_set_client_hello_cb');
  if not assigned(SSL_CTX_set_client_hello_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_hello_cb');
  SSL_CTX_set_client_hello_cb(c,cb,arg);
end;

function Load_SSL_client_hello_isv2(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_client_hello_isv2 := LoadLibSSLFunction('SSL_client_hello_isv2');
  if not assigned(SSL_client_hello_isv2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_isv2');
  Result := SSL_client_hello_isv2(s);
end;

function Load_SSL_client_hello_get0_legacy_version(s: PSSL): TOpenSSL_C_UINT; cdecl;
begin
  SSL_client_hello_get0_legacy_version := LoadLibSSLFunction('SSL_client_hello_get0_legacy_version');
  if not assigned(SSL_client_hello_get0_legacy_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_legacy_version');
  Result := SSL_client_hello_get0_legacy_version(s);
end;

function Load_SSL_client_hello_get0_random(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_client_hello_get0_random := LoadLibSSLFunction('SSL_client_hello_get0_random');
  if not assigned(SSL_client_hello_get0_random) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_random');
  Result := SSL_client_hello_get0_random(s,out_);
end;

function Load_SSL_client_hello_get0_session_id(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_client_hello_get0_session_id := LoadLibSSLFunction('SSL_client_hello_get0_session_id');
  if not assigned(SSL_client_hello_get0_session_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_session_id');
  Result := SSL_client_hello_get0_session_id(s,out_);
end;

function Load_SSL_client_hello_get0_ciphers(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_client_hello_get0_ciphers := LoadLibSSLFunction('SSL_client_hello_get0_ciphers');
  if not assigned(SSL_client_hello_get0_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_ciphers');
  Result := SSL_client_hello_get0_ciphers(s,out_);
end;

function Load_SSL_client_hello_get0_compression_methods(s: PSSL; const out_: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_client_hello_get0_compression_methods := LoadLibSSLFunction('SSL_client_hello_get0_compression_methods');
  if not assigned(SSL_client_hello_get0_compression_methods) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_compression_methods');
  Result := SSL_client_hello_get0_compression_methods(s,out_);
end;

function Load_SSL_client_hello_get1_extensions_present(s: PSSL; out_: PPOpenSSL_C_INT; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_client_hello_get1_extensions_present := LoadLibSSLFunction('SSL_client_hello_get1_extensions_present');
  if not assigned(SSL_client_hello_get1_extensions_present) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get1_extensions_present');
  Result := SSL_client_hello_get1_extensions_present(s,out_,outlen);
end;

function Load_SSL_client_hello_get0_ext(s: PSSL; type_: TOpenSSL_C_UINT; const out_: PPByte; outlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_client_hello_get0_ext := LoadLibSSLFunction('SSL_client_hello_get0_ext');
  if not assigned(SSL_client_hello_get0_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_hello_get0_ext');
  Result := SSL_client_hello_get0_ext(s,type_,out_,outlen);
end;

procedure Load_SSL_certs_clear(s: PSSL); cdecl;
begin
  SSL_certs_clear := LoadLibSSLFunction('SSL_certs_clear');
  if not assigned(SSL_certs_clear) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_certs_clear');
  SSL_certs_clear(s);
end;

procedure Load_SSL_free(ssl: PSSL); cdecl;
begin
  SSL_free := LoadLibSSLFunction('SSL_free');
  if not assigned(SSL_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_free');
  SSL_free(ssl);
end;

function Load_SSL_waiting_for_async(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_waiting_for_async := LoadLibSSLFunction('SSL_waiting_for_async');
  if not assigned(SSL_waiting_for_async) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_waiting_for_async');
  Result := SSL_waiting_for_async(s);
end;

function Load_SSL_get_all_async_fds(s: PSSL; fds: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_all_async_fds := LoadLibSSLFunction('SSL_get_all_async_fds');
  if not assigned(SSL_get_all_async_fds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_all_async_fds');
  Result := SSL_get_all_async_fds(s,fds,numfds);
end;

function Load_SSL_get_changed_async_fds(s: PSSL; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_changed_async_fds := LoadLibSSLFunction('SSL_get_changed_async_fds');
  if not assigned(SSL_get_changed_async_fds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_changed_async_fds');
  Result := SSL_get_changed_async_fds(s,addfd,numaddfds,delfd,numdelfds);
end;

function Load_SSL_accept(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_accept := LoadLibSSLFunction('SSL_accept');
  if not assigned(SSL_accept) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_accept');
  Result := SSL_accept(ssl);
end;

function Load_SSL_stateless(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_stateless := LoadLibSSLFunction('SSL_stateless');
  if not assigned(SSL_stateless) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_stateless');
  Result := SSL_stateless(s);
end;

function Load_SSL_connect(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_connect := LoadLibSSLFunction('SSL_connect');
  if not assigned(SSL_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_connect');
  Result := SSL_connect(ssl);
end;

function Load_SSL_read(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_read := LoadLibSSLFunction('SSL_read');
  if not assigned(SSL_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_read');
  Result := SSL_read(ssl,buf,num);
end;

function Load_SSL_read_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_read_ex := LoadLibSSLFunction('SSL_read_ex');
  if not assigned(SSL_read_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_read_ex');
  Result := SSL_read_ex(ssl,buf,num,readbytes);
end;

function Load_SSL_read_early_data(s: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_read_early_data := LoadLibSSLFunction('SSL_read_early_data');
  if not assigned(SSL_read_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_read_early_data');
  Result := SSL_read_early_data(s,buf,num,readbytes);
end;

function Load_SSL_peek(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_peek := LoadLibSSLFunction('SSL_peek');
  if not assigned(SSL_peek) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_peek');
  Result := SSL_peek(ssl,buf,num);
end;

function Load_SSL_peek_ex(ssl: PSSL; buf: Pointer; num: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_peek_ex := LoadLibSSLFunction('SSL_peek_ex');
  if not assigned(SSL_peek_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_peek_ex');
  Result := SSL_peek_ex(ssl,buf,num,readbytes);
end;

function Load_SSL_write(ssl: PSSL; const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_write := LoadLibSSLFunction('SSL_write');
  if not assigned(SSL_write) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_write');
  Result := SSL_write(ssl,buf,num);
end;

function Load_SSL_write_ex(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_write_ex := LoadLibSSLFunction('SSL_write_ex');
  if not assigned(SSL_write_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_write_ex');
  Result := SSL_write_ex(s,buf,num,written);
end;

function Load_SSL_write_early_data(s: PSSL; const buf: Pointer; num: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_write_early_data := LoadLibSSLFunction('SSL_write_early_data');
  if not assigned(SSL_write_early_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_write_early_data');
  Result := SSL_write_early_data(s,buf,num,written);
end;

function Load_SSL_callback_ctrl(v1: PSSL; v2: TOpenSSL_C_INT; v3: SSL_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl;
begin
  SSL_callback_ctrl := LoadLibSSLFunction('SSL_callback_ctrl');
  if not assigned(SSL_callback_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_callback_ctrl');
  Result := SSL_callback_ctrl(v1,v2,v3);
end;

function Load_SSL_ctrl(ssl: PSSL; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_ctrl := LoadLibSSLFunction('SSL_ctrl');
  if not assigned(SSL_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ctrl');
  Result := SSL_ctrl(ssl,cmd,larg,parg);
end;

function Load_SSL_CTX_ctrl(ctx: PSSL_CTX; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_ctrl := LoadLibSSLFunction('SSL_CTX_ctrl');
  if not assigned(SSL_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_ctrl');
  Result := SSL_CTX_ctrl(ctx,cmd,larg,parg);
end;

function Load_SSL_CTX_callback_ctrl(v1: PSSL_CTX; v2: TOpenSSL_C_INT; v3: SSL_CTX_callback_ctrl_v3): TOpenSSL_C_LONG; cdecl;
begin
  SSL_CTX_callback_ctrl := LoadLibSSLFunction('SSL_CTX_callback_ctrl');
  if not assigned(SSL_CTX_callback_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_callback_ctrl');
  Result := SSL_CTX_callback_ctrl(v1,v2,v3);
end;

function Load_SSL_get_early_data_status(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_early_data_status := LoadLibSSLFunction('SSL_get_early_data_status');
  if not assigned(SSL_get_early_data_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_early_data_status');
  Result := SSL_get_early_data_status(s);
end;

function Load_SSL_get_error(const s: PSSL; ret_code: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_error := LoadLibSSLFunction('SSL_get_error');
  if not assigned(SSL_get_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_error');
  Result := SSL_get_error(s,ret_code);
end;

function Load_SSL_get_version(const s: PSSL): PAnsiChar; cdecl;
begin
  SSL_get_version := LoadLibSSLFunction('SSL_get_version');
  if not assigned(SSL_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_version');
  Result := SSL_get_version(s);
end;

function Load_SSL_CTX_set_ssl_version(ctx: PSSL_CTX; const meth: PSSL_METHOD): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_ssl_version := LoadLibSSLFunction('SSL_CTX_set_ssl_version');
  if not assigned(SSL_CTX_set_ssl_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ssl_version');
  Result := SSL_CTX_set_ssl_version(ctx,meth);
end;

function Load_TLS_method: PSSL_METHOD; cdecl;
begin
  TLS_method := LoadLibSSLFunction('TLS_method');
  if not assigned(TLS_method) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    TLS_method := @COMPAT_TLS_method;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('TLS_method');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := TLS_method();
end;

function Load_TLS_server_method: PSSL_METHOD; cdecl;
begin
  TLS_server_method := LoadLibSSLFunction('TLS_server_method');
  if not assigned(TLS_server_method) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    TLS_server_method := @COMPAT_TLS_server_method;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('TLS_server_method');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := TLS_server_method();
end;

function Load_TLS_client_method: PSSL_METHOD; cdecl;
begin
  TLS_client_method := LoadLibSSLFunction('TLS_client_method');
  if not assigned(TLS_client_method) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    TLS_client_method := @COMPAT_TLS_client_method;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('TLS_client_method');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := TLS_client_method();
end;

function Load_SSL_do_handshake(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_do_handshake := LoadLibSSLFunction('SSL_do_handshake');
  if not assigned(SSL_do_handshake) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_do_handshake');
  Result := SSL_do_handshake(s);
end;

function Load_SSL_key_update(s: PSSL; updatetype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_key_update := LoadLibSSLFunction('SSL_key_update');
  if not assigned(SSL_key_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_key_update');
  Result := SSL_key_update(s,updatetype);
end;

function Load_SSL_get_key_update_type(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_key_update_type := LoadLibSSLFunction('SSL_get_key_update_type');
  if not assigned(SSL_get_key_update_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_key_update_type');
  Result := SSL_get_key_update_type(s);
end;

function Load_SSL_renegotiate(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_renegotiate := LoadLibSSLFunction('SSL_renegotiate');
  if not assigned(SSL_renegotiate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_renegotiate');
  Result := SSL_renegotiate(s);
end;

function Load_SSL_renegotiate_abbreviated(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_renegotiate_abbreviated := LoadLibSSLFunction('SSL_renegotiate_abbreviated');
  if not assigned(SSL_renegotiate_abbreviated) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_renegotiate_abbreviated');
  Result := SSL_renegotiate_abbreviated(s);
end;

function Load_SSL_new_session_ticket(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_new_session_ticket := LoadLibSSLFunction('SSL_new_session_ticket');
  if not assigned(SSL_new_session_ticket) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    SSL_new_session_ticket := @COMPAT_SSL_new_session_ticket;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_new_session_ticket');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := SSL_new_session_ticket(s);
end;

function Load_SSL_shutdown(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_shutdown := LoadLibSSLFunction('SSL_shutdown');
  if not assigned(SSL_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_shutdown');
  Result := SSL_shutdown(s);
end;

procedure Load_SSL_CTX_set_post_handshake_auth(ctx: PSSL_CTX; val: TOpenSSL_C_INT); cdecl;
begin
  SSL_CTX_set_post_handshake_auth := LoadLibSSLFunction('SSL_CTX_set_post_handshake_auth');
  if not assigned(SSL_CTX_set_post_handshake_auth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_post_handshake_auth');
  SSL_CTX_set_post_handshake_auth(ctx,val);
end;

procedure Load_SSL_set_post_handshake_auth(s: PSSL; val: TOpenSSL_C_INT); cdecl;
begin
  SSL_set_post_handshake_auth := LoadLibSSLFunction('SSL_set_post_handshake_auth');
  if not assigned(SSL_set_post_handshake_auth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_post_handshake_auth');
  SSL_set_post_handshake_auth(s,val);
end;

function Load_SSL_renegotiate_pending(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_renegotiate_pending := LoadLibSSLFunction('SSL_renegotiate_pending');
  if not assigned(SSL_renegotiate_pending) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_renegotiate_pending');
  Result := SSL_renegotiate_pending(s);
end;

function Load_SSL_verify_client_post_handshake(s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_verify_client_post_handshake := LoadLibSSLFunction('SSL_verify_client_post_handshake');
  if not assigned(SSL_verify_client_post_handshake) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_verify_client_post_handshake');
  Result := SSL_verify_client_post_handshake(s);
end;

function Load_SSL_CTX_get_ssl_method(const ctx: PSSL_CTX): PSSL_METHOD; cdecl;
begin
  SSL_CTX_get_ssl_method := LoadLibSSLFunction('SSL_CTX_get_ssl_method');
  if not assigned(SSL_CTX_get_ssl_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_ssl_method');
  Result := SSL_CTX_get_ssl_method(ctx);
end;

function Load_SSL_get_ssl_method(const s: PSSL): PSSL_METHOD; cdecl;
begin
  SSL_get_ssl_method := LoadLibSSLFunction('SSL_get_ssl_method');
  if not assigned(SSL_get_ssl_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_ssl_method');
  Result := SSL_get_ssl_method(s);
end;

function Load_SSL_set_ssl_method(s: PSSL; const method: PSSL_METHOD): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_ssl_method := LoadLibSSLFunction('SSL_set_ssl_method');
  if not assigned(SSL_set_ssl_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_ssl_method');
  Result := SSL_set_ssl_method(s,method);
end;

function Load_SSL_alert_type_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_alert_type_string_long := LoadLibSSLFunction('SSL_alert_type_string_long');
  if not assigned(SSL_alert_type_string_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_type_string_long');
  Result := SSL_alert_type_string_long(value);
end;

function Load_SSL_alert_type_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_alert_type_string := LoadLibSSLFunction('SSL_alert_type_string');
  if not assigned(SSL_alert_type_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_type_string');
  Result := SSL_alert_type_string(value);
end;

function Load_SSL_alert_desc_string_long(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_alert_desc_string_long := LoadLibSSLFunction('SSL_alert_desc_string_long');
  if not assigned(SSL_alert_desc_string_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_desc_string_long');
  Result := SSL_alert_desc_string_long(value);
end;

function Load_SSL_alert_desc_string(value: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_alert_desc_string := LoadLibSSLFunction('SSL_alert_desc_string');
  if not assigned(SSL_alert_desc_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alert_desc_string');
  Result := SSL_alert_desc_string(value);
end;

procedure Load_SSL_CTX_set_client_CA_list(ctx: PSSL_CTX; name_list: PSTACK_OF_X509_NAME); cdecl;
begin
  SSL_CTX_set_client_CA_list := LoadLibSSLFunction('SSL_CTX_set_client_CA_list');
  if not assigned(SSL_CTX_set_client_CA_list) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_client_CA_list');
  SSL_CTX_set_client_CA_list(ctx,name_list);
end;

function Load_SSL_add_client_CA(ssl: PSSL; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  SSL_add_client_CA := LoadLibSSLFunction('SSL_add_client_CA');
  if not assigned(SSL_add_client_CA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_client_CA');
  Result := SSL_add_client_CA(ssl,x);
end;

function Load_SSL_CTX_add_client_CA(ctx: PSSL_CTX; x: PX509): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_add_client_CA := LoadLibSSLFunction('SSL_CTX_add_client_CA');
  if not assigned(SSL_CTX_add_client_CA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_add_client_CA');
  Result := SSL_CTX_add_client_CA(ctx,x);
end;

procedure Load_SSL_set_connect_state(s: PSSL); cdecl;
begin
  SSL_set_connect_state := LoadLibSSLFunction('SSL_set_connect_state');
  if not assigned(SSL_set_connect_state) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_connect_state');
  SSL_set_connect_state(s);
end;

procedure Load_SSL_set_accept_state(s: PSSL); cdecl;
begin
  SSL_set_accept_state := LoadLibSSLFunction('SSL_set_accept_state');
  if not assigned(SSL_set_accept_state) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_accept_state');
  SSL_set_accept_state(s);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_SSL_library_init: TOpenSSL_C_INT; cdecl;
begin
  SSL_library_init := LoadLibSSLFunction('SSL_library_init');
  if not assigned(SSL_library_init) then
    SSL_library_init := @COMPAT_SSL_library_init;
  Result := SSL_library_init();
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_SSL_CIPHER_description(cipher: PSSL_CIPHER; buf: PAnsiChar; size_ :TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  SSL_CIPHER_description := LoadLibSSLFunction('SSL_CIPHER_description');
  if not assigned(SSL_CIPHER_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_description');
  Result := SSL_CIPHER_description(cipher,buf,size_);
end;

function Load_SSL_dup(ssl: PSSL): PSSL; cdecl;
begin
  SSL_dup := LoadLibSSLFunction('SSL_dup');
  if not assigned(SSL_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_dup');
  Result := SSL_dup(ssl);
end;

function Load_SSL_get_certificate(const ssl: PSSL): PX509; cdecl;
begin
  SSL_get_certificate := LoadLibSSLFunction('SSL_get_certificate');
  if not assigned(SSL_get_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_certificate');
  Result := SSL_get_certificate(ssl);
end;

function Load_SSL_get_privatekey(const ssl: PSSL): PEVP_PKEY; cdecl;
begin
  SSL_get_privatekey := LoadLibSSLFunction('SSL_get_privatekey');
  if not assigned(SSL_get_privatekey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_privatekey');
  Result := SSL_get_privatekey(ssl);
end;

function Load_SSL_CTX_get0_certificate(const ctx: PSSL_CTX): PX509; cdecl;
begin
  SSL_CTX_get0_certificate := LoadLibSSLFunction('SSL_CTX_get0_certificate');
  if not assigned(SSL_CTX_get0_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_certificate');
  Result := SSL_CTX_get0_certificate(ctx);
end;

function Load_SSL_CTX_get0_privatekey(const ctx: PSSL_CTX): PEVP_PKEY; cdecl;
begin
  SSL_CTX_get0_privatekey := LoadLibSSLFunction('SSL_CTX_get0_privatekey');
  if not assigned(SSL_CTX_get0_privatekey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_privatekey');
  Result := SSL_CTX_get0_privatekey(ctx);
end;

procedure Load_SSL_CTX_set_quiet_shutdown(ctx: PSSL_CTX; mode: TOpenSSL_C_INT); cdecl;
begin
  SSL_CTX_set_quiet_shutdown := LoadLibSSLFunction('SSL_CTX_set_quiet_shutdown');
  if not assigned(SSL_CTX_set_quiet_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_quiet_shutdown');
  SSL_CTX_set_quiet_shutdown(ctx,mode);
end;

function Load_SSL_CTX_get_quiet_shutdown(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_get_quiet_shutdown := LoadLibSSLFunction('SSL_CTX_get_quiet_shutdown');
  if not assigned(SSL_CTX_get_quiet_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_quiet_shutdown');
  Result := SSL_CTX_get_quiet_shutdown(ctx);
end;

procedure Load_SSL_set_quiet_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl;
begin
  SSL_set_quiet_shutdown := LoadLibSSLFunction('SSL_set_quiet_shutdown');
  if not assigned(SSL_set_quiet_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_quiet_shutdown');
  SSL_set_quiet_shutdown(ssl,mode);
end;

function Load_SSL_get_quiet_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_quiet_shutdown := LoadLibSSLFunction('SSL_get_quiet_shutdown');
  if not assigned(SSL_get_quiet_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_quiet_shutdown');
  Result := SSL_get_quiet_shutdown(ssl);
end;

procedure Load_SSL_set_shutdown(ssl: PSSL; mode: TOpenSSL_C_INT); cdecl;
begin
  SSL_set_shutdown := LoadLibSSLFunction('SSL_set_shutdown');
  if not assigned(SSL_set_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_shutdown');
  SSL_set_shutdown(ssl,mode);
end;

function Load_SSL_get_shutdown(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_get_shutdown := LoadLibSSLFunction('SSL_get_shutdown');
  if not assigned(SSL_get_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_shutdown');
  Result := SSL_get_shutdown(ssl);
end;

function Load_SSL_version(const ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_version := LoadLibSSLFunction('SSL_version');
  if not assigned(SSL_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_version');
  Result := SSL_version(ssl);
end;

function Load_SSL_client_version(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_client_version := LoadLibSSLFunction('SSL_client_version');
  if not assigned(SSL_client_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_client_version');
  Result := SSL_client_version(s);
end;

function Load_SSL_CTX_set_default_verify_paths(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_default_verify_paths := LoadLibSSLFunction('SSL_CTX_set_default_verify_paths');
  if not assigned(SSL_CTX_set_default_verify_paths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_verify_paths');
  Result := SSL_CTX_set_default_verify_paths(ctx);
end;

function Load_SSL_CTX_set_default_verify_dir(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_default_verify_dir := LoadLibSSLFunction('SSL_CTX_set_default_verify_dir');
  if not assigned(SSL_CTX_set_default_verify_dir) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_verify_dir');
  Result := SSL_CTX_set_default_verify_dir(ctx);
end;

function Load_SSL_CTX_set_default_verify_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_default_verify_file := LoadLibSSLFunction('SSL_CTX_set_default_verify_file');
  if not assigned(SSL_CTX_set_default_verify_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_verify_file');
  Result := SSL_CTX_set_default_verify_file(ctx);
end;

function Load_SSL_CTX_load_verify_locations(ctx: PSSL_CTX; const CAfile: PAnsiChar; const CApath: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_load_verify_locations := LoadLibSSLFunction('SSL_CTX_load_verify_locations');
  if not assigned(SSL_CTX_load_verify_locations) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_load_verify_locations');
  Result := SSL_CTX_load_verify_locations(ctx,CAfile,CApath);
end;

function Load_SSL_get_session(const ssl: PSSL): PSSL_SESSION; cdecl;
begin
  SSL_get_session := LoadLibSSLFunction('SSL_get_session');
  if not assigned(SSL_get_session) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_session');
  Result := SSL_get_session(ssl);
end;

function Load_SSL_get1_session(ssl: PSSL): PSSL_SESSION; cdecl;
begin
  SSL_get1_session := LoadLibSSLFunction('SSL_get1_session');
  if not assigned(SSL_get1_session) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get1_session');
  Result := SSL_get1_session(ssl);
end;

function Load_SSL_get_SSL_CTX(const ssl: PSSL): PSSL_CTX; cdecl;
begin
  SSL_get_SSL_CTX := LoadLibSSLFunction('SSL_get_SSL_CTX');
  if not assigned(SSL_get_SSL_CTX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_SSL_CTX');
  Result := SSL_get_SSL_CTX(ssl);
end;

function Load_SSL_set_SSL_CTX(ssl: PSSL; ctx: PSSL_CTX): PSSL_CTX; cdecl;
begin
  SSL_set_SSL_CTX := LoadLibSSLFunction('SSL_set_SSL_CTX');
  if not assigned(SSL_set_SSL_CTX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_SSL_CTX');
  Result := SSL_set_SSL_CTX(ssl,ctx);
end;

procedure Load_SSL_set_info_callback(ssl: PSSL; cb: SSL_info_callback); cdecl;
begin
  SSL_set_info_callback := LoadLibSSLFunction('SSL_set_info_callback');
  if not assigned(SSL_set_info_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_info_callback');
  SSL_set_info_callback(ssl,cb);
end;

function Load_SSL_get_info_callback(const ssl: PSSL): SSL_info_callback; cdecl;
begin
  SSL_get_info_callback := LoadLibSSLFunction('SSL_get_info_callback');
  if not assigned(SSL_get_info_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_info_callback');
  Result := SSL_get_info_callback(ssl);
end;

function Load_SSL_get_state(const ssl: PSSL): OSSL_HANDSHAKE_STATE; cdecl;
begin
  SSL_get_state := LoadLibSSLFunction('SSL_get_state');
  if not assigned(SSL_get_state) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_state');
  Result := SSL_get_state(ssl);
end;

procedure Load_SSL_set_verify_result(ssl: PSSL; v: TOpenSSL_C_LONG); cdecl;
begin
  SSL_set_verify_result := LoadLibSSLFunction('SSL_set_verify_result');
  if not assigned(SSL_set_verify_result) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_verify_result');
  SSL_set_verify_result(ssl,v);
end;

function Load_SSL_get_verify_result(const ssl: PSSL): TOpenSSL_C_LONG; cdecl;
begin
  SSL_get_verify_result := LoadLibSSLFunction('SSL_get_verify_result');
  if not assigned(SSL_get_verify_result) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_verify_result');
  Result := SSL_get_verify_result(ssl);
end;

function Load_SSL_get_client_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_get_client_random := LoadLibSSLFunction('SSL_get_client_random');
  if not assigned(SSL_get_client_random) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_client_random');
  Result := SSL_get_client_random(ssl,out_,outlen);
end;

function Load_SSL_get_server_random(const ssl: PSSL; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_get_server_random := LoadLibSSLFunction('SSL_get_server_random');
  if not assigned(SSL_get_server_random) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_server_random');
  Result := SSL_get_server_random(ssl,out_,outlen);
end;

function Load_SSL_SESSION_get_master_key(const sess: PSSL_SESSION; out_: PByte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_SESSION_get_master_key := LoadLibSSLFunction('SSL_SESSION_get_master_key');
  if not assigned(SSL_SESSION_get_master_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_master_key');
  Result := SSL_SESSION_get_master_key(sess,out_,outlen);
end;

function Load_SSL_SESSION_set1_master_key(sess: PSSL_SESSION; const in_: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set1_master_key := LoadLibSSLFunction('SSL_SESSION_set1_master_key');
  if not assigned(SSL_SESSION_set1_master_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_master_key');
  Result := SSL_SESSION_set1_master_key(sess,in_,len);
end;

function Load_SSL_SESSION_get_max_fragment_length(const sess: PSSL_SESSION): TOpenSSL_C_UINT8; cdecl;
begin
  SSL_SESSION_get_max_fragment_length := LoadLibSSLFunction('SSL_SESSION_get_max_fragment_length');
  if not assigned(SSL_SESSION_get_max_fragment_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_max_fragment_length');
  Result := SSL_SESSION_get_max_fragment_length(sess);
end;

function Load_SSL_set_ex_data(ssl: PSSL; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_ex_data := LoadLibSSLFunction('SSL_set_ex_data');
  if not assigned(SSL_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_ex_data');
  Result := SSL_set_ex_data(ssl,idx,data);
end;

function Load_SSL_get_ex_data(const ssl: PSSL; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  SSL_get_ex_data := LoadLibSSLFunction('SSL_get_ex_data');
  if not assigned(SSL_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_ex_data');
  Result := SSL_get_ex_data(ssl,idx);
end;

function Load_SSL_SESSION_set_ex_data(ss: PSSL_SESSION; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set_ex_data := LoadLibSSLFunction('SSL_SESSION_set_ex_data');
  if not assigned(SSL_SESSION_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set_ex_data');
  Result := SSL_SESSION_set_ex_data(ss,idx,data);
end;

function Load_SSL_SESSION_get_ex_data(const ss: PSSL_SESSION; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  SSL_SESSION_get_ex_data := LoadLibSSLFunction('SSL_SESSION_get_ex_data');
  if not assigned(SSL_SESSION_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get_ex_data');
  Result := SSL_SESSION_get_ex_data(ss,idx);
end;

function Load_SSL_CTX_set_ex_data(ssl: PSSL_CTX; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_ex_data := LoadLibSSLFunction('SSL_CTX_set_ex_data');
  if not assigned(SSL_CTX_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ex_data');
  Result := SSL_CTX_set_ex_data(ssl,idx,data);
end;

function Load_SSL_CTX_get_ex_data(const ssl: PSSL_CTX; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  SSL_CTX_get_ex_data := LoadLibSSLFunction('SSL_CTX_get_ex_data');
  if not assigned(SSL_CTX_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_ex_data');
  Result := SSL_CTX_get_ex_data(ssl,idx);
end;

function Load_SSL_get_ex_data_X509_STORE_CTX_idx: TOpenSSL_C_INT; cdecl;
begin
  SSL_get_ex_data_X509_STORE_CTX_idx := LoadLibSSLFunction('SSL_get_ex_data_X509_STORE_CTX_idx');
  if not assigned(SSL_get_ex_data_X509_STORE_CTX_idx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_ex_data_X509_STORE_CTX_idx');
  Result := SSL_get_ex_data_X509_STORE_CTX_idx();
end;

procedure Load_SSL_CTX_set_default_read_buffer_len(ctx: PSSL_CTX; len: TOpenSSL_C_SIZET); cdecl;
begin
  SSL_CTX_set_default_read_buffer_len := LoadLibSSLFunction('SSL_CTX_set_default_read_buffer_len');
  if not assigned(SSL_CTX_set_default_read_buffer_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_read_buffer_len');
  SSL_CTX_set_default_read_buffer_len(ctx,len);
end;

procedure Load_SSL_set_default_read_buffer_len(s: PSSL; len: TOpenSSL_C_SIZET); cdecl;
begin
  SSL_set_default_read_buffer_len := LoadLibSSLFunction('SSL_set_default_read_buffer_len');
  if not assigned(SSL_set_default_read_buffer_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_default_read_buffer_len');
  SSL_set_default_read_buffer_len(s,len);
end;

procedure Load_SSL_CTX_set_tmp_dh_callback(ctx: PSSL_CTX; dh: SSL_CTX_set_tmp_dh_callback_dh); cdecl;
begin
  SSL_CTX_set_tmp_dh_callback := LoadLibSSLFunction('SSL_CTX_set_tmp_dh_callback');
  if not assigned(SSL_CTX_set_tmp_dh_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tmp_dh_callback');
  SSL_CTX_set_tmp_dh_callback(ctx,dh);
end;

procedure Load_SSL_set_tmp_dh_callback(ssl: PSSL; dh: SSL_set_tmp_dh_callback_dh); cdecl;
begin
  SSL_set_tmp_dh_callback := LoadLibSSLFunction('SSL_set_tmp_dh_callback');
  if not assigned(SSL_set_tmp_dh_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tmp_dh_callback');
  SSL_set_tmp_dh_callback(ssl,dh);
end;

function Load_SSL_CIPHER_find(ssl: PSSL; const ptr: PByte): PSSL_CIPHER; cdecl;
begin
  SSL_CIPHER_find := LoadLibSSLFunction('SSL_CIPHER_find');
  if not assigned(SSL_CIPHER_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_find');
  Result := SSL_CIPHER_find(ssl,ptr);
end;

function Load_SSL_CIPHER_get_cipher_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl;
begin
  SSL_CIPHER_get_cipher_nid := LoadLibSSLFunction('SSL_CIPHER_get_cipher_nid');
  if not assigned(SSL_CIPHER_get_cipher_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_cipher_nid');
  Result := SSL_CIPHER_get_cipher_nid(c);
end;

function Load_SSL_CIPHER_get_digest_nid(const c: PSSL_CIPHEr): TOpenSSL_C_INT; cdecl;
begin
  SSL_CIPHER_get_digest_nid := LoadLibSSLFunction('SSL_CIPHER_get_digest_nid');
  if not assigned(SSL_CIPHER_get_digest_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CIPHER_get_digest_nid');
  Result := SSL_CIPHER_get_digest_nid(c);
end;

function Load_SSL_set_session_ticket_ext(s: PSSL; ext_data: Pointer; ext_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_session_ticket_ext := LoadLibSSLFunction('SSL_set_session_ticket_ext');
  if not assigned(SSL_set_session_ticket_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session_ticket_ext');
  Result := SSL_set_session_ticket_ext(s,ext_data,ext_len);
end;

function Load_SSL_set_session_ticket_ext_cb(s: PSSL; cb: tls_session_ticket_ext_cb_fn; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_session_ticket_ext_cb := LoadLibSSLFunction('SSL_set_session_ticket_ext_cb');
  if not assigned(SSL_set_session_ticket_ext_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_session_ticket_ext_cb');
  Result := SSL_set_session_ticket_ext_cb(s,cb,arg);
end;

procedure Load_SSL_CTX_set_not_resumable_session_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_not_resumable_session_callback_cb); cdecl;
begin
  SSL_CTX_set_not_resumable_session_callback := LoadLibSSLFunction('SSL_CTX_set_not_resumable_session_callback');
  if not assigned(SSL_CTX_set_not_resumable_session_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_not_resumable_session_callback');
  SSL_CTX_set_not_resumable_session_callback(ctx,cb);
end;

procedure Load_SSL_set_not_resumable_session_callback(ssl: PSSL; cb: SSL_set_not_resumable_session_callback_cb); cdecl;
begin
  SSL_set_not_resumable_session_callback := LoadLibSSLFunction('SSL_set_not_resumable_session_callback');
  if not assigned(SSL_set_not_resumable_session_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_not_resumable_session_callback');
  SSL_set_not_resumable_session_callback(ssl,cb);
end;

procedure Load_SSL_CTX_set_record_padding_callback(ctx: PSSL_CTX; cb: SSL_CTX_set_record_padding_callback_cb); cdecl;
begin
  SSL_CTX_set_record_padding_callback := LoadLibSSLFunction('SSL_CTX_set_record_padding_callback');
  if not assigned(SSL_CTX_set_record_padding_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_record_padding_callback');
  SSL_CTX_set_record_padding_callback(ctx,cb);
end;

procedure Load_SSL_CTX_set_record_padding_callback_arg(ctx: PSSL_CTX; arg: Pointer); cdecl;
begin
  SSL_CTX_set_record_padding_callback_arg := LoadLibSSLFunction('SSL_CTX_set_record_padding_callback_arg');
  if not assigned(SSL_CTX_set_record_padding_callback_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_record_padding_callback_arg');
  SSL_CTX_set_record_padding_callback_arg(ctx,arg);
end;

function Load_SSL_CTX_get_record_padding_callback_arg(const ctx: PSSL_CTX): Pointer; cdecl;
begin
  SSL_CTX_get_record_padding_callback_arg := LoadLibSSLFunction('SSL_CTX_get_record_padding_callback_arg');
  if not assigned(SSL_CTX_get_record_padding_callback_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_record_padding_callback_arg');
  Result := SSL_CTX_get_record_padding_callback_arg(ctx);
end;

function Load_SSL_CTX_set_block_padding(ctx: PSSL_CTX; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_block_padding := LoadLibSSLFunction('SSL_CTX_set_block_padding');
  if not assigned(SSL_CTX_set_block_padding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_block_padding');
  Result := SSL_CTX_set_block_padding(ctx,block_size);
end;

procedure Load_SSL_set_record_padding_callback(ssl: PSSL; cb: SSL_set_record_padding_callback_cb); cdecl;
begin
  SSL_set_record_padding_callback := LoadLibSSLFunction('SSL_set_record_padding_callback');
  if not assigned(SSL_set_record_padding_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_record_padding_callback');
  SSL_set_record_padding_callback(ssl,cb);
end;

procedure Load_SSL_set_record_padding_callback_arg(ssl: PSSL; arg: Pointer); cdecl;
begin
  SSL_set_record_padding_callback_arg := LoadLibSSLFunction('SSL_set_record_padding_callback_arg');
  if not assigned(SSL_set_record_padding_callback_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_record_padding_callback_arg');
  SSL_set_record_padding_callback_arg(ssl,arg);
end;

function Load_SSL_get_record_padding_callback_arg(const ssl: PSSL): Pointer; cdecl;
begin
  SSL_get_record_padding_callback_arg := LoadLibSSLFunction('SSL_get_record_padding_callback_arg');
  if not assigned(SSL_get_record_padding_callback_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_record_padding_callback_arg');
  Result := SSL_get_record_padding_callback_arg(ssl);
end;

function Load_SSL_set_block_padding(ssl: PSSL; block_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_block_padding := LoadLibSSLFunction('SSL_set_block_padding');
  if not assigned(SSL_set_block_padding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_block_padding');
  Result := SSL_set_block_padding(ssl,block_size);
end;

function Load_SSL_set_num_tickets(s: PSSL; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_num_tickets := LoadLibSSLFunction('SSL_set_num_tickets');
  if not assigned(SSL_set_num_tickets) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_num_tickets');
  Result := SSL_set_num_tickets(s,num_tickets);
end;

function Load_SSL_get_num_tickets(const s: PSSL): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_get_num_tickets := LoadLibSSLFunction('SSL_get_num_tickets');
  if not assigned(SSL_get_num_tickets) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_num_tickets');
  Result := SSL_get_num_tickets(s);
end;

function Load_SSL_CTX_set_num_tickets(ctx: PSSL_CTX; num_tickets: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_num_tickets := LoadLibSSLFunction('SSL_CTX_set_num_tickets');
  if not assigned(SSL_CTX_set_num_tickets) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_num_tickets');
  Result := SSL_CTX_set_num_tickets(ctx,num_tickets);
end;

function Load_SSL_CTX_get_num_tickets(const ctx: PSSL_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  SSL_CTX_get_num_tickets := LoadLibSSLFunction('SSL_CTX_get_num_tickets');
  if not assigned(SSL_CTX_get_num_tickets) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_num_tickets');
  Result := SSL_CTX_get_num_tickets(ctx);
end;

function Load_SSL_session_reused(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_session_reused := LoadLibSSLFunction('SSL_session_reused');
  if not assigned(SSL_session_reused) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_session_reused');
  Result := SSL_session_reused(s);
end;

function Load_SSL_is_server(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_is_server := LoadLibSSLFunction('SSL_is_server');
  if not assigned(SSL_is_server) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_is_server');
  Result := SSL_is_server(s);
end;

function Load_SSL_CONF_CTX_new: PSSL_CONF_CTX; cdecl;
begin
  SSL_CONF_CTX_new := LoadLibSSLFunction('SSL_CONF_CTX_new');
  if not assigned(SSL_CONF_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_new');
  Result := SSL_CONF_CTX_new();
end;

function Load_SSL_CONF_CTX_finish(cctx: PSSL_CONF_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CONF_CTX_finish := LoadLibSSLFunction('SSL_CONF_CTX_finish');
  if not assigned(SSL_CONF_CTX_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_finish');
  Result := SSL_CONF_CTX_finish(cctx);
end;

procedure Load_SSL_CONF_CTX_free(cctx: PSSL_CONF_CTX); cdecl;
begin
  SSL_CONF_CTX_free := LoadLibSSLFunction('SSL_CONF_CTX_free');
  if not assigned(SSL_CONF_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_free');
  SSL_CONF_CTX_free(cctx);
end;

function Load_SSL_CONF_CTX_set_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
begin
  SSL_CONF_CTX_set_flags := LoadLibSSLFunction('SSL_CONF_CTX_set_flags');
  if not assigned(SSL_CONF_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set_flags');
  Result := SSL_CONF_CTX_set_flags(cctx,flags);
end;

function Load_SSL_CONF_CTX_clear_flags(cctx: PSSL_CONF_CTX; flags: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
begin
  SSL_CONF_CTX_clear_flags := LoadLibSSLFunction('SSL_CONF_CTX_clear_flags');
  if not assigned(SSL_CONF_CTX_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_clear_flags');
  Result := SSL_CONF_CTX_clear_flags(cctx,flags);
end;

function Load_SSL_CONF_CTX_set1_prefix(cctx: PSSL_CONF_CTX; const pre: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CONF_CTX_set1_prefix := LoadLibSSLFunction('SSL_CONF_CTX_set1_prefix');
  if not assigned(SSL_CONF_CTX_set1_prefix) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set1_prefix');
  Result := SSL_CONF_CTX_set1_prefix(cctx,pre);
end;

function Load_SSL_CONF_cmd(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CONF_cmd := LoadLibSSLFunction('SSL_CONF_cmd');
  if not assigned(SSL_CONF_cmd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_cmd');
  Result := SSL_CONF_cmd(cctx,cmd,value);
end;

function Load_SSL_CONF_cmd_argv(cctx: PSSL_CONF_CTX; pargc: POpenSSL_C_INT; pargv: PPPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CONF_cmd_argv := LoadLibSSLFunction('SSL_CONF_cmd_argv');
  if not assigned(SSL_CONF_cmd_argv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_cmd_argv');
  Result := SSL_CONF_cmd_argv(cctx,pargc,pargv);
end;

function Load_SSL_CONF_cmd_value_type(cctx: PSSL_CONF_CTX; const cmd: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CONF_cmd_value_type := LoadLibSSLFunction('SSL_CONF_cmd_value_type');
  if not assigned(SSL_CONF_cmd_value_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_cmd_value_type');
  Result := SSL_CONF_cmd_value_type(cctx,cmd);
end;

procedure Load_SSL_CONF_CTX_set_ssl(cctx: PSSL_CONF_CTX; ssl: PSSL); cdecl;
begin
  SSL_CONF_CTX_set_ssl := LoadLibSSLFunction('SSL_CONF_CTX_set_ssl');
  if not assigned(SSL_CONF_CTX_set_ssl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set_ssl');
  SSL_CONF_CTX_set_ssl(cctx,ssl);
end;

procedure Load_SSL_CONF_CTX_set_ssl_ctx(cctx: PSSL_CONF_CTX; ctx: PSSL_CTX); cdecl;
begin
  SSL_CONF_CTX_set_ssl_ctx := LoadLibSSLFunction('SSL_CONF_CTX_set_ssl_ctx');
  if not assigned(SSL_CONF_CTX_set_ssl_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CONF_CTX_set_ssl_ctx');
  SSL_CONF_CTX_set_ssl_ctx(cctx,ctx);
end;

procedure Load_SSL_add_ssl_module; cdecl;
begin
  SSL_add_ssl_module := LoadLibSSLFunction('SSL_add_ssl_module');
  if not assigned(SSL_add_ssl_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_add_ssl_module');
  SSL_add_ssl_module();
end;

function Load_SSL_config(s: PSSL; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_config := LoadLibSSLFunction('SSL_config');
  if not assigned(SSL_config) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_config');
  Result := SSL_config(s,name);
end;

function Load_SSL_CTX_config(ctx: PSSL_CTX; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_config := LoadLibSSLFunction('SSL_CTX_config');
  if not assigned(SSL_CTX_config) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_config');
  Result := SSL_CTX_config(ctx,name);
end;

function Load_DTLSv1_listen(s: PSSL; client: PBIO_ADDr): TOpenSSL_C_INT; cdecl;
begin
  DTLSv1_listen := LoadLibSSLFunction('DTLSv1_listen');
  if not assigned(DTLSv1_listen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DTLSv1_listen');
  Result := DTLSv1_listen(s,client);
end;

function Load_SSL_enable_ct(s: PSSL; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_enable_ct := LoadLibSSLFunction('SSL_enable_ct');
  if not assigned(SSL_enable_ct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_enable_ct');
  Result := SSL_enable_ct(s,validation_mode);
end;

function Load_SSL_CTX_enable_ct(ctx: PSSL_CTX; validation_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_enable_ct := LoadLibSSLFunction('SSL_CTX_enable_ct');
  if not assigned(SSL_CTX_enable_ct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_enable_ct');
  Result := SSL_CTX_enable_ct(ctx,validation_mode);
end;

function Load_SSL_ct_is_enabled(const s: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_ct_is_enabled := LoadLibSSLFunction('SSL_ct_is_enabled');
  if not assigned(SSL_ct_is_enabled) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ct_is_enabled');
  Result := SSL_ct_is_enabled(s);
end;

function Load_SSL_CTX_ct_is_enabled(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_ct_is_enabled := LoadLibSSLFunction('SSL_CTX_ct_is_enabled');
  if not assigned(SSL_CTX_ct_is_enabled) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_ct_is_enabled');
  Result := SSL_CTX_ct_is_enabled(ctx);
end;

function Load_SSL_CTX_set_default_ctlog_list_file(ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_default_ctlog_list_file := LoadLibSSLFunction('SSL_CTX_set_default_ctlog_list_file');
  if not assigned(SSL_CTX_set_default_ctlog_list_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_default_ctlog_list_file');
  Result := SSL_CTX_set_default_ctlog_list_file(ctx);
end;

function Load_SSL_CTX_set_ctlog_list_file(ctx: PSSL_CTX; const path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_ctlog_list_file := LoadLibSSLFunction('SSL_CTX_set_ctlog_list_file');
  if not assigned(SSL_CTX_set_ctlog_list_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_ctlog_list_file');
  Result := SSL_CTX_set_ctlog_list_file(ctx,path);
end;

procedure Load_SSL_CTX_set0_ctlog_store(ctx: PSSL_CTX; logs: PCTLOG_STORE); cdecl;
begin
  SSL_CTX_set0_ctlog_store := LoadLibSSLFunction('SSL_CTX_set0_ctlog_store');
  if not assigned(SSL_CTX_set0_ctlog_store) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_ctlog_store');
  SSL_CTX_set0_ctlog_store(ctx,logs);
end;

procedure Load_SSL_set_security_level(s: PSSL; level: TOpenSSL_C_INT); cdecl;
begin
  SSL_set_security_level := LoadLibSSLFunction('SSL_set_security_level');
  if not assigned(SSL_set_security_level) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_security_level');
  SSL_set_security_level(s,level);
end;

procedure Load_SSL_set_security_callback(s: PSSL; cb: SSL_security_callback); cdecl;
begin
  SSL_set_security_callback := LoadLibSSLFunction('SSL_set_security_callback');
  if not assigned(SSL_set_security_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_security_callback');
  SSL_set_security_callback(s,cb);
end;

function Load_SSL_get_security_callback(const s: PSSL): SSL_security_callback; cdecl;
begin
  SSL_get_security_callback := LoadLibSSLFunction('SSL_get_security_callback');
  if not assigned(SSL_get_security_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_security_callback');
  Result := SSL_get_security_callback(s);
end;

procedure Load_SSL_set0_security_ex_data(s: PSSL; ex: Pointer); cdecl;
begin
  SSL_set0_security_ex_data := LoadLibSSLFunction('SSL_set0_security_ex_data');
  if not assigned(SSL_set0_security_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set0_security_ex_data');
  SSL_set0_security_ex_data(s,ex);
end;

function Load_SSL_get0_security_ex_data(const s: PSSL): Pointer; cdecl;
begin
  SSL_get0_security_ex_data := LoadLibSSLFunction('SSL_get0_security_ex_data');
  if not assigned(SSL_get0_security_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_security_ex_data');
  Result := SSL_get0_security_ex_data(s);
end;

procedure Load_SSL_CTX_set_security_level(ctx: PSSL_CTX; level: TOpenSSL_C_INT); cdecl;
begin
  SSL_CTX_set_security_level := LoadLibSSLFunction('SSL_CTX_set_security_level');
  if not assigned(SSL_CTX_set_security_level) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_security_level');
  SSL_CTX_set_security_level(ctx,level);
end;

function Load_SSL_CTX_get_security_level(const ctx: PSSL_CTX): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_get_security_level := LoadLibSSLFunction('SSL_CTX_get_security_level');
  if not assigned(SSL_CTX_get_security_level) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get_security_level');
  Result := SSL_CTX_get_security_level(ctx);
end;

function Load_SSL_CTX_get0_security_ex_data(const ctx: PSSL_CTX): Pointer; cdecl;
begin
  SSL_CTX_get0_security_ex_data := LoadLibSSLFunction('SSL_CTX_get0_security_ex_data');
  if not assigned(SSL_CTX_get0_security_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get0_security_ex_data');
  Result := SSL_CTX_get0_security_ex_data(ctx);
end;

procedure Load_SSL_CTX_set0_security_ex_data(ctx: PSSL_CTX; ex: Pointer); cdecl;
begin
  SSL_CTX_set0_security_ex_data := LoadLibSSLFunction('SSL_CTX_set0_security_ex_data');
  if not assigned(SSL_CTX_set0_security_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set0_security_ex_data');
  SSL_CTX_set0_security_ex_data(ctx,ex);
end;

function Load_OPENSSL_init_ssl(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_init_ssl := LoadLibSSLFunction('OPENSSL_init_ssl');
  if not assigned(OPENSSL_init_ssl) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_init_ssl := @COMPAT_OPENSSL_init_ssl;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_init_ssl');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_init_ssl(opts,settings);
end;

function Load_SSL_free_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_free_buffers := LoadLibSSLFunction('SSL_free_buffers');
  if not assigned(SSL_free_buffers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_free_buffers');
  Result := SSL_free_buffers(ssl);
end;

function Load_SSL_alloc_buffers(ssl: PSSL): TOpenSSL_C_INT; cdecl;
begin
  SSL_alloc_buffers := LoadLibSSLFunction('SSL_alloc_buffers');
  if not assigned(SSL_alloc_buffers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_alloc_buffers');
  Result := SSL_alloc_buffers(ssl);
end;

function Load_SSL_CTX_set_session_ticket_cb(ctx: PSSL_CTX; gen_cb: SSL_CTX_generate_session_ticket_fn; dec_cb: SSL_CTX_decrypt_session_ticket_fn; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_session_ticket_cb := LoadLibSSLFunction('SSL_CTX_set_session_ticket_cb');
  if not assigned(SSL_CTX_set_session_ticket_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_session_ticket_cb');
  Result := SSL_CTX_set_session_ticket_cb(ctx,gen_cb,dec_cb,arg);
end;

function Load_SSL_SESSION_set1_ticket_appdata(ss: PSSL_SESSION; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_set1_ticket_appdata := LoadLibSSLFunction('SSL_SESSION_set1_ticket_appdata');
  if not assigned(SSL_SESSION_set1_ticket_appdata) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_set1_ticket_appdata');
  Result := SSL_SESSION_set1_ticket_appdata(ss,data,len);
end;

function Load_SSL_SESSION_get0_ticket_appdata(ss: PSSL_SESSION; data: PPointer; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_SESSION_get0_ticket_appdata := LoadLibSSLFunction('SSL_SESSION_get0_ticket_appdata');
  if not assigned(SSL_SESSION_get0_ticket_appdata) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_SESSION_get0_ticket_appdata');
  Result := SSL_SESSION_get0_ticket_appdata(ss,data,len);
end;

procedure Load_DTLS_set_timer_cb(s: PSSL; cb: DTLS_timer_cb); cdecl;
begin
  DTLS_set_timer_cb := LoadLibSSLFunction('DTLS_set_timer_cb');
  if not assigned(DTLS_set_timer_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DTLS_set_timer_cb');
  DTLS_set_timer_cb(s,cb);
end;

procedure Load_SSL_CTX_set_allow_early_data_cb(ctx: PSSL_CTX; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl;
begin
  SSL_CTX_set_allow_early_data_cb := LoadLibSSLFunction('SSL_CTX_set_allow_early_data_cb');
  if not assigned(SSL_CTX_set_allow_early_data_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_allow_early_data_cb');
  SSL_CTX_set_allow_early_data_cb(ctx,cb,arg);
end;

procedure Load_SSL_set_allow_early_data_cb(s: PSSL; cb: SSL_allow_early_data_cb_fN; arg: Pointer); cdecl;
begin
  SSL_set_allow_early_data_cb := LoadLibSSLFunction('SSL_set_allow_early_data_cb');
  if not assigned(SSL_set_allow_early_data_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_allow_early_data_cb');
  SSL_set_allow_early_data_cb(s,cb,arg);
end;

function Load_SSL_get0_peer_certificate(const s: PSSL): PX509; cdecl;
begin
  SSL_get0_peer_certificate := LoadLibSSLFunction('SSL_get0_peer_certificate');
  if not assigned(SSL_get0_peer_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get0_peer_certificate');
  Result := SSL_get0_peer_certificate(s);
end;

function Load_SSL_get1_peer_certificate(const s: PSSL): PX509; cdecl;
begin
  SSL_get1_peer_certificate := LoadLibSSLFunction('SSL_get1_peer_certificate');
  if not assigned(SSL_get1_peer_certificate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get1_peer_certificate');
  Result := SSL_get1_peer_certificate(s);
end;

procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLv2_method := LoadLibSSLFunction('SSLv2_method');
  FuncLoadError := not assigned(SSLv2_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv2_server_method := LoadLibSSLFunction('SSLv2_server_method');
  FuncLoadError := not assigned(SSLv2_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv2_client_method := LoadLibSSLFunction('SSLv2_client_method');
  FuncLoadError := not assigned(SSLv2_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv3_method := LoadLibSSLFunction('SSLv3_method');
  FuncLoadError := not assigned(SSLv3_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv3_server_method := LoadLibSSLFunction('SSLv3_server_method');
  FuncLoadError := not assigned(SSLv3_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv3_client_method := LoadLibSSLFunction('SSLv3_client_method');
  FuncLoadError := not assigned(SSLv3_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv23_method := LoadLibSSLFunction('SSLv23_method');
  FuncLoadError := not assigned(SSLv23_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv23_server_method := LoadLibSSLFunction('SSLv23_server_method');
  FuncLoadError := not assigned(SSLv23_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  SSLv23_client_method := LoadLibSSLFunction('SSLv23_client_method');
  FuncLoadError := not assigned(SSLv23_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_method := LoadLibSSLFunction('TLSv1_method');
  FuncLoadError := not assigned(TLSv1_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_server_method := LoadLibSSLFunction('TLSv1_server_method');
  FuncLoadError := not assigned(TLSv1_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_client_method := LoadLibSSLFunction('TLSv1_client_method');
  FuncLoadError := not assigned(TLSv1_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_1_method := LoadLibSSLFunction('TLSv1_1_method');
  FuncLoadError := not assigned(TLSv1_1_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_1_server_method := LoadLibSSLFunction('TLSv1_1_server_method');
  FuncLoadError := not assigned(TLSv1_1_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_1_client_method := LoadLibSSLFunction('TLSv1_1_client_method');
  FuncLoadError := not assigned(TLSv1_1_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_2_method := LoadLibSSLFunction('TLSv1_2_method');
  FuncLoadError := not assigned(TLSv1_2_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_2_server_method := LoadLibSSLFunction('TLSv1_2_server_method');
  FuncLoadError := not assigned(TLSv1_2_server_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

  TLSv1_2_client_method := LoadLibSSLFunction('TLSv1_2_client_method');
  FuncLoadError := not assigned(TLSv1_2_client_method);
  if FuncLoadError then
  begin
    {Don't report allow nil failure}
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_CTX_set_mode := Load_SSL_CTX_set_mode;
  SSL_CTX_clear_mode := Load_SSL_CTX_clear_mode;
  SSL_CTX_sess_set_cache_size := Load_SSL_CTX_sess_set_cache_size;
  SSL_CTX_sess_get_cache_size := Load_SSL_CTX_sess_get_cache_size;
  SSL_CTX_set_session_cache_mode := Load_SSL_CTX_set_session_cache_mode;
  SSL_CTX_get_session_cache_mode := Load_SSL_CTX_get_session_cache_mode;
  SSL_clear_num_renegotiations := Load_SSL_clear_num_renegotiations;
  SSL_total_renegotiations := Load_SSL_total_renegotiations;
  SSL_CTX_set_tmp_dh := Load_SSL_CTX_set_tmp_dh;
  SSL_CTX_set_tmp_ecdh := Load_SSL_CTX_set_tmp_ecdh;
  SSL_CTX_set_dh_auto := Load_SSL_CTX_set_dh_auto;
  SSL_set_dh_auto := Load_SSL_set_dh_auto;
  SSL_set_tmp_dh := Load_SSL_set_tmp_dh;
  SSL_set_tmp_ecdh := Load_SSL_set_tmp_ecdh;
  SSL_CTX_add_extra_chain_cert := Load_SSL_CTX_add_extra_chain_cert;
  SSL_CTX_get_extra_chain_certs := Load_SSL_CTX_get_extra_chain_certs;
  SSL_CTX_get_extra_chain_certs_only := Load_SSL_CTX_get_extra_chain_certs_only;
  SSL_CTX_clear_extra_chain_certs := Load_SSL_CTX_clear_extra_chain_certs;
  SSL_CTX_set0_chain := Load_SSL_CTX_set0_chain;
  SSL_CTX_set1_chain := Load_SSL_CTX_set1_chain;
  SSL_CTX_add0_chain_cert := Load_SSL_CTX_add0_chain_cert;
  SSL_CTX_add1_chain_cert := Load_SSL_CTX_add1_chain_cert;
  SSL_CTX_get0_chain_certs := Load_SSL_CTX_get0_chain_certs;
  SSL_CTX_clear_chain_certs := Load_SSL_CTX_clear_chain_certs;
  SSL_CTX_build_cert_chain := Load_SSL_CTX_build_cert_chain;
  SSL_CTX_select_current_cert := Load_SSL_CTX_select_current_cert;
  SSL_CTX_set_current_cert := Load_SSL_CTX_set_current_cert;
  SSL_CTX_set0_verify_cert_store := Load_SSL_CTX_set0_verify_cert_store;
  SSL_CTX_set1_verify_cert_store := Load_SSL_CTX_set1_verify_cert_store;
  SSL_CTX_set0_chain_cert_store := Load_SSL_CTX_set0_chain_cert_store;
  SSL_CTX_set1_chain_cert_store := Load_SSL_CTX_set1_chain_cert_store;
  SSL_set0_chain := Load_SSL_set0_chain;
  SSL_set1_chain := Load_SSL_set1_chain;
  SSL_add0_chain_cert := Load_SSL_add0_chain_cert;
  SSL_add1_chain_cert := Load_SSL_add1_chain_cert;
  SSL_get0_chain_certs := Load_SSL_get0_chain_certs;
  SSL_clear_chain_certs := Load_SSL_clear_chain_certs;
  SSL_build_cert_chain := Load_SSL_build_cert_chain;
  SSL_select_current_cert := Load_SSL_select_current_cert;
  SSL_set_current_cert := Load_SSL_set_current_cert;
  SSL_set0_verify_cert_store := Load_SSL_set0_verify_cert_store;
  SSL_set1_verify_cert_store := Load_SSL_set1_verify_cert_store;
  SSL_set0_chain_cert_store := Load_SSL_set0_chain_cert_store;
  SSL_set1_chain_cert_store := Load_SSL_set1_chain_cert_store;
  SSL_get1_groups := Load_SSL_get1_groups;
  SSL_CTX_set1_groups := Load_SSL_CTX_set1_groups;
  SSL_CTX_set1_groups_list := Load_SSL_CTX_set1_groups_list;
  SSL_set1_groups := Load_SSL_set1_groups;
  SSL_set1_groups_list := Load_SSL_set1_groups_list;
  SSL_get_shared_group := Load_SSL_get_shared_group;
  SSL_CTX_set1_sigalgs := Load_SSL_CTX_set1_sigalgs;
  SSL_CTX_set1_sigalgs_list := Load_SSL_CTX_set1_sigalgs_list;
  SSL_set1_sigalgs := Load_SSL_set1_sigalgs;
  SSL_set1_sigalgs_list := Load_SSL_set1_sigalgs_list;
  SSL_CTX_set1_client_sigalgs := Load_SSL_CTX_set1_client_sigalgs;
  SSL_CTX_set1_client_sigalgs_list := Load_SSL_CTX_set1_client_sigalgs_list;
  SSL_set1_client_sigalgs := Load_SSL_set1_client_sigalgs;
  SSL_set1_client_sigalgs_list := Load_SSL_set1_client_sigalgs_list;
  SSL_get0_certificate_types := Load_SSL_get0_certificate_types;
  SSL_CTX_set1_client_certificate_types := Load_SSL_CTX_set1_client_certificate_types;
  SSL_set1_client_certificate_types := Load_SSL_set1_client_certificate_types;
  SSL_get_signature_nid := Load_SSL_get_signature_nid;
  SSL_get_peer_signature_nid := Load_SSL_get_peer_signature_nid;
  SSL_get_peer_tmp_key := Load_SSL_get_peer_tmp_key;
  SSL_get_tmp_key := Load_SSL_get_tmp_key;
  SSL_get0_raw_cipherlist := Load_SSL_get0_raw_cipherlist;
  SSL_get0_ec_point_formats := Load_SSL_get0_ec_point_formats;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CTX_get_options := Load_SSL_CTX_get_options;
  SSL_get_options := Load_SSL_get_options;
  SSL_CTX_clear_options := Load_SSL_CTX_clear_options;
  SSL_clear_options := Load_SSL_clear_options;
  SSL_CTX_set_options := Load_SSL_CTX_set_options;
  SSL_set_options := Load_SSL_set_options;
  SSL_CTX_sess_set_new_cb := Load_SSL_CTX_sess_set_new_cb;
  SSL_CTX_sess_get_new_cb := Load_SSL_CTX_sess_get_new_cb;
  SSL_CTX_sess_set_remove_cb := Load_SSL_CTX_sess_set_remove_cb;
  SSL_CTX_sess_get_remove_cb := Load_SSL_CTX_sess_get_remove_cb;
  SSL_CTX_set_info_callback := Load_SSL_CTX_set_info_callback;
  SSL_CTX_get_info_callback := Load_SSL_CTX_get_info_callback;
  SSL_CTX_set_client_cert_cb := Load_SSL_CTX_set_client_cert_cb;
  SSL_CTX_get_client_cert_cb := Load_SSL_CTX_get_client_cert_cb;
  SSL_CTX_set_client_cert_engine := Load_SSL_CTX_set_client_cert_engine;
  SSL_CTX_set_cookie_generate_cb := Load_SSL_CTX_set_cookie_generate_cb;
  SSL_CTX_set_cookie_verify_cb := Load_SSL_CTX_set_cookie_verify_cb;
  SSL_CTX_set_stateless_cookie_generate_cb := Load_SSL_CTX_set_stateless_cookie_generate_cb;
  SSL_CTX_set_stateless_cookie_verify_cb := Load_SSL_CTX_set_stateless_cookie_verify_cb;
  SSL_CTX_set_alpn_select_cb := Load_SSL_CTX_set_alpn_select_cb;
  SSL_get0_alpn_selected := Load_SSL_get0_alpn_selected;
  SSL_CTX_set_psk_client_callback := Load_SSL_CTX_set_psk_client_callback;
  SSL_set_psk_client_callback := Load_SSL_set_psk_client_callback;
  SSL_CTX_set_psk_server_callback := Load_SSL_CTX_set_psk_server_callback;
  SSL_set_psk_server_callback := Load_SSL_set_psk_server_callback;
  SSL_set_psk_find_session_callback := Load_SSL_set_psk_find_session_callback;
  SSL_CTX_set_psk_find_session_callback := Load_SSL_CTX_set_psk_find_session_callback;
  SSL_set_psk_use_session_callback := Load_SSL_set_psk_use_session_callback;
  SSL_CTX_set_psk_use_session_callback := Load_SSL_CTX_set_psk_use_session_callback;
  SSL_CTX_set_keylog_callback := Load_SSL_CTX_set_keylog_callback;
  SSL_CTX_get_keylog_callback := Load_SSL_CTX_get_keylog_callback;
  SSL_CTX_set_max_early_data := Load_SSL_CTX_set_max_early_data;
  SSL_CTX_get_max_early_data := Load_SSL_CTX_get_max_early_data;
  SSL_set_max_early_data := Load_SSL_set_max_early_data;
  SSL_get_max_early_data := Load_SSL_get_max_early_data;
  SSL_CTX_set_recv_max_early_data := Load_SSL_CTX_set_recv_max_early_data;
  SSL_CTX_get_recv_max_early_data := Load_SSL_CTX_get_recv_max_early_data;
  SSL_set_recv_max_early_data := Load_SSL_set_recv_max_early_data;
  SSL_get_recv_max_early_data := Load_SSL_get_recv_max_early_data;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_get_app_data := Load_SSL_get_app_data;
  SSL_set_app_data := Load_SSL_set_app_data;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_in_init := Load_SSL_in_init;
  SSL_in_before := Load_SSL_in_before;
  SSL_is_init_finished := Load_SSL_is_init_finished;
  SSL_get_finished := Load_SSL_get_finished;
  SSL_get_peer_finished := Load_SSL_get_peer_finished;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLeay_add_ssl_algorithms := Load_SSLeay_add_ssl_algorithms;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  BIO_f_ssl := Load_BIO_f_ssl;
  BIO_new_ssl := Load_BIO_new_ssl;
  BIO_new_ssl_connect := Load_BIO_new_ssl_connect;
  BIO_new_buffer_ssl_connect := Load_BIO_new_buffer_ssl_connect;
  BIO_ssl_copy_session_id := Load_BIO_ssl_copy_session_id;
  SSL_CTX_set_cipher_list := Load_SSL_CTX_set_cipher_list;
  SSL_CTX_new := Load_SSL_CTX_new;
  SSL_CTX_set_timeout := Load_SSL_CTX_set_timeout;
  SSL_CTX_get_timeout := Load_SSL_CTX_get_timeout;
  SSL_CTX_get_cert_store := Load_SSL_CTX_get_cert_store;
  SSL_want := Load_SSL_want;
  SSL_clear := Load_SSL_clear;
  BIO_ssl_shutdown := Load_BIO_ssl_shutdown;
  SSL_CTX_up_ref := Load_SSL_CTX_up_ref;
  SSL_CTX_free := Load_SSL_CTX_free;
  SSL_CTX_set_cert_store := Load_SSL_CTX_set_cert_store;
  SSL_CTX_set1_cert_store := Load_SSL_CTX_set1_cert_store;
  SSL_CTX_flush_sessions := Load_SSL_CTX_flush_sessions;
  SSL_get_current_cipher := Load_SSL_get_current_cipher;
  SSL_get_pending_cipher := Load_SSL_get_pending_cipher;
  SSL_CIPHER_get_bits := Load_SSL_CIPHER_get_bits;
  SSL_CIPHER_get_version := Load_SSL_CIPHER_get_version;
  SSL_CIPHER_get_name := Load_SSL_CIPHER_get_name;
  SSL_CIPHER_standard_name := Load_SSL_CIPHER_standard_name;
  OPENSSL_cipher_name := Load_OPENSSL_cipher_name;
  SSL_CIPHER_get_id := Load_SSL_CIPHER_get_id;
  SSL_CIPHER_get_protocol_id := Load_SSL_CIPHER_get_protocol_id;
  SSL_CIPHER_get_kx_nid := Load_SSL_CIPHER_get_kx_nid;
  SSL_CIPHER_get_auth_nid := Load_SSL_CIPHER_get_auth_nid;
  SSL_CIPHER_get_handshake_digest := Load_SSL_CIPHER_get_handshake_digest;
  SSL_CIPHER_is_aead := Load_SSL_CIPHER_is_aead;
  SSL_get_fd := Load_SSL_get_fd;
  SSL_get_rfd := Load_SSL_get_rfd;
  SSL_get_wfd := Load_SSL_get_wfd;
  SSL_get_cipher_list := Load_SSL_get_cipher_list;
  SSL_get_shared_ciphers := Load_SSL_get_shared_ciphers;
  SSL_get_read_ahead := Load_SSL_get_read_ahead;
  SSL_pending := Load_SSL_pending;
  SSL_has_pending := Load_SSL_has_pending;
  SSL_set_fd := Load_SSL_set_fd;
  SSL_set_rfd := Load_SSL_set_rfd;
  SSL_set_wfd := Load_SSL_set_wfd;
  SSL_set0_rbio := Load_SSL_set0_rbio;
  SSL_set0_wbio := Load_SSL_set0_wbio;
  SSL_set_bio := Load_SSL_set_bio;
  SSL_get_rbio := Load_SSL_get_rbio;
  SSL_get_wbio := Load_SSL_get_wbio;
  SSL_set_cipher_list := Load_SSL_set_cipher_list;
  SSL_CTX_set_ciphersuites := Load_SSL_CTX_set_ciphersuites;
  SSL_set_ciphersuites := Load_SSL_set_ciphersuites;
  SSL_get_verify_mode := Load_SSL_get_verify_mode;
  SSL_get_verify_depth := Load_SSL_get_verify_depth;
  SSL_get_verify_callback := Load_SSL_get_verify_callback;
  SSL_set_read_ahead := Load_SSL_set_read_ahead;
  SSL_set_verify := Load_SSL_set_verify;
  SSL_set_verify_depth := Load_SSL_set_verify_depth;
  SSL_use_RSAPrivateKey := Load_SSL_use_RSAPrivateKey;
  SSL_use_RSAPrivateKey_ASN1 := Load_SSL_use_RSAPrivateKey_ASN1;
  SSL_use_PrivateKey := Load_SSL_use_PrivateKey;
  SSL_use_PrivateKey_ASN1 := Load_SSL_use_PrivateKey_ASN1;
  SSL_use_certificate := Load_SSL_use_certificate;
  SSL_use_certificate_ASN1 := Load_SSL_use_certificate_ASN1;
  SSL_CTX_use_serverinfo := Load_SSL_CTX_use_serverinfo;
  SSL_CTX_use_serverinfo_ex := Load_SSL_CTX_use_serverinfo_ex;
  SSL_CTX_use_serverinfo_file := Load_SSL_CTX_use_serverinfo_file;
  SSL_use_RSAPrivateKey_file := Load_SSL_use_RSAPrivateKey_file;
  SSL_use_PrivateKey_file := Load_SSL_use_PrivateKey_file;
  SSL_use_certificate_file := Load_SSL_use_certificate_file;
  SSL_CTX_use_RSAPrivateKey_file := Load_SSL_CTX_use_RSAPrivateKey_file;
  SSL_CTX_use_PrivateKey_file := Load_SSL_CTX_use_PrivateKey_file;
  SSL_CTX_use_certificate_file := Load_SSL_CTX_use_certificate_file;
  SSL_CTX_use_certificate_chain_file := Load_SSL_CTX_use_certificate_chain_file;
  SSL_use_certificate_chain_file := Load_SSL_use_certificate_chain_file;
  SSL_load_client_CA_file := Load_SSL_load_client_CA_file;
  SSL_add_file_cert_subjects_to_stack := Load_SSL_add_file_cert_subjects_to_stack;
  SSL_add_dir_cert_subjects_to_stack := Load_SSL_add_dir_cert_subjects_to_stack;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_load_error_strings := Load_SSL_load_error_strings;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_state_string := Load_SSL_state_string;
  SSL_rstate_string := Load_SSL_rstate_string;
  SSL_state_string_long := Load_SSL_state_string_long;
  SSL_rstate_string_long := Load_SSL_rstate_string_long;
  SSL_SESSION_get_time := Load_SSL_SESSION_get_time;
  SSL_SESSION_set_time := Load_SSL_SESSION_set_time;
  SSL_SESSION_get_timeout := Load_SSL_SESSION_get_timeout;
  SSL_SESSION_set_timeout := Load_SSL_SESSION_set_timeout;
  SSL_SESSION_get_protocol_version := Load_SSL_SESSION_get_protocol_version;
  SSL_SESSION_set_protocol_version := Load_SSL_SESSION_set_protocol_version;
  SSL_SESSION_get0_hostname := Load_SSL_SESSION_get0_hostname;
  SSL_SESSION_set1_hostname := Load_SSL_SESSION_set1_hostname;
  SSL_SESSION_get0_alpn_selected := Load_SSL_SESSION_get0_alpn_selected;
  SSL_SESSION_set1_alpn_selected := Load_SSL_SESSION_set1_alpn_selected;
  SSL_SESSION_get0_cipher := Load_SSL_SESSION_get0_cipher;
  SSL_SESSION_set_cipher := Load_SSL_SESSION_set_cipher;
  SSL_SESSION_has_ticket := Load_SSL_SESSION_has_ticket;
  SSL_SESSION_get_ticket_lifetime_hint := Load_SSL_SESSION_get_ticket_lifetime_hint;
  SSL_SESSION_get0_ticket := Load_SSL_SESSION_get0_ticket;
  SSL_SESSION_get_max_early_data := Load_SSL_SESSION_get_max_early_data;
  SSL_SESSION_set_max_early_data := Load_SSL_SESSION_set_max_early_data;
  SSL_copy_session_id := Load_SSL_copy_session_id;
  SSL_SESSION_get0_peer := Load_SSL_SESSION_get0_peer;
  SSL_SESSION_set1_id_context := Load_SSL_SESSION_set1_id_context;
  SSL_SESSION_set1_id := Load_SSL_SESSION_set1_id;
  SSL_SESSION_is_resumable := Load_SSL_SESSION_is_resumable;
  SSL_SESSION_new := Load_SSL_SESSION_new;
  SSL_SESSION_dup := Load_SSL_SESSION_dup;
  SSL_SESSION_get_id := Load_SSL_SESSION_get_id;
  SSL_SESSION_get0_id_context := Load_SSL_SESSION_get0_id_context;
  SSL_SESSION_get_compress_id := Load_SSL_SESSION_get_compress_id;
  SSL_SESSION_print := Load_SSL_SESSION_print;
  SSL_SESSION_print_keylog := Load_SSL_SESSION_print_keylog;
  SSL_SESSION_up_ref := Load_SSL_SESSION_up_ref;
  SSL_SESSION_free := Load_SSL_SESSION_free;
  SSL_set_session := Load_SSL_set_session;
  SSL_CTX_add_session := Load_SSL_CTX_add_session;
  SSL_CTX_remove_session := Load_SSL_CTX_remove_session;
  SSL_CTX_set_generate_session_id := Load_SSL_CTX_set_generate_session_id;
  SSL_set_generate_session_id := Load_SSL_set_generate_session_id;
  SSL_has_matching_session_id := Load_SSL_has_matching_session_id;
  d2i_SSL_SESSION := Load_d2i_SSL_SESSION;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_get_peer_certificate := Load_SSL_get_peer_certificate;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CTX_get_verify_mode := Load_SSL_CTX_get_verify_mode;
  SSL_CTX_get_verify_depth := Load_SSL_CTX_get_verify_depth;
  SSL_CTX_get_verify_callback := Load_SSL_CTX_get_verify_callback;
  SSL_CTX_set_verify := Load_SSL_CTX_set_verify;
  SSL_CTX_set_verify_depth := Load_SSL_CTX_set_verify_depth;
  SSL_CTX_set_cert_verify_callback := Load_SSL_CTX_set_cert_verify_callback;
  SSL_CTX_set_cert_cb := Load_SSL_CTX_set_cert_cb;
  SSL_CTX_use_RSAPrivateKey := Load_SSL_CTX_use_RSAPrivateKey;
  SSL_CTX_use_RSAPrivateKey_ASN1 := Load_SSL_CTX_use_RSAPrivateKey_ASN1;
  SSL_CTX_use_PrivateKey := Load_SSL_CTX_use_PrivateKey;
  SSL_CTX_use_PrivateKey_ASN1 := Load_SSL_CTX_use_PrivateKey_ASN1;
  SSL_CTX_use_certificate := Load_SSL_CTX_use_certificate;
  SSL_CTX_use_certificate_ASN1 := Load_SSL_CTX_use_certificate_ASN1;
  SSL_CTX_set_default_passwd_cb := Load_SSL_CTX_set_default_passwd_cb;
  SSL_CTX_set_default_passwd_cb_userdata := Load_SSL_CTX_set_default_passwd_cb_userdata;
  SSL_CTX_get_default_passwd_cb := Load_SSL_CTX_get_default_passwd_cb;
  SSL_CTX_get_default_passwd_cb_userdata := Load_SSL_CTX_get_default_passwd_cb_userdata;
  SSL_set_default_passwd_cb := Load_SSL_set_default_passwd_cb;
  SSL_set_default_passwd_cb_userdata := Load_SSL_set_default_passwd_cb_userdata;
  SSL_get_default_passwd_cb := Load_SSL_get_default_passwd_cb;
  SSL_get_default_passwd_cb_userdata := Load_SSL_get_default_passwd_cb_userdata;
  SSL_CTX_check_private_key := Load_SSL_CTX_check_private_key;
  SSL_check_private_key := Load_SSL_check_private_key;
  SSL_CTX_set_session_id_context := Load_SSL_CTX_set_session_id_context;
  SSL_new := Load_SSL_new;
  SSL_up_ref := Load_SSL_up_ref;
  SSL_is_dtls := Load_SSL_is_dtls;
  SSL_set_session_id_context := Load_SSL_set_session_id_context;
  SSL_CTX_set_purpose := Load_SSL_CTX_set_purpose;
  SSL_set_purpose := Load_SSL_set_purpose;
  SSL_CTX_set_trust := Load_SSL_CTX_set_trust;
  SSL_set_trust := Load_SSL_set_trust;
  SSL_set1_host := Load_SSL_set1_host;
  SSL_add1_host := Load_SSL_add1_host;
  SSL_get0_peername := Load_SSL_get0_peername;
  SSL_set_hostflags := Load_SSL_set_hostflags;
  SSL_CTX_dane_enable := Load_SSL_CTX_dane_enable;
  SSL_CTX_dane_mtype_set := Load_SSL_CTX_dane_mtype_set;
  SSL_dane_enable := Load_SSL_dane_enable;
  SSL_dane_tlsa_add := Load_SSL_dane_tlsa_add;
  SSL_get0_dane_authority := Load_SSL_get0_dane_authority;
  SSL_get0_dane_tlsa := Load_SSL_get0_dane_tlsa;
  SSL_get0_dane := Load_SSL_get0_dane;
  SSL_CTX_dane_set_flags := Load_SSL_CTX_dane_set_flags;
  SSL_CTX_dane_clear_flags := Load_SSL_CTX_dane_clear_flags;
  SSL_dane_set_flags := Load_SSL_dane_set_flags;
  SSL_dane_clear_flags := Load_SSL_dane_clear_flags;
  SSL_CTX_set1_param := Load_SSL_CTX_set1_param;
  SSL_set1_param := Load_SSL_set1_param;
  SSL_CTX_get0_param := Load_SSL_CTX_get0_param;
  SSL_get0_param := Load_SSL_get0_param;
  SSL_CTX_set_srp_username := Load_SSL_CTX_set_srp_username;
  SSL_CTX_set_srp_password := Load_SSL_CTX_set_srp_password;
  SSL_CTX_set_srp_strength := Load_SSL_CTX_set_srp_strength;
  SSL_CTX_set_srp_client_pwd_callback := Load_SSL_CTX_set_srp_client_pwd_callback;
  SSL_CTX_set_srp_verify_param_callback := Load_SSL_CTX_set_srp_verify_param_callback;
  SSL_CTX_set_srp_username_callback := Load_SSL_CTX_set_srp_username_callback;
  SSL_CTX_set_srp_cb_arg := Load_SSL_CTX_set_srp_cb_arg;
  SSL_set_srp_server_param := Load_SSL_set_srp_server_param;
  SSL_set_srp_server_param_pw := Load_SSL_set_srp_server_param_pw;
  SSL_CTX_set_client_hello_cb := Load_SSL_CTX_set_client_hello_cb;
  SSL_client_hello_isv2 := Load_SSL_client_hello_isv2;
  SSL_client_hello_get0_legacy_version := Load_SSL_client_hello_get0_legacy_version;
  SSL_client_hello_get0_random := Load_SSL_client_hello_get0_random;
  SSL_client_hello_get0_session_id := Load_SSL_client_hello_get0_session_id;
  SSL_client_hello_get0_ciphers := Load_SSL_client_hello_get0_ciphers;
  SSL_client_hello_get0_compression_methods := Load_SSL_client_hello_get0_compression_methods;
  SSL_client_hello_get1_extensions_present := Load_SSL_client_hello_get1_extensions_present;
  SSL_client_hello_get0_ext := Load_SSL_client_hello_get0_ext;
  SSL_certs_clear := Load_SSL_certs_clear;
  SSL_free := Load_SSL_free;
  SSL_waiting_for_async := Load_SSL_waiting_for_async;
  SSL_get_all_async_fds := Load_SSL_get_all_async_fds;
  SSL_get_changed_async_fds := Load_SSL_get_changed_async_fds;
  SSL_accept := Load_SSL_accept;
  SSL_stateless := Load_SSL_stateless;
  SSL_connect := Load_SSL_connect;
  SSL_read := Load_SSL_read;
  SSL_read_ex := Load_SSL_read_ex;
  SSL_read_early_data := Load_SSL_read_early_data;
  SSL_peek := Load_SSL_peek;
  SSL_peek_ex := Load_SSL_peek_ex;
  SSL_write := Load_SSL_write;
  SSL_write_ex := Load_SSL_write_ex;
  SSL_write_early_data := Load_SSL_write_early_data;
  SSL_callback_ctrl := Load_SSL_callback_ctrl;
  SSL_ctrl := Load_SSL_ctrl;
  SSL_CTX_ctrl := Load_SSL_CTX_ctrl;
  SSL_CTX_callback_ctrl := Load_SSL_CTX_callback_ctrl;
  SSL_get_early_data_status := Load_SSL_get_early_data_status;
  SSL_get_error := Load_SSL_get_error;
  SSL_get_version := Load_SSL_get_version;
  SSL_CTX_set_ssl_version := Load_SSL_CTX_set_ssl_version;
  TLS_method := Load_TLS_method;
  TLS_server_method := Load_TLS_server_method;
  TLS_client_method := Load_TLS_client_method;
  SSL_do_handshake := Load_SSL_do_handshake;
  SSL_key_update := Load_SSL_key_update;
  SSL_get_key_update_type := Load_SSL_get_key_update_type;
  SSL_renegotiate := Load_SSL_renegotiate;
  SSL_renegotiate_abbreviated := Load_SSL_renegotiate_abbreviated;
  SSL_new_session_ticket := Load_SSL_new_session_ticket;
  SSL_shutdown := Load_SSL_shutdown;
  SSL_CTX_set_post_handshake_auth := Load_SSL_CTX_set_post_handshake_auth;
  SSL_set_post_handshake_auth := Load_SSL_set_post_handshake_auth;
  SSL_renegotiate_pending := Load_SSL_renegotiate_pending;
  SSL_verify_client_post_handshake := Load_SSL_verify_client_post_handshake;
  SSL_CTX_get_ssl_method := Load_SSL_CTX_get_ssl_method;
  SSL_get_ssl_method := Load_SSL_get_ssl_method;
  SSL_set_ssl_method := Load_SSL_set_ssl_method;
  SSL_alert_type_string_long := Load_SSL_alert_type_string_long;
  SSL_alert_type_string := Load_SSL_alert_type_string;
  SSL_alert_desc_string_long := Load_SSL_alert_desc_string_long;
  SSL_alert_desc_string := Load_SSL_alert_desc_string;
  SSL_CTX_set_client_CA_list := Load_SSL_CTX_set_client_CA_list;
  SSL_add_client_CA := Load_SSL_add_client_CA;
  SSL_CTX_add_client_CA := Load_SSL_CTX_add_client_CA;
  SSL_set_connect_state := Load_SSL_set_connect_state;
  SSL_set_accept_state := Load_SSL_set_accept_state;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSL_library_init := Load_SSL_library_init;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_CIPHER_description := Load_SSL_CIPHER_description;
  SSL_dup := Load_SSL_dup;
  SSL_get_certificate := Load_SSL_get_certificate;
  SSL_get_privatekey := Load_SSL_get_privatekey;
  SSL_CTX_get0_certificate := Load_SSL_CTX_get0_certificate;
  SSL_CTX_get0_privatekey := Load_SSL_CTX_get0_privatekey;
  SSL_CTX_set_quiet_shutdown := Load_SSL_CTX_set_quiet_shutdown;
  SSL_CTX_get_quiet_shutdown := Load_SSL_CTX_get_quiet_shutdown;
  SSL_set_quiet_shutdown := Load_SSL_set_quiet_shutdown;
  SSL_get_quiet_shutdown := Load_SSL_get_quiet_shutdown;
  SSL_set_shutdown := Load_SSL_set_shutdown;
  SSL_get_shutdown := Load_SSL_get_shutdown;
  SSL_version := Load_SSL_version;
  SSL_client_version := Load_SSL_client_version;
  SSL_CTX_set_default_verify_paths := Load_SSL_CTX_set_default_verify_paths;
  SSL_CTX_set_default_verify_dir := Load_SSL_CTX_set_default_verify_dir;
  SSL_CTX_set_default_verify_file := Load_SSL_CTX_set_default_verify_file;
  SSL_CTX_load_verify_locations := Load_SSL_CTX_load_verify_locations;
  SSL_get_session := Load_SSL_get_session;
  SSL_get1_session := Load_SSL_get1_session;
  SSL_get_SSL_CTX := Load_SSL_get_SSL_CTX;
  SSL_set_SSL_CTX := Load_SSL_set_SSL_CTX;
  SSL_set_info_callback := Load_SSL_set_info_callback;
  SSL_get_info_callback := Load_SSL_get_info_callback;
  SSL_get_state := Load_SSL_get_state;
  SSL_set_verify_result := Load_SSL_set_verify_result;
  SSL_get_verify_result := Load_SSL_get_verify_result;
  SSL_get_client_random := Load_SSL_get_client_random;
  SSL_get_server_random := Load_SSL_get_server_random;
  SSL_SESSION_get_master_key := Load_SSL_SESSION_get_master_key;
  SSL_SESSION_set1_master_key := Load_SSL_SESSION_set1_master_key;
  SSL_SESSION_get_max_fragment_length := Load_SSL_SESSION_get_max_fragment_length;
  SSL_set_ex_data := Load_SSL_set_ex_data;
  SSL_get_ex_data := Load_SSL_get_ex_data;
  SSL_SESSION_set_ex_data := Load_SSL_SESSION_set_ex_data;
  SSL_SESSION_get_ex_data := Load_SSL_SESSION_get_ex_data;
  SSL_CTX_set_ex_data := Load_SSL_CTX_set_ex_data;
  SSL_CTX_get_ex_data := Load_SSL_CTX_get_ex_data;
  SSL_get_ex_data_X509_STORE_CTX_idx := Load_SSL_get_ex_data_X509_STORE_CTX_idx;
  SSL_CTX_set_default_read_buffer_len := Load_SSL_CTX_set_default_read_buffer_len;
  SSL_set_default_read_buffer_len := Load_SSL_set_default_read_buffer_len;
  SSL_CTX_set_tmp_dh_callback := Load_SSL_CTX_set_tmp_dh_callback;
  SSL_set_tmp_dh_callback := Load_SSL_set_tmp_dh_callback;
  SSL_CIPHER_find := Load_SSL_CIPHER_find;
  SSL_CIPHER_get_cipher_nid := Load_SSL_CIPHER_get_cipher_nid;
  SSL_CIPHER_get_digest_nid := Load_SSL_CIPHER_get_digest_nid;
  SSL_set_session_ticket_ext := Load_SSL_set_session_ticket_ext;
  SSL_set_session_ticket_ext_cb := Load_SSL_set_session_ticket_ext_cb;
  SSL_CTX_set_not_resumable_session_callback := Load_SSL_CTX_set_not_resumable_session_callback;
  SSL_set_not_resumable_session_callback := Load_SSL_set_not_resumable_session_callback;
  SSL_CTX_set_record_padding_callback := Load_SSL_CTX_set_record_padding_callback;
  SSL_CTX_set_record_padding_callback_arg := Load_SSL_CTX_set_record_padding_callback_arg;
  SSL_CTX_get_record_padding_callback_arg := Load_SSL_CTX_get_record_padding_callback_arg;
  SSL_CTX_set_block_padding := Load_SSL_CTX_set_block_padding;
  SSL_set_record_padding_callback := Load_SSL_set_record_padding_callback;
  SSL_set_record_padding_callback_arg := Load_SSL_set_record_padding_callback_arg;
  SSL_get_record_padding_callback_arg := Load_SSL_get_record_padding_callback_arg;
  SSL_set_block_padding := Load_SSL_set_block_padding;
  SSL_set_num_tickets := Load_SSL_set_num_tickets;
  SSL_get_num_tickets := Load_SSL_get_num_tickets;
  SSL_CTX_set_num_tickets := Load_SSL_CTX_set_num_tickets;
  SSL_CTX_get_num_tickets := Load_SSL_CTX_get_num_tickets;
  SSL_session_reused := Load_SSL_session_reused;
  SSL_is_server := Load_SSL_is_server;
  SSL_CONF_CTX_new := Load_SSL_CONF_CTX_new;
  SSL_CONF_CTX_finish := Load_SSL_CONF_CTX_finish;
  SSL_CONF_CTX_free := Load_SSL_CONF_CTX_free;
  SSL_CONF_CTX_set_flags := Load_SSL_CONF_CTX_set_flags;
  SSL_CONF_CTX_clear_flags := Load_SSL_CONF_CTX_clear_flags;
  SSL_CONF_CTX_set1_prefix := Load_SSL_CONF_CTX_set1_prefix;
  SSL_CONF_cmd := Load_SSL_CONF_cmd;
  SSL_CONF_cmd_argv := Load_SSL_CONF_cmd_argv;
  SSL_CONF_cmd_value_type := Load_SSL_CONF_cmd_value_type;
  SSL_CONF_CTX_set_ssl := Load_SSL_CONF_CTX_set_ssl;
  SSL_CONF_CTX_set_ssl_ctx := Load_SSL_CONF_CTX_set_ssl_ctx;
  SSL_add_ssl_module := Load_SSL_add_ssl_module;
  SSL_config := Load_SSL_config;
  SSL_CTX_config := Load_SSL_CTX_config;
  DTLSv1_listen := Load_DTLSv1_listen;
  SSL_enable_ct := Load_SSL_enable_ct;
  SSL_CTX_enable_ct := Load_SSL_CTX_enable_ct;
  SSL_ct_is_enabled := Load_SSL_ct_is_enabled;
  SSL_CTX_ct_is_enabled := Load_SSL_CTX_ct_is_enabled;
  SSL_CTX_set_default_ctlog_list_file := Load_SSL_CTX_set_default_ctlog_list_file;
  SSL_CTX_set_ctlog_list_file := Load_SSL_CTX_set_ctlog_list_file;
  SSL_CTX_set0_ctlog_store := Load_SSL_CTX_set0_ctlog_store;
  SSL_set_security_level := Load_SSL_set_security_level;
  SSL_set_security_callback := Load_SSL_set_security_callback;
  SSL_get_security_callback := Load_SSL_get_security_callback;
  SSL_set0_security_ex_data := Load_SSL_set0_security_ex_data;
  SSL_get0_security_ex_data := Load_SSL_get0_security_ex_data;
  SSL_CTX_set_security_level := Load_SSL_CTX_set_security_level;
  SSL_CTX_get_security_level := Load_SSL_CTX_get_security_level;
  SSL_CTX_get0_security_ex_data := Load_SSL_CTX_get0_security_ex_data;
  SSL_CTX_set0_security_ex_data := Load_SSL_CTX_set0_security_ex_data;
  OPENSSL_init_ssl := Load_OPENSSL_init_ssl;
  SSL_free_buffers := Load_SSL_free_buffers;
  SSL_alloc_buffers := Load_SSL_alloc_buffers;
  SSL_CTX_set_session_ticket_cb := Load_SSL_CTX_set_session_ticket_cb;
  SSL_SESSION_set1_ticket_appdata := Load_SSL_SESSION_set1_ticket_appdata;
  SSL_SESSION_get0_ticket_appdata := Load_SSL_SESSION_get0_ticket_appdata;
  DTLS_set_timer_cb := Load_DTLS_set_timer_cb;
  SSL_CTX_set_allow_early_data_cb := Load_SSL_CTX_set_allow_early_data_cb;
  SSL_set_allow_early_data_cb := Load_SSL_set_allow_early_data_cb;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLv2_method := nil;
  SSLv2_server_method := nil;
  SSLv2_client_method := nil;
  SSLv3_method := nil;
  SSLv3_server_method := nil;
  SSLv3_client_method := nil;
  SSLv23_method := nil;
  SSLv23_server_method := nil;
  SSLv23_client_method := nil;
  TLSv1_method := nil;
  TLSv1_server_method := nil;
  TLSv1_client_method := nil;
  TLSv1_1_method := nil;
  TLSv1_1_server_method := nil;
  TLSv1_1_client_method := nil;
  TLSv1_2_method := nil;
  TLSv1_2_server_method := nil;
  TLSv1_2_client_method := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  SSL_get0_peer_certificate := Load_SSL_get0_peer_certificate;
  SSL_get1_peer_certificate := Load_SSL_get1_peer_certificate;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
