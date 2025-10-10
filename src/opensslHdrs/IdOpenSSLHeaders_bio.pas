(* This unit was generated from the source file bio.h2pas 
It should not be modified directly. All changes should be made to bio.h2pas
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


unit IdOpenSSLHeaders_bio;


interface

// Headers for OpenSSL 1.1.1
// bio.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ;

{$MINENUMSIZE 4}

const
  (* There are the classes of BIOs *)
  BIO_TYPE_DESCRIPTOR = $0100;
  BIO_TYPE_FILTER = $0200;
  BIO_TYPE_SOURCE_SINK = $0400;

  (* These are the 'types' of BIOs *)
  BIO_TYPE_NONE = 0;
  BIO_TYPE_MEM =  1 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_FILE =  2 or BIO_TYPE_SOURCE_SINK;

  BIO_TYPE_FD          =  4 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_SOCKET      =  5 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_NULL        =  6 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_SSL         =  7 or BIO_TYPE_FILTER;
  BIO_TYPE_MD          =  8 or BIO_TYPE_FILTER;
  BIO_TYPE_BUFFER      =  9 or BIO_TYPE_FILTER;
  BIO_TYPE_CIPHER      = 10 or BIO_TYPE_FILTER;
  BIO_TYPE_BASE64      = 11 or BIO_TYPE_FILTER;
  BIO_TYPE_CONNECT     = 12 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_ACCEPT      = 13 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;

  BIO_TYPE_NBIO_TEST   = 16 or BIO_TYPE_FILTER;
  BIO_TYPE_NULL_FILTER = 17 or BIO_TYPE_FILTER;
  BIO_TYPE_BIO         = 19 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_LINEBUFFER  = 20 or BIO_TYPE_FILTER;
  BIO_TYPE_DGRAM       = 21 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_ASN1        = 22 or BIO_TYPE_FILTER;
  BIO_TYPE_COMP        = 23 or BIO_TYPE_FILTER;
  BIO_TYPE_DGRAM_SCTP  = 24 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;

  BIO_TYPE_START = 128;

  (*
   * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
   * BIO_set_fp(in,stdin,BIO_NOCLOSE);
   *)
  BIO_NOCLOSE = $00;
  BIO_CLOSE   = $01;

  (*
   * These are used in the following macros and are passed to BIO_ctrl()
   *)
  BIO_CTRL_RESET        = 1;(* opt - rewind/zero etc *)
  BIO_CTRL_EOF          = 2;(* opt - are we at the eof *)
  BIO_CTRL_INFO         = 3;(* opt - extra tit-bits *)
  BIO_CTRL_SET          = 4;(* man - set the 'IO' type *)
  BIO_CTRL_GET          = 5;(* man - get the 'IO' type *)
  BIO_CTRL_PUSH         = 6;(* opt - internal, used to signify change *)
  BIO_CTRL_POP          = 7;(* opt - internal, used to signify change *)
  BIO_CTRL_GET_CLOSE    = 8;(* man - set the 'close' on free *)
  BIO_CTRL_SET_CLOSE    = 9;(* man - set the 'close' on free *)
  // Added "_const" to prevent naming clashes
  BIO_CTRL_PENDING_const      = 10;(* opt - is their more data buffered *)
  BIO_CTRL_FLUSH        = 11;(* opt - 'flush' buffered output *)
  BIO_CTRL_DUP          = 12;(* man - extra stuff for 'duped' BIO *)
  // Added "_const" to prevent naming clashes
  BIO_CTRL_WPENDING_const     = 13;(* opt - number of bytes still to write *)
  BIO_CTRL_SET_CALLBACK = 14;(* opt - set callback function *)
  BIO_CTRL_GET_CALLBACK = 15;(* opt - set callback function *)

  BIO_CTRL_PEEK         = 29;(* BIO_f_buffer special *)
  BIO_CTRL_SET_FILENAME = 30;(* BIO_s_file special *)

  (* dgram BIO stuff *)
  BIO_CTRL_DGRAM_CONNECT       = 31;(* BIO dgram special *)
  BIO_CTRL_DGRAM_SET_CONNECTED = 32;(* allow for an externally connected
                                           * socket to be passed in *)
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33;(* setsockopt, essentially *)
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34;(* getsockopt, essentially *)
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35;(* setsockopt, essentially *)
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36;(* getsockopt, essentially *)

  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;(* flag whether the last *)
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;(* I/O operation tiemd out *)

  BIO_CTRL_DGRAM_MTU_DISCOVER     = 39;(* set DF bit on egress packets *)

  BIO_CTRL_DGRAM_QUERY_MTU        = 40;(* as kernel for current MTU *)
  BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;
  BIO_CTRL_DGRAM_GET_MTU          = 41;(* get cached value for MTU *)
  BIO_CTRL_DGRAM_SET_MTU          = 42;(* set cached value for MTU.
                                                * want to use this if asking
                                                * the kernel fails *)

  BIO_CTRL_DGRAM_MTU_EXCEEDED     = 43;(* check whether the MTU was
                                                * exceed in the previous write
                                                * operation *)

  BIO_CTRL_DGRAM_GET_PEER         = 46;
  BIO_CTRL_DGRAM_SET_PEER         = 44;(* Destination for the data *)

  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;(* Next DTLS handshake timeout
                                                * to adjust socket timeouts *)
  BIO_CTRL_DGRAM_SET_DONT_FRAG    = 48;

  BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49;

  (* Deliberately outside of OPENSSL_NO_SCTP - used in bss_dgram.c *)
  BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE  = 50;
  (* SCTP stuff *)
  BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY      = 51;
  BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY     = 52;
  BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD     = 53;
  BIO_CTRL_DGRAM_SCTP_GET_SNDINFO       = 60;
  BIO_CTRL_DGRAM_SCTP_SET_SNDINFO       = 61;
  BIO_CTRL_DGRAM_SCTP_GET_RCVINFO       = 62;
  BIO_CTRL_DGRAM_SCTP_SET_RCVINFO       = 63;
  BIO_CTRL_DGRAM_SCTP_GET_PRINFO        = 64;
  BIO_CTRL_DGRAM_SCTP_SET_PRINFO        = 65;
  BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN     = 70;

  BIO_CTRL_DGRAM_SET_PEEK_MODE          = 71;

  (* modifiers *)
  BIO_FP_READ            = $02;
  BIO_FP_WRITE           = $04;
  BIO_FP_APPEND          = $08;
  BIO_FP_TEXT            = $10;

  BIO_FLAGS_READ         = $01;
  BIO_FLAGS_WRITE        = $02;
  BIO_FLAGS_IO_SPECIAL   = $04;
  BIO_FLAGS_RWS          = BIO_FLAGS_READ or BIO_FLAGS_WRITE or BIO_FLAGS_IO_SPECIAL;
  BIO_FLAGS_SHOULD_RETRY = $08;

  BIO_FLAGS_BASE64_NO_NL = $100;

  (*
   * This is used with memory BIOs:
   * BIO_FLAGS_MEM_RDONLY means we shouldn't free up or change the data in any way;
   * BIO_FLAGS_NONCLEAR_RST means we shouldn't clear data on reset.
   *)
  BIO_FLAGS_MEM_RDONLY   = $200;
  BIO_FLAGS_NONCLEAR_RST = $400;

  BIO_RR_SSL_X509_LOOKUP = $01;
  (* Returned from the connect BIO when a connect would have blocked *)
  BIO_RR_CONNECT         = $02;
  (* Returned from the accept BIO when an accept would have blocked *)
  BIO_RR_ACCEPT          = $03;

  (* These are passed by the BIO callback *)
  BIO_CB_FREE  = $01;
  BIO_CB_READ  = $02;
  BIO_CB_WRITE = $03;
  BIO_CB_PUTS  = $04;
  BIO_CB_GETS  = $05;
  BIO_CB_CTRL  = $06;
///*
// * The callback is called before and after the underling operation, The
// * BIO_CB_RETURN flag indicates if it is after the call
// */
//# define BIO_CB_RETURN   0x80
//# define BIO_CB_return(a) ((a)|BIO_CB_RETURN)
//# define BIO_cb_pre(a)   (!((a)&BIO_CB_RETURN))
//# define BIO_cb_post(a)  ((a)&BIO_CB_RETURN)

  BIO_C_SET_CONNECT                 = 100;
  BIO_C_DO_STATE_MACHINE            = 101;
  BIO_C_SET_NBIO                    = 102;
  (* BIO_C_SET_PROXY_PARAM            = 103 *)
  BIO_C_SET_FD                      = 104;
  BIO_C_GET_FD                      = 105;
  BIO_C_SET_FILE_PTR                = 106;
  BIO_C_GET_FILE_PTR                = 107;
  BIO_C_SET_FILENAME                = 108;
  BIO_C_SET_SSL                     = 109;
  BIO_C_GET_SSL                     = 110;
  BIO_C_SET_MD                      = 111;
  BIO_C_GET_MD                      = 112;
  BIO_C_GET_CIPHER_STATUS           = 113;
  BIO_C_SET_BUF_MEM                 = 114;
  BIO_C_GET_BUF_MEM_PTR             = 115;
  BIO_C_GET_BUFF_NUM_LINES          = 116;
  BIO_C_SET_BUFF_SIZE               = 117;
  BIO_C_SET_ACCEPT                  = 118;
  BIO_C_SSL_MODE                    = 119;
  BIO_C_GET_MD_CTX                  = 120;
  (* BIO_C_GET_PROXY_PARAM             = 121 *)
  BIO_C_SET_BUFF_READ_DATA          = 122;(* data to read first *)
  BIO_C_GET_CONNECT                 = 123;
  BIO_C_GET_ACCEPT                  = 124;
  BIO_C_SET_SSL_RENEGOTIATE_BYTES   = 125;
  BIO_C_GET_SSL_NUM_RENEGOTIATES    = 126;
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
  BIO_C_FILE_SEEK                   = 128;
  BIO_C_GET_CIPHER_CTX              = 129;
  BIO_C_SET_BUF_MEM_EOF_RETURN      = 130;(* return end of input
                                                       * value *)
  BIO_C_SET_BIND_MODE               = 131;
  BIO_C_GET_BIND_MODE               = 132;
  BIO_C_FILE_TELL                   = 133;
  BIO_C_GET_SOCKS                   = 134;
  BIO_C_SET_SOCKS                   = 135;

  BIO_C_SET_WRITE_BUF_SIZE          = 136;(* for BIO_s_bio *)
  BIO_C_GET_WRITE_BUF_SIZE          = 137;
  BIO_C_MAKE_BIO_PAIR               = 138;
  BIO_C_DESTROY_BIO_PAIR            = 139;
  BIO_C_GET_WRITE_GUARANTEE         = 140;
  BIO_C_GET_READ_REQUEST            = 141;
  BIO_C_SHUTDOWN_WR                 = 142;
  BIO_C_NREAD0                      = 143;
  BIO_C_NREAD                       = 144;
  BIO_C_NWRITE0                     = 145;
  BIO_C_NWRITE                      = 146;
  BIO_C_RESET_READ_REQUEST          = 147;
  BIO_C_SET_MD_CTX                  = 148;

  BIO_C_SET_PREFIX                  = 149;
  BIO_C_GET_PREFIX                  = 150;
  BIO_C_SET_SUFFIX                  = 151;
  BIO_C_GET_SUFFIX                  = 152;

  BIO_C_SET_EX_ARG                  = 153;
  BIO_C_GET_EX_ARG                  = 154;

  BIO_C_SET_CONNECT_MODE            = 155;

  BIO_SOCK_REUSEADDR = $01;
  BIO_SOCK_V6_ONLY   = $02;
  BIO_SOCK_KEEPALIVE = $04;
  BIO_SOCK_NONBLOCK  = $08;
  BIO_SOCK_NODELAY   = $10;

type
  BIO_ADDR = Pointer; // bio_addr_st
  PBIO_ADDR = ^BIO_ADDR;
  BIO_ADDRINFO = Pointer; // bio_addrinfo_st
  PBIO_ADDRINFO = ^BIO_ADDRINFO;
  PPBIO_ADDRINFO = ^PBIO_ADDRINFO;
  BIO_callback_fn = function(b: PBIO; oper: TOpenSSL_C_INT; const argp: PAnsiChar; 
    argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  BIO_callback_fn_ex = function(b: PBIO; oper: TOpenSSL_C_INT; const argp: PAnsiChar; len: TOpenSSL_C_SIZET; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_INT; processed: POpenSSL_C_SIZET): TOpenSSL_C_LONG;
  BIO_METHOD = Pointer; // bio_method_st
  PBIO_METHOD = ^BIO_METHOD;
  BIO_info_cb = function(v1: PBIO; v2: TOpenSSL_C_INT; v3: TOpenSSL_C_INT): TOpenSSL_C_INT;
  PBIO_info_cb = ^BIO_info_cb;
  asn1_ps_func = function(b: PBIO; pbuf: PPAnsiChar; plen: POpenSSL_C_INT; parg: Pointer): TOpenSSL_C_INT;

  bio_dgram_sctp_sndinfo = record
    snd_sid: TOpenSSL_C_UINT16;
    snd_flags: TOpenSSL_C_UINT16;
    snd_ppid: TOpenSSL_C_UINT32;
    snd_context: TOpenSSL_C_UINT32;
  end;

  bio_dgram_sctp_rcvinfo = record
    rcv_sid: TOpenSSL_C_UINT16;
    rcv_ssn: TOpenSSL_C_UINT16;
    rcv_flags: TOpenSSL_C_UINT16;
    rcv_ppid: TOpenSSL_C_UINT32;
    rcv_tsn: TOpenSSL_C_UINT32;
    rcv_cumtsn: TOpenSSL_C_UINT32;
    rcv_context: TOpenSSL_C_UINT32;
  end;

  bio_dgram_sctp_prinfo = record
    pr_policy: TOpenSSL_C_UINT16;
    pr_value: TOpenSSL_C_UINT32;
  end;

  BIO_hostserv_priorities = (BIO_PARSE_PRIO_HOST, BIO_PARSE_PRIO_SERV);

  BIO_lookup_type = (BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER);

  BIO_sock_info_u = record
    addr: PBIO_ADDR;
  end;
  PBIO_sock_info_u = ^BIO_sock_info_u;

  BIO_sock_info_type = (BIO_SOCK_INFO_ADDRESS);


{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BIO_get_new_index}
{$EXTERNALSYM BIO_set_flags}
{$EXTERNALSYM BIO_test_flags}
{$EXTERNALSYM BIO_clear_flags}
{$EXTERNALSYM BIO_get_callback}
{$EXTERNALSYM BIO_set_callback}
{$EXTERNALSYM BIO_get_callback_ex}
{$EXTERNALSYM BIO_set_callback_ex}
{$EXTERNALSYM BIO_get_callback_arg}
{$EXTERNALSYM BIO_set_callback_arg}
{$EXTERNALSYM BIO_method_name}
{$EXTERNALSYM BIO_method_type}
{$EXTERNALSYM BIO_ctrl_pending}
{$EXTERNALSYM BIO_ctrl_wpending}
{$EXTERNALSYM BIO_ctrl_get_write_guarantee}
{$EXTERNALSYM BIO_ctrl_get_read_request}
{$EXTERNALSYM BIO_ctrl_reset_read_request}
{$EXTERNALSYM BIO_set_ex_data}
{$EXTERNALSYM BIO_get_ex_data}
{$EXTERNALSYM BIO_number_read}
{$EXTERNALSYM BIO_number_written}
{$EXTERNALSYM BIO_s_file}
{$EXTERNALSYM BIO_new_file}
{$EXTERNALSYM BIO_new}
{$EXTERNALSYM BIO_free}
{$EXTERNALSYM BIO_set_data}
{$EXTERNALSYM BIO_get_data}
{$EXTERNALSYM BIO_set_init}
{$EXTERNALSYM BIO_get_init}
{$EXTERNALSYM BIO_set_shutdown}
{$EXTERNALSYM BIO_get_shutdown}
{$EXTERNALSYM BIO_vfree}
{$EXTERNALSYM BIO_up_ref}
{$EXTERNALSYM BIO_read}
{$EXTERNALSYM BIO_read_ex}
{$EXTERNALSYM BIO_gets}
{$EXTERNALSYM BIO_write}
{$EXTERNALSYM BIO_write_ex}
{$EXTERNALSYM BIO_puts}
{$EXTERNALSYM BIO_indent}
{$EXTERNALSYM BIO_ctrl}
{$EXTERNALSYM BIO_callback_ctrl}
{$EXTERNALSYM BIO_ptr_ctrl}
{$EXTERNALSYM BIO_int_ctrl}
{$EXTERNALSYM BIO_push}
{$EXTERNALSYM BIO_pop}
{$EXTERNALSYM BIO_free_all}
{$EXTERNALSYM BIO_find_type}
{$EXTERNALSYM BIO_next}
{$EXTERNALSYM BIO_set_next}
{$EXTERNALSYM BIO_get_retry_BIO}
{$EXTERNALSYM BIO_get_retry_reason}
{$EXTERNALSYM BIO_set_retry_reason}
{$EXTERNALSYM BIO_dup_chain}
{$EXTERNALSYM BIO_nread0}
{$EXTERNALSYM BIO_nread}
{$EXTERNALSYM BIO_nwrite0}
{$EXTERNALSYM BIO_nwrite}
{$EXTERNALSYM BIO_debug_callback}
{$EXTERNALSYM BIO_s_mem}
{$EXTERNALSYM BIO_s_secmem}
{$EXTERNALSYM BIO_new_mem_buf}
{$EXTERNALSYM BIO_s_socket}
{$EXTERNALSYM BIO_s_connect}
{$EXTERNALSYM BIO_s_accept}
{$EXTERNALSYM BIO_s_fd}
{$EXTERNALSYM BIO_s_log}
{$EXTERNALSYM BIO_s_bio}
{$EXTERNALSYM BIO_s_null}
{$EXTERNALSYM BIO_f_null}
{$EXTERNALSYM BIO_f_buffer}
{$EXTERNALSYM BIO_f_linebuffer}
{$EXTERNALSYM BIO_f_nbio_test}
{$EXTERNALSYM BIO_s_datagram}
{$EXTERNALSYM BIO_dgram_non_fatal_error}
{$EXTERNALSYM BIO_new_dgram}
{$EXTERNALSYM BIO_sock_should_retry}
{$EXTERNALSYM BIO_sock_non_fatal_error}
{$EXTERNALSYM BIO_fd_should_retry}
{$EXTERNALSYM BIO_fd_non_fatal_error}
{$EXTERNALSYM BIO_dump}
{$EXTERNALSYM BIO_dump_indent}
{$EXTERNALSYM BIO_hex_string}
{$EXTERNALSYM BIO_ADDR_new}
{$EXTERNALSYM BIO_ADDR_rawmake}
{$EXTERNALSYM BIO_ADDR_free}
{$EXTERNALSYM BIO_ADDR_clear}
{$EXTERNALSYM BIO_ADDR_family}
{$EXTERNALSYM BIO_ADDR_rawaddress}
{$EXTERNALSYM BIO_ADDR_rawport}
{$EXTERNALSYM BIO_ADDR_hostname_string}
{$EXTERNALSYM BIO_ADDR_service_string}
{$EXTERNALSYM BIO_ADDR_path_string}
{$EXTERNALSYM BIO_ADDRINFO_next}
{$EXTERNALSYM BIO_ADDRINFO_family}
{$EXTERNALSYM BIO_ADDRINFO_socktype}
{$EXTERNALSYM BIO_ADDRINFO_protocol}
{$EXTERNALSYM BIO_ADDRINFO_address}
{$EXTERNALSYM BIO_ADDRINFO_free}
{$EXTERNALSYM BIO_parse_hostserv}
{$EXTERNALSYM BIO_lookup}
{$EXTERNALSYM BIO_lookup_ex}
{$EXTERNALSYM BIO_sock_error}
{$EXTERNALSYM BIO_socket_ioctl}
{$EXTERNALSYM BIO_socket_nbio}
{$EXTERNALSYM BIO_sock_init}
{$EXTERNALSYM BIO_set_tcp_ndelay}
{$EXTERNALSYM BIO_sock_info}
{$EXTERNALSYM BIO_socket}
{$EXTERNALSYM BIO_connect}
{$EXTERNALSYM BIO_bind}
{$EXTERNALSYM BIO_listen}
{$EXTERNALSYM BIO_accept_ex}
{$EXTERNALSYM BIO_closesocket}
{$EXTERNALSYM BIO_new_socket}
{$EXTERNALSYM BIO_new_connect}
{$EXTERNALSYM BIO_new_accept}
{$EXTERNALSYM BIO_new_fd}
{$EXTERNALSYM BIO_new_bio_pair}
{$EXTERNALSYM BIO_copy_next_retry}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function BIO_get_new_index: TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_test_flags(const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_clear_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_get_callback(b: PBIO): BIO_callback_fn; cdecl; external CLibCrypto;
procedure BIO_set_callback(b: PBIO; callback: BIO_callback_fn); cdecl; external CLibCrypto;
function BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex; cdecl; external CLibCrypto;
procedure BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex); cdecl; external CLibCrypto;
function BIO_get_callback_arg(const b: PBIO): PAnsiChar; cdecl; external CLibCrypto;
procedure BIO_set_callback_arg(var b: PBIO; arg: PAnsiChar); cdecl; external CLibCrypto;
function BIO_method_name(const b: PBIO): PAnsiChar; cdecl; external CLibCrypto;
function BIO_method_type(const b: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ctrl_pending(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_wpending(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_get_write_guarantee(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_get_read_request(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_reset_read_request(b: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_set_ex_data(bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_get_ex_data(bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function BIO_number_read(bio: PBIO): TOpenSSL_C_UINT64; cdecl; external CLibCrypto;
function BIO_number_written(bio: PBIO): TOpenSSL_C_UINT64; cdecl; external CLibCrypto;
function BIO_s_file: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_new_file(const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl; external CLibCrypto;
function BIO_new(const cType: PBIO_METHOD): PBIO; cdecl; external CLibCrypto;
function BIO_free(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_data(a: PBIO; ptr: Pointer); cdecl; external CLibCrypto;
function BIO_get_data(a: PBIO): Pointer; cdecl; external CLibCrypto;
procedure BIO_set_init(a: PBIO; init: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_get_init(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_shutdown(a: PBIO; shut: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_get_shutdown(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_vfree(a: PBIO); cdecl; external CLibCrypto;
function BIO_up_ref(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_read(b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_read_ex(b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_gets( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_write(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_write_ex(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_puts(bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_indent(b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_callback_ctrl(b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_ptr_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl; external CLibCrypto;
function BIO_int_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_push(b: PBIO; append: PBIO): PBIO; cdecl; external CLibCrypto;
function BIO_pop(b: PBIO): PBIO; cdecl; external CLibCrypto;
procedure BIO_free_all(a: PBIO); cdecl; external CLibCrypto;
function BIO_find_type(b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_next(b: PBIO): PBIO; cdecl; external CLibCrypto;
procedure BIO_set_next(b: PBIO; next: PBIO); cdecl; external CLibCrypto;
function BIO_get_retry_BIO(bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_get_retry_reason(bio: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_retry_reason(bio: PBIO; reason: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_dup_chain(in_: PBIO): PBIO; cdecl; external CLibCrypto;
function BIO_nread0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_nread(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_nwrite0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_nwrite(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_debug_callback(bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_s_mem: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_secmem: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_new_mem_buf(const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_s_socket: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_connect: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_accept: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_fd: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_log: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_bio: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_null: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_null: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_buffer: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_linebuffer: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_nbio_test: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_datagram: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_dgram_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_new_dgram(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_sock_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_fd_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_fd_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_dump(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_dump_indent(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_hex_string(out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDR_new: PBIO_ADDR; cdecl; external CLibCrypto;
function BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_ADDR_free(a: PBIO_ADDR); cdecl; external CLibCrypto;
procedure BIO_ADDR_clear(ap: PBIO_ADDR); cdecl; external CLibCrypto;
function BIO_ADDR_family(const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDR_rawport(const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl; external CLibCrypto;
function BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function BIO_ADDR_path_string(const ap: PBIO_ADDR): PAnsiChar; cdecl; external CLibCrypto;
function BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl; external CLibCrypto;
function BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl; external CLibCrypto;
procedure BIO_ADDRINFO_free(bai: PBIO_ADDRINFO); cdecl; external CLibCrypto;
function BIO_parse_hostserv(const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_lookup(const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_lookup_ex(const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_error(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_socket_ioctl(fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_socket_nbio(fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_init: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_set_tcp_ndelay(sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_info(sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_socket(domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_connect(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_bind(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_listen(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_accept_ex(accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_closesocket(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_new_socket(sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_new_connect(const host_port: PAnsiChar): PBIO; cdecl; external CLibCrypto;
function BIO_new_accept(const host_port: PAnsiChar): PBIO; cdecl; external CLibCrypto;
function BIO_new_fd(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_new_bio_pair(bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_copy_next_retry(b: PBIO); cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
procedure BIO_set_retry_special(b: PBIO); {removed 1.0.0}
procedure BIO_set_retry_read(b: PBIO); {removed 1.0.0}
procedure BIO_set_retry_write(b: PBIO); {removed 1.0.0}
procedure BIO_clear_retry_flags(b: PBIO); {removed 1.0.0}
function BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_read(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_write(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_retry_type(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_retry(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; {removed 1.0.0}
function BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; {removed 1.0.0}
function BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; {removed 1.0.0}
function BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}

{Declare external function initialisers - should not be called directly}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_set_retry_special(b: PBIO); cdecl;
procedure Load_BIO_set_retry_read(b: PBIO); cdecl;
procedure Load_BIO_set_retry_write(b: PBIO); cdecl;
procedure Load_BIO_clear_retry_flags(b: PBIO); cdecl;
function Load_BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_should_read(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_should_write(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_retry_type(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_should_retry(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; cdecl;
function Load_BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; cdecl;
function Load_BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; cdecl;
function Load_BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_BIO_get_new_index: TOpenSSL_C_INT; cdecl;
procedure Load_BIO_set_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl;
function Load_BIO_test_flags(const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_clear_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl;
function Load_BIO_get_callback(b: PBIO): BIO_callback_fn; cdecl;
procedure Load_BIO_set_callback(b: PBIO; callback: BIO_callback_fn); cdecl;
function Load_BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex; cdecl;
procedure Load_BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex); cdecl;
function Load_BIO_get_callback_arg(const b: PBIO): PAnsiChar; cdecl;
procedure Load_BIO_set_callback_arg(var b: PBIO; arg: PAnsiChar); cdecl;
function Load_BIO_method_name(const b: PBIO): PAnsiChar; cdecl;
function Load_BIO_method_type(const b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_ctrl_pending(b: PBIO): TOpenSSL_C_SIZET; cdecl;
function Load_BIO_ctrl_wpending(b: PBIO): TOpenSSL_C_SIZET; cdecl;
function Load_BIO_ctrl_get_write_guarantee(b: PBIO): TOpenSSL_C_SIZET; cdecl;
function Load_BIO_ctrl_get_read_request(b: PBIO): TOpenSSL_C_SIZET; cdecl;
function Load_BIO_ctrl_reset_read_request(b: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_set_ex_data(bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
function Load_BIO_get_ex_data(bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl;
function Load_BIO_number_read(bio: PBIO): TOpenSSL_C_UINT64; cdecl;
function Load_BIO_number_written(bio: PBIO): TOpenSSL_C_UINT64; cdecl;
function Load_BIO_s_file: PBIO_METHOD; cdecl;
function Load_BIO_new_file(const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl;
function Load_BIO_new(const cType: PBIO_METHOD): PBIO; cdecl;
function Load_BIO_free(a: PBIO): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_set_data(a: PBIO; ptr: Pointer); cdecl;
function Load_BIO_get_data(a: PBIO): Pointer; cdecl;
procedure Load_BIO_set_init(a: PBIO; init: TOpenSSL_C_INT); cdecl;
function Load_BIO_get_init(a: PBIO): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_set_shutdown(a: PBIO; shut: TOpenSSL_C_INT); cdecl;
function Load_BIO_get_shutdown(a: PBIO): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_vfree(a: PBIO); cdecl;
function Load_BIO_up_ref(a: PBIO): TOpenSSL_C_INT; cdecl;
function Load_BIO_read(b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_read_ex(b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_BIO_gets( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_write(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_write_ex(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_BIO_puts(bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BIO_indent(b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
function Load_BIO_callback_ctrl(b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl;
function Load_BIO_ptr_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl;
function Load_BIO_int_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;
function Load_BIO_push(b: PBIO; append: PBIO): PBIO; cdecl;
function Load_BIO_pop(b: PBIO): PBIO; cdecl;
procedure Load_BIO_free_all(a: PBIO); cdecl;
function Load_BIO_find_type(b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_next(b: PBIO): PBIO; cdecl;
procedure Load_BIO_set_next(b: PBIO; next: PBIO); cdecl;
function Load_BIO_get_retry_BIO(bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_get_retry_reason(bio: PBIO): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_set_retry_reason(bio: PBIO; reason: TOpenSSL_C_INT); cdecl;
function Load_BIO_dup_chain(in_: PBIO): PBIO; cdecl;
function Load_BIO_nread0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BIO_nread(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_nwrite0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_BIO_nwrite(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_debug_callback(bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
function Load_BIO_s_mem: PBIO_METHOD; cdecl;
function Load_BIO_s_secmem: PBIO_METHOD; cdecl;
function Load_BIO_new_mem_buf(const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_s_socket: PBIO_METHOD; cdecl;
function Load_BIO_s_connect: PBIO_METHOD; cdecl;
function Load_BIO_s_accept: PBIO_METHOD; cdecl;
function Load_BIO_s_fd: PBIO_METHOD; cdecl;
function Load_BIO_s_log: PBIO_METHOD; cdecl;
function Load_BIO_s_bio: PBIO_METHOD; cdecl;
function Load_BIO_s_null: PBIO_METHOD; cdecl;
function Load_BIO_f_null: PBIO_METHOD; cdecl;
function Load_BIO_f_buffer: PBIO_METHOD; cdecl;
function Load_BIO_f_linebuffer: PBIO_METHOD; cdecl;
function Load_BIO_f_nbio_test: PBIO_METHOD; cdecl;
function Load_BIO_s_datagram: PBIO_METHOD; cdecl;
function Load_BIO_dgram_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_new_dgram(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_sock_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_sock_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_fd_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_fd_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_dump(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_dump_indent(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_hex_string(out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_ADDR_new: PBIO_ADDR; cdecl;
function Load_BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_ADDR_free(a: PBIO_ADDR); cdecl;
procedure Load_BIO_ADDR_clear(ap: PBIO_ADDR); cdecl;
function Load_BIO_ADDR_family(const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl;
function Load_BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_BIO_ADDR_rawport(const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl;
function Load_BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_BIO_ADDR_path_string(const ap: PBIO_ADDR): PAnsiChar; cdecl;
function Load_BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl;
function Load_BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
function Load_BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
function Load_BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
function Load_BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl;
procedure Load_BIO_ADDRINFO_free(bai: PBIO_ADDRINFO); cdecl;
function Load_BIO_parse_hostserv(const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl;
function Load_BIO_lookup(const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
function Load_BIO_lookup_ex(const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
function Load_BIO_sock_error(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_socket_ioctl(fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl;
function Load_BIO_socket_nbio(fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_sock_init: TOpenSSL_C_INT; cdecl;
function Load_BIO_set_tcp_ndelay(sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_sock_info(sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl;
function Load_BIO_socket(domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_connect(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_bind(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_listen(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_accept_ex(accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_closesocket(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_BIO_new_socket(sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_new_connect(const host_port: PAnsiChar): PBIO; cdecl;
function Load_BIO_new_accept(const host_port: PAnsiChar): PBIO; cdecl;
function Load_BIO_new_fd(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
function Load_BIO_new_bio_pair(bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_BIO_copy_next_retry(b: PBIO); cdecl;

var
  BIO_get_new_index: function : TOpenSSL_C_INT; cdecl = Load_BIO_get_new_index;
  BIO_set_flags: procedure (b: PBIO; flags: TOpenSSL_C_INT); cdecl = Load_BIO_set_flags;
  BIO_test_flags: function (const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_test_flags;
  BIO_clear_flags: procedure (b: PBIO; flags: TOpenSSL_C_INT); cdecl = Load_BIO_clear_flags;
  BIO_get_callback: function (b: PBIO): BIO_callback_fn; cdecl = Load_BIO_get_callback;
  BIO_set_callback: procedure (b: PBIO; callback: BIO_callback_fn); cdecl = Load_BIO_set_callback;
  BIO_get_callback_ex: function (b: PBIO): BIO_callback_fn_ex; cdecl = Load_BIO_get_callback_ex;
  BIO_set_callback_ex: procedure (b: PBIO; callback: BIO_callback_fn_ex); cdecl = Load_BIO_set_callback_ex;
  BIO_get_callback_arg: function (const b: PBIO): PAnsiChar; cdecl = Load_BIO_get_callback_arg;
  BIO_set_callback_arg: procedure (var b: PBIO; arg: PAnsiChar); cdecl = Load_BIO_set_callback_arg;
  BIO_method_name: function (const b: PBIO): PAnsiChar; cdecl = Load_BIO_method_name;
  BIO_method_type: function (const b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_method_type;
  BIO_ctrl_pending: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = Load_BIO_ctrl_pending;
  BIO_ctrl_wpending: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = Load_BIO_ctrl_wpending;
  BIO_ctrl_get_write_guarantee: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = Load_BIO_ctrl_get_write_guarantee;
  BIO_ctrl_get_read_request: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = Load_BIO_ctrl_get_read_request;
  BIO_ctrl_reset_read_request: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_ctrl_reset_read_request;
  BIO_set_ex_data: function (bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = Load_BIO_set_ex_data;
  BIO_get_ex_data: function (bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl = Load_BIO_get_ex_data;
  BIO_number_read: function (bio: PBIO): TOpenSSL_C_UINT64; cdecl = Load_BIO_number_read;
  BIO_number_written: function (bio: PBIO): TOpenSSL_C_UINT64; cdecl = Load_BIO_number_written;
  BIO_s_file: function : PBIO_METHOD; cdecl = Load_BIO_s_file;
  BIO_new_file: function (const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl = Load_BIO_new_file;
  BIO_new: function (const cType: PBIO_METHOD): PBIO; cdecl = Load_BIO_new;
  BIO_free: function (a: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_free;
  BIO_set_data: procedure (a: PBIO; ptr: Pointer); cdecl = Load_BIO_set_data;
  BIO_get_data: function (a: PBIO): Pointer; cdecl = Load_BIO_get_data;
  BIO_set_init: procedure (a: PBIO; init: TOpenSSL_C_INT); cdecl = Load_BIO_set_init;
  BIO_get_init: function (a: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_get_init;
  BIO_set_shutdown: procedure (a: PBIO; shut: TOpenSSL_C_INT); cdecl = Load_BIO_set_shutdown;
  BIO_get_shutdown: function (a: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_get_shutdown;
  BIO_vfree: procedure (a: PBIO); cdecl = Load_BIO_vfree;
  BIO_up_ref: function (a: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_up_ref;
  BIO_read: function (b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_read;
  BIO_read_ex: function (b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_BIO_read_ex;
  BIO_gets: function ( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_gets;
  BIO_write: function (b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_write;
  BIO_write_ex: function (b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_BIO_write_ex;
  BIO_puts: function (bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_BIO_puts;
  BIO_indent: function (b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_indent;
  BIO_ctrl: function (bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl = Load_BIO_ctrl;
  BIO_callback_ctrl: function (b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl = Load_BIO_callback_ctrl;
  BIO_ptr_ctrl: function (bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl = Load_BIO_ptr_ctrl;
  BIO_int_ctrl: function (bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl = Load_BIO_int_ctrl;
  BIO_push: function (b: PBIO; append: PBIO): PBIO; cdecl = Load_BIO_push;
  BIO_pop: function (b: PBIO): PBIO; cdecl = Load_BIO_pop;
  BIO_free_all: procedure (a: PBIO); cdecl = Load_BIO_free_all;
  BIO_find_type: function (b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_find_type;
  BIO_next: function (b: PBIO): PBIO; cdecl = Load_BIO_next;
  BIO_set_next: procedure (b: PBIO; next: PBIO); cdecl = Load_BIO_set_next;
  BIO_get_retry_BIO: function (bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_get_retry_BIO;
  BIO_get_retry_reason: function (bio: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_get_retry_reason;
  BIO_set_retry_reason: procedure (bio: PBIO; reason: TOpenSSL_C_INT); cdecl = Load_BIO_set_retry_reason;
  BIO_dup_chain: function (in_: PBIO): PBIO; cdecl = Load_BIO_dup_chain;
  BIO_nread0: function (bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_BIO_nread0;
  BIO_nread: function (bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_nread;
  BIO_nwrite0: function (bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_BIO_nwrite0;
  BIO_nwrite: function (bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_nwrite;
  BIO_debug_callback: function (bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = Load_BIO_debug_callback;
  BIO_s_mem: function : PBIO_METHOD; cdecl = Load_BIO_s_mem;
  BIO_s_secmem: function : PBIO_METHOD; cdecl = Load_BIO_s_secmem;
  BIO_new_mem_buf: function (const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_new_mem_buf;
  BIO_s_socket: function : PBIO_METHOD; cdecl = Load_BIO_s_socket;
  BIO_s_connect: function : PBIO_METHOD; cdecl = Load_BIO_s_connect;
  BIO_s_accept: function : PBIO_METHOD; cdecl = Load_BIO_s_accept;
  BIO_s_fd: function : PBIO_METHOD; cdecl = Load_BIO_s_fd;
  BIO_s_log: function : PBIO_METHOD; cdecl = Load_BIO_s_log;
  BIO_s_bio: function : PBIO_METHOD; cdecl = Load_BIO_s_bio;
  BIO_s_null: function : PBIO_METHOD; cdecl = Load_BIO_s_null;
  BIO_f_null: function : PBIO_METHOD; cdecl = Load_BIO_f_null;
  BIO_f_buffer: function : PBIO_METHOD; cdecl = Load_BIO_f_buffer;
  BIO_f_linebuffer: function : PBIO_METHOD; cdecl = Load_BIO_f_linebuffer;
  BIO_f_nbio_test: function : PBIO_METHOD; cdecl = Load_BIO_f_nbio_test;
  BIO_s_datagram: function : PBIO_METHOD; cdecl = Load_BIO_s_datagram;
  BIO_dgram_non_fatal_error: function (error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_dgram_non_fatal_error;
  BIO_new_dgram: function (fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_new_dgram;
  BIO_sock_should_retry: function (i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_sock_should_retry;
  BIO_sock_non_fatal_error: function (error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_sock_non_fatal_error;
  BIO_fd_should_retry: function (i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_fd_should_retry;
  BIO_fd_non_fatal_error: function (error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_fd_non_fatal_error;
  BIO_dump: function (b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_dump;
  BIO_dump_indent: function (b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_dump_indent;
  BIO_hex_string: function (out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_hex_string;
  BIO_ADDR_new: function : PBIO_ADDR; cdecl = Load_BIO_ADDR_new;
  BIO_ADDR_rawmake: function (ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl = Load_BIO_ADDR_rawmake;
  BIO_ADDR_free: procedure (a: PBIO_ADDR); cdecl = Load_BIO_ADDR_free;
  BIO_ADDR_clear: procedure (ap: PBIO_ADDR); cdecl = Load_BIO_ADDR_clear;
  BIO_ADDR_family: function (const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl = Load_BIO_ADDR_family;
  BIO_ADDR_rawaddress: function (const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_BIO_ADDR_rawaddress;
  BIO_ADDR_rawport: function (const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl = Load_BIO_ADDR_rawport;
  BIO_ADDR_hostname_string: function (const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_BIO_ADDR_hostname_string;
  BIO_ADDR_service_string: function (const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_BIO_ADDR_service_string;
  BIO_ADDR_path_string: function (const ap: PBIO_ADDR): PAnsiChar; cdecl = Load_BIO_ADDR_path_string;
  BIO_ADDRINFO_next: function (const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl = Load_BIO_ADDRINFO_next;
  BIO_ADDRINFO_family: function (const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = Load_BIO_ADDRINFO_family;
  BIO_ADDRINFO_socktype: function (const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = Load_BIO_ADDRINFO_socktype;
  BIO_ADDRINFO_protocol: function (const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = Load_BIO_ADDRINFO_protocol;
  BIO_ADDRINFO_address: function (const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl = Load_BIO_ADDRINFO_address;
  BIO_ADDRINFO_free: procedure (bai: PBIO_ADDRINFO); cdecl = Load_BIO_ADDRINFO_free;
  BIO_parse_hostserv: function (const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl = Load_BIO_parse_hostserv;
  BIO_lookup: function (const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = Load_BIO_lookup;
  BIO_lookup_ex: function (const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = Load_BIO_lookup_ex;
  BIO_sock_error: function (sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_sock_error;
  BIO_socket_ioctl: function (fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl = Load_BIO_socket_ioctl;
  BIO_socket_nbio: function (fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_socket_nbio;
  BIO_sock_init: function : TOpenSSL_C_INT; cdecl = Load_BIO_sock_init;
  BIO_set_tcp_ndelay: function (sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_set_tcp_ndelay;
  BIO_sock_info: function (sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl = Load_BIO_sock_info;
  BIO_socket: function (domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_socket;
  BIO_connect: function (sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_connect;
  BIO_bind: function (sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_bind;
  BIO_listen: function (sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_listen;
  BIO_accept_ex: function (accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_accept_ex;
  BIO_closesocket: function (sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_closesocket;
  BIO_new_socket: function (sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_new_socket;
  BIO_new_connect: function (const host_port: PAnsiChar): PBIO; cdecl = Load_BIO_new_connect;
  BIO_new_accept: function (const host_port: PAnsiChar): PBIO; cdecl = Load_BIO_new_accept;
  BIO_new_fd: function (fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl = Load_BIO_new_fd;
  BIO_new_bio_pair: function (bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_BIO_new_bio_pair;
  BIO_copy_next_retry: procedure (b: PBIO); cdecl = Load_BIO_copy_next_retry;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  BIO_get_flags: function (const b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_get_flags; {removed 1.0.0}
  BIO_set_retry_special: procedure (b: PBIO); cdecl = Load_BIO_set_retry_special; {removed 1.0.0}
  BIO_set_retry_read: procedure (b: PBIO); cdecl = Load_BIO_set_retry_read; {removed 1.0.0}
  BIO_set_retry_write: procedure (b: PBIO); cdecl = Load_BIO_set_retry_write; {removed 1.0.0}
  BIO_clear_retry_flags: procedure (b: PBIO); cdecl = Load_BIO_clear_retry_flags; {removed 1.0.0}
  BIO_get_retry_flags: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_get_retry_flags; {removed 1.0.0}
  BIO_should_read: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_should_read; {removed 1.0.0}
  BIO_should_write: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_should_write; {removed 1.0.0}
  BIO_should_io_special: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_should_io_special; {removed 1.0.0}
  BIO_retry_type: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_retry_type; {removed 1.0.0}
  BIO_should_retry: function (b: PBIO): TOpenSSL_C_INT; cdecl = Load_BIO_should_retry; {removed 1.0.0}
  BIO_do_connect: function (b: PBIO): TOpenSSL_C_LONG; cdecl = Load_BIO_do_connect; {removed 1.0.0}
  BIO_do_accept: function (b: PBIO): TOpenSSL_C_LONG; cdecl = Load_BIO_do_accept; {removed 1.0.0}
  BIO_do_handshake: function (b: PBIO): TOpenSSL_C_LONG; cdecl = Load_BIO_do_handshake; {removed 1.0.0}
  BIO_get_mem_data: function (b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_BIO_get_mem_data; {removed 1.0.0}
  BIO_set_mem_buf: function (b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_set_mem_buf; {removed 1.0.0}
  BIO_get_mem_ptr: function (b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_BIO_get_mem_ptr; {removed 1.0.0}
  BIO_set_mem_eof_return: function (b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_set_mem_eof_return; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  BIO_get_flags_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_retry_special_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_retry_read_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_retry_write_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_clear_retry_flags_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_retry_flags_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_read_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_write_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_io_special_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_retry_type_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_retry_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_do_connect_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_do_accept_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_do_handshake_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_mem_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_mem_buf_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_mem_ptr_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_mem_eof_return_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_new_index_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_callback_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_callback_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_shutdown_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_shutdown_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_read_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_write_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_next_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_retry_reason_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_s_secmem_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_f_linebuffer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_rawmake_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_clear_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_family_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_rawaddress_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_rawport_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_hostname_string_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_service_string_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_path_string_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_next_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_family_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_socktype_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_protocol_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_address_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_parse_hostserv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_lookup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_lookup_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_sock_info_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_socket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_connect_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_bind_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_listen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_accept_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_closesocket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation

// # define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))

uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function BIO_get_flags(const b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, not $0);
end;

//# define BIO_set_retry_special(b) \
//                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_set_retry_special(b: PBIO);

begin
  BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_read(b) \
//                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_set_retry_read(b: PBIO);

begin
  BIO_set_flags(b, BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_write(b) \
//                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_set_retry_write(b: PBIO);

begin
  BIO_set_flags(b, BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_clear_retry_flags(b) \
//                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_clear_retry_flags(b: PBIO);

begin
  BIO_clear_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_get_retry_flags(b) \
//                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


function BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)


function BIO_should_read(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_READ);
end;

//# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)


function BIO_should_write(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_WRITE);
end;

//# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)


function BIO_should_io_special(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL);
end;

//# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)


function BIO_retry_type(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS);
end;

//# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)


function BIO_should_retry(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY);
end;

//#  define BIO_do_connect(b)       BIO_do_handshake(b)


function BIO_do_connect(b: PBIO): TOpenSSL_C_LONG;

begin
  Result := BIO_do_handshake(b);
end;

//#  define BIO_do_accept(b)        BIO_do_handshake(b)


function BIO_do_accept(b: PBIO): TOpenSSL_C_LONG;

begin
  Result := BIO_do_handshake(b);
end;

//# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)


function BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG;

begin
  Result := BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, nil);
end;

//# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char (pp))


function BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
end;

//# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char (bm))


function BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, bm);
end;

//# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char (pp))


function BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, pp);
end;

//# define BIO_set_mem_eof_return(b,v) BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,0)


function BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, nil);
end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, not $0);
end;

//# define BIO_set_retry_special(b) \
//                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_set_retry_special(b: PBIO); cdecl;

begin
  BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_read(b) \
//                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_set_retry_read(b: PBIO); cdecl;

begin
  BIO_set_flags(b, BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_write(b) \
//                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_set_retry_write(b: PBIO); cdecl;

begin
  BIO_set_flags(b, BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_clear_retry_flags(b) \
//                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_clear_retry_flags(b: PBIO); cdecl;

begin
  BIO_clear_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_get_retry_flags(b) \
//                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


function COMPAT_BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)


function COMPAT_BIO_should_read(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_READ);
end;

//# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)


function COMPAT_BIO_should_write(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_WRITE);
end;

//# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)


function COMPAT_BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL);
end;

//# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)


function COMPAT_BIO_retry_type(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS);
end;

//# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)


function COMPAT_BIO_should_retry(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY);
end;

//#  define BIO_do_connect(b)       BIO_do_handshake(b)


function COMPAT_BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; cdecl;

begin
  Result := BIO_do_handshake(b);
end;

//#  define BIO_do_accept(b)        BIO_do_handshake(b)


function COMPAT_BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; cdecl;

begin
  Result := BIO_do_handshake(b);
end;

//# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)


function COMPAT_BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, nil);
end;

//# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char (pp))


function COMPAT_BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
end;

//# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char (bm))


function COMPAT_BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, bm);
end;

//# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char (pp))


function COMPAT_BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, pp);
end;

//# define BIO_set_mem_eof_return(b,v) BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,0)


function COMPAT_BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, nil);
end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_flags := LoadLibCryptoFunction('BIO_get_flags');
  if not assigned(BIO_get_flags) then
    BIO_get_flags := @COMPAT_BIO_get_flags;
  Result := BIO_get_flags(b);
end;

procedure Load_BIO_set_retry_special(b: PBIO); cdecl;
begin
  BIO_set_retry_special := LoadLibCryptoFunction('BIO_set_retry_special');
  if not assigned(BIO_set_retry_special) then
    BIO_set_retry_special := @COMPAT_BIO_set_retry_special;
  BIO_set_retry_special(b);
end;

procedure Load_BIO_set_retry_read(b: PBIO); cdecl;
begin
  BIO_set_retry_read := LoadLibCryptoFunction('BIO_set_retry_read');
  if not assigned(BIO_set_retry_read) then
    BIO_set_retry_read := @COMPAT_BIO_set_retry_read;
  BIO_set_retry_read(b);
end;

procedure Load_BIO_set_retry_write(b: PBIO); cdecl;
begin
  BIO_set_retry_write := LoadLibCryptoFunction('BIO_set_retry_write');
  if not assigned(BIO_set_retry_write) then
    BIO_set_retry_write := @COMPAT_BIO_set_retry_write;
  BIO_set_retry_write(b);
end;

procedure Load_BIO_clear_retry_flags(b: PBIO); cdecl;
begin
  BIO_clear_retry_flags := LoadLibCryptoFunction('BIO_clear_retry_flags');
  if not assigned(BIO_clear_retry_flags) then
    BIO_clear_retry_flags := @COMPAT_BIO_clear_retry_flags;
  BIO_clear_retry_flags(b);
end;

function Load_BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_retry_flags := LoadLibCryptoFunction('BIO_get_retry_flags');
  if not assigned(BIO_get_retry_flags) then
    BIO_get_retry_flags := @COMPAT_BIO_get_retry_flags;
  Result := BIO_get_retry_flags(b);
end;

function Load_BIO_should_read(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_should_read := LoadLibCryptoFunction('BIO_should_read');
  if not assigned(BIO_should_read) then
    BIO_should_read := @COMPAT_BIO_should_read;
  Result := BIO_should_read(b);
end;

function Load_BIO_should_write(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_should_write := LoadLibCryptoFunction('BIO_should_write');
  if not assigned(BIO_should_write) then
    BIO_should_write := @COMPAT_BIO_should_write;
  Result := BIO_should_write(b);
end;

function Load_BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_should_io_special := LoadLibCryptoFunction('BIO_should_io_special');
  if not assigned(BIO_should_io_special) then
    BIO_should_io_special := @COMPAT_BIO_should_io_special;
  Result := BIO_should_io_special(b);
end;

function Load_BIO_retry_type(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_retry_type := LoadLibCryptoFunction('BIO_retry_type');
  if not assigned(BIO_retry_type) then
    BIO_retry_type := @COMPAT_BIO_retry_type;
  Result := BIO_retry_type(b);
end;

function Load_BIO_should_retry(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_should_retry := LoadLibCryptoFunction('BIO_should_retry');
  if not assigned(BIO_should_retry) then
    BIO_should_retry := @COMPAT_BIO_should_retry;
  Result := BIO_should_retry(b);
end;

function Load_BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; cdecl;
begin
  BIO_do_connect := LoadLibCryptoFunction('BIO_do_connect');
  if not assigned(BIO_do_connect) then
    BIO_do_connect := @COMPAT_BIO_do_connect;
  Result := BIO_do_connect(b);
end;

function Load_BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; cdecl;
begin
  BIO_do_accept := LoadLibCryptoFunction('BIO_do_accept');
  if not assigned(BIO_do_accept) then
    BIO_do_accept := @COMPAT_BIO_do_accept;
  Result := BIO_do_accept(b);
end;

function Load_BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; cdecl;
begin
  BIO_do_handshake := LoadLibCryptoFunction('BIO_do_handshake');
  if not assigned(BIO_do_handshake) then
    BIO_do_handshake := @COMPAT_BIO_do_handshake;
  Result := BIO_do_handshake(b);
end;

function Load_BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_mem_data := LoadLibCryptoFunction('BIO_get_mem_data');
  if not assigned(BIO_get_mem_data) then
    BIO_get_mem_data := @COMPAT_BIO_get_mem_data;
  Result := BIO_get_mem_data(b,pp);
end;

function Load_BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_set_mem_buf := LoadLibCryptoFunction('BIO_set_mem_buf');
  if not assigned(BIO_set_mem_buf) then
    BIO_set_mem_buf := @COMPAT_BIO_set_mem_buf;
  Result := BIO_set_mem_buf(b,bm,c);
end;

function Load_BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_mem_ptr := LoadLibCryptoFunction('BIO_get_mem_ptr');
  if not assigned(BIO_get_mem_ptr) then
    BIO_get_mem_ptr := @COMPAT_BIO_get_mem_ptr;
  Result := BIO_get_mem_ptr(b,pp);
end;

function Load_BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_set_mem_eof_return := LoadLibCryptoFunction('BIO_set_mem_eof_return');
  if not assigned(BIO_set_mem_eof_return) then
    BIO_set_mem_eof_return := @COMPAT_BIO_set_mem_eof_return;
  Result := BIO_set_mem_eof_return(b,v);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_BIO_get_new_index: TOpenSSL_C_INT; cdecl;
begin
  BIO_get_new_index := LoadLibCryptoFunction('BIO_get_new_index');
  if not assigned(BIO_get_new_index) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_new_index');
  Result := BIO_get_new_index();
end;

procedure Load_BIO_set_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl;
begin
  BIO_set_flags := LoadLibCryptoFunction('BIO_set_flags');
  if not assigned(BIO_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_flags');
  BIO_set_flags(b,flags);
end;

function Load_BIO_test_flags(const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_test_flags := LoadLibCryptoFunction('BIO_test_flags');
  if not assigned(BIO_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_test_flags');
  Result := BIO_test_flags(b,flags);
end;

procedure Load_BIO_clear_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl;
begin
  BIO_clear_flags := LoadLibCryptoFunction('BIO_clear_flags');
  if not assigned(BIO_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_clear_flags');
  BIO_clear_flags(b,flags);
end;

function Load_BIO_get_callback(b: PBIO): BIO_callback_fn; cdecl;
begin
  BIO_get_callback := LoadLibCryptoFunction('BIO_get_callback');
  if not assigned(BIO_get_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_callback');
  Result := BIO_get_callback(b);
end;

procedure Load_BIO_set_callback(b: PBIO; callback: BIO_callback_fn); cdecl;
begin
  BIO_set_callback := LoadLibCryptoFunction('BIO_set_callback');
  if not assigned(BIO_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_callback');
  BIO_set_callback(b,callback);
end;

function Load_BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex; cdecl;
begin
  BIO_get_callback_ex := LoadLibCryptoFunction('BIO_get_callback_ex');
  if not assigned(BIO_get_callback_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_callback_ex');
  Result := BIO_get_callback_ex(b);
end;

procedure Load_BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex); cdecl;
begin
  BIO_set_callback_ex := LoadLibCryptoFunction('BIO_set_callback_ex');
  if not assigned(BIO_set_callback_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_callback_ex');
  BIO_set_callback_ex(b,callback);
end;

function Load_BIO_get_callback_arg(const b: PBIO): PAnsiChar; cdecl;
begin
  BIO_get_callback_arg := LoadLibCryptoFunction('BIO_get_callback_arg');
  if not assigned(BIO_get_callback_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_callback_arg');
  Result := BIO_get_callback_arg(b);
end;

procedure Load_BIO_set_callback_arg(var b: PBIO; arg: PAnsiChar); cdecl;
begin
  BIO_set_callback_arg := LoadLibCryptoFunction('BIO_set_callback_arg');
  if not assigned(BIO_set_callback_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_callback_arg');
  BIO_set_callback_arg(b,arg);
end;

function Load_BIO_method_name(const b: PBIO): PAnsiChar; cdecl;
begin
  BIO_method_name := LoadLibCryptoFunction('BIO_method_name');
  if not assigned(BIO_method_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_method_name');
  Result := BIO_method_name(b);
end;

function Load_BIO_method_type(const b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_method_type := LoadLibCryptoFunction('BIO_method_type');
  if not assigned(BIO_method_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_method_type');
  Result := BIO_method_type(b);
end;

function Load_BIO_ctrl_pending(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  BIO_ctrl_pending := LoadLibCryptoFunction('BIO_ctrl_pending');
  if not assigned(BIO_ctrl_pending) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_pending');
  Result := BIO_ctrl_pending(b);
end;

function Load_BIO_ctrl_wpending(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  BIO_ctrl_wpending := LoadLibCryptoFunction('BIO_ctrl_wpending');
  if not assigned(BIO_ctrl_wpending) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_wpending');
  Result := BIO_ctrl_wpending(b);
end;

function Load_BIO_ctrl_get_write_guarantee(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  BIO_ctrl_get_write_guarantee := LoadLibCryptoFunction('BIO_ctrl_get_write_guarantee');
  if not assigned(BIO_ctrl_get_write_guarantee) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_get_write_guarantee');
  Result := BIO_ctrl_get_write_guarantee(b);
end;

function Load_BIO_ctrl_get_read_request(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  BIO_ctrl_get_read_request := LoadLibCryptoFunction('BIO_ctrl_get_read_request');
  if not assigned(BIO_ctrl_get_read_request) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_get_read_request');
  Result := BIO_ctrl_get_read_request(b);
end;

function Load_BIO_ctrl_reset_read_request(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_ctrl_reset_read_request := LoadLibCryptoFunction('BIO_ctrl_reset_read_request');
  if not assigned(BIO_ctrl_reset_read_request) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_reset_read_request');
  Result := BIO_ctrl_reset_read_request(b);
end;

function Load_BIO_set_ex_data(bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  BIO_set_ex_data := LoadLibCryptoFunction('BIO_set_ex_data');
  if not assigned(BIO_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_ex_data');
  Result := BIO_set_ex_data(bio,idx,data);
end;

function Load_BIO_get_ex_data(bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  BIO_get_ex_data := LoadLibCryptoFunction('BIO_get_ex_data');
  if not assigned(BIO_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_ex_data');
  Result := BIO_get_ex_data(bio,idx);
end;

function Load_BIO_number_read(bio: PBIO): TOpenSSL_C_UINT64; cdecl;
begin
  BIO_number_read := LoadLibCryptoFunction('BIO_number_read');
  if not assigned(BIO_number_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_number_read');
  Result := BIO_number_read(bio);
end;

function Load_BIO_number_written(bio: PBIO): TOpenSSL_C_UINT64; cdecl;
begin
  BIO_number_written := LoadLibCryptoFunction('BIO_number_written');
  if not assigned(BIO_number_written) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_number_written');
  Result := BIO_number_written(bio);
end;

function Load_BIO_s_file: PBIO_METHOD; cdecl;
begin
  BIO_s_file := LoadLibCryptoFunction('BIO_s_file');
  if not assigned(BIO_s_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_file');
  Result := BIO_s_file();
end;

function Load_BIO_new_file(const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl;
begin
  BIO_new_file := LoadLibCryptoFunction('BIO_new_file');
  if not assigned(BIO_new_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_file');
  Result := BIO_new_file(filename,mode);
end;

function Load_BIO_new(const cType: PBIO_METHOD): PBIO; cdecl;
begin
  BIO_new := LoadLibCryptoFunction('BIO_new');
  if not assigned(BIO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new');
  Result := BIO_new(cType);
end;

function Load_BIO_free(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_free := LoadLibCryptoFunction('BIO_free');
  if not assigned(BIO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_free');
  Result := BIO_free(a);
end;

procedure Load_BIO_set_data(a: PBIO; ptr: Pointer); cdecl;
begin
  BIO_set_data := LoadLibCryptoFunction('BIO_set_data');
  if not assigned(BIO_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_data');
  BIO_set_data(a,ptr);
end;

function Load_BIO_get_data(a: PBIO): Pointer; cdecl;
begin
  BIO_get_data := LoadLibCryptoFunction('BIO_get_data');
  if not assigned(BIO_get_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_data');
  Result := BIO_get_data(a);
end;

procedure Load_BIO_set_init(a: PBIO; init: TOpenSSL_C_INT); cdecl;
begin
  BIO_set_init := LoadLibCryptoFunction('BIO_set_init');
  if not assigned(BIO_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_init');
  BIO_set_init(a,init);
end;

function Load_BIO_get_init(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_init := LoadLibCryptoFunction('BIO_get_init');
  if not assigned(BIO_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_init');
  Result := BIO_get_init(a);
end;

procedure Load_BIO_set_shutdown(a: PBIO; shut: TOpenSSL_C_INT); cdecl;
begin
  BIO_set_shutdown := LoadLibCryptoFunction('BIO_set_shutdown');
  if not assigned(BIO_set_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_shutdown');
  BIO_set_shutdown(a,shut);
end;

function Load_BIO_get_shutdown(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_shutdown := LoadLibCryptoFunction('BIO_get_shutdown');
  if not assigned(BIO_get_shutdown) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_shutdown');
  Result := BIO_get_shutdown(a);
end;

procedure Load_BIO_vfree(a: PBIO); cdecl;
begin
  BIO_vfree := LoadLibCryptoFunction('BIO_vfree');
  if not assigned(BIO_vfree) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_vfree');
  BIO_vfree(a);
end;

function Load_BIO_up_ref(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_up_ref := LoadLibCryptoFunction('BIO_up_ref');
  if not assigned(BIO_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_up_ref');
  Result := BIO_up_ref(a);
end;

function Load_BIO_read(b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_read := LoadLibCryptoFunction('BIO_read');
  if not assigned(BIO_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_read');
  Result := BIO_read(b,data,dlen);
end;

function Load_BIO_read_ex(b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  BIO_read_ex := LoadLibCryptoFunction('BIO_read_ex');
  if not assigned(BIO_read_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_read_ex');
  Result := BIO_read_ex(b,data,dlen,readbytes);
end;

function Load_BIO_gets( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_gets := LoadLibCryptoFunction('BIO_gets');
  if not assigned(BIO_gets) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_gets');
  Result := BIO_gets(bp,buf,size);
end;

function Load_BIO_write(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_write := LoadLibCryptoFunction('BIO_write');
  if not assigned(BIO_write) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_write');
  Result := BIO_write(b,data,dlen);
end;

function Load_BIO_write_ex(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  BIO_write_ex := LoadLibCryptoFunction('BIO_write_ex');
  if not assigned(BIO_write_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_write_ex');
  Result := BIO_write_ex(b,data,dlen,written);
end;

function Load_BIO_puts(bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BIO_puts := LoadLibCryptoFunction('BIO_puts');
  if not assigned(BIO_puts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_puts');
  Result := BIO_puts(bp,buf);
end;

function Load_BIO_indent(b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_indent := LoadLibCryptoFunction('BIO_indent');
  if not assigned(BIO_indent) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_indent');
  Result := BIO_indent(b,indent,max);
end;

function Load_BIO_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  BIO_ctrl := LoadLibCryptoFunction('BIO_ctrl');
  if not assigned(BIO_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl');
  Result := BIO_ctrl(bp,cmd,larg,parg);
end;

function Load_BIO_callback_ctrl(b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl;
begin
  BIO_callback_ctrl := LoadLibCryptoFunction('BIO_callback_ctrl');
  if not assigned(BIO_callback_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_callback_ctrl');
  Result := BIO_callback_ctrl(b,cmd,fp);
end;

function Load_BIO_ptr_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl;
begin
  BIO_ptr_ctrl := LoadLibCryptoFunction('BIO_ptr_ctrl');
  if not assigned(BIO_ptr_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ptr_ctrl');
  Result := BIO_ptr_ctrl(bp,cmd,larg);
end;

function Load_BIO_int_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;
begin
  BIO_int_ctrl := LoadLibCryptoFunction('BIO_int_ctrl');
  if not assigned(BIO_int_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_int_ctrl');
  Result := BIO_int_ctrl(bp,cmd,larg,iarg);
end;

function Load_BIO_push(b: PBIO; append: PBIO): PBIO; cdecl;
begin
  BIO_push := LoadLibCryptoFunction('BIO_push');
  if not assigned(BIO_push) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_push');
  Result := BIO_push(b,append);
end;

function Load_BIO_pop(b: PBIO): PBIO; cdecl;
begin
  BIO_pop := LoadLibCryptoFunction('BIO_pop');
  if not assigned(BIO_pop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_pop');
  Result := BIO_pop(b);
end;

procedure Load_BIO_free_all(a: PBIO); cdecl;
begin
  BIO_free_all := LoadLibCryptoFunction('BIO_free_all');
  if not assigned(BIO_free_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_free_all');
  BIO_free_all(a);
end;

function Load_BIO_find_type(b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_find_type := LoadLibCryptoFunction('BIO_find_type');
  if not assigned(BIO_find_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_find_type');
  Result := BIO_find_type(b,bio_type);
end;

function Load_BIO_next(b: PBIO): PBIO; cdecl;
begin
  BIO_next := LoadLibCryptoFunction('BIO_next');
  if not assigned(BIO_next) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_next');
  Result := BIO_next(b);
end;

procedure Load_BIO_set_next(b: PBIO; next: PBIO); cdecl;
begin
  BIO_set_next := LoadLibCryptoFunction('BIO_set_next');
  if not assigned(BIO_set_next) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_next');
  BIO_set_next(b,next);
end;

function Load_BIO_get_retry_BIO(bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_get_retry_BIO := LoadLibCryptoFunction('BIO_get_retry_BIO');
  if not assigned(BIO_get_retry_BIO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_retry_BIO');
  Result := BIO_get_retry_BIO(bio,reason);
end;

function Load_BIO_get_retry_reason(bio: PBIO): TOpenSSL_C_INT; cdecl;
begin
  BIO_get_retry_reason := LoadLibCryptoFunction('BIO_get_retry_reason');
  if not assigned(BIO_get_retry_reason) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_retry_reason');
  Result := BIO_get_retry_reason(bio);
end;

procedure Load_BIO_set_retry_reason(bio: PBIO; reason: TOpenSSL_C_INT); cdecl;
begin
  BIO_set_retry_reason := LoadLibCryptoFunction('BIO_set_retry_reason');
  if not assigned(BIO_set_retry_reason) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_retry_reason');
  BIO_set_retry_reason(bio,reason);
end;

function Load_BIO_dup_chain(in_: PBIO): PBIO; cdecl;
begin
  BIO_dup_chain := LoadLibCryptoFunction('BIO_dup_chain');
  if not assigned(BIO_dup_chain) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dup_chain');
  Result := BIO_dup_chain(in_);
end;

function Load_BIO_nread0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BIO_nread0 := LoadLibCryptoFunction('BIO_nread0');
  if not assigned(BIO_nread0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nread0');
  Result := BIO_nread0(bio,buf);
end;

function Load_BIO_nread(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_nread := LoadLibCryptoFunction('BIO_nread');
  if not assigned(BIO_nread) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nread');
  Result := BIO_nread(bio,buf,num);
end;

function Load_BIO_nwrite0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  BIO_nwrite0 := LoadLibCryptoFunction('BIO_nwrite0');
  if not assigned(BIO_nwrite0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nwrite0');
  Result := BIO_nwrite0(bio,buf);
end;

function Load_BIO_nwrite(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_nwrite := LoadLibCryptoFunction('BIO_nwrite');
  if not assigned(BIO_nwrite) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nwrite');
  Result := BIO_nwrite(bio,buf,num);
end;

function Load_BIO_debug_callback(bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  BIO_debug_callback := LoadLibCryptoFunction('BIO_debug_callback');
  if not assigned(BIO_debug_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_debug_callback');
  Result := BIO_debug_callback(bio,cmd,argp,argi,argl,ret);
end;

function Load_BIO_s_mem: PBIO_METHOD; cdecl;
begin
  BIO_s_mem := LoadLibCryptoFunction('BIO_s_mem');
  if not assigned(BIO_s_mem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_mem');
  Result := BIO_s_mem();
end;

function Load_BIO_s_secmem: PBIO_METHOD; cdecl;
begin
  BIO_s_secmem := LoadLibCryptoFunction('BIO_s_secmem');
  if not assigned(BIO_s_secmem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_secmem');
  Result := BIO_s_secmem();
end;

function Load_BIO_new_mem_buf(const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_new_mem_buf := LoadLibCryptoFunction('BIO_new_mem_buf');
  if not assigned(BIO_new_mem_buf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_mem_buf');
  Result := BIO_new_mem_buf(buf,len);
end;

function Load_BIO_s_socket: PBIO_METHOD; cdecl;
begin
  BIO_s_socket := LoadLibCryptoFunction('BIO_s_socket');
  if not assigned(BIO_s_socket) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_socket');
  Result := BIO_s_socket();
end;

function Load_BIO_s_connect: PBIO_METHOD; cdecl;
begin
  BIO_s_connect := LoadLibCryptoFunction('BIO_s_connect');
  if not assigned(BIO_s_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_connect');
  Result := BIO_s_connect();
end;

function Load_BIO_s_accept: PBIO_METHOD; cdecl;
begin
  BIO_s_accept := LoadLibCryptoFunction('BIO_s_accept');
  if not assigned(BIO_s_accept) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_accept');
  Result := BIO_s_accept();
end;

function Load_BIO_s_fd: PBIO_METHOD; cdecl;
begin
  BIO_s_fd := LoadLibCryptoFunction('BIO_s_fd');
  if not assigned(BIO_s_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_fd');
  Result := BIO_s_fd();
end;

function Load_BIO_s_log: PBIO_METHOD; cdecl;
begin
  BIO_s_log := LoadLibCryptoFunction('BIO_s_log');
  if not assigned(BIO_s_log) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_log');
  Result := BIO_s_log();
end;

function Load_BIO_s_bio: PBIO_METHOD; cdecl;
begin
  BIO_s_bio := LoadLibCryptoFunction('BIO_s_bio');
  if not assigned(BIO_s_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_bio');
  Result := BIO_s_bio();
end;

function Load_BIO_s_null: PBIO_METHOD; cdecl;
begin
  BIO_s_null := LoadLibCryptoFunction('BIO_s_null');
  if not assigned(BIO_s_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_null');
  Result := BIO_s_null();
end;

function Load_BIO_f_null: PBIO_METHOD; cdecl;
begin
  BIO_f_null := LoadLibCryptoFunction('BIO_f_null');
  if not assigned(BIO_f_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_null');
  Result := BIO_f_null();
end;

function Load_BIO_f_buffer: PBIO_METHOD; cdecl;
begin
  BIO_f_buffer := LoadLibCryptoFunction('BIO_f_buffer');
  if not assigned(BIO_f_buffer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_buffer');
  Result := BIO_f_buffer();
end;

function Load_BIO_f_linebuffer: PBIO_METHOD; cdecl;
begin
  BIO_f_linebuffer := LoadLibCryptoFunction('BIO_f_linebuffer');
  if not assigned(BIO_f_linebuffer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_linebuffer');
  Result := BIO_f_linebuffer();
end;

function Load_BIO_f_nbio_test: PBIO_METHOD; cdecl;
begin
  BIO_f_nbio_test := LoadLibCryptoFunction('BIO_f_nbio_test');
  if not assigned(BIO_f_nbio_test) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_nbio_test');
  Result := BIO_f_nbio_test();
end;

function Load_BIO_s_datagram: PBIO_METHOD; cdecl;
begin
  BIO_s_datagram := LoadLibCryptoFunction('BIO_s_datagram');
  if not assigned(BIO_s_datagram) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_datagram');
  Result := BIO_s_datagram();
end;

function Load_BIO_dgram_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_dgram_non_fatal_error := LoadLibCryptoFunction('BIO_dgram_non_fatal_error');
  if not assigned(BIO_dgram_non_fatal_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dgram_non_fatal_error');
  Result := BIO_dgram_non_fatal_error(error);
end;

function Load_BIO_new_dgram(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_new_dgram := LoadLibCryptoFunction('BIO_new_dgram');
  if not assigned(BIO_new_dgram) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_dgram');
  Result := BIO_new_dgram(fd,close_flag);
end;

function Load_BIO_sock_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_sock_should_retry := LoadLibCryptoFunction('BIO_sock_should_retry');
  if not assigned(BIO_sock_should_retry) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_should_retry');
  Result := BIO_sock_should_retry(i);
end;

function Load_BIO_sock_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_sock_non_fatal_error := LoadLibCryptoFunction('BIO_sock_non_fatal_error');
  if not assigned(BIO_sock_non_fatal_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_non_fatal_error');
  Result := BIO_sock_non_fatal_error(error);
end;

function Load_BIO_fd_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_fd_should_retry := LoadLibCryptoFunction('BIO_fd_should_retry');
  if not assigned(BIO_fd_should_retry) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_fd_should_retry');
  Result := BIO_fd_should_retry(i);
end;

function Load_BIO_fd_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_fd_non_fatal_error := LoadLibCryptoFunction('BIO_fd_non_fatal_error');
  if not assigned(BIO_fd_non_fatal_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_fd_non_fatal_error');
  Result := BIO_fd_non_fatal_error(error);
end;

function Load_BIO_dump(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_dump := LoadLibCryptoFunction('BIO_dump');
  if not assigned(BIO_dump) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dump');
  Result := BIO_dump(b,bytes,len);
end;

function Load_BIO_dump_indent(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_dump_indent := LoadLibCryptoFunction('BIO_dump_indent');
  if not assigned(BIO_dump_indent) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dump_indent');
  Result := BIO_dump_indent(b,bytes,len,indent);
end;

function Load_BIO_hex_string(out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_hex_string := LoadLibCryptoFunction('BIO_hex_string');
  if not assigned(BIO_hex_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_hex_string');
  Result := BIO_hex_string(out_,indent,width,data,datalen);
end;

function Load_BIO_ADDR_new: PBIO_ADDR; cdecl;
begin
  BIO_ADDR_new := LoadLibCryptoFunction('BIO_ADDR_new');
  if not assigned(BIO_ADDR_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_new');
  Result := BIO_ADDR_new();
end;

function Load_BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl;
begin
  BIO_ADDR_rawmake := LoadLibCryptoFunction('BIO_ADDR_rawmake');
  if not assigned(BIO_ADDR_rawmake) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_rawmake');
  Result := BIO_ADDR_rawmake(ap,familiy,where,wherelen,port);
end;

procedure Load_BIO_ADDR_free(a: PBIO_ADDR); cdecl;
begin
  BIO_ADDR_free := LoadLibCryptoFunction('BIO_ADDR_free');
  if not assigned(BIO_ADDR_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_free');
  BIO_ADDR_free(a);
end;

procedure Load_BIO_ADDR_clear(ap: PBIO_ADDR); cdecl;
begin
  BIO_ADDR_clear := LoadLibCryptoFunction('BIO_ADDR_clear');
  if not assigned(BIO_ADDR_clear) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_clear');
  BIO_ADDR_clear(ap);
end;

function Load_BIO_ADDR_family(const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl;
begin
  BIO_ADDR_family := LoadLibCryptoFunction('BIO_ADDR_family');
  if not assigned(BIO_ADDR_family) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_family');
  Result := BIO_ADDR_family(ap);
end;

function Load_BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  BIO_ADDR_rawaddress := LoadLibCryptoFunction('BIO_ADDR_rawaddress');
  if not assigned(BIO_ADDR_rawaddress) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_rawaddress');
  Result := BIO_ADDR_rawaddress(ap,p,l);
end;

function Load_BIO_ADDR_rawport(const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl;
begin
  BIO_ADDR_rawport := LoadLibCryptoFunction('BIO_ADDR_rawport');
  if not assigned(BIO_ADDR_rawport) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_rawport');
  Result := BIO_ADDR_rawport(ap);
end;

function Load_BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  BIO_ADDR_hostname_string := LoadLibCryptoFunction('BIO_ADDR_hostname_string');
  if not assigned(BIO_ADDR_hostname_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_hostname_string');
  Result := BIO_ADDR_hostname_string(ap,numeric);
end;

function Load_BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  BIO_ADDR_service_string := LoadLibCryptoFunction('BIO_ADDR_service_string');
  if not assigned(BIO_ADDR_service_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_service_string');
  Result := BIO_ADDR_service_string(ap,numeric);
end;

function Load_BIO_ADDR_path_string(const ap: PBIO_ADDR): PAnsiChar; cdecl;
begin
  BIO_ADDR_path_string := LoadLibCryptoFunction('BIO_ADDR_path_string');
  if not assigned(BIO_ADDR_path_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_path_string');
  Result := BIO_ADDR_path_string(ap);
end;

function Load_BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl;
begin
  BIO_ADDRINFO_next := LoadLibCryptoFunction('BIO_ADDRINFO_next');
  if not assigned(BIO_ADDRINFO_next) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_next');
  Result := BIO_ADDRINFO_next(bai);
end;

function Load_BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  BIO_ADDRINFO_family := LoadLibCryptoFunction('BIO_ADDRINFO_family');
  if not assigned(BIO_ADDRINFO_family) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_family');
  Result := BIO_ADDRINFO_family(bai);
end;

function Load_BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  BIO_ADDRINFO_socktype := LoadLibCryptoFunction('BIO_ADDRINFO_socktype');
  if not assigned(BIO_ADDRINFO_socktype) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_socktype');
  Result := BIO_ADDRINFO_socktype(bai);
end;

function Load_BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  BIO_ADDRINFO_protocol := LoadLibCryptoFunction('BIO_ADDRINFO_protocol');
  if not assigned(BIO_ADDRINFO_protocol) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_protocol');
  Result := BIO_ADDRINFO_protocol(bai);
end;

function Load_BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl;
begin
  BIO_ADDRINFO_address := LoadLibCryptoFunction('BIO_ADDRINFO_address');
  if not assigned(BIO_ADDRINFO_address) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_address');
  Result := BIO_ADDRINFO_address(bai);
end;

procedure Load_BIO_ADDRINFO_free(bai: PBIO_ADDRINFO); cdecl;
begin
  BIO_ADDRINFO_free := LoadLibCryptoFunction('BIO_ADDRINFO_free');
  if not assigned(BIO_ADDRINFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_free');
  BIO_ADDRINFO_free(bai);
end;

function Load_BIO_parse_hostserv(const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl;
begin
  BIO_parse_hostserv := LoadLibCryptoFunction('BIO_parse_hostserv');
  if not assigned(BIO_parse_hostserv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_parse_hostserv');
  Result := BIO_parse_hostserv(hostserv,host,service,hostserv_prio);
end;

function Load_BIO_lookup(const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  BIO_lookup := LoadLibCryptoFunction('BIO_lookup');
  if not assigned(BIO_lookup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_lookup');
  Result := BIO_lookup(host,service,lookup_type,family,socktype,res);
end;

function Load_BIO_lookup_ex(const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  BIO_lookup_ex := LoadLibCryptoFunction('BIO_lookup_ex');
  if not assigned(BIO_lookup_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_lookup_ex');
  Result := BIO_lookup_ex(host,service,lookup_type,family,socktype,protocol,res);
end;

function Load_BIO_sock_error(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_sock_error := LoadLibCryptoFunction('BIO_sock_error');
  if not assigned(BIO_sock_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_error');
  Result := BIO_sock_error(sock);
end;

function Load_BIO_socket_ioctl(fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  BIO_socket_ioctl := LoadLibCryptoFunction('BIO_socket_ioctl');
  if not assigned(BIO_socket_ioctl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_socket_ioctl');
  Result := BIO_socket_ioctl(fd,cType,arg);
end;

function Load_BIO_socket_nbio(fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_socket_nbio := LoadLibCryptoFunction('BIO_socket_nbio');
  if not assigned(BIO_socket_nbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_socket_nbio');
  Result := BIO_socket_nbio(fd,mode);
end;

function Load_BIO_sock_init: TOpenSSL_C_INT; cdecl;
begin
  BIO_sock_init := LoadLibCryptoFunction('BIO_sock_init');
  if not assigned(BIO_sock_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_init');
  Result := BIO_sock_init();
end;

function Load_BIO_set_tcp_ndelay(sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_set_tcp_ndelay := LoadLibCryptoFunction('BIO_set_tcp_ndelay');
  if not assigned(BIO_set_tcp_ndelay) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_tcp_ndelay');
  Result := BIO_set_tcp_ndelay(sock,turn_on);
end;

function Load_BIO_sock_info(sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl;
begin
  BIO_sock_info := LoadLibCryptoFunction('BIO_sock_info');
  if not assigned(BIO_sock_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_info');
  Result := BIO_sock_info(sock,type_,info);
end;

function Load_BIO_socket(domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_socket := LoadLibCryptoFunction('BIO_socket');
  if not assigned(BIO_socket) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_socket');
  Result := BIO_socket(domain,socktype,protocol,options);
end;

function Load_BIO_connect(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_connect := LoadLibCryptoFunction('BIO_connect');
  if not assigned(BIO_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_connect');
  Result := BIO_connect(sock,addr,options);
end;

function Load_BIO_bind(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_bind := LoadLibCryptoFunction('BIO_bind');
  if not assigned(BIO_bind) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_bind');
  Result := BIO_bind(sock,addr,options);
end;

function Load_BIO_listen(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_listen := LoadLibCryptoFunction('BIO_listen');
  if not assigned(BIO_listen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_listen');
  Result := BIO_listen(sock,addr,options);
end;

function Load_BIO_accept_ex(accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_accept_ex := LoadLibCryptoFunction('BIO_accept_ex');
  if not assigned(BIO_accept_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_accept_ex');
  Result := BIO_accept_ex(accept_sock,addr,options);
end;

function Load_BIO_closesocket(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_closesocket := LoadLibCryptoFunction('BIO_closesocket');
  if not assigned(BIO_closesocket) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_closesocket');
  Result := BIO_closesocket(sock);
end;

function Load_BIO_new_socket(sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_new_socket := LoadLibCryptoFunction('BIO_new_socket');
  if not assigned(BIO_new_socket) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_socket');
  Result := BIO_new_socket(sock,close_flag);
end;

function Load_BIO_new_connect(const host_port: PAnsiChar): PBIO; cdecl;
begin
  BIO_new_connect := LoadLibCryptoFunction('BIO_new_connect');
  if not assigned(BIO_new_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_connect');
  Result := BIO_new_connect(host_port);
end;

function Load_BIO_new_accept(const host_port: PAnsiChar): PBIO; cdecl;
begin
  BIO_new_accept := LoadLibCryptoFunction('BIO_new_accept');
  if not assigned(BIO_new_accept) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_accept');
  Result := BIO_new_accept(host_port);
end;

function Load_BIO_new_fd(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
begin
  BIO_new_fd := LoadLibCryptoFunction('BIO_new_fd');
  if not assigned(BIO_new_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_fd');
  Result := BIO_new_fd(fd,close_flag);
end;

function Load_BIO_new_bio_pair(bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  BIO_new_bio_pair := LoadLibCryptoFunction('BIO_new_bio_pair');
  if not assigned(BIO_new_bio_pair) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_bio_pair');
  Result := BIO_new_bio_pair(bio1,writebuf1,bio2,writebuf2);
end;

procedure Load_BIO_copy_next_retry(b: PBIO); cdecl;
begin
  BIO_copy_next_retry := LoadLibCryptoFunction('BIO_copy_next_retry');
  if not assigned(BIO_copy_next_retry) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_copy_next_retry');
  BIO_copy_next_retry(b);
end;


procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  BIO_get_flags := Load_BIO_get_flags;
  BIO_set_retry_special := Load_BIO_set_retry_special;
  BIO_set_retry_read := Load_BIO_set_retry_read;
  BIO_set_retry_write := Load_BIO_set_retry_write;
  BIO_clear_retry_flags := Load_BIO_clear_retry_flags;
  BIO_get_retry_flags := Load_BIO_get_retry_flags;
  BIO_should_read := Load_BIO_should_read;
  BIO_should_write := Load_BIO_should_write;
  BIO_should_io_special := Load_BIO_should_io_special;
  BIO_retry_type := Load_BIO_retry_type;
  BIO_should_retry := Load_BIO_should_retry;
  BIO_do_connect := Load_BIO_do_connect;
  BIO_do_accept := Load_BIO_do_accept;
  BIO_do_handshake := Load_BIO_do_handshake;
  BIO_get_mem_data := Load_BIO_get_mem_data;
  BIO_set_mem_buf := Load_BIO_set_mem_buf;
  BIO_get_mem_ptr := Load_BIO_get_mem_ptr;
  BIO_set_mem_eof_return := Load_BIO_set_mem_eof_return;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  BIO_get_new_index := Load_BIO_get_new_index;
  BIO_set_flags := Load_BIO_set_flags;
  BIO_test_flags := Load_BIO_test_flags;
  BIO_clear_flags := Load_BIO_clear_flags;
  BIO_get_callback := Load_BIO_get_callback;
  BIO_set_callback := Load_BIO_set_callback;
  BIO_get_callback_ex := Load_BIO_get_callback_ex;
  BIO_set_callback_ex := Load_BIO_set_callback_ex;
  BIO_get_callback_arg := Load_BIO_get_callback_arg;
  BIO_set_callback_arg := Load_BIO_set_callback_arg;
  BIO_method_name := Load_BIO_method_name;
  BIO_method_type := Load_BIO_method_type;
  BIO_ctrl_pending := Load_BIO_ctrl_pending;
  BIO_ctrl_wpending := Load_BIO_ctrl_wpending;
  BIO_ctrl_get_write_guarantee := Load_BIO_ctrl_get_write_guarantee;
  BIO_ctrl_get_read_request := Load_BIO_ctrl_get_read_request;
  BIO_ctrl_reset_read_request := Load_BIO_ctrl_reset_read_request;
  BIO_set_ex_data := Load_BIO_set_ex_data;
  BIO_get_ex_data := Load_BIO_get_ex_data;
  BIO_number_read := Load_BIO_number_read;
  BIO_number_written := Load_BIO_number_written;
  BIO_s_file := Load_BIO_s_file;
  BIO_new_file := Load_BIO_new_file;
  BIO_new := Load_BIO_new;
  BIO_free := Load_BIO_free;
  BIO_set_data := Load_BIO_set_data;
  BIO_get_data := Load_BIO_get_data;
  BIO_set_init := Load_BIO_set_init;
  BIO_get_init := Load_BIO_get_init;
  BIO_set_shutdown := Load_BIO_set_shutdown;
  BIO_get_shutdown := Load_BIO_get_shutdown;
  BIO_vfree := Load_BIO_vfree;
  BIO_up_ref := Load_BIO_up_ref;
  BIO_read := Load_BIO_read;
  BIO_read_ex := Load_BIO_read_ex;
  BIO_gets := Load_BIO_gets;
  BIO_write := Load_BIO_write;
  BIO_write_ex := Load_BIO_write_ex;
  BIO_puts := Load_BIO_puts;
  BIO_indent := Load_BIO_indent;
  BIO_ctrl := Load_BIO_ctrl;
  BIO_callback_ctrl := Load_BIO_callback_ctrl;
  BIO_ptr_ctrl := Load_BIO_ptr_ctrl;
  BIO_int_ctrl := Load_BIO_int_ctrl;
  BIO_push := Load_BIO_push;
  BIO_pop := Load_BIO_pop;
  BIO_free_all := Load_BIO_free_all;
  BIO_find_type := Load_BIO_find_type;
  BIO_next := Load_BIO_next;
  BIO_set_next := Load_BIO_set_next;
  BIO_get_retry_BIO := Load_BIO_get_retry_BIO;
  BIO_get_retry_reason := Load_BIO_get_retry_reason;
  BIO_set_retry_reason := Load_BIO_set_retry_reason;
  BIO_dup_chain := Load_BIO_dup_chain;
  BIO_nread0 := Load_BIO_nread0;
  BIO_nread := Load_BIO_nread;
  BIO_nwrite0 := Load_BIO_nwrite0;
  BIO_nwrite := Load_BIO_nwrite;
  BIO_debug_callback := Load_BIO_debug_callback;
  BIO_s_mem := Load_BIO_s_mem;
  BIO_s_secmem := Load_BIO_s_secmem;
  BIO_new_mem_buf := Load_BIO_new_mem_buf;
  BIO_s_socket := Load_BIO_s_socket;
  BIO_s_connect := Load_BIO_s_connect;
  BIO_s_accept := Load_BIO_s_accept;
  BIO_s_fd := Load_BIO_s_fd;
  BIO_s_log := Load_BIO_s_log;
  BIO_s_bio := Load_BIO_s_bio;
  BIO_s_null := Load_BIO_s_null;
  BIO_f_null := Load_BIO_f_null;
  BIO_f_buffer := Load_BIO_f_buffer;
  BIO_f_linebuffer := Load_BIO_f_linebuffer;
  BIO_f_nbio_test := Load_BIO_f_nbio_test;
  BIO_s_datagram := Load_BIO_s_datagram;
  BIO_dgram_non_fatal_error := Load_BIO_dgram_non_fatal_error;
  BIO_new_dgram := Load_BIO_new_dgram;
  BIO_sock_should_retry := Load_BIO_sock_should_retry;
  BIO_sock_non_fatal_error := Load_BIO_sock_non_fatal_error;
  BIO_fd_should_retry := Load_BIO_fd_should_retry;
  BIO_fd_non_fatal_error := Load_BIO_fd_non_fatal_error;
  BIO_dump := Load_BIO_dump;
  BIO_dump_indent := Load_BIO_dump_indent;
  BIO_hex_string := Load_BIO_hex_string;
  BIO_ADDR_new := Load_BIO_ADDR_new;
  BIO_ADDR_rawmake := Load_BIO_ADDR_rawmake;
  BIO_ADDR_free := Load_BIO_ADDR_free;
  BIO_ADDR_clear := Load_BIO_ADDR_clear;
  BIO_ADDR_family := Load_BIO_ADDR_family;
  BIO_ADDR_rawaddress := Load_BIO_ADDR_rawaddress;
  BIO_ADDR_rawport := Load_BIO_ADDR_rawport;
  BIO_ADDR_hostname_string := Load_BIO_ADDR_hostname_string;
  BIO_ADDR_service_string := Load_BIO_ADDR_service_string;
  BIO_ADDR_path_string := Load_BIO_ADDR_path_string;
  BIO_ADDRINFO_next := Load_BIO_ADDRINFO_next;
  BIO_ADDRINFO_family := Load_BIO_ADDRINFO_family;
  BIO_ADDRINFO_socktype := Load_BIO_ADDRINFO_socktype;
  BIO_ADDRINFO_protocol := Load_BIO_ADDRINFO_protocol;
  BIO_ADDRINFO_address := Load_BIO_ADDRINFO_address;
  BIO_ADDRINFO_free := Load_BIO_ADDRINFO_free;
  BIO_parse_hostserv := Load_BIO_parse_hostserv;
  BIO_lookup := Load_BIO_lookup;
  BIO_lookup_ex := Load_BIO_lookup_ex;
  BIO_sock_error := Load_BIO_sock_error;
  BIO_socket_ioctl := Load_BIO_socket_ioctl;
  BIO_socket_nbio := Load_BIO_socket_nbio;
  BIO_sock_init := Load_BIO_sock_init;
  BIO_set_tcp_ndelay := Load_BIO_set_tcp_ndelay;
  BIO_sock_info := Load_BIO_sock_info;
  BIO_socket := Load_BIO_socket;
  BIO_connect := Load_BIO_connect;
  BIO_bind := Load_BIO_bind;
  BIO_listen := Load_BIO_listen;
  BIO_accept_ex := Load_BIO_accept_ex;
  BIO_closesocket := Load_BIO_closesocket;
  BIO_new_socket := Load_BIO_new_socket;
  BIO_new_connect := Load_BIO_new_connect;
  BIO_new_accept := Load_BIO_new_accept;
  BIO_new_fd := Load_BIO_new_fd;
  BIO_new_bio_pair := Load_BIO_new_bio_pair;
  BIO_copy_next_retry := Load_BIO_copy_next_retry;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
