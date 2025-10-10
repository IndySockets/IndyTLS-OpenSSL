(* This unit was generated from the source file async.h2pas 
It should not be modified directly. All changes should be made to async.h2pas
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


unit IdOpenSSLHeaders_async;


interface

// Headers for OpenSSL 1.1.1
// async.h


uses
  IdSSLOpenSSLAPI;

const
  ASYNC_ERR = 0;
  ASYNC_NO_JOBS = 0;
  ASYNC_PAUSE = 2;
  ASYNC_FINISH = 3;

type
  async_job_st = type Pointer;
  ASYNC_JOB = async_job_st;
  PASYNC_JOB = ^ASYNC_JOB;
  PPASYNC_JOB = ^PASYNC_JOB;
  
  async_wait_ctx_st = type Pointer;
  ASYNC_WAIT_CTX = async_wait_ctx_st;
  PASYNC_WAIT_CTX = ^ASYNC_WAIT_CTX;
  
  OSSL_ASYNC_FD = type TOpenSSL_C_INT;
  POSSL_ASYNC_FD = ^OSSL_ASYNC_FD;

  ASYNC_WAIT_CTX_set_wait_fd_cleanup = procedure(v1: PASYNC_WAIT_CTX;
    const v2: Pointer; v3: OSSL_ASYNC_FD; v4: Pointer);
  ASYNC_start_job_cb = function(v1: Pointer): TOpenSSL_C_INT;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ASYNC_init_thread}
{$EXTERNALSYM ASYNC_cleanup_thread}
{$EXTERNALSYM ASYNC_WAIT_CTX_new}
{$EXTERNALSYM ASYNC_WAIT_CTX_free}
{$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd}
{$EXTERNALSYM ASYNC_WAIT_CTX_get_fd}
{$EXTERNALSYM ASYNC_WAIT_CTX_get_all_fds}
{$EXTERNALSYM ASYNC_WAIT_CTX_get_changed_fds}
{$EXTERNALSYM ASYNC_WAIT_CTX_clear_fd}
{$EXTERNALSYM ASYNC_is_capable}
{$EXTERNALSYM ASYNC_start_job}
{$EXTERNALSYM ASYNC_pause_job}
{$EXTERNALSYM ASYNC_get_current_job}
{$EXTERNALSYM ASYNC_get_wait_ctx}
{$EXTERNALSYM ASYNC_block_pause}
{$EXTERNALSYM ASYNC_unblock_pause}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ASYNC_cleanup_thread; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl; external CLibCrypto;
procedure ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_is_capable: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_pause_job: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ASYNC_get_current_job: PASYNC_JOB; cdecl; external CLibCrypto;
function ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl; external CLibCrypto;
procedure ASYNC_block_pause; cdecl; external CLibCrypto;
procedure ASYNC_unblock_pause; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_ASYNC_cleanup_thread; cdecl;
function Load_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
procedure Load_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;
function Load_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl;
function Load_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl;
function Load_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl;
function Load_ASYNC_is_capable: TOpenSSL_C_INT; cdecl;
function Load_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_ASYNC_pause_job: TOpenSSL_C_INT; cdecl;
function Load_ASYNC_get_current_job: PASYNC_JOB; cdecl;
function Load_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
procedure Load_ASYNC_block_pause; cdecl;
procedure Load_ASYNC_unblock_pause; cdecl;

var
  ASYNC_init_thread: function (max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_init_thread;
  ASYNC_cleanup_thread: procedure ; cdecl = Load_ASYNC_cleanup_thread;
  ASYNC_WAIT_CTX_new: function : PASYNC_WAIT_CTX; cdecl = Load_ASYNC_WAIT_CTX_new;
  ASYNC_WAIT_CTX_free: procedure (ctx: PASYNC_WAIT_CTX); cdecl = Load_ASYNC_WAIT_CTX_free;
  ASYNC_WAIT_CTX_set_wait_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_set_wait_fd;
  ASYNC_WAIT_CTX_get_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_fd;
  ASYNC_WAIT_CTX_get_all_fds: function (ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_all_fds;
  ASYNC_WAIT_CTX_get_changed_fds: function (ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_get_changed_fds;
  ASYNC_WAIT_CTX_clear_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl = Load_ASYNC_WAIT_CTX_clear_fd;
  ASYNC_is_capable: function : TOpenSSL_C_INT; cdecl = Load_ASYNC_is_capable;
  ASYNC_start_job: function (job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_ASYNC_start_job;
  ASYNC_pause_job: function : TOpenSSL_C_INT; cdecl = Load_ASYNC_pause_job;
  ASYNC_get_current_job: function : PASYNC_JOB; cdecl = Load_ASYNC_get_current_job;
  ASYNC_get_wait_ctx: function (job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl = Load_ASYNC_get_wait_ctx;
  ASYNC_block_pause: procedure ; cdecl = Load_ASYNC_block_pause;
  ASYNC_unblock_pause: procedure ; cdecl = Load_ASYNC_unblock_pause;
{$ENDIF}
const
  ASYNC_init_thread_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_cleanup_thread_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_set_wait_fd_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_fd_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_all_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_changed_fds_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_WAIT_CTX_clear_fd_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_is_capable_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_start_job_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_pause_job_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_get_current_job_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_get_wait_ctx_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_block_pause_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ASYNC_unblock_pause_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function Load_ASYNC_init_thread(max_size: TOpenSSL_C_SIZET; init_size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_init_thread := LoadLibCryptoFunction('ASYNC_init_thread');
  if not assigned(ASYNC_init_thread) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_init_thread');
  Result := ASYNC_init_thread(max_size,init_size);
end;

procedure Load_ASYNC_cleanup_thread; cdecl;
begin
  ASYNC_cleanup_thread := LoadLibCryptoFunction('ASYNC_cleanup_thread');
  if not assigned(ASYNC_cleanup_thread) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_cleanup_thread');
  ASYNC_cleanup_thread();
end;

function Load_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
begin
  ASYNC_WAIT_CTX_new := LoadLibCryptoFunction('ASYNC_WAIT_CTX_new');
  if not assigned(ASYNC_WAIT_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_new');
  Result := ASYNC_WAIT_CTX_new();
end;

procedure Load_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;
begin
  ASYNC_WAIT_CTX_free := LoadLibCryptoFunction('ASYNC_WAIT_CTX_free');
  if not assigned(ASYNC_WAIT_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_free');
  ASYNC_WAIT_CTX_free(ctx);
end;

function Load_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_set_wait_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_set_wait_fd');
  if not assigned(ASYNC_WAIT_CTX_set_wait_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_set_wait_fd');
  Result := ASYNC_WAIT_CTX_set_wait_fd(ctx,key,fd,custom_data,cleanup_cb);
end;

function Load_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_fd');
  if not assigned(ASYNC_WAIT_CTX_get_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_fd');
  Result := ASYNC_WAIT_CTX_get_fd(ctx,key,fd,custom_data);
end;

function Load_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_all_fds := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_all_fds');
  if not assigned(ASYNC_WAIT_CTX_get_all_fds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_all_fds');
  Result := ASYNC_WAIT_CTX_get_all_fds(ctx,fd,numfds);
end;

function Load_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: POpenSSL_C_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_get_changed_fds := LoadLibCryptoFunction('ASYNC_WAIT_CTX_get_changed_fds');
  if not assigned(ASYNC_WAIT_CTX_get_changed_fds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_get_changed_fds');
  Result := ASYNC_WAIT_CTX_get_changed_fds(ctx,addfd,numaddfds,delfd,numdelfds);
end;

function Load_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_WAIT_CTX_clear_fd := LoadLibCryptoFunction('ASYNC_WAIT_CTX_clear_fd');
  if not assigned(ASYNC_WAIT_CTX_clear_fd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_WAIT_CTX_clear_fd');
  Result := ASYNC_WAIT_CTX_clear_fd(ctx,key);
end;

function Load_ASYNC_is_capable: TOpenSSL_C_INT; cdecl;
begin
  ASYNC_is_capable := LoadLibCryptoFunction('ASYNC_is_capable');
  if not assigned(ASYNC_is_capable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_is_capable');
  Result := ASYNC_is_capable();
end;

function Load_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: POpenSSL_C_INT; func: ASYNC_start_job_cb; args: Pointer; size: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  ASYNC_start_job := LoadLibCryptoFunction('ASYNC_start_job');
  if not assigned(ASYNC_start_job) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_start_job');
  Result := ASYNC_start_job(job,ctx,ret,func,args,size);
end;

function Load_ASYNC_pause_job: TOpenSSL_C_INT; cdecl;
begin
  ASYNC_pause_job := LoadLibCryptoFunction('ASYNC_pause_job');
  if not assigned(ASYNC_pause_job) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_pause_job');
  Result := ASYNC_pause_job();
end;

function Load_ASYNC_get_current_job: PASYNC_JOB; cdecl;
begin
  ASYNC_get_current_job := LoadLibCryptoFunction('ASYNC_get_current_job');
  if not assigned(ASYNC_get_current_job) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_get_current_job');
  Result := ASYNC_get_current_job();
end;

function Load_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
begin
  ASYNC_get_wait_ctx := LoadLibCryptoFunction('ASYNC_get_wait_ctx');
  if not assigned(ASYNC_get_wait_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_get_wait_ctx');
  Result := ASYNC_get_wait_ctx(job);
end;

procedure Load_ASYNC_block_pause; cdecl;
begin
  ASYNC_block_pause := LoadLibCryptoFunction('ASYNC_block_pause');
  if not assigned(ASYNC_block_pause) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_block_pause');
  ASYNC_block_pause();
end;

procedure Load_ASYNC_unblock_pause; cdecl;
begin
  ASYNC_unblock_pause := LoadLibCryptoFunction('ASYNC_unblock_pause');
  if not assigned(ASYNC_unblock_pause) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ASYNC_unblock_pause');
  ASYNC_unblock_pause();
end;


procedure UnLoad;
begin
  ASYNC_init_thread := Load_ASYNC_init_thread;
  ASYNC_cleanup_thread := Load_ASYNC_cleanup_thread;
  ASYNC_WAIT_CTX_new := Load_ASYNC_WAIT_CTX_new;
  ASYNC_WAIT_CTX_free := Load_ASYNC_WAIT_CTX_free;
  ASYNC_WAIT_CTX_set_wait_fd := Load_ASYNC_WAIT_CTX_set_wait_fd;
  ASYNC_WAIT_CTX_get_fd := Load_ASYNC_WAIT_CTX_get_fd;
  ASYNC_WAIT_CTX_get_all_fds := Load_ASYNC_WAIT_CTX_get_all_fds;
  ASYNC_WAIT_CTX_get_changed_fds := Load_ASYNC_WAIT_CTX_get_changed_fds;
  ASYNC_WAIT_CTX_clear_fd := Load_ASYNC_WAIT_CTX_clear_fd;
  ASYNC_is_capable := Load_ASYNC_is_capable;
  ASYNC_start_job := Load_ASYNC_start_job;
  ASYNC_pause_job := Load_ASYNC_pause_job;
  ASYNC_get_current_job := Load_ASYNC_get_current_job;
  ASYNC_get_wait_ctx := Load_ASYNC_get_wait_ctx;
  ASYNC_block_pause := Load_ASYNC_block_pause;
  ASYNC_unblock_pause := Load_ASYNC_unblock_pause;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
