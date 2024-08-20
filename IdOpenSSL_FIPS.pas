unit IdOpenSSL_FIPS;

interface

implementation
uses
  IdCTypes,
  IdFIPS,
  IdGlobal,
   IdSSLOpenSSLExceptionHandlers,
   IdOpenSSLHeaders_crypto,
   IdOpenSSLHeaders_evp,
   IdOpenSSLHeaders_hmac,
   IdOpenSSLHeaders_ossl_typ,
   IdSSLOpenSSLLoader;

//**************** FIPS Support backend *******************
function OpenSSLIsHashingIntfAvail : Boolean;
begin
  Result := Assigned(EVP_DigestInit_ex) and
            Assigned(EVP_DigestUpdate) and
            Assigned(EVP_DigestFinal_ex) ;
end;

function OpenSSLGetFIPSMode : Boolean;
begin
  Result := FIPS_mode <> 0;
end;

function OpenSSLSetFIPSMode(const AMode : Boolean) : Boolean;
begin
  //leave this empty as we may not be using something that supports FIPS
  if AMode then begin
    Result := FIPS_mode_set(1) = 1;
  end else begin
    Result := FIPS_mode_set(0) = 1;
  end;
end;

function OpenSSLGetDigestCtx( AInst : PEVP_MD) : TIdHashIntCtx;
  {$IFDEF USE_INLINE} inline; {$ENDIF}
var LRet : Integer;
begin
  Result := AllocMem(SizeOf(EVP_MD_CTX));
  EVP_MD_CTX_init(Result);

  LRet := EVP_DigestInit_ex(Result, AInst, nil);
  if LRet <> 1 then begin
    EIdDigestInitEx.RaiseException('EVP_DigestInit_ex error');
  end;
end;

function OpenSSLIsMD2HashIntfAvail: Boolean;
begin
  {$IFDEF OPENSSL_NO_MD2}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_md2);
  {$ENDIF}
end;

function OpenSSLGetMD2HashInst : TIdHashIntCtx;
{$IFNDEF OPENSSL_NO_MD2}
var
  LRet : PEVP_MD;
{$ENDIF}
begin
  {$IFDEF OPENSSL_NO_MD2}
  Result := nil;
  {$ELSE}
  LRet := EVP_md2;
  Result := OpenSSLGetDigestCtx(LRet);
  {$ENDIF}
end;

function OpenSSLIsMD4HashIntfAvail: Boolean;
begin
  Result := Assigned(EVP_md4);
end;

function OpenSSLGetMD4HashInst : TIdHashIntCtx;
var
  LRet : PEVP_MD;
begin
  LRet := EVP_md4;
  Result := OpenSSLGetDigestCtx(LRet);
end;

function OpenSSLIsMD5HashIntfAvail: Boolean;
begin
  Result := Assigned(EVP_md5);
end;

function OpenSSLGetMD5HashInst : TIdHashIntCtx;
var
  LRet : PEVP_MD;
begin
  LRet := EVP_md5;
  Result := OpenSSLGetDigestCtx(LRet);
end;

function OpenSSLIsSHA1HashIntfAvail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha1);
  {$ENDIF}
end;

function OpenSSLGetSHA1HashInst : TIdHashIntCtx;
{$IFNDEF OPENSSL_NO_SHA}
var
  LRet : PEVP_MD;
{$ENDIF}
begin
  {$IFDEF OPENSSL_NO_SHA}
  Result := nil;
  {$ELSE}
  LRet := EVP_sha1;
  Result := OpenSSLGetDigestCtx(LRet);
  {$ENDIF}
end;

function OpenSSLIsSHA224HashIntfAvail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha224);
  {$ENDIF}
end;

function OpenSSLGetSHA224HashInst : TIdHashIntCtx;
{$IFNDEF OPENSSL_NO_SHA256}
var
  LRet : PEVP_MD;
{$ENDIF}
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
  {$ELSE}
  LRet := EVP_sha224;
  Result := OpenSSLGetDigestCtx(LRet);
  {$ENDIF}
end;

function OpenSSLIsSHA256HashIntfAvail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha256);
  {$ENDIF}
end;

function OpenSSLGetSHA256HashInst : TIdHashIntCtx;
{$IFNDEF OPENSSL_NO_SHA256}
var
  LRet : PEVP_MD;
{$ENDIF}
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
  {$ELSE}
  LRet := EVP_sha256;
  Result := OpenSSLGetDigestCtx(LRet);
  {$ENDIF}
end;

function OpenSSLIsSHA384HashIntfAvail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha384);
  {$ENDIF}
end;

function OpenSSLGetSHA384HashInst : TIdHashIntCtx;
{$IFNDEF OPENSSL_NO_SHA512}
var
  LRet : PEVP_MD;
{$ENDIF}
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
  {$ELSE}
  LRet := EVP_sha384;
  Result := OpenSSLGetDigestCtx(LRet);
  {$ENDIF}
end;

function OpenSSLIsSHA512HashIntfAvail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
  {$ELSE}
  Result := Assigned(EVP_sha512);
  {$ENDIF}
end;

function OpenSSLGetSHA512HashInst : TIdHashIntCtx;
{$IFNDEF OPENSSL_NO_SHA512}
var
  LRet : PEVP_MD;
{$ENDIF}
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
  {$ELSE}
  LRet := EVP_sha512;
  Result := OpenSSLGetDigestCtx(LRet);
{$ENDIF}
end;

procedure OpenSSLUpdateHashInst(ACtx: TIdHashIntCtx; const AIn: TIdBytes);
var
  LRet : TIdC_Int;
begin
  LRet := EVP_DigestUpdate(ACtx, PByte(Ain), Length(AIn));
  if LRet <> 1 then begin
    EIdDigestInitEx.RaiseException('EVP_DigestUpdate error');
  end;
end;

function OpenSSLFinalHashInst(ACtx: TIdHashIntCtx): TIdBytes;
var
  LLen : TIdC_UInt;
  LRet : TIdC_Int;
begin
  SetLength(Result,EVP_MAX_MD_SIZE);
  LRet := EVP_DigestFinal_ex(ACtx, @Result[0], LLen);
  if LRet <> 1 then begin
    EIdDigestFinalEx.RaiseException('EVP_DigestFinal_ex error');
  end;
  SetLength(Result,LLen);
  EVP_MD_CTX_cleanup(ACtx);
  FreeMem(ACtx,SizeOf(EVP_MD_CTX));
end;

function OpenSSLIsHMACAvail : Boolean;
begin
  {$IFDEF OPENSSL_NO_HMAC}
  Result := False;
  {$ELSE}
  Result := Assigned(HMAC_CTX_init) and
            Assigned(HMAC_Init_ex) or
            Assigned(HMAC_Update) or
            Assigned(HMAC_Final) or
            Assigned(HMAC_CTX_cleanup);
  {$ENDIF}
end;

function OpenSSLIsHMACMD5Avail: Boolean;
begin
 {$IFDEF OPENSSL_NO_MD5}
 Result := False;
 {$ELSE}
 Result := Assigned(EVP_md5);
 {$ENDIF}
end;

function OpenSSLGetHMACMD5Inst(const AKey : TIdBytes) : TIdHMACIntCtx;
begin
  {$IFDEF OPENSSL_NO_MD5}
  Result := nil;
  {$ELSE}
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
  HMAC_Init_ex(Result, PByte(AKey), Length(AKey), EVP_md5, nil);
  {$ENDIF}
end;

function OpenSSLIsHMACSHA1Avail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha1);
  {$ENDIF}
end;

function OpenSSLGetHMACSHA1Inst(const AKey : TIdBytes) : TIdHMACIntCtx;
begin
  {$IFDEF OPENSSL_NO_SHA}
  Result := nil;
  {$ELSE}
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
  HMAC_Init_ex(Result, PByte(AKey), Length(AKey), EVP_sha1, nil);
  {$ENDIF}
end;

function OpenSSLIsHMACSHA224Avail: Boolean;

begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha224);
  {$ENDIF}
end;

function OpenSSLGetHMACSHA224Inst(const AKey : TIdBytes) : TIdHMACIntCtx;
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
  {$ELSE}
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
  HMAC_Init_ex(Result, PByte(AKey), Length(AKey), EVP_sha224, nil);
  {$ENDIF}
end;

function OpenSSLIsHMACSHA256Avail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha256);
  {$ENDIF}
end;

function OpenSSLGetHMACSHA256Inst(const AKey : TIdBytes) : TIdHMACIntCtx;
begin
  {$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
  {$ELSE}
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
  HMAC_Init_ex(Result, PByte(AKey), Length(AKey), EVP_sha256, nil);
  {$ENDIF}
end;

function OpenSSLIsHMACSHA384Avail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha384);
  {$ENDIF}
end;

function OpenSSLGetHMACSHA384Inst(const AKey : TIdBytes) : TIdHMACIntCtx;
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
  {$ELSE}
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
  HMAC_Init_ex(Result, PByte(AKey), Length(AKey), EVP_sha384, nil);
  {$ENDIF}
end;

function OpenSSLIsHMACSHA512Avail: Boolean;
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := False;
  {$ELSE}
  Result := Assigned(EVP_sha512);
  {$ENDIF}
end;

function OpenSSLGetHMACSHA512Inst(const AKey : TIdBytes) : TIdHMACIntCtx;
begin
  {$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
  {$ELSE}
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
  HMAC_Init_ex(Result, PByte(AKey), Length(AKey), EVP_sha512, nil);
  {$ENDIF}
end;

procedure OpenSSLUpdateHMACInst(ACtx : TIdHMACIntCtx; const AIn: TIdBytes);
begin
  HMAC_Update(ACtx, PByte(AIn), Length(AIn));
end;

function OpenSSLFinalHMACInst(ACtx: TIdHMACIntCtx): TIdBytes;
var
  LLen : TIdC_UInt;
begin
  LLen := EVP_MAX_MD_SIZE;
  SetLength(Result,LLen);
  HMAC_Final(ACtx, @Result[0], @LLen);
  SetLength(Result,LLen);
  HMAC_CTX_cleanup(ACtx);
  FreeMem(ACtx,SizeOf(HMAC_CTX));
end;

function LoadOpenSSL : Boolean;
begin
  Result := GetOpenSSLLoader.Load;
end;

initialization
  SetFIPSMode := OpenSSLSetFIPSMode;
  GetFIPSMode := OpenSSLGetFIPSMode;
  IsHashingIntfAvail := OpenSSLIsHashingIntfAvail;
  IsMD2HashIntfAvail := OpenSSLIsMD2HashIntfAvail;
  GetMD2HashInst := OpenSSLGetMD2HashInst;
  IsMD4HashIntfAvail := OpenSSLIsMD4HashIntfAvail;
  GetMD4HashInst := OpenSSLGetMD4HashInst;
  IsMD5HashIntfAvail := OpenSSLIsMD5HashIntfAvail;
  GetMD5HashInst := OpenSSLGetMD5HashInst;
  IsSHA1HashIntfAvail := OpenSSLIsSHA1HashIntfAvail;
  GetSHA1HashInst := OpenSSLGetSHA1HashInst;
  IsSHA224HashIntfAvail := OpenSSLIsSHA224HashIntfAvail;
  GetSHA224HashInst := OpenSSLGetSHA224HashInst;
  IsSHA256HashIntfAvail := OpenSSLIsSHA256HashIntfAvail;
  GetSHA256HashInst := OpenSSLGetSHA256HashInst;
  IsSHA384HashIntfAvail := OpenSSLIsSHA384HashIntfAvail;
  GetSHA384HashInst := OpenSSLGetSHA384HashInst;
  IsSHA512HashIntfAvail := OpenSSLIsSHA512HashIntfAvail;
  GetSHA512HashInst := OpenSSLGetSHA512HashInst;
  UpdateHashInst := OpenSSLUpdateHashInst;
  FinalHashInst := OpenSSLFinalHashInst;
  IsHMACAvail := OpenSSLIsHMACAvail;
  IsHMACMD5Avail := OpenSSLIsHMACMD5Avail;
  GetHMACMD5HashInst := OpenSSLGetHMACMD5Inst;
  IsHMACSHA1Avail  := OpenSSLIsHMACSHA1Avail;
  GetHMACSHA1HashInst:= OpenSSLGetHMACSHA1Inst;
  IsHMACSHA224Avail := OpenSSLIsHMACSHA224Avail;
  GetHMACSHA224HashInst:= OpenSSLGetHMACSHA224Inst;
  IsHMACSHA256Avail := OpenSSLIsHMACSHA256Avail;
  GetHMACSHA256HashInst:= OpenSSLGetHMACSHA256Inst;
  IsHMACSHA384Avail := OpenSSLIsHMACSHA384Avail;
  GetHMACSHA384HashInst:= OpenSSLGetHMACSHA384Inst;
  IsHMACSHA512Avail := OpenSSLIsHMACSHA512Avail;
  GetHMACSHA512HashInst:= OpenSSLGetHMACSHA512Inst;
  UpdateHMACInst := OpenSSLUpdateHMACInst;
  FinalHMACInst := OpenSSLFinalHMACInst;
  LoadHashLibrary :=  LoadOpenSSL;
end.
