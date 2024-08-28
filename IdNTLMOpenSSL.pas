{
  This file is part of the Indy (Internet Direct) project, and is offered
  under the dual-licensing agreement described on the Indy website.
  (http://www.indyproject.org/)

  Copyright:
   (c) 1993-2024, Chad Z. Hower and the Indy Pit Crew. All rights reserved.
}

unit IdNTLMOpenSSL;

interface

implementation

uses
  IdGlobal, IdFIPS, IdSSLOpenSSLHeaders, IdHashMessageDigest,
  SysUtils;

{$I IdCompilerDefines.inc}

function LoadOpenSSL: Boolean;
begin
  Result := IdSSLOpenSSLHeaders.Load;
end;

function IsNTLMFuncsAvail: Boolean;
begin
  Result := Assigned(DES_set_odd_parity) and
    Assigned(DES_set_key) and
    Assigned(DES_ecb_encrypt);
end;

type
  Pdes_key_schedule = ^des_key_schedule;

{/*
 * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
 * The key schedule ks is also set.
 */}
procedure setup_des_key(key_56: des_cblock; Var ks: des_key_schedule);
Var
  key: des_cblock;
begin
  key[0] := key_56[0];

  key[1] := ((key_56[0] SHL 7) and $FF) or (key_56[1] SHR 1);
  key[2] := ((key_56[1] SHL 6) and $FF) or (key_56[2] SHR 2);
  key[3] := ((key_56[2] SHL 5) and $FF) or (key_56[3] SHR 3);
  key[4] := ((key_56[3] SHL 4) and $FF) or (key_56[4] SHR 4);
  key[5] := ((key_56[4] SHL 3) and $FF) or (key_56[5] SHR 5);
  key[6] := ((key_56[5] SHL 2) and $FF) or (key_56[6] SHR 6);
  key[7] :=  (key_56[6] SHL 1) and $FF;

  DES_set_odd_parity(@key);
  DES_set_key(@key, ks);
end;

{/*
 * takes a 21 byte array and treats it as 3 56-bit DES keys. The
 * 8 byte plaintext is encrypted with each key and the resulting 24
 * bytes are stored in the results array.
 */}
procedure calc_resp(keys: PDES_cblock; const ANonce: TIdBytes; results: Pdes_key_schedule);
Var
  ks: des_key_schedule;
  nonce: des_cblock;
begin
  setup_des_key(keys^, ks);
  Move(ANonce[0], nonce, 8);
  des_ecb_encrypt(@nonce, Pconst_DES_cblock(results), ks, DES_ENCRYPT);

  setup_des_key(PDES_cblock(PtrUInt(keys) + 7)^, ks);
  des_ecb_encrypt(@nonce, Pconst_DES_cblock(PtrUInt(results) + 8), ks, DES_ENCRYPT);

  setup_des_key(PDES_cblock(PtrUInt(keys) + 14)^, ks);
  des_ecb_encrypt(@nonce, Pconst_DES_cblock(PtrUInt(results) + 16), ks, DES_ENCRYPT);
end;

Const
  Magic: des_cblock = ($4B, $47, $53, $21, $40, $23, $24, $25 );

//* setup LanManager password */
function SetupLanManagerPassword(const APassword: String; const ANonce: TIdBytes): TIdBytes;
var
  lm_hpw: array[0..20] of Byte;
  lm_pw: array[0..13] of Byte;
  idx, len: Integer;
  ks: des_key_schedule;
  lm_resp: array [0..23] of Byte;
  lPassword: {$IFDEF STRING_IS_UNICODE}TIdBytes{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF STRING_IS_UNICODE}
  lPassword := IndyTextEncoding_OSDefault.GetBytes(UpperCase(APassword));
  {$ELSE}
  lPassword := UpperCase(APassword);
  {$ENDIF}

  len := IndyMin(Length(lPassword), 14);
  if len > 0 then begin
    Move(lPassword[{$IFDEF STRING_IS_UNICODE}0{$ELSE}1{$ENDIF}], lm_pw[0], len);
  end;
  if len < 14 then begin
    for idx := len to 13 do begin
      lm_pw[idx] := $0;
    end;
  end;

  //* create LanManager hashed password */

  setup_des_key(pdes_cblock(@lm_pw[0])^, ks);
  des_ecb_encrypt(@magic, Pconst_DES_cblock(@lm_hpw[0]), ks, DES_ENCRYPT);

  setup_des_key(pdes_cblock(PtrUInt(@lm_pw[0]) + 7)^, ks);
  des_ecb_encrypt(@magic, Pconst_DES_cblock(PtrUInt(@lm_hpw[0]) + 8), ks, DES_ENCRYPT);

  FillChar(lm_hpw[16], 5, 0);

  calc_resp(PDes_cblock(@lm_hpw[0]), ANonce, Pdes_key_schedule(@lm_resp[0]));

  SetLength(Result, SizeOf(lm_resp));
  Move(lm_resp[0], Result[0], SizeOf(lm_resp));
end;

//* create NT hashed password */
function CreateNTPassword(const APassword: String; const ANonce: TIdBytes): TIdBytes;
var
  nt_hpw: array [1..21] of Byte;
  nt_hpw128: TIdBytes;
  nt_resp: array [1..24] of Byte;
  LMD4: TIdHashMessageDigest4;
  {$IFNDEF STRING_IS_UNICODE}
  i: integer;
  lPwUnicode: TIdBytes;
  {$ENDIF}
begin
  CheckMD4Permitted;
  LMD4 := TIdHashMessageDigest4.Create;
  try
    {$IFDEF STRING_IS_UNICODE}
    nt_hpw128 := LMD4.HashString(APassword, IndyTextEncoding_UTF16LE);
    {$ELSE}
    // RLebeau: TODO - should this use UTF-16 as well?  This logic will
    // not produce a valid Unicode string if non-ASCII characters are present!
    SetLength(lPwUnicode, Length(S) * SizeOf(WideChar));
    for i := 0 to Length(S)-1 do begin
      lPwUnicode[i*2] := Byte(S[i+1]);
      lPwUnicode[(i*2)+1] := Byte(#0);
    end;
    nt_hpw128 := LMD4.HashBytes(lPwUnicode);
    {$ENDIF}
  finally
    LMD4.Free;
  end;

  Move(nt_hpw128[0], nt_hpw[1], 16);
  FillChar(nt_hpw[17], 5, 0);

  calc_resp(pdes_cblock(@nt_hpw[1]), ANonce, Pdes_key_schedule(@nt_resp[1]));

  SetLength(Result, SizeOf(nt_resp));
  Move(nt_resp[1], Result[0], SizeOf(nt_resp));
end;

initialization
  IdFIPS.LoadNTLMLibrary := LoadOpenSSL;
  IdFIPS.IsNTLMFuncsAvail := IsNTLMFuncsAvail;
  IdFIPS.NTLMGetLmChallengeResponse := SetupLanManagerPassword;
  IdFIPS.NTLMGetNtChallengeResponse := CreateNTPassword;

end.