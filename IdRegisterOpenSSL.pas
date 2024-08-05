{
  This file is part of the Indy (Internet Direct) project, and is offered
  under the dual-licensing agreement described on the Indy website.
  (http://www.indyproject.org/)

  Copyright:
   (c) 1993-2024, Chad Z. Hower and the Indy Pit Crew. All rights reserved.
}

unit IdRegisterOpenSSL;


interface

{$i IdCompilerDefines.inc}

uses
  Classes;

procedure Register;

implementation

uses
  IdDsnResourceStrings,
  {$IFDEF FPC}
  LResources,
  {$ENDIF}
  IdSSLOpenSSL;

{$IFNDEF FPC}
  {$IFDEF BORLAND}
  {$R IdRegisterOpenSSL.dcr}
  {$ELSE}
  {$R IdRegisterCoolOpenSSL.dcr}
  {$ENDIF}
{$ENDIF}

procedure Register;
begin
  {$IFNDEF FPC}

  RegisterComponents(RSRegIndyIOHandlers, [
   TIdServerIOHandlerSSLOpenSSL,
   TIdSSLIOHandlerSocketOpenSSL
   ]);

  {$ELSE}

  //FreePascal Lazarus Registration
  RegisterComponents(RSRegIndyIOHandlers+RSProt, [
   TIdServerIOHandlerSSLOpenSSL,
   TIdSSLIOHandlerSocketOpenSSL
   ]);

  {$ENDIF}
end;

{$IFDEF FPC}
initialization
{$i IdRegisterOpenSSL.lrs}
{$ENDIF}

end.
