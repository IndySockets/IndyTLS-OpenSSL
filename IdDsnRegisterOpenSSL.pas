{
  This file is part of the Indy (Internet Direct) project, and is offered
  under the dual-licensing agreement described on the Indy website.
  (http://www.indyproject.org/)

  Copyright:
   (c) 1993-2024, Chad Z. Hower and the Indy Pit Crew. All rights reserved.
}

unit IdDsnRegisterOpenSSL;

interface

{$I IdCompilerDefines.inc}

uses
  Classes,
  {$IFDEF DOTNET}
  Borland.Vcl.Design.DesignIntF,
  Borland.Vcl.Design.DesignEditors
  {$ELSE}
    {$IFDEF FPC}
  PropEdits,
  ComponentEditors
    {$ELSE}
      {$IFDEF VCL_6_OR_ABOVE}
  DesignIntf,
  DesignEditors
      {$ELSE}
  Dsgnintf
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
  ;

type
  {$IFDEF HAS_TSelectionEditor}
  TIdOpenSSLSelectionEditor = class(TSelectionEditor)
  public
    procedure RequiresUnits(Proc: TGetStrProc); override;
  end;
  {$ENDIF}

procedure Register;

implementation

{$IFDEF HAS_TSelectionEditor}

uses
  IdSSLOpenSSL;

{TIdOpenSSLSelectionEditor}

procedure TIdOpenSSLSelectionEditor.RequiresUnits(Proc: TGetStrProc);
begin
  inherited RequiresUnits(Proc);
  //for new callback event
  Proc('IdCTypes'); {Do not localize}
  Proc('IdSSLOpenSSLHeaders'); {Do not localize}
end;

{$ENDIF}

procedure Register;
begin
  {$IFDEF HAS_TSelectionEditor}
  RegisterSelectionEditor(TIdServerIOHandlerSSLOpenSSL, TIdOpenSSLSelectionEditor);
  RegisterSelectionEditor(TIdSSLIOHandlerSocketOpenSSL, TIdOpenSSLSelectionEditor);
  {$ENDIF}
end;

end.
