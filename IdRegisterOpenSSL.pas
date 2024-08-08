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

{$IFDEF HAS_TSelectionEditor}
type
  TIdOpenSSLSelectionEditor = class(TSelectionEditor)
  public
    procedure RequiresUnits(Proc: TGetStrProc); override;
  end;
{$ENDIF}

procedure Register;

implementation

uses
  IdDsnCoreResourceStrings, // for RSRegIndyIOHandlers in dclIndyCore package
  {$IFDEF FPC}
  IdDsnResourceStrings,     // for RSProt in dclIndyProtocols package
  LResources,
  {$ENDIF}
  IdSSLOpenSSL;

{$IFNDEF FPC}
  {$R IdRegisterOpenSSL.dcr}
{$ENDIF}

{$IFDEF HAS_TSelectionEditor}

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
  RegisterComponents(RSRegIndyIOHandlers{$IFDEF FPC}+RSProt{$ENDIF}, [
    TIdServerIOHandlerSSLOpenSSL,
    TIdSSLIOHandlerSocketOpenSSL
  ]);

  {$IFDEF HAS_TSelectionEditor}
  RegisterSelectionEditor(TIdServerIOHandlerSSLOpenSSL, TIdOpenSSLSelectionEditor);
  RegisterSelectionEditor(TIdSSLIOHandlerSocketOpenSSL, TIdOpenSSLSelectionEditor);
  {$ENDIF}
end;

{$IFDEF FPC}
initialization
{$i IdRegisterOpenSSL.lrs}
{$ENDIF}

end.
