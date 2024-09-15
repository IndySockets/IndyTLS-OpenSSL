unit AcceptableCerts;

interface
uses
  System.Classes;

var
  GAcceptableCertificates : TStrings;

function GetFTPSitesIniFilePath: String;

implementation
uses IniFiles, System.IOUtils, System.SysUtils;

function GetFTPSitesIniFilePath: String;
begin
  Result := System.IOUtils.TPath.GetHomePath + '\IndyFTPClient';
  if not DirectoryExists(Result) then
  begin
    CreateDir(Result);
  end;
  Result := Result + '\acceptable_certificates.ini';
end;

procedure ReadAcceptableCertificates;
var Lini : TIniFile;
begin
  GAcceptableCertificates := TStringList.Create;
  LIni := TIniFile.Create(GetFTPSitesIniFilePath);
  try
    LIni.ReadSection('Acceptable_Certificates',GAcceptableCertificates);
  finally
    FreeAndNil(LIni);
  end;

end;

procedure WriteAcceptableCertificates;
var Lini : TIniFile;
  i : Integer;
begin
  LIni := TIniFile.Create(GetFTPSitesIniFilePath);
  try
    for i := 0 to GAcceptableCertificates.Count -1 do begin
      LIni.WriteString('Acceptable_Certificates', GAcceptableCertificates[i], '');
    end;
  finally
    FreeAndNil(LIni);
  end;
end;

initialization
  ReadAcceptableCertificates;

finalization
  WriteAcceptableCertificates;
  FreeAndNil(GAcceptableCertificates);
end.
