unit frmAbout;

interface

uses WinApi.Windows, System.SysUtils, System.Classes, Vcl.Graphics,
  Vcl.Forms, Vcl.Controls, Vcl.StdCtrls, Vcl.Buttons, Vcl.ExtCtrls,
  Vcl.BaseImageCollection, Vcl.ImageCollection, Vcl.VirtualImage;

type
  TAboutBox = class(TForm)
    Panel1: TPanel;
    ProductName: TLabel;
    Version: TLabel;
    Copyright: TLabel;
    Comments: TLabel;
    OKButton: TButton;
    VirtualImage1: TVirtualImage;
    ImageCollection1: TImageCollection;
    LinkLabel1: TLinkLabel;
    procedure FormCreate(Sender: TObject);
    procedure LinkLabel1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  AboutBox: TAboutBox;

implementation
uses ShellApi;

{$R *.dfm}

procedure TAboutBox.FormCreate(Sender: TObject);
var LMajor, LMinor, LBuild : Cardinal;
begin
  GetProductVersion(ParamStr(0), LMajor, LMinor, LBuild);
  Self.Version.Caption := IntToStr(LMajor)+'.'+IntToStr(LMinor)+'.'+IntToStr(LBuild);
  Self.ProductName.Caption := Application.Title;
end;

procedure TAboutBox.LinkLabel1Click(Sender: TObject);
begin
  ShellExecute(0, 'open', PChar(LinkLabel1.Hint), nil, nil, SW_SHOWNORMAL);
end;

end.
 
