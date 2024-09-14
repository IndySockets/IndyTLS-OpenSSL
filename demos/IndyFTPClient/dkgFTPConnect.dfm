object frmConnect: TfrmConnect
  Left = 195
  Top = 108
  BorderStyle = bsDialog
  Caption = 'Tabbed Notebook Dialog'
  ClientHeight = 300
  ClientWidth = 427
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clBtnText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  TextHeight = 15
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 427
    Height = 266
    Align = alClient
    BevelOuter = bvNone
    BorderWidth = 5
    ParentColor = True
    TabOrder = 0
    object PageControl1: TPageControl
      Left = 5
      Top = 5
      Width = 417
      Height = 256
      ActivePage = TabSheet1
      Align = alClient
      Images = VirtualImageList1
      TabOrder = 0
      object TabSheet1: TTabSheet
        Caption = 'C&onnection'
        ImageName = 'libre-gui-server'
        DesignSize = (
          409
          226)
        object lblHost: TLabel
          Left = 62
          Top = 53
          Width = 28
          Height = 15
          Caption = '&Host:'
          FocusControl = edtHostname
        end
        object lblUsername: TLabel
          Left = 31
          Top = 127
          Width = 59
          Height = 15
          Caption = '&User name:'
          FocusControl = edtUsername
        end
        object lblPassword: TLabel
          Left = 37
          Top = 166
          Width = 53
          Height = 15
          Caption = '&Password:'
          FocusControl = edtPassword
        end
        object lblProfileName: TLabel
          Left = 18
          Top = 16
          Width = 72
          Height = 15
          Caption = 'P&rofile Name:'
        end
        object lblConnectionType: TLabel
          Left = 40
          Top = 201
          Width = 48
          Height = 15
          Caption = 'Pro&tocol:'
          FocusControl = cboConnectionType
        end
        object edtHostname: TEdit
          Left = 96
          Top = 50
          Width = 301
          Height = 23
          Anchors = [akLeft, akTop, akRight]
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -12
          Font.Name = 'Segoe UI'
          Font.Style = []
          ParentFont = False
          TabOrder = 1
          OnChange = edtHostnameChange
        end
        object chkAnonymousFTP: TCheckBox
          Left = 96
          Top = 87
          Width = 185
          Height = 17
          Anchors = [akLeft, akTop, akRight]
          Caption = '&Anonymous FTP'
          TabOrder = 2
          OnClick = chkAnonymousFTPClick
        end
        object edtUsername: TEdit
          Left = 96
          Top = 124
          Width = 297
          Height = 23
          Anchors = [akLeft, akTop, akRight]
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -12
          Font.Name = 'Segoe UI'
          Font.Style = []
          ParentFont = False
          TabOrder = 3
          OnChange = edtUsernameChange
        end
        object edtPassword: TEdit
          Left = 96
          Top = 161
          Width = 297
          Height = 23
          Anchors = [akLeft, akTop, akRight]
          PasswordChar = '*'
          TabOrder = 4
          OnChange = edtPasswordChange
        end
        object cboConnectionType: TComboBox
          Left = 96
          Top = 198
          Width = 297
          Height = 23
          Style = csDropDownList
          Anchors = [akLeft, akTop, akRight]
          TabOrder = 5
          Items.Strings = (
            'Unencrypted FTP Connection'
            'Explikcit TLS FTP Connection (FTPS)'
            'Implicit TLS FTP Connection (FTPS)')
        end
        object edtProfileName: TEdit
          Left = 96
          Top = 13
          Width = 301
          Height = 23
          TabOrder = 0
          OnChange = edtProfileNameChange
        end
      end
      object TabSheet2: TTabSheet
        Caption = '&Advanced'
        ImageIndex = 1
        ImageName = 'libre-gui-idea'
        DesignSize = (
          409
          226)
        object lblTransferType: TLabel
          Left = 15
          Top = 16
          Width = 71
          Height = 15
          Caption = '&Transfer Type:'
          FocusControl = cboTransferTypes
        end
        object cboTransferTypes: TComboBox
          Left = 92
          Top = 13
          Width = 301
          Height = 23
          Style = csDropDownList
          Anchors = [akLeft, akTop, akRight]
          ItemIndex = 0
          TabOrder = 0
          Text = 'Use Default Setting'
          Items.Strings = (
            'Use Default Setting'
            'Use PASV Transfers'
            'Use PORT Transfers')
        end
      end
    end
  end
  object Panel2: TPanel
    Left = 0
    Top = 266
    Width = 427
    Height = 34
    Align = alBottom
    BevelOuter = bvNone
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clBtnText
    Font.Height = -12
    Font.Name = 'Segoe UI'
    Font.Style = []
    ParentColor = True
    ParentFont = False
    TabOrder = 1
    object OKBtn: TButton
      Left = 187
      Top = 2
      Width = 75
      Height = 25
      Caption = 'OK'
      Default = True
      Enabled = False
      ModalResult = 1
      TabOrder = 0
    end
    object CancelBtn: TButton
      Left = 267
      Top = 2
      Width = 75
      Height = 25
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 1
    end
    object HelpBtn: TButton
      Left = 347
      Top = 2
      Width = 75
      Height = 25
      Caption = '&Help'
      TabOrder = 2
    end
  end
  object ImageCollection1: TImageCollection
    Images = <
      item
        Name = 'libre-gui-server'
        SourceImages = <
          item
            Image.Data = {
              89504E470D0A1A0A0000000D494844520000004900000049080600000071730B
              DC000000017352474200AECE1CE90000000467414D410000B18F0BFC61050000
              019F49444154785EED9AB151C4301405CF544009944009500947298444B44009
              846447098494404807E6FD913CD8927C3C3B3B7B77E68DE591A21D7D49A773D7
              F7FD01CE73959F7006241920C90049064832409201920C9064802403241920C9
              0049064832409241F3AAA4EBBA5B3D5ED2DBEE789693F7DC4E84A432E22EBA76
              9A63E98372335823E97E269FCA3629A75644CC965B397688388DC75D7028B735
              20C90049064832983B4CC6C21D0B718BA7FC2C79506E52F3A2799493D7DC4E8C
              57F12182C3E428949B01BFDD6AAADF6E7C0B6040B919CC95DBB51E51727BE44B
              4EBE733B1192CA0876B75128370324192C96A4E917EB5815757DA411DB839964
              802403241920C90049068B25E9347E6A455DDB3DA16BFBAE2238718F42B919C4
              413037FF50F9C435EC31BDED8E373999FCD1DA940453283703CAADA62AB7C92A
              3E44B0BB8D42B919AC91145722ADFC28DBA49C5A11315B6EE5D821824F6FF60C
              920C906480240324192C96A4D378DF8ABA6247DC24CC24032419705562C04C32
              409201920C9064802403241920C90049064832409201920C906480A47F391C7E
              01A438EB56B1D6B1570000000049454E44AE426082}
          end>
      end
      item
        Name = 'libre-gui-idea'
        SourceImages = <
          item
            Image.Data = {
              89504E470D0A1A0A0000000D494844520000004900000049080600000071730B
              DC000000017352474200AECE1CE90000000467414D410000B18F0BFC61050000
              099149444154785EED9C5D6C1C5715C7CFBDE3CF5D3BB11D9C38A86EDC3A6E0A
              A8515A48D352040EAA4A438B7000A90912E036AD4878A1F4A5AA8414221EA015
              2295408DA536A92950125E62D48AA44894F4A1E08A42230517306D70A334719A
              90C4B177BDFE98B99C73F76CB2DE7A67CE8C6777FDE09F64EFBD779DDDB9FF39
              F77CDC998932C6C012FE687E5DC2872591042C8924604924014B2209A85C749B
              78AE1BB4EEC66FDF84BD3A00D3A640DD9C7D330B1EDB082835426D05F01A8E1C
              87847314A03763FFA04C9451A4FE3A33E1F680565FC0C9F6A0204DFC4628F078
              3328DC001EF82B30E30C4053EF657EAB64945EA4CBFD4DA6C67D1C0C3CAA9442
              8B89173CFC3E057A0F247B477928764A2812598EB713B4D91DD56AA49075E109
              7812A6F5D3A5B0ACD28894DEDF831FBB170FBC8347CA820143023DA1123BFAB2
              23F110BF48E9033FC0DFBBB39DCA80333AA812FAC1B81C7C7C2291EFA9F69E57
              0A7A78A4A2E0AC8E2BADB7425DAF8D8E0B211E9132FD1DC6F30E6398DEC0238B
              025C7EE8CCBDAD2AF1C8200F4562E122A5FADB0CB87F29B7FF9182F3CB28F0EE
              84E423C77928340B14092358CAFB132EB13B7820322673116026CD3DA63A01AA
              AE853BD1C1398E287050A86869C2824432A903FB50A09DDC0DC74C0ABC0B6F83
              197B0F3F8756C52CBF5180AE02956C03D5B01A544B17A8C44A7E231C38CD4195
              D49BA338F3C8229989038F2A0D7BB92BC6A43F0073E60DF02EBDCB23E150CBD7
              805E759B7D0D0B4EB54F251FDAC55D31D1444A3DBB0194F316F764B853E09D19
              046F34DC3F2B866ABC0E9CCE2DB824933C22C56C85C48E01EE8888B40B60C009
              950791BF71877E1D9B4084193F0DB3275EB0CB350C06141E7B7FA8F228BC4868
              456172219A84FBF621305357782446D03ADDE1C3E09DFD2B0F0443698A2D9742
              105A24B4A27DDC0C84CEB6FBCE4B7632A5C43BFDBA0D0262B4793C8C35851309
              6B3269B827CB71FF8302158B5A31E3BDF7AA78E961C1DD16C69A428984EBF9DB
              DC0CC47BE7E5925BD01CF064B8FFFD83FC3B95F92EB7020921129AA731DDDCF1
              851C3485FAB243B917465009542198F4B3A2552116897615459B6614EA47DFE4
              4EF9F13E38213E419885DFCB4D5FE49664B75D83F1CEA303C5335A3170D999D1
              BF71C71F2C801FE0A62F429128121851D837E74F70AB72D86C5E1030EC85874C
              7F60612E13691C3A245BB014F26DA12A848A5767ED97ECCFBC85AC530B7ACDE7
              C1B9F96BA03FF2711E14800289CB1ED70DF4B33291D46C1BB77C311367B9158C
              5EBD119C4F7C1D5473A7FDA1368DE5A0DAACEA966F825EB9DE9620FA867BC0B9
              69ABBC0C193BC98D2054E0DC842209F78A262F70A338D67A3EB60DF47577E1B7
              57F128826D1AA3F79CCE2FCE2B484E3849716B52E7B9E58FD16615378B22F449
              C16A1366F212B7E6C70A44D6D370EDE32801CCCF96E93DD57213F7C83A47B361
              3DE76370099280F956371F461A3C4C4C962451DBE2FA6FD5580BC8B31ECA926D
              ED854920BD16464512C7FDE741F0DEC7D7A117E7D47FB4047DA1A4529658C6B4
              DC4C3CD7CDBC8BC3730E3C7FA2645154D5DB3A2C4F9CABD43682AA5DC61DFCAC
              0B43DC2A8E991588644C4CD12D2ED052F2EB395A567AD5ADB66DA144142B7A12
              8796590EBB4CD14FE5F0CE61464F8207A0B4C32D3F54E096AE482405106ED3C6
              074A13C85A72E8EB3FE7BF74280DE8BADFBE12D6879D7ACDB67DA1652D8B84F1
              8894BD3423A03AC10D7FC812F29DB5D3857952DE52CA872C289743D99D85777F
              6FDB41A89AF93F6F1E62B32491486A99FCAA92DDDAC82D29B2164C28E7A40408
              A50457C33D2588C30352676C7D9804A5E01C378B22B4244F2652F38DDC128093
              B61B721CD154A2359B3B313681CC0BF3EEC923E1B2F9A0E89783EE810A406649
              D3D5FFE2A62F74B9A7D8B2991772E424144342E550CBAE4D92A29D097975455C
              C6C42512DDCE62008E71CF17B53CDC85DCFC28560C73E534B764582B12386D7B
              174AC3C381F392894478F03B6EF9A23FBA097FCDF52DE546898B6125BAB42416
              495569D9B52A3C83BAED53DC293F54D648979A02233BF1FC1A4C5DEF082E39D1
              4D077A358A24ADD6E3042D98B6562418BAF7D2DEA41A8C5C24C2835F70CB1F3A
              D8F6CF72A77C50F62EBE5740D15293DD17104A24D5A0FBA489A55EB1CEEE0195
              0BCAA7AC3F14A28CFB243703096749A4BCA7E41F8EBEA11C429140B4BB290D18
              4699A7C3DCAF145224B626416E91C30A25F41351082D10DDD4E539E2134D8416
              89AC0953F9EF7147046DC186DAA3164289ABDD1D08937268E80B7B3357049190
              C48E018C74A2C89083AC29EA0D58F342C1E1461488770724D00A5053CE1EEE8A
              892612A2A6F5F630CBCE4E6AEDFDDC5938E4A4F3B78183A0EC1A97D9962837C3
              471689BE8CBED4A6F6426879880B4F3F68D7207FB34E8231DBA1B15754831612
              5D2482BE94BE3C0457B73E16806EC2FA308C1F32F0844A3E1CCA3DE4B3F05B94
              1193DEBF538112DDB774F6E4157865E83EEE45E3AE3547A06B7D03F7FC897A9F
              643E0BB324C63ECBE1799B454BAF7E0537C23376651A2E8D4DC1687A358F1487
              423D1ECFAE850A44C4624957B14F06B847EC35F6228CFEAF098EFEF916EE7D18
              126176C6C0787A0666663C48A5662135390BD3D32EFF0540CFDD19F8EA3DEF73
              EFC3644F96B765A14F02E488572422E019939133CD70F8D52EC8645C989C7221
              9D26013C181B9F4663941D8B9F48389D41E5E8ED713C5392237E91724C3CD76D
              B4DE5BF8BCC9EB6FB542DF6F42EC5E22F5750ED4D5564163433538550ABE72F7
              286C5837371FC4798C5807DDB0E3200FC546E94462CCC4FE6DA0E047B9674F8A
              89542844F3F21AA872B4ED17F2990DC3B0B63DBB7F8F4B6B94EA492A97E27A74
              AB90928B94A5BF0E52EE3603EACB6F0EB5DC37F0C7F6EA2021FC20913ADBCF1D
              43890EA969E760A99FC32D9348D7F8EDCB43B7A753356F70D717F251E4AB0A1D
              F9CA15CEDEEF3FB6F131FEB39253769188E70F0D4F6204B4F75F661D3846309C
              FCF4AC0713A9192B8A9F236F6DAEF9D64F7F78E70BDC2D39151169F7537F1F3C
              7F31B3697C628647E42413D599BEA73E5DCFDDB2104B3219969549780097CEB5
              C4671EC84F352FAF858EF646E8EC6884DBD6AF80DB6F6D853B3ED9BA99FFA46C
              54C492889F3CF38F8DA7CE4C1CD54AB52C5B560D35551A92C92AA8C708578791
              AE103CCC5165BC077BB7AF8B5C8345A56222E5E83FF4EF9E53A7D3FB1A1B6BE6
              DDF7B83C3E337B7D5BFD434EB2F6A5DE9E8E9246B162545C24E21BDF3946FF3D
              C761EECE01F3A03DBFFA79373D465F312AE2930AF9E533DD0318C976E1E92A4C
              067F5C698188456149397A771EEB703596311AEA5C05C75FFC5977A44DB2B859
              54222D5616C5725BEC2C89246049A44000FE0FE407E075DCC757DB0000000049
              454E44AE426082}
          end>
      end>
    Left = 225
    Top = 213
  end
  object VirtualImageList1: TVirtualImageList
    Images = <
      item
        CollectionIndex = 0
        CollectionName = 'libre-gui-server'
        Name = 'libre-gui-server'
      end
      item
        CollectionIndex = 1
        CollectionName = 'libre-gui-idea'
        Name = 'libre-gui-idea'
      end>
    ImageCollection = ImageCollection1
    Left = 177
    Top = 221
  end
end
