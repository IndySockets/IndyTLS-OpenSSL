object frmSettings: TfrmSettings
  Left = 195
  Top = 108
  BorderStyle = bsDialog
  Caption = 'Settings'
  ClientHeight = 382
  ClientWidth = 508
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clBtnText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnShow = FormShow
  TextHeight = 15
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 508
    Height = 348
    Align = alClient
    BevelOuter = bvNone
    BorderWidth = 5
    ParentColor = True
    TabOrder = 0
    object PageControl1: TPageControl
      Left = 5
      Top = 5
      Width = 498
      Height = 338
      ActivePage = TabSheet1
      Align = alClient
      Images = VirtualImageList1
      TabOrder = 0
      object TabSheet1: TTabSheet
        Caption = 'F&ont'
        ImageIndex = 1
        ImageName = 'libre-gui-font'
        DesignSize = (
          490
          308)
        object redtLog: TRichEdit
          Left = 13
          Top = 55
          Width = 458
          Height = 94
          Anchors = [akLeft, akTop, akRight, akBottom]
          Font.Charset = ANSI_CHARSET
          Font.Color = clWindowText
          Font.Height = -12
          Font.Name = 'Consolas'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 0
          WantReturns = False
          WordWrap = False
        end
        object btnFontSelect: TButton
          Left = 178
          Top = 13
          Width = 75
          Height = 25
          Caption = 'Fon&t'
          TabOrder = 1
          OnClick = btnFontSelectClick
        end
        object redtTextSamples: TRichEdit
          Left = 13
          Top = 155
          Width = 156
          Height = 150
          Anchors = [akLeft, akBottom]
          Font.Charset = ANSI_CHARSET
          Font.Color = clBtnText
          Font.Height = -12
          Font.Name = 'Segoe UI'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 2
          WantReturns = False
          WordWrap = False
        end
        object ScrollBox1: TScrollBox
          Left = 175
          Top = 155
          Width = 296
          Height = 150
          VertScrollBar.Position = 13
          Anchors = [akLeft, akRight, akBottom]
          TabOrder = 3
          object lblErrors: TLabel
            Left = 16
            Top = 26
            Width = 28
            Height = 15
            Caption = 'Error:'
          end
          object lblTLSMessages: TLabel
            Left = 16
            Top = 54
            Width = 70
            Height = 15
            Caption = 'TLS Message:'
          end
          object lblDirOutput: TLabel
            Left = 16
            Top = 82
            Width = 59
            Height = 15
            Caption = 'Dir Output:'
          end
          object lblForeground: TLabel
            Left = 92
            Top = 3
            Width = 65
            Height = 15
            Caption = 'Foreground:'
          end
          object lblBackground: TLabel
            Left = 208
            Top = 3
            Width = 64
            Height = 15
            Caption = 'Background'
          end
          object lblDebugOutput: TLabel
            Left = 16
            Top = 110
            Width = 38
            Height = 15
            Caption = 'Debug:'
          end
          object cboErrorForeground: TColorBox
            Left = 92
            Top = 23
            Width = 110
            Height = 22
            TabOrder = 0
            OnChange = cboErrorForegroundChange
          end
          object cboErrorBackground: TColorBox
            Left = 208
            Top = 23
            Width = 113
            Height = 22
            TabOrder = 1
            OnChange = cboErrorBackgroundChange
          end
          object cboTLSMessageForeground: TColorBox
            Left = 89
            Top = 51
            Width = 113
            Height = 22
            TabOrder = 2
            OnChange = cboTLSMessageForegroundChange
          end
          object cboTLSMessageBackground: TColorBox
            Left = 208
            Top = 51
            Width = 113
            Height = 22
            TabOrder = 3
            OnChange = cboTLSMessageBackgroundChange
          end
          object cboDirOutputForeground: TColorBox
            Left = 89
            Top = 79
            Width = 113
            Height = 22
            TabOrder = 4
            OnChange = cboDirOutputForegroundChange
          end
          object cboDirOutputBackground: TColorBox
            Left = 208
            Top = 79
            Width = 113
            Height = 22
            TabOrder = 5
            OnChange = cboDirOutputBackgroundChange
          end
          object cboDebugForeground: TColorBox
            Left = 88
            Top = 107
            Width = 114
            Height = 22
            TabOrder = 6
            OnSelect = cboDebugForegroundSelect
          end
          object cboDebugBackground: TColorBox
            Left = 208
            Top = 107
            Width = 110
            Height = 22
            TabOrder = 7
            OnSelect = cboDebugBackgroundSelect
          end
        end
      end
      object TabSheet2: TTabSheet
        Caption = '&FTP Settings'
        ImageName = 'libre-gui-idea'
        DesignSize = (
          490
          308)
        object lblTransferType: TLabel
          Left = 15
          Top = 16
          Width = 71
          Height = 15
          Caption = '&Transfer Type:'
          FocusControl = cboTransferTypes
        end
        object lblAdvancedOptions: TLabel
          Left = 30
          Top = 51
          Width = 56
          Height = 15
          Caption = '&Advanced:'
        end
        object cboTransferTypes: TComboBox
          Left = 92
          Top = 13
          Width = 382
          Height = 23
          Style = csDropDownList
          Anchors = [akLeft, akTop, akRight]
          TabOrder = 0
          Items.Strings = (
            'Use PASV Transfers'
            'Use PORT Transfers')
        end
        object chklbAdvancedOptions: TCheckListBox
          Left = 92
          Top = 51
          Width = 382
          Height = 97
          Anchors = [akLeft, akTop, akRight]
          ItemHeight = 17
          Items.Strings = (
            'Send HOST command'
            'Send EPSV/EPRT command instead of PASV/PORT'
            'Try  NAT Fast Tracking'
            'Send MLSD instead of DIR command')
          TabOrder = 1
          OnClickCheck = chklbAdvancedOptionsClickCheck
        end
      end
      object TabSheet3: TTabSheet
        Caption = 'F&irewall/Proxy'
        ImageIndex = 2
        ImageName = 'libre-gui-firewall'
        object btnNATSettings: TButton
          Left = 103
          Top = 13
          Width = 210
          Height = 25
          Caption = '&NAT Settings'
          TabOrder = 0
          OnClick = btnNATSettingsClick
        end
        object btnTransparentProxy: TButton
          Left = 104
          Top = 48
          Width = 209
          Height = 25
          Caption = '&HTTP Connect or SOCKS Proxy'
          TabOrder = 1
          OnClick = btnTransparentProxyClick
        end
        object btnFTPProxySettings: TButton
          Left = 103
          Top = 83
          Width = 209
          Height = 25
          Caption = 'F&TP Proxy'
          TabOrder = 2
          OnClick = btnFTPProxySettingsClick
        end
      end
      object TabSheet4: TTabSheet
        Caption = '&Debug Settings'
        ImageIndex = 3
        ImageName = 'libre-gui-bug'
        object chkLogDebug: TCheckBox
          Left = 97
          Top = 13
          Width = 316
          Height = 28
          Caption = 'Log Debug Output (This will be Extremely Verbose)'
          TabOrder = 0
        end
      end
    end
  end
  object Panel2: TPanel
    Left = 0
    Top = 348
    Width = 508
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
    DesignSize = (
      508
      34)
    object OKBtn: TButton
      Left = 347
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Caption = 'OK'
      Default = True
      ModalResult = 1
      TabOrder = 0
    end
    object CancelBtn: TButton
      Left = 428
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 1
    end
  end
  object ImageCollection1: TImageCollection
    Images = <
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
      end
      item
        Name = 'libre-gui-font'
        SourceImages = <
          item
            Image.Data = {
              89504E470D0A1A0A0000000D494844520000004900000049080600000071730B
              DC000000017352474200AECE1CE90000000467414D410000B18F0BFC61050000
              046649444154785EED9C315714411084392343CD30830C33CC3012328D34D34C
              437F8299FE1B0D31C3484232C9C00832CD30930CABB839DFBAEEED76F576CF1D
              7ADF7BFD6640D89BADEB9AE9995B9C5C5D5DADADE8E7566957F4B012C9C04A24
              032B910C2C64E29E4C26B7D1EC4CBF9239C6987F947E1D2852ED008FF9D2CE78
              D375CDCC5894DD9E97D6C3D3D256A3BADD8AD5BE21EE5C7FC3C726C67D5EFAE9
              2C22937611630422AF4A5B85458834C66A3322AE61A6AADD82AC36E33EC67E5A
              FAA9D4CEA467880881C88BD2A6535BA4C895A99AE5AAD9AD58ED02C1368A0718
              FF71E9A751339368B5488148956CAA2952461158655EAA6237588D933557354B
              267D47F0E7AD59F710F77054FA29D4CA24C56A0708E5A6D3B729B54452E68E8F
              25ACA45B2EDD6EA2D52E117711EB88337EC3C81EEEE3B0F4C3A991498AD50E71
              B397086E5E956A3A7595AB21926AB519FBA5B5C037220FDA2D2B006DC38E35D6
              1BBFCBD382F6BFF7C56EF3B523233B939477F80803E2F27F0DFA9C639463DA34
              CB658BA40CFC53699B48962B5B9F70D244C28069355AC64A97205DC2CD437D3D
              339999A458ED1CF6EADAA8B2B064596025C5729922BD2CAD058AF117108E7392
              527DA7582E45240C74038DF2B95A5F85AD54DF2C5CC32D979549CA568176EAAB
              9695C99B845B2E4B2465D3B90F5BCD9D77F06F6AF51D6EB970911C56B3AC604A
              36D172A115784626A9BB728B004A2940428F4FC24F0190495FD06C4FBF1A841B
              DABDD2EF05D7E5F938B3C4C2F569429F8D1542330937B285C62A10513244B11C
              E7A430CB45DB2DC36A331666B950BB21934ED0309B2CB0CADE2CFD41706DE5F0
              8ED06AF7F01AA39F650ACBA46235AB4044AA7FCACD2AD57798E5C2320922BD43
              F376FA95890F88AFD3AE994708A5A23EC0FD3D297D379122F14C9A35D2321162
              B910BB4120168FCB261009B15CD49C94FED9D70846EFE542ECB6A4566B42CBFD
              3E1A56199D494B6CB526A32C1761B7B403F840468D71B4DD90492CF078BEBCEC
              B82D372A9320106B969B2010715B6EACDD6E82D5662867EE7F30CA6E0EAB715B
              11727C01F8BACA3688F81E92A7489E00B41A3BD6B8E8BA8E370057D4F66B0C85
              EBEF52C6D84D4D5F69433B0406AF9E7D1357D1EB120936F394FBEA79900555F8
              1D8C5DAEE9BC9944AB598F5209E7A1CE0F2047E2115E7E32CE2B92BAAAF18991
              D1875F6D704DF5C91322AFC8B2484EAB299FC2AAA896DBC63D48ABA2279354AB
              91D049BB45BAE53C22A9ABDA695989B2509F3C2192E524919C56CBCC22CE4BEA
              D937D9522CA7661205A2500A194B7F1BCF9C67B71CDE097380F7FC152142ABEC
              79013CD5F759D7B5BAC29C49CB68B519B8114FF5BD817B323DD8A1D86D59AD36
              C3F38698B6298A48EAAA965565CF23AF1468FBAF2B00EBA29FFC71213E775D2B
              33009F3C698F632876BAAED50C6B2679AC965965CFC363B9C19AC92A92E704B2
              CAA4DD22C7725DE9D50CE0B1DA49D7B5B20378C6CAE8FDBB94C1E3DB5299AAC7
              0BFCEF7B1691491CEF6B34EA87137CE26EEE13C0219FE0FEEB2825C07FCB4A24
              032B9106595BFB05384EF8DF1E0A48BD0000000049454E44AE426082}
          end>
      end
      item
        Name = 'libre-gui-firewall'
        SourceImages = <
          item
            Image.Data = {
              89504E470D0A1A0A0000000D494844520000004900000049080600000071730B
              DC000000017352474200AECE1CE90000000467414D410000B18F0BFC61050000
              058D49444154785EED9A2F741547148777AA2253876B7048AA1A5CEA88A251B4
              AA44B59128401114441147AA82832AA8A32A71090A1CA9228E38708DEAF6BB33
              F7BDECEECCEC9BB7EFE51CE6ED7EE76C76EEECBF37BFDCB9337B774C5996C540
              3BDFE87EA08541A40406911218444A6010298141A40406911218444AA07F2219
              B3541AB3AA5612FD1249042A8A67A6284EB526895E8984408FD9BD2DCAF2CCD5
              A4D19F773763AED3D2031AFCADD624D31B918843AFD87DA1C19BAE269D7E7437
              639689433F517AEB2AA6A31722D157EC688650E7B6624A7A2112E25CD1E2683F
              157D1BDD7ED0E254F4A5BBD921DFC62563566CE514F4A5BBBDD7A208F6508BC9
              F4690AF011B1AC17D1E2751AFEC61E48A037310981FED0A2B04FB74B0EE27D0A
              DCCFF1203B0590D18EF2335B9B407F4472EF6B2F9DE182385DF077355BE94D4C
              B2F0FEC6DF77CEB0B1E91CB1BE47C013AD0AB2F09E647347C62C39A37C8F3087
              B60C0824A9937D35A3043D69DBCD25EE38AB95D7DB3C58CB63B85EFE63F2AE74
              A9F0EC6D2DC63146DA718A40561C44FB19715E4879040ADC45885D353D6222AD
              71A30335A370E5263FF4B99A63B8FE0ED74FFC0FCDCAC3B2E431ED208A04E87F
              C622B8C4DB67F1226B03F619F655840CBEDB2D767773DDEC26022CBB0A70428C
              03B8C07119EDA2417CD163D27D0490D0D14CD7FEA9FB2AB775EFB1B02249C0C6
              3BEEB189E7D466D70877A8F563A893001F7CAF5B48912438B33BA0E14B6C3B74
              B17A4EDB75B9F1285741AEF3583C918CD94698172210DE728820C11190E35E96
              92F36F69B1C6E288C4BB181E7444C9BEE5D3E05384D89072088E872690D7745F
              235B9168E4032D8A40F225E403A2D8342D659949AFE3455FECF1001CF73E2B51
              B72C62AB39265791F6989F3DB1A5D1A7A2CA304F790B815A5F3562702F2F78E7
              38E396A0BBCB73CF11E81ABFFEA82A10F6318DBAA1661C26CCFC0D4D987F44E0
              7A50179172DDFE432044A174B151B71A3AD7DB8A62AD79AD6E6BCD73F30DDCC6
              C844B1B6F081069EE045C76ACE8D3C4572EF5FF7D4AA922C10D74B4848224B91
              A44B54E35047827322F0027E2C705FE147D4D20997014FFE8500EC0DC59A45F8
              554D0BE7FEC5B9F64D9EF9D03EC7BD818573DED0A07535E3B861FE93332EE07A
              592BE02DA88889B4C28FF8A8E6A5C193AFD2706FAD10CF975973EDD30FE73EE0
              5C3BEC23D2BF1C1FA73A1A6C106D5F6B3908D7CB944146B71A3C233832E6D4DD
              C662B608240D7D8AA744E30D02C9222E4F2081FABFB558233F91267C81A5A12B
              087524A31FDB45DC324612FFEF38DE96FCAFE59946E4E8491303B67A9AAC6AFB
              8C38A5DD8AE215F5710F939131324BCF4924DBC5684CB4ABCD48281167C94924
              DBCDF0062FD0CF0AC24B8E7B4F4D8FEC44A24B9CD1A85A56710E48622E7ACF9C
              44AAA630E6E64D087ED2E645423622D190EFB428CC4524F5C8CD362F12629349
              098E53AD9AEFC8B14D793490C92CBBE6507FC6B976F461287F8C68F76DED6C3C
              42A0891F3883227DED20D22A2249AAB633B4FA987B48EE68627CCB522401A13E
              D1C84E0B45A59B71EDC4851223720ADC4D5ADFCFDA40A0A9D2BBB198749D1B3D
              55330A57EE1027BC65755C2F9F9643F99E5939E7991B368EC5D3AFAD70FD168D
              6E1DCD9AC444FA6A174CA848D68B3A74B9A440DD24BBEE8628D53C53F0853404
              E2EE761148C83126DDC453ADF720D80E8D9F383A71CE1E5DE6AE9A5393A34832
              8773E90E97D56C5D6A8C40B2406B4BCD4E6439BAE141BFE14D361B40F991AD6C
              A01EB68140D1156CA9E43A0590EE36F2265907599B0E60CB3A801B1CEB3C4DA8
              92AB48D69BB458F326110C5B268ADE97E5AE642B125CAC0071DE2453914DBA97
              7C08882E94E842CE22D5401C799BF7E66CF3807BF33F684050943C72CA17CE13
              2676A1EF661233826B7DE609CF0EAD569B3B419106EA2C4C77BB4C0691121844
              4A6010298141A4040691265214FF030C769EA3AE3398370000000049454E44AE
              426082}
          end>
      end
      item
        Name = 'libre-gui-bug'
        SourceImages = <
          item
            Image.Data = {
              89504E470D0A1A0A0000000D494844520000004900000049080600000071730B
              DC000000017352474200AECE1CE90000000467414D410000B18F0BFC61050000
              0A8A49444154785EED9B7F6C93C719C7EF5EFB75280B25143142A576A0AE6A50
              B53548FB03A4490D5201A71416446913D3AA8E9A00D9FE184CD55AFEA2F9672D
              FF0CD054419554645209B494D690B298508974AB4ABA6AE0AE6B93741B4DC318
              16BF4A134AC86BFB6ECFF3BEE7D7AFED37C6B1EF8C32E52339EFDDD97EFDBEDF
              F79EE7EE79EE4239E7649ADC68E2384D0EA645CA836991F2605AA43C9816290F
              0A1EDDD61E3F120489F7C3D787282543708C70CA3EF152BD2FE4AF1B121FBB23
              AC3E7EB8D2437835A1DA5242E9A384F04AB8D52AC279EBB1C79F7C597C2C6F8A
              16495433897242C3705147BB1E5F1F126D4A59DBFDEE52B897A7A158070F6DA1
              D59A41A9457AA2FB70BD46B483A23A219CF0EB60D521C6127B8EAFDE1011CD52
              A80B8716329E78118BF082DE921BCEC8F6AED5EB5F15D5BC297A32695E68C2A8
              B2BB3627702433C4DB19F05082F1D662C5C2DF4C70B683121E144D59C07DF5C1
              EDF5A10BA0712DD2B566FD80786BD2289971834FA8D6A8F61C1427E8FAA6582D
              20565434E4454D6FC78C593767BD02E7DC2A9A9CE0B942703B27649BB812919C
              A0AF208481495034091B34434EC9BAF7FD4FF68AA69C08D37A0F8AD5568B4D2F
              61899DC7563F151675E9281729C99AAE2355C44B5FCC34917CFCC4DAE36FFBB9
              A61DA484568826A49751DE9AAFC8C55032919208537C2FC30CF71DAB5DDF22CA
              69640D109CDC629435BE5FBBE19068514EC94542EA42A18A4459027A06F18B26
              B0C8446DA6C9E07C47D3687FAA07F101F0650DB247C9DB7147444AB2A6FBDDFD
              0EF38B26185BE274E66BBB8F9C82438D5523116DDCB33C545707538AD27247C3
              92D1BB465AE0192567E7951EAAED1265B2E64FEF6C81832510981808D8782704
              42EE684F429E08BF53A3718A3D4640978DDC35129935567ED136B30267CAB250
              DE93563CD3BCB426189C607249088E4E10C274882A0E77FEF25BE54B9D7E6864
              E68D9CA3DF630D4D29DFA6006522A1302B3736BF423939ED8BE93B44B32B302B
              FE231E2F5CB8403EFB7BE4977F3D7D7ACFF9E161F0E50C4DEDADDE9AE02DF383
              2EC06F04C1B977C3B1BBE6A9E06D43934250261208530F8797AC1A79097B9428
              67F1E9E099FE8F4F7F44CE9CF9940C0F7F33EFF2E54B3F8D7C76867CF8975364
              F8EB7F5F101FCBC2148593A41FF3FB742FC671D2512652CF813634A1D4448FF3
              FD1399DDA5C1E1DD57AF5C11B514374647C9E75F7EF91B3AC1F77CBABE1FE244
              D32CC1B30E197A7CBBF9866494FA242DE16984AB374724F031556E66473707AA
              E02FF63A57186755646622CBE7A099C1C16EE79437F676744C6896C5A054A4F0
              A17D43A0CE3651C5C7BD157A9333B4007D3C139AA18347C5D10662BF946971BE
              EF8337DB9585274A45B2E08F88023C6D1285A79D3ED7D1B87B822C8DB498CD04
              7A662A8340691EE7281CA5228149548332382934D1384BF5AAE2719ECBBF2AF0
              7C5A964126AA7BD22E47022E7CA2F30D69791E1818226866A20ACF42DB9B6B3E
              560CCA44124FD60E2BE0AFF491C788C75BE19034BBCADBCDC70A454958824F14
              2EF86B288AC91DDFDD73A03DCBD4167674CCB87EFE8B7D9AE6794EF378498C12
              32EEF5A08F21BA112765E273C6D858F89E453F69180A06B362B7151B9BB7C0D7
              F69A15781894684B4E74BE5E70AAD60D2522E14C1B0EC98964D4D0638B92C3F3
              43075FF78308BFE08CFA3353BB23DFDF20D16B57CDF2DCD91564EEDDB3CD7212
              B8D4287CA717AEF9E857814D763E6945A0E92CA53499B10C8329D68AB214A48B
              8443BCCFD02F267D11E7B423E6335A866A6A66949519DDF093130EF9B713C909
              5CF5005CFCBAC1C0A6819581A6974178DBD418E3B51F1C6C9796CE95EE93BC71
              6FB5C359C3B5F3208A36FFDCB9C3B9049A2C60625533FF7BB50D7A2D3C909440
              08C472526338E92259933ABE5B542D2074F08E8D3F266AD2D0BF1FFF391CD204
              811E7608CC5B6A6A57C9E8864EDA88C51680296F878B36936ADEF1B8F99E4C3C
              31FB9C38C2BD0A61D0A29307DA1A6487274A1C772698EF199F77F7D64BCB16AF
              124DAE4CC6272115FDE73F9FFDAF0BBFEBE97C43E9A2404944421E3EFC5A653C
              EEBB28AAAE4C562418D1960FD437295F52523DE3B6F962C3AF52B196245802F7
              19A8A7642221D069A56EC9D17D8674E1DD28A948301D907A532A7AA71B2511C9
              5FBF6521C672FA776359298F42D18CF8772B03CFD7AF0A6CAE124DCA50E6B831
              A74D39D9011317DC8A638A73EDE11F91D145F3CDF7DD988CE39E716D94CCFFB8
              DFAA60004D491FE56C8FCC4C4312753D8973DC0507719A2510E21D3744A9783C
              B762A2045833FC1A4EB4832AD2254A4442F3C29CB6A8E293C6510803D3B7AC86
              E2619C7F08078CCF527E09C482B0485AE893448948CC9348AEDF639810EAE96C
              9B0391F9F2EB55F7495B85BD79EF3DFB30DA87D702F8153B0CD298BD77401A4A
              4482C83F95B867049FB80946ECA2583C9CDAE702C76AFF060CA1598B06C5A2C6
              27516E3F4DAA39D6DE00E85952843262BA7D9E715FC2B1BE47722EAB17827491
              2C7F249269E08BCC5C743A458B0403727428985AFAC61518F077D6EF28F04B52
              45C22708FEC84AA5029CA6F722818C9E94B5890B3396A2482823BB30F927AA45
              234D2414C817D371E3A7BDAAAA716B238413F01F9F886211B89D83DABF85A95C
              DDF09E9225943491F4986ECD8B9270DEEA36B1A31A2B7A2B1F9873D639845937
              5A354B289FE1ED16D5A29026125CF84E311F3205EAE96C771DEEEFEFFADB66CD
              39112C807B7BCE3EEBD64B4028DCA46109851B5039C125A7A2911A96E08A2D9C
              CF7FB2B33D6BD3156E93F1E93AEEA2ADB9FCB307C9CDCA39D61B0EF2094B7C23
              37C9823FFF0334E00330616D701918CCCD148CF1A8ACC5809224DDCCE56E42B0
              EB9BF9E8911F2F20DF56DD87C534F211A9FC3F57C8DCC839AB622E7AB246D599
              49E953005738C711CF4AD8E38DC5F96B66B900C084FE609BB519B399CBDBD246
              3237948B84A31E78517BDEC235B23CFAE0032F40A9A0ACE2D8FD737EAF31CF12
              285A311B04D030AA4EDD5D25489951E6BC81E8C937DBFAAC89202DC05FF0C840
              FD962173DF937384C38D5E0A2981B9C59D37604F24C1171E15C5BC01F7E9F80E
              4F9D8B4CE1FD4908E35AEA0678EAC60CC387FF7635A9F4ABA6317B2B3367F41B
              5104B487444109CA45A294DB3700E3A87D63C2E4F21E9540D0309A9AA8C2B952
              825332D5CDCDB1554F73DC18A2EBE33BE176F35A6DA594ED1145130FF5A4565E
              A6F27640047A8FFD9439D5D2969470B58373CDDEAD3611708ED060C3E634479F
              B107A952E53440A94838FCDB6913C0D063693D09310C6F2B98528EF5387E5DA3
              09D7BD964E9353390D502A52E6F0EFB691C1DCBDC6C93A144334A5C349A3D317
              3981B024D5AE701AA04C24EC459C247E2DAA48562F4AF2D5C6E608F89C25F178
              C2FE4C82B12B2C41960D0636E55822724C03A8F6B42A93532212AEB9E931EF59
              70A8F6F664A04F1C5DC1DE7279CB0B8B2B7E50B1F087E5B31FF9B6E5B7F3FEF9
              4C73CEEFC09067E795C0ACEBC0E4FA55FCC792D400177B0F5C28EE3A4BEE974C
              12067FB44EF6BE216465A0696FC6C300EDCC2D88DB30AD2B9A8A427A4FC25489
              2842C50C441B7B0EB4D5AA1008E9E96C6FC13D9250B427A63037F3939BA92D89
              C52255241482528AFF748382848D786CB148842905F346D05317630F321B38DB
              D6FB7687BCCD14686EB25F2B024D987C737D4FF54BC56F9724E936D5513A4FFA
              7F615AA43C9816E9B610F23F3CD251B86388BFA10000000049454E44AE426082}
          end>
      end>
    Left = 305
    Top = 199
  end
  object VirtualImageList1: TVirtualImageList
    Images = <
      item
        CollectionIndex = 0
        CollectionName = 'libre-gui-idea'
        Name = 'libre-gui-idea'
      end
      item
        CollectionIndex = 1
        CollectionName = 'libre-gui-font'
        Name = 'libre-gui-font'
      end
      item
        CollectionIndex = 2
        CollectionName = 'libre-gui-firewall'
        Name = 'libre-gui-firewall'
      end
      item
        CollectionIndex = 3
        CollectionName = 'libre-gui-bug'
        Name = 'libre-gui-bug'
      end>
    ImageCollection = ImageCollection1
    Left = 193
    Top = 151
  end
  object FontDialog1: TFontDialog
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -12
    Font.Name = 'Segoe UI'
    Font.Style = []
    Options = [fdFixedPitchOnly]
    Left = 273
    Top = 159
  end
end
