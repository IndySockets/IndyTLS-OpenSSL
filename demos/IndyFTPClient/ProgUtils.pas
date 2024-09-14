unit ProgUtils;

interface
uses Vcl.ComCtrls;

procedure ScrollToTop(ARichEdit: TRichEdit);
procedure ScrollToEnd(ARichEdit: TRichEdit);

implementation
uses WinAPI.Messages;

procedure ScrollToEnd(ARichEdit: TRichEdit);
var
  isSelectionHidden: Boolean;
begin
  with ARichEdit do
  begin
    SelStart := Perform(WinAPI.Messages.EM_LINEINDEX, Lines.Count, 0);//Set caret at end
    isSelectionHidden := HideSelection;
    try
      HideSelection := False;
      Perform(WinAPI.Messages.EM_SCROLLCARET, 0, 0);  // Scroll to caret
    finally
      HideSelection := isSelectionHidden;
    end;
  end;
end;

procedure ScrollToTop(ARichEdit: TRichEdit);
var
  isSelectionHidden: Boolean;
begin
  with ARichEdit do
  begin
    SelStart := Perform(WinAPI.Messages.EM_LINEINDEX, 0, 0);//Set caret at end
    isSelectionHidden := HideSelection;
    try
      HideSelection := False;
      Perform(WinAPI.Messages.EM_SCROLLCARET, 0, 0);  // Scroll to caret
    finally
      HideSelection := isSelectionHidden;
    end;
  end;
end;

end.
