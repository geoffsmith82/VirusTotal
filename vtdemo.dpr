program vtdemo;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  System.SysUtils,
  vcl.forms,
  System.Generics.Collections,
  VirusTotal in 'VirusTotal.pas',
  config in 'config.pas';

Var
  VT: TVirusTotalAPI;
  i : Integer;
  j : Integer;
  ResultScan: TObjectList<TvtURLReport>;
  urls : TArray<String>;
  fileResult : TvtFileSend;
begin
  VT := TVirusTotalAPI.Create;
  VT.ApiKey := ConfigAPIKey;
  try
  try
    setlength(urls, 2);
    urls[0] := 'https://codmasters.ru/';
    urls[1] := 'https://www.tysontechnology.com.au';
    ResultScan := VT.reportURL(urls, True);
    for i := 0 to length(urls) - 1 do
    begin
      for j := 0 to ResultScan[i].scans.Count - 1 do
      begin
        Writeln(ResultScan[i].scans[j].scanner);
        Writeln(ResultScan[i].scans[j].detected);
        Writeln(ResultScan[i].scans[j].result);
      end;
    end;
    fileResult := VT.ScanFile('vtdemo.exe');


    Writeln('sha256: ', fileResult.sha256);
    Writeln('permalink:'+ fileResult.permalink);
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  finally
    FreeAndNil(VT);
  end;
  Readln;
end.
