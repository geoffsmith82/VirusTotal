program vtdemo;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  System.SysUtils,vcl.forms,
  VirusTotal in 'VirusTotal.pas';

Var
  VT: TVirusTotalAPI;
//  i : Integer;
//  ResultScan: TArray<TvtURLReport>;
//  ResultScan : TArray<TvtURLSend>;
  urls : TArray<String>;
  fileResult : TvtFileSend;
begin
  VT := TVirusTotalAPI.Create;
  try
    { TODO -oUser -cConsole Main : Insert code here }
    setlength(urls,1);
    urls[0] := 'https://codmasters.ru/';
//    urls[1] := 'https://www.tysontechnology.com.au';
{    ResultScan := VT.reportURL(urls,False);
    for i := 0 to length(resultscan)-1 do
      begin
        Writeln('Opera: ', ResultScan[i].permalink);
      end;}
   fileResult := VT.ScanFile('C:\Programming\ZXing.Delphi\aTestApp\Win32\Debug\aTestApp.exe');


//    Writeln('Opera: ', ResultScan.scans.Opera.result);
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  FreeAndNil(VT);
  Readln;
end.
