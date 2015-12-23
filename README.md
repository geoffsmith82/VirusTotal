# VirusTotal

VirusTotal - класс для работы с одноименным сервисом для проверки файлов на вирусы.

Как работать
---------------
1. Скачайте файл VirusTotal.pas
2. Добавьте файл VirusTotal.pas в ваш проект.
3. Теперь вы можете работать с сервисом https://www.virustotal.com.

*Note:* Для работы необходима библиотека https://github.com/onryldz/x-superobject
*Note:* Разрабатывается в Delphi X - работа в более ранних версиях не гарантируется.

**Example**
    Var
    VT: TVirusTotalAPI;
    ResultScan: TvtURLReport;
    begin
      VT := TVirusTotalAPI.Create;
      try
        { TODO -oUser -cConsole Main : Insert code here }
        ResultScan := VT.reportURL('https://codmasters.ru/');
        Writeln('Opera: ', ResultScan.scans.Opera.result);
      except
          on E: Exception do
            Writeln(E.ClassName, ': ', E.Message);
      end;
  VT.Free;
  Readln;
end.
  
