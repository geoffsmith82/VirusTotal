unit VirusTotal;

interface

uses System.Generics.Collections,
  system.json;

type
  TvtFileSend = class
    verbose_msg, resource, scan_id, permalink, sha256, sha1, md5: String;
  end;

  TvtURLSend = class
  public
    verbose_msg, resource, url, scan_id, permalink: String;
    scan_date: String;
  end;

  TvtAntiVirusItemFile = class
    scanner : string;
    detected: Boolean;
    version, result, update: String;
  end;

  TvtAntiVirusItemURL = class
    scanner : string;
    detected: Boolean;
    result: String;
  end;

  TvtFileReport = class
  private
    procedure handleFileScans(inScans: TJsonObject);
  public
    scan_id, sha1, resource, scan_date, permalink, verbose_msg, sha256, md5: String;
    response_code, total, positives: Integer;
    scans: TObjectList<TvtAntiVirusItemFile>;
    constructor Create;
    destructor Destroy; override;
  end;

  TvtIPreport = Packed Record
  Public
    verbose_msg, resource, url, scan_id, scan_date, permalink, filescan_id: String;
    response_code, total, positives: Integer;
    scans: array of TvtAntiVirusItemURL;
  End;

  TvtURLReport = class
  private
    procedure handleURLScans(inScans : TJsonObject);
  public
    verbose_msg, resource, url, scan_id, scan_date, permalink, filescan_id: String;
    response_code, total, positives: Integer;
    scans: TObjectList<TvtAntiVirusItemURL>;
    constructor Create;
    destructor Destroy; override;
  end;
{$M+}

  TVirusTotalAPI = class
  strict private
  const
    SERVER = 'https://www.virustotal.com/vtapi/v2/';
  private
    FApiKey: string;
  public
    function ScanFile(const FileName: string): TvtFileSend;
    function RescanFile(const Hash: string): TvtFileSend; overload;
    function RescanFile(const Hash: TArray<string>): TObjectList<TvtFileSend>; overload;
    function reportFile(const Hash: TArray<string>): TObjectList<TvtFileReport>; overload;
    function reportFile(const Hash: string): TvtFileReport; overload;
    function scanURL(const URLs: TArray<string>): TObjectList<TvtURLSend>; overload;
    function scanURL(const url: string): TvtURLSend; overload;
    function reportURL(const url: string; scan: Boolean = False): TvtURLReport; overload;
    function reportURL(const URLs: TArray<string>; scan: Boolean = False): TObjectList<TvtURLReport>; overload;
//    function reportIpAddress(Const IP: String): TArray<TvtURLReport>; overload;
    constructor Create;
    destructor Destroy; override;
  published
    property ApiKey: string read FApiKey write FApiKey;
  end;

implementation

uses
  System.SysUtils,
  System.Net.HttpClient,
  System.Net.Mime;
{ TVirusTotalAPI }

constructor TVirusTotalAPI.Create;
begin
  ApiKey := 'e2fd0cd961bdeaf2d054871299a6c2f056d7a5dbda813b93000a81a64087b341';
end;

destructor TVirusTotalAPI.Destroy;
begin
  inherited;
end;

procedure TvtFileReport.handleFileScans(inScans: TJsonObject);
var
  i : Integer;
  scanItem : TvtAntiVirusItemFile;
  scanner : TJsonObject;
begin
  for i := 0 to scans.Count-1 do
  begin
    scanner := inScans.Pairs[i].JsonValue as TJSONObject;
    scanItem := TvtAntiVirusItemFile.Create;
    scanItem.scanner := inScans.Pairs[i].JsonString.Value;
    if((scanner.Values['detected'] as TJSONBool).AsBoolean) then
    begin
      scanItem.detected := True;
    end
    else
    begin
      scanItem.detected := false;
    end;
    scanItem.result := scanner.Values['result'].Value;

    scans.Add(scanItem);
  end;
end;

procedure TvtURLReport.handleURLScans(inScans : TJsonObject);
var
  i: Integer;
  scanner : TJsonObject;
  scanItem : TvtAntiVirusItemURL;
begin
  for i := 0 to inScans.Count-1 do
  begin
    scanner := inScans.Pairs[i].JsonValue as TJSONObject;
    scanItem := TvtAntiVirusItemURL.Create;
    scanItem.scanner := inScans.Pairs[i].JsonString.Value;
    if((scanner.Values['detected'] as TJSONBool).AsBoolean) then
    begin
      scanItem.detected := True;
    end
    else
    begin
      scanItem.detected := false;
    end;
    scanItem.result := scanner.Values['result'].Value;

    scans.Add(scanItem);
  end;
end;


function TVirusTotalAPI.reportFile(const Hash: String): TvtFileReport;
begin
  result := reportFile([Hash])[0];
end;

function TVirusTotalAPI.reportURL(const url: String; scan: Boolean): TvtURLReport;
begin
  result := reportURL([url], scan)[0];
end;

function TVirusTotalAPI.reportURL(const URLs: TArray<string>; scan: Boolean): TObjectList<TvtURLReport>;
const
  API = 'url/report';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  requestResult : string;
  I             : Integer;
  jsonx         : TJSonArray;
  jsonsingle    : TJSONObject;
  jsonval       : TJSONValue;
  item          : TJsonObject;
  itemReport    : TvtURLReport;
  scans         : TJsonObject;
begin
  HTTP := nil;
  Part := nil;
  Result := nil;
  try
    Result := TObjectList<TvtURLReport>.Create;
    HTTP := THTTPClient.Create;
    Part := TMultipartFormData.Create;
    Part.AddField('resource', string.Join(#13#10, URLs));
    if scan then
    begin
      Part.AddField('scan', '1');
    end;
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.ASCII);

    jsonval := TJSONObject.ParseJSONValue(requestResult);


    if Length(URLs) > 1 then
    begin
      jsonx := jsonval as TJSONArray;
      for I := 0 to jsonx.Count - 1 do
      begin
        item  := jsonx.Items[i] as TJSONObject;
        itemReport := TvtURLReport.Create;
        itemReport.verbose_msg   := item.Values['verbose_msg'].Value;
        itemReport.resource      := item.Values['resource'].Value;
        itemReport.url           := item.Values['url'].Value;
        itemReport.scan_id       := item.Values['scan_id'].Value;
        itemReport.scan_date     := item.Values['scan_date'].Value;
        itemReport.permalink     := item.Values['permalink'].Value;
        itemReport.filescan_id   := item.Values['filescan_id'].Value;
        itemReport.response_code := StrToInt(item.Values['response_code'].Value);
        itemReport.total         := StrToInt(item.Values['total'].Value);
        itemReport.positives     := StrToInt(item.Values['positives'].Value);
        scans := (item.Values['scans'] as TJsonObject);
        itemReport.handleURLScans(scans);
        Result.Add(itemReport);
      end;
    end
    else
      begin
        jsonsingle := jsonval as TJSONObject;
        itemReport := TvtURLReport.Create;
        itemReport.scan_id       := jsonsingle.Values['scan_id'].Value;
        itemReport.verbose_msg   := jsonsingle.Values['verbose_msg'].Value;
        itemReport.resource      := jsonsingle.Values['resource'].Value;
        itemReport.url           := jsonsingle.Values['url'].Value;
        itemReport.scan_date     := jsonsingle.Values['scan_date'].Value;
        itemReport.permalink     := jsonsingle.Values['permalink'].Value;
        itemReport.filescan_id   := jsonsingle.Values['filescan_id'].Value;
        itemReport.response_code := StrToInt(jsonsingle.Values['response_code'].Value);
        itemReport.total         := StrToInt(jsonsingle.Values['total'].Value);
        itemReport.positives     := StrToInt(jsonsingle.Values['positives'].Value);
        scans := (jsonsingle.Values['scans'] as TJsonObject);
        itemReport.handleURLScans(scans);
        Result.Add(itemReport);
      end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

function TVirusTotalAPI.reportFile(const Hash: TArray<String>): TObjectList<TvtFileReport>;
Const
  API = 'file/report';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  requestResult : String;
  I             : Integer;
  jsonx         : TJSonArray;
  jsoninitial   : TJSONValue;
  jsonsingle    : TJSONObject;
  item          : TJsonObject;
  scans         : TJsonObject;
  itemReport    : TvtFileReport;
begin
  HTTP := nil;
  Part := nil;
  try
    Result := TObjectList<TvtFileReport>.Create;
    HTTP := THTTPClient.Create;
    Part := TMultipartFormData.Create;
    Part.AddField('resource', String.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsoninitial := TJSONObject.ParseJSONValue(requestResult);


    if Length(Hash) > 1 then
    begin
      jsonx := jsoninitial as TJSONArray;
      for I := 0 to (jsonx as TJSonArray).Count - 1 do
      begin
        item  := (jsonx.Items[i] as TJSONOBject);
        itemReport := TvtFileReport.Create;
        itemReport.scan_id       := item.Values['scan_id'].Value;
        itemReport.sha1          := item.Values['sha1'].Value;
        itemReport.resource      := item.Values['resource'].Value;
        itemReport.scan_date     := item.Values['scan_date'].Value;
        itemReport.permalink     := item.Values['permalink'].Value;
        itemReport.verbose_msg   := item.Values['verbose_msg'].Value;
        itemReport.sha256        := item.Values['sha256'].Value;
        itemReport.md5           := item.Values['md5'].Value;
        itemReport.response_code := StrToInt(item.Values['response_code'].Value);
        itemReport.total         := StrToInt(item.Values['total'].Value);
        itemReport.positives     := StrToInt(item.Values['positives'].Value);
        scans := (item.Values['scans'] as TJsonObject);
        itemReport.handleFileScans(scans);
        Result.Add(itemReport);
      end;
    end
    else
    begin
      jsonsingle := jsoninitial as TJSONObject;
      itemReport := TvtFileReport.Create;
      itemReport.scan_id       := jsonsingle.Values['scan_id'].Value;
      itemReport.sha1          := jsonsingle.Values['sha1'].Value;
      itemReport.resource      := jsonsingle.Values['resource'].Value;
      itemReport.scan_date     := jsonsingle.Values['scan_date'].Value;
      itemReport.permalink     := jsonsingle.Values['permalink'].Value;
      itemReport.verbose_msg   := jsonsingle.Values['verbose_msg'].Value;
      itemReport.sha256        := jsonsingle.Values['sha256'].Value;
      itemReport.md5           := jsonsingle.Values['md5'].Value;
      itemReport.response_code := StrToInt(jsonsingle.Values['response_code'].Value);
      itemReport.total         := StrToInt(jsonsingle.Values['total'].Value);
      itemReport.positives     := StrToInt(jsonsingle.Values['positives'].Value);
      scans := (jsonsingle.Values['scans'] as TJsonObject);
      itemReport.handleFileScans(scans);
      Result.Add(itemReport)
    end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsoninitial);
  end;
end;

function TVirusTotalAPI.RescanFile(const Hash: TArray<String>): TObjectList<TvtFileSend>;
const
  API = 'file/rescan';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  I             : Integer;
  requestResult : String;
  jsonx         : TJSonArray;
  item          : TJsonObject;
  ItemFile      : TvtFileSend;
begin
  HTTP := nil;
  Part := nil;
  try
    Result := TObjectList<TvtFileSend>.Create;
    HTTP := THTTPClient.Create;
    Part := TMultipartFormData.Create;
    Part.AddField('resource', String.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := (TJSONObject.ParseJSONValue(requestResult) as TJSONArray);

    for I := 0 to jsonx.Count - 1 do
    begin
      item  := jsonx.Items[i] as TJSONOBject;
      ItemFile := TvtFileSend.Create;
      ItemFile.verbose_msg := item.Values['verbose_msg'].Value;
      ItemFile.resource    := item.Values['resource'].Value;
      ItemFile.scan_id     := item.Values['scan_id'].Value;
      ItemFile.permalink   := item.Values['permalink'].Value;
      ItemFile.sha256      := item.Values['sha256'].Value;
      ItemFile.sha1        := item.Values['sha1'].Value;
      ItemFile.md5         := item.Values['md5'].Value;
      Result.Add(ItemFile);
    end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

function TVirusTotalAPI.RescanFile(const Hash: String): TvtFileSend;
begin
  result := RescanFile([Hash])[0];
end;

Function TVirusTotalAPI.ScanFile(const FileName: String): TvtFileSend;
Const
  API = 'file/scan';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  requestResult : String;
  jsonx         : TJSONObject;
begin
  HTTP  := nil;
  Part  := nil;
  jsonx := nil;
  Result := TvtFileSend.Create;
  try
    HTTP  := THTTPClient.Create;
    Part  := TMultipartFormData.Create;
    jsonx := TJSONObject.Create;
    Part.AddFile('file', FileName);
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := TJSONObject.ParseJSONValue(requestResult) as TJSONObject;
    Result.verbose_msg := jsonx.Values['verbose_msg'].Value;
    Result.resource    := jsonx.Values['resource'].Value;
    Result.scan_id     := jsonx.Values['scan_id'].Value;
    Result.permalink   := jsonx.Values['permalink'].Value;
    Result.sha256      := jsonx.Values['sha256'].Value;
    Result.sha1        := jsonx.Values['sha1'].Value;
    Result.md5         := jsonx.Values['md5'].Value;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

function TVirusTotalAPI.scanURL(const url: String): TvtURLSend;
begin
  result := scanURL([url])[0];
end;

function TVirusTotalAPI.scanURL(const URLs: TArray<String>): TObjectList<TvtURLSend>;
Const
  API = 'url/scan';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  I             : Integer;
  requestResult : String;
  jsonX         : TJSonObject;
  item          : TJSONObject;
  URLReport     : TvtURLSend;
begin
  HTTP := nil;
  Part := nil;
  try
    Result := TObjectList<TvtURLSend>.Create;
    HTTP := THTTPClient.Create;
    Part := TMultipartFormData.Create;
    Part.AddField('url', String.Join(#13#10, URLs));
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := jsonx.ParseJSONValue(requestResult) as TJSONObject;

    if Length(URLs) > 1 then
    begin
      for I := 0 to TJSONOBject(system.JSON.TJSonArray(jsonx)).Count-1 do
      begin
        item := TJSONObject(system.JSON.TJSonArray(jsonx).Items[i]);
        URLReport := TvtURLSend.Create;
        URLReport.verbose_msg := item.Values['verbose_msg'].Value;
        URLReport.resource    := item.Values['resource'].Value;
        URLReport.url         := item.Values['url'].Value;
        URLReport.scan_id     := item.Values['scan_id'].Value;
        URLReport.permalink   := item.Values['permalink'].Value;
        URLReport.scan_date   := item.Values['scan_date'].Value;
        Result.Add(URLReport);
      end;
    end
    else
    begin
      URLReport := TvtURLSend.Create;
      URLReport.verbose_msg := jsonx.Values['verbose_msg'].Value;
      URLReport.resource    := jsonx.Values['resource'].Value;
      URLReport.url         := jsonx.Values['url'].Value;
      URLReport.scan_id     := jsonx.Values['scan_id'].Value;
      URLReport.permalink   := jsonx.Values['permalink'].Value;
      URLReport.scan_date   := jsonx.Values['scan_date'].Value;
      Result.Add(URLReport);
    end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

{ TvtURLReport }

constructor TvtURLReport.Create;
begin
  scans := TObjectList<TvtAntiVirusItemURL>.Create;
end;

destructor TvtURLReport.Destroy;
begin
  FreeAndNil(scans);
  inherited;
end;

{ TvtFileReport }

constructor TvtFileReport.Create;
begin
  scans := TObjectList<TvtAntiVirusItemFile>.Create;
end;

destructor TvtFileReport.Destroy;
begin
  FreeAndNil(scans);
  inherited;
end;

end.
