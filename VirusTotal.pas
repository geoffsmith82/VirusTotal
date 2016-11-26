unit VirusTotal;

interface

uses system.json;

{ TODO -oOwner -cGeneral : Преобразовать время: Строка=>TDateTime }
Type
  TvtFileSend = record
    verbose_msg, resource, scan_id, permalink, sha256, sha1, md5: String;
  End;

  TvtURLSend = record//Packed Record
  Public
    verbose_msg, resource, url, scan_id, permalink: String;
    scan_date: String;
  End;

  TvtAntiVirusItemFile = record
    detected: Boolean;
    version, result, update: String;
  End;

  TvtAntiVirusItemURL = record
    detected: Boolean;
    result: String;
  End;

  TvtAVItemsURL = record
  public
    Opera, TrendMicro, Phishtank, BitDefender, MalwareDomainList, ParetoLogic,
      Avira, Wepawet: TvtAntiVirusItemURL;
    [ALIAS('Dr.Web')]
    drWeb: TvtAntiVirusItemURL;
    [ALIAS('Malc0de Database')]
    Malc0deDatabase: TvtAntiVirusItemURL;
    [ALIAS('G-Data')]
    G_Data: TvtAntiVirusItemURL;
    [ALIAS('Websense ThreatSeeker')]
    WebsenseThreatSeeker: TvtAntiVirusItemURL;
    CLEANMX,
    Rising,
    OpenPhish,
    VXVault,
    ZDBZeus,
    AutoShun,
    ZCloudsec,
    PhishLabs,
    Zerofox,
    K7AntiVirus,
    SecureBrain,
    Quttera,
    AegisLabWebGuard,
    ZeusTracker,
    zvelo,
    GoogleSafebrowsing,
    FraudScore,
    Kaspersky,
    Certly,
    CSIRT,
    CyberCrime,
    MalwarePatrol,
    Webutation,
    Trustwave,
    WebSecurityGuard,
    desenmascarame,
    ADMINUSLabs,
    MalwarebyteshpHosts,
    AlienVault,
    Emsisoft,
    SpyEyeTracker,
    malwarescomURLchecker,
    Malwared,
    StopBadware,
    AntiyAVL,
    SCUMWAREorg,
    FraudSense,
    ComodoSiteInspector,
    Malekal,
    ESET,
    Sophos,
    YandexSafebrowsing,
    Spam404,
    Nucleon,
    MalwareDomainBlocklist,
    Blueliv,
    Netcraft,
    PalevoTracker,
    CRDF,
    ThreatHive,
    Tencent,
    URLQuery,
    SucuriSiteCheck,
    Fortinet,
    ZeroCERT,
    BaiduInternational,
    securolytics :TvtAntiVirusItemURL;

  End;

  TvtAVItemsFile = record
  public
    AVG, AVware, AegisLab, Agnitum, Alibaba, Arcabit, Avast, Avira, BitDefender,
      Bkav, ByteHero, CMC, ClamAV, Comodo, Cyren, Emsisoft, Fortinet, GData,
      Ikarus, Jiangmin, K7AntiVirus, K7GW, Kaspersky, Malwarebytes, McAfee,
      Microsoft, Panda, Rising, SUPERAntiSpyware, Sophos, Symantec, Tencent,
      TheHacker, TotalDefense, TrendMicro, VBA32, VIPRE, ViRobot, Zillya, Zoner,
      nProtect: TvtAntiVirusItemFile;
    [ALIAS('Ad-Aware')]
    Ad_Aware: TvtAntiVirusItemFile;
    [ALIAS('AhnLab-V3')]
    AhnLab_V3: TvtAntiVirusItemFile;
    [ALIAS('Antiy-AVL')]
    Antiy_AVL: TvtAntiVirusItemFile;
    [ALIAS('Baidu-International')]
    Baidu_International: TvtAntiVirusItemFile;
    [ALIAS('CAT-QuickHeal')]
    CAT_QuickHeal: TvtAntiVirusItemFile;
    [ALIAS('ESET-NOD32')]
    ESET_NOD32: TvtAntiVirusItemFile;
    [ALIAS('F-Prot')]
    F_Prot: TvtAntiVirusItemFile;
    [ALIAS('F-Secure')]
    F_Secure: TvtAntiVirusItemFile;
    [ALIAS('McAfee-GW-Edition')]
    McAfee_GW_Edition: TvtAntiVirusItemFile;
    [ALIAS('MicroWorld-eScan')]
    MicroWorld_eScan: TvtAntiVirusItemFile;
    [ALIAS('NANO-Antivirus')]
    NANO_Antivirus: TvtAntiVirusItemFile;
    [ALIAS('TrendMicro-HouseCall')]
    TrendMicro_HouseCall: TvtAntiVirusItemFile;
  End;

  TvtFileReport = record
    scan_id, sha1, resource, scan_date, permalink, verbose_msg, sha256,
      md5: String;
    response_code, total, positives: Integer;
    scans: TvtAVItemsFile;
  End;

  TvtIPreport = Packed Record
  Public
    verbose_msg, resource, url, scan_id, scan_date, permalink,
      filescan_id: String;
    response_code, total, positives: Integer;
    scans: TvtAVItemsURL;
  End;

  TvtURLReport = record
    verbose_msg, resource, url, scan_id, scan_date, permalink,
      filescan_id: String;
    response_code, total, positives: Integer;
    scans: TvtAVItemsURL;
  End;
{$M+}

  TVirusTotalAPI = class
  strict private
  const
    SERVER = 'https://www.virustotal.com/vtapi/v2/';
  private
    FApiKey: string;
    function handleURLScans(scans : TJsonObject):TvtAVItemsURL;
    function handleFileScans(scans : TJsonObject):TvtAVItemsFile;
  public
    function ScanFile(const FileName: string): TvtFileSend;
    function RescanFile(const Hash: string): TvtFileSend; overload;
    function RescanFile(const Hash: TArray<string>): TArray<TvtFileSend>; overload;
    function reportFile(const Hash: TArray<string>): TArray<TvtFileReport>; overload;
    function reportFile(const Hash: string): TvtFileReport; overload;
    function scanURL(const URLs: TArray<string>): TArray<TvtURLSend>; overload;
    function scanURL(const url: string): TvtURLSend; overload;
    function reportURL(const url: string; scan: Boolean = False): TvtURLReport; overload;
    function reportURL(const URLs: TArray<string>; scan: Boolean = False): TArray<TvtURLReport>; overload;
//    function reportIpAddress(Const IP: String): TArray<TvtURLReport>; overload;
    constructor Create;
    destructor Destroy; override;
  published
    property ApiKey: string read FApiKey write FApiKey;
  End;

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

procedure handleURLScanner(actual:String;scannerName:String;var scanner:TvtAntiVirusItemUrL;source:TJSonObject);
begin
if(actual=scannerName) then
 begin
  if(source.Values['detected'].Value='true') then
    begin
      scanner.detected := True;
    end
  else
    begin
      scanner.detected := false;
    end;
  scanner.result := source.Values['result'].Value;
 end;
end;

function TVirusTotalAPI.handleFileScans(scans : TJsonObject):TvtAVItemsFile;
var
  arr : TJsonArray;
  i: Integer;
  scanner : TJsonObject;
  scannerName : String;
begin


end;

function TVirusTotalAPI.handleURLScans(scans : TJsonObject):TvtAVItemsURL;
var
  arr : TJsonArray;
  i: Integer;
  scanner : TJsonObject;
  scannerName : String;
begin
  arr := TJsonArray(scans);
  for i := 0 to arr.Count-1 do
     begin
       scannerName := TJsonPair(arr.Items[i]).JsonString.Value;
       scanner := TJSONObject(TJsonPair(arr.Items[i]).JsonValue);
       handleURLScanner(scannerName,'CLEAN MX',result.CLEANMX,scanner);
       handleURLScanner(scannerName,'Rising',result.Rising,scanner);
       handleURLScanner(scannerName,'OpenPhish',result.OpenPhish,scanner);
       handleURLScanner(scannerName,'VX Vault',result.VXVault,scanner);
       handleURLScanner(scannerName,'ZDB Zeus',result.ZDBZeus,scanner);
       handleURLScanner(scannerName,'AutoShun',result.AutoShun,scanner);
       handleURLScanner(scannerName,'ZCloudsec',result.ZCloudsec,scanner);
       handleURLScanner(scannerName,'PhishLabs',result.PhishLabs,scanner);
       handleURLScanner(scannerName,'Zerofox',result.Zerofox,scanner);
       handleURLScanner(scannerName,'K7AntiVirus',result.K7AntiVirus,scanner);
       handleURLScanner(scannerName,'SecureBrain',result.SecureBrain,scanner);
       handleURLScanner(scannerName,'Quttera',result.Quttera,scanner);
       handleURLScanner(scannerName,'AegisLab WebGuard',result.AegisLabWebGuard,scanner);
       handleURLScanner(scannerName,'MalwareDomainList',result.MalwareDomainList,scanner);
       handleURLScanner(scannerName,'ZeusTracker',result.ZeusTracker,scanner);
       handleURLScanner(scannerName,'zvelo',result.zvelo,scanner);
       handleURLScanner(scannerName,'Google Safebrowsing',result.GoogleSafebrowsing,scanner);
       handleURLScanner(scannerName,'FraudScore',result.FraudScore,scanner);
       handleURLScanner(scannerName,'Kaspersky',result.Kaspersky,scanner);
       handleURLScanner(scannerName,'BitDefender',result.BitDefender,scanner);
       handleURLScanner(scannerName,'Wepawet',result.Wepawet,scanner);
       handleURLScanner(scannerName,'Certly',result.Certly,scanner);
       handleURLScanner(scannerName,'G-Data',result.G_Data,scanner);
       handleURLScanner(scannerName,'C-SIRT',result.CSIRT,scanner);
       handleURLScanner(scannerName,'CyberCrime',result.CyberCrime,scanner);
       handleURLScanner(scannerName,'Websense ThreatSeeker',result.WebsenseThreatSeeker,scanner);
       handleURLScanner(scannerName,'MalwarePatrol',result.MalwarePatrol,scanner);
       handleURLScanner(scannerName,'Webutation',result.Webutation,scanner);
       handleURLScanner(scannerName,'Trustwave',result.Trustwave,scanner);
       handleURLScanner(scannerName,'Web Security Guard',result.WebSecurityGuard,scanner);
       handleURLScanner(scannerName,'desenmascara.me',result.desenmascarame,scanner);
       handleURLScanner(scannerName,'ADMINUSLabs',result.ADMINUSLabs,scanner);
       handleURLScanner(scannerName,'Malwarebytes hpHosts',result.MalwarebyteshpHosts,scanner);
       handleURLScanner(scannerName,'Dr.Web',result.DrWeb,scanner);
       handleURLScanner(scannerName,'AlienVault',result.AlienVault,scanner);
       handleURLScanner(scannerName,'Emsisoft',result.Emsisoft,scanner);
       handleURLScanner(scannerName,'Malc0de Database',result.Malc0deDatabase,scanner);
       handleURLScanner(scannerName,'SpyEyeTracker',result.SpyEyeTracker,scanner);
       handleURLScanner(scannerName,'malwares.com URL checker',result.malwarescomURLchecker,scanner);
       handleURLScanner(scannerName,'Phishtank',result.Phishtank,scanner);
       handleURLScanner(scannerName,'Malwared',result.Malwared,scanner);
       handleURLScanner(scannerName,'Avira',result.Avira,scanner);
       handleURLScanner(scannerName,'StopBadware',result.StopBadware,scanner);
       handleURLScanner(scannerName,'Antiy-AVL',result.AntiyAVL,scanner);
       handleURLScanner(scannerName,'SCUMWARE.org',result.SCUMWAREorg,scanner);
       handleURLScanner(scannerName,'FraudSense',result.FraudSense,scanner);
       handleURLScanner(scannerName,'Opera',result.Opera,scanner);
       handleURLScanner(scannerName,'Comodo Site Inspector',result.ComodoSiteInspector,scanner);
       handleURLScanner(scannerName,'Malekal',result.Malekal,scanner);
       handleURLScanner(scannerName,'ESET',result.ESET,scanner);
       handleURLScanner(scannerName,'Sophos',result.Sophos,scanner);
       handleURLScanner(scannerName,'Yandex Safebrowsing',result.YandexSafebrowsing,scanner);
       handleURLScanner(scannerName,'Spam404',result.Spam404,scanner);
       handleURLScanner(scannerName,'Nucleon',result.Nucleon,scanner);
       handleURLScanner(scannerName,'Malware Domain Blocklist',result.MalwareDomainBlocklist,scanner);
       handleURLScanner(scannerName,'Blueliv',result.Blueliv,scanner);
       handleURLScanner(scannerName,'Netcraft',result.Netcraft,scanner);
       handleURLScanner(scannerName,'PalevoTracker',result.PalevoTracker,scanner);
       handleURLScanner(scannerName,'CRDF',result.CRDF,scanner);
       handleURLScanner(scannerName,'ThreatHive',result.ThreatHive,scanner);
       handleURLScanner(scannerName,'ParetoLogic',result.ParetoLogic,scanner);
       handleURLScanner(scannerName,'Tencent',result.Tencent,scanner);
       handleURLScanner(scannerName,'URLQuery',result.URLQuery,scanner);
       handleURLScanner(scannerName,'Sucuri SiteCheck',result.SucuriSiteCheck,scanner);
       handleURLScanner(scannerName,'Fortinet',result.Fortinet,scanner);
       handleURLScanner(scannerName,'ZeroCERT',result.ZeroCERT,scanner);
       handleURLScanner(scannerName,'Baidu-International',result.BaiduInternational,scanner);
       handleURLScanner(scannerName,'securolytics',result.securolytics,scanner);
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



function TVirusTotalAPI.reportURL(const URLs: TArray<String>; scan: Boolean): TArray<TvtURLReport>;
Const
  API = 'url/report';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  requestResult : String;
  I             : Integer;
  jsonx         : TJSonObject;
  item          : TJsonObject;
  scans         : TJsonObject;
begin
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', String.Join(#13#10, URLs));
    if scan then
      begin
       Part.AddField('scan', '1');
      end;
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := TJSONObject(jsonx.ParseJSONValue(requestResult));

    SetLength(result, system.JSON.TJSonArray(jsonx).Count);
    if Length(URLs) > 1 then
      begin
      for I := 0 to system.JSON.TJSonArray(jsonx).Count - 1 do
       begin
        item  := TJSONObject(system.JSON.TJSonArray(jsonx).Items[i].Value);
        result[I].verbose_msg   := item.Values['verbose_msg'].Value;
        result[i].resource      := item.Values['resource'].Value;
        result[i].url           := item.Values['url'].Value;
        result[i].scan_id       := item.Values['scan_id'].Value;
        result[i].scan_date     := item.Values['scan_date'].Value;
        result[i].permalink     := item.Values['permalink'].Value;
        result[i].filescan_id   := item.Values['filescan_id'].Value;
        result[i].response_code := StrToInt(item.Values['response_code'].Value);
        result[i].total         := StrToInt(item.Values['total'].Value);
        result[i].positives     := StrToInt(item.Values['positives'].Value);
        scans := TJsonObject(item.Values['scans']);
        Result[0].scans := handleURLScans(scans);
       end;
      end
    else
      begin
        result[0].scan_id       := jsonx.Values['scan_id'].Value;
        result[0].verbose_msg   := TJsonObject(jsonx.Values['verbose_msg']).Value;
        result[0].resource      := jsonx.Values['resource'].Value;
        result[0].url           := jsonx.Values['url'].Value;
        result[0].scan_date     := jsonx.Values['scan_date'].Value;
        result[0].permalink     := jsonx.Values['permalink'].Value;
        result[0].filescan_id   := jsonx.Values['filescan_id'].Value;
        result[0].response_code := StrToInt(jsonx.Values['response_code'].Value);
        result[0].total         := StrToInt(jsonx.Values['total'].Value);
        result[0].positives     := StrToInt(jsonx.Values['positives'].Value);
        scans := TJsonObject(jsonx.Values['scans']);
        writeln(scans.ToJSON);
        Result[0].scans := handleURLScans(scans);
      end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

function TVirusTotalAPI.reportFile(const Hash: TArray<String>): TArray<TvtFileReport>;
Const
  API = 'file/report';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  requestResult : String;
  I             : Integer;
  jsonx         : TJSonObject;
  item          : TJsonObject;
  scans         : TJsonObject;
begin
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', String.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := TJSONObject(jsonx.ParseJSONValue(requestResult));

    SetLength(result, system.JSON.TJSonArray(jsonx).Count);
    if Length(Hash) > 1 then
     begin
      for I := 0 to TJSonArray(jsonx).Count - 1 do
        begin
          item  := TJSONOBject(system.JSON.TJSonArray(jsonx).Items[i]);
          result[i].scan_id       := item.Values['scan_id'].Value;
          result[i].sha1          := item.Values['sha1'].Value;
          result[i].resource      := item.Values['resource'].Value;
          result[i].scan_date     := item.Values['scan_date'].Value;
          result[i].permalink     := item.Values['permalink'].Value;
          result[i].verbose_msg   := item.Values['verbose_msg'].Value;
          result[i].sha256        := item.Values['sha256'].Value;
          result[i].md5           := item.Values['md5'].Value;
          result[i].response_code := StrToInt(item.Values['response_code'].Value);
          result[i].total         := StrToInt(item.Values['total'].Value);
          result[i].positives     := StrToInt(item.Values['positives'].Value);
          scans := TJsonObject(item.Values['scans']);
          result[i].scans := handleFileScans(scans);
        end;
     end
    else
     begin
      result[0].scan_id       := jsonx.Values['scan_id'].Value;
      result[0].sha1          := jsonx.Values['sha1'].Value;
      result[0].resource      := jsonx.Values['resource'].Value;
      result[0].scan_date     := jsonx.Values['scan_date'].Value;
      result[0].permalink     := jsonx.Values['permalink'].Value;
      result[0].verbose_msg   := jsonx.Values['verbose_msg'].Value;
      result[0].sha256        := jsonx.Values['sha256'].Value;
      result[0].md5           := jsonx.Values['md5'].Value;
      result[0].response_code := StrToInt(jsonx.Values['response_code'].Value);
      result[0].total         := StrToInt(jsonx.Values['total'].Value);
      result[0].positives     := StrToInt(jsonx.Values['positives'].Value);
      scans := TJsonObject(jsonx.Values['scans']);
      result[0].scans := handleFileScans(scans);
     end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

function TVirusTotalAPI.RescanFile(const Hash: TArray<String>): TArray<TvtFileSend>;
Const
  API = 'file/rescan';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  I             : Integer;
  requestResult : String;
  jsonx         : TJSonObject;
  item          : TJsonObject;
begin
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', String.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := TJSONObject(jsonx.ParseJSONValue(requestResult));

    SetLength(result, TJSONOBject(system.JSON.TJSonArray(jsonx)).Count);
    for I := 0 to TJSONOBject(system.JSON.TJSonArray(jsonx)).Count - 1 do
      begin
        item  := TJSONOBject(system.JSON.TJSonArray(jsonx).Items[i]);
        result[I].verbose_msg := item.Values['verbose_msg'].Value;
        result[i].resource    := item.Values['resource'].Value;
        result[i].scan_id     := item.Values['scan_id'].Value;
        result[i].permalink   := item.Values['permalink'].Value;
        result[i].sha256      := item.Values['sha256'].Value;
        result[i].sha1        := item.Values['sha1'].Value;
        result[i].md5         := item.Values['md5'].Value;
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
  HTTP  := THTTPClient.Create;
  Part  := TMultipartFormData.Create;
  jsonx := TJSONObject.Create;
  try
    Part.AddFile('file', FileName);
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := TJSONObject(jsonx.ParseJSONValue(requestResult));
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

function TVirusTotalAPI.scanURL(const URLs: TArray<String>): TArray<TvtURLSend>;
Const
  API = 'url/scan';
var
  HTTP          : THTTPClient;
  Part          : TMultipartFormData;
  I             : Integer;
  requestResult : String;
  jsonX         : TJSonObject;
  item          : TJSONObject;
begin
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('url', String.Join(#13#10, URLs));
    Part.AddField('apikey', ApiKey);
    requestResult := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    jsonx := TJSONObject(jsonx.ParseJSONValue(requestResult));
    SetLength(result, Length(URLs));

    if Length(URLs) > 1 then
     begin
      for I := 0 to TJSONOBject(system.JSON.TJSonArray(jsonx)).Count-1 do
       begin
        item := TJSONObject(system.JSON.TJSonArray(jsonx).Items[i]);
        result[i].verbose_msg := item.Values['verbose_msg'].Value;
        result[i].resource    := item.Values['resource'].Value;
        result[i].url         := item.Values['url'].Value;
        result[i].scan_id     := item.Values['scan_id'].Value;
        result[i].permalink   := item.Values['permalink'].Value;
        result[i].scan_date   := item.Values['scan_date'].Value;
       end;
     end
    else
       begin
        result[0].verbose_msg := jsonx.Values['verbose_msg'].Value;
        result[0].resource    := jsonx.Values['resource'].Value;
        result[0].url         := jsonx.Values['url'].Value;
        result[0].scan_id     := jsonx.Values['scan_id'].Value;
        result[0].permalink   := jsonx.Values['permalink'].Value;
        result[0].scan_date   := jsonx.Values['scan_date'].Value;
       end;
  finally
    FreeAndNil(Part);
    FreeAndNil(HTTP);
    FreeAndNil(jsonx);
  end;
end;

end.
