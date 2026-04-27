{******************************************************************************}
{                                                                              }
{       Delphi cross platform socket library                                   }
{                                                                              }
{       Copyright (c) 2017 WiNDDRiVER(soulawing@gmail.com)                     }
{                                                                              }
{       Homepage: https://github.com/winddriver/Delphi-Cross-Socket            }
{                                                                              }
{******************************************************************************}
unit Net.CrossHttpRouter;

{$I zLib.inc}

interface

uses
  Net.CrossHttpServer;

type
  /// <summary>
  ///   路由
  /// </summary>
  /// <remarks>
  ///   用于 TCrossHttpServer.Route(), Get(), Post() 等
  /// </remarks>
  TNetCrossRouter = class
  public
    /// <summary>
    ///   静态文件路由
    /// </summary>
    /// <param name="ALocalDir">
    ///   本地目录
    /// </param>
    class function &Static(const ALocalDir, AFileParamName: string): TCrossHttpRouterProc; static;

    /// <summary>
    ///   文件列表路由
    /// </summary>
    /// <param name="APath">
    ///   请求路径, 该参数是为了在目录列表页面中定位根路径
    /// </param>
    /// <param name="ALocalDir">
    ///   本地目录
    /// </param>
    class function Dir(const APath, ALocalDir, ADirParamName: string): TCrossHttpRouterProc; static;

    /// <summary>
    ///   含有默认首页文件的静态文件路由
    /// </summary>
    /// <param name="ALocalDir">
    ///   含有默认首页文件的本地目录
    /// </param>
    /// <param name="ADefIndexFiles">
    ///   默认的首页文件,按顺序选择,先找到哪个就使用哪个
    /// </param>
    class function Index(const ALocalDir, AFileParamName: string; const ADefIndexFiles: TArray<string>): TCrossHttpRouterProc; static;
  end;

implementation

uses
  SysUtils,
  Classes,

  Net.CrossHttpRouterDirUtils,
  Net.CrossHttpUtils,

  Utils.IOUtils;

/// <summary>
///   比较两个路径是否相同
/// </summary>
/// <param name="APath1">
///   第一个路径
/// </param>
/// <param name="APath2">
///   第二个路径
/// </param>
/// <returns>
///   如果两个路径相同则返回True，否则返回False
/// </returns>
/// <remarks>
///   Windows平台下不区分大小写，其他平台区分大小写
/// </remarks>
function _SamePathText(const APath1, APath2: string): Boolean;
begin
  {$IFDEF MSWINDOWS}
  Result := SameText(APath1, APath2);
  {$ELSE}
  Result := (APath1 = APath2);
  {$ENDIF}
end;

/// <summary>
///   检查路径是否在基础目录下
/// </summary>
/// <param name="ABaseDir">
///   基础目录路径
/// </param>
/// <param name="APath">
///   需要检查的路径
/// </param>
/// <returns>
///   如果APath在ABaseDir目录下则返回True，否则返回False
/// </returns>
function _IsPathInBaseDir(const ABaseDir, APath: string): Boolean;
var
  LBaseDir: string;
begin
  LBaseDir := IncludeTrailingPathDelimiter(ABaseDir);
  Result := _SamePathText(Copy(APath, 1, Length(LBaseDir)), LBaseDir);
end;

/// <summary>
///   尝试解析本地路径，确保路径安全性
/// </summary>
/// <param name="ALocalDir">
///   本地基础目录
/// </param>
/// <param name="APath">
///   要解析的相对路径
/// </param>
/// <param name="AResolvedPath">
///   解析后的完整路径
/// </param>
/// <returns>
///   如果路径有效且在基础目录内返回True，否则返回False
/// </returns>
/// <remarks>
///   此函数会验证路径的安全性，防止路径遍历攻击
/// </remarks>
function _TryResolveLocalPath(const ALocalDir, APath: string;
  out AResolvedPath: string): Boolean;
var
  LBaseDir, LPath, LCombinedPath: string;
begin
  AResolvedPath := '';
  LPath := TCrossHttpUtils.GetPathWithoutParams(APath).Trim;

  if (Pos(#0, LPath) > 0) then Exit(False);

  {$IFDEF MSWINDOWS}
  LPath := LPath.Replace('/', '\');
  if TPathUtils.IsDriveRooted(LPath)
    or TPathUtils.IsUNCRooted(LPath)
    or LPath.StartsWith('\') then Exit(False);
  {$ELSE}
  LPath := LPath.Replace('\', '/');
  if LPath.StartsWith('/') then Exit(False);
  {$ENDIF}

  LBaseDir := TPathUtils.GetFullPath(ALocalDir);
  LCombinedPath := TPathUtils.Combine(LBaseDir, LPath);
  AResolvedPath := TPathUtils.GetFullPath(LCombinedPath);
  Result := _IsPathInBaseDir(LBaseDir, AResolvedPath)
    or _SamePathText(LBaseDir, AResolvedPath);
end;

{ TNetCrossRouter }

class function TNetCrossRouter.Index(const ALocalDir, AFileParamName: string;
  const ADefIndexFiles: TArray<string>): TCrossHttpRouterProc;
var
  LDefIndexFiles: TArray<string>;
begin
  if (ADefIndexFiles <> nil) then
    LDefIndexFiles := ADefIndexFiles
  else
    LDefIndexFiles := [
      'index.html',
      'main.html',
      'index.js',
      'main.js',
      'index.htm',
      'main.htm'
    ];

  Result :=
    procedure(const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse; var AHandled: Boolean)
    var
      LPath, LFile, LDefMainFile, LResolvedPath: string;
    begin
      if not _TryResolveLocalPath(ALocalDir, '', LPath) then
      begin
        AHandled := False;
        Exit;
      end;
      LFile := TCrossHttpUtils.GetPathWithoutParams(ARequest.Params[AFileParamName]);

      if (LFile = '') then
      begin
        for LDefMainFile in LDefIndexFiles do
        begin
          if _TryResolveLocalPath(LPath, LDefMainFile, LResolvedPath)
            and TFileUtils.Exists(LResolvedPath) then
          begin
            AResponse.SendFile(LResolvedPath);
            AHandled := True;
            Exit;
          end;
        end;
      end else
      begin
        if _TryResolveLocalPath(LPath, LFile, LResolvedPath)
          and TFileUtils.Exists(LResolvedPath) then
        begin
          AResponse.SendFile(LResolvedPath);
          AHandled := True;
          Exit;
        end;
      end;

      AHandled := False;
    end;
end;

class function TNetCrossRouter.Static(
  const ALocalDir, AFileParamName: string): TCrossHttpRouterProc;
begin
  Result :=
    procedure(const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse; var AHandled: Boolean)
    var
      LFile, LResolvedPath: string;
    begin
      AHandled := True;

      LFile := TCrossHttpUtils.GetPathWithoutParams(ARequest.Params[AFileParamName]);
      if not _TryResolveLocalPath(ALocalDir, LFile, LResolvedPath) then
      begin
        AHandled := False;
        Exit;
      end;
      AResponse.SendFile(LResolvedPath);
    end;
end;

class function TNetCrossRouter.Dir(
  const APath, ALocalDir, ADirParamName: string): TCrossHttpRouterProc;
begin
  Result :=
    procedure(const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse; var AHandled: Boolean)
    var
      LFile, LResolvedPath: string;
    begin
      AHandled := True;

      LFile := TCrossHttpUtils.GetPathWithoutParams(ARequest.Params[ADirParamName]);
      if not _TryResolveLocalPath(ALocalDir, LFile, LResolvedPath) then
      begin
        AHandled := False;
        Exit;
      end;

      if (TDirectoryUtils.Exists(LResolvedPath)) then
        AResponse.Send(BuildDirList(LResolvedPath, ARequest.Path, APath))
      else if TFileUtils.Exists(LResolvedPath) then
        AResponse.SendFile(LResolvedPath)
      else
        AHandled := False;
    end;
end;

end.
