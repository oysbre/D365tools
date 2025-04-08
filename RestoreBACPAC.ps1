#Script to restore BACPAC on D365 CHE. Needs to run as admin session
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
#"No Administrative rights, it will display a popup window asking user for Admin rights"
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}

#------------Region custom variables----------------------------------------------#
# In LCS > Asset library > Database backup, mark the database for restore to the left of the name and then click "Generate SAS link". 
# Replace <SASURL> with the SAS URL between " " in variable $URL below:

$URL = "<SASURL>"

#Define localdir/path for bacpac download
$localdir = "D:\"  # default set to D:\. If not found, use C:\temp

#---------- END custom variables -------------

if ($URL -eq "<SASURL>"){ write-host 'Set SASURL from LCS in variable "$URL" and try again.' -foregroundcolor yellow;pause;exit}
if ($localfilename -eq "<local fullpathname here>"){ write-host "Set local pathname with filename aka: D:\dev.bacpac in variable '$localfilename'" -foregroundcolor yellow;pause;exit}
if (-not(test-path $localdir)){
	$localdir = "c:\temp"
 	if (-not(test-path $localdir)){	
  		new-item -path $localdir -type directory -force | out-null
    	} #end if testpath C:
}#end if testpath 

#add backslash to $localdir it not set   	
if ($localdir -notmatch '\\$') {$localdir += '\'}

$localfilename = $localdir + "sandboxbackup.bacpac"  # << full local filepath aka D:\tempdev.bacpac

#------------Region GLOBAL variables------------------------------------
$bacpacFileNameAndPath = $localfilename
# Will be created by script. Existing files will be overwritten.
$modelFilePath = $localdir+"BacpacModel.xml" 
$modelFileUpdatedPath = $localdir +"UpdatedBacpacModel.xml"
$newDBname = "importeddatabase_$((Get-Date).tostring("ddMMMyyyy"))" 
$servicelist = @("DynamicsAxBatch","MR2012ProcessService","W3SVC","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe")
$sqlbakPath = $localfilename
#--------------------END Region Global variables------------------------

#------------------  FUNCTIONS -------------------------------
function Get-UrlStatusCode([string] $Urlcheck) {
    try {  (Invoke-WebRequest -Uri $Urlcheck -UseBasicParsing -DisableKeepAlive -method head).StatusCode }
    catch [Net.WebException]  { [int]$_.Exception.Response.StatusCode  }
}#end function URL status

function stopservices () {     
	foreach ($service in $servicelist){
    		$serviceobject = get-service -name $service -ea 0
    		if ($serviceobject){
        		if ($serviceobject.Status -ne 'Stopped'){
            			write-host "Stopping service $($serviceobject.name)..." -ForegroundColor yellow
            			stop-service $serviceobject -force
            			$serviceobject.WaitForStatus("Stopped")
        		}#end if status
    		}#end if $serviceobject
	}#end foreach service
}#end function stopservices

function startservices () {
	foreach ($service in $servicelist){
    		$serviceobject = get-service -name $service -ea 0
    		if ($serviceobject){
        		if ($serviceobject.StartType -ne 'Disabled'){
            			write-host "Starting service $($serviceobject.name)..." -ForegroundColor yellow
            			start-service $serviceobject 
            			$serviceobject.WaitForStatus("Running")
        		}#end if startType
    		}#end if $serviceobject
	}#end foreach service
}#end function startservices

function Run-DBSync() {
    $aosPath = "{0}\AOSService" -f $env:servicedrive 
    $packageDirectory = "$aosPath\PackagesLocalDirectory" 
    $SyncToolExecutable = "$aosPath\webroot\bin\Microsoft.Dynamics.AX.Deployment.Setup.exe"
	if (-not(get-command Get-D365DatabaseAccess)){
        install-module d365fo.tools -force -AllowClobber
	}
    $dbaccess = Get-D365DatabaseAccess
    $params = @(
        '-bindir',       $($packageDirectory)
        '-metadatadir' , $($packageDirectory) 
        '-sqluser',      $($dbaccess.sqluser)
        '-sqlserver',    '.'
        '-sqldatabase',  'AxDB'
        '-setupmode',    'sync' 
        '-syncmode',     'fullall' 
        '-isazuresql',   'false' 
        '-sqlpwd',       $($dbaccess.SqlPwd)
        )#end params
    Write-host "Syncing AxDB..."-foregroundcolor yellow
    & $SyncToolExecutable $params 2>&1 | Out-String    
}#end function DB-sync

function Import-Module-SQLPS {
    #pushd and popd to avoid import from changing the current directory (ref: http://stackoverflow.com/questions/12915299/sql-server-2012-sqlps-module-changing-current-location-automatically)
    #3>&1 puts warning stream to standard output stream (see https://connect.microsoft.com/PowerShell/feedback/details/297055/capture-warning-verbose-debug-and-host-output-via-alternate-streams)
    #out-null blocks that output, so we don't see the annoying warnings described here: https://www.codykonior.com/2015/05/30/whats-wrong-with-sqlps/
    push-location
    import-module sqlps 3>&1 | out-null
    pop-location
}#end function Import-Module-SQLPS
# ----------------End Function area -----------------

# BEGIN
CLS
write-host "This script will restore BACPAC, delete the existing AXDB and quit/kill VS/SSMS applications. Continue? [Y/N]" -ForegroundColor Yellow;$goaheadans = read-host
if ($goaheadans -eq 'y'){
write-host "Sync DB after BACPAC restore? [Y/N]" -foregroundcolor yellow;$syncans=read-host
write-host 
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
if ((get-packageprovider nuget) -eq $NULL){
write-host "Installing NuGet..." -ForegroundColor yellow
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#install/update d365fo.tools
if(-not (Get-Module d365fo.tools -ListAvailable)){
    Write-host "Installing D365fo.tools..." -foregroundcolor yellow
    Install-Module d365fo.tools -Force
}
else {
    $releases = "https://api.github.com/repos/d365collaborative/d365fo.tools/releases"
    if ((Get-UrlStatusCode -Urlcheck $releases) -eq 200 ){
    $tagver = ((Invoke-WebRequest $releases -ea 0 -UseBasicParsing | ConvertFrom-Json)[0].tag_name).tostring()
        if ($tagver){
            $fover = (get-installedmodule d365fo.tools).version.tostring()
            if ([System.Version]$tagver -gt [System.Version]$fover){
             Write-host "Updating D365fo.tools..." -foregroundcolor yellow
	     Update-Module -name d365fo.tools -Force
            }#end if gt version check
        }#end if tagver 
    }
    else {write-host "Can't connect to github to fetch D365fo.tools" -ForegroundColor CYAN }
}#end install/update d365fo.tools

#use SQLPS module
if(get-module sqlps){"yes"}else{"no"}
Import-Module-SQLPS
if(get-module sqlps){"yes"}else{"no"}

#Install/update AzCopy
If (-not(test-path "C:\windows\AzCopy.exe")){
    write-host "Installing AzCopy to C:\Windows..." -ForegroundColor Yellow
    remove-item $env:temp\AzCopy.zip -force -ea 0
    invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe"
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
}
else {
$azcopyupdate = & azcopy -h | select-string -pattern "newer version"
if ($azcopyupdate){
    write-host "Updating AzCopy..." -ForegroundColor Yellow
    remove-item $env:temp\AzCopy.zip -force -ea 0 
    Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe" -force
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
    }
}#end AzCopy 

#get latest SQLPACKAGE
write-host "Installing latest SQLPACKAGE to C:\SQLPACKAGECORE..." -ForegroundColor yellow
remove-item $env:temp\sqlpackagecore.zip -force -ea 0
$uri = "https://aka.ms/sqlpackage-windows"
$request = Invoke-WebRequest -Uri $uri -MaximumRedirection 2 -ErrorAction 0 -OutFile $env:temp\sqlpackagecore.zip
unblock-file $env:temp\sqlpackagecore.zip
Expand-Archive $env:temp\sqlpackagecore.zip  c:\sqlpackagecore  -Force
remove-item $env:temp\sqlpackagecore.zip -force
$bacpacexepath = Get-ChildItem -Path "C:\sqlpackagecore" -Filter SqlPackage.exe -EA 0 -Force | sort lastwritetime | select -last 1 -expandproperty directoryname

 
#download bacpac from LCS
$statuscode = Get-UrlStatusCode -urlcheck $URL
if ($statuscode -eq 200){
    #check if we got bacpac already
    if (-not(test-path $localfilename)){
        write-host "Downloading $($localfilename) from LCS/SASURL..." -ForegroundColor yellow
        azcopy copy $URL $localfilename
        unblock-file $localfilename
    }
    else {
        write-host "Already found bacpac $($localfilename). To use this BACPAC, press Enter. Download and overwrite existing file? Press letter D" -ForegroundColor Cyan;$bacpacans=read-host
        if ($bacpacans -eq "D"){
            remove-item $localfilename -force -ea 0
            write-host "Downloading BACPAC to $($localfilename) from LCS/SASURL..." -ForegroundColor yellow
            azcopy copy $URL $localfilename
            unblock-file $localfilename 
        }#end if delete existing file
    }#end else
}#end if statuscode check
else {write-host "Error in URL $($url ): " $($statuscode) -ForegroundColor RED;pause;exit}

#stop D365 lreated services before restore
stopservices

#Check for BACPAC
$Latest = Get-ChildItem -Path $sqlbakPath -ea 0| Where-Object {$_.name -like "*.bacpac"} | Sort-Object LastWriteTime -Descending | Select-Object -First 1

#check if we got a BACPAC
if ($Latest){
$RestoreFile = $Latest.Name
write-host "Using BACPAC file $($RestoreFile)." -ForegroundColor yellow

#drop AXDB_org if exists
$sqlDropAXDB_orgQ= @"
IF DB_ID('AXDB_org') IS NOT NULL
BEGIN
ALTER DATABASE [AXDB_org] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:03';
ALTER DATABASE [AXDB_org] SET MULTI_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:03';
DROP DATABASE axdb_org;
END
"@
write-host "Dropping AXDB_org if exists..." -ForegroundColor yellow
$dbcheckpre = Invoke-SqlCmd -Query $sqlDropAXDB_orgQ -Database master -ServerInstance localhost -ErrorAction Continue -querytimeout 90

<#query rename existing AXDB
write-host "Renaming existing AXDB to AXDB_org and $($newdbname) to AXDB..." -ForegroundColor yellow
$sqlrenameorgAXDBq = @"
IF DB_ID('AXDB') IS NOT NULL
BEGIN
ALTER DATABASE [AXDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
ALTER DATABASE [AXDB] MODIFY NAME = AXDB_Org;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB_org] SET MULTI_USER;
END
"@
$renameorgaxdb = Invoke-SqlCmd -Query $sqlrenameorgAXDBq -Database master -ServerInstance localhost -ErrorAction continue -querytimeout 90 
#>

#query check if AXDB exists and drop it
$sqlDropAXDBQ= @"
IF DB_ID('AXDB') IS NOT NULL
BEGIN
ALTER DATABASE [AXDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:04';
ALTER DATABASE [AXDB] SET MULTI_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:04';
DROP DATABASE axdb;
WAITFOR DELAY '00:00:03';
END
"@
write-host "Dropping AXDB if exists..." -ForegroundColor yellow
$dbcheckaxdb = Invoke-SqlCmd -Query $sqlDropAXDBQ -Database master -ServerInstance localhost -ErrorAction Stop -querytimeout 90

#fix model.xml for unsupported features in SQL vs Azure SQL
Write-host "Exporting BACPAC Modelfile..." -ForegroundColor yellow
Export-D365BacpacModelFile -Path $bacpacFileNameAndPath -OutputPath $modelFilePath -Force -Verbose
Write-host "Fixing BACPAC Modelfile for incompatible functions in Azure SQL vs local SQL version..." -ForegroundColor yellow
Repair-D365BacpacModelFile -path $modelFilePath -Force

write-host "Truncating tables in BACPAC before restore/import..." -ForegroundColor Yellow
Clear-D365TableDataFromBacpac -Path $sqlbakPath -Table "SECURITYOBJECTHISTORY","*Staging*","BatchHistory","BatchJobHistory","SYSDATABASELOG*","ReqCalcTaskTrace","AMDEVICETRANSACTIONLOG","LACARCHIVERESENDDATA","LACARCHIVEDATA","BISWSHISTORY","DTA_*","LACARCHIVEREF","BISMESSAGEHISTORYHEADER","RETAILTRANSACTIONPAYMENTTRANS" -ClearFromSource -ErrorAction SilentlyContinue
write-host
write-host "Restore of BACPAC takes awhile. Please wait..." -ForegroundColor yellow

#Restore BACPAC 
& "$bacpacexepath\SqlPackage.exe" /a:import /sf:$sqlbakPath /tsn:localhost /tdn:$newDBname /p:CommandTimeout=0 /p:DisableIndexesForDataPhase=FALSE /ttsc:True /mfp:"$($localdir)BacpacModel-edited.xml"

start-sleep -s 2

#query check if new DB exists
$sqlCheckNewdatabaseQ= @"
IF DB_ID('$newDBname') IS NULL
BEGIN
SELECT 'Oh no! Something bad just happened'
END
"@

$newdbcheck = Invoke-SqlCmd -Query $sqlCheckNewdatabaseQ -Database master -ServerInstance localhost -ErrorAction Continue -querytimeout 90 
if ($newdbcheck.column1 -match "Something"){
write-host "Database $($newDBname) not restored ok. Restore failed? Not enough diskspace? Check errors and try again." -ForegroundColor RED;pause;exit
}

#reconnect SQL users
$sqlupdateDBQ = @"
DROP USER IF EXISTS [axretailruntimeuser]
DROP USER IF EXISTS [axretaildatasyncuser]
DROP USER IF EXISTS [axmrruntimeuser]
DROP USER IF EXISTS [axdeployuser]
DROP USER IF EXISTS [axdbadmin]
DROP USER IF EXISTS [axdeployextuser]
DROP USER IF EXISTS [NT AUTHORITY\NETWORK SERVICE]

IF EXISTS (SELECT * FROM sys.syslogins WHERE NAME = 'axdeployuser')
BEGIN
	CREATE USER axdeployuser FROM LOGIN axdeployuser
	EXEC sp_addrolemember 'db_owner', 'axdeployuser'
END

IF EXISTS (SELECT * FROM sys.syslogins WHERE NAME = 'axdbadmin')
BEGIN
	ALTER AUTHORIZATION ON database::[$newDBname] TO sa

	CREATE USER axdbadmin FROM LOGIN axdbadmin
	EXEC sp_addrolemember 'db_owner', 'axdbadmin'
END

IF EXISTS (SELECT * FROM sys.syslogins WHERE NAME = 'axmrruntimeuser')
BEGIN
	CREATE USER axmrruntimeuser FROM LOGIN axmrruntimeuser
	EXEC sp_addrolemember 'db_datareader', 'axmrruntimeuser'
	EXEC sp_addrolemember 'db_datawriter', 'axmrruntimeuser'
END

IF EXISTS (SELECT * FROM sys.syslogins WHERE NAME = 'axretaildatasyncuser')
BEGIN
	CREATE USER axretaildatasyncuser FROM LOGIN axretaildatasyncuser
	IF (DATABASE_PRINCIPAL_ID('DataSyncUsersRole') IS NOT NULL)
	BEGIN
		EXEC sp_addrolemember 'DataSyncUsersRole', 'axretaildatasyncuser'
	END
END

IF EXISTS (SELECT * FROM sys.syslogins WHERE NAME = 'axretailruntimeuser')
BEGIN
	CREATE USER axretailruntimeuser FROM LOGIN axretailruntimeuser
	IF (DATABASE_PRINCIPAL_ID('UsersRole') IS NOT NULL)
	BEGIN
		EXEC sp_addrolemember 'UsersRole', 'axretailruntimeuser'

	END
	
	IF (DATABASE_PRINCIPAL_ID('ReportUsersRole') IS NOT NULL)
	BEGIN
		EXEC sp_addrolemember 'ReportUsersRole', 'axretailruntimeuser'
	END
END

IF EXISTS (SELECT * FROM sys.syslogins WHERE NAME = 'axdeployextuser')
BEGIN
	CREATE USER axdeployextuser FROM LOGIN axdeployextuser
	IF (DATABASE_PRINCIPAL_ID('DeployExtensibilityRole') IS NOT NULL)
	BEGIN
		EXEC sp_addrolemember 'DeployExtensibilityRole', 'axdeployextuser'
	END
END

CREATE USER [NT AUTHORITY\NETWORK SERVICE] FROM LOGIN [NT AUTHORITY\NETWORK SERVICE]
EXEC sp_addrolemember 'db_owner', 'NT AUTHORITY\NETWORK SERVICE'

UPDATE T1
SET T1.storageproviderid = 0
    , T1.accessinformation = ''
    , T1.modifiedby = 'Admin'
    , T1.modifieddatetime = getdate()
FROM docuvalue T1
WHERE T1.storageproviderid = 1 --Azure storage


IF((SELECT 1
FROM SYS.CHANGE_TRACKING_DATABASES
WHERE DATABASE_ID = DB_ID('$newDBname')) IS NULL)
BEGIN
	ALTER DATABASE [$newDBname] SET CHANGE_TRACKING = ON (CHANGE_RETENTION = 6 DAYS, AUTO_CLEANUP = ON)
END

;--GO
DROP PROCEDURE IF EXISTS SP_ConfigureTablesForChangeTracking
DROP PROCEDURE IF EXISTS SP_ConfigureTablesForChangeTracking_V2
;--GO
-- Begin Refresh Retail FullText Catalogs
DECLARE @RFTXNAME NVARCHAR(MAX);
DECLARE @RFTXSQL NVARCHAR(MAX);
DECLARE retail_ftx CURSOR FOR
SELECT OBJECT_SCHEMA_NAME(object_id) + '.' + OBJECT_NAME(object_id) fullname
FROM SYS.FULLTEXT_INDEXES
WHERE FULLTEXT_CATALOG_ID = (SELECT TOP 1
	FULLTEXT_CATALOG_ID
FROM SYS.FULLTEXT_CATALOGS
WHERE NAME = 'COMMERCEFULLTEXTCATALOG');
OPEN retail_ftx;
FETCH NEXT FROM retail_ftx INTO @RFTXNAME;

BEGIN TRY
	WHILE @@FETCH_STATUS = 0
	BEGIN
		PRINT 'Refreshing Full Text Index ' + @RFTXNAME;
		EXEC SP_FULLTEXT_TABLE @RFTXNAME, 'activate';
		SET @RFTXSQL = 'ALTER FULLTEXT INDEX ON ' + @RFTXNAME + ' START FULL POPULATION';
		EXEC SP_EXECUTESQL @RFTXSQL;
		FETCH NEXT FROM retail_ftx INTO @RFTXNAME;
	END
END TRY
BEGIN CATCH
	PRINT error_message()
END CATCH

CLOSE retail_ftx;
DEALLOCATE retail_ftx;
-- End Refresh Retail FullText Catalogs

--Next, set system parameters ready for being a SQL Server Database.
UPDATE sysglobalconfiguration
SET    value = 'SQLSERVER'
WHERE  NAME = 'BACKENDDB'

UPDATE sysglobalconfiguration
SET    value = 0
WHERE  NAME = 'TEMPTABLEINAXDB'
"@

#Remap SQL users
write-host "Remapping SQL users..." -ForegroundColor yellow
Invoke-SqlCmd -Query $sqlupdateDBQ -ServerInstance localhost -Database $newDBname -ErrorAction Continue -querytimeout 0 
write-host "Done remapping SQL users. (ignore any red error messages on console output)" -ForegroundColor green
write-host ""

#Cleanup Retail
$sqlRetailcleanup = @"
/* Drop all non-system stored procs under schemas crt, ax, ext and cdx */
DECLARE @schemaCrt INT
DECLARE @schemaAx INT
DECLARE @schemaExt INT
DECLARE @schemaCdx INT

SELECT @schemaCrt = schema_id FROM sys.schemas WHERE [NAME] = 'crt'
SELECT @schemaAx = schema_id FROM sys.schemas WHERE [NAME] = 'ax'
SELECT @schemaExt = schema_id FROM sys.schemas WHERE [NAME] = 'ext'
SELECT @schemaCdx = schema_id FROM sys.schemas WHERE [NAME] = 'cdx'

DECLARE @name NVARCHAR(128)
DECLARE @objId INT
DECLARE @SQL NVARCHAR(1024)

SELECT TOP 1 @name = [name], @objId = [object_id] FROM sys.procedures WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt,@schemaCdx) ORDER BY [create_date] DESC

WHILE @name is not null AND len(@name) > 0
BEGIN
    SELECT @SQL = 'DROP PROCEDURE [' + OBJECT_SCHEMA_NAME(@objId) + '].[' + RTRIM(@name) +']'
    EXEC (@SQL)
    PRINT @SQL  
	SELECT @name = NULL, @objId = 0  
	SELECT TOP 1 @name = [name], @objId = [object_id] FROM sys.procedures WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt,@schemaCdx) ORDER BY [create_date] DESC
END
GO

/* Drop all views under schema crt, ax and ext */
DECLARE @schemaCrt INT
DECLARE @schemaAx INT
DECLARE @schemaExt INT
DECLARE @schemaCdx INT

SELECT @schemaCrt = schema_id FROM sys.schemas WHERE [NAME] = 'crt'
SELECT @schemaAx = schema_id FROM sys.schemas WHERE [NAME] = 'ax'
SELECT @schemaExt = schema_id FROM sys.schemas WHERE [NAME] = 'ext'
SELECT @schemaCdx = schema_id FROM sys.schemas WHERE [NAME] = 'cdx'

DECLARE @name NVARCHAR(128)
DECLARE @objId INT
DECLARE @SQL NVARCHAR(1024)

/* Order by id DESC to remove the later view first since there may be some dependency between different views */
SELECT TOP 1 @name = [name], @objId = [object_id] FROM sys.views WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt,@schemaCdx) ORDER BY [create_date] DESC

WHILE @name is not null AND len(@name) > 0
BEGIN
    SELECT @SQL = 'DROP VIEW [' + OBJECT_SCHEMA_NAME(@objId) + '].[' + RTRIM(@name) +']'
    EXEC (@SQL)
    PRINT @SQL	
	SELECT @name = NULL, @objId = 0
    SELECT TOP 1 @name = [name], @objId = [object_id] FROM sys.views WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt,@schemaCdx) ORDER BY [create_date] DESC
END
GO

/* Drop all functions under schemas crt, ax, ext and cdx*/
DECLARE @schemaCrt INT
DECLARE @schemaAx INT
DECLARE @schemaExt INT
DECLARE @schemaCdx INT

SELECT @schemaCrt = schema_id FROM sys.schemas WHERE [NAME] = 'crt'
SELECT @schemaAx = schema_id FROM sys.schemas WHERE [NAME] = 'ax'
SELECT @schemaExt = schema_id FROM sys.schemas WHERE [NAME] = 'ext'
SELECT @schemaCdx = schema_id FROM sys.schemas WHERE [NAME] = 'cdx'

DECLARE @name NVARCHAR(128)
DECLARE @objId INT
DECLARE @SQL NVARCHAR(1024)
DECLARE @functionsCount int
DECLARE @postDeleteFunctionsCount int

SELECT @functionsCount = count(*) FROM sysobjects WHERE [type] IN (N'FN', N'IF', N'TF', N'FS', N'FT') AND OBJECT_SCHEMA_NAME(id) IN ('crt','ax','ext','cdx')

WHILE @functionsCount > 0
BEGIN
    DECLARE dropFunctions_cursor CURSOR FOR
        SELECT [id], [name] FROM sysobjects WHERE [type] IN (N'FN', N'IF', N'TF', N'FS', N'FT') AND OBJECT_SCHEMA_NAME(id) IN ('crt','ax','ext','cdx') ORDER BY [crdate] DESC

    OPEN dropFunctions_cursor
    FETCH NEXT FROM dropFunctions_cursor INTO  @objId, @name

    WHILE @@FETCH_STATUS = 0
    BEGIN
        SELECT @SQL = 'DROP FUNCTION [' + OBJECT_SCHEMA_NAME(@objId) + '].[' + RTRIM(@name) +']'
        BEGIN TRY
            EXEC (@SQL)
            PRINT @SQL
        END TRY
        BEGIN CATCH
            PRINT 'Error occurred while executing query: ' + @SQL
            PRINT 'Error message: ' + ERROR_MESSAGE()
            PRINT 'Check log to see if this is retried.'
        END CATCH;
        FETCH NEXT FROM dropFunctions_cursor INTO  @objId, @name
    END
    CLOSE dropFunctions_cursor;
    DEALLOCATE dropFunctions_cursor;

    SELECT @postDeleteFunctionsCount = count(*) FROM sysobjects WHERE [type] IN (N'FN', N'IF', N'TF', N'FS', N'FT') AND OBJECT_SCHEMA_NAME(id) IN ('crt','ax','ext','cdx')

    IF @postDeleteFunctionsCount = @functionsCount
        THROW 60000, 'Unable to progress with deleting functions. Same number of functions left as the previous iteration.', 1
    ELSE
        SET @functionsCount = @postDeleteFunctionsCount
END
GO

/* Drop all foreign key constraints under schemas crt, ax, ext and cdx*/
DECLARE @schemaCrt INT
DECLARE @schemaAx INT
DECLARE @schemaExt INT
DECLARE @schemaCdx INT

SELECT @schemaCrt = schema_id FROM sys.schemas WHERE [NAME] = 'crt'
SELECT @schemaAx = schema_id FROM sys.schemas WHERE [NAME] = 'ax'
SELECT @schemaExt = schema_id FROM sys.schemas WHERE [NAME] = 'ext'
SELECT @schemaCdx = schema_id FROM sys.schemas WHERE [NAME] = 'cdx'

DECLARE @name NVARCHAR(128)
DECLARE @constraint NVARCHAR(254)
DECLARE @tableSchema NVARCHAR(254)
DECLARE @SQL NVARCHAR(1024)

SELECT TOP 1 @name = TABLE_NAME, @tableSchema = TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE constraint_catalog=DB_NAME() AND CONSTRAINT_TYPE = 'FOREIGN KEY' AND CONSTRAINT_SCHEMA IN ('crt','ax','ext', 'cdx') ORDER BY TABLE_NAME

WHILE @name is not null
BEGIN
	SELECT @constraint = NULL
    SELECT @constraint = (SELECT TOP 1 CONSTRAINT_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE constraint_catalog=DB_NAME() AND CONSTRAINT_TYPE = 'FOREIGN KEY' AND TABLE_NAME = @name AND CONSTRAINT_SCHEMA IN ('crt','ax','ext', 'cdx') ORDER BY CONSTRAINT_NAME)
    WHILE @constraint IS NOT NULL
    BEGIN
        SELECT @SQL = 'ALTER TABLE [' + @tableSchema + '].[' + RTRIM(@name) +'] DROP CONSTRAINT [' + RTRIM(@constraint) +']'
        EXEC (@SQL)
        PRINT @SQL
		SELECT @constraint = NULL		
        SELECT @constraint = (SELECT TOP 1 CONSTRAINT_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE constraint_catalog=DB_NAME() AND CONSTRAINT_TYPE = 'FOREIGN KEY' AND CONSTRAINT_NAME <> @constraint AND TABLE_NAME = @name AND CONSTRAINT_SCHEMA IN ('crt','ax','ext', 'cdx') ORDER BY CONSTRAINT_NAME)
    END
SELECT TOP 1 @name = TABLE_NAME, @tableSchema = TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE constraint_catalog=DB_NAME() AND CONSTRAINT_TYPE = 'FOREIGN KEY' AND CONSTRAINT_SCHEMA IN ('crt','ax','ext', 'cdx') ORDER BY TABLE_NAME
END
GO

/* Drop all tables under schemas crt, ax, ext and cdx */
DECLARE @schemaCrt INT
DECLARE @schemaAx INT
DECLARE @schemaExt INT
DECLARE @schemaCdx INT

SELECT @schemaCrt = schema_id FROM sys.schemas WHERE [NAME] = 'crt'
SELECT @schemaAx = schema_id FROM sys.schemas WHERE [NAME] = 'ax'
SELECT @schemaExt = schema_id FROM sys.schemas WHERE [NAME] = 'ext'
SELECT @schemaCdx = schema_id FROM sys.schemas WHERE [NAME] = 'cdx'

DECLARE @name NVARCHAR(128)
DECLARE @objId INT
DECLARE @SQL NVARCHAR(1024)

SELECT TOP 1 @name = [name], @objId = [object_id] FROM sys.tables WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt, @schemaCdx) ORDER BY [create_date] DESC

WHILE @name IS NOT NULL
BEGIN	
	SELECT @SQL = 'DROP TABLE [' + OBJECT_SCHEMA_NAME(@objId) + '].[' + RTRIM(@name) +']'
	EXEC (@SQL)
	PRINT @SQL	
	SELECT @name = NULL, @objId = 0
    SELECT TOP 1 @name = [name], @objId = [object_id] FROM sys.tables WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt, @schemaCdx) ORDER BY [create_date] DESC
END
GO

/* Drop all types under schemas crt, ax, ext and cdx */
DECLARE @schemaCrt INT
DECLARE @schemaAx INT
DECLARE @schemaExt INT
DECLARE @schemaCdx INT

SELECT @schemaCrt = schema_id FROM sys.schemas WHERE [NAME] = 'crt'
SELECT @schemaAx = schema_id FROM sys.schemas WHERE [NAME] = 'ax'
SELECT @schemaExt = schema_id FROM sys.schemas WHERE [NAME] = 'ext'
SELECT @schemaCdx = schema_id FROM sys.schemas WHERE [NAME] = 'cdx'

DECLARE @name NVARCHAR(128)
DECLARE @schemaId INT
DECLARE @SQL NVARCHAR(1024)

/* Order by id DESC to remove the later type first since there may be some dependency between different types */
SELECT TOP 1 @name = [name], @schemaId = [schema_id] FROM sys.types WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt,@schemaCdx) ORDER BY [user_type_id] DESC

WHILE @name is not null AND len(@name) > 0
BEGIN
    SELECT @SQL = 'DROP TYPE [' + SCHEMA_NAME(@schemaId) + '].[' + RTRIM(@name) +']'
    EXEC (@SQL)
    PRINT @SQL	
	SELECT @name = NULL, @schemaId = 0
    SELECT TOP 1 @name = [name], @schemaId = [schema_id]  FROM sys.types WHERE [schema_id] IN (@schemaCrt,@schemaAx,@schemaExt,@schemaCdx) ORDER BY [user_type_id] DESC
END
GO

/* Drop retail full text search catalog */
IF EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE [name] = 'COMMERCEFULLTEXTCATALOG')
BEGIN
	DROP FULLTEXT CATALOG [COMMERCEFULLTEXTCATALOG]
END

/* Drop retail db roles */

IF EXISTS (SELECT 1 FROM sys.procedures WHERE [name] = 'DropDatabaseRoleExt')
BEGIN
	DROP PROCEDURE dbo.DropDatabaseRoleExt
END
GO

CREATE PROCEDURE dbo.DropDatabaseRoleExt
(
	@RoleName NVARCHAR(255)
)
AS BEGIN
	IF  EXISTS (SELECT * FROM dbo.sysusers WHERE name = @RoleName AND issqlrole = 1)
	BEGIN 
      DECLARE @RoleMemberName sysname	  
      /* Cursor to Loop in for Each Member have the Role Privilege and Drop RoleMember */
      DECLARE Member_Cursor CURSOR FOR
      SELECT [name]
      FROM dbo.sysusers
      WHERE UID IN (
            SELECT memberuid
            FROM dbo.sysmembers
            WHERE groupuid IN (
                  SELECT UID FROM dbo.sysusers WHERE [name] = @RoleName AND issqlrole = 1)) 
      OPEN Member_Cursor;
 
      FETCH NEXT FROM Member_Cursor INTO @RoleMemberName
 
      WHILE @@FETCH_STATUS = 0
      BEGIN 
            EXEC sp_droprolemember @rolename=@RoleName, @membername= @RoleMemberName 
            FETCH NEXT FROM Member_Cursor INTO @RoleMemberName
      END;
 
      CLOSE Member_Cursor;
      DEALLOCATE Member_Cursor;
      /* End Of Cursor */ 
	END
	/* Checking If Role Name Exists In Database */
	IF  EXISTS (SELECT * FROM sys.database_principals WHERE name = @RoleName AND TYPE = 'R')
	BEGIN
		DECLARE @SqlStatement NVARCHAR(1024)
		SELECT @SqlStatement = 'DROP ROLE ' + @RoleName
		EXEC sp_executesql @SqlStatement
	END
END
GO

EXEC dbo.DropDatabaseRoleExt 'DataSyncUsersRole'
EXEC dbo.DropDatabaseRoleExt 'ReportUsersRole'
EXEC dbo.DropDatabaseRoleExt 'db_executor'
EXEC dbo.DropDatabaseRoleExt 'PublishersRole'
EXEC dbo.DropDatabaseRoleExt 'UsersRole'
EXEC dbo.DropDatabaseRoleExt 'DeployExtensibilityRole'
GO

IF EXISTS (SELECT 1 FROM sys.procedures WHERE [name] = 'DropDatabaseRoleExt')
BEGIN
	DROP PROCEDURE dbo.DropDatabaseRoleExt
END
GO

/* Drop retail schema crt, ax, ext, cdx */
IF EXISTS (SELECT 1 FROM sys.schemas WHERE [name] = 'crt')
BEGIN
	DROP SCHEMA crt
END
GO

IF EXISTS (SELECT 1 FROM sys.schemas WHERE [name] = 'ax')
BEGIN
	DROP SCHEMA ax
END
GO

IF EXISTS (SELECT 1 FROM sys.schemas WHERE [name] = 'ext')
BEGIN
	DROP SCHEMA ext
END
GO

IF EXISTS (SELECT 1 FROM sys.schemas WHERE [name] = 'cdx')
BEGIN
	DROP SCHEMA cdx
END
GO

IF OBJECT_ID('__RETAIL_PENDING_DEPLOYMENT') IS NOT NULL DROP VIEW __RETAIL_PENDING_DEPLOYMENT;
GO
"@

write-host "Retail fix running. Takes about 7-8 minutes. Please wait..." -ForegroundColor yellow
Invoke-SqlCmd -Query $sqlRetailcleanup -ServerInstance localhost -Database $newdbname -ErrorAction Continue -querytimeout 0 
write-host "Done fixing Retail settings." -ForegroundColor green


#Check if VS and/or SSMS and kill processes
$vs = taskkill /im devenv.exe /f | out-null
$ssms = taskkill /im ssms.exe /f | out-null

#Disable management reporter
#write-host "Disabling Management reporter service..." -ForegroundColor Yellow
#get-service | Where-Object {$_.Name -eq "MR2012ProcessService"} | Set-Service -StartupType Disabled

$sqlrenameToAXDBq= @"
ALTER DATABASE [$newDBname] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [$newDBname] MODIFY NAME = AXDB;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB] SET MULTI_USER;
"@

$renamenewaxdb = Invoke-SqlCmd -Query $sqlrenameToAXDBq -Database master -ServerInstance localhost -ErrorAction continue -querytimeout 90 
write-host "Renamed $($newDBname) to AXDB." -ForegroundColor green
start-sleep -s 2

#set AXDB to simple recovery mode
write-host "Set AxDB to simple recovery mode..." -foregroundcolor yellow
$simplerecoveryQ = @"
ALTER DATABASE AXDB SET RECOVERY SIMPLE
GO
"@
$simplerec = Invoke-SqlCmd -Query $simplerecoveryQ -Database master -ServerInstance localhost -ErrorAction continue -querytimeout 90 

#Disable metadata cache warmup
write-host "Disable metadata cache warmup..." -foregroundcolor yellow
$disablemetadatacacheyQ = @"
UPDATE SystemParameters SET ODataBuildMetadataCacheOnAosStartup = 0
"@
$disablemetadatacachey = Invoke-SqlCmd -Query $disablemetadatacacheyQ -Database AXDB -ServerInstance localhost -ErrorAction continue -querytimeout 90 

#sync DB
if ($syncans -eq 'Y'){
	Run-DBSync
}
else {write-host "Run DB sync if needed to complete database restore" -foregroundcolor CYAN}

#Start D365 services and IIS website/pools
startservices
Get-iisapppool | Where {$_.State -eq "Stopped"} | Start-WebAppPool
Get-iissite | Where {$_.State -eq "Stopped"} | Start-WebSite
write-host 
write-host "Database restore complete." -foregroundcolor green


}#end if check BACPAC
else {
write-host "BACPAC not found in $($sqlbakPath)." -ForegroundColor RED
}

}#end $goaheadans
remove-item $localfilename -force -ea 0
pause;exit
