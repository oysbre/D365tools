#Powershellscript to download BAK/BACPAC from LCS and restore it as "AXDB" in Cloudhosted environments
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}


#------------Region DEV variables----------------------------------------------#
# vvvv In LCS, checkmark the databasename left of the name and then click "Generate SAS link" vvv. Paste the SASURL in variable $URl below.
$URL = "<paste URL here>"  
$localfilename = "D:\temp\DEV.BACPAC"  # << full local filepath aka D:\temp\tempdev.bacpac

#tablenames cleaned before restore av BACPAC. remove tablename in list if needed
#tablenames cleaned before restore av BACPAC. remove tablename in list if needed
$commontablestoclear = @("SECURITYOBJECTHISTORY","*Staging*","dbo.BATCHHISTORY","BATCHJOBHISTORY","SYSDATABASELOG","ReqCalcTaskTrace")
$customtablestoclear = @("LACARCHIVERESENDDATA","LACARCHIVEDATA","BISWSHISTORY","DTA_*","LACARCHIVEREF","BISMESSAGEHISTORYHEADER","BISHISTORYENTITY") #add custom tables to clear from bacpac


#------------Region GLOBAL variables----------------------------------------------#
$tablestoclear = $commontablestoclear + $customtablestoclear
$newDBname = "importeddatabase_$((Get-Date).tostring("ddMMMyyyy"))" 
$servicelist = @("DynamicsAxBatch","MR2012ProcessService","W3SVC","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe")
$sqlbakPath =  split-path -parent $localfilename 
#--------------------

function Get-UrlStatusCode([string] $Urlcheck) {
    try {  (Invoke-WebRequest -Uri $Urlcheck -UseBasicParsing -DisableKeepAlive -method head).StatusCode }
    catch [Net.WebException]  { [int]$_.Exception.Response.StatusCode  }
}#end function URL test


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


#Set PSGallery as trusted repo
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
if ((get-packageprovider nuget) -eq $NULL){
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#stop using powershellmodule SQLPS in this session - outdated
Remove-Module SQLPS -ea 0

#install module sqlserver to use "new" invoke-sqlcmd
if((Get-Module sqlserver -ListAvailable) -eq $null){
    Write-host "Installing PS module sqlserver..." -foregroundcolor yellow
    Install-Module sqlserver -Force -AllowClobber
}

function Import-Module-SQLServer {
push-location
import-module sqlserver 3>&1 | out-null
pop-location
}#end function Import-Module-SQLServer

if(get-module sqlserver){"yes"}else{"no"}
Import-Module-SQLServer
 
if(get-module sqlserver){"yes"}else{"no"}
Import-Module-SQLServer



#install/update d365fo.tools
if(-not (Get-Module d365fo.tools -ListAvailable)){
    Write-host "Installing D365fo.tools..." -foregroundcolor yellow
    Install-Module d365fo.tools -Force
}
else {
    $releases = "https://api.github.com/repos/d365collaborative/d365fo.tools/releases"
    $tagver = ((Invoke-WebRequest $releases -ea 0 -UseBasicParsing | ConvertFrom-Json)[0].tag_name).tostring()
        if ($tagver){
            $fover = (get-installedmodule d365fo.tools).version.tostring()
            if ([System.Version]$tagver -gt [System.Version]$fover){
             Write-host "Updating D365fo.tools..." -foregroundcolor yellow
             Update-Module -name d365fo.tools -Force
            }#end if gt version check
        }#end if tagver 
}#end else


#get SQL version and set parameter trustservercert
$inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
foreach ($i in $inst)
{
   $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
   $sqlver += (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
}
$sqlver = $sqlver | sort desc
if ($sqlver -ge 16){
$trustservercert = 1
}

cls
if ($URL -eq "<paste URL here>"){write-host "Set SASURL from LCS in variable '$URL' and try again." -foregroundcolor yellow;pause;exit}
if ($localfilename -eq "<local fullpathname here>"){write-host "Set local pathname with filename aka: D:\dev.bacpac in variable '$localfilename'" -foregroundcolor yellow;pause;exit}
write-host "Using variables: " -ForegroundColor Magenta
write-host "URL: $($URL)"
write-host "NewDBname: $($newDBname)"
write-host "Localfilename: $($localfilename)"
write-host "TablesToClear: $($tablestoclear)"
write-host ""
write-host "This script will now restore BACPAC, switch the existing AXDB and quit VS/SSMS applications. Continue? [Y/N]" -ForegroundColor Yellow;$goaheadans = read-host
if ($goaheadans -eq 'y'){

#Install/update AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){
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

#download from SASURL2Local
$statuscode = Get-UrlStatusCode -urlcheck $URL
if ($statuscode -eq 200){
    write-host "Downloading file from LCS to $($localfilename)..." -ForegroundColor yellow
    azcopy copy $URL $localfilename
}
else {write-host "Error in URL $($url ): " $($statuscode);pause;exit}

#Check for BACPAC
$Latest = Get-ChildItem -Path $sqlbakPath -ea 0 -filter "*.bacpac" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

#check if we got a BACPAC
if ($Latest){
$RestoreFile = $Latest.Name
write-host "Using BACPAC file $($RestoreFile)." -ForegroundColor yellow

#get latest SQLPACKAGE
$bacpacexepath = Get-ChildItem -Path "C:\sqlpackagecore" -Filter SqlPackage.exe -EA 0 -Force | sort lastwritetime | select -last 1 -expandproperty directoryname
If ($bacpacexepath -eq $null){
    write-host "Installing latest SQLPACKAGE to C:\SQLPACKAGECORE..." -ForegroundColor yellow
    remove-item $env:temp\sqlpackagecore.zip -force -ea 0
    $uri = "https://aka.ms/sqlpackage-windows"
    $request = Invoke-WebRequest -Uri $uri -MaximumRedirection 2 -ErrorAction 0 -OutFile $env:temp\sqlpackagecore.zip
    unblock-file $env:temp\sqlpackagecore.zip
    Expand-Archive $env:temp\sqlpackagecore.zip  c:\sqlpackagecore  -Force
    remove-item $env:temp\sqlpackagecore.zip -force -ea 0
    $bacpacexepath = Get-ChildItem -Path "C:\sqlpackagecore" -Filter SqlPackage.exe -EA 0 -Force | sort lastwritetime | select -last 1 -expandproperty directoryname
}
write-host 'Truncating tables from variable $tablestoclear in BACPAC before restore/import ...' -ForegroundColor Yellow
Clear-D365BacpacTableData -Path "$sqlbakPath\$RestoreFile" -TableName $tablestoclear -ClearFromSource -ErrorAction SilentlyContinue
write-host ""
write-host "Restore of BACPAC takes awhile. Please wait..." -ForegroundColor yellow
write-host ""
& "$bacpacexepath\SqlPackage.exe" /a:import /sf:"$sqlbakPath\$RestoreFile" /tsn:localhost /tdn:$newDBname /p:CommandTimeout=0 /p:DisableIndexesForDataPhase=FALSE /ttsc:True

start-sleep -s 2

#query check if new DB exists
$sqlCheckNewdatabaseQ= @"
IF DB_ID('$newDBname') IS NULL
BEGIN
SELECT 'Oh no! Something bad just happened'
END
"@

$newdbcheck = Invoke-SqlCmd -Query $sqlCheckNewdatabaseQ -Database master -ServerInstance localhost -ErrorAction Continue -querytimeout 90 -trustservercertificate


if ($newdbcheck.column1 -match "Something"){
write-host "Database $($newDBname) don't exist in SQL. BACPAC restore failed? Check errors and try again." -ForegroundColor RED;pause;exit
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

CREATE USER axdeployuser FROM LOGIN axdeployuser
EXEC sp_addrolemember 'db_owner', 'axdeployuser'

CREATE USER axdbadmin FROM LOGIN axdbadmin
EXEC sp_addrolemember 'db_owner', 'axdbadmin'

CREATE USER axmrruntimeuser FROM LOGIN axmrruntimeuser
EXEC sp_addrolemember 'db_datareader', 'axmrruntimeuser'
EXEC sp_addrolemember 'db_datawriter', 'axmrruntimeuser'

CREATE USER axretaildatasyncuser FROM LOGIN axretaildatasyncuser

CREATE USER axretailruntimeuser FROM LOGIN axretailruntimeuser

CREATE USER axdeployextuser FROM LOGIN axdeployextuser

CREATE USER [NT AUTHORITY\NETWORK SERVICE] FROM LOGIN [NT AUTHORITY\NETWORK SERVICE]
EXEC sp_addrolemember 'db_owner', 'NT AUTHORITY\NETWORK SERVICE'

UPDATE T1
SET T1.storageproviderid = 0
    , T1.accessinformation = ''
    , T1.modifiedby = 'Admin'
    , T1.modifieddatetime = getdate()
FROM docuvalue T1
WHERE T1.storageproviderid = 1 --Azure storage

DROP PROCEDURE IF EXISTS SP_ConfigureTablesForChangeTracking
DROP PROCEDURE IF EXISTS SP_ConfigureTablesForChangeTracking_V2
GO
-- Begin Refresh Retail FullText Catalogs
DECLARE @RFTXNAME NVARCHAR(MAX);
DECLARE @RFTXSQL NVARCHAR(MAX);
DECLARE retail_ftx CURSOR FOR
SELECT OBJECT_SCHEMA_NAME(object_id) + '.' + OBJECT_NAME(object_id) fullname FROM SYS.FULLTEXT_INDEXES
    WHERE FULLTEXT_CATALOG_ID = (SELECT TOP 1 FULLTEXT_CATALOG_ID FROM SYS.FULLTEXT_CATALOGS WHERE NAME = 'COMMERCEFULLTEXTCATALOG');
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

--Begin create retail channel database record--
declare @ExpectedDatabaseName nvarchar(64) = 'Default';
declare @DefaultDataGroupRecId BIGINT;
declare @ExpectedDatabaseRecId BIGINT; 
IF NOT EXISTS (select 1 from RETAILCONNDATABASEPROFILE where NAME = @ExpectedDatabaseName)
BEGIN 
	select @DefaultDataGroupRecId = RECID from RETAILCDXDATAGROUP where NAME = 'Default'; 
	insert into RETAILCONNDATABASEPROFILE (DATAGROUP, NAME, CONNECTIONSTRING, DATASTORETYPE)
	values (@DefaultDataGroupRecId, @ExpectedDatabaseName, NULL, 0); 
	select @ExpectedDatabaseRecId = RECID from RETAILCONNDATABASEPROFILE where NAME = @ExpectedDatabaseName; 
	insert into RETAILCDXDATASTORECHANNEL (CHANNEL, DATABASEPROFILE)
	select RCT.RECID, @ExpectedDatabaseRecId from RETAILCHANNELTABLE RCT
	inner join RETAILCHANNELTABLEEXT RCTEX on RCTEX.CHANNEL = RCT.RECID
        update RETAILCHANNELTABLEEXT set LIVECHANNELDATABASE = @ExpectedDatabaseRecId where LIVECHANNELDATABASE = 0
END; 
--End create retail channel database record
"@

#Remap SQL users
write-host "Remapping SQL users..." -ForegroundColor yellow
Invoke-SqlCmd -Query $sqlupdateDBQ -ServerInstance localhost -Database $newDBname -ErrorAction Continue -querytimeout 0 -trustservercertificate
write-host "Done remapping SQL users. (ignore any red error messages on console output)" -ForegroundColor green
write-host ""

write-host "Enabling change tracking..." -ForegroundColor Yellow
$changetrackQ= @"
ALTER DATABASE [$newDBname] SET CHANGE_TRACKING = ON (CHANGE_RETENTION = 6 DAYS, AUTO_CLEANUP = ON);
"@
Invoke-SqlCmd -Query $changetrackQ -ServerInstance localhost -Database master -ErrorAction Continue -querytimeout 0 -trustservercertificate
write-host "Database import done." -ForegroundColor green
write-host ""

stopservices

#Check if VS and/or SSMS and kill processes
$vs = taskkill /im devenv.exe /f
$ssms = taskkill /im ssms.exe /f

#Disable management reporter
write-host "Disabling Management reporter service..." -ForegroundColor Yellow
get-service | Where-Object {$_.Name -eq "MR2012ProcessService"} | Set-Service -StartupType Disabled

#query check if new AXDB_org exists
$sqlDropAXDB_orgQ= @"
IF DB_ID('AXDB_org') IS NOT NULL
BEGIN
ALTER DATABASE [AXDB_org] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB_org] SET MULTI_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:02';
DROP DATABASE axdb_org;
END
"@
write-host "Dropping AXDB_org if exists..." -ForegroundColor yellow
$dbcheckpre = Invoke-SqlCmd -Query $sqlDropAXDB_orgQ -Database master -ServerInstance localhost -ErrorAction Continue -querytimeout 90 -trustservercertificate

#query rename existing AXDB
write-host "Renaming AXDB to AXDB_org and $($newdbname) to AXDB..." -ForegroundColor yellow
$sqlrenameorgAXDBq = @"
IF DB_ID('AXDB') IS NOT NULL
BEGIN
ALTER DATABASE [AXDB] SET AUTO_CLOSE OFF;
ALTER DATABASE [AXDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF;
ALTER DATABASE [AXDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
ALTER DATABASE [AXDB] MODIFY NAME = AXDB_Org;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB_org] SET MULTI_USER;
ALTER DATABASE [AXDB_org] SET AUTO_UPDATE_STATISTICS_ASYNC ON;
END
"@

$sqlrenameAXDBq= @"
ALTER DATABASE [$newDBname] SET AUTO_UPDATE_STATISTICS_ASYNC OFF;
ALTER DATABASE [$newDBname] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [$newDBname] MODIFY NAME = AXDB;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB] SET MULTI_USER;
ALTER DATABASE [AxDB] SET AUTO_UPDATE_STATISTICS_ASYNC ON;
ALTER DATABASE [AXDB] SET AUTO_CLOSE OFF;
ALTER DATABASE [AXDB] SET RECOVERY SIMPLE;
"@

$renameorgaxdb = Invoke-SqlCmd -Query $sqlrenameorgAXDBq -Database master -ServerInstance localhost -ErrorAction continue -querytimeout 90 -trustservercertificate
$renamenewaxdb = Invoke-SqlCmd -Query $sqlrenameAXDBq -Database master -ServerInstance localhost -ErrorAction continue -querytimeout 90 -trustservercertificate
write-host "Renamed existing AXDB to AXDB_org and $($newDBname) as AXDB." -ForegroundColor green
write-host ""

#disable BIS triggers
write-host "Disabling To-Increase BIS triggers..." -ForegroundColor yellow
$DisableBIStriggersQ = @"
IF OBJECT_ID(N'tempdb..#Results') IS NOT NULL
BEGIN
DROP TABLE #Results
END
 
SELECT 'ALTER TABLE '+ (select Schema_name(schema_id) from sys.objects o 
where o.object_id = parent_id) + '.'+object_name(parent_id) + ' DISABLE TRIGGER '+
Name as DisableTriggerScript into #Results
from sys.triggers t 
where t.is_disabled = 0 and t.name like 'BisT%'
 
DECLARE @isql nvarchar(max)
DECLARE c1 CURSOR LOCAL FORWARD_ONLY STATIC READ_ONLY for
SELECT *
FROM #Results
open c1
fetch next from c1 into @isql
While @@fetch_status <> -1
BEGIN
exec(@isql)
fetch next from c1 into @isql
END
close c1
deallocate c1
"@

Invoke-SqlCmd -Query $DisableBIStriggersQ -ServerInstance localhost -Database AXDB -ErrorAction Continue -querytimeout 0 -trustservercertificate


#fix rowversion in kernel tables bug
$rowversionfixQ = @"
DECLARE @KernelTables TABLE (
        TableName NVARCHAR(200),
        TableNumber Int);
DECLARE @ResultKernelTables TABLE (
        TableNumber Int);

-- List of all Kernel Tables, with a unique TableNumber
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('SQLDICTIONARY',1)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('SYSCONFIG',2)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('USERINFO',3)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('SECURITYROLE',4)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('DATABASELOG',5)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('AOSDUPLICATEKEYEXCEPTIONMESSAGE',6)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('TIMEZONESLIST',7)
INSERT INTO @KernelTables(TableName, TableNumber) VALUES('TIMEZONESRULESDATA',8)

-- get the KernelTable names
DECLARE KernelTableName_cursor CURSOR LOCAL FOR
SELECT TableName, TableNumber
FROM @KernelTables
-- (-1) : Exception happened
-- 0  : Dropped no column
-- 1  : Dropped atleast one Kernel Table column

DECLARE @Result INT = 0;
DECLARE @KernelTableName NVARCHAR(200);
DECLARE @KernelTableNumber INT;
DECLARE @SqlCmd NVARCHAR(500);
BEGIN TRY
    BEGIN TRANSACTION T1
		OPEN KernelTableName_cursor;
		FETCH NEXT FROM KernelTableName_cursor INTO @KernelTableName, @KernelTableNumber;

		WHILE @@FETCH_STATUS = 0
			BEGIN
				IF COL_LENGTH(@KernelTableName, 'SYSROWVERSIONNUMBER') IS NOT NULL
					BEGIN
                        SET @SqlCmd = 'ALTER TABLE dbo.' + @KernelTableName + ' DROP COLUMN SYSROWVERSIONNUMBER';
						EXEC sp_executesql @SqlCmd;
						SET @Result = 1;
						INSERT INTO @ResultKernelTables(TableNumber) VALUES(@KernelTableNumber);
					END

				FETCH NEXT FROM KernelTableName_cursor INTO @KernelTableName, @KernelTableNumber;
			END

    COMMIT TRANSACTION T1

    SELECT @Result AS Result, TableNumber AS KernelTableNumber, 0 AS Error, '' AS ErrorMessage
    FROM @ResultKernelTables;

END TRY

BEGIN CATCH
    SELECT -1 AS Result, -1 AS KernelTableNumber, ERROR_NUMBER() as Error, ERROR_MESSAGE() as ErrorMessage
    ROLLBACK TRANSACTION T1
END CATCH
"@

Invoke-SqlCmd -Query $rowversionfixQ -ServerInstance localhost -Database AXDB -ErrorAction Continue -querytimeout 0 -trustservercertificate


#Start D365 services
startservices
write-host 'Started AX related service after database restore. ' -ForegroundColor green


}#end if check BACPAC
else {
write-host "BACPAC not found in $($sqlbakPath)." -ForegroundColor RED
}

}#end $goaheadans

write-host 'Run DBsync from Visual Studio after database restore.' -ForegroundColor green
 
pause
exit
