#Powershellscript to download BAK/BACPAC from LCS and restore it as "AXDB" in Cloudhosted environments
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}

#------------Region Customer variables----------------------------------------------#
#Storage account/SAS URI that contains backupfile
$bloburi = "<paste SAS URL generated in LCS here>"

$downloadDBName = "Sandbox"
$FileTimeStamp = get-date -format "ddMMMyyyy"
$axdbadminpwd = ""
$downloadDBExt = ".bacpac"
$downloadDBFullName =  $downloadDBName+"_"+$FileTimeStamp+"$downloadDBExt"
if ($bloburi -match "LCS"){CLS;write-host;write-host "Please generate SAS URL in LCS and paste it in variable $bloburi first and run the script again." -ForegroundColor red;pause;exit}
#------------Region Global variables----------------------------------------------#
$servicelist = @("DynamicsAxBatch","MR2012ProcessService","W3SVC","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe")
$runpath = split-path -parent $PSCommandPath
$tempbackupdrive ='D:\'
$tempbackuppath ='backup\'
if (test-path "$tempbackupdrive"){
    if (!(test-path "$tempbackupdrive$tempbackuppath")){
        New-Item -ItemType Directory -Force -Path "$tempbackupdrive$tempbackuppath"
        }
    if(test-path "$tempbackupdrive$tempbackuppath"){$sqlbakPath = "$tempbackupdrive$tempbackuppath" }
    else {$sqlBakPath = 'c:\temp\'}
}
else {$sqlBakPath = 'c:\temp\'}

#----------------End Region Global variables---------------

#------------------------------Functions-------------------------------------------#

#Install AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){
Write-host "Installing AzCopy..." -ForegroundColor Yellow
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
Unblock-File $env:temp\AzCopy.zip
Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe"
remove-item $env:temp\AzCopy.zip -force
remove-item $env:temp\AzCopy -force -Recurse
}
else {
$azcopyupdate = & azcopy -h | select-string -pattern "newer version"
    if ($azcopyupdate){
    Write-host "Updating AzCopy..." -ForegroundColor Yellow
    $ProgressPreference = 'SilentlyContinue'
     Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe" -force
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
    }
}#end AZcopy  

function stopservices () {     
foreach ($service in $servicelist){
    $serviceobject = get-service -name $service -ea 0
    if ($serviceobject){
        stop-service $serviceobject -force
        $serviceobject.WaitForStatus("Stopped")
    }#end if $serviceobject
}#end foreach service
}#end function stopservices

function startservices () {
foreach ($service in $servicelist){
    $serviceobject = get-service -name $service -ea 0
    if ($serviceobject){
        start-service $serviceobject 
        $serviceobject.WaitForStatus("Running")
    }#end if $serviceobject
}#end foreach service
}#end function startservices

cls
function Import-Module-SQLPS {
    #pushd and popd to avoid import from changing the current directory (ref: http://stackoverflow.com/questions/12915299/sql-server-2012-sqlps-module-changing-current-location-automatically)
    #3>&1 puts warning stream to standard output stream (see https://connect.microsoft.com/PowerShell/feedback/details/297055/capture-warning-verbose-debug-and-host-output-via-alternate-streams)
    #out-null blocks that output, so we don't see the annoying warnings described here: https://www.codykonior.com/2015/05/30/whats-wrong-with-sqlps/
    push-location
    import-module sqlps 3>&1 | out-null
    pop-location
}
if(get-module sqlps){"yes"}else{"no"}
Import-Module-SQLPS

if(get-module sqlps){"yes"}else{"no"}
#------------------------------endregion function---------------------------------------#


write-host "Downloading file from LCS as $($downloadDBFullName) to $($sqlBakPath) ..." -ForegroundColor yellow
azcopy copy $BlobURI "$sqlBakPath$downloadDBFullName"  
write-host "Download finished." -ForegroundColor green

$Latest = ""
$restoremode=""
#BACPAC file
if (test-path "$sqlbakPath\*.bacpac"){
    
    $Latest = Get-ChildItem -Path $sqlbakPath | Where-Object {$_.name -like "*.bacpac"} | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $RestoreFile = $Latest.Name
    $restoremode="bacpac"
    
}

else {write-host "No backupfile of type .BACPAC found in $($sqlBakPath)" -foregroundcolor red;pause;exit}


#query check existing AXDB_org
write-host "Checking for existing AXDB_org..." -ForegroundColor yellow
$sqlcheckAXDB_orgQ= @"
If DB_ID('AXDB_Org') IS NOT NULL
BEGIN
DROP DATABASE [AXDB_Org]
WAITFOR DELAY '00:00:01'
END
"@
$dbcheckpreORG = Invoke-SqlCmd -Query $sqlcheckAXDB_orgQ -Database master -ServerInstance localhost -ErrorAction stop -querytimeout 180


#stop AX related services
stopservices
start-sleep 3


#query rename existing AXDB
write-host "Renaming existing AXDB to AXDB_org..." -ForegroundColor yellow
$sqlrenameAXDBq= @"
If DB_ID('axdb') IS NOT NULL
BEGIN
ALTER DATABASE [AXDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
ALTER DATABASE [AXDB] MODIFY NAME = AXDB_Org;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB_org] SET MULTI_USER;
END
"@

$dbcheckpre = Invoke-SqlCmd -Query $sqlrenameAXDBq -Database master -ServerInstance localhost -ErrorAction continue -querytimeout 90
write-host "Renamed existing AXDB to AXDB_org." -ForegroundColor green

write-host "Restoring $($restorefile) as AXDB..." -ForegroundColor yellow

#restore mode BACPAC
switch ($restoremode) {
"bacpac" {

   $bacpacexepath = Get-ChildItem -Path "C:\sqlpackagecore" -Filter SqlPackage.exe -EA 0 -Force | sort lastwritetime | select -last 1 -expandproperty directoryname
	If ($bacpacexepath -eq $null){
		$uri = "https://aka.ms/sqlpackage-windows"
        $ProgressPreference = 'SilentlyContinue'
        $request = Invoke-WebRequest -Uri $uri -MaximumRedirection 2 -ErrorAction 0 -OutFile c:\temp\sqlpackagecore.zip
        unblock-file c:\temp\sqlpackagecore.zip
        Expand-Archive c:\temp\sqlpackagecore.zip  c:\sqlpackagecore  -Force
        remove-item c:\temp\sqlpackagecore.zip
        $bacpacexepath = Get-ChildItem -Path "C:\sqlpackagecore" -Filter SqlPackage.exe -EA 0 -Force | sort lastwritetime | select -last 1 -expandproperty directoryname
	}
    write-host "Truncate tables in  BACPAC before restore..."
    Clear-D365TableDataFromBacpac -Path $sqlBakPath$RestoreFile -TableName "SECURITYOBJECTHISTORY","*Staging*","BatchHistory","SYSDATABASELOG*","ReqCalcTaskTrace" -ClearFromSource
    write-host "Restore of BACPAC takes awhile." -ForegroundColor yellow
    & "$bacpacexepath\SqlPackage.exe" /a:import /sf:$sqlBakPath$RestoreFile /tsn:localhost /tdn:AXDB /p:CommandTimeout=0 /p:DisableIndexesForDataPhase=FALSE /ttsc:True

}#end restoremode bacpac



default{"No restoremode set!";pause;exit}
}

start-sleep -s 5

#reconnect SQL users
$sqlupdateDB = @"
IF EXISTS (SELECT * FROM sys.database_principals WHERE name = N'axdeployuser')
DROP USER [axdeployuser]
GO
CREATE USER axdeployuser FROM LOGIN axdeployuser
EXEC sp_addrolemember 'db_owner', 'axdeployuser'

IF EXISTS (SELECT * FROM sys.database_principals WHERE name = N'axdbadmin')
DROP USER [axdbadmin]
GO
CREATE USER axdbadmin FROM LOGIN axdbadmin
EXEC sp_addrolemember 'db_owner', 'axdbadmin'

IF EXISTS (SELECT * FROM sys.database_principals WHERE name = N'axmrruntimeuser')
DROP USER [axmrruntimeuser]
GO
CREATE USER axmrruntimeuser FROM LOGIN axmrruntimeuser
EXEC sp_addrolemember 'db_datareader', 'axmrruntimeuser'
EXEC sp_addrolemember 'db_datawriter', 'axmrruntimeuser'

IF EXISTS (SELECT * FROM sys.database_principals WHERE name = N'axretaildatasyncuser')
DROP USER [axretaildatasyncuser]
GO
CREATE USER axretaildatasyncuser FROM LOGIN axretaildatasyncuser
EXEC sp_addrolemember 'DataSyncUsersRole', 'axretaildatasyncuser'


IF EXISTS (SELECT * FROM sys.database_principals WHERE name = N'axretailruntimeuser')
DROP USER [axretailruntimeuser]
GO
CREATE USER axretailruntimeuser FROM LOGIN axretailruntimeuser
EXEC sp_addrolemember 'UsersRole', 'axretailruntimeuser'
EXEC sp_addrolemember 'ReportUsersRole', 'axretailruntimeuser'

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


ALTER DATABASE [axdb] SET CHANGE_TRACKING = ON (CHANGE_RETENTION = 6 DAYS, AUTO_CLEANUP = ON)
ALTER USER axdeployuser with login = axdeployuser;
"@

write-host "Remapping SQL users..." -ForegroundColor yellow
Invoke-SqlCmd -Query $sqlupdateDB -ServerInstance localhost -Database axdb -ErrorAction Continue -querytimeout 240
write-host "Done remapping SQL users. (ignore any red error messages on console output)" -ForegroundColor green
write-host "Database import done." -ForegroundColor green
write-host "Set AXDB to SIMPLE Recovery mode..."
Invoke-Sqlcmd -ServerInstance localhost -Database master -Query "ALTER DATABASE AXDB SET RECOVERY SIMPLE;" -ErrorAction Continue -querytimeout 120
start-sleep -s 3
#start AX related services
write-host "Starting AX related service after database restore..." -ForegroundColor yellow
startservices
write-host 'Started AX related service after database restore. ' -ForegroundColor green
write-host 'Test login into the environment. It will take some time to "warmup" during first login.' -ForegroundColor green
 $aossite = (get-d365url).url
 start-process $aossite 

pause
exit
