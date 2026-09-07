#Restore SQL database 
$servicelist = @("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")
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
#---- Set variables ------
$SQLsrvName = 'localhost' #<-- if using named instance, set variable like: 'localhost\sqlexpress'
$RestoreDatabase ='AXDB'

#-------END VARIABLES. Do not change anything below this line -----

$simpleRecoveryMode = read-host "Restore database with [F]ULL or [S]imple Recovery mode?"
$cmplvlcheck = read-host "If Compatibilty mode of the restored database is lower than SQL instance, upgrade? (Y/N)"
$dateadd = get-date -f "yyyyMMMdd"

if ($RestoreDatabase -eq '<dbname>'){write-host 'Variables $RestoreDatabase is not set. Change the DB restorename and run script again.' -ForegroundColor Red;pause;exit}
Import-Module SQLPS -DisableNameChecking
cls

#check if DB restorename already exists
$checkexistingQ = @"
IF  EXISTS (SELECT 1 FROM sys.databases WHERE database_id = DB_ID(N'$RestoreDatabase'))
select 'true' as [checkexists]
"@
try {
$dbexists = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query $checkexistingQ -erroraction stop
}
catch {
write-host "Can't query the SQL instance '$SQLsrvName'" -ForegroundColor Red
write-host $_
pause
exit
}

$singlemodeQ = @"
ALTER DATABASE [AXDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:02';
ALTER DATABASE [AXDB] SET MULTI_USER WITH ROLLBACK IMMEDIATE;
WAITFOR DELAY '00:00:02';
"@

#if database already exists confirm overwrite.
if ($dbexists.checkexists -eq 'true'){
    write-host "WARNING! Database '$($RestoreDatabase)' already exists on SQL server '$($SQLsrvName)'." -ForegroundColor Yellow
    $overwrite = read-host "Overwrite? (Y/N)"
    if ($overwrite -eq 'n'){write-host "Restorescript stops here"-ForegroundColor yellow;pause;exit}

}




#Get SQL instance data-/log-/backuppaths
$localinstpathQ= @"
SELECT SERVERPROPERTY('INSTANCEDEFAULTDATAPATH') as [datapath], SERVERPROPERTY('INSTANCEDEFAULTLOGPATH') as [logpath],SERVERPROPERTY('INSTANCEDEFAULTBACKUPPATH') as [bakpath];
"@
$localdatapaths = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query $localinstpathQ
#SQL versions below 2019 don't have property for default backuppath. Use registry.
if ($localdatapaths.bakpath -notcontains '\'){
    $mssqlpath = Resolve-Path 'HKLM:\Software\Microsoft\Microsoft SQL Server\*' | where-object {$_ -like '*MSSQL*SQLSERVER*'}|Select-Object -ExpandProperty ProviderPath
    if ($mssqlpath){
        $localdatapaths.bakpath = get-itemproperty -path "Registry::$mssqlpath\MSSQLServer" -name BackupDirectory| select -ExpandProperty BackupDirectory
        $localdatapaths.bakpath = join-path $localdatapaths.bakpath "\"
    }
    else {$localdatapaths.bakpath = "c:\temp\"}
}#end if bakpath check


if ($localdatapaths){
 #Trim spaces from paths
$BAKpath = ($localdatapaths.bakpath).trim()
$TRNpath = ($localdatapaths.logpath).trim()
 #($localdatapaths.datapath).trim()

#Get latest BAK file  from the backup path $BAKpath
$BAKFile = Get-ChildItem "$BAKpath\*.bak" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-host "This script restores a database named $($RestoreDatabase) on $($SQLsrvName) from $($BAKpath)" -foregroundcolor Magenta
#check if we got a BAK file to process
if ($BAKFile){
write-host "Got BAK file $($BAKFile.name). Processing..." -foregroundcolor yellow
@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")| foreach {stop-service -name "$_" -force}
 

    #get the BAK file
    $localBakFile = Get-ChildItem "$($localdatapaths.bakpath)\*.bak"
    $localBakFile.lastwritetime = $BAKFile.lastwritetime
    
    #Extract logical name and physical path from bakfile
    $relocate = @()
    $dbfiles = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database tempdb -Query "RESTORE FILELISTONLY FROM DISK='$BAKFile';"
    
    #Loop through filelist, replace old paths with new restore paths
    foreach($dbfile in $dbfiles){
        $DbFileName = $dbfile.PhysicalName | Split-Path -Leaf
        if($dbfile.Type -eq 'L'){
            $newfile = Join-Path -Path ($localdatapaths.logpath) -ChildPath $DbFileName
            if (test-path $newfile){
                write-host "File already exists. Adding date to the physical filename"
                $newfile = [System.IO.Path]::GetDirectoryName($newfile) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($newFile) + "_" + $dateadd + ([System.IO.Path]::GetExtension($newFile))
            }
        } else {
            $newfile = Join-Path -Path ($localdatapaths.datapath) -ChildPath $DbFileName
            if (test-path $newfile){
                write-host "File already exists. Adding date to the physical filename"
                $newfile = [System.IO.Path]::GetDirectoryName($newfile) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($newFile) + "_" + $dateadd + ([System.IO.Path]::GetExtension($newFile))
            }
            
        }
        $relocate += New-Object Microsoft.SqlServer.Management.Smo.RelocateFile ($dbfile.LogicalName,$newfile)
    }#end foreach $dbfile

    #check if we got any TRN files
    $TRNFiles = Get-ChildItem "FileSystem::$TRNpath\*.trn" | Where-Object {$_.LastWriteTime -gt $BAKFile.lastwritetime} | select
    
    #Restore database with NoRecovery, we got TRN files to restore!
    if ($TRNFiles){
        #Replace database
        if ($dbexists.checkexists -eq 'true'){
            write-host "Please wait while restoring database '$($RestoreDatabase)' WITH REPLACE using BAK file $($localBAKFile.name)..." -foregroundcolor yellow
            Restore-SqlDatabase -ServerInstance $SQLsrvName -Database $RestoreDatabase -BackupFile $localbakFile -RelocateFile $relocate -RestoreAction Database -NoRecovery -ReplaceDatabase
            write-host "Restored database '$($RestoreDatabase)' using BAK file '$($localBAKFile.name)'." -foregroundcolor green
            remove-item $localbakFile
        }
        else {
            write-host "Please wait while restoring database '$($RestoreDatabase)' using BAK file '$($localBAKFile.name)'..." -foregroundcolor yellow
            Restore-SqlDatabase -ServerInstance $localSQLsrvName -Database $RestoreDatabase -BackupFile $localBAKFile -RelocateFile $relocate -RestoreAction Database -NoRecovery 
            write-host "Restored database '$($RestoreDatabase)' using BAK file '$($localBAKFile.name)'." -foregroundcolor green
            remove-item $localBAKFile
        }
        #process TRN files in sorted order (oldest>newest) after BAK restore
        $sortedTRNFiles = Get-ChildItem "FileSystem::$TRNpath\*.trn" | Where-Object {$_.LastWriteTime -gt $BAKFile.lastwritetime}| Sort-Object LastWriteTime | select
        write-host "Got $($sortedTRNFiles.count) TRN files to restore. Processing..." -foregroundcolor Yellow
            $i=1
            foreach ($TRNFile in $sortedTRNFiles){
                $destfilename = $TRNFile.name
                copy-item $TRNFile "$($localdatapaths.bakpath)\tempfiles\$destfilename"
                $trnbackupfile = gci "$($localdatapaths.bakpath)\tempfiles\$destfilename"
                $trnbackupfile.LastWriteTime = $TRNFile.LastWriteTime
                if($i -ne $sortedTRNFiles.count){
                    write-host "Please wait while restoring TRN file $($trnbackupfile.name)..." -foregroundcolor yellow
                    Restore-SqlDatabase -ServerInstance $SQLsrvName -Database $RestoreDatabase -BackupFile $trnbackupfile -NoRecovery -RestoreAction Log 
                    write-host "Restored TRN file $($trnbackupfile.name)." -foregroundcolor Green
                    remove-item $trnbackupfile
                 }
                else {
                    write-host "Please wait while restoring TRN file '$($trnbackupfile.name)'..." -foregroundcolor yellow
                    Restore-SqlDatabase -ServerInstance  $SQLsrvName -Database $RestoreDatabase -BackupFile $trnbackupfile -RestoreAction Log
                    write-host "Restored TRN file '$($trnbackupfile.name)'." -foregroundcolor Green
                    remove-item $trnbackupfile
                }
                $i++
            }#end foreach $remoteTRNfile
    }#end if remote TRN files check
   
    else {
    #Restore database with Recovery. No TRN restore is needed.
    if ($dbexists.checkexists -eq 'true'){
    #Write-host "Restarting SQL service..." -ForegroundColor yellow
    #Restart-Service -Force MSSQLSERVER
        Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query $singlemodeQ
        write-host "Please wait while restoring database '$($RestoreDatabase)' with REPLACE using BAK file '$($localBAKFile.name)'..." -foregroundcolor yellow
        Restore-SqlDatabase -ServerInstance $SQLsrvName -Database $RestoreDatabase -BackupFile $localBAKFile -RelocateFile $relocate -RestoreAction Database -ReplaceDatabase
        write-host "Restored database '$($RestoreDatabase)' using BAK file '$($localBAKFile.name)'." -foregroundcolor green
        #remove-item $localBAKFile
        }
       else {
        write-host "Please wait while restoring database using BAK file $($localBAKFile.name)..." -foregroundcolor yellow
        Restore-SqlDatabase -ServerInstance $SQLsrvName -Database $RestoreDatabase -BackupFile $localBAKFile -RelocateFile $relocate -RestoreAction Database 
        write-host "Restored database '$($RestoreDatabase)' using BAK file $($localbakFile.name)'." -foregroundcolor green
        $servicelist=@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")

        #remove-item $localBAKFile
        }

#reconnect SQL users
$sqlupdateDB = @{
'Database' = 'AXDB'
'serverinstance' = 'localhost'
'querytimeout' = 120
'query' = ""
'trustservercertificate' = $trustservercert
}
$sqlupdateDB.query = @"
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
	ALTER AUTHORIZATION ON database::[AXDB] TO sa

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


IF((SELECT 1 FROM SYS.CHANGE_TRACKING_DATABASES WHERE DATABASE_ID = DB_ID('AXDB')) IS NULL)
BEGIN
	ALTER DATABASE [AXDB] SET CHANGE_TRACKING = ON (CHANGE_RETENTION = 6 DAYS, AUTO_CLEANUP = ON)
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
Invoke-SqlCmd -Query $sqlupdateDB.query -serverinstance localhost -encrypt optional -trustservercertificate -database AXDB -querytimeout 180
write-host "Done remapping SQL users" -ForegroundColor green
write-host ""
        
startservices
Get-iisapppool | Where {$_.State -eq "Stopped"} | Start-WebAppPool
Get-iissite | Where {$_.State -eq "Stopped"} | Start-WebSite
    }
    write-host "Restoreprocess of database '$($RestoreDatabase)' complete." -foregroundcolor Green

    #Check CMP-LVL
    $cmplvlinst = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query "SELECT compatibility_level FROM sys.databases WHERE name = 'master';" | select -ExpandProperty compatibility_level
    $cmplvldb = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query "SELECT compatibility_level FROM sys.databases WHERE name = '$RestoreDatabase';" | select -ExpandProperty compatibility_level
    if ($cmplvldb -lt $cmplvlinst){
            if ($cmplvlcheck -eq 'y'){
                $setcmplvl = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query "ALTER DATABASE $RestoreDatabase SET COMPATIBILITY_LEVEL = $cmplvlinst;"
            }
       
    }#end if cmplvl check
    
    #Set simple mode
    if ($simpleRecoveryMode -eq 's'){
     $setsimple = Invoke-Sqlcmd -ServerInstance $SQLsrvName -Database master -Query "ALTER DATABASE $RestoreDatabase SET RECOVERY SIMPLE;"
     }
    pause
    exit

 }#end if $localdatapaths
 else {
 write-host "Couldn't get the SQL instance default data-/logpaths. Check the servernamevariable and/or connection." -foregroundcolor red;pause;exit
 }
}#end if Remote BAK file check
else {
write-host "No database BAK file found in $($BAKpath). Check the bak/trn path variables on top of the script" -ForegroundColor red;pause;exit
}#end else bak/trn path check
#SCRIPT END