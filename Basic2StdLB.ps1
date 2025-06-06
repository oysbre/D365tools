#Migrate VM loadbalancer SKU from Basic to Standard
#https://learn.microsoft.com/en-us/azure/load-balancer/upgrade-basic-standard-with-powershell

#Force Powershell to run as admin
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}

#Install module "AzureBasicLoadBalancerUpgrade"
if (-not(Get-InstalledModule -name AzureBasicLoadBalancerUpgrade )){
  Install-Module -Name AzureBasicLoadBalancerUpgrade -Repository PSGallery -Force
}

#Customer details - fill in tenantID and subscription as minimum requirement. User must have appropriate roles and access in Entra.
$tenantid = '<GUID>'   # Entra ID tenant GUID
$subscription = '<Subscription>' # Subscription where VM's resides
$appId = '<GUID>' #Serviceprincipal APP ID
$secretId = '<Secret>' #Serviceprincipal secret

#Static details
$outboundRuleName= "http-outbound-rule"

## BEGIN ##
#Import-Module az
$SecureStringPwd = $secretId | ConvertTo-SecureString -AsPlainText -Force
$pscredential = New-Object -TypeName System.Management.Automation.PSCredential @($appId, $SecureStringPwd)
write-host "Connect to Azure with Serviceprincipal or Regular EntraID user? S/R" -foregroundcolor Yellow ;$readansazure=read-host
if ($readansazure -eq "S"){
Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantid -Subscription $subscription # -debug
}
elseif ($readansazure -eq "R"){
Connect-AzAccount -Tenant $tenantid -Subscription $subscription # -debug
}
else {write-host "Choose R or S as valid input. Run script again." -foregroundcolor RED;pause;exit}

#Create logdir for migration
$LBlog = "c:\LBlog"
if (-not(test-path $LBlog)){
    new-item $LBlog -ItemType Directory | out-null
}

#Get all VMs
$vms = @()
$vms = get-azvm

if ($vms -is [array]){
    foreach ($vm in $vms){
        $resourceGroupName = ""
        $resourceGroupName = $($vm.resourcegroupname)
        #Check Loadbalancer SKU of the VM is Basic or not.
        if ((get-azloadbalancer -resourcegroupname $resourceGroupName).Sku.Name -eq "Basic"){
        
            #Migrate Basic to Standard IP
            write-host "Migrating LB SKU to Standard for VM $($vm.name)..." -ForegroundColor yellow
            $loadBalancerName = (get-azloadbalancer -resourcegroupname $($vm.resourcegroupname)).Name
            Start-AzBasicLoadBalancerUpgrade -ResourceGroupName $resourceGroupName -BasicLoadBalancerName $loadBalancerName -FollowLog -RecoveryBackupPath $LBlog -skipDowntimeWarning
            
            #Backendpool
            $backendPoolName = "$($vm.name)-backend-pool"
            $loadBalancer = Get-AzLoadBalancer -ResourceGroupName $resourceGroupName -Name $loadBalancerName
            $backendPool = New-AzLoadBalancerBackendAddressPoolConfig -Name $backendPoolName
            $nic = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName
            $ipConfig = $nic.IpConfigurations | Where-Object { $_.PrivateIpAddress -ne $null }
            $ipConfig.LoadBalancerBackendAddressPools.Add($backendPool)
            $loadBalancer.BackendAddressPools.Add($backendPool)
            $frontendIPConfig = $loadBalancer.FrontendIpConfigurations
            $outboundRule = New-AzLoadBalancerOutboundRuleConfig -Name $outboundRuleName -BackendAddressPool $backendPool -FrontendIpConfiguration $frontendIPConfig -Protocol All -IdleTimeoutInMinutes 4 -AllocatedOutboundPort 1000
            $loadBalancer.OutboundRules.Add($outboundRule)
            Set-AzLoadBalancer -LoadBalancer $loadBalancer
            Set-AzNetworkInterface -NetworkInterface $nic
                        
        }#end if basic LB sku
    }#end foreach
}#end if array
