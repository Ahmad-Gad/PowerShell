# Script Type: Function
# Name: Set-SecurityProtocol
# Description:  Enable or Disable security protocol. E.g. SSL 3.0, TLS 1.1, etc by adding, modifying or removing the relevant registry keys/values withing the registry key "HKLM SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols".
# Author: Ahmad Gad
# Contact Email: ahmad.gad@outlook.ie, ahmad.adel@jemmail.com
# Version: 1.1
# WebSite: https://github.com/Ahmad-Gad/PowerShell
# Created On: 07/03/2019
# Updated On: 07/03/2019
# Date Format: DD/MM/YYYY
# Minimum PowerShell Version: 2.0
# Minimum CLR Version: 2.0
# PowerShell Core Supported: Yes
# Important Notes:
#        1. When possible, instead of editing the registry directly, use Group Policy or other Windows tools such as the Microsoft Management Console (MMC) to accomplish tasks. If you must edit the registry, use extreme caution.
#           https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
#        2. It's HIGHLY/STRICTLY recommended to keep the "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" and "DTLS 1.0" disabled due to the protocol vulnerabilities in these versions. If you insist to turn them on for any reason, DO IT WITH YOUR OWN RISK WITHOUT ANY RESPONSIBILITY OR BLAME ON THE SCRIPT's AUTHOR.
#           Actually one of the reasons for writing this script, is to make sure that all these breached protocols are disabled for good!
#           Please refer to these official articles/announcments:
#            https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
#            https://docs.microsoft.com/en-us/security/solving-tls1-problem
#            https://support.microsoft.com/en-us/help/3117336/schannel-implementation-of-tls-1-0-in-windows-security-status-update-n
#            https://www.openssl.org/~bodo/ssl-poodle.pdf
#            http://www.isg.rhul.ac.uk/~kp/Darmstadt.pdf
#            https://support.microsoft.com/en-ie/help/187498/how-to-disable-pct-1-0-ssl-2-0-ssl-3-0-or-tls-1-0-in-internet-informat
#            https://knowledge.digicert.com/solution/SO8994.html
#        3. The time this script has been written, the "TLS 1.3" and "DTLS 1.3" were not part of any Windows version yet, hence, make sure that your Windows supports these protocols when using any of them.
#        4. The Datagram Transport Layer Security 1.0 (DTLS 1.0) is based on TLS 1.1, and DTLS 1.2 is based on TLS 1.2.
#        5. There is no "DTLS 1.1"; that version number was skipped in order to harmonize version numbers with TLS.
#           More info about the Datagram Transport Layer Security (DTLS):
#           https://docs.microsoft.com/en-us/windows-server/security/tls/datagram-transport-layer-security-protocol
#	Examples:
#	---------
#	.\Set-SecurityProtocol.ps1 -SecurityProtocol 'TLS 1.2' -ServiceType Both -Action Revoke;
#	.\Set-SecurityProtocol.ps1 -SecurityProtocol 'TLS 1.2' -ServiceType Server -Action Enable -DisabledByDefault False;
#	.\Set-SecurityProtocol.ps1 -SecurityProtocol 'TLS 1.0' -ServiceType Client -Action Disable -DisabledByDefault True;
#	.\Set-SecurityProtocol.ps1Set-SecurityProtocol -SecurityProtocol 'AllVulnerableProtocols' -ServiceType Both -Action Disable -DisabledByDefault True;
#   For further details, please run "Get-Help .\Set-SecurityProtocol.ps1 -Full;";

<#
      .SYNOPSIS
        Enable or Disable security protocol. E.g. SSL 3.0, TLS 1.1, etc.
      .DESCRIPTION
        Enable or Disable security protocol. E.g. SSL 3.0, TLS 1.1, etc by adding, modifying or removing the relevant registry keys/values withing the registry key "HKLM SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols".
      .INPUTS
        The Security Protocol Name (SSL 3.0, TLS 1.1, etc), Service Type (Client, Server or Both), Required action (Enable, Disable, Revoke) and the action against the "DisabledByDefault" flag as "True, False or Revoke".
      .OUTPUTS
        Boolean
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'TLS 1.2' -ServiceType Both -Action Revoke;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'TLS 1.2' -ServiceType Client -Action Revoke -DisabledByDefault Revoke;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'TLS 1.2' -ServiceType Server -Action Enable -DisabledByDefault True;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'DTLS 1.0' -ServiceType Client -Action Disable -DisabledByDefault True;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'PCT 1.0' -ServiceType Both -Action Disable -DisabledByDefault True;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'AllVulnerableProtocols' -ServiceType Both -Action Disable -DisabledByDefault True;
      .PARAMETER SecurityProtocol
        Alias: SP
        Data Type: System.String[]
        Mandatory: True
        Description: The target Security Protocol/Protocols as an array of valid list string.
        Example(s): "SSL 3.0", "TLS 1.1"
        Default Value: N/A
        Notes:
              1. It's HIGHLY/STRICTLY recommended to keep the "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" and "DTLS 1.0" disabled 
                 due to the protocol vulnerabilities in these versions.
                 If you insist to turn them on for any reason, DO IT WITH YOUR OWN RISK WITHOUT ANY RESPONSIBILITY OR BLAME ON THE SCRIPT's AUTHOR.
                 Actually one of the reasons for writing this script, is to make sure that all these breached protocols are disabled for good!
                 Please refer to these official articles/announcments:
                   https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
                   https://docs.microsoft.com/en-us/security/solving-tls1-problem
                   https://support.microsoft.com/en-us/help/3117336/schannel-implementation-of-tls-1-0-in-windows-security-status-update-n
                   https://www.openssl.org/~bodo/ssl-poodle.pdf
                   http://www.isg.rhul.ac.uk/~kp/Darmstadt.pdf
                   https://support.microsoft.com/en-ie/help/187498/how-to-disable-pct-1-0-ssl-2-0-ssl-3-0-or-tls-1-0-in-internet-informat
                   https://knowledge.digicert.com/solution/SO8994.html
              2. If you want to do an action on all the Vulnerable Protocols list as highlighted in the previous point, 
                 you can use the value "AllVulnerableProtocols".
                 You can use it as a quick action to disable all listed Vulnerable Protocols in one line of command.
                 The list of those Vulnerable Protocols are hard coded inside the function, and could require an update every 
                 while in case if other Security Protocol has been known to be breached.
              3. The time this script has been written, the "TLS 1.3" and "DTLS 1.3" were not part of any Windows version yet, 
                 hence, make sure that your Windows supports this protocol.
              4. The Datagram Transport Layer Security 1.0 (DTLS 1.0) is based on TLS 1.1, and DTLS 1.2 is based on TLS 1.2.
              5. There is no "DTLS 1.1"; that version number was skipped in order to harmonize version numbers with TLS.
                 More info about the Datagram Transport Layer Security (DTLS):
                 https://docs.microsoft.com/en-us/windows-server/security/tls/datagram-transport-layer-security-protocol
      .PARAMETER ServiceType
        Alias: ST
        Data Type: System.String
        Mandatory: True
        Description: The service type as "Client", "Server" or both together.
        Example(s): "Client", "Server", "Both".
        Default Value: If "Both" is specified, the same configuration will be typically applied on both "Client" and "Server".
        Notes: N/A
      .PARAMETER Action
        Alias: A
        Data Type: System.String
        Mandatory: True
        Description: The action to be taken against this service as "Enable", "Disable", "Revoke" or "PersistOnly".
        Example(s): "Enable", "Disable", "Revoke", "PersistOnly"
        Default Value: N/A
        Notes: If "Revoke" is specified, the relevant "DWORD" value will be removed from the relevant registry key.
               Usually this action is taken to let the Windows follow the current policy applied.
               
               If "PersistOnly" is specified, the relevant registry key for the Secutity Prvoider with the sub key 
               (Client, Server or both) will be just created if not exit without configuring any value inside them.
               This is required if the "DisabledByDefault" flag will be specified and the user needs to configure only this 
               flag without the need to explicitly Enable or Disable the protocol.
               For more info about this flag, please refer to the this article:
               https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

      .PARAMETER DisabledByDefault
        Alias: D
        Data Type: System.String
        Mandatory: False
        Description: When DisabledByDefault flag is set to "True", the specified security protocol is not used by default.
                     If an SSPI app requests to use this  security protocol, it will be negotiated.
        Example(s): "True", "False", "Revoke"
        Default Value: N/A
        Notes: If "Revoke" is specified, the relevant "DWORD" value will be removed from the relevant registry key.
               Usually this action is taken to let the Windows OS follow the current policy applied.

               For more info about this flag, please refer to the this article:
               https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
      .NOTES
        1. When possible, instead of editing the registry directly, use Group Policy or other Windows tools such as the 
           Microsoft Management Console (MMC) to accomplish tasks. If you must edit the registry, use extreme caution.
           https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
        2. It's HIGHLY/STRICTLY recommended to keep the "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" and "DTLS 1.0" disabled 
           due to the protocol vulnerabilities in these versions.
           If you insist to turn them on for any reason, DO IT WITH YOUR OWN RISK WITHOUT ANY RESPONSIBILITY OR BLAME ON THE SCRIPT's AUTHOR.
           Actually one of the reasons for writing this script, is to make sure that all these breached protocols are disabled for good!
           Please refer to these official articles/announcments:
            https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
            https://docs.microsoft.com/en-us/security/solving-tls1-problem
            https://support.microsoft.com/en-us/help/3117336/schannel-implementation-of-tls-1-0-in-windows-security-status-update-n
            https://www.openssl.org/~bodo/ssl-poodle.pdf
            http://www.isg.rhul.ac.uk/~kp/Darmstadt.pdf
            https://support.microsoft.com/en-ie/help/187498/how-to-disable-pct-1-0-ssl-2-0-ssl-3-0-or-tls-1-0-in-internet-informat
            https://knowledge.digicert.com/solution/SO8994.html
        3. The time this script has been written, the "TLS 1.3" and "DTLS 1.3" were not part of any Windows version yet, 
           hence, make sure that your Windows supports these protocols when using any of them.
        4. The Datagram Transport Layer Security 1.0 (DTLS 1.0) is based on TLS 1.1, and DTLS 1.2 is based on TLS 1.2.
        5. There is no "DTLS 1.1"; that version number was skipped in order to harmonize version numbers with TLS.
           More info about the Datagram Transport Layer Security (DTLS):
           https://docs.microsoft.com/en-us/windows-server/security/tls/datagram-transport-layer-security-protocol
      .LINK
        https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
        https://blogs.msdn.microsoft.com/kaushal/2011/10/02/support-for-ssltls-protocols-on-windows
        https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
#>

[CmdletBinding()]
[OutputType("Boolean")]
Param
(
    [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][Alias("SP")][ValidateSet("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "DTLS 1.0", "DTLS 1.2", "DTLS 1.3", "AllVulnerableProtocols")][string[]]$SecurityProtocol,
    [Parameter(Mandatory=$True, Position=1)][Alias("ST")][ValidateSet("Client", "Server", "Both")][string]$ServiceType,
    [Parameter(Mandatory=$True, Position=2)][Alias("A")][ValidateSet("Enable", "Disable", "Revoke", "PersistOnly")][string]$Action,
    [Parameter(Mandatory=$False, Position=3)][Alias("D")][ValidateSet("True", "False", "Revoke", "")][AllowNull()][AllowEmptyString()][string]$DisabledByDefault
)

Function Set-SecurityProtocol
{
	<#
      .SYNOPSIS
        Enable or Disable security protocol. E.g. SSL 3.0, TLS 1.1, etc.
      .DESCRIPTION
        Enable or Disable security protocol. E.g. SSL 3.0, TLS 1.1, etc by adding, modifying or removing the relevant registry keys/values withing the registry key "HKLM SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols".
      .INPUTS
        The Security Protocol Name (SSL 3.0, TLS 1.1, etc), Service Type (Client, Server or Both), Required action (Enable, Disable, Revoke) and the action against the "DisabledByDefault" flag as "True, False or Revoke".
      .OUTPUTS
        Boolean
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'TLS 1.2' -ServiceType Both -Action Revoke;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'TLS 1.2' -ServiceType Client -Action Revoke -DisabledByDefault Revoke;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'TLS 1.2' -ServiceType Server -Action Enable -DisabledByDefault True;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'DTLS 1.0' -ServiceType Client -Action Disable -DisabledByDefault True;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'PCT 1.0' -ServiceType Both -Action Disable -DisabledByDefault True;
      .EXAMPLE
        Set-SecurityProtocol -SecurityProtocol 'AllVulnerableProtocols' -ServiceType Both -Action Disable -DisabledByDefault True;
      .PARAMETER SecurityProtocol
        Alias: SP
        Data Type: System.String[]
        Mandatory: True
        Description: The target Security Protocol/Protocols as an array of valid list string.
        Example(s): "SSL 3.0", "TLS 1.1"
        Default Value: N/A
        Notes:
              1. It's HIGHLY/STRICTLY recommended to keep the "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" and "DTLS 1.0" disabled 
                 due to the protocol vulnerabilities in these versions.
                 If you insist to turn them on for any reason, DO IT WITH YOUR OWN RISK WITHOUT ANY RESPONSIBILITY OR BLAME ON THE SCRIPT's AUTHOR.
                 Actually one of the reasons for writing this script, is to make sure that all these breached protocols are disabled for good!
                 Please refer to these official articles/announcments:
                   https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
                   https://docs.microsoft.com/en-us/security/solving-tls1-problem
                   https://support.microsoft.com/en-us/help/3117336/schannel-implementation-of-tls-1-0-in-windows-security-status-update-n
                   https://www.openssl.org/~bodo/ssl-poodle.pdf
                   http://www.isg.rhul.ac.uk/~kp/Darmstadt.pdf
                   https://support.microsoft.com/en-ie/help/187498/how-to-disable-pct-1-0-ssl-2-0-ssl-3-0-or-tls-1-0-in-internet-informat
                   https://knowledge.digicert.com/solution/SO8994.html
              2. If you want to do an action on all the Vulnerable Protocols list as highlighted in the previous point, 
                 you can use the value "AllVulnerableProtocols".
                 You can use it as a quick action to disable all listed Vulnerable Protocols in one line of command.
                 The list of those Vulnerable Protocols are hard coded inside the function, and could require an update every 
                 while in case if other Security Protocol has been known to be breached.
              3. The time this script has been written, the "TLS 1.3" and "DTLS 1.3" were not part of any Windows version yet, 
                 hence, make sure that your Windows supports this protocol.
              4. The Datagram Transport Layer Security 1.0 (DTLS 1.0) is based on TLS 1.1, and DTLS 1.2 is based on TLS 1.2.
              5. There is no "DTLS 1.1"; that version number was skipped in order to harmonize version numbers with TLS.
                 More info about the Datagram Transport Layer Security (DTLS):
                 https://docs.microsoft.com/en-us/windows-server/security/tls/datagram-transport-layer-security-protocol
      .PARAMETER ServiceType
        Alias: ST
        Data Type: System.String
        Mandatory: True
        Description: The service type as "Client", "Server" or both together.
        Example(s): "Client", "Server", "Both".
        Default Value: If "Both" is specified, the same configuration will be typically applied on both "Client" and "Server".
        Notes: N/A
      .PARAMETER Action
        Alias: A
        Data Type: System.String
        Mandatory: True
        Description: The action to be taken against this service as "Enable", "Disable", "Revoke" or "PersistOnly".
        Example(s): "Enable", "Disable", "Revoke", "PersistOnly"
        Default Value: N/A
        Notes: If "Revoke" is specified, the relevant "DWORD" value will be removed from the relevant registry key.
               Usually this action is taken to let the Windows follow the current policy applied.
               
               If "PersistOnly" is specified, the relevant registry key for the Secutity Prvoider with the sub key 
               (Client, Server or both) will be just created if not exit without configuring any value inside them.
               This is required if the "DisabledByDefault" flag will be specified and the user needs to configure only this 
               flag without the need to explicitly Enable or Disable the protocol.
               For more info about this flag, please refer to the this article:
               https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

      .PARAMETER DisabledByDefault
        Alias: D
        Data Type: System.String
        Mandatory: False
        Description: When DisabledByDefault flag is set to "True", the specified security protocol is not used by default.
                     If an SSPI app requests to use this  security protocol, it will be negotiated.
        Example(s): "True", "False", "Revoke"
        Default Value: N/A
        Notes: If "Revoke" is specified, the relevant "DWORD" value will be removed from the relevant registry key.
               Usually this action is taken to let the Windows OS follow the current policy applied.

               For more info about this flag, please refer to the this article:
               https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
      .NOTES
        1. When possible, instead of editing the registry directly, use Group Policy or other Windows tools such as the 
           Microsoft Management Console (MMC) to accomplish tasks. If you must edit the registry, use extreme caution.
           https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
        2. It's HIGHLY/STRICTLY recommended to keep the "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" and "DTLS 1.0" disabled 
           due to the protocol vulnerabilities in these versions.
           If you insist to turn them on for any reason, DO IT WITH YOUR OWN RISK WITHOUT ANY RESPONSIBILITY OR BLAME ON THE SCRIPT's AUTHOR.
           Actually one of the reasons for writing this script, is to make sure that all these breached protocols are disabled for good!
           Please refer to these official articles/announcments:
            https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
            https://docs.microsoft.com/en-us/security/solving-tls1-problem
            https://support.microsoft.com/en-us/help/3117336/schannel-implementation-of-tls-1-0-in-windows-security-status-update-n
            https://www.openssl.org/~bodo/ssl-poodle.pdf
            http://www.isg.rhul.ac.uk/~kp/Darmstadt.pdf
            https://support.microsoft.com/en-ie/help/187498/how-to-disable-pct-1-0-ssl-2-0-ssl-3-0-or-tls-1-0-in-internet-informat
            https://knowledge.digicert.com/solution/SO8994.html
        3. The time this script has been written, the "TLS 1.3" and "DTLS 1.3" were not part of any Windows version yet, 
           hence, make sure that your Windows supports these protocols when using any of them.
        4. The Datagram Transport Layer Security 1.0 (DTLS 1.0) is based on TLS 1.1, and DTLS 1.2 is based on TLS 1.2.
        5. There is no "DTLS 1.1"; that version number was skipped in order to harmonize version numbers with TLS.
           More info about the Datagram Transport Layer Security (DTLS):
           https://docs.microsoft.com/en-us/windows-server/security/tls/datagram-transport-layer-security-protocol
      .LINK
        https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
        https://blogs.msdn.microsoft.com/kaushal/2011/10/02/support-for-ssltls-protocols-on-windows
        https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11
    #>
	[CmdletBinding()]
    [OutputType("Boolean")]
    Param
    (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][Alias("SP")][ValidateSet("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "DTLS 1.0", "DTLS 1.2", "DTLS 1.3", "AllVulnerableProtocols")][string[]]$SecurityProtocol,
        [Parameter(Mandatory=$True, Position=1)][Alias("ST")][ValidateSet("Client", "Server", "Both")][string]$ServiceType,
        [Parameter(Mandatory=$True, Position=2)][Alias("A")][ValidateSet("Enable", "Disable", "Revoke", "PersistOnly")][string]$Action,
        [Parameter(Mandatory=$False, Position=3)][Alias("D")][ValidateSet("True", "False", "Revoke", "")][AllowNull()][AllowEmptyString()][string]$DisabledByDefault
    )

    $Error.Clear();
    [string[]]$vulnerableProtocols = @("TLS 1.0", "TLS 1.1", "PCT 1.0", "SSL 1.0", "SSL 2.0", "SSL 3.0", "DTLS 1.0");
    Function Add-SecurityProtocolRegKey
    {
        [OutputType("Microsoft.Win32.RegistryKey")]
        Param
        (
            [Parameter(Mandatory=$True, Position=0)][Alias("P")][String]$Path,
            [Parameter(Mandatory=$True, Position=1)][Alias("N")][String]$Name
        )

        Try
        {
            $key = "$Path\$Name";
            $keyExists = Test-Path $key;
            if ($keyExists)
            {
                return Get-Item $key;
            }

            return New-Item -Path $Path -Name $Name;

        }
        Catch
        {
            return $null;
        }

    }

    Function Set-SecurityProtocolRegKey
    {
        [OutputType("Microsoft.Win32.RegistryKey")]
        Param
        (
            [Parameter(Mandatory=$True, Position=0)][Alias("SP")][String]$SecurityProtocol,
            [Parameter(Mandatory=$True, Position=1)][Alias("ST")][ValidateSet("Client", "Server")][string]$ServiceType,
            [Parameter(Mandatory=$True, Position=2)][Alias("A")][bool]$Add
        )

        $groupKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

        Try
        {
            if ($Add)
            {
                $key = Add-SecurityProtocolRegKey -P $groupKey -N $SecurityProtocol;
                if ($key -ne $null)
                {
                    $key = Add-SecurityProtocolRegKey -P $key.PSPath -N $ServiceType;
                    return $key;
                }

                return $null;
            }
            else
            {
                $path = "$groupKey\$SecurityProtocol";
                if (!(Test-Path $path))
                {
                    return $null;
                }

                $path+= "\$ServiceType";
                if (!(Test-Path $path))
                {
                    return $null;
                }

                return Get-Item $path;
            }
        }
        Catch
        {
            return $null;
        }

    }

    Function Set-RegDwordValue
    {
        [OutputType("Boolean")]
        Param
        (
            [Parameter(Mandatory=$True, Position=0)][Alias("K")][PSObject]$Key,
            [Parameter(Mandatory=$True, Position=1)][Alias("N")][ValidateSet("Enabled", "DisabledByDefault")][String]$Name,
            [Parameter(Mandatory=$True, Position=2)][Alias("A")][ValidateSet("Enable", "Disable", "Revoke", "PersistOnly")][string]$Action

        )

        Try
        {
            if ($Action -eq "Revoke")
            {
                if($Key.GetValue($Name) -ne $null)
                {
                    Remove-ItemProperty -Path $Key.PSPath -Name $Name -Force;
                    return $True;
                }
                else
                {
                    return $True;
                }

            }
            else
            {
                $value = If ($Action -eq "Enable") {1} Else {0};
                $keyValue = New-ItemProperty -Path $Key.PSPath -Name $Name -Value $Value -PropertyType DWORD -Force;
                return ($keyValue -ne $null);
            }
        }
        Catch
        {
            return $false;
        }

    }

    If ($SecurityProtocol.Count -gt 1)
    {
        [bool] $success = $false;
        Foreach ($sp in $SecurityProtocol)
        {
            $success = Set-SecurityProtocol -SP @($sp) -ST $ServiceType -A $Action -D $DisabledByDefault;
            If (!$success)
            {
                return $success;
            }
        }

        return $success;
    }

    If ($SecurityProtocol[0] -eq "AllVulnerableProtocols")
    {
        return Set-SecurityProtocol -SP $vulnerableProtocols -ST $ServiceType -A $Action -D $DisabledByDefault;
    }

    If ($ServiceType -eq "Both")
    {
        $success = Set-SecurityProtocol -SP $SecurityProtocol -ST Client -A $Action -D $DisabledByDefault;
        If (!$success)
        {
            return $false;
        }

        return Set-SecurityProtocol -SP $SecurityProtocol -ST Server -A $Action -D $DisabledByDefault;
    }

    $key =  Set-SecurityProtocolRegKey -SP $SecurityProtocol[0] -ST $ServiceType -A ($Action -ne "Revoke");

    if ($key -eq $null)
    {
        return ($Action -eq "Revoke");
    }
    else
    {
        if ($Action -eq "PersistOnly" -and [String]::IsNullOrEmpty($DisabledByDefault))
        {
            return $True;
        }
    }

    if($Action -ne "PersistOnly")
    {
        $success = Set-RegDwordValue -K $key -N "Enabled" -A $Action;
        if ($keyValue -eq $false)
        {
            return $False;
        }
    }

    if(![String]::IsNullOrEmpty($DisabledByDefault))
    {
        $a = "Revoke";
        if ($DisabledByDefault -eq "True")
        {
            $a = "Enable";
        }
        ElseIf ($DisabledByDefault -eq "False")
        {
            $a = "Disable";
        }

        $keyValue = Set-RegDwordValue -K $key -N "DisabledByDefault" -A $a;
        if ($null -eq $keyValue)
        {
            return $False;
        }
    }

    return $true;
}

Return Set-SecurityProtocol -SecurityProtocol $SecurityProtocol -ServiceType $ServiceType -Action $Action -DisabledByDefault $DisabledByDefault;