workflow Install-Workflow
{
     
    InlineScript {
        #Register Chocolatly Package source
        Register-PackageSource -Name chocolatey -ProviderName Chocolatey -Location http://chocolatey.org/api/v2/ -Trusted -Force
 
        #Install packages
        Install-Package -Name GoogleChrome -Source Chocolatey -Force
        Install-Package -Name adobereader -Source Chocolatey -Force
        Install-Package -Name classic-shell -Source Chocolatey -Force
        Install-Package -Name wireshark -Source Chocolatey -Force
        Install-Package -Name putty -Source Chocolatey -Force
        Install-Package -Name nmap -Source Chocolatey -Force
        Install-Package -Name 7zip -Source Chocolatey -Force
        Install-Package -Name free-hex-editor-neo -Source Chocolatey -Force
        Install-Package -Name notepadplusplus -Source Chocolatey -Force
        Install-Package -Name PowerGUI -Source Chocolatey -Force
        Install-Package -Name python2 -Source Chocolatey -Force
        Install-Package -Name hxd -Source Chocolatey -Force
    }
}
Install-Workflow
