# escape=`
FROM mcr.microsoft.com/windows/servercore:ltsc2019
SHELL ["powershell", "-command"]

RUN md c:\temp;

COPY vbrun60sp6.exe c:\temp
COPY x64\msodbcsql.msi c:\temp

RUN Start-Process "c:/temp/vbrun60sp6.exe /Q:A" -PassThru | Wait-Process -TimeOut 600 | Stop-Process

RUN Start-Process "c:/temp/msodbcsql.msi" "/qn" -PassThru | Wait-Process ;

RUN Add-WindowsFeature FS-FileServer; `
    Add-WindowsFeature Web-Server; `
    Add-WindowsFeature Web-Common-Http; `
    Add-WindowsFeature Web-Health; `
    Add-WindowsFeature Web-Stat-Compression; `
    Add-WindowsFeature Web-Filtering; `
    Add-WindowsFeature Web-Windows-Auth; `
    Add-WindowsFeature Web-Client-Auth; `
    Add-WindowsFeature Web-Net-Ext45; `
    Add-WindowsFeature Web-AppInit; `
    Add-WindowsFeature Web-Asp; `
    Add-WindowsFeature Web-Asp-Net45; `
    Add-WindowsFeature Web-ISAPI-Ext; `
    Add-WindowsFeature Web-ISAPI-Filter; `
    Add-WindowsFeature Web-WebSockets; `
    Add-WindowsFeature Net-Framework-45-Core; `
    Add-WindowsFeature Net-Framework-45-ASPNET; `
    Add-WindowsFeature Net-WCF-HTTP-Activation45; `
    Add-WindowsFeature Net-WCF-TCP-Activation45; `
    Add-WindowsFeature Net-WCF-TCP-PortSharing45; `
    Add-WindowsFeature WAS; `
    Invoke-WebRequest -UseBasicParsing -Uri "https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe" -OutFile "C:\ServiceMonitor.exe"

RUN Invoke-WebRequest "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi" -OutFile c:/temp/urlrewrite2.msi; `
    Start-Process "c:/temp/urlrewrite2.msi" "/qn" -PassThru | Wait-Process ;

COPY PayDox.zip C:\temp\PayDox.zip

RUN md C:\PayDox

RUN Expand-Archive -LiteralPath C:\temp\PayDox.zip -DestinationPath C:\ -Force | Wait-Process ;

RUN del c:\temp\*.*

RUN New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "BackConnectionHostNames" -PropertyType MultiString -Value ('http://stone-m2.local') -Force; `
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value 255 -Force;

RUN Start-Process -FilePath "$env:systemdrive\Windows\SysWOW64\regsvr32.exe" -ArgumentList "/s", "C:\PayDox\Core\PayDox.dll" -PassThru | Wait-Process ; `
    Start-Process -FilePath "$env:systemdrive\Windows\Microsoft.Net\Framework\v4.0.30319\RegAsm.exe" -ArgumentList "/codebase","/tlb", "C:\PayDox\Service\bin\COM_Wapper.dll" -PassThru | Wait-Process; `
    Start-Process -FilePath "$env:systemdrive\Windows\Microsoft.Net\Framework\v4.0.30319\RegAsm.exe" -ArgumentList "/codebase","/tlb", "C:\PayDox\MEOW\bin\MEOW_COM.dll" -PassThru | Wait-Process; `
    Start-Process -FilePath "$env:systemdrive\Windows\Microsoft.Net\Framework\v4.0.30319\RegAsm.exe" -ArgumentList "/codebase","/tlb", "C:\PayDox\Core\PayDox.FileSearch.dll" -PassThru | Wait-Process;


RUN Remove-Website 'Default Web Site'; `
    New-WebAppPool PayDoxMainPool; `
    Import-Module WebAdministration; Set-ItemProperty -Path "IIS:\AppPools\PayDoxMainPool" -Name "managedRuntimeVersion" -Value "v4.0"; `
    Set-ItemProperty -Path "IIS:\AppPools\PayDoxMainPool" -Name "managedPipelineMode" -Value "Classic"; `
    Set-ItemProperty -Path "IIS:\AppPools\PayDoxMainPool" -Name "enable32BitAppOnWin64" -Value True; `
    New-Website -Name PayDox -Port 80 -PhysicalPath C:\PayDox -ApplicationPool PayDoxMainPool; `
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value False -PSPath "IIS:/Sites/PayDox/" -Force; `
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value True  -PSPath "IIS:/Sites/PayDox/" -Force; `
    Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site" -PSPath "IIS:/Sites/PayDox/" -Name "Bindings" -Value (@{protocol='http';bindingInformation='*:80:stone-m2.local'}) -Force ; `
    New-WebVirtualDirectory -Site "PayDox" -Name "Uploads" -PhysicalPath "C:\PayDoxUploads" -Force; `
    New-WebVirtualDirectory -Site "PayDox" -Name "Downloads" -PhysicalPath "C:\PayDoxDownloads" -Force; 

EXPOSE 80

# RUN ping -n 1 stone-m2.local

ENTRYPOINT ["C:\\ServiceMonitor.exe", "w3svc"]

#    Add-WindowsFeature Web-Net-Ext; `
#    Add-WindowsFeature Web-Asp-Net; `
#    Add-WindowsFeature Web-Mgmt-Console; `
#   Add-WindowsFeature Net-Framework-Core; `
# docker run -p 80:80 --name pdxcheck01 -v D:\images\paydox\docs:C:\PayDoxDocuments -v D:\images\paydox\downloads:C:\PayDoxDownloads -v D:\images\paydox\uploads:C:\PayDoxUploads --env EDMS_DB_HOST=stone-m2.local --env EDMS_DB_NAME=paydox-epd-2-14 --env EDMS_DB_USER=paydox-sys --env EDMS_DB_PASS=!QAZ1qaz --env EDMS_LANG=RUS --env EDMS_COLOR_SCHEME=1 --env EDMS_SMTP_HOST=stone-m2.local --env EDMS_SMTP_AUTH_TYPE=OFF --env EDMS_SMTP_USER=local\paydox --env EDMS_SMTP_PASS=123456 paydox:epd214

#    EDMS_MOBILE_USER, EDMS_DB_HOST, EDMS_DB_NAME, EDMS_DB_USER, EDMS_DB_PASS, EDMS_LANG, EDMS_COLOR_SCHEME, EDMS_SMTP_HOST, EDMS_SMTP_AUTH_TYPE, EDMS_SMTP_USER, EDMS_SMTP_PASS