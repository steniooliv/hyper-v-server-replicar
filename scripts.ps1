# Create Hyper-V Server 2019 Replica

# We have two hosts, HYR1, HYR2.

# Install File Service Feature on HYR1 and HYR2
Install-WindowsFeature -Name File-Services -IncludeManagementTools

# Add and rename network adapters and disable IPV6, on both hosts
Get-NetAdapterBinding -Name * #Verify options on network adapters
Get-NetAdapter -Name "*" | Format-List -Property "Name" #List all dapaters name
  
Rename-NetAdapter -Name "Ethernet"  -NewName "Host Hyper-V" #Rename the first adapter
Rename-NetAdapter -Name "Ethernet 2"  -NewName "Network VM" #Remane the second adapter

# Change the IP on HYR1
New-NetIPAddress 192.168.0.11 -InterfaceAlias "Host Hyper-V" -DefaultGateway 192.168.0.1 -AddressFamily ipv4 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Host Hyper-V" -ServerAddresses 192.168.0.1`
  
New-NetIPAddress 192.168.0.21 -InterfaceAlias "Network VM" -DefaultGateway 192.168.0.1 -AddressFamily ipv4 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Network VM" -ServerAddresses 192.168.0.1

# Change the IP on HYR2
New-NetIPAddress 192.168.0.12 -InterfaceAlias "Host Hyper-V" -DefaultGateway 192.168.0.1 -AddressFamily ipv4 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Host Hyper-V" -ServerAddresses 192.168.0.1
  
New-NetIPAddress 192.168.0.22 -InterfaceAlias "Network VM" -DefaultGateway 192.168.0.1 -AddressFamily ipv4 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Network VM" -ServerAddresses 192.168.0.1

# Disable IPV6 for all adapters
Disable-NetAdapterBinding -Name "Host Hyper-V" -ComponentID ms_tcpip6 -PassThru
Disable-NetAdapterBinding -Name "Network VM" -ComponentID ms_tcpip6 -PassThru

# On Windows 10 set the ip for the same network, for example
New-NetIPAddress 192.168.0.9 -InterfaceAlias "Host Hyper-V" -DefaultGateway 192.168.0.1 -AddressFamily ipv4 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Host Hyper-V" -ServerAddresses 192.168.0.1

# Change the hostnames
Rename-Computer -NewName "HYR1" -DomainCredential HYR1\Administrador -Restart
Rename-Computer -NewName "HYR2" -DomainCredential HYR2\Administrador -Restart
Rename-Computer -NewName "WIN10" -DomainCredential WIN10\Administrador -Restart

# Add entries on host files on HYR1, HYR2 and Windows 10
Get-Content -Path "C:\Windows\System32\drivers\etc\hosts" #Verify entries`
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "192.168.0.11 HYR1" #Add entry
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "192.168.0.12 HYR2" #Add entry
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "192.168.0.9 WIN10" #Add entry

# Allow Firewall rules on HYR1, HYR2 and Windows 10
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" #English
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv6-In)" #English
Enable-NetFirewallRule -DisplayName "Hyper-V Replica HTTPS Listener (TCP-In)" #English
  
Enable-NetFirewallRule -DisplayName "Compartilhamento de Arquivo e Impressora (Solicitação de Eco - ICMPv4-In)" #Portuguese
Enable-NetFirewallRule -DisplayName "Compartilhamento de Arquivo e Impressora (Solicitação de Eco - ICMPv6-In)" #Portuguese
Enable-NetFirewallRule -DisplayName "Ouvinte HTTPS da Réplica do Hyper-V (TCP-In)" #Portuguese
  

### Very important step, creating a certificate for replica

# Download and install on Windows 10 the Microsoft Platform SDK
# https://www.microsoft.com/en-us/download/details.aspx?id=6510

# Create a folder on HYR1 and HYR2
New-Item -Path C:\Certificado -ItemType directory #Create folder for certificate on C:

# Locate the MakeCert.exe file within the Microsoft Platform SDK installation you just installed, copy to the folder created above in \\HYR1\C$ and \\HYR2\C$

# On HYR1, open CMD, and go to the folder of MakeCert.exe and run the command line below
makecert -pe -n "CN=PrimaryTestRootCA" -ss root -sr LocalMachine -sky signature -r "PrimaryTestRootCA.cer"
makecert -pe -n "CN=HYR1" -ss my -sr LocalMachine -sky exchange -eku 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2 -in "PrimaryTestRootCA" -is root -ir LocalMachine -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 PrimaryTestCert.cer
  
# On HYR2, open CMD, and go to the folder of MakeCert.exe and run the command line below
makecert -pe -n "CN=ReplicaTestRootCA" -ss root -sr LocalMachine -sky signature -r "ReplicaTestRootCA.cer"
makecert -pe -n "CN=HYR2" -ss my -sr LocalMachine -sky exchange -eku 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2 -in "ReplicaTestRootCA" -is root -ir LocalMachine -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 PrimaryTestCert.cer

# Now copy the primary certificate created on HYR1 to HYR2, and the replica certificate created on HYR2 copy to HYR1

# On HYR1 run
certutil -addstore -f Root "ReplicaTestRootCA.cer"
  
# On HYR2 run
certutil -addstore -f Root "PrimaryTestRootCA.cer"

# On Powershell disable certificate revocation on HYR1 and HYR2, after run command below, restart both
reg add “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\Replication” /v DisableCertRevocationCheck /d 1 /t REG_DWORD /f

# Change network profile to Private on HYR1, HYR2 and Windows 10
Get-NetConnectionProfile #Verify profiles
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private #On Windows 10
Set-NetConnectionProfile -InterfaceAlias "Host Hyper-V" -NetworkCategory Private #On HYR1 and HYR2
Set-NetConnectionProfile -InterfaceAlias "Network VM" -NetworkCategory Private #On HYR1 and HYR2
  
# On Windows 10, run the command
Enable-PSRemoting

# On Windows 10, enable delegation for hostnames
Enable-WSManCredSSP -Role "Client" -DelegateComputer "HYR1"
Enable-WSManCredSSP -Role "Client" -DelegateComputer "HYR2"

# On Windows 10, add hosts on trusted hosts
Get-Item -Path WSMan:\localhost\Client\TrustedHosts #Verify trusted hosts
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value HYR1 #Add HYR1
$curList = (Get-Item WSMan:\localhost\Client\TrustedHosts).value
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$curList, HYR2" #Add HYR2

# On Windows 10, create Windows Credentials for hosts connection
cmdkey /list #List credentials`
cmdkey /add:HYR1 /user:Administrador /pass:abc123. #Add HYR1
cmdkey /add:HYR2 /user:Administrador /pass:abc123. #Add HYR2

# On Windows 10, test connection with command below
Enter-PSSession -ComputerName HYR1
Enter-PSSession -ComputerName HYR2
