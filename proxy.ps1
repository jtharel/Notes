while($true)
{
	Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoConfigURL' -value ''
	Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxyEnable' -value '1'
	Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxyServer' -value '127.0.0.1:8080'
}