Param(
  [string]$input,
  [string]$output
)
if($input AND $output){
$servers = get-content $input
$serversAndIps = $output

$results = @()
$count = 0

$mes="Starting..."
Write-Host $mes

## Thanks to Al Feersum in the comments of http://blog.forrestshields.com/post/2012/08/01/Resolving-Reverse-DNS-Lookups-in-PowerShell.aspx
Function ResolveAddress($IP) {

    $IP = [string]$IP

    [bool]$IPv6 = ($IP -match "^[a-z0-9][a-z0-9][a-z0-9][a-z0-9]::")

    try {$Resolved = ([system.net.dns]::GetHostEntry([system.net.ipaddress]$IP)).HostName}

    catch {

        try {

            if (-not($IPv6)) {

                $Resolved = (&nslookup -timeout=1 $IP 2>$null)

                $Resolved = ($Resolved|where {$_ -match "^Name:"}).split(':')[1].trim()

            } else {

                $Resolved = "Unresolvable v6 local address"

            }

        }

        catch { $Resolved = "Unable to resolve" }

    }

    return $Resolved

}


foreach ($server in $servers)
{
    $result = "" | Select ServerName , ipaddress

    $result.servername = ResolveAddress($server)
    $result.ipaddress = $server
    $results += $result
	$count += 1
	
	$mes=[string]$count + " IPs processed"
	Write-Host $mes
}




$results | export-csv -NoTypeInformation $serversandips
}else{
	Write-Host "Usage: resolveIPList.ps1 -input <text file> -output <csv file>"
}
