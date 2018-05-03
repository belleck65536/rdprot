################################################################################
#  init
#
param(
	[switch]$reg,
	[switch]$help,
	[switch]$unreg,
	[string]$unban
)

$Prefix = "Wail2Ban"

################################################################################
#  Files
#
$img_name = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

$wail2banInstall	= $MyInvocation.MyCommand.Source.Replace( $MyInvocation.MyCommand.Name, "")
$wail2banScript		= $MyInvocation.MyCommand.Source
$ConfigFile			= $wail2banInstall+$Prefix+"_config.xml"
$BannedIPLog		= $wail2banInstall+$Prefix+"_ban.xml"
$logFile			= $wail2banInstall+$Prefix+"_log.log"


################################################################################
#  Constructs
#
if ( Test-Path $ConfigFile ) {
	[xml]$cfg = Get-Content $ConfigFile
} else {
	exit 101
}


$Check_Window		= $cfg.wail2ban.conf.check_window
$Check_Count		= $cfg.wail2ban.conf.check_count
$Max_BanDuration	= $cfg.wail2ban.conf.max_banduration
$Categories			= $cfg.wail2ban.events.entry
$WhiteList			= $cfg.wail2ban.whitelist.ip
$TaskUser			= "meuh" # prendre le compte courant ?

$taskname_exp		= "$Prefix - Expiration"
$taskname_tgr		= "$Prefix - Trigger"

if ( $Check_Window		-lt 0 ) { exit 2 }
if ( $Check_Count		-lt 0 ) { exit 2 }
if ( $Max_BanDuration	-lt 0 ) { exit 2 }


# obtention adresses locales
$WhiteList += $( Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred ).IPAddress


################################################################################
# Functions
#
# affichage aide
function help {
	"`n$($MyInvocation.MyCommand.Name) `n"
	"	-unban <ip>	: révoquer un bannissement (all = tout vider)"
	"	-unreg		: supprimer tâches planifiées et règle de pare-feu (id = nom)"
	"	-reg		: création tâches planifiées d'évènement + expiration (interval ?)"
	"	-help		: --"
	" "
}


# Log things to file and debug
function log ( $type, $text ) {
	$output = "" + ( get-date -format u ).replace( "Z", "" ) + " $text"

	switch ( $type ) {
		"D" {
			write-debug $output
		}
		"A" {
			write-debug $output
			$output | out-file $logfile -append
		}
		"W" {
			write-warning "WARNING: $output"
			$output | out-file $logfile -append
		}
		"E" {
			write-error "ERROR: $output"
			$output | out-file $logfile -append
		}
	}
}


#Log type functions
function debug		( $text ) { log "D" $text }
function actioned	( $text ) { log "A" $text }
function warning	( $text ) { log "W" $text }
function error		( $text ) { log "E" $text }


# Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function netmask ( $MaskLength ) {
	$IPAddress =  [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
	$DottedIP = $( For ($i = 3; $i -ge 0; $i--) {
		$Remainder = $IPAddress % [Math]::Pow(256, $i)
		($IPAddress - $Remainder) / [Math]::Pow(256, $i)
		$IPAddress = $Remainder
	} )

	Return [String]::Join('.', $DottedIP)
}


#
function Get-WinEventData {
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$true, 
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true, 
			ValueFromRemainingArguments=$false, 
			Position=0 )]
		[System.Diagnostics.Eventing.Reader.EventLogRecord[]]
		$event
	)

	Process {
		foreach ( $entry in $event ) {
			$XML = [xml]$entry.ToXml()
			$XMLData = $null
			if( $XMLData = @( $XML.Event.EventData.Data ) ) {
				For( $i=0; $i -lt $XMLData.count; $i++ ) {
					Add-Member -InputObject $entry -MemberType NoteProperty -name "EventData$($XMLData[$i].name)" -Value $XMLData[$i].'#text' -Force
				}
			}

			$entry
		}
	}
}


# datetime --> EPOCH
function epoch ( $datetime ) {
	return [int][double]::Parse((Get-Date -date $datetime -UFormat %s))
}


# EPOCH --> datetime
function datetime ( $epoch ) {
	return $( Get-Date -Date "1970/01/01" ).AddSeconds( $epoch )
}


# check if IP is whitelisted
function is_whitelisted ( $ip ) {
	foreach ( $item in $WhiteList ) {
		switch ( $true ) {
			"$( $ip -eq $item )" {
				return $true
				break
			}
			"$( $item.contains("/") )" {
				$subnet	= $item.Split("/")[0]
				$Mask	= netmask($item.Split("/")[1])
				if ((([net.ipaddress]$ip).Address -Band ([net.ipaddress]$Mask).Address ) -eq`
				(([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) {
					return $true
					break
				}
			}
		}
	}
	return $false
}


# obtention des ip des bans encore en vigueur
# en entrée : cf. ban_write
function ip_of_not_expired_bans ( $bans ) {
	$ips = @()
	$now = epoch ( get-date )
	foreach ( $ban in $bans ) {
		if ( [int]$ban.release -ge $now ) {
			$ips += $ban.ip
		}
	}
	return $ips
}


# vérification présence règle
function fw_rule_exists {
	return $( Get-NetFirewallRule -DisplayName $Prefix -ErrorAction SilentlyContinue )
}


# création règle pare feu
function fw_rule_create {
	if ( ! $( fw_rule_exists ) ) {
		New-NetFirewallRule -DisplayName $Prefix -Enabled False -Direction Inbound -Action Block
	}
}


# mise à jour règle pare-feu avec toutes les IP à bloquer (en array)
function fw_rule_update ( $ip ) {
	if ( $ip.Count -ge 1 ) {
		fw_rule_create
		Get-NetFirewallRule -DisplayName $Prefix | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $ip
	} else {
		fw_rule_remove
	}
}


# suppression règle pare-feu
function fw_rule_remove {
	Remove-NetFirewallRule -DisplayName $Prefix -ErrorAction SilentlyContinue
}


# recherche d'une tâche planifiée
function schtask_exists {
	return ( $(Get-ScheduledTask -taskname $taskname_exp -ErrorAction SilentlyContinue ) -and`
			 $(Get-ScheduledTask -taskname $taskname_trg -ErrorAction SilentlyContinue ) )
}


# ajout d'une tâche planifiée
function schtask_create () {
	if ( ! $( schtask_exists ) ) {
		$Aexp = New-ScheduledTaskAction -Execute $img_name -Argument "$wail2banScript -expire"
		$Atrg = New-ScheduledTaskAction -Execute $img_name -Argument $wail2banScript
		$P = New-ScheduledTaskPrincipal -UserId $TaskUser -LogonType S4U -RunLevel Highest
		$S = New-ScheduledTaskSettingsSet -Compatibility Vista
		$T = New-ScheduledTaskTrigger -Daily -At "00:00"

		$Dexp = New-ScheduledTask -Action $Aexp -Principal $P -Settings $S -Trigger $T
		$Dtrg = New-ScheduledTask -Action $Atrg -Principal $P -Settings $S

		Register-ScheduledTask $taskname_exp -InputObject $Dexp
		Register-ScheduledTask $taskname_tgr -InputObject $Dtrg
	}
}


# https://social.technet.microsoft.com/Forums/windowsserver/en-US/c2e778f6-4f63-4a07-9557-d13220ba808a/schedule-job-i-need-to-add-custom-eventtrigger-using-powershell?forum=winserverpowershell
#:! vérifier la subscription
# en entrée : $src = @( @{ "Path" = "Security" ; "EventID" = "4625" ; "Provider" = "MWSA" } ,
#                       @{ "Path" = "Security" ; "EventID" = "4625" ; "Provider" = "MWSA" } )
function schtask_update ( $evts ) {
	schtask_create

	$Ts = @()
	foreach ( $evt in $evts ) {
		$cimTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
		$T = New-CimInstance -CimClass $cimTriggerClass -ClientOnly
		$T.Enabled = $true
		$T.Subscription = "<QueryList><Query Id='0' Path='$($evt.source)'><Select Path='$($evt.source)'>*[System[Provider[@Name='$($evt.Provider)'] and EventID=$($evt.id)]]</Select></Query></QueryList>"
		$Ts +=  $T
	}

	Set-ScheduledTask -TaskName $taskname_tgr -Trigger $Ts
}


# suppression d'une tâche planifiée
function schtask_remove () {
	Unregister-ScheduledTask -Taskname $taskname_exp -ErrorAction SilentlyContinue
	Unregister-ScheduledTask -Taskname $taskname_tgr -ErrorAction SilentlyContinue
}


# obtenir liste des ban
function ban_read {
	if ( test-path $BannedIPLog ) {
		$r = @()
		[xml]$ip = get-content $BannedIPLog
		$ip.wail2ban.ban | % { $r += @{ "ip" = $_.ip ; "date" = $_.date ; "release" = $_.release } }
		return $r
	}
}


# enregistrer liste des ban
# accepte en entrée : @( @{ "ip" = "x.x.x.x" ; "date" = "EPOCH" ; "release" = EPOCH } ,
#						 @{ "ip" = "x.x.x.x" ; "date" = "EPOCH" ; "release" = EPOCH } )
function ban_write ( $bans ) {
	$w2b = new-object System.Xml.XmlDocument
	$w2b.AppendChild( $w2b.CreateElement( "wail2ban" ) )

	foreach ( $b in $bans ) {
		$ip = $w2b.CreateAttribute( "ip" )
		$ip.Value = $b.ip

		$date = $w2b.CreateAttribute( "date" )
		$date.Value = $b.date

		$release = $w2b.CreateAttribute( "release" )
		$release.Value = $b.release

		$ban = $w2b.CreateElement( "ban" )
		$ban.Attributes.Append( $ip )
		$ban.Attributes.Append( $date )
		$ban.Attributes.Append( $release )

		$w2b.LastChild.AppendChild( $ban )
	}

	$w2b.Save( $BannedIPLog )
}


# Ban the IP (with checking)
# lecture bans, ajout ban, écriture bans, màj parefeu, logfile, mail
#:!
function ban ( $ip ) {
	if ( is_whitelisted ( $ip ) ) {
		warning "L'ip protégée $ip a déclenché un bannissement"
	} else {
		$b = ban_read

		$now = epoch ( get-date )
		$b += @{ "ip" = $ip ; "date" = $now ; "release" = $( $now + $Max_BanDuration ) }

		ban_write ( $b )
		fw_rule_update ( ip_of_not_expired_bans ( $b ) )
		actioned "$ip vient de se faire bannir"
		# mail
	}
}


# lecture log
# recup des logs
function detect {
	actioned "Quelque chose se passe..."
	foreach ( $categorie in $Categories ) {
		$regroup = @{}

		$filtre = @{ Logname = $Categorie.source ; id = $Categorie.id ; StartTime = $(Get-Date).AddSeconds(-$Check_Window) }
		$Tries = Get-WinEvent -FilterHashtable $filtre -ErrorAction SilentlyContinue | Get-WinEventData

		foreach ( $trie in $Tries ) {
			if ( ! $regroup.contains( $trie.EventDataIpAddress ) ) {
				[int]$regroup.( $trie.EventDataIpAddress ) = 1
			} else {
				$regroup.( $trie.EventDataIpAddress ) ++
			}
		}
		$regroup.Keys | ? { $regroup.$_ -gt $Check_Count } | % { ban ( $_ ) }
	}
}


################################################################################
################################################################################
#	-unban <ip> : révoquer un bannissement (all = tout vider)
#	-unreg      : supprimer tâches planifiées et règle de pare-feu (id = nom)
#	-reg        : création tâches planifiées d'évènement + expiration (interval ?)
#   -help


# Display Help Message
if ( $help.IsPresent ) {
	help
	exit 0
}


#
if ( $reg.IsPresent ) {
	actioned "Intégration de $Prefix"
	schtask_update ( $Categories )
	fw_rule_update ( ip_of_not_expired_bans ( ban_read ) )
	exit 0
}


#
if ( $unreg.IsPresent ) {
	actioned "désintégration de $Prefix"
	schtask_remove
	fw_rule_remove
	exit 0
}


#
if ( $unban -ne "" ) {
	actioned "Débanissment de $unban demandé..."
	$now = epoch ( get-date )
	$b = ban_read
	$b | ? { $_.ip -eq $unban -and $_.release -ge $now } | % { $_.release = $now - 1 }
	ban_write ( $b )
	fw_rule_update ( ip_of_not_expired_bans ( $b ) )
	exit 0
}


detect

