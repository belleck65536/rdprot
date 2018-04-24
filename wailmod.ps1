################################################################################
#
#	quand le script est exécuté sans argument, on tente une détection
#	si déclenchement positif, traitement de bannissement :
#		màj parefeu (expiration implicite) + communication
#
#	-unban <ip> : révoquer un bannissement (all = tout vider)
#	-unreg      : supprimer tâches planifiées et règle de pare-feu (id = nom)
#	-reg        : création tâches planifiées d'évènement + expiration (interval ?)
#
################################################################################
#  init
#
param(
    [switch]$reg,
	[switch]$help,
    [switch]$unreg,
    [string]$unban
)

$DebugPreference = "continue"


################################################################################
#  Files
#
$wail2banInstall = "" + ( Get-Location ) + "\"
$wail2banScript  = $wail2banInstall+$MyInvocation.MyCommand.Name
$ConfigFile      = $wail2banInstall+"wail2ban_config.xml"
$BannedIPLog     = $wail2banInstall+"wail2ban_ban.xml"
$logFile         = $wail2banInstall+"wail2ban_log.log"


################################################################################
#  Constructs
#
if ( Test-Path $ConfigFile ) {
	[xml]$cfg = Get-Content $ConfigFile
} else {
	exit 1
}


$Check_Window		= $cfg.wail2ban.conf.check_window
$Check_Count		= $cfg.wail2ban.conf.check_count
$Max_BanDuration	= $cfg.wail2ban.conf.max_banduration
$RecordEventLog		= $cfg.wail2ban.conf.log
$Categories			= $cfg.wail2ban.events.entry
$WhiteList			= $cfg.wail2ban.whitelist.ip

if ( $Check_Window		-lt 0 ) { exit 2 }
if ( $Check_Count		-lt 0 ) { exit 2 }
if ( $Max_BanDuration	-lt 0 ) { exit 2 }

$FirewallRule = "Wail2Ban"
$EventTypes = @(
	 "Application"
	,"Security"
	,"System"
)


# obtention adresses locales
$WhiteList += $( Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred ).IPAddress


# regex IPv4
New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')


#:! filtrage et log (pas propre avec le -match)
$Categories = $Categories | ? { $EventTypes -match $_.source }


################################################################################
# Functions
#
#:! affichage aide
function help {
	"`nwail2ban   `n"
	" "
}


#:! journalisation vers Windows
function event ( $text, $task, $result ) {
	$event = new-object System.Diagnostics.EventLog( $RecordEventLog )
	$event.Source = $FirewallRule
	switch ( $task ) {
		"ADD"    { $logeventID = 1000 }
		"REMOVE" { $logeventID = 2000 }
	}
	switch ( $result ) {
		"FAIL"   { $eventtype = [System.Diagnostics.EventLogEntryType]::Error; $logeventID += 1 }
		default  { $eventtype = [System.Diagnostics.EventLogEntryType]::Information}
	}
	$event.WriteEntry( $text, $eventType, $logeventID )
}


#:! Log things to file and debug
function log ( $type, $text ) {
	$output = "" + ( get-date -format u ).replace( "Z", "" ) + " $text"

	switch ( $type ) {
		"D" {
            write-debug $output
        }
		"W" {
            write-warning "WARNING: $output"
            $output | out-file $logfile -append
        }
		"E" {
            write-error "ERROR: $output"
            $output | out-file $logfile -append
        }
		"A" {
            write-debug $output
            $output | out-file $logfile -append
        }
	}
}


#Log type functions
function error		( $text ) { log "E" $text }
function warning	( $text ) { log "W" $text }
function debug		( $text ) { log "D" $text }
function actioned	( $text ) { log "A" $text }


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


# conversion datetime en EPOCH
function epoch ( $datetime ) {
	return [int][double]::Parse((Get-Date -date $datetime -UFormat %s))
}


# conversion EPOCH en datetime
#:! à vérifier
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
	return $( Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue )
}


# création règle pare feu
function fw_rule_create {
	if ( ! $( fw_rule_exists ) ) {
		New-NetFirewallRule -DisplayName $FirewallRule -Enabled False -Direction Inbound -Action Block
	}
}


# mise à jour règle pare-feu avec toutes les IP à bloquer (en array)
function fw_rule_update ( $ip ) {
	if ( $ip.Count -ge 1 ) {
		fw_rule_create
		Get-NetFirewallRule -DisplayName $FirewallRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $ip
	} else {
		fw_rule_remove
	}
}


# suppression règle pare-feu
function fw_rule_remove {
	Remove-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
}


#:! recherche d'une tâche planifiée
function schtask_create ( $type, $data ) {
	
}


#:! ajout d'une tâche planifiée
function schtask_create ( $type, $data ) {
	
}


#:! suppression d'une tâche planifiée
function schtask_remove () {
	
}


# obtenir liste des ban
function ban_read {
	if ( test-path $BannedIPLog ) {
		$r = @{}
		[xml]$ip = get-content $BannedIPLog
		$ip.wail2ban.ban | % { $r += @{ "ip" = $_.ip ; "date" = $_.date ; "release" = $_.release } }
		return $r
	}
}


# enregistrer liste des ban
# accepte en entrée : @(
#							@{ "ip" = "x.x.x.x" ; "date" = "EPOCH" ; "release" = EPOCH } ,
#							@{ "ip" = "x.x.x.x" ; "date" = "EPOCH" ; "release" = EPOCH }
#						)
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
# lecture bans, ajout ban, écriture bans, màj parefeu, logfile, logwin, mail
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
		# log win
		# mail
	}
}


# lecture log
# recup des logs
function detect {
	foreach ( $categorie in $Categories ) {
		$regroup = @{}

		$filtre = @{ Logname = $Categorie.source ; id = $Categorie.id ; StartTime = $(Get-Date).AddSeconds(-$Check_Window) }
		$Tries = Get-WinEvent -FilterHashtable $filtre -ErrorAction SilentlyContinue | Get-WinEventData

		foreach ( $trie in $Tries ) {
			if ( ! $regroup.contains( $trie.ip ) ) {
				[int]$regroup.( $trie.ip ) = 1
			} else {
				$regroup.( $trie.ip ) ++
			}
		}
		$regroup.Keys | ? { $regroup.$_ -gt $Check_Count } | % { ban ( $regroup.$_ ) }
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


#:!
if ( $reg.IsPresent ) {
	actioned "Intégration de $FirewallRule"
	# vérif existence tâche expiration
	# --> création tâche expiration
	# analyse config
	# recherche des tâches d'interception
	# --> si une tâche a sa ligne de config -> suppression ligne de config
	# --> si une tâche N'a PAS sa ligne de config -> suppression tâche
	# ajout des tâches restantes dans la config
	exit 0
}


#:!
if ( $unreg.IsPresent ) {
	# supprimer tâche d'expiration
	# supprimer tâches d'interception
}


detect
