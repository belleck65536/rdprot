################################################################################
#
#
# -uninstall  : supprimer tâche planifiée et règle de pare-feu ?
# -...
#
# quand le script est exécuté sans argument, on tente une détection
# si déclenchement positif, traitement de bannissement :
# 	màj parefeu (expiration implicite)
# 	communication
#
# -unban <ip> : révoquer un bannissement (all = tout vider)
# -expire     : mise à jour parefeu sans analyse (redondance ? en fait si je
#               lance une détection alors que les logs sont clean, il n'y aura
#               pas d'impact sur la liste des bans, seul le temps de traitement
#               sera impacté
#
################################################################################
#

$DebugPreference = "continue"


################################################################################
#  Files
#
#:! revoir dossier du script et nom du script
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


$WhiteList += $( Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred ).IPAddress


# regex IPv4
New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')


#:! Ban Count structure
$BannedIPs = @{}


# Incoming event structure
$CheckEvents = New-object system.data.datatable( "CheckEvents" )
$null = $CheckEvents.columns.add( "EventLog" )
$null = $CheckEvents.columns.add( "EventID" )
$null = $CheckEvents.columns.add( "EventDescription" )


#:! voir si netsh ne peut pas totalement être remplacé par un cmdlet PS --> incompatible avec NT6.1
$OSVersion = invoke-expression "wmic os get Caption /value"
#if ( $OSVersion -match "2008" ) { $BLOCK_TYPE = "NETSH" } # compatibilité NT6.1
if ( $OSVersion -match "2012" ) { $BLOCK_TYPE = "NETSH" }
if ( $OSVersion -match "2016" ) { $BLOCK_TYPE = "NETSH" }


################################################################################
# Functions
#
function help {
	"`nwail2ban   `n"
	"wail2ban is an attempt to recreate fail2ban for windows, hence [w]indows f[ail2ban]."
	" "
	"wail2ban takes configured events known to be audit failures, or similar, checks for "+`
	"IPs in the event message, and given sufficient failures, bans them for a small amount"+`
	"of time."
	" "
	"Settings: "
	" -config    : show the settings that are being used "
	" -jail      : show the currently banned IPs"
	" -jailbreak : bust out all the currently banned IPs"
	" -help      : This message."
	" "
}


# journalisation vers Windows
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


# Log things to file and debug
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


# mise à jour règle
# accepte un tableau mono-dimension
#:! s'assurer que $ip n'est pas nul sinon ne pas traiter la mise à jour
function fw_rule_update ( $ip ) {
	fw_rule_create
	Get-NetFirewallRule -DisplayName $FirewallRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $ip
}


# suppression règle pare-feu
function fw_rule_remove {
	Remove-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
}


# obtenir liste des ban
function ban_read {
	if ( test-path $BannedIPLog ) {
		$r = @{}
		[xml]$ip = get-content $BannedIPLog
		$ip.wail2ban.ban | % { $r += @{ "ip" = $_.ip ; "date" = $_.date } }
		return $r
	}
}


# enregistrer liste des ban
# accepte en entrée une liste de tableau à 2 dimensions
# @( @{ "ip" = "x.x.x.x" ; "date" = "EPOCH" } , @{ "ip" = "x.x.x.x" ; "date" = "EPOCH" } )
function ban_write ( $bans ) {
	$w2b = new-object System.Xml.XmlDocument
	$w2b.AppendChild( $w2b.CreateElement( "wail2ban" ) )

	foreach ( $b in $bans ) {
		$ip = $w2b.CreateAttribute( "ip" )
		$ip.Value = $b.ip

		$date = $w2b.CreateAttribute( "date" )
		$date.Value = $b.date

		$ban = $w2b.CreateElement( "ban" )
		$ban.Attributes.Append( $ip )
		$ban.Attributes.Append( $date )

		$w2b.LastChild.AppendChild( $ban )
	}

	$w2b.Save( $BannedIPLog )
}


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
# @( @{ "ip" = "x.x.x.x" ; "date" = "EPOCH" } , @{ "ip" = "x.x.x.x" ; "date" = "EPOCH" } )
function ip_of_not_expired_bans ( $bans ) {
	$ips = @()
	$now = epoch ( get-date )
	foreach ( $ban in $bans ) {
		if ( $( [int]$Max_BanDuration + $ban.date ) -ge $now ) {
			$ips += $ban.ip
		}
	}
	return $ips
}


# Ban the IP (with checking)
# ip en entrée
# lecture bans, ajout ban, écriture bans, màj parefeu, logfile, logwin, mail
#:!
function ban ( $ip ) {
	if ( is_whitelisted ( $ip ) ) {
		warning "L'ip protégée $ip a déclenché un bannissement"
	} else {
		$b = ban_read
		$b += @{ "ip" = $ip ; "date" = $( epoch ( get-date ) ) } # EPOCH
		ban_write ( $b )
		fw_rule_update ( ip_of_not_expired_bans ( $b ) )
		actioned "$ip vient de se faire bannir"
		# log win
		# mail
	}
}


# lecture log
# pour chaque catégorie d'event :
#	créer hashtable de regroupement
#	requêter adns une variable les évènements selon les critères :
#		log = celui de l'entry
#		ID = celui de l'entry
#		durée de look before = celle de la conf
#	pour chaque ligne de l'extract des logs windows :
#		tester existence de $hashtable.$IP --> créer si besoin avec [int]$hashtable.$IP = 0
#		incrémenter $hashtable.$IP
#	sélectionner toutes les $hashtable.$IP >= 
function detect {
	#
}


################################################################################
################################################################################


# Unban the IP (with checking)
# 
function jail_release ($IP) { 
	if ((rule_exists $IP) -eq "No") {
		debug "$IP firewall listing doesn't exist. Can't remove it."
	} else {
		firewall_remove $IP
	}
}


#Remove any expired bans
function unban_old_records {
	$jail = get_jail_list
	if ($jail) {
		foreach ($inmate in $jail) {
			$IP = $inmate.Name.substring($FirewallRule.length+1)
			$ReleaseDate = $inmate.Description.substring("Expire: ".Length)

			if ($([int]([datetime]$ReleaseDate- (Get-Date)).TotalSeconds) -lt 0) { 
				debug "Unban old records: $IP looks old enough $(get-date $ReleaseDate -format G)"
				jail_release $IP
			}
		}
	}
}


#Convert the TimeGenerated time into Epoch
function WMIDateStringToDateTime ([String] $iSt) {
	$iSt.Trim() > $null
	$iYear   = [Int32]::Parse($iSt.SubString( 0, 4))
	$iMonth  = [Int32]::Parse($iSt.SubString( 4, 2))
	$iDay    = [Int32]::Parse($iSt.SubString( 6, 2))
	$iHour   = [Int32]::Parse($iSt.SubString( 8, 2))
	$iMinute = [Int32]::Parse($iSt.SubString(10, 2))
	$iSecond = [Int32]::Parse($iSt.SubString(12, 2))
	$iMilliseconds = 0
	$iUtcOffsetMinutes = [Int32]::Parse($iSt.Substring(21, 4))
	if ( $iUtcOffsetMinutes -ne 0 )  {
		$dtkind = [DateTimeKind]::Local
	} else {
		$dtkind = [DateTimeKind]::Utc
	}
	$ReturnDate = New-Object -TypeName DateTime -ArgumentList $iYear, $iMonth, $iDay, $iHour, $iMinute, $iSecond, $iMilliseconds, $dtkind
	return ( get-date $ReturnDate -UFormat "%s" )
}


# Remove recorded access attempts, by IP, or expired records if no IP provided.
function clear_attempts ($IP = 0) {
	$Removes = @()
	foreach ($a in $Entry.GetEnumerator()) {
		if ($IP -eq 0) {
			if ([int]$a.Value[1]+$CHECK_WINDOW -lt (get-date ((get-date).ToUniversalTime()) -UFormat "%s").replace(",",".")) {
				$Removes += $a.Key
			}
		} else {
			foreach ($a in $Entry.GetEnumerator()) {
				if ($a.Value[0] -eq $IP) {
					$Removes += $a.Key
				}
			}
		}
	}
	foreach ($b in $Removes) { $Entry.Remove($b) }
}


################################################################################
#Process input parameters
if ($setting) { debug "wail2ban started. $setting" }

#Display current configuration.
if ($args -match "-config") {
	write-host "`nwail2ban is currently configured to: `n ban IPs for " -nonewline
	for ($i = 1; $i -lt 5; $i++) { write-host (""+[math]::pow(5,$i)+", ") -foregroundcolor "cyan" -nonewline }
	write-host "... $($MAX_BANDURATION/60) " -foregroundcolor "cyan" -nonewline
	write-host " minutes, `n if more than " -nonewline
	write-host $CHECK_COUNT -foregroundcolor "cyan" -nonewline
	write-host " failed attempts are found in a " -nonewline
	write-host $CHECK_WINDOW -foregroundcolor "cyan" -nonewline
	write-host " second window. `nThis process will loop every time a new record appears. "
	write-host "`nIt's currently checking:"
	foreach ($event in $CheckEvents ) { "- "+$Event.EventLog+" event log for event ID "+$Event.EventDescription+" (Event "+$Event.EventID+")"}
	write-host "`nAnd we're whitelisting: "
	foreach ($white in $whitelist) { write-host "- $($white)" -foregroundcolor "cyan" -nonewline }
	write-host "in addition to any IPs present on the network interfaces on the machine"
	exit
}


# Release all current banned IPs
if ($args -match "-jailbreak") {
	actioned "Jailbreak initiated by console. Removing ALL IPs currently banned"
	$EnrichmentCentre = get_jail_list
	if ($EnrichmentCentre) {
		"`nAre you trying to escape? [chuckle]"
		"Things have changed since the last time you left the building."
		"What's going on out there will make you wish you were back in here."
		" "
		foreach ($subject in $EnrichmentCentre) {
			$IP = $subject.name.substring($FirewallRulePrefix.length+1)
			firewall_remove $IP
		}
		clear-content $BannedIPLog
	} else {
		"`nYou can't escape, you know. `n`n(No current firewall listings to remove.)"
	}
	exit
}


# Show the inmates in the jail.
if ($args -match "-jail") {
	$inmates = get_jail_list
	if ($inmates) {
		"wail2ban currently banned listings: `n"
		foreach ($a in $inmates) {
			$IP = $a.name.substring($FirewallRulePrefix.length+1)
			$Expire = $a.description.substring("Expire: ".length)
			""+$IP.PadLeft(14)+" expires at $Expire"
		}
		"`nThis is a listing of the current Windows Firewall with Advanced Security rules, starting with `""+$FirewallRulePrefix+" *`""
	} else {
		"There are no currrently banned IPs"
	}
	exit
}


#Unban specific IP. Remove associated schtask, if exists.
if ($args -match "-unban") {
	$IP = $args[ [array]::indexOf($args,"-unban")+1]
	actioned "Unban IP invoked: going to unban $IP and remove from the log."
	jail_release $IP
	( gc $BannedIPLog ) | ? { $_ -notmatch $IP } | sc $BannedIPLog # remove IP from ban log
	exit
}


# Display Help Message
if ( $args -match "-help" ) {
	help
	exit 0
}

################################################################################
#Setup for the loop
 
$SinkName = "LoginAttempt"
$Entry = @{}
$eventlist ="("
foreach($a in $CheckEvents) {
	$eventlist+="(TargetInstance.EventCode=$($a.EventID) and TargetInstance.LogFile='$($a.EventLog)') OR "
}
$eventlist = $eventlist.substring(0,$eventlist.length-4)+")"
$query = "SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND $eventlist"

actioned "wail2ban invoked"
actioned "Checking for a heap of events: "
$CheckEvents | %{ actioned " - $($_.EventLog) log event code $($_.EventID)" }
actioned "The Whitelist: $whitelist"
actioned "The Self-list: $Selflist"

pickupBanDuration


################################################################################
#Loop!

Register-WMIEvent -Query $query -sourceidentifier $SinkName
do {
	$new_event = wait-event -sourceidentifier $SinkName
	$TheEvent = $new_event.SourceeventArgs.NewEvent.TargetInstance
	select-string $RegexIP -input $TheEvent.message -AllMatches | foreach { foreach ($a in $_.matches) {
		$IP = $a.Value
		if ($SelfList -match $IP) {
			debug "Whitelist of self-listed IPs! Do nothing. ($IP)"
		} else {
			$RecordID = $TheEvent.RecordNumber
			$EventDate = WMIDateStringToDateTime($TheEvent.TIMEGenerated)
			$Entry.Add($RecordID, @($IP,$EventDate))

			$IPCount = 0
			foreach ($a in $Entry.Values) { if ($IP -eq $a[0]) { $IPCount++ } }
			debug "$($TheEvent.LogFile) Log Event captured: ID $($RecordID), IP $IP, Event Code $($TheEvent.EventCode), Attempt #$($IPCount). "

			if ($IPCount -ge $CHECK_COUNT) {
				jail_lockup $IP
				clear_attempts $IP
			}
			clear_attempts
			unban_old_records
		}
	}}

	Remove-event  -sourceidentifier $SinkName

} while ($true)


