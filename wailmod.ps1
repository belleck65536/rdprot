################################################################################
#
#
# sur évènement/tache planhifiée :
# argument = -detect
# sur la période définie,
# comptabiliser par IP le nombre de tentative
# en cas de dépassement -->
# vérif si IP whitelistée, si non exemptée --> procédure de ban
#    ajout au banlog (IP + date de ban)
#    modification de la règle (ajout de l'IP)
#
$ip = $e.CreateElement("ip") # création d'un noeud
# $ip.SetAttribute('name','barracas') # pour ajouter des atrtibuts à un noeud
$ip.InnerText = "0.0.0.0/1"
$e.wail2ban.whitelist.AppendChild($ip)
$e.Save(".\ee.xml")
################################################################################
#

$DebugPreference = "continue"


################################################################################
#  Files
#
#:! revoir dossier du script et nom du script
$wail2banInstall = ""+(Get-Location)+"\"
$wail2banScript  = $wail2banInstall+"wail2ban.ps1"  #$MyInvocation.MyCommand.Name
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


$CHECK_WINDOW		= $cfg.wail2ban.conf.CHECK_WINDOW
$CHECK_COUNT		= $cfg.wail2ban.conf.CHECK_COUNT
$MAX_BANDURATION	= $cfg.wail2ban.conf.MAX_BANDURATION
$RecordEventLog		= $cfg.wail2ban.conf.w2b_log     # Where we store our own event messages
$WhiteList			= $cfg.wail2ban.whitelist.ip

if ( $CHECK_WINDOW -lt 0 ) { exit 2 }
if ( $CHECK_COUNT -lt 0 ) { exit 2 }
if ( $MAX_BANDURATION -lt 0 ) { exit 2 }

$EventTypes = "Application,Security,System"          #Event logs we allow to be processed
$FirewallRule = "Wail2Ban"  # What we name our Rules


# regex IPv4
New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')


#:! Ban Count structure
$BannedIPs = @{}


# Incoming event structure
$CheckEvents = New-object system.data.datatable("CheckEvents")
$null = $CheckEvents.columns.add("EventLog")
$null = $CheckEvents.columns.add("EventID")
$null = $CheckEvents.columns.add("EventDescription")


#:! voir si netsh ne peut pas totalement être remplacé par un cmdlet PS --> incompatible avec NT6.1
$OSVersion = invoke-expression "wmic os get Caption /value"
#if ($OSVersion -match "2008") { $BLOCK_TYPE = "NETSH" } # compatibilité NT6.1
if ($OSVersion -match "2012") { $BLOCK_TYPE = "NETSH" }
if ($OSVersion -match "2016") { $BLOCK_TYPE = "NETSH" }


#:! Get-NetAdapter
#:! mettre SelfList dans whitelist
$SelfList = $(Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred).IPAddress


################################################################################
# Functions
#
# For help, read the below function.
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


# vérification présence règle
function fw_rule_exists {
	return $( Get-NetFirewallRule -DisplayName $prefixe )
}


# création règle pare feu
function fw_rule_create {
	if ( ! $(fw_rule_exists) ) {
		New-NetFirewallRule -DisplayName $prefixe -Enabled -Profile Any -Direction Inbound -Action Block -Protocol Any
	}
}

# mise à jour règle
function fw_rule_update ( $ip ) {
	if ( ! $(fw_rule_exists) ) {
		fw_rule_create
	}
	Get-NetFirewallRule -DisplayName $prefixe | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $ip
}



# journalisation vers Windows
function event ($text,$task,$result) {
	$event = new-object System.Diagnostics.EventLog($RecordEventLog)
	$event.Source="wail2ban"
	switch  ($task) {
		"ADD"    { $logeventID = 1000 }
		"REMOVE" { $logeventID = 2000 }
	}
	switch ($result) {
		"FAIL"   { $eventtype = [System.Diagnostics.EventLogEntryType]::Error; $logeventID += 1 }
		default  { $eventtype = [System.Diagnostics.EventLogEntryType]::Information}
	}
	$event.WriteEntry($text,$eventType,$logeventID)
}


#Log things to file and debug
#:! est-ce qu'il faut tout logguer ?
function log ($type, $text) {
	$output = ""+(get-date -format u).replace("Z","")+" $tag $text"
	if ($type -eq "A") { $output | out-file $logfile -append}
	switch ($type) {
		"D" { write-debug $output}
		"W" { write-warning "WARNING: $output"} 
		"E" { write-error "ERROR: $output"}
		"A" { write-debug $output }
	}
}


#Log type functions
function error		($text) { log "E" $text }
function warning	($text) { log "W" $text }
function debug		($text) { log "D" $text }
function actioned	($text) { log "A" $text }


#Get the current list of wail2ban bans
#:! tranformer en cmdlet PS
function get_jail_list {
	$fw = New-Object -ComObject hnetcfg.fwpolicy2
	return $fw.rules | Where-Object { $_.name -match $FirewallRule } | Select name, description
}


# Confirm if rule exists.
#:! tranformer en cmdlet PS
#:! retourner true/false
function rule_exists ($IP) {
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall show rule name=`"$FirewallRule $IP`""}
		default { error "Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($rule) { 
		$result = invoke-expression $rule
		if ($result -match "----------") {
			return "Yes"
		}  else { 
			return "No"
		}
	}
}


#Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
#:! récupérer mon netmask
function netmask($MaskLength) {
	$IPAddress =  [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
	$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
		$Remainder = $IPAddress % [Math]::Pow(256, $i)
		($IPAddress - $Remainder) / [Math]::Pow(256, $i)
		$IPAddress = $Remainder
	} )

	Return [String]::Join('.', $DottedIP)
}


#check if IP is whitelisted
#:! retourner true/false
#:! renommer is_whitelisted
function whitelisted ($IP) {
	foreach ($white in $Whitelist) {
		if ($IP -eq $white) {
			$Whitelisted = "Uniquely listed."
			break
		}
		if ($white.contains("/")) {
			$Mask =  netmask($white.Split("/")[1])
			$subnet = $white.Split("/")[0]
			if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$Mask).Address ) -eq`
			(([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) {
				$Whitelisted = "Contained in subnet $white"
				break
			}
		}
	}
	return $Whitelisted
}


#Read in the saved file of settings. Only called on script start, such as after reboot
function pickupBanDuration {
	if (Test-Path $BannedIPLog) {
		get-content $BannedIPLog | %{
			if (!$BannedIPs.ContainsKey($_.split(" ")[0])) {
				$BannedIPs.Add($_.split(" ")[0],$_.split(" ")[1])
			}
		}
		debug "$BannedIPLog ban counts loaded"
	} else {
		debug "No IPs to collect from BannedIPLog"
	}
}


#Get the ban time for an IP, in seconds
function getBanDuration ($IP) {
	if ( $BannedIPs.ContainsKey($IP) ) {
		[int]$Setting = $BannedIPs.Get_Item($IP)
	} else {
		$Setting = 0
		$BannedIPs.Add($IP,$Setting)
	}
	$Setting++
	$BannedIPs.Set_Item($IP,$Setting)
	$BanDuration =  [math]::min([math]::pow(5,$Setting)*60, $MAX_BANDURATION)
	debug "IP $IP has the new setting of $setting, being $BanDuration seconds"
	if (Test-Path $BannedIPLog) {
		clear-content $BannedIPLog
	} else {
		New-Item $BannedIPLog -type file
	}
	$BannedIPs.keys | %{ "$_ "+$BannedIPs.Get_Item($_) | Out-File $BannedIPLog -Append }
	return $BanDuration
}


# Ban the IP (with checking)
function jail_lockup ($IP, $ExpireDate) {
	$result = whitelisted($IP)
	if ($result) {
		warning "$IP is whitelisted, except from banning. Why? $result "
	} else {
		if (!$ExpireDate) {
			$BanDuration = getBanDuration($IP)
			$ExpireDate = (Get-Date).AddSeconds($BanDuration)
		}
		if ((rule_exists $IP) -eq "Yes") {
			warning ("IP $IP already blocked.")
		} else {
			firewall_add $IP $ExpireDate
		}
	}
}


# Unban the IP (with checking)
function jail_release ($IP) { 
	if ((rule_exists $IP) -eq "No") {
		debug "$IP firewall listing doesn't exist. Can't remove it."
	} else {
		firewall_remove $IP
	}
}


# Add the Firewall Rule
function firewall_add ($IP, $ExpireDate) {
	$Expire = (get-date $ExpireDate -format u).replace("Z","")
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall add rule name=`"$FirewallRule $IP`" dir=in protocol=any action=block remoteip=$IP description=`"Expire: $Expire`"" }
		default { error "Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($rule) {
		$result = invoke-expression $rule
		if ($LASTEXITCODE -eq 0) {
			$BanMsg = "Action Successful: Firewall rule added for $IP, expiring on $ExpireDate"
			actioned "$BanMsg"
			event "$BanMsg" ADD OK
		} else {
			$Message = "Action Failure: could not add firewall rule for $IP,  error: `"$result`". Return code: $LASTEXITCODE"
			error $Message 
			event $Message ADD FAIL
		}
	}
}


# Remore the Filewall Rule
function firewall_remove ($IP) {
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall delete rule name=`"$FirewallRule $IP`""}
		default { error "Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($rule) {
		$result = invoke-expression $rule
		if ($LASTEXITCODE -eq 0) {
			actioned "Action Successful: Firewall ban for $IP removed"
			event "Removed IP $IP from firewall rules"  REMOVE OK
		} else {
			$Message = "Action Failure: could not remove firewall rule for $IP,  error: `"$result`". Return code: $LASTEXITCODE"
			error $Message
			event $Message REMOVE FAIL
		}
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
	(gc $BannedIPLog) | ? {$_ -notmatch $IP } | sc $BannedIPLog # remove IP from ban log
	exit
}


#Display Help Message
if ($args -match "-help") {
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

