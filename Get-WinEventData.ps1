Function Get-WinEventData {
	<#
	IN / OUT
	System.Diagnostics.Eventing.Reader.EventLogRecord

	.EXAMPLE
	Get-WinEvent -LogName system -max 1 | Get-WinEventData | Select -Property MachineName, TimeCreated, EventData*
	Get-WinEvent -ComputerName DomainController1 -FilterHashtable @{Logname='security';id=4740} -MaxEvents 10 | Get-WinEventData | Select TimeCreated, EventDataTargetUserName, EventDataTargetDomainName
	#>

	[cmdletbinding()]
		param (
			[Parameter(	Mandatory=$true, 
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

			if ( $XMLData = @( $XML.Event.EventData.Data ) ) {
				for ( $i=0 ; $i -lt $XMLData.count ; $i++ ) {
					Add-Member -InputObject $entry -MemberType NoteProperty -name "EventData$($XMLData[$i].name)" -Value $XMLData[$i].'#text' -Force
				}
			}

			$entry
		}
	}
}
