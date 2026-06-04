# Documentation home: https://github.com/engrit-illinois/Get-CurrentUserLogonDateTime
# By mseng3

function Get-CurrentUserLogonDateTime {
	
	[CmdletBinding()]
	param(
		[string]$ComputerName,
		[int]$MaxLastEvents = 50,
		[switch]$PassThru
	)
	
	begin {
	
		function Translate-LogonType($logonType) {
			# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787567(v=ws.10)
			switch($logonType) {
				"2" { "Interactive" }
				"3" { "Network" }
				"4" { "Batch" }
				"5" { "Service" }
				"7" { "Unlock" }
				"8" { "NetworkCleartext" }
				"9" { "NewCredentials" }
				"10" { "RemoteInteractive" }
				"11" { "CachedInteractive" }
				default { "Unknown" }
			}
		}
	
		$filter = @{
			LogName = "Security"
			Id = 4624
		}
	}
	
	process {
		$params = @{
			FilterHashTable = $filter
		}
		if($ComputerName) { $params.ComputerName = $ComputerName }
		
		$events = Get-WinEvent @params
		
		# Initial quick filter based on whether current username is found anywhere in the giant Message string property
		# Filtering down to the exact username will be easier after parsing out this string into individual properties
		$events = $events | Where { $_.Message -like "*Account Name:*$($env:UserName)*" } | Sort "TimeCreated" | Select -Last $MaxLastEvents
		
		$messageLineFormats = @(
			[PSCustomObject]@{ Property = "Computer"; LineNum = 4; Label = "AccountName:" },
			[PSCustomObject]@{ Property = "LogonType"; LineNum = 9; Label = "LogonType:" },
			[PSCustomObject]@{ Property = "SecurityId"; LineNum = 18; Label = "SecurityID:" },
			[PSCustomObject]@{ Property = "AccountName"; LineNum = 19; Label = "AccountName:" },
			[PSCustomObject]@{ Property = "AccountDomain"; LineNum = 20; Label = "AccountDomain:" },
			[PSCustomObject]@{ Property = "LogonId"; LineNum = 21; Label = "LogonID:" },
			[PSCustomObject]@{ Property = "LinkedLogonId"; LineNum = 22; Label = "LinkedLogonID:" },
			[PSCustomObject]@{ Property = "ProcessName"; LineNum = 29; Label = "ProcessName:" },
			[PSCustomObject]@{ Property = "WorkstationName"; LineNum = 32; Label = "WorkstationName:" }
		)
		
		# Parse out interesting individual properties from the giant Message string proptery
		$events = $events | ForEach-Object {
			$event = $_
			
			$lines = $event.Message -split "`n"
			
			<# Example output
			
An account was successfully logged on.

Subject:
        Security ID:            S-1-5-18
        Account Name:           ENGRIT-MMS-HDT$
        Account Domain:         UOFI
        Logon ID:               0x3E7

Logon Information:
        Logon Type:             7
        Restricted Admin Mode:  -
        Remote Credential Guard:        -
        Virtual Account:                No
        Elevated Token:         No

Impersonation Level:            Impersonation

New Logon:
        Security ID:            S-1-5-21-2509641344-1052565914-3260824488-1361738
        Account Name:           mseng3
        Account Domain:         UOFI
        Logon ID:               0x623777A
        Linked Logon ID:                0x6235945
        Network Account Name:   -
        Network Account Domain: -
        Logon GUID:             {00000000-0000-0000-0000-000000000000}

Process Information:
        Process ID:             0x708
        Process Name:           C:\Windows\System32\lsass.exe

Network Information:
        Workstation Name:       ENGRIT-MMS-HDT
        Source Network Address: -
        Source Port:            -

Detailed Authentication Information:
        Logon Process:          Negotiat
        Authentication Package: Negotiate
        Transited Services:     -
        Package Name (NTLM only):       -
        Key Length:             0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
        - Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
        - Transited services indicate which intermediate services have participated in this logon request.
        - Package name indicates which sub-protocol was used among the NTLM protocols.
        - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
		
			#>
			
			$messageLineFormats | ForEach-Object {
				$value = $lines[$_.LineNum] -replace "\s","" -replace $_.Label,""
				$event | Add-Member -NotePropertyName $_.Property -NotePropertyValue $value.Trim()
			}
			
			$logonTypeFriendly = Translate-LogonType $event.LogonType
			$event | Add-Member -NotePropertyName "LogonTypeFriendly" -NotePropertyValue $logonTypeFriendly
			
			$event
		}
		
		# Filter down to exact username
		# Without this events for, e.g. user su-mseng3 will also show up for user mseng3, etc.
		$events = $events | Where { $_.AccountName -eq $env:UserName }
	}
	
	end {
		if($PassThru) {
			$events | Sort "TimeCreated"
		}
		else {
			$events | Sort "TimeCreated" | Select TimeCreated,LogonType,LogonTypeFriendly,AccountName,LogonId,LinkedLogonId,ProcessName
		}
	}
}