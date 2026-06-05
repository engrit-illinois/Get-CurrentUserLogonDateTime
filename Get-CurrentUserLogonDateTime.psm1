# Documentation home: https://github.com/engrit-illinois/Get-CurrentUserLogonDateTime
# By mseng3

function Get-CurrentUserLogonDateTime {

	[CmdletBinding()]
	param(
		[switch]$PassThru,
		[int]$MaxLastEvents = 100
	)
	
	begin {
		function log {
			param(
				[string]$Msg
			)
			Write-Host $Msg
		}
		
		function Translate-LogonType($logonType) {
			# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787567(v=ws.10)
			# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession#properties
			switch($logonType) {
				"2" { "Interactive" }
				"3" { "Network" }
				"4" { "Batch" }
				"5" { "Service" }
				"6" { "Proxy" }
				"7" { "Unlock" }
				"8" { "NetworkCleartext" }
				"9" { "NewCredentials" }
				"10" { "RemoteInteractive" }
				"11" { "CachedInteractive" }
				"12" { "CachedRemoteInteractive " }
				"13" { "CachedUnlock " }
				default { "Unknown" }
			}
		}
		
		function Get-Events {
			
			# Get all login events
			$filter = @{
				LogName = "Security"
				Id = 4624
			}
			$params = @{
				FilterHashTable = $filter
			}
			
			$events = Get-WinEvent @params -ErrorAction "SilentlyContinue"
			
			# Initial quick filter based on whether current username is found anywhere in the giant Message string property
			# Filtering down to the exact username will be easier after parsing out this string into individual properties
			$events = $events | Where { $_.Message -like "*Account Name:*$($env:UserName)*" } | Sort "TimeCreated" | Select -Last $MaxLastEvents
			
			# Define the assumed structure of the giant Message string property
			# If this structure output by Get-WinEvent (for this particular event) ever changes, this will break everything,
			# but we can re-define that here.
			# We just have to hope that this structure is consistent across all machines in all cases, for a given version of Get-WinEvent.
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
			
			<# Example structure of Message property:
			
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
			
			# Parse out interesting individual properties from the giant Message string proptery
			$events = $events | ForEach-Object {
				$event = $_
				
				$lines = $event.Message -split "`n"
				
				$messageLineFormats | ForEach-Object {
					$value = $lines[$_.LineNum] -replace "\s","" -replace $_.Label,""
					$event | Add-Member -NotePropertyName $_.Property -NotePropertyValue $value.Trim()
				}
				
				$logonTypeFriendly = Translate-LogonType $event.LogonType
				$event | Add-Member -NotePropertyName "LogonTypeFriendly" -NotePropertyValue $logonTypeFriendly
				
				$logonIdInt = [int]$event.LogonId
				$event | Add-Member -NotePropertyName "LogonIdInt" -NotePropertyValue $logonIdInt
				
				$linkedLogonIdInt = [int]$event.LinkedLogonId
				$event | Add-Member -NotePropertyName "LinkedLogonIdInt" -NotePropertyValue $linkedLogonIdInt
				
				$event
			}
			
			$events
		}
	}
	
	process {
		# Get all relevant data
		$sessions = Get-CimInstance "Win32_LogonSession" | Select *
		$logonIds = Get-CimInstance "Win32_LoggedOnUser" | Select *
		$events = Get-Events
		
		# Combine data from Win32_LogonSession, Win32_LoggedOnUser, and Get-WinEvent
		$sessions = $sessions | ForEach-Object {
			$session = $_ 
			
			# Translate LogonType of Win32_LogonSession
			$session | Add-Member -NotePropertyName "LogonTypeFriendly" -NotePropertyValue (Translate-LogonType $session.LogonType);
			
			# Combine data from Win32_LoggedOnUser
			$logonId = $logonIds | Where { $_.Dependent.LogonId -eq $session.LogonId }
			$user = $logonId.Antecedent.Name
			$session | Add-Member -NotePropertyName "User" -NotePropertyValue $user
			
			# Combine data from Get-WinEvent
			$event = $events | Where { $_.LogonIdInt -eq $session.LogonId }
			$session | Add-Member -NotePropertyName "EventTimeCreated" -NotePropertyValue $event.TimeCreated
			$session | Add-Member -NotePropertyName "EventLogonType" -NotePropertyValue $event.LogonType
			$session | Add-Member -NotePropertyName "EventLogonTypeFriendly" -NotePropertyValue $event.LogonTypeFriendly
			$session | Add-Member -NotePropertyName "EventAccountName" -NotePropertyValue $event.AccountName
			$session | Add-Member -NotePropertyName "EventProcessName" -NotePropertyValue $event.ProcessName
			
			$session
		}
		
		# Filter to sessions corresponding to the current user
		# Without this the sessions may include logins associated with apps lunched by the current user, but as a different user account
		$sessions = $sessions | Where { $_.User -eq $env:UserName }
		
		# Save a copy of sessions without filtering further to output for the -PassThru parameter
		$allUserSessions = $sessions
		
		# Of the remaining sessions, I think we should only have 2 or 3.
		# If 3, the most recent would be associated with the most recent unlock event.
		# The older 2 should be associated with the current session's original login, and they appear to always have an identical StartTime value, down to the millisecond.
		if(-not $sessions) {
			Throw "No matching sessions were identified!"
		}
		
		# Because this relies so heavily on assumptions, let's make sure to raise an error if those assumptions are incorrect
		$sessionsCount = $session.count
		if($sessionsCount -gt 3) {
			Throw "Identified more than the expected number of sessions to evaluate (found $sessionsCount)!"
		}
		
		# The TimeCreated value of the associated login event does appear to happen slightly later (on the order of hundredths of a second), but these values are still identical between the 2 distinct events.
		# So, these 2 should only differ (in relevant ways) in that one has an AuthenticationPackage property value of "Negotiate", while the other has a value of "Kerberos".
		# This property apparently denotes which authentication subsystem was used to validate the user's credentials during login.
		# It's unclear whether there would be any reason to prefer one or the other, or, more importantly, whether either is more likely to actually exist on a given system.
		# Most likely, in the target environment, both will always be present.
		# Thus, likely, we can just pick one arbitrarily (or randomly, based on sorting order). Just on principle it would be best to pick one intentionally, to maximize determinism.
		# Let's go with Kerberos I guess.
		$sessions = $sessions | Where { $_.AuthenticationPackage -eq "Kerberos" }
		
		$sessionsCount = $sessions.count
		if($sessionsCount -gt 1) {
			Throw "Identified more than the expected number of Kerberos-authenticated sessions to evaluate (found $sessionsCount)!"
		}
		if($sessionsCount -lt 1) {
			Throw "No matching Kerberos-authenticated sessions were identifed!"
		}
		
		# If any of these assumptions aren't correct, then there is no guarantee that the final result is at all accurate.
		$finalDateTime = $sessions.StartTime
	}
	
	end {
		if($PassThru) {
			$allUserSessions | Sort "StartTime" | Select LogonId,StartTime,EventTimeCreated,User,EventAccountName,LogonType,LogonTypeFriendly,EventLogonType,EventLogonTypeFriendly,AuthenticationPackage,EventProcessName
		}
		else {
			$finalDateTime
		}
	}
}