# Summary
This is a Powershell module meant to reliably return the DateTime corresponding to the exact time that the current user logged on.  

You would think this would be easy to do, and it is, sort of. The `query user` command does return a timestamp for the current session's (or rather every session's) login time. However this command is very old, not natively PowerShell-friendly (it outputs a string with horrific syntax indiosynracies), and most importantly, the logon timestamp it exposes is only accurate to the minute (it appears to round to the nearest minute). As far as I can tell there has never been any more modern native tools released which surface this same information.  

There are a couple of other sources to find this information, primarily WMI and Event Logs, but they each require quite a bit of logic and manipulation in order to narrow down the exact correct session and recover its actual start time. That is what this module does. Initially it was made to sanity check the information available through WMI against event logs to ensure accuracy. However the necessary event log data is only available to an elevated process. Once the event log data was used to understand the behavior of the relevant WMI output, the module was written to rely solely on the, now trusted, WMI output, which can be accessed without elevation.  

Currently the module only works to return the logon time of the current user; that is, the user running the module. In theory this could be generalized to work more like `query user` and return any or all users (within the limitations of `Win32_LogonSession` and `Win32_LoggedOnUser`), but that is not currently implemented.  

# Usage
1. Download `Get-CurrentUserLogonTime.psm1` to the appropriate subdirectory of your PowerShell [modules directory](https://github.com/engrit-illinois/how-to-install-a-custom-powershell-module).
2. Use it, e.g.: `Get-CurrentUserLogonTime`

# Parameters

### -PassThru
Optional switch.  
Returns an array of login events with all of the relevant data that was evaluated before being filtered to a single event and stripped to its `StartTime` value.  
Mostly for sanity checking the logic.  
Note: This parameter also causes the module to gather relevant event log data and include that in the output. When running without elevation, this will throw an error due to not being able to access the relevant event log data. Because the normal use case for this module is to be run without elevation, and the `-PassThru` output is only meant for debugging purposes, this is considered intended behavior.  

### -MaxLastEvents [int]
Optional integer.  
The maximum number of target events to search.  
Only relevant when using `-PassThru`.  
The events are filtered to those relating to the current user, and sorted by their `TimeCreated` property, then the most recent X number of events are returned, where X is specified by `-MaxLastEvents`.  
Default is `100`.  

# Notes
- By mseng3. See my other projects here: https://github.com/mmseng/code-compendium.
