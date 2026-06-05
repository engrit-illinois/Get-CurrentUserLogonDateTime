# THIS SCRIPT IS A WORK IN PROGRESS

# Summary
This is a Powershell module meant to reliably return the current user's logon DateTime as determined by event viewer logs (specifically event #4624). This allows for a time resolution on the order of seconds, as opposed to minutes when using the `query` command. However it also frequently returns extraneous events since logging on often creates multiple events, and logon events are also triggered by other authorization processes.  

# Usage
1. Download `Get-CurrentUserLogonTime.psm1` to the appropriate subdirectory of your PowerShell [modules directory](https://github.com/engrit-illinois/how-to-install-a-custom-powershell-module).
2. Use it, e.g.: `Get-CurrentUserLogonTime -ComputerName "computer-name-01"`

# Parameters

### -ComputerName [string]
Required string.  
The name of the target computer.  

### -MaxLastEvents [int]
Optional integer.  
The maximum number of target events to return.  
The events are filtered to those relating to the current user, and sorted by their `TimeCreated` property, then the most recent X number of events are returned, where X is specified by `-MaxLastEvents`.  
Default is `100`.  

### -PassThru
Optional switch.  
Returns the entire gathered and calculated set of data, rather than just a summary of select attributes.  

# Notes
- By mseng3. See my other projects here: https://github.com/mmseng/code-compendium.