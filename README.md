# Summary
This is a Powershell module meant to reliably return 

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
Default is `50`.  

### -PassThru
Optional switch.  
Returns the entire gathered and calculated set of data, rather than just a summary of select attributes.  

# Notes
- It uses events 6005, 6006, and 6008 as authoritative proof of boots and shutdowns. See the script comments for documentation on the various relevant event IDs.
- Currently it doesn't account for timezones, or do any of the fancy stats math that uptime.exe does. However, it returns a proper array of PowerShell objects, so that stuff could be done after the fact.
- It does account for unexpected shutdowns.
- Use "localhost" to get history for the local computer.
- By mseng3. See my other projects here: https://github.com/mmseng/code-compendium.