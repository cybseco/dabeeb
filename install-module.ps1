 #powershell.exe -executionpolicy bypass -file .\install-module.ps1

Import-Module .\dabeeb.psm1

Get-Module | Where-Object { $_.ModuleType -eq "Script" }
