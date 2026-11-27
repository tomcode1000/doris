# Run this yourself in PowerShell. It makes a random secret for the trap's door,
# stores ONLY its SHA-256 on doris-trap, and copies the secret to your clipboard
# so you can paste it into the Fly "trap-door" connector. The secret is never
# printed, saved to disk, or seen by anyone else.
$ErrorActionPreference = 'Stop'
$org = if ($env:SPRITE_ORG) { $env:SPRITE_ORG } else { Read-Host 'Fly org name' }
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$secret = -join ($bytes | ForEach-Object { $_.ToString('x2') })
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($secret)) | ForEach-Object { $_.ToString('x2') })
& "$env:LOCALAPPDATA\Programs\Sprite\sprite.exe" exec --no-stdin -o $org -s doris-trap -- bash -c "echo $hash > /home/sprite/trap/door.sha256 && echo hash stored"
Set-Clipboard -Value $secret
Write-Host 'Secret copied to clipboard. Paste it into the Fly connector, then copy something else to clear it.'
