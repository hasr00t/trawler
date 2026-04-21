<#
.SYNOPSIS
  Walks an SMB share tree and captures NTFS ACLs for every file.

.DESCRIPTION
  Run from a Windows host (domain-joined, read access to the share is enough).
  Produces a TSV you can drop alongside the findings for bin/06_join.py to
  annotate each finding with who could read the file.

  Output TSV columns (tab-separated, with header):
    UncPath   Owner   Principal   Rights   Inherited   IsSystem   IsEveryone

  One row per ACE per file. "IsEveryone" flags the scariest case: public-read
  through Everyone / Authenticated Users / Domain Users.

.PARAMETER SharePath
  UNC path to walk, e.g. \\fs01\data

.PARAMETER OutFile
  Where to write the TSV.

.PARAMETER MaxItems
  Optional cap on files walked (useful for smoke-testing).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File 05_acl_snapshot.ps1 `
    -SharePath '\\fs01\data' -OutFile 'C:\analysis\acls.tsv'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SharePath,
    [Parameter(Mandatory=$true)][string]$OutFile,
    [int]$MaxItems = 0
)

$ErrorActionPreference = 'Continue'
$WarningPreference     = 'SilentlyContinue'

# Identities that mean "effectively public" on a typical enterprise share
$PublicIdentities = @(
    'Everyone',
    'NT AUTHORITY\Authenticated Users',
    'BUILTIN\Users',
    'Authenticated Users'
    # NB: 'Domain Users' is often effectively-public too; uncomment if your
    # client considers it so:
    # , "$($env:USERDOMAIN)\Domain Users"
)

$SystemIdentities = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    "$($env:USERDOMAIN)\Domain Admins",
    'CREATOR OWNER'
)

# Write header
Set-Content -Path $OutFile -Value "UncPath`tOwner`tPrincipal`tRights`tInherited`tIsSystem`tIsEveryone" -Encoding UTF8

$count = 0
Get-ChildItem -LiteralPath $SharePath -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $file = $_
    if ($MaxItems -gt 0 -and $count -ge $MaxItems) { return }
    $count++

    try {
        $acl = Get-Acl -LiteralPath $file.FullName -ErrorAction Stop
    } catch {
        return
    }

    $owner = $acl.Owner
    foreach ($ace in $acl.Access) {
        $id = $ace.IdentityReference.Value
        $isPublic = $PublicIdentities -contains $id
        $isSystem = $SystemIdentities -contains $id
        $rights = $ace.FileSystemRights.ToString()
        $line = @(
            $file.FullName,
            $owner,
            $id,
            $rights,
            $ace.IsInherited,
            $isSystem,
            $isPublic
        ) -join "`t"
        Add-Content -Path $OutFile -Value $line -Encoding UTF8
    }

    if ($count % 1000 -eq 0) {
        Write-Host "[acls] $count files processed"
    }
}

Write-Host "[acls] complete. $count files processed. Output: $OutFile"
