# Ensure Invoke-DOSfuscation module was properly imported before continuing.
if (-not (Get-Module Invoke-DOSfuscation | where-object {$_.ModuleType -eq 'Script'}))
{
    # Get location of this script no matter what the current directory is for the process executing this script.
    $scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 

    $pathToPsd1 = "$scriptDir\..\Invoke-DOSfuscation.psd1"

    if (Test-Path $pathToPsd1)
    {
        Import-Module "$scriptDir\..\Invoke-DOSfuscation.psd1" -Force
    }
    else
    {
        Write-Warning "Invoke-DOSfuscation module manifest could not be found at $pathToPsd1"
                
        Start-Sleep -Seconds 1
        exit
    }
}


# Increase this number for more thorough testing.
$iterations = 3


Describe 'Out-EnvVarEncodedCommand' {
    It 'Encodes known string (case-sensitive)' {
        ("ECHO " + (Out-EnvVarEncodedCommand -StringToEncode 'PESTER_TEST' -MaintainCase) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1) | Should BeExactly 'PESTER_TEST'
    }
    
    It 'Encodes known string (case-insensitive)' {
        ("ECHO " + (Out-EnvVarEncodedCommand -StringToEncode 'PESTER_TEST') | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1) | Should Be 'PESTER_TEST'
    }
    
    It 'Encodes randomly-generated string (case-sensitive)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        ("ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -MaintainCase) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1) | Should BeExactly $randomString
    }
    
    It 'Encodes randomly-generated string (case-insensitive)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        ("ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1) | Should Be $randomString
    }

    It 'Encodes randomly-generated string * $iterations (case-sensitive :: -ObfuscationLevel 1)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -ObfuscationLevel 1 -MaintainCase) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly $randomString
        ($results | Group-Object).Name | Should BeExactly $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Encodes randomly-generated string * $iterations (case-sensitive :: -ObfuscationLevel 2)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -ObfuscationLevel 2 -MaintainCase) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly $randomString
        ($results | Group-Object).Name | Should BeExactly $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Encodes randomly-generated string * $iterations (case-sensitive :: -ObfuscationLevel 3)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -ObfuscationLevel 3 -MaintainCase) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly $randomString
        ($results | Group-Object).Name | Should BeExactly $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }

    It 'Encodes randomly-generated string * $iterations (case-insensitive :: -ObfuscationLevel 1)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -ObfuscationLevel 1 ) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be $randomString
        ($results | Group-Object).Name | Should Be $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }

    It 'Encodes randomly-generated string * $iterations (case-insensitive :: -ObfuscationLevel 2)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -ObfuscationLevel 2 ) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be $randomString
        ($results | Group-Object).Name | Should Be $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Encodes randomly-generated string * $iterations (case-insensitive :: -ObfuscationLevel 3)' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Out-EnvVarEncodedCommand -StringToEncode $randomString -ObfuscationLevel 3 ) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be $randomString
        ($results | Group-Object).Name | Should Be $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Get-ObfuscatedCmd' {
    It 'Generates obfuscated syntax for "cmd" * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (Get-ObfuscatedCmd) + ' /c echo PESTER_TEST' | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "cmd" * $iterations (-ObfuscationLevel 1)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $syntax = 'ECHO ' + (Get-ObfuscatedCmd -ObfuscationLevel 1)
            $results += $syntax | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be 'cmd'
        ($results | Group-Object).Name | Should Be 'cmd'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "cmd" * $iterations (-ObfuscationLevel 2)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $syntax = (Get-ObfuscatedCmd -ObfuscationLevel 2)
            $syntax = ($syntax.Split('%')[0..1] -join '%') + 'ECHO %' + $syntax.Split('%')[2]
            $results += $syntax | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be 'cmd'
        ($results | Group-Object).Name | Should Be 'cmd'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "cmd" * $iterations (-ObfuscationLevel 3)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $syntax = (Get-ObfuscatedCmd -ObfuscationLevel 3)
            $syntax = ($syntax.Split('%')[0..1] -join '%') + 'ECHO %' + $syntax.Split('%')[2]
            $results += $syntax | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be 'cmd'
        ($results | Group-Object).Name | Should Be 'cmd'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Get-ObfuscatedPowerShell' {
    It 'Generates obfuscated syntax for "powershell" * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Get-ObfuscatedPowerShell) | C:\Windows\System32\cmd.exe | select-string '^Windows PowerShell' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'Windows PowerShell '
        ($results | Group-Object).Name | Should BeExactly 'Windows PowerShell '
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "powershell" * $iterations (-ObfuscationLevel 1)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $syntax = 'ECHO ' + (Get-ObfuscatedPowerShell -ObfuscationLevel 1)
            $results += $syntax | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be 'PowerShell'
        ($results | Group-Object).Name | Should Be 'PowerShell'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "powershell" * $iterations (-ObfuscationLevel 2)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $syntax = (Get-ObfuscatedPowerShell -ObfuscationLevel 2)
            $syntax = ($syntax.Split('%')[0..1] -join '%') + 'ECHO %' + $syntax.Split('%')[2]
            $results += $syntax | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be 'powershell'
        ($results | Group-Object).Name | Should Be 'powershell'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "powershell" * $iterations (-ObfuscationLevel 3)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $syntax = (Get-ObfuscatedPowerShell -ObfuscationLevel 3)
            $syntax = ($syntax.Split('%')[0..1] -join '%') + 'ECHO %' + $syntax.Split('%')[2]
            $results += $syntax | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be 'powershell'
        ($results | Group-Object).Name | Should Be 'powershell'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Out-DosConcatenatedCommand' {
    It 'Generates obfuscated command via Concatenation * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosConcatenatedCommand -Command 'echo PESTER_TEST') | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Concatenation * $iterations (-ObfuscationLevel 1)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosConcatenatedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 1) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Concatenation * $iterations (-ObfuscationLevel 2)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosConcatenatedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 2) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Concatenation * $iterations (-ObfuscationLevel 3)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosConcatenatedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 3) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Out-DosReversedCommand' {
    It 'Generates obfuscated command via Reversing * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosReversedCommand -Command 'echo PESTER_TEST') | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Reversing * $iterations (-ObfuscationLevel 1)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosReversedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 1) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Reversing * $iterations (-ObfuscationLevel 2)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosReversedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 2) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Reversing * $iterations (-ObfuscationLevel 3)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosReversedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 3) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Out-DosFORcodedCommand' {
    It 'Generates obfuscated command via FORcoding * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosFORcodedCommand -Command 'echo PESTER_TEST') | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via FORcoding * $iterations (-ObfuscationLevel 1)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosFORcodedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 1) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via FORcoding * $iterations (-ObfuscationLevel 2)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosFORcodedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 2) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via FORcoding * $iterations (-ObfuscationLevel 3)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosFORcodedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 3) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Out-DosFINcodedCommand' {
    It 'Generates obfuscated command via FINcoding * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosFINcodedCommand -Command 'echo PESTER_TEST') | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via FINcoding * $iterations (-ObfuscationLevel 1)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Out-DosFINcodedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 1) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via FINcoding * $iterations (-ObfuscationLevel 2)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosFINcodedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 2) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via FINcoding * $iterations (-ObfuscationLevel 3)' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Out-DosFINcodedCommand -Command 'echo PESTER_TEST' -ObfuscationLevel 3) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}


Describe 'Invoke-DOSfuscation (CLI)' {
    It 'Encodes randomly-generated string * $iterations' {
        $randomString = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(5..25)))
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += "ECHO " + (Invoke-DOSfuscation -Command $randomString -CliCommand 'ENCODING\*' -Quiet) | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should Be $randomString
        ($results | Group-Object).Name | Should BeExactly $randomString
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "cmd" * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (Invoke-DOSfuscation -CliCommand 'BINARY\CMD\*' -Quiet) + ' /c echo PESTER_TEST' | C:\Windows\System32\cmd.exe | select-object -Last 3 | select-object -First 1
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated syntax for "powershell" * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += ((Invoke-DOSfuscation -CliCommand 'BINARY\PS\*' -Quiet) | C:\Windows\System32\cmd.exe | select-string '^Windows PowerShell' | out-string) -replace "`r`n",''
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'Windows PowerShell '
        ($results | Group-Object).Name | Should BeExactly 'Windows PowerShell '
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Concatenation * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Invoke-DOSfuscation -Command 'echo PESTER_TEST' -CliCommand 'PAYLOAD\CONCAT\*' -Quiet) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
    
    It 'Generates obfuscated command via Reversing * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Invoke-DOSfuscation -Command 'echo PESTER_TEST' -CliCommand 'PAYLOAD\REVERSE\*' -Quiet) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }

    It 'Generates obfuscated command via FORcoding * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Invoke-DOSfuscation -Command 'echo PESTER_TEST' -CliCommand 'PAYLOAD\FORCODE\*' -Quiet) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }

    It 'Generates obfuscated command via FINcoding * $iterations' {
        $results = @()
        for ($i = 1; $i -le $iterations; $i++)
        {
            $results += (((Invoke-DOSfuscation -Command 'echo PESTER_TEST' -CliCommand 'PAYLOAD\FINCODE\*' -Quiet) | C:\Windows\System32\cmd.exe | select-string '^PESTER_TEST' | out-string) -replace "`r`n",'').Trim()
        }
        $results[(Get-Random -InputObject (0..($iterations - 1)))] | Should BeExactly 'PESTER_TEST'
        ($results | Group-Object).Name | Should BeExactly 'PESTER_TEST'
        ($results | Sort-Object -Unique).Count | Should Be 1
    }
}
