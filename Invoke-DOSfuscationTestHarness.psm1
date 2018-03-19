#   This file is part of Invoke-DOSfuscation.
#
#   Copyright 2018 Daniel Bohannon <@danielhbohannon>
#         while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



###########################################################################################################################################################################################
## All functions in this module are solely for the test harness functionality for Invoke-DOSfuscation and do not provide any additional obfuscation functionality.                       ##
## This test harness is meant to enabled defenders to easily define and test regex-based detection ideas for command line values of obfuscated commands produced by Invoke-DOSfuscation. ##
## In addition, this harness returns PSCustomObjects containing all user-defined detection information to help identify payloads that are undetected or only have 1-2 detection matches. ##
###########################################################################################################################################################################################


function Invoke-DosTestHarness
{
<#
.SYNOPSIS

Invoke-DosTestHarness is the orchestration engine for the Invoke-DOSfuscation test harness.

Invoke-DOSfuscation Function: Invoke-DosTestHarness
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Get-DosDetectionMatch, Test-CorrectOutput, Set-RandomArgument, Test-OutDosConcatenatedCommand, Test-OutDosReversedCommand, Test-OutDosFORcodedCommand, Test-OutDosFINcodedCommand
Optional Dependencies: None

.DESCRIPTION

Invoke-DosTestHarness is the orchestration engine for the Invoke-DOSfuscation test harness.

.PARAMETER Functions

(Optional) Specifies the test functions for the current iteration of the test harness to call.

.PARAMETER Iterations

(Optional) Specifies that number of iterations for each test command/function call combination defined in each test function.

.PARAMETER TestType

(Optional) Specifies that type/genre of test function to execute for more specific testing.

TestType values are defined as:
    1) Full obfuscation from Out-DosConcatenatedCommand with fully randomized arguments
    2) Calls Out-DosConcatenatedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosConcatenatedCommand via Invoke-DOSfuscation's CLI

.EXAMPLE

C:\PS> Invoke-TestHarness

.EXAMPLE

C:\PS> Invoke-TestHarness -Functions @('Out-DosConcatenatedCommand','Out-DosReversedCommand') -Iterations 3 -TestType @(2,3)

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { $_ | foreach-object { @('Out-DosConcatenatedCommand','Out-DosReversedCommand','Out-DosFORcodedCommand','Out-DosFINcodedCommand') -contains $_ } } )]
        [System.String[]]
        $Functions = @('Out-DosConcatenatedCommand','Out-DosReversedCommand','Out-DosFORcodedCommand','Out-DosFINcodedCommand'),

        [Parameter(Position = 0, Mandatory = $false)]
        [System.Int16]
        $Iterations = 1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ((($_ | sort-object | select-object -first 1) -gt 0) -and (($_ | sort-object | select-object -last 1) -le 3)) } )]
        [System.Int16[]]
        $TestType = @(1,2,3)
    )
    
    Clear-Host
    Write-Host "`n[*] Starting " -NoNewline -ForegroundColor Cyan
    Write-Host "Invoke-" -NoNewline -ForegroundColor White
    Write-Host "D" -NoNewline -ForegroundColor Red
    Write-Host "O" -NoNewline -ForegroundColor Magenta
    Write-Host "S" -NoNewline -ForegroundColor Yellow
    Write-Host "fuscation" -NoNewline -ForegroundColor White
    Write-Host " test harness..." -ForegroundColor Cyan

    # Store all randomly-generated results in the $allResults array.
    $allResults = @()

    # Call all test functions defined in above $Functions array to generate randomly-obfuscated payloads that are stored in $allResults.
    $counter = 0
    foreach ($function in $Functions)
    {
        $counter++

        # Ensure correct casing for input $function value (because #OCD).
        $function = $function -ireplace '^out\-dos','Out-Dos' -ireplace 'concat','Concat' -ireplace 'reverse','Reverse' -ireplace 'forcode','FORcode' -ireplace 'fincode','FINcode'

        Write-Host "`n[*] ($counter of $($Functions.Count)) Generating obfuscated payloads from " -NoNewline -ForegroundColor Cyan
        Write-Host $function -NoNewline -ForegroundColor Yellow
        Write-Host "...`n    " -NoNewline -ForegroundColor Cyan

        # Call current test function.
        $results = . ($function -replace '^Out\-','Test-Out') -TestType $TestType -Iterations $Iterations

        # Store array of results from above test function in $allResults.
        $allResults += $results

        Write-Host "`n[*] Just added " -NoNewline -ForegroundColor Cyan
        Write-Host $results.Count -NoNewline -ForegroundColor Yellow
        Write-Host " test results to `$allResults for " -NoNewline -ForegroundColor Cyan
        Write-Host $function -NoNewline -ForegroundColor Yellow
        Write-Host "..." -ForegroundColor Cyan
    }

    # Ensure all results we will process are not null and are less than or equal to cmd.exe's length limit of 8190 characters.
    $allResults = ($allResults | where-object { $_ -and ($_.Length -le 8190) })

    # Iterate through all generated obfuscated commands and check for correct execution output (did the original command execute properly) and detections (if any exist).
    # Store execution and detection information as PSCustomObjects in the array $finalResults.
    Write-Host "`n"
    $counter = 0
    $finalResults = @()
    foreach ($result in $allResults)
    {
        $counter++

        # Test payload in cmd.exe engine via stdin to avoid any additional escaping.
        $stdout = (Write-Output $result | C:\Windows\System32\cmd.exe)
    
        # Check if resultant $stdout value is correct.
        $correct = Test-CorrectOutput -StdOut $stdout
    
        # Check if obfuscated command matches any defined detection regex values (returned as PSCustomObject).
        $detectionResults = Get-DosDetectionMatch -Command $result

        # Add detection results to $finalArray.
        $finalResults += [PSCustomObject] @{
            Correct        = $correct
            Num            = $counter
            Command        = $result
            Length         = $result.Length
            Skeleton       = $result -replace '(\w|\s)',''
            Stdout         = $stdout
            Detected       = $detectionResults.Detected
            DetectionName  = $detectionResults.DetectionName
            DetectionRegex = $detectionResults.DetectionRegex
            DetectionCount = $detectionResults.DetectionCount
        }

        # Display if match on output was found or not (did the obfuscated command properly execute).
        if ($correct)
        {
            Write-Host "[*] ($counter/$($allResults.Count)) SUCCESS" -NoNewline -ForegroundColor Green
        }
        else
        {
            Write-Host "[*] ($counter/$($allResults.Count)) FAILURE" -NoNewline -ForegroundColor Red
        }

        # Display if obfuscated command was detected or not.
        if ($detectionResults.Detected)
        {
            Write-Host " DETECTED (" -NoNewline -ForegroundColor Green
            Write-Host "$($detectionResults.DetectionCount) -- $($detectionResults.DetectionName -join ', ')" -NoNewline -ForegroundColor Yellow
            Write-Host ')' -ForegroundColor Green
        }
        else
        {
            Write-Host " UNDETECTED" -ForegroundColor Red
        }
    }

    # Display final rollup results for SUCCESSFUL-vs-FAILED commands.
    $failureCount = ($finalResults | where-object {-not $_.Correct} | measure-object).Count
    if ($failureCount -gt 0)
    {
        $successPercentage = (((1 - [System.Double] ($failureCount / $finalResults.Count)) * 100).ToString('0.0')).TrimEnd('0.')
        Write-Host "`n[*] SUCCESS PERCENTAGE == " -NoNewline -ForegroundColor Yellow
        Write-Host "$successPercentage%" -ForegroundColor Green
        Write-Host "`n[*] $failureCount FAILURES:" -ForegroundColor Red
        
        # Output failed commands to disk.
        $outputFile = "$scriptDir/FAILED_COMMANDS.txt"
        $finalResults | where-object {-not $_.Correct} | foreach-object {""; ""; "ECHO ##### $($_.Num) of $($finalResults.Count) #####"; $_.Command; ""} | Set-Content -Path $outputFile
    
        # Open failed commands in Notepad.
        if ($env:windir)
        {
            C:\Windows\notepad.exe $outputFile
        }
    }
    else
    {
        Write-Host "`n`n[*] ALL $($finalResults.Count) RESULTS WERE SUCCESSFUL!!!" -ForegroundColor Green
    }

    # Display final rollup results for DETECTED-vs-UNDETECTED commands.
    $undetectedCount = ($finalResults | where-object {-not $_.Detected} | measure-object).Count
    if ($undetectedCount -gt 0)
    {
        $successPercentage = ((1 - [System.Double] ($undetectedCount / $finalResults.Count)).ToString('0.00')).ToString().Split('.')[1]
        Write-Host "`n[*] DETECTION SUCCESS PERCENTAGE == " -NoNewline -ForegroundColor Yellow
        Write-Host "$successPercentage%" -ForegroundColor Green
        Write-Host "`n[*] $undetectedCount DETECTION FAILURES:" -ForegroundColor Red

        # Output failed commands to disk.
        $outputFile = "$scriptDir/UNDETECTED_COMMANDS.txt"
        $finalResults | where-object {-not $_.Detected} | foreach-object { ""; ""; "ECHO ##### $($_.Num) of $($finalResults.Count) #####"; $_.Command; "" } | Set-Content -Path $outputFile

        # Open undetected commands in Notepad.
        if ($env:windir)
        {
            C:\Windows\notepad.exe $outputFile
        }
    }
    else
    {
        Write-Host "`n`n[*] ALL $($finalResults.Count) RESULTS WERE DETECTED!!!" -ForegroundColor Green
    }

    # Output final detection counts for identifying which samples are not being detected or are only being detected by a few detection rules.
    Write-Host "`n`n[*] GROUPING OF DETECTION COUNTS:" -ForegroundColor Green
    if ($PSVersionTable.PSVersion.Major -ge 3)
    {
        $finalResults | group-object DetectionCount,DetectionName | sort-object Count -Descending | select-object @{Expression={$_.Count};Label="Command Count"},@{Expression={$_.Name};Label="Detection Count"}
    }
    else
    {
        Write-Warning "Not running as PowerShell version 3.0+ so rollup values will not be formatted as nicely."

        $finalResults | foreach-object {"$($_.DetectionCount), {$($_.DetectionName)}"} | group-object | sort-object Count -Descending | select-object @{Expression={$_.Count};Label="Command Count"},@{Expression={$_.Name};Label="Detection Count"} | format-table -AutoSize
    }
}


function Get-DosDetectionMatch
{
<#
.SYNOPSIS

Get-DosDetectionMatch checks input string (obfuscated command) and returns a PSCustomObject of all matching regular expression detection values defined in $regexDetectionTerms.
This is to enabled defenders to easily define regex-based detection ideas for command line values of obfuscated commands produced by Invoke-DOSfuscation and test these ideas against each randomly-generated payload.
In addition, since this function returns a PSCustomObject containing arrays it will help defenders quickly identify payloads that only have 1-2 (or 0) detection matches as opposed to matching on numerous building blocks on which these obfuscation techniques rely.

Invoke-DOSfuscation Function: Get-DosDetectionMatch
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-DosDetectionMatch checks input string (obfuscated command) and returns a PSCustomObject of all matching regular expression detection values defined in $regexDetectionTerms.
This is to enabled defenders to easily define regex-based detection ideas for command line values of obfuscated commands produced by Invoke-DOSfuscation and test these ideas against each randomly-generated payload.
In addition, since this function returns a PSCustomObject containing arrays it will help defenders quickly identify payloads that only have 1-2 (or 0) detection matches as opposed to matching on numerous building blocks on which these obfuscation techniques rely.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Collections.Hashtable')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $Command
    )
    
    # Set detection names and regex values to check against input $Command.
    $regexDetectionTerms  = @()
    $regexDetectionTerms += , @{ Name = 'UnobfuscatedForLoop'  ; Expression = 'FOR\s+\/[A-Z]\s+\%[A-Z]\s+IN.*DO\s' }
    $regexDetectionTerms += , @{ Name = 'MultipleVarSubstring' ; Expression = '\%.{0,25}:~.{0,25}\%.*\%.{0,25}:~.{0,25}\%' }
    $regexDetectionTerms += , @{ Name = 'INSERT_MORE_RULES'    ; Expression = '(MORE|RULES)' }
    
    # Check all detections above against input $Commands, storing all matching detection names, regex values and detection count.
    $matchedDetectionName  = @()
    $matchedDetectionRegex = @()
    $matchedDetectionCount = 0
    $detected = $false
    foreach ($regexTerm in $regexDetectionTerms)
    {
        if ($Command -match $regexTerm.Expression)
        {
            $matchedDetectionName  += $regexTerm.Name
            $matchedDetectionRegex += $regexTerm.Expression
            $matchedDetectionCount++
            $detected = $true
        }
    }

    # Return all results in array of Hashtables.
    return @{
        Detected       = $detected
        DetectionName  = $matchedDetectionName
        DetectionRegex = $matchedDetectionRegex
        DetectionCount = $matchedDetectionCount
    }
}


# Get location of this script no matter what the current directory is for the process executing this script.
$scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 
    

function Test-CorrectOutput
{
<#
.SYNOPSIS

Test-CorrectOutput checks input string (StdOut result from executed obfuscated command) and returns $true/$false if the value matches any strings or regular expression terms defined in $correctResults or $correctRegexResults.

Invoke-DOSfuscation Function: Test-CorrectOutput
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Test-CorrectOutput checks input string (StdOut result from executed obfuscated command) and returns $true/$false if the value matches any strings or regular expression terms defined in $correctResults or $correctRegexResults.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Boolean')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.Object[]]
        $StdOut
    )

    # Format $StdOut to a string.
    $StdOut = ([System.String] ($StdOut -join ''))

    # Return $false (not correct) if enteRed $StdOut value is null.
    if (-not $StdOut)
    {
        return $false
    }

    # Create array to store correct results (as strings) to validate proper execution of obfuscated commands in test harness.
    $correctResults  = @()
    $correctResults += "$($env:WINDIR.ToLower())\system32$((Get-ChildItem $env:WINDIR\System32\calc.exe).LastWriteTime.ToString('MM/dd/yyyy  hh:mm tt'))            $((Get-ChildItem $env:WINDIR\System32\calc.exe).Length.ToString('0,000')) calc.exe               1 File(s)         $((Get-ChildItem $env:WINDIR\System32\calc.exe).Length.ToString('0,000')) bytes               0 Dir(s)  "
    $correctResults += "$($env:WINDIR.ToLower())\system32$((Get-ChildItem $env:WINDIR\System32\calc.exe).LastWriteTime.AddHours(-1).ToString('MM/dd/yyyy  hh:mm tt'))            $((Get-ChildItem $env:WINDIR\System32\calc.exe).Length.ToString('0,000')) calc.exe               1 File(s)         $((Get-ChildItem $env:WINDIR\System32\calc.exe).Length.ToString('0,000')) bytes               0 Dir(s)  "
    $correctResults += "-a----        $((Get-ChildItem $env:WINDIR\System32\calc.exe).LastWriteTime.ToString('M/dd/yyyy   h:mm tt'))          $((Get-ChildItem $env:WINDIR\System32\calc.exe).Length) calc.exe"
    $correctResults += "-a----        $((Get-ChildItem $env:WINDIR\System32\calc.exe).LastWriteTime.AddHours(-1).ToString('M/dd/yyyy   h:mm tt'))          $((Get-ChildItem $env:WINDIR\System32\calc.exe).Length) calc.exe"
    $correctResults += "User accounts for \\$env:USERDOMAIN-------------------------------------------------------------------------------Administrator            "
    $correctResults += 'TEST "" PAIRed DOUBLE QUOTES and not UNPAIRed DOUBLE QUOTES'
    $correctResults += 'UDP    127.0.0.1:'
    $correctResults += '0.0.0.0:0              LISTENING'
    $correctResults += $env:TEMP
    $correctResults += '<>^^|\&^'

    # Create array to store correct results (as regular expressions) to validate proper execution of obfuscated commands in test harness.
    $correctRegexResults  = @()
    $correctRegexResults += "[^a-z0-9]$env:USERNAME                       C:\\"
    
    # Check $StdOut result against all values in $correctResults and $correctRegexResults and return $true if any match is found.
    foreach ($correctResult in $correctResults)
    {
        if ((-join $StdOut).Contains($correctResult))
        {
            return $true
        }
    }
    foreach ($correctRegexResult in $correctRegexResults)
    {
        if ((-join $StdOut) -cmatch $correctRegexResult)
        {
            return $true
        }
    }

    # Return $false (not correct) if no matches occurred above.
    return $false
}


function Set-RandomArgument
{
<#
.SYNOPSIS

Set-RandomArgument sets random values to all arguments used by the Invoke-DOSfuscation functions in the script scope to maximize the randomization of each function invocation during the test harness process. This enabled more thorough testing of proper obfuscated command execution and detection coverage.

Invoke-DOSfuscation Function: Set-RandomArgument
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Set-RandomArgument sets random values to all arguments used by the Invoke-DOSfuscation functions in the script scope to maximize the randomization of each function invocation during the test harness process. This enabled more thorough testing of proper obfuscated command execution and detection coverage.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param ()
    
    if ($PSCmdlet.ShouldProcess("Setting of random values for script-level variables successful"))
    {
        # Generate random values for all variables used in Invoke-DOSfuscation functions.
        $script:ConcatenationPercent       = Get-Random -InputObject @(1..99)
        $script:RandomCase                 = Get-Random -InputObject @($true,$false)
        $script:RandomSpace                = Get-Random -InputObject @($true,$false)
        $script:RandomSpaceRange           = @(0..10)    
        $script:RandomFlag                 = Get-Random -InputObject @($true,$false)
        $script:RandomCaret                = Get-Random -InputObject @($true,$false)
        $script:RandomCaretPercent         = Get-Random -InputObject @(1..99)
        $script:RandomChar                 = Get-Random -InputObject @($true,$false)
        $script:RandomCharRange            = @(1..10)
        $script:RandomCharPercent          = Get-Random -InputObject @(1..99)
        $script:RandomCharArray            = Get-Random -InputObject @(@(','),@(';'),@(',',';'))
        $script:VarNameSpecialChar         = Get-Random -InputObject @($true,$false)
        $script:VarNameWhitespace          = Get-Random -InputObject @($true,$false)
        $script:DecoyString1               = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
        $script:DecoyString2               = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
        $script:StdIn                      = Get-Random -InputObject @($true,$false)
        $script:FinalBinary                = Get-Random -InputObject @('powershell','cmd','none')
        $script:RandomPadding              = Get-Random -InputObject @($true,$false)
        $script:RandomPaddingFactor        = Get-Random -InputObject @(1..10)
        $script:RandomPaddingCharArray     = Get-Random -InputObject ([System.Char[]] (@(32) + @(35..47) + @(58..64) + @(91..96) + @(123..126) + @(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..25))
        $script:DecoySetCommandString      = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
        $script:DecoySetCommandChars       = Get-Random -InputObject ([System.Char[]] (@(32) + @(35..47) + @(58..64) + @(91..96) + @(123..126) + @(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..25))
        $script:SubstitutionPercent        = Get-Random -InputObject @(1..40)
        $script:RandomPlaceholderCharArray = Get-Random -InputObject ([System.Char[]] (@(32) + @(35..47) + @(58..64) + @(91..96) + @(123..126) + @(48..57) + @(65..90) + @(97..122)) | where-object { @('!','"','~','=','*','^','|','&','<','>') -notcontains $_ } ) -Count (Get-Random -InputObject @(1..25))
        
        # Generate random but valid $VFlag value.
        do
        {
            $vFlagTemp = 'V' + -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)) + @('~','!','@','#','$','*','(',')','-','_','+','=','{','}','[',']',':',';','?')) -Count (Get-Random -InputObject @(1..10)))
        }
        while (($vFlagTemp.Trim() -match '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[acdefkqstuv\?])') -or ($vFlagTemp.Trim().ToLower().StartsWith('v:of')))
        $script:VFlag = $vFlagTemp
        
        # Generate binary syntax last so variables set above will be properly reflected in the binary syntaxes.
        $script:CmdSyntax        = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('env','assoc','ftype')) -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
        $script:Cmd2Syntax       = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('env','assoc','ftype')) -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
        $script:PowerShellSyntax = Get-ObfuscatedPowerShell -ObfuscationType (Get-Random -InputObject @('env','assoc','ftype')) -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
    }
} 


function Test-OutDosConcatenatedCommand
{
<#
.SYNOPSIS

Test-OutDosConcatenatedCommand generates random obfuscated payloads from the Out-DosConcatenatedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosConcatenatedCommand with fully randomized arguments
    2) Calls Out-DosConcatenatedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosConcatenatedCommand via Invoke-DOSfuscation's CLI

Invoke-DOSfuscation Function: Test-OutDosConcatenatedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Set-RandomArgument, Out-DosConcatenatedCommand (Invoke-DOSfuscation.psm1)
Optional Dependencies: None

.DESCRIPTION

Test-OutDosConcatenatedCommand generates random obfuscated payloads from the Out-DosConcatenatedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosConcatenatedCommand with fully randomized arguments
    2) Calls Out-DosConcatenatedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosConcatenatedCommand via Invoke-DOSfuscation's CLI

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Object[]')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.Int16]
        $Iterations = 1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ((($_ | sort-object | select-object -first 1) -gt 0) -and (($_ | sort-object | select-object -last 1) -le 3)) } )]
        [System.Int16[]]
        $TestType = @(1,2,3)
    )

    # Store all obfuscated results in $curResults and return to calling function.
    $curResults = @()
    
    # Build out commands that are fine for both cmd.exe and powershell.exe.
    $testCommandsANY  = @()
    $testCommandsANY += 'net user'
    $testCommandsANY += 'net us""er'
    $testCommandsANY += 'ne""t us""er'
    $testCommandsANY += 'nets""tat -a""no | fin""dstr 12""7.0.0.1'
    $testCommandsANY += 'netstat -ano | findstr 0.0.0.0 | findstr LISTENING'
    $testCommandsANY += 'dir "c:\windows\system32\ca*c.exe"'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsANY += 'dir c:\windows\system32\ca*c.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsANY)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent:$script:ConcatenationPercent -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent:$script:ConcatenationPercent -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -StdIn:$script:StdIn -FinalBinary:$script:FinalBinary }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\*' -Quiet -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for cmd.exe.
    $testCommandsCmd  = @()
    $testCommandsCmd += 'net user | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'net user | find "me" | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'del C:\Users\me\123.txt&&net user > %userprofile%\123.txt&&type C:\Users\me\123.txt | find "me"'.Replace('C:\Users\me',$env:USERPROFILE).Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'dir c:\windows\system32\net.exe&&echo %temp%'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo %temp%'
    $testCommandsCmd += 'powershell net user ^| sls ''me'''.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'powershell "net user | sls ''me''"'.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'net us""er | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'nets""tat -ano | find "127.0.0.1"'
    $testCommandsCmd += 'echo bla&&dir c:\windows\system32\calc.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo _ > bla.txt&&echo TEST "" PAIRed DOUBLE QUOTES and not UNPAIRed DOUBLE QUOTES > bla.txt&&dir c:\windows\system32\notepad.exe&&type bla.txt'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsCmd)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent:$script:ConcatenationPercent -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent:$script:ConcatenationPercent -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -StdIn:$script:StdIn -FinalBinary cmd }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\*' -Quiet -FinalBinary cmd }
        }
    }
    
    # Build out commands that are only fine for powershell.exe.
    $testCommandsPowerShell  = @()
    $testCommandsPowerShell += 'write-output ''echo %TEMP%'' | cmd.exe'
    $testCommandsPowerShell += 'write-output "echo %TEMP%" | cmd.exe'
    $testCommandsPowerShell += 'net user | ? {$_.startswith(''me'')}'.Replace("'me'","'$env:USERNAME'")
    $testCommandsPowerShell += 'net user | ? {$_.startswith("me")}'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += 'Write-Host "this is a test 1" -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a test 2'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" test 3'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" <-- PAIRed DOUBLE QUOTES test 4'' -ForegroundColor Green; write-output ('' me ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' C:\'')'.Replace("' me '+'","' $env:USERNAME '+'")
    $testCommandsPowerShell += 'net user | sls "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += '&("IEX") ''"dir c:\windows\system32\calc.exe"|&("iex")'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '&("IEX") ''&("iex") "dir c:\windows\system32\calc.exe"'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX")'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX"); Write-Host "<>^^|\&^" -ForegroundColor Green'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += "&('iex') 'dir c:\windows\system32\cal*c.exe'".Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent:$script:ConcatenationPercent -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent:$script:ConcatenationPercent -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for powershell.exe (but Reduced obfuscation ranges since commands are extremely long).
    $testLongCommandsPowerShell  = @()
    $testLongCommandsPowerShell += '$45wthQ =[CHAr[ ] ]")''''niOj-]2,11,3[eMAN.)''*rDm*'' ELbaIRaV-tEg((& |)''\'',''p7g''(EcAlPER.)''exe.clacp7''+''g2''+''3m''+''et''+''sys''+''p7gswod''+''niwp7g:''+''c rid''( " ; [ARray]::REverSE( (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE); (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE -jOIn ''''|&( $shELLId[1]+$sHEllid[13]+''x'')'
    $testLongCommandsPowerShell += '&("{0}{1}"-f''de'',''l'') ("{0}{1}"-f ''bla.'',''txt''); .("{1}{0}"-f''ho'',''ec'') ((("{13}{8}{12}{11}{3}{10}{0}{14}{1}{2}{9}{15}{16}{17}{18}{5}{6}{4}{7}" -f ''PAI'',''LE Q'',''UO'',''}'',''U'',''DOUBLE '',''Q'',''OTES'',''{'',''TES an'','' '',''0'',''0}{'',''TEST '',''Red DOUB'',''d no'',''t UNP'',''AIRed'','' ''))-F[CHar]34) > ("{0}{1}" -f''bla'',''.txt''); &("{1}{0}"-f''r'',''di'') (("{1}{5}{0}{3}{4}{2}"-f''wsEfvsy'',''c:Efvw'',''xe'',''stem3'',''2Efvcalc.e'',''indo'')).ReplAce(''Efv'',''\''); .("{0}{1}" -f ''typ'',''e'') ("{2}{1}{0}" -f ''t'',''.tx'',''bla'')'
    $testLongCommandsPowerShell += '"$( SV  ''Ofs''  '''' )" +([StrINg] [rEGeX]::MATches(")''X''+]5[cILbUp:vNE$+]31[CiLbup:VnE$ (&|)43]Rahc[]gNIRTs[,)801]Rahc[+97]Rahc[+25]Rahc[((EcALPER.)93]Rahc[]gNIRTs[,''xeF''(EcALPER.)29]Rahc[]gNIRTs[,''9i5''(EcALPER.)'')xeFal''+''b''+''xeF,xeFx''+''t.xe''+''F,x''+''eF''+''txeF f''+''- ''+''l''+''O4}0''+''{}1{}2''+''{lO4( ''+'')xeF''+''exeF,xeFpytxeF ''+''f''+''- l''+''O4}1{}0''+''{l''+''O4(''+''. ;''+'')xeF''+''9i5xe''+''F''+'',xeFv''+''fE''+''xeF(ecA''+''lpeR.))''+''xeF''+''od''+''n''+''ixeF,xeFe.''+''clac''+''vfE2xeF,xeF3metsxeF,xeFe''+''xxeF,xeFwvfE:cxeF,xeFysv''+''fEs''+''wxeFf-lO''+''4}2{}4''+''{''+''}3''+''{}0''+''{}''+''5{}1''+''{lO4((''+'' ''+'')xeFid''+''xeF,xeFrxe''+''Ff-''+''l''+''O4}''+''0{''+''}1{l''+''O''+''4(& ;)x''+''eFt''+''x''+''t.xe''+''F,xeFalbxeFf- lO''+''4}''+''1{}0{l''+''O4''+''( >''+'' ''+'')43]raHC[F-)''+'')xeF xe''+''F,xeFDER''+''IAx''+''eF,x''+''eFPN''+''U txeF,''+''xeFon dxeF''+'',xeF''+''BU''+''OD ''+''DER''+''xeF,''+''x''+''e''+''F''+'' ''+''TSETxeF,''+''xeF''+''{}''+''0xeF''+'',xeF0xeF''+'',xeF''+'' xeF,''+''x''+''eFna SETx''+''eF''+'',xeF{xeF''+'',xe''+''FSE''+''TOxeF,xeFQ''+''xeF,''+''xeF ELBUODxe''+''F,xeFUxeF,xe''+''F''+''}xeF,xeFOUxeF,''+''xeFQ ELxeF,xeFIAPxeF''+'' f-''+'' lO''+''4}7{}4{}6{}5''+''{}81{}''+''71{}61{''+''}51{}''+''9{}2{}1{}''+''4''+''1{}0''+''{}01{}3{}1''+''1{''+''}21{}8''+''{''+''}31{''+''l''+''O4((( ''+'')''+''xeF''+''cexeF,xe''+''F''+''ohxeF''+''f-lO4}0{}1{lO''+''4''+''(. ''+'';)xeFtx''+''tx''+''eF''+'',xe''+''F.albx''+''eF''+'' f''+''-lO4}1{}0''+''{l''+''O''+''4( )xeFlxeF,''+''x''+''eFe''+''dxeFf-lO4}1''+''{}0''+''{lO''+''4(&''(", ''.'' ,''RighTTolEfT'') |ForEach-ObJECT {$_} ) +"$( sET-iTeM  ''vAriABLe:ofS''  '' '') "| &((gEt-variaBLE ''*mdr*'').NamE[3,11,2]-JOiN'''')'
    $testLongCommandsPowerShell += ' (''del b''+''la.txt; echo rtUH''+''TES''+''T VXF''+''VXF''+'' PAI''+''RE''+''D ''+''DOUBLE QUO''+''TES''+'' and''+'' no''+''t ''+''U''+''NPAIRed DOUBLE QUOTESrtUH > bla.txt; d''+''ir c:KoDwi''+''ndowsKoDsy''+''s''+''t''+''em''+''32KoDcal''+''c.''+''ex''+''e; ''+''t''+''ype bl''+''a.txt'').rEplace(''rtUH'',[sTriNG][cHAR]39).rEplace(''VXF'',[sTriNG][cHAR]34).rEplace(([cHAR]75+[cHAR]111+[cHAR]68),''\'')|& ( $sheLlID[1]+$ShELlID[13]+''x'')'
    $testLongCommandsPowerShell += 'SEt O07sTn ([cHaR[ ] ]"Xei | )421]Rahc[,93]Rahc[,63]Rahc[,29]Rahc[ F-)'')}2{x}''+''2{+''+'']31[DI''+''lLEhS}1{+''+'']1[''+''D''+''I''+''l''+''Lehs}1{ (''+'' &}3''+''{''+'')}2{}0{}2''+''{''+'',)''+''86]RA''+''Hc[''+''+111''+'']RA''+''Hc[+''+''57]RA''+''Hc[''+''((ec''+''al''+''p''+''Er''+''.''+'')''+''43]R''+''AH''+''c[]G''+''N''+''ir''+''Ts[''+'',}''+''2{FXV}2{(''+''eca''+''l''+''pEr.)93]RAHc[''+'']GNi''+''rTs[,}''+''2{HUtr''+''}2{(ec''+''alpEr.)}2''+''{tx''+''t.a''+''}2{''+''+}2''+''{l''+''b epy}2{+}''+''2''+''{t''+''}2{+''+''}2{ ;e}2{+}2{xe}2{+}2{.c''+''}2{''+''+}2{l''+''a''+''c''+''DoK''+''23}2''+''{+''+''}2''+''{me}2{+''+''}''+''2''+''{t''+''}2{+}2{s}2''+''{+}2{y''+''sDoKswod''+''n}''+''2{''+''+''+''}2{''+''iwDoK:c ''+''ri}2{+}2{''+''d ''+'';tx''+''t.''+''alb >''+'' ''+''HUt''+''rSE''+''TOU''+''Q ''+''EL''+''BUOD''+'' ''+''DERIAPN}2{+''+''}2{U}2{+}2{''+'' t''+''}2''+''{+}''+''2{on }2{+''+''}2''+''{dn''+''a ''+''}2''+''{+}2{SE''+''T}''+''2{+}2{O''+''UQ ELBU''+''O''+''D}2''+''{''+''+}2{ D}''+''2''+''{+}2{''+''ER}2{+}2''+''{IAP ''+''}''+''2''+''{''+''+''+''}''+''2{''+''FXV}''+''2''+''{+}2{FXV''+'' T}2''+''{+}2{SE''+''T}2''+''{+}2{HUt''+''r ohce ;txt.a''+''l}2''+''{+}2{b led}2{( ''(("  ) ;[aRRay]::ReVERsE( ( ls  variAbLE:O07stn ).vAlUE );[sTrIng]::jOiN('''',( ls  variAbLE:O07stn ).vAlUE) |& ((gET-vaRIable ''*mDR*'').nAme[3,11,2]-joIN'''')'
    $testLongCommandsPowerShell += '(''8A62M15u118_13z26u41>50,58-25{23M62R123>123{63R8>49_47,123,115M121_123A123-114u114-105_98A6z9M26z19_56,0M119M114{111z107M106_6M9u26u19>56,0,112R105,108{6z9u26z19R56M0{112R109z99_6R9-26-19R56_0_115>62>24{58R55A11A62>9u56A118-98z104z6z9A26z19R56z0u119u124u99_14u108R124R123A123{30{56z58R55>43-62z9u118_123A111A105M106R6>9_26-19u56_0>119A114M110R107-106_6,9{26R19u56A0_112,104z106_106,6,9{26_19-56M0_112{109,99A6z9,26{19z56-0,115_123R123u30M56_58>55{43>62z9-118{114R124-114u99R14-108A3A124z112{124M30,18>99M14>108R115R125R50-42,13-99z124M112M124{14A108{62A35u62>124,112M124R117{56_55R58-124R112-124>56>51_19A13M105M104_124,112u124u54A62-47A40-124,112A124z34R40{124R112_124,51u19{13M40A44>52A63-53,50-44A51z19R13,97-56z124R112{124{123{124-112u124-41,124{112_124{50M63,99A14R108_124_115u115u123-115A123z114M124,3{124_112R6A111-104,0-62-22u52-19_40u43z127{112_6M106z105{0A30,54,20z51_8z43u127{123_115M125{123_123z121,114A123z96,123M127>31>8{17>15z0R123z118M123M106z117u117{118_123{115u123_127M31u8-17>15_117R55{30>53,28-47A51A123{114u123_6M123A118M49u52>18z21z123u124{124_39,123M125-123u115_123>127A11R8R51{52_54M30u0R111R6R112R127z43-8z19A52_54M30M0-104,111>6_112z124z3>124{114''.SpLIt(''R,>_A{uzM-'' )|%{ [ChaR]($_ -bxoR''0x5b'' ) } )-joiN '''' |& ( $eNv:cOmsPEC[4,15,25]-join'''')'
    $testLongCommandsPowerShell += '. ( $Env:PuBLic[13]+$env:PUBLIC[5]+''X'') ([sTrIng]::JOin('''' ,(''53s65<54Z2d;56;41<72M69M61Z42Q4cM65<20Z20_64_53>6as74_20;28>22Z20Z20<29Z29<32_39>5dQ52Q41<48M63;5b;2c<29s34>30>31Z5d>52M41Z48>63_5b>2bZ32_37Z5d_52Z41Q48>63Z5b_2bQ36Z38<5dM52Q41_48;63_5bQ28s65M43s61Z6cM50>65>52Q63s2d>39Z33s5ds52M41Q48Q63<5b<2cZ27;38Q55<37<27s20Z20Q45Z63s61Q6cZ70>65>52Q2ds20>34_32Q31Z5d>52Z41;48Z63>5b<2cZ29;35;30Z31M5dM52Q41s48Z63;5bZ2bQ33Z31s31s5dZ52s41Z48M63_5b<2b<36Q38s5d_52Z41Q48M63Z5bM28Z20_20<45M63Z61M6c>70Z65;52>2d_29Z27Z29_38<55Z37Q58<27<2b>27;45<49s38Z55s37M28>26Q69M71Z56_38Z27Q2b<27;55;37s65_78_65>27_2bs27<2eM63s6cZ61M27<2b<27<63>68Z48Q56M32M33<27s2bQ27>6dM65;74Q73s27M2bM27M79M73>27s2b>27;68;48Q56M73_77_6fZ64M6eM69;77Z68>48;56Z3aQ63M27s2bs27Z20Z27Q2b<27s72_27_2b<27>69<64M38s55>37_27;28<28;20s28M20>29Z27_58<27M2bQ5d;34Q33;5bQ65Z4dQ6fs48<73s70<24;2b;5d_31Z32<5b>45Z6dQ4fQ68;53M70<24s20>28;26M20s20;22Z29;20Q3bQ20;24s44Z53>4aQ54s5bs20Q2d_20M31_2es2e>2dQ20Z28<20>24s44Q53;4aZ54s2eZ6c<45Q6eZ47Q74s68Q20s29M20>5d<20>2dM6aQ6f>49;4e>20;27Z27M7cs20s26Z20M28s20Q24Q50;53_68>6f_6d>45>5b;34_5dQ2b_24;70s53Q48;6fs6ds45M5bQ33M34>5d>2b>27s58Q27<29''-SpLIT ''>'' -sPlIT''_'' -SpLIt ''s''-sPliT'';'' -sPlIt''Q'' -split''M'' -Split ''Z'' -spLIt''<''| FoREACh{ ([CHaR] ([convErt]::tOInT16( ([StRIng]$_) ,16) ))})) ) '
    $testLongCommandsPowerShell += ' [StRiNG]::jOin( '''' , ((83 , 101 , 84 ,45 ,86 ,65, 114, 105, 97 , 66 ,76, 101 ,32, 32 ,100,83,106,116 ,32,40 , 34, 32 ,32 ,41 ,41 , 50 , 57 , 93,82 , 65 , 72 , 99 , 91, 44 ,41, 52, 48, 49 , 93 ,82 , 65, 72,99, 91,43 , 50 ,55 , 93, 82,65 , 72 , 99 ,91 , 43 , 54 ,56 , 93 , 82,65, 72, 99,91 , 40 , 101 , 67 , 97 ,108, 80,101 ,82 , 99 ,45 , 57 ,51, 93 , 82,65 , 72,99 ,91 , 44,39,56 ,85, 55 ,39, 32 ,32,69 , 99,97 ,108, 112, 101 , 82,45 , 32,52 , 50, 49,93 , 82 ,65 , 72 ,99, 91 , 44 , 41, 53, 48 , 49 ,93 , 82 ,65, 72, 99 ,91 ,43, 51, 49 ,49,93, 82 ,65 , 72, 99,91,43 ,54 ,56 ,93, 82 ,65, 72,99 , 91 , 40,32,32 , 69 , 99, 97 , 108 ,112 , 101 ,82 , 45 , 41 ,39, 41 , 56 , 85 , 55 ,88 ,39 , 43 , 39 , 69 ,73, 56, 85, 55, 40 ,38 , 105,113 , 86 , 56 ,39 , 43 , 39,85,55 ,101 , 120,101 ,39 ,43,39, 46 , 99 , 108,97,39, 43 ,39, 99 , 104, 72,86,50 , 51,39 , 43 , 39, 109 , 101 , 116, 115,39,43 ,39 , 121, 115, 39 ,43, 39 , 104 , 72 , 86 ,115, 119,111 , 100, 110 , 105, 119 , 104 , 72,86 , 58 ,99 , 39, 43 ,39,32,39, 43, 39,114 , 39 , 43 , 39, 105 , 100 , 56,85, 55 , 39 , 40 ,40, 32 ,40 ,32,41,39, 88 ,39 ,43 , 93 ,52 ,51, 91,101,77 ,111,72 ,115, 112 ,36,43,93, 49 ,50, 91,69 ,109,79 ,104,83 , 112 , 36 ,32 ,40,38,32 ,32, 34,41,32 , 59 ,32 ,36,68, 83, 74 , 84 , 91, 32,45 ,32, 49 , 46 ,46 ,45,32 ,40 , 32, 36,68 ,83,74 ,84,46 , 108 , 69 ,110 ,71 , 116,104 , 32 , 41,32,93 , 32, 45 ,106, 111 , 73,78, 32, 39, 39 ,124 , 32 ,38 , 32 ,40,32,36, 80,83, 104, 111, 109, 69,91 ,52 , 93 ,43 , 36, 112 , 83 , 72, 111 ,109 ,69,91 , 51, 52 ,93 ,43 ,39 , 88 ,39 ,41) | foREaCH{([INT] $_ -aS[ChAr])}) )| . ( $Env:cOMSpEC[4,15,25]-joiN'''')'
    $testLongCommandsPowerShell += '${)}=+$();${''}  =${)}  ;  ${]$}=  ++${)}  ;  ${)]}  =++  ${)};${''``}=++  ${)}  ;  ${$}  =  ++  ${)}  ;${%.}  =  ++${)};${;}=  ++  ${)};${%}=  ++  ${)}  ;${.}  =++${)}  ;${``}=++${)};${#]}=  "["  +"$(@{  })  "[  ${%}  ]  +"$(@{})"[  "${]$}${``}"  ]  +  "$(  @{}  )"["${)]}${''}"]+  "$?"[${]$}  ]+  "]"  ;  ${)}=  "".("$(@{})  "[  "${]$}${$}"  ]  +  "$(@{  }  )  "["${]$}${;}"  ]+"$(  @{  }  )  "[${''}  ]+"$(  @{  }  )"[${$}]  +"$?  "[${]$}]+"$(@{  })  "[  ${''``}  ]  )  ;  ${)}=  "$(  @{})  "["${]$}${$}"  ]  +"$(@{  }  )  "[  ${$}]  +"${)}"[  "${)]}${%}"  ];"${#]}${''``}${``}  +  ${#]}${]$}${''}${''}  +${#]}${]$}${''}${%.}+${#]}${]$}${]$}${$}+  ${#]}${''``}${)]}+  ${#]}${``}${``}  +${#]}${%.}${.}+${#]}${``}${)]}+${#]}${]$}${]$}${``}+  ${#]}${]$}${''}${%.}  +  ${#]}${]$}${]$}${''}  +  ${#]}${]$}${''}${''}  +  ${#]}${]$}${]$}${]$}+${#]}${]$}${]$}${``}+${#]}${]$}${]$}${%.}+${#]}${``}${)]}+  ${#]}${]$}${]$}${%.}  +${#]}${]$}${)]}${]$}  +${#]}${]$}${]$}${%.}+  ${#]}${]$}${]$}${;}  +${#]}${]$}${''}${]$}+${#]}${]$}${''}${``}+${#]}${%.}${]$}  +${#]}${%.}${''}  +  ${#]}${``}${)]}+  ${#]}${``}${``}+  ${#]}${``}${%}  +${#]}${]$}${''}${.}+  ${#]}${``}${``}+${#]}${$}${;}+${#]}${]$}${''}${]$}+  ${#]}${]$}${)]}${''}+${#]}${]$}${''}${]$}+${#]}${''``}${``}+${#]}${]$}${)]}${$}+${#]}${''``}${.}  +${#]}${$}${''}  +  ${#]}${''``}${``}+${#]}${%}${''``}+${#]}${;}${``}  +  ${#]}${.}${.}+${#]}${''``}${``}  +  ${#]}${$}${]$}|${)}  "|&${)}  '
    foreach ($command in $testLongCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ConcatenationPercent (Get-Random -InputObject @(1..10)) -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent (Get-Random -InputObject @(1..10)) -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(1..5)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(1..4)) -RandomCharPercent (Get-Random -InputObject @(1..25)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -ConcatenationPercent (Get-Random -InputObject @(1..10)) -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(1..5)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(1..4)) -RandomCharPercent (Get-Random -InputObject @(1..25)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosConcatenatedCommand -ObfuscationLevel 3 -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Concat\3' -Quiet -FinalBinary powershell }
        }
    }
    
    # Return all obfuscated results to calling function.
    return $curResults
}


function Test-OutDosReversedCommand
{
<#
.SYNOPSIS

Test-OutDosReversedCommand generates random obfuscated payloads from the Out-DosReversedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosReversedCommand with fully randomized arguments
    2) Calls Out-DosReversedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosReversedCommand via Invoke-DOSfuscation's CLI

Invoke-DOSfuscation Function: Test-OutDosReversedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Set-RandomArgument, Out-DosReversedCommand (Invoke-DOSfuscation.psm1)
Optional Dependencies: None

.DESCRIPTION

Test-OutDosReversedCommand generates random obfuscated payloads from the Out-DosReversedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosReversedCommand with fully randomized arguments
    2) Calls Out-DosReversedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosReversedCommand via Invoke-DOSfuscation's CLI

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Object[]')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.Int16]
        $Iterations = 1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ((($_ | sort-object | select-object -first 1) -gt 0) -and (($_ | sort-object | select-object -last 1) -le 3)) } )]
        [System.Int16[]]
        $TestType = @(1,2,3)
    )
    
    # Store all obfuscated results in $curResults and return to calling function.
    $curResults = @()
    
    # Build out commands that are fine for both cmd.exe and powershell.exe.
    $testCommandsANY  = @()
    $testCommandsANY += 'net user'
    $testCommandsANY += 'net us""er'
    $testCommandsANY += 'ne""t us""er'
    $testCommandsANY += 'nets""tat -a""no | fin""dstr 12""7.0.0.1'
    $testCommandsANY += 'netstat -ano | findstr 0.0.0.0 | findstr LISTENING'
    $testCommandsANY += 'dir "c:\windows\system32\ca*c.exe"'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsANY += 'dir c:\windows\system32\ca*c.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsANY)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -RandomPadding:$script:RandomPadding -RandomPaddingFactor:$script:RandomPaddingFactor -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -RandomPadding:$script:RandomPadding -RandomPaddingFactor:$script:RandomPaddingFactor -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn -FinalBinary:$script:FinalBinary }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\*' -Quiet -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\*' -Quiet -FinalBinary powershell }
        }    
    }
    
    # Build out commands that are only fine for cmd.exe.
    $testCommandsCmd  = @()
    $testCommandsCmd += 'net user | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'net user | find "me" | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'del C:\Users\me\123.txt&&net user > %userprofile%\123.txt&&type C:\Users\me\123.txt | find "me"'.Replace('C:\Users\me',$env:USERPROFILE).Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'dir c:\windows\system32\net.exe&&echo %temp%'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo %temp%'
    $testCommandsCmd += 'powershell net user ^| sls ''me'''.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'powershell "net user | sls ''me''"'.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'net us""er | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'nets""tat -ano | find "127.0.0.1"'
    $testCommandsCmd += 'echo bla&&dir c:\windows\system32\calc.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo _ > bla.txt&&echo TEST "" PAIRed DOUBLE QUOTES and not UNPAIRed DOUBLE QUOTES > bla.txt&&dir c:\windows\system32\notepad.exe&&type bla.txt'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsCmd)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -RandomPadding:$script:RandomPadding -RandomPaddingFactor:$script:RandomPaddingFactor -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -RandomPadding:$script:RandomPadding -RandomPaddingFactor:$script:RandomPaddingFactor -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn -FinalBinary cmd }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\*' -Quiet -FinalBinary cmd }
        }
    }
    
    # Build out commands that are only fine for powershell.exe.
    $testCommandsPowerShell  = @()
    $testCommandsPowerShell += 'write-output ''echo %TEMP%'' | cmd.exe'
    $testCommandsPowerShell += 'write-output "echo %TEMP%" | cmd.exe'
    $testCommandsPowerShell += 'net user | ? {$_.startswith(''me'')}'.Replace("'me'","'$env:USERNAME'")
    $testCommandsPowerShell += 'net user | ? {$_.startswith("me")}'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += 'Write-Host "this is a test 1" -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a test 2'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" test 3'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" <-- PAIRed DOUBLE QUOTES test 4'' -ForegroundColor Green; write-output ('' me ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' C:\'')'.Replace("' me '+'","' $env:USERNAME '+'")
    $testCommandsPowerShell += 'net user | sls "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += '&("IEX") ''"dir c:\windows\system32\calc.exe"|&("iex")'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '&("IEX") ''&("iex") "dir c:\windows\system32\calc.exe"'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX")'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX"); Write-Host "<>^^|\&^" -ForegroundColor Green'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += "&('iex') 'dir c:\windows\system32\cal*c.exe'".Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -RandomPadding:$script:RandomPadding -RandomPaddingFactor:$script:RandomPaddingFactor -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -RandomPadding:$script:RandomPadding -RandomPaddingFactor:$script:RandomPaddingFactor -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for powershell.exe (but Reduced obfuscation ranges since commands are extremely long).
    $testLongCommandsPowerShell  = @()
    $testLongCommandsPowerShell += '$45wthQ =[CHAr[ ] ]")''''niOj-]2,11,3[eMAN.)''*rDm*'' ELbaIRaV-tEg((& |)''\'',''p7g''(EcAlPER.)''exe.clacp7''+''g2''+''3m''+''et''+''sys''+''p7gswod''+''niwp7g:''+''c rid''( " ; [ARray]::REverSE( (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE); (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE -jOIn ''''|&( $shELLId[1]+$sHEllid[13]+''x'')'
    $testLongCommandsPowerShell += '&("{0}{1}"-f''de'',''l'') ("{0}{1}"-f ''bla.'',''txt''); .("{1}{0}"-f''ho'',''ec'') ((("{13}{8}{12}{11}{3}{10}{0}{14}{1}{2}{9}{15}{16}{17}{18}{5}{6}{4}{7}" -f ''PAI'',''LE Q'',''UO'',''}'',''U'',''DOUBLE '',''Q'',''OTES'',''{'',''TES an'','' '',''0'',''0}{'',''TEST '',''Red DOUB'',''d no'',''t UNP'',''AIRed'','' ''))-F[CHar]34) > ("{0}{1}" -f''bla'',''.txt''); &("{1}{0}"-f''r'',''di'') (("{1}{5}{0}{3}{4}{2}"-f''wsEfvsy'',''c:Efvw'',''xe'',''stem3'',''2Efvcalc.e'',''indo'')).ReplAce(''Efv'',''\''); .("{0}{1}" -f ''typ'',''e'') ("{2}{1}{0}" -f ''t'',''.tx'',''bla'')'
    $testLongCommandsPowerShell += '"$( SV  ''Ofs''  '''' )" +([StrINg] [rEGeX]::MATches(")''X''+]5[cILbUp:vNE$+]31[CiLbup:VnE$ (&|)43]Rahc[]gNIRTs[,)801]Rahc[+97]Rahc[+25]Rahc[((EcALPER.)93]Rahc[]gNIRTs[,''xeF''(EcALPER.)29]Rahc[]gNIRTs[,''9i5''(EcALPER.)'')xeFal''+''b''+''xeF,xeFx''+''t.xe''+''F,x''+''eF''+''txeF f''+''- ''+''l''+''O4}0''+''{}1{}2''+''{lO4( ''+'')xeF''+''exeF,xeFpytxeF ''+''f''+''- l''+''O4}1{}0''+''{l''+''O4(''+''. ;''+'')xeF''+''9i5xe''+''F''+'',xeFv''+''fE''+''xeF(ecA''+''lpeR.))''+''xeF''+''od''+''n''+''ixeF,xeFe.''+''clac''+''vfE2xeF,xeF3metsxeF,xeFe''+''xxeF,xeFwvfE:cxeF,xeFysv''+''fEs''+''wxeFf-lO''+''4}2{}4''+''{''+''}3''+''{}0''+''{}''+''5{}1''+''{lO4((''+'' ''+'')xeFid''+''xeF,xeFrxe''+''Ff-''+''l''+''O4}''+''0{''+''}1{l''+''O''+''4(& ;)x''+''eFt''+''x''+''t.xe''+''F,xeFalbxeFf- lO''+''4}''+''1{}0{l''+''O4''+''( >''+'' ''+'')43]raHC[F-)''+'')xeF xe''+''F,xeFDER''+''IAx''+''eF,x''+''eFPN''+''U txeF,''+''xeFon dxeF''+'',xeF''+''BU''+''OD ''+''DER''+''xeF,''+''x''+''e''+''F''+'' ''+''TSETxeF,''+''xeF''+''{}''+''0xeF''+'',xeF0xeF''+'',xeF''+'' xeF,''+''x''+''eFna SETx''+''eF''+'',xeF{xeF''+'',xe''+''FSE''+''TOxeF,xeFQ''+''xeF,''+''xeF ELBUODxe''+''F,xeFUxeF,xe''+''F''+''}xeF,xeFOUxeF,''+''xeFQ ELxeF,xeFIAPxeF''+'' f-''+'' lO''+''4}7{}4{}6{}5''+''{}81{}''+''71{}61{''+''}51{}''+''9{}2{}1{}''+''4''+''1{}0''+''{}01{}3{}1''+''1{''+''}21{}8''+''{''+''}31{''+''l''+''O4((( ''+'')''+''xeF''+''cexeF,xe''+''F''+''ohxeF''+''f-lO4}0{}1{lO''+''4''+''(. ''+'';)xeFtx''+''tx''+''eF''+'',xe''+''F.albx''+''eF''+'' f''+''-lO4}1{}0''+''{l''+''O''+''4( )xeFlxeF,''+''x''+''eFe''+''dxeFf-lO4}1''+''{}0''+''{lO''+''4(&''(", ''.'' ,''RighTTolEfT'') |ForEach-ObJECT {$_} ) +"$( sET-iTeM  ''vAriABLe:ofS''  '' '') "| &((gEt-variaBLE ''*mdr*'').NamE[3,11,2]-JOiN'''')'
    $testLongCommandsPowerShell += ' (''del b''+''la.txt; echo rtUH''+''TES''+''T VXF''+''VXF''+'' PAI''+''RE''+''D ''+''DOUBLE QUO''+''TES''+'' and''+'' no''+''t ''+''U''+''NPAIRed DOUBLE QUOTESrtUH > bla.txt; d''+''ir c:KoDwi''+''ndowsKoDsy''+''s''+''t''+''em''+''32KoDcal''+''c.''+''ex''+''e; ''+''t''+''ype bl''+''a.txt'').rEplace(''rtUH'',[sTriNG][cHAR]39).rEplace(''VXF'',[sTriNG][cHAR]34).rEplace(([cHAR]75+[cHAR]111+[cHAR]68),''\'')|& ( $sheLlID[1]+$ShELlID[13]+''x'')'
    $testLongCommandsPowerShell += 'SEt O07sTn ([cHaR[ ] ]"Xei | )421]Rahc[,93]Rahc[,63]Rahc[,29]Rahc[ F-)'')}2{x}''+''2{+''+'']31[DI''+''lLEhS}1{+''+'']1[''+''D''+''I''+''l''+''Lehs}1{ (''+'' &}3''+''{''+'')}2{}0{}2''+''{''+'',)''+''86]RA''+''Hc[''+''+111''+'']RA''+''Hc[+''+''57]RA''+''Hc[''+''((ec''+''al''+''p''+''Er''+''.''+'')''+''43]R''+''AH''+''c[]G''+''N''+''ir''+''Ts[''+'',}''+''2{FXV}2{(''+''eca''+''l''+''pEr.)93]RAHc[''+'']GNi''+''rTs[,}''+''2{HUtr''+''}2{(ec''+''alpEr.)}2''+''{tx''+''t.a''+''}2{''+''+}2''+''{l''+''b epy}2{+}''+''2''+''{t''+''}2{+''+''}2{ ;e}2{+}2{xe}2{+}2{.c''+''}2{''+''+}2{l''+''a''+''c''+''DoK''+''23}2''+''{+''+''}2''+''{me}2{+''+''}''+''2''+''{t''+''}2{+}2{s}2''+''{+}2{y''+''sDoKswod''+''n}''+''2{''+''+''+''}2{''+''iwDoK:c ''+''ri}2{+}2{''+''d ''+'';tx''+''t.''+''alb >''+'' ''+''HUt''+''rSE''+''TOU''+''Q ''+''EL''+''BUOD''+'' ''+''DERIAPN}2{+''+''}2{U}2{+}2{''+'' t''+''}2''+''{+}''+''2{on }2{+''+''}2''+''{dn''+''a ''+''}2''+''{+}2{SE''+''T}''+''2{+}2{O''+''UQ ELBU''+''O''+''D}2''+''{''+''+}2{ D}''+''2''+''{+}2{''+''ER}2{+}2''+''{IAP ''+''}''+''2''+''{''+''+''+''}''+''2{''+''FXV}''+''2''+''{+}2{FXV''+'' T}2''+''{+}2{SE''+''T}2''+''{+}2{HUt''+''r ohce ;txt.a''+''l}2''+''{+}2{b led}2{( ''(("  ) ;[aRRay]::ReVERsE( ( ls  variAbLE:O07stn ).vAlUE );[sTrIng]::jOiN('''',( ls  variAbLE:O07stn ).vAlUE) |& ((gET-vaRIable ''*mDR*'').nAme[3,11,2]-joIN'''')'
    $testLongCommandsPowerShell += '(''8A62M15u118_13z26u41>50,58-25{23M62R123>123{63R8>49_47,123,115M121_123A123-114u114-105_98A6z9M26z19_56,0M119M114{111z107M106_6M9u26u19>56,0,112R105,108{6z9u26z19R56M0{112R109z99_6R9-26-19R56_0_115>62>24{58R55A11A62>9u56A118-98z104z6z9A26z19R56z0u119u124u99_14u108R124R123A123{30{56z58R55>43-62z9u118_123A111A105M106R6>9_26-19u56_0>119A114M110R107-106_6,9{26R19u56A0_112,104z106_106,6,9{26_19-56M0_112{109,99A6z9,26{19z56-0,115_123R123u30M56_58>55{43>62z9-118{114R124-114u99R14-108A3A124z112{124M30,18>99M14>108R115R125R50-42,13-99z124M112M124{14A108{62A35u62>124,112M124R117{56_55R58-124R112-124>56>51_19A13M105M104_124,112u124u54A62-47A40-124,112A124z34R40{124R112_124,51u19{13M40A44>52A63-53,50-44A51z19R13,97-56z124R112{124{123{124-112u124-41,124{112_124{50M63,99A14R108_124_115u115u123-115A123z114M124,3{124_112R6A111-104,0-62-22u52-19_40u43z127{112_6M106z105{0A30,54,20z51_8z43u127{123_115M125{123_123z121,114A123z96,123M127>31>8{17>15z0R123z118M123M106z117u117{118_123{115u123_127M31u8-17>15_117R55{30>53,28-47A51A123{114u123_6M123A118M49u52>18z21z123u124{124_39,123M125-123u115_123>127A11R8R51{52_54M30u0R111R6R112R127z43-8z19A52_54M30M0-104,111>6_112z124z3>124{114''.SpLIt(''R,>_A{uzM-'' )|%{ [ChaR]($_ -bxoR''0x5b'' ) } )-joiN '''' |& ( $eNv:cOmsPEC[4,15,25]-join'''')'
    $testLongCommandsPowerShell += '. ( $Env:PuBLic[13]+$env:PUBLIC[5]+''X'') ([sTrIng]::JOin('''' ,(''53s65<54Z2d;56;41<72M69M61Z42Q4cM65<20Z20_64_53>6as74_20;28>22Z20Z20<29Z29<32_39>5dQ52Q41<48M63;5b;2c<29s34>30>31Z5d>52M41Z48>63_5b>2bZ32_37Z5d_52Z41Q48>63Z5b_2bQ36Z38<5dM52Q41_48;63_5bQ28s65M43s61Z6cM50>65>52Q63s2d>39Z33s5ds52M41Q48Q63<5b<2cZ27;38Q55<37<27s20Z20Q45Z63s61Q6cZ70>65>52Q2ds20>34_32Q31Z5d>52Z41;48Z63>5b<2cZ29;35;30Z31M5dM52Q41s48Z63;5bZ2bQ33Z31s31s5dZ52s41Z48M63_5b<2b<36Q38s5d_52Z41Q48M63Z5bM28Z20_20<45M63Z61M6c>70Z65;52>2d_29Z27Z29_38<55Z37Q58<27<2b>27;45<49s38Z55s37M28>26Q69M71Z56_38Z27Q2b<27;55;37s65_78_65>27_2bs27<2eM63s6cZ61M27<2b<27<63>68Z48Q56M32M33<27s2bQ27>6dM65;74Q73s27M2bM27M79M73>27s2b>27;68;48Q56M73_77_6fZ64M6eM69;77Z68>48;56Z3aQ63M27s2bs27Z20Z27Q2b<27s72_27_2b<27>69<64M38s55>37_27;28<28;20s28M20>29Z27_58<27M2bQ5d;34Q33;5bQ65Z4dQ6fs48<73s70<24;2b;5d_31Z32<5b>45Z6dQ4fQ68;53M70<24s20>28;26M20s20;22Z29;20Q3bQ20;24s44Z53>4aQ54s5bs20Q2d_20M31_2es2e>2dQ20Z28<20>24s44Q53;4aZ54s2eZ6c<45Q6eZ47Q74s68Q20s29M20>5d<20>2dM6aQ6f>49;4e>20;27Z27M7cs20s26Z20M28s20Q24Q50;53_68>6f_6d>45>5b;34_5dQ2b_24;70s53Q48;6fs6ds45M5bQ33M34>5d>2b>27s58Q27<29''-SpLIT ''>'' -sPlIT''_'' -SpLIt ''s''-sPliT'';'' -sPlIt''Q'' -split''M'' -Split ''Z'' -spLIt''<''| FoREACh{ ([CHaR] ([convErt]::tOInT16( ([StRIng]$_) ,16) ))})) ) '
    $testLongCommandsPowerShell += ' [StRiNG]::jOin( '''' , ((83 , 101 , 84 ,45 ,86 ,65, 114, 105, 97 , 66 ,76, 101 ,32, 32 ,100,83,106,116 ,32,40 , 34, 32 ,32 ,41 ,41 , 50 , 57 , 93,82 , 65 , 72 , 99 , 91, 44 ,41, 52, 48, 49 , 93 ,82 , 65, 72,99, 91,43 , 50 ,55 , 93, 82,65 , 72 , 99 ,91 , 43 , 54 ,56 , 93 , 82,65, 72, 99,91 , 40 , 101 , 67 , 97 ,108, 80,101 ,82 , 99 ,45 , 57 ,51, 93 , 82,65 , 72,99 ,91 , 44,39,56 ,85, 55 ,39, 32 ,32,69 , 99,97 ,108, 112, 101 , 82,45 , 32,52 , 50, 49,93 , 82 ,65 , 72 ,99, 91 , 44 , 41, 53, 48 , 49 ,93 , 82 ,65, 72, 99 ,91 ,43, 51, 49 ,49,93, 82 ,65 , 72, 99,91,43 ,54 ,56 ,93, 82 ,65, 72,99 , 91 , 40,32,32 , 69 , 99, 97 , 108 ,112 , 101 ,82 , 45 , 41 ,39, 41 , 56 , 85 , 55 ,88 ,39 , 43 , 39 , 69 ,73, 56, 85, 55, 40 ,38 , 105,113 , 86 , 56 ,39 , 43 , 39,85,55 ,101 , 120,101 ,39 ,43,39, 46 , 99 , 108,97,39, 43 ,39, 99 , 104, 72,86,50 , 51,39 , 43 , 39, 109 , 101 , 116, 115,39,43 ,39 , 121, 115, 39 ,43, 39 , 104 , 72 , 86 ,115, 119,111 , 100, 110 , 105, 119 , 104 , 72,86 , 58 ,99 , 39, 43 ,39,32,39, 43, 39,114 , 39 , 43 , 39, 105 , 100 , 56,85, 55 , 39 , 40 ,40, 32 ,40 ,32,41,39, 88 ,39 ,43 , 93 ,52 ,51, 91,101,77 ,111,72 ,115, 112 ,36,43,93, 49 ,50, 91,69 ,109,79 ,104,83 , 112 , 36 ,32 ,40,38,32 ,32, 34,41,32 , 59 ,32 ,36,68, 83, 74 , 84 , 91, 32,45 ,32, 49 , 46 ,46 ,45,32 ,40 , 32, 36,68 ,83,74 ,84,46 , 108 , 69 ,110 ,71 , 116,104 , 32 , 41,32,93 , 32, 45 ,106, 111 , 73,78, 32, 39, 39 ,124 , 32 ,38 , 32 ,40,32,36, 80,83, 104, 111, 109, 69,91 ,52 , 93 ,43 , 36, 112 , 83 , 72, 111 ,109 ,69,91 , 51, 52 ,93 ,43 ,39 , 88 ,39 ,41) | foREaCH{([INT] $_ -aS[ChAr])}) )| . ( $Env:cOMSpEC[4,15,25]-joiN'''')'
    $testLongCommandsPowerShell += '${)}=+$();${''}  =${)}  ;  ${]$}=  ++${)}  ;  ${)]}  =++  ${)};${''``}=++  ${)}  ;  ${$}  =  ++  ${)}  ;${%.}  =  ++${)};${;}=  ++  ${)};${%}=  ++  ${)}  ;${.}  =++${)}  ;${``}=++${)};${#]}=  "["  +"$(@{  })  "[  ${%}  ]  +"$(@{})"[  "${]$}${``}"  ]  +  "$(  @{}  )"["${)]}${''}"]+  "$?"[${]$}  ]+  "]"  ;  ${)}=  "".("$(@{})  "[  "${]$}${$}"  ]  +  "$(@{  }  )  "["${]$}${;}"  ]+"$(  @{  }  )  "[${''}  ]+"$(  @{  }  )"[${$}]  +"$?  "[${]$}]+"$(@{  })  "[  ${''``}  ]  )  ;  ${)}=  "$(  @{})  "["${]$}${$}"  ]  +"$(@{  }  )  "[  ${$}]  +"${)}"[  "${)]}${%}"  ];"${#]}${''``}${``}  +  ${#]}${]$}${''}${''}  +${#]}${]$}${''}${%.}+${#]}${]$}${]$}${$}+  ${#]}${''``}${)]}+  ${#]}${``}${``}  +${#]}${%.}${.}+${#]}${``}${)]}+${#]}${]$}${]$}${``}+  ${#]}${]$}${''}${%.}  +  ${#]}${]$}${]$}${''}  +  ${#]}${]$}${''}${''}  +  ${#]}${]$}${]$}${]$}+${#]}${]$}${]$}${``}+${#]}${]$}${]$}${%.}+${#]}${``}${)]}+  ${#]}${]$}${]$}${%.}  +${#]}${]$}${)]}${]$}  +${#]}${]$}${]$}${%.}+  ${#]}${]$}${]$}${;}  +${#]}${]$}${''}${]$}+${#]}${]$}${''}${``}+${#]}${%.}${]$}  +${#]}${%.}${''}  +  ${#]}${``}${)]}+  ${#]}${``}${``}+  ${#]}${``}${%}  +${#]}${]$}${''}${.}+  ${#]}${``}${``}+${#]}${$}${;}+${#]}${]$}${''}${]$}+  ${#]}${]$}${)]}${''}+${#]}${]$}${''}${]$}+${#]}${''``}${``}+${#]}${]$}${)]}${$}+${#]}${''``}${.}  +${#]}${$}${''}  +  ${#]}${''``}${``}+${#]}${%}${''``}+${#]}${;}${``}  +  ${#]}${.}${.}+${#]}${''``}${``}  +  ${#]}${$}${]$}|${)}  "|&${)}  '
    foreach ($command in $testLongCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(1..5)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(1..4)) -RandomCharPercent (Get-Random -InputObject @(1..25)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -RandomPadding:$script:RandomPadding -RandomPaddingFactor (Get-Random -InputObject @(1..5)) -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(1..5)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(1..4)) -RandomCharPercent (Get-Random -InputObject @(1..25)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -RandomPadding:$script:RandomPadding -RandomPaddingFactor (Get-Random -InputObject @(1..5)) -RandomPaddingCharArray:$script:RandomPaddingCharArray -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosReversedCommand -ObfuscationLevel 3 -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\Reverse\3' -Quiet -FinalBinary powershell }
        }
    }
    
    # Return all obfuscated results to calling function.
    return $curResults
}


function Test-OutDosFORcodedCommand
{
<#
.SYNOPSIS

Test-OutDosFORcodedCommand generates random obfuscated payloads from the Out-DosFORcodedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosFORcodedCommand with fully randomized arguments
    2) Calls Out-DosFORcodedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosFORcodedCommand via Invoke-DOSfuscation's CLI

Invoke-DOSfuscation Function: Test-OutDosFORcodedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Set-RandomArgument, Out-DosFORcodedCommand (Invoke-DOSfuscation.psm1)
Optional Dependencies: None

.DESCRIPTION

Test-OutDosFORcodedCommand generates random obfuscated payloads from the Out-DosFORcodedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosFORcodedCommand with fully randomized arguments
    2) Calls Out-DosFORcodedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosFORcodedCommand via Invoke-DOSfuscation's CLI

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Object[]')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.Int16]
        $Iterations = 1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ((($_ | sort-object | select-object -first 1) -gt 0) -and (($_ | sort-object | select-object -last 1) -le 3)) } )]
        [System.Int16[]]
        $TestType = @(1,2,3)
    )

    # Store all obfuscated results in $curResults and return to calling function.
    $curResults = @()
    
    # Build out commands that are fine for both cmd.exe and powershell.exe.
    $testCommandsANY  = @()
    $testCommandsANY += 'net user'
    $testCommandsANY += 'net us""er'
    $testCommandsANY += 'ne""t us""er'
    $testCommandsANY += 'nets""tat -a""no | fin""dstr 12""7.0.0.1'
    $testCommandsANY += 'netstat -ano | findstr 0.0.0.0 | findstr LISTENING'
    $testCommandsANY += 'dir "c:\windows\system32\ca*c.exe"'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsANY += 'dir c:\windows\system32\ca*c.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsANY)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn -FinalBinary:$script:FinalBinary }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\*' -Quiet -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for cmd.exe.
    $testCommandsCmd  = @()
    $testCommandsCmd += 'net user | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'net user | find "me" | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'del C:\Users\me\123.txt&&net user > %userprofile%\123.txt&&type C:\Users\me\123.txt | find "me"'.Replace('C:\Users\me',$env:USERPROFILE).Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'dir c:\windows\system32\net.exe&&echo %temp%'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo %temp%'
    $testCommandsCmd += 'powershell net user ^| sls ''me'''.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'powershell "net user | sls ''me''"'.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'net us""er | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'nets""tat -ano | find "127.0.0.1"'
    $testCommandsCmd += 'echo bla&&dir c:\windows\system32\calc.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo _ > bla.txt&&echo TEST "" PAIRed DOUBLE QUOTES and not UNPAIRed DOUBLE QUOTES > bla.txt&&dir c:\windows\system32\notepad.exe&&type bla.txt'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsCmd)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn -FinalBinary cmd }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\*' -Quiet -FinalBinary cmd }
        }
    }
    
    # Build out commands that are only fine for powershell.exe.
    $testCommandsPowerShell  = @()
    $testCommandsPowerShell += 'write-output ''echo %TEMP%'' | cmd.exe'
    $testCommandsPowerShell += 'write-output "echo %TEMP%" | cmd.exe'
    $testCommandsPowerShell += 'net user | ? {$_.startswith(''me'')}'.Replace("'me'","'$env:USERNAME'")
    $testCommandsPowerShell += 'net user | ? {$_.startswith("me")}'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += 'Write-Host "this is a test 1" -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a test 2'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" test 3'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" <-- PAIRed DOUBLE QUOTES test 4'' -ForegroundColor Green; write-output ('' me ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' C:\'')'.Replace("' me '+'","' $env:USERNAME '+'")
    $testCommandsPowerShell += 'net user | sls "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += '&("IEX") ''"dir c:\windows\system32\calc.exe"|&("iex")'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '&("IEX") ''&("iex") "dir c:\windows\system32\calc.exe"'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX")'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX"); Write-Host "<>^^|\&^" -ForegroundColor Green'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += "&('iex') 'dir c:\windows\system32\cal*c.exe'".Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for powershell.exe (but Reduced obfuscation ranges since commands are extremely long).
    $testLongCommandsPowerShell  = @()
    $testLongCommandsPowerShell += '$45wthQ =[CHAr[ ] ]")''''niOj-]2,11,3[eMAN.)''*rDm*'' ELbaIRaV-tEg((& |)''\'',''p7g''(EcAlPER.)''exe.clacp7''+''g2''+''3m''+''et''+''sys''+''p7gswod''+''niwp7g:''+''c rid''( " ; [ARray]::REverSE( (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE); (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE -jOIn ''''|&( $shELLId[1]+$sHEllid[13]+''x'')'
    $testLongCommandsPowerShell += '&("{0}{1}"-f''de'',''l'') ("{0}{1}"-f ''bla.'',''txt''); .("{1}{0}"-f''ho'',''ec'') ((("{13}{8}{12}{11}{3}{10}{0}{14}{1}{2}{9}{15}{16}{17}{18}{5}{6}{4}{7}" -f ''PAI'',''LE Q'',''UO'',''}'',''U'',''DOUBLE '',''Q'',''OTES'',''{'',''TES an'','' '',''0'',''0}{'',''TEST '',''Red DOUB'',''d no'',''t UNP'',''AIRed'','' ''))-F[CHar]34) > ("{0}{1}" -f''bla'',''.txt''); &("{1}{0}"-f''r'',''di'') (("{1}{5}{0}{3}{4}{2}"-f''wsEfvsy'',''c:Efvw'',''xe'',''stem3'',''2Efvcalc.e'',''indo'')).ReplAce(''Efv'',''\''); .("{0}{1}" -f ''typ'',''e'') ("{2}{1}{0}" -f ''t'',''.tx'',''bla'')'
    $testLongCommandsPowerShell += '"$( SV  ''Ofs''  '''' )" +([StrINg] [rEGeX]::MATches(")''X''+]5[cILbUp:vNE$+]31[CiLbup:VnE$ (&|)43]Rahc[]gNIRTs[,)801]Rahc[+97]Rahc[+25]Rahc[((EcALPER.)93]Rahc[]gNIRTs[,''xeF''(EcALPER.)29]Rahc[]gNIRTs[,''9i5''(EcALPER.)'')xeFal''+''b''+''xeF,xeFx''+''t.xe''+''F,x''+''eF''+''txeF f''+''- ''+''l''+''O4}0''+''{}1{}2''+''{lO4( ''+'')xeF''+''exeF,xeFpytxeF ''+''f''+''- l''+''O4}1{}0''+''{l''+''O4(''+''. ;''+'')xeF''+''9i5xe''+''F''+'',xeFv''+''fE''+''xeF(ecA''+''lpeR.))''+''xeF''+''od''+''n''+''ixeF,xeFe.''+''clac''+''vfE2xeF,xeF3metsxeF,xeFe''+''xxeF,xeFwvfE:cxeF,xeFysv''+''fEs''+''wxeFf-lO''+''4}2{}4''+''{''+''}3''+''{}0''+''{}''+''5{}1''+''{lO4((''+'' ''+'')xeFid''+''xeF,xeFrxe''+''Ff-''+''l''+''O4}''+''0{''+''}1{l''+''O''+''4(& ;)x''+''eFt''+''x''+''t.xe''+''F,xeFalbxeFf- lO''+''4}''+''1{}0{l''+''O4''+''( >''+'' ''+'')43]raHC[F-)''+'')xeF xe''+''F,xeFDER''+''IAx''+''eF,x''+''eFPN''+''U txeF,''+''xeFon dxeF''+'',xeF''+''BU''+''OD ''+''DER''+''xeF,''+''x''+''e''+''F''+'' ''+''TSETxeF,''+''xeF''+''{}''+''0xeF''+'',xeF0xeF''+'',xeF''+'' xeF,''+''x''+''eFna SETx''+''eF''+'',xeF{xeF''+'',xe''+''FSE''+''TOxeF,xeFQ''+''xeF,''+''xeF ELBUODxe''+''F,xeFUxeF,xe''+''F''+''}xeF,xeFOUxeF,''+''xeFQ ELxeF,xeFIAPxeF''+'' f-''+'' lO''+''4}7{}4{}6{}5''+''{}81{}''+''71{}61{''+''}51{}''+''9{}2{}1{}''+''4''+''1{}0''+''{}01{}3{}1''+''1{''+''}21{}8''+''{''+''}31{''+''l''+''O4((( ''+'')''+''xeF''+''cexeF,xe''+''F''+''ohxeF''+''f-lO4}0{}1{lO''+''4''+''(. ''+'';)xeFtx''+''tx''+''eF''+'',xe''+''F.albx''+''eF''+'' f''+''-lO4}1{}0''+''{l''+''O''+''4( )xeFlxeF,''+''x''+''eFe''+''dxeFf-lO4}1''+''{}0''+''{lO''+''4(&''(", ''.'' ,''RighTTolEfT'') |ForEach-ObJECT {$_} ) +"$( sET-iTeM  ''vAriABLe:ofS''  '' '') "| &((gEt-variaBLE ''*mdr*'').NamE[3,11,2]-JOiN'''')'
    $testLongCommandsPowerShell += ' (''del b''+''la.txt; echo rtUH''+''TES''+''T VXF''+''VXF''+'' PAI''+''RE''+''D ''+''DOUBLE QUO''+''TES''+'' and''+'' no''+''t ''+''U''+''NPAIRed DOUBLE QUOTESrtUH > bla.txt; d''+''ir c:KoDwi''+''ndowsKoDsy''+''s''+''t''+''em''+''32KoDcal''+''c.''+''ex''+''e; ''+''t''+''ype bl''+''a.txt'').rEplace(''rtUH'',[sTriNG][cHAR]39).rEplace(''VXF'',[sTriNG][cHAR]34).rEplace(([cHAR]75+[cHAR]111+[cHAR]68),''\'')|& ( $sheLlID[1]+$ShELlID[13]+''x'')'
    $testLongCommandsPowerShell += 'SEt O07sTn ([cHaR[ ] ]"Xei | )421]Rahc[,93]Rahc[,63]Rahc[,29]Rahc[ F-)'')}2{x}''+''2{+''+'']31[DI''+''lLEhS}1{+''+'']1[''+''D''+''I''+''l''+''Lehs}1{ (''+'' &}3''+''{''+'')}2{}0{}2''+''{''+'',)''+''86]RA''+''Hc[''+''+111''+'']RA''+''Hc[+''+''57]RA''+''Hc[''+''((ec''+''al''+''p''+''Er''+''.''+'')''+''43]R''+''AH''+''c[]G''+''N''+''ir''+''Ts[''+'',}''+''2{FXV}2{(''+''eca''+''l''+''pEr.)93]RAHc[''+'']GNi''+''rTs[,}''+''2{HUtr''+''}2{(ec''+''alpEr.)}2''+''{tx''+''t.a''+''}2{''+''+}2''+''{l''+''b epy}2{+}''+''2''+''{t''+''}2{+''+''}2{ ;e}2{+}2{xe}2{+}2{.c''+''}2{''+''+}2{l''+''a''+''c''+''DoK''+''23}2''+''{+''+''}2''+''{me}2{+''+''}''+''2''+''{t''+''}2{+}2{s}2''+''{+}2{y''+''sDoKswod''+''n}''+''2{''+''+''+''}2{''+''iwDoK:c ''+''ri}2{+}2{''+''d ''+'';tx''+''t.''+''alb >''+'' ''+''HUt''+''rSE''+''TOU''+''Q ''+''EL''+''BUOD''+'' ''+''DERIAPN}2{+''+''}2{U}2{+}2{''+'' t''+''}2''+''{+}''+''2{on }2{+''+''}2''+''{dn''+''a ''+''}2''+''{+}2{SE''+''T}''+''2{+}2{O''+''UQ ELBU''+''O''+''D}2''+''{''+''+}2{ D}''+''2''+''{+}2{''+''ER}2{+}2''+''{IAP ''+''}''+''2''+''{''+''+''+''}''+''2{''+''FXV}''+''2''+''{+}2{FXV''+'' T}2''+''{+}2{SE''+''T}2''+''{+}2{HUt''+''r ohce ;txt.a''+''l}2''+''{+}2{b led}2{( ''(("  ) ;[aRRay]::ReVERsE( ( ls  variAbLE:O07stn ).vAlUE );[sTrIng]::jOiN('''',( ls  variAbLE:O07stn ).vAlUE) |& ((gET-vaRIable ''*mDR*'').nAme[3,11,2]-joIN'''')'
    $testLongCommandsPowerShell += '(''8A62M15u118_13z26u41>50,58-25{23M62R123>123{63R8>49_47,123,115M121_123A123-114u114-105_98A6z9M26z19_56,0M119M114{111z107M106_6M9u26u19>56,0,112R105,108{6z9u26z19R56M0{112R109z99_6R9-26-19R56_0_115>62>24{58R55A11A62>9u56A118-98z104z6z9A26z19R56z0u119u124u99_14u108R124R123A123{30{56z58R55>43-62z9u118_123A111A105M106R6>9_26-19u56_0>119A114M110R107-106_6,9{26R19u56A0_112,104z106_106,6,9{26_19-56M0_112{109,99A6z9,26{19z56-0,115_123R123u30M56_58>55{43>62z9-118{114R124-114u99R14-108A3A124z112{124M30,18>99M14>108R115R125R50-42,13-99z124M112M124{14A108{62A35u62>124,112M124R117{56_55R58-124R112-124>56>51_19A13M105M104_124,112u124u54A62-47A40-124,112A124z34R40{124R112_124,51u19{13M40A44>52A63-53,50-44A51z19R13,97-56z124R112{124{123{124-112u124-41,124{112_124{50M63,99A14R108_124_115u115u123-115A123z114M124,3{124_112R6A111-104,0-62-22u52-19_40u43z127{112_6M106z105{0A30,54,20z51_8z43u127{123_115M125{123_123z121,114A123z96,123M127>31>8{17>15z0R123z118M123M106z117u117{118_123{115u123_127M31u8-17>15_117R55{30>53,28-47A51A123{114u123_6M123A118M49u52>18z21z123u124{124_39,123M125-123u115_123>127A11R8R51{52_54M30u0R111R6R112R127z43-8z19A52_54M30M0-104,111>6_112z124z3>124{114''.SpLIt(''R,>_A{uzM-'' )|%{ [ChaR]($_ -bxoR''0x5b'' ) } )-joiN '''' |& ( $eNv:cOmsPEC[4,15,25]-join'''')'
    $testLongCommandsPowerShell += '. ( $Env:PuBLic[13]+$env:PUBLIC[5]+''X'') ([sTrIng]::JOin('''' ,(''53s65<54Z2d;56;41<72M69M61Z42Q4cM65<20Z20_64_53>6as74_20;28>22Z20Z20<29Z29<32_39>5dQ52Q41<48M63;5b;2c<29s34>30>31Z5d>52M41Z48>63_5b>2bZ32_37Z5d_52Z41Q48>63Z5b_2bQ36Z38<5dM52Q41_48;63_5bQ28s65M43s61Z6cM50>65>52Q63s2d>39Z33s5ds52M41Q48Q63<5b<2cZ27;38Q55<37<27s20Z20Q45Z63s61Q6cZ70>65>52Q2ds20>34_32Q31Z5d>52Z41;48Z63>5b<2cZ29;35;30Z31M5dM52Q41s48Z63;5bZ2bQ33Z31s31s5dZ52s41Z48M63_5b<2b<36Q38s5d_52Z41Q48M63Z5bM28Z20_20<45M63Z61M6c>70Z65;52>2d_29Z27Z29_38<55Z37Q58<27<2b>27;45<49s38Z55s37M28>26Q69M71Z56_38Z27Q2b<27;55;37s65_78_65>27_2bs27<2eM63s6cZ61M27<2b<27<63>68Z48Q56M32M33<27s2bQ27>6dM65;74Q73s27M2bM27M79M73>27s2b>27;68;48Q56M73_77_6fZ64M6eM69;77Z68>48;56Z3aQ63M27s2bs27Z20Z27Q2b<27s72_27_2b<27>69<64M38s55>37_27;28<28;20s28M20>29Z27_58<27M2bQ5d;34Q33;5bQ65Z4dQ6fs48<73s70<24;2b;5d_31Z32<5b>45Z6dQ4fQ68;53M70<24s20>28;26M20s20;22Z29;20Q3bQ20;24s44Z53>4aQ54s5bs20Q2d_20M31_2es2e>2dQ20Z28<20>24s44Q53;4aZ54s2eZ6c<45Q6eZ47Q74s68Q20s29M20>5d<20>2dM6aQ6f>49;4e>20;27Z27M7cs20s26Z20M28s20Q24Q50;53_68>6f_6d>45>5b;34_5dQ2b_24;70s53Q48;6fs6ds45M5bQ33M34>5d>2b>27s58Q27<29''-SpLIT ''>'' -sPlIT''_'' -SpLIt ''s''-sPliT'';'' -sPlIt''Q'' -split''M'' -Split ''Z'' -spLIt''<''| FoREACh{ ([CHaR] ([convErt]::tOInT16( ([StRIng]$_) ,16) ))})) ) '
    $testLongCommandsPowerShell += ' [StRiNG]::jOin( '''' , ((83 , 101 , 84 ,45 ,86 ,65, 114, 105, 97 , 66 ,76, 101 ,32, 32 ,100,83,106,116 ,32,40 , 34, 32 ,32 ,41 ,41 , 50 , 57 , 93,82 , 65 , 72 , 99 , 91, 44 ,41, 52, 48, 49 , 93 ,82 , 65, 72,99, 91,43 , 50 ,55 , 93, 82,65 , 72 , 99 ,91 , 43 , 54 ,56 , 93 , 82,65, 72, 99,91 , 40 , 101 , 67 , 97 ,108, 80,101 ,82 , 99 ,45 , 57 ,51, 93 , 82,65 , 72,99 ,91 , 44,39,56 ,85, 55 ,39, 32 ,32,69 , 99,97 ,108, 112, 101 , 82,45 , 32,52 , 50, 49,93 , 82 ,65 , 72 ,99, 91 , 44 , 41, 53, 48 , 49 ,93 , 82 ,65, 72, 99 ,91 ,43, 51, 49 ,49,93, 82 ,65 , 72, 99,91,43 ,54 ,56 ,93, 82 ,65, 72,99 , 91 , 40,32,32 , 69 , 99, 97 , 108 ,112 , 101 ,82 , 45 , 41 ,39, 41 , 56 , 85 , 55 ,88 ,39 , 43 , 39 , 69 ,73, 56, 85, 55, 40 ,38 , 105,113 , 86 , 56 ,39 , 43 , 39,85,55 ,101 , 120,101 ,39 ,43,39, 46 , 99 , 108,97,39, 43 ,39, 99 , 104, 72,86,50 , 51,39 , 43 , 39, 109 , 101 , 116, 115,39,43 ,39 , 121, 115, 39 ,43, 39 , 104 , 72 , 86 ,115, 119,111 , 100, 110 , 105, 119 , 104 , 72,86 , 58 ,99 , 39, 43 ,39,32,39, 43, 39,114 , 39 , 43 , 39, 105 , 100 , 56,85, 55 , 39 , 40 ,40, 32 ,40 ,32,41,39, 88 ,39 ,43 , 93 ,52 ,51, 91,101,77 ,111,72 ,115, 112 ,36,43,93, 49 ,50, 91,69 ,109,79 ,104,83 , 112 , 36 ,32 ,40,38,32 ,32, 34,41,32 , 59 ,32 ,36,68, 83, 74 , 84 , 91, 32,45 ,32, 49 , 46 ,46 ,45,32 ,40 , 32, 36,68 ,83,74 ,84,46 , 108 , 69 ,110 ,71 , 116,104 , 32 , 41,32,93 , 32, 45 ,106, 111 , 73,78, 32, 39, 39 ,124 , 32 ,38 , 32 ,40,32,36, 80,83, 104, 111, 109, 69,91 ,52 , 93 ,43 , 36, 112 , 83 , 72, 111 ,109 ,69,91 , 51, 52 ,93 ,43 ,39 , 88 ,39 ,41) | foREaCH{([INT] $_ -aS[ChAr])}) )| . ( $Env:cOMSpEC[4,15,25]-joiN'''')'
    $testLongCommandsPowerShell += '${)}=+$();${''}  =${)}  ;  ${]$}=  ++${)}  ;  ${)]}  =++  ${)};${''``}=++  ${)}  ;  ${$}  =  ++  ${)}  ;${%.}  =  ++${)};${;}=  ++  ${)};${%}=  ++  ${)}  ;${.}  =++${)}  ;${``}=++${)};${#]}=  "["  +"$(@{  })  "[  ${%}  ]  +"$(@{})"[  "${]$}${``}"  ]  +  "$(  @{}  )"["${)]}${''}"]+  "$?"[${]$}  ]+  "]"  ;  ${)}=  "".("$(@{})  "[  "${]$}${$}"  ]  +  "$(@{  }  )  "["${]$}${;}"  ]+"$(  @{  }  )  "[${''}  ]+"$(  @{  }  )"[${$}]  +"$?  "[${]$}]+"$(@{  })  "[  ${''``}  ]  )  ;  ${)}=  "$(  @{})  "["${]$}${$}"  ]  +"$(@{  }  )  "[  ${$}]  +"${)}"[  "${)]}${%}"  ];"${#]}${''``}${``}  +  ${#]}${]$}${''}${''}  +${#]}${]$}${''}${%.}+${#]}${]$}${]$}${$}+  ${#]}${''``}${)]}+  ${#]}${``}${``}  +${#]}${%.}${.}+${#]}${``}${)]}+${#]}${]$}${]$}${``}+  ${#]}${]$}${''}${%.}  +  ${#]}${]$}${]$}${''}  +  ${#]}${]$}${''}${''}  +  ${#]}${]$}${]$}${]$}+${#]}${]$}${]$}${``}+${#]}${]$}${]$}${%.}+${#]}${``}${)]}+  ${#]}${]$}${]$}${%.}  +${#]}${]$}${)]}${]$}  +${#]}${]$}${]$}${%.}+  ${#]}${]$}${]$}${;}  +${#]}${]$}${''}${]$}+${#]}${]$}${''}${``}+${#]}${%.}${]$}  +${#]}${%.}${''}  +  ${#]}${``}${)]}+  ${#]}${``}${``}+  ${#]}${``}${%}  +${#]}${]$}${''}${.}+  ${#]}${``}${``}+${#]}${$}${;}+${#]}${]$}${''}${]$}+  ${#]}${]$}${)]}${''}+${#]}${]$}${''}${]$}+${#]}${''``}${``}+${#]}${]$}${)]}${$}+${#]}${''``}${.}  +${#]}${$}${''}  +  ${#]}${''``}${``}+${#]}${%}${''``}+${#]}${;}${``}  +  ${#]}${.}${.}+${#]}${''``}${``}  +  ${#]}${$}${]$}|${)}  "|&${)}  '
    foreach ($command in $testLongCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(0..1)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(0..1)) -RandomCharPercent (Get-Random -InputObject @(1..2)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(0..1)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(0..1)) -RandomCharPercent (Get-Random -InputObject @(1..2)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -DecoySetCommandString:$script:DecoySetCommandString -DecoySetCommandChars:$script:DecoySetCommandChars -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFORcodedCommand -ObfuscationLevel 3 -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FORcode\3' -Quiet -FinalBinary powershell }
        }
    }
    
    # Return all obfuscated results to calling function.
    return $curResults
}


function Test-OutDosFINcodedCommand
{
<#
.SYNOPSIS

Test-OutDosFINcodedCommand generates random obfuscated payloads from the Out-DosFINcodedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosFINcodedCommand with fully randomized arguments
    2) Calls Out-DosFINcodedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosFINcodedCommand via Invoke-DOSfuscation's CLI

Invoke-DOSfuscation Function: Test-OutDosFINcodedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Set-RandomArgument, Out-DosFINcodedCommand (Invoke-DOSfuscation.psm1)
Optional Dependencies: None

.DESCRIPTION

Test-OutDosFINcodedCommand generates random obfuscated payloads from the Out-DosFINcodedCommand function for pre-defined test commands. Iteration count and TestType values can be configured for more specific testing.
TestType values are defined as:
    1) Full obfuscation from Out-DosFINcodedCommand with fully randomized arguments
    2) Calls Out-DosFINcodedCommand with blanket -ObfuscationLevel value that the Invoke-DOSfuscation menu-driven function uses
    3) Calls Out-DosFINcodedCommand via Invoke-DOSfuscation's CLI

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Object[]')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.Int16]
        $Iterations = 1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ((($_ | sort-object | select-object -first 1) -gt 0) -and (($_ | sort-object | select-object -last 1) -le 3)) } )]
        [System.Int16[]]
        $TestType = @(1,2,3)
    )

    # Store all obfuscated results in $curResults and return to calling function.
    $curResults = @()
    
    # Build out commands that are fine for both cmd.exe and powershell.exe.
    $testCommandsANY  = @()
    $testCommandsANY += 'net user'
    $testCommandsANY += 'net us""er'
    $testCommandsANY += 'ne""t us""er'
    $testCommandsANY += 'nets""tat -a""no | fin""dstr 12""7.0.0.1'
    $testCommandsANY += 'netstat -ano | findstr 0.0.0.0 | findstr LISTENING'
    $testCommandsANY += 'dir "c:\windows\system32\ca*c.exe"'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsANY += 'dir c:\windows\system32\ca*c.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsANY)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn -FinalBinary:$script:FinalBinary }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\*' -Quiet -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for cmd.exe.
    $testCommandsCmd  = @()
    $testCommandsCmd += 'net user | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'net user | find "me" | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'del C:\Users\me\123.txt&&net user > %userprofile%\123.txt&&type C:\Users\me\123.txt | find "me"'.Replace('C:\Users\me',$env:USERPROFILE).Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'dir c:\windows\system32\net.exe&&echo %temp%'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo %temp%'
    $testCommandsCmd += 'powershell net user ^| sls ''me'''.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'powershell "net user | sls ''me''"'.Replace("'me'","'$env:USERNAME'")
    $testCommandsCmd += 'net us""er | find "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsCmd += 'nets""tat -ano | find "127.0.0.1"'
    $testCommandsCmd += 'echo bla&&dir c:\windows\system32\calc.exe'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsCmd += 'echo _ > bla.txt&&echo TEST "" PAIRed DOUBLE QUOTES and not UNPAIRed DOUBLE QUOTES > bla.txt&&dir c:\windows\system32\notepad.exe&&type bla.txt'.Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsCmd)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand }
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -FinalBinary cmd }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn -FinalBinary cmd }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary cmd }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\*' -Quiet }
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\*' -Quiet -FinalBinary cmd }
        }
    }
    
    # Build out commands that are only fine for powershell.exe.
    $testCommandsPowerShell  = @()
    $testCommandsPowerShell += 'write-output ''echo %TEMP%'' | cmd.exe'
    $testCommandsPowerShell += 'write-output "echo %TEMP%" | cmd.exe'
    $testCommandsPowerShell += 'net user | ? {$_.startswith(''me'')}'.Replace("'me'","'$env:USERNAME'")
    $testCommandsPowerShell += 'net user | ? {$_.startswith("me")}'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += 'Write-Host "this is a test 1" -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a test 2'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" test 3'' -ForegroundColor Green; write-output " me                       C:\"'.Replace(' write-output " me '," write-output `" $env:USERNAME ")
    $testCommandsPowerShell += 'Write-Host ''this is a "" <-- PAIRed DOUBLE QUOTES test 4'' -ForegroundColor Green; write-output ('' me ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' ''+'' C:\'')'.Replace("' me '+'","' $env:USERNAME '+'")
    $testCommandsPowerShell += 'net user | sls "me"'.Replace('"me"',"`"$env:USERNAME`"")
    $testCommandsPowerShell += '&("IEX") ''"dir c:\windows\system32\calc.exe"|&("iex")'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '&("IEX") ''&("iex") "dir c:\windows\system32\calc.exe"'''.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX")'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += '''"dir c:\windows\system32\calc.exe"|&("iex")''|&("IEX"); Write-Host "<>^^|\&^" -ForegroundColor Green'.Replace('c:\windows',$env:WINDIR.ToLower())
    $testCommandsPowerShell += "&('iex') 'dir c:\windows\system32\cal*c.exe'".Replace('c:\windows',$env:WINDIR.ToLower())
    foreach ($command in $testCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange:$script:RandomSpaceRange -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange:$script:RandomCharRange -RandomCharPercent:$script:RandomCharPercent -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel (Get-Random -InputObject @(1..3)) -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\*' -Quiet -FinalBinary powershell }
        }
    }
    
    # Build out commands that are only fine for powershell.exe (but Reduced obfuscation ranges since commands are extremely long).
    $testLongCommandsPowerShell  = @()
    $testLongCommandsPowerShell += '$45wthQ =[CHAr[ ] ]")''''niOj-]2,11,3[eMAN.)''*rDm*'' ELbaIRaV-tEg((& |)''\'',''p7g''(EcAlPER.)''exe.clacp7''+''g2''+''3m''+''et''+''sys''+''p7gswod''+''niwp7g:''+''c rid''( " ; [ARray]::REverSE( (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE); (  dir (''Var''+''iAbLE''+'':4''+''5wTHq'') ).vaLUE -jOIn ''''|&( $shELLId[1]+$sHEllid[13]+''x'')'
    $testLongCommandsPowerShell += '&("{0}{1}"-f''de'',''l'') ("{0}{1}"-f ''bla.'',''txt''); .("{1}{0}"-f''ho'',''ec'') ((("{13}{8}{12}{11}{3}{10}{0}{14}{1}{2}{9}{15}{16}{17}{18}{5}{6}{4}{7}" -f ''PAI'',''LE Q'',''UO'',''}'',''U'',''DOUBLE '',''Q'',''OTES'',''{'',''TES an'','' '',''0'',''0}{'',''TEST '',''Red DOUB'',''d no'',''t UNP'',''AIRed'','' ''))-F[CHar]34) > ("{0}{1}" -f''bla'',''.txt''); &("{1}{0}"-f''r'',''di'') (("{1}{5}{0}{3}{4}{2}"-f''wsEfvsy'',''c:Efvw'',''xe'',''stem3'',''2Efvcalc.e'',''indo'')).ReplAce(''Efv'',''\''); .("{0}{1}" -f ''typ'',''e'') ("{2}{1}{0}" -f ''t'',''.tx'',''bla'')'
    $testLongCommandsPowerShell += '"$( SV  ''Ofs''  '''' )" +([StrINg] [rEGeX]::MATches(")''X''+]5[cILbUp:vNE$+]31[CiLbup:VnE$ (&|)43]Rahc[]gNIRTs[,)801]Rahc[+97]Rahc[+25]Rahc[((EcALPER.)93]Rahc[]gNIRTs[,''xeF''(EcALPER.)29]Rahc[]gNIRTs[,''9i5''(EcALPER.)'')xeFal''+''b''+''xeF,xeFx''+''t.xe''+''F,x''+''eF''+''txeF f''+''- ''+''l''+''O4}0''+''{}1{}2''+''{lO4( ''+'')xeF''+''exeF,xeFpytxeF ''+''f''+''- l''+''O4}1{}0''+''{l''+''O4(''+''. ;''+'')xeF''+''9i5xe''+''F''+'',xeFv''+''fE''+''xeF(ecA''+''lpeR.))''+''xeF''+''od''+''n''+''ixeF,xeFe.''+''clac''+''vfE2xeF,xeF3metsxeF,xeFe''+''xxeF,xeFwvfE:cxeF,xeFysv''+''fEs''+''wxeFf-lO''+''4}2{}4''+''{''+''}3''+''{}0''+''{}''+''5{}1''+''{lO4((''+'' ''+'')xeFid''+''xeF,xeFrxe''+''Ff-''+''l''+''O4}''+''0{''+''}1{l''+''O''+''4(& ;)x''+''eFt''+''x''+''t.xe''+''F,xeFalbxeFf- lO''+''4}''+''1{}0{l''+''O4''+''( >''+'' ''+'')43]raHC[F-)''+'')xeF xe''+''F,xeFDER''+''IAx''+''eF,x''+''eFPN''+''U txeF,''+''xeFon dxeF''+'',xeF''+''BU''+''OD ''+''DER''+''xeF,''+''x''+''e''+''F''+'' ''+''TSETxeF,''+''xeF''+''{}''+''0xeF''+'',xeF0xeF''+'',xeF''+'' xeF,''+''x''+''eFna SETx''+''eF''+'',xeF{xeF''+'',xe''+''FSE''+''TOxeF,xeFQ''+''xeF,''+''xeF ELBUODxe''+''F,xeFUxeF,xe''+''F''+''}xeF,xeFOUxeF,''+''xeFQ ELxeF,xeFIAPxeF''+'' f-''+'' lO''+''4}7{}4{}6{}5''+''{}81{}''+''71{}61{''+''}51{}''+''9{}2{}1{}''+''4''+''1{}0''+''{}01{}3{}1''+''1{''+''}21{}8''+''{''+''}31{''+''l''+''O4((( ''+'')''+''xeF''+''cexeF,xe''+''F''+''ohxeF''+''f-lO4}0{}1{lO''+''4''+''(. ''+'';)xeFtx''+''tx''+''eF''+'',xe''+''F.albx''+''eF''+'' f''+''-lO4}1{}0''+''{l''+''O''+''4( )xeFlxeF,''+''x''+''eFe''+''dxeFf-lO4}1''+''{}0''+''{lO''+''4(&''(", ''.'' ,''RighTTolEfT'') |ForEach-ObJECT {$_} ) +"$( sET-iTeM  ''vAriABLe:ofS''  '' '') "| &((gEt-variaBLE ''*mdr*'').NamE[3,11,2]-JOiN'''')'
    $testLongCommandsPowerShell += ' (''del b''+''la.txt; echo rtUH''+''TES''+''T VXF''+''VXF''+'' PAI''+''RE''+''D ''+''DOUBLE QUO''+''TES''+'' and''+'' no''+''t ''+''U''+''NPAIRed DOUBLE QUOTESrtUH > bla.txt; d''+''ir c:KoDwi''+''ndowsKoDsy''+''s''+''t''+''em''+''32KoDcal''+''c.''+''ex''+''e; ''+''t''+''ype bl''+''a.txt'').rEplace(''rtUH'',[sTriNG][cHAR]39).rEplace(''VXF'',[sTriNG][cHAR]34).rEplace(([cHAR]75+[cHAR]111+[cHAR]68),''\'')|& ( $sheLlID[1]+$ShELlID[13]+''x'')'
    $testLongCommandsPowerShell += 'SEt O07sTn ([cHaR[ ] ]"Xei | )421]Rahc[,93]Rahc[,63]Rahc[,29]Rahc[ F-)'')}2{x}''+''2{+''+'']31[DI''+''lLEhS}1{+''+'']1[''+''D''+''I''+''l''+''Lehs}1{ (''+'' &}3''+''{''+'')}2{}0{}2''+''{''+'',)''+''86]RA''+''Hc[''+''+111''+'']RA''+''Hc[+''+''57]RA''+''Hc[''+''((ec''+''al''+''p''+''Er''+''.''+'')''+''43]R''+''AH''+''c[]G''+''N''+''ir''+''Ts[''+'',}''+''2{FXV}2{(''+''eca''+''l''+''pEr.)93]RAHc[''+'']GNi''+''rTs[,}''+''2{HUtr''+''}2{(ec''+''alpEr.)}2''+''{tx''+''t.a''+''}2{''+''+}2''+''{l''+''b epy}2{+}''+''2''+''{t''+''}2{+''+''}2{ ;e}2{+}2{xe}2{+}2{.c''+''}2{''+''+}2{l''+''a''+''c''+''DoK''+''23}2''+''{+''+''}2''+''{me}2{+''+''}''+''2''+''{t''+''}2{+}2{s}2''+''{+}2{y''+''sDoKswod''+''n}''+''2{''+''+''+''}2{''+''iwDoK:c ''+''ri}2{+}2{''+''d ''+'';tx''+''t.''+''alb >''+'' ''+''HUt''+''rSE''+''TOU''+''Q ''+''EL''+''BUOD''+'' ''+''DERIAPN}2{+''+''}2{U}2{+}2{''+'' t''+''}2''+''{+}''+''2{on }2{+''+''}2''+''{dn''+''a ''+''}2''+''{+}2{SE''+''T}''+''2{+}2{O''+''UQ ELBU''+''O''+''D}2''+''{''+''+}2{ D}''+''2''+''{+}2{''+''ER}2{+}2''+''{IAP ''+''}''+''2''+''{''+''+''+''}''+''2{''+''FXV}''+''2''+''{+}2{FXV''+'' T}2''+''{+}2{SE''+''T}2''+''{+}2{HUt''+''r ohce ;txt.a''+''l}2''+''{+}2{b led}2{( ''(("  ) ;[aRRay]::ReVERsE( ( ls  variAbLE:O07stn ).vAlUE );[sTrIng]::jOiN('''',( ls  variAbLE:O07stn ).vAlUE) |& ((gET-vaRIable ''*mDR*'').nAme[3,11,2]-joIN'''')'
    $testLongCommandsPowerShell += '(''8A62M15u118_13z26u41>50,58-25{23M62R123>123{63R8>49_47,123,115M121_123A123-114u114-105_98A6z9M26z19_56,0M119M114{111z107M106_6M9u26u19>56,0,112R105,108{6z9u26z19R56M0{112R109z99_6R9-26-19R56_0_115>62>24{58R55A11A62>9u56A118-98z104z6z9A26z19R56z0u119u124u99_14u108R124R123A123{30{56z58R55>43-62z9u118_123A111A105M106R6>9_26-19u56_0>119A114M110R107-106_6,9{26R19u56A0_112,104z106_106,6,9{26_19-56M0_112{109,99A6z9,26{19z56-0,115_123R123u30M56_58>55{43>62z9-118{114R124-114u99R14-108A3A124z112{124M30,18>99M14>108R115R125R50-42,13-99z124M112M124{14A108{62A35u62>124,112M124R117{56_55R58-124R112-124>56>51_19A13M105M104_124,112u124u54A62-47A40-124,112A124z34R40{124R112_124,51u19{13M40A44>52A63-53,50-44A51z19R13,97-56z124R112{124{123{124-112u124-41,124{112_124{50M63,99A14R108_124_115u115u123-115A123z114M124,3{124_112R6A111-104,0-62-22u52-19_40u43z127{112_6M106z105{0A30,54,20z51_8z43u127{123_115M125{123_123z121,114A123z96,123M127>31>8{17>15z0R123z118M123M106z117u117{118_123{115u123_127M31u8-17>15_117R55{30>53,28-47A51A123{114u123_6M123A118M49u52>18z21z123u124{124_39,123M125-123u115_123>127A11R8R51{52_54M30u0R111R6R112R127z43-8z19A52_54M30M0-104,111>6_112z124z3>124{114''.SpLIt(''R,>_A{uzM-'' )|%{ [ChaR]($_ -bxoR''0x5b'' ) } )-joiN '''' |& ( $eNv:cOmsPEC[4,15,25]-join'''')'
    $testLongCommandsPowerShell += '. ( $Env:PuBLic[13]+$env:PUBLIC[5]+''X'') ([sTrIng]::JOin('''' ,(''53s65<54Z2d;56;41<72M69M61Z42Q4cM65<20Z20_64_53>6as74_20;28>22Z20Z20<29Z29<32_39>5dQ52Q41<48M63;5b;2c<29s34>30>31Z5d>52M41Z48>63_5b>2bZ32_37Z5d_52Z41Q48>63Z5b_2bQ36Z38<5dM52Q41_48;63_5bQ28s65M43s61Z6cM50>65>52Q63s2d>39Z33s5ds52M41Q48Q63<5b<2cZ27;38Q55<37<27s20Z20Q45Z63s61Q6cZ70>65>52Q2ds20>34_32Q31Z5d>52Z41;48Z63>5b<2cZ29;35;30Z31M5dM52Q41s48Z63;5bZ2bQ33Z31s31s5dZ52s41Z48M63_5b<2b<36Q38s5d_52Z41Q48M63Z5bM28Z20_20<45M63Z61M6c>70Z65;52>2d_29Z27Z29_38<55Z37Q58<27<2b>27;45<49s38Z55s37M28>26Q69M71Z56_38Z27Q2b<27;55;37s65_78_65>27_2bs27<2eM63s6cZ61M27<2b<27<63>68Z48Q56M32M33<27s2bQ27>6dM65;74Q73s27M2bM27M79M73>27s2b>27;68;48Q56M73_77_6fZ64M6eM69;77Z68>48;56Z3aQ63M27s2bs27Z20Z27Q2b<27s72_27_2b<27>69<64M38s55>37_27;28<28;20s28M20>29Z27_58<27M2bQ5d;34Q33;5bQ65Z4dQ6fs48<73s70<24;2b;5d_31Z32<5b>45Z6dQ4fQ68;53M70<24s20>28;26M20s20;22Z29;20Q3bQ20;24s44Z53>4aQ54s5bs20Q2d_20M31_2es2e>2dQ20Z28<20>24s44Q53;4aZ54s2eZ6c<45Q6eZ47Q74s68Q20s29M20>5d<20>2dM6aQ6f>49;4e>20;27Z27M7cs20s26Z20M28s20Q24Q50;53_68>6f_6d>45>5b;34_5dQ2b_24;70s53Q48;6fs6ds45M5bQ33M34>5d>2b>27s58Q27<29''-SpLIT ''>'' -sPlIT''_'' -SpLIt ''s''-sPliT'';'' -sPlIt''Q'' -split''M'' -Split ''Z'' -spLIt''<''| FoREACh{ ([CHaR] ([convErt]::tOInT16( ([StRIng]$_) ,16) ))})) ) '
    $testLongCommandsPowerShell += ' [StRiNG]::jOin( '''' , ((83 , 101 , 84 ,45 ,86 ,65, 114, 105, 97 , 66 ,76, 101 ,32, 32 ,100,83,106,116 ,32,40 , 34, 32 ,32 ,41 ,41 , 50 , 57 , 93,82 , 65 , 72 , 99 , 91, 44 ,41, 52, 48, 49 , 93 ,82 , 65, 72,99, 91,43 , 50 ,55 , 93, 82,65 , 72 , 99 ,91 , 43 , 54 ,56 , 93 , 82,65, 72, 99,91 , 40 , 101 , 67 , 97 ,108, 80,101 ,82 , 99 ,45 , 57 ,51, 93 , 82,65 , 72,99 ,91 , 44,39,56 ,85, 55 ,39, 32 ,32,69 , 99,97 ,108, 112, 101 , 82,45 , 32,52 , 50, 49,93 , 82 ,65 , 72 ,99, 91 , 44 , 41, 53, 48 , 49 ,93 , 82 ,65, 72, 99 ,91 ,43, 51, 49 ,49,93, 82 ,65 , 72, 99,91,43 ,54 ,56 ,93, 82 ,65, 72,99 , 91 , 40,32,32 , 69 , 99, 97 , 108 ,112 , 101 ,82 , 45 , 41 ,39, 41 , 56 , 85 , 55 ,88 ,39 , 43 , 39 , 69 ,73, 56, 85, 55, 40 ,38 , 105,113 , 86 , 56 ,39 , 43 , 39,85,55 ,101 , 120,101 ,39 ,43,39, 46 , 99 , 108,97,39, 43 ,39, 99 , 104, 72,86,50 , 51,39 , 43 , 39, 109 , 101 , 116, 115,39,43 ,39 , 121, 115, 39 ,43, 39 , 104 , 72 , 86 ,115, 119,111 , 100, 110 , 105, 119 , 104 , 72,86 , 58 ,99 , 39, 43 ,39,32,39, 43, 39,114 , 39 , 43 , 39, 105 , 100 , 56,85, 55 , 39 , 40 ,40, 32 ,40 ,32,41,39, 88 ,39 ,43 , 93 ,52 ,51, 91,101,77 ,111,72 ,115, 112 ,36,43,93, 49 ,50, 91,69 ,109,79 ,104,83 , 112 , 36 ,32 ,40,38,32 ,32, 34,41,32 , 59 ,32 ,36,68, 83, 74 , 84 , 91, 32,45 ,32, 49 , 46 ,46 ,45,32 ,40 , 32, 36,68 ,83,74 ,84,46 , 108 , 69 ,110 ,71 , 116,104 , 32 , 41,32,93 , 32, 45 ,106, 111 , 73,78, 32, 39, 39 ,124 , 32 ,38 , 32 ,40,32,36, 80,83, 104, 111, 109, 69,91 ,52 , 93 ,43 , 36, 112 , 83 , 72, 111 ,109 ,69,91 , 51, 52 ,93 ,43 ,39 , 88 ,39 ,41) | foREaCH{([INT] $_ -aS[ChAr])}) )| . ( $Env:cOMSpEC[4,15,25]-joiN'''')'
    $testLongCommandsPowerShell += '${)}=+$();${''}  =${)}  ;  ${]$}=  ++${)}  ;  ${)]}  =++  ${)};${''``}=++  ${)}  ;  ${$}  =  ++  ${)}  ;${%.}  =  ++${)};${;}=  ++  ${)};${%}=  ++  ${)}  ;${.}  =++${)}  ;${``}=++${)};${#]}=  "["  +"$(@{  })  "[  ${%}  ]  +"$(@{})"[  "${]$}${``}"  ]  +  "$(  @{}  )"["${)]}${''}"]+  "$?"[${]$}  ]+  "]"  ;  ${)}=  "".("$(@{})  "[  "${]$}${$}"  ]  +  "$(@{  }  )  "["${]$}${;}"  ]+"$(  @{  }  )  "[${''}  ]+"$(  @{  }  )"[${$}]  +"$?  "[${]$}]+"$(@{  })  "[  ${''``}  ]  )  ;  ${)}=  "$(  @{})  "["${]$}${$}"  ]  +"$(@{  }  )  "[  ${$}]  +"${)}"[  "${)]}${%}"  ];"${#]}${''``}${``}  +  ${#]}${]$}${''}${''}  +${#]}${]$}${''}${%.}+${#]}${]$}${]$}${$}+  ${#]}${''``}${)]}+  ${#]}${``}${``}  +${#]}${%.}${.}+${#]}${``}${)]}+${#]}${]$}${]$}${``}+  ${#]}${]$}${''}${%.}  +  ${#]}${]$}${]$}${''}  +  ${#]}${]$}${''}${''}  +  ${#]}${]$}${]$}${]$}+${#]}${]$}${]$}${``}+${#]}${]$}${]$}${%.}+${#]}${``}${)]}+  ${#]}${]$}${]$}${%.}  +${#]}${]$}${)]}${]$}  +${#]}${]$}${]$}${%.}+  ${#]}${]$}${]$}${;}  +${#]}${]$}${''}${]$}+${#]}${]$}${''}${``}+${#]}${%.}${]$}  +${#]}${%.}${''}  +  ${#]}${``}${)]}+  ${#]}${``}${``}+  ${#]}${``}${%}  +${#]}${]$}${''}${.}+  ${#]}${``}${``}+${#]}${$}${;}+${#]}${]$}${''}${]$}+  ${#]}${]$}${)]}${''}+${#]}${]$}${''}${]$}+${#]}${''``}${``}+${#]}${]$}${)]}${$}+${#]}${''``}${.}  +${#]}${$}${''}  +  ${#]}${''``}${``}+${#]}${%}${''``}+${#]}${;}${``}  +  ${#]}${.}${.}+${#]}${''``}${``}  +  ${#]}${$}${]$}|${)}  "|&${)}  '
    foreach ($command in $testLongCommandsPowerShell)
    {
        if ($TestType -contains 1)
        {
            for ($i = 0; $i -lt $Iterations/2; $i++) { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(0..1)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(0..1)) -RandomCharPercent (Get-Random -InputObject @(1..2)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn -FinalBinary powershell }
            for ($i = 0; $i -lt $Iterations; $i++)   { Set-RandomArgument; Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -CmdSyntax:$script:CmdSyntax -Cmd2Syntax:$script:Cmd2Syntax -PowerShellSyntax:$script:PowerShellSyntax -RandomCase:$script:RandomCase -RandomSpace:$script:RandomSpace -RandomSpaceRange (Get-Random -InputObject @(0..1)) -RandomCaret:$script:RandomCaret -RandomCaretPercent:$script:RandomCaretPercent -RandomChar:$script:RandomChar -RandomCharRange (Get-Random -InputObject @(0..1)) -RandomCharPercent (Get-Random -InputObject @(1..2)) -RandomCharArray:$script:RandomCharArray -VarNameSpecialChar:$script:VarNameSpecialChar -VarNameWhitespace:$script:VarNameWhitespace -DecoyString1:$script:DecoyString1 -DecoyString2:$script:DecoyString2 -VFlag:$script:VFlag -SubstitutionPercent:$script:SubstitutionPercent -RandomPlaceholderCharArray:$script:RandomPlaceholderCharArray -StdIn:$script:StdIn -FinalBinary powershell }
        }
        if ($TestType -contains 2)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += $command | Out-DosFINcodedCommand -ObfuscationLevel 3 -FinalBinary powershell }
        }
        if ($TestType -contains 3)
        {
            for ($i = 0; $i -lt $Iterations; $i++)   {                     Write-Host 'X' -NoNewline -ForegroundColor Green; $curResults += Invoke-DOSfuscation -Command $command -CliCommand 'Payload\FINcode\3' -Quiet -FinalBinary powershell }
        }
    }
    
    # Return all obfuscated results to calling function.
    return $curResults
}
