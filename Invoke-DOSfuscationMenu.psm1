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



#########################################################################################################################################################################
## All functions in this module are solely for the menu-driven Invoke-DOSfuscation exploratory experience and do not provide any additional obfuscation functionality. ##
## This menu-driven experience is included to more easily enable Red and Blue Teamers to explore the DOSfuscation options in a quick and visual manner.                ##
#########################################################################################################################################################################


function Invoke-DOSfuscation
{
<#
.SYNOPSIS

Master function that orchestrates the application of all obfuscation functions to provided Cmd or PowerShell command or command path/URL contents. Interactive mode enables one to explore all available obfuscation functions, while interacting with the functions directly (outside of this Invoke-DOSfuscation function) gives the user insanely more flexibility and tuning capabilities.

Invoke-DOSfuscation Function: Invoke-DOSfuscation
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Show-DosAsciiArt, Show-DosHelpMenu, Show-DosMenu, Show-DosOptionsMenu, Show-DosTutorial and Out-DosCommandContent (all located in Invoke-DOSfuscation.psm1)
Optional Dependencies: None
 
.DESCRIPTION

Master function that orchestrates the application of all obfuscation functions to provided Cmd or PowerShell command or command path/URL contents. Interactive mode enables one to explore all available obfuscation functions, while interacting with the functions directly (outside of this Invoke-DOSfuscation function) gives the user insanely more flexibility and tuning capabilities.

.PARAMETER Command

Specifies Cmd or PowerShell command.

.PARAMETER CommandPath

Specifies path to Cmd or PowerShell command (can be local file, UNC-path, or remote URI).

.PARAMETER CliCommand

Specifies obfuscation commands to run against the input Command or CommandPath parameter.

.PARAMETER FinalBinary

(Optional) Specifies the obfuscated command should be executed by a child process of powershell.exe, cmd.exe or no unnecessary child process (default). Some command escaping scenarios require at least one child process to avoid errors and will automatically be converted to such necessary syntax.

.PARAMETER NoExit

(Optional - only works if Command is specified) Specifices that the function does not exit after running obfuscation commands defined in CliCommand parameter.

.PARAMETER Quiet

(Optional) Specifices that the function output only the final obfuscated result via stdout, or at a minimum skips animated ASCII art introduction (but why would anybody want to do that?!?).

.EXAMPLE

C:\PS> Import-Module .\Invoke-DOSfuscation.psd1; Invoke-DOSfuscation

.EXAMPLE

C:\PS> Import-Module .\Invoke-DOSfuscation.psd1; Invoke-DOSfuscation -Command 'dir C:\Windows\System32\ | findstr calc\.exe'

.EXAMPLE

C:\PS> Import-Module .\Invoke-DOSfuscation.psd1; Invoke-DOSfuscation -Command 'dir C:\Windows\System32\ | findstr calc\.exe' -CliCommand 'ENCODING\*' -Quiet

dir C%SystemRoot:~1,-8%%TMP:~-11,-10%W%CommonProgramFiles(x86):~-23,1%ndows%TMP:~-5,-4%Sy%SystemRoot:~-1%t%TEMP:~-3,1%%APPDATA:~-4,1%32%ProgramFiles:~-14,-13%%CommonProgramFiles:~10,-18%| fin%SystemRoot:~6,1%str ca%CommonProgramW6432:~-3,1%%PUBLIC:~-1%\.e%ProgramFiles(x86):~18,-3%%ProgramFiles:~-2,-1%

.EXAMPLE

C:\PS> Import-Module .\Invoke-DOSfuscation.psd1; Invoke-DOSfuscation -CommandPath https://bit.ly/L3g1t -CliCommand 'PAYLOAD\*\1' -FinalBinary powershell -Quiet

cmd /V:ON/C"set 4Ih=neerG roloCdnuorgeroF- NOITACOL ETOMER MORF EDOC LLEHSREWOP DETUCEXE YLLUFSSECCUS tsoH-etirW&&for /L %c in (91,-1,0)do set MPJf=!MPJf!!4Ih:~%c,1!&&if %c==0 powershell.exe "!MPJf:~6!" "

.NOTES

Invoke-DOSfuscation orchestrates the application of all obfuscation functions to provided Cmd or PowerShell command or command path contents to evade basic command-line detections and static signatures. This framework was developed to enable defenders to automate the generation of randomly-obfuscated payloads to develop and tune new detection approaches for highly obfuscated cmd.exe commands.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding(DefaultParameterSetName = 'Command')]
    param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'Command')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Command,
        
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'CommandPath')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CommandPath,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateSet('cmd','powershell','none')]
        [System.String]
        $FinalBinary = 'none',
        
        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $CliCommand,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $NoExit,
        
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $Quiet
    )

    # Define variables for CLI functionality.
    $script:cliCommands       = @()
    $script:compoundCommand   = @()
    $script:quietWasSpecified = $false
    $cliWasSpecified          = $false
    $noExitWasSpecified       = $false

    # Either convert Command to a string or convert script at $Path to a string.
    if ($PSBoundParameters['Command'])
    {
        $script:cliCommands += ('set command ' + $Command)
    }
    if ($PSBoundParameters['CommandPath'])
    {
        $script:cliCommands += ('set commandpath ' + $CommandPath)
    }

    # Add set FinalBinary command if -FinalBinary argument is specified.
    if ($PSBoundParameters['FinalBinary'])
    {
        $script:cliCommands += ('set finalbinary ' + $FinalBinary)
    }
    elseif ($FinalBinary -eq 'none')
    {
        $script:FinalBinary = ''
    }

    if ($PSBoundParameters['Quiet'])
    {
        $script:quietWasSpecified = $true
    }

    # Append Command to cliCommands if specified by user input.
    if ($PSBoundParameters['CliCommand'])
    {
        $script:cliCommands += $CliCommand.Split(',')
        $cliWasSpecified = $true

        if ($PSBoundParameters['NoExit'])
        {
            $noExitWasSpecified = $true
        }

        if ($PSBoundParameters['Quiet'])
        {
            # Create empty Write-Host and Start-Sleep proxy functions to cause any Write-Host or Start-Sleep invocations to not do anything until non-interactive -Command values are finished being processed.
            function Write-Host  { [CmdletBinding(SupportsShouldProcess = $true)] param($Object, [Switch] $NoNewline, $Separator, $ForegroundColor, $BackgroundColor) if ($PSCmdlet.ShouldProcess("Temporarily overriding of Write-Host cmdlet successful"))  {} }
            function Start-Sleep { [CmdletBinding(SupportsShouldProcess = $true)] param($Seconds, $Milliseconds) if ($PSCmdlet.ShouldProcess("Temporarily overriding of Start-Sleep cmdlet successful")) {} }
            $script:quietWasSpecified = $true
        }
    }

    ########################################
    ## Script-wide variable instantiation ##
    ########################################

    # Script-level array of Show Options menu, set as SCRIPT-level so it can be set from within any of the functions.
    # Build out menu for Show Options selection from user in Show-DosOptionsMenu menu.
    $script:CommandPath = ''
    $script:Command     = ''
    $script:cliSyntax         = @()
    $script:executionCommands = @()
    $script:obfuscatedCommand = ''
    $script:obfuscatedCommandHistory = @()
    $script:obfuscationLength = ''
    $script:optionsMenu  =   @()
    $script:optionsMenu += , @('Command'           , $script:Command           , $true)
    $script:optionsMenu += , @('CommandPath'       , $script:CommandPath       , $true)
    $script:optionsMenu += , @('FinalBinary'       , $script:CommandPath       , $true)
    $script:optionsMenu += , @('CommandLineSyntax' , $script:cliSyntax         , $false)
    $script:optionsMenu += , @('ExecutionCommands' , $script:executionCommands , $false)
    $script:optionsMenu += , @('ObfuscatedCommand' , $script:obfuscatedCommand , $false)
    $script:optionsMenu += , @('ObfuscationLength' , $script:obfuscatedCommand , $false)
    
    # Build out $settableInputOptions from above items set as $true (as settable).
    $settableInputOptions = @()
    foreach ($option in $script:optionsMenu)
    {
        if ($option[2])
        {
            $settableInputOptions += ([System.String] $option[0]).ToLower().Trim()
        }
    }

    # Ensure Invoke-DOSfuscation module was properly imported before continuing.
    if (-not (Get-Module Invoke-DOSfuscation | where-object {$_.ModuleType -eq 'Script'}))
    {
        $pathToPsd1 = "$scriptDir\Invoke-DOSfuscation.psd1"
        if ($pathToPsd1.Contains(' '))
        {
            $pathToPsd1 = '"' + $pathToPsd1 + '"'
        }
        Write-Host "`n`nERROR: Invoke-DOSfuscation module is not loaded. You must run:" -ForegroundColor Red
        Write-Host "       Import-Module $pathToPsd1`n`n" -ForegroundColor Yellow
        
        Start-Sleep -Seconds 1
        exit
    }
    
    # Build interactive menus.
    $lineSpacing = '[*] '
    
    # Main Menu.
    $menuLevel                  =   @()
    $menuLevel                 += , @($lineSpacing , 'BINARY  ' , 'Obfuscated <binary> syntax for cmd.exe & powershell.exe')
    $menuLevel                 += , @($lineSpacing , 'ENCODING' , 'Environment variable <encoding>')
    $menuLevel                 += , @($lineSpacing , 'PAYLOAD ' , 'Obfuscated <payload> via DOSfuscation')
    
    # Main\Binary Menu.
    $menuLevel_Binary           =   @()
    $menuLevel_Binary          += , @($lineSpacing , 'CMD'      , "`tObfuscated syntax for <cmd.exe>")
    $menuLevel_Binary          += , @($lineSpacing , 'PS'       , "`tObfuscated syntax for <powershell.exe> (if applicable)")
    
    $menuLevel_Binary_Cmd       =   @()
    $menuLevel_Binary_Cmd      += , @($lineSpacing , '1'        , 'Env var encoding'                       , @('Get-ObfuscatedCmd'          , , 1))
    $menuLevel_Binary_Cmd      += , @($lineSpacing , '2'        , 'FOR loop + sub-command'                 , @('Get-ObfuscatedCmd'          , , 2))
    $menuLevel_Binary_Cmd      += , @($lineSpacing , '3'        , 'FOR loop + sub-command + obfuscation'   , @('Get-ObfuscatedCmd'          , , 3))
    
    $menuLevel_Binary_PS        =   @()
    $menuLevel_Binary_PS       += , @($lineSpacing , '1'        , "`tEnv var encoding"                     , @('Get-ObfuscatedPowerShell'   , , 1))
    $menuLevel_Binary_PS       += , @($lineSpacing , '2'        , "`tFOR loop + sub-command"               , @('Get-ObfuscatedPowerShell'   , , 2))
    $menuLevel_Binary_PS       += , @($lineSpacing , '3'        , "`tFOR loop + sub-command + obfuscation" , @('Get-ObfuscatedPowerShell'   , , 3))

    # Main\Encoding Menu.
    $menuLevel_Encoding         =   @()
    $menuLevel_Encoding        += , @($lineSpacing , '1'        , "`t<Basic> env var encoding"             , @('Out-EnvVarEncodedCommand'   , , 1))
    $menuLevel_Encoding        += , @($lineSpacing , '2'        , "`t<Medium> env var encoding"            , @('Out-EnvVarEncodedCommand'   , , 2))
    $menuLevel_Encoding        += , @($lineSpacing , '3'        , "`t<Intense> env var encoding"           , @('Out-EnvVarEncodedCommand'   , , 3))

    # Main\Payload Menu.
    $menuLevel_Payload          =   @()
    $menuLevel_Payload         += , @($lineSpacing , 'CONCAT  ' , '<Concat>enation obfuscation')
    $menuLevel_Payload         += , @($lineSpacing , 'REVERSE ' , '<Reverse> command FOR-loop obfuscation')
    $menuLevel_Payload         += , @($lineSpacing , 'FORCODE ' , '<FOR>-loop encoding obfuscation')
    $menuLevel_Payload         += , @($lineSpacing , 'FINCODE ' , '<FIN>-style string replacement obfuscation')
    
    $menuLevel_Payload_Concat   =   @()
    $menuLevel_Payload_Concat  += , @($lineSpacing , '1'        , '<Basic> obfuscation'                    , @('Out-DosConcatenatedCommand' , , 1))
    $menuLevel_Payload_Concat  += , @($lineSpacing , '2'        , '<Medium> obfuscation'                   , @('Out-DosConcatenatedCommand' , , 2))
    $menuLevel_Payload_Concat  += , @($lineSpacing , '3'        , '<Intense> obfuscation'                  , @('Out-DosConcatenatedCommand' , , 3))
    
    $menuLevel_Payload_Reverse  =   @()
    $menuLevel_Payload_Reverse += , @($lineSpacing , '1'        , '<Basic> obfuscation'                    , @('Out-DosReversedCommand'     , , 1))
    $menuLevel_Payload_Reverse += , @($lineSpacing , '2'        , '<Medium> obfuscation'                   , @('Out-DosReversedCommand'     , , 2))
    $menuLevel_Payload_Reverse += , @($lineSpacing , '3'        , '<Intense> obfuscation'                  , @('Out-DosReversedCommand'     , , 3))
    
    $menuLevel_Payload_FORcode  =   @()
    $menuLevel_Payload_FORcode += , @($lineSpacing , '1'        , '<Basic> obfuscation'                    , @('Out-DosFORcodedCommand'     , , 1))
    $menuLevel_Payload_FORcode += , @($lineSpacing , '2'        , '<Medium> obfuscation'                   , @('Out-DosFORcodedCommand'     , , 2))
    $menuLevel_Payload_FORcode += , @($lineSpacing , '3'        , '<Intense> obfuscation'                  , @('Out-DosFORcodedCommand'     , , 3))
    
    $menuLevel_Payload_FINcode  =   @()
    $menuLevel_Payload_FINcode += , @($lineSpacing , '1'        , '<Basic> obfuscation'                    , @('Out-DosFINcodedCommand'     , , 1))
    $menuLevel_Payload_FINcode += , @($lineSpacing , '2'        , '<Medium> obfuscation'                   , @('Out-DosFINcodedCommand'     , , 2))
    $menuLevel_Payload_FINcode += , @($lineSpacing , '3'        , '<Intense> obfuscation'                  , @('Out-DosFINcodedCommand'     , , 3))
    
    # Input options to display non-interactive menus or perform actions.
    $tutorialInputOptions         = @(@('tutorial')                             , "<Tutorial> of how to use this tool        `t  " )
    $menuInputOptionsShowHelp     = @(@('help','get-help','?','-?','/?','menu') , "Show this <Help> Menu                     `t  " )
    $menuInputOptionsShowOptions  = @(@('show options','show','options')        , "<Show options> for payload to obfuscate   `t  " )
    $clearScreenInputOptions      = @(@('clear','clear-host','cls')             , "<Clear> screen                            `t  " )
    $copyToClipboardInputOptions  = @(@('copy','clip','clipboard')              , "<Copy> ObfuscatedCommand to clipboard     `t  " )
    $outputToDiskInputOptions     = @(@('out')                                  , "Write ObfuscatedCommand <Out> to disk     `t  " )
    $executionInputOptions        = @(@('exec','execute','test','run')          , "<Execute> ObfuscatedCommand locally       `t  " )
    $resetObfuscationInputOptions = @(@('reset')                                , "<Reset> ALL obfuscation for ObfuscatedCommand  ")
    $undoObfuscationInputOptions  = @(@('undo')                                 , "<Undo> LAST obfuscation for ObfuscatedCommand  ")
    $backCommandInputOptions      = @(@('back','cd ..')                         , "Go <Back> to previous obfuscation menu    `t  " )
    $exitCommandInputOptions      = @(@('quit','exit')                          , "<Quit> Invoke-DOSfuscation                `t  " )
    $homeMenuInputOptions         = @(@('home','main')                          , "return to <Home> Menu                     `t  " )
    # For Version 1.0 ASCII art is not necessary.
    #$showAsciiArtInputOptions     = @(@('ascii')                                , "Display random <ASCII> art for the lulz :)`t")
    
    # Add all above input options lists to be displayed in SHOW OPTIONS menu.
    $allAvailableInputOptionsLists   = @()
    $allAvailableInputOptionsLists  += , $tutorialInputOptions
    $allAvailableInputOptionsLists  += , $menuInputOptionsShowHelp
    $allAvailableInputOptionsLists  += , $menuInputOptionsShowOptions
    $allAvailableInputOptionsLists  += , $clearScreenInputOptions
    $allAvailableInputOptionsLists  += , $executionInputOptions
    $allAvailableInputOptionsLists  += , $copyToClipboardInputOptions
    $allAvailableInputOptionsLists  += , $outputToDiskInputOptions
    $allAvailableInputOptionsLists  += , $resetObfuscationInputOptions
    $allAvailableInputOptionsLists  += , $undoObfuscationInputOptions
    $allAvailableInputOptionsLists  += , $backCommandInputOptions   
    $allAvailableInputOptionsLists  += , $exitCommandInputOptions
    $allAvailableInputOptionsLists  += , $homeMenuInputOptions
    # For Version 1.0 ASCII art is not necessary.
    #$allAvailableInputOptionsLists  += , $showAsciiArtInputOptions

    # Input options to change interactive menus.
    $exitInputOptions = $exitCommandInputOptions[0]
    $menuInputOptions = $backCommandInputOptions[0]

    # Obligatory ASCII Art.
    Show-DosAsciiArt -Quiet:$script:quietWasSpecified
    Start-Sleep -Seconds 2
    
    # Show Help Menu once at beginning of script.
    Show-DosHelpMenu
    
    # Main loop for user interaction. Show-DosMenu function displays current function along with acceptable input options (defined in arrays instantiated above).
    # User input and validation is handled within Show-DosMenu.
    $userResponse = ''
    while ($exitInputOptions -notcontains ([System.String] $userResponse).ToLower())
    {
        $userResponse = ([System.String] $userResponse).Trim()

        if ($homeMenuInputOptions[0] -contains ([System.String] $userResponse).ToLower())
        {
            $userResponse = ''
        }

        # Display menu if it is defined in a menu variable with $userResponse in the variable name.
        if (Test-Path ('Variable:' + "MenuLevel$userResponse"))
        {
            $userResponse = Show-DosMenu -Menu (Get-Variable "MenuLevel$userResponse").Value -MenuName $userResponse
        }
        else
        {
            Write-Error "The variable MenuLevel$userResponse does not exist."
            
            $userResponse = 'quit'
        }
        
        if (($userResponse -eq 'quit') -and $cliWasSpecified -and -not $noExitWasSpecified)
        {
            Write-Output $script:obfuscatedCommand.Trim("`n")
            
            $userResponse = 'quit'
        }
    }

    $menuInputOptions = $null
}


# Get location of this script no matter what the current directory is for the process executing this script.
$scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 


function Show-DosMenu
{
<#
.SYNOPSIS

HELPER function :: Displays current menu with obfuscation navigation and application options for Invoke-DOSfuscation.

Invoke-DOSfuscation Function: Show-DosMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-DosMenu displays current menu with obfuscation navigation and application options for Invoke-DOSfuscation.

.PARAMETER Menu

Specifies the menu options to display, with acceptable input options parsed out of this array.

.PARAMETER MenuName

Specifies the menu header display and the breadcrumb used in the interactive prompt display.

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
    
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $Menu,

        [Parameter(Position = 0, Mandatory = $false)]
        [System.String]
        $MenuName
    )

    # Extract all acceptable values from $Menu.
    $acceptableInput = @()
    $selectionContainsCommand = $false
    foreach ($line in $Menu)
    {
        # If there are 4 items in each $line in $Menu then the fourth item is a command to exec if selected.
        if ($line.Count -eq 4)
        {
            $selectionContainsCommand = $true
        }
        $acceptableInput += ($line[1]).Trim(' ')
    }

    $userInput = $null
    
    while ($acceptableInput -notcontains $userInput)
    {
        # Format custom breadcrumb prompt.
        Write-Host "`n"
        $breadCrumb = $MenuName.Trim('_')
        if ($breadCrumb.Length -gt 1)
        {
            if ($breadCrumb.ToLower() -eq 'show options')
            {
                $breadCrumb = 'Show Options'
            }
            if ($MenuName -ne '')
            {
                # Handle specific case substitutions from what is ALL CAPS in interactive menu and then correct casing we want to appear in the Breadcrumb.
                $breadCrumbOCD  =   @()
                $breadCrumbOCD += , @('ps'      ,'PS')
                $breadCrumbOCD += , @('forcode' ,'FORcode')
                $breadCrumbOCD += , @('fincode' ,'FINcode')

                $breadCrumbArray = @()
                foreach ($crumb in $breadCrumb.Split('_'))
                {
                    # Perform casing substitutions for any matches in $breadCrumbOCD array.
                    $stillLookingForSubstitution = $true
                    foreach ($substitution in $breadCrumbOCD)
                    {
                        if ($crumb.ToLower() -eq $substitution[0])
                        {
                            $breadCrumbArray += $substitution[1]
                            $stillLookingForSubstitution = $false
                        }
                    }

                    # If no substitution occurred above then simply upper-case the first character and lower-case all the remaining characters.
                    if ($stillLookingForSubstitution)
                    {
                        $breadCrumbArray += $crumb.Substring(0,1).ToUpper() + $crumb.Substring(1).ToLower()
                    }
                }
                $breadCrumb = $breadCrumbArray -Join '\'
            }
            $breadCrumb = '\' + $breadCrumb
        }
        
        # Output menu heading.
        $firstLine = "Choose one of the below "
        if ($breadCrumb -ne '')
        {
            $firstLine = $firstLine + $breadCrumb.Trim('\') + ' '
        }
        Write-Host "$firstLine" -NoNewline
        
        # Change color and verbiage if selection will execute command.
        if ($selectionContainsCommand)
        {
            Write-Host "options" -NoNewline -ForegroundColor Green
            Write-Host " to" -NoNewline
            Write-Host " APPLY" -NoNewline -ForegroundColor Green
            Write-Host " to current payload" -NoNewline
        }
        else
        {
            Write-Host "options" -NoNewline -ForegroundColor Yellow
        }
        Write-Host ":`n"
    
        foreach ($line in $Menu)
        {
            $lineSpace  = $line[0]
            $lineOption = $line[1]
            $lineValue  = $line[2]
            Write-Host $lineSpace -NoNewline

            # If not empty then include breadcrumb in $lineOption output (is not colored and won't affect user input syntax).
            if (($breadCrumb -ne '') -and ($lineSpace.StartsWith('[')))
            {
                Write-Host ($breadCrumb.ToUpper().Trim('\') + '\') -NoNewline
            }
            
            # Change color if selection will execute command.
            if ($selectionContainsCommand)
            {
                Write-Host $lineOption -NoNewline -ForegroundColor Green
            }
            else
            {
                Write-Host $lineOption -NoNewline -ForegroundColor Yellow
            }
            
            # Add additional coloring to string encapsulated by <> if it exists in $lineValue.
            if ($lineValue.Contains('<') -and $lineValue.Contains('>'))
            {
                $firstPart  = $lineValue.Substring(0,$lineValue.IndexOf('<'))
                $middlePart = $lineValue.Substring($firstPart.Length + 1)
                $middlePart = $middlePart.Substring(0,$middlePart.IndexOf('>'))
                $lastPart   = $lineValue.Substring($firstPart.Length+$middlePart.Length + 2)
                Write-Host "`t$firstPart" -NoNewline
                Write-Host $middlePart -NoNewline -ForegroundColor Cyan

                # Handle if more than one term needs to be output in different color.
                if ($lastPart.Contains('<') -and $lastPart.Contains('>'))
                {
                    $lineValue  = $lastPart
                    $firstPart  = $lineValue.Substring(0,$lineValue.IndexOf('<'))
                    $middlePart = $lineValue.Substring($firstPart.Length + 1)
                    $middlePart = $middlePart.Substring(0,$middlePart.IndexOf('>'))
                    $lastPart   = $lineValue.Substring($firstPart.Length+$middlePart.Length + 2)
                    Write-Host $firstPart -NoNewline
                    Write-Host $middlePart -NoNewline -ForegroundColor Cyan
                }

                Write-Host $lastPart
            }
            else
            {
                Write-Host "`t$lineValue"
            }
        }
        
        # Prompt for user input with custom breadcrumb prompt.
        Write-Host ''
        if ($userInput -ne '')
        {
            Write-Host ''
        }
        $userInput = ''
        
        while (($userInput -eq '') -and ($script:compoundCommand.Count -eq 0))
        {
            # Output custom prompt.
            Write-Host "Invoke-DOSfuscation$breadCrumb> " -NoNewline -ForegroundColor Magenta

            # Get interactive user input if cliCommands input variable was not specified by user.
            if ($script:cliCommands -or ($script:cliCommands.Count -gt 0))
            {
                if ($script:cliCommands.GetType().Name -eq 'String')
                {
                    $nextCliCommand = $script:cliCommands.Trim()
                    $script:cliCommands = @()
                }
                else
                {
                    $nextCliCommand = ([System.String] $script:cliCommands[0]).Trim()
                    $script:cliCommands = for ($i=1; $i -lt $script:cliCommands.Count; $i++) { $script:cliCommands[$i] }
                }

                $userInput = $nextCliCommand
            }
            else
            {
                # If Command was defined on command line and -NoExit switch was not defined then output final ObfuscatedCommand to stdout and then quit. Otherwise continue with interactive Invoke-DOSfuscation.
                if ($cliWasSpecified -and ($script:cliCommands.Count -lt 1) -and ($script:compoundCommand.Count -lt 1) -and ($script:quietWasSpecified -or -not $noExitWasSpecified))
                {
                    if ($script:quietWasSpecified)
                    {
                        # Remove Write-Host and Start-Sleep proxy functions so that Write-Host and Start-Sleep cmdlets will be called during the remainder of the interactive Invoke-DOSfuscation session.
                        Remove-Item -Path Function:Write-Host
                        Remove-Item -Path Function:Start-Sleep

                        $script:quietWasSpecified = $false

                        # Automatically run 'Show Options' so the user has context of what has successfully been executed.
                        $userInput  = 'show options'
                        $breadCrumb = 'Show Options'
                    }
                    # -NoExit was not specified and -Command was, so we will output the result back in the main While loop.
                    if (-not $noExitWasSpecified)
                    {
                        $userInput = 'quit'
                    }
                }
                else
                {
                    $userInput = (Read-Host).Trim()
                }

                # Process interactive UserInput using CLI syntax, so comma-delimited and slash-delimited commands can be processed interactively.
                if (($script:cliCommands.Count -eq 0) -and -not $userInput.ToLower().StartsWith('set ') -and $userInput.Contains(','))
                {
                    $script:cliCommands = $userInput.Split(',')
                    
                    # Reset $userInput so current While loop will be traversed once more and process UserInput command as a CliCommand.
                    $userInput = ''
                }
            }
        }

        # Trim any leading trailing slashes so it doesn't misinterpret it as a compound command unnecessarily.
        $userInput = $userInput.Trim('/\')

        # If input is for home menu option and not in home menu then prepend 'Home\' to 
        $homeMenuOptions = $menuLevel | foreach-object { ($_[1]).ToLower().Trim() }
        if (($homeMenuOptions -contains $userInput.Split('/\')[0]) -and ($breadCrumb -ne ''))
        {
            $userInput = 'Home\' + $userInput
        }

        # If current command contains \ or / and does not start with SET or OUT then we are dealing with a compound command.
        # Setting $script:CompounCommand in below IF block.
        if (($script:compoundCommand.Count -eq 0) -and -not $userInput.ToLower().StartsWith('set ') -and -not $userInput.ToLower().StartsWith('out ') -and ($userInput.Contains('\') -or $userInput.Contains('/')))
        {
            $script:compoundCommand = $userInput.Split('/\')
        }

        # If current command contains \ or / and does not start with SET then we are dealing with a compound command.
        # Parsing out next command from $script:compoundCommand in below IF block.
        if ($script:compoundCommand.Count -gt 0)
        {
            $userInput = ''
            while (($userInput -eq '') -and ($script:compoundCommand.Count -gt 0))
            {
                # If last compound command then it will be a String.
                if ($script:compoundCommand.GetType().Name -eq 'String')
                {
                    $nextcompoundCommand = $script:compoundCommand.Trim()
                    $script:compoundCommand = @()
                }
                else
                {
                    # If there are more commands left in compound command then it won't be a String (above IF block).
                    # In this else block we get the next command from compoundCommand array.
                    $nextcompoundCommand = ([System.String] $script:compoundCommand[0]).Trim()
                    
                    # Set remaining commands back into compoundCommand.
                    $compoundCommandTemp = $script:compoundCommand
                    $script:compoundCommand = @()
                    for ($i=1; $i -lt $compoundCommandTemp.Count; $i++)
                    {
                        $script:compoundCommand += $compoundCommandTemp[$i]
                    }
                }
                $userInput = $nextcompoundCommand
            }
        }

        # Handle new RegEx functionality.
        # Identify if there is any regex in current UserInput by removing all alphanumeric characters.
        $tempUserInput = $userInput.ToLower() -replace '[a-z0-9\s\-\?\/\\]',''

        if (($tempUserInput.Length -gt 0) -and -not ($userInput.Trim().ToLower().StartsWith('set ')) -and -not ($userInput.Trim().ToLower().StartsWith('out ')))
        {
            # Replace any simple wildcard with .* syntax.
            $userInput = $userInput.Replace('.*','_____').Replace('*','.*').Replace('_____','.*')

            # Prepend UserInput with ^ and append with $ if not already there.
            if (-not $userInput.Trim().StartsWith('^') -and -not $userInput.Trim().StartsWith('.*'))
            {
                $userInput = '^' + $userInput
            }
            if (-not $userInput.Trim().EndsWith('$') -and -not $userInput.Trim().EndsWith('.*'))
            {
                $userInput = $userInput + '$'
            }

            # See if there are any filtered matches in the current menu.
            try
            {
                $menuFiltered = ($Menu | where-object {($_[1].Trim() -match $userInput) -and ($_[1].Trim().Length -gt 0)} | foreach-object {$_[1].Trim()})
            }
            catch
            {
                # Output error message if Regular Expression causes error in above filtering step.
                # E.g. Using *+ instead of *[+]
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' The current Regular Expression caused the following error:'
                write-host "       $_" -ForegroundColor Red
            }

            # If there are filtered matches in the current menu then randomly choose one for the UserInput value.
            if ($menuFiltered)
            {
                # Randomly select UserInput from filtered options.
                $userInput = (Get-Random -Input $menuFiltered).Trim()

                # Output randomly chosen option (and filtered options selected from) if more than one option were returned from regex.
                if ($menuFiltered.Count -gt 1)
                {
                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    if ($selectionContainsCommand)
                    {
                        $colorToOutput = 'Green'
                    }
                    else
                    {
                        $colorToOutput = 'Yellow'
                    }

                    Write-Host "`n`nRandomly selected " -NoNewline
                    Write-Host $userInput -NoNewline -ForegroundColor $colorToOutput
                    write-host " from the following filtered options: " -NoNewline

                    for ($i=0; $i -lt $menuFiltered.Count-1; $i++)
                    {
                        Write-Host $menuFiltered[$i].Trim() -NoNewline -ForegroundColor $colorToOutput
                        Write-Host ', ' -NoNewline
                    }
                    Write-Host $menuFiltered[$menuFiltered.Count-1].Trim() -NoNewline -ForegroundColor $colorToOutput
                }
            }
        }

        if ($exitInputOptions -contains $userInput.ToLower())
        {
            return $exitInputOptions[0]
        }
        elseif (($menuInputOptions -contains $userInput.ToLower()) -or ($menuInputOptions -contains $userInput.ToLower().Trim('^$')))
        {
            # Commands like 'back' that will return user to previous interactive menu.
            if ($breadCrumb.Contains('\'))
            {
                $userInput = $breadCrumb.Substring(0,$breadCrumb.LastIndexOf('\')).Replace('\','_')
            }
            else
            {
                $userInput = ''
            }
            return $userInput.ToLower()
        }
        elseif ($homeMenuInputOptions[0] -contains $userInput.ToLower())
        {
            return $userInput.ToLower()
        }
        elseif ($userInput.ToLower().StartsWith('set '))
        {
            # Extract $userInputOptionName and $userInputOptionValue from $userInput SET command.
            $userInputOptionName  = $null
            $userInputOptionValue = $null
            $hasError = $false
    
            $userInputMinusSet = $userInput.Substring(4).Trim()
            if ($userInputMinusSet.IndexOf(' ') -eq -1)
            {
                $hasError = $true
                $userInputOptionName  = $userInputMinusSet.Trim()
            }
            else
            {
                $userInputOptionName  = $userInputMinusSet.Substring(0,$userInputMinusSet.IndexOf(' ')).Trim().ToLower()
                $userInputOptionValue = $userInputMinusSet.Substring($userInputMinusSet.IndexOf(' ')).Trim()
            }

            # Validate that $userInputOptionName is defined in $settableInputOptions.
            if ($settableInputOptions -contains $userInputOptionName)
            {
                # Perform separate validation for $userInputOptionValue before setting value. Set to 'emptyvalue' if no value was entered.
                if ($userInputOptionValue.Length -eq 0)
                {
                    $userInputOptionName = 'emptyvalue'
                }

                switch ($userInputOptionName.ToLower())
                {
                    'commandpath' {
                        if ($userInputOptionValue -and ((Test-Path $userInputOptionValue) -or ($userInputOptionValue -match '(http|https)://')))
                        {
                            # Reset Command in case it contained a value.
                            $script:Command = ''
                        
                            # Check if user-input CommandPath is a URL or a directory.
                            if ($userInputOptionValue -match '(http|https)://')
                            {
                                # CommandPath is a URL.
                            
                                # Download content.
                                $script:Command = (New-Object Net.WebClient).DownloadString($userInputOptionValue)
                            
                                # Set script-wide variables for future reference.
                                $script:CommandPath               = $userInputOptionValue
                                $script:obfuscatedCommand         = $script:Command
                                $script:obfuscatedCommandHistory  = @()
                                $script:obfuscatedCommandHistory += $script:Command
                                $script:cliSyntax                 = @()
                                $script:executionCommands         = @()
                            
                                Write-Host "`n`nSuccessfully set CommandPath (as URL):" -ForegroundColor Cyan
                                Write-Host $script:CommandPath -ForegroundColor Magenta
                            }
                            elseif ((Get-Item $userInputOptionValue) -is [System.IO.DirectoryInfo])
                            {
                                # CommandPath does not exist.
                                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                Write-Host ' Path is a directory instead of a file (' -NoNewline
                                Write-Host "$userInputOptionValue" -NoNewline -ForegroundColor Cyan
                                Write-Host ").`n" -NoNewline
                            }
                            else
                            {
                                # Read contents from user-input CommandPath value.
                                Get-ChildItem $userInputOptionValue -ErrorAction Stop | Out-Null
                                $script:Command = [IO.File]::ReadAllText((Resolve-Path $userInputOptionValue))
                        
                                # Set script-wide variables for future reference.
                                $script:CommandPath               = $userInputOptionValue
                                $script:obfuscatedCommand         = $script:Command
                                $script:obfuscatedCommandHistory  = @()
                                $script:obfuscatedCommandHistory += $script:Command
                                $script:cliSyntax                 = @()
                                $script:executionCommands         = @()
                            
                                Write-Host "`n`nSuccessfully set CommandPath:" -ForegroundColor Cyan
                                Write-Host $script:CommandPath -ForegroundColor Magenta
                            }
                        }
                        else
                        {
                            # CommandPath not found (failed Test-Path).
                            Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                            Write-Host ' Path not found (' -NoNewline
                            Write-Host "$userInputOptionValue" -NoNewline -ForegroundColor Cyan
                            Write-Host ").`n" -NoNewline
                        }
                    }
                    'command' {
                        # Remove evenly paired {} '' or "" if user includes it around their command input.
                        foreach ($char in @(@('{','}'),@('"','"'),@("'","'")))
                        {
                            while ($userInputOptionValue.StartsWith($char[0]) -and $userInputOptionValue.EndsWith($char[1]))
                            {
                                $userInputOptionValue = $userInputOptionValue.Substring(1,$userInputOptionValue.Length - 2).Trim()
                            }
                        }

                        # Check if input is PowerShell encoded command syntax so we can decode for Command.
                        if ($userInputOptionValue -match 'powershell(.exe | )\s*-(e |ec |en |enc |enco |encod |encode |encoded |encodedc |encodedco |encodedcom |encodedcomm |encodedcomma |encodedcomman |encodedcommand)\s*["'']*[a-z+=/\\]')
                        {
                            # Extract encoded command.
                            $encodedCommand = $userInputOptionValue.Substring($userInputOptionValue.ToLower().IndexOf(' -e') + 3)
                            $encodedCommand = $encodedCommand.Substring($encodedCommand.IndexOf(' ')).Trim(" '`"")

                            # Decode Unicode-encoded $encodedCommand
                            $userInputOptionValue = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand))
                        }

                        # Set script-wide variables for future reference.
                        $script:CommandPath               = 'N/A'
                        $script:Command                   = $userInputOptionValue
                        $script:obfuscatedCommand         = $userInputOptionValue
                        $script:obfuscatedCommandHistory  = @()
                        $script:obfuscatedCommandHistory += $userInputOptionValue
                        $script:cliSyntax                 = @()
                        $script:executionCommands         = @()
                    
                        Write-Host "`n`nSuccessfully set Command:" -ForegroundColor Cyan
                        Write-Host $script:Command -ForegroundColor Magenta
                    }
                    'finalbinary' {
                        # Store the "base" breadcrumb values for all previous Payload commands in an array for easier warning message for FinalBinary values being set.
                        $warningMessage = ''
                        $prevPayloadCommandsBaseArray = @()
                        if ($script:cliSyntax)
                        {
                            $prevPayloadCommandsBaseArray += ($script:cliSyntax | foreach-object { $_.Split('\')[0] }) | where-object { $_ -match '^Payload$' }
                        }

                        if ($prevPayloadCommandsBaseArray.Count -eq 1)
                        {
                            $warningMessage = ' (though previous Payload obfuscation needs to be re-run)'
                        }
                        elseif ($prevPayloadCommandsBaseArray.Count -gt 1)
                        {
                            $warningMessage = ' (though previous Payload obfuscations need to be re-run)'
                        }

                        # Validate acceptable value entered for SET FINALBINARY command.
                        switch ($userInputOptionValue)
                        {
                            'cmd' {
                                $script:FinalBinary = 'Cmd'
                                
                                Write-Host "`n`nSuccessfully set FinalBinary" -NoNewline -ForegroundColor Cyan
                                Write-Host $warningMessage -NoNewline -ForegroundColor Yellow
                                Write-Host ":" -ForegroundColor Cyan
                                Write-Host $script:FinalBinary -ForegroundColor Magenta
                            }
                            'powershell' {
                                $script:FinalBinary = 'PowerShell'
                                
                                # Store the "base" breadcrumb values for all previous Encoding commands in an array for easier warning message for when FinalBinary "powershell" value is set.
                                $prevEncodingCommandsBaseArray = ($script:cliSyntax | foreach-object { $_.Split('\')[0] }) | where-object { $_ -match '^Encoding$' }
                                if ($prevEncodingCommandsBaseArray)
                                {
                                    if (-not $warningMessage)
                                    {
                                        if ($prevEncodingCommandsBaseArray.Count -eq 1)
                                        {
                                            $warningMessage = ' (though Encoding obfuscation layer needs to be removed since PowerShell cannot interpret cmd.exe-style env var resolutions)'
                                        }
                                        else
                                        {
                                            $warningMessage = ' (though Encoding obfuscation layers need to be removed since PowerShell cannot interpret cmd.exe-style env var resolutions)'
                                        }
                                    }
                                    else
                                    {
                                        if ($prevEncodingCommandsBaseArray.Count -eq 1)
                                        {
                                            $warningMessage = $warningMessage.TrimEnd(')') + ' and Encoding obfuscation layer needs to be removed since PowerShell cannot interpret cmd.exe-style env var resolutions)'
                                        }
                                        else
                                        {
                                            $warningMessage = $warningMessage.TrimEnd(')') + ' and Encoding obfuscation layers need to be removed since PowerShell cannot interpret cmd.exe-style env var resolutions)'
                                        }
                                    }
                                }

                                Write-Host "`n`nSuccessfully set FinalBinary" -NoNewline -ForegroundColor Cyan
                                Write-Host $warningMessage -NoNewline -ForegroundColor Yellow
                                Write-Host ":" -ForegroundColor Cyan
                                Write-Host $script:FinalBinary -ForegroundColor Magenta
                            }
                            'none' {
                                $script:FinalBinary = ''
                                
                                Write-Host "`n`nSuccessfully removed FinalBinary value" -NoNewline -ForegroundColor Cyan
                                Write-Host $warningMessage -NoNewline -ForegroundColor Yellow
                                Write-Host ":" -ForegroundColor Cyan
                            }
                            default {                                
                                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                Write-Host ' Invalid option entered for' -NoNewline
                                Write-Host ' FINALBINARY' -NoNewline -ForegroundColor Cyan
                                Write-Host ". `n       Valid options include " -NoNewline
                                Write-Host 'CMD' -NoNewline -ForegroundColor Green
                                Write-Host ', ' -NoNewline
                                Write-Host 'POWERSHELL ' -NoNewline -ForegroundColor Green
                                Write-Host '& ' -NoNewline
                                Write-Host 'NONE' -NoNewline -ForegroundColor Green
                                Write-Host '.' -NoNewline
                            }
                        }
                    }
                    'emptyvalue' {
                        # No OPTIONVALUE was entered after OPTIONNAME.
                        $hasError = $true
                        Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                        Write-Host ' No value was entered after' -NoNewline
                        Write-Host ' COMMAND/COMMANDPATH' -NoNewline -ForegroundColor Cyan
                        Write-Host '.' -NoNewline
                    }
                    default
                    {
                        Write-Error "An invalid OPTIONNAME ($userInputOptionName) was passed to switch block."
                    
                        exit
                    }
                }
            }
            else
            {
                $hasError = $true
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' OPTIONNAME' -NoNewline
                Write-Host " $userInputOptionName" -NoNewline -ForegroundColor Cyan
                Write-Host " is not a settable option." -NoNewline
            }
    
            if ($hasError)
            {
                Write-Host "`n       Correct syntax is" -NoNewline
                Write-Host ' SET OPTIONNAME VALUE' -NoNewline -ForegroundColor Green
                Write-Host '.' -NoNewline
        
                Write-Host "`n       Enter" -NoNewline
                Write-Host ' SHOW OPTIONS' -NoNewline -ForegroundColor Yellow
                Write-Host ' for more details.'
            }
        }
        elseif (($acceptableInput -contains $userInput) -or ($overrideAcceptableInput))
        {
            # User input matches $acceptableInput extracted from the current $Menu, so decide if:
            # 1) an obfuscation function needs to be called and remain in current interactive prompt, or
            # 2) return value to enter into a new interactive prompt.

            # Format breadcrumb trail to successfully retrieve the next interactive prompt.
            $userInput = $breadCrumb.Trim('\').Replace('\','_') + '_' + $userInput
            if ($breadCrumb.StartsWith('\'))
            {
                $userInput = '_' + $userInput
            }

            # If the current selection contains a command to execute then continue. Otherwise return to go to another menu.
            if ($selectionContainsCommand)
            {
                # Make sure user has entered command or path to script (unless Binary option is selected since no input is required for these functions).
                if ($script:obfuscatedCommand -or $breadCrumb.StartsWith('\Binary\'))
                {
                    # Iterate through lines in $Menu to extract command for the current selection in $userInput.
                    foreach ($line in $Menu)
                    {
                        if ($line[1].Trim(' ') -eq $userInput.Substring($userInput.LastIndexOf('_') + 1))
                        {
                            $commandToExec = $line[3]
                        
                            continue
                        }
                    }

                    # Extract arguments from $commandToExec.
                    $function = $commandToExec[0]
                    $token    = $commandToExec[1]

                    # Validate that user has set COMMANDPATH or COMMAND (by seeing if $script:obfuscatedCommand is empty).
                    # The exception to this are the BINARY options since no input is required.
                    if (($script:obfuscatedCommand -eq '') -and -not $breadCrumb.ToLower().StartsWith('\binary\'))
                    {
                        Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                        Write-Host " Cannot execute obfuscation commands without setting CommandPath or Command value in SHOW OPTIONS menu. Set these by executing" -NoNewline
                        Write-Host ' SET COMMAND cmd_or_powershell_command' -NoNewline -ForegroundColor Green
                        Write-Host ' or' -NoNewline
                        Write-Host ' SET COMMANDPATH path_or_URL_to_command' -NoNewline -ForegroundColor Green
                        Write-Host '.'
                        
                        continue
                    }

                    $cmdToPrint = $null

                    # Store the "base" breadcrumb values for all previous commands in an array for easier warning message displays for various dangerous combinations of obfuscation options.
                    $prevCommandsBaseArray = @()
                    if ($script:cliSyntax)
                    {
                        $prevCommandsBaseArray += ($script:cliSyntax | foreach-object { $_.Split('\')[0] }) | where-object { $_ -match '^(Binary|Encoding|Payload)$' }
                    }

                    # Cover displaying error messages for all PAYLOAD obfuscation options once here instead of repeated code in below switch block.
                    if ($function.StartsWith('Out-Dos'))
                    {
                        # Display error messages for dangerous combinations of obfuscation options.
                        if ($prevCommandsBaseArray -and ($prevCommandsBaseArray -contains 'Payload'))
                        {
                            Write-Host "`nWARNING: " -NoNewline -ForegroundColor Red
                            Write-Host 'Do not stack PAYLOAD obfuscation.'
                            Write-Host '         Run ' -NoNewline
                            Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                            Write-Host 'to remove this obfuscation.'
                            Write-Host '         This will likely not run properly.'
                        }
                        elseif ($prevCommandsBaseArray -and ($prevCommandsBaseArray -contains 'Encoding'))
                        {
                            Write-Host "`nWARNING: " -NoNewline -ForegroundColor Red
                            Write-Host 'Do not add PAYLOAD obfuscation to ENCODING obfuscation.'
                            Write-Host '         Run ' -NoNewline
                            Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                            Write-Host 'to remove this obfuscation.'
                            Write-Host '         This will likely not run properly.'
                        }
                    }
                    
                    # Switch block to route to the correct function.
                    switch ($function)
                    {
                        'Get-ObfuscatedCmd' {
                            if ($script:obfuscatedCommand.Length -gt 0)
                            {
                                Write-Host "`nNOTE: " -NoNewline
                                Write-Host 'Overwriting ObfuscatedCommand with syntax that executes ' -NoNewline -ForegroundColor Cyan
                                Write-Host 'Cmd' -NoNewline -ForegroundColor Magenta
                                Write-Host "`n      since Binary obfuscation options are not cumulative.`n      Run " -NoNewline -ForegroundColor Cyan
                                Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                                Write-Host 'to revert back to the previous ObfuscatedCommand.' -ForegroundColor Cyan
                            }
                                
                            $script:obfuscatedCommand = Get-ObfuscatedCmd -ObfuscationLevel ([System.Int16] $token[0])
                            $cmdToPrint = @("Get-ObfuscatedCmd -ObfuscationLevel $token","")
                        }
                        'Get-ObfuscatedPowerShell' {
                            if ($script:obfuscatedCommand.Length -gt 0)
                            {
                                Write-Host "`nNOTE: " -NoNewline
                                Write-Host 'Overwriting ObfuscatedCommand with syntax that executes ' -NoNewline -ForegroundColor Cyan
                                Write-Host 'PowerShell' -NoNewline -ForegroundColor Magenta
                                Write-Host "`n      since Binary obfuscation options are not cumulative.`n      Run " -NoNewline -ForegroundColor Cyan
                                Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                                Write-Host 'to revert back to the previous ObfuscatedCommand.' -ForegroundColor Cyan
                            }
                                
                            $script:obfuscatedCommand = Get-ObfuscatedPowerShell -ObfuscationLevel ([System.Int16] $token[0])
                            $cmdToPrint = @("Get-ObfuscatedPowerShell -ObfuscationLevel $token","")
                        }
                        'Out-EnvVarEncodedCommand' {
                            # Display error messages for dangerous combinations of obfuscation options.
                            if ([System.Char[]] $script:obfuscatedCommand | where-object { @('|') -contains $_ })
                            {
                                Write-Host "`nWARNING: " -NoNewline -ForegroundColor Red
                                Write-Host 'Do not use ENCODING obfuscation when escapable characters are present.'
                                Write-Host '         Run ' -NoNewline
                                Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                                Write-Host 'to remove this ENCODING.'
                                Write-Host '         Only use ENCODING on basic commands & at your own risk.'
                            }
                            if ($prevCommandsBaseArray -and ($prevCommandsBaseArray[-1] -eq 'Encoding'))
                            {
                                Write-Host "`nWARNING: " -NoNewline -ForegroundColor Red
                                Write-Host 'Do not stack ENCODING obfuscation.'
                                Write-Host '         Run ' -NoNewline
                                Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                                Write-Host 'to remove this ENCODING.'
                                Write-Host '         Only use ENCODING on basic commands & at your own risk.'
                            }
                            if ($prevCommandsBaseArray -and ($prevCommandsBaseArray[-1] -eq 'Payload'))
                            {
                                Write-Host "`nWARNING: " -NoNewline -ForegroundColor Red
                                Write-Host 'Do not add ENCODING obfuscation to PAYLOAD obfuscation.'
                                Write-Host '         Run ' -NoNewline
                                Write-Host 'UNDO ' -NoNewline -ForegroundColor Yellow
                                Write-Host 'to remove this ENCODING.'
                                Write-Host '         Only use ENCODING on basic commands & at your own risk.'
                            }

                            $script:obfuscatedCommand = Out-EnvVarEncodedCommand -StringToEncode $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0]) -MaintainCase
                            $cmdToPrint = @("Out-EnvVarEncodedCommand -StringToEncode "," -ObfuscationLevel $token -MaintainCase")
                        }
                        'Out-DosConcatenatedCommand' {
                            if ($script:FinalBinary.Length -gt 0)
                            {
                                $script:obfuscatedCommand = Out-DosConcatenatedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0]) -FinalBinary:$script:FinalBinary
                                $cmdToPrint = @("Out-DosFINcodedCommand -Command "," -ObfuscationLevel $token -FinalBinary $script:FinalBinary")
                            }
                            else
                            {
                                $script:obfuscatedCommand = Out-DosConcatenatedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0])
                                $cmdToPrint = @("Out-DosConcatenatedCommand -Command "," -ObfuscationLevel $token")
                            }
                        }
                        'Out-DosReversedCommand' {
                            if ($script:FinalBinary.Length -gt 0)
                            {
                                $script:obfuscatedCommand = Out-DosReversedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0]) -FinalBinary:$script:FinalBinary
                                $cmdToPrint = @("Out-DosFINcodedCommand -Command "," -ObfuscationLevel $token -FinalBinary $script:FinalBinary")
                            }
                            else
                            {
                                $script:obfuscatedCommand = Out-DosReversedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0])
                                $cmdToPrint = @("Out-DosReversedCommand -Command "," -ObfuscationLevel $token")
                            }
                        }
                        'Out-DosFORcodedCommand' {
                            if ($script:FinalBinary.Length -gt 0)
                            {
                                $script:obfuscatedCommand = Out-DosFORcodedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0]) -FinalBinary:$script:FinalBinary
                                $cmdToPrint = @("Out-DosFINcodedCommand -Command "," -ObfuscationLevel $token -FinalBinary $script:FinalBinary")
                            }
                            else
                            {
                                $script:obfuscatedCommand = Out-DosFORcodedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0])
                                $cmdToPrint = @("Out-DosFORcodedCommand -Command "," -ObfuscationLevel $token")
                            }
                        }
                        'Out-DosFINcodedCommand' {
                            if ($script:FinalBinary.Length -gt 0)
                            {
                                $script:obfuscatedCommand = Out-DosFINcodedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0]) -FinalBinary:$script:FinalBinary
                                $cmdToPrint = @("Out-DosFINcodedCommand -Command "," -ObfuscationLevel $token -FinalBinary $script:FinalBinary")
                            }
                            else
                            {
                                $script:obfuscatedCommand = Out-DosFINcodedCommand -Command $script:obfuscatedCommand -ObfuscationLevel ([System.Int16] $token[0])
                                $cmdToPrint = @("Out-DosFINcodedCommand -Command "," -ObfuscationLevel $token")
                            }
                        }
                        default
                        {
                            Write-Error "An invalid `$function value ($function) was passed to switch block."
                                
                            exit
                        }
                    }

                    # Add to $script:obfuscatedCommandHistory if a change took place for the current ObfuscatedCommand.
                    $script:obfuscatedCommandHistory += , $script:obfuscatedCommand
    
                    # Convert UserInput to CLI syntax to store in cliSyntax variable if obfuscation occurred.
                    $cliSyntaxCurrentCommand = $userInput.Trim('_ ').Replace('_','\')
    
                    # Add CLI command syntax to $script:cliSyntax to maintain a history of commands to arrive at current obfuscated command for CLI syntax.
                    $script:cliSyntax += $cliSyntaxCurrentCommand

                    # Add execution syntax to $script:executionCommands to maintain a history of commands to arrive at current obfuscated command.
                    $script:executionCommands += ($cmdToPrint[0] + '$Command' + $cmdToPrint[1])

                    # Output syntax of CLI syntax and full command we executed in above Switch block.
                    Write-Host "`nExecuted:`t"
                    Write-Host "  CLI:  " -NoNewline
                    Write-Host $cliSyntaxCurrentCommand -ForegroundColor Cyan
                    Write-Host "  FULL: " -NoNewline
                    Write-Host $cmdToPrint[0] -NoNewline -ForegroundColor Cyan

                    if (-not ($cmdToPrint[0].Contains('Get-ObfuscatedCmd') -or $cmdToPrint[0].Contains('Get-ObfuscatedPowerShell')))
                    {
                        Write-Host '$Command' -NoNewline -ForegroundColor Magenta
                    }
                    Write-Host $cmdToPrint[1] -ForegroundColor Cyan

                    # Output obfuscation result.
                    Write-Host "`nResult:`t"
                    Out-DosCommandContent -ScriptContents $script:obfuscatedCommand -PrintWarning
                }
            }
            else
            {
                return $userInput
            }
        }
        else
        {
            if     ($menuInputOptionsShowHelp[0]     -contains $userInput) { Show-DosHelpMenu    }
            elseif ($menuInputOptionsShowOptions[0]  -contains $userInput) { Show-DosOptionsMenu }
            elseif ($tutorialInputOptions[0]         -contains $userInput) { Show-DosTutorial    }
            elseif ($clearScreenInputOptions[0]      -contains $userInput) { Clear-Host          }
            # For Version 1.0 ASCII art is not necessary.
            #elseif ($showAsciiArtInputOptions[0]     -contains $userInput) {Show-DosAsciiArt -Random}
            elseif ($resetObfuscationInputOptions[0] -contains $userInput)
            {
                if (($script:obfuscatedCommand) -and ($script:obfuscatedCommand.Length -eq 0))
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " ObfuscatedCommand has not been set. There is nothing to reset."
                }
                elseif ($script:obfuscatedCommand -ceq $script:Command)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCommand. There is nothing to reset."
                }
                else
                {
                    $script:obfuscatedCommand = $script:Command
                    $script:obfuscatedCommandHistory = @($script:Command)
                    $script:cliSyntax         = @()
                    $script:executionCommands = @()
                    
                    Write-Host "`n`nSuccessfully reset ObfuscatedCommand." -ForegroundColor Cyan
                }
            }
            elseif ($undoObfuscationInputOptions[0] -contains $userInput)
            {
                if (($script:obfuscatedCommand) -and ($script:obfuscatedCommand.Length -eq 0))
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " ObfuscatedCommand has not been set. There is nothing to undo."
                }
                elseif ($script:obfuscatedCommand -ceq $script:Command)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCommand. There is nothing to undo."
                }
                else
                {
                    # Set ObfuscatedCommand to the last state in ObfuscatedCommandHistory.
                    $script:obfuscatedCommand = $script:obfuscatedCommandHistory[$script:obfuscatedCommandHistory.Count-2]

                    # Remove the last state from ObfuscatedCommandHistory.
                    $temp = $script:obfuscatedCommandHistory
                    $script:obfuscatedCommandHistory = @()
                    for ($i=0; $i -lt $temp.Count-1; $i++)
                    {
                        $script:obfuscatedCommandHistory += $temp[$i]
                    }

                    # Remove last command from cliSyntax. Trim all trailing OUT or CLIP commands until an obfuscation command is removed.
                    $cliSyntaxCount = $script:cliSyntax.Count
                    while (($script:cliSyntax[$cliSyntaxCount-1] -match '^(clip|out )') -and ($cliSyntaxCount -gt 0))
                    {
                        $cliSyntaxCount--
                    }
                    $temp = $script:cliSyntax
                    $script:cliSyntax = @()
                    for ($i=0; $i -lt $cliSyntaxCount-1; $i++)
                    {
                        $script:cliSyntax += $temp[$i]
                    }

                    # Remove last command from ExecutionCommands.
                    $temp = $script:executionCommands
                    $script:executionCommands = @()
                    for ($i=0; $i -lt $temp.Count-1; $i++)
                    {
                        $script:executionCommands += $temp[$i]
                    }

                    Write-Host "`n`nSuccessfully removed last obfuscation from ObfuscatedCommand." -ForegroundColor Cyan
                }
            }
            elseif (($outputToDiskInputOptions[0] -contains $userInput) -or ($outputToDiskInputOptions[0] -contains $userInput.Trim().Split(' ')[0]))
            {
                if (($script:obfuscatedCommand -ne '') -and ($script:obfuscatedCommand -ceq $script:Command))
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
                elseif ($script:obfuscatedCommand -ne '')
                {
                    # Get file path information from compound user input (e.g. OUT C:\FILENAME.TXT).
                    if ($userInput.Trim().Split(' ').Count -gt 1)
                    {
                        # Get file path information from user input.
                        $userInputOutputFilePath = $userInput.Trim().Substring(4).Trim()
                        Write-Host ''
                    }
                    else
                    {
                        # Get file path information from user interactively.
                        $userInputOutputFilePath = Read-Host "`n`nEnter path for output file (or leave blank for default)"
                    }                    
                    # Decipher if user input a full file path, just a file name or nothing (default).
                    if ($userInputOutputFilePath.Trim() -eq '')
                    {
                        # User did not input anything so use default filename and current directory of this script.
                        $OutputFilePath = "$scriptDir\Obfuscated_Command.txt"
                    }
                    elseif (-not $userInputOutputFilePath.Contains('\') -and -not $userInputOutputFilePath.Contains('/'))
                    {
                        # User input is not a file path so treat it as a filename and use current directory of this script.
                        $OutputFilePath = "$scriptDir\$($userInputOutputFilePath.Trim())"
                    }
                    else
                    {
                        # User input is a full file path.
                        $OutputFilePath = $userInputOutputFilePath
                    }
                    
                    # Write ObfuscatedCommand out to disk.
                    Write-Output $script:obfuscatedCommand > $OutputFilePath

                    if (Test-Path $OutputFilePath)
                    {
                        $script:cliSyntax += "out $OutputFilePath"
                        Write-Host "`nSuccessfully output ObfuscatedCommand to" -NoNewline -ForegroundColor Cyan
                        Write-Host " $OutputFilePath" -NoNewline -ForegroundColor Yellow
                        Write-Host "." -ForegroundColor Cyan
                        
                        if ($env:windir)
                        {
                            C:\Windows\Notepad.exe $OutputFilePath
                        }
                    }
                    else
                    {
                        Write-Host "`nERROR: Unable to write ObfuscatedCommand out to" -NoNewline -ForegroundColor Red
                        Write-Host " $OutputFilePath" -NoNewline -ForegroundColor Yellow
                    }
                }
                elseif ($script:obfuscatedCommand -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " There isn't anything to write out to disk.`n       Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
            }
            elseif ($copyToClipboardInputOptions[0] -contains $userInput)
            {
                if (($script:obfuscatedCommand -ne '') -and ($script:obfuscatedCommand -ceq $script:Command))
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
                elseif ($script:obfuscatedCommand -ne '')
                {
                    # Copy ObfuscatedCommand to clipboard.
                    # Try/catch block introduced since PowerShell v2.0 without -STA defined will not be able to perform clipboard functionality.
                    try
                    {
                        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                        [System.Windows.Forms.Clipboard]::SetText($script:obfuscatedCommand)

                        Write-Host "`n`nSuccessfully copied ObfuscatedCommand to clipboard." -ForegroundColor Cyan
                    }
                    catch
                    {
                        $errorMessage = "Clipboard functionality will not work in PowerShell version $($PsVersionTable.PsVersion.Major) unless you add -STA (Single-Threaded Apartment) execution flag to powershell.exe."

                        if ((Get-Command Write-Host).CommandType -ne 'Cmdlet')
                        {
                            # Retrieving Write-Host and Start-Sleep Cmdlets to get around the current proxy functions of Write-Host and Start-Sleep that are overloaded if -Quiet flag was used.
                            . ((Get-Command Write-Host)  | where-object {$_.CommandType -eq 'Cmdlet'}) "`n`nWARNING: " -NoNewline -ForegroundColor Red
                            . ((Get-Command Write-Host)  | where-object {$_.CommandType -eq 'Cmdlet'}) $errorMessage -NoNewline

                            . ((Get-Command Start-Sleep) | where-object {$_.CommandType -eq 'Cmdlet'}) 2
                        }
                        else
                        {
                            Write-Host "`n`nWARNING: " -NoNewline -ForegroundColor Red
                            Write-Host $errorMessage

                            if ($script:cliSyntax -gt 0)
                            {
                                Start-Sleep 2
                            }
                        }
                    }
                    
                    $script:cliSyntax += 'clip'
                }
                elseif ($script:obfuscatedCommand -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " There isn't anything to copy to your clipboard.`n       Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand." -NoNewline
                }
                
            }
            elseif ($executionInputOptions[0] -contains $userInput)
            {
                if ($script:obfuscatedCommand -ne '')
                {
                    if (-not $env:windir)
                    {
                        Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                        Write-Host " Cannot execute since cmd.exe is not present since OS is not Windows."
                    }
                    elseif ($script:obfuscatedCommand -ceq $script:Command)
                    {
                        Write-Host "`n`nInvoking via cmd.exe (though you haven't obfuscated anything yet):" -ForegroundColor Cyan
                    }
                    else
                    {
                        Write-Host "`n`nInvoking via cmd.exe:" -ForegroundColor Cyan
                    }
                    
                    Out-DosCommandContent -ScriptContents $script:obfuscatedCommand
                    Write-Host ''
                    
                    if ($env:windir)
                    {
                        $testOutput = Write-Output $script:obfuscatedCommand | C:\Windows\System32\cmd.exe
                        Write-Host ($testOutput -join "`n")
                    }
                }
                else {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot execute because you have not set CommandPath or Command.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " to set CommandPath or Command."
                }
            }
            else
            {
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host " You entered an invalid option. Enter" -NoNewline
                Write-Host " HELP" -NoNewline -ForegroundColor Yellow
                Write-Host " for more information."

                # If the failed input was part of $script:compoundCommand then cancel out the rest of the compound command so it is not further processed.
                if ($script:compoundCommand.Count -gt 0)
                {
                    $script:compoundCommand = @()
                }

                # Output all available/acceptable options for current menu if invalid input was entered.
                if ($acceptableInput.Count -gt 1)
                {
                    $message = 'Valid options for current menu include:'
                }
                else
                {
                    $message = 'Valid option for current menu includes:'
                }
                Write-Host "       $message " -NoNewline

                $counter=0
                foreach ($acceptableOption in $acceptableInput)
                {
                    $counter++

                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    if ($selectionContainsCommand)
                    {
                        $colorToOutput = 'Green'
                    }
                    else
                    {
                        $colorToOutput = 'Yellow'
                    }

                    Write-Host $acceptableOption -NoNewline -ForegroundColor $colorToOutput
                    if (($counter -lt $acceptableInput.Length) -and ($acceptableOption.Length -gt 0))
                    {
                        Write-Host ', ' -NoNewline
                    }
                }
                Write-Host ''
            }
        }
    }
    
    return $userInput.ToLower()
}


function Show-DosOptionsMenu
{
<#
.SYNOPSIS

HELPER function :: Displays options menu for Invoke-DOSfuscation.

Invoke-DOSfuscation Function: Show-DosOptionsMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-DosOptionsMenu displays options menu for Invoke-DOSfuscation.

.EXAMPLE

C:\PS> Show-DosOptionsMenu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Set potentially-updated script-level values in $script:optionsMenu before displaying.
    $counter = 0
    foreach ($line in $script:optionsMenu)
    {
        if ($line[0].ToLower().Trim() -eq 'command')           { $script:optionsMenu[$counter][1] = $script:command           }
        if ($line[0].ToLower().Trim() -eq 'commandpath')       { $script:optionsMenu[$counter][1] = $script:commandPath       }
        if ($line[0].ToLower().Trim() -eq 'finalbinary')       { $script:optionsMenu[$counter][1] = $script:finalBinary       }
        if ($line[0].ToLower().Trim() -eq 'commandlinesyntax') { $script:optionsMenu[$counter][1] = $script:cliSyntax         }
        if ($line[0].ToLower().Trim() -eq 'executioncommands') { $script:optionsMenu[$counter][1] = $script:executionCommands }
        if ($line[0].ToLower().Trim() -eq 'obfuscatedcommand')
        {
            # Only add obfuscatedcommand if it is different than scriptblock (to avoid showing obfuscatedcommand before it has been obfuscated).
            if ($script:obfuscatedCommand -cne $script:command)
            {
                $script:optionsMenu[$counter][1] = $script:obfuscatedcommand
            }
            else
            {
                $script:optionsMenu[$counter][1] = ''
            }
        }
        if ($line[0].ToLower().Trim() -eq 'obfuscationlength')
        {
            # Only set/display ObfuscationLength if there is an obfuscated command.
            if (($script:obfuscatedCommand.Length -gt 0) -and ($script:obfuscatedCommand -cne $script:command))
            {
                $script:optionsMenu[$counter][1] = $script:obfuscatedCommand.Length
            }
            else
            {
                $script:optionsMenu[$counter][1] = ''
            }
        }

        $counter++
    }
    
    # Output menu.
    Write-Host "`n`nSHOW OPTIONS" -NoNewline -ForegroundColor Cyan
    Write-Host " ::" -NoNewline
    Write-Host " Yellow" -NoNewline -ForegroundColor Yellow
    Write-Host " options can be set by entering" -NoNewline
    Write-Host " SET OPTIONNAME VALUE" -NoNewline -ForegroundColor Green
    Write-Host ".`n"

    foreach ($option in $script:optionsMenu)
    {
        $optionTitle = $option[0]
        $optionValue = $option[1]
        $canSetValue = $option[2]
      
        Write-Host $lineSpacing -NoNewline
        
        # For options that can be set by user, output as Yellow.
        if ($canSetValue)
        {
            Write-Host $optionTitle -NoNewline -ForegroundColor Yellow
        }
        else
        {
            Write-Host $optionTitle -NoNewline
        }
        Write-Host ": " -NoNewline
        
        # Handle coloring and multi-value output for ExecutionCommands and ObfuscationLength.
        if ($optionTitle -eq 'ObfuscationLength')
        {
            Write-Host $optionValue -ForegroundColor Cyan
        }
        elseif ($optionTitle -eq 'Command')
        {
            Out-DosCommandContent -ScriptContents $optionValue
        }
        elseif ($optionTitle -eq 'CommandLineSyntax')
        {
            # Assemble and display CliSyntax output.

            # Command/CommandPath syntax.
            $setSyntax = ''
            if (($script:CommandPath.Length -gt 0) -and ($script:CommandPath -ne 'N/A'))
            {
                $setSyntax = " -CommandPath '$script:CommandPath'"
            }
            elseif (($script:Command.Length -gt 0) -and ($script:CommandPath -eq 'N/A'))
            {
                $setSyntax = " -Command '" + $script:Command.Replace("'","''") + "'"
            }

            # Only display the latest Binary\Cmd or Binary\PS value if either is present since these are not cumulative and overwrite all prior values.
            if ($optionValue.Count -gt 1)
            {
                $optionValueTemp = @()
                $keepProcessing = $true
                $optionValueTemp = $optionValue[($optionValue.Length - 1)..0] | foreach-object {
                    if ($keepProcessing)
                    {
                        $_

                        if (@('Binary\PS\','Binary\Cmd\') -contains $_.TrimEnd('0123456789'))
                        {
                            $keepProcessing = $false
                        }
                    }
                }
                if ($optionValueTemp.Count -gt 1)
                {
                    $optionValue = $optionValueTemp[($optionValueTemp.Count - 1)..0]
                }
                else
                {
                    $optionValue = $optionValueTemp
                }
            }

            # FinalBinary syntax.
            $finalBinarySyntax = ''
            if ($script:FinalBinary.Length -gt 0)
            {
                $finalBinarySyntax = " -FinalBinary $script:FinalBinary"
            }

            # CliCommand syntax.
            $commandSyntax = ''
            if ($optionValue.Count -gt 0)
            {
                $commandSyntax = " -CliCommand '" + ($optionValue -Join ',') + "' -Quiet"
            }

            # Output final CliSyntax value.
            if (($setSyntax -ne '') -or ($commandSyntax -ne ''))
            {
                $cliSyntaxToOutput = "Invoke-DOSfuscation" + $setSyntax + $finalBinarySyntax + $commandSyntax
                Write-Host $cliSyntaxToOutput -ForegroundColor Cyan
            }
            else
            {
                Write-Host ''
            }
        }
        elseif ($optionTitle -eq 'ExecutionCommands')
        {
            # Only display the latest Get-ObfuscatedPowerShell or Get-ObfuscatedCmd value if either is present since these are not cumulative and overwrite all prior values.
            if ($optionValue.Count -gt 1)
            {
                $optionValueTemp = @()
                $keepProcessing = $true
                $optionValueTemp = $optionValue[($optionValue.Length - 1)..0] | foreach-object {
                    if ($keepProcessing)
                    {
                        $_

                        if (@('Get-ObfuscatedPowerShell','Get-ObfuscatedCmd') -contains $_.Split(' ')[0])
                        {
                            $keepProcessing = $false
                        }
                    }
                }
                if ($optionValueTemp.Count -gt 1)
                {
                    $optionValue = $optionValueTemp[($optionValueTemp.Count - 1)..0]
                }
                else
                {
                    $optionValue = $optionValueTemp
                }
            }

            # ExecutionCommands output.
            if ($optionValue.Count -gt 0)
            {
                Write-Host ''
            }
            $counter = 0
            foreach ($executionCommand in $optionValue)
            {
                $counter++
                if ($executionCommand.Length -eq 0)
                {
                    Write-Host ''
                
                    continue
                }
                
                $executionCommand = $executionCommand.Replace('$Command','~').Split('~')
                Write-Host "    $($executionCommand[0])" -NoNewline -ForegroundColor Cyan

                # Do not display '$Command' if one of the BINARY command options since these functions do not take '$Command' input as they are not cumulative.
                if (-not $executionCommand[0].Contains('Get-ObfuscatedCmd') -and -not $executionCommand[0].Contains('Get-ObfuscatedPowerShell'))
                {
                    Write-Host '$Command' -NoNewline -ForegroundColor Magenta
                }
                
                # Handle output formatting when SHOW OPTIONS is run.
                if (($optionValue.Count -gt 0) -and ($counter -lt $optionValue.Count))
                {
                    Write-Host $executionCommand[1] -ForegroundColor Cyan
                }
                else
                {
                    Write-Host $executionCommand[1] -NoNewline -ForegroundColor Cyan
                }

            }
            Write-Host ''
        }
        elseif ($optionTitle -eq 'ObfuscatedCommand')
        {
            Out-DosCommandContent -ScriptContents $optionValue
        }
        else
        {
            Write-Host $optionValue -ForegroundColor Magenta
        }
    }
}


function Show-DosHelpMenu
{
<#
.SYNOPSIS

HELPER function :: Displays help menu for Invoke-DOSfuscation.

Invoke-DOSfuscation Function: Show-DosHelpMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-DosHelpMenu displays help menu for Invoke-DOSfuscation.

.EXAMPLE

C:\PS> Show-DosHelpMenu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Show Help Menu.
    Write-Host "`n`nHELP MENU" -NoNewline -ForegroundColor Cyan
    Write-Host " :: Available" -NoNewline
    Write-Host " options" -NoNewline -ForegroundColor Yellow
    Write-Host " shown below:`n"
    foreach ($inputOptionsList in $allAvailableInputOptionsLists)
    {
        $inputOptionsCommands    = $inputOptionsList[0]
        $inputOptionsDescription = $inputOptionsList[1]

        # Add additional coloring to string encapsulated by <> if it exists in $inputOptionsDescription.
        if ($inputOptionsDescription.Contains('<') -and $inputOptionsDescription.Contains('>'))
        {
            $firstPart  = $inputOptionsDescription.Substring(0,$inputOptionsDescription.IndexOf('<'))
            $middlePart = $inputOptionsDescription.Substring($firstPart.Length+1)
            $middlePart = $middlePart.Substring(0,$middlePart.IndexOf('>'))
            $lastPart   = $inputOptionsDescription.Substring($firstPart.Length+$middlePart.Length+2)
            Write-Host "$lineSpacing $firstPart" -NoNewline
            Write-Host $middlePart -NoNewline -ForegroundColor Cyan
            Write-Host $lastPart -NoNewline
        }
        else
        {
            Write-Host "$lineSpacing $inputOptionsDescription" -NoNewline
        }
        
        $counter = 0
        foreach ($inputOptionCommand in $inputOptionsCommands)
        {
            $counter++
            Write-Host $inputOptionCommand.ToUpper() -NoNewline -ForegroundColor Yellow
            if ($counter -lt $inputOptionsCommands.Count)
            {
                Write-Host ',' -NoNewline
            }
        }
        Write-Host ''
    }
}


function Show-DosTutorial
{
<#
.SYNOPSIS

HELPER function :: Displays tutorial information for Invoke-DOSfuscation.

Invoke-DOSfuscation Function: Show-DosTutorial
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-DosTutorial displays tutorial information for Invoke-DOSfuscation.

.EXAMPLE

C:\PS> Show-DosTutorial

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Write-Host "`n`nTUTORIAL" -NoNewline -ForegroundColor Cyan
    Write-Host " :: Here is a quick tutorial showing you how to get your " -NoNewline
    Write-Host "D" -NoNewline -ForegroundColor Red
    Write-Host "O" -NoNewline -ForegroundColor Magenta
    Write-Host "S" -NoNewline -ForegroundColor Yellow
    Write-Host "fuscation on:"
    
    Write-Host "`n1) " -NoNewline -ForegroundColor Cyan
    Write-Host "Load a Cmd/PowerShell command (SET COMMAND) or a path/URL to a command."
    Write-Host "   SET COMMAND dir C:\Windows\System32\ | findstr calc\.exe" -ForegroundColor Green
    Write-Host "   Or"
    Write-Host "   SET COMMANDPATH https://bit.ly/L3g1t" -ForegroundColor Green

    Write-Host "`n2) " -NoNewline -ForegroundColor Cyan
    Write-Host "(Optional) Set FinalBinary (SET FINALBINARY) to be Cmd, PowerShell or None."
    Write-Host "   NOTE: If setting a PowerShell command, FinalBinary must be set to PowerShell."
    Write-Host "   SET FINALBINARY PowerShell" -ForegroundColor Green

    Write-Host "`n3) " -NoNewline -ForegroundColor Cyan
    Write-Host "Navigate through the obfuscation menus where the options are in" -NoNewline
    Write-Host " YELLOW" -NoNewline -ForegroundColor Yellow
    Write-Host "."
    Write-Host "   GREEN" -NoNewline -ForegroundColor Green
    Write-Host " options apply obfuscation."
    Write-Host "   Enter" -NoNewline
    Write-Host " BACK" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "CD .." -NoNewline -ForegroundColor Yellow
    Write-Host " to go to previous menu and" -NoNewline
    Write-Host " HOME" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "MAIN" -NoNewline -ForegroundColor Yellow
    Write-Host " to go to home menu.`n   E.g. Enter" -NoNewline
    Write-Host " PAYLOAD" -NoNewline -ForegroundColor Yellow
    Write-Host "," -NoNewline
    Write-Host "CONCAT" -NoNewline -ForegroundColor Yellow
    Write-Host " & then" -NoNewline
    Write-Host " 1" -NoNewline -ForegroundColor Green
    Write-Host " to apply basic concatenation obfuscation."
    
    Write-Host "`n4) " -NoNewline -ForegroundColor Cyan
    Write-Host "Enter" -NoNewline
    Write-Host " TEST" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "EXEC" -NoNewline -ForegroundColor Yellow
    Write-Host " to test the obfuscated command locally.`n   Enter" -NoNewline
    Write-Host " SHOW" -NoNewline -ForegroundColor Yellow
    Write-Host " to see the currently obfuscated command."
    
    Write-Host "`n5) " -NoNewline -ForegroundColor Cyan
    Write-Host "Enter" -NoNewline
    Write-Host " COPY" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "CLIP" -NoNewline -ForegroundColor Yellow
    Write-Host " to copy obfuscated command out to your clipboard."
    Write-Host "   Enter" -NoNewline
    Write-Host " OUT" -NoNewline -ForegroundColor Yellow
    Write-Host " to write obfuscated command out to disk."
    
    Write-Host "`n6) " -NoNewline -ForegroundColor Cyan
    Write-Host "Enter" -NoNewline
    Write-Host " RESET" -NoNewline -ForegroundColor Yellow
    Write-Host " to remove all obfuscation and start over.`n   Enter" -NoNewline
    Write-Host " UNDO" -NoNewline -ForegroundColor Yellow
    Write-Host " to undo last obfuscation.`n   Enter" -NoNewline
    Write-Host " HELP" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "?" -NoNewline -ForegroundColor Yellow
    Write-Host " for help menu."
    
    Write-Host "`nAnd finally the obligatory `"Don't use this for evil, please`"" -NoNewline -ForegroundColor Cyan
    Write-Host " :)" -ForegroundColor Green
}


function Out-DosCommandContent
{
<#
.SYNOPSIS

HELPER function :: Displays current obfuscated command for Invoke-DOSfuscation.

Invoke-DOSfuscation Function: Out-DosCommandContent
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-DosCommandContent displays current obfuscated command for Invoke-DOSfuscation.

.PARAMETER ScriptContents

Specifies the string containing your payload.

.PARAMETER PrintWarning

Switch to output redacted form of ScriptContents if it exceeds 8,190 characters.

.EXAMPLE

C:\PS> Out-DosCommandContent

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
    
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
        [System.String]
        $ScriptContents,

        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $PrintWarning
    )
    
    # Maximum size for cmd.exe and clipboard.
    $cmdMaxLength = 8190
    
    if ($ScriptContents.Length -gt $cmdMaxLength)
    {
        # Output ScriptContents, handling if the size of ScriptContents exceeds $cmdMaxLength characters.
        $redactedPrintLength = $cmdMaxLength / 5
        
        # Handle printing redaction message in middle of screen. #OCD
        $cmdLineWidth = (Get-Host).UI.RawUI.BufferSize.Width
        $redactionMessage = "<REDACTED: ObfuscatedLength = $($ScriptContents.Length)>"
        $centeredRedactionMessageStartIndex = (($cmdLineWidth-$redactionMessage.Length) / 2) - "[*] ObfuscatedCommand: ".Length
        $currentRedactionMessageStartIndex = ($redactedPrintLength % $cmdLineWidth)
        
        if ($currentRedactionMessageStartIndex -gt $centeredRedactionMessageStartIndex)
        {
            $redactedPrintLength = $redactedPrintLength - ($currentRedactionMessageStartIndex - $centeredRedactionMessageStartIndex)
        }
        else
        {
            $redactedPrintLength = $redactedPrintLength + ($centeredRedactionMessageStartIndex - $currentRedactionMessageStartIndex)
        }
    
        Write-Host $ScriptContents.Substring(0,$redactedPrintLength) -NoNewline -ForegroundColor Magenta
        Write-Host $redactionMessage -NoNewline -ForegroundColor Yellow
        Write-Host $ScriptContents.Substring($ScriptContents.Length-$redactedPrintLength) -ForegroundColor Magenta
    }
    else
    {
        Write-Host $ScriptContents -ForegroundColor Magenta
    }

    # Make sure final command doesn't exceed cmd.exe's character limit.
    if ($ScriptContents.Length -gt $cmdMaxLength)
    {
        if ($PrintWarning.IsPresent)
        {
            Write-Host "`nWARNING: This command exceeds the cmd.exe maximum length of $cmdMaxLength." -ForegroundColor Red
            Write-Host "         Its length is" -NoNewline -ForegroundColor Red
            Write-Host " $($ScriptContents.Length)" -NoNewline -ForegroundColor Yellow
            Write-Host " characters." -ForegroundColor Red
        }
    }
}          


function Show-DosAsciiArt
{
<#
.SYNOPSIS

HELPER function :: Displays random ASCII art for Invoke-DOSfuscation.

Invoke-DOSfuscation Function: Show-DosAsciiArt
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-DosAsciiArt displays random ASCII art for Invoke-DOSfuscation, and also displays ASCII art during script startup.

.EXAMPLE

C:\PS> Show-DosAsciiArt

.NOTES

Credit for ASCII art font generation: http://patorjk.com/software/taag/
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $Random,

        [Parameter(Position = 0, Mandatory = $false)]
        [Switch]
        $Quiet
    )
    
    # Create multiple ASCII art title banners.
    $spacing = "`t"
    $invokeDOSfuscationAscii  = @()
    $invokeDOSfuscationAscii += $spacing + " ___                 _                                       "
    $invokeDOSfuscationAscii += $spacing + "|_ _|_ ____   _____ | | _____                                "
    $invokeDOSfuscationAscii += $spacing + " | || '_ \ \ / / _ \| |/ / _ \____                           "
    $invokeDOSfuscationAscii += $spacing + " | || | | \ V / (_) |   <  __/____|                          "
    $invokeDOSfuscationAscii += $spacing + "|___|_| |_|\_/_\___/|_|\_\___|             _   _             "
    $invokeDOSfuscationAscii += $spacing + "|  _ \ / _ \/ ___| / _|_   _ ___  ___ __ _| |_(_) ___  _ __  "
    $invokeDOSfuscationAscii += $spacing + "| | | | | | \___ \| |_| | | / __|/ __/ _`` | __| |/ _ \| '_ \ "
    $invokeDOSfuscationAscii += $spacing + "| |_| | |_| |___) |  _| |_| \__ \ (_| (_| | |_| | (_) | | | |"
    $invokeDOSfuscationAscii += $spacing + "|____/ \___/|____/|_|  \__,_|___/\___\__,_|\__|_|\___/|_| |_|"
    
    # Ascii art to run only during script startup.
    if (-not $Random.IsPresent)
    {
        # Only display animated portion of ASCII art if -Quiet switch is not selected.
        if (-not $Quiet.IsPresent)
        {
            Clear-Host
        
            $prompt = 'C:\>'
            $sleepInMilliseconds = 200
        
            Write-Host "Starting MS-DOS...`n`n$prompt " -NoNewline -ForegroundColor White
            Start-Sleep -Milliseconds ($sleepInMilliseconds * 2)
        
            # Write out below Invoke-DOSfuscation in interactive format.
            foreach ($char in [System.Char[]] 'cmd.exe /c "echo Invoke-DOSfuscation"')
            {
                Start-Sleep -Milliseconds (Get-Random -Input @(40..80))

                if     ($char -ceq 'D') { $color = 'Red'     }
                elseif ($char -ceq 'O') { $color = 'Magenta' }
                elseif ($char -ceq 'S') { $color = 'Yellow'  }
                else                    { $color = 'White'   }

                Write-Host $char -NoNewline -ForegroundColor $color
            }
            Start-Sleep -Milliseconds ($sleepInMilliseconds * 3)
            Write-Host ''
        
            Write-Host "$prompt cmd.exe /c `" echo Invoke-DOSfuscation`"" -ForegroundColor White
            Start-Sleep -Milliseconds ($sleepInMilliseconds * 2)
            Write-Host "$prompt cmd.exe /c `"  echo Invoke-DOSfuscation`"" -ForegroundColor White
            Start-Sleep -Milliseconds ($sleepInMilliseconds * 2)
            Write-Host "$prompt cmd.exe /c `"   echo Invoke-DOSfuscation`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
            Write-Host "$prompt cmd.exe /c `"    echo Invoke-DOSfuscation`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
            Write-Host "$prompt cmd.exe /c `"     echo Invoke-DOSfuscation`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
            Write-Host "$prompt cmd.exe /c `"      echo Invoke-DOSfuscation`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
        
            Write-Host "$prompt cmd.exe /c `"" -NoNewline -ForegroundColor White
            Write-Host "set D=" -NoNewline -ForegroundColor Green
            Write-Host "echo Invoke-DOSfuscation" -NoNewline -ForegroundColor White
            Write-Host "&&call %D%" -NoNewline -ForegroundColor Green
            Write-Host '"' -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds

            Write-Host "$prompt cmd.exe /c `"" -NoNewline -ForegroundColor White
            Write-Host "set D=" -NoNewline -ForegroundColor Green
            Write-Host "echo Inv" -NoNewline -ForegroundColor White
            Write-Host "&set B=" -NoNewline -ForegroundColor Green
            Write-Host "oke-DOSfuscation" -NoNewline -ForegroundColor White
            Write-Host "&&call %D%%B%" -NoNewline -ForegroundColor Green
            Write-Host '"' -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds

            Write-Host "$prompt cmd.exe /c `"" -NoNewline -ForegroundColor White
            Write-Host "set D=" -NoNewline -ForegroundColor Green
            Write-Host "echo Inv" -NoNewline -ForegroundColor White
            Write-Host "&set B=" -NoNewline -ForegroundColor Green
            Write-Host "oke-DOS" -NoNewline -ForegroundColor White
            Write-Host "&&set O=" -NoNewline -ForegroundColor Green
            Write-Host "fuscation" -NoNewline -ForegroundColor White
            Write-Host "&&call %D%%B%%O%" -NoNewline -ForegroundColor Green
            Write-Host '"' -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds

            Write-Host "$prompt cmd.exe /c `"" -NoNewline -ForegroundColor White
            Write-Host "set O=" -NoNewline -ForegroundColor Green
            Write-Host "fuscation" -NoNewline -ForegroundColor White
            Write-Host "&set B=" -NoNewline -ForegroundColor Green
            Write-Host "oke-DOS" -NoNewline -ForegroundColor White
            Write-Host "&&set D=" -NoNewline -ForegroundColor Green
            Write-Host "echo Inv" -NoNewline -ForegroundColor White
            Write-Host "&&call %D%%B%%O%" -NoNewline -ForegroundColor Green
            Write-Host '"' -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
        
            # Add newline for each remaining $prompt for better readability (ha, in an obfuscation framework's ASCII art demo, amirite?).
            $prompt = "`n$prompt"
        
            Write-Host "$prompt cm" -NoNewline -ForegroundColor White
            Write-Host "%windir:~-4,-3%" -NoNewline -ForegroundColor Green
            Write-Host ".eXe/C`"SEt o=fuscation&seT B=oke-DOS&&sEt d=echo Inv&&CAll %D%%B%%o%`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
        
            Write-Host "$prompt cm%windir:~   -4,   -3%.eXe/C`"SEt   o=fuscation&seT   B=oke-DOS&&sEt   d=echo Inv&&CAll %D%%B%%o%`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
        
            Write-Host "$prompt cm%windir:~   -4,   -3%.eXe" -NoNewline -ForegroundColor White
            Write-Host ",;," -NoNewline -ForegroundColor Green
            Write-Host "/C`"" -NoNewline -ForegroundColor White
            Write-Host ",;," -NoNewline -ForegroundColor Green
            Write-Host "SEt   o=fuscation&" -NoNewline -ForegroundColor White
            Write-Host ",;," -NoNewline -ForegroundColor Green
            Write-Host "seT   B=oke-DOS&&" -NoNewline -ForegroundColor White
            Write-Host ",;," -NoNewline -ForegroundColor Green
            Write-Host "sEt   d=echo Inv&&" -NoNewline -ForegroundColor White
            Write-Host ",;," -NoNewline -ForegroundColor Green
            Write-Host "CAll" -NoNewline -ForegroundColor White
            Write-Host ",;," -NoNewline -ForegroundColor Green
            Write-Host "%D%%B%%o%`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds

            $substringsToPrint = "$prompt cm%windir:~   -4,   -3%.e^Xe,;^,/^C`",;,S^Et  ^ ^o^=fus^cat^ion&,;,^se^T ^ ^ ^B^=o^ke-D^OS&&,;,s^Et^ ^  d^=ec^ho I^nv&&,;,C^Al^l,;,^%^D%^%B%^%o".Split('^')
            foreach ($substring in $substringsToPrint)
            {
                Write-Host $substring -NoNewline -ForegroundColor White
                Write-Host '^' -NoNewline -ForegroundColor Green
            }
            Write-Host "%`"" -ForegroundColor White
            Start-Sleep -Milliseconds $sleepInMilliseconds
        
            Write-Host "$prompt " -NoNewline -ForegroundColor White
            Write-Host "FOR /F `"delims=il tokens=+4`" %Z IN ('assoc .cdxml') DO  %Z" -NoNewline -ForegroundColor Green
            Write-Host ",;^,/^C`",;,S^Et  ^ ^o^=fus^cat^ion&,;,^se^T ^ ^ ^B^=o^ke-D^OS&&,;,s^Et^ ^  d^=ec^ho I^nv&&,;,C^Al^l,;,^%^D%^%B%^%o%`"" -ForegroundColor White
            Start-Sleep -Milliseconds ($sleepInMilliseconds * 1.5)
        
            Write-Host "$prompt " -NoNewline
            Write-Host "^F^oR   ,   ,   ,    ,  ,  ;  ;   /^f   ;    ;  ;  ;   ;  ,  `"    delims=il       tokens=    +4   `"  ;   ;  ;  ,    ,    ,  ,   %Z  ;  ,  ,  ,    ,  ^In   ,  ,  ;   ;  ,   ,  ,  (    ,   ;    ;   ;  '   ,  ,   ,   ,    ,  ;  ^^a^^S^^s^^oC   ;  ,   ,  ,   ,   ;  .c^^d^^xm^^l   '    ;  ,   ,  ,   ,    )  ,  ,    ,  ,   ;  ,   ^d^o  ,   ,  ,   ,   ,  ,  ,  %Z  ,  ;  ^  ,/^C`"  ,  ;   ,   S^Et   ^   ^o^=fus^cat^ion&   ,  ;   ,  ^se^T   ^    ^   ^B^=o^ke-D^OS&&   ,    ; ,    s^Et^    ^   d^=ec^ho I^nv&&   ,    ;    ,   C^Al^l   ,   ;   ,   ^   %^D%^%B%^%o%`"" -ForegroundColor Green
            Start-Sleep -Milliseconds ($sleepInMilliseconds * 1.5)
        }

        # Print final ASCII art banner with DOS being multi-colored according to MS-DOS logo.
        Start-Sleep -Milliseconds 1000
        Write-Host "`n`n`n"
        foreach ($line in $invokeDOSfuscationAscii[0..3])
        {
            Write-Host $line -ForegroundColor Green
        }

        $lineSplit = $invokeDOSfuscationAscii[4].Split('|')
        Write-Host ($lineSplit[0] + '|') -NoNewline -ForegroundColor Green
        Write-Host $lineSplit[1] -NoNewline -ForegroundColor Red
        Write-Host ('|' + ($lineSplit[2..3] -join '|') + '|') -NoNewline -ForegroundColor Green
        Write-Host $lineSplit[4] -NoNewline -ForegroundColor Magenta
        Write-Host ('|' + ($lineSplit[5..($lineSplit.Count - 1)] -join '|').Substring(0,3)) -NoNewline -ForegroundColor Green
        Write-Host ($lineSplit[5..($lineSplit.Count - 1)] -join '|').Substring(3,1) -NoNewline -ForegroundColor Yellow
        Write-Host ($lineSplit[5..($lineSplit.Count - 1)] -join '|').Substring(4,1) -NoNewline -ForegroundColor Green
        Write-Host ($lineSplit[5..($lineSplit.Count - 1)] -join '|').Substring(5,1) -NoNewline -ForegroundColor Yellow
        Write-Host ($lineSplit[5..($lineSplit.Count - 1)] -join '|').Substring(6) -ForegroundColor Green

        foreach ($line in $invokeDOSfuscationAscii[5..($invokeDOSfuscationAscii.Length - 1)])
        {
            Write-Host $line.Substring(0,($spacing.Length + 6))  -NoNewline -ForegroundColor Red
            
            $substringDistance = 6
            if ($line.Substring(($spacing.Length + 6),7) -eq '| |_| |')
            {
                $substringDistance = 7
            }
            Write-Host $line.Substring(($spacing.Length + 6),$substringDistance)  -NoNewline -ForegroundColor Magenta
            
            Write-Host $line.Substring(($spacing.Length + 6 + $substringDistance),6) -NoNewline -ForegroundColor Yellow
            Write-Host $line.Substring(($spacing.Length + 6 + $substringDistance + 6)) -ForegroundColor Green
        }
    }
    else
    {
        # ASCII option in Invoke-DOSfuscation interactive console.
    }
    
    # Output tool banner after all ASCII art.
    Write-Host ""
    Write-Host "`tTool    :: Invoke-DOSfuscation" -ForegroundColor Magenta
    Write-Host "`tAuthor  :: Daniel Bohannon (DBO)" -ForegroundColor Magenta
    Write-Host "`tTwitter :: @danielhbohannon" -ForegroundColor Magenta
    Write-Host "`tBlog    :: http://danielbohannon.com" -ForegroundColor Magenta
    Write-Host "`tGithub  :: https://github.com/danielbohannon/Invoke-DOSfuscation" -ForegroundColor Magenta
    Write-Host "`tVersion :: 1.0" -ForegroundColor Magenta
    Write-Host "`tLicense :: Apache License, Version 2.0" -ForegroundColor Magenta
    Write-Host "`tNotes   :: if (-not `$caffeinated) { exit }" -ForegroundColor Magenta
}
