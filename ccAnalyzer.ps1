##################################################################################################
# ccPowerShellProject
##################################################################################################
# Analyze PowerShell transcripts and alerting on potentially harmful actions.
#
# Thomas Koscheck
#
# FUNCTION DETAILS
# - <<function 1>>
# - <<function 2>>
# - <<function ...>>
#
# METADATA:
# <<Customer Company>>/<<Customer Contact Person>>, CCVOSSEL GmbH
#
# SYNTAX: ccAnalyzer.ps1 
#         -eventRecordID The unique record id of the event, that triggered the script
#         -eventCreatedTime The creation time of the event, that triggered the script
#         -eventUserSID User of the event, that triggered the script 
#         [-Output display|file|displayandfile|none]
#
#        Output  : possible values: display, file, displayandfile, none
#                  display = output to standard output only
#                  file = only output in log file at script directory
#                  displayandfile = output to standard output and log file 
#                  none = no output
#
##################################################################################################
# Sample call: 
# ccAnalyzer.ps1 -eventRecordID "878" - eventCreatedTime -eventUserSID "S-1-5-21-3270792536-1858956553-1543462974-1101"
##################################################################################################

##################################################################################################
# Parameters
##################################################################################################
Param (
    [Parameter(Mandatory=$true)]
    [string]$eventRecordID,
    [Parameter(Mandatory=$true)]
    $eventCreatedTime,
    [Parameter(Mandatory=$true)]
    $eventUserSID, 
    [string]$Output = "file"
)

##################################################################################################
##################################################################################################
# Initialisation
##################################################################################################
##################################################################################################

# region Include required files
#
try {
    . ("modules\sendGrid.ps1")
    . ("modules\splunk.ps1")
}
catch {
    Write-Host "Error while loading supporting PowerShell Scripts" 
}
#endregion

##################################################################################################
# Parameter check
##################################################################################################

switch($output.trim().tolower())
{
    "none" 
    { 
        $bolOutputDisplay = $false
        $bolOutputFile = $false
    }
    "display" 
    { 
        $bolOutputDisplay = $true
        $bolOutputFile = $false
    }
    "file" 
    { 
        $bolOutputDisplay = $false
        $bolOutputFile = $true
    }
    {("fileanddisplay","displayandfile" -contains $_)} 
    { 
        $bolOutputDisplay = $true
        $bolOutputFile = $true
    }
    default 
    { 
        $bolOutputDisplay = $true
        $bolOutputFile = $false
    }

}

##################################################################################################
# Script variables
##################################################################################################
$strScriptVersion = "v.0.3.1"
$strScriptAuthors = "ThomasKoscheck"
$strScriptLastChange = "14.05.2020"
$strScriptFunction = "Analyze PowerShell transcripts and alerting on potentially harmful actions."

##################################################################################################
# Determine script paths
##################################################################################################
$strScriptPath = Split-Path $myInvocation.MyCommand.Path
$strScriptFullPath = $myInvocation.MyCommand.Path
$strScriptName = $myInvocation.MyCommand.Name
$strLogFileSubDir = "Logfiles"

Import-Module (Join-Path $strScriptPath "CCV.Logging\CCV.Logging.psd1") -Force

if ($bolOutputFile)
{
    $strLogFileDir = (Join-Path $strScriptPath $strLogFileSubDir)
    ##################################################################################################
    # Create log file
    ##################################################################################################

    New-CCVLog -strLogFolderPath $strLogFileDir  -strLogFileName ($strScriptName -replace ".ps1",".log")
}


##################################################################################################
# Write log file header
##################################################################################################
Write-CCVLogHead -strScriptFileName $strScriptName -strScriptVersion $strScriptVersion -strScriptAuthors $strScriptAuthors -strScriptLastChange $strScriptLastChange -strScriptFunction $strScriptFunction


##################################################################################################
# Global Constants
##################################################################################################
$rulesPath  = Join-Path $strScriptPath "\configuration\rules.json"
$configPath = Join-Path $strScriptPath "\configuration\config.json"

##################################################################################################
##################################################################################################
##################################################################################################
# Sub routines
##################################################################################################
##################################################################################################
##################################################################################################
function WriteSyntaxError($strErrorMessage)
{
    Write-Host ""
    Write-Host "SYNTAX ERROR"
    Write-Host ""
    Write-Host $strErrorMessage
    Write-Host ""

    Write-Host ("SYNTAX: <Skriptname.ps1>" + `
        " -Param1 " + "<<Param1 description>>" + `
        " -Param2 " + "<<Param2 description>>" + `
        " [-Output display|file|displayandfile|none]")

    Write-Host ""

    Write-Host "Param1         : <<detailed description of param1>>"
    Write-Host ""
    Write-Host "Param2         : <<detailed description of param2>>"
    Write-Host ""

    Write-Host "Output         : possible values: display, file, displayandfile, none"
    Write-Host "               : display = output to standard output only"
    Write-Host "               : file = only output in log file at script directory"
    Write-Host "               : displayandfile = output to standard output and log file"
    Write-Host "               : none = no output"
    Write-Host ""
    Write-Host "Script created $strScriptLastChange, $strScriptAuthors"
}

function CheckMandatoryParameter($strParamName,$strParamValue)
{
	if ($strParamValue -eq "")
	{
		WriteSyntaxError "Value of parameter '$strParamName' is missing."
		return $false
	}
	else
	{
		return $true
    }
}

function Extract-Metadata {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # Matches the beginning of the line until ): and a new line
    # this indicates the first line which is usually smth like 'Creating Scriptblock text (1 of 1):'
   
    #return  ($EventMessage -split '^.*\)\:')[1]

    $lines = $EventMessage -split '\n' 

    $command = ""
    foreach ( $word in $lines[1 .. ($lines.Count - 4)] ) { 
        $command += $word + ' '
    }

    # remove two last lines, because of empty last line
    $path =  $lines[$lines.Count - 2]

    [string[]]$returnArray = $command,$path
    return $returnArray
}

function Get-EventExecutionPath {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # Matches the beginning of the path line until 'Path:' 
    # this indicates the path line which is usually smth like 'Path: C:\Windows\TEMP\SDIAG_141a5465-4c2b-4e13-86e7-9787237a38c1\TS_DiagnosticHistory.ps1'
    $path = ($EventMessage -split '\: ')[1]
    $pathClean = ($path -split '\n')[0].Trim()

    # path is empty, if command is invoked by user
    if ($pathClean) { 
        return $pathClean
    } else {
        return "Interactively by user"
    }
}

function Get-ADUserEmail ($userName) {
    $user = Get-ADUser -Identity $userName -Properties EmailAddress
    $userMail = $user.EmailAddress

    if (IsEmailValid $userMail) {
        return $userMail
    } else {
        # the email we found in the AD seems not to be a valid email, send mail to admin instead
        Write-CCVLog "warning" "We found a non valid email: $userMail"
        Write-CCVLog "warning" "Sending notification to admin instead"
        return  $settings.config.notifications.mailTo
    }
}

function Convert-SIDToUserName ($sid) {
    Try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } 
    Catch {
        Write-CCVLog "warning" "Could not convert SID to username"
        Write-CCVLog "warning" "Error:$_"
    } 
}

##################################################################################################
##################################################################################################
###########################################################################power#######################
# Main program
##################################################################################################
##################################################################################################
##################################################################################################
# rules are heavily based on https://github.com/secprentice/PowerShellBlacklist/blob/master/badshell.txt,
# https://gist.github.com/gfoss/2b39d680badd2cad9d82
$rules = [System.IO.File]::ReadAllLines((Resolve-Path $rulesPath)) | ConvertFrom-Json
$settings = [System.IO.File]::ReadAllLines((Resolve-Path $configPath)) | ConvertFrom-Json

$event = Get-WinEvent -FilterHashtable @{LogName='Application';ID=4104;StartTime=$eventCreatedTime} | Where-Object -Property RecordId -eq $eventRecordID


# event.Message is Type System.Object[]
$eventMessage = $event.Message | Out-String

# prepare event message and clean unnecessary lines and characters
$eventMetadata = Extract-Metadata $eventMessage
$PSCodeLines = $eventMetadata[0]

# extract event meta data
$eventPath = Get-EventExecutionPath $eventMetadata[1]
$eventTime = $event.TimeCreated
$eventMachine = $event.MachineName
$eventUser = Convert-SIDToUserName $event.UserId

Write-CCVLog "info" "EventId: $eventRecordID"
Write-CCVLog "info" "Command: $PSCodeLines"
Write-CCVLog "info" "Time: $eventTime"
Write-CCVLog "info" "MachineName: $eventMachine"
Write-CCVLog "info" "User: $eventUser"
Write-CCVLog "info" "Path: $eventPath"

# filter for malicious content      
$matched = $false
$PSCodeLinesLower = $PSCodeLines.ToLower()
foreach ($rule in $rules.rules) {
    if (($PSCodeLinesLower) -match ($rule.rule)) {
        $matched = $true
        Write-CCVLog "warning" $PSCodeLines $bolOutputDisplay $true $ColorHighlight

        # send mail only if badness is above threshold in config.json
        if ($rule.badness -gt $settings.config.notifications.badnessThreshold) {
            # create and send mail
            $Subject = "ccPowerShellProtect - New alert"
            $Body = New-MailBody -match $rule.rule `
                                    -matchComment $rule.comment `
                                    -badness $rule.badness `
                                    -eventTime $eventTime `
                                    -eventUser $eventUser `
                                    -eventMachine $eventMachine `
                                    -PSCodeLines $PSCodeLines `
                                    -eventPath $eventPath

            # send mail to user/admin depending on config.json
            if ($settings.config.notifications.sendNotificationToUser) {
                # remove the domain\ prefix of the username
                $cleanUsername = ($eventUser -split "\\")[1]
                $mailTo = Get-ADUserEmail $cleanUsername
            } else {
                $mailTo = $settings.config.notifications.mailTo
            }

            Send-Mail -from $settings.config.notifications.mailFrom `
                        -to $mailTo `
                        -ApiKey $settings.config.notifications.apiKey `
                        -Body $Body `
                        -Subject $Subject  

            Write-CCVLog "info" "sent mail"
        }

        # send event to splunk if enabled
        if ($settings.config.splunk.enabled) {
            $match = $rule.rule
            $comment = $rule.comment
            $splunkMessage = "Rule: $match, comment: $comment, eventRecordID: $eventRecordID, supiciousCode: $PSCodeLinesLower"
            $severity = Get-SplunkSeverity $rule.badness
            $splunkEvent = @{message=$splunkMessage;severity=$severity;user=$eventUser}
            Send-SplunkEvent -InputObject $splunkEvent -Hostname $eventMachine -DateTime $eventTime
        }
            
        break
    }
}
if (-not $matched)
{
    if ($settings.config.others.logHarmlessCommands) {
        Write-CCVLog "info" $PSCodeLinesLower $bolOutputDisplay $true $ColorHighlight
    }

    # send harmless events to splunk
    if ($settings.config.splunk.logHarmlessCommands) {
        # send harmlesse events to splunk if event does not equal "prompt"
        if ($settings.config.splunk.excludePromptEvents -and  (-not ($PSCodeLinesLower -eq "prompt"))) {
            $splunkMessage = "Rule: $PSCodeLinesLower, comment: NA, eventRecordID: $eventRecordID"
            $severity = Get-SplunkSeverity 0 # because harmless commands have no severity, we wil log this as "debug"
            $splunkEvent = @{message=$splunkMessage;severity=$severity;user=$eventUser}
            Send-SplunkEvent -InputObject $splunkEvent -Hostname $eventMachine -DateTime $eventTime
        } 
        # also sent "prompt" events
        elseIF (-not $settings.config.splunk.excludePromptEvents) {
            $splunkMessage = "Rule: $PSCodeLinesLower, comment: NA, eventRecordID: $eventRecordID"
            $severity = Get-SplunkSeverity 0 # because harmless commands have no severity, we wil log this as "debug"
            $splunkEvent = @{message=$splunkMessage;severity=$severity;user=$eventUser}
            Send-SplunkEvent -InputObject $splunkEvent -Hostname $eventMachine -DateTime $eventTime
        }
    }
}

##################################################################################################
# Write log file bottom
##################################################################################################
Write-CCVLogBottom -strScriptFileName $strScriptName