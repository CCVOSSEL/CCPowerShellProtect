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
# REMARKS:
#
# VERSION HISTORY:
# - 14.04.2020: v0.1.0 Watching file changes and parsing file content
# - 15.04.2020: v0.2.0 Watching event changes instead of files, parsing event details
# - 16.04.2020: v0.2.1 checking event message for harmful content
# - 17.04.2020: v0.2.2 sending mail on harmful command
# - 20.04.2020: v0.2.3 working with winevent
# - 21.04.2020: v0.2.4 filerting winevent, working with scheduled task
# - 27.04.2020: v0.2.5 Send only notification when badness over threshold
# - 27.04.2020: v0.2.6 Send mail to user or admin
# - 28.04.2020: v0.2.7 Query performance improved x15
# - 29.04.2020: v0.2.8 Making code more fail save, validating emails addresses
# - 14.05.2020: v0.3.0 Adding Splunk support
# - 14.05.2020: v0.3.1 Optionally send all events to splunk
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
    [string]$Output = "none"
)

##################################################################################################
##################################################################################################
# Initialisation
##################################################################################################
##################################################################################################


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
$rulesPath = Join-Path $strScriptPath "\configuration\rules.json"
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

function Send-Mail {
    Param
   (
       [Parameter(Mandatory=$true)]
       [String] $From,

       [Parameter(Mandatory=$true)]
       [String] $To,

       [Parameter(Mandatory=$true)]
       [string] $ApiKey,

       [Parameter(Mandatory=$true)]
       [string] $Subject,

       [Parameter(Mandatory=$true)]
       [string] $Body
   )

   $headers = @{}
   [void]$headers.Add("Authorization","Bearer $apiKey")
   [void]$headers.Add("Content-Type", "application/json")

   $jsonRequest = [ordered]@{
                           personalizations= @(@{to = @(@{email =  "$To"})
                               subject = "$SubJect" })
                               from = @{email = "$From"}
                               content = @( @{ type = "text/html"
                                           value = "$Body" }
                               )} | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri "https://api.sendgrid.com/v3/mail/send" -Method Post -Headers $headers -Body $jsonRequest 
}

function Get-EventExecutionPath {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # Matches the beginning of the path line until 'Path:' 
    # this indicates the path line which is usually smth like 'Path: C:\Windows\TEMP\SDIAG_141a5465-4c2b-4e13-86e7-9787237a38c1\TS_DiagnosticHistory.ps1'
    $path = ($EventMessage -split 'Path\: ')[1]
    $pathClean = ($path -split '\n')[0].Trim()

    # path is empty, if command is invoked by user
    if ($pathClean) { 
        return $pathClean
    } else {
        return "Interactively by user"
    }
}

function Remove-LastLines {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # Matches the beginning of the line until ): and a new line
    # this indicates the second last line which is usually smth like:
    # }
    # 
    # ScriptBlock ID: 420e6429-ddc6-41e9-9eb5-3b35a838ab45'
    return ($EventMessage -split '\n\s\nScriptBlock ID\: ')[0]
}

function Remove-FirstLine {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # Matches the beginning of the line until ): and a new line
    # this indicates the first line which is usually smth like 'Creating Scriptblock text (1 of 1):'
   
    return  ($EventMessage -split '^.*\)\:')[1]
}

function Remove-NewLines {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # To get rid of newline characters '`n' and '`r' and windows
    return  $EventMessage.replace("`n","").replace("`r","").replace("\n","")
}

function Remove-MultipleWhitespaces {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$EventMessage
    )
    # To get rid of multiple whitespaces, tabs, 
    return  $EventMessage.replace('\s+\r\n+',"").replace("`t","")
}

function New-MailBody {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$match,
        [string]$matchComment,
        [int]$badness,
        [Parameter(Mandatory=$true)]
        [DateTime]$eventTime,
        [Parameter(Mandatory=$true)]
        [string]$eventMachine,
        [Parameter(Mandatory=$true)]
        [string]$PSCodeLines,
        [Parameter(Mandatory=$true)]
        [string]$eventPath,
        [Parameter(Mandatory=$true)]
        [string]$eventUser
    )

    $Body = "Dear Customer," + "<br/><br/>"

    $Body += "This is a new alert from ccPowerShellProtect. While analyzing the logs, I found the following suspicious command:"+ "<br/><br/>"
    $Body += "<b>Time: </b>" + $eventTime + "<br/>"
    $Body += "<b>User: </b>" + $eventUser + "<br/>" 
    $Body += "<b>MachineName: </b>" + $eventMachine + "<br/>" 
    $Body += "<b>Path: </b>" + $eventPath + "<br/>"              
    $Body += "<b>Suspicious Code: </b>" + $PSCodeLines + "<br/>"
    $Body += "<b>Badness: </b>"

    if ($badness -eq 1) { $Body += "<span style='color:green'>$badness </span>" }
    elseif ($badness -eq 2) {$Body += "<span style='color:orange'>$badness </span>" }
    elseif ($badness -eq 3) {$Body += "<span style='color:red'>$badness </span>" }

    $Body += "<br/>"
    $Body += "<b>Triggered Rule: </b>" + $match + "<br/>"
    $Body += "<b>Why is this dangerous?: </b>" + $matchComment + "<br/><br/>"
    $Body += "Kind regards, " + "<br/>" + "CCVOSSEL Security Team"

    return $Body
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

function IsEmailValid($email) {
    $EmailRegex = '^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$'

    return $email -match $EmailRegex
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

function Send-SplunkEvent {
    param (
        # Data object that will be sent to Splunk's HTTP Event Collector.
        [Parameter(Mandatory)]
        $InputObject,
        
        # HostName to be used for Splunk's 'host' property. Default's to name of the local system.
        [Parameter()]
        [string]
        $HostName = (hostname),

        # Date and Time of the event. Defaults to now() on the local system.
        [Parameter()]
        [System.DateTime]
        $DateTime = (Get-Date)
    )
    process {
        # Splunk events can have a 'time' property in epoch time. If it's not set, use current system time.
        $unixEpochStart = New-Object -TypeName DateTime -ArgumentList 1970,1,1,0,0,0,([DateTimeKind]::Utc)
        $unixEpochTime = [int]($DateTime.ToUniversalTime() - $unixEpochStart).TotalSeconds

        $uri = $settings.config.splunk.eventCollectorURI | Out-String
        $token =$settings.config.splunk.httpEventCollectorToken | Out-String

        # Create json object to send 
        $Body = ConvertTo-Json -InputObject @{event=$InputObject; host=$HostName; time=$unixEpochTime} -Compress
        Write-CCVLog "info" "Sending $Body to $uri"

        # Only return if something went wrong, i.e. http response is not "success"
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers @{Authorization="Splunk  $token"} -Body $Body

        if($response.text -ne "Success") {
            Write-CCVLog "warning" "Could not send event to splunk $response"
        }       
    }
}

function Get-SplunkSeverity($badness) {
    # https://answers.splunk.com/answers/32385/alert-script-and-severity.html
    switch($badness){
        0 { return "Debug"; break }
        1 { return "Info"; break }
        2 { return "Warn"; break }
        3 { return "Severe"; break }
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
$eventMessage = Remove-FirstLine $eventMessage
$PSCodeLines = Remove-LastLines $eventMessage
$PSCodeLines = Remove-NewLines $PSCodeLines 
$PSCodeLines = Remove-MultipleWhitespaces $PSCodeLines

# extract event meta data
$eventPath = Get-EventExecutionPath $eventMessage
$eventTime = $event.TimeCreated
$eventMachine = $event.MachineName
$eventUser = Convert-SIDToUserName $event.UserId

Write-CCVLog "debug" "EventId: $eventRecordID"
Write-CCVLog "debug" "Command: $PSCodeLines"
Write-CCVLog "debug" "Time: $eventTime"
Write-CCVLog "debug" "MachineName: $eventMachine"
Write-CCVLog "debug" "User: $eventUser"
Write-CCVLog "debug" "Path: $eventPath"

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