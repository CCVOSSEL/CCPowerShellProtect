##################################################################################################
# ccPowerShellProject
##################################################################################################
# Creating custom scheduled task on new events in application log for forwarded PS events
#
# Thomas Koscheck
#
# FUNCTION DETAILS
# - <<function 1>>
# - <<function 2>>
# - <<function ...>>
#
# METADATA:
# CCVOSSEL GmbH
#
# SYNTAX: <scriptname>.ps1 
#         -<<parameter name 1>> <<short description of value 1>> 
#         -<<parameter name 2>> <<short description of value 2>> 
#         [-Output display|file|displayandfile|none]
#
#
#        Output  : possible values: display, file, displayandfile, none
#                  display = output to standard output only
#                  file = only output in log file at script directory
#                  displayandfile = output to standard output and log file 
#                  none = no output
#
##################################################################################################
# Sample call: 
# <<sample call with arguments>>
##################################################################################################

##################################################################################################
# Parameters
##################################################################################################
Param (
    [string]$Output = "fileandisplay"
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
$strScriptVersion = "v.0.1.0"
$strScriptAuthors = "ThomasKoscheck"
$strScriptLastChange = "21.04.2020"
$strScriptFunction = "Creating custom scheduled task on new events in application log for forwarded PS events."

##################################################################################################
# Determine script paths
##################################################################################################
$strScriptPath = Split-Path $myInvocation.MyCommand.Path
$strScriptFullPath = $myInvocation.MyCommand.Path
$strScriptName = $myInvocation.MyCommand.Name
$strLogFileSubDir = "Logfiles"

Import-Module (Join-Path $strScriptPath "..\CCV.Logging\CCV.Logging.psd1") -Force

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
$gMSAName = "gMSATest1$"
$scheduledTaskName = "ccPowerShellProtect"
$domain = "sec.demo.local"

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

function StopScript {
    Write-CCVLog "Warning" "Exiting."
    exit
}

##################################################################################################
##################################################################################################
##################################################################################################
# Main program
##################################################################################################
##################################################################################################
##################################################################################################

# delete task if existing
Try {
    schtasks /delete /f /TN $scheduledTaskName
}
Catch {
    Write-Log "warning" "Could not delete old scheduled tasks"
    Write-Log "warning" $_
}

# create new task
if (Test-Path -LiteralPath (Join-Path $strScriptPath "scheduledTask.xml") -PathType Leaf) {
    $principal = New-ScheduledTaskPrincipal -UserID "$domain\$gMSAName" -LogonType Password
    $xml = Get-Content (Join-Path $strScriptPath "scheduledTask.xml") | Out-String

    Register-ScheduledTask -TaskName $scheduledTaskName -Xml (Get-Content (Join-Path $strScriptPath "scheduledTask.xml") | Out-String)
} else {
    Write-CCVLog "Error" "scheduledTask.xml should be in the same path as this script is executed."
    StopScript
}

##################################################################################################
# Write log file bottom
##################################################################################################
Write-CCVLogBottom -strScriptFileName $strScriptName