##################################################################################################
# ModifyRules
##################################################################################################
# Creating, checking for duplicates and modifying rules for ccPowerShellProtect
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
# SYNTAX: ModifyRules.ps1 
#        
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
# REMARKS:
#
# VERSION HISTORY:
# - 24.04.2020: v0.1.0 Check for exisiting rules
# - 27.04.2020: v0.2.0 Add new rule if not exising
# - 27.04.2020: v0.2.1 Option to whitelist a rule
# - 13.05.2020: v0.2.2 Some bugfixing, adding option to add new rule without restarting the script
##################################################################################################


##################################################################################################
# Parameters
##################################################################################################
Param (
    [string]$Output = "display"
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
$strScriptVersion = "v.0.2.1"
$strScriptAuthors = "ThomasKoscheck"
$strScriptLastChange = "27.04.2020"
$strScriptFunction = " Creating, checking for duplicates and modifying rules for ccPowerShellProtect."

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
 
function ReturnExistingRule($json, $rule) {
   return $json.rules | Where-Object { $_.rule -eq $rule } 
}

function IsRuleAlreadyExisting($json, $rule) {
    $result = $json.rules | Where-Object { $_.rule -eq $rule } 

    if ($result) {
        return $true
    }
    else {
        return $false
    }
}

# whitelist a rule by setting its badness to zero
function WhiteListRule($json, $rule) {
    $json.rules | Where-Object { $_.rule -eq  $rule } | ForEach-Object {$_.badness = 0}
    return $json
}

# saves new rules json to exiting rules.json file
function SaveNewRulesToFile($json) {
    $json | ConvertTo-Json -Compress | Out-File  (Join-Path $strScriptPath "rules.json")
}

function CreateNewRule ($newRule, [int]$newRuleBadness, $newRuleComment) {
    return @{rule=$newRule; badness=$newRuleBadness; comment=$newRuleComment}
}

function StopScript {
    Write-CCVLog "Warning" "Exiting."
    exit
}

function Is-Numeric ($Value) {
    return $Value -match "^[\d\.]+$"
}

function Read-NewRuleBadnessFromUser() {
   return Read-Host -Prompt 'Input the the badness of this new rule'
} 

function Read-NewRuleCommentFromUser() {
    return Read-Host -Prompt 'Please describe, why this rule is or could be dangerous'
}

function Read-NewRuleMatchFromUser() {
    return Read-Host -Prompt 'Input the string which the new rule should match'
}

function Read-ExitOrNewOrDisable() {
    $input = Read-Host -Prompt 'Do you want to disable the rule, add a new rule or exit the script [d(isable)/N(ew)/e(xit)]?'
    return $input.ToLower()
}

##################################################################################################
##################################################################################################
##################################################################################################
# Main program
##################################################################################################
##################################################################################################
##################################################################################################
# try to load existing rules.json file
if (Test-Path -LiteralPath (Join-Path $strScriptPath "rules.json") -PathType Leaf) {
    $rulesJSON = Get-Content -Raw -Path (Join-Path $strScriptPath "rules.json") | ConvertFrom-Json
} else {
    Write-CCVLog "Error" "Rules.json should be in the same path as this script is executed."
    StopScript
}

while($true) {
    # read new rule string from user
    $newRuleString = Read-NewRuleMatchFromUser
    $newRuleString = $newRuleString.ToLower()

    while($newRuleString -eq "") {
        Write-CCVLog "Warning" "Match cannot be empty."
        $newRuleString = Read-NewRuleMatchFromUser
    }

    # check if this rule match is already existing
    if (IsRuleAlreadyExisting $rulesJSON $newRuleString) {
        Write-CCVLog "Info" "This rule is already existing."
        Write-CCVLog "Info" (ReturnExistingRule $rulesJSON $newRuleString)

        $readExitOrNewOrDisable = Read-ExitOrNewOrDisable
        while (($readExitOrNewOrDisable -ne "") -and ($readExitOrNewOrDisable -ne "d") -and ($readExitOrNewOrDisable -ne "e") -and ($readExitOrNewOrDisable -ne "n")) {
            Write-CCVLog "Warning" "Invalid selection"
            $readExitOrNewOrDisable = Read-ExitOrNewOrDisable
        }

        # default action is new rule
        if (($readExitOrNewOrDisable -eq "") -or ($readExitOrNewOrDisable -eq "n")) {
            # start from the beginning
            Write-CCVLog "Info" "Starting again."
            Continue
        } elseIf ($readExitOrNewOrDisable -eq "e") {
            StopScript
        } elseIf ($readExitOrNewOrDisable -eq "d") {
            WhiteListRule $rulesJSON $newRuleString
            SaveNewRulesToFile $rulesJSON
            Write-CCVLog "Info" "Disabled rule $newRuleString"
            StopScript
        }
        
    } else {
        # read new rule badness from user
        $newRuleBadness = Read-NewRuleBadnessFromUser
        while (!((Is-Numeric $newRuleBadness) -and ($newRuleBadness -ge 1) -and ($newRuleBadness -le 3))) {
            Write-CCVLog "Warning" "Badness must be a number between 1 and 3."
            $newRuleBadness = Read-NewRuleBadnessFromUser
        }

        # read new rule comment from user
        $newRuleComment = Read-NewRuleCommentFromUser
        while ($newRuleComment -eq "") {
            Write-CCVLog "Warning" "Comment cannot be empty."
            $newRuleComment = Read-NewRuleCommentFromUser
        }
        
        # create the new rule as addable object
        $newRule = CreateNewRule $newRuleString $newRuleBadness $newRuleComment

        # merge with existing rules and save to file
        $rulesJSON.rules += $newRule
        SaveNewRulesToFile $rulesJSON
        Write-CCVLog "Info" "Added new rule to file successfully"
    }
}

##################################################################################################
# Write log file bottom
##################################################################################################
Write-CCVLogBottom -strScriptFileName $strScriptName