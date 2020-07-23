
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