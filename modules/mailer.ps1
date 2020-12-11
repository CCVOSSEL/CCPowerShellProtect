function Send-Mail-Mailjet {
    Param
   (
       [Parameter(Mandatory=$true)]
       [String] $From,
  
       [Parameter(Mandatory=$true)]
       [String] $To,
  
       [Parameter(Mandatory=$true)]
       [string] $Username,
  
       [Parameter(Mandatory=$true)]
       [string] $Password,
  
       [Parameter(Mandatory=$true)]
       [string] $Subject,
  
       [Parameter(Mandatory=$true)]
       [string] $Body
   )

   $strPasswordDecrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Password)))

  
   $mailPattern = Get-Content $mailPatternPath
   $mailFooter = $mailPattern.Replace('$(Get-date -f "dd.MM.yyyy")',(Get-date -f "dd.MM.yyyy"))
   $Body = $Body + $mailFooter
  
   $SMTPMessage = New-Object System.Net.Mail.MailMessage($From, $To, $Subject, $Body)
   $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587) 
   $SMTPClient.EnableSsl = $true 
   $cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, (ConvertTo-SecureString $strPasswordDecrypted -AsPlainText -Force)
   $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($cred.UserName, $cred.Password); 
   $SMTPClient.Send($SMTPMessage)
}

function Send-Mail-SendGrid {
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

# general methods
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

    # add HTML encode methods
    Add-Type -AssemblyName System.Web

    $Body = "Dear Customer," + "<br/><br/>"

    # ToDo write a method for htmlencode
    $Body += "This is a new alert from ccPowerShellProtect. While analyzing the logs, I found the following suspicious command:"+ "<br/><br/>"
    $Body += "<b>Time: </b>" + $eventTime + "<br/>"
    $Body += "<b>User: </b>" + [System.Web.HttpUtility]::HtmlEncode($eventUser) + "<br/>" 
    $Body += "<b>MachineName: </b>" + [System.Web.HttpUtility]::HtmlEncode($eventMachine) + "<br/>" 
    $Body += "<b>Path: </b>" + [System.Web.HttpUtility]::HtmlEncode($eventPath) + "<br/>"              
    $Body += "<b>Suspicious Code: </b>" + [System.Web.HttpUtility]::HtmlEncode($PSCodeLines) + "<br/>"
    $Body += "<b>Badness: </b>"

    if ($badness -eq 1) { $Body += "<span style='color:green'>$badness </span>" }
    elseif ($badness -eq 2) {$Body += "<span style='color:orange'>$badness </span>" }
    elseif ($badness -eq 3) {$Body += "<span style='color:red'>$badness </span>" }

    $Body += "<br/>"
    $Body += "<b>Triggered Rule: </b>" + [System.Web.HttpUtility]::HtmlEncode($match) + "<br/>"
    $Body += "<b>Why is this dangerous?: </b>" + [System.Web.HttpUtility]::HtmlEncode($matchComment) + "<br/><br/>"
    $Body += "Kind regards, " + "<br/>" + "CCVOSSEL Security Team"

    return $Body
}s