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