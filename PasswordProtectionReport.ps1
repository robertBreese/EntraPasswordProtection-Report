<#
.SYNOPSIS
    Query Domain Controllers for Microsoft Entra Password Protection audit failures.
.DESCRIPTION
    Discovers all DCs running the Password Protection Agent, queries event logs,
    and exports results to CSV with detailed console output.
#>

# --- Configuration ---
$DaysToGoBack = 90

# Audit-only failures (passwords that WOULD have been rejected)
$EventIDsToFind = @(10024, 10025, 30007, 30008, 30009, 30010, 30023, 30024, 30028, 30029)

# To also include actual rejections, uncomment this line:
# $EventIDsToFind += @(30002, 30003, 30004, 30005, 30021, 30022, 30026, 30027)

$OutputPath = "$env:USERPROFILE\Desktop\PasswordAuditReport_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"

# --- Script Body ---

Write-Host "=== Microsoft Entra Password Protection Audit Report ===" -ForegroundColor Cyan
Write-Host "Report Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Looking back: $DaysToGoBack days`n" -ForegroundColor Cyan

# Step 1: Discover all DCs with the Password Protection Agent
Write-Host "Discovering Domain Controllers with the Password Protection Agent..." -ForegroundColor Yellow

try {
    $forestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
    Write-Host "Querying forest: $forestName" -ForegroundColor Gray
    
    $dcAgents = Get-AzureADPasswordProtectionDCAgent -Forest $forestName
    
    if (-not $dcAgents) {
        Write-Error "No Domain Controllers with the Password Protection Agent were found."
        return
    }

    $dcAgentNames = $dcAgents | Select-Object -ExpandProperty ServerFQDN
    Write-Host "Found $($dcAgentNames.Count) Domain Controller(s):" -ForegroundColor Green
    $dcAgentNames | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
}
catch {
    Write-Error "Failed to discover DCs. Error: $($_.Exception.Message)"
    return
}

Write-Host "`nQuerying event logs on each DC..." -ForegroundColor Yellow
$allResults = @()

# Step 2: Query each DC
foreach ($dc in $dcAgentNames) {
    Write-Host "  -> Processing $dc..." -NoNewline
    $session = $null
    
    try {
        $session = New-PSSession -ComputerName $dc -ErrorAction Stop

        $scriptBlock = {
            param($DaysBack, $EventIDsToFind)
            
            try {
                $startTime = (Get-Date).AddDays(-$DaysBack)
                
                $filter = @{
                    LogName   = 'Microsoft-AzureADPasswordProtection-DCAgent/Admin'
                    StartTime = $startTime
                }
                
                $allEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
                $events = $allEvents | Where-Object { $_.Id -in $EventIDsToFind }
                
            }
            catch {
                try {
                    $filter = @{
                        LogName = 'Microsoft-AzureADPasswordProtection-DCAgent/Admin'
                    }
                    
                    $allEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop
                    
                    $startTime = (Get-Date).AddDays(-$DaysBack)
                    $events = $allEvents | Where-Object { 
                        $_.TimeCreated -ge $startTime -and $_.Id -in $EventIDsToFind 
                    }
                }
                catch {
                    return $null
                }
            }
            
            if (-not $events) {
                return $null
            }
            
            $output = foreach ($event in $events) {
                # Extract username from message
                $userName = "Unknown"
                if ($event.Message -match "UserName:\s*([^\r\n]+)") {
                    $userName = $matches[1].Trim()
                }
                
                # Extract full name if available
                $fullName = ""
                if ($event.Message -match "FullName:\s*([^\r\n]+)") {
                    $fullName = $matches[1].Trim()
                }
                
                # Determine operation type
                $operationType = if ($event.Id -in @(10024, 30002, 30004, 30008, 30010, 30021, 30024, 30026, 30028)) {
                    "Password Change"
                } else {
                    "Password Reset"
                }
                
                # Map Event ID to policy type and detailed reason
                $policyType = ""
                $detailedReason = ""
                $shortReason = ""
                
                switch ($event.Id) {
                    # Audit Mode - Custom Banned List
                    { $_ -in @(10024, 30008) } {
                        $policyType = "Custom Banned List"
                        $shortReason = "Matched Custom Banned List"
                        $detailedReason = "Password contains word(s) from organization's custom banned password list"
                    }
                    { $_ -in @(10025, 30007) } {
                        $policyType = "Custom Banned List"
                        $shortReason = "Matched Custom Banned List"
                        $detailedReason = "Password contains word(s) from organization's custom banned password list"
                    }
                    
                    # Audit Mode - Microsoft Global Banned List
                    { $_ -in @(30010) } {
                        $policyType = "Microsoft Global Banned List"
                        $shortReason = "Matched Microsoft Global List"
                        $detailedReason = "Password contains commonly used weak password(s) from Microsoft's global banned list"
                    }
                    { $_ -in @(30009) } {
                        $policyType = "Microsoft Global Banned List"
                        $shortReason = "Matched Microsoft Global List"
                        $detailedReason = "Password contains commonly used weak password(s) from Microsoft's global banned list"
                    }
                    
                    # Audit Mode - Contains Username
                    { $_ -in @(30024) } {
                        $policyType = "Username Policy"
                        $shortReason = "Contains Username"
                        $detailedReason = "Password contains the user's account name or display name"
                    }
                    { $_ -in @(30023) } {
                        $policyType = "Username Policy"
                        $shortReason = "Contains Username"
                        $detailedReason = "Password contains the user's account name or display name"
                    }
                    
                    # Audit Mode - Combined Policies
                    { $_ -in @(30028) } {
                        $policyType = "Combined Policies"
                        $shortReason = "Multiple Policy Violations"
                        $detailedReason = "Password violated BOTH Microsoft global AND custom banned password lists"
                    }
                    { $_ -in @(30029) } {
                        $policyType = "Combined Policies"
                        $shortReason = "Multiple Policy Violations"
                        $detailedReason = "Password violated BOTH Microsoft global AND custom banned password lists"
                    }
                    
                    # Actual Rejections - Custom Banned List
                    { $_ -in @(30002, 30003) } {
                        $policyType = "Custom Banned List"
                        $shortReason = "REJECTED - Custom Banned List"
                        $detailedReason = "Password REJECTED: Contains word(s) from organization's custom banned password list"
                    }
                    
                    # Actual Rejections - Microsoft Global Banned List
                    { $_ -in @(30004, 30005) } {
                        $policyType = "Microsoft Global Banned List"
                        $shortReason = "REJECTED - Microsoft Global List"
                        $detailedReason = "Password REJECTED: Contains commonly used weak password(s)"
                    }
                    
                    # Actual Rejections - Contains Username
                    { $_ -in @(30021, 30022) } {
                        $policyType = "Username Policy"
                        $shortReason = "REJECTED - Contains Username"
                        $detailedReason = "Password REJECTED: Contains the user's account name or display name"
                    }
                    
                    # Actual Rejections - Combined Policies
                    { $_ -in @(30026, 30027) } {
                        $policyType = "Combined Policies"
                        $shortReason = "REJECTED - Multiple Violations"
                        $detailedReason = "Password REJECTED: Violated BOTH Microsoft global AND custom lists"
                    }
                    
                    default {
                        $policyType = "Unknown"
                        $shortReason = "Unknown Event ID: $($event.Id)"
                        $detailedReason = "Unknown event type"
                    }
                }
                
                # Determine mode
                $mode = if ($event.Id -in @(10024, 10025, 30007, 30008, 30009, 30010, 30023, 30024, 30028, 30029)) {
                    "Audit"
                } else {
                    "Enforced"
                }
                
                [PSCustomObject]@{
                    Date                = $event.TimeCreated.ToString("yyyy-MM-dd")
                    Time                = $event.TimeCreated.ToString("HH:mm:ss")
                    TimeCreated         = $event.TimeCreated
                    UserName            = $userName
                    FullName            = $fullName
                    OperationType       = $operationType
                    Mode                = $mode
                    PolicyType          = $policyType
                    FailureReason       = $shortReason
                    DetailedExplanation = $detailedReason
                    EventID             = $event.Id
                    DomainController    = $event.MachineName
                }
            }
            return $output
        }

        $resultsOnDC = Invoke-Command -Session $session -ScriptBlock $scriptBlock `
            -ArgumentList $DaysToGoBack, $EventIDsToFind

        if ($null -ne $resultsOnDC -and @($resultsOnDC).Count -gt 0) {
            $count = @($resultsOnDC).Count
            Write-Host " Found $count event(s)" -ForegroundColor Cyan
            $allResults += $resultsOnDC
        } else {
            Write-Host " No events found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " ERROR" -ForegroundColor Red
        Write-Warning "  Failed to query $dc. Error: $($_.Exception.Message)"
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

# --- Output Results ---
Write-Host "`n========================================" -ForegroundColor Cyan

if ($allResults.Count -gt 0) {
    Write-Host "SUCCESS: Found $($allResults.Count) password audit failure(s)" -ForegroundColor Green
    
    # Sort results
    $sortedResults = $allResults | Sort-Object TimeCreated -Descending
    
    # Export to CSV
    Write-Host "`nExporting to CSV..." -ForegroundColor Yellow
    $sortedResults | 
        Select-Object Date, Time, UserName, FullName, OperationType, Mode, PolicyType, FailureReason, DetailedExplanation, DomainController, EventID |
        Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "CSV report created: $OutputPath" -ForegroundColor Green
    
    # --- Detailed Console Output ---
    
    # Executive Summary
    Write-Host "`n=== EXECUTIVE SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Report Period:        Last $DaysToGoBack days" -ForegroundColor White
    Write-Host "Total Events:         $($allResults.Count)" -ForegroundColor White
    Write-Host "Unique Users:         $(($allResults | Select-Object -ExpandProperty UserName -Unique).Count)" -ForegroundColor White
    Write-Host "Forest:               $forestName" -ForegroundColor White
    
    # Summary by Mode
    Write-Host "`n=== SUMMARY BY MODE ===" -ForegroundColor Cyan
    $sortedResults | Group-Object Mode | 
        Select-Object @{N='Mode';E={$_.Name}}, @{N='Count';E={$_.Count}} |
        Format-Table -AutoSize
    
    # Summary by Policy Type
    Write-Host "=== SUMMARY BY POLICY TYPE ===" -ForegroundColor Cyan
    $sortedResults | Group-Object PolicyType | 
        Select-Object @{N='Policy Type';E={$_.Name}}, @{N='Count';E={$_.Count}}, @{N='Percentage';E={"{0:P1}" -f ($_.Count / $allResults.Count)}} |
        Sort-Object Count -Descending |
        Format-Table -AutoSize
    
    # Summary by User
    Write-Host "=== TOP 10 USERS BY EVENT COUNT ===" -ForegroundColor Cyan
    $sortedResults | Group-Object UserName | 
        Select-Object @{N='User';E={$_.Name}}, 
                      @{N='Total Events';E={$_.Count}}, 
                      @{N='Last Incident';E={($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.ToString("yyyy-MM-dd HH:mm")}} |
        Sort-Object 'Total Events' -Descending |
        Select-Object -First 10 |
        Format-Table -AutoSize
    
    # Daily breakdown
    Write-Host "=== EVENTS BY DAY ===" -ForegroundColor Cyan
    $sortedResults | Group-Object Date | 
        Select-Object @{N='Date';E={$_.Name}}, @{N='Count';E={$_.Count}} |
        Sort-Object Date -Descending |
        Format-Table -AutoSize
    
    # Most Recent Events (Detailed)
    Write-Host "=== MOST RECENT 10 EVENTS (DETAILED) ===" -ForegroundColor Cyan
    $sortedResults | Select-Object -First 10 | ForEach-Object {
        Write-Host "`n---" -ForegroundColor DarkGray
        
        Write-Host "Date/Time:       " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.Date) $($_.Time)" -ForegroundColor White
        
        Write-Host "User:            " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.UserName)" -ForegroundColor White -NoNewline
        if ($_.FullName) {
            Write-Host " ($($_.FullName))" -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }
        
        Write-Host "Operation:       " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.OperationType)" -ForegroundColor White
        
        Write-Host "Mode:            " -NoNewline -ForegroundColor Gray
        $modeColor = if ($_.Mode -eq "Audit") { "Cyan" } else { "Magenta" }
        Write-Host "$($_.Mode)" -ForegroundColor $modeColor
        
        Write-Host "Policy Type:     " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.PolicyType)" -ForegroundColor White
        
        Write-Host "Reason:          " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.FailureReason)" -ForegroundColor Yellow
        
        Write-Host "Explanation:     " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.DetailedExplanation)" -ForegroundColor White
        
        Write-Host "DC:              " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.DomainController)" -ForegroundColor White
        
        Write-Host "Event ID:        " -NoNewline -ForegroundColor Gray
        Write-Host "$($_.EventID)" -ForegroundColor DarkGray
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Full report exported to: $OutputPath" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
} else {
    Write-Host "No audit failure events found in the last $DaysToGoBack days" -ForegroundColor Yellow
    Write-Host "`nNote: Your policy is in AUDIT mode. To see events:" -ForegroundColor Cyan
    Write-Host "  - Users must attempt weak passwords (matching banned lists)" -ForegroundColor Gray
    Write-Host "  - Events are logged but passwords are still accepted" -ForegroundColor Gray
    Write-Host "`nTo switch to ENFORCE mode:" -ForegroundColor Cyan
    Write-Host "  - Azure Portal → Entra ID → Security → Authentication methods → Password protection" -ForegroundColor Gray
    Write-Host "  - Change mode from 'Audit' to 'Enforced'" -ForegroundColor Gray
}

Write-Host "`n========================================" -ForegroundColor Cyan
