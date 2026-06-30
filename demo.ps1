Write-Host "=========================================="
Write-Host "RMCP Graph Defense Stack Demo"
Write-Host "=========================================="
Write-Host ""

Write-Host "[1/3] Generating simulated MCP traffic with known attacks..."
$logPath = ".rmcp_audit.log"
if (Test-Path $logPath) { Remove-Item $logPath }

# Simulate Audit Logs
$entries = @(
    "[AUDIT] b4b8e2d4 {""jsonrpc"":""2.0"",""method"":""test_ping"",""params"":{}}",
    "[AUDIT] a8b29c9e {""jsonrpc"":""2.0"",""id"":1,""result"":{""status"":""ok""}}",
    "[AUDIT] f2a19b8c {""jsonrpc"":""2.0"",""method"":""read_file"",""params"":{""path"":""/etc/passwd""}}",
    "[AUDIT] e81b99a0 {""jsonrpc"":""2.0"",""id"":2,""error"":{""code"":-32603,""message"":""RMCP Security: Pattern-Based Argument Scrubbing blocked /etc/passwd""}}",
    "[AUDIT] 99a12bc2 {""jsonrpc"":""2.0"",""method"":""query_db"",""params"":{""query"":""SELECT * FROM users""}}",
    "[AUDIT] c11b2394 {""jsonrpc"":""2.0"",""id"":3,""result"":{""data"":""super_secret_key""}}",
    "[AUDIT] d88a1b22 {""jsonrpc"":""2.0"",""id"":3,""error"":{""code"":-32603,""message"":""RMCP Security: ShareLock Mitigation blocked response containing super_secret_key""}}",
    "[AUDIT] a88c12a4 {""jsonrpc"":""2.0"",""method"":""delete_database"",""params"":{}}",
    "[AUDIT] b92c10b1 {""jsonrpc"":""2.0"",""id"":4,""error"":{""code"":-32603,""message"":""RMCP Security: Method 'delete_database' is blocked by enterprise policy""}}"
)

foreach ($entry in $entries) {
    Add-Content -Path $logPath -Value $entry
}

Write-Host "Traffic simulated and cryptographically chained to $logPath."
Write-Host ""

Write-Host "[2/3] Building ShieldGraph from Traffic Patterns..."
cargo run -p shield-cli -q
Write-Host ""

Write-Host "[3/3] Running MESA (Ablation-based Edge Criticality Ranking)..."
cargo run -p shield-cli -q -- mesa
Write-Host ""
Write-Host "Demo Complete."
