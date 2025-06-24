Write-Host "Setting up Edibubble backend"

# List of required tools
$requiredTools = @("go", "sqlc", "migrate", "psql", "redis-cli")

foreach ($tool in $requiredTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "$tool is not installed. Please install it first."
        exit 1
    }
}

# Load .env file
if (Test-Path ".env") {
    Get-Content .env | Where-Object { $_ -notmatch '^#' -and $_ -match '=' } |
        ForEach-Object {
            $parts = $_ -split '=', 2
            [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
        }
    Write-Host "Loaded environment from .env"
}
else {
    Write-Host "No .env file found. Create one referencing the '.copy.env' file before continuing."
    exit 1
}

# Run SQLC
Write-Host "Generating SQLC models"
sqlc generate

# Run DB migrations
Write-Host "Running database migrations"
migrate -path db/migrations -database $env:DATABASE_URL up

Write-Host "Completed Edibubble backend setup. Execute 'go run cmd/server' to start the server locally."
