@echo off
echo Setting up Edibubble backend

:: Check required tools
set tools=go sqlc migrate psql redis-cli
for %%t in (%tools%) do (
    where %%t >nul 2>&1
    if errorlevel 1 (
        echo %%t is not installed. Please install it first.
        exit /b 1
    )
)

:: Check for .env
if not exist ".env" (
    echo No .env file found. Create one referencing the '.copy.env' file before continuing.
    exit /b 1
)

:: Load environment from .env
for /f "tokens=1,2 delims==" %%A in ('findstr /v "^#" .env') do (
    set "%%A=%%B"
)

echo Loaded environment from .env

:: Generate SQLC models
echo Generating SQLC models
sqlc generate

:: Run migrations
echo Running database migrations
migrate -path db/migrations -database %DATABASE_URL% up

echo Completed Edibubble backend setup. Execute 'go run cmd/server' to start the server locally.
