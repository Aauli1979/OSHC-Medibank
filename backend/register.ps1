$body = @{
    email = "test@example.com"
    password = "TestPassword123!"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://localhost:8080/api/auth/register" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body