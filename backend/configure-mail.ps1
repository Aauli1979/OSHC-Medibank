# Example Gmail SMTP configuration for the current PowerShell session.
# IMPORTANT: use a Google App Password, not your normal Gmail password.
$env:MAIL_HOST = "smtp.gmail.com"
$env:MAIL_PORT = "587"
$env:MAIL_USERNAME = "your-sender@gmail.com"
$env:MAIL_PASSWORD = "your-16-character-Google-App-Password"
$env:MAIL_SMTP_AUTH = "true"
$env:MAIL_SMTP_STARTTLS = "true"
$env:MAIL_SMTP_STARTTLS_REQUIRED = "true"
$env:MAIL_SMTP_SSL_TRUST = "smtp.gmail.com"
$env:FRONTEND_URL = "http://localhost:5173"
Write-Host "SMTP variables configured for this PowerShell session."
Write-Host "Edit MAIL_USERNAME and MAIL_PASSWORD before running mvn spring-boot:run."
