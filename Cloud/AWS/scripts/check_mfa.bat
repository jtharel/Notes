@echo off
set PROFILE=XXXXXXXXX

echo ========================================
echo MFA STATUS AUDIT
echo ========================================
echo.

echo [*] Generating credential report...
aws iam generate-credential-report --profile %PROFILE% >nul 2>&1
timeout /t 5 /nobreak >nul

echo [*] Downloading credential report...
aws iam get-credential-report --profile %PROFILE% --output json --query "Content" > mfa_report_b64.txt

echo.
python -I -c "import base64,csv,io;f=open('mfa_report_b64.txt');raw=f.read().strip().strip('\"');f.close();data=base64.b64decode(raw).decode();rows=list(csv.DictReader(io.StringIO(data)));hdr='{:<35} {:<12} {:<18} {:<14} {:<14}'.format('User','MFA','Password','Key 1','Key 2');print(hdr);print('-'*93);[print('{:<35} {:<12} {:<18} {:<14} {:<14}'.format(r['user'],r['mfa_active'],r.get('password_enabled','N/A'),r.get('access_key_1_active','N/A'),r.get('access_key_2_active','N/A'))) for r in rows]"

echo.
echo ========================================
echo Done.
echo ========================================
