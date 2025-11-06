# HTTPS/SSL Configuration Guide for Secure E-Commerce Project

## Overview
This guide explains how to configure HTTPS/SSL security for your Django e-commerce project. The configuration has been added to `settings.py`, and this document explains how to use it step by step.

---

## Step 1: Understanding the Current Configuration

### What Was Fixed:
1. ✅ **Fixed missing import**: Added `from pathlib import Path`
2. ✅ **Removed unnecessary import**: Removed `from nt import O_TEMPORARY`
3. ✅ **Fixed database configuration**: Corrected syntax for `OPTIONS`, `CONN_MAX_AGE`, and `sslmode`
4. ✅ **Added comprehensive HTTPS/SSL security settings**

### Security Settings Added:
- **SECURE_PROXY_SSL_HEADER**: For reverse proxy setups
- **SECURE_SSL_REDIRECT**: Force HTTPS redirects
- **Cookie Security**: Secure, HttpOnly, and SameSite attributes
- **HSTS**: HTTP Strict Transport Security
- **Security Headers**: X-Frame-Options, Content-Type, XSS Protection, Referrer Policy

---

## Step 2: Environment Variables Setup

Create or update your `.env` file with the following HTTPS-related variables:

```bash
# HTTPS/SSL Configuration
SECURE_SSL_REDIRECT=False          # Set to True in production
SESSION_COOKIE_SECURE=False        # Set to True in production
CSRF_COOKIE_SECURE=False           # Set to True in production

# HSTS Configuration (HTTP Strict Transport Security)
SECURE_HSTS_SECONDS=0              # Set to 31536000 (1 year) in production
SECURE_HSTS_INCLUDE_SUBDOMAINS=False  # Set to True in production if you have subdomains
SECURE_HSTS_PRELOAD=False          # Set to True in production (requires HSTS_SECONDS > 0)

# Database SSL (already configured)
DB_SSLMODE=require                 # Use 'require' or 'verify-full' in production
```

### Development vs Production Values:

**Development (.env):**
```bash
SECURE_SSL_REDIRECT=False
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False
SECURE_HSTS_SECONDS=0
```

**Production (.env):**
```bash
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_HSTS_PRELOAD=True
```

---

## Step 3: SSL Certificate Setup

### Option A: Using a Reverse Proxy (Recommended for Production)

**With Nginx:**
1. Install Nginx and obtain SSL certificate (Let's Encrypt recommended)
2. Configure Nginx to handle SSL termination
3. Set `SECURE_PROXY_SSL_HEADER` in Django settings (already configured)
4. Configure Nginx to pass `X-Forwarded-Proto: https` header

**Nginx Configuration Example:**
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;  # Important for Django
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

**With Apache:**
```apache
<VirtualHost *:443>
    ServerName yourdomain.com
    
    SSLEngine on
    SSLCertificateFile /path/to/certificate.crt
    SSLCertificateKeyFile /path/to/private.key
    
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
    
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

### Option B: Using Let's Encrypt (Free SSL)

1. **Install Certbot:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install certbot python3-certbot-nginx
   
   # macOS
   brew install certbot
   ```

2. **Obtain Certificate:**
   ```bash
   sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
   ```

3. **Auto-renewal (cron job):**
   ```bash
   sudo certbot renew --dry-run
   ```

### Option C: Development/Testing with Self-Signed Certificate

**For local development only:**
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost"

# Run Django with SSL
python manage.py runserver_plus --cert-file cert.pem --key-file key.pem
```

**Note:** Self-signed certificates will show browser warnings. Only use for development!

---

## Step 4: Activating HTTPS Settings

### For Development:
1. Keep all HTTPS settings as `False` in `.env`
2. Test your application normally
3. Use `runserver` without SSL (Django doesn't handle SSL directly)

### For Production:
1. **Update `.env` file:**
   ```bash
   SECURE_SSL_REDIRECT=True
   SESSION_COOKIE_SECURE=True
   CSRF_COOKIE_SECURE=True
   SECURE_HSTS_SECONDS=31536000
   SECURE_HSTS_INCLUDE_SUBDOMAINS=True
   SECURE_HSTS_PRELOAD=True
   ```

2. **Ensure your reverse proxy is configured** (Nginx/Apache)

3. **Test the configuration:**
   ```bash
   # Check if HTTPS redirect works
   curl -I http://yourdomain.com
   # Should return 301/302 redirect to https://
   
   # Check security headers
   curl -I https://yourdomain.com
   # Should show HSTS, X-Frame-Options, etc.
   ```

---

## Step 5: Testing HTTPS Configuration

### Test Checklist:

1. **HTTPS Redirect:**
   - Visit `http://yourdomain.com` → Should redirect to `https://yourdomain.com`

2. **Security Headers:**
   Use browser DevTools or curl:
   ```bash
   curl -I https://yourdomain.com
   ```
   Check for:
   - `Strict-Transport-Security` (HSTS)
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: strict-origin-when-cross-origin`

3. **Cookie Security:**
   - Check cookies in browser DevTools
   - Should have `Secure`, `HttpOnly`, and `SameSite` flags

4. **SSL Certificate:**
   - Visit site in browser
   - Check for green padlock icon
   - Verify certificate is valid and not expired

### Online Security Testing Tools:
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **Security Headers**: https://securityheaders.com/
- **Mozilla Observatory**: https://observatory.mozilla.org/

---

## Step 6: Common Issues and Solutions

### Issue 1: "Too Many Redirects" Error
**Cause:** `SECURE_SSL_REDIRECT=True` but proxy not sending `X-Forwarded-Proto`

**Solution:**
- Ensure reverse proxy sets `X-Forwarded-Proto: https` header
- Verify `SECURE_PROXY_SSL_HEADER` is correctly configured

### Issue 2: Cookies Not Working
**Cause:** `SESSION_COOKIE_SECURE=True` but site accessed via HTTP

**Solution:**
- Ensure all access is via HTTPS
- In development, set `SESSION_COOKIE_SECURE=False`

### Issue 3: CSRF Token Errors
**Cause:** `CSRF_COOKIE_SECURE=True` but site accessed via HTTP

**Solution:**
- Ensure all access is via HTTPS
- Check CORS settings if using API from different domain

### Issue 4: HSTS Not Working
**Cause:** HSTS requires HTTPS to be working first

**Solution:**
1. First ensure HTTPS works correctly
2. Then enable HSTS with small value (e.g., 300 seconds) for testing
3. Gradually increase to production value (31536000)

---

## Step 7: Production Deployment Checklist

Before going live, verify:

- [ ] SSL certificate is valid and not expired
- [ ] `SECURE_SSL_REDIRECT=True` in production `.env`
- [ ] `SESSION_COOKIE_SECURE=True` in production `.env`
- [ ] `CSRF_COOKIE_SECURE=True` in production `.env`
- [ ] `SECURE_HSTS_SECONDS=31536000` in production `.env`
- [ ] Reverse proxy configured correctly
- [ ] HTTP to HTTPS redirect working
- [ ] All security headers present
- [ ] Database SSL connection configured (`DB_SSLMODE=require`)
- [ ] `DEBUG=False` in production
- [ ] `ALLOWED_HOSTS` includes your domain
- [ ] Tested with SSL Labs (A or A+ rating)

---

## Step 8: Monitoring and Maintenance

### Regular Tasks:

1. **Certificate Renewal:**
   - Let's Encrypt certificates expire every 90 days
   - Set up auto-renewal: `sudo certbot renew --dry-run`

2. **Security Headers Monitoring:**
   - Regularly check with securityheaders.com
   - Monitor for new security recommendations

3. **SSL/TLS Updates:**
   - Keep Nginx/Apache updated
   - Monitor for deprecated TLS versions
   - Currently recommended: TLS 1.2 and TLS 1.3

4. **Log Monitoring:**
   - Monitor Django logs for SSL-related errors
   - Check reverse proxy logs for SSL handshake failures

---

## Additional Security Recommendations

### 1. Content Security Policy (CSP)
Consider installing `django-csp`:
```bash
pip install django-csp
```

Add to `INSTALLED_APPS`:
```python
INSTALLED_APPS = [
    # ... existing apps
    'csp',
]
```

### 2. Rate Limiting
Protect against brute force attacks:
```bash
pip install django-ratelimit
```

### 3. Security Headers Middleware
Consider using `django-security` for additional headers:
```bash
pip install django-security
```

### 4. Database Connection Security
Already configured in your settings:
- SSL mode: `require` or `verify-full` in production
- Connection timeout and max age configured

---

## Summary

Your Django project now has comprehensive HTTPS/SSL security configuration:

✅ **Fixed code issues** (imports, database config)  
✅ **Added HTTPS redirect** (SECURE_SSL_REDIRECT)  
✅ **Secure cookies** (Secure, HttpOnly, SameSite)  
✅ **HSTS enabled** (HTTP Strict Transport Security)  
✅ **Security headers** (X-Frame-Options, Content-Type, etc.)  
✅ **Environment-based configuration** (dev vs production)

**Next Steps:**
1. Update your `.env` file with HTTPS settings
2. Set up SSL certificate (Let's Encrypt recommended)
3. Configure reverse proxy (Nginx/Apache)
4. Test HTTPS configuration
5. Deploy to production with production settings

For questions or issues, refer to Django's security documentation:
https://docs.djangoproject.com/en/5.2/topics/security/

