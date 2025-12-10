# Secure E-Commerce API - Complete Implementation

A comprehensive, production-ready secure e-commerce API built with Django REST Framework, featuring enterprise-grade security practices.

## 🎯 Features

### Core Features
- ✅ **User Authentication & Authorization**
  - JWT-based authentication with token rotation
  - Role-Based Access Control (RBAC)
  - Multi-Factor Authentication (MFA) with TOTP
  - Account lockout after failed attempts

- ✅ **Product Management**
  - CRUD operations for products
  - Stock management
  - Seller-specific product management
  - Product search and filtering

- ✅ **Order Management**
  - Order creation with automatic stock reduction
  - Order status tracking
  - Order cancellation with stock restoration
  - Customer order history

- ✅ **Review System**
  - Product reviews and ratings
  - Review approval workflow
  - Verified purchase badges
  - Helpful vote tracking

### Security Features

#### Authentication & Authorization
- **JWT Authentication**: Short-lived access tokens (15 minutes) with refresh tokens
- **MFA/TOTP**: Time-based One-Time Password support with QR code setup
- **Biometric Authentication**: WebAuthn support for Face ID, Touch ID, Windows Hello, and hardware security keys (FIDO2)
- **Passwordless Login**: Biometric authentication enables passwordless login
- **AI-Powered Monitoring**: Autonomous AI agent for health monitoring and automatic remediation
- **Admin Dashboard**: Comprehensive dashboard showing system health, alerts, incidents, and AI actions
- **Role-Based Access Control**: Fine-grained permissions (Admin, Seller, Customer)
- **Account Lockout**: Automatic lockout after failed login attempts
- **Django Axes**: Brute force protection with configurable lockout

#### Input Validation & Sanitization
- **Comprehensive Validation**: All inputs validated at serializer level
- **SQL Injection Prevention**: Django ORM prevents SQL injection
- **XSS Protection**: Content Security Policy and input sanitization
- **CSRF Protection**: Built-in CSRF protection for state-changing operations

#### Rate Limiting
- **Per-User Rate Limiting**: Configurable limits per authenticated user
- **Per-IP Rate Limiting**: Protection against anonymous abuse
- **Endpoint-Specific Limits**: Different limits for different operations
- **Sliding Window Algorithm**: Fair and accurate rate limiting

#### Security Headers
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME type sniffing prevention
- **Referrer-Policy**: Control referrer information leakage
- **Permissions-Policy**: Restrict browser features

#### Audit Logging
- **Comprehensive Logging**: All security-relevant events logged
- **IP Tracking**: Client IP addresses logged for security analysis
- **User Agent Tracking**: Help identify bot traffic
- **Metadata Storage**: Flexible JSON metadata for event-specific data
- **Non-Intrusive**: Logging failures don't affect request processing

#### Advanced Security Features
- **Secrets Management**: Encryption utilities for sensitive data
- **Enhanced Rate Limiting**: Sliding window algorithm
- **Biometric Authentication Support**: WebAuthn foundation
- **Security Event Monitoring**: Threat detection and anomaly detection
- **Encryption Utilities**: Secure token generation and hashing

## 📁 Project Structure

```
secure_ecommerce_project/
├── authentication/          # Authentication and authorization
│   ├── models.py           # User, Role, AuditLog models
│   ├── views.py            # Authentication endpoints
│   ├── serializers.py      # User and role serializers
│   ├── middleware.py       # Audit logging and security headers
│   ├── totp_utils.py       # TOTP/MFA utilities
│   └── advanced_security.py # Advanced security features
├── products/               # Product management
│   ├── models.py           # Product model
│   ├── views.py            # Product ViewSet
│   └── serializers.py      # Product serializers
├── orders/                 # Order management
│   ├── models.py           # Order and OrderItem models
│   ├── views.py            # Order ViewSet
│   └── serializers.py      # Order serializers
├── reviews/                # Review system
│   ├── models.py           # Review model
│   ├── views.py            # Review ViewSet
│   └── serializers.py      # Review serializers
└── secure_ecommerce_project/
    ├── settings.py         # Django settings with security configs
    └── urls.py             # URL routing
```

## 🚀 Installation

### Prerequisites
- Python 3.14+
- PostgreSQL 12+
- Redis (optional, for caching and rate limiting)

### Setup

1. **Clone the repository**
   ```bash
   cd secure_ecommerce_project
   ```

2. **Install dependencies**
   ```bash
   pipenv install
   # or
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   Create a `.env` file based on `env.example.txt`:
   ```env
   SECRET_KEY=your-secret-key-here
   DEBUG=True
   ALLOWED_HOSTS=localhost,127.0.0.1
   CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200
   
   DB_NAME=ecommerce_db
   DB_USER=ecommerce_user
   DB_PASSWORD=secure_password
   DB_HOST=localhost
   DB_PORT=5432
   DB_CON_TIMEOUT=10
   DB_SSLMODE=prefer
   DB_CON_MAX_AGE=600
   ```

4. **Run migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Run development server**
   ```bash
   python manage.py runserver
   ```

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `GET /api/auth/me/` - Get current user
- `GET /api/auth/users/` - List users (Admin only)
- `POST /api/auth/assign-roles/` - Assign roles (Admin only)
- `GET /api/auth/roles/` - List roles (Admin only)
- `POST /api/auth/roles/` - Create role (Admin only)

### TOTP/MFA
- `POST /api/auth/totp/setup/` - Set up TOTP (returns QR code)
- `POST /api/auth/totp/verify/` - Verify TOTP code and enable MFA
- `POST /api/auth/totp/disable/` - Disable MFA

### WebAuthn/Biometric Authentication (Face ID, Touch ID, etc.)
- `POST /api/auth/webauthn/register/start/` - Start biometric registration (returns options)
- `POST /api/auth/webauthn/register/complete/` - Complete biometric registration
- `POST /api/auth/webauthn/authenticate/start/` - Start biometric authentication (passwordless login)
- `POST /api/auth/webauthn/authenticate/complete/` - Complete biometric authentication
- `GET /api/auth/webauthn/credentials/` - List user's biometric credentials
- `POST /api/auth/webauthn/revoke/` - Revoke a biometric credential

### Products
- `GET /api/products/` - List products
- `POST /api/products/` - Create product (Seller/Admin)
- `GET /api/products/{id}/` - Get product details
- `PUT /api/products/{id}/` - Update product (Owner/Admin)
- `PATCH /api/products/{id}/` - Partial update (Owner/Admin)
- `DELETE /api/products/{id}/` - Delete product (Owner/Admin)
- `POST /api/products/{id}/update_stock/` - Update stock (Owner/Admin)

### Orders
- `GET /api/orders/` - List orders (own orders for customers, all for admins)
- `POST /api/orders/` - Create order
- `GET /api/orders/{id}/` - Get order details
- `PUT /api/orders/{id}/` - Update order
- `POST /api/orders/{id}/cancel/` - Cancel order
- `POST /api/orders/{id}/update_status/` - Update order status (Admin/Seller)

### Reviews
- `GET /api/reviews/` - List reviews (approved only for anonymous)
- `POST /api/reviews/` - Create review
- `GET /api/reviews/{id}/` - Get review details
- `PUT /api/reviews/{id}/` - Update review (Owner/Admin)
- `DELETE /api/reviews/{id}/` - Delete review (Owner/Admin)
- `POST /api/reviews/{id}/approve/` - Approve review (Admin)
- `POST /api/reviews/{id}/mark_helpful/` - Mark review as helpful

### File Uploads
- `POST /api/files/` - Upload a file (with validation)
- `GET /api/files/` - List files (own files + public files)
- `GET /api/files/{id}/` - Get file details
- `PUT /api/files/{id}/` - Update file metadata (Owner/Admin)
- `DELETE /api/files/{id}/` - Delete file (Owner/Admin)
- `GET /api/files/{id}/download/` - Download file (access controlled)
- `POST /api/files/{id}/verify/` - Verify file (Admin only)
- `GET /api/files/my_files/` - Get current user's files

### Monitoring & AI Agent Dashboard
- `GET /api/monitoring/dashboard/` - Get comprehensive dashboard data (Admin only)
- `GET /api/monitoring/metrics/` - List health metrics (Admin only)
- `GET /api/monitoring/alerts/` - List alerts (Admin only)
- `POST /api/monitoring/alerts/{id}/acknowledge/` - Acknowledge alert (Admin only)
- `POST /api/monitoring/alerts/{id}/resolve/` - Resolve alert (Admin only)
- `GET /api/monitoring/incidents/` - List incidents (Admin only)
- `GET /api/monitoring/ai-actions/` - List AI agent actions (Admin only)
- `POST /api/monitoring/ai-actions/trigger_monitoring/` - Trigger monitoring cycle (Admin only)
- `GET /api/monitoring/health/` - List system health snapshots (Admin only)

## 🔐 Security Best Practices Implemented

1. **Authentication**
   - Short-lived JWT tokens (15 minutes)
   - Refresh token rotation
   - MFA/TOTP support
   - Account lockout after failed attempts

2. **Authorization**
   - Role-Based Access Control (RBAC)
   - Permission checks at ViewSet level
   - Resource ownership validation

3. **Input Validation**
   - Serializer-level validation
   - Model-level constraints
   - Type checking and sanitization

4. **Rate Limiting**
   - Per-user limits
   - Per-IP limits
   - Endpoint-specific limits
   - Sliding window algorithm

5. **Security Headers**
   - HSTS
   - CSP
   - X-Frame-Options
   - X-Content-Type-Options
   - Referrer-Policy
   - Permissions-Policy

6. **Audit Logging**
   - All security events logged
   - IP and user agent tracking
   - Non-intrusive logging

7. **Brute Force Protection**
   - Django Axes integration
   - Configurable lockout thresholds
   - IP and username tracking

## 🧪 Testing

Run tests:
```bash
python manage.py test
```

## 📚 Documentation

### Security Decorators

#### `@role_required(*role_names)`
Decorator to enforce role-based access:
```python
@role_required("ADMIN", "SELLER")
def my_view(request):
    ...
```

### Rate Limiting

Rate limiting is implemented using `@ratelimit` decorator:
```python
@method_decorator(ratelimit(key='user', rate='10/m', method='POST'))
def create(self, request):
    ...
```

### ViewSets

All models use ViewSets with comprehensive security:
- Permission checks
- Rate limiting
- Audit logging
- Input validation

## 🔧 Configuration

### Django Axes
Configure in `settings.py`:
- `AXES_FAILURE_LIMIT`: Failed attempts before lockout (default: 5)
- `AXES_COOLOFF_TIME`: Lockout duration in hours (default: 1)
- `AXES_LOCKOUT_PARAMETERS`: What to track (IP, username, etc.)

### Rate Limiting
Configure in `settings.py`:
- `REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']`: Global rate limits
- Per-endpoint limits using `@ratelimit` decorator

### TOTP/MFA
Configure in `settings.py`:
- `TOTP_ISSUER_NAME`: Name shown in authenticator apps
- `TOTP_INTERVAL`: Time step in seconds (default: 30)
- `TOTP_DIGITS`: Number of digits (default: 6)
- `TOTP_WINDOW`: Clock skew tolerance (default: 1)

## 🚨 Security Considerations

1. **Production Deployment**
   - Set `DEBUG=False`
   - Use strong `SECRET_KEY`
   - Enable HTTPS (`SECURE_SSL_REDIRECT=True`)
   - Configure proper CORS origins
   - Use Redis for caching and rate limiting
   - Encrypt TOTP secrets at rest
   - Use environment variables for sensitive configs

2. **Database**
   - Use SSL connections (`DB_SSLMODE=require`)
   - Regular backups
   - Connection pooling
   - Proper indexing

3. **Monitoring**
   - Monitor audit logs
   - Set up alerts for security events
   - Track failed authentication attempts
   - Monitor API usage patterns

## 📝 License

This project is for educational purposes as part of the Secure Programming course at ISG Tunis.

## 👨‍💻 Author

Chaouki Bayoudhi  
Institut Supérieur de Gestion de Tunis  
Department of Computer Science

## 🙏 Acknowledgments

- Django REST Framework
- Django Axes
- pyotp for TOTP implementation
- All security best practices from OWASP

