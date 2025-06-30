# Changelog

All notable changes to the Ricardo Auth Spring Boot Starter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-24

### Added
- **Initial Release** of Ricardo Auth Spring Boot Starter
- **JWT Authentication**: Complete JWT token generation, validation, and management
- **User Management**: CRUD operations for user entities with domain-driven design
- **Auto-Configuration**: Spring Boot auto-configuration for zero-setup experience
- **Security Integration**: Built-in Spring Security configuration with sensible defaults
- **REST API Endpoints**: Pre-built authentication and user management endpoints
- **Role-Based Access Control**: Support for USER and ADMIN roles with extensible role system
- **Password Security**: BCrypt password hashing with automatic salt generation
- **Configuration Properties**: Comprehensive configuration options via `ricardo.auth` prefix
- **Domain Objects**: Clean domain entities with value objects (Username, Email, Password)
- **Exception Handling**: Global exception handling with proper error responses
- **Validation**: Input validation with Bean Validation (JSR-303)
- **Documentation**: Comprehensive documentation with examples and guides

### Security Features
- **JWT Token Security**: HMAC SHA-256 signing with configurable secrets
- **Password Encryption**: BCrypt with secure defaults
- **Input Validation**: Protection against malicious input
- **CORS Support**: Configurable cross-origin resource sharing
- **Authorization**: Method-level security with `@PreAuthorize`

### API Endpoints
- `POST /api/auth/login` - User authentication with JWT token response
- `GET /api/auth/me` - Get current authenticated user information
- `POST /api/users/create` - Create new user account
- `GET /api/users/{id}` - Get user by ID
- `GET /api/users/email/{email}` - Get user by email
- `GET /api/users/exists/{email}` - Check if user exists
- `PUT /api/users/update/{id}` - Update user information
- `DELETE /api/users/delete/{id}` - Delete user account

### Configuration Options
- `ricardo.auth.enabled` - Enable/disable auth module
- `ricardo.auth.jwt.secret` - JWT signing secret (required)
- `ricardo.auth.jwt.expiration` - Token expiration time in milliseconds
- `ricardo.auth.controllers.auth.enabled` - Enable/disable auth endpoints
- `ricardo.auth.controllers.user.enabled` - Enable/disable user endpoints

### Dependencies
- **Spring Boot**: 3.5.3
- **Spring Security**: 6.x
- **Spring Data JPA**: 3.x
- **JWT**: io.jsonwebtoken:jjwt-api:0.12.6
- **Java**: 21+ (compatible with 17+)

### Build and Distribution
- **Maven Central**: Available at `io.github.ricardomorim:auth-spring-boot-starter:1.0.0`
- **GitHub Packages**: Alternative distribution channel
- **License**: MIT License
- **Source Code**: Available on [GitHub](https://github.com/RicardoMorim/Auth-Provider)

### Documentation
- Comprehensive README with quick start guide
- [Configuration Guide](docs/configuration-guide.md) - Detailed configuration options
- [API Reference](docs/api-reference.md) - Complete API documentation
- [Security Guide](docs/security-guide.md) - Security best practices
- [Examples](docs/examples.md) - Real-world usage examples
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

### Testing
- **Unit Tests**: Complete test coverage for core functionality
- **Integration Tests**: End-to-end authentication flow testing
- **Security Tests**: Authentication and authorization testing
- **Test Utilities**: Helper classes for testing applications using the starter

### Performance
- **Stateless Design**: JWT-based stateless authentication
- **Database Optimization**: Indexed queries for user lookups
- **Connection Pooling**: HikariCP integration for database connections
- **Caching**: Prepared for future caching enhancements

### Compatibility
- **Spring Boot**: 3.4.x - 3.5.x
- **Java**: 17, 21
- **Databases**: H2, PostgreSQL, MySQL, MariaDB (via JPA)
- **Build Tools**: Maven 3.6+

## [1.0.1] - 2025-06-24

### Added
- **Comprehensive Documentation Suite**: Complete documentation overhaul with detailed guides
  - [Configuration Guide](docs/configuration-guide.md) - Complete configuration reference with examples
  - [API Reference](docs/api-reference.md) - Detailed REST API documentation with examples
  - [Security Guide](docs/security-guide.md) - Security best practices and implementation guidelines
  - [Examples](docs/examples.md) - Real-world usage examples for different application types
  - [Troubleshooting Guide](docs/troubleshooting.md) - Common issues and debugging solutions
  - [Documentation Index](docs/index.md) - Navigation and organization of all documentation
- **Spring Boot Auto-Configuration**: Enhanced auto-configuration with `AuthAutoConfiguration` and `AuthProperties`
  - `AuthAutoConfiguration` class for automatic bean configuration and component scanning
  - `AuthProperties` class for comprehensive configuration property management
  - Conditional bean creation based on configuration properties
- **Configurable Controllers**: Ability to enable/disable auth and user management endpoints independently
- **User Security Service**: Custom authorization logic with `UserSecurityService` for fine-grained access control
- **Enhanced Error Handling**: Improved global exception handling with detailed error responses
- **Maven Central Publishing**: Proper configuration for publishing to Maven Central with GPG signing
- **GitHub Packages Support**: Alternative distribution channel configuration

### Improved
- **Code Documentation**: Added comprehensive JavaDoc comments to all public classes and methods
  - Complete JavaDoc coverage for all public APIs in main source code
  - Detailed parameter and return value documentation
  - Usage examples and security considerations in documentation
- **Test Coverage**: Enhanced test suite with detailed JavaDoc and improved test organization
  - Improved `GlobalExceptionHandlerTest` with comprehensive error scenario testing (25+ test methods)
  - Enhanced `AuthControllerTest` with better authentication flow testing
  - Improved `UserControllerTest` with validation and error handling tests
  - Added `DomainObjectsTest` for comprehensive domain validation testing (40+ test methods)
  - Added `DtoAndMappingTest` for DTO validation and mapping testing
  - Enhanced `JwtAuthFilterTest` with comprehensive filter testing scenarios
  - Improved `SecurityIntegrationTest` with end-to-end security testing
  - Enhanced `UserServiceImplTest` and `UserDetailsServiceImplTest` with comprehensive service layer testing
  - Better test documentation with descriptive JavaDoc comments
- **Domain Value Objects**: Better validation and error messages for `Email`, `Username`, and `Password`
- **Security Configuration**: Enhanced security setup with proper authentication entry points
- **Project Structure**: Better organization with auto-configuration package and cleaner separation of concerns

### Fixed
- **POM Configuration**: Corrected SCM URLs and improved Maven publishing configuration
  - Fixed GitHub repository URL in SCM section
  - Enhanced Maven publishing configuration with profiles for GitHub Packages and Maven Central
  - Improved dependency management and exclusion configuration
- **Import Organization**: Cleaned up imports and removed unused dependencies across all source files
- **Authentication Flow**: Fixed security configuration for proper JWT authentication
- **Exception Handling**: Improved error message formatting and status code consistency

### Documentation
- **README Enhancement**: Updated with comprehensive installation, configuration, and usage examples
- **CONTRIBUTING Guide**: Detailed contribution guidelines with development setup and coding standards
- **LICENSE**: Added MIT License for clear usage rights
- **CHANGELOG**: Structured changelog following semantic versioning principles

### Development Experience
- **Better Testing**: Comprehensive test examples for integration and unit testing
- **Development Setup**: Improved local development configuration with H2 database support
- **Environment Configuration**: Better separation of development, testing, and production configurations
- **Debug Support**: Enhanced logging configuration and debugging tools

### Technical Debt Reduction
- **Code Quality**: Consistent code formatting and style across all source files
- **Test Organization**: Better test structure with clear separation of concerns
- **Documentation Consistency**: Standardized documentation format and style
- **Build Process**: Improved Maven configuration for reliable builds and publishing

### Breaking Changes
- None. This release maintains full backward compatibility with v1.0.0

### Migration Notes
- No migration required from v1.0.0
- New configuration options are optional and have sensible defaults
- Existing applications will continue to work without changes

## [1.0.2] - 2025-06-24

### Added
- **Fixed errors for proper Maven publishing**: Corrected SCM URLs and improved POM configuration

### Migration Notes
- No migration required from v1.0.1
- Existing applications will continue to work without changes
- 
## [1.1.0] - 2024-01-15

### 🔒 Added - Password Policy System
- **Comprehensive Password Validation**: Configurable password strength requirements
  - Minimum/maximum length validation
  - Character type requirements (uppercase, lowercase, digits, special characters)
  - Customizable special character sets
  - Common password prevention with built-in protection list
- **Password Policy Configuration**: Full control over password requirements via `ricardo.auth.password-policy`
- **Enhanced Error Messages**: Detailed validation feedback for password policy violations
- **Environment-Specific Policies**: Different password requirements for development vs production

### 📚 Documentation Improvements
- **Restructured README**: Clearer quick start guide with step-by-step instructions
- **Improved Navigation**: Better organized documentation index with role-based guides
- **Enhanced Examples**: More practical, real-world usage examples with complete code
- **Better Troubleshooting**: Emergency quick fixes section with searchable error messages
- **Configuration Clarity**: Simplified configuration guide with quick setup options
- **Password Policy Guide**: Comprehensive documentation for new password policy features

### 🔧 Technical Improvements
- **Bean Configuration**: Improved auto-configuration to prevent bean creation conflicts
- **Repository Architecture**: Better separation with `@NoRepositoryBean` annotations
- **Test Coverage**: Updated all tests to use password policy compliant passwords
- **Error Handling**: Enhanced error responses for password policy violations

### 🏗 Breaking Changes
- **Password Requirements**: Existing passwords may need to meet new policy requirements
- **Default Password Policy**: Minimum 8 characters with character type requirements enabled by default

### ⚙️ New Configuration Options
```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                    # Default minimum length
      max-length: 128                  # Default maximum length
      require-uppercase: true          # Require A-Z characters
      require-lowercase: true          # Require a-z characters
      require-digits: true             # Require 0-9 characters
      require-special-chars: true      # Require special characters
      special-characters: "!@#$%^&*"   # Allowed special characters
      prevent-common-passwords: true   # Block common passwords
      common-passwords-file: "/commonpasswords.txt" # Custom password list
```

### 🔄 Migration Guide
- **Existing Users**: Current users with weak passwords can still log in but will need to update passwords on next change
- **New Users**: All new user registrations must meet the configured password policy
- **Custom Policies**: Configure `ricardo.auth.password-policy.min-length: 6` for backwards compatibility

---

## [Unreleased]

### Planned Features
- **Refresh Token Support**: Automatic token refresh mechanism
- **Social Login**: OAuth2 integration with Google, GitHub, Facebook
- **Multi-Factor Authentication**: TOTP and SMS-based 2FA
- **Rate Limiting**: Built-in rate limiting for authentication endpoints
- **Audit Logging**: Comprehensive security event logging
- **Password Policy**: Configurable password complexity requirements
- **Account Management**: Email verification, password reset, account locking
- **Redis Cache**: Caching integration for improved performance
- **Metrics Integration**: Micrometer metrics for monitoring
- **WebFlux Support**: Reactive web stack compatibility
- **Kotlin Support**: Kotlin DSL configuration support



### Breaking Changes (Future Versions)
> No breaking changes planned for 1.x series. Major version increments will be used for breaking changes.



## Version Support Policy

| Version | Status | Support Until | Notes |
|---------|--------|---------------|-------|
| 1.x     | Active | TBD          | Current stable release |
| 0.x     | N/A    | N/A          | Pre-release versions |

## Security Updates

Security updates will be released as patch versions (e.g., 1.0.1, 1.0.2) and will be clearly marked in this changelog. 

### Security Policy
- **Critical/High**: Immediate release (as soon as possible)
- **Medium**: Within 30 days
- **Low**: Next regular release

## Deprecation Policy

Features will be deprecated with at least one minor version notice before removal:

1. **Deprecation Notice**: Feature marked as deprecated with removal timeline
2. **Migration Path**: Alternative solutions provided
3. **Removal**: Feature removed in next major version

## Release Schedule

- **Major Releases**: Annually (breaking changes)
- **Minor Releases**: Quarterly (new features, backward compatible)
- **Patch Releases**: As needed (bug fixes, security updates)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### Legend
- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security fixes and improvements

### Version Format
- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible functionality additions
- **PATCH**: Backward-compatible bug fixes
