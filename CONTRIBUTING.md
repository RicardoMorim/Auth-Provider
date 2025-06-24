# Contributing to Ricardo Auth Spring Boot Starter

Thank you for your interest in contributing to the Ricardo Auth Spring Boot Starter! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [How to Contribute](#how-to-contribute)
4. [Development Setup](#development-setup)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Documentation](#documentation)
8. [Pull Request Process](#pull-request-process)
9. [Issue Reporting](#issue-reporting)
10. [Community](#community)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior to [ricardomorim05@gmail.com](mailto:ricardomorim05@gmail.com).

### Our Pledge

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive criticism
- Prioritize the community's well-being

## Getting Started

### Prerequisites

- **Java 21**
- **Maven 3.6+**
- **Git**
- **IDE**: IntelliJ IDEA (recommended) or Eclipse

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Auth-Provider.git
   cd Auth-Provider
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/RicardoMorim/Auth-Provider.git
   ```

## How to Contribute

### Types of Contributions

We welcome the following types of contributions:

1. **Bug Fixes**: Resolve issues in existing functionality
2. **Feature Enhancements**: Improve existing features
3. **New Features**: Add new functionality
4. **Documentation**: Improve or add documentation
5. **Testing**: Add or improve test coverage
6. **Performance**: Optimize performance
7. **Security**: Address security concerns

### Contribution Process

1. **Check existing issues**: Look for existing issues or create a new one
2. **Discuss**: For major changes, discuss your approach in the issue
3. **Fork and branch**: Create a feature branch from `main`
4. **Develop**: Implement your changes following our guidelines
5. **Test**: Ensure all tests pass and add new tests
6. **Document**: Update documentation as needed
7. **Submit**: Create a pull request

## Development Setup

### Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/RicardoMorim/Auth-Provider.git
   cd Auth-Provider
   ```

2. **Install dependencies**:
   ```bash
   mvn clean install
   ```

3. **Run tests**:
   ```bash
   mvn test
   ```

4. **Set up environment variables**:
   ```bash
   export RICARDO_AUTH_JWT_SECRET="development-secret-key-for-testing"
   ```

### IDE Configuration

#### IntelliJ IDEA

1. **Import Project**: File → Open → Select the `pom.xml`
2. **Code Style**: 
   - File → Settings → Editor → Code Style → Java
   - Import the project's code style (if available)
3. **Enable Annotations**: 
   - File → Settings → Build → Compiler → Annotation Processors
   - Enable annotation processing

#### Eclipse

1. **Import Project**: File → Import → Existing Maven Projects
2. **Code Formatter**: Import the project's formatter configuration
3. **Enable Annotation Processing**: Project Properties → Java Build Path → Annotation Processing

### Database Setup

For development, use H2 database:

```yaml
# application-dev.yml
spring:
  datasource:
    url: jdbc:h2:mem:devdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  h2:
    console:
      enabled: true
      path: /h2-console
```

## Coding Standards


#### Naming Conventions

```java
// Classes: PascalCase
public class UserService {

// Methods: camelCase
public void createUser() {

// Variables: camelCase
private String userName;

// Constants: UPPER_SNAKE_CASE
private static final String DEFAULT_ROLE = "USER";

// Packages: lowercase with dots
package com.ricardo.auth.service;
```

#### Code Examples

**Good:**
```java
@Service
@Transactional
public class UserServiceImpl implements UserService {
    
    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    public User createUser(User user) {
        validateUser(user);
        
        if (userRepository.existsByEmail(user.getEmail().getValue())) {
            throw new UserAlreadyExistsException("User already exists: " + user.getEmail().getValue());
        }
        
        User savedUser = userRepository.save(user);
        logger.info("Created user with ID: {}", savedUser.getId());
        
        return savedUser;
    }
    
    private void validateUser(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        // Additional validation
    }
}
```

### Documentation Standards

#### JavaDoc

All public classes and methods should have comprehensive JavaDoc:

```java
/**
 * Service for managing user accounts and authentication.
 * 
 * <p>This service provides comprehensive user management functionality including
 * user creation, authentication, and profile management. It integrates with
 * Spring Security for authentication and authorization.
 * 
 * @author Ricardo
 * @since 1.0.0
 */
@Service
public class UserService {
    
    /**
     * Creates a new user account with the provided information.
     * 
     * <p>This method validates the user information, checks for duplicates,
     * encrypts the password, and persists the user to the database.
     * 
     * @param user the user to create, must not be null
     * @return the created user with generated ID
     * @throws UserAlreadyExistsException if a user with the same email exists
     * @throws IllegalArgumentException if user is null or invalid
     * @since 1.0.0
     */
    public User createUser(User user) {
        // Implementation
    }
}
```

#### Comments

- Use comments sparingly and only when necessary
- Prefer self-documenting code
- Comment complex algorithms and business logic

```java
// Good: Explains why, not what
// Use BCrypt with strength 12 for enhanced security in production
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

// Bad: Explains what (obvious from code)
// Create a new BCrypt password encoder
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
```

## Testing Guidelines

### Test Structure

Follow the AAA pattern (Arrange, Act, Assert):

```java
@Test
void shouldCreateUserSuccessfully() {
    // Arrange
    CreateUserRequestDTO request = new CreateUserRequestDTO();
    request.setUsername("testuser");
    request.setEmail("test@example.com");
    request.setPassword("password123");
    
    // Act
    UserDTO result = userService.createUser(request);
    
    // Assert
    assertThat(result).isNotNull();
    assertThat(result.getUsername()).isEqualTo("testuser");
    assertThat(result.getEmail()).isEqualTo("test@example.com");
}
```

### Test Categories

#### Unit Tests

```java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @InjectMocks
    private UserServiceImpl userService;
    
    @Test
    void shouldCreateUserWhenValidInput() {
        // Test implementation
    }
}
```

#### Integration Tests

```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@Transactional
class UserControllerIntegrationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    void shouldCreateUserViaRestAPI() {
        // Test implementation
    }
}
```

#### Security Tests

```java
@SpringBootTest
@AutoConfigureTestDatabase
class SecurityIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    @WithMockUser(roles = "USER")
    void shouldAllowAuthenticatedUserAccess() {
        // Test implementation
    }
}
```

### Test Requirements

- **Coverage**: Maintain at least 80% code coverage
- **Naming**: Use descriptive test method names
- **Data**: Use test-specific data, not production data
- **Isolation**: Tests should be independent and can run in any order
- **Performance**: Keep tests fast (unit tests < 1s, integration tests < 10s)

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=UserServiceTest

# Run with coverage
mvn test jacoco:report

# Run integration tests only
mvn test -Dtest=*IntegrationTest
```

## Documentation

### Types of Documentation

1. **Code Documentation**: JavaDoc and inline comments
2. **User Documentation**: README, guides, and tutorials
3. **API Documentation**: REST API documentation
4. **Developer Documentation**: Setup and contribution guides

### Documentation Standards

- **Clarity**: Write for your target audience
- **Examples**: Include practical examples
- **Completeness**: Cover all public APIs
- **Maintenance**: Keep documentation up-to-date

### Updating Documentation

When making changes, update relevant documentation:

- **README.md**: For user-facing changes
- **API Documentation**: For endpoint changes
- **Configuration Guide**: For new configuration options
- **Examples**: For new features or usage patterns

## Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes and commit**:
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

4. **Run tests**:
   ```bash
   mvn clean test
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

### Pull Request Template

When creating a pull request, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs tests
2. **Code review**: Maintainers review the code
3. **Feedback**: Address review comments
4. **Approval**: At least one maintainer approval required
5. **Merge**: Maintainer merges the PR

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

**Examples:**
```
feat(auth): add refresh token support
fix(security): resolve JWT validation issue
docs(readme): update installation instructions
test(user): add integration tests for user creation
```

## Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Describe the bug**
A clear description of the bug

**To Reproduce**
Steps to reproduce the behavior

**Expected behavior**
What you expected to happen

**Environment:**
- OS: [e.g., Windows 10]
- Java Version: [e.g., 17]
- Spring Boot Version: [e.g., 3.5.3]
- Starter Version: [e.g., 1.0.0]

**Additional context**
Any other context about the problem
```

### Feature Requests

Use the feature request template:

```markdown
**Is your feature request related to a problem?**
Description of the problem

**Describe the solution you'd like**
Clear description of what you want to happen

**Describe alternatives you've considered**
Alternative solutions or features considered

**Additional context**
Any other context or screenshots
```

### Security Issues

For security issues:
1. **Do not create a public issue**
2. **Email**: [ricardomorim05@gmail.com](mailto:ricardomorim05@gmail.com)
3. **Include**: Detailed description and steps to reproduce
4. **Response**: We'll respond as soon as possible

## Community

### Communication Channels

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions and discussions
- **Email**: [ricardomorim05@gmail.com](mailto:ricardomorim05@gmail.com) for direct contact

### Getting Help

1. **Documentation**: Check existing documentation first
2. **Search Issues**: Look for existing issues
3. **Ask Questions**: Use GitHub Discussions
4. **Stack Overflow**: Tag questions with `ricardo-auth-starter`

### Recognition

Contributors will be recognized in:
- **Contributors section** in README
- **Changelog** for significant contributions
- **GitHub releases** notes

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Ricardo Auth Spring Boot Starter! Your contributions help make authentication easier for Spring Boot developers worldwide.
