package com.ricardo.auth.autoconfig;

import com.ricardo.auth.blocklist.InMemoryTokenBlocklist;
import com.ricardo.auth.blocklist.RedisTokenBlockList;
import com.ricardo.auth.config.UserSecurityService;
import com.ricardo.auth.controller.AuthController;
import com.ricardo.auth.controller.UserController;
import com.ricardo.auth.core.*;
import com.ricardo.auth.domain.user.AppRole;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.factory.AuthUserFactory;
import com.ricardo.auth.factory.UserFactory;
import com.ricardo.auth.helper.*;
import com.ricardo.auth.ratelimiter.InMemoryRateLimiter;
import com.ricardo.auth.ratelimiter.RedisRateLimiter;
import com.ricardo.auth.repository.PasswordResetToken.DefaultJpaPasswordResetTokenRepository;
import com.ricardo.auth.repository.PasswordResetToken.PasswordResetTokenRepository;
import com.ricardo.auth.repository.PasswordResetToken.PostgreSqlPasswordResetTokenRepository;
import com.ricardo.auth.repository.refreshToken.DefaultJpaRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.PostgreSQLRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
import com.ricardo.auth.repository.user.UserPostgreSQLRepository;
import com.ricardo.auth.repository.user.UserRepository;
import com.ricardo.auth.security.JwtAuthFilter;
import com.ricardo.auth.service.*;
import com.zaxxer.hikari.HikariDataSource;
import io.github.cdimascio.dotenv.Dotenv;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.util.Properties;
import java.util.UUID;

/**
 * Auto-configuration for Ricardo Auth Starter.
 * <p>
 * This configuration automatically selects the appropriate database driver and repository implementation
 * based on the configuration properties and available dependencies.
 */
@AutoConfiguration
@ConditionalOnClass({User.class, JwtService.class})
@ConditionalOnProperty(prefix = "ricardo.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuthProperties.class)
@ComponentScan(basePackages = "com.ricardo.auth")
public class AuthAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(AuthAutoConfiguration.class);

    /**
     * Jwt service.
     *
     * @param authProperties the auth properties
     * @return the jwt service
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(AuthProperties authProperties) {
        return new JwtServiceImpl(authProperties);
    }

    // ========== COMMON SERVICES ==========

    /**
     * User service.
     *
     * @param userRepository the user repository
     * @param eventPublisher the event publisher
     * @param cacheManager   the cache manager
     * @return the user service
     */
    @Bean
    @ConditionalOnMissingBean
    public UserService<User, AppRole, UUID> userService(UserRepository<User, AppRole, UUID> userRepository, EventPublisher eventPublisher, CacheHelper<User, AppRole, UUID> cacheManager) {
        return new UserServiceImpl<>(userRepository, eventPublisher, cacheManager);
    }

    /**
     * User security service user security service.
     *
     * @param userService the user service
     * @param idConverter the id converter
     * @return the user security service
     */
    @Bean
    @ConditionalOnMissingBean
    public UserSecurityService<User, AppRole, UUID> userSecurityService(UserService<User, AppRole, UUID> userService, IdConverter<UUID> idConverter) {
        return new UserSecurityService<>(userService, idConverter);
    }

    /**
     * Refresh token service refresh token service.
     *
     * @param refreshTokenRepository the refresh token repository
     * @param userService            the user service
     * @param authProperties         the auth properties
     * @return the refresh token service
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens", name = "enabled", havingValue = "true", matchIfMissing = true)
    public RefreshTokenService<User, AppRole, UUID> refreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserService<User, AppRole, UUID> userService,
            AuthProperties authProperties) {

        return new RefreshTokenServiceImpl<>(refreshTokenRepository, userService, authProperties);
    }

    /**
     * User details service user details service.
     *
     * @param userService the user service
     * @return the user details service
     */
    @Bean
    @ConditionalOnMissingBean
    public UserDetailsServiceImpl<User, AppRole, UUID> userDetailsService(UserService<User, AppRole, UUID> userService) {
        return new UserDetailsServiceImpl<>(userService);
    }

    /**
     * Jwt auth filter jwt auth filter.
     *
     * @param jwtService     the jwt service
     * @param tokenBlocklist the token blocklist
     * @param authProperties the auth properties
     * @return the jwt auth filter
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService, TokenBlocklist tokenBlocklist, AuthProperties authProperties) {
        return new JwtAuthFilter(jwtService, tokenBlocklist, authProperties);
    }

    /**
     * Password policy service password policy service.
     *
     * @param authProperties the auth properties
     * @return the password policy service
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicyService passwordPolicyService(AuthProperties authProperties) {
        return new PasswordPolicy(authProperties);
    }

    /**
     * Auth controller auth controller.
     *
     * @param jwtService          the jwt service
     * @param authManager         the auth manager
     * @param refreshTokenService the refresh token service
     * @param authProperties      the auth properties
     * @param tokenBlocklist      the token blocklist
     * @param publisher           the publisher
     * @param userService         the user service
     * @return the auth controller
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "auth.enabled", havingValue = "true", matchIfMissing = true)
    public AuthController<User, AppRole, UUID> authController(
            JwtService jwtService,
            AuthenticationManager authManager,
            RefreshTokenService<User, AppRole, UUID> refreshTokenService,
            AuthProperties authProperties,
            TokenBlocklist tokenBlocklist,
            EventPublisher publisher,
            UserService<User, AppRole, UUID> userService) {
        return new AuthController<>(jwtService, authManager, refreshTokenService, authProperties, tokenBlocklist, publisher, userService);
    }

    /**
     * App role mapper role mapper.
     *
     * @return the role mapper
     */
    @Bean
    @ConditionalOnMissingBean(name = "appRoleMapper")
    public RoleMapper<AppRole> appRoleMapper() {
        return new AppRoleMapper();
    }

    /**
     * User controller user controller.
     *
     * @param userService the user service
     * @param userBuilder the user builder
     * @param idConverter the id converter
     * @return the user controller
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "user.enabled", havingValue = "true", matchIfMissing = true)
    public UserController<User, AppRole, UUID> userController(
            UserService<User, AppRole, UUID> userService, AuthUserFactory<User, AppRole, UUID> userBuilder, IdConverter<UUID> idConverter) {
        return new UserController<>(userService, userBuilder, idConverter);
    }

    /**
     * Redis connection factory redis connection factory.
     *
     * @param properties the properties
     * @return the redis connection factory
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory(AuthProperties properties) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                properties.getRedis().getHost(),
                properties.getRedis().getPort()
        );
        config.setPassword(properties.getRedis().getPassword());
        config.setDatabase(properties.getRedis().getDatabase());

        return new LettuceConnectionFactory(config);
    }

    // ========== CONTROLLERS ==========

    /**
     * Data source data source.
     *
     * @param ds the datasource
     * @return the template
     */
    @Bean
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    @ConditionalOnMissingBean(JdbcTemplate.class)
    public JdbcTemplate jdbcTemplate(DataSource ds) {
        return new JdbcTemplate(ds);
    }

    /**
     * Data source data source.
     *
     * @param properties the properties
     * @return the data source
     */
    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    public DataSource dataSource(AuthProperties properties) {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl(properties.getRepository().getDatabase().getUrl());
        ds.setUsername(properties.getRepository().getDatabase().getUsername());
        ds.setPassword(properties.getRepository().getDatabase().getPassword());
        ds.setDriverClassName(properties.getRepository().getDatabase().getDriverClassName());
        return ds;
    }

    /**
     * User vo converter user vo converter.
     *
     * @return the user vo converter
     */
    @Bean
    @ConditionalOnMissingBean(VoConverter.class)
    public UserVoConverter userVoConverter() {
        return new UserVoConverter();
    }

    /**
     * Cache helper cache helper.
     *
     * @param cacheManager the cache manager
     * @return the cache helper
     */
    @Bean
    @ConditionalOnMissingBean(CacheHelper.class)
    public CacheHelper<User, AppRole, UUID> cacheHelper(CacheManager cacheManager) {
        return new CacheHelperImpl<>(cacheManager);
    }

    /**
     * The type Jpa configuration.
     */
// ========== JPA CONFIGURATION ==========
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "JPA", matchIfMissing = true)
    @EntityScan(basePackages = "com.ricardo.auth.domain")
    @EnableJpaRepositories(
            basePackages = "com.ricardo.auth.repository",
            includeFilters = @ComponentScan.Filter(
                    type = FilterType.ASSIGNABLE_TYPE,
                    classes = {DefaultUserJpaRepository.class, DefaultJpaRefreshTokenRepository.class, DefaultJpaPasswordResetTokenRepository.class}
            )
    )
    static class JpaConfiguration {
        // JPA configuration is handled by annotations
    }

    /**
     * The type Ip resolver config.
     */
    @Configuration
    @ConditionalOnMissingBean(IpResolver.class)
    static class IpResolverConfig {
        /**
         * Ip resolver ip resolver.
         *
         * @return the ip resolver
         */
        @Bean
        public IpResolver ipResolver() {
            return new com.ricardo.auth.service.SimpleIpResolver();
        }
    }

    /**
     * PostgreSQL Refresh Token Repository Configuration (EXPLICIT ONLY)
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    @ConditionalOnMissingBean(RefreshTokenRepository.class)
    static class PostgreSQLRefreshTokenRepositoryConfiguration {
        /**
         * Refresh token repository refresh token repository.
         *
         * @param jdbcTemplate   the data source
         * @param authProperties the auth properties
         * @return the refresh token repository
         */
        @Bean
        public RefreshTokenRepository refreshTokenRepository(
                JdbcTemplate jdbcTemplate,
                AuthProperties authProperties) {
            logger.info("Creating PostgreSQL Repositories");
            return new PostgreSQLRefreshTokenRepository(jdbcTemplate, authProperties);
        }


        /**
         * User repository user repository.
         *
         * @param userRowMapper          the user row mapper
         * @param userSqlParameterMapper the user sql parameter mapper
         * @param roleMapper             the role mapper
         * @param idConverter            the id converter
         * @param dataSource             the data source
         * @return the user repository
         */
        @Bean
        public UserRepository<User, AppRole, UUID> userRepository(
                UserRowMapper<User, AppRole, UUID> userRowMapper,
                UserSqlParameterMapper<User> userSqlParameterMapper,
                RoleMapper<AppRole> roleMapper,
                IdConverter<UUID> idConverter,
                DataSource dataSource
        ) {
            logger.info("Creating PostgreSQL User Repository");
            return new UserPostgreSQLRepository<>(
                    userRowMapper,
                    userSqlParameterMapper,
                    roleMapper,
                    idConverter,
                    dataSource
            );
        }
    }

    /**
     * The type Refresh token schema initializer.
     */
    @Order(3)
    @DependsOn("userSchemaInitializer")
    @Component("RefreshTokenSchemaInitializer")
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    public static class RefreshTokenSchemaInitializer {

        private final JdbcTemplate jdbcTemplate;

        /**
         * Instantiates a new Refresh token schema initializer.
         *
         * @param jdbcTemplate the jdbc template
         */
        public RefreshTokenSchemaInitializer(JdbcTemplate jdbcTemplate) {
            this.jdbcTemplate = jdbcTemplate;
        }

        /**
         * Initialize schema.
         */
        @PostConstruct
        public void initializeSchema() {
            try {
                createTableIfNotExists(jdbcTemplate);
                createIndexes(jdbcTemplate);
                logger.info("RefreshToken schema initialization completed successfully");
            } catch (Exception e) {
                logger.error("Failed to initialize RefreshToken schema", e);
                throw new RuntimeException("RefreshToken schema initialization failed", e);
            }
        }

        private void createTableIfNotExists(JdbcTemplate jdbcTemplate) {
            jdbcTemplate.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"");

            String createTableSql = """
                                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    token VARCHAR(1000) UNIQUE NOT NULL,
                    user_email VARCHAR(255) NOT NULL,
                    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    version BIGINT NOT NULL DEFAULT 0,
                    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
                                    )
                    """;

            jdbcTemplate.execute(createTableSql);
            logger.debug("Table 'refresh_tokens' created or already exists");
        }

        private void createIndexes(JdbcTemplate jdbcTemplate) {
            // Note: UNIQUE constraint on token is already handled by table creation
            String[] indexStatements = {
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_email ON refresh_tokens(user_email)",
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)",
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry_date ON refresh_tokens(expiry_date)",
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked)",

                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_email_revoked ON refresh_tokens(user_email, revoked)",
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked_expiry ON refresh_tokens(revoked, expiry_date)",
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_email_expiry ON refresh_tokens(user_email, expiry_date)",
                    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_email_created_at_desc ON refresh_tokens(user_email, created_at DESC);"
            };
            for (String indexSql : indexStatements) {
                jdbcTemplate.execute(indexSql);
            }

            logger.debug("All indexes created or already exist");
        }
    }

    /**
     * The type User schema initializer.
     */
    @Component("userSchemaInitializer")
    @Order(1)
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    public static class UserSchemaInitializer {

        private final JdbcTemplate jdbcTemplate;

        /**
         * Instantiates a new User schema initializer.
         *
         * @param jdbcTemplate the jdbc template
         */
        public UserSchemaInitializer(JdbcTemplate jdbcTemplate) {
            this.jdbcTemplate = jdbcTemplate;
        }

        /**
         * Initialize schema.
         */
        @PostConstruct
        public void initializeSchema() {
            try {
                createUserTablesIfNotExists(jdbcTemplate);
                createUserIndexes(jdbcTemplate);
                logger.info("User schema initialization completed successfully");
            } catch (Exception e) {
                logger.error("Failed to initialize User schema", e);
                throw new RuntimeException("User schema initialization failed", e);
            }
        }

        private void createUserTablesIfNotExists(JdbcTemplate jdbcTemplate) {
            jdbcTemplate.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"");

            // Create users table
            String createUsersTableSql = """
                    CREATE TABLE IF NOT EXISTS users (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        username VARCHAR(255) UNIQUE NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        version BIGINT DEFAULT 0,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                    )
                    """;

            jdbcTemplate.execute(createUsersTableSql);
            logger.debug("Table 'users' created or already exists");

            // Create user_roles table
            String createUserRolesTableSql = """
                    CREATE TABLE IF NOT EXISTS user_roles (
                        user_id UUID NOT NULL,
                        role VARCHAR(50) NOT NULL,
                        PRIMARY KEY (user_id, role),
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    """;

            jdbcTemplate.execute(createUserRolesTableSql);
            logger.debug("Table 'user_roles' created or already exists");
        }

        private void createUserIndexes(JdbcTemplate jdbcTemplate) {
            String[] indexStatements = {
                    // Índices para queries de data e versioning
                    "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)",
                    "CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at)",
                    "CREATE INDEX IF NOT EXISTS idx_users_version ON users(version)",

                    // Índices compostos para performance
                    "CREATE INDEX IF NOT EXISTS idx_users_created_updated ON users(created_at, updated_at)",

                    // Índices para user_roles
                    "CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)",
                    "CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role)",
                    "CREATE INDEX IF NOT EXISTS idx_user_roles_role_user_id ON user_roles(role, user_id)"
            };

            for (String indexSql : indexStatements) {
                jdbcTemplate.execute(indexSql);
            }
        }

    }

    /**
     * The type Memory rate limiter config.
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "memory", matchIfMissing = true)

    static class MemoryRateLimiterConfig {
        /**
         * Memory rate limiter rate limiter.
         *
         * @param authProperties the auth properties
         * @return the rate limiter
         */
        @Bean("generalRateLimiter")
        @ConditionalOnMissingBean(name = "generalRateLimiter")
        public RateLimiter memoryRateLimiter(AuthProperties authProperties) {
            return new InMemoryRateLimiter(authProperties);
        }

    }

    /**
     * The type Redis rate limiter config.
     */
    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "redis")
    static class RedisRateLimiterConfig {
        /**
         * Redis rate limiter rate limiter.
         *
         * @param redisTemplate  the redis template
         * @param authProperties the auth properties
         * @return the rate limiter
         */
        @Bean("generalRateLimiter")
        @ConditionalOnMissingBean(name = "generalRateLimiter")
        public RateLimiter redisRateLimiter(
                RedisTemplate<String, String> redisTemplate,
                AuthProperties authProperties
        ) {
            return new RedisRateLimiter(redisTemplate, authProperties);
        }
    }

    /**
     * The type Redis blocklist config.
     */
    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(prefix = "ricardo.auth.token-blocklist", name = "type", havingValue = "redis")
    static class RedisBlocklistConfig {
        /**
         * Redis token blocklist token blocklist.
         *
         * @param redisTemplate  the redis template
         * @param authProperties the auth properties
         * @return the token blocklist
         */
        @Bean
        @ConditionalOnMissingBean
        public TokenBlocklist redisTokenBlocklist(
                RedisTemplate<String, String> redisTemplate,
                AuthProperties authProperties
        ) {
            return new RedisTokenBlockList(redisTemplate, authProperties.getJwt().getAccessTokenExpiration());
        }
    }

    /**
     * The type Memory blocklist config.
     */
    @Configuration
    @ConditionalOnMissingBean(TokenBlocklist.class)
    static class MemoryBlocklistConfig {
        /**
         * In memory token blocklist token blocklist.
         *
         * @param authProperties the auth properties
         * @return the token blocklist
         */
        @Bean
        public TokenBlocklist inMemoryTokenBlocklist(AuthProperties authProperties) {
            return new InMemoryTokenBlocklist(authProperties);
        }
    }

    /**
     * The type Auth user factory config.
     */
    @Configuration
    @ConditionalOnMissingBean(AuthUserFactory.class)
    static class AuthUserFactoryConfig {
        /**
         * Auth user factory auth user factory.
         *
         * @param passwordPolicyService the password policy service
         * @param passwordEncoder       the password encoder
         * @return the auth user factory
         */
        @Bean
        public AuthUserFactory<User, AppRole, UUID> authUserFactory(PasswordPolicyService passwordPolicyService, PasswordEncoder passwordEncoder) {
            return new UserFactory(passwordEncoder, passwordPolicyService);
        }
    }

    /**
     * The type Id converter config.
     */
    @Configuration
    @ConditionalOnMissingBean(IdConverter.class)
    static class IdConverterConfig {
        /**
         * Id converter id converter.
         *
         * @return the id converter
         */
        @Bean
        public IdConverter<UUID> idConverter() {
            return new UUIDConverter();
        }
    }

    /**
     * The type Email sender service config.
     */
    @Configuration
    @ConditionalOnMissingBean(EmailSenderService.class)
    static class EmailSenderServiceConfig {
        /**
         * Email sender service email sender service.
         *
         * @param javaMailSender the java mail sender
         * @param properties     the properties
         * @return the email sender service
         */
        @Bean
        public EmailSenderService emailSenderService(JavaMailSender javaMailSender, AuthProperties properties) {
            return new EmailSenderServiceImpl(javaMailSender, properties);
        }
    }

    /**
     * The type Java mail sender config.
     */
    @Configuration
    @ConditionalOnMissingBean(JavaMailSender.class)
    static class JavaMailSenderConfig {
        /**
         * Java mail sender java mail sender.
         *
         * @param properties the properties
         * @return the java mail sender
         */
        @Bean
        public JavaMailSender javaMailSender(AuthProperties properties) {
            Dotenv dotenv = Dotenv.load();
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            String mailUsername = dotenv.get("MAIL_USERNAME");
            String mailPassword = dotenv.get("MAIL_PASSWORD");
            if (properties.getEmail().getPassword() == null && mailPassword == null) {
                logger.warn("Email password not configured. Email sending will be disabled. Set 'MAIL_PASSWORD' env variable or configure in properties.");
                return null; // Return null to indicate email service is not available
            }

            if (mailUsername == null && properties.getEmail().getFromAddress() == null) {
                logger.warn("Email username not configured. Email sending will be disabled. Set 'MAIL_USERNAME' env variable or configure in properties.");
                return null;
            }


            if (mailUsername != null && !mailUsername.isBlank()) {
                properties.getEmail().setFromAddress(mailUsername);
            }

            if (mailPassword != null && !mailPassword.isBlank()) {
                properties.getEmail().setPassword(mailPassword);
            }


            sender.setUsername(properties.getEmail().getFromAddress());
            sender.setPassword(properties.getEmail().getPassword());
            sender.setPort(properties.getEmail().getPort());
            sender.setHost(properties.getEmail().getHost());

            Properties props = sender.getJavaMailProperties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
            props.put("mail.smtp.ssl.trust", properties.getEmail().getHost());

            return sender;
        }
    }

    /**
     * The type Event publisher config.
     */
    @Configuration
    @ConditionalOnMissingBean(Publisher.class)
    static class EventPublisherConfig {
        /**
         * Event publisher publisher.
         *
         * @param publisher the publisher
         * @return the publisher
         */
        @Bean
        public Publisher eventPublisher(ApplicationEventPublisher publisher) {
            return new EventPublisher(publisher);
        }
    }

    /**
     * The type User row mapper config.
     */
    @Configuration
    @ConditionalOnMissingBean(UserRowMapper.class)
    static class UserRowMapperConfig {
        /**
         * User row mapper user row mapper.
         *
         * @param idConverter the id converter
         * @return the user row mapper
         */
        @Bean
        public UserRowMapper<User, AppRole, UUID> userRowMapper(IdConverter<UUID> idConverter) {
            return new UserRowMapperImpl(idConverter);
        }
    }

    /**
     * The type User sql parameter mapper config.
     */
    @Configuration
    @ConditionalOnMissingBean(UserSqlParameterMapper.class)
    static class UserSqlParameterMapperConfig {
        /**
         * User sql parameter mapper user sql parameter mapper.
         *
         * @return the user sql parameter mapper
         */
        @Bean
        public UserSqlParameterMapper<User> userSqlParameterMapper() {
            return new UserSqlMapper();
        }
    }

    /**
     * PostgreSQL Password Reset Token Repository Configuration (EXPLICIT ONLY)
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    @ConditionalOnMissingBean(PasswordResetTokenRepository.class)
    static class PostgreSQLPasswordResetTokenRepositoryConfiguration {
        /**
         * Password reset token repository password reset token repository.
         *
         * @param dataSource     the data source
         * @param authProperties the auth properties
         * @return the password reset token repository
         */
        @Bean
        public PasswordResetTokenRepository passwordResetTokenRepository(
                DataSource dataSource,
                AuthProperties authProperties) {
            logger.info("Creating PostgreSQL Password Reset Token Repository");
            return new PostgreSqlPasswordResetTokenRepository(dataSource, authProperties);
        }
    }

    /**
     * The type Password reset service config.
     */
    @Configuration
    @ConditionalOnMissingBean(PasswordResetService.class)
    static class PasswordResetServiceConfig {
        /**
         * Password reset service password reset service.
         *
         * @param emailSenderService    the email sender service
         * @param userService           the user service
         * @param tokenRepository       the token repository
         * @param passwordEncoder       the password encoder
         * @param passwordPolicyService the password policy service
         * @param authProperties        the auth properties
         * @param eventPublisher        the event publisher
         * @param idConverter           the id converter
         * @param properties            the properties
         * @param cacheManager          the cache manager
         * @return the password reset service
         */
        @Bean
        public PasswordResetService passwordResetService(EmailSenderService emailSenderService,
                                                         UserService<User, AppRole, UUID> userService,
                                                         PasswordResetTokenRepository tokenRepository,
                                                         PasswordEncoder passwordEncoder,
                                                         PasswordPolicyService passwordPolicyService,
                                                         AuthProperties authProperties,
                                                         Publisher eventPublisher,
                                                         IdConverter<UUID> idConverter,
                                                         AuthProperties properties,
                                                         CacheManager cacheManager) {
            return new PasswordResetServiceImpl<>(emailSenderService,
                    userService,
                    tokenRepository,
                    passwordEncoder,
                    passwordPolicyService,
                    authProperties,
                    eventPublisher,
                    idConverter,
                    properties,
                    cacheManager);
        }
    }


    // ========== PASSWORD RESET RATE LIMITER CONFIGURATION ==========

    /**
     * The type Role service config.
     */
    @Configuration
    @ConditionalOnMissingBean(RoleService.class)
    static class RoleServiceConfig {
        /**
         * Role service role service.
         *
         * @param userService    the user service
         * @param roleMapper     the role mapper
         * @param authProperties the auth properties
         * @param eventPublisher the event publisher
         * @param idConverter    the id converter
         * @param cacheHelper    the cache helper
         * @return the role service
         */
        @Bean
        public RoleService<User, AppRole, UUID> roleService(UserService<User, AppRole, UUID> userService,
                                                            RoleMapper<AppRole> roleMapper,
                                                            AuthProperties authProperties,
                                                            Publisher eventPublisher,
                                                            IdConverter<UUID> idConverter, CacheHelper<User, AppRole, UUID> cacheHelper) {
            return new RoleServiceImpl<>(userService, roleMapper, authProperties, eventPublisher, idConverter, cacheHelper);
        }
    }

    /**
     * The type Password reset token schema initializer.
     */
    @Order(2)
    @DependsOn("userSchemaInitializer")
    @Component("PasswordResetTokenSchemaInitializer")
    @ConditionalOnProperty(prefix = "ricardo.auth.repository", name = "type", havingValue = "POSTGRESQL")
    @ConditionalOnMissingBean(PasswordResetTokenSchemaInitializer.class)
    public static class PasswordResetTokenSchemaInitializer {

        private final AuthProperties authProperties;
        private final JdbcTemplate jdbcTemplate;

        /**
         * Instantiates a new Password reset token schema initializer.
         *
         * @param jdbcTemplate   the jdbc template
         * @param authProperties the auth properties
         */
        public PasswordResetTokenSchemaInitializer(JdbcTemplate jdbcTemplate, AuthProperties authProperties) {
            this.authProperties = authProperties;
            this.jdbcTemplate = jdbcTemplate;
        }

        /**
         * Initialize schema.
         */
        @PostConstruct
        public void initializeSchema() {
            try {
                createPasswordResetTokenTableIfNotExists(jdbcTemplate);
                createPasswordResetTokenIndexes(jdbcTemplate);
                logger.info("Password Reset Token schema initialization completed successfully");
            } catch (Exception e) {
                logger.error("Failed to initialize Password Reset Token schema", e);
                throw new RuntimeException("Password Reset Token schema initialization failed", e);
            }
        }


        private void createPasswordResetTokenTableIfNotExists(JdbcTemplate jdbcTemplate) {
            jdbcTemplate.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"");

            String tableName = authProperties.getRepository().getDatabase().getPasswordResetTokensTable();

            // Validate table name to prevent SQL injection
            if (!tableName.matches("^[a-zA-Z_][a-zA-Z0-9_]*$")) {
                throw new IllegalArgumentException("Invalid table name: " + tableName);
            }

            String createTableSql = String.format("""
                                    CREATE TABLE IF NOT EXISTS %s (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    token VARCHAR(1000) UNIQUE NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                    used BOOLEAN NOT NULL DEFAULT FALSE,
                    used_at TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
                                    )
                    """, tableName);
            jdbcTemplate.execute(createTableSql);
            logger.debug("Reset Password token Table created or already exists");
        }

        private void createPasswordResetTokenIndexes(JdbcTemplate jdbcTemplate) {
            String tableName = authProperties.getRepository().getDatabase().getPasswordResetTokensTable();
            String[] indexStatements = {
                    String.format("CREATE UNIQUE INDEX IF NOT EXISTS idx_%s_token ON %s(token)", tableName, tableName),
                    String.format("CREATE INDEX IF NOT EXISTS idx_%s_email ON %s(email)", tableName, tableName),
                    String.format("CREATE INDEX IF NOT EXISTS idx_%s_expiry_date ON %s(expiry_date)", tableName, tableName),
                    String.format("CREATE INDEX IF NOT EXISTS idx_%s_used ON %s(used)", tableName, tableName),
                    String.format("CREATE INDEX IF NOT EXISTS idx_%s_used_expiry ON %s(used, expiry_date)", tableName, tableName),
                    String.format("CREATE INDEX IF NOT EXISTS idx_%s_email_created ON %s(email, created_at)", tableName, tableName),
                    String.format("CREATE INDEX IF NOT EXISTS idx_%s_email_active ON %s(email, used, expiry_date)", tableName, tableName)
            };

            for (String indexSql : indexStatements) {
                jdbcTemplate.execute(indexSql);
            }

            logger.debug("All password reset token indexes created or already exist");
        }
    }

    /**
     * Configuration for the Password Reset specific Memory-based Rate Limiter.
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "memory", matchIfMissing = true)
    @ConditionalOnMissingBean(name = "passwordResetRateLimiter")
    static class PasswordResetMemoryRateLimiterConfig {

        /**
         * Creates the memory-based rate limiter for password reset operations.
         *
         * @param authProperties The main authentication properties.
         * @return The named "passwordResetRateLimiter" bean.
         */
        @Bean("passwordResetRateLimiter")
        public RateLimiter passwordResetMemoryRateLimiter(AuthProperties authProperties) {
            InMemoryRateLimiter limiter = new InMemoryRateLimiter(authProperties);

            int maxAttempts = authProperties.getPasswordReset().getMaxAttempts();
            long timeWindowMs = authProperties.getPasswordReset().getTimeWindowMs();
            limiter.changeSettings(maxAttempts, timeWindowMs);
            logger.debug("Configured Password Reset Memory Rate Limiter: maxAttempts={}, windowMs={}", maxAttempts, timeWindowMs);
            return limiter;
        }
    }

    /**
     * Configuration for the Password Reset specific Redis-based Rate Limiter.
     */
    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "redis")
    @ConditionalOnMissingBean(name = "passwordResetRateLimiter")
    static class PasswordResetRedisRateLimiterConfig {

        /**
         * Creates the Redis-based rate limiter for password reset operations.
         *
         * @param redisTemplate  The Redis template for string operations.
         * @param authProperties The main authentication properties.
         * @return The named "passwordResetRateLimiter" bean.
         */
        @Bean("passwordResetRateLimiter")
        public RateLimiter passwordResetRedisRateLimiter(
                RedisTemplate<String, String> redisTemplate,
                AuthProperties authProperties) {
            RedisRateLimiter limiter = new RedisRateLimiter(redisTemplate, authProperties);

            int maxAttempts = authProperties.getPasswordReset().getMaxAttempts();
            long timeWindowMs = authProperties.getPasswordReset().getTimeWindowMs();
            limiter.changeSettings(maxAttempts, timeWindowMs);
            logger.debug("Configured Password Reset Redis Rate Limiter: maxAttempts={}, windowMs={}", maxAttempts, timeWindowMs);
            return limiter;
        }
    }
}

