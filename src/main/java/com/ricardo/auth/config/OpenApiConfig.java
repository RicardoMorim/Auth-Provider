package com.ricardo.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI/Swagger configuration for the Auth Provider.
 * This configuration is only loaded when SpringDoc OpenAPI is on the classpath.
 */
@Configuration
@ConditionalOnClass(OpenAPI.class)
public class OpenApiConfig {

    @Bean
    public OpenAPI authProviderOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth Provider API")
                        .description("JWT Authentication Spring Boot Starter API Documentation. " +
                                "Uses secure HTTP-only cookie authentication for maximum security. " +
                                "Cookies are automatically managed with httpOnly, secure, and sameSite flags. " +
                                "CORS is properly configured for cross-origin requests.")
                        .version("3.1.0")
                        .contact(new Contact()
                                .name("Ricardo")
                                .email("ricardomorim05@gmail.com")
                                .url("https://ricardoportfolio.vercel.app"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8080")
                                .description("Development server")))
                .addSecurityItem(new SecurityRequirement()
                        .addList("CookieAuth"))
                .components(new Components()
                        .addSecuritySchemes("CookieAuth", new SecurityScheme()
                                .name("CookieAuth")
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.COOKIE)
                                .name("access_token")
                                .description("Secure HTTP-only cookie authentication. " +
                                        "Automatically managed by browser when credentials are included in requests. " +
                                        "Cookies are set with httpOnly=true, secure=true, and sameSite=Strict for maximum security. " +
                                        "No manual token management required - just include credentials: 'include' in fetch requests.")));
    }
}
