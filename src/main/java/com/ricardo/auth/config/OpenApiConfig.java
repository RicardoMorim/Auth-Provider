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

    /**
     * Auth provider open api open api.
     *
     * @return the open api
     */
    @Bean
    public OpenAPI authProviderOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth Provider API")
                        .description("JWT Authentication Spring Boot Starter API Documentation. " +
                                "Uses secure HTTP-only cookie authentication. " +
                                "For cross-site cookie auth, set cookies with SameSite=None; Secure; httpOnly and " +
                                "configure CORS to allow credentials (Access-Control-Allow-Credentials: true) and " +
                                "an exact allowed origin (not '*').")
                        .version("4.0.0")
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
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.COOKIE)
                                .name("access_token")
                                .description("Secure HTTP-only cookie authentication. " +
                                        "For cross-origin use, set cookies with SameSite=None; Secure; httpOnly. " +
                                        "Ensure the client sends requests with credentials: 'include' and the server's CORS " +
                                        "allows credentials and the exact Origin. No manual token management required.")));
    }
}
