package com.ricardo.auth.autoconfig;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.core.type.filter.TypeFilter;

import java.io.IOException;

/**
 * Filter to exclude JPA entities and repositories when using PostgreSQL direct implementation.
 * This prevents conflicts between JPA auto-configuration and PostgreSQL JDBC implementation.
 */
@ConditionalOnProperty(prefix = "ricardo.auth.repositories", name = "type", havingValue = "POSTGRESQL")
public class PostgreSQLExcludeFilter implements TypeFilter {

    @Override
    public boolean match(MetadataReader metadataReader, MetadataReaderFactory metadataReaderFactory) throws IOException {
        String className = metadataReader.getClassMetadata().getClassName();

        // Exclude JPA entities when using PostgreSQL
        if (className.contains("domain") && metadataReader.getAnnotationMetadata().hasAnnotation("jakarta.persistence.Entity")) {
            return true;
        }

        // Exclude JPA repositories when using PostgreSQL
        if (className.contains("repository") && className.contains("Jpa")) {
            return true;
        }

        return false;
    }
}
