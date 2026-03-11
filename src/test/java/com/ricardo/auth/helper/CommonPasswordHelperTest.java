package com.ricardo.auth.helper;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CommonPasswordHelperTest {

    @Test
    void loadCommonPasswords_FromFileSystem_ShouldNormalizeAndIgnoreComments() throws IOException {
        Path tempFile = Files.createTempFile("common-passwords", ".txt");
        Files.writeString(tempFile, "# comment\nPassword123\n\n ADMIN \n", StandardCharsets.UTF_8);

        Set<String> passwords = CommonPasswordHelper.loadCommonPasswords(tempFile.toString());

        assertThat(passwords).containsExactlyInAnyOrder("password123", "admin");

        Files.deleteIfExists(tempFile);
    }

    @Test
    void loadCommonPasswords_FromClasspath_ShouldLoadResource() {
        Set<String> passwords = CommonPasswordHelper.loadCommonPasswords("/commonpasswords.txt", CommonPasswordHelperTest.class);

        assertThat(passwords).isNotEmpty();
        assertThat(passwords).contains("password");
    }

    @Test
    void loadCommonPasswords_WhenNotFoundAnywhere_ShouldFallbackToDefaults() {
        Set<String> passwords = CommonPasswordHelper.loadCommonPasswords("/does-not-exist-password-list.txt", CommonPasswordHelperTest.class);

        assertThat(passwords).contains("password", "123456", "admin");
    }

    @Test
    void isCommonPassword_ShouldBeCaseInsensitive() {
        Set<String> common = Set.of("password", "admin");

        assertThat(CommonPasswordHelper.isCommonPassword("PASSWORD", common)).isTrue();
        assertThat(CommonPasswordHelper.isCommonPassword("Admin", common)).isTrue();
        assertThat(CommonPasswordHelper.isCommonPassword("somethingElse", common)).isFalse();
    }
}
