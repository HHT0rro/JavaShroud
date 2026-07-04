package io.github.hht0rro.javashroud.annotations;

import org.junit.jupiter.api.Test;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AnnotationApiSmokeTest {
    @Test
    void annotationsUseClassRetentionAndExposeConstants() {
        Retention retention = JavaShroudPass.class.getAnnotation(Retention.class);
        assertNotNull(retention);
        assertEquals(RetentionPolicy.CLASS, retention.value());
        assertEquals("string-encryption", PassId.STRING_ENCRYPTION);
        assertEquals("scope", PassOptionKey.SCOPE);
        assertEquals("annotated", PassOptionValue.Scope.ANNOTATED);
    }
}