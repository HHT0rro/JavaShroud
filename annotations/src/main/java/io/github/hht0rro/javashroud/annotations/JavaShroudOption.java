package io.github.hht0rro.javashroud.annotations;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** A typed key/value option attached to a JavaShroud pass annotation. */
@Retention(RetentionPolicy.CLASS)
public @interface JavaShroudOption {
    String key();
    String value();
}