package com.meltmedia.jackson.crypto;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import com.fasterxml.jackson.annotation.JacksonAnnotation;

@JacksonAnnotation
@Retention(RetentionPolicy.RUNTIME)
public @interface Encrypted {
  String encoding() default "UTF-8";
}
