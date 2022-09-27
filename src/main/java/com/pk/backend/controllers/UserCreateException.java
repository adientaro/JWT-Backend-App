package com.pk.backend.controllers;

public class UserCreateException extends RuntimeException {
    public UserCreateException(String errorMessage) {
        super(errorMessage);
    }
}
