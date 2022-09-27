package com.pk.backend.controllers;

import com.pk.backend.payload.response.MessageResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

@ControllerAdvice
@Log4j2
public class RestResponseEntityExceptionHandler {

    @ExceptionHandler(value = { UserCreateException.class })
    public ResponseEntity<Object> handleConflict(UserCreateException ex, WebRequest request) {
        MessageResponse message = new MessageResponse(ex.getMessage());
        log.error(ex);
        return new ResponseEntity<>(message, HttpStatus.BAD_REQUEST );
    }
}