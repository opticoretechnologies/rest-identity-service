package com.opticoretechnologies.rest.identity.exceptionhandler;


import com.opticoretechnologies.rest.identity.exception.BadRequestException;
import com.opticoretechnologies.rest.identity.exception.DuplicateResourceException;
import com.opticoretechnologies.rest.identity.exception.ResourceNotFoundException;
import com.opticoretechnologies.rest.identity.exception.TokenException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import com.opticoretechnologies.rest.identity.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException ex , HttpServletRequest request) {
        log.error("Resource not found: {} {} ", ex.getMessage(),request.getRequestURI() , ex); // Log the full stack trace
        ErrorResponse errorResponse = getErrorResponse(HttpStatus.NOT_FOUND, request, ex);
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);

    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(BadRequestException ex , HttpServletRequest request) {
        log.error("Bad request: {} {} ", ex.getMessage(),request.getRequestURI(), ex);
        ErrorResponse errorResponse = getErrorResponse(HttpStatus.BAD_REQUEST, request, ex);
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);

    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex, HttpServletRequest request) {
       log.error("Bad credentials: {} {} ", ex.getMessage(),request.getRequestURI(), ex);
        ErrorResponse errorResponse = getErrorResponse(HttpStatus.UNAUTHORIZED, request, ex);
        errorResponse.setMessage("Invalid username or password");
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }
    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateResourceException(DuplicateResourceException ex, HttpServletRequest request) {
        ErrorResponse errorResponse = getErrorResponse(HttpStatus.CONFLICT, request, ex);
        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponse errorResponse = getErrorResponse( HttpStatus.BAD_REQUEST, request, ex);
        errorResponse.setValidationErrors(errors);
        errorResponse.setError("Validation Failed");
        errorResponse.setMessage("Input validation failed, please check the errors.");
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ErrorResponse> handleTokenException(TokenException ex, HttpServletRequest request) {
        ErrorResponse errorResponse = getErrorResponse(HttpStatus.UNAUTHORIZED, request, ex);
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex, HttpServletRequest request) {
        log.error("An unexpected error occurred: {}", ex.getMessage(), ex); // Log the full stack trace

        ErrorResponse errorResponse = getErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, request, ex);
        errorResponse.setMessage("An unexpected error occurred. Please try again later.");
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
        private static ErrorResponse getErrorResponse(HttpStatus status, HttpServletRequest request, Exception ex) {
        return ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .path(request.getRequestURI())
                .message(ex.getMessage())
                .build();
    }
}
