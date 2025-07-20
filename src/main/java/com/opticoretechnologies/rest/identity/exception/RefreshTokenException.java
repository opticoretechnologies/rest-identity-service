package com.opticoretechnologies.rest.identity.exception;

public class RefreshTokenException extends RuntimeException {

    public RefreshTokenException(String message) {
        super(message);
    }

    public RefreshTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public RefreshTokenException(Throwable cause) {
        super(cause);
    }

}
