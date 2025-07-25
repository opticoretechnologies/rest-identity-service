package com.opticoretechnologies.rest.identity.exception;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public class UserAlreadyExistsException extends Throwable {
    public UserAlreadyExistsException(@NotEmpty(message = "New username cannot be empty.") @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters.") String s) {
    }
}
