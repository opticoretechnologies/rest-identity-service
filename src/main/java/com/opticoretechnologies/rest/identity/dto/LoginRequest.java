package com.opticoretechnologies.rest.identity.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.*;


@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Data
public class LoginRequest {
    @NotEmpty(message = "Username cannot be empty.")
    private String username;

    @NotEmpty(message = "Password cannot be empty.")
    private String password;
}