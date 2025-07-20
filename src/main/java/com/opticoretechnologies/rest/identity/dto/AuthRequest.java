package com.opticoretechnologies.rest.identity.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;
}
