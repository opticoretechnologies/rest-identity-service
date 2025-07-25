package com.opticoretechnologies.rest.identity.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserInfo {
    private String username;
    private String email;
}
