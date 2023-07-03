package com.miniecomerce.eredux.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthenticationErrorResponse {
    private int error;
    private String message;
    private boolean result;
}
