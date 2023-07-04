package com.miniecomerce.eredux.auth.responses;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {

    @JsonProperty("access_token")
    private String accessToken;
    private boolean result;
    private String message;
    private String email;
    private int error;
}
