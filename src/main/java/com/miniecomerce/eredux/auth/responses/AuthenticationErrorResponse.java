package com.miniecomerce.eredux.auth.responses;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthenticationErrorResponse {

    @JsonProperty("error")
    private int error;
    @JsonProperty("message")
    private String message;
    @JsonProperty("result")
    private boolean result;
}
