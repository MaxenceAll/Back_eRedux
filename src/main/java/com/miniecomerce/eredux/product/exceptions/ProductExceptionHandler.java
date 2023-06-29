package com.miniecomerce.eredux.product.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class ProductExceptionHandler {

    @ExceptionHandler(ProductNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleProductNotFoundException(ProductNotFoundException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                ex.getMessage(),
                "/api/products/{id}",
                HttpStatus.NOT_FOUND.value(),
                HttpStatus.NOT_FOUND.getReasonPhrase(),
                LocalDateTime.now()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    private static class ErrorResponse {
        private String message;
        private String path;
        private int status;
        private String error;
        private LocalDateTime timestamp;

        public ErrorResponse(String message, String path, int status, String error, LocalDateTime timestamp) {
            this.message = message;
            this.path = path;
            this.status = status;
            this.error = error;
            this.timestamp = timestamp;
        }

        public String getMessage() {
            return message;
        }

        public String getPath() {
            return path;
        }

        public int getStatus() {
            return status;
        }

        public String getError() {
            return error;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }
    }
}