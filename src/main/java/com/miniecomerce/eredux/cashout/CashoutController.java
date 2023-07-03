package com.miniecomerce.eredux.cashout;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/cashout")
public class CashoutController {

    @GetMapping
    public ResponseEntity<String> sayHello () {
        return ResponseEntity.ok("Hello World from secreted endpoint");
    }
}
