package com.miniecomerce.eredux.customer;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.miniecomerce.eredux.customer.exceptions.RegistrationException;
import com.miniecomerce.eredux.customer.exceptions.InvalidLoginException;

import java.util.Optional;

@Service
public class CustomerService {
    private final CustomerRepository customerRepository;

    public CustomerService(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    public void registerCustomer(RegistrationRequest registrationRequest) {
        // Check if the user with the given email already exists
        Optional<Customer> existingCustomer = customerRepository.findByEmail(registrationRequest.getEmail());
        if (existingCustomer.isPresent()) {
            throw new RegistrationException("Email is already registered");
        }

        // Create a new Customer object with the provided email
        Customer customer = new Customer();
        customer.setEmail(registrationRequest.getEmail());

        // Hash the password
        String hashedPassword = hashPassword(registrationRequest.getPassword());

        // Set the hashed password
        customer.setPassword(hashedPassword);

        // Save the customer in the database
        customerRepository.save(customer);
    }

    private String hashPassword(String password) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(password);
    }


    public Customer login(String email, String password) {
        Customer customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidLoginException("Invalid email or password"));

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        boolean passwordMatch = passwordEncoder.matches(password, customer.getPassword());

        if (!passwordMatch) {
            throw new InvalidLoginException("Invalid email or password");
        }

        return customer;
    }
}
