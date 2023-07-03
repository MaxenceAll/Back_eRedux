-- PRODUCT TABLE SCHEMA
-- Drop the "customer" table if it exists
DROP TABLE IF EXISTS product;
-- Create the "product" table if it doesn't exist
CREATE TABLE product (
       id SERIAL PRIMARY KEY,
       name VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    type VARCHAR(50) NOT NULL,
    img_src VARCHAR(200) NOT NULL
    );
-------------------------------------------------------
-- CUSTOMER TABLE SCHEMA
-- Drop the "customer" table if it exists
DROP TABLE IF EXISTS customer;
-- Create the "customer" table
CREATE TABLE customer (
                          id SERIAL PRIMARY KEY,
                          email VARCHAR(255) NOT NULL,
                          password VARCHAR(255) NOT NULL
);
-- Add unique constraint to the "email" column
ALTER TABLE customer
    ADD CONSTRAINT unique_email UNIQUE (email);
-------------------------------------------------------