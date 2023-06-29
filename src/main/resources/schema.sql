-- Create the "product" table if it doesn't exist
CREATE TABLE IF NOT EXISTS product (
       id SERIAL PRIMARY KEY,
       name VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    type VARCHAR(50) NOT NULL,
    img_src VARCHAR(200) NOT NULL
    );