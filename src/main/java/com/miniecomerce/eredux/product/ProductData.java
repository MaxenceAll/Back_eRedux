package com.miniecomerce.eredux.product;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;

@Component
public class ProductData implements CommandLineRunner {

    private final DataSource dataSource;

    public ProductData(DataSource dataSource) {
        this.dataSource = dataSource;
    }
    @Override
    public void run(String... args) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            Statement statement = connection.createStatement();
            String sqlStatement =
                    "-- Insert the data into the \"product\" table\n" +
                    "INSERT INTO product (id, name, price, type, img_src)\n" +
                    "VALUES\n" +
                    "    (1, 'Pomme', 1.99, 'fruit', 'https://picsum.photos/id/1/200'),\n" +
                    "    (2, 'Banane', 0.99, 'fruit', 'https://picsum.photos/id/2/200'),\n" +
                    "    (3, 'Orange', 0.79, 'fruit', 'https://picsum.photos/id/3/200'),\n" +
                    "    (4, 'Fraise', 2.49, 'fruit', 'https://picsum.photos/id/4/200'),\n" +
                    "    (5, 'Myrtille', 1.89, 'fruit', 'https://picsum.photos/id/5/200'),\n" +
                    "    (6, 'Raisin', 3.99, 'fruit', 'https://picsum.photos/id/6/200'),\n" +
                    "    (7, 'Pastèque', 4.99, 'fruit', 'https://picsum.photos/id/7/200'),\n" +
                    "    (8, 'Mangue', 2.99, 'fruit', 'https://picsum.photos/id/8/200'),\n" +
                    "    (9, 'Ananas', 3.49, 'fruit', 'https://picsum.photos/id/9/200'),\n" +
                    "    (10, 'Kiwi', 1.69, 'fruit', 'https://picsum.photos/id/10/200'),\n" +
                    "    (11, 'Carotte', 0.69, 'légumes', 'https://picsum.photos/id/11/200'),\n" +
                    "    (12, 'Brocoli', 1.29, 'légumes', 'https://picsum.photos/id/12/200'),\n" +
                    "    (13, 'Tomate', 0.99, 'légumes', 'https://picsum.photos/id/13/200'),\n" +
                    "    (14, 'Epinard', 1.99, 'légumes', 'https://picsum.photos/id/14/200'),\n" +
                    "    (15, 'Concombre', 0.79, 'légumes', 'https://picsum.photos/id/15/200'),\n" +
                    "    (16, 'Pomme de terre', 0.89, 'légumes', 'https://picsum.photos/id/16/200'),\n" +
                    "    (17, 'Oignon', 0.69, 'légumes', 'https://picsum.photos/id/17/200'),\n" +
                    "    (18, 'Poivron', 0.99, 'légumes', 'https://picsum.photos/id/18/200'),\n" +
                    "    (19, 'Laitue', 1.49, 'légumes', 'https://picsum.photos/id/19/200'),\n" +
                    "    (20, 'Courguette', 1.19, 'légumes', 'https://picsum.photos/id/20/200'),\n" +
                    "    (21, 'Lait', 2.99, 'produit frais', 'https://picsum.photos/id/21/200'),\n" +
                    "    (22, 'Yaourt', 1.99, 'produit frais', 'https://picsum.photos/id/22/200'),\n" +
                    "    (23, 'Fromage', 3.49, 'produit frais', 'https://picsum.photos/id/23/200'),\n" +
                    "    (24, 'Oeufs', 1.79, 'produit frais', 'https://picsum.photos/id/24/200'),\n" +
                    "    (25, 'Beurre', 2.49, 'produit frais', 'https://picsum.photos/id/25/200'),\n" +
                    "    (26, 'Poulet', 5.99, 'produit frais', 'https://picsum.photos/id/26/200'),\n" +
                    "    (27, 'Poisson', 7.99, 'produit frais', 'https://picsum.photos/id/27/200'),\n" +
                    "    (28, 'Boeuf', 6.99, 'produit frais', 'https://picsum.photos/id/28/200'),\n" +
                    "    (29, 'Porc', 5.49, 'produit frais', 'https://picsum.photos/id/29/200'),\n" +
                    "    (30, 'Crevette', 8.99, 'produit frais', 'https://picsum.photos/id/30/200'),\n" +
                    "    (31, 'Riz', 3.49, 'épicerie', 'https://picsum.photos/id/31/200'),\n" +
                    "    (32, 'Pates', 2.99, 'épicerie', 'https://picsum.photos/id/32/200'),\n" +
                    "    (33, 'Pain', 1.99, 'épicerie', 'https://picsum.photos/id/33/200'),\n" +
                    "    (34, 'Céréales', 4.49, 'épicerie', 'https://picsum.photos/id/34/200'),\n" +
                    "    (35, 'Sucre', 1.49, 'épicerie', 'https://picsum.photos/id/35/200'),\n" +
                    "    (36, 'Sel', 0.99, 'épicerie', 'https://picsum.photos/id/36/200'),\n" +
                    "    (37, 'Huile d''olive', 5.99, 'épicerie', 'https://picsum.photos/id/37/200'),\n" +
                    "    (38, 'Café', 3.99, 'épicerie', 'https://picsum.photos/id/38/200'),\n" +
                    "    (39, 'Thé', 2.49, 'épicerie', 'https://picsum.photos/id/39/200'),\n" +
                    "    (40, 'Jus', 2.99, 'boisson', 'https://picsum.photos/id/40/200'),\n" +
                    "    (41, 'Soda', 1.99, 'boisson', 'https://picsum.photos/id/41/200'),\n" +
                    "    (42, 'Eau', 0.99, 'boisson', 'https://picsum.photos/id/42/200'),\n" +
                    "    (43, 'Energy Drink', 3.49, 'boisson', 'https://picsum.photos/id/43/200'),\n" +
                    "    (44, 'Vin', 9.99, 'boisson', 'https://picsum.photos/id/44/200'),\n" +
                    "    (45, 'Bière', 1.49, 'boisson', 'https://picsum.photos/id/45/200'),\n" +
                    "    (46, 'Cocktail', 6.99, 'boisson', 'https://picsum.photos/id/46/200'),\n" +
                    "    (47, 'Smoothie', 4.99, 'boisson', 'https://picsum.photos/id/47/200'),\n" +
                    "    (48, 'Thé glacé', 2.49, 'boisson', 'https://picsum.photos/id/48/200')\n" +
                    ";";

            statement.executeUpdate(sqlStatement);
        }
    }
}