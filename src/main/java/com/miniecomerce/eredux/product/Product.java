package com.miniecomerce.eredux.product;

import jakarta.persistence.*;

@Entity
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private double price;
    private String type;
    private String img_src;

    public Product() {
    }

    public Product(String name, double price, String type, String img_src) {
        this.name = name;
        this.price = price;
        this.type = type;
        this.img_src = img_src;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getImg_src() {
        return img_src;
    }

    public void setImgSrc(String img_src) {
        this.img_src = img_src;
    }

    @Override
    public String toString() {
        return "Product{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", price=" + price +
                ", type='" + type + '\'' +
                ", img_src='" + img_src + '\'' +
                '}';
    }
}
