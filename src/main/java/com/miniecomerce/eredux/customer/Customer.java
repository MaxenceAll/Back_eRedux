package com.miniecomerce.eredux.customer;

import com.miniecomerce.eredux.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "customer")
public class Customer implements UserDetails {

    @Id
    @GeneratedValue
    private Long id;
    @Column(unique = true)
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    @OneToMany(mappedBy = "customer")
    private List<Token> tokens;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities () {
        return List.of(new SimpleGrantedAuthority((role.name())));
    }
    @Override
    public String getUsername () {
        return email;
    }
    @Override
    public boolean isAccountNonExpired () {
        return true;
    }
    @Override
    public boolean isAccountNonLocked () {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired () {
        return true;
    }
    @Override
    public boolean isEnabled () {
        return true;
    }
}