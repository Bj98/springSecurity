package com.example.springSecurity.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.springSecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    EMPLOYEE(new HashSet<>()),
    ADMIN(new HashSet<>(Arrays.asList(EMPLOYEE_READ,EMPLOYEE_WRITE,WORK_READ,WORK_WRITE))),
    ADMINTRAINEE(new HashSet<>(Arrays.asList(EMPLOYEE_READ,WORK_READ)));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions=getPermissions().stream()
                .map(permission-> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return permissions;
    }
}
