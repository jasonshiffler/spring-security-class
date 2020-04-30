package com.shiffler.springsecurityclass.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(ApplicationUserPermission.COURSE_READ,
            ApplicationUserPermission.COURSE_WRITE,
            ApplicationUserPermission.STUDENT_READ,
            ApplicationUserPermission.STUDENT_WRITE)),

    ADMINTRAINEE(Sets.newHashSet(ApplicationUserPermission.COURSE_READ,
                    ApplicationUserPermission.STUDENT_READ));

    private final Set<ApplicationUserPermission> permissionSet;

    ApplicationUserRole(Set<ApplicationUserPermission> permissionSet) {
        this.permissionSet = permissionSet;
    }

    public Set<ApplicationUserPermission> getPermissions(){
        return permissionSet;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permisions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission())).collect(Collectors.toSet());
        permisions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permisions;
    }
}
