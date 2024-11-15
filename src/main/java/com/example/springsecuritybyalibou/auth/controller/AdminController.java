package com.example.springsecuritybyalibou.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/admin")
@PreAuthorize("hasRole('ADMIN')") //for this PreAuthorized we have to @EnableMethodSecurity (on security config)
public class AdminController {

    @GetMapping
    @PreAuthorize("hasAuthority('admin::read')")
    public String get(){
        return "GET:: admin controller";
    }


    @PostMapping
    @PreAuthorize("hasAuthority('admin::create')")
    public String post(){
        return "POST:: admin controller";
    }



    @PutMapping
    @PreAuthorize("hasAuthority('admin::update')")
    public String put(){
        return "PUT:: admin controller";
    }


    @DeleteMapping
    @PreAuthorize("hasAuthority('admin::delete')")
    public String delete(){
        return "DELETE:: admin controller";
    }

}
