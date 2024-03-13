package com.springSecurity.Authentication;

import com.springSecurity.user.Rol;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
   
    private String nombre;
    private String apellido;
    private String email;
    private String pass;
    private Rol rol;
}
