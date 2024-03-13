package com.springSecurity.user;

import com.springSecurity.token.Token;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.Collection;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


@Data
@Builder    
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "User" )
public class User implements UserDetails{ 
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String nombre;
    private String apellido;
    private String email;
    private String pass;
    @Enumerated(EnumType.STRING)
    /*Los valores almacenados se almacen como cadenas Esto es más seguro en términos de integridad de datos, ya que los valores almacenados no cambiarán 
    incluso si el orden de los valores enumerados se modifica.*/
    private Rol rol;
    
 @OneToMany(mappedBy = "user")
  private List<Token> tokens;




    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        /*  SimpleGrantedAuthority es una clase que representa roles o autorizaciones en el contexto de Spring Security. 
        Se utiliza para definir y configurar qué acciones o recursos puede acceder un usuario autenticado en una aplicación.
       return List.of(new SimpleGrantedAuthority(rol.name()));
       nos retorna una losta con los roles 
       */
        
         return rol.getAuthorities();
        
    }

    @Override
    public String getUsername() {
      return email;
    }

    @Override
    public boolean isAccountNonExpired() {
       return true ;
    }

    @Override
    public boolean isAccountNonLocked() {
       return true ;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true ;
    }

    @Override
    public boolean isEnabled() {
         return true ; 
    }

    @Override
    public String getPassword() {
        return pass;
    }
    
}
