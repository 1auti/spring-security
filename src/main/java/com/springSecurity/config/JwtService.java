package com.springSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
 public class JwtService {
    
  @Value("${application.security.jwt.secret-key}")
  private String secretKey;
  @Value("${application.security.jwt.expiration}")
  private long jwtExpiration;
  @Value("${application.security.jwt.refresh-token.expiration}")
  private long refreshExpiration;
   
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
     /*se utiliza para extraer una "claim" específica (información) de un token JWT.
    Esta función toma como argumentos el token JWT y una función (Function<Claims, T> claimsResolver)
    que se utiliza para extraer y resolver la información de la "claim" específica del objeto Claims.*/
    final Claims claims = extractAllClaims(token);// Llama al método extractAllClaims(token) para obtener todas las "claims" del token JWT
    return claimsResolver.apply(claims);
    /*Utiliza la función claimsResolver para aplicarla al objeto Claims y extraer la información específica de la claim que deseas obtener. 
    Esta función claimsResolver debe ser proporcionada cuando se llama al método. 
    La función apply(claims) toma el objeto Claims y devuelve el valor deseado del tipo T (que se especifica cuando se llama al método).*/
  }
    
    public String extractUsername(String token){ //utiliza el método genérico extractClaim para obtener el sujeto (subject) de un token JWT. El método Claims::getSubject se pasa como argumento para resolver y extraer la información del sujeto del token.
           return extractClaim(token, Claims::getSubject); 
           /*return extractClaim(token, Claims::getSubject);: Utiliza el método genérico extractClaim para extraer el sujeto del token JWT. 
           La notación Claims::getSubject es una referencia a un método y se pasa como argumento a extractClaim. 
           Esto significa que estás utilizando la función getSubject de la clase Claims para extraer el sujeto.

           Claims::getSubject: Esto es una referencia a un método. 
           Claims es la clase que representa las afirmaciones (claims) del token JWT,
           y getSubject es un método en la clase Claims que devuelve el sujeto del token.

           extractClaim(token, Claims::getSubject): Llama al método genérico extractClaim, pasando el token y la referencia al método getSubject.
           Esto indica que quieres extraer el sujeto del token JWT.*/
           
    }
    
    private Claims extractAllClaims(String token) {
      //toma un token JWT como argumento y devuelve un objeto Claims. 
    //El objeto Claims es una parte del token que contiene las declaraciones (claims) del mismo.
    return Jwts //La clase Jwts proporciona métodos estáticos para trabajar con tokens JWT.
        .parserBuilder() //Aquí estás obteniendo un builder (constructor) para crear un parser (analizador) de tokens JWT.
        .setSigningKey(getSignInKey()) //setSigningKey(getSignInKey()): Configura la clave de firma que se utilizará para validar el token
            //La función getSignInKey() se utiliza para obtener la clave de firma.
        .build() //Construye el analizador de tokens JWT con la configuración previamente establecida.
        .parseClaimsJws(token) // Este método toma el token JWT y lo analiza. Devuelve un objeto Jws<Claims>, que contiene las claims del token y la firma digital.
        .getBody(); // Desde el objeto Jws<Claims>, puedes obtener el cuerpo del token (que contiene las claims) usando este método. Devuelve un objeto Claims que contiene la información de las claims en el token.
    
    /*En resumen, este código se encarga de analizar y validar un token JWT. Utiliza la librería jjwt para realizar estas operaciones. 
    Primero, configura el parser con la clave de firma adecuada. 
    Luego, analiza el token para obtener las claims y devuelve el objeto Claims que contiene la información de las claims. 
    Esto es útil cuando necesitas acceder a la información contenida en el token JWT, como los datos del usuario o los detalles de autenticación.*/
    
  } 
    
    private Key getSignInKey() { 
 //se encarga de obtener la clave de firma (SECRET KEY) para validar un token JWT
//método privado que devuelve un objeto de tipo Key, que será la clave de firma utilizada para verificar la autenticidad del token JWT.
    byte[] keyBytes = Decoders.BASE64.decode(secretKey); //estás decodificando una cadena base64 SECRET_KEY en un array de bytes. La clase Decoders proporciona métodos para decodificar valores base64.
    return Keys.hmacShaKeyFor(keyBytes); 
    /* Utilizas el array de bytes decodificado para construir una clave de firma HMAC (Hash-Based Message Authentication Code) 
    utilizando el algoritmo SHA (Secure Hash Algorithm). La clase Keys proporciona métodos estáticos para crear claves.*/
    }
    
    public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }
   
    public String generateToken(Map<String, Object> extraClaims,UserDetails userDetails) {
    return buildToken(extraClaims, userDetails, jwtExpiration);
  }
    
    public String generateRefreshToken(UserDetails userDetails){
    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

    private String buildToken(Map<String,Object> extraClaims,UserDetails userDetails,long expiration){ //se utiliza para construir y generar un nuevo token JWT con información adicional y ciertos detalles de usuario
        return Jwts
            .builder() // Aquí estás obteniendo un objeto JwtBuilder para construir el token JWT.
            .setClaims(extraClaims)// Establece las "claims" adicionales que deseas incluir en el token.
            .setSubject(userDetails.getUsername())//Establece el sujeto (subject) del token como el nombre de usuario del usuario en los detalles proporcionados.
            .setIssuedAt(new Date(System.currentTimeMillis()))// Establece el momento de emisión del token como la fecha y hora actual.
            .setExpiration(new Date(System.currentTimeMillis() + expiration))// Establece el tiempo de expiración del token sumando la duración de expiración proporcionada al tiempo actual.
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)//Firma el token con la clave de firma utilizando el algoritmo de firma HMAC-SHA256.
            .compact();//Genera el token JWT en forma compacta (cadena codificada).
    }
    
    public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

    private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

    private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }
    
    
}
