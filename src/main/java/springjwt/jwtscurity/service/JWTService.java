package springjwt.jwtscurity.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import springjwt.jwtscurity.model.User;

import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import java.util.Date;
import java.util.function.Function;

@Service
public class JWTService {

    private final String SECRET_KEY = "47eeeda608e83c43c1a70934d930b48f5f4c650b3947bc4087f1ef86534d3d0a";//secret key generate


 public String extractUsername(String token){ //extract username from claim
    return extractClaim(token,Claims::getSubject);
}

//validate the token
    public boolean isValid(String token, UserDetails user){
     String username = extractUsername(token); // equal to username to token (if the extract to username)
     return (username.equals(user.getUsername())) && !isTokenExpired(token);
     ///if the extract username equal user.getsername is the true , then return value


        //if the username = extractUsername for token and token is not expired , then return the boolen value true


    }

    private boolean isTokenExpired(String token) {
     return extractExpiration(token).before(new Date());
     //make isTokenExpired method
    }

    private Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);// what is the expire date of token
    }

    public <T> T extractClaim(String token, Function<Claims,T>resolver){
        Claims claims = extraAllClaims(token);
        return  resolver.apply(claims); //extract all claims or payload

    }


    private Claims extraAllClaims(String token){ //extract payload from token
        return  Jwts
                .parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();


    }

    public String generateToken(User user){ //token generation
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
                .signWith(getSignKey())
                .compact();

             return token;

    }
    private SecretKey getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
