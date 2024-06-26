package springjwt.jwtscurity.service;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import springjwt.jwtscurity.model.AuthenticationResponse;
import springjwt.jwtscurity.model.User;
import springjwt.jwtscurity.repository.UserRepository;

import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;

    //we will need another bean for user Authentication
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository, UserRepository repository, PasswordEncoder passwordEncoder, JWTService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    // make registration methods

   public AuthenticationResponse register(User request){
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        user.setRole(request.getRole());

        user = repository.save(user); // save the repository


//after the saving user, let's genrate a token from a jwtService

        String token = jwtService.generateToken(user);

        return new AuthenticationResponse(token);
   }

    //create a method logging the user

    //(user response ) -  accepts the user and variable name is response
    public AuthenticationResponse authenticate(User request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        //now add a new variable
        //user equals this is our registered user we need get the user from the database
        User user = repository.findByUsername(request.getUsername()).orElseThrow();

        // after the  user =  registed user from the database ,generate the token
        String token = jwtService.generateToken(user);

        //finally return new authentication response and pass token
        return new AuthenticationResponse(token);
    }
}
