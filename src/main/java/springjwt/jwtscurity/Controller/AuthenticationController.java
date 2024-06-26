package springjwt.jwtscurity.Controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import springjwt.jwtscurity.model.AuthenticationResponse;
import springjwt.jwtscurity.model.User;
import springjwt.jwtscurity.service.AuthenticationService;

@RestController
public class AuthenticationController {

    //this class handle login and registration request for user registration and login


    private final AuthenticationService authService;

    public AuthenticationController(AuthenticationService authService) {
        this.authService = authService;
    }


    //generate the constructor for setting the value


    @PostMapping("/register") // It is for register
    public ResponseEntity<AuthenticationResponse> register( @RequestBody User request){
        return ResponseEntity.ok(authService.register(request));
    }

    //another postmapping for login url
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse>login(@RequestBody User request){
    return  ResponseEntity.ok(authService.authenticate(request));
    }
}
