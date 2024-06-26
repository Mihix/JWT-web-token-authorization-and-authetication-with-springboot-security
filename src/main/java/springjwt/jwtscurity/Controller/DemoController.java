package springjwt.jwtscurity.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/demo")
    public ResponseEntity<String> demo(){
        return  ResponseEntity.ok("Hello from Secured url");
    }

    //let's do the authorization part
    @GetMapping("/admin_only")
    public ResponseEntity<String>adminOnly(){
        return ResponseEntity.ok("Hello from the admin only");
    }
}
