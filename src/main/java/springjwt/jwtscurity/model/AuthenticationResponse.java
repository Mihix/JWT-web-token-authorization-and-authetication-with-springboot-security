package springjwt.jwtscurity.model;

public class AuthenticationResponse {

    private String token;


    //why made a constructor , reason is set the value
    public AuthenticationResponse(String token) {
        this.token = token;
    }


    //get the value of token
    public String getToken() {
        return token;
    }


}
