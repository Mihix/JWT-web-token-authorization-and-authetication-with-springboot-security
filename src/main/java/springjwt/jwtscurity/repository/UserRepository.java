package springjwt.jwtscurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springjwt.jwtscurity.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByUsername(String username);
}
