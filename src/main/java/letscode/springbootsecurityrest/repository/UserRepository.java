package letscode.springbootsecurityrest.repository;

import letscode.springbootsecurityrest.model.User;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserRepository {
    private List<User> users;

    public UserRepository() {
        this.users = List.of(
                new User("a", "1234", "Anton", "Ivanov", 20 ),
                new User("u", "123", "Ivan", "Petrov", 21)
        );
    }

    public User getByLogin(String login) {
        return this.users
                .stream()
                .filter(user -> login.equals(user.getLogin()))
                .findFirst()
                .orElse(null);
    }
    public List<User> getAll() {
        return  this.users;
    }
}
