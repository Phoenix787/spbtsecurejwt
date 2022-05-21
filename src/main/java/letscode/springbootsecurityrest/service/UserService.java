package letscode.springbootsecurityrest.service;

import letscode.springbootsecurityrest.model.User;
import letscode.springbootsecurityrest.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

@Service
public class UserService implements UserDetailsService {
    private UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    public List<User> getAll() {
        return repository.getAll();
    }
    public User getByLogin(String login) {
        return repository.getByLogin(login);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = getByLogin(username);
        if (Objects.isNull(u)) {
            throw new UsernameNotFoundException( String.format("User %s is not found", username));
        }
        return new org.springframework.security.core.userdetails.User(
                u.getLogin(),
                u.getPassword(),
                true,
                true,
                true,
                true,
                new HashSet<>());
    }
}
