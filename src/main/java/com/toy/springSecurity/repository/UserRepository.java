package com.toy.springSecurity.repository;

import com.toy.springSecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

//@Repository jparepository 내부에서 들고있고 그걸 상속받았기 때문에 없어도됨
public interface UserRepository extends JpaRepository<User,Integer> {
    public User findByUsername(String username);
}
