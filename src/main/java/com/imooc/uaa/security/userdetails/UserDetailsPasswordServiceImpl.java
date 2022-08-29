package com.imooc.uaa.security.userdetails;

import com.imooc.uaa.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/***
 * 密码无缝升级，用户无感知
 */
@Transactional
@RequiredArgsConstructor
@Service
public class UserDetailsPasswordServiceImpl implements UserDetailsPasswordService {

    private final UserRepo userRepo;

    /**
     *
     * @param user
     * @param newPassword 系统已经按照新的编码方式处理好的 新的密码的hash
     * @return
     * @with 用于更改的  @Builder 用于构造
     */
    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        return userRepo.findOptionalByUsername(user.getUsername())
            // userFromDb其实是查询出来的optional<User>他有可能为null，map是不为null的情况下
            /*.map(userFromDb -> userRepo.save(userFromDb.withPassword(newPassword)))
            .orElseThrow();*/
        .map(userFromDB->{
            return (UserDetails)userRepo.save(userFromDB.withPassword(newPassword));
        }).orElse(user);

    }
}
