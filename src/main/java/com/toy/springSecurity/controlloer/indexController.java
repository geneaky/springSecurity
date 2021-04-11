package com.toy.springSecurity.controlloer;
import javax.servlet.http.HttpSession;

import com.toy.springSecurity.config.auth.PrincipalDetails;
import com.toy.springSecurity.model.User;
import com.toy.springSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class indexController {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String loginTest(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        System.out.println("principalDetails = " + principalDetails);
        System.out.println("userDetails.getUsername() = " + userDetails.getUser());
        return "세션 정보 확인";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oauth){
        System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("principalDetails.getUser() = " + oauth2User.getAttributes());
        System.out.println("oauth.getAttributes() = " + oauth.getAttributes());
        return "oauth 세션 정보 확인";
    }
    //스프링 시큐리티는 자신만의 세션을 가지는데(시큐리티 세션)이건 서버가 가지고있는 session영역안에 있음
    //시큐리티 세션 영역에 들어갈수있는 타입은 Authentication객체 밖에 없음
    //Authentication객체에 들어갈 수 있는 2개의 타입은 UserDetails(일반 로그인)와 OAuth2User(oauth 로그인)가 있다.

    @GetMapping({"","/"})
    public String index(){
        return "index";
    }

    //OAuth 로그인을 해도 PrincipalDetails 타입으로 받을 수 있고
    //일반 로그인을 해도 PrincipalDetails 타입으로 받을 수 있다.
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails)
    {
        System.out.println("principalDetails = " + principalDetails.getUser());
        return "user";

    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String login(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping ("/join")
    public String join(User user){
        System.out.println("user = " + user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("/data")
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    public @ResponseBody String data(){
        return "데이터정보";
    }

}
