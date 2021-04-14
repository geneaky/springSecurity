package com.toy.springSecurity.config.oauth;

import com.toy.springSecurity.config.auth.PrincipalDetails;
import com.toy.springSecurity.config.oauth.provider.FaceBookUserInfo;
import com.toy.springSecurity.config.oauth.provider.GoogleUserInfo;
import com.toy.springSecurity.config.oauth.provider.OAuth2UserInfo;
import com.toy.springSecurity.model.User;
import com.toy.springSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());
        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 ->액세스코드를 주는데 이걸 (OAuth-Client라이브러리가 인터셉트해서) -> accesstoken을 요청
        //userRequest -> loadUser함수 -> 회원 프로필
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("google login request");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("facebook login request");
            oAuth2UserInfo = new FaceBookUserInfo(oAuth2User.getAttributes());
        }else{
            System.out.println("notProper request");
        }


        String provider = oAuth2UserInfo.getProvider();//google
        String providerId = oAuth2UserInfo.getProviderId();
        String email = oAuth2UserInfo.getEmail();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("geneaky");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if(userEntity==null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
