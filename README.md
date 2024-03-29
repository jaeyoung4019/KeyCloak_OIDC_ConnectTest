# KeyCloak_OIDC_ConnectTest
현재 아키텍쳐 상으로

React - ( Authorization Code 방식 앤드포인트요청) → KeyCloak - (Code , Token 교환)  → Node- (Token) → React

이기 때문에 keycloak user 를 가져와서 현재 사용하는 user 테이블에 넣어주어야 한다.

node 에서 react 로 기본적인 추가 설정을 받도록 하는 페이지로 redirect 보낼 것이기 때문에 

그 페이지에서 요청 받아 users 테이블에 save 하는 과정이 필요하다.

```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

  private final UserService userService;

		@PostMapping("/init/save")
    @ApiOperation(value = "첫 로그인 회원 저장")
    public Response<String> userInitSave(@RequestBody
                                             @ApiParam(name = "첫 로그인 회원 저장 요청 객체")
                                                UserSaveRequestDto userSaveRequestDto ,
                                         @ApiIgnore
	                                         Authentication authentication){
        return new Response.ResponseBuilder<String>("회원 가입에 성공하였습니다." , 200)
                .total(userService.initSave(userSaveRequestDto, authentication))
                .build();
    }
	
}
```

토큰으로 인증되어 있는 객체의 값을 가져와서 id 를 알아와야 하기 때문에 Authentication 객체를 가져와서 service 에 넘겨준다.

마이바티스 xml 설정시 인텔리제이 워닝이 떠서 고치는 방법

![image](https://github.com/jaeyoung4019/KeyCloak_OIDC_ConnectTest/assets/135151752/796968da-02ad-4ab0-813d-697b170c60a9)

```markup
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.keti.iam.idthub.mapper.UserMapper">

    <!-- 유저 테이블에 가입이 되어있는 사람인지 체크 -->
    <select id="countFindById" parameterType="string" resultType="int">
        select
            count(id)
        from iam.users
          where id = #{id}
    </select>

    <!-- 유저 테이블 저장-->
    <insert id="initSave" parameterType="userSaveRequestDto" >
        insert into iam.users values ( #{id} , #{email} , #{name} , #{company} , #{location} , #{webSite}
        , 'Y' , now() , now())
    </insert>

</mapper>
```

userService 

```java
package com.keti.iam.idthub.service.user;

import com.keti.iam.idthub.dto.user.UserSaveRequestDto;
import com.keti.iam.idthub.mapper.UserMapper;
import com.keti.iam.idthub.util.exception.RestException;
import com.keti.iam.idthub.util.keycloak.KeyCloakUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.resource.UserResource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImp implements UserService{

    private final UserMapper userMapper;
    private final KeyCloakUser keyCloakUser;

    @Override
    public int initSave(UserSaveRequestDto userSaveRequestDto , Authentication authentication) throws RestException {
        String keyCloakId = authentication.getName(); // a3e0e937-a23a-4af5-a09a-388deb3cf14f
        if(userMapper.countFindById(keyCloakId) > 0)
            throw new RestException("이미 존재하는 회원 입니다." , 403);
        else {
            userSaveRequestDto.setId(keyCloakId);
            String email = keyCloakUser.keyCloakUserInfoFindById(keyCloakId).toRepresentation().getEmail();
            userSaveRequestDto.setEmail(email);
            return userMapper.initSave(userSaveRequestDto);
        }
    }
}
```

controller 

```java
package com.keti.iam.idthub.controller.user;

import com.keti.iam.idthub.dto.user.UserSaveRequestDto;
import com.keti.iam.idthub.service.user.UserService;
import com.keti.iam.idthub.util.exception.RestException;
import com.keti.iam.idthub.util.response.Response;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.Authorization;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/init/save")
    @ApiOperation(value = "첫 로그인 회원 저장")
    public Response<String> userInitSave(@RequestBody
                                             @ApiParam(name = "첫 로그인 회원 저장 요청 객체")
                                                UserSaveRequestDto userSaveRequestDto ,
                                         @ApiIgnore
                                         Authentication authentication) throws RestException {
        return new Response.ResponseBuilder<String>("회원 가입에 성공하였습니다." , 200)
                .total(userService.initSave(userSaveRequestDto, authentication))
                .build();
    }

}
```

gitHubIdp 추가하기 



![image](https://github.com/jaeyoung4019/KeyCloak_OIDC_ConnectTest/assets/135151752/99d795cd-c2c4-45be-9a6a-56df94057ec7)

추가 해준다.

![image](https://github.com/jaeyoung4019/KeyCloak_OIDC_ConnectTest/assets/135151752/a68943d4-12b3-4363-84c5-7d10b6657bc7)

깃 허브도 정상적으로 연동 됨

테스트 코드 

```java
package com.keti.iam.idthub.user;

import com.keti.iam.idthub.dto.user.UserSaveRequestDto;
import com.keti.iam.idthub.mapper.UserMapper;
import com.keti.iam.idthub.service.user.UserService;
import com.keti.iam.idthub.util.exception.RestException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@SpringBootTest
public class UserTest {

    @Autowired
    UserService userService;
    @Autowired
    UserMapper userMapper;

    @Test
    @DisplayName("유저 저장 테스트")
    void userSaveTest() throws RestException {
        UserSaveRequestDto user = new UserSaveRequestDto();
        user.setCompany("testCompany");
        user.setLocation("testLocation");
        user.setName("testName");
        user.setFirstLoginRequest(true);
        user.setWebSite("www.test.co.kr");

        userService.initSave(user, new Authentication() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return false;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

            }

            @Override
            public String getName() {
                return "a3e0e937-a23a-4af5-a09a-388deb3cf14f";
            }
        });
        int i = userMapper.countFindById("a3e0e937-a23a-4af5-a09a-388deb3cf14f");

        Assertions.assertThat(i).isEqualTo(1);
    }
}
```

테스트용 yml 설정 

```markup
mybatis:
  mapper-locations: classpath:/mapper/*.xml

spring:
  mvc:
    path match:
      matching-strategy: ant_path_matcher
  jwt:
    header: Authorization
  datasource:
    driver-class-name: org.postgresql.Driver
    jdbc-url: jdbc:postgresql://13.209.166.14:30000/idthub
    username: idthub
    password: Idthub!A
  security:
    oauth2:
      resource-server:
        jwt:
          issuer-uri: http://localhost:8090/realms/test # require
          jwk-set-uri: http://localhost:8090/realms/test/protocol/openid-connect/certs  # require
keycloak:
  enabled: true
  realm: test
  auth-server-url: http://localhost:8090
  ssl-required: external
  resource: test
  credentials:
    secret: 2ocjAn7aoWmSPirKbqHvdiVfagNYTpKs
  use-resource-role-mappings: true
  # bearer-only: true  #// ??? ??? ??? ?? ??.
  principal-attribute: preferred_username

cors.iamWeb: http://localhost:8081
cors.keycloak: http://localhost:8090
```

결과 

![image](https://github.com/jaeyoung4019/KeyCloak_OIDC_ConnectTest/assets/135151752/0fbbec3b-fb9f-4d77-b1e3-4d9768b88ba1)


유저 카운트 체크 테스트
![image](https://github.com/jaeyoung4019/KeyCloak_OIDC_ConnectTest/assets/135151752/a44b0c82-178b-4303-9175-37e6a4c0ec10)

