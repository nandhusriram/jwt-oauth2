package org.januslabs.oauth2.authorization.server;

import org.januslabs.oauth2.jwt.base.OAuthClientDetailsService;
import org.januslabs.oauth2.jwt.base.OAuthUserService;
import org.januslabs.oauth2.jwt.mongo.repository.JWTMongoTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@EnableMongoRepositories(basePackages = "org.januslabs.oauth2.jwt.mongo")
@ComponentScan(basePackages = {"org.januslabs.oauth2.jwt.base", "org.januslabs.oauth2.jwt.mongo"})
public class OAuth2Application {

  public static void main(String[] args) {
    SpringApplication.run(OAuth2Application.class);
  }


  @Configuration
  @EnableWebSecurity
  protected static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    private @Autowired OAuthUserService userDetailsService;

    @Override
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.userDetailsService(userDetailsService);
    }

    @Override
    @Bean(name="authenticationManagerBean")
    public AuthenticationManager authenticationManagerBean() throws Exception 
    {
        return super.authenticationManagerBean();
    }

  }
  
  @Configuration
  @EnableAuthorizationServer
  @Slf4j
  protected static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
      // @formatter:off
      endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer())
          .userApprovalHandler(approvalHandler()).authenticationManager(authenticationManager);
      // @formatter:on
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
      oauthServer.tokenKeyAccess("isAnonymous()").checkTokenAccess("permitAll()")
          .checkTokenAccess("hasRole('TRUSTED_CLIENT')");
    }

    @Bean
    public OAuthClientDetailsService clientDetailsService() {
      return new OAuthClientDetailsService();
    }

    @Bean
    @Qualifier("tokenStore")
    public TokenStore tokenStore() {

      log.info("Created JwtTokenStore");
      return new JWTMongoTokenStore(jwtTokenEnhancer());
    }

    @Bean
    protected JwtAccessTokenConverter jwtTokenEnhancer() {
      KeyStoreKeyFactory keyStoreKeyFactory =
          new KeyStoreKeyFactory(new ClassPathResource("oauth2-authorization-server.jks"), "royals".toCharArray());
      JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
      /*
       * converter.setSigningKey(privateKey); converter.setVerifierKey(publicKey);
       */
      converter.setKeyPair(keyStoreKeyFactory.getKeyPair("januslabskey"));
      return converter;
    }

    @Bean
    public UserApprovalHandler approvalHandler() {
      UserApprovalHandler approvalHandler = new DefaultUserApprovalHandler();
      return approvalHandler;

    }

  }

}
