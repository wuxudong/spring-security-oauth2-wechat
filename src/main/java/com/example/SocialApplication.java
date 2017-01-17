/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.Filter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
@RestController
@EnableOAuth2Client
public class SocialApplication extends WebSecurityConfigurerAdapter {

    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @RequestMapping({ "/user", "/me" })
    public Principal user(Principal principal) {
        return principal;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests().antMatchers("/login**").permitAll().anyRequest()
                .authenticated().and().exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")).and().logout()
                .logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
        // @formatter:on
    }

    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new WechatOAuth2ClientContextFilter());
        registration.setOrder(-100);
        return registration;
    }

    private Filter ssoFilter() {
        OAuth2ClientAuthenticationProcessingFilter wechatFilter = new OAuth2ClientAuthenticationProcessingFilter(
                "/login");
        OAuth2RestTemplate wechatTemplate = new OAuth2RestTemplate(wechat(), oauth2ClientContext) {
            @Override
            protected URI appendQueryParameter(URI uri, OAuth2AccessToken accessToken) {
                try {
                    String query = uri.getRawQuery(); // Don't decode anything here
                    String tokenQueryFragment = this.getResource().getTokenName() + "=" + URLEncoder.encode
                            (accessToken.getValue(),
                                    "UTF-8");
                    if (query == null) {
                        query = tokenQueryFragment;
                    } else {
                        query = query + "&" + tokenQueryFragment;
                    }

                    String openid = (String) accessToken
                            .getAdditionalInformation().get("openid");

                    String openIdQueryFragment = "openid=" + URLEncoder.encode(openid, "UTF-8");
                    query = query + "&" + openIdQueryFragment;

                    // first form the URI without query and fragment parts, so that it doesn't re-encode some query
                    // string chars
                    // (SECOAUTH-90)
                    URI update = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), uri
                            .getPath(), null,
                            null);
                    // now add the encoded query string and the then fragment
                    StringBuffer sb = new StringBuffer(update.toString());
                    sb.append("?");
                    sb.append(query);
                    if (uri.getFragment() != null) {
                        sb.append("#");
                        sb.append(uri.getFragment());
                    }

                    return new URI(sb.toString());

                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException("Could not parse URI", e);
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalArgumentException("Could not encode URI", e);
                }
            }
        };


        AuthorizationCodeAccessTokenProvider accessTokenProvider = new AuthorizationCodeAccessTokenProvider();
        RequestEnhancer requestEnhancer = (request, resource, form, headers) -> {

            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

            List<String> clientId = form.get("client_id");
            if (clientId != null) {
                form.remove("client_id");
                form.put("appid", clientId);
            }

            List<String> clientSecret = form.get("client_secret");

            if (clientSecret != null) {
                form.remove("client_secret");
                form.put("secret", clientSecret);
            }
        };

        accessTokenProvider.setAuthorizationRequestEnhancer(requestEnhancer);
        accessTokenProvider.setTokenRequestEnhancer(requestEnhancer);

        MappingJackson2HttpMessageConverter customJsonMessageConverter = new
                MappingJackson2HttpMessageConverter();
        customJsonMessageConverter.setSupportedMediaTypes(Arrays.asList(MediaType.TEXT_PLAIN));

        accessTokenProvider.setMessageConverters(Arrays.asList(customJsonMessageConverter));

        wechatTemplate.setAccessTokenProvider(accessTokenProvider);
        wechatTemplate.setMessageConverters(Arrays.asList(customJsonMessageConverter));


        wechatFilter.setRestTemplate(wechatTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(wechatResource().getUserInfoUri(), wechat
                ().getClientId());

        tokenServices.setRestTemplate(wechatTemplate);
        wechatFilter.setTokenServices(tokenServices);
        return wechatFilter;
    }

    @Bean
    @ConfigurationProperties("wechat.client")
    public AuthorizationCodeResourceDetails wechat() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("wechat.resource")
    public ResourceServerProperties wechatResource() {
        return new ResourceServerProperties();
    }

}
