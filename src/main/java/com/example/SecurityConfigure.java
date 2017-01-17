package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.servlet.Filter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

/**
 * User: xudong
 * Date: 17/01/2017
 * Time: 5:19 PM
 */
@Configuration
public class SecurityConfigure extends WebSecurityConfigurerAdapter {
    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests().antMatchers("/login**").permitAll().anyRequest()
                .authenticated().and().exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")).and().logout()
                .logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class).addFilterBefore(new
                WechatOAuth2ClientContextFilter(), OAuth2ClientAuthenticationProcessingFilter.class);
        // @formatter:on
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
