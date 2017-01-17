package com.example;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * User: xudong
 * Date: 17/01/2017
 * Time: 4:47 PM
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class WechatUser {
    public String openid;
    public String nickname;
    public Integer sex;
    public String language;
    public String country;
    public String province;
    public String city;
    public String headimgurl;
}
