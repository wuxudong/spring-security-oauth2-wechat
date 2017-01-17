# spring-security-oauth2-wechat

## oauth2 & 微信

因为需要一个微信授权登录的功能，官方例子基本是基于node js的。  
由于java写得顺手，所以想找一个java的例子。  
网上能搜到一些 java 的实现，但基本上也是 js 的翻译版。
    
## spring-security-oauth2 & 微信

因为之前权限一般丢给spring-security，所以也想将微信集成进去，但没有现成的例子。   
spring 官方提供 oauth2 的标准实现，可以直接支持 github，twitter，facebook 等等的 oauth2 授权登录。  
所以应该也能支持微信吧，不都是oauth2么。
    
## 坑 & 解决办法

拷贝了github的例子，改成微信的配置，运行了一把，发现有以下坑:
    
* 标准在重定向到授权方时，携带的参数为 client_id, 而微信为 appid, 并且要求在尾部追加 fragment #wechat_redirect
    
解决方法:扩展 OAuth2ClientContextFilter， 将参数 client_id 修改为 appid, 并追加 #wechat_redirect。    
将扩展的 OAuth2ClientContextFilter 注入spring security filter chain
    
* 在获取 access_token 时，标准应该是 client_id, client_secret, 但微信使用的是 appid, secret.

解决方法:spring-security-oauth2 提供了 RequestEnhancer, 设置自定义的 enhancer, 将client_id, client_secret 强行替换为 appid, secret。  

* 微信的接口返回 json 格式的内容，但 response header 却是 'text/plain' , 并无视请求的 Accept , 导致 spring resttemplate 无法解析。

解决方法: 设置 AuthorizationCodeAccessTokenProvider 和 resttemplate 的 MessageConverter， 碰到 'text/plain' 也用 json 来解析。

* 微信在获取用户信息时，同 facebook，github 等等不同，还需要额外的 openid (这个应该和 [openid](https://zh.wikipedia.org/zh-hans/OpenID) 协议无关)

解决方法: 扩展 OAuth2RestTemplate， 除了追加 access_token，还额外追加 openid 参数
      
      
## 结语

通过这些折腾，终于将 spring-security-oauth2 和 微信 集成在一起.    
这样可以方便的利用 spring security 带来的各种便利，如注解，remember me 等等。    
本来是极其标准的协议和接口，借助标准框架只需几行配置就可以完成集成.  
却因为一些不必要的不一致和低级错误，浪费了无数程序员的时间。
