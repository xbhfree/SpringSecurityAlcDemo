package java.com.example.security;

import com.example.utils.MD5;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class TokenManager {
    //token有效时间 ms为单位,Expiration截至时间，到期
    //@Value("${jwt.tokenExpiration}")  可以配置文件设置
    private long tokenExpiration = 24*60*60*1000;

    //编码密钥，需要自动生成
    private String tokenSignKey = "123456";
    // 从本地文件生成密钥
    private SecretKey secretKey = Keys.hmacShaKeyFor(MD5.encrypt(tokenSignKey).getBytes());

    /**
     * 初始化负载参数
     */
    private Map<String, Object> initClaims(String username){
        Map<String, Object> claims = new HashMap<String, Object>();
        //iss(Issuer),代表jwt的签发者，可以填入应用程序名或者一个标识符
        claims.put("iss", "spring_security_alc_demo");
        //sub(subject),代表jwt的主题，即jwt面向的用户，可以是用户的唯一标识或者其他相关信息
        claims.put("sub", username);
        //exp(expiration time),代表jwt的过期时间，通常以unix时间戳表示，表示在这个时间之后该jwt会过期
        //通常设定一个未来的时间点保证jwt的有效性，比如1个小时，1天，1个月
        claims.put("exp", new Date(System.currentTimeMillis() + tokenExpiration));
        //aud(audience),代表jwt的接受者，可以填入该jwt预期的接收者，可以是1个、1组用户或者某个服务
        claims.put("aud", "alisa");
        //iat(Issued At),代表jwt的签发时间，以unix时间戳表示
        claims.put("iat", new Date());
        //jti(jtw id),代表jwt的唯一标识，标志jwt的唯一性，避免重放攻击等问题
        claims.put("jti", UUID.randomUUID().toString());
        //nbf(not before),代表jwt的生效时间，在这个时间之前jwt不会生效，以unix时间戳表示
        return claims;
    }
    //使用jwt根据用户名生成token
    public String createToken(String username){
        //claims 要求,可以加别的信息进去
        //claims.put("id", userDetails.getId());
        String token = Jwts.builder()
                .claims(initClaims(username))
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
        return token;
    }

    //根据token获取用户信息
    public String getUserInfoFromToken(String token){
        String username;
        try {
            username = getPayloadFromToken(token).getSubject();
        }catch (Exception e){
            username = null;
        }
        return username;
    }

    //从token中获取负载中的claims
    private Claims getPayloadFromToken(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
