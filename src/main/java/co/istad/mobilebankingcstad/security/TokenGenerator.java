package co.istad.mobilebankingcstad.security;

import co.istad.mobilebankingcstad.domain.User;
import co.istad.mobilebankingcstad.features.auth.dto.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;


@Component
public class TokenGenerator {

    JwtEncoder jwtAccessTokenEncoder;
    JwtEncoder jwtRefreshTokenEncoder;

    public TokenGenerator(JwtEncoder jwtAccessTokenEncoder,@Qualifier("jwtRefreshTokenEncoder") JwtEncoder jwtRefreshTokenEncoder){
        this.jwtAccessTokenEncoder = jwtAccessTokenEncoder;
        this.jwtRefreshTokenEncoder = jwtRefreshTokenEncoder;
    }

    private String createAccessToken(Authentication authentication){
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(now.plus(5, ChronoUnit.MINUTES))
                .subject(userDetails.getUsername())
                .issuer("istad.co.mobilebanking")
                .claim("scope", "read write")
                .build();
        return jwtAccessTokenEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // expired 7 days
    private String createRefreshToken(Authentication authentication){
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet
                .builder()
                .issuedAt(now)
                .expiresAt(now.plus(7, ChronoUnit.DAYS))
                .subject(userDetails.getUsername())
                .issuer("istad.co.mobilebanking")
                .claim("scope", "read write")
                .notBefore(now)
                .build();
        return null;
    }
    public AuthResponse generateAccessToken(Authentication authentication){
        if (!(authentication.getPrincipal() instanceof CustomUserDetails customUserDetails)){
            throw new BadCredentialsException("Provided principal is not an instance of CustomUserDetails");
        }

        String refreshToken;
        if (authentication.getCredentials() instanceof Jwt jwt){
            Instant now = Instant.now();
            Instant expireAt = jwt.getExpiresAt();
            Duration duration = Duration.between(now, expireAt);
            long daysUtilsExpired = duration.toDays();

            if (daysUtilsExpired > 7){
                refreshToken = createRefreshToken(authentication);
            }else {
                refreshToken = jwt.getTokenValue();
            }
        }else {
            refreshToken = createRefreshToken(authentication);
        }



        return AuthResponse.builder()
                .refreshToken(refreshToken)
                .accessToken(createAccessToken(authentication))
                .userId(customUserDetails.getUser().getId())
                .build();
    }
}
