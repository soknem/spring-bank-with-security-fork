package co.istad.mobilebankingcstad.security;

import co.istad.mobilebankingcstad.features.auth.dto.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class TokenGenerator {
    @Autowired
    JwtEncoder jwtAccessTokenEncoder;
    @Autowired
    @Qualifier("jwtRefreshTokenEncoder")
    JwtEncoder jwtRefreshTokenEncoder;

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
    public AuthResponse generateAccessToken(){


        return AuthResponse.builder()
                .userId("12345")
                .accessToken(createAccessToken(null))
                .refreshToken(createRefreshToken(null))
                .build();
    }
}
