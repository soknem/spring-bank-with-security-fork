package co.istad.mobilebankingcstad.features.auth;

import co.istad.mobilebankingcstad.features.auth.dto.AuthRequest;
import co.istad.mobilebankingcstad.features.auth.dto.AuthResponse;
import co.istad.mobilebankingcstad.features.auth.dto.RefreshTokenRequest;
import co.istad.mobilebankingcstad.security.TokenGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class AuthServiceImpl {
    private final TokenGenerator tokenGenerator;
    private final DaoAuthenticationProvider daoAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public AuthResponse login(AuthRequest request) {
        Authentication authentication = daoAuthenticationProvider
                .authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.email(), request.password()
                        )
                );
        return tokenGenerator.generateAccessToken(authentication);
    }
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest){
        Authentication authentication=jwtAuthenticationProvider
                .authenticate(
                        new BearerTokenAuthenticationToken(refreshTokenRequest.refreshToken())
                );
        return tokenGenerator.generateAccessToken(authentication);
    }

}
