package co.istad.mobilebankingcstad.features.auth.dto;

import lombok.Builder;

@Builder
public class AuthResponse {
    private String userId;
    private String accessToken;
    private String refreshToken;
}
