package co.istad.mobilebankingcstad.features.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
public record AuthResponse(
        String userId,
         String accessToken,
        String refreshToken
        ) {

}
