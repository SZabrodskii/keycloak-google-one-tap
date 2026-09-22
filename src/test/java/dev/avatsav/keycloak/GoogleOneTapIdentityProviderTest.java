package dev.avatsav.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.social.google.GoogleIdentityProviderConfig;

class GoogleOneTapIdentityProviderTest {

  private static final String TOKEN = "google.id.token";

  private final GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
  private final EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);
  private GoogleIdentityProviderConfig config;
  private GoogleOneTapIdentityProvider provider;

  @BeforeEach
  void setUp() {
    Profile.defaults();
    config = new GoogleIdentityProviderConfig();
    config.setAlias("google-one-tap");
    config.setClientId("client-id.apps.googleusercontent.com");
    provider = new GoogleOneTapIdentityProvider(mock(KeycloakSession.class), config);
    provider.setVerifier(verifier);
  }

  @Test
  void verifiedIdTokenBecomesBrokeredIdentity() throws Exception {
    when(verifier.verify(TOKEN))
        .thenReturn(idToken("10769150350006150715", "ada@example.com", true));

    BrokeredIdentityContext identity = exchange(OAuth2Constants.ID_TOKEN_TYPE);

    assertEquals("10769150350006150715", identity.getId());
    assertEquals("ada@example.com", identity.getEmail());
    assertEquals("ada@example.com", identity.getUsername());
    assertEquals("Ada", identity.getFirstName());
    assertEquals("Lovelace", identity.getLastName());
    assertEquals("google-one-tap.10769150350006150715", identity.getBrokerUserId());
    verify(event)
        .detail("validation_method", GoogleOneTapIdentityProvider.VALIDATION_METHOD_ID_TOKEN);
    verify(event, never()).error(any());
  }

  @Test
  void idTokenTypeIsAcceptedThroughTheParamsEntryPoint() throws Exception {
    when(verifier.verify(TOKEN)).thenReturn(idToken("1", "ada@example.com", true));

    MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
    params.putSingle(OAuth2Constants.SUBJECT_TOKEN, TOKEN);
    params.putSingle(OAuth2Constants.SUBJECT_TOKEN_TYPE, OAuth2Constants.ID_TOKEN_TYPE);

    assertEquals("1", provider.exchangeExternalUserInfoValidationOnly(event, params).getId());
  }

  @Test
  void rejectedIdTokenIsInvalidToken() throws Exception {
    when(verifier.verify(TOKEN)).thenReturn(null);

    ErrorResponseException e =
        assertThrows(ErrorResponseException.class, () -> exchange(OAuth2Constants.ID_TOKEN_TYPE));

    assertEquals(400, e.getResponse().getStatus());
    verify(event).detail(Details.REASON, GoogleOneTapIdentityProvider.REASON_ID_TOKEN_REJECTED);
    verify(event).error(Errors.INVALID_TOKEN);
  }

  @Test
  void securityFailureIsInvalidToken() throws Exception {
    when(verifier.verify(TOKEN)).thenThrow(new GeneralSecurityException("bad signature"));

    ErrorResponseException e =
        assertThrows(ErrorResponseException.class, () -> exchange(OAuth2Constants.ID_TOKEN_TYPE));

    assertEquals(400, e.getResponse().getStatus());
    verify(event).detail(Details.REASON, GoogleOneTapIdentityProvider.REASON_ID_TOKEN_REJECTED);
  }

  @Test
  void malformedIdTokenIsInvalidToken() throws Exception {
    when(verifier.verify(TOKEN)).thenThrow(new IllegalArgumentException("not a JWS"));

    ErrorResponseException e =
        assertThrows(ErrorResponseException.class, () -> exchange(OAuth2Constants.ID_TOKEN_TYPE));

    assertEquals(400, e.getResponse().getStatus());
    verify(event).detail(Details.REASON, GoogleOneTapIdentityProvider.REASON_ID_TOKEN_REJECTED);
    verify(event).error(Errors.INVALID_TOKEN);
  }

  @Test
  void unreachableGoogleKeysIsServiceUnavailable() throws Exception {
    when(verifier.verify(TOKEN)).thenThrow(new IOException("connection reset"));

    ErrorResponseException e =
        assertThrows(ErrorResponseException.class, () -> exchange(OAuth2Constants.ID_TOKEN_TYPE));

    assertEquals(503, e.getResponse().getStatus());
    verify(event)
        .detail(Details.REASON, GoogleOneTapIdentityProvider.REASON_PUBLIC_KEYS_UNAVAILABLE);
    verify(event).error(Errors.IDENTITY_PROVIDER_ERROR);
  }

  @Test
  void unverifiedEmailIsRejected() throws Exception {
    when(verifier.verify(TOKEN)).thenReturn(idToken("1", "ada@example.com", false));

    ErrorResponseException e =
        assertThrows(ErrorResponseException.class, () -> exchange(OAuth2Constants.ID_TOKEN_TYPE));

    assertEquals(400, e.getResponse().getStatus());
    verify(event).detail(Details.REASON, GoogleOneTapIdentityProvider.REASON_EMAIL_NOT_VERIFIED);
  }

  @Test
  void hostedDomainMustMatchWhenConfigured() throws Exception {
    config.getConfig().put("hostedDomain", "example.com");
    GoogleIdToken token = idToken("1", "ada@other.com", true);
    token.getPayload().setHostedDomain("other.com");
    when(verifier.verify(TOKEN)).thenReturn(token);

    ErrorResponseException e =
        assertThrows(ErrorResponseException.class, () -> exchange(OAuth2Constants.ID_TOKEN_TYPE));

    assertEquals(400, e.getResponse().getStatus());
    verify(event)
        .detail(Details.REASON, GoogleOneTapIdentityProvider.REASON_HOSTED_DOMAIN_MISMATCH);
  }

  @Test
  void hostedDomainWildcardAcceptsAnyDomain() throws Exception {
    config.getConfig().put("hostedDomain", "*");
    GoogleIdToken token = idToken("1", "ada@other.com", true);
    token.getPayload().setHostedDomain("other.com");
    when(verifier.verify(TOKEN)).thenReturn(token);

    assertEquals("ada@other.com", exchange(OAuth2Constants.ID_TOKEN_TYPE).getEmail());
  }

  @Test
  void unknownSubjectTokenTypeIsRejectedBeforeVerification() throws Exception {
    MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
    params.putSingle(OAuth2Constants.SUBJECT_TOKEN, TOKEN);
    params.putSingle(OAuth2Constants.SUBJECT_TOKEN_TYPE, OAuth2Constants.REFRESH_TOKEN_TYPE);

    ErrorResponseException e =
        assertThrows(
            ErrorResponseException.class,
            () -> provider.exchangeExternalUserInfoValidationOnly(event, params));

    assertEquals(400, e.getResponse().getStatus());
    verify(event).error(Errors.INVALID_TOKEN_TYPE);
    verify(verifier, never()).verify(any(String.class));
  }

  @Test
  void missingSubjectTokenIsRejected() throws Exception {
    MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
    params.putSingle(OAuth2Constants.SUBJECT_TOKEN_TYPE, OAuth2Constants.ID_TOKEN_TYPE);

    ErrorResponseException e =
        assertThrows(
            ErrorResponseException.class,
            () -> provider.exchangeExternalUserInfoValidationOnly(event, params));

    assertEquals(400, e.getResponse().getStatus());
    verify(event).error(eq(Errors.INVALID_TOKEN));
    verify(verifier, never()).verify(any(String.class));
  }

  private BrokeredIdentityContext exchange(String subjectTokenType) {
    return provider.validateExternalTokenThroughUserInfo(event, TOKEN, subjectTokenType);
  }

  private static GoogleIdToken idToken(String subject, String email, boolean emailVerified) {
    GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
    payload.setFactory(GsonFactory.getDefaultInstance());
    payload.setSubject(subject);
    payload.setEmail(email);
    payload.setEmailVerified(emailVerified);
    payload.set("given_name", "Ada");
    payload.set("family_name", "Lovelace");
    payload.set("name", "Ada Lovelace");
    return new GoogleIdToken(new JsonWebSignature.Header(), payload, new byte[0], new byte[0]);
  }
}
