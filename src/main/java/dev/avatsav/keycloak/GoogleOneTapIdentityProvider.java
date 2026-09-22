package dev.avatsav.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.social.google.GoogleIdentityProvider;
import org.keycloak.social.google.GoogleIdentityProviderConfig;

/**
 * Keycloak's Google identity provider, extended so that an external token exchange with {@code
 * subject_token_type=urn:ietf:params:oauth:token-type:id_token} accepts the Google ID token that
 * Sign in with Google / One Tap hands to the browser. Browser login, mappers and the access-token
 * (user info) exchange are inherited unchanged.
 *
 * <p>The ID token is verified with Google's own client library: signature against Google's
 * published keys, issuer, expiry and audience (the provider's client id). On top of that the email
 * must be verified by Google and, when the provider restricts the hosted domain, the token's {@code
 * hd} claim must match.
 */
public class GoogleOneTapIdentityProvider extends GoogleIdentityProvider {
  static final String VALIDATION_METHOD_ID_TOKEN = "google id token";
  static final String REASON_ID_TOKEN_REJECTED = "id token rejected";
  static final String REASON_EMAIL_NOT_VERIFIED = "email not verified";
  static final String REASON_HOSTED_DOMAIN_MISMATCH = "hosted domain mismatch";
  static final String REASON_PUBLIC_KEYS_UNAVAILABLE = "google public keys unavailable";

  private static final Logger logger = Logger.getLogger(GoogleOneTapIdentityProvider.class);
  private static final List<String> VALID_SUBJECT_TOKEN_TYPES =
      List.of(OAuth2Constants.ID_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);

  /** Shared by every provider instance so Google's signing keys are fetched and cached once. */
  private static final GooglePublicKeysManager PUBLIC_KEYS =
      new GooglePublicKeysManager.Builder(new NetHttpTransport(), new GsonFactory()).build();

  private GoogleIdTokenVerifier verifier;

  public GoogleOneTapIdentityProvider(
      KeycloakSession session, GoogleIdentityProviderConfig config) {
    super(session, config);
  }

  GoogleIdTokenVerifier verifier() {
    if (verifier == null) {
      verifier =
          new GoogleIdTokenVerifier.Builder(PUBLIC_KEYS)
              .setAudience(List.of(getConfig().getClientId()))
              .build();
    }
    return verifier;
  }

  void setVerifier(GoogleIdTokenVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  protected BrokeredIdentityContext exchangeExternalUserInfoValidationOnly(
      EventBuilder event, MultivaluedMap<String, String> params) {
    String subjectToken = params.getFirst(OAuth2Constants.SUBJECT_TOKEN);
    if (subjectToken == null) {
      event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN + " param unset");
      event.error(Errors.INVALID_TOKEN);
      throw new ErrorResponseException(
          OAuthErrorException.INVALID_TOKEN, "token not set", Response.Status.BAD_REQUEST);
    }
    String subjectTokenType = params.getFirst(OAuth2Constants.SUBJECT_TOKEN_TYPE);
    if (subjectTokenType == null) {
      subjectTokenType = OAuth2Constants.ACCESS_TOKEN_TYPE;
    }
    if (!VALID_SUBJECT_TOKEN_TYPES.contains(subjectTokenType)) {
      event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN_TYPE + " invalid");
      event.error(Errors.INVALID_TOKEN_TYPE);
      throw new ErrorResponseException(
          OAuthErrorException.INVALID_TOKEN, "invalid token type", Response.Status.BAD_REQUEST);
    }
    return validateExternalTokenThroughUserInfo(event, subjectToken, subjectTokenType);
  }

  @Override
  protected BrokeredIdentityContext validateExternalTokenThroughUserInfo(
      EventBuilder event, String subjectToken, String subjectTokenType) {
    if (!OAuth2Constants.ID_TOKEN_TYPE.equals(subjectTokenType)) {
      return super.validateExternalTokenThroughUserInfo(event, subjectToken, subjectTokenType);
    }
    event.detail("validation_method", VALIDATION_METHOD_ID_TOKEN);

    GoogleIdToken idToken;
    try {
      idToken = verifier().verify(subjectToken);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      // IllegalArgumentException: the library's precondition failure on a string that is not
      // even a three-part JWS — a rejected token, not a server fault.
      logger.debug("Google id token verification failed", e);
      throw invalidToken(event, REASON_ID_TOKEN_REJECTED);
    } catch (IOException e) {
      logger.warn("Google public keys could not be fetched", e);
      event.detail(Details.REASON, REASON_PUBLIC_KEYS_UNAVAILABLE);
      event.error(Errors.IDENTITY_PROVIDER_ERROR);
      throw new ErrorResponseException(
          OAuthErrorException.TEMPORARILY_UNAVAILABLE,
          "identity provider unavailable",
          Response.Status.SERVICE_UNAVAILABLE);
    }
    if (idToken == null) {
      throw invalidToken(event, REASON_ID_TOKEN_REJECTED);
    }

    GoogleIdToken.Payload payload = idToken.getPayload();
    if (!Boolean.TRUE.equals(payload.getEmailVerified())) {
      throw invalidToken(event, REASON_EMAIL_NOT_VERIFIED);
    }
    String hostedDomain = ((GoogleIdentityProviderConfig) getConfig()).getHostedDomain();
    if (hostedDomain != null
        && !"*".equals(hostedDomain)
        && !hostedDomain.equals(payload.getHostedDomain())) {
      throw invalidToken(event, REASON_HOSTED_DOMAIN_MISMATCH);
    }

    JsonNode profile;
    try {
      profile = asJsonNode(payload.toString());
    } catch (IOException e) {
      logger.debug("Google id token payload could not be read", e);
      throw invalidToken(event, REASON_ID_TOKEN_REJECTED);
    }
    return extractIdentityFromProfile(event, profile);
  }

  private static ErrorResponseException invalidToken(EventBuilder event, String reason) {
    event.detail(Details.REASON, reason);
    event.error(Errors.INVALID_TOKEN);
    return new ErrorResponseException(
        OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
  }
}
