package dev.avatsav.keycloak;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.tokenexchange.V1TokenExchangeProvider;
import org.keycloak.services.validation.Validation;

/**
 * Token exchange provider that takes over external exchanges whose {@code subject_issuer} names a
 * {@link GoogleOneTapIdentityProvider} instance. It behaves exactly like Keycloak's v1 provider
 * with one addition: when the realm already holds a user with the email Google verified and that
 * user has no link to the provider yet, the link is created instead of failing with "User already
 * exists". Any other exchange is left to the built-in providers.
 */
public class GoogleOneTapTokenExchangeProvider extends V1TokenExchangeProvider {
  static final String DETAIL_TOKEN_EXCHANGE_PROVIDER = "token_exchange_provider";

  @Override
  public boolean supports(TokenExchangeContext context) {
    String alias = context.getFormParams().getFirst(OAuth2Constants.SUBJECT_ISSUER);
    if (Validation.isBlank(alias)) {
      return false;
    }
    IdentityProviderModel idp = context.getSession().identityProviders().getByAlias(alias);
    return idp != null && GoogleOneTapIdentityProviderFactory.ID.equals(idp.getProviderId());
  }

  @Override
  protected Response tokenExchange() {
    event.detail(DETAIL_TOKEN_EXCHANGE_PROVIDER, GoogleOneTapTokenExchangeProviderFactory.ID);
    return super.tokenExchange();
  }

  @Override
  protected UserModel importUserFromExternalIdentity(BrokeredIdentityContext context) {
    linkExistingUserByEmail(context);
    return super.importUserFromExternalIdentity(context);
  }

  /**
   * Links the realm user owning the verified email to the brokered identity, so the inherited
   * import finds a federated user instead of refusing to register a duplicate. Only done when the
   * provider is configured to trust email and the realm keeps emails unique.
   *
   * @return whether a link was created
   */
  boolean linkExistingUserByEmail(BrokeredIdentityContext context) {
    IdentityProviderModel idp = context.getIdpConfig();
    if (idp.isTransientUsers() || !idp.isTrustEmail()) {
      return false;
    }
    String email = context.getEmail();
    if (Validation.isBlank(email) || realm.isDuplicateEmailsAllowed()) {
      return false;
    }
    FederatedIdentityModel link =
        new FederatedIdentityModel(
            idp.getAlias(), context.getId(), context.getUsername(), context.getToken());
    if (session.users().getUserByFederatedIdentity(realm, link) != null) {
      return false;
    }
    UserModel existing = session.users().getUserByEmail(realm, email);
    if (existing == null) {
      return false;
    }
    session.users().addFederatedIdentity(realm, existing, link);
    event
        .clone()
        .event(EventType.FEDERATED_IDENTITY_LINK)
        .user(existing.getId())
        .detail(Details.IDENTITY_PROVIDER, idp.getAlias())
        .detail(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername())
        .detail(Details.EMAIL, email)
        .success();
    return true;
  }
}
