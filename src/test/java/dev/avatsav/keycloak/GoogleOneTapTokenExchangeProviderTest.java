package dev.avatsav.keycloak;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.Profile;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.protocol.oidc.TokenExchangeContext;

class GoogleOneTapTokenExchangeProviderTest {

  private static final String ALIAS = "google-one-tap";
  private static final String GOOGLE_SUBJECT = "10769150350006150715";
  private static final String EMAIL = "ada@example.com";

  /** Exposes the fields Keycloak wires in {@code exchange()} without running a full exchange. */
  private static class WiredProvider extends GoogleOneTapTokenExchangeProvider {
    void wire(KeycloakSession session, RealmModel realm, EventBuilder event) {
      this.session = session;
      this.realm = realm;
      this.event = event;
    }
  }

  private final KeycloakSession session = mock(KeycloakSession.class);
  private final UserProvider users = mock(UserProvider.class);
  private final RealmModel realm = mock(RealmModel.class);
  private final EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);
  private final UserModel existing = mock(UserModel.class);
  private final WiredProvider provider = new WiredProvider();
  private IdentityProviderModel idp;
  private BrokeredIdentityContext context;

  @BeforeEach
  void setUp() {
    Profile.defaults();
    when(session.users()).thenReturn(users);
    when(realm.isDuplicateEmailsAllowed()).thenReturn(false);
    when(existing.getId()).thenReturn("user-1");
    provider.wire(session, realm, event);

    idp = new IdentityProviderModel();
    idp.setAlias(ALIAS);
    idp.setProviderId(GoogleOneTapIdentityProviderFactory.ID);
    idp.setTrustEmail(true);

    context = new BrokeredIdentityContext(GOOGLE_SUBJECT, idp);
    context.setEmail(EMAIL);
    context.setUsername(EMAIL);
  }

  @Test
  void linksExistingUserWithSameEmailAndRecordsEvent() {
    when(users.getUserByFederatedIdentity(eq(realm), any())).thenReturn(null);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(existing);

    assertTrue(provider.linkExistingUserByEmail(context));

    verify(users)
        .addFederatedIdentity(
            eq(realm),
            eq(existing),
            argThat(
                (FederatedIdentityModel link) ->
                    ALIAS.equals(link.getIdentityProvider())
                        && GOOGLE_SUBJECT.equals(link.getUserId())
                        && EMAIL.equals(link.getUserName())));
    verify(event).event(EventType.FEDERATED_IDENTITY_LINK);
    verify(event).user("user-1");
    verify(event).success();
  }

  @Test
  void alreadyLinkedUserIsLeftAlone() {
    when(users.getUserByFederatedIdentity(eq(realm), any())).thenReturn(existing);

    assertFalse(provider.linkExistingUserByEmail(context));

    verify(users, never()).getUserByEmail(any(), any());
    verify(users, never()).addFederatedIdentity(any(), any(), any());
  }

  @Test
  void unknownEmailIsLeftToTheInheritedImport() {
    when(users.getUserByFederatedIdentity(eq(realm), any())).thenReturn(null);
    when(users.getUserByEmail(realm, EMAIL)).thenReturn(null);

    assertFalse(provider.linkExistingUserByEmail(context));

    verify(users, never()).addFederatedIdentity(any(), any(), any());
  }

  @Test
  void neverLinksWhenProviderDoesNotTrustEmail() {
    idp.setTrustEmail(false);

    assertFalse(provider.linkExistingUserByEmail(context));

    verify(users, never()).getUserByEmail(any(), any());
    verify(users, never()).addFederatedIdentity(any(), any(), any());
  }

  @Test
  void neverLinksWithoutEmail() {
    context.setEmail(null);

    assertFalse(provider.linkExistingUserByEmail(context));

    verify(users, never()).addFederatedIdentity(any(), any(), any());
  }

  @Test
  void neverLinksWhenRealmAllowsDuplicateEmails() {
    when(realm.isDuplicateEmailsAllowed()).thenReturn(true);

    assertFalse(provider.linkExistingUserByEmail(context));

    verify(users, never()).getUserByEmail(any(), any());
    verify(users, never()).addFederatedIdentity(any(), any(), any());
  }

  @Test
  void supportsOnlyExchangesAimedAtAOneTapProvider() {
    IdentityProviderStorageProvider idps = mock(IdentityProviderStorageProvider.class);
    when(session.identityProviders()).thenReturn(idps);
    when(idps.getByAlias(ALIAS)).thenReturn(idp);
    IdentityProviderModel plainGoogle = new IdentityProviderModel();
    plainGoogle.setAlias("google");
    plainGoogle.setProviderId("google");
    when(idps.getByAlias("google")).thenReturn(plainGoogle);

    assertTrue(provider.supports(exchangeWithSubjectIssuer(ALIAS)));
    assertFalse(provider.supports(exchangeWithSubjectIssuer("google")));
    assertFalse(provider.supports(exchangeWithSubjectIssuer("missing")));
    assertFalse(provider.supports(exchangeWithSubjectIssuer(null)));
  }

  private TokenExchangeContext exchangeWithSubjectIssuer(String subjectIssuer) {
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    if (subjectIssuer != null) {
      form.putSingle(OAuth2Constants.SUBJECT_ISSUER, subjectIssuer);
    }
    TokenExchangeContext exchange = mock(TokenExchangeContext.class);
    when(exchange.getFormParams()).thenReturn(form);
    when(exchange.getSession()).thenReturn(session);
    return exchange;
  }
}
