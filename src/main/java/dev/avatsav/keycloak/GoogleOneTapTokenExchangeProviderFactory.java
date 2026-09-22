package dev.avatsav.keycloak;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public class GoogleOneTapTokenExchangeProviderFactory
    implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {

  public static final String ID = "google-one-tap";

  /**
   * Keycloak asks providers in descending order; the built-in ones sit at 10 (standard) and 0 (v1),
   * so this one is consulted first and steps aside for every exchange it does not support.
   */
  static final int ORDER = 100;

  @Override
  public TokenExchangeProvider create(KeycloakSession session) {
    return new GoogleOneTapTokenExchangeProvider();
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public int order() {
    return ORDER;
  }

  @Override
  public boolean isSupported(Config.Scope config) {
    return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE);
  }
}
