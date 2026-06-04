// src/config/configuration.ts
export default () => {
  // Validate required OAuth configs
  const requiredOAuthConfigs = [
    'OAUTH_AUTHORIZATION_URL',
    'OAUTH_TOKEN_URL',
    'OAUTH_REFRESH_URL',
    'OAUTH_USERINFO_URL',
    'OAUTH_JWKS_URI',
    'OAUTH_CLIENT_ID',
    'OAUTH_CLIENT_SECRET',
    'OAUTH_ISSUER',
  ];

  const missingConfigs = requiredOAuthConfigs.filter(
    (key) => !process.env[key],
  );

  if (missingConfigs.length > 0) {
    throw new Error(
      `Missing required OAuth configuration: ${missingConfigs.join(', ')}`,
    );
  }

  return {
    port: parseInt(process.env.PORT || '8000', 10),
    frontend_url: process.env.FRONTEND_URL || 'http://localhost:3001',

    database: {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      username: process.env.DB_USERNAME || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      database: process.env.DB_NAME || 'oauth_db',
    },

    oauth: {
      authorizationURL: process.env.OAUTH_AUTHORIZATION_URL!,
      tokenURL: process.env.OAUTH_TOKEN_URL!,
      refreshURL: process.env.OAUTH_REFRESH_URL!,
      userInfoURL: process.env.OAUTH_USERINFO_URL!,
      revokeRefreshURL: process.env.OAUTH_REVOKE_REFRESH!,
      jwksUri: process.env.OAUTH_JWKS_URI!,
      clientId: process.env.OAUTH_CLIENT_ID!,
      clientSecret: process.env.OAUTH_CLIENT_SECRET!,
      callbackURL:
        process.env.OAUTH_CALLBACK_URL ||
        'http://localhost:8000/api/auth/callback',
      issuer: process.env.OAUTH_ISSUER!,
      logoutURL: process.env.OAUTH_LOGOUT_URL || '',
    },
  };
};
