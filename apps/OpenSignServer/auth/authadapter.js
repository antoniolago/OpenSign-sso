import axios from 'axios';
import dotenv from 'dotenv';
dotenv.config({ quiet: true });

// Generic OIDC issuer — compatible with any OpenID Connect provider
// (Keycloak, Azure AD, Auth0, Google, Okta, etc.)
const OIDC_ISSUER = process.env.OIDC_ISSUER_URL || '';

export const SSOAuth = {
  /**
   * Validates an access_token from any OIDC provider by calling the
   * standard UserInfo endpoint (RFC 7662).
   *
   * authData.id       — email claimed by the user
   * authData.access_token — OIDC access_token to validate
   */
  validateAuthData: async (authData) => {
    try {
      const response = await axios.get(
        `${OIDC_ISSUER}/protocol/openid-connect/userinfo`,
        {
          headers: {
            Authorization: `Bearer ${authData.access_token}`,
          },
        },
      );

      if (
        response.data &&
        response.data.email?.toLowerCase()?.replace(/\s/g, '') === authData.id
      ) {
        return;
      }

      throw new Parse.Error(
        Parse.Error.OBJECT_NOT_FOUND,
        'SSO auth is invalid for this user.',
      );
    } catch (error) {
      console.log('error in oidc adapter', error?.response?.data || error.message);
      throw new Parse.Error(
        Parse.Error.OBJECT_NOT_FOUND,
        'SSO auth is invalid for this user.',
      );
    }
  },

  validateAppId: () => Promise.resolve(),
};
