import dotenv from 'dotenv';
dotenv.config({ quiet: true });

/**
 * Generically maps OIDC id_token claims to an OpenSign extended user profile.
 *
 * Configuration (all optional, pure OIDC standard defaults):
 *   OIDC_CLAIM_EMAIL    — which JWT claim holds the email  (default: "email")
 *   OIDC_CLAIM_NAME     — which JWT claim holds the name   (default: "name")
 *   OIDC_CLAIM_GROUPS   — which JWT claim holds roles/groups (default: "groups")
 *   OIDC_ADMIN_GROUP    — group value that grants admin role (default: "admin")
 *   OIDC_DEFAULT_ROLE   — UserRole assigned when no admin match (default: "contracts_User")
 *   OIDC_ADMIN_ROLE     — UserRole assigned to admins      (default: "contracts_Admin")
 *
 * The id_token is decoded client-side and sent as a raw JSON object in params.
 * No provider-specific code — works with Keycloak, Azure AD, Auth0, Google, Okta…
 */
const CLAIM_EMAIL = process.env.OIDC_CLAIM_EMAIL || 'email';
const CLAIM_NAME = process.env.OIDC_CLAIM_NAME || 'name';
const CLAIM_GROUPS = process.env.OIDC_CLAIM_GROUPS || 'groups';
const ADMIN_GROUP = process.env.OIDC_ADMIN_GROUP || 'admin';
const DEFAULT_ROLE = process.env.OIDC_DEFAULT_ROLE || 'contracts_User';
const ADMIN_ROLE = process.env.OIDC_ADMIN_ROLE || 'contracts_Admin';

async function oidcSetupUser(request) {
  const { id_token: rawClaims } = request.params;
  const user = request.user;

  if (!rawClaims) {
    throw new Parse.Error(Parse.Error.INVALID_QUERY, 'Missing id_token claims.');
  }

  // Normalise: if the caller sent a JWT string, decode it
  let claims = rawClaims;
  if (typeof rawClaims === 'string' && rawClaims.split('.').length === 3) {
    try {
      const payload = rawClaims.split('.')[1];
      claims = JSON.parse(
        Buffer.from(payload, 'base64url').toString('utf-8'),
      );
    } catch {
      throw new Parse.Error(Parse.Error.INVALID_JSON, 'Could not decode id_token.');
    }
  }

  // Extract user info using configurable claim paths
  const email =
    _getNested(claims, CLAIM_EMAIL) || user.getEmail() || '';
  const displayName =
    _getNested(claims, CLAIM_NAME) || email.split('@')[0] || 'User';
  const groups = _getNested(claims, CLAIM_GROUPS) || [];

  // Determine role based on group membership
  const groupsList = Array.isArray(groups) ? groups : [groups];
  const isAdmin = groupsList.some(
    (g) => g.toLowerCase() === ADMIN_GROUP.toLowerCase(),
  );
  const userRole = isAdmin ? ADMIN_ROLE : DEFAULT_ROLE;

  // Upsert contracts_Users record
  const ExtUser = Parse.Object.extend('contracts_Users');
  const query = new Parse.Query(ExtUser);
  query.equalTo('User', user);
  let extUser = await query.first({ useMasterKey: true });

  if (!extUser) {
    extUser = new ExtUser();
    extUser.set('User', user);
  }

  extUser.set('Email', email.toLowerCase());
  extUser.set('Name', displayName);
  extUser.set('UserRole', userRole);
  extUser.set('IsDisabled', false);

  // Optional: store the raw OIDC claims so admins can inspect them
  extUser.set('OIDCGroups', JSON.stringify(groupsList));

  await extUser.save(null, { useMasterKey: true });

  return {
    email: email.toLowerCase(),
    name: displayName,
    role: userRole,
    groups: groupsList,
  };
}

/**
 * Safely traverse a nested object path, e.g. "user.email" or "claims[0].value".
 */
function _getNested(obj, path) {
  if (!obj || !path) return undefined;
  return path
    .split(/[.\[\]]+/)
    .filter(Boolean)
    .reduce((acc, key) => {
      if (acc && typeof acc === 'object' && key in acc) return acc[key];
      return undefined;
    }, obj);
}

export default oidcSetupUser;
