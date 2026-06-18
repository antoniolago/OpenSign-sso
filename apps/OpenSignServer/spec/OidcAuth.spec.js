import axios from 'axios';

// ---------------------------------------------------------------------------
// SSOAuth adapter — auth/authadapter.js
// ---------------------------------------------------------------------------
describe('SSOAuth adapter', () => {
  let SSOAuth;
  let _origParse;
  let _origEnv;

  beforeAll(async () => {
    // Preserve original Parse global (if set by helper) and install a minimal
    // mock so the module can reference Parse.Error without a real server.
    _origParse = global.Parse;

    class MockParseError {
      constructor(code, message) {
        this.code = code;
        this.message = message;
      }
    }
    MockParseError.INVALID_QUERY = 102;
    MockParseError.INVALID_JSON = 109;
    MockParseError.OBJECT_NOT_FOUND = 101;

    global.Parse = {
      Error: MockParseError,
      Object: { extend: () => {} },
      Query() {},
    };

    _origEnv = { ...process.env };
    process.env.OIDC_ISSUER_URL =
      'https://keycloak.example.com/auth/realms/test';

    // Dynamically import so OIDC_ISSUER is captured from our env
    const mod = await import('../../auth/authadapter.js');
    SSOAuth = mod.SSOAuth;
  });

  afterAll(() => {
    global.Parse = _origParse;
    process.env = _origEnv;
  });

  beforeEach(() => {
    spyOn(console, 'log');
    spyOn(axios, 'get');
  });

  it('should resolve when userinfo email matches authData.id', async () => {
    axios.get.and.resolveTo({
      data: { email: 'user@example.com', id: '123' },
    });

    await expectAsync(
      SSOAuth.validateAuthData({
        access_token: 'mock-token',
        id: 'user@example.com',
      }),
    ).toBeResolved();
  });

  it('should reject with Parse.Error when email does not match', async () => {
    axios.get.and.resolveTo({
      data: { email: 'other@example.com', id: '456' },
    });

    try {
      await SSOAuth.validateAuthData({
        access_token: 'mock-token',
        id: 'user@example.com',
      });
      fail('Should have thrown');
    } catch (e) {
      expect(e.code).toBe(Parse.Error.OBJECT_NOT_FOUND);
      expect(e.message).toBe('SSO auth is invalid for this user.');
    }
  });

  it('should reject with Parse.Error on network error', async () => {
    axios.get.and.rejectWith(new Error('Connection refused'));

    try {
      await SSOAuth.validateAuthData({
        access_token: 'mock-token',
        id: 'user@example.com',
      });
      fail('Should have thrown');
    } catch (e) {
      expect(e.code).toBe(Parse.Error.OBJECT_NOT_FOUND);
      expect(e.message).toBe('SSO auth is invalid for this user.');
    }
  });

  it('should compare email case-insensitively', async () => {
    axios.get.and.resolveTo({
      data: { email: 'User@Example.COM', id: '123' },
    });

    await expectAsync(
      SSOAuth.validateAuthData({
        access_token: 'mock-token',
        id: 'user@example.com',
      }),
    ).toBeResolved();
  });

  it('should call userinfo endpoint with the correct bearer token', async () => {
    axios.get.and.resolveTo({
      data: { email: 'test@example.com', id: '007' },
    });

    await SSOAuth.validateAuthData({
      access_token: 'secret-token-42',
      id: 'test@example.com',
    });

    expect(axios.get).toHaveBeenCalledWith(
      'https://keycloak.example.com/auth/realms/test/protocol/openid-connect/userinfo',
      jasmine.objectContaining({
        headers: jasmine.objectContaining({
          Authorization: 'Bearer secret-token-42',
        }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// oidcSetupUser — cloud/parsefunction/oidcSetupUser.js (default claims)
// ---------------------------------------------------------------------------
describe('oidcSetupUser (default claim paths)', () => {
  let oidcSetupUser;
  let _origParse;
  let _origEnv;

  // Helper: create a fresh mock contracts_Users instance
  function createMockExtUser() {
    const data = {};
    const mock = {
      _data: data,
      set: jasmine
        .createSpy('extUser.set')
        .and.callFake((k, v) => { data[k] = v; }),
      get: jasmine
        .createSpy('extUser.get')
        .and.callFake((k) => data[k]),
      save: jasmine
        .createSpy('extUser.save')
        .and.resolveTo(mock),
    };
    return mock;
  }

  beforeAll(async () => {
    _origParse = global.Parse;
    _origEnv = { ...process.env };

    // Explicit defaults identical to what the module falls back to
    process.env.OIDC_CLAIM_EMAIL = 'email';
    process.env.OIDC_CLAIM_NAME = 'name';
    process.env.OIDC_CLAIM_GROUPS = 'groups';
    process.env.OIDC_ADMIN_GROUP = 'admin';
    process.env.OIDC_DEFAULT_ROLE = 'contracts_User';
    process.env.OIDC_ADMIN_ROLE = 'contracts_Admin';

    class MockParseError {
      constructor(code, message) {
        this.code = code;
        this.message = message;
      }
    }
    MockParseError.INVALID_QUERY = 102;
    MockParseError.INVALID_JSON = 109;

    global.Parse = {
      Error: MockParseError,
      Object: { extend: jasmine.createSpy('Parse.Object.extend') },
      Query: jasmine.createSpy('Parse.Query'),
    };

    const mod = await import('../../cloud/parsefunction/oidcSetupUser.js');
    oidcSetupUser = mod.default;
  });

  afterAll(() => {
    global.Parse = _origParse;
    process.env = _origEnv;
  });

  /** Shared test infrastructure — create a query mock with configurable first() */
  function makeQueryMock(firstResult) {
    return {
      equalTo: jasmine.createSpy('query.equalTo').and.returnThis(),
      first: jasmine.createSpy('query.first').and.resolveTo(firstResult),
    };
  }

  beforeEach(() => {
    // Spy on console to keep output clean
    spyOn(console, 'log');
  });

  // ---- (a) New user, no admin group -----------------------------------
  it('should create a new user with default role when no admin group', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null)); // no existing record

    const userObj = {
      getEmail: jasmine.createSpy('user.getEmail').and.returnValue('a@b.com'),
    };

    const result = await oidcSetupUser({
      params: { id_token: { email: 'a@b.com', name: 'Alice', groups: ['user'] } },
      user: userObj,
    });

    expect(result).toEqual({
      email: 'a@b.com',
      name: 'Alice',
      role: 'contracts_User',
      groups: ['user'],
    });

    // Verify new-user path: User pointer was set
    expect(mockUser.set).toHaveBeenCalledWith('User', userObj);
    expect(mockUser.set).toHaveBeenCalledWith('Email', 'a@b.com');
    expect(mockUser.set).toHaveBeenCalledWith('Name', 'Alice');
    expect(mockUser.set).toHaveBeenCalledWith('UserRole', 'contracts_User');
    expect(mockUser.set).toHaveBeenCalledWith('IsDisabled', false);
    expect(mockUser.save).toHaveBeenCalledWith(null, { useMasterKey: true });
  });

  // ---- (b) New user with admin group ----------------------------------
  it('should create a new user with admin role when groups include admin', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    const result = await oidcSetupUser({
      params: {
        id_token: { email: 'admin@b.com', name: 'Admin', groups: ['admin'] },
      },
      user: { getEmail: () => 'admin@b.com' },
    });

    expect(result.role).toBe('contracts_Admin');
    expect(mockUser.set).toHaveBeenCalledWith('UserRole', 'contracts_Admin');
  });

  // ---- (c) Existing user update ---------------------------------------
  it('should update an existing user instead of creating a duplicate', async () => {
    const existingData = {
      Email: 'admin@b.com',
      Name: 'OldName',
      UserRole: 'contracts_Admin',
      IsDisabled: true,
    };
    const existingUser = createMockExtUser();
    // Pre-populate to simulate existing record
    Object.assign(existingUser._data, existingData);

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return createMockExtUser(); // fresh — should NOT be used
        }
      },
    );
    // Return the existing record
    Parse.Query.and.returnValue(makeQueryMock(existingUser));

    const result = await oidcSetupUser({
      params: {
        id_token: { email: 'admin@b.com', name: 'Admin Updated', groups: ['admin'] },
      },
      user: { getEmail: () => 'admin@b.com' },
    });

    expect(result).toEqual({
      email: 'admin@b.com',
      name: 'Admin Updated',
      role: 'contracts_Admin',
      groups: ['admin'],
    });

    // Existing user: set('User', …) is NOT called because it already exists
    expect(existingUser.set).not.toHaveBeenCalledWith('User', jasmine.anything());
    // All other fields are updated on the existing record
    expect(existingUser.set).toHaveBeenCalledWith('Email', 'admin@b.com');
    expect(existingUser.set).toHaveBeenCalledWith('Name', 'Admin Updated');
    expect(existingUser.set).toHaveBeenCalledWith('UserRole', 'contracts_Admin');
    expect(existingUser.set).toHaveBeenCalledWith('IsDisabled', false);
    expect(existingUser.save).toHaveBeenCalledWith(null, { useMasterKey: true });
  });

  // ---- (e) Missing name falls back to email prefix --------------------
  it('should fall back to email prefix when name claim is missing', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    const result = await oidcSetupUser({
      params: { id_token: { email: 'alice@b.com', groups: ['user'] } },
      user: { getEmail: () => 'alice@b.com' },
    });

    expect(result.name).toBe('alice');
  });

  // ---- (f) Groups as a single string ----------------------------------
  it('should treat a single string group value as an array of one', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    const result = await oidcSetupUser({
      params: {
        id_token: { email: 'admin@b.com', name: 'Admin', groups: 'admin' },
      },
      user: { getEmail: () => 'admin@b.com' },
    });

    expect(result.role).toBe('contracts_Admin');
    expect(result.groups).toEqual(['admin']);
  });

  // ---- (g) Missing id_token -------------------------------------------
  it('should throw Parse.Error when id_token is missing', async () => {
    try {
      await oidcSetupUser({
        params: {},
        user: { getEmail: () => 'x@y.com' },
      });
      fail('Should have thrown');
    } catch (e) {
      expect(e.code).toBe(Parse.Error.INVALID_QUERY);
      expect(e.message).toBe('Missing id_token claims.');
    }
  });

  // ---- Extra: email from user.getEmail when no claim ------------------
  it('should use user.getEmail when the email claim is absent', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    const result = await oidcSetupUser({
      params: { id_token: { name: 'Bob', groups: ['user'] } },
      user: { getEmail: () => 'bob@fallback.com' },
    });

    expect(result.email).toBe('bob@fallback.com');
  });

  // ---- Extra: supports JWT string id_token ----------------------------
  it('should decode a JWT-formatted id_token', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    // Create a valid-looking JWT with base64url-encoded JSON payload
    const payload = Buffer.from(
      JSON.stringify({ email: 'jwt@test.com', name: 'JWT User', groups: ['user'] }),
    ).toString('base64url');
    const fakeJwt = `header.${payload}.signature`;

    const result = await oidcSetupUser({
      params: { id_token: fakeJwt },
      user: { getEmail: () => 'jwt@test.com' },
    });

    expect(result.email).toBe('jwt@test.com');
    expect(result.name).toBe('JWT User');
  });

  // ---- Extra: groups with different casing ----------------------------
  it('should match admin group case-insensitively', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    const result = await oidcSetupUser({
      params: {
        id_token: { email: 'admin@b.com', name: 'Admin', groups: ['Admin'] },
      },
      user: { getEmail: () => 'admin@b.com' },
    });

    expect(result.role).toBe('contracts_Admin');
  });
});

// ---------------------------------------------------------------------------
// oidcSetupUser with custom claim paths (sub as email claim)
// ---------------------------------------------------------------------------
describe('oidcSetupUser (custom claim paths)', () => {
  let oidcSetupUser;
  let _origParse;
  let _origEnv;

  function createMockExtUser() {
    const data = {};
    const mock = {
      _data: data,
      set: jasmine
        .createSpy('extUser.set')
        .and.callFake((k, v) => { data[k] = v; }),
      get: jasmine
        .createSpy('extUser.get')
        .and.callFake((k) => data[k]),
      save: jasmine
        .createSpy('extUser.save')
        .and.resolveTo(mock),
    };
    return mock;
  }

  function makeQueryMock(firstResult) {
    return {
      equalTo: jasmine.createSpy('query.equalTo').and.returnThis(),
      first: jasmine.createSpy('query.first').and.resolveTo(firstResult),
    };
  }

  beforeAll(async () => {
    _origParse = global.Parse;
    _origEnv = { ...process.env };

    // Custom claim paths
    process.env.OIDC_CLAIM_EMAIL = 'sub';
    process.env.OIDC_CLAIM_NAME = 'name';
    process.env.OIDC_CLAIM_GROUPS = 'groups';
    process.env.OIDC_ADMIN_GROUP = 'admin';
    process.env.OIDC_DEFAULT_ROLE = 'contracts_User';
    process.env.OIDC_ADMIN_ROLE = 'contracts_Admin';

    class MockParseError {
      constructor(code, message) {
        this.code = code;
        this.message = message;
      }
    }
    MockParseError.INVALID_QUERY = 102;
    MockParseError.INVALID_JSON = 109;

    global.Parse = {
      Error: MockParseError,
      Object: { extend: jasmine.createSpy('Parse.Object.extend') },
      Query: jasmine.createSpy('Parse.Query'),
    };

    const mod = await import('../../cloud/parsefunction/oidcSetupUser.js');
    oidcSetupUser = mod.default;
  });

  afterAll(() => {
    global.Parse = _origParse;
    process.env = _origEnv;
  });

  beforeEach(() => {
    spyOn(console, 'log');
  });

  // ---- (d) Custom claim: OIDC_CLAIM_EMAIL=sub ------------------------
  it('should read email from the "sub" claim when OIDC_CLAIM_EMAIL=sub', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    const result = await oidcSetupUser({
      params: {
        id_token: { sub: 'custom@claim.com', name: 'Charlie', groups: ['user'] },
      },
      user: { getEmail: () => '' },
    });

    expect(result.email).toBe('custom@claim.com');
    expect(mockUser.set).toHaveBeenCalledWith('Email', 'custom@claim.com');
  });

  it('should read groups from a nested path (fallback test)', async () => {
    const mockUser = createMockExtUser();

    Parse.Object.extend.and.returnValue(
      class FakeExtUser {
        constructor() {
          return mockUser;
        }
      },
    );
    Parse.Query.and.returnValue(makeQueryMock(null));

    // Even with default claim paths, nested paths via _getNested work
    const result = await oidcSetupUser({
      params: {
        id_token: {
          sub: 'nested@test.com',
          name: 'Nested',
          'realm_access': { roles: ['admin'] },
        },
      },
      user: { getEmail: () => '' },
    });

    // Since CLAIM_GROUPS is 'groups' (not 'realm_access.roles'),
    // and id_token.groups is undefined, it falls back to [].
    expect(result.groups).toEqual([]);
    expect(result.role).toBe('contracts_User');
  });
});
