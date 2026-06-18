import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import Parse from "parse";
import axios from "axios";

// ====================================================================
// OIDC Callback — Vitest Unit Tests
// ====================================================================
//
// The component reads OIDC config from module-level constants which
// fall back to window.RUNTIME_ENV.  We set RUNTIME_ENV via vi.hoisted
// so the default top-level import (import OidcCallback) is the
// CONFIGURED version.  The "not configured" scenario uses
// vi.resetModules() + dynamic import.
//
// Scenarios:
//   a) Successful token exchange + login → navigate to dashboard
//   b) Missing authorization code       → error UI + redirect to /
//   c) OIDC provider error param        → error UI
//   d) OIDC not configured              → configuration error
//   e) Token exchange failure           → error UI
//   f) Parse.User.logInWith failure     → error UI
//   g) id_token missing email claim     → error UI
//   h) getUserDetails returns null      → navigate to /
//   i) Disabled user (IsDisabled)       → error UI
// ====================================================================

// ----- Hoisted helpers (run BEFORE any import) -----
vi.hoisted(() => {
  window.RUNTIME_ENV = {
    REACT_APP_OIDC_ISSUER_URL: "https://keycloak.example.com/auth/realms/test",
    REACT_APP_OIDC_CLIENT_ID: "test-client-id",
    REACT_APP_OIDC_CLIENT_SECRET: "test-client-secret",
  };
});

const mockNavigate = vi.fn();

// ----- Mock external modules (hoisted by Vitest) -----

vi.mock("react-router", async () => {
  const actual = await vi.importActual("react-router");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("parse", () => {
  const mockUser = {
    getSessionToken: vi.fn().mockReturnValue("test-session-token"),
    toJSON: vi.fn().mockReturnValue({
      id: "user-123",
      email: "user@example.com",
      sessionToken: "test-session-token",
    }),
    get: vi.fn().mockReturnValue(null),
  };
  return {
    default: {
      User: { logInWith: vi.fn().mockResolvedValue(mockUser), become: vi.fn() },
      Cloud: { run: vi.fn() },
    },
  };
});

vi.mock("axios", () => ({
  default: { post: vi.fn() },
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key) => {
      const dict = {
        "something-went-wrong-mssg": "Something went wrong",
        redirecting: "Redirecting",
        "do-not-access-contact-admin": "Account disabled",
      };
      return dict[key] || key;
    },
    i18n: { language: "en" },
  }),
}));

vi.mock("react-redux", () => ({
  useDispatch: () => vi.fn(),
}));

vi.mock("../primitives/Loader", () => ({
  default: () => <div data-testid="loader">Loading...</div>,
}));

vi.mock("../constant/appinfo", () => ({
  appInfo: {
    appId: "test-app",
    applogo: "test-logo.png",
    baseUrl: "/api",
    defaultRole: "contracts_User",
    settings: [
      {
        role: "contracts_User",
        menuId: "H9vRfEYKhT",
        pageType: "dashboard",
        pageId: "35KBoSgoAK",
      },
    ],
  },
}));

vi.mock("../constant/Utils", () => ({
  saveLanguageInLocal: vi.fn(),
}));

// ----- This import is the CONFIGURED version -----
import OidcCallback from "./OidcCallback";

/** Reference to the mock user created in the parse mock. */
const defaultMockUser = {
  getSessionToken: vi.fn().mockReturnValue("test-session-token"),
  toJSON: vi.fn().mockReturnValue({
    id: "user-123",
    email: "user@example.com",
    sessionToken: "test-session-token",
  }),
  get: vi.fn().mockReturnValue(null),
};

// ----- Helpers -----

/** Build a fake id_token JWT containing the given email. */
function makeIdToken(email) {
  const payload = btoa(JSON.stringify({ email, preferred_username: email }));
  return `header.${payload}.signature`;
}

/**
 * Create a mock extUser that behaves like a Parse.Object:
 *  - .get(key) returns a property
 *  - serialising via JSON.parse(JSON.stringify(...)) yields the props
 */
function createMockExtUser(overrides = {}) {
  const props = {
    IsDisabled: false,
    UserRole: "contracts_User",
    Email: "user@example.com",
    Name: "Test User",
    TenantId: { objectId: "tenant-1", TenantName: "Test Tenant" },
    ...overrides,
  };
  return {
    get: vi.fn((key) => props[key] ?? null),
    ...props,
  };
}

// ----- Tests -----

describe("OidcCallback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();
    mockNavigate.mockReset();
    // Re-apply default implementations that clearAllMocks strips
    Parse.User.logInWith.mockResolvedValue(defaultMockUser);
    Parse.Cloud.run.mockReset();
  });

  // ----------------------------------------------------------------
  // a) Successful flow
  // ----------------------------------------------------------------
  it("exchanges code, logs in via Parse, and navigates to dashboard", async () => {
    sessionStorage.setItem("oidc_code_verifier", "test-verifier");

    axios.post.mockResolvedValue({
      data: {
        access_token: "access-token-123",
        id_token: makeIdToken("user@example.com"),
      },
    });

    Parse.Cloud.run.mockImplementation((fn) => {
      if (fn === "oidcSetupUser") return Promise.resolve();
      if (fn === "getUserDetails") return Promise.resolve(createMockExtUser());
      return Promise.resolve();
    });

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith("/dashboard/35KBoSgoAK");
    });

    // Token exchange
    expect(axios.post).toHaveBeenCalledWith(
      "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/token",
      expect.stringContaining("grant_type=authorization_code"),
      expect.objectContaining({
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }),
    );
    const body = axios.post.mock.calls[0][1];
    expect(body).toContain("code_verifier=test-verifier");
    expect(body).toContain("client_secret=test-client-secret");
    expect(body).toContain("code=abc123");

    // Parse login
    expect(Parse.User.logInWith).toHaveBeenCalledWith("sso", {
      authData: { id: "user@example.com", access_token: "access-token-123" },
    });

    // oidcSetupUser cloud function
    expect(Parse.Cloud.run).toHaveBeenCalledWith("oidcSetupUser", {
      id_token: expect.any(String),
      access_token: "access-token-123",
    });

    // localStorage populated
    expect(localStorage.getItem("accesstoken")).toBe("test-session-token");
    expect(localStorage.getItem("userEmail")).toBe("user@example.com");
    expect(localStorage.getItem("_user_role")).toBe("User");
    expect(localStorage.getItem("PageLanding")).toBe("35KBoSgoAK");

    // code_verifier purged from sessionStorage
    expect(sessionStorage.getItem("oidc_code_verifier")).toBeNull();
  });

  // ----------------------------------------------------------------
  // b) Missing authorization code
  // ----------------------------------------------------------------
  it("shows error and redirects to / when no code is present", async () => {
    render(
      <MemoryRouter initialEntries={["/oidc/callback"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(
        screen.getByText(
          "No authorization code received from the OIDC provider.",
        ),
      ).toBeInTheDocument();
    });

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    // "Redirecting..." is split as <div>Redirecting</div><div>...</div>
    expect(screen.getByText(/^Redirecting/)).toBeInTheDocument();

    // After 4 s navigate("/") is called
    await waitFor(
      () => {
        expect(mockNavigate).toHaveBeenCalledWith("/");
      },
      { timeout: 5000 },
    );
  });

  // ----------------------------------------------------------------
  // c) Error from OIDC provider
  // ----------------------------------------------------------------
  it("shows error when OIDC provider returns an error parameter", async () => {
    render(
      <MemoryRouter
        initialEntries={[
          "/oidc/callback?error=access_denied&error_description=User+denied",
        ]}
      >
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(
        screen.getByText("OIDC provider returned an error: access_denied"),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
  });

  // ----------------------------------------------------------------
  // d) OIDC not configured
  // ----------------------------------------------------------------
  it("shows configuration error when OIDC_ISSUER and OIDC_CLIENT_ID are empty", async () => {
    delete window.RUNTIME_ENV;
    vi.resetModules();

    const OidcCallbackNC = (await import("./OidcCallback")).default;

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallbackNC />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText(/OIDC is not configured/i)).toBeInTheDocument();
    });
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();

    // Restore env
    window.RUNTIME_ENV = {
      REACT_APP_OIDC_ISSUER_URL:
        "https://keycloak.example.com/auth/realms/test",
      REACT_APP_OIDC_CLIENT_ID: "test-client-id",
      REACT_APP_OIDC_CLIENT_SECRET: "test-client-secret",
    };
    vi.resetModules();
    await import("./OidcCallback");
  });

  // ----------------------------------------------------------------
  // e) Token exchange failure
  // ----------------------------------------------------------------
  it("shows error when token exchange (axios.post) fails", async () => {
    sessionStorage.setItem("oidc_code_verifier", "test-verifier");
    axios.post.mockRejectedValue(new Error("Network error: 502 Bad Gateway"));

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(
        screen.getByText("Network error: 502 Bad Gateway"),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
  });

  // ----------------------------------------------------------------
  // f) Parse.User.logInWith failure
  // ----------------------------------------------------------------
  it("shows error when Parse.User.logInWith rejects", async () => {
    sessionStorage.setItem("oidc_code_verifier", "test-verifier");

    axios.post.mockResolvedValue({
      data: {
        access_token: "access-token-456",
        id_token: makeIdToken("user@example.com"),
      },
    });

    Parse.User.logInWith.mockRejectedValue(
      new Error("Parse login failed: invalid auth data"),
    );

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(
        screen.getByText("Parse login failed: invalid auth data"),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
  });

  // ----------------------------------------------------------------
  // g) id_token missing email claim
  // ----------------------------------------------------------------
  it("shows error when id_token has no email or preferred_username", async () => {
    sessionStorage.setItem("oidc_code_verifier", "test-verifier");

    const payload = btoa(JSON.stringify({ sub: "no-email-user" }));
    axios.post.mockResolvedValue({
      data: {
        access_token: "access-token-789",
        id_token: `header.${payload}.signature`,
      },
    });

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(
        screen.getByText("Could not extract email from the OIDC id_token."),
      ).toBeInTheDocument();
    });
  });

  // ----------------------------------------------------------------
  // h) getUserDetails returns null → navigate to /
  // ----------------------------------------------------------------
  it("navigates to / when getUserDetails returns null", async () => {
    sessionStorage.setItem("oidc_code_verifier", "test-verifier");

    axios.post.mockResolvedValue({
      data: {
        access_token: "access-token-111",
        id_token: makeIdToken("user@example.com"),
      },
    });

    Parse.Cloud.run.mockImplementation((fn) => {
      if (fn === "oidcSetupUser") return Promise.resolve();
      if (fn === "getUserDetails") return Promise.resolve(null);
      return Promise.resolve();
    });

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith("/");
    });
  });

  // ----------------------------------------------------------------
  // i) Disabled user
  // ----------------------------------------------------------------
  it("shows error when extUser IsDisabled is true", async () => {
    sessionStorage.setItem("oidc_code_verifier", "test-verifier");

    axios.post.mockResolvedValue({
      data: {
        access_token: "access-token-222",
        id_token: makeIdToken("disabled@example.com"),
      },
    });

    Parse.Cloud.run.mockImplementation((fn) => {
      if (fn === "oidcSetupUser") return Promise.resolve();
      if (fn === "getUserDetails")
        return Promise.resolve(createMockExtUser({ IsDisabled: true }));
      return Promise.resolve();
    });

    render(
      <MemoryRouter initialEntries={["/oidc/callback?code=abc123"]}>
        <OidcCallback />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("Account disabled")).toBeInTheDocument();
    });
  });
});
