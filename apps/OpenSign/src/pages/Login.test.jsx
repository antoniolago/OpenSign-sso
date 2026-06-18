import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import Parse from "parse";
import axios from "axios";

// ====================================================================
// Login — SSO-specific Vitest Unit Tests
// ====================================================================
//
// The component reads OIDC config from module-level constants which
// fall back to window.RUNTIME_ENV.  We set RUNTIME_ENV per test group
// via vi.resetModules() + dynamic import so each scenario gets the
// exact config it needs.
//
// This file focusses exclusively on the SSO/OIDC parts:
//   a) SSO button hidden when OIDC not configured
//   b) SSO button visible when OIDC configured
//   c) Custom button text via REACT_APP_OIDC_BUTTON_TEXT
//   d) Auto-redirect enabled (no session) → triggerOidcRedirect()
//   e) Auto-redirect enabled (has session) → GetLoginData()
// ====================================================================

// ----- Hoisted: crypto mocks for PKCE (needed by triggerOidcRedirect) -----
vi.hoisted(() => {
  if (typeof globalThis.crypto !== "object" || !globalThis.crypto) {
    globalThis.crypto = {};
  }
  // jsdom already defines getRandomValues — keep it, or override for determinism
  globalThis.crypto.getRandomValues ??= function (arr) {
    for (let i = 0; i < arr.length; i++) arr[i] = 42;
    return arr;
  };
  // subtle has a read-only getter in jsdom — use defineProperty to override.
  // Use vi.fn() so we can spy on digest() calls.
  const digestFn = vi.fn(() => Promise.resolve(new ArrayBuffer(32)));
  Object.defineProperty(globalThis.crypto, "subtle", {
    value: { digest: digestFn },
    configurable: true,
    writable: false,
  });
});

// ---------------------------------------------------------------
// Mock everything Login depends on
// ---------------------------------------------------------------

const mockNavigate = vi.fn();

vi.mock("react-router", async () => {
  const actual = await vi.importActual("react-router");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({ state: null, pathname: "/login" }),
  };
});

vi.mock("react-redux", () => ({
  useDispatch: () => vi.fn(),
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key) => {
      const dict = {
        "login-sso": "login-sso",
        or: "or",
        loading: "loading",
        welcome: "Welcome",
        "Login-to-your-account": "Log in to your account",
        email: "Email",
        password: "Password",
        login: "Log In",
      };
      return dict[key] || key;
    },
    i18n: { language: "en", changeLanguage: vi.fn() },
  }),
}));

vi.mock("parse", () => {
  const mockBecomeUser = {
    getSessionToken: vi.fn().mockReturnValue("session-from-become"),
    toJSON: vi.fn().mockReturnValue({
      sessionToken: "session-from-become",
      email: "existing@example.com",
      id: "user-existing",
    }),
    get: vi.fn().mockReturnValue(null),
  };
  return {
    default: {
      User: {
        become: vi.fn().mockResolvedValue(mockBecomeUser),
        logOut: vi.fn(),
      },
      Cloud: { run: vi.fn() },
    },
  };
});

vi.mock("axios", () => ({
  default: { post: vi.fn(), get: vi.fn() },
}));

vi.mock("../hook/useWindowSize", () => ({
  useWindowSize: () => ({ width: 1024, height: 768 }),
}));

vi.mock("../constant/Utils", () => ({
  getAppLogo: vi.fn(),
  saveLanguageInLocal: vi.fn(),
  usertimezone: "America/New_York",
}));

vi.mock("../constant/appinfo", () => ({
  appInfo: {
    appId: "test-app",
    applogo: "test-logo.png",
    baseUrl: "/api",
    defaultRole: "contracts_User",
    fev_Icon: "data:image/png;base64,test",
    settings: [
      {
        role: "contracts_Admin",
        menuId: "VPh91h0ZHk",
        pageType: "dashboard",
        pageId: "35KBoSgoAK",
      },
      {
        role: "contracts_User",
        menuId: "H9vRfEYKhT",
        pageType: "dashboard",
        pageId: "35KBoSgoAK",
      },
    ],
  },
}));

vi.mock("../redux/reducers/infoReducer", () => ({
  fetchAppInfo: () => ({ type: "FETCH_APP_INFO" }),
}));

vi.mock("../redux/reducers/ShowTenant", () => ({
  showTenant: (name) => ({ type: "SHOW_TENANT", payload: name }),
}));

vi.mock("../primitives/Loader", () => ({
  default: () => <div data-testid="loader">Loading...</div>,
}));

vi.mock("../primitives/ModalUi", () => ({
  default: ({ isOpen, title, showClose, children }) =>
    isOpen ? (
      <div data-testid="modal" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

vi.mock("../primitives/Alert", () => ({
  default: ({ type, children }) => (
    <div data-testid="alert" data-type={type}>
      {children}
    </div>
  ),
}));

vi.mock("../components/pdf/SelectLanguage", () => ({
  default: () => <div data-testid="select-language" />,
}));

// ----- Helpers -----

/** Create a mock extUser for Parse.Cloud.run("getUserDetails"). */
function createMockExtUser(overrides = {}) {
  const props = {
    IsDisabled: false,
    UserRole: "contracts_User",
    Email: "existing@example.com",
    Name: "Existing User",
    TenantId: { objectId: "tenant-1", TenantName: "Test Tenant" },
    ...overrides,
  };
  return {
    get: vi.fn((key) => props[key] ?? null),
    ...props,
  };
}

/**
 * Shared env for "OIDC configured" tests.
 * Auto-redirect is OFF so the component renders the login form.
 */
const CONFIGURED_ENV = {
  REACT_APP_OIDC_ISSUER_URL: "https://keycloak.example.com/auth/realms/test",
  REACT_APP_OIDC_CLIENT_ID: "test-client-id",
  REACT_APP_OIDC_CLIENT_SECRET: "",
  REACT_APP_OIDC_BUTTON_TEXT: "",
  REACT_APP_OIDC_AUTO_REDIRECT: "false",
};

// ----- Imports (will be re-imported dynamically per test) -----
// No static import of Login — each test calls import() after setting env.

describe("Login — SSO behaviour", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    mockNavigate.mockReset();
  });

  // ----------------------------------------------------------------
  // a) SSO button hidden when OIDC not configured
  // ----------------------------------------------------------------
  it("hides SSO button when OIDC_ISSUER is not set", async () => {
    delete window.RUNTIME_ENV;
    vi.resetModules();

    const { getAppLogo } = await import("../constant/Utils");
    getAppLogo.mockResolvedValue({ logo: "test-logo.png" });
    Parse.Cloud.run.mockResolvedValue(null); // getUserDetails returns null

    const Login = (await import("./Login")).default;

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );

    // Wait for effects to settle (getAppLogo resolves, fetchAppInfo dispatched)
    await waitFor(() => {
      expect(screen.getByText("Welcome")).toBeInTheDocument();
    });

    // SSO elements MUST NOT be present
    expect(screen.queryByText("login-sso")).not.toBeInTheDocument();
    expect(screen.queryByText("or")).not.toBeInTheDocument();
  });

  // ----------------------------------------------------------------
  // b) SSO button visible when OIDC configured
  // ----------------------------------------------------------------
  it("shows SSO button when OIDC_ISSUER and OIDC_CLIENT_ID are set", async () => {
    window.RUNTIME_ENV = { ...CONFIGURED_ENV };
    vi.resetModules();

    const { getAppLogo } = await import("../constant/Utils");
    getAppLogo.mockResolvedValue({ logo: "test-logo.png" });
    Parse.Cloud.run.mockResolvedValue(null);

    const Login = (await import("./Login")).default;

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("login-sso")).toBeInTheDocument();
    });

    // Divider "or" should also be present
    expect(screen.getByText("or")).toBeInTheDocument();
  });

  // ----------------------------------------------------------------
  // c) Custom SSO button text
  // ----------------------------------------------------------------
  it("shows custom text on the SSO button when OIDC_BUTTON_TEXT is set", async () => {
    window.RUNTIME_ENV = {
      ...CONFIGURED_ENV,
      REACT_APP_OIDC_BUTTON_TEXT: "Custom SSO",
    };
    vi.resetModules();

    const { getAppLogo } = await import("../constant/Utils");
    getAppLogo.mockResolvedValue({ logo: "test-logo.png" });
    Parse.Cloud.run.mockResolvedValue(null);

    const Login = (await import("./Login")).default;

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("Custom SSO")).toBeInTheDocument();
    });

    // Default key "login-sso" must NOT appear
    expect(screen.queryByText("login-sso")).not.toBeInTheDocument();
  });

  // ----------------------------------------------------------------
  // d) Auto-redirect enabled (no session)
  // ----------------------------------------------------------------
  it("triggers OIDC redirect when auto-redirect is enabled and no session exists", async () => {
    window.RUNTIME_ENV = {
      ...CONFIGURED_ENV,
      REACT_APP_OIDC_AUTO_REDIRECT: "true",
    };
    vi.resetModules();

    // getAppLogo must resolve so checkUserExt proceeds to the redirect check
    const { getAppLogo } = await import("../constant/Utils");
    getAppLogo.mockResolvedValue({ logo: "test-logo.png" });

    const Login = (await import("./Login")).default;

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );

    // checkUserExt should call triggerOidcRedirect which sets the verifier
    await waitFor(() => {
      expect(sessionStorage.getItem("oidc_code_verifier")).toBeTruthy();
    });

    // triggerOidcRedirect also calls crypto.subtle.digest for the PKCE challenge
    expect(globalThis.crypto.subtle.digest).toHaveBeenCalledWith(
      "SHA-256",
      expect.any(Object),
    );

    // The component redirects away via window.location.href (which jsdom
    // won't navigate, but the redirect call is confirmed above). The SSO
    // login form is still rendered in jsdom since no real navigation occurs.
  });

  // ----------------------------------------------------------------
  // e) Auto-redirect with existing session
  // ----------------------------------------------------------------
  it("calls GetLoginData when auto-redirect is enabled and session exists", async () => {
    localStorage.setItem("accesstoken", "existing-session-token");

    window.RUNTIME_ENV = {
      ...CONFIGURED_ENV,
      REACT_APP_OIDC_AUTO_REDIRECT: "true",
    };
    vi.resetModules();

    const { getAppLogo } = await import("../constant/Utils");
    getAppLogo.mockResolvedValue({ logo: "test-logo.png" });

    // GetLoginData calls Parse.User.become then Parse.Cloud.run("getUserDetails")
    Parse.Cloud.run.mockImplementation((fn) => {
      if (fn === "getUserDetails")
        return Promise.resolve(createMockExtUser());
      return Promise.resolve();
    });

    const Login = (await import("./Login")).default;

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );

    // Wait for Parse.User.become to be called with the stored token
    await waitFor(() => {
      expect(Parse.User.become).toHaveBeenCalledWith("existing-session-token");
    });

    // Should navigate to dashboard
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith("/dashboard/35KBoSgoAK");
    });

    // Should NOT trigger OIDC redirect (no verifier set)
    expect(sessionStorage.getItem("oidc_code_verifier")).toBeNull();
  });
});
