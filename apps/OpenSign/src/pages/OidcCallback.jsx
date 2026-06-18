import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import Parse from "parse";
import axios from "axios";
import { useTranslation } from "react-i18next";
import Loader from "../primitives/Loader";
import { useDispatch } from "react-redux";
import { fetchAppInfo } from "../redux/reducers/infoReducer";
import { showTenant } from "../redux/reducers/ShowTenant";
import { appInfo } from "../constant/appinfo";
import { saveLanguageInLocal } from "../constant/Utils";

/**
 * Generic OIDC callback handler.
 *
 * Required env vars (can be injected at build or runtime via entrypoint.sh):
 *   OIDC_ISSUER_URL     — e.g. https://accounts.google.com
 *   OIDC_CLIENT_ID      — client id registered with the OIDC provider
 *   OIDC_CLIENT_SECRET  — (optional, leave empty for PKCE-only)
 */
const OIDC_ISSUER =
  process.env.REACT_APP_OIDC_ISSUER_URL ||
  window.RUNTIME_ENV?.REACT_APP_OIDC_ISSUER_URL ||
  "";
const OIDC_CLIENT_ID =
  process.env.REACT_APP_OIDC_CLIENT_ID ||
  window.RUNTIME_ENV?.REACT_APP_OIDC_CLIENT_ID ||
  "";
const OIDC_CLIENT_SECRET =
  process.env.REACT_APP_OIDC_CLIENT_SECRET ||
  window.RUNTIME_ENV?.REACT_APP_OIDC_CLIENT_SECRET ||
  "";
const OIDC_REDIRECT_URI = `${window.location.origin}/oidc/callback`;

function OidcCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { t, i18n } = useTranslation();
  const [error, setError] = useState(null);

  useEffect(() => {
    handleCallback();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleCallback() {
    try {
      if (!OIDC_ISSUER || !OIDC_CLIENT_ID) {
        throw new Error(
          "OIDC is not configured. Set REACT_APP_OIDC_ISSUER_URL and REACT_APP_OIDC_CLIENT_ID.",
        );
      }

      const code = searchParams.get("code");
      const errorParam = searchParams.get("error");

      if (errorParam) {
        throw new Error(`OIDC provider returned an error: ${errorParam}`);
      }
      if (!code) {
        throw new Error("No authorization code received from the OIDC provider.");
      }

      // Retrieve PKCE code_verifier stored before redirect
      const codeVerifier = sessionStorage.getItem("oidc_code_verifier");
      sessionStorage.removeItem("oidc_code_verifier");

      // Exchange authorization code for tokens
      const tokenParams = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: OIDC_CLIENT_ID,
        code,
        redirect_uri: OIDC_REDIRECT_URI,
      });

      if (codeVerifier) {
        tokenParams.set("code_verifier", codeVerifier);
      }
      if (OIDC_CLIENT_SECRET) {
        tokenParams.set("client_secret", OIDC_CLIENT_SECRET);
      }

      const tokenResponse = await axios.post(
        `${OIDC_ISSUER}/protocol/openid-connect/token`,
        tokenParams.toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
      );

      const { access_token, id_token } = tokenResponse.data;

      // Decode id_token to extract user email (standard OIDC claim)
      let email = "";
      if (id_token) {
        const payload = JSON.parse(atob(id_token.split(".")[1]));
        email = payload.email || payload.preferred_username || "";
      }
      if (!email) {
        throw new Error("Could not extract email from the OIDC id_token.");
      }

      // Log in to Parse using the SSO auth adapter
      const user = await Parse.User.logInWith("sso", {
        authData: { id: email.toLowerCase(), access_token },
      });

      // Create/update the extended user profile (contracts_Users) via cloud function.
      // This maps OIDC claims (email, name, groups) to OpenSign roles.
      // All configurable via env vars — see OIDC_CLAIM_*, OIDC_ADMIN_GROUP, etc.
      try {
        await Parse.Cloud.run("oidcSetupUser", {
          id_token: id_token || "",
          access_token,
        });
      } catch (setupErr) {
        console.warn("OIDC profile setup warning (non-fatal):", setupErr.message);
      }

      // Post-login flow (mirrors thirdpartyLoginfn from Login.jsx)
      const sessionToken = user.getSessionToken();
      window.localStorage.setItem("accesstoken", sessionToken);
      window.localStorage.setItem(
        "UserInformation",
        JSON.stringify(user.toJSON()),
      );
      window.localStorage.setItem("userEmail", email);

      if (user.get("ProfilePic")) {
        localStorage.setItem("profileImg", user.get("ProfilePic"));
      }

      dispatch(fetchAppInfo());
      const userSettings = appInfo.settings;

      const extUser = await Parse.Cloud.run("getUserDetails");
      if (extUser) {
        const IsDisabled = extUser?.get("IsDisabled") || false;
        if (IsDisabled) {
          throw new Error(t("do-not-access-contact-admin"));
        }

        const userRole = extUser?.get("UserRole");
        const menu =
          userRole && userSettings?.find((menu) => menu.role === userRole);

        if (menu) {
          const extInfo = JSON.parse(JSON.stringify(extUser));
          const _role = userRole.replace("contracts_", "");
          localStorage.setItem("_user_role", _role);
          localStorage.setItem("Extand_Class", JSON.stringify([extUser]));
          localStorage.setItem("userEmail", extInfo.Email);
          localStorage.setItem("username", extInfo.Name || "");

          if (extInfo?.TenantId) {
            const tenant = {
              Id: extInfo.TenantId.objectId || "",
              Name: extInfo.TenantId.TenantName || "",
            };
            localStorage.setItem("TenantId", tenant.Id);
            dispatch(showTenant(tenant.Name));
            localStorage.setItem("TenantName", tenant.Name);
          }

          localStorage.setItem("PageLanding", menu.pageId);
          localStorage.setItem("defaultmenuid", menu.menuId);
          localStorage.setItem("pageType", menu.pageType);

          navigate(`/${menu.pageType}/${menu.pageId}`);
        } else {
          navigate("/");
        }
      } else {
        navigate("/");
      }
    } catch (err) {
      console.error("OIDC callback error:", err);
      setError(err.message || t("something-went-wrong-mssg"));
      setTimeout(() => navigate("/"), 4000);
    }
  }

  if (error) {
    return (
      <div className="h-screen flex flex-col justify-center items-center p-4 text-center">
        <div className="text-red-500 text-lg font-semibold mb-2">
          {t("something-went-wrong-mssg")}
        </div>
        <div className="text-gray-500 text-sm">{error}</div>
        <div className="text-gray-400 text-xs mt-4">
          {t("redirecting")}...
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex justify-center items-center">
      <Loader />
    </div>
  );
}

export default OidcCallback;
