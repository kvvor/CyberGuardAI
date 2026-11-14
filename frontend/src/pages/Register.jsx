import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../contexts/Auth";
import { api } from "../services/api";
import { PasswordField } from "./Auth";
import { ErrorMessage, Preferences, Resource, useResource } from "../components/common";
import { Button } from "../components/ui/button";
import "../i18n/registration";

export function RegistrationLink() {
  const config = useResource("/config/public");
  const { t } = useTranslation();
  return config.data?.public_signup === true ? <p><Link to="/register">{t("register")}</Link></p> : null;
}

export default function Register() {
  const { t } = useTranslation();
  const auth = useAuth();
  const navigate = useNavigate();
  const config = useResource("/config/public");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [disabled, setDisabled] = useState(false);
  if (auth.setup) return <Navigate to="/activate-account" replace />;
  if (auth.user) return <Navigate to="/dashboard" replace />;

  async function submit(event) {
    event.preventDefault();
    if (busy || disabled || config.data?.public_signup !== true) return;
    const values = Object.fromEntries(new FormData(event.currentTarget));
    values.display_name = values.display_name.trim();
    values.email = values.email.trim().toLowerCase();
    const bytes = value => new TextEncoder().encode(value).length;
    if (!values.display_name || bytes(values.display_name) > 200 || /\p{Cc}/u.test(values.display_name)) return setError("nameRequirements");
    if (bytes(values.email) > 254) return setError("invalid");
    if ([...values.password].length < 12 || bytes(values.password) > 1024) return setError("passwordHelp");
    if (values.password !== values.confirm_password) return setError("PASSWORD_MISMATCH");
    setBusy(true);
    setError("");
    try {
      const result = await api("/auth/register", { method: "POST", body: values });
      if (result?.code !== "REGISTRATION_ACCEPTED") throw new Error("Unexpected response");
      navigate("/login", { replace: true, state: { registrationAccepted: true } });
    } catch (failure) {
      setError(failure.code || "error");
      if (failure.code === "REGISTRATION_DISABLED") setDisabled(true);
    } finally { setBusy(false); }
  }

  return <main className="auth"><Preferences /><div className="auth-card">
    <ShieldCheck className="brand-icon" size={46} />
    <h1>CyberGuard <span>AI</span></h1><p className="muted">Security, made clear.</p>
    <h2>{t("register")}</h2>
    <Resource resource={config}>{data => data.public_signup === true && !disabled ?
      <form onSubmit={submit} aria-busy={busy}>
        <fieldset disabled={busy} className="registration-fields">
          <label>{t("display_name")}<input name="display_name" autoComplete="name" required /></label>
          <label>{t("email")}<input name="email" type="email" autoComplete="username" required /></label>
          <PasswordField name="password" autoComplete="new-password" />
          <PasswordField name="confirm_password" />
        </fieldset>
        <small>{t("passwordHelp")}</small><ErrorMessage code={error} />
        {busy && <p role="status">{t("loading")}</p>}
        <Button disabled={busy}>{t("register")}</Button>
      </form> : <div className="notice" role="status">{t("REGISTRATION_DISABLED")}</div>}
    </Resource>
    <p><Link to="/login">{t("backToLogin")}</Link></p>
  </div></main>;
}
