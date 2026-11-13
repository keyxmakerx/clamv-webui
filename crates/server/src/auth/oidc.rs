//! OpenID Connect sign-in: authorization code with PKCE, confidential client,
//! ID token checked with ring. Roles come only from configured groups; an
//! identity with no matching group is refused (deny by default).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::Role;
use crate::config::Config;

pub const CALLBACK_PATH: &str = "/login/oauth2/code/clamav";
const PENDING_TTL_MS: i64 = 10 * 60 * 1000;
const PENDING_MAX: usize = 1000;
const META_TTL_MS: i64 = 60 * 60 * 1000;
const JWKS_RETRY_MS: i64 = 60 * 1000;
const LEEWAY_SECS: i64 = 60;

#[derive(Debug, Clone, Deserialize)]
struct Meta {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

struct Cached {
    meta: Meta,
    jwks: Jwks,
    fetched: i64,
    jwks_fetched: i64,
}

struct Pending {
    nonce: String,
    verifier: String,
    created: i64,
}

/// A verified identity from the provider.
#[derive(Debug, Clone)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    pub name: String,
    pub groups: Vec<String>,
}

impl Identity {
    /// Stable local name derived from issuer and subject, never from email or username.
    pub fn principal(&self) -> String {
        let d = Sha256::digest(format!("{}\0{}", self.issuer, self.subject));
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        format!("oidc:{}", &hex[..48])
    }
}

pub struct Oidc {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,
    groups_claim: String,
    admin: Vec<String>,
    operator: Vec<String>,
    viewer: Vec<String>,
    label: String,
    provider_logout: bool,
    allow_http: bool,
    http: reqwest::Client,
    cache: tokio::sync::Mutex<Option<Cached>>,
    pending: Mutex<HashMap<String, Pending>>,
}

fn loopback(u: &Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        None => false,
    }
}

fn groups_list(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|g| g.trim().to_lowercase())
        .filter(|g| !g.is_empty())
        .collect()
}

fn b64url(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| "bad base64".to_owned())
}

fn now_ms() -> i64 {
    crate::db::now_ms()
}

impl Oidc {
    /// None when OIDC is not configured; an error when it is configured wrongly.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Option<Self>> {
        let issuer = cfg
            .oidc_issuer
            .clone()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if issuer.is_empty() {
            return Ok(None);
        }
        let client_id = cfg
            .oidc_client_id
            .clone()
            .unwrap_or_default()
            .trim()
            .to_owned();
        let client_secret = match &cfg.oidc_client_secret_file {
            Some(p) => std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("cannot read OIDC_CLIENT_SECRET_FILE {}: {e}", p.display())
            })?,
            None => cfg.oidc_client_secret.clone().unwrap_or_default(),
        }
        .trim()
        .to_owned();
        let redirect_uri = cfg
            .oidc_redirect_uri
            .clone()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if client_id.is_empty() || client_secret.is_empty() || redirect_uri.is_empty() {
            anyhow::bail!(
                "OIDC_ISSUER needs OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI"
            );
        }
        let iu = Url::parse(&issuer).map_err(|_| anyhow::anyhow!("OIDC_ISSUER is not a URL"))?;
        let allow_http = loopback(&iu);
        if iu.scheme() != "https" && !(iu.scheme() == "http" && allow_http) {
            anyhow::bail!("OIDC_ISSUER must use https");
        }
        let ru = Url::parse(&redirect_uri)
            .map_err(|_| anyhow::anyhow!("OIDC_REDIRECT_URI is not a URL"))?;
        if !matches!(ru.scheme(), "http" | "https") || !ru.path().ends_with(CALLBACK_PATH) {
            anyhow::bail!("OIDC_REDIRECT_URI must be an http(s) URL ending in {CALLBACK_PATH}");
        }
        let admin = groups_list(&cfg.oidc_admin_groups);
        let operator = groups_list(&cfg.oidc_operator_groups);
        let viewer = groups_list(&cfg.oidc_viewer_groups);
        if admin.is_empty() && operator.is_empty() && viewer.is_empty() {
            anyhow::bail!(
                "set OIDC_ADMIN_GROUPS, OIDC_OPERATOR_GROUPS or OIDC_VIEWER_GROUPS; nobody could sign in"
            );
        }
        let tls = crate::webhook::client_tls(cfg.oidc_ca_file.as_deref())?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("clamv-webui/", env!("CARGO_PKG_VERSION")))
            .tls_backend_preconfigured(tls)
            .build()
            .map_err(|e| anyhow::anyhow!("OIDC client: {e}"))?;
        Ok(Some(Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            client_id,
            client_secret,
            redirect_uri,
            scopes: cfg.oidc_scopes.clone(),
            groups_claim: cfg.oidc_groups_claim.clone(),
            admin,
            operator,
            viewer,
            label: cfg.oidc_button_label.clone(),
            provider_logout: cfg.oidc_provider_logout,
            allow_http,
            http,
            cache: tokio::sync::Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
        }))
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn check_url(&self, s: &str) -> Result<Url, String> {
        let u = Url::parse(s).map_err(|_| "provider sent a bad URL".to_owned())?;
        if u.scheme() == "https" || (self.allow_http && u.scheme() == "http") {
            Ok(u)
        } else {
            Err("provider endpoint is not https".into())
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, String> {
        let u = self.check_url(url)?;
        let r = self
            .http
            .get(u)
            .send()
            .await
            .map_err(|e| format!("provider unreachable: {}", e.without_url()))?;
        if !r.status().is_success() {
            return Err(format!("provider answered HTTP {}", r.status().as_u16()));
        }
        r.json()
            .await
            .map_err(|_| "provider sent invalid JSON".to_owned())
    }

    async fn discover(&self) -> Result<Cached, String> {
        let meta: Meta = self
            .get_json(&format!("{}/.well-known/openid-configuration", self.issuer))
            .await?;
        if meta.issuer.trim_end_matches('/') != self.issuer {
            return Err("discovery issuer does not match OIDC_ISSUER".into());
        }
        let jwks: Jwks = self.get_json(&meta.jwks_uri).await?;
        let now = now_ms();
        Ok(Cached {
            meta,
            jwks,
            fetched: now,
            jwks_fetched: now,
        })
    }

    async fn meta(&self) -> Result<Meta, String> {
        let mut g = self.cache.lock().await;
        if g.as_ref()
            .is_none_or(|c| now_ms() - c.fetched > META_TTL_MS)
        {
            match self.discover().await {
                Ok(c) => *g = Some(c),
                // Keep serving a cached document if the provider blips.
                Err(e) if g.is_none() => return Err(e),
                Err(e) => {
                    tracing::warn!(event = "oidc.discovery_failed", error = %e, "using cached OIDC metadata")
                }
            }
        }
        g.as_ref()
            .map(|c| c.meta.clone())
            .ok_or_else(|| "no metadata".into())
    }

    /// Begin a sign-in: the provider URL to send the browser to, and the state to bind in a cookie.
    pub async fn start(&self) -> Result<(String, String), String> {
        let meta = self.meta().await?;
        let mut u = self.check_url(&meta.authorization_endpoint)?;
        let state = super::token::random_secret();
        let nonce = super::token::random_secret();
        let verifier = super::token::random_secret();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        {
            let mut p = self.pending.lock().map_err(|_| "busy".to_owned())?;
            let now = now_ms();
            p.retain(|_, v| now - v.created < PENDING_TTL_MS);
            if p.len() >= PENDING_MAX {
                return Err("too many sign-ins in progress; try again shortly".into());
            }
            p.insert(
                state.clone(),
                Pending {
                    nonce: nonce.clone(),
                    verifier,
                    created: now,
                },
            );
        }
        u.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((u.to_string(), state))
    }

    /// Finish a sign-in from the callback's state and code.
    pub async fn finish(&self, state: &str, code: &str) -> Result<Identity, String> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| "busy".to_owned())?
            .remove(state)
            .filter(|p| now_ms() - p.created < PENDING_TTL_MS)
            .ok_or_else(|| "sign-in expired or was already used".to_owned())?;
        let meta = self.meta().await?;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("code_verifier", &pending.verifier)
            .finish();
        let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
        let basic = STANDARD.encode(format!(
            "{}:{}",
            enc(&self.client_id),
            enc(&self.client_secret)
        ));
        let r = self
            .http
            .post(self.check_url(&meta.token_endpoint)?)
            .header(reqwest::header::AUTHORIZATION, format!("Basic {basic}"))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(form)
            .send()
            .await
            .map_err(|e| format!("token endpoint unreachable: {}", e.without_url()))?;
        let status = r.status();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let code = body["error"].as_str().unwrap_or("unknown");
            return Err(format!("provider refused the code ({})", clean(code)));
        }
        let id_token = body["id_token"]
            .as_str()
            .ok_or("no id_token in the response")?;
        let claims = self.verify(id_token).await?;
        self.check_claims(&claims, &pending.nonce)?;
        let subject = claims["sub"].as_str().unwrap_or_default().to_owned();
        let mut groups = claim_groups(&claims, &self.groups_claim);
        let mut name_src = claims.clone();
        if groups.is_none()
            && let (Some(ep), Some(at)) = (
                meta.userinfo_endpoint.as_deref(),
                body["access_token"].as_str(),
            )
        {
            let info: Value = self
                .http
                .get(self.check_url(ep)?)
                .bearer_auth(at)
                .send()
                .await
                .map_err(|e| format!("userinfo unreachable: {}", e.without_url()))?
                .json()
                .await
                .map_err(|_| "userinfo sent invalid JSON".to_owned())?;
            if info["sub"].as_str() != Some(subject.as_str()) {
                return Err("userinfo subject does not match the ID token".into());
            }
            groups = claim_groups(&info, &self.groups_claim);
            name_src = info;
        }
        let name = ["preferred_username", "email", "name"]
            .iter()
            .find_map(|k| name_src[*k].as_str().or_else(|| claims[*k].as_str()))
            .unwrap_or(&subject)
            .to_owned();
        Ok(Identity {
            issuer: self.issuer.clone(),
            subject,
            name,
            groups: groups.unwrap_or_default(),
        })
    }

    fn check_claims(&self, c: &Value, nonce: &str) -> Result<(), String> {
        let now = now_ms() / 1000;
        if c["iss"].as_str().map(|s| s.trim_end_matches('/')) != Some(self.issuer.as_str()) {
            return Err("ID token issuer does not match".into());
        }
        let aud_ok = match &c["aud"] {
            Value::String(a) => a == &self.client_id,
            Value::Array(list) => {
                list.iter()
                    .any(|a| a.as_str() == Some(self.client_id.as_str()))
                    && (list.len() == 1 || c["azp"].as_str() == Some(self.client_id.as_str()))
            }
            _ => false,
        };
        if !aud_ok {
            return Err("ID token is not for this client".into());
        }
        match c["exp"].as_i64() {
            Some(exp) if exp + LEEWAY_SECS > now => {}
            _ => return Err("ID token expired".into()),
        }
        if c["iat"].as_i64().is_some_and(|iat| iat > now + 300) {
            return Err("ID token is from the future; check the clock".into());
        }
        if c["nonce"].as_str() != Some(nonce) {
            return Err("ID token nonce does not match".into());
        }
        if c["sub"]
            .as_str()
            .is_none_or(|s| s.is_empty() || s.len() > 255)
        {
            return Err("ID token has no usable subject".into());
        }
        Ok(())
    }

    async fn verify(&self, jwt: &str) -> Result<Value, String> {
        let parts: Vec<&str> = jwt.split('.').collect();
        let [h, p, s] = parts.as_slice() else {
            return Err("ID token is not a JWS".into());
        };
        let header: Value =
            serde_json::from_slice(&b64url(h)?).map_err(|_| "bad ID token header".to_owned())?;
        let alg = header["alg"].as_str().unwrap_or_default().to_owned();
        let kid = header["kid"].as_str().map(str::to_owned);
        let sig = b64url(s)?;
        let msg = format!("{h}.{p}");
        for round in 0..2 {
            let keys = {
                let mut g = self.cache.lock().await;
                // Unknown key: the provider may have rotated; refetch at most once a minute.
                if round == 1 {
                    let Some(c) = g.as_mut() else { break };
                    if now_ms() - c.jwks_fetched < JWKS_RETRY_MS {
                        break;
                    }
                    let uri = c.meta.jwks_uri.clone();
                    drop(g);
                    let jwks: Jwks = self.get_json(&uri).await?;
                    let mut g = self.cache.lock().await;
                    if let Some(c) = g.as_mut() {
                        c.jwks = jwks.clone();
                        c.jwks_fetched = now_ms();
                    }
                    jwks.keys
                } else {
                    g.as_ref().map(|c| c.jwks.keys.clone()).unwrap_or_default()
                }
            };
            let candidates = keys.iter().filter(|k| {
                k.usage.as_deref().is_none_or(|u| u == "sig")
                    && match (&kid, &k.kid) {
                        (Some(a), Some(b)) => a == b,
                        (Some(_), None) => false,
                        (None, _) => true,
                    }
            });
            for k in candidates {
                if verify_sig(&alg, k, msg.as_bytes(), &sig)? {
                    let payload: Value = serde_json::from_slice(&b64url(p)?)
                        .map_err(|_| "bad ID token payload".to_owned())?;
                    return Ok(payload);
                }
            }
        }
        Err("ID token signature is not valid".into())
    }

    /// The highest role any of the groups grants.
    pub fn role_for(&self, groups: &[String]) -> Option<Role> {
        let have: Vec<String> = groups.iter().map(|g| g.trim().to_lowercase()).collect();
        let hit = |want: &[String]| want.iter().any(|w| have.contains(w));
        if hit(&self.admin) {
            Some(Role::Admin)
        } else if hit(&self.operator) {
            Some(Role::Operator)
        } else if hit(&self.viewer) {
            Some(Role::Viewer)
        } else {
            None
        }
    }

    /// Where to send an SSO user after local sign-out, if provider logout is on.
    pub async fn logout_url(&self) -> Option<String> {
        if !self.provider_logout {
            return None;
        }
        let meta = self.meta().await.ok()?;
        let mut u = self.check_url(meta.end_session_endpoint.as_deref()?).ok()?;
        let back = Url::parse(&self.redirect_uri)
            .ok()?
            .join("/login?logout")
            .ok()?;
        u.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("post_logout_redirect_uri", back.as_str());
        Some(u.to_string())
    }
}

fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

/// Groups at a dotted claim path: an array of strings or one string.
fn claim_groups(v: &Value, path: &str) -> Option<Vec<String>> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    match cur {
        Value::Array(a) => Some(
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .take(1000)
                .collect(),
        ),
        Value::String(s) => Some(vec![s.clone()]),
        _ => None,
    }
}

fn verify_sig(alg: &str, k: &Jwk, msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    use ring::signature as rs;
    let rsa = |params: &'static rs::RsaParameters| -> Result<bool, String> {
        if k.kty != "RSA" {
            return Ok(false);
        }
        let (Some(n), Some(e)) = (&k.n, &k.e) else {
            return Ok(false);
        };
        let key = rs::RsaPublicKeyComponents {
            n: b64url(n)?,
            e: b64url(e)?,
        };
        Ok(key.verify(params, msg, sig).is_ok())
    };
    let ec = |crv: &str, alg: &'static rs::EcdsaVerificationAlgorithm| -> Result<bool, String> {
        if k.kty != "EC" || k.crv.as_deref() != Some(crv) {
            return Ok(false);
        }
        let (Some(x), Some(y)) = (&k.x, &k.y) else {
            return Ok(false);
        };
        let mut point = vec![4u8];
        point.extend(b64url(x)?);
        point.extend(b64url(y)?);
        Ok(rs::UnparsedPublicKey::new(alg, point)
            .verify(msg, sig)
            .is_ok())
    };
    match alg {
        "RS256" => rsa(&rs::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => rsa(&rs::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => rsa(&rs::RSA_PKCS1_2048_8192_SHA512),
        "PS256" => rsa(&rs::RSA_PSS_2048_8192_SHA256),
        "PS384" => rsa(&rs::RSA_PSS_2048_8192_SHA384),
        "PS512" => rsa(&rs::RSA_PSS_2048_8192_SHA512),
        "ES256" => ec("P-256", &rs::ECDSA_P256_SHA256_FIXED),
        "ES384" => ec("P-384", &rs::ECDSA_P384_SHA384_FIXED),
        "EdDSA" => {
            if k.kty != "OKP" || k.crv.as_deref() != Some("Ed25519") {
                return Ok(false);
            }
            let Some(x) = &k.x else { return Ok(false) };
            Ok(rs::UnparsedPublicKey::new(&rs::ED25519, b64url(x)?)
                .verify(msg, sig)
                .is_ok())
        }
        // "none" and HMAC algorithms are never accepted.
        _ => Err(format!("ID token algorithm {} is not accepted", clean(alg))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_follow_dotted_paths() {
        let v = serde_json::json!({"groups": ["a", "b"], "realm_access": {"roles": ["x"]}, "one": "solo"});
        assert_eq!(
            claim_groups(&v, "groups"),
            Some(vec!["a".into(), "b".into()])
        );
        assert_eq!(
            claim_groups(&v, "realm_access.roles"),
            Some(vec!["x".into()])
        );
        assert_eq!(claim_groups(&v, "one"), Some(vec!["solo".into()]));
        assert_eq!(claim_groups(&v, "missing"), None);
    }

    #[test]
    fn es256_and_algorithm_rules() {
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("gen");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng)
            .expect("kp");
        let pk = kp.public_key().as_ref();
        let jwk = Jwk {
            kty: "EC".into(),
            kid: None,
            crv: Some("P-256".into()),
            n: None,
            e: None,
            x: Some(URL_SAFE_NO_PAD.encode(&pk[1..33])),
            y: Some(URL_SAFE_NO_PAD.encode(&pk[33..65])),
            usage: None,
        };
        let sig = kp.sign(&rng, b"msg").expect("sign");
        assert_eq!(verify_sig("ES256", &jwk, b"msg", sig.as_ref()), Ok(true));
        assert_eq!(verify_sig("ES256", &jwk, b"other", sig.as_ref()), Ok(false));
        assert_eq!(
            verify_sig("RS256", &jwk, b"msg", sig.as_ref()),
            Ok(false),
            "kty must match"
        );
        assert!(verify_sig("none", &jwk, b"msg", b"").is_err());
        assert!(verify_sig("HS256", &jwk, b"msg", b"").is_err());
    }

    #[test]
    fn principal_is_stable_and_bounded() {
        let i = Identity {
            issuer: "https://id.example".into(),
            subject: "abc".into(),
            name: "n".into(),
            groups: vec![],
        };
        assert_eq!(i.principal().len(), 53);
        assert_eq!(i.principal(), i.principal());
    }
}
