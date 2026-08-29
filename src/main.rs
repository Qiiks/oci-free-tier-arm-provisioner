use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer as _};
use sha2::{Digest, Sha256};

// ─── Configuration ─────────────────────────────────────────────────────────

const SHAPE: &str = "VM.Standard.A1.Flex";
const API_VERSION: &str = "20160918";
const UA: &str = "oci-free-tier-arm/1.0";

// Hard caps — Always Free entitlement for A1.Flex
const MAX_OCPUS: f64 = 2.0;
const MAX_MEMORY_GB: f64 = 12.0;

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_i64(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn expand_home(path: &str) -> String {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", home, rest)
    } else if path == "~" {
        home
    } else {
        path.to_string()
    }
}

// ─── Logging ───────────────────────────────────────────────────────────────

fn ts() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn log(msg: &str) {
    println!("[{}] [INFO] {}", ts(), msg);
}

fn warn(msg: &str) {
    println!("[{}] [WARN] {}", ts(), msg);
}

fn error(msg: &str) {
    println!("[{}] [ERROR] {}", ts(), msg);
}

// ─── OCI Config ────────────────────────────────────────────────────────────

struct OciConfig {
    user: String,
    fingerprint: String,
    key_file: String,
    tenancy: String,
    region: String,
}

fn load_config() -> Result<OciConfig, String> {
    let config_path = expand_home(&env_str("OCI_CONFIG_FILE", "~/.oci/config"));
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("OCI config not found at {}: {}\nRun: oci setup config", config_path, e))?;

    let mut map = std::collections::HashMap::new();
    let mut in_default = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_default = line == "[DEFAULT]";
            continue;
        }
        if in_default {
            if let Some(eq) = line.find('=') {
                let k = line[..eq].trim().to_string();
                let v = line[eq + 1..].trim().to_string();
                map.insert(k, v);
            }
        }
    }

    let get = |k: &str| map.get(k).cloned().unwrap_or_default();
    let cfg = OciConfig {
        user: get("user"),
        fingerprint: get("fingerprint"),
        key_file: get("key_file"),
        tenancy: get("tenancy"),
        region: get("region"),
    };
    for (name, val) in [
        ("user", &cfg.user),
        ("fingerprint", &cfg.fingerprint),
        ("key_file", &cfg.key_file),
        ("tenancy", &cfg.tenancy),
        ("region", &cfg.region),
    ] {
        if val.is_empty() {
            return Err(format!("OCI config missing required field '{name}'"));
        }
    }
    Ok(cfg)
}

// ─── OCI Signature Version 1 ──────────────────────────────────────────────

struct OciSigner {
    tenancy: String,
    user: String,
    fingerprint: String,
    signing_key: SigningKey<Sha256>,
}

struct SignedRequest {
    date: String,
    authorization: String,
    content_type: Option<String>,
    content_length: Option<String>,
    x_content_sha256: Option<String>,
}

impl OciSigner {
    fn new(cfg: &OciConfig) -> Result<Self, String> {
        let pem = std::fs::read_to_string(&cfg.key_file)
            .map_err(|e| format!("cannot read key file {}: {}", cfg.key_file, e))?;
        // The OCI console appends trailing text (e.g. "OCI_API_KEY") after the
        // END marker; strict PEM parsers reject that. Trim to the END line.
        let pem = pem.trim_start_matches('\u{feff}');
        let pem = match pem.rfind("-----END") {
            Some(idx) => {
                let rest = &pem[idx..];
                let end = idx + rest.find('\n').unwrap_or(rest.len());
                &pem[..end.min(pem.len())]
            }
            None => pem,
        };
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| format!("cannot parse private key {}: {}", cfg.key_file, e))?;
        let signing_key = SigningKey::<Sha256>::new(key);
        Ok(OciSigner {
            tenancy: cfg.tenancy.clone(),
            user: cfg.user.clone(),
            fingerprint: cfg.fingerprint.clone(),
            signing_key,
        })
    }

    fn sign(
        &self,
        method: &str,
        host: &str,
        path_and_query: &str,
        body: Option<&[u8]>,
    ) -> Result<SignedRequest, String> {
        let request_target = format!("{} {}", method.to_lowercase(), path_and_query);
        let date = httpdate::fmt_http_date(SystemTime::now());

        let mut lines = vec![
            format!("date: {}", date),
            format!("(request-target): {}", request_target),
            format!("host: {}", host),
        ];
        let mut headers = vec!["date", "(request-target)", "host"];

        let mut content_type = None;
        let mut content_length = None;
        let mut x_content_sha256 = None;

        if let Some(body) = body {
            let ct = "application/json".to_string();
            let cl = body.len().to_string();
            let xcs = B64.encode(Sha256::digest(body));
            lines.push(format!("content-length: {}", cl));
            lines.push(format!("content-type: {}", ct));
            lines.push(format!("x-content-sha256: {}", xcs));
            headers.push("content-length");
            headers.push("content-type");
            headers.push("x-content-sha256");
            content_type = Some(ct);
            content_length = Some(cl);
            x_content_sha256 = Some(xcs);
        }

        let signing_string = lines.join("\n");
        let sig = self
            .signing_key
            .try_sign(signing_string.as_bytes())
            .map_err(|e| format!("signing failed: {}", e))?;
        let sig_b64 = B64.encode(sig.to_bytes());

        let key_id = format!("{}/{}/{}", self.tenancy, self.user, self.fingerprint);
        let authorization = format!(
            "Signature version=\"1\",headers=\"{}\",keyId=\"{}\",algorithm=\"rsa-sha256\",signature=\"{}\"",
            headers.join(" "),
            key_id,
            sig_b64
        );

        Ok(SignedRequest {
            date,
            authorization,
            content_type,
            content_length,
            x_content_sha256,
        })
    }
}

// ─── HTTP + error classification ──────────────────────────────────────────

enum ApiError {
    Http { status: u16, message: String },
    Transport(String),
    Other(String),
}

impl ApiError {
    fn status(&self) -> u16 {
        match self {
            ApiError::Http { status, .. } => *status,
            _ => 0,
        }
    }
    fn message(&self) -> String {
        match self {
            ApiError::Http { message, .. } => message.clone(),
            ApiError::Transport(m) => m.clone(),
            ApiError::Other(m) => m.clone(),
        }
    }
    fn is_rate_limited(&self) -> bool {
        self.status() == 429
    }
    fn is_retryable(&self) -> bool {
        let status = self.status();
        let msg = self.message().to_lowercase();
        if status == 500 && msg.contains("out of host capacity") {
            return true;
        }
        if status == 429 {
            return true;
        }
        if matches!(status, 502 | 503 | 504) {
            return true;
        }
        if status == 500 && (msg.contains("internal") || msg.contains("timeout") || msg.contains("temporary")) {
            return true;
        }
        matches!(self, ApiError::Transport(_))
    }
    fn is_non_retryable(&self) -> bool {
        let status = self.status();
        let msg = self.message().to_lowercase();
        if matches!(status, 400 | 401 | 403 | 404 | 409) {
            if msg.contains("out of host capacity") {
                return false;
            }
            return true;
        }
        msg.contains("limitexceeded") && !msg.contains("out of host capacity")
    }
}

/// Global HTTP agent with `http_status_as_error(false)` so 4xx/5xx responses
/// return a body we can read (needed to extract OCI error messages).
fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::config::Config::builder()
            .http_status_as_error(false)
            .build()
            .new_agent()
    })
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn extract_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| body.to_string())
}

fn make_request(
    signer: &OciSigner,
    method: &str,
    host: &str,
    path: &str,
    query: &[(&str, &str)],
    body: Option<serde_json::Value>,
    extra_headers: &[(&str, &str)],
) -> Result<serde_json::Value, ApiError> {
    let mut qs = String::new();
    for (i, (k, v)) in query.iter().enumerate() {
        if i > 0 {
            qs.push('&');
        }
        qs.push_str(&pct_encode(k));
        qs.push('=');
        qs.push_str(&pct_encode(v));
    }
    let path_and_query = if qs.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, qs)
    };
    let url = format!("https://{}{}", host, path_and_query);

    let body_bytes = body.as_ref().map(|v| serde_json::to_vec(v).unwrap());
    let signed = signer
        .sign(method, host, &path_and_query, body_bytes.as_deref())
        .map_err(ApiError::Other)?;

    let a = agent();
    let response = match body_bytes {
        Some(bytes) => {
            let req = match method {
                "POST" => a.post(&url),
                "PUT" => a.put(&url),
                _ => return Err(ApiError::Other(format!("{} with body not supported", method))),
            };
            let mut req = req
                .header("date", signed.date.as_str())
                .header("authorization", signed.authorization.as_str())
                .header("user-agent", UA)
                .header("content-type", signed.content_type.as_deref().unwrap_or("application/json"))
                .header("content-length", signed.content_length.as_deref().unwrap_or("0"))
                .header("x-content-sha256", signed.x_content_sha256.as_deref().unwrap_or(""));
            for (k, v) in extra_headers {
                req = req.header(*k, *v);
            }
            req.send(bytes)
        }
        None => {
            let req = match method {
                "GET" => a.get(&url),
                "DELETE" => a.delete(&url),
                _ => return Err(ApiError::Other(format!("{} without body not supported", method))),
            };
            let mut req = req
                .header("date", signed.date.as_str())
                .header("authorization", signed.authorization.as_str())
                .header("user-agent", UA);
            for (k, v) in extra_headers {
                req = req.header(*k, *v);
            }
            req.call()
        }
    };

    let resp = response.map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    let mut resp_body = resp.into_body();
    let text = resp_body
        .read_to_string()
        .map_err(|e| ApiError::Transport(e.to_string()))?;

    if (200..300).contains(&status) {
        serde_json::from_str(&text).map_err(|e| ApiError::Other(format!("invalid JSON from OCI: {}", e)))
    } else {
        let message = extract_message(&text);
        Err(ApiError::Http { status, message })
    }
}

fn get_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

// ─── SSH key ───────────────────────────────────────────────────────────────

fn ensure_ssh_key(key_file: &Path) -> Result<String, String> {
    let pub_file = PathBuf::from(format!("{}.pub", key_file.display()));
    if pub_file.exists() {
        return std::fs::read_to_string(&pub_file)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("cannot read {}: {}", pub_file.display(), e));
    }
    if key_file.exists() {
        if let Ok(out) = std::process::Command::new("ssh-keygen")
            .args(["-y", "-f", key_file.to_str().unwrap_or_default()])
            .output()
        {
            if out.status.success() && !out.stdout.is_empty() {
                let pub_key = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let _ = std::fs::write(&pub_file, format!("{}\n", pub_key));
                return Ok(pub_key);
            }
        }
    }

    log(&format!("No SSH key found at {}, generating...", key_file.display()));
    if let Some(parent) = key_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let run_gen = |t: &str, bits: Option<&str>| {
        let mut cmd = std::process::Command::new("ssh-keygen");
        cmd.arg("-t").arg(t);
        if let Some(b) = bits {
            cmd.arg("-b").arg(b);
        }
        cmd.arg("-f")
            .arg(key_file.to_str().unwrap_or_default())
            .arg("-N")
            .arg("")
            .arg("-q");
        cmd.status().map(|s| s.success()).unwrap_or(false)
    };
    if !run_gen("rsa", Some("4096")) && !run_gen("ed25519", None) {
        return Err(format!(
            "Cannot generate SSH key. Run: ssh-keygen -t rsa -b 4096 -f {}",
            key_file.display()
        ));
    }
    std::fs::read_to_string(&pub_file)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("cannot read {}: {}", pub_file.display(), e))
}

// ─── Notifications ─────────────────────────────────────────────────────────

fn notify(message: &str, success: bool, webhook: &str) {
    if webhook.is_empty() {
        return;
    }
    let color = if success { 0x28a745 } else { 0xdc3545 };
    let payload = serde_json::json!({
        "embeds": [{
            "title": format!("OCI Free Tier ARM — {}", if success { "SUCCESS" } else { "UPDATE" }),
            "description": message.chars().take(2048).collect::<String>(),
            "color": color,
        }]
    });
    let body = serde_json::to_vec(&payload).unwrap();
    match ureq::post(webhook)
        .header("content-type", "application/json")
        .send(body)
    {
        Ok(_) => {}
        Err(e) => warn(&format!("Discord notification failed: {}", e)),
    }
}

// ─── Resource helpers ──────────────────────────────────────────────────────

fn list_availability_domains(
    signer: &OciSigner,
    identity_host: &str,
    compartment: &str,
) -> Result<Vec<String>, ApiError> {
    let v = make_request(
        signer,
        "GET",
        identity_host,
        &format!("/{}/availabilityDomains", API_VERSION),
        &[("compartmentId", compartment)],
        None,
        &[],
    )?;
    let names: Vec<String> = v
        .as_array()
        .map(|arr| arr.iter().filter_map(|a| get_str(a, "name")).collect())
        .unwrap_or_default();
    if names.is_empty() {
        return Err(ApiError::Other("No availability domains found in compartment.".into()));
    }
    Ok(names)
}

fn find_existing_network(
    signer: &OciSigner,
    iaas_host: &str,
    compartment: &str,
) -> Result<Option<serde_json::Value>, ApiError> {
    let vcns = make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/vcns", API_VERSION),
        &[("compartmentId", compartment)],
        None,
        &[],
    )?;
    if let Some(arr) = vcns.as_array() {
        for vcn in arr {
            if get_str(vcn, "lifecycleState").as_deref() == Some("AVAILABLE") {
                let vcn_id = get_str(vcn, "id").unwrap_or_default();
                let subnets = make_request(
                    signer,
                    "GET",
                    iaas_host,
                    &format!("/{}/subnets", API_VERSION),
                    &[("compartmentId", compartment), ("vcnId", &vcn_id)],
                    None,
                    &[],
                )?;
                if let Some(subs) = subnets.as_array() {
                    for subnet in subs {
                        let prohibit = subnet
                            .get("prohibitPublicIpOnVnic")
                            .and_then(|x| x.as_bool())
                            .unwrap_or(true);
                        if get_str(subnet, "lifecycleState").as_deref() == Some("AVAILABLE")
                            && !prohibit
                        {
                            log(&format!(
                                "Using existing VCN: {} ({})",
                                get_str(vcn, "displayName").unwrap_or_default(),
                                vcn_id
                            ));
                            log(&format!(
                                "Using existing public subnet: {} ({})",
                                get_str(subnet, "displayName").unwrap_or_default(),
                                get_str(subnet, "id").unwrap_or_default()
                            ));
                            return Ok(Some(subnet.clone()));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

fn wait_available(
    signer: &OciSigner,
    iaas_host: &str,
    get_path: &str,
    what: &str,
) -> Result<serde_json::Value, ApiError> {
    for _ in 0..120 {
        let v = make_request(signer, "GET", iaas_host, get_path, &[], None, &[])?;
        match get_str(&v, "lifecycleState").as_deref() {
            Some("AVAILABLE") => return Ok(v),
            Some("TERMINATED") | Some("FAILED") => {
                return Err(ApiError::Other(format!("{} reached failed state", what)))
            }
            _ => sleep(Duration::from_secs(5)),
        }
    }
    Err(ApiError::Other(format!("timed out waiting for {} to be AVAILABLE", what)))
}

fn create_network(
    signer: &OciSigner,
    iaas_host: &str,
    compartment: &str,
    vcn_cidr: &str,
    subnet_cidr: &str,
) -> Result<serde_json::Value, ApiError> {
    let vcn_name = "free-arm-vcn";

    let existing = make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/vcns", API_VERSION),
        &[("compartmentId", compartment), ("displayName", vcn_name)],
        None,
        &[],
    )?;
    let mut vcn_id = String::new();
    if let Some(arr) = existing.as_array() {
        for vcn in arr {
            if get_str(vcn, "lifecycleState").as_deref() == Some("AVAILABLE") {
                vcn_id = get_str(vcn, "id").unwrap_or_default();
                log(&format!("VCN '{}' already exists ({}), using it", vcn_name, vcn_id));
                break;
            }
        }
    }
    if vcn_id.is_empty() {
        log(&format!("Creating VCN '{}' with CIDR {}...", vcn_name, vcn_cidr));
        let vcn = make_request(
            signer,
            "POST",
            iaas_host,
            &format!("/{}/vcns", API_VERSION),
            &[],
            Some(serde_json::json!({
                "compartmentId": compartment,
                "cidrBlock": vcn_cidr,
                "displayName": vcn_name,
            })),
            &[],
        )?;
        vcn_id = get_str(&vcn, "id").unwrap_or_default();
        let vcn = wait_available(
            signer,
            iaas_host,
            &format!("/{}/vcns/{}", API_VERSION, vcn_id),
            "VCN",
        )?;
        let default_route_table = get_str(&vcn, "defaultRouteTableId").unwrap_or_default();
        log(&format!("VCN created: {}", vcn_id));

        let igw_name = "free-arm-igw";
        log(&format!("Creating Internet Gateway '{}'...", igw_name));
        let igw = make_request(
            signer,
            "POST",
            iaas_host,
            &format!("/{}/internetGateways", API_VERSION),
            &[],
            Some(serde_json::json!({
                "compartmentId": compartment,
                "displayName": igw_name,
                "isEnabled": true,
                "vcnId": vcn_id,
            })),
            &[],
        )?;
        let igw_id = get_str(&igw, "id").unwrap_or_default();
        wait_available(
            signer,
            iaas_host,
            &format!("/{}/internetGateways/{}", API_VERSION, igw_id),
            "IGW",
        )?;
        log(&format!("Internet Gateway created: {}", igw_id));

        log("Adding route rule (0.0.0.0/0 → IGW) to default route table...");
        let route_table = make_request(
            signer,
            "GET",
            iaas_host,
            &format!("/{}/routeTables/{}", API_VERSION, default_route_table),
            &[],
            None,
            &[],
        )?;
        let mut rules: Vec<serde_json::Value> = route_table
            .get("routeRules")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        rules.push(serde_json::json!({
            "destination": "0.0.0.0/0",
            "destinationType": "CIDR_BLOCK",
            "networkEntityId": igw_id,
        }));
        make_request(
            signer,
            "PUT",
            iaas_host,
            &format!("/{}/routeTables/{}", API_VERSION, default_route_table),
            &[],
            Some(serde_json::json!({ "routeRules": rules })),
            &[],
        )?;
        log("Route table updated.");
    }

    let subnet_name = "free-arm-subnet";
    let existing_subs = make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/subnets", API_VERSION),
        &[("compartmentId", compartment), ("vcnId", &vcn_id)],
        None,
        &[],
    )?;
    if let Some(arr) = existing_subs.as_array() {
        for subnet in arr {
            let prohibit = subnet
                .get("prohibitPublicIpOnVnic")
                .and_then(|x| x.as_bool())
                .unwrap_or(true);
            if get_str(subnet, "lifecycleState").as_deref() == Some("AVAILABLE") && !prohibit {
                log(&format!(
                    "Using existing subnet '{}' ({})",
                    get_str(subnet, "displayName").unwrap_or_default(),
                    get_str(subnet, "id").unwrap_or_default()
                ));
                return Ok(subnet.clone());
            }
        }
    }

    log(&format!("Creating public subnet '{}' with CIDR {}...", subnet_name, subnet_cidr));
    let subnet = make_request(
        signer,
        "POST",
        iaas_host,
        &format!("/{}/subnets", API_VERSION),
        &[],
        Some(serde_json::json!({
            "compartmentId": compartment,
            "cidrBlock": subnet_cidr,
            "displayName": subnet_name,
            "vcnId": vcn_id,
            "prohibitPublicIpOnVnic": false,
        })),
        &[],
    )?;
    let subnet_id = get_str(&subnet, "id").unwrap_or_default();
    let subnet = wait_available(
        signer,
        iaas_host,
        &format!("/{}/subnets/{}", API_VERSION, subnet_id),
        "subnet",
    )?;
    log(&format!("Subnet created: {}", get_str(&subnet, "id").unwrap_or_default()));
    Ok(subnet)
}

fn get_latest_image(
    signer: &OciSigner,
    iaas_host: &str,
    compartment: &str,
    os_name: &str,
    os_version: &str,
) -> Result<serde_json::Value, ApiError> {
    log(&format!("Discovering latest {} {} ARM image...", os_name, os_version));
    let mut query = vec![
        ("compartmentId", compartment),
        ("operatingSystem", os_name),
        ("operatingSystemVersion", os_version),
        ("shape", SHAPE),
        ("sortBy", "TIMECREATED"),
        ("sortOrder", "DESC"),
    ];
    let v = make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/images", API_VERSION),
        &query,
        None,
        &[],
    )?;
    let mut arr = v.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        warn(&format!("No {} {} image found, trying any {} version...", os_name, os_version, os_name));
        query = vec![
            ("compartmentId", compartment),
            ("operatingSystem", os_name),
            ("shape", SHAPE),
            ("sortBy", "TIMECREATED"),
            ("sortOrder", "DESC"),
        ];
        let v = make_request(
            signer,
            "GET",
            iaas_host,
            &format!("/{}/images", API_VERSION),
            &query,
            None,
            &[],
        )?;
        arr = v.as_array().cloned().unwrap_or_default();
    }

    let image = arr.into_iter().next().ok_or_else(|| {
        ApiError::Other(format!(
            "No {} images found for shape {}. Try setting OS_NAME / OS_VERSION.",
            os_name, SHAPE
        ))
    })?;
    log(&format!("Found image: {}", get_str(&image, "displayName").unwrap_or_default()));
    log(&format!("  OCID: {}", get_str(&image, "id").unwrap_or_default()));
    log(&format!(
        "  OS: {} {}",
        get_str(&image, "operatingSystem").unwrap_or_default(),
        get_str(&image, "operatingSystemVersion").unwrap_or_default()
    ));
    Ok(image)
}

fn check_existing_instance(
    signer: &OciSigner,
    iaas_host: &str,
    compartment: &str,
    display_name: &str,
) -> Result<Option<serde_json::Value>, ApiError> {
    let v = make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/instances", API_VERSION),
        &[("compartmentId", compartment), ("displayName", display_name)],
        None,
        &[],
    )?;
    if let Some(arr) = v.as_array() {
        for inst in arr {
            if let Some(state) = get_str(inst, "lifecycleState") {
                if matches!(state.as_str(), "PROVISIONING" | "RUNNING" | "STARTING") {
                    return Ok(Some(inst.clone()));
                }
            }
        }
    }
    Ok(None)
}

fn launch_instance(
    signer: &OciSigner,
    iaas_host: &str,
    compartment: &str,
    ad: &str,
    image_id: &str,
    subnet_id: &str,
    ssh_pub_key: &str,
    display_name: &str,
    ocpus: f64,
    memory_gb: f64,
    boot_volume_gb: i64,
    assign_public_ip: bool,
) -> Result<serde_json::Value, ApiError> {
    let retry_token = format!(
        "{:x}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    );
    let body = serde_json::json!({
        "displayName": display_name,
        "compartmentId": compartment,
        "availabilityDomain": ad,
        "shape": SHAPE,
        "shapeConfig": {
            "ocpus": ocpus,
            "memoryInGBs": memory_gb,
        },
        "sourceDetails": {
            "sourceType": "image",
            "imageId": image_id,
            "bootVolumeSizeInGBs": boot_volume_gb,
        },
        "createVnicDetails": {
            "subnetId": subnet_id,
            "assignPublicIp": assign_public_ip,
        },
        "metadata": {
            "ssh_authorized_keys": ssh_pub_key,
        },
    });

    make_request(
        signer,
        "POST",
        iaas_host,
        &format!("/{}/instances", API_VERSION),
        &[],
        Some(body),
        &[("opc-retry-token", &retry_token)],
    )
}

fn get_instance(
    signer: &OciSigner,
    iaas_host: &str,
    instance_id: &str,
) -> Result<serde_json::Value, ApiError> {
    make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/instances/{}", API_VERSION, instance_id),
        &[],
        None,
        &[],
    )
}

fn wait_for_running(
    signer: &OciSigner,
    iaas_host: &str,
    instance_id: &str,
) -> Result<serde_json::Value, ApiError> {
    log(&format!("Waiting for instance {} to reach RUNNING state...", instance_id));
    loop {
        let inst = get_instance(signer, iaas_host, instance_id)?;
        let state = get_str(&inst, "lifecycleState").unwrap_or_default();
        log(&format!("  Instance state: {}", state));
        match state.as_str() {
            "RUNNING" => return Ok(inst),
            "TERMINATED" => {
                error("Instance was terminated during provisioning!");
                return Err(ApiError::Other("terminated during provisioning".into()));
            }
            "FAULTED" | "FAILED" => {
                error("Instance provisioning FAILED.");
                return Err(ApiError::Other("provisioning FAILED".into()));
            }
            _ => sleep(Duration::from_secs(10)),
        }
    }
}

fn get_instance_ip(
    signer: &OciSigner,
    iaas_host: &str,
    compartment: &str,
    instance_id: &str,
) -> (Option<String>, Option<String>) {
    match make_request(
        signer,
        "GET",
        iaas_host,
        &format!("/{}/vnicAttachments", API_VERSION),
        &[("compartmentId", compartment), ("instanceId", instance_id)],
        None,
        &[],
    ) {
        Ok(v) => {
            if let Some(arr) = v.as_array() {
                for att in arr {
                    if get_str(att, "lifecycleState").as_deref() == Some("ATTACHED") {
                        if let Some(vnic_id) = get_str(att, "vnicId") {
                            if let Ok(vnic) = make_request(
                                signer,
                                "GET",
                                iaas_host,
                                &format!("/{}/vnics/{}", API_VERSION, vnic_id),
                                &[],
                                None,
                                &[],
                            ) {
                                return (get_str(&vnic, "publicIp"), get_str(&vnic, "privateIp"));
                            }
                        }
                    }
                }
            }
        }
        Err(e) => warn(&format!("Could not retrieve instance IP: {}", e.message())),
    }
    (None, None)
}

// ─── Main ──────────────────────────────────────────────────────────────────

fn main() {
    let ocpus = env_f64("OCPUS", 1.0).min(MAX_OCPUS);
    let memory_gb = env_f64("MEMORY_GB", 12.0).min(MAX_MEMORY_GB);
    let display_name = env_str("DISPLAY_NAME", "free-arm");
    let ssh_key_file = expand_home(&env_str("SSH_KEY_FILE", "~/.ssh/id_rsa"));
    let boot_volume_gb = env_i64("BOOT_VOLUME_SIZE_GB", 50).max(50);
    let os_name = env_str("OS_NAME", "Canonical Ubuntu");
    let os_version = env_str("OS_VERSION", "22.04");
    let assign_public_ip = env_bool("ASSIGN_PUBLIC_IP", true);
    let initial_backoff = env_i64("INITIAL_BACKOFF", 30);
    let max_backoff = env_i64("MAX_BACKOFF", 300);
    let max_retries = env_i64("MAX_RETRIES", 0);
    let discord_webhook = env_str("DISCORD_WEBHOOK_URL", "");
    let dry_run = env_bool("DRY_RUN", false);
    let vcn_cidr = env_str("VCN_CIDR", "10.0.0.0/16");
    let subnet_cidr = env_str("SUBNET_CIDR", "10.0.0.0/24");

    log("============================================================");
    log("OCI Free Tier ARM Instance Auto-Provisioner");
    log("============================================================");
    log(&format!("Shape:        {}", SHAPE));
    log(&format!("OCPUs:        {} (max {})", ocpus, MAX_OCPUS));
    log(&format!("Memory:       {} GB (max {})", memory_gb, MAX_MEMORY_GB));
    log(&format!("Display name: {}", display_name));
    log(&format!("OS:           {} {}", os_name, os_version));
    log(&format!("Boot volume:  {} GB", boot_volume_gb));
    log(&format!("Public IP:    {}", assign_public_ip));
    log(&format!("Dry run:      {}", dry_run));
    log("============================================================");

    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            error(&e);
            exit(1);
        }
    };
    let compartment = env_str("COMPARTMENT_ID", "").trim().to_string();
    let compartment = if compartment.is_empty() {
        config.tenancy.clone()
    } else {
        compartment
    };
    log(&format!("Compartment:  {}", compartment));

    let signer = match OciSigner::new(&config) {
        Ok(s) => s,
        Err(e) => {
            error(&e);
            exit(1);
        }
    };

    let identity_host = format!("identity.{}.oraclecloud.com", config.region);
    let iaas_host = format!("iaas.{}.oraclecloud.com", config.region);

    let ssh_pub_key = match ensure_ssh_key(Path::new(&ssh_key_file)) {
        Ok(k) => k,
        Err(e) => {
            error(&e);
            exit(1);
        }
    };
    log(&format!("SSH key:      {}.pub", ssh_key_file));

    log("");
    log("--- Discovering resources ---");
    let ads = match list_availability_domains(&signer, &identity_host, &compartment) {
        Ok(a) => a,
        Err(e) => {
            error(&format!("Failed to list availability domains: {}", e.message()));
            exit(1);
        }
    };
    log(&format!("Found {} availability domain(s):", ads.len()));
    for ad in &ads {
        log(&format!("  - {}", ad));
    }

    let subnet = match find_existing_network(&signer, &iaas_host, &compartment) {
        Ok(Some(s)) => s,
        Ok(None) => {
            log("No existing public subnet found. Creating VCN, subnet, and internet gateway...");
            match create_network(&signer, &iaas_host, &compartment, &vcn_cidr, &subnet_cidr) {
                Ok(s) => s,
                Err(e) => {
                    error(&format!("Failed to create network: {}", e.message()));
                    exit(1);
                }
            }
        }
        Err(e) => {
            error(&format!("Failed to discover network: {}", e.message()));
            exit(1);
        }
    };
    let subnet_id = get_str(&subnet, "id").unwrap_or_default();

    let image = match get_latest_image(&signer, &iaas_host, &compartment, &os_name, &os_version) {
        Ok(i) => i,
        Err(e) => {
            error(&format!("Failed to discover image: {}", e.message()));
            exit(1);
        }
    };
    let image_id = get_str(&image, "id").unwrap_or_default();

    if let Ok(Some(existing)) = check_existing_instance(&signer, &iaas_host, &compartment, &display_name)
    {
        let existing_id = get_str(&existing, "id").unwrap_or_default();
        let state = get_str(&existing, "lifecycleState").unwrap_or_default();
        log(&format!("Instance '{}' already exists: {}", display_name, existing_id));
        log(&format!("  State: {}", state));
        let (pub_ip, priv_ip) = get_instance_ip(&signer, &iaas_host, &compartment, &existing_id);
        if let Some(ip) = &pub_ip {
            log(&format!("  Public IP:  {}", ip));
        }
        if let Some(ip) = &priv_ip {
            log(&format!("  Private IP: {}", ip));
        }
        notify(
            &format!(
                "Instance '{}' already exists (state: {}). IP: {}",
                display_name,
                state,
                pub_ip.unwrap_or_else(|| "N/A".into())
            ),
            true,
            &discord_webhook,
        );
        return;
    }

    if dry_run {
        log("");
        log("DRY RUN — would launch with:");
        log(&format!("  AD:          {}", ads.first().map(|s| s.as_str()).unwrap_or("")));
        log(&format!("  Subnet:      {}", subnet_id));
        log(&format!(
            "  Image:       {} ({})",
            image_id,
            get_str(&image, "displayName").unwrap_or_default()
        ));
        log(&format!("  Shape:       {} ({} OCPU, {} GB)", SHAPE, ocpus, memory_gb));
        log(&format!("  SSH key:     {}...", &ssh_pub_key[..ssh_pub_key.len().min(40)]));
        return;
    }

    log("");
    log("--- Starting launch retry loop ---");
    let mut backoff = initial_backoff;
    let mut attempt: u64 = 0;

    loop {
        attempt += 1;
        if max_retries > 0 && attempt as i64 > max_retries {
            error(&format!("Reached max retries ({}). Giving up.", max_retries));
            exit(1);
        }

        let ad = &ads[((attempt - 1) as usize) % ads.len()];
        log(&format!("Attempt {} — AD: {}, backoff: {}s", attempt, ad, backoff));

        match launch_instance(
            &signer,
            &iaas_host,
            &compartment,
            ad,
            &image_id,
            &subnet_id,
            &ssh_pub_key,
            &display_name,
            ocpus,
            memory_gb,
            boot_volume_gb,
            assign_public_ip,
        ) {
            Ok(instance) => {
                let instance_id = get_str(&instance, "id").unwrap_or_default();
                log(&format!("SUCCESS! Instance launched: {}", instance_id));
                log(&format!("  State: {}", get_str(&instance, "lifecycleState").unwrap_or_default()));

                match wait_for_running(&signer, &iaas_host, &instance_id) {
                    Ok(_running) => {
                        let (pub_ip, priv_ip) =
                            get_instance_ip(&signer, &iaas_host, &compartment, &instance_id);
                        let mut msg = format!("Instance '{}' is RUNNING!\n", display_name);
                        msg.push_str(&format!("  Instance ID: {}\n", instance_id));
                        if let Some(ip) = &pub_ip {
                            msg.push_str(&format!("  Public IP: {}\n", ip));
                            msg.push_str(&format!("  SSH: ssh ubuntu@{}\n", ip));
                        }
                        if let Some(ip) = &priv_ip {
                            msg.push_str(&format!("  Private IP: {}\n", ip));
                        }
                        log(&msg);
                        notify(&msg, true, &discord_webhook);
                        return;
                    }
                    Err(e) => {
                        error("Instance did not reach RUNNING state.");
                        notify(
                            &format!("Instance launched but failed to reach RUNNING state: {}", e.message()),
                            false,
                            &discord_webhook,
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                if e.is_non_retryable() {
                    error(&format!("Non-retryable error (HTTP {}): {}", e.status(), e.message()));
                    error("Fix the configuration and try again.");
                    notify(
                        &format!("Non-retryable error: {}", e.message()),
                        false,
                        &discord_webhook,
                    );
                    exit(1);
                }
                if e.is_retryable() {
                    if e.is_rate_limited() {
                        let next = backoff.saturating_mul(2).min(max_backoff);
                        warn(&format!("Rate limited (429). Backing off to {}s", next));
                        backoff = next;
                    } else {
                        warn(&format!("Retryable error (HTTP {}): {}", e.status(), e.message()));
                    }
                    log(&format!("Sleeping {}s before next attempt...", backoff));
                    sleep(Duration::from_secs(backoff as u64));
                    let jitter = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() % 11) as i64;
                    backoff = ((backoff as f64 * 1.5) as i64).saturating_add(jitter).min(max_backoff);
                    if backoff < initial_backoff {
                        backoff = initial_backoff;
                    }
                    continue;
                }
                error(&format!("Unexpected service error (HTTP {}): {}", e.status(), e.message()));
                notify(
                    &format!("Unexpected error: {}", e.message()),
                    false,
                    &discord_webhook,
                );
                exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_encode_encodes_space_as_20_and_keeps_unreserved() {
        assert_eq!(pct_encode("Canonical Ubuntu"), "Canonical%20Ubuntu");
        assert_eq!(pct_encode("22.04"), "22.04");
        assert_eq!(pct_encode("a_b-c.d~e"), "a_b-c.d~e");
        assert_eq!(pct_encode("dWCX:AP-KULAI-2-AD-1"), "dWCX%3AAP-KULAI-2-AD-1");
    }

    #[test]
    fn extract_message_reads_oci_error_body() {
        assert_eq!(
            extract_message(r#"{"code":"LimitExceeded","message":"Out of host capacity"}"#),
            "Out of host capacity"
        );
        assert_eq!(extract_message("not json"), "not json");
    }

    #[test]
    fn retryable_classification() {
        let cap = ApiError::Http { status: 500, message: "Out of host capacity".into() };
        assert!(cap.is_retryable());
        assert!(!cap.is_non_retryable());

        let rl = ApiError::Http { status: 429, message: "Too many requests".into() };
        assert!(rl.is_retryable());
        assert!(rl.is_rate_limited());

        let auth = ApiError::Http { status: 401, message: "NotAuthenticated".into() };
        assert!(auth.is_non_retryable());
        assert!(!auth.is_retryable());
    }
}
