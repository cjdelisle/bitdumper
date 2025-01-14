use hyper::StatusCode;
use reqwest::{dns::{Addrs, Resolving}, redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{sync::Mutex, task::JoinSet};
use trust_dns_resolver::{config::{NameServerConfigGroup, ResolverConfig, ResolverOpts}, TokioAsyncResolver};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use eyre::{bail,Result};
use warp::Filter;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    user: String,
    password: String,
    host: String,
    port: u16,
    ip_check_interval: u64,
    ip_check_workers: u64,
    ip_check_timeout: u64,
    name_check_interval: u64,
    useragent: String,
    domain_suffix: String,
    nameserver_ip: IpAddr,
    db_file: String,
    http_bind: SocketAddr,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    result: Option<Vec<serde_json::Value>>,
    error: Option<serde_json::Value>, // Assuming the error can be of any type or `null`
    id: String,
}

#[derive(Debug, Deserialize)]
struct NameEntry {
    name: String,
    name_encoding: String,
    value: String,
    value_encoding: String,
    txid: String,
    vout: u32,
    address: String,
    height: u32,
    expires_in: i32,
    expired: bool,
    ismine: bool,
}

pub fn is_valid_domain_label(label: &str) -> bool {
    // Check length
    if label.len() < 1 || label.len() > 63 {
        return false;
    }

    // Check if it starts and ends with a lowercase letter or digit
    if !label.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) ||
       !label.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }

    // Check if all characters are valid (lowercase letters, digits, or hyphens)
    if !label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return false;
    }

    // Check for consecutive hyphens (not allowed in DNS labels)
    if label.contains("--") {
        return false;
    }

    true
}

fn is_public_routed_ip(ip: Ipv4Addr) -> bool {
    if ip.is_broadcast() || ip.is_documentation() || ip.is_link_local() ||
        ip.is_loopback() || ip.is_multicast() || ip.is_unspecified()
    {
        return false;
    }
    let ip = ip.octets();
    if ip[0] == 10 {
        return false;
    }
    if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
        return false;
    }
    if ip[0] == 192 && ip[1] == 168 {
        return false;
    }
    true
}

fn webpage_summary(text: &str, headers: &HashMap<String, String>) -> String {
    // If it's html, check for a <title> or a <h1> tag
    if headers.get("content-type").map(|x| x.starts_with("text/html")) == Some(true) {
        let title = text.find("<title>").and_then(|x| text[x+7..].find("</title>").map(|y| &text[x+7..x+7+y]));
        if let Some(title) = title {
            return title.trim().to_string();
        }
        let h1 = text.find("<h1>").and_then(|x| text[x+4..].find("</h1>").map(|y| &text[x+4..x+4+y]));
        if let Some(h1) = h1 {
            return h1.trim().to_string();
        }
    } else if headers.get("content-type").map(|x| x.starts_with("text/")) == Some(true) {
        // If it's text, use the first line
        if let Some(line) = text.lines().next() {
            return line.trim().to_string();
        }
    }

    // Otherwise use the content type and the length
    let mut out = headers.get("content-type").map(|x| x.to_string()).unwrap_or_default();
    if let Some(len) = headers.get("content-length") {
        out.push_str(" (");
        out.push_str(len);
        out.push(')');
    }
    out
}

fn now_sec() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Debug,Default,Serialize,Deserialize)]
struct NameStatus {
    is_ok: bool,
    last_test: u64,
    partial_text: String,
    summary: String,
}

#[derive(Debug,Default,Serialize,Deserialize)]
struct ServerIp {
    is_ok: bool,
    last_test: u64,
    names: HashMap<String, NameStatus>,
}

struct ServerMut {
    map: HashMap<Ipv4Addr,ServerIp>,
    need_test_names: VecDeque<(Ipv4Addr,String)>,
    config: Config,
}
impl ServerMut {
    fn parse_ips(&mut self, name: &str, ip: Option<&Value>, map: Option<&Value>) {
        if let Some(ip) = ip {
            if let Some(ip) = ip.as_str() {
                if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                    self.map.entry(ip).or_default().names.entry(name.into()).or_default();
                }
            }
        }
        if let Some(map) = map.and_then(|m| m.as_object()) {
            for (key, value) in map {
                if let Some(ip) = value.get("ip")
                    .and_then(|ip| ip.as_str())
                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                {
                    if !is_public_routed_ip(ip) {
                        continue;
                    }
                    let v = if key.is_empty() || key == "*" {
                        name.into()
                    } else {
                        format!("{}.{}", key, name)
                    };
                    let e = self.map.entry(ip).or_default();
                    if key == "*" && e.names.contains_key(&v) {
                        // Skip because we're not going to make a domain for * and we already have an entry
                    } else {
                        e.names.entry(v.into()).or_default();
                    }
                }
            }
        }
    }
    fn process_name(&mut self, item: &NameEntry) {
        if item.expired {
            return;
        }
        let Some(name) = item.name.strip_prefix("d/") else {
            return;
        };
        if !is_valid_domain_label(name) {
            return;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&item.value) else {
            return;
        };
        self.parse_ips(name, value.get("ip"), value.get("map"));
    }
    fn ip_check(&mut self, ip: Ipv4Addr, is_ok: bool, now: u64) {
        let e = self.map.entry(ip).or_default();
        e.is_ok = is_ok;
        e.last_test = now;
        if is_ok {
            for (name, x) in &e.names {
                if x.last_test + self.config.name_check_interval < now {
                    self.need_test_names.push_back((ip, name.clone()));
                }
            }
        }
    }
    fn name_check(
        &mut self,
        ip: Ipv4Addr,
        name: String,
        is_ok: bool,
        now: u64,
        content: String,
        headers: &HashMap<String, String>,
    ) {
        if let Some(x) = self.map.get_mut(&ip) {
            if let Some(x) = x.names.get_mut(&name) {
                x.is_ok = is_ok;
                x.last_test = now;
                x.summary = webpage_summary(&content, headers);
                x.partial_text = content;
                println!("Name: {} is {} ({})", name, if is_ok { "UP" } else { "DOWN" }, x.summary);
            }
        }
    }
}

struct Server {
    m: Mutex<ServerMut>,
    config: Config,
    resolver: Arc<MyTokioAsyncResolver>,
}
impl Server {
    async fn sync_db(self: &Arc<Self>) {
        println!("Syncing db");
        let m = self.m.lock().await;
        let db = serde_json::to_string(&m.map).unwrap();
        drop(m);
        match tokio::fs::write(&self.config.db_file, db).await {
            Ok(()) => (),
            Err(e) => {
                println!("Error writing db: {}", e);
            }
        }
    }
    async fn nmc_dump_cycle(self: &Arc<Self>) -> Result<()> {
        let client = Client::new();
        let count = 100000;
        let mut next = String::new();
        println!("First query");
        loop {
            let params = serde_json::json!([&next, count, { "prefix": "d/" }]);
            let response = make_nmc_request(&client, &self.config, &params).await?;

            if response.len() < 2 {
                break;
            }

            let mut m = self.m.lock().await;
            for item in &response {
                m.process_name(item);
            }
            drop(m);

            let last = response.last().unwrap().name.clone();
            if last == next {
                break;
            }
            next = last;
            println!("{} items, next query: {}", response.len(), next);
        }
        Ok(())
    }
    async fn nmc_dump_thread(self: Arc<Self>) {
        loop {
            match self.nmc_dump_cycle().await {
                Ok(()) => (),
                Err(e) => {
                    println!("Error querying namecoin: {}", e);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            }
            self.sync_db().await;
            tokio::time::sleep(Duration::from_secs(1200)).await;
        }
    }
    async fn http_check_name(self: Arc<Self>, ip: Ipv4Addr, name: String) {
        let url = format!("http://{}.bit.{}/", name, self.config.domain_suffix);
        let res = http_get(&url, &self.config, &self.resolver).await;
    
        let (operational, headers, body) = match res {
            Ok(HttpGetRes::Ok(HttpGetOk { status, headers, body })) => {
                (
                    if status.is_success() {
                        true
                    } else if status.is_redirection() {
                        if let Some(location) = headers.get("location") {
                            if location.starts_with("/") && location.contains("404.html") {
                                println!("{url} 404 redirect -> {}", location);
                            } else if location.starts_with("https://") && location.contains(".bit.pkt.") {
                                println!("{url} https redirect -> {}", location);
                            } else {
                                println!("{url} Redirected -> {}", location);
                            }
                        } else {
                            for (k,v) in &headers {
                                println!("{url} - Unexpected redirect: Header: {k} {v}");
                            }
                        }
                        false
                    } else {
                        println!("{url} Unexpected status code {}", status);
                        false
                    },
                    headers,
                    body
                )
            },
            Ok(HttpGetRes::Connect(_)) => {
                println!("{url} Connection error");
                (false, HashMap::new(), String::new())
            },
            Err(e) => {
                println!("{url} Error checking: {}", e);
                (false, HashMap::new(), String::new())
            }
        };
    
        self.m.lock().await.name_check(ip, name, operational, now_sec(), body, &headers);
    }

    async fn http_check_ip(self: Arc<Self>, ip: Ipv4Addr) {
        let url = format!("http://{}/", ip);
        let res = http_get(&url, &self.config, &self.resolver).await;
        let res = match res {
            Ok(HttpGetRes::Ok(..)) => {
                // If the server ... exists ... then we continue on to check the name.
                true
            },
            Ok(HttpGetRes::Connect(_)) => false,
            Err(e) => {
                println!("Error checking {}: {}", ip, e);
                false
            }
        };
        println!("IP: {} is {}", url, if res { "UP" } else { "DOWN" });
        self.m.lock().await.ip_check(ip.clone(), res, now_sec());
    }
    async fn check_ip_cycle(self: &Arc<Self>) -> Result<bool> {
        let now = now_sec();
        let need_test_ips = {
            // lock m and scan over the array of IPs for any that have not
            // been checked in the last ip_check_interval seconds
            // select ip_check_workers ips
            let mut need_test_ips = Vec::new();
            let m = self.m.lock().await;
            for (ip, server) in &m.map {
                if server.last_test + self.config.ip_check_interval < now {
                    need_test_ips.push(*ip);
                }
                if need_test_ips.len() >= self.config.ip_check_workers as usize {
                    break;
                }
            }
            if need_test_ips.is_empty() && m.need_test_names.is_empty() {
                return Ok(false);
            }
            need_test_ips
        };

        // spawn a joinset to check all need_test_ips using http_check_ip()
        {
            let mut joinset = JoinSet::new();
            for ip in need_test_ips {
                let server = Arc::clone(self);
                joinset.spawn(server.http_check_ip(ip));
            }
            joinset.join_all().await;
        }

        // Get the next ip_check_workers names from need_test_names
        // each name should come from a different IP, otherwise we use less workers.
        let check_names = {
            let mut m = self.m.lock().await;
            println!("need_test_names = {}", m.need_test_names.len());
            let mut check_names = Vec::new();
            let mut discards = VecDeque::new();
            let mut ips = HashSet::new();
            loop {
                if check_names.len() >= self.config.ip_check_workers as usize {
                    break;
                }
                if let Some((ip, name)) = m.need_test_names.pop_front() {
                    if !ips.contains(&ip) {
                        ips.insert(ip.clone());
                        check_names.push((ip, name));
                    } else {
                        discards.push_back((ip, name));
                    }
                } else {
                    break;
                }
            }
            m.need_test_names.append(&mut discards);
            check_names
        };
        println!("check_names = {}", check_names.len());

        // spawn another joinset to take up to ip_check_workers names from need_test_names
        // each name should come from a different IP, otherwise we use less workers.
        {
            let mut joinset = JoinSet::new();
            for (ip, name) in check_names {
                let server = Arc::clone(self);
                joinset.spawn(server.http_check_name(ip, name));
            }
            joinset.join_all().await;
        }

        Ok(true)
    }
    async fn check_ip_thread(self: Arc<Self>) {
        loop {
            match self.check_ip_cycle().await {
                Ok(more) => {
                    if more {
                        self.sync_db().await;
                        continue;
                    }
                },
                Err(e) => {
                    println!("Error checking IP: {}", e);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiName {
    name: String,
    last_checked: u64,
    summary: String,
}

async fn api_names(
    srv: Arc<Server>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let api_names = {
        let m = srv.m.lock().await;
        let mut out = Vec::new();
        for (_, server) in &m.map {
            if !server.is_ok {
                continue;
            }
            for (name, x) in &server.names {
                if !x.is_ok {
                    continue;
                }
                out.push(ApiName {
                    name: name.clone(),
                    last_checked: x.last_test,
                    summary: x.summary.clone(),
                });
            }
        }
        out
    };
    Ok(Box::new(
        warp::http::response::Builder::new()
            .header("Content-Type", "application/json")
            .body(serde_json::to_string_pretty(&api_names).unwrap()),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config_yaml = std::fs::read_to_string("config.yaml")?;
    let config: Config = serde_yaml::from_str(&config_yaml)?;

    // load db file if it exists
    if tokio::fs::metadata(&config.db_file).await.is_err() {
        tokio::fs::write(&config.db_file, "{}").await?;
    }
    let db = tokio::fs::read_to_string(&config.db_file).await?;
    let db = serde_json::from_str::<HashMap<Ipv4Addr,ServerIp>>(&db)?;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(
            &[config.nameserver_ip],
            53,
            true,
        ),
    ), ResolverOpts::default())?;
    let resolver = Arc::new(MyTokioAsyncResolver(Arc::new(resolver)));

    let server = Arc::new(Server {
        m: Mutex::new(ServerMut {
            map: db,
            need_test_names: VecDeque::new(),
            config: config.clone(),
        }),
        config,
        resolver,
    });
    tokio::task::spawn(Arc::clone(&server).nmc_dump_thread());
    tokio::task::spawn(Arc::clone(&server).check_ip_thread());

    let api = {
        let server = Arc::clone(&server);
        warp::path!("api" / "v1" / "names")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&server)))
            .and_then(api_names)
    };

    warp::serve(api).bind(server.config.http_bind).await;
    Ok(())
}

struct MyTokioAsyncResolver(Arc<TokioAsyncResolver>);

type BoxError = Box<dyn Error + Send + Sync>;
async fn resolve(name: hyper::client::connect::dns::Name, r: Arc<TokioAsyncResolver>) -> Result<Addrs, BoxError> {
    let res = match r.lookup_ip(name.as_str()).await {
        Ok(r) => r,
        Err(e) => {
            return Err(e.into());
        }
    };
    Ok(Box::new(res.into_iter().map(|ip|SocketAddr::new(ip, 0))))
}

impl reqwest::dns::Resolve for MyTokioAsyncResolver {
    fn resolve(&self, name: hyper::client::connect::dns::Name) -> Resolving {
        Box::pin(resolve(name, Arc::clone(&self.0)))
    }
}

struct HttpGetOk {
    status: StatusCode,
    headers: HashMap<String,String>,
    body: String,
}
enum HttpGetRes {
    Connect(reqwest::Error),
    Ok(HttpGetOk),
}
async fn http_get(url: &str, cfg: &Config, resolver: &Arc<MyTokioAsyncResolver>) -> Result<HttpGetRes> {
    let client = Client::builder()
        .redirect(Policy::none())
        .dns_resolver(Arc::clone(resolver))
        .build()?;
    let response = client
        .get(url)
        .header("User-Agent", &cfg.useragent)
        .timeout(Duration::from_secs(cfg.ip_check_timeout))
        .send()
        .await;
    match response {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers()
                .iter()
                .map(|(k,v)| (k.as_str().into(), v.to_str().unwrap().into()))
                .collect();
            let body = response.text().await?;
            Ok(HttpGetRes::Ok(HttpGetOk { status, headers, body }))
        },
        Err(e) => {
            if e.is_timeout() || e.is_connect() {
                Ok(HttpGetRes::Connect(e))
            } else if let Some(status) = e.status() {
                Ok(HttpGetRes::Ok(HttpGetOk {
                    status: status,
                    headers: HashMap::new(),
                    body: e.to_string(),
                }))
            } else {
                Err(e.into())
            }
        }
    }
}

async fn make_nmc_request(client: &Client, config: &Config, params: &Value) -> Result<Vec<NameEntry>> {
    let url = format!("http://{}:{}/", config.host, config.port);
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "bitdumper",
        "method": "name_scan",
        "params": params
    });

    let response = client
        .post(&url)
        .basic_auth(&config.user, Some(&config.password))
        .json(&body)
        .send()
        .await?
        .json::<ApiResponse>()
        .await?;

    if let Some(err) = response.error {
        bail!("Error: {:?}", err);
    }

    let mut out = Vec::new();
    if let Some(res) = response.result {
        for item in res {
            if item.get("name").is_none() || item.get("value").is_none() {
                continue;
            }
            match serde_json::from_value(item.clone()) {
                Ok(entry) => out.push(entry),
                Err(e) => bail!("Error parsing {}: {}", serde_json::to_string_pretty(&item)?, e),
            }
        }
    } else {
        bail!("No result in response: {:?}", response);
    }

    Ok(out)
}
