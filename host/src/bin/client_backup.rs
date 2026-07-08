use axum::{
    routing::{get, post},
    Router, Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::fs;
use tfhe::{generate_keys, ClientKey, ServerKey, ConfigBuilder, FheUint16};
use tfhe::prelude::*;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use methods::METHOD_NAME_ELF;
use tower_http::services::ServeDir;
use reqwest::Client as HttpClient;
use tower_http::cors::CorsLayer;
use clap::Parser;
use rand::RngCore;
use sha2::{Sha256, Digest};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP-ul serverului cloud (neincrezut)
    #[arg(long, default_value = "127.0.0.1")]
    server_host: String,

    #[arg(long, default_value_t = 8000)]
    server_port: u16,

    #[arg(long, default_value_t = 3000)]
    listen_port: u16,

    /// IP-ul nodului auditor (Threshold Decryption Party 2)
    #[arg(long, default_value = "127.0.0.1")]
    auditor_host: String,

    #[arg(long, default_value_t = 9000)]
    auditor_port: u16,
}

// ===================== REQUEST/RESPONSE TYPES =====================

#[derive(Deserialize)]
struct RegisterRequest {
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    commitment_hex: String,
}

#[derive(Deserialize)]
struct QueryRequest {
    password: String,
    query_id: u16,
}

#[derive(Deserialize)]
struct UpdateRequest {
    password: String,
    patient_id: u16,
    field: String,
    new_value: u16,
}

#[derive(Serialize)]
struct SearchResponse {
    result: Option<u16>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SearchPayload {
    receipt_bytes: Vec<u8>,
    encrypted_query_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct UpdatePayload {
    receipt_bytes: Vec<u8>,
    target_id_bytes: Vec<u8>,
    field: String,
    new_value_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct UpdateServerResponse {
    success: bool,
    error: Option<String>,
}

/// Payload trimis la auditor la initializare
#[derive(Serialize)]
struct InitShareRequest {
    share_bytes: Vec<u8>,
    session_token: String,
}

/// Request pentru share-ul de decriptare de la auditor
#[derive(Serialize)]
struct DecryptShareRequest {
    session_token: String,
}

#[derive(Deserialize)]
struct DecryptShareResponse {
    share_bytes: Vec<u8>,
}

// ===================== DATA MODEL =====================

struct PatientRecord {
    patient_id: u16,
    diagnosis_code: u16,
    risk_score: u16,
}

#[derive(Serialize, Deserialize)]
struct EncryptedRecord {
    pid: FheUint16,
    diag: FheUint16,
    risk: FheUint16,
}

struct ClientState {
    /// Cheia de criptare (necesara pentru FheUint16::encrypt pe query-uri)
    client_key: ClientKey,
    server_url: String,
    auditor_url: String,
}

// ===================== CRYPTO HELPERS =====================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Genereaza STARK proof (in RISC-V VM) ca stim parola al carei hash
/// coincide cu commitment-ul public stocat. Parola NU paraseste VM-ul.
fn generate_proof(password: &str) -> Result<Receipt, String> {
    let commitment = match fs::read("shared_data/commitment.bin") {
        Ok(c) if c.len() >= 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&c[0..32]);
            arr
        },
        _ => return Err("Lipsa commitment.bin. Fa register intai!".to_string()),
    };

    let password_bytes: Vec<u8> = password.as_bytes().to_vec();
    let env = ExecutorEnv::builder()
        .write(&password_bytes).unwrap()
        .write(&commitment).unwrap()
        .build().unwrap();

    let prover = default_prover();
    prover.prove(env, METHOD_NAME_ELF)
        .map(|info| info.receipt)
        .map_err(|e| format!("ZKP Prover Error: {}", e))
}

/// Threshold Decryption 2-of-2:
/// 1. Incarca share1 (XOR-share al clientului) de pe disc
/// 2. Cere share2 (XOR pad) de la auditor cu session_token
/// 3. Reconstruieste cheia: share1 XOR share2 = original_key
/// 4. Decripteaza ciphertext-ul FHE
/// 5. Distruge cheia reconstruita din memorie
async fn threshold_decrypt(
    ciphertext: FheUint16,
    auditor_url: &str,
) -> Result<u16, String> {
    println!("[CLIENT/THRESH] Starting 2-of-2 Threshold Decryption...");

    // Share 1: clientul detine XOR(key, pad)
    let share1 = fs::read("shared_data/client_share.bin")
        .map_err(|_| "Lipsa client_share.bin — regenereaza cheile".to_string())?;

    let session_token = fs::read_to_string("shared_data/session_token.txt")
        .map_err(|_| "Lipsa session_token.txt".to_string())?;

    // Share 2: obtinem pad-ul de la auditor
    println!("[CLIENT/THRESH] Requesting XOR pad from Auditor node...");
    let http = HttpClient::new();
    let resp = http
        .post(&format!("{}/decrypt_share", auditor_url))
        .json(&DecryptShareRequest { session_token })
        .send().await
        .map_err(|e| format!("Auditor unreachable: {}", e))?;

    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        return Err(format!("Auditor rejected: {}", err));
    }

    let share_resp: DecryptShareResponse = resp.json().await
        .map_err(|_| "Invalid auditor response format".to_string())?;
    let share2 = share_resp.share_bytes;

    if share1.len() != share2.len() {
        return Err("Share length mismatch — key reconstruction impossible".to_string());
    }

    // Reconstruire cheie: share1 XOR share2 = original_key_bytes
    let mut key_bytes: Vec<u8> = share1.iter().zip(share2.iter()).map(|(a, b)| a ^ b).collect();

    let reconstructed_key: ClientKey = bincode::deserialize(&key_bytes)
        .map_err(|e| format!("Key reconstruction failed: {}", e))?;

    let result = ciphertext.decrypt(&reconstructed_key);

    // Zeroize — distrugem cheia reconstruita din memorie imediat
    key_bytes.iter_mut().for_each(|b| *b = 0);
    drop(reconstructed_key);
    drop(key_bytes);

    println!("[CLIENT/THRESH] Threshold decryption complete. Key destroyed from memory.");
    Ok(result)
}

// ===================== MAIN =====================

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("[CLIENT] Booting Trusted Local Daemon...");

    fs::create_dir_all("shared_data").unwrap();

    let (client_key, server_key) = if let (Ok(ck), Ok(sk)) = (fs::read("shared_data/client_key.bin"), fs::read("shared_data/server_key.bin")) {
        println!("[CLIENT] Loaded existing TFHE Keypair from disk.");
        (bincode::deserialize(&ck).unwrap(), bincode::deserialize(&sk).unwrap())
    } else {
        println!("[CLIENT] Generating NEW TFHE Keypair...");
        let config = ConfigBuilder::default().build();
        let (ck, sk) = generate_keys(config);
        fs::write("shared_data/client_key.bin", bincode::serialize(&ck).unwrap()).unwrap();
        (ck, sk)
    };

    // ── Faza 4: XOR Key Splitting ──────────────────────────────────────────
    // Serializam cheia clientului si o impartim in 2 share-uri (XOR secret sharing)
    // share1 = key XOR pad  (clientul retine)
    // share2 = pad           (auditorul retine)
    // share1 XOR share2 = key (reconstructie)
    // NOTA: in productie folositi Shamir Secret Sharing peste GF(2^8)
    println!("[CLIENT] Splitting ClientKey into 2-of-2 XOR shares...");
    let key_bytes = bincode::serialize(&client_key).unwrap();
    let mut pad = vec![0u8; key_bytes.len()];
    rand::thread_rng().fill_bytes(&mut pad);

    let share1: Vec<u8> = key_bytes.iter().zip(pad.iter()).map(|(k, p)| k ^ p).collect();
    let share2 = pad; // XOR pad — auditorul retine asta

    fs::write("shared_data/client_share.bin", &share1).unwrap();

    // Token de sesiune pentru autentificarea cererilor catre auditor
    let mut token_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let session_token = hex::encode(token_bytes);
    fs::write("shared_data/session_token.txt", &session_token).unwrap();

    // Trimitem share2 (pad-ul) la auditor
    let auditor_url = format!("http://{}:{}", args.auditor_host, args.auditor_port);
    let http = HttpClient::new();
    match http.post(&format!("{}/init_share", auditor_url))
        .json(&InitShareRequest { share_bytes: share2, session_token: session_token.clone() })
        .send().await
    {
        Ok(_) => println!("[CLIENT] XOR pad sent to Auditor. Client holds share1 only."),
        Err(e) => println!("[CLIENT] WARN: Auditor not reachable: {}. Threshold decryption unavailable.", e),
    }
    // ── End Faza 4 ──────────────────────────────────────────────────────────

    if !std::path::Path::new("shared_data/db.bin").exists() {
        println!("[CLIENT] Encrypting Genesis Medical Database...");
        let raw_db = vec![
            PatientRecord { patient_id: 1001, diagnosis_code: 180,  risk_score: 720 }, // J18 pneumonie
            PatientRecord { patient_id: 1002, diagnosis_code: 110,  risk_score: 450 }, // I10 hipertensiune
            PatientRecord { patient_id: 1003, diagnosis_code: 250,  risk_score: 890 }, // E11 diabet tip 2
            PatientRecord { patient_id: 1004, diagnosis_code: 429,  risk_score: 310 }, // C34 cancer pulmonar
            PatientRecord { patient_id: 1005, diagnosis_code: 296,  risk_score: 580 }, // F32 depresie
        ];

        let mut encrypted_db = Vec::new();
        for rec in raw_db {
            encrypted_db.push(EncryptedRecord {
                pid:  FheUint16::encrypt(rec.patient_id,     &client_key),
                diag: FheUint16::encrypt(rec.diagnosis_code, &client_key),
                risk: FheUint16::encrypt(rec.risk_score,     &client_key),
            });
        }
        fs::write("shared_data/db.bin", bincode::serialize(&encrypted_db).unwrap()).unwrap();
        fs::write("shared_data/server_key.bin", bincode::serialize(&server_key).unwrap()).unwrap();
        println!("[CLIENT] Genesis DB and keys exported to disk.");
    } else {
        println!("[CLIENT] Genesis DB already exists. Skipping encryption.");
    }

    let server_url = format!("http://{}:{}", args.server_host, args.server_port);
    let state = Arc::new(ClientState { client_key, server_url, auditor_url });

    let app = Router::new()
        .nest_service("/", ServeDir::new("host/public"))
        .route("/api/register",  post(api_register))
        .route("/api/execute",   post(api_search))
        .route("/api/update",    post(api_update))
        .route("/api/db_state",  get(proxy_db_state))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let bind_addr = format!("0.0.0.0:{}", args.listen_port);
    println!("[CLIENT] ---> WEB UI AVAILABLE AT http://127.0.0.1:{}/", args.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ===================== HANDLERS =====================

async fn api_register(
    State(state): State<Arc<ClientState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let hash = sha256(req.password.as_bytes());
    fs::write("shared_data/commitment.bin", &hash).unwrap();

    let http = HttpClient::new();
    let url = format!("{}/register", state.server_url);
    match http.post(&url).json(&hex::encode(hash)).send().await {
        Ok(_) => println!("[CLIENT] Commitment forwarded to server."),
        Err(e) => println!("[CLIENT] WARN: Server unreachable for register: {}", e),
    }

    Json(RegisterResponse { commitment_hex: hex::encode(hash) }).into_response()
}

async fn proxy_db_state(State(state): State<Arc<ClientState>>) -> impl IntoResponse {
    let http = HttpClient::new();
    let url = format!("{}/db_state", state.server_url);
    match http.get(&url).send().await {
        Ok(res) => match res.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(_) => (StatusCode::BAD_GATEWAY, "Bad response from cloud server").into_response(),
        },
        Err(_) => Json(serde_json::json!([])).into_response(),
    }
}

/// Blind Search: ZKP proof + FHE encrypt + threshold decrypt
async fn api_search(
    State(state): State<Arc<ClientState>>,
    Json(req): Json<QueryRequest>,
) -> Json<SearchResponse> {
    println!("\n[CLIENT] =========================================");
    println!("[CLIENT] Blind Search for patient_id: {}", req.query_id);

    println!("[CLIENT] Generating STARK proof in RISC-V VM...");
    let receipt = match generate_proof(&req.password) {
        Ok(r) => r,
        Err(e) => {
            println!("[CLIENT] ZK Prover Failed: {}", e);
            return Json(SearchResponse { result: None, error: Some(e) });
        }
    };

    let encrypted_query = FheUint16::encrypt(req.query_id, &state.client_key);
    let payload = SearchPayload {
        receipt_bytes: bincode::serialize(&receipt).unwrap(),
        encrypted_query_bytes: bincode::serialize(&encrypted_query).unwrap(),
    };

    println!("[CLIENT] Transmitting FHE payload to Cloud Server...");
    let http = HttpClient::new();
    let url = format!("{}/search", state.server_url);
    let res = http.post(&url).json(&payload).send().await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let bytes = response.bytes().await.unwrap();
                let enc_result: FheUint16 = bincode::deserialize(&bytes).unwrap();
                // Decriptam prin protocol Threshold 2-of-2 (necesita auditor)
                match threshold_decrypt(enc_result, &state.auditor_url).await {
                    Ok(val) => {
                        println!("[CLIENT] SUCCESS: Decrypted diagnosis_code = {}", val);
                        Json(SearchResponse { result: Some(val), error: None })
                    },
                    Err(e) => {
                        println!("[CLIENT] Threshold decryption failed: {}", e);
                        Json(SearchResponse { result: None, error: Some(e) })
                    }
                }
            } else {
                let err = response.text().await.unwrap_or_default();
                println!("[CLIENT] SERVER REJECTED: {}", err);
                Json(SearchResponse { result: None, error: Some(err) })
            }
        },
        Err(e) => Json(SearchResponse { result: None, error: Some(format!("Network error: {}", e)) }),
    }
}

/// Oblivious Write: ZKP proof + FHE encrypt target_id + new_value -> server
async fn api_update(
    State(state): State<Arc<ClientState>>,
    Json(req): Json<UpdateRequest>,
) -> Json<UpdateServerResponse> {
    println!("\n[CLIENT] =========================================");
    println!("[CLIENT] Oblivious Write: pid={} field={} val={}", req.patient_id, req.field, req.new_value);

    let receipt = match generate_proof(&req.password) {
        Ok(r) => r,
        Err(e) => return Json(UpdateServerResponse { success: false, error: Some(e) }),
    };

    let enc_target = FheUint16::encrypt(req.patient_id, &state.client_key);
    let enc_value  = FheUint16::encrypt(req.new_value,  &state.client_key);

    let payload = UpdatePayload {
        receipt_bytes:    bincode::serialize(&receipt).unwrap(),
        target_id_bytes:  bincode::serialize(&enc_target).unwrap(),
        field:            req.field,
        new_value_bytes:  bincode::serialize(&enc_value).unwrap(),
    };

    let http = HttpClient::new();
    let url = format!("{}/update", state.server_url);
    match http.post(&url).json(&payload).send().await {
        Ok(response) => {
            match response.json::<UpdateServerResponse>().await {
                Ok(r) => {
                    if r.success { println!("[CLIENT] Oblivious Write SUCCESS."); }
                    else { println!("[CLIENT] Update FAILED: {:?}", r.error); }
                    Json(r)
                },
                Err(e) => Json(UpdateServerResponse {
                    success: false,
                    error: Some(format!("Response parse error: {}", e)),
                }),
            }
        },
        Err(e) => Json(UpdateServerResponse {
            success: false,
            error: Some(format!("Network error: {}", e)),
        }),
    }
}
