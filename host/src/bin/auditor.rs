use axum::{
    routing::post,
    Router, Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::fs;
use tower_http::cors::CorsLayer;
use clap::Parser;

/// Auditor Node — Threshold Decryption 2-of-2 (Faza 4)
///
/// Detine jumatatea de cheie (XOR pad) necesara pentru decriptare.
/// Fara cooperarea auditorului, clientul nu poate decripta niciun ciphertext FHE.
/// Auditoriul nu stie ce se decripteaza, primeste/returneaza doar bytes opaci.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    listen_host: String,

    #[arg(long, default_value_t = 9000)]
    listen_port: u16,
}

#[derive(Deserialize)]
struct InitShareRequest {
    /// Jumatatea de cheie (XOR pad) pe care auditorul o pastreaza
    share_bytes: Vec<u8>,
    /// Token de sesiune (HMAC-like PoC) pentru validarea cererilor ulterioare
    session_token: String,
}

#[derive(Deserialize)]
struct DecryptShareRequest {
    session_token: String,
}

#[derive(Serialize)]
struct DecryptShareResponse {
    share_bytes: Vec<u8>,
}

struct AuditorState {
    /// XOR pad — jumatatea de cheie stocata de auditor
    share: Mutex<Option<Vec<u8>>>,
    /// Token de sesiune validat la fiecare cerere de decriptare
    session_token: Mutex<Option<String>>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("[AUDITOR] Booting Auditor Node (Threshold Decryption Party 2-of-2)...");

    // Incarcam share-ul si token-ul daca exista deja pe disc (reboot)
    let initial_share = fs::read("shared_data/auditor_share.bin").ok();
    let initial_token = fs::read_to_string("shared_data/auditor_token.txt").ok();

    if initial_share.is_some() {
        println!("[AUDITOR] Loaded existing key share from disk ({} bytes).",
            initial_share.as_ref().unwrap().len());
    } else {
        println!("[AUDITOR] No existing share found. Waiting for /init_share from Client...");
    }

    let state = Arc::new(AuditorState {
        share: Mutex::new(initial_share),
        session_token: Mutex::new(initial_token),
    });

    let app = Router::new()
        .route("/init_share", post(init_share))
        .route("/decrypt_share", post(get_decrypt_share))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let bind_addr = format!("{}:{}", args.listen_host, args.listen_port);
    println!("[AUDITOR] ---> RUNNING ON {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Initializare share — clientul trimite jumatatea de cheie la pornire.
async fn init_share(
    State(state): State<Arc<AuditorState>>,
    Json(req): Json<InitShareRequest>,
) -> impl IntoResponse {
    let share_len = req.share_bytes.len();

    *state.share.lock().unwrap() = Some(req.share_bytes.clone());
    *state.session_token.lock().unwrap() = Some(req.session_token.clone());

    fs::create_dir_all("shared_data").unwrap();
    fs::write("shared_data/auditor_share.bin", &req.share_bytes).unwrap();
    fs::write("shared_data/auditor_token.txt", &req.session_token).unwrap();

    println!("[AUDITOR] Key share initialized ({} bytes). Session token registered.", share_len);
    StatusCode::OK.into_response()
}

/// Cerere de decriptare — auditorul returneaza share-ul dupa validarea token-ului.
/// Auditorul nu stie ce ciphertext se decripteaza (blind participation).
async fn get_decrypt_share(
    State(state): State<Arc<AuditorState>>,
    Json(req): Json<DecryptShareRequest>,
) -> impl IntoResponse {
    // Validare token de sesiune
    let token_guard = state.session_token.lock().unwrap();
    match &*token_guard {
        None => {
            println!("[AUDITOR] REJECTED: No session token registered yet.");
            return (StatusCode::FORBIDDEN, "No session token registered").into_response();
        },
        Some(stored) if *stored != req.session_token => {
            println!("[AUDITOR] REJECTED: Invalid session token. Unauthorized access attempt!");
            return (StatusCode::FORBIDDEN, "Invalid session token — Unauthorized").into_response();
        },
        _ => {}
    }
    drop(token_guard);

    let share_guard = state.share.lock().unwrap();
    match &*share_guard {
        None => {
            (StatusCode::SERVICE_UNAVAILABLE, "Auditor has no share stored").into_response()
        },
        Some(share) => {
            println!("[AUDITOR] Providing XOR pad share for threshold decryption.");
            Json(DecryptShareResponse { share_bytes: share.clone() }).into_response()
        }
    }
}
