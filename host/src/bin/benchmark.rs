use std::time::Instant;
use std::fs;
use serde::Serialize;
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use tfhe::{generate_keys, ConfigBuilder, FheUint16};
use tfhe::prelude::*;
use risc0_zkvm::{default_prover, ExecutorEnv};
use methods::METHOD_NAME_ELF;
use rayon::prelude::*;

#[derive(Serialize)]
struct Metrics {
    avg_ms: f64,
    min_ms: u128,
    max_ms: u128,
}

#[derive(Serialize)]
struct BenchmarkResults {
    zkp_fhe_auth: Metrics,
    sql_hash_auth: Metrics,
    zkp_fhe_query: Metrics,
    sql_hash_query: Metrics,
    zkp_fhe_update: Metrics,
    sql_hash_update: Metrics,
    memory_peak_mb: f64,
}

fn get_memory_rss() -> f64 {
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<f64>() {
                        return kb / 1024.0;
                    }
                }
            }
        }
    }
    0.0
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn run_metrics<F>(mut func: F, iterations: usize) -> Metrics
where
    F: FnMut(),
{
    let mut min = u128::MAX;
    let mut max = 0;
    let mut total = 0;

    for i in 0..iterations {
        let start = Instant::now();
        func();
        let duration = start.elapsed().as_millis();
        if duration < min { min = duration; }
        if duration > max { max = duration; }
        total += duration;

        if (i + 1) % 10 == 0 {
            println!("  ... completed {}/{}", i + 1, iterations);
        }
    }

    Metrics {
        avg_ms: (total as f64) / (iterations as f64),
        min_ms: min,
        max_ms: max,
    }
}

fn build_svg(
    auth_avg: f64,
    query_avg: f64,
    update_avg: f64,
) -> String {
    // Construim SVG prin concatenare simpla — evitam raw string literals cu
    // font-family="sans-serif" si fill="#hex" care produc prefix errors in Rust 2021
    let ff      = "sans-serif";
    let bg      = "#1a1d27";
    let fg      = "#f1f5f9";
    let muted   = "#94a3b8";
    let c_auth   = "#6366f1";
    let c_query  = "#10b981";
    let c_update = "#f59e0b";

    let aw = (auth_avg   / 100.0).min(350.0).max(5.0);
    let qw = (query_avg  / 10.0) .min(350.0).max(5.0);
    let uw = (update_avg / 10.0) .min(350.0).max(5.0);

    let mut s = String::new();
    s += "<svg width=\"600\" height=\"400\" xmlns=\"http://www.w3.org/2000/svg\">\n";
    s += &format!("  <rect width=\"100%\" height=\"100%\" fill=\"{}\" />\n", bg);
    s += &format!(
        "  <text x=\"300\" y=\"40\" font-family=\"{}\" font-size=\"20\" fill=\"{}\" text-anchor=\"middle\">Latenta: ZKP+FHE vs SQL+Hash (ms)</text>\n",
        ff, fg
    );
    // --- Auth row ---
    s += &format!("  <text x=\"50\" y=\"100\" font-family=\"{}\" font-size=\"14\" fill=\"{}\">Auth (ZKP)</text>\n", ff, fg);
    s += &format!("  <rect x=\"150\" y=\"85\" width=\"{:.2}\" height=\"20\" fill=\"{}\" />\n", aw, c_auth);
    s += &format!(
        "  <text x=\"{:.2}\" y=\"100\" font-family=\"{}\" font-size=\"12\" fill=\"{}\">{:.2} ms</text>\n",
        160.0 + aw, ff, muted, auth_avg
    );
    // --- Query row ---
    s += &format!("  <text x=\"50\" y=\"150\" font-family=\"{}\" font-size=\"14\" fill=\"{}\">Query (FHE)</text>\n", ff, fg);
    s += &format!("  <rect x=\"150\" y=\"135\" width=\"{:.2}\" height=\"20\" fill=\"{}\" />\n", qw, c_query);
    s += &format!(
        "  <text x=\"{:.2}\" y=\"150\" font-family=\"{}\" font-size=\"12\" fill=\"{}\">{:.2} ms</text>\n",
        160.0 + qw, ff, muted, query_avg
    );
    // --- Update row ---
    s += &format!("  <text x=\"50\" y=\"200\" font-family=\"{}\" font-size=\"14\" fill=\"{}\">Update (FHE)</text>\n", ff, fg);
    s += &format!("  <rect x=\"150\" y=\"185\" width=\"{:.2}\" height=\"20\" fill=\"{}\" />\n", uw, c_update);
    s += &format!(
        "  <text x=\"{:.2}\" y=\"200\" font-family=\"{}\" font-size=\"12\" fill=\"{}\">{:.2} ms</text>\n",
        160.0 + uw, ff, muted, update_avg
    );
    s += "</svg>\n";
    s
}

fn main() {
    let iterations = 100;
    println!("[BENCHMARK] Starting Academic Benchmark ({} iteratii)...", iterations);

    println!("[BENCHMARK] Setting up SQLite...");
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute(
        "CREATE TABLE patients (id INTEGER PRIMARY KEY, diagnosis INTEGER, risk INTEGER)",
        (),
    ).unwrap();
    for i in 1..=5 {
        conn.execute("INSERT INTO patients (id, diagnosis, risk) VALUES (?1, ?2, ?3)", (1000 + i, 100 + i, 500 + i)).unwrap();
    }
    let sql_password = "my_secret_password";
    let mut hasher = Sha256::new();
    hasher.update(sql_password);
    let _sql_stored_hash = hasher.finalize();

    println!("[BENCHMARK] Generating TFHE Keys...");
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    tfhe::set_server_key(server_key.clone());

    let mut db_fhe = vec![
        (FheUint16::encrypt(1001u16, &client_key), FheUint16::encrypt(101u16, &client_key), FheUint16::encrypt(501u16, &client_key)),
        (FheUint16::encrypt(1002u16, &client_key), FheUint16::encrypt(102u16, &client_key), FheUint16::encrypt(502u16, &client_key)),
        (FheUint16::encrypt(1003u16, &client_key), FheUint16::encrypt(103u16, &client_key), FheUint16::encrypt(503u16, &client_key)),
        (FheUint16::encrypt(1004u16, &client_key), FheUint16::encrypt(104u16, &client_key), FheUint16::encrypt(504u16, &client_key)),
        (FheUint16::encrypt(1005u16, &client_key), FheUint16::encrypt(105u16, &client_key), FheUint16::encrypt(505u16, &client_key)),
    ];
    let query_id = 1003u16;
    let enc_query  = FheUint16::encrypt(query_id, &client_key);
    let zero       = FheUint16::encrypt_trivial(0u16);
    let enc_update = FheUint16::encrypt(999u16, &client_key);

    let zkp_password   = "my_secret_password";
    let zkp_commitment = sha256(zkp_password.as_bytes());

    // ── Auth benchmarks ──────────────────────────────────────────────────────
    println!("[BENCHMARK] Running SQL+Hash Auth Metrics...");
    let sql_hash_auth = run_metrics(|| {
        let mut h = Sha256::new();
        h.update(sql_password);
        let _ = h.finalize();
    }, iterations);

    println!("[BENCHMARK] Running ZKP Proving (100 proof will take a long time)...");
    let zkp_fhe_auth = run_metrics(|| {
        let env = ExecutorEnv::builder()
            .write(&zkp_password.as_bytes().to_vec()).unwrap()
            .write(&zkp_commitment).unwrap()
            .build().unwrap();
        let prover = default_prover();
        let _ = prover.prove(env, METHOD_NAME_ELF).unwrap();
    }, iterations);

    // ── Query benchmarks ─────────────────────────────────────────────────────
    println!("[BENCHMARK] Running SQL Query Metrics...");
    let sql_hash_query = run_metrics(|| {
        let mut stmt = conn.prepare("SELECT diagnosis FROM patients WHERE id = ?1").unwrap();
        let mut rows = stmt.query([1003]).unwrap();
        while let Some(_row) = rows.next().unwrap() {}
    }, iterations);

    println!("[BENCHMARK] Running FHE Blind Search Metrics (Parallel)...");
    let zkp_fhe_query = run_metrics(|| {
        let acc: FheUint16 = db_fhe.par_iter().map(|(pid, diag, _)| {
            tfhe::set_server_key(server_key.clone());
            let is_match = pid.eq(&enc_query);
            is_match.if_then_else(diag, &zero)
        }).reduce(|| {
            tfhe::set_server_key(server_key.clone());
            zero.clone()
        }, |a, b| {
            tfhe::set_server_key(server_key.clone());
            a + b
        });
    }, iterations);

    // ── Update benchmarks ────────────────────────────────────────────────────
    println!("[BENCHMARK] Running SQL Update Metrics...");
    let sql_hash_update = run_metrics(|| {
        conn.execute("UPDATE patients SET diagnosis = ?1 WHERE id = ?2", (999, 1003)).unwrap();
    }, iterations);

    println!("[BENCHMARK] Running FHE Oblivious Write Metrics (Parallel)...");
    let zkp_fhe_update = run_metrics(|| {
        db_fhe.par_iter_mut().for_each(|(pid, diag, _)| {
            tfhe::set_server_key(server_key.clone());
            let is_match = pid.eq(&enc_query);
            *diag = is_match.if_then_else(&enc_update, diag);
        });
    }, iterations);

    let memory_peak_mb = get_memory_rss();

    let results = BenchmarkResults {
        zkp_fhe_auth,
        sql_hash_auth,
        zkp_fhe_query,
        sql_hash_query,
        zkp_fhe_update,
        sql_hash_update,
        memory_peak_mb,
    };

    // ── Outputs ───────────────────────────────────────────────────────────────
    println!("[BENCHMARK] Saving results...");
    let json_str = serde_json::to_string_pretty(&results).unwrap();
    fs::write("benchmark_results.json", json_str).unwrap();

    let md_report = format!(
        "## Benchmark Report\n| Operatie                | ZKP+FHE (ms) | SQL+Hash(ms) |\n|-------------------------|--------------|--------------|\\n| Auth (proof/verify)     | {:<12.2} | {:<12.2} |\n| Query (search)          | {:<12.2} | {:<12.2} |\n| Update (write)          | {:<12.2} | {:<12.2} |\n| Memoria peak (MB)       | {:<12.2} | N/A          |\n",
        results.zkp_fhe_auth.avg_ms, results.sql_hash_auth.avg_ms,
        results.zkp_fhe_query.avg_ms, results.sql_hash_query.avg_ms,
        results.zkp_fhe_update.avg_ms, results.sql_hash_update.avg_ms,
        memory_peak_mb
    );
    fs::write("benchmark_report.md", md_report).unwrap();

    let svg = build_svg(
        results.zkp_fhe_auth.avg_ms,
        results.zkp_fhe_query.avg_ms,
        results.zkp_fhe_update.avg_ms,
    );
    fs::write("benchmark_chart.svg", svg).unwrap();

    println!("[BENCHMARK] Done. Saved: benchmark_results.json | benchmark_report.md | benchmark_chart.svg");
}
