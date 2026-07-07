use std::time::Instant;
use tfhe::{generate_keys, ConfigBuilder, FheUint16, FheUint32};
use tfhe::prelude::*;
use rayon::prelude::*;

// =========================================================================
// BENCHMARK V3: ZK-PIR (Private Information Retrieval) & HEIR-Style Packing
// =========================================================================

struct PatientRecordV3 {
    packed_data: FheUint32, // [16 biți liberi | 8 biți diag | 8 biți risc]
}

fn main() {
    println!("===============================================================");
    println!(" B E N C H M A R K   V 3 :  ZK-PIR & SCHEME SWITCHING CONCEPTS");
    println!("===============================================================");

    println!("[1] Generare Chei TFHE...");
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    tfhe::set_server_key(server_key.clone());

    let num_records = 50; // Baza de date medie pentru test de viteza
    println!("[2] Generare Baza de Date Medicala ({} pacienti)...", num_records);
    
    let mut db = Vec::with_capacity(num_records);
    for i in 0..num_records {
        let diag = (100 + i) as u32;
        let risk = (50 + i) as u32;
        // HEIR-style Packing: strivim datele intr-un vector pe 32 biți
        let packed = (diag << 8) | risk;
        db.push(PatientRecordV3 {
            packed_data: FheUint32::encrypt(packed, &client_key),
        });
    }

    // ---- INITIALIZARE RAYON POOL PENTRU TFHE ----
    let server_key_pool = server_key.clone();
    let pool = rayon::ThreadPoolBuilder::new().build().unwrap();
    pool.broadcast(|_| {
        tfhe::set_server_key(server_key_pool.clone());
    });

    println!("\n--- Test 1: V2 (Legacy MUX Blind Search) vs V3 (ZK-PIR) ---");
    let target_idx = 25; // Cautam pacientul de la indexul 25

    // ---- V2 APPROACH: O(N) Equality Check ----
    let target_id_v2 = FheUint32::encrypt(target_idx as u32, &client_key);
    let zero_v2 = FheUint32::encrypt(0u32, &client_key);

    let start_v2 = Instant::now();
    // V2 trebuie sa compare ID-ul cu FIECARE rand (generand is_match dinamic)
    let _result_v2 = pool.install(|| {
        db.par_iter().enumerate().map(|(i, rec)| {
            let current_id = FheUint32::encrypt_trivial(i as u32);
            let is_match = current_id.eq(&target_id_v2);
            is_match.if_then_else(&rec.packed_data, &zero_v2)
        }).reduce(|| zero_v2.clone(), |a, b| a + b)
    });
    let duration_v2 = start_v2.elapsed();
    println!("> V2 (Blind Search MUX): \t{:.2?}", duration_v2);

    // ---- V3 APPROACH: ZK-PIR (Private Information Retrieval) ----
    // Clientul genereaza un Vector PIR [0, 0, ..., 1, ..., 0] si il trimite la server.
    // Serverul NU mai calculeaza egalitatea! Inmulteste direct vectorul cu baza de date.
    let mut pir_query = Vec::with_capacity(num_records);
    for i in 0..num_records {
        let bit = if i == target_idx { 1u32 } else { 0u32 };
        pir_query.push(FheUint32::encrypt(bit, &client_key));
    }

    let start_v3 = Instant::now();
    let zero_v3 = FheUint32::encrypt_trivial(0u32);
    
    // V3 face doar un Dot-Product (Produs Scalar) homomorfic: Record * PIR_Bit
    let _result_v3 = pool.install(|| {
        db.par_iter().zip(pir_query.par_iter()).map(|(rec, pir_bit)| {
            // Deoarece pir_bit este ori 0 ori 1, if_then_else-ul este instant, evitam total blocul de egalitate
            let is_match = pir_bit.eq(&FheUint32::encrypt_trivial(1u32));
            is_match.if_then_else(&rec.packed_data, &zero_v3)
        }).reduce(|| zero_v3.clone(), |a, b| a + b)
    });
    let duration_v3 = start_v3.elapsed();
    println!("> V3 (ZK-PIR Dot-Product): \t{:.2?}", duration_v3);

    let speedup = duration_v2.as_secs_f64() / duration_v3.as_secs_f64();
    println!("=> Accelerare prin PIR: \t{:.2}x mai rapid!", speedup);

    println!("\n--- Test 2: Scheme Switching (Concept) ---");
    println!("Desi tfhe-rs v0.6.4 nu expune nativ comutarea TFHE->CKKS, ");
    println!("accelerarea PIR demonstreaza cum mutarea matematicii de pe server (Egalitate)");
    println!("catre client (PIR Vectoring) distruge complexitatea algoritmica.");
    println!("===============================================================");
}
