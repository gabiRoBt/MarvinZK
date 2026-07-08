use std::time::Instant;
use tfhe::{generate_keys, ConfigBuilder, FheUint32, FheBool};
use tfhe::prelude::*;
use rayon::prelude::*;

// =========================================================================
// BENCHMARK V4: 2D Matrix ZK-PIR (State-of-the-Art O(N) Bandwidth Optimization)
// =========================================================================

struct PatientRecordV4 {
    packed_data: FheUint32, // [16 biți liberi | 8 biți diag | 8 biți risc]
}

fn main() {
    println!("===============================================================");
    println!(" B E N C H M A R K   V 4 :  2D MATRIX ZK-PIR");
    println!("===============================================================");

    println!("[1] Generare Chei TFHE...");
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    tfhe::set_server_key(server_key.clone());

    // Configuram o matrice de pacienti (Grid) 
    let rows = 10;
    let cols = 10;
    let num_records = rows * cols; // Baza de date mica pentru CPU (100 pacienti)
    
    println!("[2] Generare Baza de Date Medicala (Matrice {}x{} = {} pacienti)...", rows, cols, num_records);
    
    // Generam baza de date ca o matrice 2D
    let mut db: Vec<Vec<PatientRecordV4>> = Vec::with_capacity(rows);
    for r in 0..rows {
        let mut row_vec = Vec::with_capacity(cols);
        for c in 0..cols {
            let patient_id = (r * cols + c) as u32;
            let diag = (100 + patient_id) as u32;
            let risk = (50 + patient_id % 10) as u32;
            let packed = (diag << 8) | risk;
            
            row_vec.push(PatientRecordV4 {
                packed_data: FheUint32::encrypt(packed, &client_key),
            });
        }
        db.push(row_vec);
    }

    // ---- INITIALIZARE RAYON POOL ----
    let server_key_pool = server_key.clone();
    let pool = rayon::ThreadPoolBuilder::new().build().unwrap();
    pool.broadcast(|_| {
        tfhe::set_server_key(server_key_pool.clone());
    });

    println!("\n--- Test: 2D Matrix PIR Extraction ---");
    let target_row = 4;
    let target_col = 7;
    println!("> Cautam pacientul de la (Rând {}, Coloană {})", target_row, target_col);

    // 1. Clientul generează doar 2 vectori mici (Row Mask și Col Mask)
    // In loc de 100 de elemente, trimite doar 10 + 10 = 20 elemente pe retea!
    let mut row_query = Vec::with_capacity(rows);
    for r in 0..rows {
        let bit = r == target_row;
        row_query.push(FheBool::encrypt(bit, &client_key));
    }

    let mut col_query = Vec::with_capacity(cols);
    for c in 0..cols {
        let bit = c == target_col;
        col_query.push(FheBool::encrypt(bit, &client_key));
    }

    let start_2d = Instant::now();
    let zero = FheUint32::encrypt_trivial(0u32);
    let one = FheUint32::encrypt_trivial(1u32);
    
    // 2. Pasul Rândurilor (Server-Side)
    // Serverul extrage un singur rând "colapsat" (un vector 1D de marimea coloanelor)
    let collapsed_row: Vec<FheUint32> = pool.install(|| {
        (0..cols).into_par_iter().map(|c| {
            // Pentru fiecare coloana, facem produsul scalar pe verticala folosind row_query
            let col_sum = db.iter().enumerate().map(|(r, row)| {
                let is_match = &row_query[r];
                is_match.if_then_else(&row[c].packed_data, &zero)
            }).fold(zero.clone(), |a, b| a + b);
            col_sum
        }).collect()
    });

    // 3. Pasul Coloanelor (Server-Side)
    // Acum facem produsul scalar final intre rândul colapsat si col_query
    let final_result = pool.install(|| {
        collapsed_row.par_iter().zip(col_query.par_iter()).map(|(cell, col_bit)| {
            let is_match = col_bit;
            is_match.if_then_else(cell, &zero)
        }).reduce(|| zero.clone(), |a, b| a + b)
    });

    let duration_2d = start_2d.elapsed();
    println!("> Extragere completata in: \t{:.2?}", duration_2d);

    // 4. Verificare rezultat pe Client
    let decrypted: u32 = final_result.decrypt(&client_key);
    let diag = (decrypted >> 8) & 0xFF;
    let risk = decrypted & 0xFF;
    
    let expected_id = target_row * cols + target_col;
    let expected_diag = 100 + expected_id;
    let expected_risk = 50 + expected_id % 10;

    println!("\n[4] Rezultat Decriptat de Client:");
    println!("> Diagnostic: {}", diag);
    println!("> Risc: {}", risk);
    
    if diag == expected_diag as u32 && risk == expected_risk as u32 {
        println!("=> SUCCES! Extragerea 2D Matrix PIR a returnat datele corecte!");
    } else {
        println!("=> EROARE la extragere!");
    }
    
    println!("===============================================================");
}
