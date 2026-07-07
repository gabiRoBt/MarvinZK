use rayon::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheUint16};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    tfhe::set_server_key(server_key.clone());

    let db_fhe = vec![
        (FheUint16::encrypt(1001u16, &client_key), FheUint16::encrypt(101u16, &client_key)),
        (FheUint16::encrypt(1002u16, &client_key), FheUint16::encrypt(102u16, &client_key)),
        (FheUint16::encrypt(1003u16, &client_key), FheUint16::encrypt(103u16, &client_key)),
        (FheUint16::encrypt(1004u16, &client_key), FheUint16::encrypt(104u16, &client_key)),
        (FheUint16::encrypt(1005u16, &client_key), FheUint16::encrypt(105u16, &client_key)),
    ];
    let query_id = 1003u16;
    let enc_query = FheUint16::encrypt(query_id, &client_key);
    let zero = FheUint16::encrypt_trivial(0u16);

    let start = std::time::Instant::now();
    let acc: FheUint16 = db_fhe.par_iter().map(|(pid, diag)| {
        tfhe::set_server_key(server_key.clone());
        let is_match = pid.eq(&enc_query);
        is_match.if_then_else(diag, &zero)
    }).reduce(|| zero.clone(), |a, b| {
        tfhe::set_server_key(server_key.clone());
        a + b
    });
    println!("Par time: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let mut acc2 = FheUint16::encrypt_trivial(0u16);
    for (pid, diag) in &db_fhe {
        let is_match = pid.eq(&enc_query);
        acc2 = acc2 + is_match.if_then_else(diag, &zero);
    }
    println!("Seq time: {:?}", start.elapsed());

    let res: u16 = acc.decrypt(&client_key);
    println!("Result: {}", res);
}
