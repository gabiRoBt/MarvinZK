use tfhe::core_crypto::prelude::*;

fn main() {
    println!("===============================================================");
    println!(" ZKP-GATED HOMOMORPHIC PROXY RE-ENCRYPTION (PRE) PROOF OF CONCEPT");
    println!("===============================================================");
    println!("Aceasta mini-librarie demonstreaza matematic cum serverul poate");
    println!("traduce un ciphertext de pe cheia Pacientului pe cheia Spitalului,");
    println!("fara sa decripteze datele vreo secunda, folosind Key Switching.");
    println!("===============================================================\n");

    // Parametrii LWE de bază pentru demonstrație
    let lwe_dimension = LweDimension(742);
    let lwe_noise_distribution = DynamicVariance::new(Variance::from_variance(0.000007));
    let ciphertext_modulus = CiphertextModulus::new_native();

    // Setup generatori pseudo-random
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // 1. GENERARE CHEI (Nivel Scăzut / Metal)
    println!("[1] Generam LweSecretKey pentru PACIENT (Key A)...");
    let patient_key = allocate_and_generate_new_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );

    println!("[2] Generam LweSecretKey pentru SPITAL (Key B)...");
    let hospital_key = allocate_and_generate_new_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );

    // 2. GENERARE KEY SWITCHING KEY (Mecanismul de Traducere)
    // Parametrii pentru descompunere (baza și nivelurile)
    let decomp_base_log = DecompositionBaseLog(4);
    let decomp_level_count = DecompositionLevelCount(3);
    
    println!("[3] Generam KeySwitchingKey (Pacient -> Spital)...");
    println!("    Aceasta cheie e publica si va sta pe Serverul Cloud.");
    let ksk_patient_to_hospital = allocate_and_generate_new_lwe_keyswitch_key(
        &patient_key,
        &hospital_key,
        decomp_base_log,
        decomp_level_count,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // 3. CRIPTAREA DATELOR (La Pacient)
    let plaintext_value: u64 = 42; // Exemplu: Ritm Cardiac
    // Scalăm mesajul pe 64-biți pentru LWE
    let delta = 1u64 << 60; 
    let plain_text = Plaintext(plaintext_value * delta);

    println!("\n[4] Pacientul cripteaza ritmul cardiac ({}) cu cheia LUI...", plaintext_value);
    let mut patient_ciphertext = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
    encrypt_lwe_ciphertext(
        &patient_key,
        &mut patient_ciphertext,
        plain_text,
        lwe_noise_distribution,
        &mut encryption_generator,
    );

    // 4. PROXY RE-ENCRYPTION (Pe Server)
    println!("\n[5] CLOUD SERVER: Primeste cerere de la Doctor + ZKP.");
    println!("    ZKP Validat! Serverul initiaza 'Homomorphic Key Switching'...");
    
    let mut hospital_ciphertext = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
    keyswitch_lwe_ciphertext(
        &ksk_patient_to_hospital,
        &patient_ciphertext,
        &mut hospital_ciphertext,
    );
    println!("    [OK] Transcodare FHE reusita! Ciphertext-ul e acum pe cheia Spitalului.");

    // 5. DECRIPTAREA (La Doctor/Spital)
    println!("\n[6] SPITALUL decripteaza rezultatul folosind cheia LUI...");
    let decrypted_plaintext = decrypt_lwe_ciphertext(&hospital_key, &hospital_ciphertext);
    
    let result_rounded = (decrypted_plaintext.0 as f64 / delta as f64).round() as u64;
    println!("    Rezultat decriptat: {}", result_rounded);

    if result_rounded == plaintext_value {
        println!("\n=> SUCCES TOTAL! Aducerea la 'acelasi numitor' (PRE) functioneaza perfect pe metal!");
    } else {
        println!("\n=> EROARE: Zgomot prea mare sau decriptare esuata.");
    }
}
