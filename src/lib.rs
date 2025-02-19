use anyhow::Result;
use mopro_ffi::{MoproError, ProofCalldata, G1, G2};
use rust_rapidsnark::groth16_prover_zkey_file_wrapper;

struct GenerateProofResult {
    proof: String,
    inputs: String,
}

fn generate_circom_proof(
    zkey_path: String,
    inputs_json: String,
) -> Result<GenerateProofResult, mopro_ffi::MoproError> {
    let wtns_buffer = multiplier2_witness(inputs_json.as_str())
        .map_err(|e| mopro_ffi::MoproError::CircomError(format!("WitGen error: {}", e)))
        .unwrap();
    let proof = groth16_prover_zkey_file_wrapper(&zkey_path, wtns_buffer)
        .map_err(|e| mopro_ffi::MoproError::CircomError(format!("Prover error: {}", e)))
        .unwrap();
    Ok(GenerateProofResult {
        proof: proof.proof,
        inputs: proof.public_signals,
    })
}

fn verify_circom_proof(
    vkey: String,
    proof: String,
    public_input: String,
) -> Result<bool, mopro_ffi::MoproError> {
    Ok(
        rust_rapidsnark::groth16_verify_wrapper(&proof, &public_input, &vkey)
            .map_err(|e| mopro_ffi::MoproError::CircomError(format!("Verification error: {}", e)))
            .unwrap(),
    )
}

uniffi::include_scaffolding!("mopro");

witnesscalc_adapter::witness!(multiplier2);
