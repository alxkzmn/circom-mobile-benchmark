use anyhow::Result;
use mopro_ffi::{MoproError, ProofCalldata, G1, G2};

uniffi::include_scaffolding!("mopro");

witnesscalc_adapter::witness!(sha256);

struct GenerateProofResult {
    proof: String,
    inputs: String,
}

fn generate_circom_proof(
    zkey_path: String,
    inputs_json: String,
) -> Result<GenerateProofResult, mopro_ffi::MoproError> {
    let wtns_buffer = sha256_witness(inputs_json.as_str())
        .map_err(|e| mopro_ffi::MoproError::CircomError(format!("WitGen error: {}", e)))
        .unwrap();
    let proof = rust_rapidsnark::groth16_prover_zkey_file_wrapper(&zkey_path, wtns_buffer)
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

#[cfg(test)]
mod tests {
    use crate::GenerateProofResult;
    use anyhow::Result;
    use rust_rapidsnark::groth16_prover_zkey_file_wrapper;

    witnesscalc_adapter::witness!(sha256);

    fn generate_circom_proof(
        zkey_path: String,
        inputs_json: String,
    ) -> Result<GenerateProofResult, mopro_ffi::MoproError> {
        let wtns_buffer = sha256_witness(inputs_json.as_str())
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
                .map_err(|e| {
                    mopro_ffi::MoproError::CircomError(format!("Verification error: {}", e))
                })
                .unwrap(),
        )
    }

    #[test]
    fn test_generate_circom_proof() {
        let zkey_path = "test-vectors/circom/sha256.zkey".to_string();
        let inputs_json_path = "test-vectors/circom/inputs.json".to_string();
        let inputs_json = std::fs::read_to_string(inputs_json_path).unwrap();
        let result = generate_circom_proof(zkey_path, inputs_json).unwrap();

        println!("Proof: {}", result.proof);
        println!("Inputs: {}", result.inputs);

        let vkey_path = "test-vectors/circom/verification_key".to_string();
        let vkey = std::fs::read_to_string(vkey_path).unwrap();
        let result = verify_circom_proof(vkey, result.proof, result.inputs).unwrap();
        assert_eq!(result, true);
    }
}
