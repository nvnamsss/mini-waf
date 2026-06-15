/// Issue a Proof-of-Work challenge.  Returns the challenge string to send to
/// the client (target hash prefix, nonce, difficulty).
pub fn issue_pow(_difficulty: u8) -> String {
    todo!("generate random nonce + difficulty descriptor, return as challenge payload")
}

/// Verify a PoW solution submitted by the client.
pub fn verify_pow(_challenge: &str, _solution: &str) -> bool {
    todo!("check that hash(challenge + solution) has the required leading zero bits")
}
