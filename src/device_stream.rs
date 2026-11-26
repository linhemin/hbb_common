/// Bind a registered control connection to the operator key, device identity and both fresh
/// nonces. Direction-specific tags prevent reflecting the server's signature back as a proof.
pub fn transcript(
    server: bool, operator: &[u8; 32], device: &[u8; 32], id: &str,
    client_nonce: &[u8; 32], challenge: &[u8; 32],
) -> Vec<u8> {
    let mut out = b"RustDesk registered control stream v1\0".to_vec();
    out.push(u8::from(server));
    out.extend_from_slice(operator);
    out.extend_from_slice(device);
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(challenge);
    out.extend_from_slice(id.as_bytes());
    out
}
