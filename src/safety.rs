use hex;
use qrcode::QrCode;

/// Renders the handshake safety number as a QR code for scanning.
pub fn safety_number_qr(data: &[u8]) -> String {
    QrCode::new(data)
        .map(|code| code.render::<char>().build())
        .unwrap_or_else(|_| hex::encode(data))
}

/// Formats the safety number as a pair of short authentication strings.
pub fn safety_number_sas(data: &[u8]) -> String {
    if data.len() < 4 {
        return hex::encode(data);
    }
    let num = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    format!("{} {}", num / 1000 % 1000, num % 1000)
}
