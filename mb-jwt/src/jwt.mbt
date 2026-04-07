// JWT (JSON Web Tokens) implementation with HS256 signing
// RFC 7519: https://tools.ietf.org/html/rfc7519

let jwt_header : String = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

fn fixed_to_array(fixed: FixedArray[UInt]) -> Array[UInt] {
  let arr : Array[UInt] = []
  for i in 0..<fixed.length() {
    arr.push(fixed[i])
  }
  arr
}

fn constant_time_eq(a: Array[UInt], b: Array[UInt]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff : UInt = 0U
  for i in 0..<a.length() {
    diff = diff | (a[i] ^ b[i])
  }
  diff == 0U
}

fn string_to_bytes_filtered_jwt(s: String) -> Array[Int] {
  let raw = s.to_bytes()
  let result : Array[Int] = []
  for i in 0..<raw.length() {
    let v = raw[i].to_int()
    if v != 0 {
      result.push(v)
    }
  }
  result
}

fn split_token(token: String) -> Result[Array[String], String] {
  let chars = string_to_bytes_filtered_jwt(token)
  let parts : Array[String] = []
  let mut current = ""

  for c in chars {
    if c == 46 {  // '.'
      parts.push(current)
      current = ""
    } else {
      current = current + c.unsafe_to_char().to_string()
    }
  }
  parts.push(current)

  if parts.length() != 3 {
    return Err("Invalid JWT format: expected 3 parts separated by dots")
  }
  Ok(parts)
}

/// Signs a JSON payload and returns a JWT token string.
/// The payload should be a valid JSON string.
///
/// Example:
/// ```
/// let token = sign("{\"sub\":\"1234567890\",\"name\":\"John\"}", "secret")
/// ```
pub fn sign(payload: String, secret: String) -> String {
  let header_encoded = base64url_encode_string(jwt_header)
  let payload_encoded = base64url_encode_string(payload)

  let signing_input = header_encoded + "." + payload_encoded

  let signature = @hmac.hmac_sha256_string(signing_input, secret)
  let signature_encoded = base64url_encode(fixed_to_array(signature))

  signing_input + "." + signature_encoded
}

/// Verifies a JWT token and returns the decoded payload if valid.
/// Returns an error if the signature is invalid or the token is malformed.
pub fn verify(token: String, secret: String) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let header_encoded = parts[0]
      let payload_encoded = parts[1]
      let signature_encoded = parts[2]

      let signing_input = header_encoded + "." + payload_encoded
      let expected_signature = @hmac.hmac_sha256_string(signing_input, secret)
      let actual_signature = base64url_decode(signature_encoded)

      if not(constant_time_eq(fixed_to_array(expected_signature), actual_signature)) {
        return Err("Invalid signature")
      }

      Ok(base64url_decode_to_string(payload_encoded))
    }
  }
}

/// Decodes a JWT token without verifying the signature.
/// Use this only when you need to inspect the payload without verification.
/// WARNING: Never trust the contents of an unverified token.
pub fn decode(token: String) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let payload_encoded = parts[1]
      Ok(base64url_decode_to_string(payload_encoded))
    }
  }
}

/// Decodes the header of a JWT token without verification.
pub fn decode_header(token: String) -> Result[String, String] {
  match split_token(token) {
    Err(e) => Err(e)
    Ok(parts) => {
      let header_encoded = parts[0]
      Ok(base64url_decode_to_string(header_encoded))
    }
  }
}
