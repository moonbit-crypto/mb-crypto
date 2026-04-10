// JWT tests with known test vectors

test "base64url encode simple" {
  let input : Array[UInt] = [72U, 101U, 108U, 108U, 111U]  // "Hello"
  let result = base64url_encode(input)
  assert_eq(result, "SGVsbG8")
}

test "base64url encode string" {
  let result = base64url_encode_string("Hello")
  assert_eq(result, "SGVsbG8")
}

test "base64url decode simple" {
  let result = base64url_decode("SGVsbG8")
  assert_eq(result.length(), 5)
  assert_eq(result[0], 72U)   // H
  assert_eq(result[1], 101U)  // e
  assert_eq(result[2], 108U)  // l
  assert_eq(result[3], 108U)  // l
  assert_eq(result[4], 111U)  // o
}

test "base64url roundtrip" {
  let original = "The quick brown fox jumps over the lazy dog"
  let encoded = base64url_encode_string(original)
  let decoded = base64url_decode_to_string(encoded)
  assert_eq(decoded, original)
}

test "base64url encode jwt header" {
  let header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
  let encoded = base64url_encode_string(header)
  assert_eq(encoded, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

test "jwt sign and verify roundtrip" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let secret = "your-256-bit-secret"

  let token = sign(payload, secret)
  let result = verify(token, secret)

  match result {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

test "jwt verify with wrong secret fails" {
  let payload = "{\"sub\":\"1234567890\"}"
  let secret = "correct-secret"
  let wrong_secret = "wrong-secret"

  let token = sign(payload, secret)
  let result = verify(token, wrong_secret)

  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

test "jwt decode without verification" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}"
  let secret = "secret"

  let token = sign(payload, secret)
  let result = decode(token)

  match result {
    Ok(decoded_payload) => assert_eq(decoded_payload, payload)
    Err(_) => assert_true(false)
  }
}

test "jwt decode header" {
  let payload = "{\"sub\":\"test\"}"
  let secret = "secret"

  let token = sign(payload, secret)
  let header = decode_header(token)

  match header {
    Ok(h) => assert_eq(h, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
    Err(_) => assert_true(false)
  }
}

test "jwt invalid format" {
  let result = verify("invalid-token", "secret")
  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

test "jwt tampered payload fails verification" {
  let payload = "{\"sub\":\"1234567890\"}"
  let secret = "secret"

  let token = sign(payload, secret)

  // Manually tamper with the token by replacing the payload part
  // Original token: header.payload.signature
  // We'll create: header.tampered_payload.signature (same signature)
  let tampered_payload = base64url_encode_string("{\"sub\":\"hacked\"}")

  // Find the dots and reconstruct with tampered payload
  let token_bytes = @utf8.encode(token)
  let mut first_dot = -1
  let mut second_dot = -1
  for i in 0..<token_bytes.length() {
    let c = token_bytes[i].to_int()
    if c == 46 {  // '.'
      if first_dot < 0 {
        first_dot = i
      } else {
        second_dot = i
        break
      }
    }
  }

  // Extract header and signature parts
  let mut header_part = ""
  for i in 0..<first_dot {
    let c = token_bytes[i].to_int()
    header_part = header_part + c.unsafe_to_char().to_string()
  }

  let mut signature_part = ""
  for i in (second_dot + 1)..<token_bytes.length() {
    let c = token_bytes[i].to_int()
    signature_part = signature_part + c.unsafe_to_char().to_string()
  }

  let tampered_token = header_part + "." + tampered_payload + "." + signature_part

  let result = verify(tampered_token, secret)
  match result {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}

// Test vector from jwt.io
test "jwt.io test vector" {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
  let secret = "your-256-bit-secret"

  let token = sign(payload, secret)

  // Verify it starts with the correct header
  assert_true(token.has_prefix("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."))

  // Verify roundtrip works
  match verify(token, secret) {
    Ok(_) => assert_true(true)
    Err(_) => assert_true(false)
  }
}
