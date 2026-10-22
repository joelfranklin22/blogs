function generateSalt(rounds = 10) {
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);

  const b64 = toBcryptBase64(randomBytes);
  return `$2b$${rounds.toString().padStart(2, "0")}$${b64}`;
}

function toBcryptBase64(buffer) {
  const alphabet =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";

  for (let i = 0; i < buffer.length; i += 3) {
    const b1 = buffer[i];
    const b2 = buffer[i + 1] || 0;
    const b3 = buffer[i + 2] || 0;

    result += alphabet[b1 >> 2];
    console.log(i, result);

    result += alphabet[((b1 & 0x03) << 4) | (b2 >> 4)];
    console.log(result);

    result += alphabet[((b2 & 0x0f) << 2) | (b3 >> 6)];
    console.log(result);

    result += alphabet[b3 & 0x3f];
    console.log(result);
  }
  return result.slice(0, 22);
}

const salt = generateSalt(10);
console.log("Generated Salt ", salt);
