export class SNCryptoOperator {

  constructor(crypto) {
    this.crypto = crypto;
  }

  async decryptText({ciphertextToAuth, contentCiphertext, encryptionKey, iv, authHash, authKey} = {}, requiresAuth) {
    if(requiresAuth && !authHash) {
      console.error("Auth hash is required.");
      return;
    }

    if(authHash) {
      var localAuthHash = await this.crypto.hmac256(ciphertextToAuth, authKey);
      if(this.crypto.timingSafeEqual(authHash, localAuthHash) === false) {
        console.error("Auth hash does not match, returning null.");
        return null;
      }
    }

    var keyData = await this.crypto.hexStringToArrayBuffer(encryptionKey);
    var ivData  = await this.crypto.hexStringToArrayBuffer(iv || "");
    return this.crypto.aes256CbcDecrypt(contentCiphertext, keyData, ivData);
  }

  async encryptText(text, key, iv) {
    var keyData = await this.crypto.hexStringToArrayBuffer(key);
    var ivData  = await this.crypto.hexStringToArrayBuffer(iv || "");
    return this.crypto.aes256CbcEncrypt(text, keyData, ivData);
  }
}
