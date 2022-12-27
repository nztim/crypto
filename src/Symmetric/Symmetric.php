<?php declare(strict_types=1);

namespace NZTim\Crypto\Symmetric;

use RuntimeException;

class Symmetric
{
    public function encrypt(string $plaintext, SymmetricKey $key): string
    {
        // Encrypt with nonce, convert to base64, zero out RAM
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertextBinary = sodium_crypto_secretbox($plaintext, $nonce, $key->binary());
        $ciphertextBase64 = sodium_bin2base64($nonce . $ciphertextBinary, SODIUM_BASE64_VARIANT_ORIGINAL);
        sodium_memzero($plaintext);
        sodium_memzero($nonce);
        return $ciphertextBase64;
    }

    public function decrypt(string $ciphertextBase64, SymmetricKey $key): string
    {
        // Base64->binary, separate nonce and actual encrypted message, decrypt and return plaintext
        $ciphertextBinary = sodium_base642bin($ciphertextBase64, SODIUM_BASE64_VARIANT_ORIGINAL);
        $nonce = mb_substr($ciphertextBinary, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($ciphertextBinary, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key->binary());
        if ($plaintext === false) {
            throw new RuntimeException('Decryption error, incorrect/corrupted message?');
        }
        sodium_memzero($nonce);
        sodium_memzero($ciphertext);
        return $plaintext;
    }
}
