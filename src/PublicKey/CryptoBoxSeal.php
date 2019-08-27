<?php

namespace NZTim\Crypto\PublicKey;

class CryptoBoxSeal
{
    public function encrypt(string $plaintext, PublicKey $publicKey): string
    {
        return base64_encode(sodium_crypto_box_seal($plaintext, $publicKey->binaryKey()));
    }

    public function decrypt(string $base64ciphertext, KeyPair $kp): string
    {
        return sodium_crypto_box_seal_open(base64_decode($base64ciphertext), $kp->binary());
    }
}
