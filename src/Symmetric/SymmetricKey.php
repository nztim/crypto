<?php declare(strict_types=1);

namespace NZTim\Crypto\Symmetric;

use RuntimeException;

class SymmetricKey
{
    private string $secretKeyHex;

    public function __construct(string $secretKeyHex)
    {
        // Secret key is always 32 bytes -> 64 hex characters
        if (!ctype_xdigit($secretKeyHex)  || strlen($secretKeyHex) !== 64) {
            throw new RuntimeException("Invalid secret key, must be 32 byte hex string");
        }
        $this->secretKeyHex = $secretKeyHex;
    }

    // Hex-encoded key using time-constant function
    public static function generate(): SymmetricKey
    {
        return new SymmetricKey(sodium_bin2hex(sodium_crypto_secretbox_keygen()));
    }

    public function binary(): string
    {
        return sodium_hex2bin($this->secretKeyHex);
    }

    public function hex(): string
    {
        return $this->secretKeyHex;
    }
}
