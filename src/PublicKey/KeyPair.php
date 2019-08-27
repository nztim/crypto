<?php

namespace NZTim\Crypto\PublicKey;

class KeyPair
{
    private $seed;
    private $kp;

    private function __construct(string $seed)
    {
        $this->seed = $seed;
        $this->kp = sodium_crypto_box_seed_keypair($seed);
    }

    public static function generate(): KeyPair
    {
        return new KeyPair(random_bytes(SODIUM_CRYPTO_BOX_SEEDBYTES));
    }

    public static function fromString(string $base64seed): KeyPair
    {
        return new KeyPair(base64_decode($base64seed));
    }

    /**
     * Seed in base64 for storage/transmission
     */
    public function toString(): string
    {
        return base64_encode($this->seed);
    }

    /**
     * Public key in base64 for storage/transmission
     */
    public function publicKey(): PublicKey
    {
        return PublicKey::fromBinary(sodium_crypto_box_publickey($this->kp));
    }

    /**
     * Key pair in binary form for use by other crypto functions
     */
    public function binary(): string
    {
        return $this->kp;
    }
}
