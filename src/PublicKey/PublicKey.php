<?php

namespace NZTim\Crypto\PublicKey;

class PublicKey
{
    private $key;

    function __construct(string $key)
    {
        $this->key = $key;
    }

    public static function fromString(string $base64key)
    {
        return new PublicKey(base64_decode($base64key));
    }

    public static function fromBinary(string $key)
    {
        return new PublicKey($key);
    }

    public function binaryKey(): string
    {
        return $this->key;
    }

    /**
     * Key in base64 format for storage/transmission
     */
    public function toString(): string
    {
        return base64_encode($this->key);
    }
}
