<?php declare(strict_types=1);

use NZTim\Crypto\Symmetric\Symmetric;
use NZTim\Crypto\Symmetric\SymmetricKey;
use PHPUnit\Framework\TestCase;

class SymmetricTest extends TestCase
{
    /** @test */
    public function non_hex_key()
    {
        $this->expectException(RuntimeException::class);
        new SymmetricKey('not-hex-but-is-correct-length-----------------------------------');
    }

    /** @test */
    public function hex_key_incorrect_length()
    {
        $this->expectException(RuntimeException::class);
        new SymmetricKey('29fbf5313c2ca2aa38d341e2f6e79de5d643d2d7b4728e86974ca2752d073a35a');
    }

    /** @test */
    public function correct_key()
    {
        $key = new SymmetricKey('29fbf5313c2ca2aa38d341e2f6e79de5d643d2d7b4728e86974ca2752d073a35');
        $this->assertTrue($key instanceof SymmetricKey);
    }

    /** @test */
    public function generate()
    {
        $key = SymmetricKey::generate();
        $this->assertTrue($key instanceof SymmetricKey);
    }

    /** @test */
    public function encryption_decryption_works()
    {
        $key = SymmetricKey::generate();
        $message = 'Hello World with unusual characters !@(*%$%*#*(()@@<>><<>😀';
        $s = new Symmetric();
        $output = $s->decrypt($s->encrypt($message, $key), $key);
        $this->assertEquals($message, $output);

    }
}
