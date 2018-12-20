<?php

/**
 * PHP Class for handling Google Authenticator 2-factor authentication.
 * Tests.
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 *
 * @link http://www.phpgangsta.de/
 */
declare(strict_types=1);

namespace PHPGangsta\Tests;

use PHPGangsta\GoogleAuthenticator;
use PHPUnit\Framework\TestCase;
use RangeException;

/**
 * Google Authenticator Tests
 */
class GoogleAuthenticatorTest extends TestCase
{
    /**
     * @var GoogleAuthenticator
     */
    protected $googleAuthenticator;

    /**
     * Set up.
     */
    protected function setUp()
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    /**
     * Test if class ca be instantiated.
     *
     * @return void
     */
    public function testItCanBeInstantiated(): void
    {
        $this->assertInstanceOf(GoogleAuthenticator::class, (new GoogleAuthenticator()));
    }

    /**
     * Test create secret with default sixteen characters key.
     *
     * @return void
     */
    public function testCreateSecretDefaultsToSixteenCharacters(): void
    {
        $secret = $this->googleAuthenticator->createSecret();

        $this->assertEquals(strlen($secret), 16);
    }

    public function invalidLengtProvider(): array
    {
    }

    /**
     * Valid length provider.
     *
     * @return array
     */
    public function validLengthProvider(): array
    {
        $array = [];

        for ($i = 16; $i < 129; $i++) {
            $array[] = [$i];
        }

        return $array;
    }

    /**
     * Test create secret with valid secret length.
     *
     * @dataProvider validLengthProvider
     *
     * @return void
     */
    public function testCreateSecretWithValidSecretLength(int $secretLength): void
    {
        $this->assertEquals(strlen($this->googleAuthenticator->createSecret($secretLength)), $secretLength);
    }

    /**
     * Invalid length provider.
     *
     * @return array
     */
    public function invalidLengthProvider(): array
    {
        return [
            [12],
            [13],
            [14],
            [15],
            [129],
            [130],
            [131],
            [132],
        ];
    }

    /**
     * Test create secret with invalid secret length.
     *
     * @dataProvider invalidLengthProvider
     * @expectedException RangeException
     * @expectedExceptionMessage Bad secret length provided
     *
     * @return void
     */
    public function testCreateSecretWithInvalidSecretLength(int $secretLength): void
    {
        $this->assertEquals(strlen($this->googleAuthenticator->createSecret($secretLength)), $secretLength);
    }

    /**
     * Code Provider.
     *
     * @return array
     */
    public function codeProvider(): array
    {
        // Secret, time, code
        return [
            ['SECRET', 0, '857148'],
            ['SECRET', 1385909245, '979377'],
            ['SECRET', 1378934578, '560773'],
        ];
    }

    /**
     * Test if getCode returns correct values.
     *
     * @dataProvider codeProvider
     *
     * @param string $secret
     * @param int    $timeSlice
     * @param string $code
     *
     * @return void
     */
    public function testGetCodeReturnsCorrectValues(string $secret, int $timeSlice, string $code): void
    {
        $this->assertEquals($code, $this->googleAuthenticator->getCode($secret, $timeSlice));
    }

    /**
     * Test verifyCode.
     *
     * @return void
     */
    public function testVerifyCode(): void
    {
        $secret = 'SECRET';

        $code = $this->googleAuthenticator->getCode($secret);
        $this->assertEquals(true, $this->googleAuthenticator->verifyCode($secret, $code));

        $code = 'INVALIDCODE';
        $this->assertEquals(false, $this->googleAuthenticator->verifyCode($secret, $code));
    }

    /**
     * Test verifyCode with leading zero.
     *
     * @return void
     */
    public function testVerifyCodeWithLeadingZero(): void
    {
        $secret = 'SECRET';

        $code = $this->googleAuthenticator->getCode($secret);
        $this->assertEquals(true, $this->googleAuthenticator->verifyCode($secret, $code));

        $code = '0'.$code;
        $this->assertEquals(false, $this->googleAuthenticator->verifyCode($secret, $code));
    }
}
