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
     * Code Provider.
     *
     * @return array
     */
    public function codeProvider(): array
    {
        // Secret, time, code
        return [
            ['SECRET', 0, '200470'],
            ['SECRET', 1385909245, '780018'],
            ['SECRET', 1378934578, '705013'],
        ];
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
        //$generatedCode = $this->googleAuthenticator->getCode($secret, $timeSlice);

        $this->assertEquals($code, $this->googleAuthenticator->getCode($secret, $timeSlice));
    }

    /**
     * Test if getQRCodeGoogleUrl returns correct url.
     *
     * @return void
     */
    public function testGetQRCodeGoogleUrlReturnsCorrectUrl(): void
    {
        $secret = 'SECRET';
        $name = 'Test';
        $url = $this->googleAuthenticator->getQRCodeGoogleUrl($name, $secret);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals($urlParts['scheme'], 'https');
        $this->assertEquals($urlParts['host'], 'chart.googleapis.com');
        $this->assertEquals($urlParts['path'], '/chart');

        $expectedChl = 'otpauth://totp/'.$name.'?secret='.$secret;

        $this->assertEquals($queryStringArray['chl'], $expectedChl);
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
        $result = $this->googleAuthenticator->verifyCode($secret, $code);

        $this->assertEquals(true, $result);

        $code = 'INVALIDCODE';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);

        $this->assertEquals(false, $result);
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
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(true, $result);

        $code = '0'.$code;
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);
    }

    /**
     * Test SetCodeLength.
     *
     * @return void
     */
    public function testSetCodeLength(): void
    {
        $this->assertInstanceOf(GoogleAuthenticator::class, $this->googleAuthenticator->setCodeLength(6));
    }
}
