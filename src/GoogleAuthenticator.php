<?php

/**
 * PHP Class for handling Google Authenticator 2-factor authentication.
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 *
 * @link http://www.phpgangsta.de/
 */
declare(strict_types=1);

namespace PHPGangsta;

use RangeException;

/**
 * Google Authenticator.
 */
class GoogleAuthenticator
{
    /**
     * base32 alphabet as rfc4648
     * https://tools.ietf.org/html/rfc4648
     */
    private const VALID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Code length
     */
    private const CODE_LENGTH = 6;

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param int $secretLength
     *
     * @return string
     *
     * @throws RangeException if secret length is less than 16 or grater than 128
     */
    public function createSecret(int $secretLength = 16): string
    {
        if ($secretLength < 16 || $secretLength > 128) {
            throw new RangeException('Bad secret length provided');
        }

        for ($secret = '', $i = 0; $i < $secretLength; ++$i) {
            $secret .= substr(self::VALID_CHARS, random_int(0, 31), 1);
        }

        return $secret;
    }

    /**
     * Calculate the code, with given secret and point in time.
     *
     * @param string   $secret
     * @param int|null $timeSlice
     *
     * @return string
     */
    public function getCode(string $secret, ?int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = (int) floor(time() / 30);
        }

        $secretkey = base32_decode($secret);

        // Pack time into binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);

        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretkey, true);

        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;

        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value and get only 32 bits
        $value = unpack('N', $hashpart)[1] & 0x7FFFFFFF;

        $modulo = pow(10, self::CODE_LENGTH);

        return str_pad((string)($value % $modulo), self::CODE_LENGTH, '0', STR_PAD_LEFT);
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string   $secret           Secret key
     * @param string   $code             Six digits code for verify
     * @param int      $discrepancy      This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param int|null $currentTimeSlice Time slice if we want use other that time()
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int $currentTimeSlice = null): bool
    {
        if ($currentTimeSlice === null) {
            $currentTimeSlice = (int) floor(time() / 30);
        }

        if (strlen($code) !== 6) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);

            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }
}
