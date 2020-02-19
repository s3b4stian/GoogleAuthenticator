<?php

/**
 * Decodes data encoded with MIME base32
 * https://tools.ietf.org/html/rfc4648
 *
 * @param string $data   The encoded data.
 *
 * @return string Function will return void string if the input contains a
 *                character outside the base 32 alphabet.
 */
function base32_decode(string $data): string
{
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $data = \rtrim($data, "=\x20\t\n\r\0\x0B");
    $dataSize = \strlen($data);
    $buf = 0;
    $bufSize = 0;
    $res = '';
    $charMap = \array_flip(\str_split($chars));

    $dataChars = \array_flip(\str_split($data));

    if (\count(\array_diff_key($dataChars, $charMap)) > 0) {
        return '';
    }

    unset($dataChars);

    for ($i = 0; $i < $dataSize; $i++) {
        $c = $data[$i];
        $b = $charMap[$c];
        $buf = ($buf << 5) | $b;
        $bufSize += 5;
        if ($bufSize > 7) {
            $bufSize -= 8;
            $b = ($buf & (0xff << $bufSize)) >> $bufSize;
            $res .= \chr($b);
        }
    }

    return $res;
}
