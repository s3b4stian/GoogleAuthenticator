Google Authenticator PHP class
==============================

* Copyright (c) 2012-2016, [http://www.phpgangsta.de](http://www.phpgangsta.de)
* Author: Michael Kliewe, [@PHPGangsta](http://twitter.com/PHPGangsta) and [contributors](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
* Licensed under the BSD License.

[![Build Status](https://travis-ci.org/s3b4stian/GoogleAuthenticator.svg?branch=master)](https://travis-ci.org/s3b4stian/GoogleAuthenticator)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/s3b4stian/GoogleAuthenticator/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/s3b4stian/GoogleAuthenticator/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/s3b4stian/GoogleAuthenticator/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/s3b4stian/GoogleAuthenticator/?branch=master)
[![StyleCI](https://github.styleci.io/repos/162298866/shield?branch=master&style=flat)](https://github.styleci.io/repos/162298866)
[![PDS Skeleton](https://img.shields.io/badge/pds-skeleton-blue.svg?style=flat)](https://github.com/php-pds/skeleton)
[![PHP 7.1](https://img.shields.io/badge/PHP-7.1-8892BF.svg)](http://php.net)

This PHP class can be used to interact with the Google Authenticator mobile app for 2-factor-authentication. This class
can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret. It implements TOTP 
according to [RFC6238](https://tools.ietf.org/html/rfc6238)

For a secure installation you have to make sure that used codes cannot be reused (replay-attack). You also need to
limit the number of verifications, to fight against brute-force attacks. For example you could limit the amount of
verifications to 10 tries within 10 minutes for one IP address (or IPv6 block). It depends on your environment.

Differences with the original branch:
-------------------------------------
* PHP 7.1 support 
* Strict type checking
* php-pds/skeleton compliant
* namespaces added for library and tests
* Google QR code url removed beacause Google QR api are deprecated

Usage:
------

See following example:

```php
<?php
include '../GoogleAuthenticator/vendor/autoload.php';

use PHPGangsta\GoogleAuthenticator;

$ga = new GoogleAuthenticator();
$secret = $ga->createSecret();
echo "Secret is: ".$secret."\n\n";

$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

$checkResult = $ga->verifyCode($secret, $oneCode, 2);    // 2 = 2*30sec clock tolerance
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}
```
Running the script provides the following output:
```
Secret is: OQB6ZZGYHCPSX4AK

Checking Code '848634' and Secret 'OQB6ZZGYHCPSX4AK':
OK
```

Installation:
-------------

- Use [Composer](https://getcomposer.org/doc/01-basic-usage.md) to
  install the package

- From project root directory execute following

```composer install```

- [Composer](https://getcomposer.org/doc/01-basic-usage.md) will take care of autoloading
  the library. Just include the following at the top of your file

  `require_once __DIR__ . '/../vendor/autoload.php';`

Run Tests:
----------

- All tests are inside `tests` folder.
- Execute `composer install` and then run the tests from project root
  directory
- Run `phpunit` from the project root directory


Notes:
------

If you like this script or have some features to add: contact me, visit my blog, fork this project, send pull requests, you know how it works.
