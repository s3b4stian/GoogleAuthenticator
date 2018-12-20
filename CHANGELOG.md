
# Google Authenticator Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] [v2.00.0](https://github.com/linna/app/compare/master...v2.00.0) - 201X-XX-XX

### Added
* PHP 7.1 support 
* Strict type checking
* php-pds/skeleton compliant
* namespaces added for library and tests
* `src` directory
* `src/Functions.php` file, containing function for base32 decoding
* `CHANGELOG.md` file
* `phpunit.xml` file
* `.travis.yml` file
* `.scrutinizer.yml` file
* `.styleci.yml` file

### Changed
* `PHPGangsta\GoogleAuthenticator` methods refactor

### Removed
* `PHPGangsta` directory
* `PHPGangsta\GoogleAuthenticator->getQRCodeGoogleUrl()` method, google QR api deprecated
* `tests/bootstrap.php` file
* `tests/phpunit.xml` file
