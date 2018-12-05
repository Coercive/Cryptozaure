Coercive Security Cryptozaure
=============================

Project in works. For research only.

Get
---
```
composer require coercive/cryptozaure
```

Example
-------
```php
$text = '⊗ ✘ Top Secret Information ✘ ⊗';
$pass = 'helloWord123';
$prefix = 'test_';

$encrypted = (new Cryptozaure($text, $pass, $prefix))->encrypt();
$decrypted = (new Cryptozaure($encrypted, $pass, $prefix))->decrypt();
```