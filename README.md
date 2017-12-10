# vWAF - Web Application Firewall

Free open-source, Web Application Firewall.

# Requirements

- [x] PHP 5.x+

# Features

- [x] XSS Vulnerabilities detection.
- [x] SQLi Vulnerabilities detection.
- [x] HTML Characters detection.
- [x] Lightweight.
- [x] CloudFlare and BlazingFast support.

# Sample Usage
```php
// Before everything.

require 'vwaf.php'; // Before everything, very important, include the class.

$vWAF = new vWAF(); // Define a var for the class.
$vWAF->init(); // Check all GET, POST & COOKIE's values and block if a malicious is detected.

// Your code below.
```
# Advanced Usage
```php
// Before everything.

require 'vwaf.php'; // Before everything, very important, include the class.

$vWAF = new vWAF(); // Define a var for the class.

// CloudFlare support [Optional]
$vWAF->CloudFlare();
// BlazingFast support [Optional]
$vWAF->BlazingFast();

// Check separated types.
$vWAF->Validate_GET();
$vWAF->Validate_POST();
$vWAF->Validate_COOKIE();

// Your code below.
```
# Example
Please look at index.php
