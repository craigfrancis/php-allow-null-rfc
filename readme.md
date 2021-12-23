# PHP RFC: Allow NULL

* Version: 1.0
* Voting Start: ?
* Voting End: ?
* RFC Started: 2021-12-23
* RFC Updated: 2021-12-23
* Author: Craig Francis, craig#at#craigfrancis.co.uk
* Status: ?
* First Published at: https://wiki.php.net/rfc/allow_null
* GitHub Repo: https://github.com/craigfrancis/php-allow-null-rfc
* Implementation: ?

## Introduction

PHP 8.1 introduced "Passing null to parameter X of type string is deprecated" with internal functions ([discussion](https://externals.io/message/112327)), which is making it difficult for developers to upgrade, even those not using `strict_types`.

Often `NULL` is used for undefined `GET`/`POST`/`COOKIE` variables:

```php
	$name = ($_POST['name'] ?? NULL);

	$name = $request->input('name'); // Laravel
	$name = $request->get('name'); // Symfony
	$name = $this->request->getQuery('name'); // CakePHP
	$name = $request->getGet('name'); // CodeIgniter
```

And `NULL` can be returned from functions like `array_pop()`, `error_get_last()`, `mysqli_fetch_row()`, `json_decode()`, `filter_input()`, etc.

While this currently only affects those using PHP 8.1 with `E_DEPRECATED`, it implies everyone will need to modify their code in the future.

And those modifications are not easy (both in finding them, and quantity).

Currently you either have to use these deprecation warnings, or use strict static analysis (one that can determine when a variable can be `NULL`, e.g. XXX at level XXX). This will affect every variable that could be set to `NULL`, which could be passed to any one of the internal functions that no longer accept NULL. And for each one, developers will need to do the seemingly pointless task of converting those `NULL` values to an empty string.

## Proposal

To make upgrading easier, we could either:

- Allow `NULL` when `strict_types` is not being used;
- Update some of the internal functions to accept `NULL`.

## Backward Incompatible Changes

N/A

## Proposed PHP Version(s)

PHP 8.1

## RFC Impact

### To SAPIs

None known

### To Existing Extensions

None known

### To Opcache

None known

## Open Issues

TODO

## Future Scope

TODO

## Voting

Accept the RFC

<doodle title="is_literal" auth="craigfrancis" voteType="single" closed="true">
   * Yes
   * No
</doodle>

## Patches and Tests

TODO

## Implementation

TODO

## Rejected Features

TODO



---

# Notes

grep -h -r -E '^\s*(ZEND_FUNCTION|PHP_FUNCTION|static void)|Z_PARAM_STR\(' ./php-src/

Search
	^(\s*(ZEND_FUNCTION|PHP_FUNCTION|static void).*\n)*(ZEND_FUNCTION\(|PHP_FUNCTION\(|static void *)(.+?)(\)|\().*
Replace
	$4


Quoting [[http://news.php.net/php.internals/71525|Rasmus]]:

> PHP is and should remain:
> 1) a pragmatic web-focused language
> 2) a loosely typed language
> 3) a language which caters to the skill-levels and platforms of a wide range of users
