# PHP RFC: Allow NULL

* Version: 1.0
* Voting Start: ?
* Voting End: ?
* RFC Started: 2021-12-23
* RFC Updated: 2021-12-23
* Author: Craig Francis, craig#at#craigfrancis.co.uk
* Status: Draft
* First Published at: https://wiki.php.net/rfc/allow_null
* GitHub Repo: https://github.com/craigfrancis/php-allow-null-rfc
* Implementation: ?

## Introduction

PHP 8.1 introduced "Deprecate passing null to non-nullable arguments of internal functions" ([short discussion](https://externals.io/message/112327)), which is making it difficult for developers to upgrade.

Often `NULL` is used for undefined `GET`/`POST`/`COOKIE` variables:

```php
$name = ($_POST['name'] ?? NULL);

$name = $request->input('name'); // Laravel
$name = $request->get('name'); // Symfony
$name = $this->request->getQuery('name'); // CakePHP
$name = $request->getGet('name'); // CodeIgniter
```

And `NULL` can be returned from many functions, e.g.

* `array_pop()`
* `filter_input()`
* `mysqli_fetch_row()`
* `error_get_last()`
* `json_decode()`

Which makes it common for developers to pass potential `NULL` values to these internal functions, e.g.

```php
trim($name);
strtoupper($name);
strlen($name);
urlencode($name);
htmlspecialchars($name);
hash('sha256', $name);
preg_match('/^[a-z]/', $name);
setcookie('name', $name);
socket_write($socket, $name);
xmlwriter_text($writer, $name);
```

And sometimes a developer may explicitly use `NULL` to skip certain parameters, e.g. `$additional_headers` in `mail()`.

Currently this affects those using PHP 8.1 with `E_DEPRECATED`, but it implies everyone will need to modify their code in the future.

It also applies even if they are not using `strict_types=1`.

And while the individual modifications are easy, there are many of them, they are difficult to find, and often pointless (e.g. `urlencode(strval($name))`).

Without the changes listed below, developers will need to either use these deprecation warnings, or use strict Static Analysis (one that can determine when a variable can be `NULL`; e.g. Psalm at [level 3](https://psalm.dev/docs/running_psalm/error_levels/), with no baseline).

## Proposal

Update **some** internal function parameters to accept NULL, to reduce the burden for developers upgrading.

While this is in Draft, the [list of functions is hosted on GitHub](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions-change.md) (pull requests welcome):

## Decision Process

Does the parameter work with `NULL`, in the same way that it would if an empty string is provided? e.g.

- `preg_match()` should continue to deprecate `NULL` for `$pattern`, whereas `$subject` should accept `NULL`.
- `hash_file()` should continue to deprecate `NULL` for the `$filename`.
- `hash()` should accept `NULL` for `$data`.
- `substr_count()` requires a non-empty string `$needle` (continue to deprecate `NULL`).
- `mb_convert_encoding()` requires a valid encoding for `$to_encoding` (continue to deprecate `NULL`).

You could argue some function parameters should not accept an empty string (e.g. `strrpos()` accepting an empty string for `$needle`), but those should be addressed in a different RFC, involving a discussion on backwards compatibility for every change.

One set of candidates that could be removed are functions like `sodium_crypto_box_open()` where a blank `$ciphertext` will always return `false` (for failure).

## Backward Incompatible Changes

None

## Proposed PHP Version(s)

PHP 8.2

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

None

## Voting

Accept the RFC

TODO

## Patches and Tests

TODO

## Implementation

TODO

## Rejected Features

TODO

## Notes

Interesting the example quote from [Rasmus](http://news.php.net/php.internals/71525) is:

> PHP is and should remain:
> 1) a pragmatic web-focused language
> 2) a loosely typed language
> 3) a language which caters to the skill-levels and platforms of a wide range of users
