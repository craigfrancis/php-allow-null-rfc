# PHP RFC: Allow NULL

* Version: 1.1
* Voting Start: ?
* Voting End: ?
* RFC Started: 2021-12-23
* RFC Updated: 2021-12-31
* Author: Craig Francis, craig#at#craigfrancis.co.uk
* Status: Draft
* First Published at: https://wiki.php.net/rfc/allow_null
* GitHub Repo: https://github.com/craigfrancis/php-allow-null-rfc
* Implementation: ?

## Introduction

PHP 8.1 introduced "Deprecate passing null to non-nullable arguments of internal functions" ([short discussion](https://externals.io/message/112327)), which is making it difficult (time consuming) for developers to upgrade.

Often `NULL` is used for undefined `GET`/`POST`/`COOKIE` variables:

```php
$name = ($_POST['name'] ?? NULL);

$name = $request->input('name'); // Laravel
$name = $request->get('name'); // Symfony
$name = $this->request->getQuery('name'); // CakePHP
$name = $request->getGet('name'); // CodeIgniter
```

And `NULL` can be returned from functions, e.g.

* `array_pop()`
* `filter_input()`
* `mysqli_fetch_row()`
* `error_get_last()`
* `json_decode()`

Which makes it common for `NULL` to be passed to internal functions, e.g.

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

Another example is when PHP provides `NULL` for undefined variables, e.g.

```php
locale_accept_from_http($_SERVER['HTTP_ACCEPT_LANGUAGE']);
```

Or when developers explicitly use `NULL` to skip certain parameters, e.g. `$additional_headers` in `mail()`.

Currently this only affects those using PHP 8.1 with `E_DEPRECATED`, but it implies everyone will need to modify their code in the future - presumably this will be a **fatal error** in PHP 9.0, with a `TypeError` exception?

This also applies to those developers not using `strict_types=1`, which is excessive.

And while the individual changes are easy - there are many of them, they are difficult to find, and often pointless (e.g. `urlencode(strval($name))`).

Without the changes below, developers will need to either - use these deprecation notices, or use very strict Static Analysis (one that can determine when a variable can be `NULL`; e.g. Psalm at [level 3](https://psalm.dev/docs/running_psalm/error_levels/), with no baseline).

## Proposal

Update **some** internal function parameters to accept (be tolerant to) `NULL`.

This needs to be done before the eventual end of the deprecation period, and `TypeError` exceptions are thrown, which would create an unnecessary burden for developers to upgrade.

While this is in Draft, the [list of functions are hosted on GitHub](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions-change.md).

Only the parameters in **bold** would be changed.

Suggestions and pull requests welcome.

There is also a [Maybe List](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions-maybe.md), where the more questionable arguments end with a "!". For example, `strrpos()` accepting an empty string for `$needle` is wired in itself, and `sodium_crypto_box_open()` should never receive a blank `$ciphertext`.

## Decision Process

Does the parameter work with `NULL`, in the same way it would with an empty string? e.g.

- `preg_match()` should **deprecate** `NULL` for `$pattern` ("empty regular expression" warning).
- `preg_match()` should **accept** `NULL` for `$subject` (e.g. checking user input).
- `hash_file()` should **deprecate** `NULL` for the `$filename`.
- `hash()` should **accept** `NULL` for `$data`.
- `substr_count()` should **deprecate** `NULL` for `$needle` ("$needle cannot be empty" error).
- `mb_convert_encoding()` should **deprecate** `NULL` for `$to_encoding` (requires a valid encoding).

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

Is the [list of functions](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions-change.md) complete?

## Future Scope

Some functions parameters could be updated to complain when an Empty String or `NULL` is provided.

## Voting

Accept the RFC

TODO

## Patches and Tests

To get and **Test** the list of functions, I wrote a script to `get_defined_functions()`, then used `ReflectionFunction()` to identify parameters that accepted the 'string' type, and not `->allowsNull()`. This resulted in the [list of functions to change](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions-change.md), where I manually removed the [functions that shouldn't be changed](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions-other.md), and updated the script to test every argument (to see that it complained with `NULL`, and the output remained the same) - [Source](https://github.com/craigfrancis/php-allow-null-rfc/blob/main/functions.php).

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
