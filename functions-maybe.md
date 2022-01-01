# May Change

Only change parameters which are in **bold**.

The ones ending in a "!" could allow `NULL`, but doing so is questionable - it might be worth taking it further, and deprecating an empty string as well.

## Encoding/Decoding

- `json_decode`(**json:string!**, associative:bool, depth:int, flags:int)
- `session_decode`(**data:string!**)
- `escapeshellcmd`(**command:string!**)
- `pack`(**format:string!**, values:mixed)
- `unpack`(**format:string!**, **string:string**, offset:int)
- `iconv_mime_encode`(**field_name:string!**, **field_value:string**, options:array)
- `mb_encode_mimeheader`(**string:string**, charset:string, transfer_encoding:string, **newline:string!**, indent:int)
- `pg_escape_identifier`(_connection:?_, **string:string!**)

## String Modification

- `ucwords`(**string:string**, **separators:string!**)
- `trim`(**string:string**, **characters:string!**)
- `ltrim`(**string:string**, **characters:string!**)
- `rtrim`(**string:string**, **characters:string!**)
- `chop`(**string:string**, **characters:string!**)
- `implode`(**separator:array|string!**, array:array)
- `join`(**separator:array|string!**, array:array)
- `chunk_split`(**string:string**, length:int, **separator:string!**)
- `strtr`(**string:string**, **from:array|string!**, to:string)
- `mb_split`(**pattern:string!**, **string:string**, limit:int)

## String Position

- `strpos`(**haystack:string**, **needle:string!**, offset:int)
- `strrpos`(**haystack:string**, **needle:string!**, offset:int)
- `stripos`(**haystack:string**, **needle:string!**, offset:int)
- `strripos`(**haystack:string**, **needle:string!**, offset:int)
- `iconv_strpos`(**haystack:string**, **needle:string!**, offset:int, encoding:string)
- `iconv_strrpos`(**haystack:string**, **needle:string!**, encoding:string)
- `mb_strpos`(**haystack:string**, **needle:string!**, offset:int, encoding:string)
- `mb_strrpos`(**haystack:string**, **needle:string!**, offset:int, encoding:string)
- `mb_stripos`(**haystack:string**, **needle:string!**, offset:int, encoding:string)
- `mb_strripos`(**haystack:string**, **needle:string!**, offset:int, encoding:string)
- `grapheme_strpos`(**haystack:string**, **needle:string!**, offset:int)
- `grapheme_strrpos`(**haystack:string**, **needle:string!**, offset:int)
- `grapheme_stripos`(**haystack:string**, **needle:string!**, offset:int)
- `grapheme_strripos`(**haystack:string**, **needle:string!**, offset:int)

## String Comparison

- `substr_compare`(**haystack:string**, **needle:string!**, offset:int, length:int, case_insensitive:bool)
- `str_contains`(**haystack:string**, **needle:string!**)
- `str_starts_with`(**haystack:string**, **needle:string!**)
- `str_ends_with`(**haystack:string**, **needle:string!**)
- `version_compare`(**version1:string!**, **version2:string!**, operator:string)

## String Details

- `strstr`(**haystack:string**, **needle:string!**, before_needle:bool)
- `strchr`(**haystack:string**, **needle:string!**, before_needle:bool)
- `stristr`(**haystack:string**, **needle:string!**, before_needle:bool)
- `strrchr`(**haystack:string**, **needle:string!**)
- `strspn`(**string:string**, **characters:string!**, offset:int, length:int)
- `strcspn`(**string:string**, **characters:string!**, offset:int, length:int)
- `ord`(**character:string!**)
- `mb_strstr`(**haystack:string**, **needle:string!**, before_needle:bool, encoding:string)
- `mb_strrchr`(**haystack:string**, **needle:string!**, before_needle:bool, encoding:string)
- `mb_stristr`(**haystack:string**, **needle:string!**, before_needle:bool, encoding:string)
- `mb_strrichr`(**haystack:string**, **needle:string!**, before_needle:bool, encoding:string)
- `grapheme_strstr`(**haystack:string**, **needle:string!**, beforeNeedle:bool)
- `grapheme_stristr`(**haystack:string**, **needle:string!**, beforeNeedle:bool)

## RegEx

- `mb_ereg_replace`(**pattern:string!**, **replacement:string**, **string:string**, options:string)
- `mb_eregi_replace`(**pattern:string!**, **replacement:string**, **string:string**, options:string)
- `mb_ereg_replace_callback`(**pattern:string!**, callback:callable, **string:string**, options:string)
- `mb_ereg_match`(**pattern:string!**, **string:string**, options:string)

## Normalising


## Hashing

- `hash_hmac`(algo:string, **data:string**, **key:string!**, binary:bool)
- `hash_pbkdf2`(algo:string, **password:string**, **salt:string!**, iterations:int, length:int, binary:bool)
- `crypt`(**string:string**, **salt:string!**)

## Files

- `basename`(**path:string**, **suffix:string!**)

## Output

- `output_add_rewrite_var`(**name:string!**, **value:string**)

## Parsing

- `sscanf`(**string:string**, **format:string!**, vars:mixed)
- `msgfmt_parse_message`(**locale:string!**, **pattern:string!**, **message:string**)

## CSV

- `str_getcsv`(**string:string**, **separator:string!**, **enclosure:string**, **escape:string**)

## Date

- `date_create`(**datetime:string!**, timezone:DateTimeZone)
- `date_create_immutable`(**datetime:string!**, timezone:DateTimeZone)
- `date_create_from_format`(**format:string!**, **datetime:string!**, timezone:DateTimeZone)
- `date_create_immutable_from_format`(**format:string!**, **datetime:string!**, timezone:DateTimeZone)
- `date_parse`(**datetime:string!**)
- `date_parse_from_format`(**format:string!**, **datetime:string!**)
- `date_format`(object:DateTimeInterface, **format:string!**)
- `datefmt_parse`(formatter:IntlDateFormatter, **string:string!**, _offset:?_)
- `datefmt_localtime`(formatter:IntlDateFormatter, **string:string!**, _offset:?_)

## Passwords

- `password_get_info`(**hash:string!**)
- `password_needs_rehash`(**hash:string!**, algo:string|int|null, options:array)
- `password_verify`(**password:string**, **hash:string!**)

## PSpell

- `pspell_new_personal`(**filename:string!**, language:string, **spelling:string**, **jargon:string**, **encoding:string**, mode:int)
- `pspell_config_personal`(config:PSpell\Config, **filename:string!**)
- `pspell_config_dict_dir`(config:PSpell\Config, **directory:string!**)
- `pspell_config_data_dir`(config:PSpell\Config, **directory:string!**)
- `pspell_config_repl`(config:PSpell\Config, **filename:string!**)

## Sodium

- `sodium_crypto_aead_aes256gcm_decrypt`(**ciphertext:string!**, **additional_data:string**, nonce:string, key:string)
- `sodium_crypto_aead_chacha20poly1305_decrypt`(**ciphertext:string!**, **additional_data:string**, nonce:string, key:string)
- `sodium_crypto_aead_chacha20poly1305_ietf_decrypt`(**ciphertext:string!**, **additional_data:string**, nonce:string, key:string)
- `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt`(**ciphertext:string!**, **additional_data:string**, nonce:string, key:string)
- `sodium_crypto_box_open`(**ciphertext:string!**, nonce:string, key_pair:string)
- `sodium_crypto_box_seal_open`(**ciphertext:string!**, key_pair:string)
- `sodium_crypto_pwhash_str_needs_rehash`(**password:string!**, opslimit:int, memlimit:int)
- `sodium_crypto_secretbox_open`(**ciphertext:string!**, nonce:string, key:string)
- `sodium_crypto_secretstream_xchacha20poly1305_pull`(state:string, **ciphertext:string!**, **additional_data:string**)

## DNS

- `gethostbyname`(**hostname:string!**)
- `gethostbynamel`(**hostname:string!**)
- `dns_get_record`(**hostname:string!**, type:int, _authoritative_name_servers:?_, _additional_records:?_, raw:bool)
- `dns_get_mx`(**hostname:string!**, _hosts:?_, _weights:?_)
- `getmxrr`(**hostname:string!**, _hosts:?_, _weights:?_)

## Logging

- `trigger_error`(**message:string!**, error_level:int)
- `user_error`(**message:string!**, error_level:int)
- `openlog`(**prefix:string!**, flags:int, facility:int)
- `syslog`(priority:int, **message:string!**)

## E-Mail

- `mail`(**to:string!**, **subject:string**, **message:string**, **additional_headers:array|string**, **additional_params:string**)
- `mb_send_mail`(**to:string!**, **subject:string**, **message:string**, **additional_headers:array|string**, additional_params:string)
