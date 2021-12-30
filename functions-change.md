# To Change

## Encoding/Decoding

- `urlencode`(**string:string**)
- `urldecode`(**string:string**)
- `rawurlencode`(**string:string**)
- `rawurldecode`(**string:string**)

- `base64_encode`(**string:string**)
- `base64_decode`(**string:string**, strict:bool)

- `utf8_encode`(**string:string**)
- `utf8_decode`(**string:string**)

- `bin2hex`(**string:string**)
- `hex2bin`(**string:string**)

- `bindec`(**binary_string:string**)
- `hexdec`(**hex_string:string**)
- `octdec`(**octal_string:string**)

- `base_convert`(**num:string**, from_base:int, to_base:int)

- `htmlspecialchars`(**string:string**, flags:int, encoding:string, double_encode:bool)
- `htmlspecialchars_decode`(**string:string**, flags:int)
- `html_entity_decode`(**string:string**, flags:int, encoding:string)
- `htmlentities`(**string:string**, flags:int, encoding:string, double_encode:bool)

- `json_decode`(**json:string**, associative:bool, depth:int, flags:int)

- `session_decode`(**data:string**)

- `addslashes`(**string:string**)
- `addcslashes`(**string:string**, **characters:string**)
- `stripslashes`(**string:string**)
- `stripcslashes`(**string:string**)

- `quotemeta`(**string:string**)

- `quoted_printable_decode`(**string:string**)
- `quoted_printable_encode`(**string:string**)

- `escapeshellcmd`(**command:string**)
- `escapeshellarg`(**arg:string**)

- `curl_escape`(handle:CurlHandle, **string:string**)
- `curl_unescape`(handle:CurlHandle, **string:string**)

- `convert_uuencode`(**string:string**)

- `zlib_encode`(**data:string**, encoding:int, level:int)

- `gzdeflate`(**data:string**, level:int, encoding:int)
- `gzencode`(**data:string**, level:int, encoding:int)
- `gzcompress`(**data:string**, level:int, encoding:int)
- `gzwrite`(_stream:?_, **data:string**, length:int)
- `gzputs`(_stream:?_, **data:string**, length:int)

- `deflate_add`(context:DeflateContext, **data:string**, flush_mode:int)
- `inflate_add`(context:InflateContext, **data:string**, flush_mode:int)

- `pack`(**format:string**, values:mixed)
- `unpack`(**format:string**, **string:string**, offset:int)

- `iconv_mime_encode`(**field_name:string**, **field_value:string**, options:array)
- `iconv_mime_decode`(**string:string**, mode:int, encoding:string)
- `iconv`(**from_encoding:string**, **to_encoding:string**, **string:string**)

- `sodium_bin2hex`(**string:string**)
- `sodium_hex2bin`(**string:string**, **ignore:string**)
- `sodium_bin2base64`(**string:string**, id:int)
- `sodium_base642bin`(**string:string**, id:int, **ignore:string**)

- `mb_convert_encoding`(**string:array|string**, to_encoding:string, from_encoding:array|string|null)
- `mb_detect_encoding`(**string:string**, encodings:array|string|null, strict:bool)
- `mb_encode_mimeheader`(**string:string**, charset:string, transfer_encoding:string, **newline:string**, indent:int)
- `mb_decode_mimeheader`(**string:string**)
- `mb_encode_numericentity`(**string:string**, map:array, encoding:string, hex:bool)
- `mb_decode_numericentity`(**string:string**, map:array, encoding:string)

- `transliterator_transliterate`(transliterator:Transliterator|string, **string:string**, start:int, end:int)

- `mysqli_real_escape_string`(mysql:mysqli, **string:string**)
- `mysqli_escape_string`(mysql:mysqli, **string:string**)

- ? `pg_escape_string`(_connection:?_, **string:string**)
- ? `pg_escape_bytea`(_connection:?_, **string:string**)
- ? `pg_unescape_bytea`(**string:string**)
- ? `pg_escape_literal`(_connection:?_, **string:string**)
- ? `pg_escape_identifier`(_connection:?_, **string:string**)

## String Modification

- `strtoupper`(**string:string**)
- `strtolower`(**string:string**)
- `ucfirst`(**string:string**)
- `lcfirst`(**string:string**)
- `ucwords`(**string:string**, **separators:string**)

- `trim`(**string:string**, **characters:string**)
- `ltrim`(**string:string**, **characters:string**)
- `rtrim`(**string:string**, **characters:string**)
- `chop`(**string:string**, **characters:string**)

- `str_rot13`(**string:string**)
- `str_shuffle`(**string:string**)

- `substr`(**string:string**, offset:int, length:int)
- `substr_replace`(**string:array|string**, **replace:array|string**, offset:array|int, length:array|int|null)
- `substr_count`(**haystack:string**, needle:string, offset:int, length:int)

- `explode`(separator:string, **string:string**, limit:int)
- `implode`(**separator:array|string**, array:array)
- `join`(**separator:array|string**, array:array)

- `strcoll`(**string1:string**, **string2:string**)
- `str_split`(**string:string**, length:int)
- `chunk_split`(**string:string**, length:int, **separator:string**)
- `wordwrap`(**string:string**, width:int, break:string, cut_long_words:bool)

- `strtr`(**string:string**, **from:array|string**, to:string)
- `strrev`(**string:string**)

- `str_replace`(**search:array|string**, **replace:array|string**, **subject:array|string**, _count:?_)
- `str_ireplace`(**search:array|string**, **replace:array|string**, **subject:array|string**, _count:?_)

- `str_repeat`(**string:string**, times:int)
- `str_pad`(**string:string**, length:int, pad_string:string, pad_type:int)

- `nl2br`(**string:string**, use_xhtml:bool)
- `strip_tags`(**string:string**, allowed_tags:array|string|null)

- `hebrev`(**string:string**, max_chars_per_line:int)

- `iconv_substr`(**string:string**, offset:int, length:int, encoding:string)

- `mb_strtoupper`(**string:string**, encoding:string)
- `mb_strtolower`(**string:string**, encoding:string)
- `mb_convert_case`(**string:string**, mode:int, encoding:string)
- `mb_convert_kana`(**string:string**, **mode:string**, encoding:string)
- `mb_scrub`(**string:string**, encoding:string)
- `mb_substr`(**string:string**, start:int, length:int, encoding:string)
- `mb_substr_count`(**haystack:string**, needle:string, encoding:string)
- `mb_str_split`(**string:string**, length:int, encoding:string)
- `mb_split`(**pattern:string**, **string:string**, limit:int)

- `sodium_pad`(**string:string**, block_size:int)

- `grapheme_substr`(**string:string**, offset:int, length:int)

## String Position

- `strpos`(**haystack:string**, **needle:string**, offset:int)
- `strrpos`(**haystack:string**, **needle:string**, offset:int)
- `stripos`(**haystack:string**, **needle:string**, offset:int)
- `strripos`(**haystack:string**, **needle:string**, offset:int)

- `iconv_strpos`(**haystack:string**, **needle:string**, offset:int, encoding:string)
- `iconv_strrpos`(**haystack:string**, **needle:string**, encoding:string)

- `mb_strpos`(**haystack:string**, **needle:string**, offset:int, encoding:string)
- `mb_strrpos`(**haystack:string**, **needle:string**, offset:int, encoding:string)
- `mb_stripos`(**haystack:string**, **needle:string**, offset:int, encoding:string)
- `mb_strripos`(**haystack:string**, **needle:string**, offset:int, encoding:string)

- `grapheme_strpos`(**haystack:string**, **needle:string**, offset:int)
- `grapheme_strrpos`(**haystack:string**, **needle:string**, offset:int)
- `grapheme_stripos`(**haystack:string**, **needle:string**, offset:int)
- `grapheme_strripos`(**haystack:string**, **needle:string**, offset:int)

## String Comparison

- `strcmp`(**string1:string**, **string2:string**)
- `strncmp`(**string1:string**, **string2:string**, length:int)
- `strcasecmp`(**string1:string**, **string2:string**)
- `strncasecmp`(**string1:string**, **string2:string**, length:int)
- `strnatcmp`(**string1:string**, **string2:string**)
- `strnatcasecmp`(**string1:string**, **string2:string**)
- `substr_compare`(**haystack:string**, **needle:string**, offset:int, length:int, case_insensitive:bool)
- `str_contains`(**haystack:string**, **needle:string**)
- `str_starts_with`(**haystack:string**, **needle:string**)
- `str_ends_with`(**haystack:string**, **needle:string**)
- `version_compare`(**version1:string**, **version2:string**, operator:string)
- `collator_compare`(object:Collator, **string1:string**, **string2:string**)
- `collator_get_sort_key`(object:Collator, **string:string**)

- `metaphone`(**string:string**, max_phonemes:int)
- `soundex`(**string:string**)
- `levenshtein`(**string1:string**, **string2:string**, insertion_cost:int, replacement_cost:int, deletion_cost:int)
- `similar_text`(**string1:string**, **string2:string**, _percent:?_)

- `sodium_compare`(**string1:string**, **string2:string**)
- `sodium_memcmp`(**string1:string**, **string2:string**)

## String Details

- `strlen`(**string:string**)
- `strstr`(**haystack:string**, **needle:string**, before_needle:bool)
- `strchr`(**haystack:string**, **needle:string**, before_needle:bool)
- `stristr`(**haystack:string**, **needle:string**, before_needle:bool)
- `strrchr`(**haystack:string**, **needle:string**)
- `strpbrk`(**string:string**, characters:string)
- `strspn`(**string:string**, **characters:string**, offset:int, length:int)
- `strcspn`(**string:string**, **characters:string**, offset:int, length:int)
- `strtok`(**string:string**, token:string)
- `str_word_count`(**string:string**, format:int, characters:string)
- `count_chars`(**string:string**, mode:int)
- `ord`(**character:string**)

- `iconv_strlen`(**string:string**, encoding:string)

- `mb_strlen`(**string:string**, encoding:string)
- `mb_strstr`(**haystack:string**, **needle:string**, before_needle:bool, encoding:string)
- `mb_strrchr`(**haystack:string**, **needle:string**, before_needle:bool, encoding:string)
- `mb_stristr`(**haystack:string**, **needle:string**, before_needle:bool, encoding:string)
- `mb_strrichr`(**haystack:string**, **needle:string**, before_needle:bool, encoding:string)
- `mb_strcut`(**string:string**, start:int, length:int, encoding:string)
- `mb_strwidth`(**string:string**, encoding:string)
- `mb_strimwidth`(**string:string**, start:int, width:int, **trim_marker:string**, encoding:string)

- `grapheme_strlen`(**string:string**)
- `grapheme_strstr`(**haystack:string**, **needle:string**, beforeNeedle:bool)
- `grapheme_stristr`(**haystack:string**, **needle:string**, beforeNeedle:bool)

## RegEx

- `preg_match`(pattern:string, **subject:string**, _matches:?_, flags:int, offset:int)
- `preg_match_all`(pattern:string, **subject:string**, _matches:?_, flags:int, offset:int)
- `preg_replace`(pattern:array|string, **replacement:array|string**, **subject:array|string**, limit:int, _count:?_)
- `preg_filter`(pattern:array|string, **replacement:array|string**, **subject:array|string**, limit:int, _count:?_)
- `preg_replace_callback`(pattern:array|string, callback:callable, **subject:array|string**, limit:int, _count:?_, flags:int)
- `preg_replace_callback_array`(pattern:array, **subject:array|string**, limit:int, _count:?_, flags:int)
- `preg_split`(pattern:string, **subject:string**, limit:int, flags:int)
- `preg_quote`(**str:string**, delimiter:string)

- `mb_ereg`(pattern:string, **string:string**, _matches:?_)
- `mb_eregi`(pattern:string, **string:string**, _matches:?_)
- `mb_ereg_replace`(**pattern:string**, **replacement:string**, **string:string**, options:string)
- `mb_eregi_replace`(**pattern:string**, **replacement:string**, **string:string**, options:string)
- `mb_ereg_replace_callback`(**pattern:string**, callback:callable, **string:string**, options:string)
- `mb_ereg_match`(**pattern:string**, **string:string**, options:string)
- `mb_ereg_search_init`(**string:string**, pattern:string, options:string)

? pattern:string, why can some be an empty string?

## Normalising

- `normalizer_normalize`(**string:string**, form:int)
- `normalizer_is_normalized`(**string:string**, form:int)
- `normalizer_get_raw_decomposition`(**string:string**, form:int)

## Hashing

- `hash`(algo:string, **data:string**, binary:bool, options:array)
- `hash_hmac`(algo:string, **data:string**, **key:string**, binary:bool)
- `hash_update`(context:HashContext, **data:string**)
- `hash_pbkdf2`(algo:string, **password:string**, **salt:string**, iterations:int, length:int, binary:bool)

- `crc32`(**string:string**)
- `md5`(**string:string**, binary:bool)
- `sha1`(**string:string**, binary:bool)
- `crypt`(**string:string**, **salt:string**)

## Files

- `basename`(**path:string**, **suffix:string**)
- `dirname`(**path:string**, levels:int)
- `pathinfo`(**path:string**, flags:int)

- `fwrite`(_stream:?_, **data:string**, length:int)
- `fputs`(_stream:?_, **data:string**, length:int)

## Output

- `setcookie`(name:string, **value:string**, expires_or_options:array|int, **path:string**, **domain:string**, secure:bool, httponly:bool)
- `setrawcookie`(name:string, **value:string**, expires_or_options:array|int, **path:string**, **domain:string**, secure:bool, httponly:bool)

- `output_add_rewrite_var`(**name:string**, **value:string**)

## Parsing

- `parse_url`(**url:string**, component:int)
- `parse_str`(**string:string**, _result:?_)

- `mb_parse_str`(**string:string**, _result:?_)

- `numfmt_parse`(formatter:NumberFormatter, **string:string**, type:int, _offset:?_)

- `parse_ini_string`(**ini_string:string**, process_sections:bool, scanner_mode:int)

- `sscanf`(**string:string**, **format:string**, vars:mixed)

- `locale_accept_from_http`(**header:string**)

- `msgfmt_parse`(formatter:MessageFormatter, **string:string**)
- `msgfmt_parse_message`(**locale:string**, **pattern:string**, **message:string**)

## E-Mail

- ? `mail`(**to:string**, **subject:string**, **message:string**, **additional_headers:array|string**, **additional_params:string**)
- ? `mb_send_mail`(**to:string**, **subject:string**, **message:string**, **additional_headers:array|string**, **additional_params:string**)

## CSV

- `str_getcsv`(**string:string**, **separator:string**, **enclosure:string**, **escape:string**)
- `fputcsv`(_stream:?_, fields:array, separator:string, enclosure:string, **escape:string**, eol:string)
- `fgetcsv`(_stream:?_, length:int, separator:string, enclosure:string, **escape:string**)

## Images

- `imagechar`(image:GdImage, font:GdFont|int, x:int, y:int, **char:string**, color:int)
- `imagecharup`(image:GdImage, font:GdFont|int, x:int, y:int, **char:string**, color:int)
- `imagestring`(image:GdImage, font:GdFont|int, x:int, y:int, **string:string**, color:int)
- `imagestringup`(image:GdImage, font:GdFont|int, x:int, y:int, **string:string**, color:int)
- `imageftbbox`(size:float, angle:float, font_filename:string, **string:string**, options:array)
- `imagefttext`(image:GdImage, size:float, angle:float, x:int, y:int, color:int, font_filename:string, **text:string**, options:array)
- `imagettfbbox`(size:float, angle:float, font_filename:string, **string:string**, options:array)
- `imagettftext`(image:GdImage, size:float, angle:float, x:int, y:int, color:int, font_filename:string, **text:string**, options:array)

## Passwords

- `password_get_info`(**hash:string**)
- `password_hash`(**password:string**, algo:string|int|null, options:array)
- `password_needs_rehash`(**hash:string**, algo:string|int|null, options:array)
- `password_verify`(**password:string**, **hash:string**)

## Stream

- ? `stream_socket_sendto`(_socket:?_, **data:string**, flags:int, **address:string**)
- ? `stream_get_line`(_stream:?_, length:int, **ending:string**)

## Socket

- ? `socket_write`(socket:Socket, **data:string**, length:int)
- ? `socket_send`(socket:Socket, **data:string**, length:int, flags:int)
- ? `socket_sendto`(socket:Socket, **data:string**, length:int, flags:int, address:string, port:int)

## BC Math

- `bcadd`(**num1:string**, **num2:string**, scale:int)
- `bcsub`(**num1:string**, **num2:string**, scale:int)
- `bcmul`(**num1:string**, **num2:string**, scale:int)
- `bcdiv`(**num1:string**, num2:string, scale:int)
- `bcmod`(**num1:string**, num2:string, scale:int)
- `bcpow`(**num:string**, **exponent:string**, scale:int)
- `bcpowmod`(**num:string**, **exponent:string**, modulus:string, scale:int)
- `bcsqrt`(**num:string**, scale:int)
- `bccomp`(**num1:string**, **num2:string**, scale:int)

## XML

- `simplexml_load_string`(**data:string**, class_name:string, options:int, **namespace_or_prefix:string**, is_prefix:bool)
- `xml_parser_create_ns`(encoding:string, **separator:string**)
- `xml_parse`(parser:XMLParser, **data:string**, is_final:bool)
- `xml_parse_into_struct`(parser:XMLParser, **data:string**, _values:?_, _index:?_)
- `xmlwriter_set_indent_string`(writer:XMLWriter, **indentation:string**)
- `xmlwriter_write_attribute`(writer:XMLWriter, name:string, **value:string**)
- `xmlwriter_write_attribute_ns`(writer:XMLWriter, prefix:string, name:string, namespace:string, **value:string**)
- `xmlwriter_write_pi`(writer:XMLWriter, target:string, **content:string**)
- `xmlwriter_write_cdata`(writer:XMLWriter, **content:string**)
- `xmlwriter_text`(writer:XMLWriter, **content:string**)
- `xmlwriter_write_raw`(writer:XMLWriter, **content:string**)
- `xmlwriter_write_comment`(writer:XMLWriter, **content:string**)
- `xmlwriter_write_dtd`(writer:XMLWriter, **name:string**, publicId:string, systemId:string, content:string)
- `xmlwriter_write_dtd_element`(writer:XMLWriter, name:string, **content:string**)
- `xmlwriter_write_dtd_attlist`(writer:XMLWriter, name:string, **content:string**)
- `xmlwriter_write_dtd_entity`(writer:XMLWriter, name:string, **content:string**, isParam:bool, publicId:string, systemId:string, notationData:string)

---

# TODO

- ? `trigger_error`(**message:string**, error_level:int)
- ? `user_error`(**message:string**, error_level:int)

- ? `date_create`(**datetime:string**, timezone:DateTimeZone)
- ? `date_create_immutable`(**datetime:string**, timezone:DateTimeZone)
- ? `date_create_from_format`(**format:string**, **datetime:string**, timezone:DateTimeZone)
- ? `date_create_immutable_from_format`(**format:string**, **datetime:string**, timezone:DateTimeZone)
- ? `date_parse`(**datetime:string**)
- ? `date_parse_from_format`(**format:string**, **datetime:string**)
- ? `date_format`(object:DateTimeInterface, **format:string**)
- ? `date_modify`(object:DateTime, **modifier:string**)
- ? `datefmt_parse`(formatter:IntlDateFormatter, **string:string**, _offset:?_)
- ? `datefmt_localtime`(formatter:IntlDateFormatter, **string:string**, _offset:?_)

- ? `grapheme_extract`(**haystack:string**, size:int, type:int, offset:int, _next:?_)

- ? `gethostbyaddr`(**ip:string**)
- ? `gethostbyname`(**hostname:string**)
- ? `gethostbynamel`(**hostname:string**)
- ? `dns_check_record`(**hostname:string**, **type:string**)
- ? `checkdnsrr`(**hostname:string**, **type:string**)
- ? `dns_get_record`(**hostname:string**, type:int, _authoritative_name_servers:?_, _additional_records:?_, raw:bool)
- ? `dns_get_mx`(**hostname:string**, _hosts:?_, _weights:?_)
- ? `getmxrr`(**hostname:string**, _hosts:?_, _weights:?_)

- ? `openlog`(**prefix:string**, flags:int, facility:int)
- ? `syslog`(priority:int, **message:string**)

- ? `sodium_crypto_aead_aes256gcm_decrypt`(**ciphertext:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_aes256gcm_encrypt`(**message:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_chacha20poly1305_decrypt`(**ciphertext:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_chacha20poly1305_encrypt`(**message:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_chacha20poly1305_ietf_decrypt`(**ciphertext:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_chacha20poly1305_ietf_encrypt`(**message:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt`(**ciphertext:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt`(**message:string**, **additional_data:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_auth`(**message:string**, **key:string**)
- ? `sodium_crypto_auth_verify`(**mac:string**, **message:string**, **key:string**)
- ? `sodium_crypto_box`(**message:string**, **nonce:string**, **key_pair:string**)
- ? `sodium_crypto_box_seed_keypair`(**seed:string**)
- ? `sodium_crypto_box_keypair_from_secretkey_and_publickey`(**secret_key:string**, **public_key:string**)
- ? `sodium_crypto_box_open`(**ciphertext:string**, **nonce:string**, **key_pair:string**)
- ? `sodium_crypto_box_publickey`(**key_pair:string**)
- ? `sodium_crypto_box_publickey_from_secretkey`(**secret_key:string**)
- ? `sodium_crypto_box_seal`(**message:string**, **public_key:string**)
- ? `sodium_crypto_box_seal_open`(**ciphertext:string**, **key_pair:string**)
- ? `sodium_crypto_box_secretkey`(**key_pair:string**)
- ? `sodium_crypto_core_ristretto255_add`(**p:string**, **q:string**)
- ? `sodium_crypto_core_ristretto255_from_hash`(**s:string**)
- ? `sodium_crypto_core_ristretto255_is_valid_point`(**s:string**)
- ? `sodium_crypto_core_ristretto255_scalar_add`(**x:string**, **y:string**)
- ? `sodium_crypto_core_ristretto255_scalar_complement`(**s:string**)
- ? `sodium_crypto_core_ristretto255_scalar_invert`(**s:string**)
- ? `sodium_crypto_core_ristretto255_scalar_mul`(**x:string**, **y:string**)
- ? `sodium_crypto_core_ristretto255_scalar_negate`(**s:string**)
- ? `sodium_crypto_core_ristretto255_scalar_reduce`(**s:string**)
- ? `sodium_crypto_core_ristretto255_scalar_sub`(**x:string**, **y:string**)
- ? `sodium_crypto_core_ristretto255_sub`(**p:string**, **q:string**)
- ? `sodium_crypto_kx_publickey`(**key_pair:string**)
- ? `sodium_crypto_kx_secretkey`(**key_pair:string**)
- ? `sodium_crypto_kx_seed_keypair`(**seed:string**)
- ? `sodium_crypto_kx_client_session_keys`(**client_key_pair:string**, **server_key:string**)
- ? `sodium_crypto_kx_server_session_keys`(**server_key_pair:string**, **client_key:string**)
- ? `sodium_crypto_generichash`(**message:string**, **key:string**, length:int)
- ? `sodium_crypto_generichash_init`(**key:string**, length:int)
- ? `sodium_crypto_generichash_update`(**state:string**, **message:string**)
- ? `sodium_crypto_generichash_final`(**state:string**, length:int)
- ? `sodium_crypto_kdf_derive_from_key`(subkey_length:int, subkey_id:int, **context:string**, **key:string**)
- ? `sodium_crypto_pwhash`(length:int, **password:string**, **salt:string**, opslimit:int, memlimit:int, algo:int)
- ? `sodium_crypto_pwhash_str`(**password:string**, opslimit:int, memlimit:int)
- ? `sodium_crypto_pwhash_str_verify`(**hash:string**, **password:string**)
- ? `sodium_crypto_pwhash_str_needs_rehash`(**password:string**, opslimit:int, memlimit:int)
- ? `sodium_crypto_pwhash_scryptsalsa208sha256`(length:int, **password:string**, **salt:string**, opslimit:int, memlimit:int)
- ? `sodium_crypto_pwhash_scryptsalsa208sha256_str`(**password:string**, opslimit:int, memlimit:int)
- ? `sodium_crypto_pwhash_scryptsalsa208sha256_str_verify`(**hash:string**, **password:string**)
- ? `sodium_crypto_scalarmult`(**n:string**, **p:string**)
- ? `sodium_crypto_scalarmult_ristretto255`(**n:string**, **p:string**)
- ? `sodium_crypto_scalarmult_ristretto255_base`(**n:string**)
- ? `sodium_crypto_secretbox`(**message:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_secretbox_open`(**ciphertext:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_secretstream_xchacha20poly1305_init_push`(**key:string**)
- ? `sodium_crypto_secretstream_xchacha20poly1305_push`(**state:string**, **message:string**, **additional_data:string**, tag:int)
- ? `sodium_crypto_secretstream_xchacha20poly1305_init_pull`(**header:string**, **key:string**)
- ? `sodium_crypto_secretstream_xchacha20poly1305_pull`(**state:string**, **ciphertext:string**, **additional_data:string**)
- ? `sodium_crypto_secretstream_xchacha20poly1305_rekey`(**state:string**)
- ? `sodium_crypto_shorthash`(**message:string**, **key:string**)
- ? `sodium_crypto_sign`(**message:string**, **secret_key:string**)
- ? `sodium_crypto_sign_detached`(**message:string**, **secret_key:string**)
- ? `sodium_crypto_sign_ed25519_pk_to_curve25519`(**public_key:string**)
- ? `sodium_crypto_sign_ed25519_sk_to_curve25519`(**secret_key:string**)
- ? `sodium_crypto_sign_keypair_from_secretkey_and_publickey`(**secret_key:string**, **public_key:string**)
- ? `sodium_crypto_sign_open`(**signed_message:string**, **public_key:string**)
- ? `sodium_crypto_sign_publickey`(**key_pair:string**)
- ? `sodium_crypto_sign_secretkey`(**key_pair:string**)
- ? `sodium_crypto_sign_publickey_from_secretkey`(**secret_key:string**)
- ? `sodium_crypto_sign_seed_keypair`(**seed:string**)
- ? `sodium_crypto_sign_verify_detached`(**signature:string**, **message:string**, **public_key:string**)
- ? `sodium_crypto_stream`(length:int, **nonce:string**, **key:string**)
- ? `sodium_crypto_stream_xor`(**message:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_stream_xchacha20`(length:int, **nonce:string**, **key:string**)
- ? `sodium_crypto_stream_xchacha20_xor`(**message:string**, **nonce:string**, **key:string**)
- ? `sodium_crypto_scalarmult_base`(**secret_key:string**)

- ? `pspell_new`(**language:string**, **spelling:string**, **jargon:string**, **encoding:string**, mode:int)
- ? `pspell_new_personal`(**filename:string**, **language:string**, **spelling:string**, **jargon:string**, **encoding:string**, mode:int)
- ? `pspell_check`(dictionary:PSpell\Dictionary, **word:string**)
- ? `pspell_suggest`(dictionary:PSpell\Dictionary, **word:string**)
- ? `pspell_store_replacement`(dictionary:PSpell\Dictionary, **misspelled:string**, **correct:string**)
- ? `pspell_add_to_personal`(dictionary:PSpell\Dictionary, **word:string**)
- ? `pspell_add_to_session`(dictionary:PSpell\Dictionary, **word:string**)
- ? `pspell_config_create`(**language:string**, **spelling:string**, **jargon:string**, **encoding:string**)
- ? `pspell_config_personal`(config:PSpell\Config, **filename:string**)
- ? `pspell_config_dict_dir`(config:PSpell\Config, **directory:string**)
- ? `pspell_config_data_dir`(config:PSpell\Config, **directory:string**)
- ? `pspell_config_repl`(config:PSpell\Config, **filename:string**)

- ? `pg_copy_to`(connection:PgSql\Connection, **table_name:string**, **separator:string**, **null_as:string**)
- ? `pg_copy_from`(connection:PgSql\Connection, **table_name:string**, rows:array, **separator:string**, **null_as:string**)