<?php

//--------------------------------------------------
// Error handler

	$GLOBALS['null_errors'] = [];

	function error_handler($err_no, $err_str, $err_file, $err_line) {
		if ($err_no === E_DEPRECATED && preg_match('/^([^\)]+)\(\): Passing null to parameter #([0-9]+) .* of type .* is deprecated$/', $err_str, $err_match)) {
			$GLOBALS['null_errors'][$err_match[1]][$err_match[2]] = $err_line;
			return true;
		} else if ($err_no == E_USER_NOTICE && $err_str == '') {
			return true; // `trigger_error` test
		}
		return false;
	}

	set_error_handler('error_handler');

//--------------------------------------------------
// Test function

	$GLOBALS['tested_functions'] = [];

	function test($function, $arg, $a, $b) {

		$called_from = debug_backtrace();
		$called_from_line = $called_from[0]['line'];

		$error_line = ($GLOBALS['null_errors'][$function][$arg] ?? NULL);

		if ($a instanceof PSpell\Dictionary && $b instanceof PSpell\Dictionary) {
			$a = '-';
			$b = '-';
		} else if ($a instanceof PSpell\Config && $b instanceof PSpell\Config) {
			$a = '-';
			$b = '-';
		} else if ($a instanceof XMLParser && $b instanceof XMLParser) {
			$a = '-';
			$b = '-';
		} else if ($a instanceof SimpleXMLElement && $b instanceof SimpleXMLElement) {
			$a = $a->asXML();
			$b = $b->asXML();
		} else if ($a instanceof DateTime && $b instanceof DateTime) {
			$a = $a->getTimestamp(); // Do not include sub-second resolution
			$b = $b->getTimestamp();
		} else if ($a instanceof DateTimeImmutable && $b instanceof DateTimeImmutable) {
			$a = $a->getTimestamp(); // Do not include sub-second resolution
			$b = $b->getTimestamp();
		}

		// if ($a === false) echo $called_from_line . ' ' . $function . ' - False A.' . "\n";
		// if ($b === false) echo $called_from_line . ' ' . $function . ' - False B.' . "\n";

		if ($a !== $b) {
			echo $called_from_line . ' ' . $function . ' - Values do not match.' . "\n";
		} else if ($error_line === NULL) {
			echo $called_from_line . ' ' . $function . ' - Did not trigger error.' . "\n";
		} else if ($error_line !== $called_from_line) {
			echo $called_from_line . ' ' . $function . ' - Triggered error on different line (' . $error_line . ').' . "\n";
		} else {
			unset($GLOBALS['null_errors'][$function][$arg]);
			if (count($GLOBALS['null_errors'][$function]) == 0) {
				unset($GLOBALS['null_errors'][$function]);
			}
			$GLOBALS['tested_functions'][$function][] = $arg;
		}

	}

//--------------------------------------------------
// Config

	$tmp_file = tempnam(sys_get_temp_dir(), '.allow-null');

	$ignore_nullable = [];

//--------------------------------------------------
// Tests

	//--------------------------------------------------
	// Encoding/Decoding

		test('urlencode', 1, urlencode(''), urlencode(NULL));
		test('urldecode', 1, urldecode(''), urldecode(NULL));

		test('rawurlencode', 1, rawurlencode(''), rawurlencode(NULL));
		test('rawurldecode', 1, rawurldecode(''), rawurldecode(NULL));

		test('base64_encode', 1, base64_encode(''), base64_encode(NULL));
		test('base64_decode', 1, base64_decode(''), base64_decode(NULL));

		test('utf8_encode', 1, utf8_encode(''), utf8_encode(NULL));
		test('utf8_decode', 1, utf8_decode(''), utf8_decode(NULL));

		test('bin2hex', 1, bin2hex(''), bin2hex(NULL));
		test('hex2bin', 1, hex2bin(''), hex2bin(NULL));
		test('bindec', 1, bindec(''), bindec(NULL));
		test('hexdec', 1, hexdec(''), hexdec(NULL));
		test('octdec', 1, octdec(''), octdec(NULL));

		test('base_convert', 1, base_convert('', 16, 2), base_convert(NULL, 16, 2));

		test('htmlspecialchars', 1, htmlspecialchars(''), htmlspecialchars(NULL));
		test('htmlspecialchars_decode', 1, htmlspecialchars_decode(''), htmlspecialchars_decode(NULL));
		test('html_entity_decode', 1, html_entity_decode(''), html_entity_decode(NULL));
		test('htmlentities', 1, htmlentities(''), htmlentities(NULL));

		test('json_decode', 1, json_decode(''), json_decode(NULL));

		session_start();
		test('session_decode', 1, session_decode(''), session_decode(NULL));

		test('addslashes', 1, addslashes(''), addslashes(NULL));
		test('addcslashes', 1, addcslashes('', 'A..z'), addcslashes(NULL, 'A..z'));
		test('addcslashes', 2, addcslashes('A', ''), addcslashes('A', NULL));
		test('stripslashes', 1, stripslashes(''), stripslashes(NULL));
		test('stripcslashes', 1, stripcslashes(''), stripcslashes(NULL));
		test('quotemeta', 1, quotemeta(''), quotemeta(NULL));
		test('quoted_printable_decode', 1, quoted_printable_decode(''), quoted_printable_decode(NULL));
		test('quoted_printable_encode', 1, quoted_printable_encode(''), quoted_printable_encode(NULL));

		test('escapeshellcmd', 1, escapeshellcmd(''), escapeshellcmd(NULL));
		test('escapeshellarg', 1, escapeshellarg(''), escapeshellarg(NULL));

		$ch = curl_init();
		test('curl_escape', 2, curl_escape($ch, ''), curl_escape($ch, NULL));
		test('curl_unescape', 2, curl_unescape($ch, ''), curl_unescape($ch, NULL));

		test('convert_uuencode', 1, convert_uuencode(''), convert_uuencode(NULL));

		test('zlib_encode', 1, zlib_encode('', ZLIB_ENCODING_DEFLATE), zlib_encode(NULL, ZLIB_ENCODING_DEFLATE));

		test('gzdeflate', 1, gzdeflate(''), gzdeflate(NULL));
		test('gzencode', 1, gzencode(''), gzencode(NULL));
		test('gzcompress', 1, gzcompress(''), gzcompress(NULL));
		$gz = gzopen($tmp_file,'w9');
		test('gzwrite', 2, gzwrite($gz, ''), gzwrite($gz, NULL));
		test('gzputs', 2, gzputs($gz, ''), gzputs($gz, NULL)); // Alias of gzwrite
		gzclose($gz);

		$de = deflate_init(ZLIB_ENCODING_DEFLATE);
		test('deflate_add', 2, deflate_add($de, ''), deflate_add($de, NULL));
		$in = inflate_init(ZLIB_ENCODING_DEFLATE);
		test('inflate_add', 2, inflate_add($in, ''), inflate_add($in, NULL));

		test('pack', 1, pack(''), pack(NULL));
		test('unpack', 1, unpack('', ''), unpack(NULL, ''));
		test('unpack', 2, unpack('X', ''), unpack('X', NULL));

		test('iconv_mime_encode', 1, iconv_mime_encode('', 'A'), iconv_mime_encode(NULL, 'A'));
		test('iconv_mime_encode', 2, iconv_mime_encode('A', ''), iconv_mime_encode('A', NULL));
		test('iconv_mime_decode', 1, iconv_mime_decode(''), iconv_mime_decode(NULL));
		test('iconv', 1, iconv('', 'ISO-8859-1', 'A'), iconv(NULL, 'ISO-8859-1', 'A'));
		test('iconv', 2, iconv('UTF-8', '', 'A'), iconv('UTF-8', NULL, 'A'));
		test('iconv', 3, iconv('UTF-8', 'ISO-8859-1', ''), iconv('UTF-8', 'ISO-8859-1', NULL));

		test('sodium_bin2hex', 1, sodium_bin2hex(''), sodium_bin2hex(NULL));
		test('sodium_hex2bin', 1, sodium_hex2bin(''), sodium_hex2bin(NULL));
		test('sodium_hex2bin', 2, sodium_hex2bin(31, ''), sodium_hex2bin(31, NULL));
		test('sodium_bin2base64', 1, sodium_bin2base64('', SODIUM_BASE64_VARIANT_ORIGINAL), sodium_bin2base64(NULL, SODIUM_BASE64_VARIANT_ORIGINAL));
		test('sodium_base642bin', 1, sodium_base642bin('', SODIUM_BASE64_VARIANT_ORIGINAL), sodium_base642bin(NULL, SODIUM_BASE64_VARIANT_ORIGINAL));
		test('sodium_base642bin', 3, sodium_base642bin('QQ==', SODIUM_BASE64_VARIANT_ORIGINAL, ''), sodium_base642bin('QQ==', SODIUM_BASE64_VARIANT_ORIGINAL, NULL));

		test('mb_convert_encoding', 1, mb_convert_encoding('', 'UTF-8', 'ISO-8859-1'), mb_convert_encoding(NULL, 'UTF-8', 'ISO-8859-1'));
		// test('mb_convert_encoding', 2, mb_convert_encoding('a', 'UTF-8', ''), mb_convert_encoding('a', 'UTF-8', NULL)); // must specify at least one encoding
		$ignore_nullable['mb_convert_encoding'][] = '2:to_encoding';
		test('mb_detect_encoding', 1, mb_detect_encoding(''), mb_detect_encoding(NULL));
		test('mb_encode_mimeheader', 1, mb_encode_mimeheader(''), mb_encode_mimeheader(NULL));
		test('mb_encode_mimeheader', 3, mb_encode_mimeheader('A', 'UTF-8', ''), mb_encode_mimeheader('A', 'UTF-8', NULL)); // Oddity with transfer_encoding, complains when in theory it can be NULL?
		test('mb_encode_mimeheader', 4, mb_encode_mimeheader('A', 'UTF-8', 'B', ''), mb_encode_mimeheader('A', 'UTF-8', 'B', NULL));
		test('mb_decode_mimeheader', 1, mb_decode_mimeheader(''), mb_decode_mimeheader(NULL));
		test('mb_encode_numericentity', 1, mb_encode_numericentity('', [0x80, 0xff, 0, 0xff]), mb_encode_numericentity(NULL, [0x80, 0xff, 0, 0xff]));
		test('mb_decode_numericentity', 1, mb_decode_numericentity('', [0x80, 0xff, 0, 0xff]), mb_decode_numericentity(NULL, [0x80, 0xff, 0, 0xff]));

		// test('transliterator_transliterate', 2, transliterator_transliterate('', 'a'), transliterator_transliterate(NULL, 'a')); // Could not create transliterator with ID "")
		$ignore_nullable['transliterator_transliterate'][] = '1:transliterator';
		test('transliterator_transliterate', 2, transliterator_transliterate('Hex-Any/Java', ''), transliterator_transliterate('Hex-Any/Java', NULL));

		$mysqli = new mysqli('localhost', 'test', 'test', 'test');
		test('mysqli_real_escape_string', 2, mysqli_real_escape_string($mysqli, ''), mysqli_real_escape_string($mysqli, NULL));
		test('mysqli_escape_string', 2, mysqli_escape_string($mysqli, ''), mysqli_escape_string($mysqli, NULL)); // Alias of mysqli_real_escape_string

		$pg = pg_connect('dbname=test user=craig');
		test('pg_escape_string', 2, pg_escape_string($pg, ''), pg_escape_string($pg, NULL));
		test('pg_escape_bytea', 2, pg_escape_bytea($pg, ''), pg_escape_bytea($pg, NULL));
		test('pg_unescape_bytea', 1, pg_unescape_bytea(''), pg_unescape_bytea(NULL));
		test('pg_escape_literal', 2, pg_escape_literal($pg, ''), pg_escape_literal($pg, NULL));
		test('pg_escape_identifier', 2, pg_escape_identifier($pg, ''), pg_escape_identifier($pg, NULL));
		// test('pg_copy_to', 2, pg_copy_to($pg, '', '|', 'NULL'), pg_copy_to($pg, NULL, '|', 'NULL')); // syntax error at or near
		// test('pg_copy_to', 3, pg_copy_to($pg, 'users', '', 'NULL'), pg_copy_to($pg, 'users', NULL, 'NULL')); // must be one character
		test('pg_copy_to', 4, pg_copy_to($pg, 'users', '|', ''), pg_copy_to($pg, 'users', '|', NULL));
		$ignore_nullable['pg_copy_to'][] = '2:table_name';
		$ignore_nullable['pg_copy_to'][] = '3:separator';
		// test('pg_copy_from', 2, pg_copy_from($pg, '', ['1|Amy'], '|', 'NULL'), pg_copy_from($pg, NULL, ['1|Amy'], '|', 'NULL')); // syntax error at or near
		// test('pg_copy_from', 4, pg_copy_from($pg, 'users', ['1|Amy'], '', 'NULL'), pg_copy_from($pg, 'users', ['1|Amy'], NULL, 'NULL')); must be one character
		test('pg_copy_from', 5, pg_copy_from($pg, 'users', ['1|Amy'], '|', ''), pg_copy_from($pg, 'users', ['1|Amy'], '|', NULL));
		$ignore_nullable['pg_copy_from'][] = '2:table_name';
		$ignore_nullable['pg_copy_from'][] = '4:separator';

	//--------------------------------------------------
	// String Modification

		test('strtoupper', 1, strtoupper(''), strtoupper(NULL));
		test('strtolower', 1, strtolower(''), strtolower(NULL));

		test('ucfirst', 1, ucfirst(''), ucfirst(NULL));
		test('lcfirst', 1, lcfirst(''), lcfirst(NULL));
		test('ucwords', 1, ucwords(''), ucwords(NULL));
		test('ucwords', 2, ucwords('a', ''), ucwords('a', NULL));

		test('trim', 1, trim(''), trim(NULL));
		test('trim', 2, trim('a', ''), trim('a', NULL));
		test('ltrim', 1, ltrim(''), ltrim(NULL));
		test('ltrim', 2, ltrim('a', ''), ltrim('a', NULL));
		test('rtrim', 1, rtrim(''), rtrim(NULL));
		test('rtrim', 2, rtrim('a', ''), rtrim('a', NULL));

		test('chop', 1, chop(''), chop(NULL));
		test('chop', 2, chop('a', ''), chop('a', NULL));

		test('str_rot13', 1, str_rot13(''), str_rot13(NULL));
		test('str_shuffle', 1, str_shuffle(''), str_shuffle(NULL));

		test('substr', 1, substr('', 0), substr(NULL, 0));
		test('substr_replace', 1, substr_replace('', 'a', 0), substr_replace(NULL, 'a', 0));
		test('substr_replace', 2, substr_replace('a', '', 0), substr_replace('a', NULL, 0));
		test('substr_count', 1, substr_count('', 'a'), substr_count(NULL, 'a'));
		// test('substr_count', 2, substr_count('a', ''), substr_count('a', NULL)); // cannot be empty in
		$ignore_nullable['substr_count'][] = '2:needle';

		// test('explode', 1, explode('', 'a'), explode(NULL, 'a')); // cannot be empty
		$ignore_nullable['explode'][] = '1:separator';
		test('explode', 2, explode(' ', ''), explode(' ', NULL));
		test('implode', 1, implode('', []), implode(NULL, []));
		test('join', 1, join('', []), join(NULL, [])); // Alias of implode

		test('strcoll', 1, strcoll('', ''), strcoll(NULL, ''));
		test('strcoll', 2, strcoll('', ''), strcoll('', NULL));

		test('str_split', 1, str_split(''), str_split(NULL));

		test('chunk_split', 1, chunk_split(''), chunk_split(NULL));
		test('chunk_split', 3, chunk_split('a', 10, ''), chunk_split('a', 10, NULL));

		test('wordwrap', 1, wordwrap(''), wordwrap(NULL));
		// test('wordwrap', 1, wordwrap('a', 10, ''), wordwrap('a', 10, NULL)); // cannot be empty
		$ignore_nullable['wordwrap'][] = '3:break';

		test('strtr', 1, strtr('', 'a', 'ä'), strtr(NULL, 'a', 'ä'));
		test('strtr', 2, strtr('a', '', 'ä'), strtr('a', NULL, 'ä'));
		// test('strtr', 3, strtr('a', 'a', ''), strtr('a', 'a', NULL)); // Does not work

		test('strrev', 1, strrev(''), strrev(NULL));

		test('str_replace', 1, str_replace('', 'a', 'ä'), str_replace(NULL, 'a', 'ä'));
		test('str_replace', 2, str_replace('a', '', 'ä'), str_replace('a', NULL, 'ä'));
		test('str_replace', 3, str_replace('a', 'a', ''), str_replace('a', 'a', NULL));
		test('str_ireplace', 1, str_ireplace('', 'a', 'ä'), str_ireplace(NULL, 'a', 'ä'));
		test('str_ireplace', 2, str_ireplace('a', '', 'ä'), str_ireplace('a', NULL, 'ä'));
		test('str_ireplace', 3, str_ireplace('a', 'a', ''), str_ireplace('a', 'a', NULL));

		test('str_repeat', 1, str_repeat('', 10), str_repeat(NULL, 10));

		test('str_pad', 1, str_pad('', 10), str_pad(NULL, 10));
		// test('str_pad', 3, str_pad('a', 10, ''), str_pad('a', 10, NULL)); // must be a non-empty string
		$ignore_nullable['str_pad'][] = '3:pad_string';

		test('nl2br', 1, nl2br(''), nl2br(NULL));

		test('strip_tags', 1, strip_tags(''), strip_tags(NULL));

		test('hebrev', 1, hebrev(''), hebrev(NULL));

		test('iconv_substr', 1, iconv_substr('', 0), iconv_substr(NULL, 0));

		test('mb_strtoupper', 1, mb_strtoupper(''), mb_strtoupper(NULL));
		test('mb_strtolower', 1, mb_strtolower(''), mb_strtolower(NULL));
		test('mb_convert_case', 1, mb_convert_case('', MB_CASE_UPPER), mb_convert_case(NULL, MB_CASE_UPPER));
		test('mb_convert_kana', 1, mb_convert_kana(''), mb_convert_kana(NULL));
		test('mb_convert_kana', 2, mb_convert_kana('a', ''), mb_convert_kana('a', NULL));
		test('mb_scrub', 1, mb_scrub(''), mb_scrub(NULL));
		test('mb_substr', 1, mb_substr('', 0), mb_substr(NULL, 0));
		test('mb_substr_count', 1, mb_substr_count('', 'a'), mb_substr_count(NULL, 'a'));
		// test('mb_substr_count', 2, mb_substr_count('a', ''), mb_substr_count('a', NULL)); // must not be empty
		$ignore_nullable['mb_substr_count'][] = '2:needle';
		test('mb_str_split', 1, mb_str_split(''), mb_str_split(NULL));
		test('mb_split', 1, mb_split('', 'a'), mb_split(NULL, 'a')); // Weird, but works.
		test('mb_split', 2, mb_split('a', ''), mb_split('a', NULL));

		test('sodium_pad', 1, sodium_pad('', 1), sodium_pad(NULL, 1));
		// test('sodium_unpad', 1, sodium_unpad('', 0), sodium_unpad(NULL, 0)); // $string must be at least as long as the block size... and $block_size must be greater than 0
		// $b = '';
		// $n = NULL;
		// test('sodium_add', 1, sodium_add($b, $n), sodium_add($b, $n));
		// test('sodium_add', 2, sodium_add($n, $b), sodium_add($n, $b)); // Uncaught SodiumException: PHP strings are required
		// test('sodium_increment', 1, sodium_increment($b), sodium_increment($n)); // Uncaught SodiumException: a PHP string is required

		test('grapheme_substr', 1, grapheme_substr('', 0), grapheme_substr(NULL, 0));
		test('grapheme_extract', 1, grapheme_extract('', 1), grapheme_extract(NULL, 1));

	//--------------------------------------------------
	// String Position

		test('strpos', 1, strpos('', 'a'), strpos(NULL, 'a'));
		test('strpos', 2, strpos('a', ''), strpos('a', NULL));
		test('strrpos', 1, strrpos('', 'a'), strrpos(NULL, 'a'));
		test('strrpos', 2, strrpos('a', ''), strrpos('a', NULL));
		test('stripos', 1, stripos('', 'a'), stripos(NULL, 'a'));
		test('stripos', 2, stripos('a', ''), stripos('a', NULL));
		test('strripos', 1, strripos('', 'a'), strripos(NULL, 'a'));
		test('strripos', 2, strripos('a', ''), strripos('a', NULL));

		test('iconv_strpos', 1, iconv_strpos('', 'a'), iconv_strpos(NULL, 'a'));
		test('iconv_strpos', 2, iconv_strpos('a', ''), iconv_strpos('a', NULL));
		test('iconv_strrpos', 1, iconv_strrpos('', 'a'), iconv_strrpos(NULL, 'a'));
		test('iconv_strrpos', 2, iconv_strrpos('a', ''), iconv_strrpos('a', NULL));

		test('mb_strpos', 1, mb_strpos('', 'a'), mb_strpos(NULL, 'a'));
		test('mb_strpos', 2, mb_strpos('a', ''), mb_strpos('a', NULL));
		test('mb_strrpos', 1, mb_strrpos('', 'a'), mb_strrpos(NULL, 'a'));
		test('mb_strrpos', 2, mb_strrpos('a', ''), mb_strrpos('a', NULL));
		test('mb_stripos', 1, mb_stripos('', 'a'), mb_stripos(NULL, 'a'));
		test('mb_stripos', 2, mb_stripos('a', ''), mb_stripos('a', NULL));
		test('mb_strripos', 1, mb_strripos('', 'a'), mb_strripos(NULL, 'a'));
		test('mb_strripos', 2, mb_strripos('a', ''), mb_strripos('a', NULL));

		test('grapheme_strpos', 1, grapheme_strpos('', 'a'), grapheme_strpos(NULL, 'a'));
		test('grapheme_strpos', 2, grapheme_strpos('a', ''), grapheme_strpos('a', NULL));
		test('grapheme_strrpos', 1, grapheme_strrpos('', 'a'), grapheme_strrpos(NULL, 'a'));
		test('grapheme_strrpos', 2, grapheme_strrpos('a', ''), grapheme_strrpos('a', NULL));
		test('grapheme_stripos', 1, grapheme_stripos('', 'a'), grapheme_stripos(NULL, 'a'));
		test('grapheme_stripos', 2, grapheme_stripos('a', ''), grapheme_stripos('a', NULL));
		test('grapheme_strripos', 1, grapheme_strripos('', 'a'), grapheme_strripos(NULL, 'a'));
		test('grapheme_strripos', 2, grapheme_strripos('a', ''), grapheme_strripos('a', NULL));

	//--------------------------------------------------
	// String Comparison

		test('strcmp', 1, strcmp('', 'a'), strcmp(NULL, 'a'));
		test('strcmp', 2, strcmp('a', ''), strcmp('a', NULL));
		test('strncmp', 1, strncmp('', 'a', 1), strncmp(NULL, 'a', 1));
		test('strncmp', 2, strncmp('a', '', 1), strncmp('a', NULL, 1));
		test('strcasecmp', 1, strcasecmp('', 'a'), strcasecmp(NULL, 'a'));
		test('strcasecmp', 2, strcasecmp('a', ''), strcasecmp('a', NULL));
		test('strncasecmp', 1, strncasecmp('', 'a', 1), strncasecmp(NULL, 'a', 1));
		test('strncasecmp', 2, strncasecmp('a', '', 1), strncasecmp('a', NULL, 1));
		test('strnatcmp', 1, strnatcmp('', 'a'), strnatcmp(NULL, 'a'));
		test('strnatcmp', 2, strnatcmp('a', ''), strnatcmp('a', NULL));
		test('strnatcasecmp', 1, strnatcasecmp('', 'a'), strnatcasecmp(NULL, 'a'));
		test('strnatcasecmp', 2, strnatcasecmp('a', ''), strnatcasecmp('a', NULL));
		test('substr_compare', 1, substr_compare('', 'a', 0), substr_compare(NULL, 'a', 0));
		test('substr_compare', 2, substr_compare('a', '', 0), substr_compare('a', NULL, 0));
		test('str_contains', 1, str_contains('', 'a'), str_contains(NULL, 'a'));
		test('str_contains', 2, str_contains('a', ''), str_contains('a', NULL));
		test('str_starts_with', 1, str_starts_with('', 'a'), str_starts_with(NULL, 'a'));
		test('str_starts_with', 2, str_starts_with('a', ''), str_starts_with('a', NULL));
		test('str_ends_with', 1, str_ends_with('', 'a'), str_ends_with(NULL, 'a'));
		test('str_ends_with', 2, str_ends_with('a', ''), str_ends_with('a', NULL));

		test('version_compare', 1, version_compare('', 'a'), version_compare(NULL, 'a'));
		test('version_compare', 2, version_compare('a', ''), version_compare('a', NULL));

		$col = collator_create('en');
		test('collator_compare', 2, collator_compare($col, '', 'a'), collator_compare($col, NULL, 'a'));
		test('collator_compare', 3, collator_compare($col, 'a', ''), collator_compare($col, 'a', NULL));
		test('collator_get_sort_key', 2, collator_get_sort_key($col, ''), collator_get_sort_key($col, NULL));

		test('sodium_compare', 1, sodium_compare('', ''), sodium_compare(NULL, ''));
		test('sodium_compare', 2, sodium_compare('', ''), sodium_compare('', NULL));

		test('metaphone', 1, metaphone(''), metaphone(NULL));
		test('soundex', 1, soundex(''), soundex(NULL));
		test('levenshtein', 1, levenshtein('', 'a'), levenshtein(NULL, 'a'));
		test('levenshtein', 2, levenshtein('a', ''), levenshtein('a', NULL));
		test('similar_text', 1, similar_text('', 'a'), similar_text(NULL, 'a'));
		test('similar_text', 2, similar_text('a', ''), similar_text('a', NULL));
		test('sodium_memcmp', 1, sodium_memcmp('', ''), sodium_memcmp(NULL, ''));
		test('sodium_memcmp', 2, sodium_memcmp('', ''), sodium_memcmp('', NULL));

	//--------------------------------------------------
	// String Details

		test('strlen', 1, strlen(''), strlen(NULL));
		test('strstr', 1, strstr('', 'a'), strstr(NULL, 'a'));
		test('strstr', 2, strstr('a', ''), strstr('a', NULL));
		test('strchr', 1, strchr('', 'a'), strchr(NULL, 'a')); // Alias of strstr
		test('strchr', 2, strchr('a', ''), strchr('a', NULL));
		test('stristr', 1, stristr('', 'a'), stristr(NULL, 'a'));
		test('stristr', 2, stristr('a', ''), stristr('a', NULL));
		test('strrchr', 1, strrchr('', 'a'), strrchr(NULL, 'a'));
		test('strrchr', 2, strrchr('a', ''), strrchr('a', NULL));
		test('strpbrk', 1, strpbrk('', 'a'), strpbrk(NULL, 'a'));
		// test('strpbrk', 2, strpbrk('a', ''), strpbrk('a', NULL)); // must be a non-empty string
		$ignore_nullable['strpbrk'][] = '2:characters';
		test('strspn', 1, strspn('', 'a'), strspn(NULL, 'a'));
		test('strspn', 2, strspn('a', ''), strspn('a', NULL));
		test('strcspn', 1, strcspn('', 'a'), strcspn(NULL, 'a'));
		test('strcspn', 2, strcspn('a', ''), strcspn('a', NULL));
		test('strtok', 1, strtok('', 'a'), strtok(NULL, 'a'));
		// test('strtok', 2, strtok('a', ''), strtok('a', NULL)); // Returns false when $token is NULL
		test('str_word_count', 1, str_word_count(''), str_word_count(NULL));
		test('count_chars', 1, count_chars(''), count_chars(NULL));
		test('ord', 1, ord(''), ord(NULL));

		test('iconv_strlen', 1, iconv_strlen(''), iconv_strlen(NULL));

		test('mb_strlen', 1, mb_strlen(''), mb_strlen(NULL));
		test('mb_strstr', 1, mb_strstr('', 'a'), mb_strstr(NULL, 'a'));
		test('mb_strstr', 2, mb_strstr('a', ''), mb_strstr('a', NULL));
		test('mb_stristr', 1, mb_stristr('', 'a'), mb_stristr(NULL, 'a'));
		test('mb_stristr', 2, mb_stristr('a', ''), mb_stristr('a', NULL));
		test('mb_strrchr', 1, mb_strrchr('', 'a'), mb_strrchr(NULL, 'a'));
		test('mb_strrchr', 2, mb_strrchr('a', ''), mb_strrchr('a', NULL));
		test('mb_strrichr', 1, mb_strrichr('', 'a'), mb_strrichr(NULL, 'a'));
		test('mb_strrichr', 2, mb_strrichr('a', ''), mb_strrichr('a', NULL));
		test('mb_strcut', 1, mb_strcut('', 0), mb_strcut(NULL, 0));
		test('mb_strwidth', 1, mb_strwidth(''), mb_strwidth(NULL));
		test('mb_strimwidth', 1, mb_strimwidth('', 0, 10), mb_strimwidth(NULL, 0, 10));
		test('mb_strimwidth', 4, mb_strimwidth('a', 0, 10, ''), mb_strimwidth('a', 0, 10, NULL));
		// test('mb_ord', 1, mb_ord(''), mb_ord(NULL)); // must not be empty

		test('grapheme_strlen', 1, grapheme_strlen(''), grapheme_strlen(NULL));
		test('grapheme_strstr', 1, grapheme_strstr('', 'a'), grapheme_strstr(NULL, 'a'));
		test('grapheme_strstr', 2, grapheme_strstr('a', ''), grapheme_strstr('a', NULL));
		test('grapheme_stristr', 1, grapheme_stristr('', 'a'), grapheme_stristr(NULL, 'a'));
		test('grapheme_stristr', 2, grapheme_stristr('a', ''), grapheme_stristr('a', NULL));

	//--------------------------------------------------
	// RegEx

		// test('preg_match', 1, preg_match('', 'a'), preg_match(NULL, 'a')); // Empty regular expression
		$ignore_nullable['preg_match'][] = '1:pattern';
		test('preg_match', 2, preg_match('/a/', ''), preg_match('/a/', NULL));
		// test('preg_match_all', 1, preg_match_all('', 'a'), preg_match_all(NULL, 'a')); // Empty regular expression
		$ignore_nullable['preg_match_all'][] = '1:pattern';
		test('preg_match_all', 2, preg_match_all('/a/', ''), preg_match_all('/a/', NULL));
		// test('preg_replace', 1, preg_replace('', 'a', 'ä'), preg_replace(NULL, 'a', 'ä')); // Empty regular expression
		$ignore_nullable['preg_replace'][] = '1:pattern';
		test('preg_replace', 2, preg_replace('/a/', '', 'ä'), preg_replace('/a/', NULL, 'ä'));
		test('preg_replace', 3, preg_replace('/a/', 'a', ''), preg_replace('/a/', 'a', NULL));
		// test('preg_filter', 1, preg_filter('', 'a', 'ä'), preg_filter(NULL, 'a', 'ä')); // Empty regular expression
		$ignore_nullable['preg_filter'][] = '1:pattern';
		test('preg_filter', 2, preg_filter('/a/', '', 'ä'), preg_filter('/a/', NULL, 'ä'));
		test('preg_filter', 3, preg_filter('/a/', 'a', ''), preg_filter('/a/', 'a', NULL));
		function preg_callback() {}
		// test('preg_replace_callback', 1, preg_replace_callback('', 'preg_callback', 'a'), preg_replace_callback(NULL, 'preg_callback', 'a')); // Empty regular expression
		$ignore_nullable['preg_replace_callback'][] = '1:pattern';
		test('preg_replace_callback', 3, preg_replace_callback('/a/', 'preg_callback', 'a'), preg_replace_callback('/a/', 'preg_callback', NULL));
		test('preg_replace_callback_array', 2, preg_replace_callback_array(['/a/' => 'preg_callback'], ''), preg_replace_callback_array(['/a/' => 'preg_callback'], NULL));
		// test('preg_split', 1, preg_split('', 'a'), preg_split(NULL, 'a')); // Empty regular expression
		$ignore_nullable['preg_split'][] = '1:pattern';
		test('preg_split', 2, preg_split('/a/', ''), preg_split('/a/', NULL));
		test('preg_quote', 1, preg_quote(''), preg_quote(NULL));

		// test('mb_ereg', 1, mb_ereg('', 'a'), mb_ereg(NULL, 'a')); // must not be empty
		$ignore_nullable['mb_ereg'][] = '1:pattern';
		test('mb_ereg', 2, mb_ereg('a', ''), mb_ereg('a', NULL));
		// test('mb_eregi', 1, mb_eregi('', 'a'), mb_eregi(NULL, 'a')); // must not be empty
		$ignore_nullable['mb_eregi'][] = '1:pattern';
		test('mb_eregi', 2, mb_eregi('a', ''), mb_eregi('a', NULL));
		test('mb_ereg_replace', 1, mb_ereg_replace('', 'a', 'ä'), mb_ereg_replace(NULL, 'a', 'ä')); // Oddity... Empty regular expression?
		test('mb_ereg_replace', 2, mb_ereg_replace('a', '', 'ä'), mb_ereg_replace('a', NULL, 'ä'));
		test('mb_ereg_replace', 3, mb_ereg_replace('a', 'a', ''), mb_ereg_replace('a', 'a', NULL));
		test('mb_eregi_replace', 1, mb_eregi_replace('', 'a', 'ä'), mb_eregi_replace(NULL, 'a', 'ä')); // Oddity... Empty regular expression?
		test('mb_eregi_replace', 2, mb_eregi_replace('a', '', 'ä'), mb_eregi_replace('a', NULL, 'ä'));
		test('mb_eregi_replace', 3, mb_eregi_replace('a', 'a', ''), mb_eregi_replace('a', 'a', NULL));
		function ereg_callback() {}
		test('mb_ereg_replace_callback', 1, mb_ereg_replace_callback('', 'ereg_callback', 'ä'), mb_ereg_replace_callback(NULL, 'ereg_callback', 'ä')); // Oddity... Empty regular expression?
		test('mb_ereg_replace_callback', 3, mb_ereg_replace_callback('a', 'ereg_callback', ''), mb_ereg_replace_callback('a', 'ereg_callback', NULL));
		test('mb_ereg_match', 1, mb_ereg_match('', 'a'), mb_ereg_match(NULL, 'a')); // Oddity... Empty regular expression?
		test('mb_ereg_match', 2, mb_ereg_match('a', ''), mb_ereg_match('a', NULL));
		test('mb_ereg_search_init', 1, mb_ereg_search_init('', 'a'), mb_ereg_search_init(NULL, 'a'));
		// test('mb_ereg_search_init', 2, mb_ereg_search_init('a', ''), mb_ereg_search_init('a', NULL)); // must not be empty

	//--------------------------------------------------
	// Normalising

		test('normalizer_normalize', 1, normalizer_normalize(''), normalizer_normalize(NULL));
		test('normalizer_is_normalized', 1, normalizer_is_normalized(''), normalizer_is_normalized(NULL));
		test('normalizer_get_raw_decomposition', 1, normalizer_get_raw_decomposition(''), normalizer_get_raw_decomposition(NULL));

	//--------------------------------------------------
	// Hashing

		// test('hash', 1, hash('', 'a'), hash(NULL, 'a')); // must be a valid hashing algorithm
		$ignore_nullable['hash'][] = '1:algo';
		test('hash', 2, hash('sha256', ''), hash('sha256', NULL));
		// test('hash_hmac', 1, hash_hmac('', 'a', 'a'), hash_hmac(NULL, 'a', 'a')); // must be a valid cryptographic hashing algorithm
		$ignore_nullable['hash_hmac'][] = '1:algo';
		test('hash_hmac', 2, hash_hmac('sha256', '', 'a'), hash_hmac('sha256', NULL, 'a'));
		test('hash_hmac', 3, hash_hmac('sha256', 'a', ''), hash_hmac('sha256', 'a', NULL)); // Oddity, should an empty key be allowed?
		$h = hash_init('sha256');
		test('hash_update', 2, hash_update($h, ''), hash_update($h, NULL));
		// test('hash_equals', 1, hash_equals('', 'a'), hash_equals(NULL, 'a')); // must be of type string, null given
		// test('hash_equals', 1, hash_equals('a', ''), hash_equals('a', NULL)); // must be of type string, null given
		// test('hash_pbkdf2', 1, hash_pbkdf2('', 'a', 'a', 1000), hash_pbkdf2(NULL, 'a', 'a', 1000)); // must be a valid cryptographic hashing algorithm
		$ignore_nullable['hash_pbkdf2'][] = '1:algo';
		test('hash_pbkdf2', 2, hash_pbkdf2('sha256', '', 'a', 1000), hash_pbkdf2('sha256', NULL, 'a', 1000));
		test('hash_pbkdf2', 3, hash_pbkdf2('sha256', 'a', '', 1000), hash_pbkdf2('sha256', 'a', NULL, 1000)); // Oddity, should an empty key be allowed?

		test('crc32', 1, crc32(''), crc32(NULL));
		test('md5', 1, md5(''), md5(NULL));
		test('sha1', 1, sha1(''), sha1(NULL));

		test('crypt', 1, crypt('', '$5$rounds=5000$cMzt9CbBEXf9AAzvFj$'), crypt(NULL, '$5$rounds=5000$cMzt9CbBEXf9AAzvFj$'));
		test('crypt', 2, crypt('a', ''), crypt('a', NULL)); // Oddity, should an empty salt be allowed?

	//--------------------------------------------------
	// Files

		test('basename', 1, basename(''), basename(NULL));
		test('basename', 2, basename('/', ''), basename('/', NULL));
		test('dirname', 1, dirname(''), dirname(NULL));
		test('pathinfo', 1, pathinfo(''), pathinfo(NULL));

		$fp = fopen($tmp_file, 'w+');
		test('fwrite', 2, fwrite($fp, ''), fwrite($fp, NULL));
		test('fputs', 2, fputs($fp, ''), fputs($fp, NULL)); // Alias of fwrite
		fclose($fp);

	//--------------------------------------------------
	// Output

		// test('setcookie', 1, setcookie(''), setcookie(NULL)); // cannot be empty
		$ignore_nullable['setcookie'][] = '1:name';
		test('setcookie', 2, setcookie('a', ''), setcookie('a', NULL));
		test('setcookie', 4, setcookie('a', 'a', 0, ''), setcookie('a', 'a', 0, NULL)); // path
		test('setcookie', 5, setcookie('a', 'a', 0, '/', ''), setcookie('a', 'a', 0, '/', NULL)); // domain

		// test('setrawcookie', 1, setrawcookie(''), setrawcookie(NULL)); // cannot be empty
		$ignore_nullable['setrawcookie'][] = '1:name';
		test('setrawcookie', 2, setrawcookie('a', ''), setrawcookie('a', NULL));
		test('setrawcookie', 4, setrawcookie('a', 'a', 0, ''), setrawcookie('a', 'a', 0, NULL)); // path
		test('setrawcookie', 5, setrawcookie('a', 'a', 0, '/', ''), setrawcookie('a', 'a', 0, '/', NULL)); // domain

		test('output_add_rewrite_var', 1, output_add_rewrite_var('', 'a'), output_add_rewrite_var(NULL, 'a'));
		test('output_add_rewrite_var', 2, output_add_rewrite_var('a', ''), output_add_rewrite_var('a', NULL));

	//--------------------------------------------------
	// Parsing

		test('parse_url', 1, parse_url(''), parse_url(NULL));
		$result = [];
		test('parse_str', 1, parse_str('', $result), parse_str(NULL, $result));

		test('mb_parse_str', 1, mb_parse_str('', $result), mb_parse_str(NULL, $result));

		$fmt = numfmt_create('en_GB', NumberFormatter::DECIMAL );
		test('numfmt_parse', 2, numfmt_parse($fmt, ''), numfmt_parse($fmt, NULL));

		test('parse_ini_string', 1, parse_ini_string(''), parse_ini_string(NULL));

		test('sscanf', 1, sscanf('', '%s'), sscanf(NULL, '%s'));
		test('sscanf', 2, sscanf('a', ''), sscanf('a', NULL));

		test('locale_accept_from_http', 1, locale_accept_from_http(''), locale_accept_from_http(NULL));

		$fmt = msgfmt_create('en_GB', '{0,number,integer}');
		test('msgfmt_parse', 2, msgfmt_parse($fmt, ''), msgfmt_parse($fmt, NULL));
		test('msgfmt_parse_message', 1, msgfmt_parse_message('', '{0,number,integer}', '123'), msgfmt_parse_message(NULL, '{0,number,integer}', '123'));
		test('msgfmt_parse_message', 2, msgfmt_parse_message('en_GB', '', '123'), msgfmt_parse_message('en_GB', NULL, '123'));
		test('msgfmt_parse_message', 3, msgfmt_parse_message('en_GB', '{0,number,integer}', ''), msgfmt_parse_message('en_GB', '{0,number,integer}', NULL));

	//--------------------------------------------------
	// CSV

		test('str_getcsv', 1, str_getcsv('', ',', '"', '\\'), str_getcsv(NULL, ',', '"', '\\'));
		test('str_getcsv', 2, str_getcsv('a', '', '"', '\\'), str_getcsv('a', NULL, '"', '\\'));
		test('str_getcsv', 3, str_getcsv('a', ',', '', '\\'), str_getcsv('a', ',', NULL, '\\'));
		test('str_getcsv', 4, str_getcsv('a', ',', '"', ''), str_getcsv('a', ',', '"', NULL));
		$fp = fopen($tmp_file, 'w+');
		// test('fputcsv', 3, fputcsv($fp, ['a'], '', '"', '\\', "\n"), fputcsv($fp, ['a'], NULL, '"', '\\', "\n")); // must be a single character
		$ignore_nullable['fputcsv'][] = '3:separator';
		// test('fputcsv', 4, fputcsv($fp, ['a'], ',', '', '\\', "\n"), fputcsv($fp, ['a'], ',', NULL, '\\', "\n")); // must be a single character
		$ignore_nullable['fputcsv'][] = '4:enclosure';
		test('fputcsv', 5, fputcsv($fp, ['a'], ',', '"', '', "\n"), fputcsv($fp, ['a'], ',', '"', NULL, "\n"));
		// test('fputcsv', 6, fputcsv($fp, ['a'], ',', '"', '\\', ""), fputcsv($fp, ['a'], ',', '"', '\\', NULL)); // Oddity, already allows null?
		$ignore_nullable['fputcsv'][] = '6:eol';
		rewind($fp);
		// test('fgetcsv', 3, fgetcsv($fp, 0, '', '"', '\\'), fgetcsv($fp, 0, NULL, '"', '\\')); // must be a single character
		$ignore_nullable['fgetcsv'][] = '3:separator';
		// test('fgetcsv', 4, fgetcsv($fp, 0, ',', '', '\\'), fgetcsv($fp, 0, ',', NULL, '\\')); must be a single character
		$ignore_nullable['fgetcsv'][] = '4:enclosure';
		test('fgetcsv', 5, fgetcsv($fp, 0, ',', '"', ''), fgetcsv($fp, 0, ',', '"', NULL));
		fclose($fp);

	//--------------------------------------------------
	// Date

		test('date_create', 1, date_create(''), date_create(NULL));
		test('date_create_immutable', 1, date_create_immutable(''), date_create_immutable(NULL));
		test('date_create_from_format', 1, date_create_from_format('', '2000-01-01'), date_create_from_format(NULL, '2000-01-01'));
		test('date_create_from_format', 2, date_create_from_format('Y-m-d', ''), date_create_from_format('Y-m-d', NULL));
		test('date_create_immutable_from_format', 1, date_create_immutable_from_format('', '2000-01-01'), date_create_immutable_from_format(NULL, '2000-01-01'));
		test('date_create_immutable_from_format', 2, date_create_immutable_from_format('Y-m-d', ''), date_create_immutable_from_format('Y-m-d', NULL));
		test('date_parse', 1, date_parse(''), date_parse(NULL));
		test('date_parse_from_format', 1, date_parse_from_format('', '2000-01-01'), date_parse_from_format(NULL, '2000-01-01'));
		test('date_parse_from_format', 2, date_parse_from_format('Y-m-d', ''), date_parse_from_format('Y-m-d', NULL));
		$date = date_create('2000-01-01');
		test('date_format', 2, date_format($date, ''), date_format($date, NULL));
		// test('date_modify', 1, date_modify($date, ''), date_modify($date, NULL)); // Failed to parse time string
		$fmt = datefmt_create('en_GB', IntlDateFormatter::SHORT, IntlDateFormatter::NONE, 'Europe/London', IntlDateFormatter::GREGORIAN);
		test('datefmt_parse', 2, datefmt_parse($fmt, ''), datefmt_parse($fmt, NULL));
		test('datefmt_localtime', 2, datefmt_localtime($fmt, ''), datefmt_localtime($fmt, NULL));

	//--------------------------------------------------
	// Images

		$im = imagecreate(100, 100);
		$bg = imagecolorallocate($im, 0, 0, 0);
		test('imagechar', 5, imagechar($im, 0, 0, 0, '', $bg), imagechar($im, 0, 0, 0, NULL, $bg));
		test('imagecharup', 5, imagecharup($im, 0, 0, 0, '', $bg), imagecharup($im, 0, 0, 0, NULL, $bg));
		test('imagestring', 5, imagestring($im, 0, 0, 0, '', $bg), imagestring($im, 0, 0, 0, NULL, $bg));
		test('imagestringup', 5, imagestringup($im, 0, 0, 0, '', $bg), imagestringup($im, 0, 0, 0, NULL, $bg));
		$ignore_nullable['imageftbbox'][] = '3:font_filename';
		test('imageftbbox', 4, imageftbbox(0, 0, './a/gd-tuffy.ttf', ''), imageftbbox(0, 0, './a/gd-tuffy.ttf', NULL));
		$ignore_nullable['imagefttext'][] = '7:font_filename';
		test('imagefttext', 8, imagefttext($im, 0, 0, 0, 0, $bg, './a/gd-tuffy.ttf', ''), imagefttext($im, 0, 0, 0, 0, $bg, './a/gd-tuffy.ttf', NULL));
		$ignore_nullable['imagettfbbox'][] = '3:font_filename';
		test('imagettfbbox', 4, imagettfbbox(0, 0, './a/gd-tuffy.ttf', ''), imagettfbbox(0, 0, './a/gd-tuffy.ttf', NULL));
		$ignore_nullable['imagettftext'][] = '7:font_filename';
		test('imagettftext', 8, imagettftext($im, 0, 0, 0, 0, $bg, './a/gd-tuffy.ttf', ''), imagettftext($im, 0, 0, 0, 0, $bg, './a/gd-tuffy.ttf', NULL));

	//--------------------------------------------------
	// Passwords

		test('password_get_info', 1, password_get_info(''), password_get_info(NULL));
		$a = password_hash('', PASSWORD_DEFAULT); $b = password_hash(NULL, PASSWORD_DEFAULT); test('password_hash', 1, '', ''); // Do not check output values, as salt changes
		test('password_needs_rehash', 1, password_needs_rehash('', PASSWORD_DEFAULT), password_needs_rehash(NULL, PASSWORD_DEFAULT));
		test('password_verify', 1, password_verify('', '$2y$10$5bTKaOpLhLzIJHuheLWXrODkrn0eVQ870GesIXvqppD1ShoMYMBeS'), password_verify(NULL, '$2y$10$5bTKaOpLhLzIJHuheLWXrODkrn0eVQ870GesIXvqppD1ShoMYMBeS'));
		test('password_verify', 2, password_verify('a', ''), password_verify('a', NULL));

	//--------------------------------------------------
	// BC Math

		test('bcadd', 1, bcadd('', '1'), bcadd(NULL, '1'));
		test('bcadd', 2, bcadd('1', ''), bcadd('1', NULL));
		test('bcsub', 1, bcsub('', '1'), bcsub(NULL, '1'));
		test('bcsub', 2, bcsub('1', ''), bcsub('1', NULL));
		test('bcmul', 1, bcmul('', '1'), bcmul(NULL, '1'));
		test('bcmul', 2, bcmul('1', ''), bcmul('1', NULL));
		test('bcdiv', 1, bcdiv('', '1'), bcdiv(NULL, '1'));
		// test('bcdiv', 2, bcdiv('1', ''), bcdiv('1', NULL)); // Division by zero
		$ignore_nullable['bcdiv'][] = '2:num2';
		test('bcmod', 1, bcmod('', '1'), bcmod(NULL, '1'));
		// test('bcmod', 2, bcmod('1', ''), bcmod('1', NULL)); // Modulo by zero
		$ignore_nullable['bcmod'][] = '2:num2';
		test('bcpow', 1, bcpow('', '1'), bcpow(NULL, '1'));
		test('bcpow', 2, bcpow('1', ''), bcpow('1', NULL));
		test('bcpowmod', 1, bcpowmod('', '1', '1'), bcpowmod(NULL, '1', '1'));
		test('bcpowmod', 2, bcpowmod('1', '', '1'), bcpowmod('1', NULL, '1'));
		// test('bcpowmod', 3, bcpowmod('1', '1', ''), bcpowmod('1', '1', NULL)); // Modulo by zero
		$ignore_nullable['bcpowmod'][] = '3:modulus';
		test('bcsqrt', 1, bcsqrt(''), bcsqrt(NULL));
		test('bccomp', 1, bccomp('', '1'), bccomp(NULL, '1'));
		test('bccomp', 2, bccomp('1', ''), bccomp('1', NULL));

	//--------------------------------------------------
	// XML

		test('simplexml_load_string', 1, simplexml_load_string(''), simplexml_load_string(NULL));
		// test('simplexml_load_string', 2, simplexml_load_string('<a></a>', ''), simplexml_load_string('<a></a>', NULL)); // must be a class name
		test('simplexml_load_string', 4, simplexml_load_string('<a></a>', SimpleXMLElement::class, 0, ''), simplexml_load_string('<a></a>', SimpleXMLElement::class, 0, NULL));

		test('xml_parser_create_ns', 2, xml_parser_create_ns('UTF-8', ''), xml_parser_create_ns('UTF-8', NULL));
		$x = xml_parser_create();
		test('xml_parse', 2, xml_parse($x, ''), xml_parse($x, NULL));
		$values = [];
		test('xml_parse_into_struct', 2, xml_parse_into_struct($x, '', $values), xml_parse_into_struct($x, NULL, $values));

		$x = xmlwriter_open_memory();
		xmlwriter_start_element($x, 'a');
		test('xmlwriter_set_indent_string', 2, xmlwriter_set_indent_string($x, ''), xmlwriter_set_indent_string($x, NULL));
		// test('xmlwriter_write_attribute', 1, xmlwriter_write_attribute($x, '', 'a'), xmlwriter_write_attribute($x, NULL, 'a')); // must be a valid attribute name
		$ignore_nullable['xmlwriter_write_attribute'][] = '2:name';
		test('xmlwriter_write_attribute', 3, xmlwriter_write_attribute($x, 'a', ''), xmlwriter_write_attribute($x, 'a', NULL));
		// test('xmlwriter_write_attribute_ns', 2, xmlwriter_write_attribute_ns($x, '', 'a', 'a', 'a'), xmlwriter_write_attribute_ns($x, NULL, 'a', 'a', 'a')); // fine
		// test('xmlwriter_write_attribute_ns', 3, xmlwriter_write_attribute_ns($x, 'a', '', 'a', 'a'), xmlwriter_write_attribute_ns($x, 'a', NULL, 'a', 'a')); // must be a valid attribute name
		$ignore_nullable['xmlwriter_write_attribute_ns'][] = '3:name';
		// test('xmlwriter_write_attribute_ns', 4, xmlwriter_write_attribute_ns($x, 'a', 'a', '', 'a'), xmlwriter_write_attribute_ns($x, 'a', 'a', NULL, 'a')); // fine
		test('xmlwriter_write_attribute_ns', 5, xmlwriter_write_attribute_ns($x, 'a', 'a', 'a', ''), xmlwriter_write_attribute_ns($x, 'a', 'a', 'a', NULL));
		// test('xmlwriter_write_element', 3, xmlwriter_write_element($x, ''), xmlwriter_write_element($x, NULL)); // must be a valid element name
		// test('xmlwriter_write_element_ns', 3, xmlwriter_write_element_ns($x, ''), xmlwriter_write_element_ns($x, NULL)); // must be a valid element name
		// test('xmlwriter_write_pi', 2, xmlwriter_write_pi($x, '', 'a'), xmlwriter_write_pi($x, NULL, 'a')); // must be a valid PI target
		$ignore_nullable['xmlwriter_write_pi'][] = '2:target';
		test('xmlwriter_write_pi', 3, xmlwriter_write_pi($x, 'a', ''), xmlwriter_write_pi($x, 'a', NULL));
		test('xmlwriter_write_cdata', 2, xmlwriter_write_cdata($x, ''), xmlwriter_write_cdata($x, NULL));
		test('xmlwriter_text', 2, xmlwriter_text($x, ''), xmlwriter_text($x, NULL));
		test('xmlwriter_write_raw', 2, xmlwriter_write_raw($x, ''), xmlwriter_write_raw($x, NULL));
		test('xmlwriter_write_comment', 2, xmlwriter_write_comment($x, ''), xmlwriter_write_comment($x, NULL));
		test('xmlwriter_write_dtd', 2, xmlwriter_write_dtd($x, ''), xmlwriter_write_dtd($x, NULL));
		// test('xmlwriter_write_dtd_element', 2, xmlwriter_write_dtd_element($x, '', 'a'), xmlwriter_write_dtd_element($x, NULL, 'a')); // must be a valid element name
		$ignore_nullable['xmlwriter_write_dtd_element'][] = '2:name';
		test('xmlwriter_write_dtd_element', 3, xmlwriter_write_dtd_element($x, 'a', ''), xmlwriter_write_dtd_element($x, 'a', NULL));
		// test('xmlwriter_write_dtd_attlist', 2, xmlwriter_write_dtd_attlist($x, '', 'a'), xmlwriter_write_dtd_attlist($x, NULL, 'a')); // must be a valid element name
		$ignore_nullable['xmlwriter_write_dtd_attlist'][] = '2:name';
		test('xmlwriter_write_dtd_attlist', 3, xmlwriter_write_dtd_attlist($x, 'a', ''), xmlwriter_write_dtd_attlist($x, 'a', NULL));
		// test('xmlwriter_write_dtd_entity', 2, xmlwriter_write_dtd_entity($x, '', 'a'), xmlwriter_write_dtd_entity($x, NULL, 'a')); // must be a valid element name
		$ignore_nullable['xmlwriter_write_dtd_entity'][] = '2:name';
		test('xmlwriter_write_dtd_entity', 3, xmlwriter_write_dtd_entity($x, 'a', ''), xmlwriter_write_dtd_entity($x, 'a', NULL));

	//--------------------------------------------------
	// PSpell

		// test('pspell_new', 1, pspell_new(''), pspell_new(NULL)); // No word lists can be found for the language
		$ignore_nullable['pspell_new'][] = '1:language';
		test('pspell_new', 2, pspell_new('en', '', 'jargon', 'utf-8'), pspell_new('en', NULL, 'jargon', 'utf-8'));
		test('pspell_new', 3, pspell_new('en', 'british', '', 'utf-8'), pspell_new('en', 'british', NULL, 'utf-8'));
		test('pspell_new', 4, pspell_new('en', 'british', 'jargon', ''), pspell_new('en', 'british', 'jargon', NULL));
		test('pspell_new_personal', 1, pspell_new_personal('', 'en', 'british', 'jargon', 'utf-8'), pspell_new_personal(NULL, 'en', 'british', 'jargon', 'utf-8'));
		// test('pspell_new_personal', 2, pspell_new_personal('./pspell.txt', '', 'british', 'jargon', 'utf-8'), pspell_new_personal('./pspell.txt', NULL, 'british', 'jargon', 'utf-8'));
		$ignore_nullable['pspell_new_personal'][] = '2:language';
		test('pspell_new_personal', 3, pspell_new_personal('./pspell.txt', 'en', '', 'jargon', 'utf-8'), pspell_new_personal('./pspell.txt', 'en', NULL, 'jargon', 'utf-8'));
		test('pspell_new_personal', 4, pspell_new_personal('./pspell.txt', 'en', 'british', '', 'utf-8'), pspell_new_personal('./pspell.txt', 'en', 'british', NULL, 'utf-8'));
		test('pspell_new_personal', 5, pspell_new_personal('./pspell.txt', 'en', 'british', 'jargon', ''), pspell_new_personal('./pspell.txt', 'en', 'british', 'jargon', NULL));
		$ps = pspell_new_personal('./pspell.txt', 'en', 'british', '', 'utf-8');
		test('pspell_check', 2, pspell_check($ps, ''), pspell_check($ps, NULL));
		test('pspell_suggest', 2, pspell_suggest($ps, ''), pspell_suggest($ps, NULL));
		// test('pspell_store_replacement', 2, pspell_store_replacement($ps, '', 'b'), pspell_store_replacement($ps, NULL, 'b')); // 503 Service Unavailable
		$ignore_nullable['pspell_store_replacement'][] = '2:misspelled';
		test('pspell_store_replacement', 3, pspell_store_replacement($ps, 'a', ''), pspell_store_replacement($ps, 'a', NULL));
		test('pspell_add_to_personal', 2, pspell_add_to_personal($ps, ''), pspell_add_to_personal($ps, NULL));
		test('pspell_add_to_session', 2, pspell_add_to_session($ps, ''), pspell_add_to_session($ps, NULL));
		test('pspell_config_create', 1, pspell_config_create('', 'british', 'jargon', 'utf-8'), pspell_config_create(NULL, 'british', 'jargon', 'utf-8'));
		test('pspell_config_create', 2, pspell_config_create('en', '', 'jargon', 'utf-8'), pspell_config_create('en', NULL, 'jargon', 'utf-8'));
		test('pspell_config_create', 3, pspell_config_create('en', 'british', '', 'utf-8'), pspell_config_create('en', 'british', NULL, 'utf-8'));
		test('pspell_config_create', 4, pspell_config_create('en', 'british', 'jargon', ''), pspell_config_create('en', 'british', 'jargon', NULL));
		$c = pspell_config_create('en', 'british', 'jargon', 'uf-8');
		test('pspell_config_personal', 2, pspell_config_personal($c, ''), pspell_config_personal($c, NULL));
		test('pspell_config_dict_dir', 2, pspell_config_dict_dir($c, ''), pspell_config_dict_dir($c, NULL));
		test('pspell_config_data_dir', 2, pspell_config_data_dir($c, ''), pspell_config_data_dir($c, NULL));
		test('pspell_config_repl', 2, pspell_config_repl($c, ''), pspell_config_repl($c, NULL));

	//--------------------------------------------------
	// Sodium

		$aead_aes256gcm_key = sodium_crypto_aead_aes256gcm_keygen();
		$aead_aes256gcm_ad = random_bytes(32);
		$aead_aes256gcm_nonce = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
		test('sodium_crypto_aead_aes256gcm_encrypt', 1, sodium_crypto_aead_aes256gcm_encrypt('', $aead_aes256gcm_ad, $aead_aes256gcm_nonce, $aead_aes256gcm_key), sodium_crypto_aead_aes256gcm_encrypt(NULL, $aead_aes256gcm_ad, $aead_aes256gcm_nonce, $aead_aes256gcm_key));
		test('sodium_crypto_aead_aes256gcm_encrypt', 2, sodium_crypto_aead_aes256gcm_encrypt('a', '', $aead_aes256gcm_nonce, $aead_aes256gcm_key), sodium_crypto_aead_aes256gcm_encrypt('a', NULL, $aead_aes256gcm_nonce, $aead_aes256gcm_key));
		// test('sodium_crypto_aead_aes256gcm_encrypt', 3, sodium_crypto_aead_aes256gcm_encrypt('a', $aead_aes256gcm_ad, '', $aead_aes256gcm_key), sodium_crypto_aead_aes256gcm_encrypt('a', $aead_aes256gcm_ad, NULL, $aead_aes256gcm_key)); // must be SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES bytes long
		// test('sodium_crypto_aead_aes256gcm_encrypt', 4, sodium_crypto_aead_aes256gcm_encrypt('a', $aead_aes256gcm_ad, $aead_aes256gcm_nonce, ''), sodium_crypto_aead_aes256gcm_encrypt('a', $aead_aes256gcm_ad, $aead_aes256gcm_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_aes256gcm_encrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_aes256gcm_encrypt'][] = '4:key';
		$data = sodium_crypto_aead_aes256gcm_encrypt('a', $aead_aes256gcm_ad, $aead_aes256gcm_nonce, $aead_aes256gcm_key);
		test('sodium_crypto_aead_aes256gcm_decrypt', 1, sodium_crypto_aead_aes256gcm_decrypt('', $aead_aes256gcm_ad, $aead_aes256gcm_nonce, $aead_aes256gcm_key), sodium_crypto_aead_aes256gcm_decrypt(NULL, $aead_aes256gcm_ad, $aead_aes256gcm_nonce, $aead_aes256gcm_key));
		test('sodium_crypto_aead_aes256gcm_decrypt', 2, sodium_crypto_aead_aes256gcm_decrypt($data, '', $aead_aes256gcm_nonce, $aead_aes256gcm_key), sodium_crypto_aead_aes256gcm_decrypt($data, NULL, $aead_aes256gcm_nonce, $aead_aes256gcm_key));
		// test('sodium_crypto_aead_aes256gcm_decrypt', 3, sodium_crypto_aead_aes256gcm_decrypt($data, $aead_aes256gcm_ad, '', $aead_aes256gcm_key), sodium_crypto_aead_aes256gcm_decrypt($data, $aead_aes256gcm_ad, NULL, $aead_aes256gcm_key)); // must be SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES bytes long
		// test('sodium_crypto_aead_aes256gcm_decrypt', 4, sodium_crypto_aead_aes256gcm_decrypt($data, $aead_aes256gcm_ad, $aead_aes256gcm_nonce, ''), sodium_crypto_aead_aes256gcm_decrypt($data, $aead_aes256gcm_ad, $aead_aes256gcm_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_aes256gcm_decrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_aes256gcm_decrypt'][] = '4:key';

		$aead_chacha20poly1305_key = sodium_crypto_aead_chacha20poly1305_keygen();
		$aead_chacha20poly1305_ad = random_bytes(32);
		$aead_chacha20poly1305_nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
		test('sodium_crypto_aead_chacha20poly1305_encrypt', 1, sodium_crypto_aead_chacha20poly1305_encrypt('', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_encrypt(NULL, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		test('sodium_crypto_aead_chacha20poly1305_encrypt', 2, sodium_crypto_aead_chacha20poly1305_encrypt('a', '', $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_encrypt('a', NULL, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		// test('sodium_crypto_aead_chacha20poly1305_encrypt', 3, sodium_crypto_aead_chacha20poly1305_encrypt('a', $aead_chacha20poly1305_ad, '', $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_encrypt('a', $aead_chacha20poly1305_ad, NULL, $aead_chacha20poly1305_key)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes long
		// test('sodium_crypto_aead_chacha20poly1305_encrypt', 4, sodium_crypto_aead_chacha20poly1305_encrypt('a', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, ''), sodium_crypto_aead_chacha20poly1305_encrypt('a', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_encrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_encrypt'][] = '4:key';
		$data = sodium_crypto_aead_chacha20poly1305_encrypt('a', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key);
		test('sodium_crypto_aead_chacha20poly1305_decrypt', 1, sodium_crypto_aead_chacha20poly1305_decrypt('', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_decrypt(NULL, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		test('sodium_crypto_aead_chacha20poly1305_decrypt', 2, sodium_crypto_aead_chacha20poly1305_decrypt($data, '', $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_decrypt($data, NULL, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		// test('sodium_crypto_aead_chacha20poly1305_decrypt', 3, sodium_crypto_aead_chacha20poly1305_decrypt($data, $aead_chacha20poly1305_ad, '', $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_decrypt($data, $aead_chacha20poly1305_ad, NULL, $aead_chacha20poly1305_key)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes long
		// test('sodium_crypto_aead_chacha20poly1305_decrypt', 4, sodium_crypto_aead_chacha20poly1305_decrypt($data, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, ''), sodium_crypto_aead_chacha20poly1305_decrypt($data, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_decrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_decrypt'][] = '4:key';

		$aead_chacha20poly1305_key = sodium_crypto_aead_chacha20poly1305_ietf_keygen();
		$aead_chacha20poly1305_ad = random_bytes(32);
		$aead_chacha20poly1305_nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
		test('sodium_crypto_aead_chacha20poly1305_ietf_encrypt', 1, sodium_crypto_aead_chacha20poly1305_ietf_encrypt('', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_ietf_encrypt(NULL, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		test('sodium_crypto_aead_chacha20poly1305_ietf_encrypt', 2, sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', '', $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', NULL, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		// test('sodium_crypto_aead_chacha20poly1305_ietf_encrypt', 3, sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', $aead_chacha20poly1305_ad, '', $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', $aead_chacha20poly1305_ad, NULL, $aead_chacha20poly1305_key)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES bytes long
		// test('sodium_crypto_aead_chacha20poly1305_ietf_encrypt', 4, sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, ''), sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_ietf_encrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_ietf_encrypt'][] = '4:key';
		$data = sodium_crypto_aead_chacha20poly1305_ietf_encrypt('a', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key);
		test('sodium_crypto_aead_chacha20poly1305_ietf_decrypt', 1, sodium_crypto_aead_chacha20poly1305_ietf_decrypt('', $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_ietf_decrypt(NULL, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		test('sodium_crypto_aead_chacha20poly1305_ietf_decrypt', 2, sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, '', $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, NULL, $aead_chacha20poly1305_nonce, $aead_chacha20poly1305_key));
		// test('sodium_crypto_aead_chacha20poly1305_ietf_decrypt', 3, sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, $aead_chacha20poly1305_ad, '', $aead_chacha20poly1305_key), sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, $aead_chacha20poly1305_ad, NULL, $aead_chacha20poly1305_key)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES bytes long
		// test('sodium_crypto_aead_chacha20poly1305_ietf_decrypt', 4, sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, ''), sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, $aead_chacha20poly1305_ad, $aead_chacha20poly1305_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_ietf_decrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_chacha20poly1305_ietf_decrypt'][] = '4:key';

		$aead_xchacha20poly1305_key = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
		$aead_xchacha20poly1305_ad = random_bytes(32);
		$aead_xchacha20poly1305_nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		test('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt', 1, sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('', $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key), sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(NULL, $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key));
		test('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt', 2, sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', '', $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key), sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', NULL, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key));
		// test('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt', 3, sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', $aead_xchacha20poly1305_ad, '', $aead_xchacha20poly1305_key), sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', $aead_xchacha20poly1305_ad, NULL, $aead_xchacha20poly1305_key)); // must be SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES bytes long
		// test('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt', 4, sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, ''), sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_xchacha20poly1305_ietf_encrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_xchacha20poly1305_ietf_encrypt'][] = '4:key';
		$data = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('a', $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key);
		test('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt', 1, sodium_crypto_aead_xchacha20poly1305_ietf_decrypt('', $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key), sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(NULL, $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key));
		test('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt', 2, sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, '', $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key), sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, NULL, $aead_xchacha20poly1305_nonce, $aead_xchacha20poly1305_key));
		// test('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt', 3, sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, $aead_xchacha20poly1305_ad, '', $aead_xchacha20poly1305_key), sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, $aead_xchacha20poly1305_ad, NULL, $aead_xchacha20poly1305_key)); // must be SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES bytes long
		// test('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt', 4, sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, ''), sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, $aead_xchacha20poly1305_ad, $aead_xchacha20poly1305_nonce, NULL)); // must be SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_aead_xchacha20poly1305_ietf_decrypt'][] = '3:nonce';
		$ignore_nullable['sodium_crypto_aead_xchacha20poly1305_ietf_decrypt'][] = '4:key';

		$key = sodium_crypto_auth_keygen();
		test('sodium_crypto_auth', 1, sodium_crypto_auth('', $key), sodium_crypto_auth(NULL, $key));
		// test('sodium_crypto_auth', 2, sodium_crypto_auth('a', ''), sodium_crypto_auth('a', NULL)); // must be SODIUM_CRYPTO_AUTH_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_auth'][] = '2:key';
		$signature = sodium_crypto_auth('a', $key);
		// test('sodium_crypto_auth_verify', 1, sodium_crypto_auth_verify('', 'a', $key), sodium_crypto_auth_verify(NULL, 'a', $key)); // must be SODIUM_CRYPTO_AUTH_BYTES bytes long
		test('sodium_crypto_auth_verify', 2, sodium_crypto_auth_verify($signature, '', $key), sodium_crypto_auth_verify($signature, NULL, $key));
		// test('sodium_crypto_auth_verify', 3, sodium_crypto_auth_verify($signature, 'a', ''), sodium_crypto_auth_verify($signature, 'a', NULL)); // must be SODIUM_CRYPTO_AUTH_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_auth_verify'][] = '1:mac';
		$ignore_nullable['sodium_crypto_auth_verify'][] = '3:key';

		$sodium_crypto_box_key1 = sodium_crypto_box_keypair();
		$sodium_crypto_box_key1_public = sodium_crypto_box_publickey($sodium_crypto_box_key1);
		$sodium_crypto_box_key1_secret = sodium_crypto_box_secretkey($sodium_crypto_box_key1);
		$sodium_crypto_box_key2 = sodium_crypto_box_keypair();
		$sodium_crypto_box_key2_public = sodium_crypto_box_publickey($sodium_crypto_box_key2);
		$sodium_crypto_box_key2_secret = sodium_crypto_box_secretkey($sodium_crypto_box_key2);
		$sodium_crypto_box_key_a = sodium_crypto_box_keypair_from_secretkey_and_publickey($sodium_crypto_box_key1_secret, $sodium_crypto_box_key2_public);
		$sodium_crypto_box_key_b = sodium_crypto_box_keypair_from_secretkey_and_publickey($sodium_crypto_box_key2_secret, $sodium_crypto_box_key1_public);
		$nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
		test('sodium_crypto_box', 1, sodium_crypto_box('', $nonce, $sodium_crypto_box_key_a), sodium_crypto_box(NULL, $nonce, $sodium_crypto_box_key_a));
		// test('sodium_crypto_box', 2, sodium_crypto_box('a', '', $sodium_crypto_box_key_a), sodium_crypto_box('a', NULL, $sodium_crypto_box_key_a)); // must be SODIUM_CRYPTO_BOX_NONCEBYTES bytes long
		// test('sodium_crypto_box', 3, sodium_crypto_box('', $nonce, ''), sodium_crypto_box(NULL, $nonce, NULL)); // must be SODIUM_CRYPTO_BOX_KEYPAIRBYTES bytes long
		$ignore_nullable['sodium_crypto_box'][] = '2:nonce';
		$ignore_nullable['sodium_crypto_box'][] = '3:key_pair';
		// $seed = sodium_crypto_pwhash()
		// test('sodium_crypto_box_seed_keypair', 1, sodium_crypto_box_seed_keypair(''), sodium_crypto_box(NULL)); // must be SODIUM_CRYPTO_BOX_SEEDBYTES bytes long
		// test('sodium_crypto_box_keypair_from_secretkey_and_publickey', 1, sodium_crypto_box_keypair_from_secretkey_and_publickey('', $sodium_crypto_box_key2_public), sodium_crypto_box_keypair_from_secretkey_and_publickey(NULL, $sodium_crypto_box_key2_public)); // must be SODIUM_CRYPTO_BOX_SECRETKEYBYTES bytes long
		// test('sodium_crypto_box_keypair_from_secretkey_and_publickey', 2, sodium_crypto_box_keypair_from_secretkey_and_publickey($sodium_crypto_box_key1_secret, ''), sodium_crypto_box_keypair_from_secretkey_and_publickey($sodium_crypto_box_key1_secret, NULL)); // must be SODIUM_CRYPTO_BOX_PUBLICKEYBYTES bytes long
		$encrypted = sodium_crypto_box('a', $nonce, $sodium_crypto_box_key_a);
		test('sodium_crypto_box_open', 1, sodium_crypto_box_open('', $nonce, $sodium_crypto_box_key_b), sodium_crypto_box_open(NULL, $nonce, $sodium_crypto_box_key_b));
		// test('sodium_crypto_box_open', 2, sodium_crypto_box_open($encrypted, '', $sodium_crypto_box_key_b), sodium_crypto_box_open($encrypted, NULL, $sodium_crypto_box_key_b)); // must be SODIUM_CRYPTO_BOX_NONCEBYTES bytes long
		// test('sodium_crypto_box_open', 3, sodium_crypto_box_open($encrypted, $nonce, ''), sodium_crypto_box_open($encrypted, $nonce, NULL)); // must be SODIUM_CRYPTO_BOX_KEYPAIRBYTES bytes long
		$ignore_nullable['sodium_crypto_box_open'][] = '2:nonce';
		$ignore_nullable['sodium_crypto_box_open'][] = '3:key_pair';
		$a = sodium_crypto_box_seal('', $sodium_crypto_box_key1_public); $b = sodium_crypto_box_seal(NULL, $sodium_crypto_box_key1_public); test('sodium_crypto_box_seal', 1, '', ''); // Do not check output values, as nonce changes
		// test('sodium_crypto_box_seal', 1, sodium_crypto_box_seal('a', ''), sodium_crypto_box_seal('a', NULL)); // must be SODIUM_CRYPTO_BOX_PUBLICKEYBYTES bytes long
		$ignore_nullable['sodium_crypto_box_seal'][] = '2:public_key';
		$encrypted = sodium_crypto_box_seal('a', $sodium_crypto_box_key1_public);
		test('sodium_crypto_box_seal_open', 1, sodium_crypto_box_seal_open('', $sodium_crypto_box_key1), sodium_crypto_box_seal_open(NULL, $sodium_crypto_box_key1));
		// test('sodium_crypto_box_seal_open', 2, sodium_crypto_box_seal_open($encrypted, ''), sodium_crypto_box_seal_open($encrypted, NULL)); // must be SODIUM_CRYPTO_BOX_KEYPAIRBYTES bytes long
		$ignore_nullable['sodium_crypto_box_seal_open'][] = '2:key_pair';

		test('sodium_crypto_generichash', 1, sodium_crypto_generichash(''), sodium_crypto_generichash(NULL));
		test('sodium_crypto_generichash', 2, sodium_crypto_generichash('a', ''), sodium_crypto_generichash('a', NULL));
		$gh = sodium_crypto_generichash_init();
		// $b = '';
		// $n = NULL;
		// test('sodium_crypto_generichash_update', 1, sodium_crypto_generichash_update($b, 'a'), sodium_crypto_generichash_update($n, 'a')); // cannot be passed by reference... and incorrect state length
		test('sodium_crypto_generichash_update', 2, sodium_crypto_generichash_update($gh, ''), sodium_crypto_generichash_update($gh, NULL));
		$ignore_nullable['sodium_crypto_generichash_update'][] = '1:state';
		$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
		// test('sodium_crypto_pwhash', 1, sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_SEEDBYTES, '', $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_DEFAULT), sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_SEEDBYTES, NULL, $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_DEFAULT)); // empty password
		// test('sodium_crypto_pwhash', 2, sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_SEEDBYTES, 'a', '', SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_DEFAULT), sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_SEEDBYTES, 'a', NULL, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_DEFAULT)); // must be SODIUM_CRYPTO_PWHASH_SALTBYTES bytes long
		// test('sodium_crypto_pwhash_str', 1, sodium_crypto_pwhash_str('', SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE), sodium_crypto_pwhash_str(NULL, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE)); // empty password
		$pw = sodium_crypto_pwhash_str('a', SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
		// test('sodium_crypto_pwhash_str_verify', 1, sodium_crypto_pwhash_str_verify($pw, ''), sodium_crypto_pwhash_str_verify($pw, NULL)); // empty password
		test('sodium_crypto_pwhash_str_needs_rehash', 1, sodium_crypto_pwhash_str_needs_rehash('', SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE), sodium_crypto_pwhash_str_needs_rehash(NULL, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE)); // empty password

		$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
		// test('sodium_crypto_pwhash_scryptsalsa208sha256', 1, sodium_crypto_pwhash_scryptsalsa208sha256(SODIUM_CRYPTO_BOX_SEEDBYTES, '', $salt, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE), sodium_crypto_pwhash_scryptsalsa208sha256(SODIUM_CRYPTO_BOX_SEEDBYTES, NULL, $salt, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE)); // empty password
		// test('sodium_crypto_pwhash_scryptsalsa208sha256', 2, sodium_crypto_pwhash_scryptsalsa208sha256(SODIUM_CRYPTO_BOX_SEEDBYTES, 'a', '', SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE), sodium_crypto_pwhash_scryptsalsa208sha256(SODIUM_CRYPTO_BOX_SEEDBYTES, 'a', NULL, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE)); // must be SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES bytes long
		// test('sodium_crypto_pwhash_scryptsalsa208sha256_str', 1, sodium_crypto_pwhash_scryptsalsa208sha256_str('', SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE), sodium_crypto_pwhash_scryptsalsa208sha256_str(NULL, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE)); // empty password
		$pw = sodium_crypto_pwhash_scryptsalsa208sha256_str('a', SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
		// test('sodium_crypto_pwhash_scryptsalsa208sha256_str_verify', 1, sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($pw, ''), sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($pw, NULL)); // empty password

		$key = sodium_crypto_secretbox_keygen();
		$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		test('sodium_crypto_secretbox', 1, sodium_crypto_secretbox('', $nonce, $key), sodium_crypto_secretbox(NULL, $nonce, $key));
		// test('sodium_crypto_secretbox', 2, sodium_crypto_secretbox('a', '', $key), sodium_crypto_secretbox('a', NULL, $key)); // must be SODIUM_CRYPTO_SECRETBOX_NONCEBYTES bytes long
		// test('sodium_crypto_secretbox', 3, sodium_crypto_secretbox('a', $nonce, ''), sodium_crypto_secretbox('a', $nonce, NULL)); // must be SODIUM_CRYPTO_SECRETBOX_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_secretbox'][] = '2:nonce';
		$ignore_nullable['sodium_crypto_secretbox'][] = '3:key';
		$encrypted = sodium_crypto_secretbox('a', $nonce, $key);
		test('sodium_crypto_secretbox_open', 1, sodium_crypto_secretbox_open('', $nonce, $key), sodium_crypto_secretbox_open(NULL, $nonce, $key));
		// test('sodium_crypto_secretbox_open', 2, sodium_crypto_secretbox_open($encrypted, '', $key), sodium_crypto_secretbox_open($encrypted, NULL, $key)); // must be SODIUM_CRYPTO_SECRETBOX_NONCEBYTES bytes long
		// test('sodium_crypto_secretbox_open', 3, sodium_crypto_secretbox_open($encrypted, $nonce, ''), sodium_crypto_secretbox_open($encrypted, $nonce, NULL)); // must be SODIUM_CRYPTO_SECRETBOX_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_secretbox_open'][] = '2:nonce';
		$ignore_nullable['sodium_crypto_secretbox_open'][] = '3:key';

		$k = sodium_crypto_secretstream_xchacha20poly1305_keygen();
		list($state, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($k);
		// $b = '';
		// $n = NULL;
		// $a = sodium_crypto_secretstream_xchacha20poly1305_push($b, 'a', 'a'); $b = sodium_crypto_secretstream_xchacha20poly1305_push($n, 'a', 'a'); test('sodium_crypto_secretstream_xchacha20poly1305_push', 1, '', ''); // cannot be passed by reference... and incorrect state length
		$a = sodium_crypto_secretstream_xchacha20poly1305_push($state, '', 'a'); $b = sodium_crypto_secretstream_xchacha20poly1305_push($state, NULL, 'a'); test('sodium_crypto_secretstream_xchacha20poly1305_push', 2, '', ''); // Do not check output values, as state changes
		$a = sodium_crypto_secretstream_xchacha20poly1305_push($state, 'a', ''); $b = sodium_crypto_secretstream_xchacha20poly1305_push($state, 'a', NULL); test('sodium_crypto_secretstream_xchacha20poly1305_push', 3, '', ''); // Do not check output values, as state changes
		$ignore_nullable['sodium_crypto_secretstream_xchacha20poly1305_push'][] = '1:state';
		list($state, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($k);
		$e = sodium_crypto_secretstream_xchacha20poly1305_push($state, 'a', 'x');
		$pull_state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $k);
		// $b = '';
		// $n = NULL;
		// $a = sodium_crypto_secretstream_xchacha20poly1305_pull($b, $e, 'x'); $b = sodium_crypto_secretstream_xchacha20poly1305_pull($n, $e, 'x'); test('sodium_crypto_secretstream_xchacha20poly1305_pull', 1, '', ''); // cannot be passed by reference... and incorrect state length
		$a = sodium_crypto_secretstream_xchacha20poly1305_pull($pull_state, '', 'x'); $b = sodium_crypto_secretstream_xchacha20poly1305_pull($pull_state, NULL, 'x'); test('sodium_crypto_secretstream_xchacha20poly1305_pull', 2, '', ''); // Do not check output values, as state changes
		$a = sodium_crypto_secretstream_xchacha20poly1305_pull($pull_state, $e, ''); $b = sodium_crypto_secretstream_xchacha20poly1305_pull($pull_state, $e, NULL); test('sodium_crypto_secretstream_xchacha20poly1305_pull', 3, '', ''); // Do not check output values, as state changes
		$ignore_nullable['sodium_crypto_secretstream_xchacha20poly1305_pull'][] = '1:state';

		$key = random_bytes(SODIUM_CRYPTO_SHORTHASH_KEYBYTES);
		test('sodium_crypto_shorthash', 1, sodium_crypto_shorthash('', $key), sodium_crypto_shorthash(NULL, $key));
		// test('sodium_crypto_shorthash', 1, sodium_crypto_shorthash('a', ''), sodium_crypto_shorthash('a', NULL)); // must be SODIUM_CRYPTO_SHORTHASH_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_shorthash'][] = '2:key';

		$key_pair = sodium_crypto_sign_keypair();
		$key_secret = sodium_crypto_sign_secretkey($key_pair);
		$key_public = sodium_crypto_sign_publickey($key_pair);
		test('sodium_crypto_sign', 1, sodium_crypto_sign('', $key_secret), sodium_crypto_sign(NULL, $key_secret));
		// test('sodium_crypto_sign', 2, sodium_crypto_sign('a', ''), sodium_crypto_sign('a', NULL)); // must be SODIUM_CRYPTO_SIGN_SECRETKEYBYTES bytes long
		$ignore_nullable['sodium_crypto_sign'][] = '2:secret_key';
		test('sodium_crypto_sign_detached', 1, sodium_crypto_sign_detached('', $key_secret), sodium_crypto_sign_detached(NULL, $key_secret));
		// test('sodium_crypto_sign_detached', 2, sodium_crypto_sign_detached('a', ''), sodium_crypto_sign_detached('a', NULL)); // must be SODIUM_CRYPTO_SIGN_SECRETKEYBYTES bytes long
		$ignore_nullable['sodium_crypto_sign_detached'][] = '2:secret_key';
		$encrypted = sodium_crypto_sign('a', $key_secret);
		test('sodium_crypto_sign_open', 1, sodium_crypto_sign_open('', $key_public), sodium_crypto_sign_open(NULL, $key_public));
		// test('sodium_crypto_sign_open', 2, sodium_crypto_sign_open($encrypted, ''), sodium_crypto_sign_open($encrypted, NULL)); // must be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes long
		$ignore_nullable['sodium_crypto_sign_open'][] = '2:public_key';
		$message = 'a';
		$signature = sodium_crypto_sign_detached($message, $key_secret);
		// test('sodium_crypto_sign_verify_detached', 1, sodium_crypto_sign_verify_detached('', $message, $key_public), sodium_crypto_sign_verify_detached(NULL, $message, $key_public)); // must be SODIUM_CRYPTO_SIGN_BYTES bytes long
		test('sodium_crypto_sign_verify_detached', 2, sodium_crypto_sign_verify_detached($signature, '', $key_public), sodium_crypto_sign_verify_detached($signature, NULL, $key_public));
		// test('sodium_crypto_sign_verify_detached', 3, sodium_crypto_sign_verify_detached($signature, $message, ''), sodium_crypto_sign_verify_detached($signature, $message, NULL)); // must be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes long
		$ignore_nullable['sodium_crypto_sign_verify_detached'][] = '1:signature';
		$ignore_nullable['sodium_crypto_sign_verify_detached'][] = '3:public_key';

		$message = 'hello';
		$nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
		$key = sodium_crypto_stream_keygen();
		$stream = sodium_crypto_stream(strlen($message), $nonce, $key);
		test('sodium_crypto_stream_xor', 1, sodium_crypto_stream_xor('', $nonce, $key), sodium_crypto_stream_xor(NULL, $nonce, $key));
		// test('sodium_crypto_stream_xor', 2, sodium_crypto_stream_xor($message, '', $key), sodium_crypto_stream_xor($message, NULL, $key)); // must be SODIUM_CRYPTO_STREAM_NONCEBYTES bytes long
		// test('sodium_crypto_stream_xor', 3, sodium_crypto_stream_xor($message, $nonce, ''), sodium_crypto_stream_xor($message, $nonce, NULL)); // must be SODIUM_CRYPTO_STREAM_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_stream_xor'][] = '2:nonce';
		$ignore_nullable['sodium_crypto_stream_xor'][] = '3:key';

		$message = 'hello';
		$nonce = random_bytes(SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES);
		$key = sodium_crypto_stream_xchacha20_keygen();
		$stream = sodium_crypto_stream_xchacha20(strlen($message), $nonce, $key);
		test('sodium_crypto_stream_xchacha20_xor', 1, sodium_crypto_stream_xchacha20_xor('', $nonce, $key), sodium_crypto_stream_xchacha20_xor(NULL, $nonce, $key));
		// test('sodium_crypto_stream_xchacha20_xor', 2, sodium_crypto_stream_xchacha20_xor($message, '', $key), sodium_crypto_stream_xchacha20_xor($message, NULL, $key)); // must be SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES bytes long
		// test('sodium_crypto_stream_xchacha20_xor', 3, sodium_crypto_stream_xchacha20_xor($message, $nonce, ''), sodium_crypto_stream_xchacha20_xor($message, $nonce, NULL)); // must be SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES bytes long
		$ignore_nullable['sodium_crypto_stream_xchacha20_xor'][] = '2:nonce';
		$ignore_nullable['sodium_crypto_stream_xchacha20_xor'][] = '3:key';

	//--------------------------------------------------
	// DNS

		// test('gethostbyaddr', 1, gethostbyaddr(''), gethostbyaddr(NULL)); // Address is not a valid IPv4 or IPv6 address
		test('gethostbyname', 1, gethostbyname(''), gethostbyname(NULL));
		test('gethostbynamel', 1, gethostbynamel(''), gethostbynamel(NULL));
		// test('dns_check_record', 1, dns_check_record(''), dns_check_record(NULL)); // Alias of checkdnsrr... and cannot be empty
		// test('checkdnsrr', 1, checkdnsrr(''), checkdnsrr(NULL)); // cannot be empty
		test('dns_get_record', 1, dns_get_record(''), dns_get_record(NULL));
		$hosts = [];
		test('dns_get_mx', 1, dns_get_mx('', $hosts), dns_get_mx(NULL, $hosts)); // Alias of getmxrr()
		test('getmxrr', 1, getmxrr('', $hosts), getmxrr(NULL, $hosts));

	//--------------------------------------------------
	// Stream

		$sc = stream_socket_client('tcp://www.example.com:80');
		stream_set_timeout($sc, 0, 10);
		test('stream_socket_sendto', 2, stream_socket_sendto($sc, ''), stream_socket_sendto($sc, NULL));
		test('stream_socket_sendto', 4, stream_socket_sendto($sc, 'a', STREAM_OOB, ''), stream_socket_sendto($sc, 'a', STREAM_OOB, NULL));
		test('stream_get_line', 3, stream_get_line($sc, 0, ''), stream_get_line($sc, 0, NULL));

	//--------------------------------------------------
	// Socket

		$sc = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		socket_connect($sc, '127.0.0.1', 443);
		test('socket_write', 2, socket_write($sc, ''), socket_write($sc, NULL));
		test('socket_send', 2, socket_send($sc, '', 0, MSG_OOB), socket_send($sc, NULL, 0, MSG_OOB));
		test('socket_sendto', 2, socket_sendto($sc, '', 0, MSG_OOB, '127.0.0.1', 443), socket_sendto($sc, NULL, 0, MSG_OOB, '127.0.0.1', 443));
		// test('socket_sendto', 5, socket_sendto($sc, '', 0, MSG_OOB, '', 443), socket_sendto($sc, '', 0, MSG_OOB, NULL, 443)); // Unknown host
		$ignore_nullable['socket_sendto'][] = '5:address';

	//--------------------------------------------------
	// Logging

		test('trigger_error', 1, trigger_error(''), trigger_error(NULL));
		test('user_error', 1, user_error(''), user_error(NULL)); // Alias of trigger_error()
		test('openlog', 1, openlog('', LOG_PID, LOG_SYSLOG), openlog(NULL, LOG_PID, LOG_SYSLOG));
		test('syslog', 2, syslog(LOG_DEBUG, ''), syslog(LOG_DEBUG, NULL));

	//--------------------------------------------------
	// E-Mail

		// test('mail', 1, mail('', 'Subject', 'Message', 'From: user@example.com', '-fwebmaster@example.com'), mail(NULL, 'Subject', 'Message', 'From: user@example.com', '-fwebmaster@example.com'));
		// test('mail', 2, mail('user@example.com', '', 'Message', 'From: user@example.com', '-fwebmaster@example.com'), mail('user@example.com', NULL, 'Message', 'From: user@example.com', '-fwebmaster@example.com'));
		// test('mail', 3, mail('user@example.com', 'Subject', '', 'From: user@example.com', '-fwebmaster@example.com'), mail('user@example.com', 'Subject', NULL, 'From: user@example.com', '-fwebmaster@example.com'));
		// test('mail', 4, mail('user@example.com', 'Subject', 'Message', '', '-fwebmaster@example.com'), mail('user@example.com', 'Subject', 'Message', NULL, '-fwebmaster@example.com'));
		// test('mail', 5, mail('user@example.com', 'Subject', 'Message', 'From: user@example.com', ''), mail('user@example.com', 'Subject', 'Message', 'From: user@example.com', NULL));

		// test('mb_send_mail', 1, mb_send_mail('', 'Subject', 'Message', 'From: user@example.com', '-fwebmaster@example.com'), mb_send_mail(NULL, 'Subject', 'Message', 'From: user@example.com', '-fwebmaster@example.com'));
		// test('mb_send_mail', 2, mb_send_mail('user@example.com', '', 'Message', 'From: user@example.com', '-fwebmaster@example.com'), mb_send_mail('user@example.com', NULL, 'Message', 'From: user@example.com', '-fwebmaster@example.com'));
		// test('mb_send_mail', 3, mb_send_mail('user@example.com', 'Subject', '', 'From: user@example.com', '-fwebmaster@example.com'), mb_send_mail('user@example.com', 'Subject', NULL, 'From: user@example.com', '-fwebmaster@example.com'));
		// test('mb_send_mail', 4, mb_send_mail('user@example.com', 'Subject', 'Message', '', '-fwebmaster@example.com'), mb_send_mail('user@example.com', 'Subject', 'Message', NULL, '-fwebmaster@example.com'));

//--------------------------------------------------
// Check functions from functions-change.md

	$functions_listed = [];
	$functions_skipped = [];

	foreach (file('functions-change.md') as $line_text) {
		if (preg_match('/^-( \?)? `([^`]+)`\((.*)\)/', $line_text, $line_match)) {
			$args = [];
			foreach (array_map('trim', explode(',', $line_match[3])) as $k => $arg_info) {
				if (preg_match('/^(\*\*)?([^:]+):([^\*]*)(\*\*)?$/', $arg_info, $arg_match)) {
					$arg_number = ($k + 1);
					$args[$arg_number] = ['name' => $arg_match[2], 'types' => $arg_match[2], 'make_nullable' => ($arg_match[1] == '**')];
				} else {
					echo $function_name . ' (' . trim($arg_info) . ') - Unrecognised Arg' . "\n";
				}
			}
			if ($line_match[1] == ' ?') {
				$functions_skipped[] = $line_match[2];
			} else {
				$functions_listed[$line_match[2]] = $args;
			}
		// } else if (str_starts_with($line_text, '?')) {
		} else if (trim($line_text) !== '' && trim($line_text) !== '---' && !preg_match('/^##? [A-Z]/', $line_text)) {
			echo 'Unrecognised Line: "' . trim($line_text) . '"' . "\n";
		}
	}

	foreach ($functions_listed as $function_name => $args) {
		$test_results = ($GLOBALS['tested_functions'][$function_name] ?? NULL);
		if ($test_results === NULL) {
			echo 'Not Tested: "' . $function_name . '" (' . implode(', ', array_column($args, 'name')) . ')' . "\n";
		} else {
			foreach ($args as $arg_number => $arg_info) {
				if ($arg_info['make_nullable']) {
					if (in_array($arg_number, $test_results)) {
						// echo $function_name . ' (' . $arg_number . ') - Passed' . "\n";
					} else {
						echo $function_name . ' (' . $arg_number . ') - Failed' . "\n";
					}
				} else {
					// echo $function_name . ' (' . $arg_number . ') - No Test Needed' . "\n";
				}
			}
		}
	}

	foreach ($GLOBALS['tested_functions'] as $function_name => $args) {
		if (!array_key_exists($function_name, $functions_listed)) {
			echo $function_name . '  - Tested, but not listed as needing changes.' . "\n";
		}
	}

//--------------------------------------------------
// Check defined functions

	$functions = get_defined_functions();

	$other_functions = [];

	$k = 0;

	foreach ($functions['internal'] as $function_name) {

		$r = new ReflectionFunction($function_name);

		if ($r->isDeprecated()) {
			continue;
		}

		$non_nullable = [];
		$unknowns = [];
		$parameters = [];

		foreach ($r->getParameters() as $parameter_id => $parameter) {

			$parameter_type = $parameter->getType();

			if ($parameter_type) {

				$type_names = [];
				foreach (($parameter_type instanceof ReflectionNamedType ? [$parameter_type] : $parameter_type->getTypes()) as $type) {
					$type_names[] = $type->getName();
				}

				if (!$parameter_type->allowsNull() && in_array('string', $type_names)) { // array, int, bool, false, finfo, float, null, object... and 'mixed'
					$non_nullable[] = $parameter_id;
				}

				$parameters[] = $parameter->getName() . ':' . implode('|' , $type_names);

			} else {

				$parameters[] = $parameter->getName() . ':?';

				if (!$parameter->allowsNull()) {
					$unknowns[] = $parameter_id;
				}

			}

		}

		if (count($non_nullable) > 0 || count($unknowns) > 0) {

			$function_definition = '- `' . $function_name . '`('; // (++$k)
			foreach ($parameters as $parameter_id => $parameter_info) {
				if ($parameter_id > 0) {
					$function_definition .= ', ';
				}
				if (in_array($parameter_id, $non_nullable)) {
					$function_definition .= '**' . $parameter_info . '**';
				} else if (in_array($parameter_id, $unknowns)) {
					$function_definition .= '_' . $parameter_info . '_';
				} else {
					$function_definition .= $parameter_info;
				}
			}
			$function_definition .= ')'; // implode(",", $non_nullable)

			$listed_args = ($functions_listed[$function_name] ?? NULL);

			if ($listed_args !== NULL) {

				foreach ($listed_args as $arg_number => $arg_info) {

					if ($arg_info['make_nullable']) {
						if (!in_array(($arg_number - 1), $non_nullable)) {
							echo 'Error: "' . $function_name . '", arg "' . $arg_info['name'] . '" is being asked to be nullable, when it already is?' . "\n";
							echo $function_definition . "\n";
						}
					} else {
						if (in_array(($arg_number - 1), $non_nullable)) {
							$ref = $arg_number . ':' . $arg_info['name'];
							if (in_array($ref, ($ignore_nullable[$function_name] ?? []))) {
								// echo 'Ignored: "' . $function_name . '", arg "' . $arg_info['name'] . '"' . "\n";
							} else {
								echo 'Error: "' . $function_name . '", arg "' . $ref . '" is NOT being asked to be nullable, when it could be?' . "\n";
							}
						}
					}

				}

			} else if (in_array($function_name, $functions_skipped)) {

				// Skipped

			} else {

				$other_functions[] = $function_definition;

			}

		}

	}

//--------------------------------------------------
// Cleanup

	unlink($tmp_file);

//--------------------------------------------------
// Output

	echo "\n\n";
	echo 'Remaining Errors';
	echo "\n";
	print_r($GLOBALS['null_errors']);

	echo "\n\n";
	echo 'Skipped Functions';
	echo "\n";
	print_r($functions_skipped);

	echo "\n\n";
	echo 'Other Functions';
	echo "\n";
	echo implode("\n", $other_functions);

?>