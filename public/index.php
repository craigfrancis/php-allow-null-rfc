<?php

//--------------------------------------------------
// Config

	define('ROOT', dirname(__FILE__));

	require_once(ROOT . '/../private/config.php');

	if (PHP_VERSION_ID < 80000) {
		function str_contains($haystack, $needle) {
			return ($needle == '' || strpos($haystack, $needle) !== false);
		}
		function str_starts_with($haystack, $needle) {
			return (strncmp($haystack, $needle, strlen($needle)) === 0);
		}
		function str_ends_with($haystack, $needle) {
			return ($needle === '' || ($haystack !== '' && substr_compare($haystack, $needle, 0 - strlen($needle)) === 0));
		}
	}

	$results_limit = 50;

	$now = new DateTime();
	$now_iso = $now->format('Y-m-d H:i:s');

	$output_results = ($_GET['results'] ?? NULL);
	if ($output_results !== NULL && $output_results !== 'all') {
		$output_results = intval($output_results);
	}

	$page = intval($_GET['page'] ?? 0);

	$approach_label = 'How should PHP 9 work?';
	$approaches = [
			'1' => 'NULL triggers a Fatal Error with strict_types=1, otherwise use coercion (like how integers can be coerced to a string)',
			'2' => 'NULL triggers a Fatal Error for everyone, but update some parameters to explicitly allow NULL (e.g. `?string`)',
			'3' => 'NULL triggers a Fatal Error for everyone (forget about backwards compatibility)',
			'4' => 'Don\'t Mind',
		];

//--------------------------------------------------
// Database

	mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

	$db = mysqli_init();

	if ($db_ca_certificate) {
		$db->ssl_set(NULL, NULL, $db_ca_certificate, NULL, NULL);
	}

	if (!$db->real_connect($db_host, $db_user, $db_pass, $db_name, NULL, NULL, ($db_ca_certificate ? MYSQLI_CLIENT_SSL : 0))) {
		exit('<p>Cannot connect to database</p>');
	}

	function db_query($sql, $parameters) {
		global $db;
		$ref_types = '';
		$ref_values = [];
		foreach ($parameters as $key => $value) {
			$ref_types .= (is_int($value) ? 'i' : 's'); // 'd' for double, or 'b' for blob.
			$ref_values[] = &$parameters[$key];
		}
		array_unshift($ref_values, $ref_types);
		if (function_exists('is_literal') && !is_literal($sql)) {
			exit('SQL is not a literal.');
		}
		$statement = $db->prepare($sql);
		call_user_func_array([$statement, 'bind_param'], $ref_values);
		$statement->execute();
		return $statement;
	}

	function db_select($sql, $parameters) {
		$statement = db_query($sql, $parameters);
		return $statement->get_result();
	}

//--------------------------------------------------
// JavaScript

	$output_js = (($_POST['output'] ?? NULL) === 'js');

	if ($output_js) {
		header('Content-Type: application/json; charset=UTF-8');
	}

//--------------------------------------------------
// CSRF

	$csrf_cookie = '__Host-c';
	$csrf_val = intval($_COOKIE[$csrf_cookie] ?? 0);
	$csrf_min = 1000000;
	$csrf_max = 9999999;

	$request_valid_post = false;

	if ($csrf_val < $csrf_min || $csrf_val > $csrf_max) {

		$csrf_val = random_int($csrf_min, $csrf_max);

	} else if ($csrf_val === intval($_POST['csrf'] ?? 0)) {

		$request_valid_post = true;

	}

	setcookie($csrf_cookie, $csrf_val, [
			'path'     => '/',
			'secure'   => true,
			'httponly' => true,
			'samesite' => 'Lax',
		]);

//--------------------------------------------------
// Person

	$person_cookie = '__Host-p';
	$person_list = NULL;
	$person_id = NULL;
	$person_uuid = trim(strval($_COOKIE[$person_cookie] ?? ''));
	$person_details = NULL;
	$person_new = [
			'name'     => ($_POST['name'] ?? NULL),
			'notes'    => ($_POST['notes'] ?? NULL),
			'approach' => ($_POST['approach'] ?? NULL),
			'voter'    => ($_POST['voter'] ?? NULL),
		];

	$approach_building = false;
	foreach ($approaches as $a => $approach) {
		$append = ($_POST['approach_' . $a] ?? NULL);
		if ($append !== NULL) {
			$person_new['approach'] = trim($person_new['approach'] . '-' . $a, '-');
			$approach_building = true;
		}
	}

	if ($output_results !== NULL) {

		if (is_int($output_results)) {

			$sql = 'SELECT
						`p`.`id`,
						`p`.`name`,
						`p`.`notes`,
						`p`.`approach`,
						`p`.`voter`
					FROM
						`person` AS `p`
					WHERE
						`p`.`id` = ? AND
						`p`.`deleted` = "0000-00-00 00:00:00"';

			$result = db_select($sql, [$output_results]);

			if ($row = $result->fetch_assoc()) {
				$person_details = $row;
			} else {
				$output_results = 'all';
			}

		}

		if (!is_int($output_results)) {

			$sql = 'SELECT
						`p`.`id`,
						`p`.`name`,
						`p`.`notes`,
						`p`.`approach`,
						`p`.`created`,
						`p`.`edited`
					FROM
						`person` AS `p`
					WHERE
						`p`.`approach` != "" AND
						`p`.`deleted` = "0000-00-00 00:00:00"
					ORDER BY
						`p`.`created` DESC
					LIMIT
						?';

			$result = db_select($sql, [$results_limit]);

			$person_list = [];

			while ($row = $result->fetch_assoc()) {
				$person_list[$row['id']] = array_merge($row, [
						'created' => new DateTime($row['created']),
						'ended'   => new DateTime($row['edited']),
						'url'     => '/?results=' . urlencode($row['id']),
						'counts'  => ['2' => 0, '3' => 0],
					]);
			}

			$person_count = count($person_list);

			if ($person_count > 0) {

				$in_sql = '?';
				for ($k = 1; $k < $person_count; $k++) {
					$in_sql .= ',?';
				}

				$sql = 'SELECT
							`a`.`person_id`,
							`a`.`selection`,
							COUNT(`a`.`function`) AS `c`,
							MAX(`a`.`created`) AS m
						FROM
							`answer` AS `a`
						WHERE
							`a`.`person_id` IN (' . $in_sql . ') AND
							`a`.`deleted` = "0000-00-00 00:00:00"
						GROUP BY
							`a`.`person_id`,
							`a`.`selection`';

				$result = db_select($sql, array_keys($person_list));

				while ($row = $result->fetch_assoc()) {
					$person_list[$row['person_id']]['counts'][$row['selection']] = $row['c'];
					$ended = new DateTime($row['m']);
					if ($person_list[$row['person_id']]['ended'] < $ended) {
						$person_list[$row['person_id']]['ended'] = $ended;
					}
				}

			}

		}

	} else {

		if ($person_uuid !== '') {

			$sql = 'SELECT
						`p`.`id`,
						`p`.`name`,
						`p`.`notes`,
						`p`.`approach`,
						`p`.`voter`
					FROM
						`person` AS `p`
					WHERE
						`p`.`uuid` = ? AND
						`p`.`deleted` = "0000-00-00 00:00:00"';

			$result = db_select($sql, [$person_uuid]);

			if ($row = $result->fetch_assoc()) {
				$person_id = intval($row['id']);
				$person_details = $row;
			} else {
				$person_uuid = '';
			}

		}

		if ($request_valid_post) {

			$remote_ip = ($_SERVER['REMOTE_ADDR'] ?? '-');

			if ($person_uuid === '') {

				$person_uuid = random_bytes(16); // https://stackoverflow.com/a/15875555/6632
				$person_uuid[6] = chr(ord($person_uuid[6]) & 0x0f | 0x40); // set version to 0100
				$person_uuid[8] = chr(ord($person_uuid[8]) & 0x3f | 0x80); // set bits 6-7 to 10
				$person_uuid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($person_uuid), 4));

				$person_details['name'] = strval($person_new['name']);
				$person_details['notes'] = strval($person_new['notes']);

				$sql = 'INSERT INTO `person` (
							`id`,
							`uuid`,
							`ip`,
							`name`,
							`notes`,
							`created`,
							`edited`,
							`deleted`
						) VALUES (
							"",
							?,
							?,
							?,
							?,
							?,
							?,
							"0000-00-00 00:00:00"
						)';

				$statement = db_query($sql, [$person_uuid, $remote_ip, $person_details['name'], $person_details['notes'], $now_iso, $now_iso]);

				$person_id = $statement->insert_id;

			} else {

				foreach ($person_new as $new_field => $new_value) {
					if ($new_value !== NULL && strval($person_details[$new_field]) !== strval($new_value)) {

						$sql = 'INSERT INTO `person_log` (
									`person_id`,
									`created`,
									`field`,
									`old_value`,
									`new_value`
								) VALUES (
									?,
									?,
									?,
									?,
									?
								)';

						db_query($sql, [$person_id, $now_iso, $new_field, $person_details[$new_field], $new_value]);

						$sql = 'UPDATE
									`person`
								SET
									`' . $new_field . '` = ?,
									edited = ?
								WHERE
									`id` = ? AND
									`deleted` = "0000-00-00 00:00:00"';

						db_query($sql, [$new_value, $now_iso, $person_id]);

						$person_details[$new_field] = $new_value;

					}
				}

			}

		}

		if ($person_uuid !== '') {

			setcookie($person_cookie, $person_uuid, [
					'path'     => '/',
					'secure'   => true,
					'httponly' => true,
					'samesite' => 'Strict',
				]);

		}

	}

	if ($person_id === NULL && $page > 0) {
		$url = '/';
		header('Location: ' . $url);
		exit('<p>Go to <a href="' . htmlspecialchars($url) . '">next page</a>.</p>');
	}

//--------------------------------------------------
// Selected approaches

	$person_approaches = ($_GET['approach'] ?? NULL);
	if ($person_approaches === NULL && isset($person_details['approach'])) {
		$person_approaches = $person_details['approach'];
	}

	$person_approaches = array_unique(array_filter(array_map('trim', explode('-', strval($person_approaches)))));

//--------------------------------------------------
// Current answers

	$current_answers = [];

	if ($page >= 3 || is_int($output_results)) {

		$sql = 'SELECT
					`a`.`function`,
					`a`.`argument`,
					`a`.`selection`,
					`a`.`notes`
				FROM
					`answer` AS `a`
				WHERE
					`a`.`person_id` = ? AND
					`a`.`deleted` = "0000-00-00 00:00:00"';

		$select_id = ($output_results ? $output_results : $person_id);

		$result = db_select($sql, [$select_id]);

		while ($row = $result->fetch_assoc()) {
			$current_answers[$row['function']][$row['argument']] = [
					'selection' => intval($row['selection']),
					'notes'     => $row['notes'],
				];
		}

	}

//--------------------------------------------------
// Save answers

	if ($page >= 3 && $request_valid_post && $output_results === NULL) {

		$confirm_saved = [];

		$question_values = [];
		foreach ($_POST as $name => $value) {
			if (preg_match('/^q([0-9]+)(f|s|n)$/', $name, $matches) && is_string($value)) {
				if (!isset($question_values[$matches[1]])) {
					$question_values[$matches[1]] = array_fill_keys(['f', 's', 'n'], NULL);
				}
				$question_values[$matches[1]][$matches[2]] = $value;
			}
		}
		$new_values = [];
		foreach ($question_values as $question_id => $v) {

			if ($v['f'] !== NULL && $v['s'] !== NULL && $v['n'] !== NULL) {

				$value_function  = strval($v['f']);

				if (($pos = strpos($value_function, ':')) !== false) {

					$value_argument = substr($value_function, ($pos + 1));
					$value_function = substr($value_function, 0, $pos);

					$value_selection = intval($v['s']);
					$value_notes     = strval($v['n']);

					if ($value_function !== '' && strlen($value_argument) > 0 && in_array($value_selection, [1, 2, 3])) {

						$value_argument = intval($value_argument);

						$current_answer = ($current_answers[$value_function][$value_argument] ?? NULL);

						$confirmed = false;

						if ($current_answer && $current_answer['selection'] == $value_selection && $current_answer['notes'] == $value_notes) {

							$confirmed = true; // No Change

						} else {

							$sql = 'UPDATE
										`answer`
									SET
										`deleted` = ?
									WHERE
										`person_id` = ? AND
										`function` = ? AND
										`argument` = ? AND
										`deleted` = "0000-00-00 00:00:00"';

							db_query($sql, [$now_iso, $person_id, $value_function, $value_argument]);

							if ($value_selection !== 1 || $value_notes !== '') {

								$sql = 'INSERT INTO `answer` (
											`person_id`,
											`function`,
											`argument`,
											`selection`,
											`notes`,
											`created`,
											`deleted`
										) VALUES (
											?,
											?,
											?,
											?,
											?,
											?,
											"0000-00-00 00:00:00"
										)';

								db_query($sql, [$person_id, $value_function, $value_argument, $value_selection, $value_notes, $now_iso]);

							}

							$confirmed = true;

						}

						if ($confirmed && $output_js) {
							foreach ($v as $field => $value) {
								$confirm_saved['q' . $question_id . $field] = $value;
							}
						}

					}

				}

			}

		}

		if ($output_js) {
			exit(json_encode(['success' => true, 'confirm_saved' => $confirm_saved]));
		}

	} else if ($output_js) {

		exit(json_encode(['success' => false, 'csrf' => $csrf_val]));

	}

//--------------------------------------------------
// Drop POST request (browser refresh)

	if ($request_valid_post) {
		$button = strtolower(trim($_POST['button'] ?? ''));
		if ($button === 'save') {
			$url = '/?results=all';
		} else {
			if ($button === 'next' || $button === 'continue') {
				$page++;
			}
			$url = '/?page=' . urlencode($page);
		}
		if ($approach_building) {
			if (count($person_approaches) == count($approaches)) {
				$url = '/?page=2';
			} else {
				$url .= '&approach=' . urlencode($person_new['approach']); // Support back button
			}
		}
		header('Location: ' . $url);
		exit('<p>Go to <a href="' . htmlspecialchars($url) . '">next page</a>.</p>');
	}

//--------------------------------------------------
// Arguments

	$sections = [];
	$section_id = 0;
	$section_last = NULL;
	$section_pages = NULL;
	$section_answers = [];
	$questions = [];
	$question_id = 0;
	$function_arguments = [];

	if ($page >= 3 || is_int($output_results)) {

		$changes_md = file_get_contents(ROOT . '/../functions-change.md');
		$changes_md = array_filter(array_map('trim', explode("\n", $changes_md)));

		foreach ($changes_md as $change) {

			if (preg_match('/^## (.*)$/', $change, $matches)) {

				$section_id++;

				$sections[$section_id] = $matches[1];
				$section_answers[$section_id] = 0;

			} else if ($section_id > 0 && preg_match('/^- `([^`]+)`\(([^\)]+)\)$/', $change, $matches)) {

				$function = $matches[1];

				$arguments = array_filter(array_map('trim', explode(',', $matches[2])));

				foreach ($arguments as $k => $argument) {
					if (str_starts_with($argument, '**') && str_ends_with($argument, '**')) {

						$arguments[$k] = substr($argument, 2, -2);

						$label = $arguments[$k];
						if (($pos = strpos($label, ':')) !== false) {
							$label = substr($label, 0, $pos);
						}

						$question_id++;

						$current_answer = ($current_answers[$function][$k] ?? NULL);

						if ($current_answer) {
							$section_answers[$section_id]++;
						}

						$questions[$section_id][$question_id] = [
								'function'          => $function,
								'function_url'      => 'https://php.net/' . urlencode($function),
								'argument'          => $k,
								'current_selection' => ($current_answer ? $current_answer['selection'] : 1),
								'current_notes'     => ($current_answer ? $current_answer['notes'] : ''),
							];

					}
				}

				$function_arguments[$function] = $arguments;

			} else if (!in_array($change, ['# To Change', 'Only change parameters which are in **bold**.'])) {

				var_dump($change);
				exit();

			}

		}

		if ($page >= 3) {

			$section_pages = [];
			foreach ($sections as $section_id => $section_name) {
				$section_page_id = ($section_id + 2);
				$section_pages[] = [
						'id' => $section_page_id,
						'name' => $section_name,
						'answers' => $section_answers[$section_id],
						'questions' => count($questions[$section_id] ?? []),
						'url' => '/?page=' . urlencode($section_page_id),
					];
			}

			$focus_selection = ($page - 2);
			if (isset($sections[$focus_selection])) {
				if (!isset($sections[$focus_selection + 1])) {
					$section_last = true;
				}
				$sections = [$focus_selection => $sections[$focus_selection]];
			}

		}

	}

//--------------------------------------------------
// CSS

	$css_path = ROOT . '/styles.css';
	$css_url = str_replace(ROOT, '', $css_path);

	if (is_file($css_path)) {
		$css_hash = 'sha256-' . base64_encode(hash('sha256', file_get_contents($css_path), true));
		if (($p = strrpos($css_url, '/')) !== false) {
			$css_url = substr($css_url, 0, ($p + 1)) . filemtime($css_path) . '-' . substr($css_url, ($p + 1));
		}
	} else {
		$css_hash = '';
	}

//--------------------------------------------------
// JS

	$js_path = ROOT . '/form.js';
	$js_url = str_replace(ROOT, '', $js_path);

	if (is_file($js_path)) {
		$js_hash = 'sha256-' . base64_encode(hash('sha256', file_get_contents($js_path), true));
		if (($p = strrpos($js_url, '/')) !== false) {
			$js_url = substr($js_url, 0, ($p + 1)) . filemtime($js_path) . '-' . substr($js_url, ($p + 1));
		}
	} else {
		$js_hash = '';
	}

//--------------------------------------------------
// Headers

	header("Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'; block-all-mixed-content");
	header("Permissions-Policy: accelerometer=(), autoplay=(), camera=(), ch-device-memory=(), ch-downlink=(), ch-dpr=(), ch-ect=(), ch-prefers-color-scheme=(), ch-rtt=(), ch-ua=(), ch-ua-arch=(), ch-ua-bitness=(), ch-ua-full-version=(), ch-ua-full-version-list=(), ch-ua-mobile=(), ch-ua-model=(), ch-ua-platform=(), ch-ua-platform-version=(), ch-viewport-width=(), ch-width=(), clipboard-read=(), clipboard-write=(), cross-origin-isolated=(self), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(self), payment=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=(), sync-xhr=(), picture-in-picture=()");

	if (str_starts_with(ROOT, '/Volumes')) {
		header("Content-Type: application/xhtml+xml; charset=UTF-8");
	}

?>
<!DOCTYPE html>
<html lang="en-GB" xml:lang="en-GB" xmlns="http://www.w3.org/1999/xhtml">
<head>

	<meta charset="UTF-8" />

	<script src="<?= htmlentities($js_url) ?>" async="async" integrity="<?= htmlentities($js_hash) ?>"></script>

	<meta http-equiv="Content-Security-Policy" content="script-src 'none'" /> <!-- No scripts after this -->

	<title>Allow NULL</title>

	<link rel="stylesheet" type="text/css" href="<?= htmlentities($css_url) ?>" media="all" integrity="<?= htmlentities($css_hash) ?>" />
	<link href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQEAYAAABPYyMiAAAABmJLR0T///////8JWPfcAAAACXBIWXMAAABIAAAASABGyWs+AAAAF0lEQVRIx2NgGAWjYBSMglEwCkbBSAcACBAAAeaR9cIAAAAASUVORK5CYII=" rel="icon" type="image/x-icon" />

	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="description" content="How should NULL be handled?" />

</head>
<body>

	<!-- <p class="warning"><strong>Testing Mode: Answers will be deleted!</strong></p> -->

	<main>

		<h1>Allow NULL</h1>

		<p>A questionnaire on how to implement the <a href="https://wiki.php.net/rfc/allow_null" target="_blank" rel="noopener">Allow NULL RFC</a>.</p>

		<?php if ($person_list) { ?>

			<?php if (count($person_list) >= $results_limit) { ?>
				<p>Only showing the last <strong><?= htmlspecialchars($results_limit) ?></strong> results.</p>
			<?php } ?>

			<h2 class="sub_heading">Results</h2>
			<div class="basic_table">
				<table>
					<thead>
						<tr>
							<th scope="col">Person</th>
							<th scope="col">Approach</th>
							<th scope="col">Accept NULL</th>
							<th scope="col">Fatal Error</th>
							<th scope="col">Start</th>
							<th scope="col">End</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($person_list as $p) { ?>
							<tr>
								<th>
									<?php if ($p['name'] == '') { ?>
										<a href="<?= htmlspecialchars($p['url']) ?>">N/A</a>
									<?php } else { ?>
										"<a href="<?= htmlspecialchars($p['url']) ?>"><?= htmlspecialchars($p['name']) ?></a>"
									<?php } ?>
								</th>
								<td><?= htmlspecialchars($p['approach'] == '' ? '-' : str_replace('-', ', ', $p['approach'])) ?></td>
								<td><strong class="accept_null"><?= htmlspecialchars($p['counts']['2'] == 0 ? '-' : 'x' . $p['counts']['2']) ?></strong></td>
								<td><strong class="fatal_error"><?= htmlspecialchars($p['counts']['3'] == 0 ? '-' : 'x' . $p['counts']['3']) ?></strong></td>
								<td><?= htmlspecialchars($p['created']->format('H:i - jS M Y')) ?></td>
								<td><?= htmlspecialchars($p['ended']->format('H:i - jS M Y')) ?></td>
							</tr>
						<?php } ?>
					</tbody>
				</table>
			</div>

			<h2 class="sub_heading">Approaches:</h2>
			<ol>
				<?php foreach ($approaches as $approach) { ?>
					<li><?= htmlspecialchars($approach) ?></li>
				<?php } ?>
			</ol>

		<?php } else { ?>

			<form action="/?page=<?= htmlspecialchars(urlencode($page)) ?>" method="post">

				<?php if (is_int($output_results)) { ?>

					<p>Results from <strong><?= htmlspecialchars($person_details['name']) ?></strong> (<a href="/?results=all">back</a>)</p>

					<?php if ($person_details['notes']) { ?>
						<p class="person_notes"><?= htmlspecialchars($person_details['notes']) ?></p>
					<?php } ?>

				<?php } else if ($page > 0) { ?>

					<p>Your Name: <strong><?= htmlspecialchars($person_details['name']) ?></strong> (<a href="/">edit</a>)</p>

				<?php } else { ?>

					<div class="row person_name">
						<label for="field_name">Your Name:</label>
						<input id="field_name" name="name" type="text" value="<?= htmlspecialchars($person_details ? $person_details['name'] : '') ?>" maxlength="30" />
					</div>

					<div class="row person_notes">
						<label for="field_notes">Notes About You:</label>
						<input id="field_notes" name="notes" type="text" value="<?= htmlspecialchars($person_details ? $person_details['notes'] : '') ?>" maxlength="200" />
						<span>e.g. Do you maintain any open source projects? Can you vote on this RFC? etc.</span>
					</div>

					<div><input type="submit" name="button" value="Next" /></div>

				<?php } ?>

				<?php if ($person_details) { ?>

					<?php if ($page == 1) { ?>

						<hr />

						<?php if (count($person_approaches) == 0) { ?>

							<p></p>

							<p>When <strong>not</strong> using `strict_types=1`, "PHP will coerce values of the wrong type into the expected scalar type declaration if possible" (<a href="https://www.php.net/manual/en/language.types.declarations.php#language.types.declarations.strict">ref</a>).</p>

							<p>NULL is coerced to an empty string, the integer/float 0, or the boolean false.</p>

							<p>NULL has frequently been used by developers, e.g.</p>
							<code class="block">
								<a href="https://php.net/mail" target="_blank" rel="noopener">mail</a>('nobody@example.com', 'subject', 'message', <span class="nullable">NULL</span>, '-fwebmaster@example.com');<br />
								<br />
								<a href="https://php.net/setcookie" target="_blank" rel="noopener">setcookie</a>('name', 'value', 0, <span class="nullable">NULL</span>, <span class="nullable">NULL</span>, true, true);<br />
								<br />
								<span class="nullable">$search</span> = $request->get('q'); <span class="comment">// Frameworks like <a href="https://github.com/symfony/symfony/blob/34a265c286fe30a309ab77e57a1f69d7bbd76583/src/Symfony/Component/HttpFoundation/Request.php#L674" target="_blank" rel="noopener">Symfony</a> return NULL if a user value is not provided (e.g. $_GET)</span><br />
								$results = $entries->findBy([<span class="literal_string">'name'</span> => <a href="https://php.net/trim" target="_blank" rel="noopener">trim</a>(<span class="nullable">$search</span>]);<br />
								$url = <span class="literal_string">'./?q='</span> . <a href="https://php.net/urlencode" target="_blank" rel="noopener">urlencode</a>(<span class="nullable">$search</span>);<br />
								echo <span class="literal_string">'Search for: '</span> . <a href="https://php.net/htmlspecialchars" target="_blank" rel="noopener">htmlspecialchars</a>(<span class="nullable">$search</span>);<br />
								<br />
								echo <span class="literal_string">'Random: '</span> . <a href="https://php.net/htmlspecialchars" target="_blank" rel="noopener">htmlspecialchars</a>(rand(1, 6));
							</code>

							<p>But these are using coercion, e.g.</p>

							<code class="block">
								<a href="https://php.net/trim" target="_blank" rel="noopener">trim</a>(<span class="nullable">string</span> $string, string $characters = " \n\r\t\v\x00"): string<br />
								<br />
								<a href="https://php.net/urlencode" target="_blank" rel="noopener">urlencode</a>(<span class="nullable">string</span> $string): string<br />
								<br />
								<a href="https://php.net/htmlspecialchars" target="_blank" rel="noopener">htmlspecialchars</a>(<br />
								&#xA0; &#xA0; <span class="nullable">string</span> $string,<br />
								&#xA0; &#xA0; int $flags = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401,<br />
								&#xA0; &#xA0; <strong>?string</strong> $encoding = null,<br />
								&#xA0; &#xA0; bool $double_encode = true<br />
								&#xA0; ): string<br />
							</code>

							<p>PHP 8.1 introduced "Deprecate passing null to non-nullable arguments of internal functions" (<a href="https://externals.io/message/112327">discussion</a>), to create consistency between internal and user-defined functions. But, with the possible exception of Craig Duncan, there was no discussion about the inconsistency of NULL coercion compared to string/int/float/bool values, and the difficulty involved in updating existing code.</p>

							<p>It's worth noting that some parameters should not accept NULL <em>or</em> an Empty String. For example, $separator in <a href="https://php.net/explode" target="_blank" rel="noopener">explode</a>() already has a "cannot be empty" Fatal Error. A different RFC could consider updating more parameters to consistently reject NULL <em>or</em> Empty Strings, e.g. $needle in <a href="https://php.net/strpos" target="_blank" rel="noopener">strpos</a>() and $json in <a href="https://php.net/json_decode" target="_blank" rel="noopener">json_decode</a>().</p>

						<?php } ?>

						<fieldset class="row">
							<legend><?= htmlspecialchars($approach_label) ?></legend>
							<input type="hidden" name="approach" value="<?= htmlspecialchars(implode('-', $person_approaches)) ?>" />
							<?php

								if (count($person_approaches) == 0) {
									echo '
										<p>Please rank these 4 options, starting with your 1st choice.</p>';
								} else {
									echo '
										<ol>';
									$change = [];
									foreach ($person_approaches as $a) {
										echo '
											<li>' . htmlentities($approaches[$a]) . ' - <a href="' . htmlentities('/?page=1&approach=' . urlencode(implode('-', $change))) . '">Change</a></li>';
										$change[] = $a;
									}
									echo '
										</ol>';
								}

								$question = 'Next Choice';
								switch (count($person_approaches)) {
									case 0:
										$question = '1st Choice';
										break;
									case 1:
										$question = '2nd Choice';
										break;
									case 2:
										$question = '3rd Choice';
										break;
									case 3:
										$question = '4th Choice';
										break;
								}
								foreach ($approaches as $a => $approach) {
									if (!in_array($a, $person_approaches)) {
										echo '
											<p class="choice"><label><input type="submit" name="approach_' . htmlspecialchars($a) . '" value="' . htmlspecialchars($question) . ':" /> <span>' . htmlspecialchars($approach) . '.</span></label></p>';
									}
								}
								if (count($person_approaches) > 0) {
									echo '
										<p>Or <input type="submit" name="button" value="Continue" /></p>';
								}

							?>
						</fieldset>

					<?php } else if ($page >= 2 || is_int($output_results)) { ?>

						<div>
							<?= htmlspecialchars($approach_label) ?><?= ($page >= 2 ? ' (<a href="/?page=1&amp;approach=">edit</a>)' : '') ?>
							<ol>
								<?php foreach ($person_approaches as $a) { ?>
									<li><?= htmlentities($approaches[$a]) ?>.</li>
								<?php } ?>
								<?php if (count($person_approaches) == 0) { ?>
									<li>N/A</li>
								<?php } ?>
							</ol>
						</div>

					<?php } ?>

				<?php } ?>

				<?php if ($page == 2) { ?>

					<hr />

					<p>Thank you.</p>

					<p>There is an <strong>optional</strong> second part to this questionnaire.</p>

					<p><strong>If</strong> we "update some parameters to explicitly allow NULL" (e.g. `?string`), we should confirm which functions should be updated.</p>

					<p>For example, there is no point allowing NULL for $needle in <a href="https://php.net/strpos" target="_blank" rel="noopener">strpos()</a>, $characters in <a href="https://php.net/strpos" target="_blank" rel="noopener">trim()</a>, or $method in <a href="https://php.net/strpos" target="_blank" rel="noopener">method_exists()</a>.</p>

					<p>You can <a href="https://github.com/craigfrancis/php-allow-null-rfc/issues" target="_blank" rel="noopener">suggest additional parameters</a>; and what follows is a "short-list" of 335 parameters.</p>

					<div><input type="submit" name="button" value="Continue" /></div>

				<?php } else if ($person_details && $person_details['approach'] && ($page >= 3 || is_int($output_results))) { ?>

					<hr />

					<p>Which of the following parameters should continue to <strong class="accept_null">Accept NULL</strong>, or should NULL trigger a <strong class="fatal_error">Fatal Error</strong>?</p>

					<?php foreach ($sections as $section_id => $section_name) { ?>

						<section class="functions">
							<h2><?= htmlspecialchars($section_name) ?></h2>
							<?php foreach ($questions[$section_id] as $q => $question) { ?>

								<fieldset data-value="<?= htmlspecialchars($question['current_selection']) ?>">

									<?php

										echo '<legend><a href="' . htmlspecialchars($question['function_url']) . '" target="_blank" rel="noopener">' . str_replace('_', '_<wbr />', htmlspecialchars($question['function'])) . '</a><wbr />(';
										foreach ($function_arguments[$question['function']] as $k => $argument) {
											if ($k > 0) {
												echo ', ';
											}
											if ($k == $question['argument']) {
												echo '<strong>' . htmlspecialchars($argument) . '</strong>';
											} else {
												echo '<span>' . htmlspecialchars($argument) . '</span>';
											}
										}
										echo ')</legend>' . "\n";

									?>

									<?php if (is_int($output_results)) { ?>

										<?php if ($question['current_selection'] == 1) { ?>
											<span class="option">Don't Mind</span>
										<?php } else if ($question['current_selection'] == 2) { ?>
											<span class="option accept_null">Accept NULL</span>
										<?php } else if ($question['current_selection'] == 3) { ?>
											<span class="option fatal_error">Fatal Error</span>
										<?php } ?>

										<?php if ($question['current_notes']) { ?>
											<span class="notes"><?= htmlspecialchars($question['current_notes']) ?></span>
										<?php } ?>

									<?php } else { ?>

										<input type="hidden" name="q<?= htmlspecialchars($q) ?>f" value="<?= htmlspecialchars($question['function']) ?>:<?= htmlspecialchars($question['argument']) ?>" />

										<label class="option" data-key="d"><input type="radio" name="q<?= htmlspecialchars($q) ?>s" value="1"<?= ($question['current_selection'] == 1 ? ' checked="checked"' : '') ?> /> <span>Don't Mind</span></label>
										<label class="option" data-key="a"><input type="radio" name="q<?= htmlspecialchars($q) ?>s" value="2"<?= ($question['current_selection'] == 2 ? ' checked="checked"' : '') ?> /> <span>Accept NULL</span></label>
										<label class="option" data-key="f"><input type="radio" name="q<?= htmlspecialchars($q) ?>s" value="3"<?= ($question['current_selection'] == 3 ? ' checked="checked"' : '') ?> /> <span>Fatal Error</span></label>

										<label class="notes"><span>Notes:</span> <input type="text" name="q<?= htmlspecialchars($q) ?>n" value="<?= htmlspecialchars($question['current_notes']) ?>" maxlength="200" /></label>

									<?php } ?>

								</fieldset>

							<?php } ?>

						</section>

					<?php } ?>

					<?php if ($page >= 3) { ?>

						<div><input type="submit" name="button" value="<?= htmlspecialchars($section_last ? 'Save' : 'Next') ?>" /></div>

						<hr />

						<nav class="sections">
							<ul>
								<?php
									foreach ($section_pages as $p) {
										$classes = [];
										$classes[] = ($p['id'] == $page ? 'current' : 'other');
										if ($p['answers'] == 0) {
											$classes[] = 'answered_none';
										} else if ($p['answers'] == $p['questions']) {
											$classes[] = 'answered_all';
										}
										echo '
											<li class="' . htmlspecialchars(implode(' ', $classes)) . '"><a href="' . htmlspecialchars($p['url']) . '">' . htmlspecialchars($p['name']) . '</a> <span class="answers"><span>' . htmlspecialchars($p['answers']) . '</span> of </span><span class="questions">' . htmlspecialchars($p['questions']) . '</span></li>';
									}
									echo "\n";
								?>
							</ul>
						</nav>

					<?php } ?>

				<?php } ?>

				<div>
					<input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf_val) ?>" />
				</div>

			</form>

		<?php } ?>

	</main>

	<!-- <p class="warning"><strong>Testing Mode: Answers will be deleted!</strong></p> -->

	<footer>
		<p>© <a href="https://twitter.com/craigfrancis" target="_blank" rel="noopener">Craig Francis</a> 2022</p>
	</footer>

</body>
</html>