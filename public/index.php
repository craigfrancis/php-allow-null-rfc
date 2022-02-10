<?php

//--------------------------------------------------
// Config

	define('ROOT', dirname(__FILE__));

	require_once(ROOT . '/../private/config.php');

	$now = new DateTime();
	$now_iso = $now->format('Y-m-d H:i:s');

	$output_results = ($_GET['results'] ?? NULL);
	if ($output_results !== NULL && $output_results !== 'all') {
		$output_results = intval($output_results);
	}

	$approach_label = 'How should PHP 9 work?';
	$approaches = [
			'1' => 'Update parameters to explicitly allow NULL (e.g. `?string`)',
			'2' => 'NULL should trigger a Fatal Error when using strict_types=1, for everyone else NULL should be accepted',
			'3' => 'NULL should trigger a Fatal Error for everyone',
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
			'approach' => ($_POST['approach'] ?? NULL),
			'voter'    => ($_POST['voter'] ?? NULL),
		];

	if ($output_results !== NULL) {

		if (is_int($output_results)) {

			$sql = 'SELECT
						`p`.`id`,
						`p`.`name`,
						`p`.`approach`,
						`p`.`voter`
					FROM
						`person` AS `p`
					WHERE
						`p`.`id` = ? AND
						`p`.`deleted` = "0000-00-00 00:00:00"';

			$statement = $db->prepare($sql);
			$statement->bind_param('i', $output_results);
			$statement->execute();
			$result = $statement->get_result();

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
						`p`.`created`
					FROM
						`person` AS `p`
					WHERE
						`p`.`deleted` = "0000-00-00 00:00:00"
					ORDER BY
						`p`.`created` DESC
					LIMIT
						50';

			$statement = $db->prepare($sql);
			$statement->execute();
			$result = $statement->get_result();

			$person_list = [];

			while ($row = $result->fetch_assoc()) {
				$person_list[$row['id']] = array_merge($row, [
						'created' => new DateTime($row['created']),
						'ended'   => new DateTime($row['created']),
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

				$parameters = [];
				$parameters[] = str_repeat('i', $person_count);
				foreach ($person_list as $id => $person) {
					$parameters[] = &$person_list[$id]['id'];
				}

				$statement = $db->prepare($sql);
				call_user_func_array([$statement, 'bind_param'], $parameters);
				$statement->execute();
				$result = $statement->get_result();

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
						`p`.`approach`,
						`p`.`voter`
					FROM
						`person` AS `p`
					WHERE
						`p`.`uuid` = ? AND
						`p`.`deleted` = "0000-00-00 00:00:00"';

			$statement = $db->prepare($sql);
			$statement->bind_param('s', $person_uuid);
			$statement->execute();
			$result = $statement->get_result();

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

				$statement = $db->prepare('INSERT INTO `person` (`id`, `uuid`, `ip`, `name`, `created`, `deleted`) VALUES ("", ?, ?, ?, ?, "0000-00-00 00:00:00")');
				$statement->bind_param('ssss', $person_uuid, $remote_ip, $person_details['name'], $now_iso);
				$statement->execute();

				$person_id = $statement->insert_id;

			} else {

				foreach ($person_new as $new_field => $new_value) {
					if ($new_value !== NULL && $person_details[$new_field] !== $new_value) {

						$statement = $db->prepare('INSERT INTO `person_log` (`person_id`, `created`, `field`, `old_value`, `new_value`) VALUES (?, ?, ?, ?, ?)');
						$statement->bind_param('issss', $person_id, $now_iso, $new_field, $person_details[$new_field], $new_value);
						$statement->execute();

						$statement = $db->prepare('UPDATE `person` SET `' . $new_field . '` = ? WHERE `id` = ? AND `deleted` = "0000-00-00 00:00:00"');
						$statement->bind_param('si', $new_value, $person_id);
						$statement->execute();

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

//--------------------------------------------------
// Current answers

	$current_answers = [];

	if ($person_id || is_int($output_results)) {

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

		$statement = $db->prepare($sql);
		$statement->bind_param('s', $select_id);
		$statement->execute();
		$result = $statement->get_result();

		while ($row = $result->fetch_assoc()) {
			$current_answers[$row['function']][$row['argument']] = [
					'selection' => intval($row['selection']),
					'notes'     => $row['notes'],
				];
		}

	}

//--------------------------------------------------
// Save answers

	if ($request_valid_post && $output_results === NULL) {

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

							$statement = $db->prepare('UPDATE `answer` SET `deleted` = ? WHERE `person_id` = ? AND `function` = ? AND `argument` = ? AND `deleted` = "0000-00-00 00:00:00"');
							$statement->bind_param('ssss', $now_iso, $person_id, $value_function, $value_argument);
							$statement->execute();

							if ($value_selection !== 1 || $value_notes !== '') {
								$statement = $db->prepare('INSERT INTO `answer` (`person_id`, `function`, `argument`, `selection`, `notes`, `created`, `deleted`) VALUES (?, ?, ?, ?, ?, ?, "0000-00-00 00:00:00")');
								$statement->bind_param('ssssss', $person_id, $value_function, $value_argument, $value_selection, $value_notes, $now_iso);
								$statement->execute();
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
		$url = (strtolower(trim($_POST['button'] ?? '')) == 'save' ? '/?results=all' : '/');
		header('Location: ' . $url);
		exit('<p>Go to <a href="' . htmlspecialchars($url) . '">next page</a>.</p>');
	}

//--------------------------------------------------
// Arguments

	$sections = [];
	$section_id = 0;
	$questions = [];
	$question_id = 0;
	$function_arguments = [];

	if ($person_id || is_int($output_results)) {

		$changes_md = file_get_contents(ROOT . '/../functions-change.md');
		$changes_md = array_filter(array_map('trim', explode("\n", $changes_md)));

		foreach ($changes_md as $change) {

			if (preg_match('/^## (.*)$/', $change, $matches)) {

				$section_id++;

				$sections[$section_id] = $matches[1];

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
	<meta name="description" content="Which PHP functions should accept NULL" />

</head>
<body>

	<p class="warning"><strong>Testing Mode: Answers will be deleted!</strong></p>

	<main>

		<h1>Allow NULL</h1>

		<p>A questionnaire to see which function parameters should continue to accept NULL, as per the <a href="https://wiki.php.net/rfc/allow_null" target="_blank" rel="noopener">Allow NULL RFC</a>.</p>

		<?php if ($person_list) { ?>

			<div class="basic_table">
				<table>
					<thead>
						<tr>
							<th scope="col">Person</th>
							<th scope="col">Accept NULL</th>
							<th scope="col">Fatal Error</th>
							<th scope="col">Start</th>
							<th scope="col">End</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($person_list as $p) { ?>
							<tr>
								<th><a href="<?= htmlspecialchars($p['url']) ?>"><?= htmlspecialchars($p['name']) ?></a></th>
								<td><strong class="accept_null"><?= htmlspecialchars($p['counts']['2']) ?></strong></td>
								<td><strong class="fatal_error"><?= htmlspecialchars($p['counts']['3']) ?></strong></td>
								<td><?= htmlspecialchars($p['created']->format('H:i - jS M Y')) ?></td>
								<td><?= htmlspecialchars($p['ended']->format('H:i - jS M Y')) ?></td>
							</tr>
						<?php } ?>
					</tbody>
				</table>
			</div>

		<?php } else { ?>

			<form action="./" method="post">

				<?php if (is_int($output_results)) { ?>

					<p>Results from <strong><?= htmlspecialchars($person_details['name']) ?></strong> (<a href="/?results=all">back</a>):</p>

				<?php } else { ?>

					<div class="row">
						<label for="field_name">Your Name:</label>
						<input id="field_name" name="name" type="text" value="<?= htmlspecialchars($person_details ? $person_details['name'] : '') ?>" maxlength="30" />
						<input type="submit" name="button" value="<?= htmlspecialchars($person_details ? 'Update' : 'Next') ?>" />
					</div>

				<?php } ?>

				<?php if ($person_details) { ?>

					<hr />

					<p>NULL is often used in PHP, e.g.</p>
					<code class="block">
						setcookie('name', 'value', 0, <span class="nullable">NULL</span>, <span class="nullable">NULL</span>, true, true);<br />
						<br />
						<span class="nullable">$search</span> = $request->get('q'); <span class="comment">// e.g. <a href="https://github.com/symfony/symfony/blob/34a265c286fe30a309ab77e57a1f69d7bbd76583/src/Symfony/Component/HttpFoundation/Request.php#L674" target="_blank" rel="noopener">Symfony returns NULL</a> if user value not provided (e.g. $_GET)</span><br />
						$results = $entries->findBy([<span class="literal_string">'name'</span> => trim(<span class="nullable">$search</span>]);<br />
						$url = <span class="literal_string">'./?q='</span> . urlencode(<span class="nullable">$search</span>);<br />
						echo <span class="literal_string">'Search for: '</span> . htmlspecialchars(<span class="nullable">$search</span>);
					</code>

					<p>Currently these functions have signatures that state they only accept strings, e.g.</p>

					<code class="block">
						<a href="https://php.net/trim" target="_blank" rel="noopener">trim</a>(string <span class="nullable">$string</span>, string $characters = " \n\r\t\v\x00"): string<br />
						<br />
						<a href="https://php.net/urlencode" target="_blank" rel="noopener">urlencode</a>(string <span class="nullable">$string</span>): string<br />
						<br />
						<a href="https://php.net/htmlspecialchars" target="_blank" rel="noopener">htmlspecialchars</a>(<br />
						&#xA0; &#xA0; string <span class="nullable">$string</span>,<br />
						&#xA0; &#xA0; int $flags = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401,<br />
						&#xA0; &#xA0; ?string <span class="nullable">$encoding</span> = null,<br />
						&#xA0; &#xA0; bool $double_encode = true<br />
						&#xA0; ): string<br />
					</code>

					<?php if (is_int($output_results)) { ?>

						<p>
							<?= htmlspecialchars($approach_label) ?>:
							<?php if (array_key_exists($person_details['approach'], $approaches)) { ?>
								<strong><?= htmlspecialchars($approaches[$person_details['approach']]) ?></strong>.
							<?php } else { ?>
								<strong>N/A</strong>
							<?php } ?>
						</p>

					<?php } else { ?>

						<fieldset class="row">
							<legend><?= htmlspecialchars($approach_label) ?>:</legend>
							<?php
								foreach ($approaches as $a => $approach) {
									echo '<p class="radio"><label><input type="radio" name="approach" value="' . htmlspecialchars($a) . '"' . ($person_details['approach'] == $a ? ' checked="checked"' : '') . ' /> <span>' . htmlspecialchars($approach) . '.</span></label></p>';
								}
							?>
							<p><input type="submit" name="button" value="<?= ($person_details['approach'] ? 'Update' : 'Next') ?>" /></p>
						</fieldset>

					<?php } ?>

				<?php } ?>

				<?php if ($person_details && $person_details['approach']) { ?>

					<hr />

					<p>We shouldn't update parameters where NULL is clearly an invalid value; e.g, PHP probably should complain with an empty $needle in <a href="https://php.net/strpos" target="_blank" rel="noopener">strpos()</a>, or $characters in <a href="https://php.net/strpos" target="_blank" rel="noopener">trim()</a>, or $method in <a href="https://php.net/strpos" target="_blank" rel="noopener">method_exists()</a>.</p>

					<p>While you can <a href="https://github.com/craigfrancis/php-allow-null-rfc/issues" target="_blank" rel="noopener">suggest additional parameters</a>; which of these parameters should continue to <strong class="accept_null">Accept NULL</strong>, or should NULL trigger a <strong class="fatal_error">Fatal Error</strong>?</p>

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
										<label class="option" data-key="e"><input type="radio" name="q<?= htmlspecialchars($q) ?>s" value="2"<?= ($question['current_selection'] == 2 ? ' checked="checked"' : '') ?> /> <span>Accept NULL</span></label>
										<label class="option" data-key="f"><input type="radio" name="q<?= htmlspecialchars($q) ?>s" value="3"<?= ($question['current_selection'] == 3 ? ' checked="checked"' : '') ?> /> <span>Fatal Error</span></label>

										<label class="notes"><span>Notes:</span> <input type="text" name="q<?= htmlspecialchars($q) ?>n" value="<?= htmlspecialchars($question['current_notes']) ?>" maxlength="200" /></label>

									<?php } ?>

								</fieldset>

							<?php } ?>

						</section>

					<?php } ?>

					<div><input type="submit" name="button" value="Save" /></div>

				<?php } ?>

				<div>
					<input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf_val) ?>" />
				</div>

			</form>

		<?php } ?>

	</main>

	<p class="warning"><strong>Testing Mode: Answers will be deleted!</strong></p>

	<footer>
		<p>© <a href="https://twitter.com/craigfrancis" target="_blank" rel="noopener">Craig Francis</a> 2022</p>
	</footer>

</body>
</html>