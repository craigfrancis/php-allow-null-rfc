
;(function(document, window, undefined) {

	'use strict';

	if (!document.addEventListener || !document.querySelector || !window.XMLHttpRequest || !window.FormData || !window.JSON) {
		return;
	}

	function offset_bottom(element) { // Use bottom, because it's the next question that may span multiple lines.
		if (!element) return 0;
		return offset_bottom(element.offsetParent) + element.offsetTop + element.offsetHeight;
	}

	var count_questions = [],
		count_wrapper = null,
		count_span = null,
		save_csrf_input = null,
		save_queue = {},
		save_xhr = null,
		save_response = null;

	function question_save(wrapper, new_selection) {

		var question,
			input_selection,
			input_fields,
			saving_wrapper,
			saving_img;

		if (new_selection) {
			input_selection = wrapper.querySelector('label.option[data-key="' + new_selection + '"] input[type="radio"]');
			input_selection.checked = true;
		} else {
			input_selection = wrapper.querySelector('label.option input[type="radio"]:checked');
		}
		if (input_selection) {
			save_queue[input_selection.name] = input_selection.value;
			wrapper.setAttribute('data-value', input_selection.value);
		} else {
			return;
		}

		input_fields = wrapper.querySelectorAll('input[type="hidden"], .notes input[type="text"]');
		for (var k = (input_fields.length - 1); k >= 0; k--) {

			save_queue[input_fields[k].name] = input_fields[k].value;

			if (input_fields[k].getAttribute('type').toLowerCase() == 'text') {
				saving_wrapper = input_fields[k].parentNode.querySelector('em');
				if (!saving_wrapper) {
					saving_img = document.createElement('img');
					saving_img.setAttribute('src', '/1609691221-loader.gif');
					saving_img.setAttribute('alt', 'Saving');
					saving_wrapper = document.createElement('em');
					saving_wrapper.setAttribute('class', 'loader');
					saving_wrapper.appendChild(saving_img);
					input_fields[k].parentNode.appendChild(saving_wrapper);
				}
			}

		}

		question_send();

	}

	function question_send() {

		if (save_xhr === null) {

			var data = new FormData();
			data.append('output', 'js');
			data.append(save_csrf_input.name, save_csrf_input.value);

			for (var field in save_queue) { // Count fields
				if (!save_queue.hasOwnProperty(field)) continue;
				data.append(field, save_queue[field]);
			}

			save_response = null;

			save_xhr = new XMLHttpRequest();
			save_xhr.open('POST', window.location, true);
			save_xhr.onreadystatechange = function() {
				if (this.readyState == 4) {
					if (this.status == 200) {
						try {
							save_response = JSON.parse(save_xhr.responseText);
						} catch (e) {
							save_response = null;
						}
					}
					window.setTimeout(question_complete, 300);
				}
			}
			save_xhr.send(data);

		}

	}

	function question_complete() {

		var field,
			value,
			notes_ref,
			loading_ref;

		if (save_response && save_response['success'] && save_response['confirm_saved']) {

			for (field in save_response['confirm_saved']) { // Count fields
				if (!save_response['confirm_saved'].hasOwnProperty(field)) continue;

				value = save_response['confirm_saved'][field];
				if (save_queue[field] === value) {
					delete save_queue[field];
				}

				if (field.slice(-1) === 'n') {
					notes_ref = document.querySelector('.notes input[type="text"][name="' + field + '"]');
					if (notes_ref) {
						loading_ref = notes_ref.parentNode.querySelector('em.loader');
						if (loading_ref) {
							loading_ref.parentNode.removeChild(loading_ref);
						}
					}
				}

			}

		}

		if (save_response && save_response['csrf']) {
			save_csrf_input.value = save_response['csrf'];
		}

		var questions_answered = 0,
			wrapper_classes = count_wrapper.className.replace(/\b(answered_none|answered_all)\b/g, ' ').trim();
		for (var k = (count_questions.length - 1); k >= 0; k--) {
			if (parseInt(count_questions[k].getAttribute('data-value'), 10) > 1) {
				questions_answered++;
			}
		}
		count_span.textContent = questions_answered;
		if (questions_answered == 0) {
			count_wrapper.className = wrapper_classes + ' answered_none';
		} else if (questions_answered == count_questions.length) {
			count_wrapper.className = wrapper_classes + ' answered_all';
		} else {
			count_wrapper.className = wrapper_classes;
		}

		save_xhr = null;
		save_response = null;

		if (Object.keys(save_queue).length > 0) {
			question_send();
		}

	}

	// Safari does not support: window.scrollBy({'top': (), 'behavior': 'smooth'});
	var scroll_move_main = 0,
		scroll_move_end = 0,
		scroll_updates = 10, // speed
		scroll_count = 0,
		scroll_timeout = null;
	function scroll_start(t) {
		scroll_move_main = Math.floor(t / scroll_updates);
		scroll_move_end = (t - (scroll_move_main * scroll_updates));
		scroll_count = 0;
		window.addEventListener('wheel', scroll_end);
		scroll_update();
	}
	function scroll_end() {
		if (scroll_timeout) {
			window.clearTimeout(scroll_timeout);
		}
		window.removeEventListener('wheel', scroll_end);
	}
	function scroll_update() {
		if (scroll_count === scroll_updates) {
			window.scrollBy(0, scroll_move_end);
			scroll_end();
		} else {
			scroll_count++;
			window.scrollBy(0, scroll_move_main);
			window.setTimeout(scroll_update, 10);
		}
	}

	function input_next(wrapper, direction_down) {
		var next_wrapper = (direction_down ? wrapper.nextElementSibling : wrapper.previousElementSibling);
		if (!next_wrapper || next_wrapper.tagName.toLowerCase() != 'fieldset') {
			var parent_section = wrapper.parentNode;
			while (parent_section && parent_section.tagName.toLowerCase() != 'section') {
				parent_section = parent_section.parentNode;
			}
			if (parent_section) {
				var next_section = (direction_down ? parent_section.nextElementSibling : parent_section.previousElementSibling);
				if (next_section) {
					next_wrapper = next_section.querySelector(direction_down ? 'h2:first-child + fieldset' : 'fieldset:last-child');
				}
			}
		}
		if (next_wrapper) {
			var next_input = next_wrapper.querySelector('input[type="radio"]:checked');
			if (next_input) {
				scroll_start(offset_bottom(next_wrapper) - offset_bottom(wrapper));
				next_input.focus();
			}
		}
	}

	function input_change(e) {
		var wrapper = this.parentNode;
		while (wrapper && wrapper.tagName.toLowerCase() != 'fieldset') {
			wrapper = wrapper.parentNode;
		}
		if (wrapper) {
			question_save(wrapper);
		}
	}

	var input_keys = ['d', 'a', 'f'];
	function input_keydown(e) {
		var wrapper = this.parentNode;
		while (wrapper && wrapper.tagName.toLowerCase() != 'fieldset') {
			wrapper = wrapper.parentNode;
		}
		if (wrapper) {
			if (input_keys.includes(e.key)) {
				question_save(wrapper, e.key);
				input_next(wrapper, true);
				e.preventDefault();
			} else if (e.key === 'ArrowUp') {
				input_next(wrapper, false);
				e.preventDefault();
			} else if (e.key === 'ArrowDown') {
				input_next(wrapper, true);
				e.preventDefault();
			}
		}
	}

	function label_mouseup(e) {
		var wrapper = this.parentNode;
		while (wrapper && wrapper.tagName.toLowerCase() != 'fieldset') {
			wrapper = wrapper.parentNode;
		}
		if (wrapper) {
			input_next(wrapper, true);
		}
	}

	function init() {

		var inputs = document.querySelectorAll('section.functions .option input[type="radio"]'),
			first_input = null;

		for (var l = inputs.length, k = 0; k < l; k++) {
			inputs[k].addEventListener('change', input_change);
			inputs[k].addEventListener('keydown', input_keydown);
			inputs[k].parentNode.addEventListener('mouseup', label_mouseup);
			if (first_input === null && inputs[k].checked && inputs[k].parentNode.getAttribute('data-key') === 'd') {
				first_input = inputs[k];
			}
		}

		var note_inputs = document.querySelectorAll('section.functions .notes input[type="text"]');
		for (var k = (note_inputs.length - 1); k >= 0; k--) {
			note_inputs[k].addEventListener('change', input_change);
		}

		if (first_input) {
			first_input.focus();
		}

		save_csrf_input = document.querySelector('input[name="csrf"]');

		count_questions = document.querySelectorAll('section.functions fieldset[data-value]');
		count_wrapper = document.querySelector('nav.sections ul li.current');
		if (count_wrapper) {
			count_span = count_wrapper.querySelector('span.answers span');
		}

	}

	if (document.readyState !== 'loading') {
		window.setTimeout(init); // Handle asynchronously
	} else {
		document.addEventListener('DOMContentLoaded', init);
	}

})(document, window);
