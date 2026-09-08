#include "heuristic.h"
#include <encodings.h>
#include <vector>

#define MIN_SCRIPT_LENGTH 128

// C++23 implements the contains function for std::string but the compiler doesn't support that yet. So let's implement ourselves for now.
static bool string_contains(const std::string& str, const char* substr)
{
	return str.find(substr) != std::string::npos;
}

// Tests the HTML body for script tags having a minimum length.
// Email clients should ignore scripts, but attackers still like to try.
static bool test_html_script_tags(const std::string& body)
{
	// Find first occurrence of script tag.
	auto script_start = body.find("<script>");
	if (script_start == std::string::npos) return false;

	// Now find the nearest closing tag.
	auto script_end = body.find("</script>", script_start + 1);
	if (script_end == std::string::npos) return false;

	// Still here, so we have a completed script block inside the email. Test for the length as final check.
	const uint32_t script_length = script_end - (script_start + 8);
	return script_length >= MIN_SCRIPT_LENGTH;
}

// Analyzes mail message features using heuristics and outputs a score based on those results.
bool heuristic_proc(nlohmann::json& input, classifier_module_result& output)
{
	// We start with a score of zero, since we have no idea what we are dealing with yet.
	uint32_t score = 0;

	// Obtain body if applicable and decode it.
	std::string body;
	if (!input["mail"]["encoded_body"].is_null())
	{
		body = base64_decode(input["mail"]["encoded_body"]);
	}

	// Rule 1: script tags inside the body having a minimum, non-trivial length, add to the score of suspiciousness.
	if (test_html_script_tags(body)) score += 10;

	// Rule 2: not very strong but quite suspicious: at least two occurrences of the word 'iframe'.
	auto first_iframe_pos = body.find("iframe");
	if (first_iframe_pos != std::string::npos && body.find("iframe", first_iframe_pos + 1) != std::string::npos) score += 5;

	// Did any of the rules match? If so, output the result object.
	if (!score) return false;

	output.confidence = score;
	return true;
}
