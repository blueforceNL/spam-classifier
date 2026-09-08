#include "advertisement.h"
#include <vector>

#define CONFIDENCE_MEDIOCRE 50

// Defines a group of advertisements.
struct advertisement_group
{
	const char* name;
	uint32_t num_matches;

	advertisement_group(const char* name, const uint32_t num_matches)
	{
		this->name = name;
		this->num_matches = num_matches;
	};
};

// C++23 implements the contains function for std::string but the compiler doesn't support that yet. So let's implement ourselves for now.
static bool string_contains(const std::string& str, const char* substr)
{
	return str.find(substr) != std::string::npos;
}

// Checks the subject for matching keywords and returns whether matches were found and in which groups.
// Note: Since best matches will only occur on a greater number of matches than the previous, we need to
// implement the groups with the most keywords first in this function.
static bool subject_contains_keywords(const std::string& subject, std::vector<advertisement_group>& matches)
{
	// Pharmacy ads commonly are about erectile disfunction or painkillers for example.
	uint32_t num_matches = 0;
	if (string_contains(subject, "erectile")) ++num_matches;
	if (string_contains(subject, "viagra")) ++num_matches;
	if (string_contains(subject, "painkiller")) ++num_matches;
	if (string_contains(subject, "pharmacy")) ++num_matches;
	if (string_contains(subject, "pills")) ++num_matches;
	if (string_contains(subject, "cialis")) ++num_matches;
	if (string_contains(subject, "levitra")) ++num_matches;
	if (num_matches) matches.push_back(advertisement_group("pharmacy", num_matches));

	// Found nothing.
	return matches.size() > 0;
}

// Analyzes mail message results to determine whether it contains unwanted advertisements.
bool advertisement_proc(nlohmann::json& input, classifier_module_result& output)
{
	// Check whether any URLs were extracted from the mail message. If not, we will discard it right away.
	if (!input.contains("extracted_urls")) return false;

	// There must also be at least one URL in the message.
	if (input["extracted_urls"].size() == 0) return false;

	// Test the subject against a series of known keywords.
	std::string subject = input["mail"]["subject"];
	std::transform(subject.begin(), subject.end(), subject.begin(), [](unsigned char c){ return std::tolower(c); });
	std::string bounced_subject = !input["mail"]["bounced_subject"].is_null() ? input["mail"]["bounced_subject"] : "";
	std::transform(bounced_subject.begin(), bounced_subject.end(), bounced_subject.begin(), [](unsigned char c){ return std::tolower(c); });
	std::vector<advertisement_group> matches;
	if (!subject_contains_keywords(subject, matches) && !subject_contains_keywords(bounced_subject, matches)) return false;

	// We found matches, so let's inspect those further.
	const advertisement_group* best_match = NULL;
	for (const advertisement_group& group : matches)
	{
		// Any groups having less than two matches are ignored.
		if (group.num_matches < 2) continue;

		// Keep track of the best match we have, given we have multiple advertisement groups.
		if (!best_match || best_match->num_matches < group.num_matches) best_match = &group;
	}

	// Did we find any advertisement group having at least two keyword matches?
	if (!best_match) return false;

	// Set the best matched group as attribute.
	output.attributes["group"] = best_match->name;

	// Store the output confidence and URLs as indicators.
	output.confidence = CONFIDENCE_MEDIOCRE;
	for (const std::string& url : input["extracted_urls"])
	{
		output.indicators.push_back(indicator(indicator_type::url, url, CONFIDENCE_MEDIOCRE));
	}

	// Still here, so this mail is probably an unwanted advertisement.
	return true;
}
