#include "scam_generic.h"

#define CONFIDENCE_REASONABLE 60
#define CONFIDENCE_NO_INDICATOR 30

// C++23 implements the contains function for std::string but the compiler doesn't support that yet. So let's implement ourselves for now.
static bool string_contains(const std::string& str, const char* substr)
{
	return str.find(substr) != std::string::npos;
}

// Checks the subject for matching keywords.
static bool subject_contains_keywords(const std::string& subject)
{
	// Check the subject against some basic Dutch and English keywords like: hacked.
	if (string_contains(subject, "hacked") || string_contains(subject, "gehackt") || string_contains(subject, "leaked") ||
		string_contains(subject, "gestolen") || string_contains(subject, "stolen")) return true;

	// Bad news oriented subject.
	if (string_contains(subject, "bad") && string_contains(subject, "news")) return true;

	// Security notice.
	if (string_contains(subject, "security notice")) return true;

	// Payment oriented.
	if (string_contains(subject, "openstaande betaling") || string_contains(subject, "pending for payment") ||
		string_contains(subject, "you have outstanding debt") || string_contains(subject, "betalingsachterstand") ||
		(string_contains(subject, "betaling") && string_contains(subject, "rekening"))) return true;

	// Oriented around the attacker recording the victim.
	if (string_contains(subject, "i recorded you")) return true;

	// Found nothing.
	return false;
}

// Analyzes mail message results to determine whether it classifies as a generic scam such as 'your computer is hacked, send me btc'.
bool scam_generic_proc(nlohmann::json& input, classifier_module_result& output)
{
	// Check whether the subject of the mail contains strings like 'hacked'. Check case-insensitive.
	std::string subject = !input["mail"]["subject"].is_null() ? input["mail"]["subject"] : "";
	std::transform(subject.begin(), subject.end(), subject.begin(), [](unsigned char c){ return std::tolower(c); });
	if (!subject_contains_keywords(subject))
	{
		// Check the bounced subject as well, as this type of spam mails might have been bounced.
		std::string bounced_subject = !input["mail"]["bounced_subject"].is_null() ? input["mail"]["bounced_subject"] : "";
		std::transform(bounced_subject.begin(), bounced_subject.end(), bounced_subject.begin(), [](unsigned char c){ return std::tolower(c); });
	 	if (!subject_contains_keywords(bounced_subject)) return false;
	}

	// However, there are plenty of emails with sketchy titles but no, or incorrectly formatted BTC addresses.
	// We don't want to discard those emails, so we just scale down the confidence.
	// There must also be at least one BTC address of course.
	output.confidence = CONFIDENCE_NO_INDICATOR;
	if (input.contains("extracted_btc") && input["extracted_btc"].size() > 0)
	{
		// Upgrade the confidence of the detection.
		output.confidence = CONFIDENCE_REASONABLE;

		// Store the result and BTC addresses as indicators.
		for (const std::string& btc : input["extracted_btc"])
		{
			output.indicators.push_back(indicator(indicator_type::btc, btc, CONFIDENCE_REASONABLE));
		}
	}

	// Still here, also store the sender IP address as indicator. This address has been sending spam emails.
	// In a later stage when generating the blacklist we might filter down on IPs that have occurred on at
	// least two occasions for example, to reduce false positives.
	const std::string& sender_ip = input["mail"]["sender_ip"];
	if (sender_ip.size() > 0 && sender_ip[0] != 0)
	{
		// Store the sender IP as indicator with the specified confidence.
		output.indicators.push_back(indicator(indicator_type::ip, sender_ip, output.confidence));
	}

	return true;
}
