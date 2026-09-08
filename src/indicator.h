#ifndef INDICATOR_H
#define INDICATOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <json.hpp>

// The indicator types the classifier supports.
enum class indicator_type
{
	domain,
	url,
	btc,
	ip,
	iban,
	phone
};

// Converts indicator type to string representation in the JSON output.
std::string indicator_type_to_string(const indicator_type& type);

// Specifies an indicator.
struct indicator
{
	// Indicator type.
	indicator_type type;

	// Value of the indicator.
	std::string value;

	// Level of confidence, between 0 and 100.
	uint32_t confidence;

	// Default constructor.
	indicator(const indicator_type& type, const std::string& value, const uint32_t confidence)
	{
		this->type = type;
		this->value = value;
		this->confidence = confidence;
	};
};

// Serialization function to convert indicator struct to JSON automatically.
void to_json(nlohmann::json& j, const indicator& p);

#endif
