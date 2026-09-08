#include "indicator.h"

// Converts indicator type to string representation in the JSON output.
std::string indicator_type_to_string(const indicator_type& type)
{
	switch (type)
	{
		case indicator_type::btc:
			return "btc";
		case indicator_type::url:
			return "url";
		case indicator_type::domain:
			return "domain";
		case indicator_type::ip:
			return "ip";
		case indicator_type::iban:
			return "iban";
		case indicator_type::phone:
			return "phone";
		default:
			return "unknown";
	}
}

// Converts indicator structure to JSON when called by the nlohmann objects.
void to_json(nlohmann::json& j, const indicator& i)
{
	j = nlohmann::json{{"type", indicator_type_to_string(i.type)}, {"value", i.value}, {"confidence", i.confidence}};
}
