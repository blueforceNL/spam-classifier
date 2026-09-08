#ifndef MODULE_RESULT_H
#define MODULE_RESULT_H

#include "indicator.h"
#include <map>

// Defines a module result.
struct classifier_module_result
{
	// Specifies the confidence the module gives to it, between 0 and 100.
	uint32_t confidence;

	// The list of indicators, if successful.
	std::vector<indicator> indicators;

	// The list of attributes stored with a detection.
	std::map<std::string, std::string> attributes;
};

#endif
