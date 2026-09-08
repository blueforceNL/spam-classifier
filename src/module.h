#ifndef MODULE_H
#define MODULE_H

#include "module_result.h"

// Defines a module that implements a certain detection for spam mails.
struct classifier_module
{
	// Display name of the module and hence the detection.
	std::string name;

	// Pointer to function implementing the classification.
	bool (*proc)(nlohmann::json& input, classifier_module_result& output);

	// Parameterized constructor to ease initialization of modules.
	classifier_module(const std::string& name, bool (*proc)(nlohmann::json& input, classifier_module_result& output))
	{
		this->name = name;
		this->proc = proc;
	};
};

#endif
