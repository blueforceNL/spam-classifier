#include <cstdio>
#include <string>
#include <iostream>
#include <json.hpp>
#include "module.h"
#include "classifier_modules.h"

// Load detection modules into memory.
static void load_classifier_modules(std::vector<classifier_module>& mods)
{
	mods.push_back(classifier_module("heuristic", heuristic_proc));
	mods.push_back(classifier_module("scam_generic", scam_generic_proc));
	mods.push_back(classifier_module("advertisement", advertisement_proc));
}

int main(int argc, char** argv)
{
	// Parse command line arguments.
/*	bool help = false;
	for (int i = 0; i < argc; ++i)
	{
		std::string next(argv[i]);
		if (next.compare("-h") == 0 || next.compare("--help") == 0) help = true;
		else if (next.compare("-v"
		{

		}
	}*/

	// Read JSON input from STDIN.
	std::string json_input_string;
	for (std::string line; std::getline(std::cin, line);)
	{
		json_input_string += line;
	}

	// Import JSON string into nlohmann object.
	nlohmann::json input_json = nlohmann::json::parse(json_input_string);

	// Create output JSON object for the classifications.
	nlohmann::json output_json;
	output_json["version"] = input_json["version"];

	// Load modules for detection.
	std::vector<classifier_module> classifier_modules;
	load_classifier_modules(classifier_modules);

	// Iterate over the loaded modules and start detecting stuff.
	std::vector<nlohmann::json> detections;
	for (const classifier_module& mod : classifier_modules)
	{
		// Execute module procedure with given JSON input and collect the module result.
		classifier_module_result mod_result;
		bool res = mod.proc(input_json, mod_result);

		// Did the classifier module trigger detection or not?
		if (!res) continue;

		// Store the module result in the output JSON. The JSON serializer functions for the structs are automatically called.
		nlohmann::json mod_result_json;
		mod_result_json["name"] = mod.name;
		mod_result_json["confidence"] = mod_result.confidence;
		mod_result_json["indicators"] = mod_result.indicators;
		mod_result_json["attributes"] = mod_result.attributes;
		detections.push_back(mod_result_json);
	}

	// If there is at least one detection, place the detections object in the output JSON.
	if (detections.size() > 0) output_json["detections"] = detections;

	// Write classification JSON object to STDOUT and finish.
	std::cout << output_json.dump() << std::endl;
	return 0;
}
