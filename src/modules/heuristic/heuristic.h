#ifndef HEURISTIC_H
#define HEURISTIC_H

#include "module_result.h"

// Module procedure for detecting malicious or unwanted emails by using heuristic.
bool heuristic_proc(nlohmann::json& input, classifier_module_result& output);

#endif
