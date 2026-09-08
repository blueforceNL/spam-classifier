#ifndef SCAM_GENERIC_H
#define SCAM_GENERIC_H

#include "module_result.h"

// Module procedure for the generic scam detection.
bool scam_generic_proc(nlohmann::json& input, classifier_module_result& output);

#endif
