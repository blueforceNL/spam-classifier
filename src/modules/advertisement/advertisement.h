#ifndef ADVERTISEMENT_H
#define ADVERTISEMENT_H

#include "module_result.h"

// Module procedure for detection of mails regarding unwanted advertisement.
bool advertisement_proc(nlohmann::json& input, classifier_module_result& output);

#endif
