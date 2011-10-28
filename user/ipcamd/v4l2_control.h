#pragma once

#include "config.h"

int ctrl_get_value(int control_id);
void ctrl_set_value(int control_id, int val);

int jpeg_get_quality();
void jpeg_set_quality(int quality);

#ifdef ENUM_CONTROLS
void enumerate_controls();
#endif
