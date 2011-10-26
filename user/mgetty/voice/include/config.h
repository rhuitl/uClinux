/*
 * voice_config.h
 *
 * This file contains the definitions for the structure and the prototype of
 * the configuration data. This is a bit tricky, but that way we can have
 * the complete description of the options in default.h, which makes it much
 * easier to add new options.
 *
 * $Id: config.h,v 1.4 1998/09/09 21:06:32 gert Exp $
 *
 */

/*
 * If CONFIG_C is set, we have to include the definition of the
 * configuration structure otherwise only the prototype.
 *
 */

#ifdef CONFIG_C

#undef KEYWORD
#undef CONF
#define KEYWORD(name) \
 {# name, {0}, CT_KEYWORD, C_IGNORE},
#define CONF(field_name, default_value, value_type) \
 {# field_name, {default_value}, value_type, C_PRESET},
 
struct conf_voice_data cvd =
     {
           
#else

#define STRING (p_int)
#define KEYWORD(name) \
 struct conf_data name;
#define CONF(field_name, default_value, value_type) \
 struct conf_data field_name;

extern struct conf_voice_data
     {

#endif

/*
 * Now we read the default values into the structure or prototype.
 *
 */

#include "default.h"

/*
 * And now we have to add the code for the end of the definition.
 *
 */

#ifdef CONFIG_C

     {NULL, {(p_int) ""}, CT_STRING, C_EMPTY}
     };

#else

     struct conf_data end_of_config;
     } cvd;

#endif
