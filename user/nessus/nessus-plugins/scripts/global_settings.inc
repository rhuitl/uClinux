# -*- sh -*-
global_var	experimental_scripts, report_verbosity, log_verbosity, debug_level, thorough_tests, report_paranoia;

experimental_scripts = 0;
report_verbosity = 1;
debug_level = 0;
log_verbosity = 1;
thorough_tests = 0;
report_paranoia = 1;
all_addr_private = 0;
all_addr_public = 0;


__gs_opt = get_kb_item("global_settings/network_type");
if (__gs_opt)
{
  if ("LAN" >< __gs_opt) all_addr_private = 1;
  else if ("Internet" >< __gs_opt) all_addr_public = 1;
}




__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}

__gs_opt = get_kb_item("global_settings/report_paranoia");
if (__gs_opt)
{
  if ("Avoid false alarms" >< __gs_opt) report_paranoia = 0;
  else if ("Normal" >< __gs_opt) report_paranoia = 1;
  else if ("Paranoid" >< __gs_opt) report_paranoia = 2;
}

__gs_opt = get_kb_item("global_settings/log_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) log_verbosity = 1;
  else if ("Quiet" >< __gs_opt) log_verbosity = 0;
  else if ("Verbose" >< __gs_opt) log_verbosity = 2;
  else if ("Debug" >< __gs_opt)
  {
   log_verbosity = 3;
   __gs_opt = get_kb_item("global_settings/debug_level");
   if (__gs_opt =~ '^[0-9]+$') debug_level = int(__gs_opt);
   if (debug_level <= 0) debug_level = 1;
  }
}

if (COMMAND_LINE) experimental_scripts = 1;
else
{
 __gs_opt = get_kb_item("global_settings/experimental_scripts");
  if ( __gs_opt )
  {
   if ( "no" >< __gs_opt ) experimental_scripts = 0;
   else if ("yes" >< __gs_opt) experimental_scripts = 1;
  }
}

__gs_opt = get_kb_item("global_settings/thorough_tests");
if ( __gs_opt )
{
 if ( "no" >< __gs_opt) thorough_tests = 0;
 else if ("yes" >< __gs_opt) thorough_tests = 1;
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 if ( NASL_LEVEL < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function log_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level <= 0 || log_verbosity < level) return;
 if ( NASL_LEVEL < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("LOG: ", msg);
}

GLOBAL_SETTINGS_INC = 1;
