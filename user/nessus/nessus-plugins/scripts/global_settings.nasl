#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL, blah blah blah
#

if(description)
{
 script_id(12288);
 script_version ("$Revision: 1.10 $");

 name["english"] = "Global variable settings";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin configures miscellaneous global variables 
for Nessus scripts. It does not perform any security check
but may disable or change the behaviour of others.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Global variable settings";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SETTINGS);	
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");
 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN; Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"Log verbosity", type:"radio", value:"Normal;Quiet;Verbose;Debug");
 script_add_preference(name:"Debug level", type:"entry", value:"0");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"Mozilla/4.75 [en] (X11, U; Nessus)");

 exit(0);
}

opt = script_get_preference("Enable CGI scanning");
if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);

opt = script_get_preference("Enable experimental scripts");
if (! opt) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt) opt = "no";
set_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) set_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = script_get_preference("Log verbosity");
if (! opt) opt = "Quiet";
set_kb_item(name:"global_settings/log_verbosity", value:opt);

opt = script_get_preference("Debug level");
if (! opt) opt = "0";
set_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);

opt = script_get_preference("Network type");
if (! opt) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (! opt) opt = "Mozilla/4.75 [en] (X11, U; Nessus)";
set_kb_item(name:"global_settings/http_user_agent", value:opt);


