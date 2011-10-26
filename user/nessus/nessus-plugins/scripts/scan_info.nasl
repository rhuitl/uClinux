#
# (C) Tenable Network Security
# 
# This script is released under the GPLv2
#

if(description)
{
 script_id(19506);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Information about the scan";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays, for each tested host, information about the scan itself:

 - The version of the plugin set
 - The type of plugin feed (Direct, Registered or GPL)
 - The version of the Nessus Engine
 - The port scanner(s) used
 - The port range scanned
 - The date of the scan
 - The duration of the scan
 - The number of hosts scanned in parallel
 - The number of checks done in parallel

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Displays information about the scan";
 script_summary(english:summary["english"]);
 
 script_category(ACT_END);
 
 
 script_copyright(english:"This script is released under the GNU GPLv2");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}

include('plugin_feed_info.inc');
include('global_settings.inc');


NESSUS2 = make_list(2,2,8);
NESSUS3 = make_list(3,0,3);

array = split(NESSUS_VERSION, sep:'.', keep:FALSE);
myVersion = make_list(int(array[0]), int(array[1]), int(array[2]));

if ( myVersion[0] == 2 && ( myVersion[1] < NESSUS2[1] || (myVersion[1] == NESSUS2[1] && myVersion[2] < NESSUS2[2]) ) ) new_vers = string(NESSUS2[0], ".", NESSUS2[1], ".", NESSUS2[2]);
if ( myVersion[0] == 3 && ( myVersion[1] < NESSUS3[1] || (myVersion[1] == NESSUS3[1] && myVersion[2] < NESSUS3[2]) ) ) new_vers = string(NESSUS3[0], ".", NESSUS3[1], ".", NESSUS3[2]);





# 
# If no plugin has shown anything, quietly exit
#
list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0);


if ( ! strlen(NESSUS_VERSION) )
	{
	if ( ! defined_func("pread") && NASL_LEVEL >= 2202 )
		version = "NeWT";
	else
		version = "Unknown (NASL_LEVEL=" + NASL_LEVEL + ")";
	}
 else
	version = NESSUS_VERSION;


if ( new_vers )
 version += " (Nessus " + new_vers + ' is available - consider upgrading)\n';

report = 'Information about this scan : \n\n';
report += 'Nessus version : ' + version + '\n';

if ( PLUGIN_SET )
{
 report += 'Plugin feed version : ' + PLUGIN_SET     + '\n';
 report += 'Type of plugin feed : ' + PLUGIN_FEED    + '\n';
}

report += 'Scanner IP : ' + this_host()    + '\n';


list = get_kb_list("Host/scanners/*");
if ( ! isnull(list) )
{
 foreach item ( keys(list) )
 {
  item -= "Host/scanners/";
  scanners += item + ' ';
 }

 report += 'Port scanner(s) : ' + scanners + '\n';
}


range = get_preference("port_range");
if ( ! range ) range = "(?)";
report += 'Port range : ' + range + '\n';

report += 'Thorough tests : ';
if ( thorough_tests ) report += 'yes\n';
else report += 'no\n';

report += 'Experimental tests : ';
if ( experimental_scripts ) report += 'yes\n';
else report += 'no\n';

report += 'Paranoia level : ';
report += report_paranoia + '\n';

report += 'Report Verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';


start = get_kb_item("/tmp/start_time");



if ( start )
{
 time = localtime(start);
 if ( time["min"] < 10 ) zero = "0";
 else zero = NULL;

 report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' + zero + time["min"] + '\n';
}



if ( ! start ) scan_duration = 'unknown (ping_host.nasl not launched?)';
else           scan_duration = string (unixtime() - start, " sec");
report += 'Scan duration : ' + scan_duration + '\n';






security_note(port:0, data:report);

