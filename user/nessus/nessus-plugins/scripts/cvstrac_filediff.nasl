#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
# Ref: Richard Ngo (August 2004)
# This script is released under the GNU GPLv2


if(description)
{
script_id(14220);
script_cve_id("CVE-2004-1456");
script_bugtraq_id(10878);

 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8373");
 script_version ("$Revision: 1.11 $");
 name["english"] = "CVSTrac filediff vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running cvstrac, 
a web-based bug and patch-set tracking system for CVS.

This version of filediff has a flaw in the input sanitation
which, when exploited, can lead to a remote attacker 
executing arbitrary commands on the system.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there. 

Solution : Update to version 1.1.4 or disable this CGI suite
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for CVSTrac version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 family["fancais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];
if(ereg(pattern:"^(0\.|1\.(0|1\.[0-3]([^0-9]|$)))", string:version))
 		security_hole(port);
