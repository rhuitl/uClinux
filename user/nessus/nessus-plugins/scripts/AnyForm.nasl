#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10277);
 script_bugtraq_id(719);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-1999-0066");
 name["english"] = "AnyForm";
 name["francais"] = "AnyForm";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The CGI 'AnyForm2' is installed.
 
 
Old versions of this CGI have a well known security flaw that lets 
anyone execute arbitrary commands with the privileges of the http daemon 
(root or nobody).

Solution : remove it.
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of AnyForm2";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"AnyForm2", port:port);
if( res )security_hole(port);

