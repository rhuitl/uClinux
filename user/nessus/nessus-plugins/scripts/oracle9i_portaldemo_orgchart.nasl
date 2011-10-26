#
# This script was written by Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# License: GPL v 2.0  http://www.gnu.org/copyleft/gpl.html
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11918);
 script_version("$Revision: 1.3 $");
 name["english"] = "Oracle 9iAS PORTAL_DEMO ORG_CHART";
 name["francais"] = "Oracle 9iAS PORTAL_DEMO ORG_CHART";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In your installation of Oracle 9iAS, it is possible to access 
a demo (PORTAL_DEMO.ORG_CHART) via mod_plsql. Access to these pages should
be restricted, because it may be possible to abuse this demo for 
SQL Injection attacks.


Solution: 
Remove the Execute for Public grant from the PL/SQL package in schema
PORTAL_DEMO (REVOKE execute ON portal_demo.org_chart FROM public;).
Please check also Oracle Security Alert 61 for patch-information.

Reference : http://otn.oracle.com/deploy/security/pdf/2003alert61_2.pdf 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for presence of Oracle9iAS PORTAL_DEMO.ORG_CHART";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Frank Berger",
		francais:"Ce script est Copyright (C) 2003 Frank Berger");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80, 7777, 7778, 7779);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if( "Organization Chart" >< res )	
 	security_hole(port);
}
