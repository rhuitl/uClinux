#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10808);
 script_bugtraq_id(3760, 3762);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0102");
 
 name["english"] = "DoSable Oracle WebCache server";
 script_name(english:name["english"]);
 desc["english"] = "
There is a bug in the remote version of OracleWebCache
which allows any attacker to disable this service 
remotely.

An attacker may use this flaw to prevent outsiders from
accessing your website.

Solution: Contact your vendor for the latest software release.

*** Note that Nessus solely relied on the version number of the remote
*** service to issue this warning

Risk factor : Medium";
 script_description(english:desc["english"]);
 summary["english"] = "Determines via ver. the remote server can be disabled";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 script_dependencies("find_service.nes", "proxy_use.nasl");
 script_require_ports(1100, 4000, 4001, 4002, "Services/www");
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:1100);
ports = add_port_in_list(list:ports, port:4000);
ports = add_port_in_list(list:ports, port:4001);
ports = add_port_in_list(list:ports, port:4002);

foreach port (ports)
{
data = get_http_banner(port:port);
if(egrep(pattern:".*Oracle9iAS Web Cache/2\.0\.0\.[012].*",
	  string:data))security_warning(port);
}
