#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
command execution attacks.

Description :

The remote host appears to be using the CdomainFree 'whois_raw.cgi'
script. 

This CGI script allows an attacker to view any file on the target
computer, as well as to execute arbitrary commands. 

See also :

http://cert.uni-stuttgart.de/archive/bugtraq/1999/06/msg00007.html

Solution : 

Upgrade to CdomainFree 2.5 or to one of the commercial versions.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(10306);
 script_bugtraq_id(304);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-1999-1063");
 
 name["english"] = "whois_raw";
 name["francais"] = "whois_raw";
 script_name(english:name["english"], francais:name["francais"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if whois_raw.cgi is vulnerable";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  http_check_remote_code(
    unique_dir:dir,
    check_request:string("/whois_raw.cgi?fqdn=%0Aid"),
    check_result:"uid=[0-9]+.*gid=[0-9]+.*",
    command:"id",
    description:desc["english"],
    port:port
  );
}
