#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(14324);
 script_cve_id("CVE-2004-1730", "CVE-2004-1731", "CVE-2004-1734");
 script_bugtraq_id(10993, 10994, 10995);
 script_version ("$Revision: 1.7 $");

 name["english"] = "Mantis Multiple Flaws (2)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilties. 

Description :

According to its banner, the remote version of Mantis contains
multiple flaws that may allow an attacker to use it to perform a mass
emailing, to inject HTML tags in the remote pages, or to execute
arbitrary commands on the remote host if PHP's 'register_globals'
setting is enabled. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=109312225727345&w=2
http://marc.theaimsgroup.com/?l=bugtraq&m=109313416727851&w=2

Solution : 

Upgrade to Mantis 0.18.3 or 0.19.0a2 or newer.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)"; 

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.[0-2][^0-9]|19\.0 *a[01]([^0-9]|$))", string:ver))
	security_warning(port);
}	
