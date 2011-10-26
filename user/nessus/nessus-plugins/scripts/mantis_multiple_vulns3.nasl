#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(15651);
 script_bugtraq_id(11622);
 script_version ("$Revision: 1.2 $");

 name["english"] = "Mantis Multiple Flaws (3)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple vulnerabilities. 

Description :

According to its banner, the remote version of Mantis suffers from
several information disclosure vulnerabilities that may allow an
attacker to view stats of all projects or to receive information for a
project after he was removed from it. 

See also :

http://bugs.mantisbt.org/view.php?id=3117
http://bugs.mantisbt.org/view.php?id=4341

Solution : 

Upgrade to Mantis 0.19.1 or newer.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)"; 

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

  if(ereg(pattern:"^0\.(0?[0-9]\.|1([0-8]\.|9\.0))", string:ver))
	security_note(port);
	
}
