#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15939);
 script_bugtraq_id(11845);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"7976");

 name["english"] = "PunBB install.php XSS";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.5 $"); 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
several cross-site scripting vulnerabilities. 

Description :

The remote version of PunBB is vulnerable to cross-site scripting
flaws through 'install.php' script.  With a specially-crafted URL, an
attacker can inject arbitrary HTML and script code into a user's
browser resulting in the possible theft of authentication cookies,
mis-representation of site contents, and the like. 

See also :

http://www.punbb.org/changelogs/1.1.1_to_1.1.2.txt

Solution : 

Update to PunBB version 1.1.2 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PunBB install.php XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("punBB_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.1)",string:ver))
  {
    security_note(port);
    exit(0);
  }
}
