#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
#  Ref: Paul Richards
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14344);
 script_bugtraq_id(9184);
 script_version ("$Revision: 1.5 $");

 name["english"] = "Mantis multiple unspecified XSS";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone
to cross-site scripting attacks.

Description :

According to its banner, the remote version of Mantis contains a flaw
in the handling of some types of input.  Because of this, an attacker
may be able to cause arbitrary HTML and script code to be executed in
a user's browser within the security context of the affected web site. 

See also :

http://sourceforge.net/project/shownotes.php?release_id=202559

Solution : 

Upgrade to Mantis 0.18.1 or newer.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)"; 


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2003 David Maciejak");
 family["english"] = "CGI abuses : XSS";
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

  if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.0[^0-9])", string:ver))
	security_note(port);
}
