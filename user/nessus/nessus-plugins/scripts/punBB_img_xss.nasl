#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15937);
 script_bugtraq_id(11850);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"7977");

 name["english"] = "PunBB IMG Tag Client Side Scripting XSS";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.5 $"); 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
a cross-site scripting vulnerability. 

Description :

The remote version of PunBB is vulnerable to cross-site scripting
flaws because the application does not validate IMG tag.  With a
specially crafted URL, an attacker can cause arbitrary code execution
within a user's browser, resulting in a loss of integrity. 

See also :

http://www.punbb.org/changelogs/1.0_to_1.0.1.txt

Solution : 

Update to PunBB version 1.0.1 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PunBB version";
 
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

include('http_func.inc');

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (egrep(pattern: "^(0\.|1\.0[^.])",string:ver))
  {
    security_note(port);
    exit(0);
  }
}
