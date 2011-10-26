#
# This script is (C) Tenable Network Security
#


if(description)
{
 script_id(15443);
 script_cve_id("CVE-2004-1584");
 script_bugtraq_id(11348);
 script_version ("$Revision: 1.7 $");

 name["english"] = "WordPress HTTP Splitting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to HTTP
splitting attacks. 

Description :

According to its banner, the remote version of WordPress is vulnerable
to an HTTP-splitting attack wherein an attacker can insert CR LF
characters and then entice an unsuspecting user into accessing the URL. 
The client will parse and possibly act on the secondary header which was
supplied by the attacker. 

See also : 

http://www.securityfocus.com/archive/1/377770

Solution : 

Upgrade to WordPress version 1.2.1 or greater.

Risk factor : 

Low / CVSS Base Score : 1 
(AV:R/AC:L/Au:R/C:N/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for HTTP response splitting vulnerability in WordPress < 1.2.1";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("wordpress_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  # The actual attack requires credentials -> do a banner check.
  ver = matches[1];
  if (ver =~ "(0\.|1\.([01]|2[^0-9]))") { 
    security_note(port); 
    exit(0); 
  }
}
