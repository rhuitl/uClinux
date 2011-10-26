#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: Stefan Esser <s.esser@e-matters.de>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14258);
 script_cve_id("CVE-2004-2255");
 script_bugtraq_id(10374);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"6300");
 
 script_version("$Revision: 1.7 $");

 name["english"] = "phpMyFAQ action parameter arbitrary file disclosure vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that permits information
disclosure of local files.

Description :

The version of phpMyFAQ on the remote host contains a flaw that may lead
to an unauthorized information disclosure.  The problem is that user
input passed to the 'action' parameter is not properly verified before
being used to include files, which could allow an remote attacker to
view any accessible file on the system, resulting in a loss of
confidentiality. 

See also : 

http://security.e-matters.de/advisories/052004.html
http://www.phpmyfaq.de/advisory_2004-05-18.php

Solution : 

Upgrade to phpMyFAQ 1.3.13 or newer.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check the version of phpMyFAQ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpmyfaq_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);
if ( ! can_host_php(port:port) ) 
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "(0\.|1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-2])))") security_note(port);
}
