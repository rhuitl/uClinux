#
# (C) Tenable Network Security
# This script is written by Shruti@tenablesecurity.com
#

if (description)
{
 script_id(15911);
 script_cve_id("CVE-2004-1219");
 script_bugtraq_id(11818);
 script_version ("$Revision: 1.4 $");

 script_name(english:"paFileDB password hash disclosure");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by an
information disclosure issue.

Description :

According to its version number, the remote installation of paFileDB is
vulnerable to an attack that would allow an attacker to view the
password hash of user accounts, including an administrator account, by
making a direct request to the application's 'sessions' directory.  This
may allow an attacker to perform brute force attack on the password hash
and gain access to account information. 

The vulnerability exists only when session-based authentication is
performed, which is not the default. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110245123927025&w=2

Solution: 

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines the version of paFileDB");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

 script_dependencies("pafiledb_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 ver = matches[1];
 if (ver =~ "^([0-2]|3\.0|3\.1( *b|$))") security_note(port);
}
