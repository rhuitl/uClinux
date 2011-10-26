# This script was written by Renaud Deraison
#
# Ref :
#  Date: 20 Mar 2003 19:58:55 -0000
#  From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
#  To: bugtraq@securityfocus.com
#  Subject: [SCSA-011] Path Disclosure Vulnerability in XOOPS
#
# This check will incidentally cover other flaws.

if(description)
{
 script_id(11439);
 script_bugtraq_id(3977, 3978, 3981, 5785, 6344, 6393);
 script_cve_id("CVE-2002-0216", "CVE-2002-0217", "CVE-2002-1802");
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Xoops Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple vulnerabilities. 

Description :

The version of Xoops installed on the remote host is affected by SQL
injection, cross-site scripting, and information disclosure. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=104820295115420&w=2
http://marc.theaimsgroup.com/?l=bugtraq&m=101232435812837&w=2
http://marc.theaimsgroup.com/?l=bugtraq&m=101232476214247&w=2

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Xoops";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("xoops_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];

 req = http_get(item:string(d, "/index.php?xoopsOption=nessus"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( res == NULL ) exit(0);
 
 if(egrep(pattern:".*Fatal error.* in <b>/.*", string:res)){
 	security_warning(port);
	exit(0);
 }
}
