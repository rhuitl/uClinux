#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Wed, 2 Apr 2003 09:38:28 +0200
#  From: Lars Eilebrecht <lars@apache.org>
#  To: bugtraq@securityfocus.com
#  Subject: [ANNOUNCE] Apache 2.0.45 Released


if(description)
{
 script_id(11507);
 script_bugtraq_id(7254, 7255);
 script_cve_id("CVE-2003-0132");

 script_version("$Revision: 1.14 $");
 
 name["english"] = "Apache < 2.0.45";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of
Apache 2.x which is older than 2.0.45

This version is vulnerable to various flaws :

- There is a denial of service attack which may allow
an attacker to disable this server remotely

- The httpd process leaks file descriptors to child processes,
such as CGI scripts. An attacker who has the ability to execute
arbitrary CGI scripts on this server (including PHP code) would
be able to write arbitrary data in the file pointed to (in particular,
the log files)

Solution : Upgrade to version 2.0.45
See also : http://www.apache.org/dist/httpd/CHANGES_2.0
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if( safe_checks() )
{
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-4])", string:serv))
 {
   security_hole(port);
 }
}
else if(egrep(pattern:"Apache(-AdvancedExtranetServer)/2", string:serv))
{
 if ( egrep(pattern:"Apache(-AdvancedExtranetServer)?/([3-9]\.|2\.([1-9]|0\.([5-9][0-9]|4[6-9])))", string:serv) ) exit(0);


 soc = open_sock_tcp(port);
 for(i=0;i<101;i++)
 {
  n = send(socket:soc, data:string("\r\n"));
  if(n <= 0)exit(0);
 }

 r = http_recv(socket:soc);
 if(!r)security_hole(port);
 }
}
