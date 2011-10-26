#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# The real DoS will be performed by plugin#10930, so we just check
# the banner 
#

if(description)
{
 script_id(11209);
 script_cve_id("CVE-2003-0016");
 script_bugtraq_id(6659);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0003");
 script_version("$Revision: 1.7 $");
 
 name["english"] = "Apache < 2.0.44 DOS device name";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of
Apache for Windows which is older than 2.0.44

There are several flaws in this version which allow
an attacker to crash this host or even execute arbitrary
code remotely, but it only affects WindowsME and Windows9x


*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive

Solution : Upgrade to version 2.0.44
See also : http://www.apache.org/dist/httpd/Announcement.html
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
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
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-3][0-9][^0-9])|(4[0-3][^0-9])).*Win32.*", string:serv))
 {
   security_hole(port);
 }
}
