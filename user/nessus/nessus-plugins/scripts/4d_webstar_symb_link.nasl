#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: @stake inc.
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14241);
 script_cve_id("CVE-2004-0698");
 script_bugtraq_id(10714);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "4D WebStar Symbolic Link Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running 4D WebStar FTP Server.

4D WebStar is reportedly vulnerable to a local symbolic link vulnerability.
This issue is due to a design error that causes the application
to open files without properly verifying their existence or their absolute location.

Successful exploitation of this issue will allow an attacker to write 
to arbitrary files writable by the affected application, 
facilitating privilege escalation.

See also : http://www.atstake.com/research/advisories/2004/a071304-1.txt
Solution : Upgrade to 4D WebStar 5.3.3 or later.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 4D FTP Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, "Services/ftp", 21);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) 
	exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 port = get_kb_item("Services/ftp");
 if ( ! port ) 
	port = 21;
 if ( ! get_port_state(port) ) 
	exit(0);
 ftpbanner = get_ftp_banner(port:port);
 if ( egrep(string:ftpbanner, pattern:"^220 FTP server ready\."))
 { 
  security_hole(port);
 }
}
