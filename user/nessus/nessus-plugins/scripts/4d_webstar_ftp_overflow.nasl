#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14195);
 script_cve_id("CVE-2004-0695");
 script_bugtraq_id(10720);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "4D WebStar FTP Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running 4D WebStar FTP Server.

There is a buffer overflow condition in the remote version of this
software. An attacker may exploit this flaw to execute arbitrary code 
on the remote host with the privileges of the FTP server (root).

See also : http://www.atstake.com/research/advisories/2004/a071304-1.txt
Solution : Upgrade to 4D WebStar 5.3.3 or later.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 4D FTP Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, "Services/ftp", 21);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same host
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 port = get_kb_item("Services/ftp");
 if ( ! port ) port = 21;
 if ( ! get_port_state(port) ) exit(0);
 ftpbanner = get_ftp_banner(port:port);
 if (egrep(string:ftpbanner, pattern:"^220 FTP server ready\."))
 { 
  security_hole(port);
 }
}
