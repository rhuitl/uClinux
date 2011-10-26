#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Braden Thomas <bjthomas@usc.edu>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18212);
 script_cve_id("CVE-2005-1507");
 script_bugtraq_id(13538, 14192);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"16154");
 }
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "4D WebStar Tomcat Plugin Remote Buffer Overflow flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running 4D WebStar Web Server.

The remote server is vulnerable to a remote buffer overflow 
in its Tomcat plugin.

A malicious user may be able to crash service or execute
arbitrary code on the computer with the privileges of the
HTTP server.
 
Solution : Upgrade to latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 4D WebStar";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.|4[^.]))", string:banner) ) security_warning(port);
