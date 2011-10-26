#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14375);
 script_cve_id("CVE-2004-1743");
 script_bugtraq_id(11034);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "Easy File Sharing Web Server ACL Bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Easy File Sharing Web Server, a web server package
designed to facilitate file sharing.

There is a flaw in the remote version of this software which may allow an
attacker to read arbitrary files on the remote host by requesting /disk_c.

Solution : None at this time
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks /disk_c";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

banner = get_http_banner(port:port);

if ( "Server: Easy File Sharing Web Server" >< banner )
{
  res = http_keepalive_send_recv(port:port, data:http_get(item:"/disk_c/boot.ini", port:port));
  if ( '\r\n\r\n' >< res )
   res = strstr(res, '\r\n\r\n');

  if(egrep(pattern:"\[boot loader\]", string:res))
  {
    txt  = "
The remote host is running Easy File Sharing Web Server, a web server package
designed to facilitate file sharing.

There is a flaw in the remote version of this software which may allow an
attacker to read arbitrary files on the remote host by requesting /disk_c.

Requesting the file c:\boot.ini returns :

" + res + "

Solution : None at this time
Risk factor: High";

   security_hole(port:port, data:txt);
  }
}
 
