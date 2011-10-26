#
# (C) Tenable Network Security
#
#


if(description)
{
 script_id(14327);
 script_cve_id("CVE-2004-1732", "CVE-2004-1733");
 script_bugtraq_id(10996);
 script_version ("$Revision: 1.6 $");

 name["english"] = "MyDMS SQL Injection and Directory Traversal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running MyDMS, an open source document management
system based on MySQL and PHP.

The remote version of this software is vulnerable to a SQL injection
bug which may allow any guest user to execute arbitrary SQL commands
against the remote database. There is also a directory traversal issue
which may allow logged users to read arbitrary files on the remote
host with the privileges of the HTTP daemon.

Solution : Upgrade to MyDMS 1.4.3
Risk factor : High"; 




 script_description(english:desc["english"]);
 
 summary["english"] = "SQL injection against the remote MyDMS installation";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( ! can_host_php(port:port) ) exit(0);

foreach dir (cgi_dirs())
{
req = http_get(item:dir + "/op/op.Login.php?login=guest&sesstheme=default&lang=English", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( "mydms_" >< res )
{
 cookie = egrep(pattern:"^Set-Cookie:", string:res);
 req = http_get(item:dir + "/out/out.ViewFolder.php?folderid='", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 if(idx <= 0) return(0);
 cookie = ereg_replace(pattern:"Set-Cookie", replace:"Cookie", string:cookie);
 req = insstr(req, string("\r\n", cookie, "\r\n"), idx);
 res = http_keepalive_send_recv(port:port, data:req);
 if ("SELECT * FROM tblFolders WHERE id =" >< res ) 
  {
  security_hole(port);
  exit(0);
  }
 }
}
