#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14183);
 script_cve_id("CVE-2004-0681", "CVE-2004-0682");
 script_bugtraq_id(10674, 10824);
 script_version ("$Revision: 1.9 $");

 
 name["english"] = "Comersus Login SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Comersus Shopping Cart Software.

There is a flaw in this interface which allows an attacker to log in 
as any user by using a SQL injection flaw in the code of 
comersus_backoffice_login.php.

An attacker may use this flaw to gain unauthorized access on
this host, or to gain the control of the remote database.

In addition to this, the remote version of this software may be
vulnerable to other issues (see bid 10674).

Solution : Upgrade to the newest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Comersus";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:3689);

if(!get_port_state(port)) exit(0);
if(!can_host_asp(port:port)) exit(0);

foreach dir (make_list( cgi_dirs()))
{
 if ( is_cgi_installed_ka(item:dir + "/comersus_backoffice_login", port:port) ) 
 {
 req = http_post(item:dir + "/comersus_backoffice_login.php", port:port);
 data = "adminName=admin%27&adminpassword=123456&Submit2=Submit";
 
 req = http_post(item:dir + "/comersus_backoffice_login.php", port:port);
 idx = stridx(req, '\r\n\r\n');
 req = insstr(req, '\r\nContent-Length: ' + strlen(data) + '\r\n' + 
 'Content-Type: application/x-www-form-urlencoded\r\n\r\n' + data, idx);
 
 
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(egrep(pattern:"Microsoft.*ODBC.*80040e14", string:res ) )
  {
  security_hole(port);
  exit(0);
  }
 }
}
