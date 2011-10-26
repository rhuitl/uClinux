#
# (C) Tenable Network Security
#

if(description)
{
 script_version ("$Revision: 1.6 $");
 script_id(11942);
 script_bugtraq_id(9133, 9134);
 
 name["english"] = "VP-ASP shopsearch SQL injection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the VP-ASP CGI suite.

There is a bug in this suite which may allow an attacker
to force it to execute arbitrary SQL statements on the remote
host. An attacker may use this flaw to gain the control of the remote
website and possibly execute arbitrary commands on the remote host.

Solution: Disable this suite or upgrade to the latest version
Risk factor: High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of VP-ASP";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl", "no404.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


poison = "Keyword='&Category=All&SubCategory=All&action=+Search+";

foreach dir ( cgi_dirs() )
{
 req = http_post(item:string(dir, "/shopsearch.asp?search=Yes"), port:port, data:poison);
 idx = stridx(req, 'Content-Length');
 req = insstr(req, '\r\nContent-Type: application/x-www-form-urlencoded', idx - 2, idx - 2);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if ("ShopDisplayproducts.asp" >< res )
 {
  cookie = ereg_replace(pattern:"^Set-Cookie: (.*);.*$", replace:"\1", string:egrep(pattern:"^Set-Cookie", string:res));
  
  req = http_get(item: dir + "/ShopDisplayProducts.asp?Search=Yes", port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nCookie: ", cookie, "\r\n\r\n"), idx);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
 if ( egrep(pattern:".*ODBC.*80040e14.*", string:res) ) {
	security_hole(port);
	exit(0);
	}
  }
}

