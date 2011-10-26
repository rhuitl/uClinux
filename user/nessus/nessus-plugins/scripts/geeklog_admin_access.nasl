#
# (C) Tenable Network Security
#
# Date: Thu, 29 May 2003 13:02:55 +0800
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Subject: [VulnWatch] Geeklog 1.3.7sr1 and below multiple vulnerabilities.

if(description)
{
 script_id(11670);
 script_bugtraq_id(3783, 3844, 4969, 4974, 6601, 6602, 6603, 6604, 7742, 7744);
 script_cve_id("CVE-2002-0962", "CVE-2002-0096", "CVE-2002-0097");

 script_version ("$Revision: 1.9 $");
 name["english"] = "GeekLog SQL vulns";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is running a version of the GeekLog  
weblog which is vulnerable to various SQL related
issues which may allow an attacker to log into
this site as anyone.

An attacker may use this flaw to impersonate users
or to edit the content of this website.

Solution : upgrade to the latest version of this CGI suite
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "sends a rotten cookie to the remote host";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


			 

function check(port, dir)
{

 req = http_get(item:dir + "/users.php", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nCookie: geeklog=2.1\r\n\r\n"), idx);


 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) return(0);

 if(egrep(pattern:"^Set-Cookie.*gl_session=", string:r))
 { 
 security_hole(port);
 exit(0);
 }
}    
    
    

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir (make_list("/geeklog", "/log", cgi_dirs()))
{
check(dir:dir, port:port);
}
