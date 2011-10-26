#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15506);
 script_cve_id("CVE-2004-1599", "CVE-2004-1601");
 script_bugtraq_id(11437);
 script_version ("$Revision: 1.6 $");


 name["english"] = "CoolPHP Multiple Vulnerabilities";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the CoolPHP Content Management system.

There are various flaws in the remote version of this software which
may allow an attacker to read arbitrary files on the remote host or to
set up a cross-site scripting attack.

Solution : None at this time
Risk factor : Medium";




 script_description(english:desc["english"]);

 summary["english"] = "Checks for CoolPHP";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/index.php?op=userinfo&nick=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&
    "<script>foo</script>" >< res )
	{
 	security_warning(port);
	exit(0);
 	}
}
