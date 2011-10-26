# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL

if(description)
{
   script_id(17304);
   script_bugtraq_id(6671);
   script_version ("$Revision: 1.8 $");
   
   script_cve_id("CVE-2001-1135", "CVE-1999-0571");
   
   name["english"] = "Default web account on Zyxel";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote host is a Zyxel router with its default password set.

An attacker could connect to the web interface and reconfigure it.

Solution : Change the password immediately.
Risk factor : High";

   script_description(english:desc["english"]);
   summary["english"] = "Logs into the Zyxel web administration";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english: "This script is Copyright (C) 2005 Michel Arboi");
   script_family(english: "Backdoors");
   script_dependencie("http_version.nasl");
   script_require_ports(80);
   exit(0);
}

include("http_func.inc");
port = get_http_port(default:80);
if ( ! port || port != 80 ) exit(0);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

# Do not use http_get, we do not want an Authorization header
send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
h = http_recv_headers2(socket:soc);
if (h =~ "^HTTP/1\.[01] +401 ")
{ 
 http_close_socket(soc);
 soc = http_open_socket(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n');
 h = http_recv_headers2(socket:soc);
 if (h =~ "^HTTP/1\.[01] +200 ") security_hole(port);
}

http_close_socket(soc);

