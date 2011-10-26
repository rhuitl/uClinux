#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17142);
 script_cve_id("CVE-2005-0474");
 script_bugtraq_id(12581);
 script_version ("$Revision: 1.3 $");
 name["english"] = "WebCalendar SQL Injection Vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server has a PHP script that is affected by a SQL
injection flaw. 

Description :

The remote version of WebCalendar is vulnerable to a SQL injection
vulnerability that may allow an attacker to execute arbitrary SQL
statements against the remote database.  An attacker may be able to
leverage this issue to, for example, delete arbitrary database tables. 

See also :

http://www.scovettalabs.com/advisory/SCL-2005.001.txt
http://marc.theaimsgroup.com/?l=bugtraq&m=110868446431706&w=2

Solution : 

Upgrade to WebCalendar 0.9.5 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a malformed cookie to the remote host";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 
 script_family(english:family["english"]);
 script_dependencies("webcalendar_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:dir + "/views.php", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nCookie: webcalendar_session=7d825292854146\r\n\r\n"), idx);


 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) return(0);
 if ( "<!--begin_error(dbierror)-->" >< r )
	security_warning(port);
}    
