#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15561);
 script_cve_id("CVE-2004-1622");
 script_bugtraq_id(11502);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"11050");
 }

 script_version("$Revision: 1.5 $");
 name["english"] = "UBB.threads dosearch.php SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to 
SQL injection attacks.

Description :

There is a SQL injection issue in the remote version of UBB.threads
that may allow an attacker to execute arbitrary SQL statements on the
remote host and potentially overwrite arbitrary files on the remote
system by sending a malformed value to the 'Name' argument of the file
'dosearch.php'. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=109839925207038&w=2

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in UBB.threads";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("ubbthreads_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 res = http_keepalive_send_recv(port:port, data:http_get(item:dir + "/dosearch.php?Name=42'", port:port), bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( "mysql_fetch_array()" >< res ) security_warning(port);
}
