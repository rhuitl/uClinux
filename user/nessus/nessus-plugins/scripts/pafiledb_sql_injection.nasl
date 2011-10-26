#
# written by Renaud Deraison
#
# Date: Sun, 23 Mar 2003 16:13:37 -0500
# To: bugtraq Security List <bugtraq@securityfocus.com>
# From: flur <flur@flurnet.org>
# Subject: paFileDB 3.x SQL Injection Vulnerability

if (description)
{
 script_id(11478);
 script_bugtraq_id(7183);
 script_version ("$Revision: 1.9 $");

 
 script_name(english:"paFileDB SQL injection");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by
several SQL injection issues.

Description :

The remote installation of paFileDB is vulnerable to SQL injection
attacks because of its failure to sanitize input to the 'id' and
'rating' parameters to the 'pafiledb.php' script.  An attacker may use
this flaw to control your database. 

See also :

http://www.securityfocus.com/archive/1/316053

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if pafiledb is vulnerable to a SQL injection");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003-2006 Renaud Deraison");

 script_dependencies("pafiledb_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];

 url = string(d, "/pafiledb.php?action=rate&id=1&rate=dorate&ratin=`");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);
 
 if("UPDATE pafiledb_files SET file_rating" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}

