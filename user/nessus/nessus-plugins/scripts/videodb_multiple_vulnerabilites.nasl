#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16140);
 script_bugtraq_id(12219,12224);
 script_version ("$Revision: 1.2 $");
 name["english"] = "VideoDB Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is VideoDB, a web based video dabatase manager written
in PHP.

The remote version of this software is vulnerable to a SQL injection
vulnerability due to a lack of filtering on user-supplied input. An
attacker may exploit this flaw to modify the remote database.

This software may be vulnerable to an unauthorized access vulnerability
in the file 'edit.php' which may allow an attacker to edit database
entries.

Solution : Upgrade to VideoDB 2.0.2 or later
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of VideoDB";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
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


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
  req = http_get(item:string(url, "/index.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( r == NULL ) exit(0);

  if ( egrep(pattern:"^span class=.*a href=.*www\.splitbrain\.org/go/videodb.*v\.(1_|2_0_0)", string:r))
  {
    security_warning(port);
    exit(0);
   }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
