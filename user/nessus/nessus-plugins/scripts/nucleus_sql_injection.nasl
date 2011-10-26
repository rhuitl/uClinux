#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14194); 
 script_bugtraq_id(10798);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Nucleus CMS SQL Injection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Nucleus CMS, an open-source content management
system.

There is a SQL injection condition in the remote version of this software
which may allow an attacker to execute arbitrary SQL commands against
the remote database.

An attacker may exploit this flaw to gain unauthorized access to the remote
database and gain admin privileges on the remote CMS.

Solution : Upgrade to Nucleus 3.1 or newer
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Nucleus Version Check";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

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
if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:"/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ('"generator" content="Nucleus' >< res )
 { 
     line = egrep(pattern:"generator.*content=.*Nucleus v?([0-9.]*)", string:res);
     version = ereg_replace(pattern:".*generator.*content=.*Nucleus v?([0-9.]*).*", string:line);
     if ( version == line ) version = "unknown";
     if ( dir == "" ) dir = "/";

     set_kb_item(name:"www/" + port + "/nucleus", value:version + " under " + dir );

    if ( ereg(pattern:"^([0-2]|3\.0)", string:version) )
    {
     security_hole(port);
     exit(0);
    }
 }
}
