#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14178);
 script_cve_id("CVE-2004-2514");
 script_bugtraq_id(10835);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8319");
 }
 script_version("$Revision: 1.4 $");
 
 name["english"] = "PowerPortal Private Message HTML Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using PowerPortal, a content management system, 
written in PHP. 

A vulnerability exists in the remote version of this product which may allow 
a remote attacker to inject arbitrary HTML tags in when sending a private
message to a victim user of the remote portal.

An attacker may exploit this flaw to steal the credentials of another
user on the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PowerPortal Installation";
 
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

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( egrep(pattern:"Powered by.*PowerPortal", string:r) )
 {
   version = egrep(pattern:"Powered by.*PowerPortal v.*", string:r);
   version = ereg_replace(pattern:".*Powered by.*PowerPortal v([0-9.]*).*", string:version, replace:"\1");
   if ( loc == "") loc = "/";
   set_kb_item(name:"www/" + port + "/powerportal", value:version + " under " + loc );
   if ( ereg(pattern:"^(0\..*|1\.[0-3]([^0-9]|$))", string:version) )
   {
    security_warning(port);
    exit(0);
   }
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

