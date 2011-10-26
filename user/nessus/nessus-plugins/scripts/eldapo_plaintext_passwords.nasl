#
# (C) Tenable Network Security

if(description)
{
 script_id(11758);
 script_bugtraq_id(7535);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "eLDAPo cleartext passwords";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is hosting eLDAPo, a PHP-based CGI
suite designed to perform LDAP queries.

This application stores the passwords to the LDAP server
in clear text in its source file. An attacker could read
the source code of index.php and  may use the information
contained to gain credentials on a third party server.


Solution : Upgrade to eLDAPo 1.18 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for eLDAPo";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

if ( ! can_host_php(port:port) ) exit(0);


foreach d (cgi_dirs())
{
 req = http_get(item:d+"/listing.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ("images/eLDAPo.jpg" >< res )
 {
  if(egrep(pattern:".*images/eLDAPo\.jpg.*V (0\.|1\.([0-9][^0-9]|1[0-7][^0-9]))", 
  	   string:res))
	   {
	    security_warning(port);
	   }
     exit(0);	   
 }
}
