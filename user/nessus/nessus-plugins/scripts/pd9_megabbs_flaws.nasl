#
# This script is (C) Tenable Network Security
#
#




if(description)
{
 script_id(14837);
 script_bugtraq_id(11253);
 script_version ("$Revision: 1.2 $");

 name["english"] = "PD9 MegaBBS multiple vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running MegaBBS, a web-based bulletin board system written
in ASP.

The remote version of this software is vulnerable to a SQL injection attack
due to a lack of sanitization of user-supplied input. An attacker may exploit
this flaw to issue arbitrary statements in the remote database, and therefore
bypass authorization or even overwrite arbitrary files on the remote system.

Solution : Upgrade to the latest version of this software (greater than 2.1)
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of MegaBBS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
 req = http_get(item:string(loc, "/index.asp"), port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "MegaBBS ASP Forum Software" >< r &&
     egrep(pattern:"MegaBBS ASP Forum Software</a>v([0-1]\.*|2\.[0-1]\.*)", string:r) )
 {
 	security_hole(port);
	exit(0);
 }
}




foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
