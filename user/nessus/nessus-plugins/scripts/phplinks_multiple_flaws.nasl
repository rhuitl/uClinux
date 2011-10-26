#
# (C) Tenable Network Security
#



if(description)
{
 script_id(16210);
 script_bugtraq_id(11329);
 script_version ("$Revision: 1.2 $");
 

 name["english"] = "PHPLinks Multiple Input Validation Vulnerabilities"; 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running PHPLinks, a link manager written in PHP.

The remote version of this software is vulnerable to multiple input validation
vulnerabilities which may allow an attacker to execute arbitrary SQL statements
against the remote host or to execute arbitrary PHP code.

Solution : Upgrade to the latest version of this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of PHPLinks";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2005 Tenable Network Security");
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


foreach dir ( cgi_dirs() )
{
 req = http_get(item: dir + "/index.php?show=http://xxx./nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( "http://xxx./nessus.php" >< res &&
      "phpLinks" >< res )
		{
		security_hole(port);
		exit(0);
		}
 
 return(0);
}
