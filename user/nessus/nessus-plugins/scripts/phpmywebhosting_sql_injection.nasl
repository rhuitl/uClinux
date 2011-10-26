#
# (C) Tenable Network Security
#



if(description)
{
 script_id(16208);
 script_cve_id("CVE-2004-2218");
 script_bugtraq_id(10942);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8976");
 }
 script_version ("$Revision: 1.4 $");
 

 name["english"] = "PHPMyWebHosting SQL Injection Vulnerability"; 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running PHPMyWebHosting, a webhosting management interface
written in PHP.

The remote version of this software does not perform a proper validation
of user-supplied input, and is therefore vulnerable to a SQL injection
attack.

An attacker may execute arbitrary SQL statements against the remote database
by sending a malformed username contain SQL escape characters when logging 
into the remote interface in 'login.php'.

Solution : None at this time.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of PHPMyWebhosting";
 
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
  host = get_host_name();
  variables = string("PHP_AUTH_USER='&password=&language=english&submit=login");
  req = string("POST ", dir, "/index.php HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(buf == NULL)exit(0);

 if ( "SQL" >< buf &&
      " timestamp > date_add" >< buf  && "INTERVAL " >< buf)
	security_hole ( port );
 
 return(0);
}
