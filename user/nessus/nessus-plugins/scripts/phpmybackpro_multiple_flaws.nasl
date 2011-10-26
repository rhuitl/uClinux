#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14787);
 script_bugtraq_id(11103);
 script_version("$Revision: 1.2 $");
 name["english"] = "PHPMyBackupPro Input Validation Issues";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be using phpMyBackupPro. 

It is reported that the remote version of this software is prone to multiple security weaknesses 
regarding user input validation. 

An attacker may use these issues to gain access to the application or to access the underlying 
database.


Solution : Upgrade to version 1.0.0 of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Fetches the version of phpMyBackupPro";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/index.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( "phpMyBackupPro" >< res &&    
       egrep(pattern:"<title>phpMyBackupPro 0\.([0-5]\.[0-9]|6\.[0-2])</title>", string:res) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
