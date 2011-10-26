#
# (C) Tenable Network Security
#



if(description)
{
 script_id(16207);
 script_bugtraq_id(11082);
 script_version ("$Revision: 1.3 $");
 

 name["english"] = "pLog User Registration HTML Injection Vulnerability"; 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running pLog, a blogging system written in PHP.

The remote version of this software does not perform a proper validation
of user-supplied input, and is therefore vulnerable to a cross-site scripting
attack.

To exploit this flaw, an attacker would need to use the script 'register.php'
to register a user profile containing HTML and script code as his name or
blog.

Regular users of the remote website would then display the HTML and/or script
code in their browser when visiting the page 'summary.php'.

Solution : Upgrade to pLog 0.3.3 or newer
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of pLog";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
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
 req = http_get(item:dir + "/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (  '<meta name="generator" content="PLOG_0_' >< res )
 {
  if ( egrep(pattern:'<meta name="generator" content="PLOG_0_([0-2]|3_[0-2][^0-9])', string:res) )
	security_warning ( port );
 }
}
       
