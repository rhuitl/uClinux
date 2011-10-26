#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16281);
 script_bugtraq_id(12405); 
 script_version ("$Revision: 1.3 $");

 name["english"] = "SmarterTools SmarterMail Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
There are flaws in the remote SmarterMail, a web mail interface.

This version of SmarterMail is vulnerable to a cross site scripting 
vulnerability.
An attacker, exploiting this flaw, would be able to steal user credentials.

Solution: Upgrade to SmarterMail 2.0.0.1837 or later

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of SmarterMail";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/About/frmAbout.aspx"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ("<title>About SmarterMail - SmarterMail</title>" >< r)
 {
  if ( egrep(pattern:"SmarterMail Professional Edition v\.([0-1]\.|2\.0\.([0-9]([0-9])?([0-9])?\.|1([0-7][0-9][0-9]\.|8([0-2][0-9]\.|3[0-6]\.))))", string:r))
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

