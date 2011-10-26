#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

if(description)
{
 script_id(10415);
 script_version ("$Revision: 1.16 $");
 
 name["english"] = "Sambar sendmail /session/sendmail";
 script_name(english:name["english"]);
 
 desc["english"] = "The Sambar webserver is running. It provides a web interface for sending emails.
You may simply pass a POST request to /session/sendmail and by this send mails to anyone you want.
Due to the fact that Sambar does not check HTTP referrers you do not need direct access to the server!

Solution : Try to disable this module. There might be a patch in the future. 

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sambar /session/sendmail mailer installed ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Hendrik Scholz");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if( is_cgi_installed_ka(port:port, item:"/session/sendmail") ) security_warning(port);
