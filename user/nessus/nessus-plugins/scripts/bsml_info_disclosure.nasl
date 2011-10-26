#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11973);
 script_bugtraq_id(9311);
 script_version ("$Revision: 1.4 $");
 name["english"] = "BulletScript MailList bsml.pl Information Disclosure";
 
 script_name(english:name["english"]);
 desc["english"] = "
The remote host is using BulletScript's bsml.pl, the web interface to a mailing
list manager.

The lack of authentication in this CGI may allow an attacker to gain
control on the email addresses database of the remote mailing list. An attacker
may use it to add or remove an e-mail address or to gather the list of
subscribers to the remote mailing list for spam purposes.

Solution: Disable this CGI
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary commands");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);




if(!get_port_state(port))exit(0);


foreach d (make_list(cgi_dirs()))
{
 url = string(d, "/bsml.pl?action=sm");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if ("/bsml.pl?action=empty" >< buf ) { security_warning(port); exit(0); }
}
