#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11515);
 script_bugtraq_id(7277);
 script_version ("$Revision: 1.4 $");



 name["english"] = "AutomatedShops WebC.cgi installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running webc.cgi, a shopping cart application.

By default, webc.cgi sends some information to every user, including
its version number, serial number and company name. This script extracts
this information and displays it to the user.


Solution : None
Risk factor : Low";





 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of webc.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
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




foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/webc.cgi/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);
 data = egrep(pattern:"WEBC_", string:res);
 if(data)
 {
  report = "AutomatedShops webc.cgi is running under " + dir + "
By making a bogus request to it, we could obtain the following information : 

" + data + "

This data might be valuable to a potential attacker.

Solution : None
Risk factor : Low";

  version = egrep(pattern:"WEBC_VERSION", string:data);
  if(version)set_kb_item(name:string("www/", port, "/content/webc.cgi/version"),
  			 value:ereg_replace(pattern:"WEBC_VERSION = (.*)", 
			 		    string:version - string("\n"),
					    replace:"\1"));
			 
			 
  security_note(port:port, data:report);
  exit(0);
 }
}
