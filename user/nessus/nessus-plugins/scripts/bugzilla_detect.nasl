#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11462);
 script_version ("$Revision: 1.6 $");
 

 name["english"] = "Bugzilla Detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script detects whether the bugzilla bug tracking
system is running on the remote host, and extracts its 
version if it is.

Risk factor : None";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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

foreach d (make_list("/bugs", "/bugzilla", cgi_dirs()))
{
 req = http_get(item:string(d, "/query.cgi"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 res = egrep(pattern:"Bugzilla version", string:res, icase:TRUE);
 if( res )
 {
  vers = ereg_replace(pattern:".*Bugzilla version ([0-9.]*).*", string:res, replace:"\1", icase:TRUE);
  set_kb_item(name:string("www/", port, "/bugzilla/version"),
  	      value:vers);
	      
  rep = "The remote host is running bugzilla " + vers + " under /" + d;
  security_note(port:port, data:rep);
  exit(0);     
 }
} 
