#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(17282);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "vBulletin Detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script detects whether vBulletin discussion forum is running 
on the remote host, and extracts its version if it is.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of vBulletin";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
if(!can_host_php(port:port)) exit(0);


foreach d (make_list("/forum", cgi_dirs()))
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 res = egrep(pattern:" content=.vBulletin ", string:res, icase:TRUE);
 if( res )
 {
  vers = ereg_replace(pattern:".*vBulletin ([0-9.]+).*", string:res, replace:"\1", icase:TRUE);
  set_kb_item(name:string("www/", port, "/vBulletin"),
  	      value:string(vers," under ",d));
	      
  rep = "The remote host is running vBulletin " + vers + " under " + d;
  security_note(port:port, data:rep);
  exit(0);     
 }
} 
