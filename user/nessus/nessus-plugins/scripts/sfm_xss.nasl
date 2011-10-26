
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11362);
 script_bugtraq_id(7035);
 script_version ("$Revision: 1.6 $");

 name["english"] = "Simple File Manager Filename Script Injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Simple File Manager CGI (fm.php) improperly validates 
the names of the directories entered and created by the user.

As a result, a user could generate a cross-site scripting attack
on this host.

Solution : Upgrade to SFM 0.21 or newer
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of fm.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (make_list(cgi_dirs(), "/sfm"))
{
 req = http_get(item:string(dir, "/fm.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL) exit(0);

 str = egrep(pattern:"simple file manager", string:res, icase:TRUE);
 if(str)
 {
  if(ereg(string:str, pattern:".*class=tiny> \.0(0[0-9]|1[0-9]|20)[^0-9]"))
   {
    security_warning(port);
    exit(0);
   }
 }
}
