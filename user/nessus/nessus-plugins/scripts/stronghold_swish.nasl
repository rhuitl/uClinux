#
# This script was written by Randy Matz <rmatz@ctusa.net>
#

if(description)
{
 script_version ("$Revision: 1.6 $");
 script_id(11230);
 script_bugtraq_id(4785);
 name["english"] = "Stronghold Swish";
 name["francais"] = "Stronghold Swish";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
An information disclosure vulnerability was reported in a 
sample script provided with Red Hat's Stronghold web server. 
A remote user can determine the web root directory path.

A remote user can send a request to the Stronghold sample script 
swish to cause the script to reveal the full path to the webroot directory. 

Apparently, swish may also display system-specific information in the 
HTML returned by the script

Solution : remove it
Risk factor : Low";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of cgi-bin/search";
 summary["francais"] = "Vérifie la présence de cgi-bin/search";
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Randy Matz",
                francais:"Ce script est Copyright (C) 2003 Randy Matz");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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





if (is_cgi_installed_ka(port:port, item:"/search"))
{
  req = http_get(item:"/search", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);
   if(egrep(pattern:".*sourcedir value=?/.*stronghold.*", string:r))
     {
     security_warning(port);
     exit(0);
     }
}


foreach dir (cgi_dirs())
{
 if (is_cgi_installed_ka(port:port, item:string(dir, "/search")))
 {
  req = http_get(item:string(dir, "/search"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(r == NULL)exit(0);
  if(egrep(pattern:"sourcedir value=./.*stronghold.*", string:r))
     {
     security_warning(port);
     exit(0);
     }
  }
}
