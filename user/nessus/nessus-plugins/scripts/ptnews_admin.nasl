#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11589);
 script_bugtraq_id(7394);
 script_version ("$Revision: 1.5 $");

 script_name(english:"PT News Unauthorized Administrative Access");
 desc["english"] = "
The remote host is using the PT News management system.

There is a flaw in this version which allows anyone to execute 
arbitrary admnistrative PTnews command on this host (such as deleting
news or editing a news) without having to know the administrator
password.

An attacker may use this flaw to edit the content of this website
or even to delete it completely.

Solution : Upgrade to PT News 1.7.8 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if PTNews grants administrative access to everyone");
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
if(!can_host_php(port:port))exit(0);


dirs = make_list("/ptnews", cgi_dirs());
		

foreach d (dirs)
{
 rnd = rand();
 
 url = string(d, "/index.php?edit=nonexistant", rnd);
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:"./nonexistant" + rnd + " .*/news.inc", string:buf))
   {
    security_hole(port);
    exit(0);
   }
}
