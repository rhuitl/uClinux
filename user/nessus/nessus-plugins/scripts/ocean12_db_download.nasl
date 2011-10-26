#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
#  From: "drG4njubas" <drG4nj@mail.ru>
#  To: <bugtraq@securityfocus.com>
#  Subject: Ocean12 ASP Guestbook Manager v1.00
#  Date: Fri, 11 Apr 2003 16:29:16 +0400


if(description)
{
 script_id(11599);
 script_bugtraq_id(7328);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Ocean12 Database Download";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Ocean12 GuestBook, a set of scripts
to manage an interactive guestbook.

An attacker may download the database 'o12guest.mdb' 
and use it to extract the password of the admninistrator
of these CGIs.

Solution : Block the download of .mdb files from your web server.
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Ocean12 guestbook";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


dirs = make_list(cgi_dirs(), "/guestbook");

foreach d (dirs)
{
 req = http_get(item:string(d, "/admin/o12guest.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 if("Standard Jet DB" >< res)
 {
  security_warning(port);
  exit(0);
 }
}
