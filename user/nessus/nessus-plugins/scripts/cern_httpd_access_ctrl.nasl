# This script was written by Michel Arboi
#
# It is released under the GNU Public Licence (GPL v2)
# For now.
# Unless I change my mind if you don't stop complaining about Nessus
# going commercial
# <grin>


if(description)
{
 script_id(17230);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "CERN HTTPD access control bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to access protected web pages 
by changing / with // or /./
This was a bug in old versions of CERN web server

A work around consisted in rejecting patterns like:
//*
*//*
/./* 
*/./*

Solution : Upgrade your web server or tighten your filtering rules
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if web access control can be circumvented";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl",
 "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

# If this script gives FP, uncomment the next line
if (report_paranoia < 2) exit(0);	# Disable with "Avoid false alarms" 

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

no404 = get_kb_item(strcat('www/no404/', port));

function check(port, loc)
{
 local_var	req, res;
 req = http_get(item:loc, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if (isnull(res)) exit(0);
 if (res =~ "^HTTP/[0-9]\.[0-9] +40[13]") return 403;
 else if (res =~ "^HTTP/[0-9]\.[0-9] +200 ")
 {
   if (no404 && no404 >< res) return 404;
   else return 200;
 }
 else return;
}

dirs = get_kb_list(strcat("www/", port, "/content/auth_required"));
if (isnull(dirs)) exit(0);

foreach dir (dirs)
{
  if (check(port: port, loc: dir) == 403)
  {
    foreach pat (make_list("//", "/./"))
    {
      dir2 = ereg_replace(pattern: "^/", replace: pat, string: dir);
      if (check(port: port, loc: dir2) == 200)
      {
        debug_print('>', dir2, '< can be read on ', get_host_name(),
	':', port, '\n');
        security_hole(port: port);
        exit(0);
      }

      dir2 = ereg_replace(pattern: "^(.+)/", replace: "\\1"+pat, string: dir);
      if (check(port: port, loc: dir2) == 200)
      {
        debug_print('>', dir2, '< can be read on ', get_host_name(),
	':', port, '\n');
        security_hole(port: port);
        exit(0);
      }
    }
  }
}
