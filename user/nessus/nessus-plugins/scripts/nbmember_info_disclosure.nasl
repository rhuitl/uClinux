#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: ls
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15542);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"10902");
  script_version("$Revision: 1.5 $");
  script_bugtraq_id(11504);
  script_name(english:"nbmember.cgi information disclosure");
 
 desc["english"] = "
nbmember.cgi is installed on the remote host.

The remote version of this software is vulnerable to an
information disclosure flaw which may allow an attacker to 
access sensitive system information resulting in a loss 
of confidentiality.

Solution: None at this time
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks for nbmember.cgi");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");


function check(req)
{
  buf = http_get(item:string(req,"/nbmember.cgi?cmd=test"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"Version.*Config file.*Password file.*Password file exists.*Password file is readable.*Password file is writable.*SERVER_SOFTWARE ", string:r))
  {
 	security_warning(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);
foreach dir (cgi_dirs()) check(req:dir);
