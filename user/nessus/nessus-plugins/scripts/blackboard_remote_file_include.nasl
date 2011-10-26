#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Lin Xiaofeng <Cracklove@Gmail.Com>
#
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15450);
  script_cve_id("CVE-2004-1582");
  script_bugtraq_id(11336);
  script_version("$Revision: 1.6 $");
  script_name(english:"BlackBoard Internet Newsboard System remote file include flaw");

 
 desc["english"] = "
The remote host is running the BlackBoard Internet Newsboard System,
an open-source PHP-based internet bulletin board software.

The remote version of this software is vulnerable to a remote file
include flaw due to a lack of sanitization of user-supplied data.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Therefore,
*** this might be a false positive.

Solution: Upgrade to the newest version of this software
Risk factor : High";

  script_description(english:desc["english"]);

  script_summary(english:"Checks BlackBoard Internet Newsboard System version");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port))exit(0);

if(get_port_state(port))
{
  buf = http_get(item:"/forum.php", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<title>BlackBoard Internet Newsboard System</title>.*BlackBoard.*(0\.|1\.([0-4]|5[^.]|5\.1[^-]|5\.1-[a-g]))", string:r))
  {
    security_hole(port);
  }
}
exit(0);
