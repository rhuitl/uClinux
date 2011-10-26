# This script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#
# References:
#
# Date:	 Mon, 14 Oct 2002 14:50:02 -0400 (EDT)
# From:	"Larry W. Cashdollar" <lwc@vapid.ath.cx>
# To:	bugtraq@securityfocus.com
# Subject: TheServer log file access password in cleartext w/vendor resolution.
#

if(description)
{
 script_id(11914);
 script_bugtraq_id(5250);
 script_version ("$Revision: 1.7 $");
 #script_cve_id();

 name["english"] = "TheServer clear text password";
 script_name(english:name["english"]);
 
 desc["english"] = "
We were able to read the server.ini file
It may contain sensitive information like clear text passwords.
This flaw is known to affect TheServer.

Solution : upgrade your software or reconfigure it
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "TheServer stores clear text passwords in server.ini";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

####

include("http_func.inc");
include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

function testfile(port, no404, f)
{
  local_var	req, h, b, soc;

  soc = http_open_socket(port);
  if (!soc) return 0;
  req = http_get(port: port, item: f);
  send(socket: soc, data: req);
  h = http_recv_headers2(socket:soc);
  b = http_recv_body(socket: soc, headers: h);
  http_close_socket(soc);
  #display(h, "\n");
  #display(b, "\n");

  if (h =~ '^HTTP/[0-9.]+ +2[0-9][0-9]' && b)
  {
    if (! no404 || no404 >!< b)
      return 1;
  }
  return 0;
#if (egrep(string: b, pattern: "^ *password *=")) ...
}

port = get_http_port(default:80);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

if (! get_port_state(port)) exit(0);
no404 = get_kb_item("www/no404/" + port);
if ( no404 ) exit(0);

if (testfile(port: port, no404: no404, f: "/" + rand_str() + ".ini"))
  exit(0);

if (testfile(port: port, no404: no404, f: "/server.ini"))
  security_hole(port);

