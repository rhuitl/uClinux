#
# (C) Tenable Network Security
#


if (description) {
  script_id(19228);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2276");
  script_bugtraq_id(14310);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18064");

  name["english"] = "GroupWise WebAccess Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a script that is affected by a
cross-site scripting issue. 

Description :

The remote host is running a version of GroupWise WebAccess from
Novell that fails to sanitize email messages of HTML and script code
embedded in IMG tags.  An attacker can exploit this flaw to launch
cross-site scripting attacks against users of WebAccess by sending
them specially crafted email messages. 

See also : 

http://www.infobyte.com.ar/adv/ISR-11.html
http://archives.neohapsis.com/archives/bugtraq/2005-07/0322.html
http://support.novell.com/cgi-bin/search/searchtid.cgi?/10098301.htm

Solution : 

Upgrade to GroupWise 6.5 SP5 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerability in GroupWise WebAccess";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# The aboutpqa.htm associated with the Palm app often has more detailed info.
req = http_get(item:"/com/novell/webaccess/palm/en/aboutpqa.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);
# nb: looks like:
#     <BR>Program Release:
#     <BR>6.5.4 
if ("<BR>Program Release:" >< res) {
  res = strstr(res, "Program Release:");
  pat = "^<BR>([0-9].+)$";
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }
}

# If that failed, try to get it from WebAccess' main page.
if (isnull(ver)) {
  req = http_get(item:"/servlet/webacc", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Look for the version number in the banner.
  pat = "^<BR>Version ([0-9].+)";
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        # nb: 6.5 by itself doesn't give us enough details.
        if (ver =~ "^6\.5$") {
          ver = NULL;
        }
        break;
      }
    }
  }
}

# Versions 6.5.4 and below are affected.
if (ver && ver =~ "^([0-5]\.|6\.([0-4]|5\.[0-4]))") {
  security_note(port);
  exit(0);
}
