#
# (C) Tenable Network Security
#


if (description) {
  script_id(17214);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2004-0465", "CVE-2004-0466");
  script_bugtraq_id(12613);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14009");
    script_xref(name:"OSVDB", value:"14010");
  }

 name["english"] = "Multiple vulnerabilities in OpenConnect WebConnect < 6.5.1";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a Java application that is vulnerable to
multiple attacks. 

Description :

The remote host is running OpenConnect WebConnect, a web-based graphical
user interface that gives remote users console access to mainframe,
midrange, and Unix systems using a Java-based telnet console which
communicates securely over HTTP.  OC WebConnect 6.44 and 6.5 (and
possibly previous versions) have multiple remote vulnerabilities :

  - A remote attacker can bring about a denial of service by 
    sending an HTTP GET or POST request with an MS-DOS device 
    name in it (Windows platforms only). 

  - A read-only directory traversal vulnerability in 'jretest.html'
    allows exposure of files formatted in an INI-style format (any 
    platform). 

See also :  

http://cirt.dk/advisories/cirt-29-advisory.pdf

Solution : 

Upgrade to OpenConnect WebConnect 6.5.1 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for multiple vulnerabilities in OpenConnect WebConnect < 6.5.1";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


global_var wc_ver, wc_platform;


# This function tries to identify the version and platform of WebConnect 
# based on an array of lines. If successful, it sets the global 
# variables "wc_ver" and "wc_platform".
function id_webconnect(page) {
  local_var pat, matches, match;

  # Some pages embed the server version and platform in a Java applet.
  pat = 'PARAM NAME="serverVersion" VALUE="WC(.+)"';
  matches = egrep(pattern:pat, string:page);
  foreach match (split(matches)) {
    match = chomp(match);
    wc_ver = eregmatch(pattern:pat, string:match);
    if (wc_ver == NULL) break;
    wc_ver = wc_ver[1];
  }
  pat = 'PARAM NAME="serverType" VALUE="(.+)"';
  matches = egrep(pattern:pat, string:page);
  foreach match (split(matches)) {
    match = chomp(match);
    wc_platform = eregmatch(pattern:pat, string:match);
    if (wc_platform == NULL) break;
    wc_platform = wc_platform[1];
  }

  # And others have it as plain HTML in a frame.
  if (wc_ver == NULL) {
    pat = '<b>Version WC(.+)</b>';
    matches = egrep(pattern:pat, string:page);
    foreach match (split(matches)) {
      match = chomp(match);
      wc_ver = eregmatch(pattern:pat, string:match);
      if (wc_ver == NULL) break;
      wc_ver = wc_ver[1];
    }
  }
}


port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);


# Check whether the server is running OC WebConnect.
#
# nb: the server doesn't seem to add a Server: header but does 
#     put its name in the title of both /jretest.html if it
#     exists and an error page otherwise.
req = http_get(item:"/jretest.html", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if ( !egrep(pattern:"TITLE>OC://WebConnect", string:res) ) exit(0);


# Determine if jretest.html exists.
if ( egrep(pattern:"HTTP/.+ 200 OK", string:res) ) jretest_exists = 1;
else jretest_exists = 0;


# Determine OC WebConnect's version number and platform.
#
# nb: look at selected frames on the main page and then in linked pages
#     looking for telltale identifiers.
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

pat = 'SRC="([^"]+)"';
matches = egrep(pattern:pat, string:res);
foreach match (split(matches)) {
  match = chomp(match);
  frame = eregmatch(pattern:pat, string:match);
  if (frame == NULL) break;
  frame = frame[1];
  if (frame[0] != '/') frame = '/' + frame;

  if (frame =~ "\.html\?.*lang=") {
    req = http_get(item:frame, port:port);
    html = http_keepalive_send_recv(port:port, data:req);
    if ( html == NULL ) exit(0);

    # nb: scan the frame's html since sometimes the version number
    #     can be found in a top / left frame.
    id_webconnect(page:html);

    # nb: ideally, though, we want to find the Java applet since 
    #     it has both version and platform so we'll look through
    #     selected local links too.
    pat2 = 'HREF="(/[^"]+)"';
    matches2 = egrep(pattern:pat2, string:html);
    foreach match2 (split(matches2)) {
      match2 = chomp(match2);
      link = eregmatch(pattern:pat2, string:match2);
      if (link == NULL) break;
      link = link[1];

      if (link =~ "\.html\?.*lang=") {
        req = http_get(item:link, port:port);
        html = http_keepalive_send_recv(port:port, data:req);
        if ( html == NULL ) exit(0);

        id_webconnect(page:html);
        # If the version and platform were both identified, we're done.
        if (!isnull(wc_ver) && !isnull(wc_platform)) break;
      }
    }

    # If the version and platform were both identified, we're done.
    if (!isnull(wc_ver) && !isnull(wc_platform)) break;
  }
}


# Finally, determine whether the target is vulnerable.
#
if (wc_ver =~ "^([0-5]|6\.([0-4]|5$|5\.0))") {
  if (isnull(wc_platform) || wc_platform =~ "^Win") security_note(port);
  else if (jretest_exists) security_warning(port);
}
