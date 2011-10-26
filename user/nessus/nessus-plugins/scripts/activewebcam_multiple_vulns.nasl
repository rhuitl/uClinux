#
# (C) Tenable Network Security
#


if (description) {
  script_id(17320);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0730", "CVE-2005-0731", "CVE-2005-0732", "CVE-2005-0733", "CVE-2005-0734");
  script_bugtraq_id(12778);

  name["english"] = "Multiple Vulnerabilities in Active WebCam Webserver 5.5 and older";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by multiple vulnerabilities.

Description :

The version of PY Software's Active WebCam webserver running on the
remote host is prone to multiple vulnerabilities:

  o Denial of Service Vulnerabilities.
    A request for a file on floppy drive may result in a dialog
    prompt, causing service to cease until it is acknowledged by an
    administrator. In addition, requesting the file 'Filelist.html'
    reportedly causes CPU usage on the remote host to increase,
    ultimately leading to denial of service.

  o Information Disclosure Vulnerabilities.
    A request for a non-existent file will return an error message
    with the installation path for the software. Further, error
    messages differ depending on whether a file exists or is
    inaccessible. An attacker may exploit these issues to gain
    information about the filesystem on the remote host.

Note that while versions 4.3 and 5.5 are known to be affected, earlier
versions are likely to be as well. 

See also : 

http://secway.org/advisory/ad20050104.txt
http://archives.neohapsis.com/archives/fulldisclosure/2005-03/0216.html

Solution : 

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote vulnerabilities in Active WebCam webserver 5.5 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Grab the main page and make sure it's for Active WebCam.
res = http_get_cache(item:"/", port:port);
if ('name="GENERATOR" content="Active WebCam' >!< res) exit(0);

if (safe_checks()) {
  if (egrep(string:res, pattern:'name="GENERATOR" content="Active WebCam ([0-4][^0-9]|5\\.[0-5] )'))
    security_note(port);
}
else {
  # Let's request a non-existent page and see if we can find the install path.
  # Use the number of microseconds in the time for the page.
  now = split(gettimeofday(), sep:".", keep:0);
  page = now[1];

  req = http_get(item:"/" + page, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  pat = "The requested file: <B>([^<]+)</B> was not found.";
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    path = eregmatch(pattern:pat, string:match);
    if (!isnull(path)) {
      path = path[1];
      if (ereg(string:path, pattern:"^[A-Z]:\\")) security_note(port);
    }
  }
}
