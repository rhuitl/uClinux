#
# (C) Tenable Network Security
#

if (description) {
  script_id(17160);
  script_cve_id(
    "CVE-2005-0478",
    "CVE-2005-0479",
    "CVE-2005-0480",
    "CVE-2005-0481",
    "CVE-2005-0482"
  );
  script_bugtraq_id(12592);
  script_version("$Revision: 1.3 $");
 
  name["english"] = "TrackerCam Multiple Remote Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running TrackerCam, a HTTP software which allow a 
user to publish a webcam feed thru a web site.

The remote version of this software is prone to multiple vulnerabilities :

- Buffer overflows which may allow an attacker to execute arbitrary code
on the remote host 

- A directory traversal bug which may allow an attacker to read arbitrary
files on the remote host with the privileges of the web server daemon

- A cross site scripting issue which may allow an attacker to use the
remote host to perform a cross site scripting attack

Solution : Upgrade to the newest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for flaws in TrackerCam";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8090);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8090);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( "Server: TrackerCam/" >!< banner ) exit(0);

req = http_get(item:"/tuner/ComGetLogFile.php3?fn=../HTTPRoot/tuner/ComGetLogFile.php3", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( ! res ) exit(0);
if ( "$fcontents = file ('../../log/'.$fn);" >< res )
	security_hole(port);
