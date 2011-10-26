#
# (C) Tenable Network Security
#


if (description) {
  script_id(17661);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0386");
  script_bugtraq_id(12945);

  name["english"] = "Mailreader Remote HTML Injection Vulnerability";
  script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains a CGI script that is vulnerable to a cross-
site scripting attack. 

Description :

According to its banner, the version of Mailreader installed on the
remote host is affected by a remote HTML injection vulnerability due
to its failure to properly sanitize messages using a 'text/enriched'
or 'text/richtext' MIME type.  An attacker can exploit this flaw by
sending a specially crafted message to a user who reads his mail with
Mailreader.  Then, when the user reads that message, malicious HTML or
script code embedded in the message will be run by the user's browser
in the context of the remote host, enabling the attacker to steal
authentication cookies as well as perform other attacks. 

See also :

http://www.debian.org/security/2005/dsa-700

Solution : 

Upgrade to Mailreader 2.3.36 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote HTML injection vulnerability in Mailreader";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Search for Mailreader.
foreach dir (cgi_dirs()) {
  # Run the main script.
  req = http_get(item:string(dir, "/nph-mr.cgi"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Check the version number.
  if (egrep(pattern:">Mailreader.com v([01]\..*|2\.([012]\..*|3\.([012].*|3[0-5]))) ", string:res)) {
    security_note(port);
    exit(0);
  }
}
