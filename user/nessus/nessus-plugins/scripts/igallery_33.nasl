#
# (C) Tenable Network Security
#


if (description) {
  script_id(18539);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2033", "CVE-2005-2034");
  script_bugtraq_id(14000, 14002);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17401");

  name["english"] = "i-Gallery <= 3.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is susceptible
to multiple issues. 

Description :

The remote host is running i-Gallery, a web-based photo gallery from
Blue-Collar Productions. 

The installed version of i-Gallery fails to sanitize user-supplied
input before using it as a folder name in several scripts.  An
unauthenticated attacker can exploit this flaw to access files and
folders outside i-Gallery's main gallery folder and to conduct
cross-site scripting attacks against visitors to the affected
application. 

See also : 

http://www.securityfocus.com/archive/1/402880/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:L/Au:NR/C:C/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in i-Gallery <= 3.3";
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
if (!can_host_asp(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the directory traversal flaw.
  req = http_get(item:string(dir, "/folderview.asp?folder=.."), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we can see anything in the parent directory.
  if (
    egrep(
      string:res, 
      # nb: 'i' is for the filename, 'f' the folder.
      pattern:"viewphoto\.asp?i=[^&]+&f=\.\."
    )
  ) { 
    security_note(port);
    exit(0);
  }
}
