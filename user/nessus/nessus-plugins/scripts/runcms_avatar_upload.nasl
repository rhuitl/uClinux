#
# (C) Tenable Network Security
#


if (description) {
  script_id(17987);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1031");
  script_bugtraq_id(13027);

  name["english"] = "RunCMS Remote Arbitrary File Upload Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that allows arbitrary
file uploads. 

Description :

The remote host is running RunCMS / E-Xoops, a content management
system written in PHP. 

According to its banner, the version of this software installed on the
remote host may allow a user to upload arbitrary files and potentially
run them.  This issue arises if avatar uploads are enabled (they are
not by default). 

See also : 

http://www.securityfocus.com/archive/1/395097

Solution : 

Set 'Allow custom avatar upload' to 'No' in 'Custom avatar settings'. 

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote arbitrary file upload vulnerability in RunCMS";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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
if (!can_host_php(port:port)) exit(0);


# Identify RunCMS / E-Xoops.
foreach dir (cgi_dirs()) {
  # Try to pull up the user login form.
  req = http_get(item:string(dir, "/user.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # Check the version number.
  #
  # nb: there does not appear to be a way to check if avatar 
  #     uploads are enabled short of logging in.
  if (
    # in the page itself or...
    egrep(string:res, pattern:"RUNCMS\.? *(0.+|1\.(0.*|1A?)) +&copy; 20") ||
    # in a generator meta tag or...
    (
      egrep(string:res, pattern:"^X-Meta-Generator: *(RUNCMS )?(0.+|1\.(0.*|1A?))") &&
      "function xoops" >< res
    ) ||
    # any version of E-Xoops (older than RunCMS but uses the same code).
    "X-Meta-Generator: E-Xoops" >< res ||
    ">Powered by E-Xoops" >< res
  ) {
    security_note(port);
    exit(0);
  }
}
