#
# (C) Tenable Network Security
#


if (description) {
  script_id(19520);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2781");
  script_bugtraq_id(14678);

  name["english"] = "FUDforum < 2.7.1 Avatar Upload Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that allows for
arbitrary code execution. 

Description :

The remote host is running FUDforum, an open-source web forum written
in PHP. 

According to its banner, the version of FUDforum installed on the
remote host may allow an authenticated attacker to upload a file with
arbitrary PHP code as an avatar image and later run that code subject
to the privileges of the web server user id. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-08/0394.html
http://fudforum.org/forum/index.php?t=msg&th=5470&start=0&

Solution : 

Upload to FUDforum 2.7.1 or later.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for avatar upload vulnerability in FUDforum < 2.7.1";
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Request the main index.php script.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  if (egrep(string:res, pattern:'>Powered by: FUDforum ([01]\\.|2.([0-6]\\.|7\\.0)).+&copy;.+ <a href="http://fudforum.org/">')) {
    security_note(port);
    exit(0);
  }
}

