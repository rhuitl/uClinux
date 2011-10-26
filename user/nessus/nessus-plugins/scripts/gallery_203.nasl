#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running Gallery, a web-based photo album
application written in PHP. 

The version of Gallery installed on the remote host allows an attacker
to spoof his IP address with a bogus 'X_FORWARDED_FOR' HTTP header. 
An authenticated attacker can reportedly leverage this flaw to launch
cross-site scripting attacks by adding comments to a photo as well as
other attacks. 

In addition, the application reportedly fails to validate a session id
before using it, which can be used to delete arbitrary files on the
remote host subject to the privileges of the web server user id. 

See also :

http://www.gulftech.org/?node=research&article_id=00106-03022006
http://www.securityfocus.com/archive/1/426655/30/0/threaded
http://gallery.menalto.com/gallery_2.0.3_released

Solution :

Upgrade to Gallery 2.0.3 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(21017);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1127");
  script_bugtraq_id(16940, 16948);

  script_name(english:"Gallery < 2.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for IP spoofing in Gallery");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/gallery", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  ip = string("nessus", rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789"));
  useragent = string("Mozilla/4.0 (compatible; ", SCRIPT_NAME, "; Googlebot)");

  req = http_get(item:string(dir, "/main.php"), port:port);
  req = ereg_replace(
    string:req,
    pattern:"User-Agent:.+Accept:",
    replace:string(
      "User-Agent: ", useragent, "\r\n",
      "X_FORWARDED_FOR: ", ip, "\r\n",
      "Accept:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if the GALLERYSID cookie has our fake "IP".
  if (egrep(pattern:string("^Set-Cookie: .*GALLERYSID=google", ip), string:res)) {
    security_note(port);
    exit(0);
  }
}
