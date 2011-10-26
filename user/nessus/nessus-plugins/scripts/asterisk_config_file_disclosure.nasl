#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an information disclosure issue. 

Description :

The remote host is running Asterisk Recording Interface (ARI), a
web-based portal for the Asterisk PBX software. 

The version of ARI installed on the remote host allows an
unauthenticated attacker to view its configuration file, which
contains sensitive information such as passwords. 

See also :

http://www.securityfocus.com/archive/1/431655/30/0/threaded

Solution :

Upgrade to ARI 0.10 / Asterisk@Home 2.8 or later. 

Risk factor :

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:N)";


if (description)
{
  script_id(21303);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2020");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24805");

  script_name(english:"Asterisk Recording Interface Configuration File Disclosure Vulnerability");
  script_summary(english:"Tries to read ARI's configuration file");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/recordings", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(item:string(dir, "/includes/main.conf"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like an ARI config file.
  if (egrep(pattern:"(asterisk_mgrpass|ari_admin_password)", string:res))
  {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the repeated contents of ARI's config file that\n",
      "that Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
