#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21304);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2006-2021");
  script_bugtraq_id(17641);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24806");

  script_name(english:"Asterisk Recording Interface recording Parameter Information Disclosure Vulnerability");
  script_summary(english:"Requests a file using ARI's misc/audio.php");

  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an information disclosure issue. 

Description :

The remote host is running Asterisk Recording Interface (ARI), a
web-based portal for the Asterisk PBX software. 

The version of ARI installed on the remote host reportedly allows an
unauthenticated attacker to retrieve arbitrary sound files, such as
voicemail messages, and to determine the existence of other files on
the remote host by passing a specially crafted path to the 'recording'
parameter of the 'misc/audio.php' script. 

See also :

http://www.securityfocus.com/archive/1/431655/30/0/threaded

Solution :

Upgrade to ARI 0.10 / Asterisk@Home 2.8 or later. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/recordings", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Request a file known to exist; a vulnerable version will complain 
  # the file can't be used while a patched one will complain the file
  # isn't found because it encrypts the parameter.
  file = "../version.inc";
  req = http_get(
    item:string(
      dir, "/misc/audio.php?",
      "recording=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (string("Cannot use file: ", file) >< res)
  {
    security_note(port);
    exit(0);
  }
}
