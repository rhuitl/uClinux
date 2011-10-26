#
# (C) Tenable Network Security
#


if (description) {
  script_id(20932);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0711");
  script_bugtraq_id(16651);

  script_name(english:"NeoMail Session Id Validation Vulnerability");
  script_summary(english:"Checks for session id validation vulnerability in NeoMail");
 
  desc = "
Synopsis :

The remote web server contains a Perl application that is affected by
an access validation failure. 

Description :

The remote host is running NeoMail, an open-source webmail application
written in Perl. 

The installed version of this software fails to validate the
'sessionid' parameter in the 'neomail-prefs.pl' script as a valid
session identifier.  An unauthenticated attacker may be able to
exploit this issue to create or delete arbitrary mail-folder files on
the affected host subject to the permissions of the group id under
which the affected application operates. 

Note that successful exploitation requires that '$homedirfolders' and
'$homedirspools' both be set to 'no' in NeoMail's configuration. 

See also :

http://secunia.com/secunia_research/2006-3/advisory/
http://sourceforge.net/project/shownotes.php?release_id=392562&group_id=2874

Solution :

Upgrade to NeoMail version 1.29 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to add a folder.
  #
  # nb: we'll use a name that's too long so it will fail.
  req = http_get(
    item:string(
      dir, "/neomail-prefs.pl?",
      "sessionid=nessus-session-0.", SCRIPT_NAME, "&",
      "action=addfolder&",
      "foldername=", rand_str(length:17)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if ...
  #
  # nb: the error strings depend on the application's default
  #     language; adjust if it's not English.
  if (
    # the folder name is too long or...
    "<BR>Folder name cannot be more" >< res ||
    # we can't create the folder.
    "<BR>Can't create folder!<BR>" >< res
  ) {
    security_note(port);
    exit(0);
  }
}
