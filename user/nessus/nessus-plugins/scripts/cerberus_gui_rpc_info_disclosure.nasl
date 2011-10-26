#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22876);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(20598);

  script_name(english:"Cerberus Helpdesk rpc.php Information Disclosure Vulnerability");
  script_summary(english:"Gets requestors for a Cerberus ticket");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by an
information disclosure issue. 

Description :

The remote host is running Cerberus Helpdesk, a web-based helpdesk
suite written in PHP. 

The installed version of Cerberus Helpdesk on the remote host allows
an unauthenticated attacker to retrieve information about ticket
requesters through the 'rpc.php' script. 

See also :

http://forum.cerberusweb.com/showthread.php?t=7922

Solution :

Patch the affected file as described in the forum thread referenced
above. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
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
if (thorough_tests) dirs = make_list("/cerberus", "/cerberus-gui", "/helpdesk", "/tickets", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  ticket = 1;
  req = http_get(
    item:string(
      dir, "/rpc.php?",
      "cmd=display_get_requesters&",
      "id=", ticket
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get a response (eg, see a link to add a requester).
  #
  # nb: this works even if the ticket number is invalid.
  if ('input type="text" name="requester_add"' >< res)
  {
    security_note(port);
    exit(0);
  }
}
