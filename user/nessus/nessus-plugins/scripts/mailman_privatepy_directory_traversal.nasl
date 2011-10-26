#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
 
if (description) {
  script_id(16339);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-0202");
  script_bugtraq_id(12504);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13671");
  }
 
  name["english"] = "Mailman private.py Directory Traversal Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

Authenticated Mailman users can view arbitrary files on the remote
host. 

Description : 

According to its version number, the remote installation of Mailman
reportedly is prone to a directory traversal vulnerability in
'Cgi/private.py'.  The flaw comes into play only on web servers that
don't strip extraneous slashes from URLs, such as Apache 1.3.x, and
allows a list subscriber, using a specially crafted web request, to
retrieve arbitrary files from the server - any file accessible by the
user under which the web server operates, including email addresses
and passwords of subscribers of any lists hosted on the server.  For
example, if '$user' and '$pass' identify a subscriber of the list
'$listname@$target', then the following URL :

  http://$target/mailman/private/$listname/.../....///mailman?username=$user&password=$pass

allows access to archives for the mailing list named 'mailman' for
which the user might not otherwise be entitled. 

See also : 

http://mail.python.org/pipermail/mailman-announce/2005-February/000076.html
http://lists.netsys.com/pipermail/full-disclosure/2005-February/031562.html

Solution :

Upgrade to Mailman 2.1.6b1 or apply the fix referenced in the first
URL above. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for Mailman private.py Directory Traversal Vulnerability";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Remote file access");

  script_copyright(english:"This script is Copyright (C) 2005 George A. Theall");

  script_dependencie("mailman_detect.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# Web servers to ignore because it's known they strip extra slashes from URLs.
#
# nb: these can be regex patterns.
web_servers_to_ignore = make_list(
  "Apache(-AdvancedExtranetServer)?/2",                      # Apache 2.x
  'Apache.*/.* \\(Darwin\\)'
);

# Skip check if the server's type and version indicate it's not a problem,
# unless report paranoia is set high.
banner = get_http_banner(port: port);
if (banner && report_paranoia < 2) {
  web_server = strstr(banner, "Server:");
  if (web_server) {
    web_server = web_server - "Server: ";
    web_server = web_server - strstr(web_server, '\r');
    foreach pat (web_servers_to_ignore) {
      if (ereg(string:web_server, pattern:pat)) {
        debug_print("skipping because web server claims to be '", web_server, "'.");
        exit(0);
      }
    }
  }
}


# Test an install.
install = get_kb_item(string("www/", port, "/Mailman"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^2\.(0.*|1($|[^0-9.]|\.[1-5]($|[^0-9])))") {
    security_note(port);
  }
}
