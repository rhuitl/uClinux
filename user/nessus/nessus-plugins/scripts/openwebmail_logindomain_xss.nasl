#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(16463);
  script_version("$Revision: 1.3 $");
  script_cve_id("CVE-2005-0445");
  script_bugtraq_id(12547);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13788");
  }

  name["english"] = "Open WebMail Logindomain Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote webmail server is affected by a cross-site scripting flaw.

Description :

The remote host is running at least one instance of Open WebMail that
fails to sufficiently validate user input supplied to the 'logindomain'
parameter.  This failure enables an attacker to run arbitrary script
code in the context of a user's web browser.

See also :

http://openwebmail.org/openwebmail/download/cert/advisories/SA-05:01.txt

Solution : 

Upgrade to Open WebMail version 2.50 20040212 or later.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for logindomain parameter cross-site scripting vulnerability in Open WebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# We test whether the hole exists by trying to echo magic (urlencoded
# as alt_magic for http) and checking whether we get it back.
magic = "logindomain xss vulnerability";
alt_magic = str_replace(string:magic, find:" ", replace:"%20");


# Test an install.
install = get_kb_item(string("www/", port, "/openwebmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  url = string( "/openwebmail.pl?logindomain=%22%20/%3E%3Cscript%3Ewindow.alert('",
    alt_magic,
    "')%3C/script%3E"
  );
  debug_print("retrieving '", url, "'.");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);           # can't connect
  debug_print("res =>>", res, "<<");

  if (egrep(string:res, pattern:magic)) {
    security_note(port);
    exit(0);
  }
}
