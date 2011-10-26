#
# (C) Tenable Network Security
#


if (description) {
  script_id(20833);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3411");
  script_bugtraq_id(15241);
  script_xref(name:"OSVDB", value:"20421");

  script_name(english:"Snitz Forums 2000 type Parameter Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks for type parameter cross-site scripting vulnerability in Snitz Forums 2000");
 
  desc = "
Synopsis :

The remote web server contains an ASP script that is prone to a cross-
site scripting attack. 

Description :

The remote host is running Snitz Forums 2000, a web-based electronic
forum written in ASP. 

The version of Snitz Forums 2000 installed on the remote host fails to
sanitize the 'type' parameter before using it in the 'post.asp' script
to generate dynamic content.  By leveraging this flaw, an attacker may
be able to execute arbitrary HTML and script code in a user's browser
within the security context of the affected application. 

See also :

http://forum.snitz.com/forum/topic.asp?TOPIC_ID=60011

Solution : 

Upgrade to Snitz Forums 2000 version 3.4.06 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Loop through directories.
if (thorough_tests) dirs = make_list("/forum", "/snitz", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get the initial page for a list of forums.
  res = http_get_cache(item:string(dir, "/default.asp"), port:port);
  if (res == NULL) exit(0);

  # Exploiting the flaw requires an existent forum.
  pat = '<a href="forum.asp?FORUM_ID=([0-9]+)">';
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    forum = eregmatch(pattern:pat, string:match);
    if (!isnull(forum)) {
      forum = forum[1];
      break;
    }
  }

  # Try to exploit the flaw.
  if (isnull(forum)) {
    if (log_verbosity > 1) debug_print("couldn't find a forum to use!", level:0);
  }
  else {
    req = http_get(
      item:string(
        dir, "/post.asp?",
        "method=Topic&",
        "FORUM_ID=", forum, "&",
        'type=">', exss
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we see our XSS, there's a problem.
    if (xss >< res) {
      security_note(port);
      exit(0);
    }
  }
}

