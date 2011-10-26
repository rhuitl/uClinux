#
# (C) Tenable Network Security
#


if (description) {
  script_id(20970);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");
  script_bugtraq_id(16756);

  script_name(english:"SquirrelMail < 1.4.6 Multiple Vulnerabilities");
  script_summary(english:"Checks for IMAP command injection in SquirrelMail");
 
  desc = "
Synopsis :

The remote webmail application is affected by multiple issues. 

Description :

The installed version of SquirrelMail fails to sanitize user-supplied
input to mailbox names before passing them to an IMAP server.  An
unauthenticated attacker may be able to leverage this issue to launch
attacks against the underlying IMAP server or against a user's
mailboxes by tricking him into clicking on a specially-formatted link
in an email message. 

There are also reportedly several possible cross-site scripting flaws
that could be exploited to injection arbitrary HTML and script code
into a user's browser. 

See also :

http://www.squirrelmail.org/security/issue/2006-02-01
http://www.squirrelmail.org/security/issue/2006-02-10
http://www.squirrelmail.org/security/issue/2006-02-15

Solution :

Upgrade to SquirrelMail 1.4.6 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("imap/login", "imap/password");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: the vulnerabilities can't be exploited without being authenticated.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to login.
  req = http_get(item:string(dir, "/src/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # - first grab the session cookie.
  pat = "Set-Cookie: SQMSESSID=(.+); path=";
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      sid = eregmatch(pattern:pat, string:match);
      if (!isnull(sid)) {
        sid = sid[1];
        break;
      }
    }
  }
  if (isnull(sid)) {
    #if (log_verbosity > 1) debug_print("can't get session cookie!", level:0);
    exit(1);
  }
  # - now send the username / password.
  postdata = string(
    "login_username=", user, "&",
    "secretkey=", pass, "&",
    "js_autodetect_results=0&",
    "just_logged_in=1"
  );
  req = string(
    "POST ",  dir, "/src/redirect.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: SQMSESSID=", sid, "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);
  if ("Set-Cookie: SQMSESSID=deleted;" >< res) {
    #if (log_verbosity > 1) debug_print("user/password incorrect!", level:0);
    exit(1);
  }

  # - and get the secret key.
  pat = "Set-Cookie: key=(.+); path=";
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      key = eregmatch(pattern:pat, string:match);
      if (!isnull(key)) {
        key = key[1];
        break;
      }
    }
  }
  if (isnull(key)) {
    #if (log_verbosity > 1) debug_print("can't get secret key!", level:0);
    exit(1);
  }

  # Finally, try to exploit the IMAP injection flaw.
  req = http_get(
    item:string(
      dir, "/src/right_main.php?",
      "PG_SHOWALL=0&",
      "sort=0&",
      "startMessage=1&",
      # nb: this is just a corrupted mailbox name, but since the fix
      #     strips out CR/LFs, this will suffice as a check.
      "mailbox=INBOX\\r\\n", SCRIPT_NAME
    ), 
    port:port
  );
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: key=", key, "; SQMSESSID=", sid, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  # There's a problem if we see an error with the corrupted mailbox name.
  if (string("SELECT &quot;INBOX\\r\\n", SCRIPT_NAME) >< res) {
    security_note(port);
  }

  # Be nice and sign out.
  req = http_get(
    item:string(dir, "/src/signout.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: key=", key, "; SQMSESSID=", sid, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
}
