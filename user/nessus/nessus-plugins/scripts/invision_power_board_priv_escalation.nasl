#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18401);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1816");
  script_bugtraq_id(13797, 14289);

  name["english"] = "Invision Power Board Privilege Escalation Vulnerability / SQL Injection";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the version of Invision Power Board on the remote 
host suffers from a privilege escalation issue.  To carry out an attack, an 
authenticated user goes to delete his own group and moves users from that 
group into the root admin group.

In addition to this, the remote version of this software is vulnerable to a SQL
injection vulnerability which may allow an attacker to execute arbitrary SQL
statements against the remote database.

**** If you're using version Invision Power Board version 2.0.4, 
**** this may be a false positive as the fix does not update the
**** version number.

See also : http://lists.grok.org.uk/pipermail/full-disclosure/2005-May/034355.html
           http://forums.invisionpower.com/index.php?showtopic=169215
Solution : Apply the patch as discussed in the forum posting above.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for privilege escalation vulnerability in Invision Power Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  # nb: do a banner check; actually exploiting it requires authentication.
  ver = matches[1];

  # versions <= 2.0.4 are vulnerable.
  if (ver =~ "^([01]\.|2\.0\.[0-4][^0-9]*)") security_hole(port);
}
