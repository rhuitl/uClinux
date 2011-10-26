#
# (C) Tenable Network Security
#
#
#
# Ref:
#  Date: Wed, 17 Sep 2003 11:19:46 +0200 (CEST)
#  From: Michal Zalewski <lcamtuf@dione.ids.pl>
#  To: bugtraq@securityfocus.com, <vulnwatch@securityfocus.com>,
#      <full-disclosure@netsys.com>
#	Subject: Sendmail 8.12.9 prescan bug (a new one) [CVE-2003-0694]


if(description)
{
 script_id(11838);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0005");
 script_bugtraq_id(8641, 8649);
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:283-01");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:040");

 script_cve_id("CVE-2003-0681", "CVE-2003-0694");
 script_version("$Revision: 1.13 $");
 
 name["english"] = "Sendmail prescan() overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to a remote buffer overflow allowing remote
users to gain root privileges.

Sendmail versions from 5.79 to 8.12.9 are vulnerable.
Solution : Upgrade to Sendmail ver 8.12.10.
See also : http://lists.netsys.com/pipermail/full-disclosure/2003-September/010287.html


NOTE: manual patches do not change the version numbers.
Vendors who have released patched versions of sendmail
may still falsely show vulnerability.

*** Nessus reports this vulnerability using only
*** the banner of the remote SMTP server. Therefore,
*** this might be a false positive.

Risk factor : High";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version number"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
	script_dependencie("smtpserver_detect.nasl");
 else
 	script_dependencie("smtpserver_detect.nasl", "solaris7_107684.nasl", "solaris7_x86_107685.nasl", "solaris8_110615.nasl", "solaris8_x86_110616.nasl", "solaris9_113575.nasl", "solaris9_x86_114137.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("backport.inc");

if ( get_kb_item("BID-8641") ) exit(0);

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
 banner = get_backport_banner(banner:banner);
 if(egrep(pattern:".*Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(\/|UCB| )([5-7]\.|8\.([0-9](\.|;|$)|10|11\.[0-6][^0-9]|12\.[0-9](\/| |\.|\+)))).*", string:banner, icase:TRUE))
    security_hole(port);
 else if(egrep(pattern:".*Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-6]|8\.12\.[0-9]|SMI-[0-8]\.([0-9]|1[0-2]))/.*",
  string:banner, icase:TRUE))
    security_hole(port);
}
