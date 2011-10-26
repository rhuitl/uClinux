#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11316);
 script_bugtraq_id(2794, 6991);
 script_cve_id("CVE-2001-1349", "CVE-2002-1337");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0002");
 script_version("$Revision: 1.21 $");
 
 name["english"] = "Sendmail remote header buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to a remote buffer overflow allowing remote
users to gain root privileges.

Sendmail versions from 5.79 to 8.12.7 are vulnerable.
Solution : Upgrade to Sendmail ver 8.12.8 or greater or
if you cannot upgrade, apply patches for 8.10-12 here:

http://www.sendmail.org/patchcr.html

NOTE: manual patches do not change the version numbers.
Vendors who have released patched versions of sendmail
may still falsely show vulnerability.

*** Nessus reports this vulnerability using only
*** the banner of the remote SMTP server. Therefore,
*** this might be a false positive.

see http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?oid=21950
    http://www.cert.org/advisories/CA-2003-07.html
    http://www.kb.cert.org/vuls/id/398025

Risk factor : High";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version number"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 SECNAP Network Security");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") ) 
 	script_dependencie("smtpserver_detect.nasl");
 else
 	script_dependencie("smtpserver_detect.nasl", "solaris26_105395.nasl", "solaris26_x86_105396.nasl", "solaris7_107684.nasl", "solaris7_x86_107685.nasl", "solaris8_110615.nasl", "solaris8_x86_110616.nasl", "solaris9_113575.nasl", "solaris9_x86_114137.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

if ( get_kb_item("BID-6991") ) exit(0);


port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
  # Digital Defense came up with this nice regex :
  if(egrep(pattern:".*Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(\/|UCB| )([5-7]\.|8\.([0-9](\.|;|$)|10\.|11\.[0-6]|12\.[0-7](\/| |\.|\+)))).*", string:banner, icase:TRUE))
		security_hole(port);

  # Since the regex above is VERY complicated, I also include this simpler one, in case the first misses
  # something.
  else if(egrep(pattern:".*Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-6]|8\.12\.[0-7]|SMI-8\.([0-9]|1[0-2]))/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
