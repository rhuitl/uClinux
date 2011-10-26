#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11499);
 script_bugtraq_id(7230);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0003");
 script_cve_id("CVE-2003-0161");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:120-01");
 script_version("$Revision: 1.14 $");

 
 name["english"] = "Sendmail buffer overflow due to type conversion";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to a remote buffer overflow allowing remote
users to gain root privileges.

Sendmail versions from 5.79 to 8.12.8 are vulnerable.
Solution : Upgrade to Sendmail ver 8.12.9 or greater or
if you cannot upgrade, apply patches for 8.10-12 here:

http://www.sendmail.org/patchps.html

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
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
	script_dependencie("smtpserver_detect.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("smtpserver_detect.nasl", "os_fingerprint.nasl", "solaris7_107684.nasl", "solaris7_x86_107685.nasl", "solaris8_110615.nasl", "solaris8_x86_110616.nasl", "solaris9_113575.nasl", "solaris9_x86_114137.nasl");

 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

if ( get_kb_item("BID-8641") ) exit(0);

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
 if(egrep(pattern:".*Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(\/|UCB| )([5-7]\.|8\.([0-9](\.|;|$)|1[01]\.|12\.[0-8](\/| |\.|\+)))).*", string:banner, icase:TRUE))
    security_hole(port);
 else if(egrep(pattern:".*Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.1[01]\..*|8\.12\.[0-8]|SMI-[0-8]\.([0-9]|1[0-2]))/.*",
  string:banner, icase:TRUE))
    security_hole(port);
}
