#
# (C) Tenable Network Security
#
#
# Ref:
# From: Damien Miller <djm@cvs.openbsd.org>
# To: openssh-unix-announce@mindrot.org
# Subject: Multiple PAM vulnerabilities in portable OpenSSH
# also covers CVE-2001-1380

if(description)
{
 script_id(11848);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0020");
 script_bugtraq_id(8677);
 script_cve_id("CVE-2003-0786", "CVE-2003-0787");
 script_version ("$Revision: 1.11 $");

 
 name["english"] = "Portable SSH OpenSSH < 3.7.1p2";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running OpenSSH 3.7p1 or 3.7.1p1.

These versions are vulnerable to a flaw in the way they handle PAM 
authentication and may allow an attacker to gain a shell on this host.

*** Note that Nessus did not detect whether PAM is being enabled
*** in the remote sshd or not, so this might be a false positive.


Solution : Upgrade to OpenSSH 3.7.1p2 or disable PAM support in sshd_config
Risk factor : High";
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


include("backport.inc"); 
include("global_settings.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

if ( report_paranoia < 2 ) exit(0);

# Windows not affected
os = get_kb_item("Host/OS/icmp");
if ( os )
{
 if ( "Linux" >!< os &&
      "SCO" >!< os ) exit(0);
}



banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));
if(ereg(pattern:".*openssh[-_]3\.7(\.1)?p1", string:banner))
	security_hole(port);	
