#
# (C) Tenable Network Security
#
#
# Thanks to H D Moore for his notification.
#

if(description)
{
 script_id(11837);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0020");
 script_bugtraq_id(8628);
 script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:279");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:039");

 script_version ("$Revision: 1.20 $");

 
 name["english"] = "OpenSSH < 3.7.1";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH which is older than 3.7.1

Versions older than 3.7.1 are vulnerable to a flaw in the buffer management
functions which might allow an attacker to execute arbitrary commands on this 
host.

An exploit for this issue is rumored to exist.


Note that several distribution patched this hole without changing
the version number of OpenSSH. Since Nessus solely relied on the
banner of the remote SSH server to perform this check, this might
be a false positive.

If you are running a RedHat host, make sure that the command :
          rpm -q openssh-server
	  
Returns :
	openssh-server-3.1p1-13 (RedHat 7.x)
	openssh-server-3.4p1-7  (RedHat 8.0)
	openssh-server-3.5p1-11 (RedHat 9)

Solution : Upgrade to OpenSSH 3.7.1
See also : http://marc.theaimsgroup.com/?l=openbsd-misc&m=106375452423794&w=2
	   http://marc.theaimsgroup.com/?l=openbsd-misc&m=106375456923804&w=2
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
 if ( ! defined_func("bn_random") )
	script_dependencie("ssh_detect.nasl");
 else
 	script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl", "redhat-RHSA-2003-280.nasl", "redhat_fixes.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc"); 

port = get_kb_item("Services/ssh");
if(!port)port = 22;

if ( get_kb_item("CVE-2003-0682") ) exit(0);

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));
if(ereg(pattern:".*openssh[-_](([12]\..*)|(3\.[0-6].*)|(3\.7[^\.]*$))[^0-9]*", 
	string:banner)) {
		security_hole(port);
	}
