#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10269);
 script_bugtraq_id(843);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0834");
 
 name["english"] = "SSH Overflow";
 name["francais"] = "Buffer overflow dans SSH";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code might be executed on the remote host

Description :

The remote host is a running a version of the SSH server which is older than 
(or as old as) version 1.2.27.

If this version was compiled against the RSAREF library, then it is very 
likely to be vulnerable to a buffer overflow which may be exploited by an 
attacker to gain root privileges on your system.

To determine if you compiled ssh against the RSAREF library, type 
'ssh -V' on the remote host.

Solution : 

Use SSH 2.x, or do not compile ssh against the RSAREF library

Risk factor :

Critical / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 - 2006 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('backport.inc');

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/ssh");
if(!port)port = 22;


banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = get_backport_banner(banner:banner);

if ( "openssh" >< tolower(banner) ) exit(0);

if(ereg(string:banner, pattern:"SSH-.*-1\.([0-1]|2\.([0-1]..*|2[0-7]))[^0-9]*$", icase:TRUE))security_warning(port);
