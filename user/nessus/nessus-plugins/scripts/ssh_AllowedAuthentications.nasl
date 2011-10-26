#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10965);
 script_cve_id("CVE-2005-0962");
 script_bugtraq_id(4810);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "SSH 3 AllowedAuthentication";
 name["francais"] = "SSH 3 AllowedAuthentication";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote SSH server may accept password-based authentications even when
not explicitely enabled.

Description :

The remote host is running a version of SSH which is older than 3.1.2
and newer or equal to 3.0.0.

There is a vulnerability in this release that may, under some circumstances, 
allow users to authenticate using a password whereas it is not explicitly 
listed as a valid authentication mechanism.

An attacker may use this flaw to attempt to brute force a password using a 
dictionary attack (if the passwords used are weak).

Solution : 

Upgrade to version 3.1.2 of SSH which solves this problem.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:N/A:N/I:P/B:I)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#
include("backport.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));


if("openssh" >< banner)exit(0);
if("f-secure" >< banner)exit(0);
if("mpSSH" >< banner)exit(0);
if("Sun_SSH" >< banner)exit(0);

if(ereg(pattern:"SSH[-_](3\.(0\.[0-9]+)|(1\.[01])[^0-9]*)$", string:banner))
	security_note(port);
