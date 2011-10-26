#
# (C) Tenable Network Security
#

if(description) {
 script_id(11895);
 script_bugtraq_id(4396, 4985);
 script_cve_id("CVE-2002-0158", "CVE-2002-0164");
 script_version ("$Revision: 1.7 $");
 name["english"] = "SCO OpenServer multiple vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
OpenServer 5.0.7, OpenServer 5.0.6, and OpenServer 5.0.5 are vulnerable
to two (2) distinct exploits.  Namely,

1) Xsco can be locally exploited by any valid user in order to escalate
their privileges to 'root'.  The bug is due to improper input handling
when running the command line switch '-co'.

2) There is a vulnerability in the MIT-SHM extension within
all X servers that are running as root.  Any user with local X access 
can exploit the MIT-SHM extension and gain read/write access to any 
shared memory segment on the system.

*** This plugin relied on the banner of the remote system
*** to determine that it is a SCO Unix server, so this alert
*** might be a false positive


More information can be found at:
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0158
http://marc.theaimsgroup.com/?l=bugtraq&m=101776858410652&w=2
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0164
http://marc.theaimsgroup.com/?l=bugtraq&m=103547625009363&w=2
http://www.securityfocus.com/bid/4396

Solution: Install the patched binaries from
ftp://ftp.sco.com/pub/updates/OpenServer/CSSA-2003-SCO.26

Risk factor : High";

script_description(english:desc["english"]);


 summary["english"] = "Checks the remote SCO OpenServer";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}




# start script

# kind of a hokey way to find the bug...but, both bugs are local...

include ("telnet_func.inc");

port = get_kb_item("Services/telnet");
if (!port) port=23;
r = get_telnet_banner(port:port); 
if (egrep(pattern:".*SCO OpenServer\(TM\) Release.*5\.0\.[5-7].*", string:r)) security_hole(0);
