#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11821);
 script_bugtraq_id(8439);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Dropbear SSH server format string vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute arbitrary code on the remote host.

Description :

The remote host is runnning Dropbear SSH.

There is a format string vulnerability in all versions of the Dropbear SSH 
server up to and including version 0.34. An attacker may use this flaw to 
execute arbitrary code on the remote host.

Solution : 

Upgrade to the latest version of the Dropbear SSH server.

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks remote SSH server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/ssh", 22);
 script_dependencies("ssh_detect.nasl");
 exit(0);
}

#
# The script code starts here
#

include("backport.inc");
port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));

if("dropbear" >< banner)
{
    if (ereg(pattern:"ssh-.*-dropbear_0\.(([0-2].*)|3[0-4])", string:banner))
    {
        security_hole(port);
    }
}
 
