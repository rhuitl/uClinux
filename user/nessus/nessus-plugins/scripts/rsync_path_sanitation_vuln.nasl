#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: Reported by vendor
# This script is released under the GNU GPLv2

if (description)
{
 script_id(14223);
 script_bugtraq_id(10938);
 script_cve_id("CVE-2004-0792");
  

 script_name(english:"rsync path sanitation vulnerability");
 script_version ("$Revision: 1.9 $");
 desc["english"] = "
A vulnerability has been reported in rsync, which potentially can be exploited 
by malicious users to read or write arbitrary files on a vulnerable system.

rsync is a software product for keeping files synched across multiple
systems.  Rsync is a network-based program and typically communicates
over TCP port 873.  

There is a flaw in this version of rsync which, due to an input validation
error, would allow a remote attacker to gain access to the remote system.

An attacker, exploiting this flaw, would need network access to the TCP port.  

Successful exploitation requires that the rsync daemon is *not* running chrooted.

*** Since rsync does not advertise its version number
*** and since there are little details about this flaw at
*** this time, this might be a false positive

Solution : Upgrade to rsync 2.6.3 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);


port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("rsync/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}




#
# rsyncd speaking protocol 28 are not vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-8])", string:welcome))
{
 security_hole(port);
}
