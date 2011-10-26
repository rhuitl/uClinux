#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20182);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-3116");
 script_bugtraq_id(15353);
 script_xref(name:"OSVDB", value:"20674");

 name["english"] = "VERITAS NetBackup Volume Manager Daemon Buffer Overflow Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running a version of VERITAS NetBackup Volume
Manager that is vulnerable to a remote buffer overflow.  An attacker
may exploit this flaw to execute arbitrary code on the remote host
with the privileges of a local administrator or to disable the remote
service remotely. 

To exploit this flaw, an attacker would need to send a specially
crafted packet to the remote service. 

Solution :

http://seer.support.veritas.com/docs/279553.htm

Risk factor :

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:I)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if VERITAS NetBackup Volume Manager is vulnerable to an overflow";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("veritas_netbackup_vmd_detect.nasl");
 script_require_keys("VERITAS/NetBackupVolumeManager");
 exit(0);
}

include ("byte_func.inc");

string = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA661292220 9 1 1 \n\n\n\n\n\n\n\n\0' + crap (data:"A", length:0x28);

port = get_kb_item ("VERITAS/NetBackupVolumeManager");
if (!get_port_state (port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

send (socket:soc, data:string);
len = recv (socket:soc, length:4, min:4);
if (strlen(len) != 4)
  exit (0);

len = getdword (blob:len, pos:0);
if ( (len <= 0) || (len >= 65535) )
  exit (0);

buf = recv (socket:soc, length:len, min:len);
if (strlen(buf) != len)
  exit (0);

if (egrep (pattern:"^REQUEST ACKNOWLEDGED", string:buf))
  security_hole (port);

