#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Refs: o http://lists.samba.org/pipermail/samba-technical/2002-June/037400.html
#       o FreeBSD-SN-02:05
#
# Only Samba 2.2.4 is affected by this.
#

if(description)
{
 script_id(11113);
 script_cve_id("CVE-2002-2196");
 script_bugtraq_id(5587);
 script_version ("$Revision: 1.8 $");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2002:045");


 name["english"] = "Samba Buffer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number,
is vulnerable to a possible buffer overflow.

The implications of this vulnerability are not clear at this
time.


Solution : upgrade to Samba 2.2.5
Risk factor : High
See also : http://lists.samba.org/pipermail/samba-technical/2002-June/037400.html";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smb_nativelanman.nasl");
 script_require_ports(139);
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.4[^0-9]*$",
 	 string:lanman))security_hole(139);
}
