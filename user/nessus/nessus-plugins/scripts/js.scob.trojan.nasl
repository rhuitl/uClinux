# This script was written by Jeff Adams <jadams@netcentrics.com>
# This script is Copyright (C) 2004 Jeff Adams


if(description)
{
 script_id(12286);
 
 script_version("$Revision: 1.1 $");

 name["english"] = "JS.Scob.Trojan or Download.Ject Trojan";

 script_name(english:name["english"]);
 
 desc["english"] = "
JS.Scob.Trojan or Download.Ject Trojan

JS.Scob.Trojan or Download.Ject is a simple Trojan that executes a 
JavaScript file from a remote server. 

The Trojan's dropper sets it as the document footer for all pages 
served by IIS Web sites on the infected computer.  The presence of 
Kk32.dll or Surf.dat may indicate a client side infection.  More 
information is available here:

http://www.microsoft.com/security/incident/download_ject.mspx

Solution : Use Latest Anti Virus to clean machine. Virus Definitions 
and removal tools are being released as of 06/25/04

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "JS.Scob.Trojan/JS/Exploit-DialogArg.b Trojan";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Jeff Adams");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		    "smb_login.nasl","smb_registry_access.nasl",
		    "smb_registry_full_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");
include("smb_file_funcs.inc");


rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");

if (! rootfile)
	exit(0);

file[0] = string(rootfile, "\\system32\\kk32.dll");
file[1] = string(rootfile, "\\system32\\Surf.dat");


for (mu=0; file[mu]; mu++)
{
	myread = smb_file_read(file:file[mu], count:4, offset:0);
	if (! egrep(string:myread, pattern:"^ERROR"))
		security_hole(port);
}




