#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Knud Erik Højgaard <knud@skodliv.dk>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14263);
 script_bugtraq_id(6724);
 script_cve_id("CVE-2003-0048");
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"7687");

 script_version("$Revision: 1.4 $");

 name["english"] = "PuTTY SSH2 authentication password persistence weakness";

 script_name(english:name["english"]);


 desc["english"] = "
PuTTY is a free SSH client.

It has been reported that this version does not safely handle password information. 
As a result, a local user may be able to recover authentication passwords.

Solution : Upgrade to the newest version of PuTTY 

Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Determine PuTTY version";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("netbios_name_get.nasl", "smb_registry_access.nasl",
                     "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);

 exit(0);
}

include("smb_nt.inc");
include("smb_file_funcs.inc");

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");
if(!rootfile)
{
	# the location of putty.exe is *not* stored in the registry
	# we will just check some common directories
	cdir[0] = "c:\\windows";
	cdir[1] = "c:\\windows\\system";
	cdir[2] = "c:\\windows\\system32";
	cdir[3] = "c:\\winnt";
	cdir[4] = "c:\\winnt\\system";
	cdir[5] = "c:\\winnt\\system32";
}
else
{
	cdir[0] = rootfile;
	cdir[1] = string(rootfile, "\\system");
	cdir[2] = string(rootfile, "\\system32");
}



for (i=0; cdir[i]; i++)
{
	myread = smb_file_read(file:string(cdir[i],"\\putty.exe"), count:4096, offset:0);
	if (! egrep(string:myread, pattern:"^ERROR")) 
	{
		myread = str_replace(find:raw_string(0), replace:"", string:myread);
		if (strstr(myread, "PuTTY-Release-"))  
		{
			#version 0.48 0.49 0.53 and 0.53b are vulnerable
    			if (egrep(string:myread, pattern:"PuTTY-Release-0\.(4[89]|53)")) 
				security_hole(port);
		}
	}
}






