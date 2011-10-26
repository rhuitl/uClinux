#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(14236);
 script_cve_id("CVE-2004-1440");
 script_bugtraq_id(10850);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8299");

 script_version("$Revision: 1.9 $");

 name["english"] = "Putty Modpow integer handling";
 script_name(english:name["english"]);

 desc["english"] = "
PuTTY is a free SSH client.  There is a flaw in this version of putty
which would allow a remote attacker to remotely execute code on the
target machine. 

Solution : Upgrade to the newest version of PuTTY.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Putty Modpow integer handling detection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("netbios_name_get.nasl", "smb_registry_access.nasl",
                     "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);

 exit(0);
}


exit(0); # to be fixed

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
		if (( s = strstr(myread, "PuTTY-Release-") ) )  
		{
			version = ereg_replace(pattern:"PuTTY-Release-([0-9.]*).*", replace:"\1", string:s);
			set_kb_item(name:"SMB/PuTTY/version", value:version);
    			if (egrep(string:version, pattern:"^0\.([0-4].|5[0-3])")) 
				security_hole(port);
		}
	}
}
