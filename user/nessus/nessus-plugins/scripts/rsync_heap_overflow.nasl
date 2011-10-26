#
# This script is (C) 2003 Tenable Network Security
#
#

if (description)
{
 script_id(11943);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0024");
 script_bugtraq_id(9153);
 script_cve_id("CVE-2003-0962");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:398-01");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:050");
 
 script_version ("$Revision: 1.8 $");
 script_name(english:"rsync heap overflow");
 desc["english"] = "
The remote rsync server might be vulnerable to a heap
overflow.

*** Since rsync does not advertise its version number
*** and since there are little details about this flaw at
*** this time, this might be a false positive

An attacker may use this flaw to gain a shell on this host

Solution : Upgrade to rsync 2.5.7
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 exit(0);
}



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
# rsyncd speaking protocol 26 or older *MIGHT* be vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-6])[^0-9]", string:welcome))
{
 security_hole(port);
}
