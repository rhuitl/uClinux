#
# This script was written by Tenable Network Security
#
#
# See the Nessus Scripts License for details
#

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12513);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english:"MacOS X Server Default Password");
	     

 desc["english"] = "
The login/password combination 'root/12345678' is valid.

On older Macintosh computers, Mac OS X server is configured by
default with the account 'root/1234568' (on newer computers, the
serial number of the system is used instead).

Solution : Set a strong password for the root account
Risk factor : High";

 script_description(english:desc["english"]);

		 
script_summary(english:"Logs into the remote host");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 
 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

os = get_kb_item("Host/OS/icmp");
if ( os && "Mac OS X" >!< os ) exit(0);

port = check_account(login:"root", password:"12345678");
if(port)security_hole(port);
