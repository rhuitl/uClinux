#
# This script was copied & modified by Michel Arboi :-)
#
#
# See the Nessus Scripts License for details
#

account = "bash";

if(description)
{
 script_id(15583);
 script_version ("$Revision: 1.6 $");
 
 script_name(english:"Unpassworded bash account");
	     
desc["english"] = "
The account 'account' has no password set. 
An attacker may use it to gain further privileges on this system

This account was probably created by a backdoor installed 
by a fake Linux Redhat patch.

See http://www.k-otik.com/news/FakeRedhatPatchAnalysis.txt

Risk factor : High
Solution : disable this account and check your system";

 script_description(english:desc["english"]);

 script_summary(english:"Logs into the remote host with bash account");

 script_category(ACT_GATHER_INFO);

 # script_family(english:"Default Unix Accounts");
 script_family(english:"Backdoors");
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 
 script_dependencie("find_service.nes", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

include("default_account.inc");
include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = check_account(login:account);
if(port)security_hole(port);
