# This script was written by Michel Arboi

account = "help";

if(description)
{
 script_id(17575);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(247);
 
 script_name(english:"Unpassworded help account");

 desc["english"] = "
The account 'help' has no password set. 
An attacker may use it to gain further privileges on this system

Risk factor : High
Solution : Set a password for this account or disable it";

 script_description(english:desc["english"]);
		 
 script_summary(english:"Logs into the remote host");
 script_category(ACT_GATHER_INFO);

 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 
 
 script_dependencie("find_service.nes", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 script_require_keys("Settings/ThoroughTests");

 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(0);

port = check_account(login:account);
if(port)security_hole(port);
