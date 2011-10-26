# This script was written by Michel Arboi (GPL)

account = "super";
password = "forgot";

if(description)
{
 script_id(17292);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-1999-1420", "CVE-1999-1421");
 script_bugtraq_id(212);
 
 script_name(english:"Default password 'forgot' for account 'super'");

 desc["english"] = "
The account 'super' has the password 'forgot'.  An attacker may use it
to gain further privileges on this system. 

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
include("default_account.inc");
include('global_settings.inc');

if ( ! thorough_tests )exit(0);

port = check_account(login:account, password:password);
if(port)security_hole(port);
