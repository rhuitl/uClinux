#
# (C) Tenable Network Security
# 
# 

if(description)
{
 script_id(12128);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Agobot.FO Backdoor Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the Agobot.FO backdoor installed.  This
backdoor is known to:
1) scan local networks for common Microsoft vulnerabilities
2) scan local networks for exploitable DameWare systems
3) brute force local Microsoft machine User accounts
4) connect to an IRC channel and setup a BOT for remote command
execution.
 
See also: http://www.f-secure.com/v-descs/agobot_fo.shtml
Solution: This backdoor should be immediately removed from the network
and manually cleaned.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Agobot.FO";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 exit(0);
}


#
# The code starts here:
#

# This service is detected by find_service2.nasl
port = get_kb_item("Services/agobot.fo");
if ( port ) security_hole(port);
