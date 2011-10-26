# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# GPL
#
# Ref: Juan Pablo Martinez Kuhn


if(description)
{
 script_id(14314);
 script_cve_id("CVE-2004-1701", "CVE-2004-1702");
 script_bugtraq_id(10899, 10900);
 script_version ("$Revision: 1.7 $");

 name["english"] = "cfengine AuthenticationDialogue vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Cfengine is running on this remote host.

cfengine cfservd is reported prone to a remote heap-based buffer 
overrun vulnerability. 

The vulnerability presents itself in the cfengine cfservd 
AuthenticationDialogue() function. The issue exists due to a 
lack of sufficient boundary checks performed on challenge data 
that is received from a client. 

In addition, cfengine cfservd is reported prone to a remote denial 
of service vulnerability. The vulnerability presents itself in the cfengine 
cfservd AuthenticationDialogue() function which is responsible for processing 
SAUTH commands and also performing RSA based authentication.  The vulnerability 
presents itself because return values for several statements within the 
AuthenticationDialogue() function are not checked. 

Solution: Upgrade to 2.1.8 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "check for cfengine flaw based on its version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);
version = get_kb_item("cfengine/version");
if (version)
{
 if (egrep(pattern:"^2\.(0\.|1\.[0-7]([^0-9]|$))", string:version))
  security_hole(port);
}
