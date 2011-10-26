# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# GPL
#
# Ref: Pekka Savola <pekkas@netcore.fi>


if(description)
{
 script_id(14316);
 script_bugtraq_id(1757);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2000-0947");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"1590");

 name["english"] = "cfengine format string vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Cfengine is running on this remote host.

Cfengine contains a component, cfd, which serves as a remote-configuration
client to cfengine.  This version of cfd contains several flaws in the
way that it calls syslog().  As a result, trusted hosts and valid users
(if access controls are not in place) can cause the vulnerable host to
log malicious data which, when logged, can either crash the server or
execute arbitrary code on the stack.  In the latter case, the code would
be executed as the 'root' user.

Solution: Upgrade to 1.6.0a11 or newer

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "check for cfengine flaw based on its version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
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
 	if (egrep(pattern:"^1\.([0-5]\..*|6\.0a([0-9]|10)[^0-9])", string:version))
  		security_hole(port);
}
