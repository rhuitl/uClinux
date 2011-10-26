#
# This script was written by Thomas reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd: description moved, bugfix

if(description)
{
 script_id(10948);
 script_bugtraq_id(2811);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2001-1046");
 name["english"] = "qpopper options buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"]  = "
The remote qpopper server, according to its banner, is
running version 4.0.3 or version 4.0.4.  These versions
are vulnerable to a buffer overflow if they are configured
to allow the processing of a user's ~/.qpopper-options file.
A local user can cause a buffer overflow by setting the
bulldir variable to something longer than 256 characters.

*** This test could not confirm the existence of the
*** problem - it relied on the banner being returned.

Solution : Upgrade to the latest version, or disable
processing of user option files.

Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "qpopper options buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 
 script_copyright(english:"This script is Copyright (C) 2002 Thomas Reinke");
 
 family["english"] = "Misc.";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner)
{
    if(get_port_state(port))
    {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
    }
}

if(banner)
{
  
    if(ereg(pattern:".*Qpopper.*version (4\.0\.[34]).*", string:banner, icase:TRUE))
    {
	security_hole(port);
    }
}
exit(0);
