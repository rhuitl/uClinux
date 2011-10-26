#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL...

desc = 
"The remote server seems open to outsiders.
Some people love open public NNTP servers to
be able to read or post articles anonymously.
Keep in mind that robots are harvesting such 
open servers on Internet, so you cannot hope that
you will stay hidden for long.

Unwanted connections could waste your bandwith
or put you into legal trouble if outsiders use your server
to read or post 'politically incorrects' articles.

** As it is very common to have IP based authentication,
** this might be a false positive if the Nessus scanner is
** among the allowed source addresses.

Solution: Enforce authentication or filter connections from outside

Risk factor : Medium";

if(description)
{
 script_id(17204);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Open News server";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Public NNTP server is open to outside";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("nntp_info.nasl");
 script_require_ports("Services/nntp", 119);

 exit(0);
}

#

include('global_settings.inc');
include('network_func.inc');

port = get_kb_item("Services/nntp");
if ( ! port ) port = 119;

# Unusable server
if (! get_kb_item('nntp/'+port+'/ready') ||
    ! get_kb_item('nntp/'+port+'/noauth') )
 exit(0);

# Only warn on private addresses. The server might be accessible
# through NAT, so we warn if we prefere FP
if (report_paranoia < 2 && is_private_addr()) exit(0);

post = get_kb_item('nntp/'+port+'/posting');
# If we want to avoid FP, check that the message was posted
if (post && report_paranoia < 1 && get_kb_item('nntp/'+port+'/posted') <= 0)
  post = 0;

if (! post) 
  desc = str_replace(string: desc, find: 'read and post', replace: 'read');
security_warning(port: port, data: desc);
