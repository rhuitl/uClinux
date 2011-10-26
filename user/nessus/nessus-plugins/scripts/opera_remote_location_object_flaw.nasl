#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: GreyMagic Software
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14261);
 script_cve_id("CVE-2004-2570");
 script_bugtraq_id(10873);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8331");
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Opera remote location object cross-domain scripting vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains a web browser that is affected by 
multiple flaws.

Description :

The version of Opera on the remote host fails to block write access to
the 'location' object.  This could allow a user to create a specially
crafted URL to overwrite methods within the 'location' object that would
execute arbitrary code in a user's browser within the trust relationship
between the browser and the server, leading to a loss of confidentiality
and integrity. 

See also :

http://www.greymagic.com/security/advisories/gm008-op/
http://www.opera.com/docs/changelogs/windows/754/

Solution : 

Upgrade to Opera 7.54 or newer.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

v = get_kb_item("SMB/Opera/Version");
if(strlen(v))
{
  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 54))
    security_note(get_kb_item("SMB/transport"));
}


