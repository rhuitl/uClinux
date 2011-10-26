#
# (C) Tenable Network Security
#
# Ref: 
# Date: Mon, 05 May 2003 16:44:47 -0300
# From: CORE Security Technologies Advisories <advisories@coresecurity.com>
# To: Bugtraq <bugtraq@securityfocus.com>,
# Subject: CORE-2003-0303: Multiple Vulnerabilities in Mirabilis ICQ client
#

if(description)
{
 script_id(11572);
 script_bugtraq_id( 132, 246, 929, 1307, 2664, 3226, 3813, 7461, 7462, 7463, 7464, 7465, 7466);
 script_cve_id(
   "CVE-1999-1418",
   "CVE-1999-1440", 
   "CVE-2000-0046",
   "CVE-2000-0564",
   "CVE-2000-0552",
   "CVE-2001-0367",
   "CVE-2002-0028",
   "CVE-2001-1305",
   "CVE-2003-0235", 
   "CVE-2003-0236", 
   "CVE-2003-0237",
   "CVE-2003-0238",
   "CVE-2003-0239"
 );
 
 script_version("$Revision: 1.7 $");
 name["english"] = "Multiple ICQ Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows host contains a program that is affected by
multiple flaws. 

Description :

There are multiple flaws in versions of ICQ before 2003b, including
some that may allow an attacker to execute arbitrary code on the
remote host. 

See also :

http://www.coresecurity.com/common/showdoc.php?idx=315&idxseccion=10

Solution : 

Upgrade to ICQ 2003b or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks version of ICQ installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("icq_installed.nasl");
 script_require_keys("SMB/ICQ/Version");

 exit(0);
}


include("smb_func.inc");


ver = get_kb_item("SMB/ICQ/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  # Check whether it's an affected version.
  #
  # nb: 2003b == "5.5.6.3916"
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 &&
      (
        int(iver[1]) < 5 ||
        (
          int(iver[1]) == 5 &&
          (
            int(iver[2]) < 6 ||
            (int(iver[2]) == 6 && int(iver[3]) < 3916)
          )
        )
      )
    )
  ) security_warning(kb_smb_transport());
}
