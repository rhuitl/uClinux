#
# (C) Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# freebsd_package.inc 
# $Revision: 1.5 $
#



# Globals
OPERATOR_GT	=	1;
OPERATOR_GTE	=	2;
OPERATOR_LT	=	3;
OPERATOR_LTE	=	4;
OPERATOR_EQ	=	5;


function parse_pkg_name(pkg)
{
 local_var elems, num, i, name, version;
 local_var my_pkg;

 elems = split(pkg, sep:" ", keep:0);
 num = max_index(elems);
 elems = split(elems[0], sep:"-", keep:0);

 name = elems[0];

 for ( i = 1 ; i < max_index(elems) - 1 ; i ++ )
 {
 name += "-" + elems[i];
 }

 version = split(elems[i], sep:"_", keep:0);
 if ( version[0] == elems[i] ) version = split(elems[i], sep:"p", keep:0);
 if ( version[0] == elems[i] ) version = split(elems[i], sep:",", keep:0);
 
 my_pkg["name"]     = name;
 my_pkg["version"]  = version[0];
 my_pkg["revision"] = version[1];

 return my_pkg;
}


#
# Handle stuff such as "10b"
#
function convert_int(s)
{
 local_var i, ret, flag;

 flag = 0;

 for ( i = 0; i < strlen(s) ; i ++ )
 {
  if ( ord(s[i]) < ord("0") || ord(s[i]) > ord("9") ) flag = 1;
 }

 if ( flag == 0 )
	{
	return int(s);
	}

 ret = 0;
 for ( i = 0 ; i < strlen(s) ; i ++ )
 {
  ret *= 36;
  if ( ord(s[i]) >= ord("0") &&
       ord(s[i]) <= ord("9") ) ret += ord(s[i]);
  else
	ret += ord(tolower(s[i])) - ord("a");
 }

 return ret;
}


function vers_cmp(a, b)
{
 local_var array_a, array_b, i, max;

 array_a = split(a, sep:".", keep:0);
 array_b = split(b, sep:".", keep:0);

 max = max_index(array_a);
 if ( max_index(array_b) > max ) max = max_index(array_b);

 for ( i = 0 ; i < max ; i ++ )
 {
  if ( convert_int(s:array_a[i]) != convert_int(s:array_b[i]) )
  {
    return convert_int(s:array_a[i]) - convert_int(s:array_b[i]);
  }
 }

 return 0;
}


function pkg_cmp(pkg, reference)
{
 local_var my_pkg, my_reference, eq;


 if ( strlen(pkg) == 0 || strlen(reference) == 0) return 0;

 my_pkg = parse_pkg_name(pkg:pkg);
 my_reference = parse_pkg_name(pkg:reference);

 eq = vers_cmp(a:my_pkg["version"], b:my_reference["version"]);
 if ( eq ) return eq;
	
 
 if ( !isnull(my_reference["revision"]) &&
      isnull(my_pkg["revision"])  ) return -1;


 eq = vers_cmp(a:my_pkg["revision"], b:my_reference["revision"]);
 return eq; 
}






function pkg_op(str)
{
 if ( strlen(str) == 0 ) return 0;
 if ( str[0] == ">" && str[1] == "=" ) return OPERATOR_GTE; 
 else if ( str[0] == ">" ) return OPERATOR_GT; 
 else if ( str[0] == "=" ) return OPERATOR_EQ; 
 else if ( str[0] == "<" && str[1] == "=") return OPERATOR_LTE;
 else if ( str[0] == "<" ) return OPERATOR_LT;
 else return -1;
}

function pkg_op_match(op, n)
{
 if ( (op == OPERATOR_GT || op == OPERATOR_GTE) && n > 0 ) return 1;
 if ( (op == OPERATOR_LT || op == OPERATOR_LTE) && n < 0 ) return 1;
 if ( (op == OPERATOR_EQ || op == OPERATOR_LTE || op == OPERATOR_GTE ) && n == 0 ) return 1;
 return 0;
}

function freebsd_packages()
{
 return get_kb_item("Host/FreeBSD/pkg_info");
}

function pkg_test(pkg, problem, url, seealso)
{
 local_var pkg_name, orig, op1, op2, op1_arg, op2_arg, n, pkgs, package, report;

 pkgs = freebsd_packages();
 if ( ! pkgs ) exit(0);
 
 orig = pkg;

 pkg_name = ereg_replace(pattern:"([^<>=]*).*", string:pkg, replace:"\1");
 if ( pkg_name == "FreeBSD" ) return 0; # TBD
 pkg -= pkg_name;

 pkg_name = str_replace(find:"{", replace:"(", string:pkg_name);
 pkg_name = str_replace(find:"}", replace:")", string:pkg_name);
 pkg_name = str_replace(find:",", replace:"|", string:pkg_name);


 op1     = pkg_op(str:pkg);
 if (op1 < 0 )
 {
   #display(orig, " -- unsupported operator\n");
   return 0;
 }
 else if ( op1 > 0 ) op1_arg = ereg_replace(pattern:"^[<>=]*([^<>=]*).*", string:pkg, replace:"\1");

 pkg     = ereg_replace(pattern:"^[<>=]*([^<>=]*)(.*)", string:pkg, replace:"\2");
 op2     = pkg_op(str:pkg);
 if (op1 < 0 )
 {
   #display(orig, " -- unsupported operator\n");
   return 0;
 } else if ( op1 > 0 ) op2_arg = ereg_replace(pattern:"^[<>=]*([^<>=]*).*", string:pkg, replace:"\1");



 package = egrep(pattern:"^" + pkg_name + "-", string:pkgs);
 if (  ! package ) return 0;

 n = pkg_cmp(pkg:package, reference:pkg_name + "-" + op1_arg);
 if ( !pkg_op_match(op:op1, n:n) ) return 0;

 # All versions > X vulnerables ? I don't think so
 if ( op2 == 0 && ( op1 == OPERATOR_GT || op1 == OPERATOR_GTE ) ) return 0;


 if ( op2 != 0 )
 {
 n = pkg_cmp(pkg:package, reference:pkg_name + "-" + op2_arg);
 if ( !pkg_op_match(op:op2, n:n) ) return 0;
 }
 
 #display(ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1"), " IS TOO OLD  - should be ",op1, " ", op1_arg, " ", op2, " ", op2_arg, "\n");

 report = "
Synopsis :

The remote host is missing a security update

Description :


The remote package " + ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1") + " is not up-to-date.

Type of problem : " + problem + "


Solution :\n\n" + url + '\n';

 if ( strlen(seealso) > 1 ) report += "See also : " + seealso;

 report += '\n\nPlugin output :

' + package + ' is installed on the remote host.\n';

 security_hole(port:0, data:report);
 return 1;
}
