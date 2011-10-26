# mawk test gulam script
#
#  This is a simple test that a new made mawk seems to
#  be working OK.
#  Its certainly not exhaustive, but the last two tests in 
#  particular use most features.
# 
#  It needs to be run from mawk/test and mawk needs to be in PATH 
#

## set dat=mawk_test.dat

#  find out which mawk were testing
echo testing mawk version
.\mawk.ttp -W version
echo  ===================== status = $status  =====================
echo " "
# ################################

echo testing input and field splitting
.\mawk.ttp -f wc.awk mawk_tes.dat >temp1
diff -c temp1 wc-awk.out
echo  ===================== status = $status  =====================
echo " "
# ####################################

echo testing regular expression matching
.\mawk.ttp -f reg0.awk mawk_tes.dat >temp2
.\mawk.ttp -f reg1.awk mawk_tes.dat >>temp2
.\mawk.ttp -f reg2.awk mawk_tes.dat >>temp2
diff -c temp2 reg-awk.out
echo  ===================== status = $status  =====================
echo " "
# ######################################

echo testing arrays and flow of control
.\mawk.ttp -f wfrq0.awk mawk_tes.dat >temp3
diff -c temp3 wfrq-awk.out
echo  ===================== status = $status  =====================
echo " "
# ################################

echo testing function calls and general stress test
.\mawk.ttp -f examples\decl.awk mawk_tes.dat >temp4
diff -c temp4 decl-awk.out
echo  ===================== status = $status  =====================
echo " "
echo if the status after each test is 0, then the tested mawk seems OK
#rm temp[1-4]
