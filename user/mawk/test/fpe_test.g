#  tests if mawk has been compiled to correctly handle
#  floating point exceptions

echo testing division by zero
mawk -f fpetest1.awk
echo ========================== status = $status ==========================

echo testing overflow
mawk -f fpetest2.awk
echo ========================== status = $status ==========================

echo testing domain error
cat fpetest3.awk
mawk -f fpetest3.awk >temp
echo ========================== status = $status ==========================

cat temp

echo  the returns should  be 1 0 1
echo  note on the atari it cannot be 1 1 1
# rm  temp
