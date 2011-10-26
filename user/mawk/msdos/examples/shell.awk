# Ben Myers <0003571400@mcimail.com>

# Test pipes under DOS. comment/uncomment print statements below
BEGIN {
# redirection done by shelled command
system("dir *.* /b >pippo.")
lcount = 0
}
{
# print
# Below is redirection done by mawk
# print >"pippo2."
print $0 | "sort"
lcount++
}
END { print "mawk NR line count=" NR " our line count=" lcount " lines in pippo"}
