# /bin/bash
pip2 install simplejson
pip2 install psutil
pip2 install httplib
pip2 install mimetypes
path=`pwd`
command1="alias emg='python "
command2="alias whois='python "
command3="alias vt='python "
files1="/emergency.py'"
files2="/mywhois.py'"
files3="/virustotal.py'"
var1=$command1$path$files1
var2=$command2$path$files2
var3=$command3$path$files3
echo $var1 >> /root/.bash_profile
echo $var2 >> /root/.bash_profile
echo $var3 >> /root/.bash_profile
source /root/.bash_profile
