#!/bin/bash
# Michael Rieder 19.05.2020
# Script search the keychain for 802.1X Certificates and delete duplicated certs.


# Clean up computer certs
ComputerName=$(hostname)

cfgPath="/tmp/certchecker"
cfgAllCerts="AllCerts.cfg"
cfgSingleFile="SingleCert-"
declare -a certsArrayDate
declare -a certsArrayHash
mkdir -p ${cfgPath}
certscounter=1


countCerts=$(security find-certificate -a  -c "${ComputerName}" | grep "subj" | wc -l |  xargs)

if [ $countCerts -eq 1 ]; then
    	echo "No cert exist exiting.."
    	exit 0
fi 

if [ $countCerts -eq 1 ]; then
    	echo "only one cert exist exiting.."
    	exit 0
fi 

if [ $countCerts -ge 2  ]; then
    	echo "More then one cert exist"
fi 





AllCerts=$(security find-certificate -aZ -p -c "${ComputerName}" >${cfgPath}/${cfgAllCerts})
# split all certs to single files
split -p "SHA-256 hash: " ${cfgPath}/${cfgAllCerts} ${cfgPath}/${cfgSingleFile}

for filename in ${cfgPath}/${cfgSingleFile}*; do
    [ -e "$filename" ] || continue
  # grep SHA265 hash from single file
  shaHash=$(grep -m1 "" ${filename}| awk -F ": " {'print $2'})
    
  # remove the first two rows of the file and save it as a new file 
  tail -n +3 ${filename} > ${cfgPath}/${shaHash}
  
  # get the expired date from the certfile   
	longCertDate=$(openssl x509 -enddate -noout -in ${cfgPath}/${shaHash} |  awk -F "=" {'print $2'} )
	# convert the date to unixtimestamp
  UnixCertdate=$(LANG=en_us_88591;  date -juf '%b %d %T %Y %Z' "$longCertDate" +%s)
  # add values to array 
	certsArrayHash[${certscounter}]=$shaHash
	certsArrayDate[${certscounter}]=$UnixCertdate

certscounter=$((certscounter+1)) # used for the arrays
done

# return the timestamp from the Certificate with the longest validity 
longestValid=$(echo ${certsArrayDate[*]}| tr " " "\n" | sort -n | tr "\n" " " | awk -F " " {'print $1'})

for Unixtimestamp in "${certsArrayDate[@]}"
do
   a=$((a+1))
   #echo "$Unixtimestamp -> ${certsArrayHash[$a]}"

   # we delete old certificates and exlude the Certificate with the longest validity
   if [ $Unixtimestamp != $longestValid ]; 
   then
   	 /usr/bin/security delete-certificate -Z $hash ${certsArrayHash[$a]}
   		echo "Delete Certificate with hash -> ${certsArrayHash[$a]}"
   fi 

done
