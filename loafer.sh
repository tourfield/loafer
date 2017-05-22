#!/bin/bash

####################################################
####################################################
##
## Analyzer SELINUX log to Create solutions for 
## avc denied.
## Author : Geary Young 
## Date : 2016.10.26
##
####################################################
####################################################

logPath=
sepolicy=
tmpdir=
tmpfile=
services=
function createTmpDir(){
	if [ -d tmpdir ];then
		rm -rf tmpdir
	fi
	
	if [ -d sepolicy ];then
		rm -rf sepolicy
	fi

	mkdir -p sepolicy
	mkdir -p tmpdir
	tmpdir="tmpdir"
	tmpfile="tmpdir/file"
	sepolicy="sepolicy"
}

function cleanTmpFiles(){
	rm -rf tmpdir
}

function dgprint(){
	echo ""
	echo "$@"
	echo ""
}

function searchByChar(){
		str=$1
		split=$2
		i=$3
		result=
		num=`echo $str | grep -o "$split" | wc -l`
		if [ $i -eq -1 ];then
				let num+=1
				result=`echo $str | awk -F "$split" '{ print $'$num' }'`
		else
			if [ $i -le $num ];then
					result=`echo $str | awk -F "$split" '{ print $'$i' }'`
			fi
		fi
		echo "$result"
}

function addInitDomain(){
		srvPath=$1
		fword=`echo $srvPath | awk -F "/" '{print $1}'`
		allow=$2
		if [ "x$srvPath" == "x" -o  "x$fword" != "x" ];then
				echo "Service's entity path is Error or the path isn't Absolute path! "
				return -1
		fi
		srv=`searchByChar $srvPath '/' -1`
		if [ "x$srv" == "x" ];then
				echo "service name is null!"
				return -1
		fi

		mkdir -p $sepolicy/$srv
		
		echo -e "## Please copy the follow codes into \"init.rc\" ,and you should make sure the path is correct !\n"\
						"\nservice $srv $srvPath" >>  $sepolicy/$srv/init.rc
		
		echo -e "## Please copy the follow sepolicies into \"$srv.te\"\n"\
						"\ntype $srv, domain;"\
						"\ntype ${srv}_exec, exec_type, file_type;\n"\
						"\ninit_daemon_domain($srv)\n"\ >> $sepolicy/$srv/$srv.te
		if [ "x$allow" == "x" ];then
				echo -e "\n## You should added the follow codes yourself,or get the running log again,"\
								"\n## after added ahead codes."\
								"\n# Ex: allow $srv ......;\n" >> $sepolicy/$srv/$srv.te
		else
				echo -e "\n$allow" >> $sepolicy/$srv/$srv.te
		fi
		echo -e "\n## Please copy the follow codes into \"file_contexts\" ,and you should make sure the path is correct !\n"\
						"\n$srvPath u:object_r:${srv}_exec:s0" >> $sepolicy/$srv/file_contexts
}

function addSbinDomain(){
		srv=$1
		if [ "x$srv" == "x" ];then
				echo "service name is null!"
				return -1
		fi

		mkdir -p $sepolicy/$srv
		
		echo -e "## Please copy the follow codes into \"init.rc\"\n"\
						"\nservice $srv /sbin/$srv"\
						"\n\tcritical    ## As you needed"\
						"\n\tseclabel u:r:$srv:s0"\
						"\n\toneshot   ## As you needed" >>  $sepolicy/$srv/init.rc
		
		echo -e "## Please copy the follow sepolicies into \"$srv.te\"\n"\
						"\ntype $srv, domain;"\
						"\n## You should added the follow codes yourself,or get the running log again,"\
						"\n## after added ahead codes."\
						"\n# Ex: allow $srv ......;\n" >> $sepolicy/$srv/$srv.te

		echo -e "## Please copy the follow sepolicies into \"init.te\"\n"\
						"\ndomain_trans(init, rootfs, $srv)" >> $sepolicy/$srv/init.te
}

function echoHelpInfo(){
		echo "Using this script to analyzer android \"avc denied\" problems,"
		echo "but I'm not sure all of the sollutions are correct, if you find"
		echo " a bug or other wrong things,please report to me[ywzj0306@163.com]."
		echo "THANK YOU !!"
		echo "	Enjoy your android programming!!"
		echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
		dgprint -e "\t-f <logfile0/logdir> [logfile1] ...  AVC denied log dir or files\n\b" \
									"\t-s <exeFilePath> [exeFilePath] ... Normal Services you want to add\n"\
									"\t-i <exeFilePath> [exeFilePath] ... Init Services you want to add in init.rc except sbin files\n"\
									"\t-b <service0> [service1] ... Init Services you want to add in init.rc which is sbin files\n"\
									"\t-h Show help info\n"\
									"\thelp Show help info\n"\
									"\t--help Show help info\n"
		echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

function analyzerArgs(){
		
		argsNum=$#
		if [ $argsNum -le 1 ];then
			echoHelpInfo
		fi
		for((index=1;index<$argsNum;index++))
		do
				arg=${!index}
				case $arg in
						"-f") 
						    let index+=1
								findex=$index
								for((;findex<=$argsNum;findex++))
								do
										nextArg=${!findex}
										if [ `echo "${nextArg:0:1}"` == "-" ];then
												index=$(($findex-1))
												break
										fi
										
										if [ -f $nextArg -o -d $nextArg ];then
												logPath=$nextArg
												echo "analyzer \"$logPath\" .... "
												analyzerAVCDenied $logPath
										else
												echo "The file or dir \"$nextArg\" isn't exist!!"
										fi
								done
								
								;;
						"-s")
								echo "Add new Service sepolicy .... "
						    let index+=1
								findex=$index
								for((;findex<=$argsNum;findex++))
								do
										nextArg=${!findex}
										# echo $nextArg
										if [ `echo "${nextArg:0:1}"` == "-" ];then
												index=$(($findex-1))
												break
										fi
										addNewService $nextArg
								done
								;;
						"-i")
								echo "Add init domain sepolicy ...."
						    let index+=1
								findex=$index
								for((;findex<=$argsNum;findex++))
								do
										nextArg=${!findex}
										#echo $nextArg
										if [ `echo "${nextArg:0:1}"` == "-" ];then
												index=$(($findex-1))
												break
										fi
										addInitDomain $nextArg
								done
								;;
						"-b")
								echo "Add sbin domain sepolicy ...."
						    let index+=1
								findex=$index
								for((;findex<=$argsNum;findex++))
								do
										nextArg=${!findex}
										#echo $nextArg
										if [ `echo "${nextArg:0:1}"` == "-" ];then
												index=$(($findex-1))
												break
										fi
										addSbinDomain $nextArg
								done
								;;
						"--help")
								echoHelpInfo
								;;
						"-h")
								echoHelpInfo
								;;
						"help")
								echoHelpInfo
								;;
				esac
		done
}

function getDeniedServices(){
	services=`grep "avc: *denied" $1 | gawk -F "scontext=u:r:" '{print $2}' | awk -F ":" '{print $1}' | sort -u`
}

function serviceDeniedLog(){
		for service in $services
		do 
				comms=
				curcomm=
				svrLogFile=${tmpfile}-${service}-log
				echo -e `grep "avc: *denied" $1 | gawk -F "avc: *" '{print $2}' | grep "scontext=u:r:${service}:s0"` > $svrLogFile
				sed -i "s/permissive=[0,1]/\n/g" $svrLogFile
				gawk -F "(comm=)|\"" '{print $3 $0}' $svrLogFile | sort | uniq > $svrLogFile-1

				while read line
				do
						pid=`echo $line | gawk -F "pid=" '{print $2}' | awk '{print $1}'`
						comm=`echo $line | gawk -F "comm=" '{print $2}' | awk -F "\"" '{print $2}'`
						op=`echo $line | awk -F "{|}" '{print $2}'`
						sc=`echo $line | gawk -F "scontext=" '{print $2}' | gawk -F ":" '{print $3}'` 
						tc=`echo $line | gawk -F "tcontext=" '{print $2}' | gawk -F ":" '{print $3}'`
						tclass=`echo $line | gawk -F "tclass=" '{print $2}'`
						
						case $sc in
								"init")
										comms=`grep "comm=" $svrLogFile-1 | gawk -F "comm=" '{print $2}' | awk -F "\"" '{print $2}' | sort | uniq`
										if [ $pid -eq 1 ];then
													echo "allow $sc $tc:$tclass $op;" >> ${tmpfile}-${service}-aw
										else
												if [ "$comm" != "init" ];then
														if [ "$curcomm" != "$comm" ];then
																addInitDomain /system/bin/$comm "## "
														fi
														curcomm=$comm
														echo "allow $sc $tc:$tclass $op;" >> ${tmpfile}-${comm}-aw
												fi
										fi
										;;
								*)
											rst=`echo ":${sc}:${tc}:${tclass}:${op}" | grep "::"`
											if [  "x$rst" == "x" ];then
													echo "allow $sc $tc:$tclass $op;" >> ${tmpfile}-${service}-aw
											fi
											;;
						esac
				done < $svrLogFile-1
				writeSepolicyIntoFile $service
				for cmm in $comms
				do
						if [ "$cmm" != "init" ];then
								writeSepolicyIntoFile $cmm
						fi
				done
		done
}

function writeSepolicyIntoFile(){
		srv=$1
		mkdir -p $sepolicy/$srv/
		grep "allow" ${tmpfile}-${srv}-aw | sort | uniq >> ${tmpfile}-${srv}-aw1
		tts=`grep "allow" ${tmpfile}-${srv}-aw1 | awk -F " |;" '{print $3}' | sort | uniq`
		echo -e "## Please copy this seploicies into \"$srv.te\" \n">> $sepolicy/$srv/$srv.te
		for tt in $tts
		do
				ops=`grep "allow" ${tmpfile}-${srv}-aw1 | gawk -F "($tt)|;" '{print $2}'| uniq`
				echo "allow"" "$srv" "$tt" { "$ops" };" >> $sepolicy/$srv/$srv.te
		done
}

function analyzerAVCDenied(){
		deniedLog=$1
		getDeniedServices $deniedLog
		serviceDeniedLog $deniedLog
}


createTmpDir
analyzerArgs $*
cleanTmpFiles
