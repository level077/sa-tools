#!/bin/sh

while getopts h:p:t:f:i: OPTION
do
	case $OPTION in
		h)	host=$OPTARG
			shift 2
			OPTIND=1
			;;
		p)	port=$OPTARG
			shift 2
			OPTIND=1
			;;
		f)	config=$OPTARG
			shift 2
			OPTIND=1
			;;
		t)	target=$OPTARG
			shift 2
			OPTIND=1
			;;
		i)
			type=$OPTARG
			shift 2
			OPTIND=1
			;;
		*)	echo "usage: $0 -h hostname -p port -f defaults-file -t target-dir -i full"
			echo "	     -h: hostname"
			echo "	     -p: port"
			echo "	     -f: /path/to/my.cnf"
			echo "	     -t: target-dir"
			echo "	     -i: type,full backup or incremental backup.values:full or incre"
			exit
			;;
	esac
done

if [ -z "$host" ]
then
	echo "no hostname"
     	exit
fi

if [ -z "$port" ]
then
        echo "no port"
        exit
fi

if [ -z "$config" ]
then
        echo "no defaults file"
        exit
fi

if [ -z "$target" ]
then
        echo "no target dir"
        exit
fi

if [ -z "$target" ]
then
	echo "no type"
	exit
fi
#-----------------init-----------------
user="xxx"
passwd="xxxx"

[ ! -d "$target" ] && mkdir -p $target
dir_full="$target/full_back"
dir_incre="$target/increment_back"
error_log="$target/error.log"
backup_log="$target/backup.log"
process_log="$target/back_process.log"

func_fullbackup ()
{
	#-----------------mv when full_back exist-------
	[ -d ${dir_full}.bak ] && rm -rf ${dir_full}.bak >> $error_log 2>&1
	[ -d "$dir_full" ] && mv $dir_full ${dir_full}.bak >> $error_log 2>&1 

	#---------------start backup--------------------
	echo "`date`	$host:$port full_backup start" >> $backup_log 2>&1

	innobackupex --defaults-file=$config --user=$user --password=$passwd --host=$host --no-timestamp --slave-info $dir_full  >> $process_log 2>&1

	if [ $? -eq 0 ]
	then
		echo "`date`	$host:$port full_backup prepare" >> $backup_log 2>&1
		innobackupex --defaults-file=$config --apply-log --redo-only --use-memory 4G $dir_full >> $process_log 2>&1
		if [ $? -ne 0 ]
		then
			echo "`date`    $host:$port innobackupex full prepare error" 
			exit
		fi
		echo "`date`    $host:$port full_backup down" >> $backup_log 2>&1
	else
		echo "`date`    $host:$port full_backup error" >> $error_log 2>&1
		echo "`date`    $host:$port innobackupex full backup error" 
	fi
	cp $config $dir_full
}

func_increment ()
{
	#-----------------mv when increment_back exist-------
	[ -d ${dir_incre}.bak ] && rm -rf ${dir_incre}.bak >> $error_log 2>&1
        [ -d "$dir_incre" ] && mv $dir_incre ${dir_incre}.bak >> $error_log 2>&1

	#---------------start backup--------------------
	[ ! -f $dir_full/xtrabackup_checkpoints ] && echo "can't find $dir_full/xtrabackup_checkpoints" >> $error_log 2>&1
	last_lsn=`awk -F '[= ]' '/to_lsn/ {print $NF}' $dir_full/xtrabackup_checkpoints`
        echo "`date`    $host:$port incremental backup start,full backup last lsn:$last_lsn" >> $backup_log 2>&1
	
	innobackupex --defaults-file=$config --user=$user --password=$passwd --host=$host --no-timestamp --slave-info --incremental $dir_incre --incremental-lsn=$last_lsn  >> $process_log 2>&1

	if [ $? -eq 0 ]
	then
		echo "`date`    $host:$port incremental backup prepare,full backup last lsn:$last_lsn" >> $backup_log 2>&1
		innobackupex --defaults-file=$config --apply-log --redo-only --use-memory 4G $dir_full --incremental-dir=$dir_incre >> $process_log 2>&1
		if [ $? -ne 0 ]
		then
			 echo "`date`    $host:$port innobackupex incremental prepare error" 
			exit
		fi
		echo "`date`    $host:$port incremental backup down,full backup last lsn:$last_lsn" >> $backup_log 2>&1
	else
		echo "`date`    $host:$port incremental backup error,full backup last lsn:$last_lsn" >> $error_log 2>&1
		echo "`date`    $host:$port innobackupex incremental backup error" 
		exit
	fi
}

if [ $type == "full" ]
then
	func_fullbackup
elif [ $type == "incre" ]
then
	func_increment
fi

chown -R mysql:mysql $dir_full

echo "`date`	$host:$port innobackupex full backup successful" 
