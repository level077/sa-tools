#!/usr/bin/perl
 
# First written by orczhou.com orchzou@gmail.com
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; version 2 of the License.
 
#  How faster it is:
#    $ls -lh backup.sql.gz 
#     -rw-r--r-- 1 mysql dba 14G Nov 21 04:49 backup.sql.gz
#    $date && gunzip -c backup.sql.gz|./tbdba-restore-mysqldump.pl -s monitor_general -t monitor_host_info && date
#    Fri Nov 25 14:35:06 CST 2011
#    Fri Nov 25 14:46:49 CST 2011
#    (the unzip of backup.sql.gz is 88G)
#  
#  About it :
#    Restore one single table from a Huge mysqldump file VERY QUICKLY!
#    The backup file of mysqldump is sometimes very huge, if you wanna restore one 
#    or two table from the file, there is no easy way to do this. There some way we 
#    try:
#      1. split/csplit the file
#      2. restore some tables.
#    This script will get a tiny improvement, all you need do is :
#      tbdba-restore-mysqldump.pl -t process,user -s monitor -f backup.sql
#
#  Feature:
#    1. When all the table has been found and -s is specified, exit immediately.
#       So it's quicker; If the table you wanna is at the header of the sql file,
#       It will be very quick. That's why i use this a lot.
#    2. Every result sql file will hold the dump header, something like this:
#         /*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
#         /*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
#         /*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
#         /*!40101 SET NAMES utf8 */;
#         /*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
#         /*!40103 SET TIME_ZONE='+00:00' */;
#    3. With -a(--all-tables),you can get all the sql file. So this script also can 
#       split the dump file(It will be very useful for parallel restore).
#  
#  Tips:
#    1. If you only wanna dump ONE table: with -s will be much quicker.
#    2. At the end of every dump file, There will be a string like this:
#         -- Table Finished
#       This can be help you to tell whether job on this table finished(If 
#       finished,maybe you can restore it).
#
#  To Do:
#    [Done]1. Add parameter --target-dir to specify the target dir where dump file put
#    [Done]2. With -d(--debug),script will output some infomation of processing
#    3. Write the documentation with POD
#    [Done]4. add a parameter -i|ignore-use to igone the 'use db', in case you wanna retore table to 
#       another database.
#
 
use strict;
use File::stat;     # To get the file stat
use Time::localtime;
use Socket;
use Getopt::Long;
 
sub print_usage () {
  my $text = <<EOF;
 NAME:
    tbdba-restore-mysqldump.pl

 SYNTAX:
    Sample:
       1. Get table "process" from backup.sql
          tbdba-restore-mysqldump.pl -t process -f backup.sql
       2. Get table "process" of database "monitor" from backup.sql
          tbdba-restore-mysqldump.pl -t process -s monitor -f backup.sql
       3. Get table "process","users" of database "monitor" from backup.sql
          tbdba-restore-mysqldump.pl -t process,user -s monitor -f backup.sql
       4. Get sql files of some tables from a STDIN 
          gunzip -c backup.sql.gz|tbdba-restore-mysqldump.pl -t process,user -s monitor
       5. Get all the tables's sql files in schema 'monitor'
          gunzip -c backup.sql.gz|tbdba-restore-mysqldump.pl -s monitor --all-tables
       6. Get all the table sql files in the dump file 
          tbdba-restore-mysqldump.pl --all-tables -f backup.sql
          Get all the table sql files in *** DATABASE *** monitor 
          tbdba-restore-mysqldump.pl -s monitor --all-tables -f backup.sql
       7. With -d, more infomation of processing will be output
          date && gunzip -c /backdir/backup.sql.gz|tbdba-restore-mysqldump.pl -d -a && date
       8. With -i, "use db" will be ignore,This can help you import table to a different database. 
          tbdba-restore-mysqldump.pl -t process -s monitor -i
       9. Specify the output directory with -r|--target-dir
          tbdba-restore-mysqldump.pl --target-dir /opt/restore/ -t process -s monitor
          Here is "/opt/restore/". NOT "/opt/restore".

 FUNCTION:
    Restore some tables from the while mysqldump backup

 PARAMETER:
    -t|--table=s
        which table you wanna recovery
    -s|schema=s
        in which schema the table your wanna recovery
    -a|--all-tables
        get all the sql file
        With --schema, will get all the sql file just in the schema
        Without --schema, will get all the sql file in the dump file
        If this paramter is specified, -t will be ignore
    -f|sql-file=s
        from which mysqldump backup file 
    -i|--ignore-use
        from which mysqldump backup file 
    -r|--target-dir=s 
        where put the split files
    -d|--debug
        debug mode; more output will be there
    -h|--help
        You already know
EOF
 print STDERR $text;
 exit 0;
}
 
my %opt = (
);
 
GetOptions(\%opt,
    's|database=s',          # write result to database
    'f|sql-file=s',          # write result to database
    't|table=s',             # debug mode  
    'i|ignore-use+',         # ignore use `..` 
    'r|target-dir=s',        # where put the split files 
    'a|all-tables+',       # debug mode  
    'd|debug+',              # debug mode  
    'h|help+',               # debug mode  
    # order-by: 
    #   execs|Query_time:cnt
    #   ela_time|Query_time:sum 
) or print_usage();
 
print_usage() if $opt{h};
my $file = "";
my $db = "";
my @tabs ;
my $inTableFlag = 0;
my $inDBFlag = 0;
my $outputdir = "./";
my $outputdir = $opt{r} if $opt{r};
if( ! -d $outputdir){
  $outputdir = "./";
}
push(@tabs, $opt{t}) if $opt{t};
@tabs = split(/,/,join(',',@tabs));
my $tabcount = scalar(@tabs);
my $alltable = 0;
my $ignoreUse= 0;
$alltable = 1 if $opt{a};
$ignoreUse = 1 if $opt{i};
$db = $opt{s} if $opt{s};
$file = $opt{f} if $opt{f};
 
# if no db speicefied, all db is allowed
if($db eq ""){
  $inDBFlag = 1;
}
 
my $curtab = "";        # is dealing with this table
my $curdb = "";         # is dealing with this db
my $curCreatedbSQL="";  # the sql of create current database
my $headerFlag = 1;     # Whether is in the dump header
my $dumpHeader = "";
open (TABFILE, ">>STDERR"); 
my $ifh;
if($file eq ""){
  $ifh = *STDIN;
}else{
  open $ifh,"<", $file or die $!;
}
while(<$ifh>){
  if ($_ =~ /^-- Current Database\: `(.*)`/){
    print "$_" if $opt{d};
    $headerFlag = 0;
    $curdb = $1;
    if($db ne ""){
      if($inDBFlag == 1){
        # if $db ne "" and $inDBFlag == 1, A new database coming, now we quit
        exit 0;
      }
      $inDBFlag = 0;
      $inDBFlag=1  if $1 eq $db;
    }
  }elsif ($_ =~ /^-- Table structure for table `(.*)`/){
    print "$_" if $opt{d};
    $headerFlag = 0;
    if($db ne ""  && $tabcount == 0 && $alltable ==0){exit 0;}
    $curtab = $1;
    $inTableFlag = 0;
    print TABFILE "-- Table Finished";
    close (TABFILE);
    if($alltable == 1){
      $inTableFlag=1;
    }else{
      for(my $i=0;$i <= scalar(@tabs);$i++){
        if($tabs[$i] eq $1) {
          $inTableFlag=1;
          if($inTableFlag == 1 && $inDBFlag == 1){
            $tabcount = $tabcount - 1;
          }
        }
      }
    }
    if($inTableFlag == 1 && $inDBFlag == 1){
      open (TABFILE, ">>$outputdir"."split-$curdb"."-$curtab".".sql");
      print TABFILE "$dumpHeader";
      print TABFILE "\n\n";
      if( $ignoreUse != 1 ){
        print TABFILE $curCreatedbSQL;
      	print TABFILE "\n\n";
        print TABFILE "USE `$curdb`;\n\n";
      }
    }
  }elsif($_ =~ /^CREATE DATABASE.*;$/){
    print "$_" if $opt{d};
    $headerFlag = 0;
    $curCreatedbSQL = $_;
  }elsif($_ =~ /^USE .*;$/){
    # do nothing;
  }else{
    if($headerFlag == 1) {$dumpHeader .= $_};
    if($inTableFlag == 1 && $inDBFlag == 1) {print TABFILE $_;}
  }
}
