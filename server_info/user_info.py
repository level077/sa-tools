#!/usr/bin/python

import pwd
import spwd
import grp
import datetime

user = []

def serial_date_to_string(srl_no):
    new_date = datetime.datetime(1970,1,1,0,0) + datetime.timedelta(srl_no - 1)
    return new_date.strftime("%Y-%m-%d")

def get_user():
  for p in pwd.getpwall():
    tmp = {"user":p.pw_name,"uid":p.pw_uid,"group":grp.getgrgid(p.pw_gid).gr_name}
    if spwd.getspnam(p.pw_name).sp_expire == -1:
      tmp["expire"] = "Never"
    else:
      tmp["expire"] = serial_date_to_string(spwd.getspnam(p.pw_name).sp_expire)
    user.append(tmp)
  return user

if __name__ == "__main__":
  uinfo = get_user()
  print(uinfo)
