import argparse
import json
import sys
import os
import pwd

if __name__ == '__main__':
 
    parser = argparse.ArgumentParser(description='Add Users from JSON file')
    parser.add_argument('-u','--users', metavar='<file name>', help='user list in JSON', default=None)
    parser.add_argument('-o','--outfile', metavar='<file name>', help='list of added users', default=None)
    
    args = parser.parse_args()
    file_name = args.users
    outfile_name = args.outfile

    user_list = []
    
    if file_name == None:
        print 'user list is not defined; use --help for more info'
        sys.exit(-1)
    else:
        if not os.path.isfile(file_name):
            print('"{}" does not exist'.format(file_name), sys.stderr)
            sys.exit(-1)
        else:            
            with open(file_name, 'rb') as fn:
               user_list = json.load(fn)
  
    existed_users =  [x[0] for x in pwd.getpwall()]
    added_users = [] 
    for user in user_list:
        if user["username"] in existed_users:
            print user["username"]+' already exists'
        else:
            print 'Added ' + user["username"]
            added_users.append(user["username"])
            os.system("sudo useradd "+user["username"])
            os.system("echo "+user["username"]+":"+user["passwd"] + " | sudo chpasswd ")
    
    # print(added_users)
    if outfile_name != None:
         if not os.path.isfile(outfile_name):
            print('"{}" does not exist'.format(outfile_name), sys.stderr)
         else:
            with open(outfile_name, 'a') as ofn:
              for user in added_users:
                ofn.write(user)
                ofn.write("\n")
