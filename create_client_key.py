#!/usr/bin/python3

from dialog import Dialog
import subprocess as sp
import sys,os

from ssl_common import *


user_basename="user"
user_key=user_basename+key_suffix
user_crt=user_basename+crt_suffix
user_csr=user_basename+csr_suffix
user_p12=user_basename+p12_suffix


d=Dialog(dialog="dialog")


def create_key():
	code,username=d.inputbox("Enter your name/username")
	if code!=d.OK:
		sys.exit()
	subject=create_subject_line(username)
	sp.check_call(["openssl","genrsa","-out",user_key,KEYSIZE])
	sp.check_call(["openssl","req","-new","-key",user_key,"-out",username+csr_suffix,"-subj",subject])

def get_cert():
	csr=glob.glob("*"+csr_suffix)[0]
	shaproc=sp.Popen(["openssl","dgst","-sha1",csr],stdout=sp.PIPE)
	out,err=shaproc.communicate()
	sha1=str(out).partition("= ")[2][:-3]
	d.msgbox("A certificate signing request (csr) has been saved in \"{}\". Send this file (and only this file!) to the server administrator and tell him the following code through an authenticated channel (e.g. phone line, meeting in person etc.). It is NOT necessary to keep this code a secret, it is only important that the admin will know it is definitely yours. After you received a certificate from your administrator, continue with the second step (export).\nThe code reads:\n\n{}".format(csr,sha1),width=60,height=20)

def export_key():
	crts=glob.glob("*"+crt_suffix)
	if len(crts)!=1:
		d.msgbox("This step assumes you already got a client certificate from your administrator. The certificate was not found in this directory. Please make sure you copied it to the right place.",width=40,height=10)
		return
	username=crts[0][:-len(crt_suffix)]
	d.msgbox("You will now prompted for the passphrase which is used to decrypt the key using the browser. You will have to enter this key every time you unlock/authenticate.",width=60)
	sp.check_call(["openssl","pkcs12","-export","-clcerts","-in",username+crt_suffix,"-inkey",username+key_suffix,"-out",username+p12_suffix])

def cleanup():
	if d.yesno("You should only do this when you have exported your key and made sure it works. After this step, you have to redo every single step again, if something goes wrong! Are you sure you wish to continue?",width=40,height=10)!=d.OK:
		return
	sp.check_call(["shred","*"+key_suffix])



while True:
	code,tag=d.menu("Main menu",choices=[("create","Step 1: Create a new key"),("cert","Step 2: Get a certificate"),("export","Step 3: Export the key to your browser"),("cleanup","Step 4: Overwrite temporary key file"),("exit","Exit")])
	if code!=d.OK:
		sys.exit()

	{"create":create_key,"cert":get_cert,"export":export_key,"cleanup":cleanup,"exit":lambda: sys.exit()}[tag]()
