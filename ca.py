#!/usr/bin/python3
from dialog import Dialog
import subprocess as sp
import os,sys,pickle

from ssl_common import *

d=Dialog(dialog="dialog")

script_dir=os.path.dirname(sys.argv[0])+"/"
root_ca="root_ca"
cert_index="cert_index"
crl_number="crl_number"
serial="serial"
crl_file="crl.crl"

root_ca_key=root_ca+key_suffix
root_ca_crt=root_ca+crt_suffix
root_ca_csr=root_ca+csr_suffix

user_cert_folder="usercerts/"

configfile="openssl.cnf"


defaultparams={}

def save_config():
	d.msgbox("the following data will be saved in your configuration file")
	cdp=None
	if d.yesno("do you have a CRL distribution point?")==d.OK:
		cdp=d.inputbox("location of CDP")
	global defaultparams
	defaultparams={
		"root_ca_crt":root_ca_crt,
		"root_ca_key":root_ca_key,
		"days_cert":365,
		"CDP":"",
		"country":d.inputbox("2-digit country code (required)",init="DE")[1],
		"province":d.inputbox("province (optional)")[1],
		"locality":d.inputbox("locality (optional)")[1],
		"organization":d.inputbox("organization (required)",init="ssltest")[1],
		"organization_unit":d.inputbox("subunit (optional)")[1],
		"cert_index":cert_index,
		"crl_number":crl_number,
		"serial":serial
	}
	if not cdp is None:
		params["CDP"]="crlDistributionPoints = {}".format(cdp)
		#URI:http://certs.example.com/example_root.crl
	config_template=None
	with open(script_dir+"openssl.cnf.template","r") as f:
		config_template=f.read()

	config=config_template.format(**defaultparams)
	with open(configfile,"w") as f:
		f.write(config)
	
	with open("pyconfig","wb") as f:
		pickle.dump(defaultparams,f)
	
	params={key: defaultparams[key] for key in ["country","province","locality","organization","organization_unit"]}
	with open("config.json","w") as f:
		json.dump(params,f)
	
	os.mkdir(user_cert_folder)


def get_int(text,default=""):
	while True:
		try:
			code,answer=d.inputbox(text,init=default)
			if code==d.DIALOG_OK:
				result=int(answer)
				return result
		except:
			pass#d.msgbox("you have to enter a number")

def new_ca():
	save_config()
	days=get_int("how long should the CA key be valid (in days)?",default="3650")

	# generate keypair
	if True:
		d.infobox("creating keypair for CA...")
		sp.check_call(["openssl","genrsa","-out",root_ca_key,"4096"], stdout=open(os.devnull, 'wb'),stderr=sp.STDOUT)

	# create signing request
	if True:
		d.infobox("signing CA key...")
		sp.check_call(["openssl","req","-new","-days",str(days),"-x509","-key",root_ca_key,"-out",root_ca_crt,"-config",configfile,"-subj",create_subject_line("ROOT CA")])
	
	# create index files
	sp.check_call(["touch","index"])
	with open(cert_index,"w") as f:
		pass
	with open(serial,"w") as f:
		f.write("0001")
	with open(crl_number,"w") as f:
		f.write("0001")
	
def new_cert():
	code,name=d.inputbox("FQDN for certificate")
	if code!=d.OK:
		return

	sp.check_call(["openssl","req","-config",configfile,"-nodes","-new","-keyout",name+key_suffix,"-out",name+csr_suffix,"-subj",create_subject_line(name),"-extensions","extensions_server"])
	sp.check_call(["openssl","ca","-preserveDN","-config",configfile,"-in",name+csr_suffix,"-keyfile",root_ca_key,"-out",name+crt_suffix])
	
def get_next_filenumber(filename):
	i=0
	while os.path.isfile(filename.format(i)):
		i+=1
	return i

def sign_cert():
	requests=find_files("*.csr")
	if len(requests)==0:
		d.msgbox("No CSRs found!")
		return

	print(requests)
	usernames=[]
	for r in requests:
		shaproc=sp.Popen(["openssl","dgst","-sha1",r],stdout=sp.PIPE)
		out,err=shaproc.communicate()
		sha1=str(out).partition("= ")[2][:-3]
		usernames.append((r[:-4],sha1))
	print(usernames)
	code,username=d.menu("Choose a CSR",choices=usernames,width=60)
	if code==d.OK:
		do_sign_cert(username)

def do_sign_cert(username):
	folder=user_cert_folder+username+"/"
	crt_basename=folder+"{}"+crt_suffix
	if os.path.isdir(folder):
		i=get_next_filenumber(crt_basename)
	else:
		os.mkdir(folder)
		i=0
	crtname=crt_basename.format(i)
	sp.check_call(["openssl","ca","-preserveDN","-config",configfile,"-in",username+csr_suffix,"-keyfile",root_ca_key,"-out",crtname])
	return crtname

def revoke_user():
	userlist=find_files(user_cert_folder+"*")
	usernames=[]
	for u in userlist:
		us=u[len(user_cert_folder):]
		usernames.append((us,us))
	code,username=d.menu("Username to revoke",choices=usernames)
	if code!=d.OK:
		return

	folder=user_cert_folder+username+"/"
	certlist=find_files(folder+"*"+crt_suffix)
	if len(certlist)==0:
		d.msgbox("No certificates found for user "+username)
		return
	if len(certlist)==1:
		certfile=certlist[0]
	else:
		choicelist=[]
		for c in certlist:
			cs=c[len(folder):]
			choicelist.append((cs,cs))
		code,certname=d.menu("There are multiple certificates for this user. Which one do you want to revoke?",choices=choicelist)
		if code != d.OK:
			return
		certfile=folder+certname
	code,reason=d.menu("Why should this certificate be revoked?",choices=[("unspecified","Not specified"),("keyCompromise","Key has been compromised"),("affiliationChanged","Affiliation has changed (e.g. end of employment/revocation of user access in general)"),("superseded","A new key will be used from now on")])
	sp.check_call(["openssl","ca","-config",configfile,"-crl_reason",reason,"-revoke",certfile])

def create_crl():
	sp.check_call(["openssl","ca","-config",configfile,"-gencrl","-out",crl_file])
	if os.path.isfile("./publish_crl"):
		sp.check_call(["./publish_crl"])

def new_cc():
	code,username=d.inputbox("Enter name/username")
	if code!=d.OK:
		sys.exit()
	subject=create_subject_line(username)
	sp.check_call(["openssl","genrsa","-out",username+key_suffix,KEYSIZE])
	sp.check_call(["openssl","req","-config",configfile,"-new","-key",username+key_suffix,"-out",username+csr_suffix,"-subj",subject,"-extensions","extensions_client"])
	
	crtname=do_sign_cert(username)
	
	sp.check_call(["openssl","pkcs12","-export","-clcerts","-in",crtname,"-inkey",username+key_suffix,"-out",username+p12_suffix])
	sp.check_call(["rm",username+key_suffix])
	sp.check_call(["rm",username+csr_suffix])

# MAIN
try:
	with open("pyconfig","rb") as f:
		defaultparams=pickle.load(f)
except:
	pass
while True:
	calls={"new":new_ca,"new_cert":new_cert,"sign":sign_cert,"revoke":revoke_user,"crl":create_crl,"new_cc":new_cc}
	code,tag=d.menu("Main menu",choices=[
		("new",		"create new CA config"),
		("new_cert",	"create a new server key/cert"),
		("sign",	"sign certificate using CA"),
		("new_cc",	"create new client certificate using CA (use only if server and client are identical)"),
		("revoke",	"revoke user certificate"),
		("crl",		"create new certificate revocation list (CRL)")
		])

	if code==d.DIALOG_OK:
		calls[tag]()
	else:
		break
