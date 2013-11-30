import json,glob

KEYSIZE="1024"
key_suffix=".key"
crt_suffix=".crt"
csr_suffix=".csr"
p12_suffix=".p12"


def create_subject_line(CN):
	with open("config.json","r") as f:
		params=json.load(f)
	params["CN"]=CN
	print(params)
	return "/C={country}/ST={province}/L={locality}/O={organization}/OU={organization_unit}/CN={CN}".format(**params)

def find_files(fil):
	return glob.glob(fil)
