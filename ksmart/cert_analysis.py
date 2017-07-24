# -*- coding: utf_8 -*-

import subprocess
import re
import os

def get_hardcoded_cert_keystore(files):
	try:
		dat = ''
		certz = ''
		key_store = ''
		for file_name in files:
			ext = file_name.split('.')[-1]
			if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
				certz += file_name
			if re.search("jks|bks", ext):
				key_store += file_name
		if len(certz) > 1:
			dat += 'cert in file: %s ' %(certz)
		if len(key_store) > 1:
		    dat += "key file in %s " % ( key_store )
		return dat
	except:
		print "[ERROR] Getting Hardcoded Certificates/Keystores"



def cert_info(app_dir, tools_dir):
	try:
		cert = os.path.join(app_dir, 'META-INF/')
		cp_path = tools_dir + 'CertPrint.jar'
		files = [f for f in os.listdir(cert) if os.path.isfile(os.path.join(cert, f))]
		certfile = None
		dat = ''
		if "CERT.RSA" in files:
			certfile = os.path.join(cert, "CERT.RSA")
		else:
			for file_name in files:
				if file_name.lower().endswith(".rsa"):
					certfile = os.path.join(cert, file_name)
				elif file_name.lower().endswith(".dsa"):
					certfile = os.path.join(cert, file_name)
		if certfile:
			args = [ 'java', '-jar', cp_path, certfile]
			issued = 'good'
			dat = subprocess.check_output(args)
			unicode_output = unicode(dat, encoding="utf-8", errors="replace")
			dat = unicode_output
		else:
			dat = 'No Code Signing Certificate Found!'
			issued = 'missing'
		if re.findall(r"Issuer: CN=Android Debug|Subject: CN=Android Debug", dat):
			issued = 'bad'
		if re.findall(r"\[SHA1withRSA\]",dat):
			issued = 'bad hash'
		cert_dic = {
		    'cert_info': dat,
		    'issued': issued
		}
		return cert_dic
	except:
		print  "[ERROR] Reading Code Signing Certificate"
