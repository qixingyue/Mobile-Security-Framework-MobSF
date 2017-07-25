#coding=utf-8

import hashlib
import os
import zipfile

def PrintException(message,ex = ""):
	print "%s \n ex : \n %s\n"  % (message,ex)
	print "BAD"

def wind_file(root):
	for parent,dirnames,filenames in os.walk(root): 
		for f in filenames:
			yield (parent,f)

def file_trunks(name,size=8096):
	f = file(name,"rb")
	trunk = f.read(size)
	while True:
		yield trunk
		trunk = f.read(size)
		if not trunk :
			break

def FileSize(path):
    return round(float(os.path.getsize(path)) / (1024 * 1024), 2)

def filemd5(name):
	m = hashlib.md5()
	for trunk in file_trunks(name):
		m.update(trunk)
	return m.hexdigest()
	
def HashGen(name):
	try:
		sha1 = hashlib.sha1()
		sha256 = hashlib.sha256()
		for trunk in file_trunks(name):
			sha1.update(trunk)
			sha256.update(trunk)
		sha1val = sha1.hexdigest()
		sha256val = sha256.hexdigest()
		return sha1val, sha256val
	except:
		print "[ERROR] Generating Hashes"


def Unzip(apkfile, extractpath):
	try:
		files = []
		with zipfile.ZipFile(apkfile, "r") as z:
			for fileinfo in z.infolist():
				filename = fileinfo.filename
				if not isinstance(filename, unicode):
					filename = unicode(filename, encoding="utf-8", errors="replace")
				files.append(filename)
				z.extract(fileinfo, extractpath)
		return files
	except:
		print "[ERROR] unzip bad "
		exit()

		

def escape(text):
	return text
