#coding=utf-8

import os
import util
import zipfile
from log import out as Logout

from cert_analysis import ( get_hardcoded_cert_keystore, cert_info)
from manifest_analysis import ( manifest_data, manifest_analysis, get_manifest)
from binary_analysis import ( elf_analysis, res_analysis) 
from converter import ( dex_2_jar, dex_2_smali, jar_2_java )
from code_analysis import code_analysis 

tools_dir = 'tools/'
download_dir = "download/"

def zipdir(path, zip_file):
    """Zip a directory."""
    try:
        print "[INFO] Zipping"
        # pylint: disable=unused-variable
        # Needed by os.walk
        for root, _sub_dir, files in os.walk(path):
            for file_name in files:
                zip_file.write(os.path.join(root, file_name))
    except:
        PrintException("[ERROR] Zipping")

def gen_downloads(app_dir, md5):
    try:
        print "[INFO] Generating Downloads"
        # For Java
        directory = os.path.join(app_dir, 'java_source/')
        dwd_dir = os.path.join(download_dir, md5 + '-java.zip')
        zipf = zipfile.ZipFile(dwd_dir, 'w')
        zipdir(directory, zipf)
        zipf.close()
        # For Smali
        directory = os.path.join(app_dir, 'smali_source/')
        dwd_dir = os.path.join(download_dir, md5 + '-smali.zip')
        zipf = zipfile.ZipFile(dwd_dir, 'w')
        zipdir(directory, zipf)
        zipf.close()
    except Exception,e:
        print "[ERROR] Generating Downloads" , e



def static_check_android(apkfile):
	app_dic = {}
	uniq = util.filemd5(apkfile)
	
	extract_dir = "extract/" + uniq
	extract_dir_ = "extract/" + uniq + "/"
	os.system("mkdir -p extract/%s/" % (uniq) )
	app_dic['size'] = str(util.FileSize(apkfile)) + 'MB'
	app_dic['sha1'] , app_dic['sha256'] = util.HashGen(apkfile)
	app_dic['files'] = util.Unzip(apkfile,extract_dir)
	app_dic['cert'] = get_hardcoded_cert_keystore(app_dic['files'])

	app_dic['parsed_xml'] = get_manifest(extract_dir,tools_dir,'',True)
	app_dic['mani_dic'] = manifest_data(app_dic['parsed_xml'])
	manifest_dic = manifest_analysis(app_dic['parsed_xml'],app_dic['mani_dic'])
	app_dic['mani_dic_2'] = manifest_dic


	app_dic['cert_info'] = cert_info(extract_dir,tools_dir)
	app_dic['res_info'] = res_analysis(extract_dir,"apk")
	app_dic['elf_info'] = elf_analysis(extract_dir,"apk")

	dex_2_jar(extract_dir_ ,extract_dir_ ,tools_dir)
	dex_2_smali(extract_dir_,tools_dir)
	jar_2_java(extract_dir_,tools_dir)

	if 'permissons' not in manifest_dic :
		manifest_dic['permissons']	 = []
	code_an_dic = code_analysis(extract_dir_,uniq,manifest_dic['permissons'],'apk')
	gen_downloads(extract_dir_, uniq)

for path,f in util.wind_file("apk"):
	print ""
	Logout("info","begin %s" % (f))
	static_check_android("apk/%s" % (f))
	Logout("info","end %s" % (f))
	print ""

