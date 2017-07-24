#coding=utf-8

import os
import util
from cert_analysis import ( get_hardcoded_cert_keystore, cert_info)
from manifest_analysis import ( manifest_data, manifest_analysis, get_manifest)

tools_dir = 'tools/'

def static_check_android(apkfile):
	app_dic = {}
	uniq = util.filemd5(apkfile)
	app_dic['md5'] = uniq
	extract_dir = "extract/" + uniq
	os.system("mkdir -p extract/%s/" % (uniq) )
	app_dic['size'] = str(util.FileSize(apkfile)) + 'MB'
	app_dic['sha1'] , app_dic['sha256'] = util.HashGen(apkfile)
	app_dic['files'] = util.Unzip(apkfile,extract_dir)
	app_dic['cert'] = get_hardcoded_cert_keystore(app_dic['files'])
	app_dic['parsed_xml'] = get_manifest(extract_dir,tools_dir,'',True)

	for k in app_dic:
		print k , "  --  " , app_dic[k]


	

#  
#  		app_dic['mani'] = '../ManifestView/?md5=' + \
#  			app_dic['md5'] + '&type=apk&bin=1'
#  			man_data_dic = manifest_data(app_dic['parsed_xml'])
#  
#  			man_an_dic = manifest_analysis(
#  					app_dic['parsed_xml'],
#  					man_data_dic
#  					)
#  			bin_an_buff = []
#  			bin_an_buff += elf_analysis(
#  					app_dic['app_dir'],
#  					"apk"
#  					)
#  			bin_an_buff += res_analysis(
#  					app_dic['app_dir'],
#  					"apk"
#  					)
#  			cert_dic = cert_info(
#  					app_dic['app_dir'], app_dic['tools_dir'])
#  			dex_2_jar(app_dic['app_path'], app_dic[
#  					'app_dir'], app_dic['tools_dir'])
#  			dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])
#  			jar_2_java(app_dic['app_dir'], app_dic['tools_dir'])
#  			code_an_dic = code_analysis(
#  					app_dic['app_dir'],
#  					app_dic['md5'],
#  					man_an_dic['permissons'],
#  					"apk"
#  					)
#  			print "\n[INFO] Generating Java and Smali Downloads"
#  			gen_downloads(app_dic['app_dir'], app_dic['md5'])
#  
#  # Get the strings
#  			app_dic['strings'] = strings(
#  					app_dic['app_file'],
#  					app_dic['app_dir'],
#  					app_dic['tools_dir']
#  					)
#  			app_dic['zipped'] = '&type=apk'
#  
#  

for path,f in util.wind_file("apk"):
	print "begin %s " %  (f)
	static_check_android("apk/%s" % (f))
