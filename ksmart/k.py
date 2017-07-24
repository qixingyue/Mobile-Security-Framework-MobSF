#coding=utf-8

import os
import util
from log import out as Logout
from cert_analysis import ( get_hardcoded_cert_keystore, cert_info)
from manifest_analysis import ( manifest_data, manifest_analysis, get_manifest)
from binary_analysis import ( elf_analysis, res_analysis) 
from converter import ( dex_2_jar, dex_2_smali, jar_2_java )

tools_dir = 'tools/'

def static_check_android(apkfile):
	app_dic = {}
	uniq = util.filemd5(apkfile)
	
	extract_dir = "extract/" + uniq
	os.system("mkdir -p extract/%s/" % (uniq) )
	app_dic['size'] = str(util.FileSize(apkfile)) + 'MB'
	app_dic['sha1'] , app_dic['sha256'] = util.HashGen(apkfile)
	app_dic['files'] = util.Unzip(apkfile,extract_dir)
	app_dic['cert'] = get_hardcoded_cert_keystore(app_dic['files'])

	app_dic['parsed_xml'] = get_manifest(extract_dir,tools_dir,'',True)
	app_dic['mani_dic'] = manifest_data(app_dic['parsed_xml'])
	app_dic['mani_dic_2'] = manifest_analysis(app_dic['parsed_xml'],app_dic['mani_dic'])


	app_dic['cert_info'] = cert_info(extract_dir,tools_dir)
	app_dic['res_info'] = res_analysis(extract_dir,"apk")
	app_dic['elf_info'] = elf_analysis(extract_dir,"apk")



	for k in app_dic:
	 	if k != 'files':
	 		print k , "  --  " , app_dic[k]



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
	print ""
	Logout("info","begin %s" % (f))
	static_check_android("apk/%s" % (f))
	Logout("info","end %s" % (f))
	print ""
	break

