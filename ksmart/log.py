#coding=utf-8

import datetime

class Simple:

	def log(self,type,message):
		formate = '%Y-%m-%d %H:%M:%S.%f'
		n_date = datetime.datetime.now()
		now = n_date.strftime(formate)
		message = "%s [%s] %s" % (now,type,message)
		self.out(type,message)

	def out(self,type,message):
		print message


def out(type,message):
	instance = Simple()
	instance.log(type,message)


if __name__ == "__main__":
	Simple().log("SEC","hello world, i am message")

