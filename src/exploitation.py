import subprocess


def upload_exploit(repository,user,target):


	subprocess.run(['git','clone',repository], stdout=None) #Downloading exploit

	exploit = repository[repository.rfind("/")+1:] #Obtaining exploit folder name

	subprocess.run(['zip','-rq',exploit+'.zip',exploit],stdout=None) #Compressing exploit in order to send it through spc

	subprocess.run(['sudo','mv',exploit,'pentesting_files/exploits'], stdout=None) #Moving exploit to the exploits folder

	subprocess.run(['scp',exploit+'.zip',user+'@'+target+':~'], stdout=None) #Uploading exploit to the target

	subprocess.run(['ssh',user+'@'+target,'unzip','-q',exploit+'.zip'], stdout=None) #Connecting to the target and decompress it
	
	subprocess.run(['ssh',user+'@'+target,'rm',exploit+'.zip'], stdout=None) #Remove compressed exploit

	subprocess.run(['ssh',user+'@'+target], stdout=None) #Finally connects to the machine
