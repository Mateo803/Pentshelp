import requests

import mysql.connector


def retrieve_cve_data(cve):

	cve_data = requests.get("https://www.opencve.io/api/cve/"+cve,auth=requests.auth.HTTPBasicAuth('Mateo803','Pentshelp_passw0rd'))

	if cve_data.status_code != 200: #Check that the given url is correct

		
		return -1


	cve_data = cve_data.json() #Transform request into JSON format in order to retrieve information

	id = cve_data["id"]

	name = cve_data["summary"]

	cvss = [cve_data["cvss"]["v2"],cve_data["cvss"]["v3"]] #By default show only CVSS v3 (if doesn´t exist, show v2 instead)

	if cvss[1] is None:

		cvss = cvss[0]


	cwes = cve_data["cwes"] #Obtain the names of the differents cwes found in the vulnerability

	cwes_names = []

	for cwe in cwes:

		cwe_data = requests.get("https://www.opencve.io/api/cwe/"+cwe,auth=requests.auth.HTTPBasicAuth('Mateo803','Pentshelp_passw0rd'))

		cwe_data = cwe_data.json()

		cwes_names.append(cwe_data["name"])


	#Transform cwes_names into str in order to insert it into the database

	cwes_names = str(cwes_names)

	cwes_names = cwes_names.replace("['","")

	cwes_names = cwes_names.replace("']","")


	date = cve_data["created_at"]

	date = date[0:10] #In order to be a valid date format when inserting it in the database

	cpe_match = cve_data["raw_nvd_data"]["configurations"]["nodes"][0]["cpe_match"]

	cpes = [] #List that contains vulnerable products in CPE form

	for cpe in cpe_match:

		cpes.append(cpe["cpe23Uri"])

	#Transform cpes into str in order to insert it into the database

	cpes = str(cpes)

	cpes = cpes.replace("['","")

	cpes = cpes.replace("']","")


	cve_data_dictionary = {
  "id": id,
  "name": name,
  "date": date,
  "score": cvss,
  "kind_of_vulnerability": cwes_names,
  "vulnerable_products": cpes
}


	return cve_data_dictionary



def report_cve(cve):


	cve_data = retrieve_cve_data(cve)

	if cve_data == -1:

		print ("Invalid CVE")

		return

	try:

		db = mysql.connector.connect(
	  host="localhost",
	  user="pentshelp",
	  password="*Zq%GPG@Vn$BzjC*h8Ma6^VWpL*^85",
	  database="pentshelp"
	)

	except:

		print('The database is not well configured')

		return

	cursor = db.cursor()

	
	sql = "INSERT INTO CVES (ID,Name,Date,Score,Kind_of_vulnerability,Vulnerable_products) VALUES (%s,%s,%s,%s,%s,%s)"

	val = (cve_data["id"], cve_data["name"],cve_data["date"],cve_data["score"],cve_data["kind_of_vulnerability"],cve_data["vulnerable_products"])

	try:

		cursor.execute(sql,val)

		db.commit()

	except:

		print('The CVE has already been reported')

	else:

		print('CVE reported successfully')
