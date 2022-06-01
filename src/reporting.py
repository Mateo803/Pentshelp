import requests
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph
import mysql.connector
import matplotlib.pyplot as plot
from os import path


def retrieve_cve_data(cve):

	cve_data = requests.get("https://www.opencve.io/api/cve/"+cve,auth=requests.auth.HTTPBasicAuth('Mateo803','Pentshelp_passw0rd'))

	if cve_data.status_code != 200: #Check that the given url is correct

		
		return -1


	cve_data = cve_data.json() #Transform request into JSON format in order to retrieve information

	id = cve_data["id"]

	description = cve_data["summary"]

	cvss = [cve_data["cvss"]["v2"],cve_data["cvss"]["v3"]] #By default show only CVSS v3 (if doesn´t exist, show v2 instead)

	if cvss[1] is None:

		cvss = cvss[0]

	else:

		cvss = cvss[1]


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
  "description": description,
  "date": date,
  "score": cvss,
  "kind_of_vulnerability": cwes_names,
  "vulnerable_products": cpes
}


	return cve_data_dictionary



def report_cve(cve, solution):


	cve_data = retrieve_cve_data(cve)

	if cve_data == -1:

		print("\nInvalid CVE")

		return

	try:

		connection = mysql.connector.connect(
	  host="localhost",
	  user="root",
	  password="root",
	  database="pentshelp"
	)

	except:

		print('\nThe database is not well configured')

		return

	cursor = connection.cursor()

	if solution is None:


		sql = "INSERT INTO CVES (ID,Description,Date,Score,Kind_of_vulnerability,Vulnerable_products) VALUES (%s,%s,%s,%s,%s,%s)"

		val = (cve_data["id"], cve_data["description"],cve_data["date"],cve_data["score"],cve_data["kind_of_vulnerability"],cve_data["vulnerable_products"])


	else:

		try:

			solution = open(solution,mode="r",encoding="utf-8")

			solution_content = solution.read()

			solution.close()

		except:

			print('\nThe solution file does not exist or is not a text file')

			return


		sql = "INSERT INTO CVES (ID,Description,Date,Score,Kind_of_vulnerability,Vulnerable_products,Solution) VALUES (%s,%s,%s,%s,%s,%s,%s)"

		val = (cve_data["id"], cve_data["description"],cve_data["date"],cve_data["score"],cve_data["kind_of_vulnerability"],cve_data["vulnerable_products"],solution_content)


	try:

		cursor.execute(sql,val)

		connection.commit()

	except:

		print('\nThe CVE has already been reported')

	else:

		print('\nCVE reported successfully')




def delete_cve(cve):


	try:

		connection = mysql.connector.connect(
	  host="localhost",
	  user="root",
	  password="root",
	  database="pentshelp"
	)

	except:

		print('\nThe database is not well configured')

		return

	cursor = connection.cursor()

	sql = "DELETE FROM CVES WHERE ID = %s"

	val = (cve,)


	try:

		cursor.execute(sql,val)

		connection.commit()

	except:

		print('\nThe CVE is not registered')

	else:

		print('\nCVE deleted successfully')



def generate_report(report_name):


	try:

		connection = mysql.connector.connect(
	  host="localhost",
	  user="root",
	  password="root",
	  database="pentshelp"
	)

	except:

		print('\nThe database is not well configured')

		return


	cursor = connection.cursor()

	sql = "select * from CVES;"

	cursor.execute(sql)

	cves = cursor.fetchall();

	connection.close()

	if len(cves) == 0:

		print("\nAt least must be one vulnerability reported")

		return

	#Declaration of lists that will be necessary to create the final report

	names = []

	impacts = []

	if not path.exists('pentesting_files'):

		print('\nYou need to create the pentshelp folders first')

		return


	report = canvas.Canvas('pentesting_files/reports/'+report_name)

	for cve in cves:

		title = report.beginText(250,750)

		title.setFont("Helvetica-Bold", 20)

		title.textOut(cve[0])

		subtitle_summary = report.beginText(50,700)

		subtitle_summary.setFont("Helvetica-Bold", 15)

		subtitle_summary.textOut('Description')

		summary = Paragraph(cve[1][:-1])

		summary.wrap(500,50)

		summary.drawOn(report,50,650)

		subtitle_date = report.beginText(50,600)

		subtitle_date.setFont("Helvetica-Bold", 15)

		subtitle_date.textOut('Date')

		date = Paragraph(str(cve[2]))

		date.wrap(500,50)

		date.drawOn(report,50,580)

		subtitle_cvss = report.beginText(50,550)

		subtitle_cvss.setFont("Helvetica-Bold", 15)

		subtitle_cvss.textOut('CVSS score')

		cvss = Paragraph(str(cve[3]))

		cvss.wrap(500,50)

		cvss.drawOn(report,50,530)

		subtitle_cwe = report.beginText(50,500)

		subtitle_cwe.setFont("Helvetica-Bold", 15)

		subtitle_cwe.textOut('Kind of vulnerability')

		cve_text = cve[4].replace('["',"")

		cve_text = cve_text.replace('"]',"")

		cwe = Paragraph(cve_text+'.')

		cwe.wrap(500,50)

		cwe.drawOn(report,50,470)

		subtitle_cpes = report.beginText(50,440)

		subtitle_cpes.setFont("Helvetica-Bold", 15)

		subtitle_cpes.textOut('Vulnerable products (CPE format)')

		cpes = cve[5]

		if len(cpes) != 2: #Because [] has exactly 2 characters

			cpes = cpes.replace("'","")

			cpes = cpes.split(',')

			cpes_initial_height = 400

			for cpe in cpes:

				report.drawString(50, cpes_initial_height, u'\u2022 '+cpe)

				cpes_initial_height -= 30

			solution_height = 400 - (len(cpes)+2) * 25

		else:

			report.drawString(50, 400,'Unknown information')

			solution_height = 350


		subtitle_solution = report.beginText(50,solution_height)

		subtitle_solution.setFont("Helvetica-Bold", 15)

		subtitle_solution.textOut('Solution')

		solution_content = cve[6]

		if solution_content is not None:

			solution = Paragraph(solution_content)

			solution.wrap(600,50)

			solution.drawOn(report,50,solution_height-30)

		else:

			report.drawString(50, solution_height-30,'No solution attached.')

		report.drawText(title)

		report.drawText(subtitle_summary)

		report.drawText(subtitle_date)

		report.drawText(subtitle_cvss)

		report.drawText(subtitle_cwe)

		report.drawText(subtitle_cpes)

		report.drawText(subtitle_solution)

		page = str(report.getPageNumber())

		report.drawString(300,25,page)

		report.showPage()

		names.append(cve[0])

		impacts.append(cve[3])


	plot.bar(names,impacts, color="#b3003b")

	plot.ylabel('Impact (CVSS)')

	plot.xlabel('Vulnerabilities')

	plot.title('Report summary')

	plot.savefig("summary.png")

	report.drawImage('summary.png',0,250)

	plot.savefig("summary.png",dpi=300)

	page = str(report.getPageNumber())

	report.drawString(300,25,page)

	report.save()

	print("\nReport generated successfully")
