from flask import *
import secrets
import sqlite3
import re
import os
import requests 
from dotenv import load_dotenv, find_dotenv

app = Flask(__name__)
app.secret_key = "test"


load_dotenv(find_dotenv(".env_var"))

def generate_auth_token(email_name):
	con = sqlite3.connect("user_api.sqlite")
	new_auth_key = secrets.token_hex(16)
	query_cmd = f"insert into user_api(name, apikey) values ('{email_name}', '{new_auth_key}')"
	
	con.execute(query_cmd)
	con.commit()
	con.close()
	return new_auth_key

def validate_email(email_name):
	email_format = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
	if re.fullmatch(email_format, str(email_name.strip())):
		return True
	return False

def check_session(authentication_key):
	if "api_key" in session:
		query = f"select apikey from user_api where apikey='{authentication_key}'"

		con = sqlite3.connect("user_api.sqlite")
		cur = con.cursor()

		cur.execute(query)
		data = cur.fetchone()

		if data is None:
			return False
		else:
			return True


def advanced_email_lookup(email):
		url = f"https://ipqualityscore.com/api/json/email/{str(os.getenv('BUNDLE_QUALITY_API_KEY'))}/{email}"

		response = requests.get(url)

		formatJson = json.loads(response.text)

		try:
			return f'''\n
			Valid -> {str(formatJson["valid"])} |
			TImed Out -> {str(formatJson["timed_out"])} |
			Disposable -> {str(formatJson["disposable"])} |
			First Name -> {str(formatJson["first_name"])} |
			Deliverability -> {str(formatJson["deliverability"])} |
			SMTP Score -> {str(formatJson["smtp_score"])} |
			Overall Score -> {str(formatJson["overall_score"])} |
			DNS Valid -> {str(formatJson["dns_valid"])} |
			Honeypot -> {str(formatJson["honeypot"])} |
			Fraud Score -> {str(formatJson["fraud_score"])} |
			First Seen -> {str(formatJson["first_seen"]["human"])} |
			'''
		except:
			return "Error with user input"
def advanced_ip_lookup(target_ip):

		url = f"https://api.apilayer.com/ip_to_location/{target_ip}"

		payload = {}
		headers= {
		  "apikey": str(os.getenv("GEO_IP_API_KEY"))
		}

		response = requests.request("GET", url, headers=headers, data=payload)

		formatJson = json.loads(response.text)

		try:
			return f'''
	Longtitude -> {str(formatJson["longitude"])} |
	Latitude -> {str(formatJson["latitude"])} |
	City -> {str(formatJson["city"])} |
	Continent Code -> {str(formatJson["continent_code"])} |
	Continent Name -> {str(formatJson["continent_name"])} |
	Country Name -> {str(formatJson["country_name"])} |
	Country Code -> {str(formatJson["country_code"])} |
	Currencies -> {str(formatJson["currencies"])} |
	Region Name -> {str(formatJson["region_name"])} |
	Type -> {str(formatJson["type"])} |'''
		except:
			return "Error with user input"

def advanced_phone_lookup(prefix, number):
		url2 = f"https://ipqualityscore.com/api/json/phone/{os.getenv('BUNDLE_QUALITY_API_KEY')}/{prefix + number}?strictness=1"
		url = f"https://api.apilayer.com/number_verification/validate?number={prefix + number}"

		payload = {}
		headers= {
		  "apikey": str(os.getenv("NUM_LOOKUP_API_KEY"))
		}

		response = requests.request("GET", url, headers=headers, data=payload)
		response1 = requests.get(url2)

		formatJson1 = json.loads(response1.text)
		formatJson = json.loads(response.text)

		try:
			return f'''
		Valid -> {  str(formatJson["valid"])  } |
		Number -> {  formatJson["number"]  } |
		Local Format -> {  formatJson["local_format"]  } |
		International Format -> {  formatJson["international_format"]  } |
		Country Prefix -> {  formatJson["country_prefix"]  } |
		Country Code -> {  formatJson["country_code"]  } |
		Country Name -> {  formatJson["country_name"]  } |
		Location -> {  formatJson["location"]  } |
		Carrier -> {  formatJson["carrier"]  } |
		Line Type -> {  formatJson["line_type"]  } |
		Region -> {  formatJson1["region"]  } |
		Fraud Score -> {  str(formatJson1["fraud_score"])  } |
		Recent Abuse -> {  str(formatJson1["recent_abuse"])  } |
		VOIP -> {  str(formatJson1["VOIP"])  } |
		Prepaid -> {  str(formatJson1["prepaid"])  } |
		Risky -> {  str(formatJson1["risky"])  } |
		Active -> {  str(formatJson1["active"])  } |
		Name -> {  str(formatJson1["name"])  } |
		Timezone -> {  str(formatJson1["timezone"])  } |
		ZIP Code -> {  str(formatJson1["zip_code"])  } |
		Leaked -> {  str(formatJson1["leaked"])  } |
		Active Status -> {  str(formatJson1["active_status"])  } |
				'''
		except:
			return "Error with user input"
		

@app.route("/")
def home():
	return render_template("home.html")

@app.route("/get_validation", methods=["GET"])
def get_validation():
	if request.method == "GET":
		api_key = request.headers.get("Authorization")
		if api_key in valid_api_keys:
			return "Valid API Key"
		return "Invalid API Key"

@app.route("/get_token", methods=["GET", "POST"])
def get_auth_key():
	if request.method == "POST":
		email_var = request.form.get("name_email")
		
		if validate_email(email_var) is False: 
			return render_template("generate_auth.html")

		return f"<script>alert('Your authentication token: {generate_auth_token(email_var)}');window.location.href = '/#';</script>"

	else:
		return render_template("generate_auth.html")


@app.route("/login", methods=["GET", "POST"])
def login_page():
	if request.method == "POST":

		email_var = request.form.get("email_name")
		auth_var = request.form.get("auth_key")

		query = f"select name, apikey from user_api where name='{email_var.strip()}' and apikey='{auth_var.strip()}'"

		con = sqlite3.connect("user_api.sqlite")
		cur = con.cursor()

		cur.execute(query)
		response_data = cur.fetchone() 

		if response_data is None:
			return render_template("login.html")
		else:
			session["api_key"] = auth_var
			return "<script>window.location.href = '/workshop'; </script>"

	return render_template("login.html")


@app.route("/workshop", methods=["GET","POST"])
def osint_workshop():
	if request.method == "GET":
		try:
			if check_session(session["api_key"]):
				return render_template("workshop.html")

		except:
			return "Unauthorized Request"
		

	return "None"


@app.route("/workshop/ip_lookup", methods=["GET", "POST"])
def ip_osint():
	try:
		if check_session(session["api_key"]):
			pass
	except:
		return "Unauthorized Request"

	if request.method == "POST":
		ip_n = request.form.get("ip_name")
		result = advanced_ip_lookup(ip_n)
		return render_template("ip_lookup.html", output=result)

	return render_template("ip_lookup.html")

@app.route("/workshop/email_lookup", methods=["GET", "POST"])
def email_osint():
	try:
		if check_session(session["api_key"]):
			pass
	except:
		return "Unauthorized Request"



	if request.method == "POST":
		email_n = request.form.get("emailname")
		result = advanced_email_lookup(email_n)
		if validate_email(email_n) is False:
			return render_template("email_lookup.html", output="Error with user input")
		return render_template("email_lookup.html", output=result)


	return render_template("email_lookup.html")
	



@app.route("/workshop/phone_lookup", methods=["GET", "POST"])
def phone_osint():
	try:
		if check_session(session["api_key"]):
			pass

	except:
		return "Unauthorized Request"

	if request.method == "POST":
		phone_pre = request.form.get("prefix")
		phone_local = request.form.get("local_phone")
		result = advanced_phone_lookup(phone_pre, phone_local)
		return render_template("phone_lookup.html", output=result)

	return render_template("phone_lookup.html")




app.run(debug=True, host="127.0.0.1", port=9999)