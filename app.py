import os
from flask import Flask, request, render_template
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall
from datetime import datetime, timedelta
import urllib.request, urllib.parse, json

app = Flask(__name__)

nightfall = Nightfall(
	key=os.getenv('NIGHTFALL_API_KEY'),
	signing_secret=os.getenv('NIGHTFALL_SIGNING_SECRET')
)

@app.route("/")
def ping():
	return "Hello World", 200

# respond to POST requests at /ingest
# Nightfall will send requests to this webhook endpoint with file scan results
@app.route("/ingest", methods=['POST'])
def ingest():
	data = request.get_json(silent=True)
	# validate webhook URL with challenge response
	challenge = data.get("challenge") 
	if challenge:
		return challenge
	# challenge was passed, now validate the webhook payload
	else: 
		# get details of the inbound webhook request for validation
		request_signature = request.headers.get('X-Nightfall-Signature')
		request_timestamp = request.headers.get('X-Nightfall-Timestamp')
		request_data = request.get_data(as_text=True)

		if nightfall.validate_webhook(request_signature, request_timestamp, request_data):
			# check if any sensitive findings were found in the file, return if not
			if not data["findingsPresent"]: 
				print("No sensitive data present!")
				return "", 200

			# there are sensitive findings in the file
			# URL escape the temporary signed S3 URL where findings are available for download
			escaped_url = urllib.parse.quote(data['findingsURL'])
			# print the download URL and the URL where we can view the results in our web app
			print(f"Sensitive data present. Findings available until {data['validUntil']}.\n\nDownload:\n{data['findingsURL']}\n\nView:\n{request.url_root}view?findings_url={escaped_url}\n")
			return "", 200
		else:
			return "Invalid webhook", 500

# respond to GET requests at /view
# Users can access this page to view their file scan results in a table
@app.route("/view")
def view():
	# get the findings URL from the query parameters
	findings_url = request.args.get('findings_url')
	if findings_url:
		# download the findings from the findings URL and parse them as JSON
		with urllib.request.urlopen(findings_url) as url:
			data = json.loads(url.read().decode())
			# render the view.html template and provide the findings object to display in the template
			return render_template('view.html', findings=data['findings'])