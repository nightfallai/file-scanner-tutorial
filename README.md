# Deploy a File Scanner for Sensitive Data in 40 Lines of Code

#### In this tutorial, we will create and deploy a server that scans files for sensitive data (like credit card numbers) with Nightfall's data loss prevention APIs and the Flask framework. 

The service ingests a local file, scans it for sensitive data with Nightfall, and displays the results in a simple table UI. We'll deploy the server on Render (a PaaS Heroku alternative) so that you can serve your application publicly in production instead of running it off your local machine. You'll build familiarity with the following tools and frameworks: Python, Flask, Nightfall, Ngrok, Jinja, Render.

## Key Concepts

Before we get started on our implementation, start by familiarizing yourself with [how scanning files works](https://docs.nightfall.ai/docs/scanning-files#prerequisites) with Nightfall, so you're acquainted with the flow we are implementing. 

In a nutshell, file scanning is done asynchronously by Nightfall; after you upload a file to Nightfall and trigger the scan, we perform the scan in the background. When the scan completes, Nightfall delivers the results to you by making a request to your webhook server. This asynchronous behavior allows Nightfall to scan files of varying sizes and complexities without requiring you to hold open a long synchronous request, or continuously poll for updates. The impact of this pattern is that you need a webhook endpoint that can receive inbound notifications from Nightfall when scans are completed - that's what we are building in this tutorial.

## Getting Started

You can fork the sample repo and view the complete code [here](https://github.com/nightfallai/file-scanner-tutorial), or follow along below. If you're starting from scratch, create a new GitHub repository.

## Setting Up Dependencies

First, let's start by installing our dependencies. We'll be using Nightfall for data classification, the [Flask](https://flask.palletsprojects.com/en/2.0.x/) web framework in Python, and [Gunicorn](https://gunicorn.org/) as our web server. Create `requirements.txt` and add the following to the file:

```
nightfall
Flask
Gunicorn
```

Then run `pip install -r requirements.txt` to do the installation.

## Configuring Detection with Nightfall

Next, we'll need our Nightfall API Key and Webhook Signing Secret; the former authenticates us to the Nightfall API, while the latter authenticates that incoming webhooks are originating from Nightfall. You can retrieve your API Key and Webhook Signing Secret from the Nightfall [Dashboard](https://app.nightfall.ai). Complete the Nightfall [Quickstart](https://docs.nightfall.ai/docs/quickstart) for a more detailed walk-through. [Sign up](https://app.nightfall.ai/sign-up) for a free Nightfall account if you don't have one.

These values are unique to your account and should be kept safe. This means that we will store them as environment variables and should not store them directly in code or commit them into version control. If these values are ever leaked, be sure to visit the Nightfall Dashboard to re-generate new values for these secrets.


```bash
export NIGHTFALL_API_KEY=<your_key_here>
export NIGHTFALL_SIGNING_SECRET=<your_secret_here>
```

## Setting Up Our Server

Let's start writing our Flask server. Create a file called `app.py`. We'll start by importing our dependencies and initializing the Flask and Nightfall clients:

```python
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
```

Next, we'll add our first route, which will display "Hello World" when the client navigates to `/ping` simply as a way to validate things are working:

```python
@app.route("/ping")
def ping():
	return "Hello World", 200
```

Run `gunicorn app:app` on the command line to fire up your server, and navigate to your local server in your web browser. You'll see where the web browser is hosted in the Gunicorn logs, typically it will be `127.0.0.1:8000` aka `localhost:8000`.

```bash
[2021-11-26 14:22:53 -0800] [61196] [INFO] Starting gunicorn 20.1.0
[2021-11-26 14:22:53 -0800] [61196] [INFO] Listening at: http://127.0.0.1:8000 (61196)
[2021-11-26 14:22:53 -0800] [61196] [INFO] Using worker: sync
[2021-11-26 14:22:53 -0800] [61246] [INFO] Booting worker with pid: 61246
```

To expose our local webhook server via a public tunnel that Nightfall can send requests to, we'll use ngrok. Download and install ngrok via their quickstart documentation [here](https://ngrok.com/docs/guides/quickstart). We'll create an ngrok tunnel as follows:

```bash
./ngrok http 8000
```

After running this command, `ngrok` will create a tunnel on the public internet that redirects traffic from their site to your local machine. Copy the HTTPS tunnel endpoint that ngrok has created: we can use this as the webhook URL when we trigger a file scan.

```bash
Account                       Nightfall Example
Version                       2.3.40
Region                        United States (us)
Web Interface                 http://127.0.0.1:4040
Forwarding                    http://3ecedafba368.ngrok.io -> http://localhost:8000
Forwarding                    https://3ecedafba368.ngrok.io -> http://localhost:8000
```

Let's set this HTTPS endpoint as a local environment variable so we can reference it later:

```bash
export NIGHTFALL_SERVER_URL=https://3ecedafba368.ngrok.io
```

Tip: With a Pro ngrok account, you can create a subdomain so that your tunnel URL is consistent, instead of randomly generated each time you start the tunnel.

## Handling an Inbound Webhook

Before we send a file scan request to Nightfall, let's add logic for our incoming webhook endpoint, so that when Nightfall finishes scanning a file, it can successfully send the sensitive findings to us.

First, what does it mean to have findings? If a file has findings, this means that Nightfall identified sensitive data in the file that matched the detection rules you configured. For example, if you told Nightfall to look for credit card numbers, any substring from the request payload that matched our credit card detector would constitute sensitive findings.

We'll host our incoming webhook at `/ingest` with a POST method.

Nightfall will POST to the webhook endpoint, and in the inbound payload, Nightfall will indicate if there are sensitive findings in the file, and provide a link where we can access the sensitive findings as JSON.

```python
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
```

Restart your server so the changes propagate. We'll take a look at the console output of our webhook endpoint and explain what it means in the next section.

## Scan a File

Now, we want to trigger a file scan request, so that Nightfall will scan the file and send a POST request to our `/ingest` webhook endpoint when the scan is complete. We'll write a simple script that sends a file to Nightfall to scan it for [credit card numbers](https://docs.nightfall.ai/docs/detector-glossary#finance). Create a new file called `scan.py`.

First, we'll establish our dependencies, initialize the Nightfall client, and specify the filepath to the file we wish to scan as well as the webhook endpoint we created above. The filepath is a relative path to any file, in this case we are scanning the `sample-pci-xs.csv` file which is in the same directory as `scan.py`. This is a sample CSV file with 10 credit card numbers in it - you can download it in the tutorial's GitHub [repo](https://github.com/nightfallai/file-scanner-tutorial).

```python
import os
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall

nightfall = Nightfall() # reads API key from NIGHTFALL_API_KEY environment variable by default

filepath = "sample-pci-xs.csv" # sample file with sensitive data
webhook_url = f"{os.getenv('NIGHTFALL_SERVER_URL')}/ingest"
```

Next, we will initiate the scan request to Nightfall, by specifying our filepath, webhook URL where the scan results should be posted, and our Detection Rule that specifies what sensitive data we are looking for.

In this simple example, we have specified an inline Detection Rule that detects Likely Credit Card Numbers. This Detection Rule is a simple starting point that just scratches the surface of the types of detection you can build with Nightfall. Learn more about building inline detection rules [here](https://docs.nightfall.ai/docs/creating-an-inline-detection-rule) or how to configure them in the Nightfall [Dashboard](https://app.nightfall.ai/developer-platform).

```python
scan_id, message = nightfall.scan_file(filepath, 
	webhook_url=webhook_url,
	detection_rules=[ DetectionRule([ 
		Detector(
			min_confidence=Confidence.LIKELY,
   			nightfall_detector="CREDIT_CARD_NUMBER",
   			display_name="Credit Card Number"
       	)])
	])

print(scan_id, message)
```

The `scan_id` is useful for identifying your scan results later.

## View Sensitive Findings

Let's run `scan.py` to trigger our file scan job.

Once Nightfall has finished scanning the file, we'll see our Flask server receive the request at our webhook endpoint (`/ingest`). In our code above, we parse the webhook payload, and print the following when there are sensitive findings:

```bash
Sensitive data present. Findings available until 2021-11-28T00:29:00.479700877Z.

Download:
https://files.nightfall.ai/d2160270-6b07-4304-b1ee-e7b98498be82.json?Expires=1638059340&Signature=AjSdNGlXWGXO0QGSi-lOoDBtbhJdLPE7IWXA7IaBCfLr~3X2IcZ1vavHF5iaEDaoZ-3etnZA4Nu8K8Dq8Kd81ShuX6Ze1o87mzb~8lD6WBk8hXShgW-TPBPpLMoBx2sA9TnefTqy94gI4ykt4tt1MttB67Cj69Miw-46cpFkgY9tannNPOF-90b3vlcS44PwqDUGrtTpQiN6WdsTT6LbpN1N92KbPJIRj3PkGwQW7VvpfM8L4wKmyVmVnRO3ixaW-mXXiOWk9rmfHP9UFMYnk99yaGHp4dZ1JfJiClci~Z8dBx288CrvXVjGUCXBJbdlwo6UrKQJCEk9i9vSbCpI2Q__&Key-Pair-Id=K24YOPZ1EKX0YC

View:
https://d3vwatchtower.ngrok.io/ingest/view?findings_url=https%3A//files.nightfall.ai/d2160270-6b07-4304-b1ee-e7b98498be82.json%3FExpires%3D1638059340%26Signature%3DAjSdNGlXWGXO0QGSi-lOoDBtbhJdLPE7IWXA7IaBCfLr~3X2IcZ1vavHF5iaEDaoZ-3etnZA4Nu8K8Dq8Kd81ShuX6Ze1o87mzb~8lD6WBk8hXShgW-TPBPpLMoBx2sA9TnefTqy94gI4ykt4tt1MttB67Cj69Miw-46cpFkgY9tannNPOF-90b3vlcS44PwqDUGrtTpQiN6WdsTT6LbpN1N92KbPJIRj3PkGwQW7VvpfM8L4wKmyVmVnRO3ixaW-mXXiOWk9rmfHP9UFMYnk99yaGHp4dZ1JfJiClci~Z8dBx288CrvXVjGUCXBJbdlwo6UrKQJCEk9i9vSbCpI2Q__%26Key-Pair-Id%3DK24YOPZ1EKX0YC
```

In our output, we are printing two URLs.

The first URL is provided to us by Nightfall. It is the temporary signed S3 URL that we can access to fetch the sensitive findings that Nightfall detected. 

The second URL won't work yet, we'll implement it next. This URL a we constructed in our `ingest()` method above - the URL calls `/view` and passes the Findings URL above as a URL-escaped query parameter.

Let's add a method to our Flask server that opens this URL and displays the findings in a formatted table, so that the results are easier to view than downloading them as JSON.

We'll do this by adding a `view` method that responds to GET requests to the `/view` route. The `/view` route will read the URL to the S3 Findings URL via a query parameter. It will then open the findings URL, parse it as JSON, pass the results to an HTML template, and display the results in a simple HTML table using [Jinja](https://jinja.palletsprojects.com/en/3.0.x/). Jinja is a simple templating engine in Python.

Add the following to our Flask server in `app.py`:

```python
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
```

## Create the Table View

To display the findings in an HTML table, we'll create a new Flask template. Create a folder in your project directory called `templates` and add a new file within it called `view.html`.

Our template uses Jinja to iterate through our findings, and create a table row for each sensitive finding.

```html
<!DOCTYPE HTML>
<html>
<head>
    <title>File Scan Viewer</title>
    <style>
    	table, th, td {
		  border: 1px solid black;
		}
		table {
			width: 100%;
		}
	</style>
</head>

<body>
	<table>
		<thead>
			<tr>
				<th>Detector</th>
				<th>beforeContext</th>
				<th>Finding</th>
				<th>afterContext</th>
				<th>byteRangeStart</th>
				<th>byteRangeEnd</th>
				<th>Confidence</th>
			</tr>
		</thead>

		<tbody>
			{% for finding in findings %}
				<tr>
					<td>{{ finding['detector']['name'] }}</td>
					<td>{{ finding['beforeContext'] }}</td>
					<td>{{ finding['finding'] }}</td>
					<td>{{ finding['afterContext'] }}</td>
					<td>{{ finding['location']['byteRange']['start'] }}</td>
					<td>{{ finding['location']['byteRange']['start'] }}</td>
					<td>{{ finding['confidence'] }}</td>
				</tr>
			{% endfor %}
		</tbody>
	</table>

</body>
</html>
```

Now, if we restart our Flask server, trigger a file scan request, and navigate to the "View" URL printed in the server logs, we should see a formatted table with our results! In fact, we can input any Nightfall-provided signed S3 URL (after URL-escaping it) in the `findings_url` parameter of the `/view` route to view it.

## Deploy on Render

As a longtime Heroku user, I was initially inclined to write this tutorial with instructions to deploy our app on Heroku. However, new PaaS vendors have been emerging and I was curious to try them out and see how they compare to Heroku. One such vendor is Render, which is where we'll deploy our app.

Deploying our service on Render is straightforward. If you're familiar with Heroku, the process is quite similar. Once you've signed up or logged into Render (free), we'll do the following:

1. Create a new `Web Service` on Render, and give Render permission to access your new repo.

2. Use the following values during creation:

* Environment: Python
* Build Command: `pip install -r requirements.txt`
* Start Command: `gunicorn app:app`

Let's also set our environment variables during creation. These are the same values we set locally.

```bash
NIGHTFALL_API_KEY
NIGHTFALL_SIGNING_SECRET
```

## Scan a file (in production)

Once Render has finished deploying, you'll get the base URL of your application. Set this as your `NIGHTFALL_SERVER_URL` locally and re-run `scan.py` - this time, the file scan request is served by your production Flask server running on Render!

```bash
export NIGHTFALL_SERVER_URL=https://your-app-url.onrender.com
python3 scan.py
```

To confirm this, navigate to the `Logs` tab in your Render app console, you'll see the webhook's output of your file scan results:

```bash
Nov 26 04:29:06 PM  Sensitive data present. Findings available until 2021-11-28T00:28:24.564972786Z.
Nov 26 04:29:06 PM  
Nov 26 04:29:06 PM  Download:
Nov 26 04:29:06 PM  https://files.nightfall.ai/d6b6ee4f-d1a8-4fb6-b35a-cb6f88d58083.json?Expires=1638059304&Signature=hz1TN5UXjCGTxCxq~jT2wfuUWlj9Se-mWNL1K-tJhiAIXUg1FxJrCVP2iH1I4TNymFBuOnj5TTiLGpD8tZAKGm9J0lTHncZkaeaU8KZQ2j-~8qYQVlunNj019sqtTkMbVRfakzYzW-qWHEvLXN-PFcGYX05g3LZHvW802-lAVlM-WpGApw2u8BnzoY1pdWAxpJ0VIN1Zax4UuVeQBKieR7k8H9v9HdYYJlVGkVA5F9EzklLy99fyD8r4WR~jfqN5Fr1KceDtsxffC6MPuZ8nIIdSG5~tVtjCjgIjyh3IePPW1Wq-E8yZiVAhpDDbYX1wngUTwlAu~MU7N39vd8mlYQ__&Key-Pair-Id=K24YOPZ1EKX0YC
Nov 26 04:29:06 PM  
Nov 26 04:29:06 PM  View:
Nov 26 04:29:06 PM  https://flask-file-scanner-example.onrender.com/view?findings_url=https%3A//files.nightfall.ai/d6b6ee4f-d1a8-4fb6-b35a-cb6f88d58083.json%3FExpires%3D1638059304%26Signature%3Dhz1TN5UXjCGTxCxq~jT2wfuUWlj9Se-mWNL1K-tJhiAIXUg1FxJrCVP2iH1I4TNymFBuOnj5TTiLGpD8tZAKGm9J0lTHncZkaeaU8KZQ2j-~8qYQVlunNj019sqtTkMbVRfakzYzW-qWHEvLXN-PFcGYX05g3LZHvW802-lAVlM-WpGApw2u8BnzoY1pdWAxpJ0VIN1Zax4UuVeQBKieR7k8H9v9HdYYJlVGkVA5F9EzklLy99fyD8r4WR~jfqN5Fr1KceDtsxffC6MPuZ8nIIdSG5~tVtjCjgIjyh3IePPW1Wq-E8yZiVAhpDDbYX1wngUTwlAu~MU7N39vd8mlYQ__%26Key-Pair-Id%3DK24YOPZ1EKX0YC
```

Navigate to the `View` link above in your browser to verify that you can see the results formatted in a table on your production site.

Congrats, you've successfully created a file scanning server and deployed it in production! You're now ready to build more advanced business logic around your file scanner. Here are some ideas on how to extend this tutorial:

* Use WebSockets to send a notification back from the webhook to the client that initiated the file scan request
* Build a more advanced detection rule using pre-built or custom detectors
* Add a user interface to add more interactive capabilities, for example allowing users to upload files or read files from URLs
