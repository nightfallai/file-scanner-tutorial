import os
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall

nightfall = Nightfall() # reads API key from NIGHTFALL_API_KEY environment variable by default

filepath = "sample-pci-xs.csv" # sample file with sensitive data
webhook_url = f"{os.getenv('NIGHTFALL_SERVER_URL')}/ingest"

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