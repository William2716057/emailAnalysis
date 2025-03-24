from langdetect import detect
import re
import emoji
import requests
from email import message_from_string
from email.policy import default
from datetime import datetime
from hashlib import md5
from datetime import datetime



#1. Is email in English
#2. Is greater than 4 words
#3. Does address not end in corporate domain @gmail, @yahoo, @aol, @outlook, @icloud
#4. Is there sender name
#5. save to .eml or .smg format
#6. Does not contain Re: or Fw:
#7. Does not contain emojis
#8. Is date > 01/10/2001
#9. check for information to deem TSE
#10. is duplicate
#11. Is sent by business or organisation
#12. Does contain keywords indicating promotional
#13. Does belong to accepted category

# Open and read the email file
with open("test1.eml", "r") as file:
    raw_email = file.read()

email_message = message_from_string(raw_email, policy=default)
email_body = email_message.get_body(preferencelist=('plain')).get_content()

#check whether domain is corpor
def is_not_corporate_domain(email):
    corporate_domains = ["gmail.com", "yahoo.com", "aol.com", "outlook.com", "icloud.com"]
    domain = email.split('@')[-1]
    return domain not in corporate_domains

def contains_no_emoji(text):
    return not any(emoji.is_emoji(char) for char in text)

def find_links(text):

    # Regular expression to find URLs in the text
    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    return url_pattern.findall(text)


#UNCOMMENT HERE IF USING VIRUS TOTAL API
# Your VirusTotal API key
#API_KEY = input("Input API key: ")
#BASE_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
#def check_url(url):
#    params = {'apikey': API_KEY, 'resource': url}
#    response = requests.get(BASE_URL, params=params)
#    return response.json()


def extract_subject(email_message):
    return email_message['Subject'] or ""

def is_subject_valid(subject):
    clean_subject = re.sub(r'\b\w{1,2}\b|\d+|Re:|Fw:', '', subject).strip()
    word_count = len(clean_subject.split())
    return word_count >= 4

def contains_sender_name(email_message):
    sender = email_message['From']
    if sender:
        match = re.search(r'\"?([^\"\<\>]+)\"?\s*<', sender)
        if match:
            return True
    return False

def is_recent(email_message):
    email_date = email_message['Date']
    email_datetime = datetime.strptime(email_date, '%a, %d %b %Y %H:%M:%S %z')
    
    # Convert to offset-naive datetime by removing timezone info
    email_datetime_naive = email_datetime.replace(tzinfo=None)
    
    # Compare with a naive datetime
    return email_datetime_naive > datetime(2021, 1, 1)

def is_not_duplicate(subject):
    subject_hash = md5(subject.encode()).hexdigest()
    if subject_hash in seen_subjects:
        return False
    seen_subjects.add(subject_hash)
    return True
seen_subjects = set()

# Rule Checks
language = detect(email_body)
is_english = language == 'en'
print(f"Language detected: {language} (Is English: {is_english})")

subject = extract_subject(email_message)
valid_subject = is_subject_valid(subject)
print(f"Is subject valid (at least 4 words excluding numbers/dates/etc.)? {valid_subject}")

sender_email = re.search(r'From:.*<(.+?)>', raw_email)
if sender_email:
    email_address = sender_email.group(1)

# Check if the email is in English
print("Language detected:", detect(raw_email))

# Count words in the email
word_count = len(raw_email.split())
is_greater_than_4_words = word_count > 4
print(f"Is the email longer than 4 words? {is_greater_than_4_words}")

# Extract sender's email address
sender_email = re.search(r'From:.*<(.+?)>', raw_email)
if sender_email:
    email_address = sender_email.group(1)
    print(f"Sender's email: {email_address}")
    
    not_corporate_domain = is_not_corporate_domain(email_address)
    print(f"Is the email address not a corporate domain? {not_corporate_domain}")
else:
    print("Sender's email address not found.")

has_sender_name = contains_sender_name(email_message)
print(f"Does the email have a sender name? {has_sender_name}")

recent_email = is_recent(email_message)
print(f"Is the email recent (after Jan 1st, 2021)? {recent_email}")

no_re_fwd = 'Re:' not in subject and 'Fw:' not in subject
print(f"Subject does not contain 'Re:' or 'Fw:': {no_re_fwd}")

no_emoji_in_subject = contains_no_emoji(subject)
print(f"Subject does not contain emojis: {no_emoji_in_subject}")

not_duplicate = is_not_duplicate(subject)
print(f"Is the email subject not a duplicate? {not_duplicate}")

links = find_links(email_body)
# Check for emojis in the email content
no_emoji = contains_no_emoji(raw_email)
print(f"No emoji in email content? {no_emoji}")

# Find and print links in the email content
links = find_links(raw_email)

print(f"Links found in the email: {links}")

#def is_malicious(url):
#    result = check_url(url)

    # The 'positives' field indicates how many antivirus engines flagged the URL as malicious

#    if result.get('positives', 0) > 0:
#        return True, result
#    return False, result


# Check each link for malicious content
#for link in links:
#    malicious, report = is_malicious(link)

#    if malicious:
#        print(f"The URL {link} is flagged as malicious.")
#    else:
#        print(f"The URL {link} is not flagged as malicious.")

# Check each link for malicious content
#for link in links:
#    malicious, report = is_malicious(link)
    
#    if malicious:
#        print(f"The URL {link} is flagged as malicious.")
#        print(f"Report: {report}")
#    else:
#        print(f"The URL {link} is not flagged as malicious.")
#        print(f"Report: {report}")
        

travelKeywords = {"Booking reference"}

        

#categories Accepted
#travel updates accepted
    #itinerary/trip updates 
    #car rental updates 
    #hotel/apartment updates 
    #Train/Bus/Cruise/Ferry/Tour package Ticket updates 

#Utility and Services Notices accepted
    #Notifications for scheduled maintenances, outages or 
    #disruption of services related to the 
    #following utility services:

    #electricity 
    #water 
    #internet 
    #telephone 
    #gas 

#Appointment Reminders
    #physician appointment 
    #dental appointment 
    #therapy appointment 

#Calendar Invites
    #Calendar invites (Invitation and confirmation to meeting/interview/calls).

#Calendar Updates
    #Calendar Updates (Change or important information about an already 
    #scheduled important calendar event). 

#Digital Signatures
    #emails related to actions needed for e-signatures or 
    #any other type of action that replaces paper signatures. 

#Lease and Property Notices
    #important notices about a lease or property. 

#Travel/Reservation Confirmations
    #itinerary or trip confirmation
    #car rental confirmation
    #hotel/AirBnB/Booking booking or reservation confirmation
    #train/bus/cruise/ferry/tour package ticket confirmation
    #truck rental update, cancelation, change, status, reminder
    #restaurant reservation

#Order Confirmations
    #online shopping order
    #order return confirmation
    #food order confirmation
    #subscription confirmation

#Order Receipts
    #online shopping receipt
    #payment service receipt
    #subscription receipt
    #transportation (such as Uber) receipt
    #gift card receipt

#Shipments
    #tracking provided, confirmation, shipment, delivery, delay, reschedule, status, failure to deliver of:
    #packages
    #parcels
    #letters
    #orders
    #freights
    #pickups
    #food or grocery

#Bill Statements/ Payments
    #monthly bill statement
    #payment statement
    #billing summary

#Bank Statements/ Updates
    #monthly bank statement
    #payment statement
    #billing summary
    #trading account statement
    #fund transfer
    #fund transfer


