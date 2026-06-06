import re
import sys
import os
import json
import argparse
import emoji
from email import message_from_string
from email.policy import default
from datetime import datetime
from hashlib import md5
from langdetect import detect, LangDetectException



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

CUTOFF_DATE = datetime(2021, 1, 10)

CONSUMER_DOMAINS = {
    "gmail.com", "yahoo.com", "aol.com", "outlook.com",
    "icloud.com", "hotmail.com", "live.com", "msn.com",
    "protonmail.com", "mail.com",
} #continue adding

PROMOTIONAL_KEYWORDS = {
    "unsubscribe", "click here", "limited time", "act now", "special offer",
    "free trial", "exclusive deal", "buy now", "sale ends", "discount",
    "% off", "don't miss out", "win a", "you've been selected",
    "congratulations you", "earn money", "make money fast",
    "this is not spam", "opt out", "opt-out", "click below to",
    "no longer wish to receive", "remove me from", "marketing",
    "advertisement", "sponsor", "promotional",
} #continue adding
 
BUSINESS_INDICATORS = {
    "inc", "llc", "ltd", "corp", "co", "gmbh", "bv", "pty",
    "plc", "ag", "sa", "srl", "pte", "ngo", "foundation",
    "group", "services", "solutions", "technologies", "consulting",
    "enterprises", "holdings", "international",
}

#accepted categories
ACCEPTED_CATEGORIES = {
    "Travel Update": {
        "itinerary", "flight", "departure", "arrival", "gate", "boarding",
        "car rental", "hotel", "check-in", "check out", "reservation update",
        "trip update", "train", "bus", "cruise", "ferry", "tour package",
        "booking update", "travel alert", "schedule change",
    },
    "Utility & Service Notice": {
        "scheduled maintenance", "power outage", "service disruption",
        "electricity", "water supply", "internet outage", "service interruption",
        "telephone", "gas supply", "network maintenance", "planned outage",
    },
    "Appointment Reminder": {
        "appointment reminder", "your appointment", "scheduled appointment",
        "physician", "dental", "dentist", "therapy", "therapist",
        "doctor's appointment", "medical appointment", "clinic",
        "reminder: appointment",
    },
    "Calendar Invite": {
        "you're invited", "calendar invite", "meeting invite",
        "interview invitation", "call invitation", "join the meeting",
        "has invited you", "rsvp", "please join",
    },
    "Calendar Update": {
        "meeting update", "calendar update", "event update",
        "rescheduled", "time change", "meeting time has changed",
        "event change", "updated invitation",
    },
    "Digital Signature": {
        "please sign", "e-signature", "digital signature", "docusign",
        "hellosign", "sign the document", "signature required",
        "action required: sign", "awaiting your signature",
    },
    "Lease & Property Notice": {
        "lease", "tenancy", "rental agreement", "property notice",
        "landlord", "tenant", "eviction", "rent due", "move-in",
        "move-out", "property inspection", "notice to vacate",
    },
    "Travel/Reservation Confirmation": {
        "booking confirmation", "reservation confirmation", "your booking",
        "itinerary confirmation", "hotel confirmation", "flight confirmation",
        "car rental confirmation", "restaurant reservation",
        "your reservation", "confirmed booking", "booking reference",
        "airbnb", "confirmation number",
    },
    "Order Confirmation": {
        "order confirmation", "your order", "order #", "order number",
        "thank you for your order", "purchase confirmation",
        "subscription confirmed", "food order", "order placed",
    },
    "Order Receipt": {
        "receipt", "payment receipt", "your receipt", "invoice",
        "amount charged", "payment of", "subscription receipt",
        "uber receipt", "lyft receipt", "gift card",
    },
    "Shipment": {
        "tracking", "shipment", "shipped", "out for delivery",
        "delivery confirmation", "package", "parcel", "order dispatched",
        "estimated delivery", "delivery failed", "attempted delivery",
        "pickup ready", "freight", "courier",
    },
    "Bill Statement": {
        "bill statement", "monthly statement", "payment due",
        "payment statement", "billing summary", "amount due",
        "your bill", "statement of account", "invoice attached",
    },
    "Bank Statement": {
        "bank statement", "account statement", "trading account",
        "fund transfer", "transaction summary", "wire transfer",
        "direct deposit", "account activity", "monthly statement",
    },
}

TSE_SIGNALS = {
    "account number", "account balance", "transaction id", "reference number",
    "case number", "policy number", "membership number", "patient id",
    "invoice number", "order id", "tracking number", "booking reference",
    "confirmation number", "contract number", "claim number", "tax id",
    "social security", "date of birth", "national id",
}
 

SEEN_FILE = "repeat_subjects.json"
 
def load_seen_subjects():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()
 
def save_seen_subjects(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)
        

#get body
def get_plain_body(email_message):

    body_part = email_message.get_body(preferencelist=("plain",))
    if body_part is None:
        return ""
    try:
        return body_part.get_content()
    except Exception:
        return ""
   
 #extract sender address
def get_sender_email(email_message):
    from_header = email_message.get("From", "")
    match = re.search(r"<(.+?)>", from_header)
    if match:
        return match.group(1).strip().lower()

    if "@" in from_header:
        return from_header.strip().lower()
    return ""
 
#extract names from headers 
def get_sender_name(email_message):
    from_header = email_message.get("From", "")
    match = re.search(r'^"?([^"<>]+)"?\s*<', from_header)
    if match:
        name = match.group(1).strip()
        return name if name else ""
    return ""
 
#return urls in email file
def find_urls(text):
    url_pattern = re.compile(r"https?://\S+|www\.\S+")
    return url_pattern.findall(text)
 

def text_lower(email_message):
    """Combined lower-cased subject + body for keyword scanning."""
    subject = email_message.get("Subject", "")
    body = get_plain_body(email_message)
    return (subject + " " + body).lower()
 
#rules

#rule one: emails must be in English
def rule_is_english(body):
    if not body.strip():
        return False, "Empty body"
    try:
        lang = detect(body)
        return lang == "en", f"Detected language: {lang}"
    except LangDetectException:
        return False, "Could not detect language"
 
#rule two: must contain minimum number of words
def rule_min_word_count(body, minimum=4):
    count = len(body.split())
    return count > minimum, f"Word count: {count}"
 
#rule three: must not be a consumer domain
def rule_not_consumer_domain(email_message):
    addr = get_sender_email(email_message)
    if not addr:
        return False, "No sender address found"
    domain = addr.split("@")[-1]
    passed = domain not in CONSUMER_DOMAINS
    return passed, f"Sender domain: {domain}"
 
#rule four: must have sender name
def rule_has_sender_name(email_message):
    name = get_sender_name(email_message)
    return bool(name), f"Sender name: '{name}'"
 
#rule five subject must not start with Re
def rule_not_reply_or_forward(email_message):
    subject = email_message.get("Subject", "")
    flags = re.IGNORECASE
    is_reply = bool(re.match(r"\s*re\s*:", subject, flags))
    is_fwd   = bool(re.match(r"\s*fw(d)?\s*:", subject, flags))
    passed = not (is_reply or is_fwd)
    return passed, f"Subject: '{subject}'"
 
#Rule six must not contain emojis
def rule_no_emoji(email_message):
    subject = email_message.get("Subject", "")
    body    = get_plain_body(email_message)
    full    = subject + body
    has_emoji = any(emoji.is_emoji(ch) for ch in full)
    return not has_emoji, "Emoji found" if has_emoji else "No emoji"
 
#rule seven must be sent after cut off date
def rule_is_recent(email_message):
    date_str = email_message.get("Date", "")
    if not date_str:
        return False, "No Date header"
    # various date formats
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S",
    ]
    parsed = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(date_str.strip(), fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        return False, f"Could not parse date: '{date_str}'"
    naive = parsed.replace(tzinfo=None)
    passed = naive > CUTOFF_DATE
    return passed, f"Email date: {naive.date()} (cutoff: {CUTOFF_DATE.date()})"

#rule eight should contain transactional/sensitive/exclusive signals
def rule_is_tse(email_message): #transactional/sensitive/exclusive 
    combined = text_lower(email_message)
    found = [sig for sig in TSE_SIGNALS if sig in combined]
    passed = len(found) > 0
    detail = f"TSE signals found: {found}" if found else "No TSE signals detected"
    return passed, detail

 #rule nine must not be a duplicate 
def rule_not_duplicate(email_message, seen_subjects):
    subject = email_message.get("Subject", "")
    h = md5(subject.strip().encode()).hexdigest()
    if h in seen_subjects:
        return False, f"Duplicate subject hash: {h}"
    seen_subjects.add(h)
    return True, "Unique subject"
 
#rule ten must be a business or organisation 
def rule_is_business_sender(email_message):
    name   = get_sender_name(email_message).lower()
    domain = get_sender_email(email_message).split("@")[-1].lower()
    # Check for business words
    name_words = set(re.split(r"[\s,.\-]+", name))
    if name_words & BUSINESS_INDICATORS:
        return True, f"Business indicator in sender name: '{name}'"
    # Check domain for business words
    domain_parts = set(re.split(r"[\.\-]+", domain))
    if domain_parts & BUSINESS_INDICATORS:
        return True, f"Business indicator in domain: '{domain}'"
    # Non-consumer domain is itself a reasonable proxy
    if domain not in CONSUMER_DOMAINS and domain:
        return True, f"Non-consumer domain treated as business: '{domain}'"
    return False, f"No business indicators found (name='{name}', domain='{domain}')"

 #rule eleven must not contain promotional language 
def rule_not_promotional(email_message):
    combined = text_lower(email_message)
    found = [kw for kw in PROMOTIONAL_KEYWORDS if kw in combined]
    passed = len(found) == 0
    detail = f"Promotional keywords found: {found}" if found else "No promotional keywords"
    return passed, detail
 
#rule twelve must match accepted categories
def rule_accepted_category(email_message):
    combined = text_lower(email_message)
    matched = []
    for category, keywords in ACCEPTED_CATEGORIES.items():
        if any(kw in combined for kw in keywords):
            matched.append(category)
    passed = len(matched) > 0
    detail = f"Matched categories: {matched}" if matched else "No accepted category matched"
    return passed, detail


#run against all above rules
def process_email(path, seen_subjects, verbose=False):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError as e:
        print(f"[ERROR] Could not read {path}: {e}")
        return False, {}
 
    msg  = message_from_string(raw, policy=default)
    body = get_plain_body(msg)
 
    rules = [
        ("Language (English)", rule_is_english(body)),
        ("Word count: ",rule_min_word_count(body)),
        ("Non-consumer domain: ",rule_not_consumer_domain(msg)),
        ("Sender name present ",rule_has_sender_name(msg)),
        ("Not reply / forward ",rule_not_reply_or_forward(msg)),
        ("No emoji ",rule_no_emoji(msg)),
        ("Date: ",rule_is_recent(msg)),
        ("TSE signals: ",rule_is_tse(msg)),
        ("10 Not duplicate: ",rule_not_duplicate(msg, seen_subjects)),
        ("11 Business sender: ",rule_is_business_sender(msg)),
        ("12 Not promotional: ",rule_not_promotional(msg)),
        ("13 Accepted category: ",rule_accepted_category(msg)),
    ]
 
    results = {}
    all_passed = True
    for label, (passed, detail) in rules:
        results[label] = {"passed": passed, "detail": detail}
        if not passed:
            all_passed = False
 
    # URL extraction 
    urls = find_urls(body)
    results["URLs found"] = {"passed": None, "detail": urls if urls else "None"}
 
    # Results
    print(f"\n{'='*60}")
    print(f"File: {os.path.basename(path)}")
    print(f"From: {msg.get('From', 'N/A')}")
    print(f"Subj: {msg.get('Subject', 'N/A')}")
    print(f"{'='*60}")
 
    for label, info in results.items():
        if info["passed"] is None:
            status = "....."
        elif info["passed"]:
            status = "Passed"
        else:
            status = "Failed"
 
        if verbose or not info["passed"]:
            print(f"{status}  {label}")
            print(f"{info['detail']}")
        else:
            print(f"  {status}  {label}")
 
    verdict = "ACCEPTED" if all_passed else "REJECTED"
    print(f"\n Verdict: {verdict}\n")
 
    return all_passed, results
 
 
def process_path(path, seen_subjects, verbose=False):
    if os.path.isdir(path):
        files = [
            os.path.join(path, f)
            for f in sorted(os.listdir(path))
            if f.lower().endswith(".eml")
        ]
        if not files:
            print(f"No .eml files found in {path}")
            return
        accepted = 0
        for fp in files:
            passed, _ = process_email(fp, seen_subjects, verbose)
            if passed:
                accepted += 1
        print(f"\nSummary: {accepted}/{len(files)} emails accepted.")
    elif os.path.isfile(path):
        process_email(path, seen_subjects, verbose)
    else:
        print(f"Path not found: {path}")

#use cli interface 
#python phishing_email_detection.py <email.eml>

def main():
    parser = argparse.ArgumentParser(
        description="Filter and classify .eml files against rules."
    )
    parser.add_argument("path", help="Path to a .eml file or a directory of .eml files")
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detail for every rule",
    )
    parser.add_argument(
        "--reset-duplicates",
        action="store_true",
        help="Clear the persisted duplicate-subject cache before running",
    )
    args = parser.parse_args()
 
    seen_subjects = set()
    if args.reset_duplicates:
        if os.path.exists(SEEN_FILE):
            os.remove(SEEN_FILE)
        print("Duplicate cache cleared.")
    else:
        seen_subjects = load_seen_subjects()
 
    process_path(args.path, seen_subjects, verbose=args.verbose)
 
    save_seen_subjects(seen_subjects)
 
 
if __name__ == "__main__":
    main()


#UNCOMMENT HERE IF USING VIRUS TOTAL API
# Your VirusTotal API key
#API_KEY = input("Input API key: ")
#BASE_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
#def check_url(url):
#    params = {'apikey': API_KEY, 'resource': url}
#    response = requests.get(BASE_URL, params=params)
#    return response.json()


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
        

#travelKeywords = {"Booking reference"}

        

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


