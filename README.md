# Email Analyzer

This Python script analyzes email messages to filter out undesirable content and identify potentially useful or suspicious emails. It follows a set of criteria to assess each email's quality and relevance.

## Features
- **Language Detection:** Identifies if the email is in English.
- **Minimum Word Count:** Ensures the email has more than four words.
- **Non-Corporate Domain Filtering:** Filters out common public domains like Gmail, Yahoo, etc.
- **Sender Name Check:** Verifies if the sender's name is present.
- **File Saving:** Supports saving emails in `.eml` or `.smg` format.
- **Subject Line Filtering:** Excludes emails with "Re:" or "Fw:" in the subject.
- **Emoji Detection:** Identifies and filters emails containing emojis.
- **Date Validation:** Ensures the email date is after January 1st, 2021.
- **Duplicate Detection:** Identifies and filters duplicate emails based on hashed subject lines.
- **Promotional Content Detection:** Flags promotional emails.
- **Category Filtering:** Ensures emails fit accepted categories.
- **Link Extraction:** Identifies and extracts URLs from email content.

## Requirements
- Python 3.x
- `langdetect`
- `emoji`
- `requests`

Install dependencies using:
```bash
pip install langdetect emoji requests
```

## Usage
1. Place the email file (e.g., `test1.eml`) in the working directory.
2. Run the script to analyze the email:

```bash
python email_analyzer.py
```

3. The script will output details such as:
   - Language detected
   - Word count status
   - Corporate domain status
   - Presence of sender name
   - Email recency
   - Subject validity
   - Links found in the email

## VirusTotal Integration (Optional)
The script supports VirusTotal API integration for checking URLs.

1. Uncomment the VirusTotal section in the code.
2. Insert your VirusTotal API key in the `API_KEY` variable.
3. The script will check detected links for potential threats.

## Example Output
```
Language detected: en (Is English: True)
Is the email longer than 4 words? True
Is the email address not a corporate domain? True
Does the email have a sender name? True
Is the email recent (after Jan 1st, 2021)? True
Subject does not contain 'Re:' or 'Fw:': True
Subject does not contain emojis: True
Is the email subject not a duplicate? True
Links found in the email: ['http://example.com']
```

## Notes
- For security purposes, ensure the VirusTotal API key is kept confidential.
- The code includes logic to filter out common spam patterns, making it useful for forensic analysis or email filtering solutions.

## License
This project is licensed under the MIT License.

