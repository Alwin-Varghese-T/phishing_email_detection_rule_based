from textblob import TextBlob
import nltk
nltk.download('punkt_tab')
import random


def is_suspicious_domain(sender):
    with open('ALL-phishing-domains\\ALL-phishing-domains.txt', 'r') as file:
        suspicious_domains = file.read().splitlines()
    domain = sender.split('@')[-1]
    return domain in suspicious_domains


def is_suspicious_link(link):
    with open('ALL-phishing-links\\ALL-phishing-links.txt', 'r', encoding='utf-8') as file:
        suspicious_domains = file.read().splitlines()

    domain = link.split('//')[-1].split('/')[0]

    for suspicious_domain in suspicious_domains:
        if domain == suspicious_domain or domain.endswith('.' + suspicious_domain):
            return True
    return False


def has_malicious_attachments(attachments):
    
    malicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.js', '.vbs', '.wsf', '.cpl', '.jar']
    for attachment in attachments:
        if any(attachment.endswith(ext) for ext in malicious_extensions):
            return True
    return False


def has_grammar_errors(body, threshold=5):
    blob = TextBlob(body)
    corrections = sum(1 for word, corrected_word in zip(blob.words, blob.correct().words) if word != corrected_word)
    return corrections > threshold

def contains_urgent_language(email_body, email_subject):
    email_content = email_subject + " " + email_body
    urgent_phrases = [ 
        "act now", "limited time", "important", "hurry", "quickly", "soon", 
        "serious legal action", "respond within 24 hours", "immediate action required",
        "urgent", "failure to respond", "important notice", "last warning"
    ]
    return any(phrase in email_content.lower() for phrase in urgent_phrases)


def main(link, attachments, body, subject):
    
    if is_suspicious_link(link):
        print("Suspicious link detected.")
        return False
    
    
    if has_malicious_attachments(attachments):
        print("Malicious attachment detected.")
        return False
    
    
    if has_grammar_errors(body):
        print("Grammar errors detected.")
        return False
    
    
    if contains_urgent_language(subject, body):
        print("Warning: This email might be phishing.")
        return False

    print("Email is not suspicious.")
    return True


def evaluate_system(test_cases):
    TP = FP = TN = FN = 0
    for case in test_cases:
        link, attachments, body, subject, is_phishing = case
        result = not main(link, attachments, body, subject)
        if result and is_phishing:
            TP += 1
        elif result and not is_phishing:
            FP += 1
        elif not result and not is_phishing:
            TN += 1
        elif not result and is_phishing:
            FN += 1
    accuracy = (TP + TN) / (TP + FP + TN + FN)
    return TP, FP, TN, FN, accuracy

def generate_test_dataset(num_samples=20):
    phishing_domains = [
        "thekelpiesfamily.io", "thekendallalexandercollection.com", "thekindergarten.com.au",
        "thelabbasketballtraining.com", "thelabron.com", "thelamtheabus.000webhostapp.com"
    ]
    legitimate_domains = [
        "google.com", "amazon.com", "duk.ac.in", "iitmk.ac.in", "stc.ac.in", "gmail.com"
    ]
    malicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.js', '.vbs', '.wsf', '.cpl', '.jar']
    safe_extensions = ['.pdf', '.docx', '.xlsx', '.txt', '.jpg']

    test_cases = []

    for _ in range(num_samples):
        is_phishing = random.choice([True, False])
        if is_phishing:
            domain = random.choice(phishing_domains)
            attachments = [f"file{random.randint(1, 100)}{random.choice(malicious_extensions)}"]
            body = "This is a phishing email body with some grammar errors."
            subject = "Urgent: Action Required"
        else:
            domain = random.choice(legitimate_domains)
            attachments = [f"file{random.randint(1, 100)}{random.choice(safe_extensions)}"]
            body = "This is a legitimate email body with correct grammar."
            subject = "Hello"

        link = f"http://{domain}/path"
        test_cases.append((link, attachments, body, subject, is_phishing))

    return test_cases


test_cases = generate_test_dataset()


for case in test_cases:
    print(case)

TP, FP, TN, FN, accuracy = evaluate_system(test_cases)
print(f"TP: {TP}, FP: {FP}, TN: {TN}, FN: {FN}, Accuracy: {accuracy:.2f}")