import os
import re
import string
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np

class Request:
    def __init__(self, process_path, process_id, destination_ip, destination_port, protocol, user_id, process_args):
        self.process_path = process_path
        self.process_id = process_id
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.user_id = user_id
        self.process_args = process_args

def clean_text(text):
    text = text.lower()
    text = re.sub(r'\d+', '', text)
    text = text.translate(str.maketrans('', '', string.punctuation))
    return text

class RequestClassifier:
    def __init__(self, data_folder):
        self.data_folder = data_folder
        self.vectorizer = TfidfVectorizer()
        self.classifier = MultinomialNB()
        self.file_labels = []
        self.trained = False

    def extract_features(self, request):
        return f"{request.process_path} {request.destination_ip} {request.destination_port} {request.protocol} {request.user_id} {request.process_args}"

    def load_data(self):
        texts = []
        labels = []
        file_list = sorted(f for f in os.listdir(self.data_folder) if f.endswith(".txt"))
        self.file_labels = file_list

        for idx, filename in enumerate(file_list):
            file_path = os.path.join(self.data_folder, filename)
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue  # Skip empty or comment lines
                    if line.startswith("0.0.0.0"):
                        line = line[len("0.0.0.0"):].strip()  # Remove "0.0.0.0" from start
                    texts.append(clean_text(line))
                    labels.append(idx)

        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        self.classifier.fit(X, y)
        self.trained = True

    def classify_request(self, request):
        if not self.trained:
            raise ValueError("Classifier is not trained. Call load_data() first.")

        request_text = clean_text(self.extract_features(request))
        request_vector = self.vectorizer.transform([request_text])
        proba = self.classifier.predict_proba(request_vector)[0]

        result = {self.file_labels[i]: float(f"{prob*100:.2f}") for i, prob in enumerate(proba)}
        return result

# Example usage:
if __name__ == "__main__":
    data_folder = r"C:\Users\jonaj\OneDrive - UCB-O365\gitHub\RemoteGithub\weems\lists"
    classifier = RequestClassifier(data_folder)
    classifier.load_data()

    requests = [
        Request("/usr/bin/python3", "67890", "affiliatecashpile.go2jump.org", "80", "tcp", "1000", "wget http://affiliatecashpile.go2jump.org/badfile"),
        Request("/usr/bin/python3", "67890", "088156060096.nidzica.vectranet.pl", "80", "tcp", "1000", "wget http://088156060096.nidzica.vectranet.pl/badfile"),
        Request("firefox", "6789", "0-0-0-0-0-0proxy.tserv.se", "443", "TCP", "user4", "https://0-0-0-0-0-0proxy.tserv.se"),
        Request("chrome", "1234", "104.27.135.50", "443", "TCP", "user1", "http://armdl.adobe.com/"),
        Request("chrome", "2345", "185.221.88.122", "443", "TCP", "user2", "https://www.8cr.purredheanb.online"),
        Request("firefox", "5678", "104.26.12.50", "443", "TCP", "user3", "https://tracking-site.net"),
        Request("firefox", "67890", "1-170-195-217.cust.centrio.cz", "80", "tcp", "1001", "wget http://1-170-195-217.cust.centrio.cz/badfile"),
        Request("firefox", "6789", "08.185.87.118.liveadvert.com", "443", "TCP", "user5", "https://08.185.87.118.liveadvert.com"),
        Request("firefox", "12345", "1-2fly-befragung.de", "80", "TCP", "user6", "http://1-2fly-befragung.de"),
        Request("/usr/bin/python3", "67890", "0-0-0-6te.net", "80", "tcp", "1000", "wget http://0-0-0-6te.net/badfile"),
        Request("firefox", "6789", "104.27.135.50", "443", "TCP", "user4", "https://phishing-page.net"),
        Request("chrome", "1234", "142.250.190.78", "443", "TCP", "user1", "https://www.google.com"),
        Request("chrome", "2345", "185.221.88.122", "443", "TCP", "user2", "https://phishing-page.net"),
        Request("firefox", "5678", "104.26.12.50", "443", "TCP", "user3", "https://www.cloudflare.com"),
        Request("chrome", "6789", "104.27.135.50", "443", "TCP", "user4", "https://tracking-site.net"),
    ]
    for request in requests:
        print(f"\nRequest to: {request.destination_ip}")
        scores = classifier.classify_request(request)
        for file, score in scores.items():
            print(f"{file}: {score}%")
