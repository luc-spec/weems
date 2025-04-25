import os
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# Step 1: Preprocessing the PiHole blocklist file
def preprocess_pihole_blocklist(file_path):
    """Remove comments and '0.0.0.0' from each line in a blocklist."""
    processed_lines = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) > 1:
                domain = parts[1]
                processed_lines.append(domain)
    return processed_lines

# Step 2: Build a Naive Bayes text classifier from blocklist
def create_classifier(blocklist_data):
    """Create and train a Naive Bayes classifier."""
    df = pd.DataFrame(blocklist_data, columns=["url"])
    df["label"] = 1  # Block = 1

    # Add a few examples of allowed URLs
    allow_urls = ["example.com", "github.com", "openai.com", "wikipedia.org"]
    allow_df = pd.DataFrame(allow_urls, columns=["url"])
    allow_df["label"] = 0  # Allow = 0

    # Combine datasets
    full_df = pd.concat([df, allow_df], ignore_index=True)

    # Train the classifier
    model = make_pipeline(CountVectorizer(), MultinomialNB())
    model.fit(full_df["url"], full_df["label"])

    return model

# Step 3: Classify a single URI
def classify_request(classifier, uri):
    prediction = classifier.predict([uri])[0]
    return "blocked" if prediction == 1 else "allowed"

# Step 4: Process all files and classify requests
def process_and_classify_requests(blocklist_folder, opensnitch_requests):
    blocklist_data = []

    # Load all .txt files from the folder
    for file_name in os.listdir(blocklist_folder):
        if file_name.endswith(".txt"):
            file_path = os.path.join(blocklist_folder, file_name)
            blocklist_data.extend(preprocess_pihole_blocklist(file_path))

    # Create classifier
    classifier = create_classifier(blocklist_data)

    # Classify each Opensnitch request
    results = []
    for request in opensnitch_requests:
        uri = request['uri']
        classification = classify_request(classifier, uri)
        results.append((request, classification))

    return results

# Example Opensnitch request simulation
if __name__ == "__main__":
    # blocklist_folder = 'weems\\lists' 
    blocklist_folder = 'lists'
    
    # Sample requests
    opensnitch_requests = [
        {"uri": "0-0-0.6te.net", "executable": "chrome", "protocol": "TCP", "to_uri": "0-0-0.6te.net"},
        {"uri": "openai.com", "executable": "python", "protocol": "TCP", "to_uri": "openai.com"},
        {"uri": "badexample.mal", "executable": "wget", "protocol": "TCP", "to_uri": "badexample.mal"},
        {"uri": "github.com", "executable": "code", "protocol": "TCP", "to_uri": "github.com"},
    ]

    results = process_and_classify_requests(blocklist_folder, opensnitch_requests)

    for request, classification in results:
        print(f"Request: {request}, Classification: {classification}")
