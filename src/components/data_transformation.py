import re
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer

class AdversarialThreatTransformer:
    def __init__(self, max_features=5000):
        self.vectorizer = TfidfVectorizer(
            stop_words='english',
            max_features=max_features,
            ngram_range=(1, 2)
        )
        # Obfuscation mapping to counter leetspeak evasion attempts
        self.char_map = {
            '@': 'a', '4': 'a', '8': 'b', '3': 'e', '1': 'i', '!': 'i',
            '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't', '€': 'e'
        }

    def normalize_adversarial_text(self, text: str) -> str:
        """Decodes leetspeak and obfuscated characters."""
        text = str(text)
        for char, replacement in self.char_map.items():
            text = text.replace(char, replacement)
        return text

    def clean_text(self, text: str) -> str:
        # 1. Strip raw HTML
        soup = BeautifulSoup(str(text), "html.parser")
        text = soup.get_text()

        # 2. De-obfuscate leetspeak
        text = self.normalize_adversarial_text(text)

        # 3. Standardize URLs and remove non-alphabetic noise
        text = re.sub(r'http\S+|www\S+', ' httpurl ', text)
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        return text.lower().strip()

    def fit_transform(self, texts):
        cleaned = [self.clean_text(t) for t in texts]
        return self.vectorizer.fit_transform(cleaned)

    def transform(self, texts):
        cleaned = [self.clean_text(t) for t in texts]
        return self.vectorizer.transform(cleaned)