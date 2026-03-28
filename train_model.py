import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Sample training dataset
data = {
    "text":[
        "Congratulations you won a lottery claim now",
        "Free bonus click this link",
        "Urgent your bank account will be blocked",
        "Win money now limited offer",
        "Meeting scheduled tomorrow",
        "Your amazon order shipped",
        "Let's have lunch today",
        "Reminder for your appointment"
    ],
    "label":[
        1,1,1,1,   # fraud
        0,0,0,0    # safe
    ]
}

df = pd.DataFrame(data)

X = df["text"]
y = df["label"]

vectorizer = TfidfVectorizer()

X_vec = vectorizer.fit_transform(X)

model = LogisticRegression()

model.fit(X_vec,y)

# create models folder
import os
os.makedirs("models",exist_ok=True)

# save files
pickle.dump(model,open("models/ml_model.pkl","wb"))
pickle.dump(vectorizer,open("models/vectorizer.pkl","wb"))

print("Model trained and saved successfully!")