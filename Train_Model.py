import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Embedding, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

# Load SQL Injection payload dataset
dataset_path = r"C:\Users\ELCOT\hybrid-honeypot\Dataset\Modified_SQL_Dataset.csv"
df = pd.read_csv(dataset_path, encoding="latin1")

# Print column names to verify
print("Columns in the dataset:", df.columns)

# Print first few rows to inspect the data
print(df.head())

# Ensure the dataset has both SQLi and normal queries
if "Query" not in df.columns or "Label" not in df.columns:
    raise ValueError("The dataset must contain 'Query' and 'Label' columns (1 for SQLi, 0 for normal).")

# Check the distribution of labels
print("Label distribution:")
print(df["Label"].value_counts())

# Clean the "Query" column: convert everything to string and handle missing values
df['Query'] = df['Query'].astype(str)  # Convert all entries to strings
df['Query'] = df['Query'].fillna('')   # Replace NaN values with empty strings

# Now you can proceed with tokenizing the queries
tokenizer = Tokenizer(num_words=10000)  # Limit vocabulary size to 10,000
tokenizer.fit_on_texts(df["Query"])
X = tokenizer.texts_to_sequences(df["Query"])

# Pad sequences to ensure uniform length
max_sequence_length = 100  # Set maximum sequence length for all inputs
X_padded = pad_sequences(X, maxlen=max_sequence_length, padding='post')

# Assign labels: 1 for SQLi, 0 for normal text
y = df["Label"]

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X_padded, y, test_size=0.2, random_state=42)

# Build the CNN Model
model = Sequential([
    Embedding(input_dim=10000, output_dim=128, input_length=max_sequence_length),  # Embedding layer
    Conv1D(filters=64, kernel_size=3, activation='relu'),  # Convolutional layer
    MaxPooling1D(pool_size=2),  # Max pooling layer
    Dropout(0.5),  # Dropout for regularization
    Flatten(),  # Flatten the feature maps
    Dense(64, activation='relu'),  # Fully connected layer
    Dropout(0.5),  # Dropout for regularization
    Dense(1, activation='sigmoid')  # Output layer for binary classification
])

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the CNN model
history = model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))

# Evaluate the model on the test set
y_pred = (model.predict(X_test) > 0.5).astype("int32")
print("\nModel Evaluation:")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall: {recall_score(y_test, y_pred):.4f}")
print(f"F1-Score: {f1_score(y_test, y_pred):.4f}")

# Save the trained model and tokenizer (vectorizer)
model_path = "sqli_cnn_model.h5"
vectorizer_path = "tokenizer.pkl"
model.save(model_path)
joblib.dump(tokenizer, vectorizer_path)

print("\nSQL Injection CNN Model Trained and Saved")
print(f"Model saved to: {model_path}")
print(f"Tokenizer saved to: {vectorizer_path}")
