import numpy as np
import joblib
import pandas as pd
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping
import tensorflow as tf

# Load the dataset (make sure 'normal_login_data.csv' exists and has columns 'username' and 'password')
data = pd.read_csv('normal_login_data.csv')

# Combine username and password pairs into a single list of login data
login_data = data['username'] + ' ' + data['password']

# Tokenize the login pairs
tokenizer = Tokenizer(filters='', oov_token='<OOV>') 
tokenizer.fit_on_texts(login_data)
sequences = tokenizer.texts_to_sequences(login_data)
padded_sequences = pad_sequences(sequences, maxlen=10, padding='post')

# Build Autoencoder
input_dim = padded_sequences.shape[1]
encoding_dim = 4

input_layer = Input(shape=(input_dim,))
encoded = Dense(8, activation='relu')(input_layer)
bottleneck = Dense(encoding_dim, activation='relu')(encoded)
decoded = Dense(8, activation='relu')(bottleneck)
output_layer = Dense(input_dim, activation='linear')(decoded)

autoencoder = Model(input_layer, output_layer)
autoencoder.compile(optimizer='adam', loss='mse')

# Train the model
autoencoder.fit(
    padded_sequences, padded_sequences,
    epochs=100,
    batch_size=4,
    validation_split=0.2,
    callbacks=[EarlyStopping(monitor='val_loss', patience=5)],
    verbose=1
)

# Save the model and tokenizer
autoencoder.save("autoencoder_model.h5")
joblib.dump(tokenizer, "autoencoder_tokenizer.pkl")

print("Model and tokenizer saved successfully.")
