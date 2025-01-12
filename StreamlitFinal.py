# -*- coding: utf-8 -*-
"""
Created on Sun Jan 12 13:24:30 2025

@author: ostac
"""

import streamlit as st
import pandas as pd
import pickle
import numpy as np
from urllib.parse import urlparse
import re

# Path to the saved models and scaler
save_path = r'D:\MASTER\Cyber Security\Proiect\Pregatire_Proiect'
# rf_model_path = f"{save_path}/Fine_Tuned_Random_Forest.pkl"  # Comentat pentru Random Forest
xgb_model_path = f"{save_path}/Fine_Tuned_XGBoost.pkl"
scaler_path = f"{save_path}/scaler.pkl"

# Load the fine-tuned models and scaler
# with open(rf_model_path, "rb") as rf_file:
#     fine_tuned_rf_model = pickle.load(rf_file)  # Comentat pentru Random Forest

with open(xgb_model_path, "rb") as xgb_file:
    fine_tuned_xgb_model = pickle.load(xgb_file)

with open(scaler_path, "rb") as scaler_file:
    scaler = pickle.load(scaler_file)

# Function to extract features from URLs
def extract_features(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ''
    path = parsed_url.path if parsed_url.path else ''
    
    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'length_path': len(path),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_slashes': url.count('/'),
        'nb_digits': len(re.findall(r'\d', url)),
        'contains_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        'check_www': 1 if 'www' in hostname else 0,
        'check_com': 1 if '.com' in hostname else 0,
        'count_subdomains': hostname.count('.') - 1,
        'shortening_service': 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|short\.to|ow\.ly', url) else 0,
        'abnormal_subdomain': 1 if re.search(r'(http[s]?://(w[w]?|\d))([w]?(\d|-))', url) else 0,
        'count_special_chars': sum(1 for c in url if c in ['@', '!', '$', '%', '^', '&', '*', '(', ')']),
        'path_extension': 1 if re.search(r'\.(exe|zip|pdf|js|html|php|asp)$', path) else 0,
        'avg_word_length': np.mean([len(word) for word in re.findall(r'\w+', hostname)]) if hostname else 0,
        'total_words': len(re.findall(r'\w+', hostname)),
        'ratio_digits_url': len(re.findall(r'\d', url)) / (len(url) + 0.001),
        'ratio_digits_host': len(re.findall(r'\d', hostname)) / (len(hostname) + 0.001),
    }
    return pd.DataFrame([features])

# Streamlit App
st.title("Phishing URL Detection")
st.write("""
Această aplicație vă permite să preziceți dacă un URL este de tip phishing sau nu, utilizând două modele optimizate:
- **XGBoost**

Aplicația a fost creată de Ostache Andrei Tudor în cadrul proiectului de Securitate Cibernetică.
""")

# Input URL
url_input = st.text_input("Introduceți un URL suspect:", placeholder="https://example.com")

if st.button("Prezice tipul URL-ului"):
    if url_input:
        # Extract features from the input URL
        features_df = extract_features(url_input)

        # Scale the features
        features_df_scaled = scaler.transform(features_df)

        # Random Forest prediction (comentat)
        # rf_prediction_proba = fine_tuned_rf_model.predict_proba(features_df_scaled)[0]
        # rf_prediction = "Phishing" if rf_prediction_proba[1] > 0.5 else "Legitim"

        # XGBoost prediction
        xgb_prediction_proba = fine_tuned_xgb_model.predict_proba(features_df_scaled)[0]
        xgb_prediction = "Phishing" if xgb_prediction_proba[1] > 0.5 else "Legitim"

        # Display results
        st.subheader("Rezultatele Predicției")
        
        # st.write(f"**Random Forest Prediction:** {rf_prediction}")  # Comentat
        # st.write(f"**Probability of Phishing:** {rf_prediction_proba[1]:.2%}")  # Comentat
        # st.write(f"**Probability of Legitimate:** {rf_prediction_proba[0]:.2%}")  # Comentat
        
        st.write(f"**XGBoost Prediction:** {xgb_prediction}")
        st.write(f"**Probability of Phishing:** {xgb_prediction_proba[1]:.2%}")
        st.write(f"**Probability of Legitimate:** {xgb_prediction_proba[0]:.2%}")
    else:
        st.error("Introduceți un URL valid!")
