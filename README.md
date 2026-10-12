# AI-Based Phishing Email Detection System

A college-level project focused on detecting phishing emails using machine learning, static URL analysis, and a modern web interface. The system allows users to input an email, upload an `.eml` file, and receive a risk-based phishing detection result alongside explanations and recommendations.

## Project Overview

This project demonstrates an end-to-end phishing email detection workflow using:

- A responsive frontend built with HTML5, CSS3, JavaScript, and Bootstrap
- A Flask backend for API services and business logic
- A TF-IDF + machine learning pipeline for textual phishing detection
- Static URL and header analysis modules for additional risk signals
- SQLite persistence for scan history and dashboard statistics

The system is designed for educational and prototype use, with emphasis on applying AI concepts to cybersecurity problems in a practical, demonstrable way.

## Problem Statement

Phishing emails continue to be one of the most common and damaging forms of cyber attacks. Attackers use deceptive messages to steal sensitive information, trick users into clicking malicious links, or cause financial and reputational harm.

Traditional rule-based detection systems are often limited in effectiveness because phishing content constantly evolves. There is a clear need for automated, data-driven detection methods capable of analyzing email text and identifying suspicious patterns early.

## Objectives

1. Develop a phishing email detection system using machine learning.
2. Combine text classification with URL and header-based risk indicators.
3. Provide a user-friendly interface for analyzing emails and reviewing results.
4. Support `.eml` upload for realistic email analysis scenarios.
5. Store historical scan information for reporting and dashboard analysis.
6. Demonstrate a practical AI-based cybersecurity application suitable for a B.E. CSE project.

## Features

- Email analysis using sender, subject, and body input
- `.eml` file upload and parsing
- Machine learning-based phishing classification
- URL static analysis without visiting submitted links
- Email header inspection for suspicious indicators
- Risk scoring and recommendations
- Real-time result page with explanation details
- Scan history and dashboard analytics
- Responsive interface for desktop and mobile
- SQLite-backed historical tracking

## Technology Stack

### Frontend
- HTML5
- CSS3
- JavaScript
- Bootstrap 5
- Chart.js

### Backend
- Python
- Flask
- SQLite

### Machine Learning
- pandas
- scikit-learn
- NumPy
- joblib
- TF-IDF vectorization
- Logistic Regression

### Supporting Libraries
- Flask-CORS
- Gunicorn
- python-dotenv

## System Architecture

The project follows a lightweight three-layer architecture:

1. User Interface Layer
   - Static pages such as `index.html`, `result.html`, `dashboard.html`, and `history.html`
   - Browser-based interaction for analysis and history review

2. Backend/API Layer
   - Flask routes for analysis, health checks, upload, dashboard, and history
   - Risk evaluation and service orchestration

3. Intelligence Layer
   - ML model and TF-IDF vectorizer
   - Text preprocessing and prediction logic
   - URL and email header analysis modules

The architecture is intentionally simple and suitable for academic demonstration while keeping separation between frontend, backend, and ML logic.

## Machine Learning Methodology

The system uses text classification based on email content.

### Workflow
1. Dataset preparation and validation
2. Train/test split with fixed random state
3. Text cleaning and normalization
4. TF-IDF vectorization
5. Model training using supervised learning
6. Prediction on unseen test data
7. Evaluation using standard classification metrics
8. Model and vectorizer persistence via `joblib`

### Models Evaluated
- Logistic Regression
- Multinomial Naive Bayes
- Linear SVM

The project applies the same split and evaluation pipeline to each model for comparison. The selected model is stored for use in production prediction.

## Dataset Description

The project uses a phishing email dataset prepared for classification.

### Dataset Characteristics
- Email text content used as the main feature source
- Labels mapped to phishing or legitimate classes
- Preprocessing applied to remove noise, HTML content, and inconsistent formatting
- Dataset is cleaned and stored in the project under `ml/data/processed/`

### Data Handling Principles
- No fabricated metrics are included in the documentation
- Evaluation values should be generated from the actual dataset and project scripts
- The TF-IDF vectorizer is fitted only on the training data to avoid data leakage

## Installation

### Prerequisites
- Python 3.10 or newer
- pip
- Virtual environment recommended

### Clone the project

```bash
git clone <your-repository-url>
cd <project-folder>
```

### Create and activate a virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r backend/requirements.txt
```

### Environment variables

Copy the example environment file and update values as needed:

```bash
copy .env.example .env
```

Then adjust the variables for your environment, especially:

- `SECRET_KEY`
- `ALLOWED_ORIGINS`
- `DATABASE_PATH`
- `PORT`
- `FLASK_ENV`

## How to Run

### Start the Flask backend

From the project root:

```bash
python backend/run.py
```

The app will run on the configured host and port, typically:

- `http://127.0.0.1:5000`

### Open the frontend

Open the project pages in a browser:

- `index.html`
- `result.html`
- `dashboard.html`
- `history.html`

The frontend pages are designed to interact with the Flask API at the local backend URL.

## API Endpoints

### Health
- `GET /api/health`
  - Returns service status information.

### Analysis
- `POST /api/analyze`
  - Accepts sender, subject, and email body.
  - Returns prediction, confidence, risk level, reasons, and recommendation.

### Upload
- `POST /api/upload`
  - Accepts multipart `.eml` upload.
  - Parses the file and runs it through the same analysis pipeline.

### History
- `GET /api/history`
  - Returns recent scan records from SQLite.

### Dashboard
- `GET /api/dashboard`
  - Returns aggregated scan counts and risk statistics.

## Model Evaluation

This section should be updated with actual values generated from the dataset after running the evaluation scripts.

### Metrics to report
- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix
- Model comparison table

### Placeholder

```text
Actual evaluation results will be added after running the final ML evaluation workflow.
```

The project includes scripts for model training and comparison under the `ml/` directory, and the final report should be based on the real test dataset rather than placeholder values.

## Screenshots

Add screenshots of the following pages once available:

- Landing page / analysis form
- Result page with prediction output
- Dashboard with charts and summary cards
- History table with previous scans
- Upload flow for `.eml` messages

### Placeholder

```text
[Screenshot 1: Homepage]
[Screenshot 2: Result page]
[Screenshot 3: Dashboard]
[Screenshot 4: History page]
```

## Project Structure

```text
AI-Based-Phishing-Email-Detection-System/
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── run.py
│   ├── requirements.txt
│   ├── database/
│   │   └── database.py
│   ├── routes/
│   │   ├── analyze.py
│   │   ├── health.py
│   │   ├── history.py
│   │   └── upload.py
│   └── services/
│       ├── analyze_service.py
│       ├── email_parser.py
│       ├── header_analyzer.py
│       ├── risk_analyzer.py
│       └── url_analyzer.py
├── ml/
│   ├── data/
│   ├── models/
│   ├── compare_models.py
│   ├── prepare_dataset.py
│   ├── preprocess.py
│   ├── train.py
│   └── predict.py
├── static/
│   ├── css/
│   └── js/
├── index.html
├── result.html
├── dashboard.html
├── history.html
├── .env.example
├── gunicorn.conf.py
├── README.md
└── LICENSE (optional)
```

## Limitations

- The project is intended for academic/prototype use and may not generalize to every phishing pattern in real-world traffic.
- The dataset size may be limited depending on the available training corpus.
- Static URL analysis does not fetch or visit submitted links.
- Header and URL checks are heuristic and should be interpreted as additional signals rather than proof.
- SQLite is suitable for development and demonstration, but not ideal for large-scale production workloads.
- Machine learning performance depends on the quality and diversity of the dataset.

## Future Enhancements

- Use a larger and more diverse phishing dataset
- Explore advanced models such as XGBoost, Random Forest, or transformer-based classifiers
- Add a better explainability module for model decisions
- Introduce user authentication and admin features
- Deploy the app using Docker and cloud hosting
- Add real-time threat intelligence integration (with safe, approved sources only)
- Improve database scalability by migrating to PostgreSQL
- Add more robust email parsing and attachment handling policy

## Team and Project Information

### Project Title
AI-Based Phishing Email Detection System

### Academic Information
- Department: Computer Science and Engineering
- Institution: <Your College/University Name>
- Program: Bachelor of Engineering
- Year: <Academic Year>

### Team Members
- <Student Name 1>
- <Student Name 2>
- <Student Name 3>

### Guide / Supervisor
- <Guide Name>

### Project Status
- Status: In Progress / Completed / Demo Ready
- Submission: <Semester/Year>

## Acknowledgements

This project was developed as part of academic work in the field of cybersecurity and artificial intelligence. It is intended to demonstrate the practical application of machine learning to phishing detection and awareness.

## License

This project can be licensed under an appropriate open-source or institutional license if required by the college or department.

```text
Add license details here if applicable.
```

## Notes

This README is structured to be professional and project-report ready. Any placeholder values should be replaced with the actual project, team, and evaluation details before final submission.
