FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate data and run evaluator
RUN python scripts/generate_data.py

CMD ["python", "evaluator.py"]
